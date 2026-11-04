//! One connection attempt: TCP → X.224 negotiation → our TLS (TOFU verifier) → `CredSSP`/NLA →
//! capability exchange (ADR-0011). Ends `Connected`, `NeedsTrust` (unknown certificate: the
//! driver prompts and reconnects on a new TCP connection) or `Failed`.

use std::sync::Arc;
use std::time::Duration;

use ironrdp_connector::connection_activation::ConnectionActivationFactory;
use ironrdp_connector::{
    BitmapConfig, ClientConnector, ClientConnectorState, ConnectionOutcome, ConnectionResult,
    Credentials, DesktopSize, ServerName as RdpServerName,
};
use ironrdp_pdu::gcc::{ConnectionType, KeyboardType};
use ironrdp_pdu::nego::SecurityProtocol;
use ironrdp_pdu::rdp::capability_sets::{
    client_codecs_capabilities, MajorPlatformType, RailSupportLevel,
};
use ironrdp_pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};
use ironrdp_tokio::{
    connect_begin, connect_finalize, mark_as_upgraded, NetworkClient, TokioFramed,
};
use mooring_core::audit::AuthMethod;
use mooring_core::known_certs::{display_fingerprint, CertVerdict, KnownCerts};
use mooring_core::options::RdpConnOptions;
use mooring_core::session::CloseCode;
use mooring_core::SessionAudit;
use secrecy::ExposeSecret;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::creds::Creds;
use crate::errors::{self, end, End};
use crate::options::AuditSink;
use crate::tls::{self, take_decision, Decision, DecisionSlot, TofuVerifier};

/// The transport after the security upgrade.
pub(crate) type RdpStream = TlsStream<TcpStream>;

/// Where and how to connect (everything but the credentials).
#[derive(Debug, Clone)]
pub(crate) struct Target {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) conn: RdpConnOptions,
    pub(crate) known_certs: std::path::PathBuf,
    pub(crate) connect_timeout: Duration,
    pub(crate) keepalive: Option<Duration>,
    pub(crate) client_name: String,
    pub(crate) desktop: DesktopSize,
    /// A certificate trusted for this session only (`trusted_once`, or a `yes` to the prompt);
    /// added to the loaded store in memory so the connect hits the pin row. The pin file is
    /// written by the Tauri layer, never here.
    pub(crate) session_pin: Option<[u8; 32]>,
}

/// A connected, authenticated session ready for the active stage.
pub(crate) struct Established {
    pub(crate) framed: TokioFramed<RdpStream>,
    pub(crate) result: ConnectionResult,
    pub(crate) security: &'static str,
    pub(crate) fingerprint: [u8; 32],
}

pub(crate) enum Attempt {
    Connected(Box<Established>),
    NeedsTrust(Decision),
    Failed(End),
}

/// Kerberos is off in A2 (ADR-0011): the `CredSSP` network client refuses every request, so
/// no KDC traffic ever starts from Mooring.
struct NoNetwork;

impl NetworkClient for NoNetwork {
    async fn send(
        &mut self,
        _request: &ironrdp_connector::sspi::generator::NetworkRequest,
    ) -> ironrdp_connector::ConnectorResult<Vec<u8>> {
        Err(ironrdp_connector::general_err!("network requests (Kerberos) are disabled"))
    }
}

/// Even width, 200..=8192 (MS-RDPEDISP 2.2.2.2.1 limits, also fine for the initial size).
pub fn clamp_desktop(width: u32, height: u32) -> DesktopSize {
    let w = u16::try_from(width.clamp(200, 8192)).unwrap_or(8192) & !1;
    let h = u16::try_from(height.clamp(200, 8192)).unwrap_or(8192);
    DesktopSize { width: w, height: h }
}

/// The connector configuration, without the password (it is set right before `CredSSP`).
pub(crate) fn config(target: &Target, creds: &Creds) -> ironrdp_connector::Config {
    let nla_only = !target.conn.allow_tls_without_nla;
    ironrdp_connector::Config {
        desktop_size: target.desktop,
        monitor_layout: None,
        desktop_scale_factor: 0,
        desktop_physical_size: None,
        desktop_orientation: None,
        device_scale_factor: None,
        monitor_extended_layout: None,
        relative_mouse_input: false,
        enable_tls: !nla_only,
        enable_credssp: true,
        enable_standard_rdp_security: false,
        credentials: Credentials::UsernamePassword {
            username: creds.username.clone(),
            password: String::new(),
        },
        domain: creds.domain.clone(),
        client_build: 0,
        client_name: target.client_name.chars().take(15).collect(),
        keyboard_type: KeyboardType::IBM_ENHANCED,
        keyboard_subtype: 0,
        keyboard_functional_keys_count: 12,
        keyboard_layout: target.conn.keyboard_layout,
        connection_type: ConnectionType::Lan,
        ime_file_name: String::new(),
        bitmap: Some(BitmapConfig {
            lossy_compression: false,
            color_depth: 32,
            codecs: client_codecs_capabilities(&[]).unwrap_or_default(),
        }),
        dig_product_id: String::new(),
        client_dir: String::new(),
        alternate_shell: String::new(),
        work_dir: String::new(),
        remote_application_mode: false,
        rail_support_level: RailSupportLevel::empty(),
        platform: MajorPlatformType::UNSPECIFIED,
        hardware_id: None,
        request_data: None,
        // With NLA the server logs on with the CredSSP credentials; only TLS-only legacy
        // hosts get them in the Client Info PDU (inside TLS).
        autologon: !nla_only,
        enable_audio_playback: false,
        enable_audio_capture: false,
        performance_flags: PerformanceFlags::default(),
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
        compression_type: None,
        enable_server_pointer: true,
        pointer_software_rendering: false,
        multitransport_flags: None,
        support_dyn_vc_gfx_protocol: false,
    }
}

fn set_keepalive(stream: &TcpStream, idle: Option<Duration>) {
    if let Some(idle) = idle {
        let ka =
            socket2::TcpKeepalive::new().with_time(idle).with_interval(Duration::from_secs(10));
        if let Err(e) = socket2::SockRef::from(stream).set_tcp_keepalive(&ka) {
            tracing::debug!(error = %e, "tcp keepalive not set");
        }
    }
}

async fn load_trust(target: &Target) -> Result<(KnownCerts, rustls::RootCertStore), End> {
    let path = target.known_certs.clone();
    let ca = target.conn.ca_pem.clone();
    let (host, port, pin) = (target.host.clone(), target.port, target.session_pin);
    tokio::task::spawn_blocking(move || {
        let mut known = KnownCerts::load(&path)?;
        if let Some(pin) = pin {
            if !known.has_pin(&host, port) {
                known.add(&host, port, &pin, time::OffsetDateTime::now_utc());
            }
        }
        Ok::<_, mooring_core::known_certs::KnownCertsError>((
            known,
            tls::root_store(tls::system_roots(), ca.as_deref()),
        ))
    })
    .await
    .map_err(|_| end(CloseCode::ProtocolError, "trust store task failed"))?
    .map_err(|e| {
        tracing::debug!(error = %e, "known_rdp_certs unreadable");
        end(CloseCode::ProtocolError, "the certificate trust store could not be read")
    })
}

fn mismatch(target: &Target, d: &Decision, expected: &[u8; 32], audit: &AuditSink) -> End {
    let (old, new) = (display_fingerprint(expected), display_fingerprint(&d.fingerprint));
    audit.push(SessionAudit::CertMismatch {
        host: target.host.clone(),
        port: target.port,
        expected: old.clone(),
        presented: new.clone(),
    });
    let reason = format!(
        "CERTIFICATE CHANGED for {}:{}: expected {old}, got {new}",
        target.host, target.port
    );
    (CloseCode::TrustMismatch, reason)
}

/// Run one attempt. `creds` is only read; the password is copied into the connector right
/// before `CredSSP` and the connector is consumed by it.
pub(crate) async fn attempt(
    target: &Target,
    creds: &Creds,
    channels: crate::active::Channels,
    audit: &AuditSink,
) -> Attempt {
    match attempt_inner(target, creds, channels, audit).await {
        Ok(a) => a,
        Err(e) => Attempt::Failed(e),
    }
}

/// Result of the TLS step: the stream, or the decision that needs the user.
enum Upgrade {
    Done(Box<RdpStream>, Decision),
    NeedsTrust(Decision),
}

async fn upgrade_tls(
    target: &Target,
    tcp: TcpStream,
    known: KnownCerts,
    roots: rustls::RootCertStore,
    audit: &AuditSink,
) -> Result<Upgrade, End> {
    let name = tls::server_name(&target.host)
        .ok_or_else(|| end(CloseCode::ProtocolError, "host is not a valid TLS server name"))?;
    let slot = DecisionSlot::default();
    let verifier =
        Arc::new(TofuVerifier::new(&target.host, target.port, known, roots, Arc::clone(&slot)));
    let tls_config = tls::client_config(verifier)
        .map_err(|_| end(CloseCode::ProtocolError, "TLS setup failed"))?;
    let handshake = tokio_rustls::TlsConnector::from(Arc::new(tls_config)).connect(name, tcp).await;
    match (handshake, take_decision(&slot)) {
        (Ok(s), Some(d)) => {
            match d.verdict {
                CertVerdict::AcceptCa => audit.push(SessionAudit::CertCaValid {
                    host: target.host.clone(),
                    port: target.port,
                    fingerprint: display_fingerprint(&d.fingerprint),
                }),
                CertVerdict::AcceptPinned { chain_valid: false } => {
                    tracing::info!(
                        "pinned certificate accepted although its chain does not validate"
                    );
                }
                _ => {}
            }
            Ok(Upgrade::Done(Box::new(s), d))
        }
        (Err(_), Some(d)) => match d.verdict {
            CertVerdict::Prompt => Ok(Upgrade::NeedsTrust(d)),
            CertVerdict::Mismatch { expected } => Err(mismatch(target, &d, &expected, audit)),
            // Accepted chain, failed later: e.g. the handshake signature did not verify.
            _ => Err(end(CloseCode::Network, "TLS handshake failed")),
        },
        (Err(e), None) => {
            tracing::debug!(error = %e, "rdp tls handshake failed before certificate verification");
            Err(end(CloseCode::Network, "TLS handshake failed"))
        }
        (Ok(_), None) => Err(end(CloseCode::ProtocolError, "TLS handshake without a certificate")),
    }
}

async fn tcp_connect(target: &Target) -> Result<TcpStream, End> {
    let tcp = tokio::time::timeout(
        target.connect_timeout,
        TcpStream::connect((target.host.as_str(), target.port)),
    )
    .await
    .map_err(|_| end(CloseCode::Network, "connection timed out"))?
    .map_err(|e| {
        tracing::debug!(error = %e, "rdp tcp connect failed");
        end(CloseCode::Network, "connection failed")
    })?;
    let _ = tcp.set_nodelay(true);
    set_keepalive(&tcp, target.keepalive);
    Ok(tcp)
}

async fn attempt_inner(
    target: &Target,
    creds: &Creds,
    channels: crate::active::Channels,
    audit: &AuditSink,
) -> Result<Attempt, End> {
    let (known, roots) = load_trust(target).await?;
    let tcp = tcp_connect(target).await?;
    let client_addr = tcp.local_addr().map_err(|e| errors::io(&e))?;

    let base = config(target, creds);
    let mut connector = channels.attach(ClientConnector::new(base.clone(), client_addr));
    let mut framed = TokioFramed::new(tcp);
    let should_upgrade =
        connect_begin(&mut framed, &mut connector).await.map_err(|e| errors::connector(&e))?;
    let ClientConnectorState::EnhancedSecurityUpgrade { selected_protocol: selected } =
        connector.state
    else {
        return Err(end(CloseCode::ProtocolError, "unexpected connection state"));
    };
    let nla = selected.intersects(SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX);
    let tls_only_ok = target.conn.allow_tls_without_nla && selected.contains(SecurityProtocol::SSL);
    if !(nla || tls_only_ok) {
        return Err(end(
            CloseCode::ProtocolError,
            "the server does not offer NLA (enable allowTlsWithoutNla only for legacy hosts)",
        ));
    }
    let (tcp, leftover) = framed.into_inner();
    if !leftover.is_empty() {
        return Err(end(CloseCode::ProtocolError, "unexpected data before the TLS upgrade"));
    }
    let (tls, decision) = match upgrade_tls(target, tcp, known, roots, audit).await? {
        Upgrade::Done(s, d) => (s, d),
        Upgrade::NeedsTrust(d) => return Ok(Attempt::NeedsTrust(d)),
    };
    let spki = crate::cert::server_public_key(&decision.der)
        .map_err(|_| end(CloseCode::ProtocolError, "the server certificate could not be parsed"))?;

    let upgraded = mark_as_upgraded(should_upgrade, &mut connector);
    let mut framed = TokioFramed::new(*tls);
    if !nla {
        audit.push(SessionAudit::RdpLegacySecurity);
    }
    // R-RDP-STR: IronRDP keeps the password as a plain String inside the connector (consumed
    // below) and CredSSP; ours stays a SecretString.
    connector.config.credentials = Credentials::UsernamePassword {
        username: creds.username.clone(),
        password: creds.password.expose_secret().to_owned(),
    };
    let server = RdpServerName::new(target.host.clone());
    let outcome =
        connect_finalize(upgraded, connector, &mut framed, &mut NoNetwork, server, spki, None)
            .await
            .map_err(|e| {
                let ended = errors::connector(&e);
                if ended.0 == CloseCode::AuthFailed {
                    audit.push(SessionAudit::AuthFailed);
                }
                ended
            })?;
    let ConnectionOutcome::Connected(mut result) = outcome else {
        return Err(end(CloseCode::ProtocolError, "server redirection is not supported"));
    };
    // The factory IronRDP built holds a clone of the config with the password; replace it with
    // one built from the password-free config so it does not live for the whole session.
    result.activation_factory = ConnectionActivationFactory::new(
        base,
        result.activation_factory.io_channel_id(),
        result.activation_factory.user_channel_id(),
    );
    audit.push(SessionAudit::AuthSucceeded {
        method: if nla { AuthMethod::Nla } else { AuthMethod::RdpTls },
    });
    Ok(Attempt::Connected(Box::new(Established {
        framed,
        result,
        security: if nla { "nla" } else { "tls" },
        fingerprint: decision.fingerprint,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_is_clamped_and_even() {
        assert_eq!(clamp_desktop(1921, 1080), DesktopSize { width: 1920, height: 1080 });
        assert_eq!(clamp_desktop(10, 10), DesktopSize { width: 200, height: 200 });
        assert_eq!(clamp_desktop(100_000, 100_000), DesktopSize { width: 8192, height: 8192 });
    }

    #[test]
    fn config_requires_nla_unless_allowed_and_never_offers_rc4() {
        let mut t = Target {
            host: "rdp.example.test".into(),
            port: 3389,
            conn: RdpConnOptions::default(),
            known_certs: "/nonexistent/known_rdp_certs".into(),
            connect_timeout: Duration::from_secs(1),
            keepalive: None,
            client_name: "A-VERY-LONG-CLIENT-NAME".into(),
            desktop: clamp_desktop(1024, 768),
            session_pin: None,
        };
        let c = Creds {
            username: "u".into(),
            domain: Some("D".into()),
            password: "pw".to_owned().into(),
        };
        let cfg = config(&t, &c);
        assert!(cfg.enable_credssp && !cfg.enable_tls && !cfg.enable_standard_rdp_security);
        assert!(!cfg.autologon && !cfg.enable_audio_playback && !cfg.support_dyn_vc_gfx_protocol);
        assert_eq!(cfg.client_name.chars().count(), 15);
        assert_eq!(cfg.keyboard_layout, 0x0409);
        let Credentials::UsernamePassword { password, .. } = &cfg.credentials else {
            panic!("kind")
        };
        assert!(password.is_empty(), "password is set only right before CredSSP");
        t.conn.allow_tls_without_nla = true;
        t.conn.keyboard_layout = 0x041F;
        let cfg = config(&t, &c);
        assert!(cfg.enable_tls && cfg.enable_credssp && !cfg.enable_standard_rdp_security);
        assert_eq!(cfg.keyboard_layout, 0x041F);
    }
}
