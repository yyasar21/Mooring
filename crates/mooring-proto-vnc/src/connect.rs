//! Connect: TCP → version → security (with the downgrade guard) → `VeNCrypt` X509 / VNC auth /
//! None → `SecurityResult` → `ClientInit` / `ServerInit`. Retries on a new TCP connection after
//! a TOFU `yes`, and once without `VeNCrypt` when it offered only anonymous TLS and TLS is not
//! required.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use mooring_core::audit::AuthMethod;
use mooring_core::known_certs::{display_fingerprint, host_key, CertTrust, KnownCerts};
use mooring_core::options::VncConnOptions;
use mooring_core::SessionAudit;
use tokio::net::TcpStream;

use crate::conn::{send, Conn, RecvBuf};
use crate::error::VncError;
use crate::handshake::{self, ServerInit};
use crate::security::{self, Credential, SecChoice, SecPolicy};
use crate::shared::Shared;
use crate::tls::{self, TofuVerifier, TrustOutcome};
use crate::vencrypt::{self, SubtypeError};
use crate::wire::{take, Parsed, Rd};

/// Where and how to connect.
#[derive(Debug, Clone)]
pub(crate) struct Target {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) conn: VncConnOptions,
    pub(crate) known_certs: PathBuf,
    pub(crate) connect_timeout: Duration,
    pub(crate) handshake_timeout: Duration,
}

/// A connection past `ServerInit`.
pub(crate) struct Established {
    pub(crate) conn: Conn,
    pub(crate) init: ServerInit,
    /// `vencrypt-x509`, `vnc-auth` or `none`.
    pub(crate) security: &'static str,
    /// Leaf fingerprint when TLS is in use.
    pub(crate) tls_fp: Option<[u8; 32]>,
}

impl std::fmt::Debug for Established {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Established").field("security", &self.security).finish_non_exhaustive()
    }
}

/// Connect with retries for TOFU and the anonymous-TLS fallback.
pub(crate) async fn establish(
    t: &Target,
    cred: &Credential,
    shared: &Shared,
) -> Result<Established, VncError> {
    let mut known = match KnownCerts::load(&t.known_certs) {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(error = %e, "known_vnc_certs unreadable; treating as empty");
            KnownCerts::new()
        }
    };
    let mut skip_vencrypt = false;
    let mut trusted_once = false;
    loop {
        let mut no_x509 = false;
        let attempt = tokio::time::timeout(
            t.handshake_timeout,
            attempt(t, cred, &known, skip_vencrypt, &mut no_x509, shared),
        )
        .await
        .unwrap_or_else(|_| Err(VncError::Network("handshake timed out".into())));
        match attempt {
            Ok(e) => return Ok(e),
            Err(_) if no_x509 && !skip_vencrypt && !policy(t, &known, false).tls_required() => {
                tracing::info!("VeNCrypt offers no X509 subtype; retrying without VeNCrypt");
                skip_vencrypt = true;
            }
            Err(VncError::TrustUnknown { fp, info }) if !trusted_once => {
                let hp = host_key(&t.host, t.port);
                let fingerprint = display_fingerprint(&fp);
                if !shared.ask_certificate(&hp, *info).await {
                    shared.audit.push(SessionAudit::CertRejected {
                        host: t.host.clone(),
                        port: t.port,
                        fingerprint,
                    });
                    return Err(VncError::TrustRejected);
                }
                let (path, host, port) = (t.known_certs.clone(), t.host.clone(), t.port);
                let now = time::OffsetDateTime::now_utc();
                let stored = tokio::task::spawn_blocking(move || {
                    KnownCerts::add_and_save(&path, &host, port, &fp, now)
                })
                .await
                .is_ok_and(|r| r.is_ok());
                known.add(&t.host, t.port, &fp, now);
                shared.audit.push(SessionAudit::CertAdded {
                    host: t.host.clone(),
                    port: t.port,
                    fingerprint,
                    stored,
                });
                trusted_once = true;
            }
            Err(e) => return Err(e),
        }
    }
}

fn policy(t: &Target, known: &KnownCerts, skip_vencrypt: bool) -> SecPolicy {
    SecPolicy { security: t.conn.security, pinned: known.has_pin(&t.host, t.port), skip_vencrypt }
}

fn stripped(t: &Target, known: &KnownCerts, shared: &Shared) -> VncError {
    // `check` with a fingerprint that cannot be pinned returns the stored pin.
    let expected = match known.check(&t.host, t.port, &[0u8; 32]) {
        CertTrust::Mismatch { expected } => display_fingerprint(&expected),
        _ => "pinned".to_owned(),
    };
    shared.audit.push(SessionAudit::CertMismatch {
        host: t.host.clone(),
        port: t.port,
        expected,
        presented: "none".to_owned(),
    });
    VncError::TrustMismatch(format!("TLS EXPECTED for {}", host_key(&t.host, t.port)))
}

async fn attempt(
    t: &Target,
    cred: &Credential,
    known: &KnownCerts,
    skip_vencrypt: bool,
    no_x509: &mut bool,
    shared: &Shared,
) -> Result<Established, VncError> {
    let tcp =
        tokio::time::timeout(t.connect_timeout, TcpStream::connect((t.host.as_str(), t.port)))
            .await
            .map_err(|_| VncError::Network("connection timed out".into()))??;
    let _ = tcp.set_nodelay(true);
    let mut conn: Conn = RecvBuf::new(Box::new(tcp));

    conn.next(handshake::parse_version).await?;
    send(&mut conn.io, handshake::CLIENT_VERSION).await?;
    let offered = conn.next(handshake::parse_security_types).await?;
    let pol = policy(t, known, skip_vencrypt);
    let choice = match security::select_security(&offered, cred.kind(), pol) {
        Err(VncError::TrustMismatch(_)) => return Err(stripped(t, known, shared)),
        other => other?,
    };
    send(&mut conn.io, &[choice.byte()]).await?;

    let (security, method, tls_fp) = match choice {
        SecChoice::None => ("none", AuthMethod::None, None),
        SecChoice::VncAuth => {
            vnc_auth(&mut conn, cred).await?;
            ("vnc-auth", AuthMethod::VncAuth, None)
        }
        SecChoice::VeNCrypt => {
            conn.next(vencrypt::parse_version).await?;
            send(&mut conn.io, &vencrypt::CLIENT_VERSION).await?;
            conn.next(vencrypt::parse_version_ack).await?;
            let subtypes = conn.next(vencrypt::parse_subtypes).await?;
            let subtype = match vencrypt::select_subtype(&subtypes, cred.kind()) {
                Ok(s) => s,
                Err(SubtypeError::NoX509) if pol.pinned => return Err(stripped(t, known, shared)),
                Err(e) => {
                    *no_x509 = e == SubtypeError::NoX509;
                    return Err(e.into_error());
                }
            };
            send(&mut conn.io, &subtype.to_be_bytes()).await?;
            conn.next(vencrypt::parse_subtype_ack).await?;
            let (tls_conn, fp) = upgrade(conn, t, known, shared).await?;
            conn = tls_conn;
            let method = match subtype {
                vencrypt::X509_VNC => {
                    vnc_auth(&mut conn, cred).await?;
                    AuthMethod::VncAuth
                }
                vencrypt::X509_PLAIN => {
                    let Credential::UserPassword { user, password } = cred else {
                        return Err(VncError::AuthFailed("no username and password".into()));
                    };
                    send(&mut conn.io, &security::plain_auth_message(user, password)?).await?;
                    AuthMethod::VncPlain
                }
                _ => AuthMethod::None,
            };
            ("vencrypt-x509", method, Some(fp))
        }
    };

    if let Err(e) = conn.next(handshake::parse_security_result).await {
        if matches!(e, VncError::AuthFailed(_)) {
            shared.audit.push(SessionAudit::AuthFailed);
        }
        return Err(e);
    }
    shared.audit.push(SessionAudit::AuthSucceeded { method });
    if tls_fp.is_none() {
        shared.audit.push(SessionAudit::VncPlaintext { security });
    }
    send(&mut conn.io, &handshake::client_init(t.conn.shared)).await?;
    let init = conn.next(handshake::parse_server_init).await?;
    Ok(Established { conn, init, security, tls_fp })
}

async fn vnc_auth(conn: &mut Conn, cred: &Credential) -> Result<(), VncError> {
    let Credential::Password(secret) = cred else {
        return Err(VncError::AuthFailed("the server requires a VNC password".into()));
    };
    let challenge = conn
        .next(|b| {
            let mut r = Rd::new(b);
            let c = take!(r.bytes(16));
            let mut out = [0u8; 16];
            out.copy_from_slice(c);
            Ok(Parsed::Done(out, 16))
        })
        .await?;
    let password = security::vnc_password_bytes(secret)?;
    send(&mut conn.io, &security::vnc_auth_response(&password, &challenge)).await
}

async fn upgrade(
    conn: Conn,
    t: &Target,
    known: &KnownCerts,
    shared: &Shared,
) -> Result<(Conn, [u8; 32]), VncError> {
    let (io, leftover) = conn.into_parts();
    if !leftover.is_empty() {
        return Err(VncError::protocol("data before the TLS handshake"));
    }
    let roots = tls::root_store(t.conn.ca_pem.as_deref(), true)?;
    let verifier = Arc::new(TofuVerifier::new(known.clone(), &t.host, t.port, roots));
    let config = tls::client_config(Arc::clone(&verifier))?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = tls::server_name(&t.host)?;
    let result = connector.connect(name, io).await;
    match (result, verifier.outcome()) {
        (Ok(stream), Some(outcome)) if outcome.accepted() => {
            if let TrustOutcome::CaValid { fp } = outcome {
                shared.audit.push(SessionAudit::CertCaValid {
                    host: t.host.clone(),
                    port: t.port,
                    fingerprint: display_fingerprint(&fp),
                });
            }
            let io: Box<dyn crate::conn::Io> = Box::new(stream);
            Ok((RecvBuf::new(io), outcome.presented()))
        }
        (_, Some(TrustOutcome::Mismatch { expected, presented })) => {
            let (expected, presented) =
                (display_fingerprint(&expected), display_fingerprint(&presented));
            shared.audit.push(SessionAudit::CertMismatch {
                host: t.host.clone(),
                port: t.port,
                expected: expected.clone(),
                presented: presented.clone(),
            });
            Err(VncError::TrustMismatch(format!(
                "CERTIFICATE CHANGED for {}: pinned {expected}, presented {presented}",
                host_key(&t.host, t.port)
            )))
        }
        (_, Some(TrustOutcome::Unknown { fp, info })) => Err(VncError::TrustUnknown { fp, info }),
        (Err(e), _) => Err(VncError::Network(format!("TLS handshake failed: {}", e.kind()))),
        (Ok(_), _) => Err(VncError::protocol("TLS without a certificate decision")),
    }
}
