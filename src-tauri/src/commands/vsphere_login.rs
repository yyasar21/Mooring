//! vCenter login from stored data only (ADR-0015 §1): the connection's host / port / `caPem`,
//! its `vsphere_user` credential (UPN + password, read from the unlocked vault for this login
//! and for each re-login, never kept), and `known_vsphere_certs`. An unknown certificate is
//! confirmed in the Rust-native dialog (pin on "Trust"), then the login is retried once; a
//! scheduled refresh never prompts. Errors map to the literal `vsphere.*` / `http.*` codes.

use std::sync::Arc;

use mooring_core::credential::CredentialFields;
use mooring_core::known_certs::{host_key, CertProtocol, KnownCerts};
use mooring_core::options::VsphereConnOptions;
use mooring_core::{ConnectionId, Protocol, ProtocolOptions, Role, SecretName};
use mooring_http::{HttpConfig, HttpError, TrustDecision};
use mooring_vsphere::{Credential, Session, VsphereClient, VsphereError};
use secrecy::SecretString;
use tauri::Url;
use time::OffsetDateTime;

use crate::commands::vsphere_confirm::{Ask, Prompt};
use crate::confirm_gate::Scope;
use crate::error::{IpcError, IpcResult};
use crate::session_audit::cert;
use crate::state::Ready;
use crate::vsphere_sync::VsCtx;

/// A vCenter connection resolved for a login.
#[derive(Debug, Clone)]
pub struct Target {
    /// `https://host[:port]/`.
    pub base: Url,
    /// Host as stored.
    pub host: String,
    /// Port (443 by default).
    pub port: u16,
    /// Connection name.
    pub name: String,
    /// Its options.
    pub options: VsphereConnOptions,
}

/// A logged-in session and what it was built from.
pub struct Login {
    /// The session (re-login closure attached).
    pub session: Session,
    /// The target.
    pub target: Target,
}

impl std::fmt::Debug for Login {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Login").field("target", &self.target).finish_non_exhaustive()
    }
}

/// `known_vsphere_certs`.
pub fn known_certs(ctx: &VsCtx) -> std::path::PathBuf {
    ctx.data_dir.join(CertProtocol::Vsphere.file_name())
}

/// The vCenter connection `source`: protocol, not a synced VM row, options, base URL.
pub fn target(ready: &Ready, source: ConnectionId) -> IpcResult<Target> {
    ready.with_ready(|_, store| {
        let c = store.get_connection(source)?;
        if c.protocol != Protocol::VsphereConsole || store.connection_sync(source)?.is_some() {
            return Err(IpcError::invalid("connectionId", "not a vCenter connection"));
        }
        let ProtocolOptions::Vsphere(options) = store.connection_options(source)? else {
            return Err(IpcError::invalid("connectionId", "not a vCenter connection"));
        };
        let port = c.port.unwrap_or(443);
        let host = if c.host.contains(':') { format!("[{}]", c.host) } else { c.host.clone() };
        let base = Url::parse(&format!("https://{host}:{port}/"))
            .map_err(|_| IpcError::invalid("host", "not a vCenter address"))?;
        Ok(Target { base, host: c.host, port, name: c.name, options })
    })
}

/// UPN and password of the vCenter's `vsphere_user` credential (vault unlocked).
pub fn credential(ready: &Ready, source: ConnectionId) -> IpcResult<Credential> {
    ready.with_ready(|vault, store| {
        let r = store.resolve_credential(source, Role::Primary)?.ok_or_else(|| {
            IpcError::new("vsphere.auth_failed", "this vCenter connection has no vSphere credential")
        })?;
        let CredentialFields::VsphereUser(f) = &r.fields else {
            return Err(IpcError::new("credential.incompatible", "a vsphere_user credential is required"));
        };
        let bytes = store.open_secret(vault, r.id, SecretName::Password)?;
        let text = String::from_utf8(bytes.to_vec())
            .map_err(|_| IpcError::new("credential.secret_missing", "stored password is not text"))?;
        drop(bytes);
        Ok(Credential { upn: f.upn.clone(), password: SecretString::from(text) })
    })
}

fn http_config(
    ctx: &VsCtx,
    t: &Target,
    trusted_once: Option<[u8; 32]>,
    events: &tokio::sync::mpsc::Sender<TrustDecision>,
) -> HttpConfig {
    let mut http = HttpConfig::new(CertProtocol::Vsphere, t.base.as_str(), known_certs(ctx));
    http.extra_ca_pem.clone_from(&t.options.ca_pem);
    http.trusted_once = trusted_once;
    http.trust_events = Some(events.clone());
    http
}

/// V2 decision (VMRC ticket host): the DNS names of every certificate this login accepted
/// (pinned, `trusted_once` or CA-valid) may appear as the ticket host.
fn accepted_names(rx: &mut tokio::sync::mpsc::Receiver<TrustDecision>) -> Vec<String> {
    let mut names = Vec::new();
    while let Ok(d) = rx.try_recv() {
        if d.verdict.accepted() {
            names.extend(d.info.san.iter().filter(|n| n.parse::<std::net::IpAddr>().is_err()).cloned());
        }
    }
    names.sort();
    names.dedup();
    names
}

/// Log in to the vCenter `source`. `prompt = None` never prompts (scheduler).
pub async fn login(ctx: &VsCtx, source: ConnectionId, prompt: Option<Prompt<'_>>) -> IpcResult<Login> {
    let target = target(&ctx.ready, source)?;
    let cred = credential(&ctx.ready, source)?;
    let reauth_ready = ctx.ready.clone();
    let reauth: mooring_vsphere::CredentialSource =
        Arc::new(move || credential(&reauth_ready, source).ok());
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let first = VsphereClient::login(target.base.clone(), &cred.upn, &cred.password, http_config(ctx, &target, None, &tx)).await;
    let session = match first {
        Ok(s) => s,
        Err(VsphereError::Http(HttpError::TrustPrompt(d))) => {
            let Some(prompt) = prompt else { return Err(map_error(&VsphereError::Http(HttpError::TrustPrompt(d)))) };
            let once = trust_prompt(ctx, &target, &d, prompt).await?;
            VsphereClient::login(target.base.clone(), &cred.upn, &cred.password, http_config(ctx, &target, once, &tx))
                .await
                .map_err(|e| map_error(&e))?
        }
        Err(e) => return Err(map_error(&e)),
    };
    drop(cred);
    session.allow_ticket_hosts(accepted_names(&mut rx));
    Ok(Login { session: session.with_reauth(reauth), target })
}

/// Ask whether to trust `d`; "Trust" pins it (or, when the pin cannot be stored, trusts it
/// for this login only). Audited `cert_decision` like the RDP / VNC Gate.
async fn trust_prompt(ctx: &VsCtx, t: &Target, d: &TrustDecision, prompt: Prompt<'_>) -> IpcResult<Option<[u8; 32]>> {
    let host = host_key(&t.host, t.port);
    let fp = d.info.display_fingerprint();
    let text = format!(
        "The certificate of vCenter \"{}\" ({host}) is not trusted yet.\n\nSubject: {}\nIssuer: {}\nFingerprint: {fp}\n\nTrust this certificate for future connections?",
        t.name, d.info.subject, d.info.issuer
    );
    let ask = Ask { title: "Mooring \u{b7} vCenter certificate".to_owned(), text, ok: "Trust".to_owned(), warning: true };
    let scope = Scope { kind: "vsphere_trust", target: &host, destructive: true };
    let yes = prompt.ask(&ctx.confirm, scope, ask).await?;
    let audit = |decision: &str| ctx.audit(cert("vsphere".to_owned(), host.clone(), fp.clone(), decision, None));
    if !yes {
        audit("rejected");
        return Err(IpcError::new("http.trust_rejected", "the vCenter certificate was not trusted"));
    }
    let (path, h, port, sha) = (known_certs(ctx), t.host.clone(), t.port, d.fingerprint);
    let saved = tokio::task::spawn_blocking(move || KnownCerts::add_and_save(&path, &h, port, &sha, OffsetDateTime::now_utc()))
        .await
        .map_err(|_| IpcError::new("state.io", "the certificate store could not be written"))?;
    if let Err(e) = saved {
        tracing::warn!(error = %e, "vsphere pin not stored; trusted for this login only");
        audit("accepted_session_only");
        return Ok(Some(d.fingerprint));
    }
    audit("accepted");
    Ok(None)
}

/// Literal IPC codes for every `VsphereError` (the golden `ipc-codes.json` scanner reads
/// literals in this crate). Messages are the crate's secret-free `Display`.
pub fn map_error(e: &VsphereError) -> IpcError {
    let code = match e {
        VsphereError::Auth => "vsphere.auth_failed",
        VsphereError::Forbidden => "vsphere.forbidden",
        VsphereError::RateLimited { .. } => "vsphere.rate_limited",
        VsphereError::NotFound => "vsphere.not_found",
        VsphereError::TooLarge(_) => "vsphere.too_large",
        VsphereError::ToolsMissing => "vsphere.tools_missing",
        VsphereError::WrongState => "vsphere.wrong_state",
        VsphereError::PowerDisabled => "vsphere.power_disabled",
        VsphereError::NotConfirmed => "vsphere.not_confirmed",
        VsphereError::Busy => "vsphere.busy",
        VsphereError::Invalid(_) => "vsphere.invalid",
        VsphereError::BadResponse(_) | VsphereError::Failed { .. } => "vsphere.failed",
        VsphereError::Unavailable => "vsphere.unavailable",
        VsphereError::Http(h) => match h {
            HttpError::TrustPrompt(_) => "http.trust_prompt",
            HttpError::TrustMismatch(_) => "http.trust_mismatch",
            HttpError::TrustRejected(_) => "http.trust_rejected",
            HttpError::TrustStore => "http.trust_store",
            HttpError::Tls(_) => "http.tls",
            HttpError::PlaintextRefused | HttpError::InvalidConfig(_) | HttpError::InvalidRequest(_) => "vsphere.invalid",
            _ => "vsphere.unavailable",
        },
    };
    let message = match e {
        VsphereError::RateLimited { retry_after: Some(d) } => {
            format!("{e}; retry in {} s", d.as_secs().max(1))
        }
        _ => e.to_string(),
    };
    IpcError { code, message }
}
