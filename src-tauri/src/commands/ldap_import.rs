//! LDAPS directory importer commands (ADR-0019 §4, §5): `ldap_import_preview` binds with a
//! vault credential, runs the read-only search and keeps the plan under a `planId` like a
//! file import (`import_apply` / `import_discard` finish it); `ldap_import_test` binds and
//! unbinds. Transport trust is `known_ldap_certs` plus `caPem`, with the Rust-native TOFU
//! prompt of the vSphere / sync Gates (pin on "Trust", `trusted_once` when the pin cannot be
//! stored). Audit: `ldap_bind { host, success }` for every bind the server saw (`false` when
//! it refused or the bind never completed; a run that dies after the bind writes `true` and
//! then the refusal), `import_previewed { format: "ldap" }`, `import_refused { code }` —
//! never a bind name, DN, entry or password.
//!
//! Review 7 L-43: a compromised `WebView` could otherwise send any stored password to a host
//! of its choice in one call (a CA-valid or `caPem`-valid host never raises the TOFU dialog).
//! Every run therefore goes trust → **sign-in confirmation** → bind: transport trust is
//! settled first with a handshake-only probe ([`ldap::probe_tls`], no LDAP frame), then the
//! first bind of a (credential, `host:port`) pair in this unlocked session asks in the native
//! Gate ("Sign in to <host>?", three-slot rule, busy / cool-down as elsewhere), remembered in
//! [`ConfirmedBinds`] until the vault locks. A refusal is audited `confirm_refused`.

use std::collections::HashSet;
use std::sync::Mutex;

use mooring_audit::AuditEvent;
use mooring_core::credential::CredentialFields;
use mooring_core::known_certs::{host_key, CertProtocol, KnownCerts};
use mooring_core::SecretName;
use mooring_http::tls::{client_config, TlsClient, TlsTarget};
use mooring_http::{HttpError, TrustDecision, MAX_CA_PEM};
use mooring_import::ldap::{self, BindCredential, BindPhase, BindSignal, DirectoryKind, LdapError, LdapLimits, LdapQuery, Prepared, SearchScope};
use mooring_import::ImportFormat;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, Runtime, State};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::autolock::AutoLock;
use crate::commands::import::{self, ImportPreview};
use crate::commands::vsphere_confirm::{Ask, DialogConfirm, Prompt};
use crate::confirm_gate::Scope;
use crate::error::{IpcError, IpcResult};
use crate::session_audit::cert;
use crate::state::AppState;

/// Codes forwarded from `LdapError::code` (listed so `ipc-codes.json` carries them; a test
/// pins the list against the crate).
pub const LDAP_CODES: &[&str] = &[
    "ldap.insecure",
    "ldap.invalid",
    "ldap.dn_invalid",
    "ldap.bind",
    "ldap.size_limit",
    "ldap.timeout",
    "ldap.unavailable",
    "ldap.response",
];

/// `ldap_import_preview` / `ldap_import_test` input.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LdapInput {
    /// `ldaps://host[:636]`.
    pub url: String,
    /// Search base.
    pub base_dn: String,
    /// `base` | `one` | `sub` (default `sub`).
    #[serde(default = "default_scope")]
    pub scope: SearchScope,
    /// `ad` | `openldap`.
    pub kind: DirectoryKind,
    /// Optional substring the computer name must contain (escaped before use).
    #[serde(default)]
    pub filter: Option<String>,
    /// A `domain_user` or `user_password` credential id (the bind account).
    pub credential_id: String,
    /// Extra PEM roots for the server certificate.
    #[serde(default)]
    pub ca_pem: Option<String>,
    /// Entry cap (clamped to 5 000).
    #[serde(default)]
    pub size_limit: Option<usize>,
}

fn default_scope() -> SearchScope {
    SearchScope::Sub
}

/// (credential id, `host:port`) pairs whose sign-in was confirmed since the last unlock
/// (L-43). Memory only; `vault_lock` clears it.
#[derive(Debug, Default)]
pub struct ConfirmedBinds {
    inner: Mutex<HashSet<(String, String)>>,
}

impl ConfirmedBinds {
    fn with<T>(&self, f: impl FnOnce(&mut HashSet<(String, String)>) -> T) -> T {
        let mut g = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut g)
    }

    /// Whether this pair was confirmed in this session.
    pub fn contains(&self, credential_id: &str, host: &str) -> bool {
        self.with(|m| m.contains(&(credential_id.to_owned(), host.to_owned())))
    }

    fn insert(&self, credential_id: &str, host: &str) {
        self.with(|m| {
            m.insert((credential_id.to_owned(), host.to_owned()));
        });
    }

    /// Forget every pair (vault lock).
    pub fn clear(&self) {
        self.with(HashSet::clear);
    }

    /// Pairs remembered (tests).
    pub fn len(&self) -> usize {
        self.with(|m| m.len())
    }

    /// Whether nothing is remembered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The resolved bind account: the wire credential and what the dialog may say about it.
struct Resolved {
    /// Id as validated (the key of [`ConfirmedBinds`]).
    id: String,
    /// The credential's display name (never the password).
    label: String,
    bind: BindCredential,
}

/// `ldap_import_test` result: names only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LdapTestResult {
    /// Host as typed (lower-case).
    pub host: String,
    /// Port.
    pub port: u16,
    /// The bind name used (`user@domain`, `DOMAIN\user` or the stored username).
    pub bound_as: String,
}

fn map_error(e: &LdapError) -> IpcError {
    IpcError::new(e.code(), e.to_string())
}

/// The bind name of the credential: `domain_user` → `user@domain` (UPN) or `DOMAIN\user`
/// (`NetBIOS`); `user_password` → the stored username, with `user@domain` when a domain is set.
fn bind_name(fields: &CredentialFields) -> IpcResult<String> {
    use mooring_core::credential::AccountForm;
    match fields {
        CredentialFields::DomainUser(f) => Ok(match f.form {
            AccountForm::Upn => format!("{}@{}", f.user, f.domain),
            AccountForm::Netbios => format!("{}\\{}", f.domain, f.user),
        }),
        CredentialFields::UserPassword(f) if !f.username.is_empty() => Ok(match &f.domain {
            Some(d) if !d.is_empty() => format!("{}@{d}", f.username),
            _ => f.username.clone(),
        }),
        _ => Err(IpcError::new("credential.incompatible", "a domain_user or user_password credential is required")),
    }
}

/// The bind credential from a stored password. Review 7 N-54 / RFC 4513 §5.1.2: a name with
/// an empty password is an *unauthenticated* bind that many servers answer with success, so
/// an empty (or non-UTF-8) secret is refused here, before any network. The store refuses to
/// seal an empty secret on every write path; this is the last line.
fn bind_credential(name: String, bytes: &[u8]) -> IpcResult<BindCredential> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| IpcError::new("credential.secret_missing", "stored password is not text"))?;
    if text.is_empty() {
        return Err(IpcError::new("ldap.bind", "the stored password is empty; an unauthenticated bind is never sent"));
    }
    Ok(BindCredential { name, password: Zeroizing::new(text.to_owned()) })
}

/// Resolve the bind credential from the unlocked vault (never kept beyond the call).
fn credential(state: &AppState, id: &str) -> IpcResult<Resolved> {
    let id = crate::dto::credential_id("credentialId", id)?;
    state.with_ready(|vault, store| {
        let meta = store.get_credential(id)?;
        let name = bind_name(&meta.fields)?;
        let bytes = store.open_secret(vault, id, SecretName::Password)?;
        let bind = bind_credential(name, &bytes)?;
        Ok(Resolved { id: id.to_string(), label: meta.name, bind })
    })
}

fn prepare(input: &LdapInput) -> IpcResult<Prepared> {
    if input.ca_pem.as_ref().is_some_and(|p| p.len() > MAX_CA_PEM) {
        return Err(IpcError::invalid("caPem", "longer than 64 KiB"));
    }
    let q = LdapQuery {
        url: input.url.clone(),
        base_dn: input.base_dn.clone(),
        scope: input.scope,
        kind: input.kind,
        name_contains: input.filter.clone(),
        size_limit: input.size_limit,
    };
    q.prepare(&LdapLimits::DEFAULT).map_err(|e| map_error(&e))
}

async fn tls(state: &AppState, p: &Prepared, ca_pem: Option<&str>, trusted_once: Option<[u8; 32]>) -> IpcResult<TlsClient> {
    let target = TlsTarget {
        protocol: CertProtocol::Ldap,
        host: p.target.host.clone(),
        port: p.target.port,
        known_certs_path: state.data_dir.join(CertProtocol::Ldap.file_name()),
        extra_ca_pem: ca_pem.map(str::to_owned),
        trusted_once,
    };
    client_config(&target).await.map_err(|e| IpcError::new(e.code(), e.to_string()))
}

/// Ask whether to trust `d`; "Trust" pins it (or trusts it for this run when the pin cannot
/// be stored). Audited `cert_decision` with protocol `ldap`, like the vSphere Gate.
async fn trust_prompt(state: &AppState, p: &Prepared, d: &TrustDecision, prompt: Prompt<'_>) -> IpcResult<Option<[u8; 32]>> {
    let host = host_key(&p.target.host, p.target.port);
    let fp = d.info.display_fingerprint();
    let text = format!(
        "The certificate of the directory server {host} is not trusted yet.\n\nSubject: {}\nIssuer: {}\nFingerprint: {fp}\n\nTrust this certificate for future connections?",
        d.info.subject, d.info.issuer
    );
    let ask = Ask { title: "Mooring \u{b7} Directory certificate".to_owned(), text, ok: "Trust".to_owned(), warning: true };
    let scope = Scope { kind: "ldap_trust", target: &host, destructive: true };
    let yes = prompt.ask(&state.confirm, scope, ask).await?;
    let audit = |decision: &str| state.audit(cert("ldap".to_owned(), host.clone(), fp.clone(), decision, None));
    if !yes {
        audit("rejected");
        return Err(IpcError::new("http.trust_rejected", "the directory certificate was not trusted"));
    }
    let (path, h, port, sha) = (state.data_dir.join(CertProtocol::Ldap.file_name()), p.target.host.clone(), p.target.port, d.fingerprint);
    let saved = tokio::task::spawn_blocking(move || KnownCerts::add_and_save(&path, &h, port, &sha, OffsetDateTime::now_utc()))
        .await
        .map_err(|_| IpcError::new("state.io", "the certificate store could not be written"))?;
    if let Err(e) = saved {
        tracing::warn!(error = %e, "ldap pin not stored; trusted for this run only");
        audit("accepted_session_only");
        return Ok(Some(d.fingerprint));
    }
    audit("accepted");
    Ok(None)
}

/// L-43: the first bind of (`cred.id`, `host:port`) in this unlocked session needs the
/// user's word in the native Gate; a confirmed pair is remembered until the vault locks.
/// Without a prompt object the run is refused (`ldap.confirm_required`); a declined dialog
/// is `ldap.bind_declined`, audited `confirm_refused { kind: ldap_bind }`, and starts the
/// Gate's cool-down for this host like every cancelled destructive confirmation.
async fn confirm_bind(state: &AppState, p: &Prepared, cred: &Resolved, prompt: Option<Prompt<'_>>) -> IpcResult<()> {
    let host = host_key(&p.target.host, p.target.port);
    if state.ldap_binds.contains(&cred.id, &host) {
        return Ok(());
    }
    let Some(prompt) = prompt else {
        return Err(IpcError::new("ldap.confirm_required", "signing in to the directory server needs a confirmation"));
    };
    let text = format!(
        "Sign in to the directory server {host} with the password of \u{201c}{}\u{201d}?\n\nMooring will send the stored password of this credential to {host}. Continue only if you started this import yourself and the server is the one you expect.",
        cred.label
    );
    let ask = Ask { title: "Mooring \u{b7} Directory sign-in".to_owned(), text, ok: format!("Sign in to {host}"), warning: true };
    let scope = Scope { kind: "ldap_bind", target: &host, destructive: true };
    let yes = prompt.ask(&state.confirm, scope, ask).await?;
    if !yes {
        state.audit(AuditEvent::ConfirmRefused { kind: "ldap_bind".to_owned(), target: host, reason: "declined".to_owned() });
        return Err(IpcError::new("ldap.bind_declined", "the directory sign-in was not confirmed"));
    }
    state.ldap_binds.insert(&cred.id, &host);
    Ok(())
}

/// Settle transport trust with a handshake-only probe: on `http.trust_prompt` ask (when a
/// prompt is given) and probe again with the pin written or `trusted_once`. Returns the
/// `trusted_once` fingerprint the run must reuse, if any. No LDAP frame leaves the client.
async fn settle_trust(state: &AppState, p: &Prepared, input: &LdapInput, prompt: Option<Prompt<'_>>) -> IpcResult<Option<[u8; 32]>> {
    let limits = LdapLimits::DEFAULT;
    let first = ldap::probe_tls(p, tls(state, p, input.ca_pem.as_deref(), None).await?, &limits).await;
    match (first, prompt) {
        (Ok(()), _) => Ok(None),
        (Err(LdapError::Tls(HttpError::TrustPrompt(d))), Some(prompt)) => {
            let once = trust_prompt(state, p, &d, prompt).await?;
            ldap::probe_tls(p, tls(state, p, input.ca_pem.as_deref(), once).await?, &limits).await.map_err(|e| map_error(&e))?;
            Ok(once)
        }
        (Err(e), _) => Err(map_error(&e)),
    }
}

/// The whole run: trust ([`settle_trust`]) → sign-in confirmation ([`confirm_bind`]) → `op`
/// with a TLS client. Audits the bind the server saw: `true` when it accepted (even if the
/// run died afterwards, so the chain reads bind → refused), `false` when a bind request
/// went out and was not accepted; nothing when no bind left the client.
async fn with_trust<T, F, Fut>(state: &AppState, p: &Prepared, input: &LdapInput, cred: &Resolved, prompt: Option<Prompt<'_>>, op: F) -> IpcResult<T>
where
    F: Fn(TlsClient, BindSignal) -> Fut,
    Fut: std::future::Future<Output = Result<T, LdapError>>,
{
    let host = host_key(&p.target.host, p.target.port);
    let once = settle_trust(state, p, input, prompt).await?;
    confirm_bind(state, p, cred, prompt).await?;
    let bind = BindSignal::default();
    let result = op(tls(state, p, input.ca_pem.as_deref(), once).await?, bind.clone()).await;
    match (result.is_ok(), bind.phase()) {
        (true, _) | (false, BindPhase::Bound) => state.audit(AuditEvent::LdapBind { host, success: true }),
        (false, BindPhase::Attempted) => state.audit(AuditEvent::LdapBind { host, success: false }),
        (false, BindPhase::NotAttempted) => {}
    }
    result.map_err(|e| map_error(&e))
}

/// `ldap_import_preview`: bind, search, map, keep the plan (format `ldap`).
pub async fn preview(state: &AppState, prompt: Option<Prompt<'_>>, input: LdapInput) -> IpcResult<ImportPreview> {
    state.with_ready(|_, _| Ok(()))?;
    let refused = |e: IpcError| {
        state.audit(AuditEvent::ImportRefused { code: e.code.to_owned() });
        e
    };
    let p = prepare(&input).map_err(refused)?;
    let cred = credential(state, &input.credential_id)?;
    let limits = LdapLimits::DEFAULT;
    let (q, c, l) = (&p, &cred.bind, &limits);
    let op = |tls, bind: BindSignal| async move { ldap::preview(q, c, tls, l, &bind).await };
    let plan = with_trust(state, &p, &input, &cred, prompt, op).await.map_err(refused)?;
    drop(cred);
    let home = std::path::Path::new("/nonexistent");
    import::finish_preview(state, home, ImportFormat::Ldap, plan, false)
}

/// `ldap_import_test`: bind and unbind; names only.
pub async fn test(state: &AppState, prompt: Option<Prompt<'_>>, input: LdapInput) -> IpcResult<LdapTestResult> {
    state.with_ready(|_, _| Ok(()))?;
    let p = prepare(&input)?;
    let cred = credential(state, &input.credential_id)?;
    let limits = LdapLimits::DEFAULT;
    let (q, c, l) = (&p, &cred.bind, &limits);
    let op = |tls, bind: BindSignal| async move { ldap::bind_only(q, c, tls, l, &bind).await };
    with_trust(state, &p, &input, &cred, prompt, op).await?;
    Ok(LdapTestResult { host: p.target.host.clone(), port: p.target.port, bound_as: cred.bind.name.clone() })
}

/// `ldap_import_preview({ url, baseDn, scope?, kind, filter?, credentialId, caPem?, sizeLimit? })`.
#[tauri::command]
#[allow(clippy::too_many_arguments)] // one flat IPC object, as the UI contract states it
pub async fn ldap_import_preview<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    url: String,
    base_dn: String,
    scope: Option<SearchScope>,
    kind: DirectoryKind,
    filter: Option<String>,
    credential_id: String,
    ca_pem: Option<String>,
    size_limit: Option<usize>,
) -> IpcResult<ImportPreview> {
    let dialog = DialogConfirm { app: app.clone() };
    let autolock = app.try_state::<AutoLock>();
    let input = LdapInput { url, base_dn, scope: scope.unwrap_or(SearchScope::Sub), kind, filter, credential_id, ca_pem, size_limit };
    preview(&state, Some(Prompt { confirm: &dialog, autolock: autolock.as_deref() }), input).await
}

/// `ldap_import_test({ url, baseDn, kind, credentialId, caPem? })` → `{ host, port, boundAs }`.
#[tauri::command]
pub async fn ldap_import_test<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, AppState>,
    url: String,
    base_dn: String,
    kind: DirectoryKind,
    credential_id: String,
    ca_pem: Option<String>,
) -> IpcResult<LdapTestResult> {
    let dialog = DialogConfirm { app: app.clone() };
    let autolock = app.try_state::<AutoLock>();
    let input = LdapInput { url, base_dn, scope: SearchScope::Base, kind, filter: None, credential_id, ca_pem, size_limit: None };
    test(&state, Some(Prompt { confirm: &dialog, autolock: autolock.as_deref() }), input).await
}

#[cfg(test)]
#[path = "ldap_import_tests.rs"]
mod tests;
