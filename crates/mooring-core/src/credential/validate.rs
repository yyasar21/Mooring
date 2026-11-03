//! Per-kind trimming, caps and format rules for plaintext fields (ADR-0009 §5). Runs on input
//! and on every read of a stored row.

use super::account::{MAX_DNS, MAX_USER};
use super::fingerprint::{is_sha256_fingerprint, MAX_PEM, MAX_PUBLIC_KEY};
use super::kubeconfig::MAX_CONTEXT_NAME;
use super::structs::KubeconfigFields;
use super::text::{line, multiline, opt_line};
use super::{parse_account, Account, AccountForm, CredentialError, CredentialFields};

/// Longest HTTP header name / scheme.
const MAX_HEADER: usize = 64;
/// Longest token URL.
const MAX_URL: usize = 2048;
/// Longest client id / subject / become user.
const MAX_SHORT: usize = 256;
/// Longest scope / external reference.
const MAX_REFERENCE: usize = 1024;
/// Longest UPN (user 256 + `@` + domain 253).
const MAX_UPN: usize = MAX_USER + 1 + MAX_DNS;

fn token_chars(field: &'static str, v: &str) -> Result<(), CredentialError> {
    // RFC 7230 token: visible ASCII minus separators.
    if v.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)) {
        Ok(())
    } else {
        Err(CredentialError::invalid(field, "must be an HTTP token (letters, digits, -_.)"))
    }
}

fn set(slot: &mut String, field: &'static str, max: usize) -> Result<(), CredentialError> {
    *slot = line(field, slot, max)?;
    Ok(())
}

fn set_opt(
    slot: &mut Option<String>,
    field: &'static str,
    max: usize,
) -> Result<(), CredentialError> {
    *slot = opt_line(field, slot.as_deref(), max)?;
    Ok(())
}

fn one_line_public(
    slot: &mut Option<String>,
    field: &'static str,
    max: usize,
) -> Result<(), CredentialError> {
    if let Some(v) = slot.as_ref() {
        multiline(field, v, max)?;
        let t = v.trim();
        if t.contains(['\n', '\r']) {
            return Err(CredentialError::invalid(field, "must be one OpenSSH line"));
        }
        *slot = Some(t.to_owned());
    }
    Ok(())
}

/// Trim and check every field of `f` in place.
pub(crate) fn normalise(f: &mut CredentialFields) -> Result<(), CredentialError> {
    match f {
        CredentialFields::UserPassword(f) => {
            set(&mut f.username, "username", MAX_USER)?;
            set_opt(&mut f.domain, "domain", MAX_DNS)?;
        }
        CredentialFields::DomainUser(f) => {
            let a = Account::validate(f.form, &f.user, &f.domain)?;
            f.user = a.user;
            f.domain = a.domain;
        }
        CredentialFields::SshKey(f) => {
            set(&mut f.username, "username", MAX_USER)?;
            one_line_public(&mut f.public_key, "public_key", MAX_PUBLIC_KEY)?;
            one_line_public(&mut f.certificate, "certificate", MAX_PEM)?;
            if f.fingerprint.as_deref().is_some_and(|fp| !is_sha256_fingerprint(fp)) {
                return Err(CredentialError::invalid("fingerprint", "malformed"));
            }
        }
        CredentialFields::SshAgent(f) => {
            set(&mut f.username, "username", MAX_USER)?;
            set_opt(&mut f.key_fingerprint, "key_fingerprint", 128)?;
            if f.key_fingerprint.as_deref().is_some_and(|fp| !is_sha256_fingerprint(fp)) {
                return Err(CredentialError::invalid(
                    "key_fingerprint",
                    "must be SHA256:<43 base64>",
                ));
            }
        }
        CredentialFields::X509(f) => {
            set_opt(&mut f.username, "username", MAX_USER)?;
            multiline("cert_pem", &f.cert_pem, MAX_PEM)?;
            if f.fingerprint.as_deref().is_some_and(|fp| !is_sha256_fingerprint(fp)) {
                return Err(CredentialError::invalid("fingerprint", "malformed"));
            }
        }
        CredentialFields::ApiToken(f) => {
            set_opt(&mut f.header_name, "header_name", MAX_HEADER)?;
            set_opt(&mut f.scheme, "scheme", MAX_HEADER)?;
            for (name, v) in [("header_name", &f.header_name), ("scheme", &f.scheme)] {
                if let Some(v) = v {
                    token_chars(name, v)?;
                }
            }
        }
        CredentialFields::OauthClient(f) => {
            set(&mut f.token_url, "token_url", MAX_URL)?;
            if !f.token_url.starts_with("https://") || f.token_url.contains(char::is_whitespace) {
                return Err(CredentialError::invalid("token_url", "must be an https:// URL"));
            }
            set(&mut f.client_id, "client_id", MAX_SHORT)?;
            set_opt(&mut f.scope, "scope", MAX_REFERENCE)?;
        }
        CredentialFields::Kubeconfig(f) => {
            set_opt(&mut f.context, "context", MAX_CONTEXT_NAME)?;
            if f.contexts.len() > super::kubeconfig::MAX_CONTEXTS
                || f.contexts.iter().any(|c| line("contexts", c, MAX_CONTEXT_NAME).is_err())
            {
                return Err(CredentialError::invalid("contexts", "malformed"));
            }
        }
        CredentialFields::KubeToken(f) => set_opt(&mut f.subject, "subject", MAX_SHORT)?,
        CredentialFields::VsphereUser(f) => {
            set(&mut f.upn, "upn", MAX_UPN)?;
            match parse_account(&f.upn) {
                Ok(a) if a.form == AccountForm::Upn => f.upn = a.render(),
                _ => return Err(CredentialError::invalid("upn", "must be user@domain")),
            }
        }
        CredentialFields::VncPassword(_) => {}
        CredentialFields::VncUserPassword(f) => set(&mut f.username, "username", MAX_USER)?,
        CredentialFields::Prompt(f) => {
            set_opt(&mut f.username, "username", MAX_USER)?;
            set_opt(&mut f.domain, "domain", MAX_DNS)?;
        }
        CredentialFields::ExternalRef(f) => {
            set(&mut f.reference, "reference", MAX_REFERENCE)?;
            if !f.target_kind.is_ref_target() {
                return Err(CredentialError::invalid(
                    "target_kind",
                    "cannot be resolved from a reference",
                ));
            }
        }
        CredentialFields::SudoBecome(f) => {
            if f.become_user.trim().is_empty() {
                "root".clone_into(&mut f.become_user);
            }
            set(&mut f.become_user, "become_user", MAX_SHORT)?;
        }
    }
    Ok(())
}

/// The selected context must be one of the derived names (when those are known).
pub(crate) fn validate_context(f: &KubeconfigFields) -> Result<(), CredentialError> {
    match &f.context {
        Some(c) if !f.contexts.is_empty() && !f.contexts.contains(c) => {
            Err(CredentialError::invalid("context", "is not in this kubeconfig"))
        }
        _ => Ok(()),
    }
}
