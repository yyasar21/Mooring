//! Field rules of the `ssh_sk_key` kind (ADR-0024 §1): `fingerprint` and `application` are
//! derived from `public_key`, the certificate must certify that key, and a stored key-handle
//! file must hold the same key (its flags then decide `resident`).

use super::account::MAX_USER;
use super::fingerprint::{is_sha256_fingerprint, MAX_PEM, MAX_PUBLIC_KEY};
use super::sk_key::{parse_sk_certificate_line, parse_sk_key_handle, parse_sk_public_line};
use super::structs::SshSkKeyFields;
use super::text::{line, multiline};
use super::CredentialError;

fn one_line(field: &'static str, v: &str, max: usize) -> Result<String, CredentialError> {
    multiline(field, v, max)?;
    let t = v.trim();
    if t.is_empty() || t.contains(['\n', '\r']) {
        return Err(CredentialError::invalid(field, "must be one OpenSSH line"));
    }
    Ok(t.to_owned())
}

/// Trim and cap (runs on input and on every stored read).
pub(crate) fn normalise(f: &mut SshSkKeyFields) -> Result<(), CredentialError> {
    f.username = line("username", &f.username, MAX_USER)?;
    f.public_key = one_line("public_key", &f.public_key, MAX_PUBLIC_KEY)?;
    if let Some(c) = &f.certificate {
        f.certificate = Some(one_line("certificate", c, MAX_PEM)?);
    }
    if f.fingerprint.as_deref().is_some_and(|fp| !is_sha256_fingerprint(fp)) {
        return Err(CredentialError::invalid("fingerprint", "malformed"));
    }
    if f.application.as_deref().is_some_and(|a| a.len() > super::sk_key::MAX_APPLICATION) {
        return Err(CredentialError::invalid("application", "malformed"));
    }
    Ok(())
}

/// Recompute `fingerprint` / `application` from the public line; check the certificate.
pub(crate) fn derive_public(f: &mut SshSkKeyFields) -> Result<(), CredentialError> {
    let key = parse_sk_public_line(&f.public_key)?;
    if let Some(cert) = &f.certificate {
        if parse_sk_certificate_line(cert)?.blob != key.blob {
            return Err(CredentialError::invalid(
                "certificate",
                "certifies a different key than public_key",
            ));
        }
    }
    f.fingerprint = Some(key.fingerprint);
    f.application = Some(key.application);
    Ok(())
}

/// A key-handle file being stored: same key as `public_key`; clear flags set `resident`.
pub(crate) fn derive_handle(f: &mut SshSkKeyFields, plain: &[u8]) -> Result<(), CredentialError> {
    let handle = parse_sk_key_handle(plain)?;
    if f.fingerprint.as_deref() != Some(handle.public.fingerprint.as_str()) {
        return Err(CredentialError::invalid("private_key", "is the handle of another key"));
    }
    if let Some(resident) = handle.resident() {
        f.resident = resident;
    }
    Ok(())
}

#[cfg(test)]
#[path = "sk_fields_tests.rs"]
mod tests;
