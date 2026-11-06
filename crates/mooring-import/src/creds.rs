//! Credential shapes the importers emit (ADR-0009 kinds):
//!
//! * a username without a usable secret → `prompt` (ask at connect, username pre-filled);
//! * a username with a plaintext password and the opt-in → `user_password`;
//! * an OpenSSH `IdentityFile` → `ssh_agent` by default (the key stays with the agent), or a
//!   plaintext private key with the opt-in → `ssh_key`.
//!
//! Encrypted or obfuscated values are never decrypted; mRemoteNG passwords are never
//! imported (owner decision 17).

use mooring_core::{CredentialKind, SecretName};
use serde_json::json;
use zeroize::Zeroizing;

use crate::plan::{NewCredential, SecretBundle};

/// Display name of a credential: `DOMAIN\user` or `user`.
#[must_use]
pub fn account_name(user: &str, domain: Option<&str>) -> String {
    match domain.map(str::trim).filter(|d| !d.is_empty()) {
        Some(d) => format!("{d}\\{user}"),
        None => user.to_owned(),
    }
}

/// `prompt` with the username (and domain) pre-filled.
#[must_use]
pub fn prompt(user: &str, domain: Option<&str>) -> NewCredential {
    let mut fields = json!({ "username": user });
    if let Some(d) = domain.filter(|d| !d.trim().is_empty()) {
        fields["domain"] = json!(d);
    }
    NewCredential {
        name: account_name(user, domain),
        kind: CredentialKind::Prompt,
        fields,
        secrets: None,
        key_file: None,
    }
}

/// `user_password` with a plaintext password (caller has checked the opt-in).
#[must_use]
pub fn user_password(user: &str, domain: Option<&str>, password: &[u8]) -> NewCredential {
    let mut fields = json!({ "username": user });
    if let Some(d) = domain.filter(|d| !d.trim().is_empty()) {
        fields["domain"] = json!(d);
    }
    let mut secrets = SecretBundle::default();
    secrets.push(SecretName::Password, Zeroizing::new(password.to_vec()));
    NewCredential {
        name: account_name(user, domain),
        kind: CredentialKind::UserPassword,
        fields,
        secrets: Some(secrets),
        key_file: None,
    }
}

/// `ssh_agent` for `user`, remembering the key file the source named.
#[must_use]
pub fn ssh_agent(user: &str, key_file: Option<&str>) -> NewCredential {
    let name = match key_file.and_then(|k| k.rsplit(['/', '\\']).next()).filter(|b| !b.is_empty()) {
        Some(base) => format!("{user} ({base})"),
        None => user.to_owned(),
    };
    NewCredential {
        name,
        kind: CredentialKind::SshAgent,
        fields: json!({ "username": user }),
        secrets: None,
        key_file: key_file.map(str::to_owned),
    }
}

/// `ssh_key` with a plaintext private key (caller has checked the opt-in).
#[must_use]
pub fn ssh_key(user: &str, label: &str, private_key: &[u8]) -> NewCredential {
    let mut secrets = SecretBundle::default();
    secrets.push(SecretName::PrivateKey, Zeroizing::new(private_key.to_vec()));
    NewCredential {
        name: format!("{user} ({label})"),
        kind: CredentialKind::SshKey,
        fields: json!({ "username": user }),
        secrets: Some(secrets),
        key_file: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_kinds() {
        assert_eq!(account_name("alice", Some("CORP")), "CORP\\alice");
        assert_eq!(account_name("alice", Some(" ")), "alice");
        let p = prompt("alice", Some("CORP"));
        assert_eq!(p.kind, CredentialKind::Prompt);
        assert_eq!(p.fields["domain"], "CORP");
        assert!(p.secrets.is_none());
        let u = user_password("bob", None, b"pw");
        assert!(u.secrets.as_ref().is_some_and(|s| !s.is_empty()));
        assert_eq!(format!("{:?}", u.secrets), "Some(SecretBundle { names: [\"password\"] })");
        let a = ssh_agent("carol", Some("~/.ssh/id_ed25519"));
        assert_eq!(a.name, "carol (id_ed25519)");
        assert_eq!(a.key_file.as_deref(), Some("~/.ssh/id_ed25519"));
        assert_eq!(ssh_agent("carol", None).name, "carol");
        assert_eq!(ssh_key("d", "k", b"x").kind, CredentialKind::SshKey);
    }
}
