//! Credential mapping for NLA (ADR-0011 §Security protocol and credentials, ADR-0009 matrix).
//!
//! - `user_password` → `ConnectSecret::Password`: the username is sent verbatim, no domain.
//! - `domain_user` → `ConnectSecret::DomainPassword`: netbios `(user, DOMAIN)`, UPN `(upn, "")`.
//! - `prompt` → a `credential` form with `needs_domain: true`.
//!
//! `x509`, keys, tokens and kubeconfigs are refused for RDP. The password stays a
//! `SecretString` until the connector needs it (R-RDP-STR: `IronRDP` keeps a plain `String`).

use mooring_core::session::{ConnectSecret, PromptAccount};
use mooring_core::MooringError;
use secrecy::SecretString;

use crate::shared::Reply;

/// Resolved sign-in data. `Debug` hides the password.
pub(crate) struct Creds {
    pub(crate) username: String,
    pub(crate) domain: Option<String>,
    pub(crate) password: SecretString,
}

impl std::fmt::Debug for Creds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Creds")
            .field("username", &self.username)
            .field("domain", &self.domain)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Credentials now, or a form to show first.
#[derive(Debug)]
pub(crate) enum CredSource {
    Ready(Creds),
    Prompt(PromptAccount),
}

fn invalid(reason: &str) -> MooringError {
    MooringError::Invalid { field: "credential", reason: reason.to_owned() }
}

fn clean(s: &str) -> Option<String> {
    let s = s.trim();
    (!s.is_empty() && !s.chars().any(char::is_control)).then(|| s.to_owned())
}

/// Map what the vault resolved.
pub(crate) fn from_params(
    username: Option<&str>,
    secret: ConnectSecret,
) -> Result<CredSource, MooringError> {
    let username = username.and_then(clean);
    match secret {
        ConnectSecret::Password(password) => {
            let username = username.ok_or_else(|| invalid("rdp needs a username"))?;
            Ok(CredSource::Ready(Creds { username, domain: None, password }))
        }
        ConnectSecret::DomainPassword { user, domain, password } => {
            let username = clean(&user).ok_or_else(|| invalid("rdp needs a username"))?;
            Ok(CredSource::Ready(Creds { username, domain: clean(&domain), password }))
        }
        ConnectSecret::Prompt(mut account) => {
            account.needs_domain = true;
            if account.username.is_none() {
                account.username = username;
            }
            Ok(CredSource::Prompt(account))
        }
        other => Err(invalid(&format!(
            "a {} credential cannot be used for rdp (use user_password, domain_user or prompt)",
            other.kind()
        ))),
    }
}

/// Map the sign-in form. `None` means the user cancelled (empty username and password).
/// `DOMAIN\user` in the username field is split when the domain field is empty; a UPN stays
/// whole with no domain.
pub(crate) fn from_reply(reply: Reply) -> Option<Creds> {
    use secrecy::ExposeSecret;
    let Reply::Credential { username, domain, password } = reply else {
        return None;
    };
    if username.trim().is_empty() && password.expose_secret().is_empty() {
        return None;
    }
    let domain = domain.as_deref().and_then(clean);
    let (username, domain) = match (domain, username.trim().split_once('\\')) {
        (None, Some((d, u))) => (clean(u)?, clean(d)),
        (domain, _) => (clean(&username)?, domain),
    };
    Some(Creds { username, domain, password })
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    fn pw(s: &str) -> SecretString {
        s.to_owned().into()
    }

    fn ready(src: CredSource) -> Creds {
        match src {
            CredSource::Ready(c) => c,
            CredSource::Prompt(_) => panic!("expected ready"),
        }
    }

    #[test]
    fn user_password_is_verbatim() {
        let c =
            ready(from_params(Some("ACME\\alice"), ConnectSecret::Password(pw("p"))).expect("ok"));
        assert_eq!((c.username.as_str(), c.domain), ("ACME\\alice", None));
        assert!(from_params(None, ConnectSecret::Password(pw("p"))).is_err());
    }

    #[test]
    fn domain_user_netbios_and_upn() {
        let nb = ConnectSecret::DomainPassword {
            user: "alice".into(),
            domain: "ACME".into(),
            password: pw("p"),
        };
        let c = ready(from_params(None, nb).expect("ok"));
        assert_eq!((c.username.as_str(), c.domain.as_deref()), ("alice", Some("ACME")));
        let upn = ConnectSecret::DomainPassword {
            user: "alice@example.test".into(),
            domain: String::new(),
            password: pw("p"),
        };
        let c = ready(from_params(None, upn).expect("ok"));
        assert_eq!((c.username.as_str(), c.domain.as_deref()), ("alice@example.test", None));
        assert_eq!(c.password.expose_secret(), "p");
        assert!(!format!("{c:?}").contains("\"p\""));
    }

    #[test]
    fn prompt_asks_for_domain_and_other_kinds_are_refused() {
        match from_params(Some("bob"), ConnectSecret::Prompt(PromptAccount::default())).expect("ok")
        {
            CredSource::Prompt(a) => {
                assert!(a.needs_domain);
                assert_eq!(a.username.as_deref(), Some("bob"));
            }
            CredSource::Ready(_) => panic!("expected prompt"),
        }
        let x509 = ConnectSecret::ClientCert { cert: "c".into(), key: pw("k"), passphrase: None };
        let err = from_params(Some("u"), x509).expect_err("refused").to_string();
        assert!(err.contains("client-cert"), "{err}");
        assert!(from_params(Some("u"), ConnectSecret::None).is_err());
    }

    #[test]
    fn form_answers() {
        let r = |u: &str, d: Option<&str>, p: &str| Reply::Credential {
            username: u.into(),
            domain: d.map(Into::into),
            password: pw(p),
        };
        assert!(from_reply(r("", None, "")).is_none(), "cancel");
        let c = from_reply(r("ACME\\alice", None, "p")).expect("split");
        assert_eq!((c.username.as_str(), c.domain.as_deref()), ("alice", Some("ACME")));
        let c = from_reply(r("alice", Some("CORP"), "p")).expect("domain field");
        assert_eq!(c.domain.as_deref(), Some("CORP"));
        let c = from_reply(r("alice@example.test", Some(" "), "p")).expect("upn");
        assert_eq!((c.username.as_str(), c.domain), ("alice@example.test", None));
        assert!(from_reply(Reply::Text(pw("yes"))).is_none());
    }
}
