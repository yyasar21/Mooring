//! What a protocol crate receives at `connect` (ADR-0004, extended by ADR-0009 §6): resolved
//! secret material for the handshake only, an optional privilege-escalation step and, for the
//! `prompt` kind, what to ask the user. Every type holding a secret has a hand-written
//! redacting `Debug` and no `Serialize`.

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::credential::kubeconfig::KubeAuth;
use crate::credential::BecomeMethod;
use crate::session::Size;

/// Secret material handed to a session for the duration of the handshake only.
pub enum ConnectSecret {
    /// Password / passphrase.
    Password(SecretString),
    /// Windows account: `user` + `domain` (`NetBIOS`) or `user@domain` + `""` (UPN), password.
    DomainPassword {
        /// User (or full UPN).
        user: String,
        /// `NetBIOS` domain, empty for UPN.
        domain: String,
        /// Password.
        password: SecretString,
    },
    /// PEM-encoded private key and optional passphrase.
    PrivateKey {
        /// PEM text.
        pem: SecretString,
        /// Passphrase for the key, if any.
        passphrase: Option<SecretString>,
    },
    /// Login through the local ssh-agent; `fingerprint` pins one agent key (`SHA256:…`).
    Agent {
        /// Pinned key, `None` = try every agent key.
        fingerprint: Option<String>,
    },
    /// HTTP header token (`Authorization: Bearer …` by default).
    Token {
        /// Header name.
        header: String,
        /// Full header value (scheme + token).
        value: SecretString,
    },
    /// X.509 client certificate (public) + key.
    ClientCert {
        /// Certificate PEM.
        cert: String,
        /// Private key PEM.
        key: SecretString,
        /// Key passphrase.
        passphrase: Option<SecretString>,
    },
    /// Whole kubeconfig and the selected context.
    Kubeconfig {
        /// YAML.
        yaml: SecretString,
        /// Context, `None` = `current-context`.
        context: Option<String>,
    },
    /// A resolved Kubernetes user (ADR-0014 §3): bearer token or client certificate, from a
    /// `kubeconfig` context via [`crate::credential::kubeconfig::resolve`] or a `kube_token`.
    Kube(KubeAuth),
    /// Ask the user at connect time (`prompt` kind); see [`PromptAccount`].
    Prompt(PromptAccount),
    /// No secret (e.g. anonymous VNC, or agent / keyboard-interactive only).
    None,
}

impl ConnectSecret {
    /// Short variant name for logs (never the content).
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Password(_) => "password",
            Self::DomainPassword { .. } => "domain-password",
            Self::PrivateKey { .. } => "private-key",
            Self::Agent { .. } => "agent",
            Self::Token { .. } => "token",
            Self::ClientCert { .. } => "client-cert",
            Self::Kubeconfig { .. } => "kubeconfig",
            Self::Kube(_) => "kube",
            Self::Prompt(_) => "prompt",
            Self::None => "none",
        }
    }
}

impl std::fmt::Debug for ConnectSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ConnectSecret(<{}, redacted>)", self.kind())
    }
}

/// What the connect-time credential form asks (`SessionEvent::Prompt.account`, wire
/// `snake_case`). `username` / `domain` are pre-fills from the credential or the connection
/// overrides. Contains no secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PromptAccount {
    /// Pre-filled username.
    pub username: Option<String>,
    /// Pre-filled domain.
    pub domain: Option<String>,
    /// The form must ask for a username.
    pub needs_username: bool,
    /// The form must ask for a domain.
    pub needs_domain: bool,
}

/// Privilege escalation after login (`sudo_become` credential, ADR-0009 §3).
pub struct Become {
    /// `sudo` / `su` / `doas`.
    pub method: BecomeMethod,
    /// Target user.
    pub user: String,
    /// Password, sent only when the remote prompt is detected; never echoed.
    pub password: Option<SecretString>,
}

impl std::fmt::Debug for Become {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Become")
            .field("method", &self.method)
            .field("user", &self.user)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Everything a protocol crate needs to open a session.
#[derive(Debug)]
pub struct ConnectParams {
    /// Host or URL.
    pub host: String,
    /// Port.
    pub port: u16,
    /// User name, when the protocol has one.
    pub username: Option<String>,
    /// Secret material (dropped after the handshake).
    pub secret: ConnectSecret,
    /// Privilege escalation after login (SSH only).
    pub r#become: Option<Become>,
    /// Initial terminal / screen size.
    pub size: Size,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_variant_prints_its_secret() {
        let s = |v: &str| SecretString::from(v.to_owned());
        let all = [
            ConnectSecret::Password(s("hunter2")),
            ConnectSecret::DomainPassword {
                user: "u".into(),
                domain: "D".into(),
                password: s("hunter2"),
            },
            ConnectSecret::PrivateKey { pem: s("hunter2"), passphrase: Some(s("hunter2")) },
            ConnectSecret::Agent { fingerprint: None },
            ConnectSecret::Token { header: "Authorization".into(), value: s("hunter2") },
            ConnectSecret::ClientCert { cert: "c".into(), key: s("hunter2"), passphrase: None },
            ConnectSecret::Kubeconfig { yaml: s("hunter2"), context: None },
            ConnectSecret::Kube(KubeAuth::Token(s("hunter2"))),
            ConnectSecret::Kube(KubeAuth::ClientCert {
                cert_pem: "c".into(),
                key_pem: s("hunter2"),
            }),
            ConnectSecret::Prompt(PromptAccount::default()),
            ConnectSecret::None,
        ];
        for v in &all {
            let shown = format!("{v:?}");
            assert!(!shown.contains("hunter2") && shown.contains("redacted"), "{shown}");
        }
        let b = Become {
            method: BecomeMethod::Sudo,
            user: "root".into(),
            password: Some(s("hunter2")),
        };
        let p = ConnectParams {
            host: "h".into(),
            port: 22,
            username: None,
            secret: ConnectSecret::Password(s("hunter2")),
            r#become: Some(b),
            size: Size { width: 80, height: 24 },
        };
        let shown = format!("{p:?}");
        assert!(!shown.contains("hunter2") && shown.contains("Sudo"), "{shown}");
    }

    #[test]
    fn prompt_account_is_snake_case() {
        let a = PromptAccount {
            username: Some("alice".into()),
            domain: None,
            needs_username: false,
            needs_domain: true,
        };
        assert_eq!(
            serde_json::to_string(&a).expect("json"),
            r#"{"username":"alice","domain":null,"needs_username":false,"needs_domain":true}"#
        );
    }
}
