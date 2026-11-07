//! The kind table served by `credential_kinds()` (ADR-0009 §1, §2, §6). It is also the
//! protocol matrix: `protocols` lists, per kind, where it may sign in and in which secondary
//! roles. Labels are English. The UI renders every credential form from this table; its copy
//! in `apps/desktop/src/lib/ipc.kinds.ts` is checked against it by a snapshot test.

use serde::{Serialize, Serializer};

use super::{CredentialKind as K, Role, SecretName};
use crate::model::Protocol;

/// Field validation format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldFormat {
    /// Single-line text.
    Text,
    /// PEM block(s).
    Pem,
    /// Base32 (TOTP seed).
    Base32,
    /// YAML document.
    Yaml,
    /// `https://` URL.
    Url,
    /// `DOMAIN\user` or `user@domain`.
    NetbiosOrUpn,
    /// `user@domain`.
    Upn,
    /// One of `options` (or of a derived list when `options` is absent).
    Enum,
}

/// `validation` of a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Validation {
    /// Byte cap.
    pub max_bytes: usize,
    /// Format.
    pub format: FieldFormat,
    /// Allowed values for `enum`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<&'static [&'static str]>,
    /// Regex the UI checks (Rust validates the same rule in code).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<&'static str>,
}

/// One form field (plain or secret).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)] // mirrors the wire shape of ADR-0009 §6
pub struct FieldSchema {
    /// Wire name.
    pub name: &'static str,
    /// English label.
    pub label: &'static str,
    /// Sealed secret (write-only) or plain field.
    pub secret: bool,
    /// Required on create.
    pub required: bool,
    /// Multi-line input.
    pub multiline: bool,
    /// Placeholder text.
    pub placeholder: &'static str,
    /// Secret may be copied with `credential_copy_secret`.
    pub copyable: bool,
    /// Validation rules.
    pub validation: Validation,
}

/// Where a kind may be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct KindProtocol {
    /// Protocol (wire name `ssh`, `vsphere-console`, ...).
    #[serde(serialize_with = "protocol_name")]
    pub protocol: Protocol,
    /// Roles on that protocol.
    pub roles: &'static [Role],
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's serialize_with signature
fn protocol_name<S: Serializer>(p: &Protocol, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(p.name())
}

/// A non-connection consumer of a credential (ADR-0016 §1, ADR-0017 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Consumer {
    /// Login of a Vault / `OpenBao` secret source (`api_token`, `vault_approle`).
    SecretSource,
    /// The vault sync target (`s3_access_key`).
    Sync,
}

/// One row of `credential_kinds()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KindSchema {
    /// Kind.
    pub kind: K,
    /// English label.
    pub label: &'static str,
    /// Picker group.
    pub group: &'static str,
    /// Protocol matrix row.
    pub protocols: &'static [KindProtocol],
    /// Non-connection consumers (omitted on the wire when empty).
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    pub consumers: &'static [Consumer],
    /// Accepts the `otp_seed` secret + `otp` field.
    pub supports_otp: bool,
    /// Plain fields and secrets in display order.
    pub fields: &'static [FieldSchema],
}

impl KindSchema {
    /// Schema of a secret this kind accepts (`otp_seed` when `supports_otp`).
    #[must_use]
    pub fn secret(&self, name: SecretName) -> Option<&'static FieldSchema> {
        if name == SecretName::OtpSeed {
            return self.supports_otp.then_some(&OTP_SEED);
        }
        self.fields.iter().find(|f| f.secret && f.name == name.as_str())
    }

    /// Every secret name this kind accepts.
    pub fn secret_names(&self) -> impl Iterator<Item = SecretName> + '_ {
        SecretName::ALL.into_iter().filter(|n| self.secret(*n).is_some())
    }
}

const KIB: usize = 1024;
const P: Role = Role::Primary;

const fn v(max_bytes: usize, format: FieldFormat) -> Validation {
    Validation { max_bytes, format, options: None, pattern: None }
}

const fn plain(
    name: &'static str,
    label: &'static str,
    required: bool,
    validation: Validation,
) -> FieldSchema {
    FieldSchema {
        name,
        label,
        secret: false,
        required,
        multiline: false,
        placeholder: "",
        copyable: false,
        validation,
    }
}

const fn ph(mut f: FieldSchema, placeholder: &'static str) -> FieldSchema {
    f.placeholder = placeholder;
    f
}

const fn ml(mut f: FieldSchema) -> FieldSchema {
    f.multiline = true;
    f
}

const fn sec(mut f: FieldSchema, copyable: bool) -> FieldSchema {
    f.secret = true;
    f.copyable = copyable;
    f
}

const fn opts(mut f: FieldSchema, options: &'static [&'static str]) -> FieldSchema {
    f.validation.options = Some(options);
    f
}

const fn proto(protocol: Protocol, roles: &'static [Role]) -> KindProtocol {
    KindProtocol { protocol, roles }
}

use FieldFormat::{Enum, NetbiosOrUpn, Pem, Text, Upn, Url, Yaml};

const USERNAME: FieldSchema = ph(plain("username", "Username", true, v(256, Text)), "alice");
const USERNAME_OPT: FieldSchema = ph(plain("username", "Username", false, v(256, Text)), "alice");
const DOMAIN_OPT: FieldSchema = ph(plain("domain", "Domain", false, v(253, Text)), "optional");
const PASSWORD: FieldSchema = sec(plain("password", "Password", true, v(4 * KIB, Text)), true);

/// The TOTP seed slot (not listed in `fields`; implied by `supportsOtp`).
pub const OTP_SEED: FieldSchema =
    sec(plain("otp_seed", "TOTP seed", false, v(128, FieldFormat::Base32)), false);

/// Kinds an `external_ref` may resolve to (same list as the UI's `TARGET_KINDS`).
pub const TARGET_KINDS: &[&str] = &[
    "user_password",
    "domain_user",
    "ssh_key",
    "x509",
    "api_token",
    "oauth_client",
    "kubeconfig",
    "kube_token",
    "vsphere_user",
    "vnc_password",
    "vnc_user_password",
    "sudo_become",
];

const LOGIN_PROTOCOLS: &[KindProtocol] = &[
    proto(Protocol::Ssh, &[P]),
    proto(Protocol::Rdp, &[P, Role::Gateway]),
    proto(Protocol::Web, &[P]),
    proto(Protocol::VsphereConsole, &[P]),
];
const SSH_ONLY: &[KindProtocol] = &[proto(Protocol::Ssh, &[P])];
const WEB_ONLY: &[KindProtocol] = &[proto(Protocol::Web, &[P])];
const KUBE_ONLY: &[KindProtocol] = &[proto(Protocol::Kubernetes, &[P])];
const VNC_ONLY: &[KindProtocol] = &[proto(Protocol::Vnc, &[P])];

static KINDS: [KindSchema; 18] = [
    KindSchema {
        kind: K::UserPassword,
        label: "Username and password",
        group: "Windows",
        protocols: LOGIN_PROTOCOLS,
        consumers: &[],
        supports_otp: true,
        fields: &[USERNAME, DOMAIN_OPT, PASSWORD],
    },
    KindSchema {
        kind: K::DomainUser,
        label: "Domain account",
        group: "Windows",
        protocols: LOGIN_PROTOCOLS,
        consumers: &[],
        supports_otp: true,
        fields: &[
            ph(
                plain("user", "Account", true, v(256, NetbiosOrUpn)),
                "CORP\\alice or alice@corp.example",
            ),
            plain("domain", "Domain", true, v(253, Text)),
            opts(plain("form", "Form", true, v(8, Enum)), &["netbios", "upn"]),
            PASSWORD,
        ],
    },
    KindSchema {
        kind: K::SshKey,
        label: "SSH key",
        group: "SSH",
        protocols: SSH_ONLY,
        consumers: &[],
        supports_otp: true,
        fields: &[
            USERNAME,
            ml(ph(
                sec(plain("private_key", "Private key", true, v(64 * KIB, Pem)), false),
                "-----BEGIN OPENSSH PRIVATE KEY-----",
            )),
            ph(
                sec(plain("passphrase", "Key passphrase", false, v(4 * KIB, Text)), true),
                "optional",
            ),
            ml(ph(
                plain("public_key", "Public key", false, v(16 * KIB, Text)),
                "ssh-ed25519 AAAA… (optional)",
            )),
            ml(ph(
                plain("certificate", "OpenSSH certificate", false, v(64 * KIB, Text)),
                "ssh-ed25519-cert-v01@openssh.com AAAA… (optional, from *-cert.pub)",
            )),
        ],
    },
    KindSchema {
        kind: K::SshAgent,
        label: "SSH agent",
        group: "SSH",
        protocols: SSH_ONLY,
        consumers: &[],
        supports_otp: false,
        fields: &[USERNAME, {
            let mut f = ph(
                plain("key_fingerprint", "Pin agent key", false, v(128, Text)),
                "SHA256:… (optional)",
            );
            f.validation.pattern = Some("^SHA256:[A-Za-z0-9+/]{43}=?$");
            f
        }],
    },
    KindSchema {
        kind: K::SudoBecome,
        label: "Become (sudo, su, doas)",
        group: "SSH",
        protocols: &[proto(Protocol::Ssh, &[Role::Become])],
        consumers: &[],
        supports_otp: false,
        fields: &[
            opts(plain("method", "Method", true, v(8, Enum)), &["sudo", "su", "doas"]),
            ph(plain("become_user", "Become user", false, v(256, Text)), "root"),
            ph(
                sec(plain("password", "Become password", false, v(4 * KIB, Text)), true),
                "optional",
            ),
        ],
    },
    KindSchema {
        kind: K::X509,
        label: "X.509 client certificate",
        group: "Web/API",
        protocols: &[proto(Protocol::Web, &[P]), proto(Protocol::Kubernetes, &[P])],
        consumers: &[],
        supports_otp: false,
        fields: &[
            USERNAME_OPT,
            ml(ph(
                plain("cert_pem", "Certificate", true, v(64 * KIB, Pem)),
                "-----BEGIN CERTIFICATE-----",
            )),
            ml(ph(
                sec(plain("key_pem", "Private key", true, v(64 * KIB, Pem)), false),
                "-----BEGIN PRIVATE KEY-----",
            )),
            ph(
                sec(plain("key_passphrase", "Key passphrase", false, v(4 * KIB, Text)), false),
                "optional",
            ),
        ],
    },
    KindSchema {
        kind: K::ApiToken,
        label: "API token",
        group: "Web/API",
        protocols: WEB_ONLY,
        consumers: &[Consumer::SecretSource],
        supports_otp: false,
        fields: &[
            ph(plain("header_name", "Header", false, v(64, Text)), "Authorization"),
            ph(plain("scheme", "Scheme", false, v(64, Text)), "Bearer"),
            sec(plain("token", "Token", true, v(16 * KIB, Text)), true),
        ],
    },
    KindSchema {
        kind: K::OauthClient,
        label: "OAuth client credentials",
        group: "Web/API",
        protocols: WEB_ONLY,
        consumers: &[],
        supports_otp: false,
        fields: &[
            ph(
                plain("token_url", "Token URL", true, v(2048, Url)),
                "https://login.example.test/oauth2/token",
            ),
            plain("client_id", "Client ID", true, v(256, Text)),
            ph(plain("scope", "Scope", false, v(1024, Text)), "optional"),
            sec(plain("client_secret", "Client secret", true, v(16 * KIB, Text)), true),
            ph(
                sec(plain("refresh_token", "Refresh token", false, v(16 * KIB, Text)), false),
                "optional",
            ),
        ],
    },
    KindSchema {
        kind: K::Kubeconfig,
        label: "kubeconfig",
        group: "Kubernetes",
        protocols: KUBE_ONLY,
        consumers: &[],
        supports_otp: false,
        fields: &[
            ml(ph(
                sec(plain("kubeconfig_yaml", "kubeconfig", true, v(1024 * KIB, Yaml)), false),
                "apiVersion: v1\nkind: Config\n…",
            )),
            ph(plain("context", "Context", false, v(253, Enum)), "current-context"),
        ],
    },
    KindSchema {
        kind: K::KubeToken,
        label: "Kubernetes token",
        group: "Kubernetes",
        protocols: KUBE_ONLY,
        consumers: &[],
        supports_otp: false,
        fields: &[
            ph(
                plain("subject", "Subject", false, v(256, Text)),
                "system:serviceaccount:ns:name (display only)",
            ),
            sec(plain("token", "Bearer token", true, v(16 * KIB, Text)), true),
        ],
    },
    KindSchema {
        kind: K::VsphereUser,
        label: "vSphere SSO account",
        group: "vSphere",
        protocols: &[proto(Protocol::Web, &[P]), proto(Protocol::VsphereConsole, &[P])],
        consumers: &[],
        supports_otp: true,
        fields: &[
            ph(plain("upn", "Account", true, v(510, Upn)), "administrator@vsphere.local"),
            PASSWORD,
        ],
    },
    KindSchema {
        kind: K::VncPassword,
        label: "VNC password",
        group: "VNC",
        protocols: VNC_ONLY,
        consumers: &[],
        supports_otp: false,
        // RFB DES uses 8 bytes; longer input is rejected, never truncated (ADR-0009 §5).
        fields: &[ph(
            sec(plain("password", "Password", true, v(8, Text)), true),
            "at most 8 bytes",
        )],
    },
    KindSchema {
        kind: K::VncUserPassword,
        label: "VNC username and password",
        group: "VNC",
        protocols: VNC_ONLY,
        consumers: &[],
        supports_otp: false,
        fields: &[USERNAME, PASSWORD],
    },
    KindSchema {
        kind: K::Prompt,
        label: "Ask at connect",
        group: "Other",
        protocols: &[
            proto(Protocol::Ssh, &[P]),
            proto(Protocol::Rdp, &[P, Role::Gateway]),
            proto(Protocol::Vnc, &[P]),
            proto(Protocol::Web, &[P]),
            proto(Protocol::VsphereConsole, &[P]),
        ],
        consumers: &[],
        supports_otp: false,
        fields: &[USERNAME_OPT, DOMAIN_OPT],
    },
    KindSchema {
        kind: K::ExternalRef,
        label: "Secret manager reference",
        group: "Other",
        protocols: &[],
        consumers: &[],
        supports_otp: false,
        fields: &[
            opts(
                plain("provider", "Provider", true, v(16, Enum)),
                &["vault", "onepassword", "bitwarden"],
            ),
            plain("reference", "Reference", true, v(1024, Text)),
            opts(plain("target_kind", "Resolves to", true, v(32, Enum)), TARGET_KINDS),
            ph(plain("source", "Secret source", false, v(36, Enum)), "required for Vault"),
            ph(plain("version", "KV version", false, v(20, Text)), "latest"),
            opts(
                plain("engine", "Vault engine", false, v(16, Enum)),
                &["kv2", "database", "ssh_sign", "ssh_otp", "pki"],
            ),
            ph(plain("ttl", "TTL (seconds)", false, v(8, Text)), "role default"),
            ph(plain("common_name", "Common name", false, v(255, Text)), "required for PKI"),
            ph(
                plain("username", "One-time password login", false, v(64, Text)),
                "required for SSH OTP",
            ),
        ],
    },
    source::VAULT_APPROLE,
    source::S3_ACCESS_KEY,
    source::BITWARDEN_ACCESS_TOKEN,
];

#[path = "schema_source.rs"]
mod source;

/// The whole table, in display order.
#[must_use]
pub fn credential_kinds() -> &'static [KindSchema] {
    &KINDS
}

pub(crate) fn schema_of(kind: K) -> &'static KindSchema {
    // Every kind has exactly one row (checked by `every_kind_has_one_row`); the fallback is
    // unreachable and keeps library code free of panics.
    KINDS.iter().find(|s| s.kind == kind).unwrap_or(&KINDS[0])
}

#[cfg(test)]
#[path = "schema_tests.rs"]
mod tests;
