//! `resolve` (ADR-0014 §3): one context of an already-validated kubeconfig tree, turned into
//! what a client needs: server URL, trust anchor, one authentication shape, namespace.
//!
//! Nothing here reads a file or runs a command: every field is an allow-listed key of the
//! selected `context`, `cluster` and `user` mapping; any other key there is refused (so an
//! unknown or case-variant spelling can never be silently ignored). Inline data
//! (`*-data`) is base64, capped before and after decoding, and must be PEM of the right kind.
//! Errors are [`KubeResolveError`] with static reasons: never a value, never a token.

use data_encoding::BASE64;
use secrecy::SecretString;
use thiserror::Error;
use zeroize::Zeroizing;

use super::names::{is_dns_label, is_dns_subdomain, KubeServer};
use super::{validate, Node, MAX_CONTEXT_NAME};
use crate::credential::{is_forbidden, CredentialError};

/// Largest decoded `certificate-authority-data` / `client-certificate-data` /
/// `client-key-data` (bytes of PEM text).
pub const MAX_CA_PEM: usize = 64 * 1024;
/// Largest bearer token (bytes). Service-account JWTs are ~1-2 KiB.
pub const MAX_TOKEN: usize = 16 * 1024;
/// Largest base64 text before decoding (the decoded cap plus line breaks).
const MAX_B64: usize = MAX_CA_PEM / 3 * 4 + 8 * 1024;

const CONTEXT_KEYS: &[&str] = &["cluster", "user", "namespace", "extensions"];
const CLUSTER_KEYS: &[&str] = &[
    "server",
    "certificate-authority-data",
    "insecure-skip-tls-verify",
    "tls-server-name",
    "disable-compression",
    "extensions",
];
const USER_KEYS: &[&str] = &["token", "client-certificate-data", "client-key-data", "extensions"];
const BASIC_KEYS: &[&str] = &["username", "password"];
const IMPERSONATE_KEYS: &[&str] = &[
    "as",
    "as-uid",
    "as-groups",
    "as-user-extra",
    "impersonate",
    "impersonate-uid",
    "impersonate-groups",
    "impersonate-user-extra",
];
const KEY_LABELS: &[&str] = &["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"];

/// Why a context could not be resolved. `Display` is static text (ADR-0009 §5).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum KubeResolveError {
    /// The document failed [`super::parse`] (`credential.kubeconfig_rejected`).
    #[error("{0}")]
    Rejected(#[from] CredentialError),
    /// No context was named and `current-context` is unset or dangling.
    #[error("kubeconfig has no current-context; choose a context")]
    NoContext,
    /// The named context, or the cluster / user it points at, is missing.
    #[error("kubeconfig {0} not found")]
    NotFound(&'static str),
    /// Two entries share a name, so which one applies is ambiguous.
    #[error("kubeconfig has two {0} entries with the same name")]
    Duplicate(&'static str),
    /// A field is malformed, too large or not allowed (reason names the key only).
    #[error("kubeconfig {0}")]
    Invalid(&'static str),
    /// The user entry has no supported authentication (`kube.unsupported_auth`).
    #[error("unsupported Kubernetes authentication: {0}")]
    UnsupportedAuth(&'static str),
}

impl KubeResolveError {
    /// IPC error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedAuth(_) => "kube.unsupported_auth",
            _ => "credential.kubeconfig_rejected",
        }
    }
}

impl From<KubeResolveError> for crate::MooringError {
    fn from(e: KubeResolveError) -> Self {
        Self::Invalid { field: "kubeconfig", reason: e.to_string() }
    }
}

/// Trust anchor for the API server's certificate.
#[derive(Clone, PartialEq, Eq)]
pub enum CaSource {
    /// `certificate-authority-data`: certificate PEM blocks only (≤ [`MAX_CA_PEM`]). The chain
    /// **must** validate against it; no TOFU, no system roots (ADR-0014 §3).
    Pem(Vec<u8>),
    /// No CA data: system roots, then the ADR-0011 TOFU prompt (`known_kube_certs`).
    None,
}

impl std::fmt::Debug for CaSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pem(p) => write!(f, "CaSource::Pem({} bytes)", p.len()),
            Self::None => f.write_str("CaSource::None"),
        }
    }
}

/// The one authentication shape of a resolved user. Secrets are zeroized on drop.
#[derive(Clone)]
pub enum KubeAuth {
    /// Static bearer token (visible ASCII only, ≤ [`MAX_TOKEN`]).
    Token(SecretString),
    /// Client certificate (public PEM) and its unencrypted private key PEM.
    ClientCert {
        /// Certificate PEM (validated: first block is a DER certificate).
        cert_pem: String,
        /// Private key PEM (`PRIVATE KEY`, `RSA PRIVATE KEY` or `EC PRIVATE KEY`).
        key_pem: SecretString,
    },
}

impl KubeAuth {
    /// Short name for logs and audit (never the content).
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Token(_) => "token",
            Self::ClientCert { .. } => "client-cert",
        }
    }
}

impl std::fmt::Debug for KubeAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KubeAuth(<{}, redacted>)", self.kind())
    }
}

/// One resolved context.
#[derive(Debug, Clone)]
pub struct Resolved {
    /// The context that was resolved (the named one or `current-context`).
    pub context_name: String,
    /// API server.
    pub server: KubeServer,
    /// Trust anchor.
    pub ca: CaSource,
    /// `tls-server-name` (SNI / verification name), lower-case DNS name.
    pub tls_server_name: Option<String>,
    /// Authentication.
    pub auth: KubeAuth,
    /// Context namespace (RFC 1123 label).
    pub namespace: Option<String>,
    /// `insecure-skip-tls-verify: true`. Never a silent skip: the caller treats it as
    /// [`CaSource::None`] and goes through the TOFU prompt (ADR-0014 §3).
    pub insecure_skip: bool,
}

/// Resolve `context` (or `current-context` when `None`) of a kubeconfig. The document is
/// validated by [`super::parse`] first; only the validated tree is read.
pub fn resolve(yaml: &[u8], context: Option<&str>) -> Result<Resolved, KubeResolveError> {
    let (root, info) = validate(yaml)?;
    let context_name = match context {
        Some(c) => {
            if c.is_empty() || c.len() > MAX_CONTEXT_NAME || c.chars().any(is_forbidden) {
                return Err(KubeResolveError::Invalid("context name is not valid"));
            }
            c.to_owned()
        }
        None => info.current_context.ok_or(KubeResolveError::NoContext)?,
    };
    let ctx = body(&root, "contexts", "context", &context_name)?;
    only_keys(ctx, CONTEXT_KEYS, "context has an unsupported field")?;
    let cluster_name =
        scalar(ctx, "cluster")?.ok_or(KubeResolveError::Invalid("context has no cluster"))?;
    let user_name = scalar(ctx, "user")?.ok_or(KubeResolveError::Invalid("context has no user"))?;
    let namespace = match scalar(ctx, "namespace")? {
        None | Some("") => None,
        Some(ns) if is_dns_label(ns) => Some(ns.to_owned()),
        Some(_) => return Err(KubeResolveError::Invalid("context namespace is not a DNS label")),
    };
    let cluster = body(&root, "clusters", "cluster", cluster_name)?;
    let user = body(&root, "users", "user", user_name)?;
    let (server, ca, tls_server_name, insecure_skip) = read_cluster(cluster)?;
    let auth = read_user(user)?;
    Ok(Resolved { context_name, server, ca, tls_server_name, auth, namespace, insecure_skip })
}

fn read_cluster(
    c: &Node,
) -> Result<(KubeServer, CaSource, Option<String>, bool), KubeResolveError> {
    if c.get("proxy-url").is_some() {
        return Err(KubeResolveError::Invalid("cluster uses proxy-url, which is not supported"));
    }
    only_keys(c, CLUSTER_KEYS, "cluster has an unsupported field")?;
    let server = scalar(c, "server")?.ok_or(KubeResolveError::Invalid("cluster has no server"))?;
    let server = KubeServer::parse(server).map_err(KubeResolveError::Invalid)?;
    let insecure_skip = match scalar(c, "insecure-skip-tls-verify")? {
        None => false,
        Some(v) if v.eq_ignore_ascii_case("true") => true,
        Some(v) if v.eq_ignore_ascii_case("false") => false,
        Some(_) => {
            return Err(KubeResolveError::Invalid("insecure-skip-tls-verify must be a boolean"))
        }
    };
    let ca = match scalar(c, "certificate-authority-data")? {
        None | Some("") => CaSource::None,
        Some(_) if insecure_skip => {
            return Err(KubeResolveError::Invalid(
                "cluster sets both certificate-authority-data and insecure-skip-tls-verify",
            ))
        }
        Some(b64) => {
            let pem = decode_b64(b64, "certificate-authority-data")?;
            let text = std::str::from_utf8(&pem)
                .map_err(|_| KubeResolveError::Invalid("certificate-authority-data is not PEM"))?;
            crate::credential::fingerprint::x509_pem(text).map_err(|_| {
                KubeResolveError::Invalid("certificate-authority-data must be certificate PEM only")
            })?;
            CaSource::Pem(pem.to_vec())
        }
    };
    let tls_server_name = match scalar(c, "tls-server-name")? {
        None | Some("") => None,
        Some(n) => {
            let n = n.to_ascii_lowercase();
            if !is_dns_subdomain(&n) {
                return Err(KubeResolveError::Invalid("tls-server-name is not a DNS name"));
            }
            Some(n)
        }
    };
    Ok((server, ca, tls_server_name, insecure_skip))
}

fn read_user(u: &Node) -> Result<KubeAuth, KubeResolveError> {
    if BASIC_KEYS.iter().any(|k| u.get(k).is_some()) {
        return Err(KubeResolveError::UnsupportedAuth("basic auth (username/password)"));
    }
    if IMPERSONATE_KEYS.iter().any(|k| u.get(k).is_some()) {
        return Err(KubeResolveError::UnsupportedAuth("impersonation"));
    }
    if let Node::Map(entries) = u {
        if entries.iter().any(|(k, _)| !USER_KEYS.contains(&k.as_str())) {
            return Err(KubeResolveError::UnsupportedAuth("unknown user field"));
        }
    }
    let token = scalar(u, "token")?.filter(|t| !t.is_empty());
    let cert = scalar(u, "client-certificate-data")?.filter(|t| !t.is_empty());
    let key = scalar(u, "client-key-data")?.filter(|t| !t.is_empty());
    match (token, cert, key) {
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
            Err(KubeResolveError::UnsupportedAuth("both a token and a client certificate"))
        }
        (Some(t), None, None) => {
            if t.len() > MAX_TOKEN || !t.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(KubeResolveError::Invalid("token is too long or not visible ASCII"));
            }
            Ok(KubeAuth::Token(SecretString::from(t.to_owned())))
        }
        (None, Some(c), Some(k)) => client_cert(c, k),
        (None, Some(_), None) | (None, None, Some(_)) => Err(KubeResolveError::Invalid(
            "client-certificate-data and client-key-data must be set together",
        )),
        (None, None, None) => {
            Err(KubeResolveError::UnsupportedAuth("no token or client certificate"))
        }
    }
}

fn client_cert(cert_b64: &str, key_b64: &str) -> Result<KubeAuth, KubeResolveError> {
    let cert = decode_b64(cert_b64, "client-certificate-data")?;
    let cert_pem = std::str::from_utf8(&cert)
        .map_err(|_| KubeResolveError::Invalid("client-certificate-data is not PEM"))?;
    crate::credential::fingerprint::x509_pem(cert_pem).map_err(|_| {
        KubeResolveError::Invalid("client-certificate-data must be certificate PEM only")
    })?;
    let key = decode_b64(key_b64, "client-key-data")?;
    let key_pem = std::str::from_utf8(&key)
        .map_err(|_| KubeResolveError::Invalid("client-key-data is not PEM"))?
        .trim();
    if key_pem.matches("-----BEGIN ").count() != 1 {
        return Err(KubeResolveError::Invalid("client-key-data must hold exactly one PEM key"));
    }
    let mut der = Zeroizing::new(vec![0u8; key_pem.len()]);
    let label = pem_rfc7468::decode(key_pem.as_bytes(), &mut der)
        .map(|(label, _)| label)
        .map_err(|_| KubeResolveError::Invalid("client-key-data is not an unencrypted PEM key"))?;
    if !KEY_LABELS.contains(&label) {
        return Err(KubeResolveError::Invalid("client-key-data is not an unencrypted PEM key"));
    }
    let key_pem = SecretString::from(key_pem.to_owned());
    Ok(KubeAuth::ClientCert { cert_pem: cert_pem.to_owned(), key_pem })
}

/// Base64 (standard alphabet, padded; ASCII whitespace ignored), capped before decoding and
/// decoded into a zeroizing buffer (it may be a private key).
fn decode_b64(b64: &str, what: &'static str) -> Result<Zeroizing<Vec<u8>>, KubeResolveError> {
    let too_large = KubeResolveError::Invalid(match what {
        "certificate-authority-data" => "certificate-authority-data is larger than 64 KiB",
        "client-certificate-data" => "client-certificate-data is larger than 64 KiB",
        _ => "client-key-data is larger than 64 KiB",
    });
    if b64.len() > MAX_B64 {
        return Err(too_large);
    }
    let compact: Zeroizing<Vec<u8>> =
        Zeroizing::new(b64.bytes().filter(|b| !b.is_ascii_whitespace()).collect());
    let len = BASE64.decode_len(compact.len()).map_err(|_| bad_b64(what))?;
    if len > MAX_CA_PEM + 2 {
        return Err(too_large);
    }
    let mut out = Zeroizing::new(vec![0u8; len]);
    let n = BASE64.decode_mut(&compact, &mut out).map_err(|_| bad_b64(what))?;
    out.truncate(n);
    if n > MAX_CA_PEM {
        return Err(too_large);
    }
    Ok(out)
}

fn bad_b64(what: &'static str) -> KubeResolveError {
    KubeResolveError::Invalid(match what {
        "certificate-authority-data" => "certificate-authority-data is not valid base64",
        "client-certificate-data" => "client-certificate-data is not valid base64",
        _ => "client-key-data is not valid base64",
    })
}

/// The body mapping (`context` / `cluster` / `user`) of the one `section[]` entry named `name`.
fn body<'a>(
    root: &'a Node,
    section: &'static str,
    inner: &'static str,
    name: &str,
) -> Result<&'a Node, KubeResolveError> {
    let mut found = None;
    for item in root.get(section).map(Node::items).unwrap_or_default() {
        if item.get("name").and_then(Node::str) == Some(name) {
            if found.is_some() {
                return Err(KubeResolveError::Duplicate(inner));
            }
            found = Some(item);
        }
    }
    let item = found.ok_or(KubeResolveError::NotFound(inner))?;
    match item.get(inner) {
        Some(b @ Node::Map(_)) => Ok(b),
        _ => Err(KubeResolveError::Invalid(match inner {
            "context" => "context entry has no context mapping",
            "cluster" => "cluster entry has no cluster mapping",
            _ => "user entry has no user mapping",
        })),
    }
}

fn only_keys(n: &Node, allowed: &[&str], why: &'static str) -> Result<(), KubeResolveError> {
    match n {
        Node::Map(e) if e.iter().all(|(k, _)| allowed.contains(&k.as_str())) => Ok(()),
        _ => Err(KubeResolveError::Invalid(why)),
    }
}

/// An optional scalar field; a mapping or list where a scalar belongs is refused.
fn scalar<'a>(n: &'a Node, key: &'static str) -> Result<Option<&'a str>, KubeResolveError> {
    match n.get(key) {
        None => Ok(None),
        Some(Node::Scalar(s)) => Ok(Some(s.as_str())),
        Some(_) => Err(KubeResolveError::Invalid("a field that must be text is not")),
    }
}
