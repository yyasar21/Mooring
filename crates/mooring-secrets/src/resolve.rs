//! KV secret → target credential (ADR-0016 §2). Each name of the target kind (plain fields,
//! secrets, `otp_seed` where the kind has the TOTP slot) is read from the KV key of the same
//! name or its `field_map` rename. Required names must be present; KV keys the kind does not
//! use are refused (no silent truncation of a secret into the wrong slot). The values then run
//! through the target kind's **own** validators and caps, exactly as UI input would.

use std::collections::BTreeMap;
use std::fmt;

use mooring_core::credential::external::{kv_key, target_names};
use mooring_core::credential::{validate_secret, CredentialError, OtpParams};
use mooring_core::{CredentialFields, CredentialKind, SecretName};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::error::SecretsError;
use crate::wire::SecretMap;

/// A resolved credential, held only for one connect. `Debug` shows names only.
pub struct ResolvedSecrets {
    /// The target kind.
    pub kind: CredentialKind,
    /// Validated plain fields (from KV).
    pub fields: CredentialFields,
    /// Validated secrets, zeroized on drop.
    pub secrets: BTreeMap<SecretName, Zeroizing<Vec<u8>>>,
    /// KV version that was read.
    pub version: u64,
    filled: Vec<&'static str>,
}

impl ResolvedSecrets {
    /// Names filled from the KV secret (fields and secrets), sorted; for the audit event.
    #[must_use]
    pub fn names(&self) -> Vec<&'static str> {
        self.filled.clone()
    }

    /// One secret.
    #[must_use]
    pub fn secret(&self, name: SecretName) -> Option<&[u8]> {
        self.secrets.get(&name).map(|v| v.as_slice())
    }
}

impl fmt::Debug for ResolvedSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedSecrets")
            .field("kind", &self.kind)
            .field("secrets", &self.secrets.keys().collect::<Vec<_>>())
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

/// Which names of `kind` the KV keys provide: `(present, missing_required, extra_keys)`.
#[must_use]
pub fn presence(
    kind: CredentialKind,
    map: Option<&BTreeMap<String, String>>,
    kv: &SecretMap,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let schema = kind.schema();
    let mut present = Vec::new();
    let mut missing = Vec::new();
    let mut used: Vec<&str> = Vec::new();
    for name in target_names(kind) {
        let key = kv_key(map, name);
        let required = schema.fields.iter().any(|f| f.name == name && f.required);
        if kv.get(key).is_some() {
            present.push(name.to_owned());
            used.push(key);
        } else if required {
            missing.push(name.to_owned());
        }
    }
    let extra = kv.keys().filter(|k| !used.contains(k)).map(sanitize_key).collect();
    (present, missing, extra)
}

/// A KV key as it may appear in an error or `external_ref_test` (server-controlled: visible
/// ASCII only, capped).
fn sanitize_key(k: &str) -> String {
    let s: String =
        k.chars().map(|c| if c.is_ascii_graphic() { c } else { '?' }).take(64).collect();
    s
}

fn shape(e: &CredentialError) -> SecretsError {
    match e {
        CredentialError::Invalid { field, reason } => {
            SecretsError::shape(format!("{field}: {reason}"))
        }
        other => SecretsError::shape(other.to_string()),
    }
}

/// Build the target credential from `kv`.
pub fn build(
    kind: CredentialKind,
    map: Option<&BTreeMap<String, String>>,
    kv: &SecretMap,
    version: u64,
) -> Result<ResolvedSecrets, SecretsError> {
    if !kind.is_ref_target() {
        return Err(SecretsError::Invalid("target_kind"));
    }
    let (_, missing, extra) = presence(kind, map, kv);
    if !missing.is_empty() || !extra.is_empty() {
        return Err(SecretsError::Shape { missing, extra, invalid: None });
    }
    let mut plain = Map::new();
    let mut secrets = BTreeMap::new();
    let mut filled = Vec::new();
    for name in target_names(kind) {
        let Some(v) = kv.get(kv_key(map, name)) else { continue };
        filled.push(name);
        match SecretName::parse(name) {
            Some(s) => {
                secrets.insert(s, Zeroizing::new(v.expose().as_bytes().to_vec()));
            }
            None => {
                plain.insert(name.to_owned(), Value::String(v.expose().to_owned()));
            }
        }
    }
    let mut fields =
        CredentialFields::from_input(kind, &Value::Object(plain), None).map_err(|e| shape(&e))?;
    for (name, value) in &secrets {
        validate_secret(kind, *name, value).map_err(|e| shape(&e))?;
        fields.derive_from_secret(*name, value).map_err(|e| shape(&e))?;
    }
    if secrets.contains_key(&SecretName::OtpSeed) {
        fields.set_otp(Some(OtpParams::default())).map_err(|e| shape(&e))?;
    }
    filled.sort_unstable();
    Ok(ResolvedSecrets { kind, fields, secrets, version, filled })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mooring_core::credential::testdata::{placeholder_key_pem, KUBECONFIG};
    use CredentialKind as K;

    fn kv(p: &[(&str, &str)]) -> SecretMap {
        SecretMap::from_pairs(p)
    }

    type Case<'a> = (K, Vec<(&'a str, &'a str)>, Vec<&'a str>);

    #[test]
    fn mapping_table() {
        let pem = placeholder_key_pem();
        let seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let cases: Vec<Case<'_>> = vec![
            (
                K::UserPassword,
                vec![("username", "ops"), ("password", "pw")],
                vec!["password", "username"],
            ),
            (
                K::UserPassword,
                vec![
                    ("username", "ops"),
                    ("password", "pw"),
                    ("domain", "CORP"),
                    ("otp_seed", seed),
                ],
                vec!["domain", "otp_seed", "password", "username"],
            ),
            (
                K::DomainUser,
                vec![
                    ("user", "alice"),
                    ("domain", "CORP"),
                    ("form", "netbios"),
                    ("password", "pw"),
                ],
                vec!["domain", "form", "password", "user"],
            ),
            (
                K::SshKey,
                vec![("username", "root"), ("private_key", pem.as_str())],
                vec!["private_key", "username"],
            ),
            (K::ApiToken, vec![("token", "t")], vec!["token"]),
            (K::KubeToken, vec![("token", "t")], vec!["token"]),
            (K::Kubeconfig, vec![("kubeconfig_yaml", KUBECONFIG)], vec!["kubeconfig_yaml"]),
            (
                K::VsphereUser,
                vec![("upn", "administrator@vsphere.local"), ("password", "pw")],
                vec!["password", "upn"],
            ),
            (K::VncPassword, vec![("password", "12345678")], vec!["password"]),
            (
                K::VncUserPassword,
                vec![("username", "v"), ("password", "pw")],
                vec!["password", "username"],
            ),
            (K::SudoBecome, vec![("method", "sudo")], vec!["method"]),
        ];
        for (kind, pairs, names) in cases {
            let r = build(kind, None, &kv(&pairs), 1).unwrap_or_else(|e| panic!("{kind:?}: {e}"));
            assert_eq!(r.fields.kind(), kind);
            assert_eq!(r.names(), names, "{kind:?}");
            assert!(!format!("{r:?}").contains("pw"), "no values in Debug");
        }
        let r = build(
            K::UserPassword,
            None,
            &kv(&[("username", "u"), ("password", "pw"), ("otp_seed", seed)]),
            1,
        )
        .expect("otp");
        assert!(r.fields.otp().is_some(), "otp params follow the seed");
    }

    #[test]
    fn field_map_renames() {
        let map: BTreeMap<String, String> = [
            ("password".to_owned(), "db_pass".to_owned()),
            ("username".to_owned(), "db_user".to_owned()),
        ]
        .into_iter()
        .collect();
        let r =
            build(K::UserPassword, Some(&map), &kv(&[("db_user", "app"), ("db_pass", "pw")]), 4)
                .expect("mapped");
        assert_eq!(r.secret(SecretName::Password), Some(&b"pw"[..]));
        assert_eq!(r.fields.account().0.as_deref(), Some("app"));
        assert_eq!(r.version, 4);
        let e =
            build(K::UserPassword, Some(&map), &kv(&[("username", "app"), ("password", "pw")]), 1)
                .expect_err("defaults no longer apply");
        let SecretsError::Shape { missing, extra, .. } = e else { panic!("shape") };
        assert_eq!(missing, ["username", "password"]);
        assert_eq!(extra, ["username", "password"]);
    }

    #[test]
    fn missing_extra_and_invalid() {
        let e = build(K::UserPassword, None, &kv(&[("username", "u")]), 1).expect_err("missing");
        assert_eq!(e.code(), "credential.external_shape");
        assert!(e.to_string().contains("missing password"), "{e}");
        let e =
            build(K::ApiToken, None, &kv(&[("token", "t"), ("note", "x")]), 1).expect_err("extra");
        assert!(e.to_string().contains("unexpected note"), "{e}");
        let e = build(K::VncPassword, None, &kv(&[("password", "123456789")]), 1).expect_err("cap");
        assert!(e.to_string().contains("password"), "{e}");
        assert!(!e.to_string().contains("123456789"), "no echo");
        let e =
            build(K::UserPassword, None, &kv(&[("username", "a\u{202e}b"), ("password", "p")]), 1)
                .expect_err("bidi");
        assert!(e.to_string().contains("username"));
        let e = build(
            K::Kubeconfig,
            None,
            &kv(&[("kubeconfig_yaml", "users: [{user: {exec: {}}}]")]),
            1,
        )
        .expect_err("hardened parser");
        assert_eq!(e.code(), "credential.external_shape");
        let e = build(K::SshKey, None, &kv(&[("username", "r"), ("private_key", "not pem")]), 1)
            .expect_err("pem");
        assert_eq!(e.code(), "credential.external_shape");
        assert!(matches!(build(K::Prompt, None, &kv(&[]), 1), Err(SecretsError::Invalid(_))));
        assert!(matches!(build(K::VaultApprole, None, &kv(&[]), 1), Err(SecretsError::Invalid(_))));
        let (present, missing, extra) =
            presence(K::UserPassword, None, &kv(&[("password", "p"), ("x\u{7}y", "z")]));
        assert_eq!((present, missing), (vec!["password".to_owned()], vec!["username".to_owned()]));
        assert_eq!(extra, ["x?y"], "server keys are sanitised");
    }
}
