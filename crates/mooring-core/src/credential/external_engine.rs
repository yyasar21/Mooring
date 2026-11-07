//! Engine rules of an `external_ref` (ADR-0026 §1): which target kind each Vault engine
//! yields, which request parameters it takes and their caps. Run on input and on every read,
//! so a stored row that breaks them is refused, never half used.

use super::structs::{ExternalRefFields, VaultEngine};
use super::{CredentialError, CredentialKind as K, RefProvider};

/// Most `principals` / `alt_names`.
pub const MAX_NAMES: usize = 16;
/// Longest principal (bytes).
pub const MAX_PRINCIPAL: usize = 64;
/// Longest `common_name` / alt name (bytes).
pub const MAX_COMMON_NAME: usize = 255;
/// Longest `ssh_otp` username (bytes).
pub const MAX_OTP_USER: usize = 64;
/// Longest requested TTL (24 h).
pub const MAX_TTL_SECONDS: u64 = 24 * 3600;

fn bad(field: &'static str, reason: &'static str) -> CredentialError {
    CredentialError::invalid(field, reason)
}

/// The target kind each engine yields (`kv2`: any reference target).
#[must_use]
pub const fn engine_target(engine: VaultEngine) -> Option<K> {
    match engine {
        VaultEngine::Kv2 => None,
        VaultEngine::Database | VaultEngine::SshOtp => Some(K::UserPassword),
        VaultEngine::SshSign => Some(K::SshKey),
        VaultEngine::Pki => Some(K::X509),
    }
}

fn principal_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_PRINCIPAL
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'@'))
}

fn dns_name_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_COMMON_NAME
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'*' | b'@'))
}

fn names(
    field: &'static str,
    v: Option<&Vec<String>>,
    ok: fn(&str) -> bool,
) -> Result<(), CredentialError> {
    let Some(v) = v else { return Ok(()) };
    if v.is_empty() || v.len() > MAX_NAMES {
        return Err(bad(field, "must list 1..=16 names"));
    }
    if !v.iter().all(|s| ok(s)) {
        return Err(bad(field, "entries must be [A-Za-z0-9._@-] names (≤ 64 B; ≤ 255 B for PKI)"));
    }
    if v.iter().enumerate().any(|(i, a)| v[..i].contains(a)) {
        return Err(bad(field, "lists a name twice"));
    }
    Ok(())
}

fn none<T>(field: &'static str, v: Option<&T>, engine: VaultEngine) -> Result<(), CredentialError> {
    if v.is_some() {
        return Err(CredentialError::Invalid {
            field,
            reason: format!("is not a parameter of the {} engine", engine.name()),
        });
    }
    Ok(())
}

/// Validate the engine and its parameters.
pub(crate) fn check(f: &ExternalRefFields) -> Result<(), CredentialError> {
    let e = f.engine;
    if f.provider != RefProvider::Vault && e != VaultEngine::Kv2 {
        return Err(bad("engine", "only Vault references have an engine"));
    }
    if let Some(target) = engine_target(e) {
        if f.target_kind != target {
            return Err(CredentialError::Invalid {
                field: "target_kind",
                reason: format!("the {} engine yields {}", e.name(), target.name()),
            });
        }
        none("version", f.version.as_ref(), e)?;
        none("field_map", f.field_map.as_ref(), e)?;
        super::parse_vault_reference(&f.reference)?;
    }
    if !matches!(e, VaultEngine::SshSign) {
        none("principals", f.principals.as_ref(), e)?;
    }
    if !matches!(e, VaultEngine::SshSign | VaultEngine::Pki) {
        none("ttl", f.ttl.as_ref(), e)?;
    }
    if e != VaultEngine::Pki {
        none("common_name", f.common_name.as_ref(), e)?;
        none("alt_names", f.alt_names.as_ref(), e)?;
    }
    if e != VaultEngine::SshOtp {
        none("username", f.username.as_ref(), e)?;
    }
    if f.ttl.is_some_and(|t| t == 0 || t > MAX_TTL_SECONDS) {
        return Err(bad("ttl", "must be 1..=86400 seconds"));
    }
    names("principals", f.principals.as_ref(), principal_ok)?;
    names("alt_names", f.alt_names.as_ref(), dns_name_ok)?;
    match e {
        VaultEngine::Pki if !f.common_name.as_deref().is_some_and(dns_name_ok) => {
            Err(bad("common_name", "is required: a [A-Za-z0-9._*@-] name of ≤ 255 bytes"))
        }
        VaultEngine::SshOtp
            if !f
                .username
                .as_deref()
                .is_some_and(|u| u.len() <= MAX_OTP_USER && principal_ok(u)) =>
        {
            Err(bad("username", "is required: a [A-Za-z0-9._@-] login of ≤ 64 bytes"))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::CredentialFields;
    use serde_json::{json, Value};

    fn input(v: &Value) -> Result<CredentialFields, CredentialError> {
        CredentialFields::from_input(K::ExternalRef, v, None)
    }

    fn base(engine: &str, target: &str) -> Value {
        json!({"provider": "vault", "reference": "team/db/app-ro", "target_kind": target,
               "source": crate::model::SecretSourceId::new().to_string(), "engine": engine})
    }

    fn with(mut v: Value, k: &str, x: Value) -> Value {
        v[k] = x;
        v
    }

    #[test]
    fn engines_fix_their_target_kind() {
        for (engine, target) in [
            ("database", "user_password"),
            ("ssh_otp", "user_password"),
            ("ssh_sign", "ssh_key"),
            ("pki", "x509"),
        ] {
            let mut v = base(engine, target);
            if engine == "ssh_otp" {
                v["username"] = json!("deploy");
            }
            if engine == "pki" {
                v["common_name"] = json!("app.example.test");
            }
            let CredentialFields::ExternalRef(f) =
                input(&v).unwrap_or_else(|e| panic!("{engine}: {e}"))
            else {
                panic!("kind")
            };
            assert_eq!(f.engine.name(), engine);
            let json = f.clone();
            let stored = CredentialFields::ExternalRef(json).to_json().expect("json");
            assert!(stored.contains(&format!("\"engine\":\"{engine}\"")), "{stored}");
            assert!(
                input(&with(v.clone(), "target_kind", json!("api_token"))).is_err(),
                "{engine}"
            );
            assert!(input(&with(v.clone(), "version", json!(2))).is_err(), "{engine} version");
            assert!(input(&with(v.clone(), "field_map", json!({"password": "p"}))).is_err());
            assert!(input(&with(v, "reference", json!("single"))).is_err(), "<mount>/<role>");
        }
        let kv = json!({"provider": "vault", "reference": "secret/x", "target_kind": "api_token",
                        "source": crate::model::SecretSourceId::new().to_string()});
        let CredentialFields::ExternalRef(f) = input(&kv).expect("kv2") else { panic!("kind") };
        assert!(f.engine.is_kv2());
        assert!(
            !CredentialFields::ExternalRef(f).to_json().expect("j").contains("engine"),
            "unchanged rows"
        );
        assert!(input(&with(kv, "engine", json!("transit"))).is_err());
    }

    #[test]
    fn parameters_belong_to_their_engine() {
        let sign = base("ssh_sign", "ssh_key");
        assert!(input(&with(sign.clone(), "principals", json!(["deploy", "ops@example"]))).is_ok());
        assert!(input(&with(sign.clone(), "ttl", json!(3600))).is_ok());
        assert!(input(&with(sign.clone(), "ttl", json!(0))).is_err());
        assert!(input(&with(sign.clone(), "ttl", json!(86_401))).is_err());
        assert!(input(&with(sign.clone(), "principals", json!([]))).is_err());
        assert!(input(&with(sign.clone(), "principals", json!(["a", "a"]))).is_err());
        assert!(input(&with(sign.clone(), "principals", json!(["a b"]))).is_err());
        assert!(input(&with(sign.clone(), "principals", json!(["p".repeat(65)]))).is_err());
        let many: Vec<String> = (0..17).map(|i| format!("p{i}")).collect();
        assert!(input(&with(sign.clone(), "principals", json!(many))).is_err());
        assert!(input(&with(sign.clone(), "common_name", json!("x"))).is_err());
        assert!(input(&with(sign, "username", json!("x"))).is_err());
        let db = base("database", "user_password");
        assert!(input(&db).is_ok());
        assert!(input(&with(db.clone(), "ttl", json!(60))).is_err());
        assert!(input(&with(db, "principals", json!(["x"]))).is_err());
        let otp = base("ssh_otp", "user_password");
        assert!(input(&otp).is_err(), "username required");
        assert!(input(&with(otp.clone(), "username", json!("bad user"))).is_err());
        let pki = base("pki", "x509");
        assert!(input(&pki).is_err(), "common_name required");
        let pki = with(pki, "common_name", json!("*.example.test"));
        assert!(input(&with(pki.clone(), "alt_names", json!(["a.example.test"]))).is_ok());
        assert!(input(&with(pki.clone(), "alt_names", json!(["a/b"]))).is_err());
        assert!(input(&with(pki, "common_name", json!("c".repeat(256)))).is_err());
        let kv = json!({"provider": "vault", "reference": "secret/x", "target_kind": "api_token",
                        "source": crate::model::SecretSourceId::new().to_string(), "ttl": 60});
        assert!(input(&kv).is_err(), "kv2 has no ttl");
        let op = json!({"provider": "onepassword", "reference": "op://v/i/f", "target_kind": "api_token",
                        "source": crate::model::SecretSourceId::new().to_string(), "engine": "database"});
        assert!(input(&op).is_err(), "engines are Vault only");
    }
}
