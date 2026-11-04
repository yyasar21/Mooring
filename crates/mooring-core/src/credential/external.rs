//! `external_ref` rules of ADR-0016 §2: the strict Vault reference grammar
//! (`<mount>/<path>`, segments `[A-Za-z0-9._-]+`, no `.`/`..`, no empty segment, ≤ 1 KiB),
//! `version` and `field_map` checks, and the KV key a target-kind name maps to.

use std::collections::BTreeMap;

use super::structs::ExternalRefFields;
use super::{CredentialError, CredentialFields, CredentialKind, RefProvider};

/// Longest `reference`.
pub const MAX_REFERENCE: usize = 1024;
/// Most `field_map` entries.
pub const MAX_FIELD_MAP: usize = 32;
/// Longest KV key a `field_map` value may name.
pub const MAX_KV_KEY: usize = 128;
/// Most path segments (mount included).
const MAX_SEGMENTS: usize = 64;

/// A parsed Vault KV v2 reference: the first segment is the mount, the rest the secret path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultPath {
    /// KV v2 mount (`secret`).
    pub mount: String,
    /// Path segments below the mount (at least one).
    pub path: Vec<String>,
}

impl VaultPath {
    /// `<path>` joined with `/` (each segment is already URL-safe by the grammar).
    #[must_use]
    pub fn joined_path(&self) -> String {
        self.path.join("/")
    }
}

fn segment_ok(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Parse a Vault reference strictly. No trimming, no normalisation: what is stored is what is
/// requested.
pub fn parse_vault_reference(reference: &str) -> Result<VaultPath, CredentialError> {
    let bad = |reason: &'static str| CredentialError::invalid("reference", reason);
    if reference.is_empty() {
        return Err(bad("is required"));
    }
    if reference.len() > MAX_REFERENCE {
        return Err(bad("longer than 1024 bytes"));
    }
    let mut segments = reference.split('/');
    let mount = segments.next().unwrap_or_default();
    let path: Vec<&str> = segments.collect();
    if path.is_empty() {
        return Err(bad("must be <mount>/<path>"));
    }
    if path.len() + 1 > MAX_SEGMENTS {
        return Err(bad("has too many segments"));
    }
    if !segment_ok(mount) || !path.iter().all(|s| segment_ok(s)) {
        return Err(bad("segments must be [A-Za-z0-9._-]+ without empty, '.' or '..' segments"));
    }
    Ok(VaultPath { mount: mount.to_owned(), path: path.into_iter().map(str::to_owned).collect() })
}

/// Names of `kind` that a KV secret may fill: its plain fields, its secrets and `otp_seed`
/// when the kind has the TOTP slot.
pub fn target_names(kind: CredentialKind) -> impl Iterator<Item = &'static str> {
    let s = kind.schema();
    s.fields.iter().map(|f| f.name).chain(s.supports_otp.then_some("otp_seed"))
}

/// The KV key that holds `name` (default: the name itself).
#[must_use]
pub fn kv_key<'a>(map: Option<&'a BTreeMap<String, String>>, name: &'a str) -> &'a str {
    map.and_then(|m| m.get(name)).map_or(name, String::as_str)
}

fn kv_key_ok(v: &str) -> bool {
    !v.is_empty() && v.len() <= MAX_KV_KEY && !v.chars().any(super::is_forbidden)
}

/// Shape rules of the amended fields (run on input and on every read).
pub(crate) fn normalise(f: &mut ExternalRefFields) -> Result<(), CredentialError> {
    if f.version == Some(0) {
        return Err(CredentialError::invalid("version", "must be at least 1"));
    }
    if let Some(map) = &f.field_map {
        if map.len() > MAX_FIELD_MAP {
            return Err(CredentialError::invalid("field_map", "has too many entries"));
        }
        for (name, key) in map {
            if !target_names(f.target_kind).any(|n| n == name) {
                return Err(CredentialError::invalid("field_map", "names a field the kind lacks"));
            }
            if !kv_key_ok(key) {
                return Err(CredentialError::invalid(
                    "field_map",
                    "KV keys must be 1..=128 bytes of visible text",
                ));
            }
        }
        if map.is_empty() {
            f.field_map = None;
        }
    }
    if f.provider != RefProvider::Vault && (f.source.is_some() || f.field_map.is_some()) {
        return Err(CredentialError::invalid("source", "only Vault references have a source"));
    }
    Ok(())
}

/// Input-only rules (stored A1/A2 rows keep validating): a Vault reference needs a source and
/// the strict grammar.
pub(crate) fn check_input(f: &ExternalRefFields) -> Result<(), CredentialError> {
    if f.provider == RefProvider::Vault {
        if f.source.is_none() {
            return Err(CredentialError::invalid("source", "is required for a Vault reference"));
        }
        parse_vault_reference(&f.reference)?;
    }
    Ok(())
}

/// Fuzz entry (`fuzz/fuzz_targets/external_ref_parse.rs`): the reference grammar and the
/// whole `external_ref` field parser. Never panics.
pub fn fuzz_external_ref(data: &[u8]) {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(p) = parse_vault_reference(s) {
            assert_eq!(format!("{}/{}", p.mount, p.joined_path()), s, "round trip");
        }
    }
    if data.len() <= 64 * 1024 {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) {
            let _ = CredentialFields::from_input(CredentialKind::ExternalRef, &v, None);
            if let Ok(s) = std::str::from_utf8(data) {
                let _ = CredentialFields::from_stored(CredentialKind::ExternalRef, s);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    #[test]
    fn reference_grammar() {
        let p = parse_vault_reference("secret/team-a/db.prod").expect("ok");
        assert_eq!(p.mount, "secret");
        assert_eq!(p.joined_path(), "team-a/db.prod");
        for bad in [
            "",
            "secret",
            "secret/",
            "/secret/x",
            "secret//x",
            "secret/../x",
            "secret/./x",
            "secret/x y",
            "secret/x?version=2",
            "secret/x#y",
            "secret/x%2F",
            "secret/é",
            "secret\\x",
        ] {
            assert!(parse_vault_reference(bad).is_err(), "{bad:?}");
        }
        let long = format!("s/{}", "a".repeat(MAX_REFERENCE - 1));
        assert!(parse_vault_reference(&long).is_err());
        assert!(parse_vault_reference(&long[..MAX_REFERENCE]).is_ok());
    }

    fn input(v: &serde_json::Value) -> Result<CredentialFields, CredentialError> {
        CredentialFields::from_input(CredentialKind::ExternalRef, v, None)
    }

    #[test]
    fn amended_fields_validate() {
        let src = crate::model::SecretSourceId::new().to_string();
        let ok = json!({"provider": "vault", "reference": "secret/db", "target_kind": "user_password",
                        "source": src, "version": 3, "field_map": {"password": "pw"}});
        let CredentialFields::ExternalRef(f) = input(&ok).expect("ok") else { panic!("kind") };
        assert_eq!(f.version, Some(3));
        assert_eq!(kv_key(f.field_map.as_ref(), "password"), "pw");
        assert_eq!(kv_key(f.field_map.as_ref(), "username"), "username");
        let with = |k: &str, v: serde_json::Value| {
            let mut o = ok.clone();
            o[k] = v;
            input(&o)
        };
        assert!(with("version", json!(0)).is_err());
        assert!(with("version", json!(-1)).is_err());
        assert!(with("field_map", json!({"private_key": "k"})).is_err(), "not a name of the kind");
        assert!(with("field_map", json!({"password": "a\u{7}"})).is_err());
        assert!(with("field_map", json!({"password": "k".repeat(129)})).is_err());
        assert!(with("field_map", json!({"otp_seed": "totp"})).is_ok(), "otp slot");
        assert!(with("reference", json!("secret/../x")).is_err());
        assert!(with("target_kind", json!("vault_approle")).is_err());
        assert!(with("target_kind", json!("s3_access_key")).is_err());
        let mut no_src = ok.clone();
        no_src.as_object_mut().expect("obj").remove("source");
        assert!(input(&no_src).is_err(), "vault needs a source on input");
        // a stored A1/A2 row without a source still reads
        let legacy =
            r#"{"provider":"vault","reference":"kv/anything goes","target_kind":"api_token"}"#;
        assert!(CredentialFields::from_stored(CredentialKind::ExternalRef, legacy).is_ok());
        let op = json!({"provider": "onepassword", "reference": "op://v/i/f",
                        "target_kind": "api_token", "source": src});
        assert!(input(&op).is_err(), "only vault has a source");
    }

    #[test]
    fn fuzz_entry_smoke() {
        for d in [&b""[..], b"secret/x", b"{\"provider\":\"vault\"}", b"\xff\xfe", b"[1,2"] {
            fuzz_external_ref(d);
        }
    }

    proptest! {
        #[test]
        fn fuzz_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            fuzz_external_ref(&data);
        }

        #[test]
        fn valid_references_round_trip(segs in proptest::collection::vec("[A-Za-z0-9_-][A-Za-z0-9._-]{0,8}", 2..6)) {
            let s = segs.join("/");
            let p = parse_vault_reference(&s).expect("valid");
            prop_assert_eq!(format!("{}/{}", p.mount, p.joined_path()), s);
        }
    }
}
