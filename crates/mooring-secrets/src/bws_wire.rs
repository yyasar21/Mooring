//! `bws … --output json` shapes (ADR-0026 §4): one secret object, a list of them, a list of
//! projects. Bounded hand-written parsing (capped lists, capped labels, `value` straight into
//! [`SecretValue`]); unknown fields skipped. Then the value onto the target kind: a kind with
//! one required value takes the secret's `value` as is; any other kind needs the value to be
//! a JSON object of strings, mapped like a KV v2 secret (`fieldMap` renames).

use std::collections::BTreeMap;

use mooring_core::CredentialKind;
use mooring_http::decode_json;
use serde::Deserialize;

use crate::error::SecretsError;
use crate::op_wire::{single_name, Capped, Label};
use crate::resolve::{build, ResolvedSecrets};
use crate::wire::{SecretMap, SecretValue};

/// Most secrets / projects a list may return.
pub const MAX_BWS_LIST: usize = 1000;

/// One secret (`secret get`, `secret list` entry).
#[derive(Debug, Deserialize)]
pub(crate) struct BwsSecret {
    pub id: Label,
    pub key: Label,
    pub value: SecretValue,
}

/// `secret list`.
pub(crate) type BwsSecrets = Capped<BwsSecret, MAX_BWS_LIST>;

/// `project list` entry.
#[derive(Debug, Deserialize)]
pub(crate) struct BwsProject {
    #[allow(dead_code)] // read to validate the shape
    pub id: Label,
}

/// `project list`.
pub(crate) type BwsProjects = Capped<BwsProject, MAX_BWS_LIST>;

/// Parse `secret get` output; the id must be the one asked for.
pub(crate) fn one_secret(stdout: &[u8], id: &str) -> Result<BwsSecret, SecretsError> {
    let s: BwsSecret = decode_json(stdout)?;
    if !s.id.0.eq_ignore_ascii_case(id) {
        return Err(SecretsError::shape("bws returned another secret"));
    }
    Ok(s)
}

/// The one secret of `list` whose key is `key`.
pub(crate) fn by_key(stdout: &[u8], key: &str) -> Result<BwsSecret, SecretsError> {
    let list: BwsSecrets = decode_json(stdout)?;
    let mut hits = list.0.into_iter().filter(|s| s.key.0 == key);
    match (hits.next(), hits.next()) {
        (Some(s), None) => Ok(s),
        (Some(_), Some(_)) => Err(SecretsError::shape("two secrets of the project have this key")),
        (None, _) => Err(SecretsError::NotFound),
    }
}

/// The map of names a secret's value provides for `kind`.
pub(crate) fn value_map(
    value: &SecretValue,
    kind: CredentialKind,
    field_map: Option<&BTreeMap<String, String>>,
) -> Result<(SecretMap, bool), SecretsError> {
    if field_map.is_none() {
        if let Some(name) = single_name(kind) {
            if !value.expose().trim_start().starts_with('{') {
                return Ok((SecretMap::from_values(vec![(name.to_owned(), value.clone())]), false));
            }
        }
    }
    let map: SecretMap = decode_json(value.expose().as_bytes()).map_err(|_| {
        SecretsError::shape("the secret value must be a JSON object of strings for this kind")
    })?;
    Ok((map, true))
}

/// Build the target credential from a secret's value.
pub(crate) fn resolve_value(
    value: &SecretValue,
    kind: CredentialKind,
    field_map: Option<&BTreeMap<String, String>>,
) -> Result<ResolvedSecrets, SecretsError> {
    let (map, keyed) = value_map(value, kind, field_map)?;
    build(kind, if keyed { field_map } else { None }, &map, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mooring_core::SecretName;
    use zeroize::Zeroizing;

    const ID: &str = "3b5c1e02-1d2a-4c8e-9f00-0123456789ab";

    fn v(s: &str) -> SecretValue {
        SecretValue(Zeroizing::new(s.to_owned()))
    }

    #[test]
    fn shapes() {
        let ok = format!(r#"{{"object":"secret","id":"{ID}","key":"db","value":"pw","note":""}}"#);
        assert_eq!(one_secret(ok.as_bytes(), ID).expect("ok").value.expose(), "pw");
        let other = ok.replace(ID, "00000000-0000-0000-0000-000000000000");
        assert!(one_secret(other.as_bytes(), ID).is_err(), "another id");
        for bad in [
            "",
            "[]",
            "{}",
            r#"{"id":"x","key":"k","value":5}"#,
            r#"{"id":"x","key":"k\u0007","value":"v"}"#,
            "{\"id\":\"x\",\"key\":\"k\",\"value\":\"v\"",
            "garbage",
        ] {
            assert!(one_secret(bad.as_bytes(), "x").is_err(), "{bad}");
        }
        let list = r#"[{"id":"a","key":"db","value":"1"},{"id":"b","key":"api","value":"2"}]"#;
        assert_eq!(by_key(list.as_bytes(), "api").expect("api").value.expose(), "2");
        assert!(matches!(by_key(list.as_bytes(), "x"), Err(SecretsError::NotFound)));
        let dup = r#"[{"id":"a","key":"db","value":"1"},{"id":"b","key":"db","value":"2"}]"#;
        assert!(by_key(dup.as_bytes(), "db").is_err(), "duplicate keys are ambiguous");
        let many: Vec<String> = (0..=MAX_BWS_LIST)
            .map(|i| format!(r#"{{"id":"{i}","key":"k{i}","value":"v"}}"#))
            .collect();
        assert!(by_key(format!("[{}]", many.join(",")).as_bytes(), "k1").is_err(), "capped");
    }

    #[test]
    fn values_map_onto_kinds() {
        let r = resolve_value(&v("tok-1"), CredentialKind::ApiToken, None).expect("single");
        assert_eq!(r.secret(SecretName::Token), Some(&b"tok-1"[..]));
        let up = v(r#"{"username":"app","password":"pw"}"#);
        let r = resolve_value(&up, CredentialKind::UserPassword, None).expect("object");
        assert_eq!(r.secret(SecretName::Password), Some(&b"pw"[..]));
        let map: BTreeMap<String, String> = [("password".to_owned(), "pass".to_owned())].into();
        let renamed = v(r#"{"username":"app","pass":"pw"}"#);
        assert!(resolve_value(&renamed, CredentialKind::UserPassword, Some(&map)).is_ok());
        let e = resolve_value(&v("plain"), CredentialKind::UserPassword, None)
            .expect_err("needs object");
        assert_eq!(e.code(), "credential.external_shape");
        assert!(!e.to_string().contains("plain"), "no echo");
        assert!(resolve_value(
            &v(r#"{"username":"a","password":"b","x":"y"}"#),
            CredentialKind::UserPassword,
            None
        )
        .is_err());
        assert!(resolve_value(&v(r#"{"username":5}"#), CredentialKind::UserPassword, None).is_err());
    }
}
