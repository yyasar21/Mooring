//! Vault response shapes, decoded from the capped, zeroizing body by hand-written visitors:
//! secret values go straight into [`SecretValue`] (`Zeroizing<String>`), never through an
//! intermediate `serde_json::Value` or a plain `String`. Unknown fields are skipped
//! (`IgnoredAny`), which never allocates for an unescaped string.
//!
//! Residue (R-EXT-STR): `serde_json` keeps escaped strings in a scratch buffer it does not
//! zeroize, and hyper / rustls buffer the response before we own it.

use std::fmt;

use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

/// Most keys in one KV v2 secret.
pub const MAX_KV_FIELDS: usize = 64;
/// Longest KV key.
pub const MAX_KV_KEY: usize = 128;
/// Most policies a token may report.
pub const MAX_POLICIES: usize = 256;
/// Longest policy name we keep.
const MAX_POLICY: usize = 256;

/// One secret string. `Debug` prints its length only; memory is wiped on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(pub(crate) Zeroizing<String>);

impl SecretValue {
    /// The value (keep the borrow short).
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Take the inner buffer.
    #[must_use]
    pub fn into_inner(self) -> Zeroizing<String> {
        self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretValue(<{} bytes>)", self.0.len())
    }
}

struct SecretVisitor;

impl Visitor<'_> for SecretVisitor {
    type Value = SecretValue;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<SecretValue, E> {
        Ok(SecretValue(Zeroizing::new(v.to_owned())))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<SecretValue, E> {
        Ok(SecretValue(Zeroizing::new(v)))
    }
}

impl<'de> Deserialize<'de> for SecretValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_str(SecretVisitor)
    }
}

/// The `data.data` object of a KV v2 read: string values only, ≤ [`MAX_KV_FIELDS`] keys of
/// ≤ [`MAX_KV_KEY`] bytes, no duplicate keys. Zeroized on drop.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct SecretMap(Vec<(String, SecretValue)>);

impl SecretMap {
    /// Value of `key`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&SecretValue> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Keys, in response order.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|(k, _)| k.as_str())
    }

    /// Number of keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// No keys.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        Self(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), SecretValue(Zeroizing::new((*v).to_owned()))))
                .collect(),
        )
    }
}

impl Zeroize for SecretMap {
    fn zeroize(&mut self) {
        for (k, v) in &mut self.0 {
            k.zeroize();
            v.0.zeroize();
        }
        self.0.clear();
    }
}

impl Drop for SecretMap {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for SecretMap {}

impl fmt::Debug for SecretMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.keys()).finish()
    }
}

struct MapVisitor;

impl<'de> Visitor<'de> for MapVisitor {
    type Value = SecretMap;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an object of strings")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<SecretMap, A::Error> {
        let mut out = SecretMap::default();
        while let Some(key) = m.next_key::<String>()? {
            if out.0.len() == MAX_KV_FIELDS {
                return Err(de::Error::custom("too many keys"));
            }
            if key.is_empty() || key.len() > MAX_KV_KEY || key.chars().any(char::is_control) {
                return Err(de::Error::custom("bad key"));
            }
            if out.get(&key).is_some() {
                return Err(de::Error::custom("duplicate key"));
            }
            let value = m.next_value::<SecretValue>()?;
            out.0.push((key, value));
        }
        Ok(out)
    }
}

impl<'de> Deserialize<'de> for SecretMap {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_map(MapVisitor)
    }
}

/// Policy names, capped in count and length.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Policies(pub Vec<String>);

impl Policies {
    /// Whether `root` is among them.
    #[must_use]
    pub fn has_root(&self) -> bool {
        self.0.iter().any(|p| p == "root")
    }
}

impl<'de> Deserialize<'de> for Policies {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v: Option<Vec<String>> = Deserialize::deserialize(d)?;
        let v = v.unwrap_or_default();
        if v.len() > MAX_POLICIES || v.iter().any(|p| p.len() > MAX_POLICY) {
            return Err(de::Error::custom("too many policies"));
        }
        Ok(Self(v))
    }
}

/// `auth` of a login / renew response.
#[derive(Debug, Deserialize)]
pub(crate) struct AuthBlock {
    pub client_token: SecretValue,
    #[serde(default)]
    pub policies: Policies,
    #[serde(default)]
    pub token_policies: Policies,
    #[serde(default)]
    pub lease_duration: u64,
    #[serde(default)]
    pub renewable: bool,
}

/// `{ "auth": … }` (login, renew-self, OIDC callback).
#[derive(Debug, Deserialize)]
pub(crate) struct AuthResponse {
    pub auth: Option<AuthBlock>,
}

/// `data` of `lookup-self` (the `id` field, the token itself, is skipped unread).
#[derive(Debug, Deserialize)]
pub(crate) struct LookupData {
    #[serde(default)]
    pub policies: Policies,
    #[serde(default)]
    pub identity_policies: Policies,
    #[serde(default)]
    pub ttl: u64,
    #[serde(default)]
    pub renewable: bool,
}

/// `{ "data": … }`.
#[derive(Debug, Deserialize)]
pub(crate) struct DataResponse<T> {
    pub data: Option<T>,
}

/// KV v2 `data.metadata`.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
pub struct KvMetadata {
    /// Version that was read.
    #[serde(default)]
    pub version: u64,
    /// Non-empty when the version was soft-deleted.
    #[serde(default)]
    pub deletion_time: String,
    /// The version was destroyed.
    #[serde(default)]
    pub destroyed: bool,
}

/// KV v2 `data` of a read.
#[derive(Debug, Deserialize)]
pub(crate) struct KvData {
    pub data: Option<SecretMap>,
    #[serde(default)]
    pub metadata: Option<KvMetadata>,
}

/// `data` of `oidc/auth_url`.
#[derive(Debug, Deserialize)]
pub(crate) struct AuthUrlData {
    pub auth_url: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use mooring_http::decode_json;

    fn kv(json: &str) -> Result<DataResponse<KvData>, mooring_http::HttpError> {
        decode_json(json.as_bytes())
    }

    #[test]
    fn kv_shapes() {
        let ok = kv(r#"{"data":{"data":{"username":"u","password":"p\"w"},
                     "metadata":{"version":3,"deletion_time":"","destroyed":false}}}"#)
        .expect("ok");
        let d = ok.data.expect("data");
        let m = d.data.expect("map");
        assert_eq!(m.get("password").expect("pw").expose(), "p\"w");
        assert_eq!(d.metadata.expect("meta").version, 3);
        assert_eq!(format!("{m:?}"), r#"["username", "password"]"#, "keys only");
        let deleted = kv(r#"{"data":{"data":null,"metadata":{"version":2,
                          "deletion_time":"2026-11-01T00:00:00Z","destroyed":false}}}"#)
        .expect("deleted");
        assert!(deleted.data.expect("data").data.is_none());
        for bad in [
            r#"{"data":{"data":{"a":1}}}"#,
            r#"{"data":{"data":{"a":null}}}"#,
            r#"{"data":{"data":{"a":["x"]}}}"#,
            r#"{"data":{"data":{"a":{"b":"c"}}}}"#,
            r#"{"data":{"data":{"a":"x","a":"y"}}}"#,
            r#"{"data":{"data":{"":"x"}}}"#,
            r#"{"data":{"data":"str"}}"#,
            r#"{"data":{"data":{"a":"x"},"metadata":{"version":-1}}}"#,
            r#"{"data":{"data":{"a":"x""#,
        ] {
            assert!(kv(bad).is_err(), "{bad}");
        }
        let many: String =
            (0..=MAX_KV_FIELDS).map(|i| format!("\"k{i}\":\"v\"")).collect::<Vec<_>>().join(",");
        assert!(kv(&format!(r#"{{"data":{{"data":{{{many}}}}}}}"#)).is_err());
        let long = "k".repeat(MAX_KV_KEY + 1);
        assert!(kv(&format!(r#"{{"data":{{"data":{{"{long}":"v"}}}}}}"#)).is_err());
    }

    #[test]
    fn errors_never_echo_values() {
        let e = kv(r#"{"data":{"data":{"password":12345678}}}"#).expect_err("type");
        assert!(!e.to_string().contains("12345678"), "{e}");
        let e =
            decode_json::<AuthResponse>(br#"{"auth":{"client_token":42424242}}"#).expect_err("t");
        assert!(!e.to_string().contains("42424242"));
    }

    #[test]
    fn auth_and_lookup() {
        let a: AuthResponse = decode_json(
            br#"{"auth":{"client_token":"hvs.test-only","policies":["default","app"],
                 "lease_duration":3600,"renewable":true,"accessor":"x"},"data":null}"#,
        )
        .expect("auth");
        let a = a.auth.expect("auth");
        assert_eq!(a.lease_duration, 3600);
        assert!(!a.policies.has_root());
        assert!(!format!("{a:?}").contains("hvs.test-only"));
        let l: DataResponse<LookupData> = decode_json(
            br#"{"data":{"id":"hvs.test-only","policies":["root"],"ttl":0,"renewable":false}}"#,
        )
        .expect("lookup");
        assert!(l.data.expect("data").policies.has_root());
        let many: Vec<String> = (0..=MAX_POLICIES).map(|i| format!("\"p{i}\"")).collect();
        let body = format!(r#"{{"data":{{"policies":[{}]}}}}"#, many.join(","));
        assert!(decode_json::<DataResponse<LookupData>>(body.as_bytes()).is_err());
    }

    #[test]
    fn zeroize_clears_the_map() {
        fn assert_zod<T: zeroize::ZeroizeOnDrop>() {}
        assert_zod::<SecretMap>();
        assert_zod::<Zeroizing<String>>();
        let mut m = SecretMap::from_pairs(&[("password", "test-only")]);
        m.zeroize();
        assert!(m.is_empty());
    }
}
