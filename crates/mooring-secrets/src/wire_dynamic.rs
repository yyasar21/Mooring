//! Response shapes of the Vault dynamic engines (ADR-0026 §1), one hand-written shape per
//! engine; secrets go straight into [`SecretValue`]. The lease id is treated as a secret too
//! (RAM only, zeroized). Unknown fields are skipped; wrong types, oversized strings and
//! missing values are refused. Every parser here has a fuzz entry ([`crate::fuzz`]).

use std::time::Duration;

use serde::de::{self, Deserializer};
use serde::Deserialize;

use crate::error::SecretsError;
use crate::wire::SecretValue;

/// Longest lease id we accept (Vault's are `<path>/<24 chars>`).
pub const MAX_LEASE_ID: usize = 1024;
/// Longest lease we keep track of (30 days); longer values are capped.
pub const MAX_LEASE: Duration = Duration::from_secs(30 * 24 * 3600);
/// Most `ca_chain` entries.
pub const MAX_CHAIN: usize = 16;
/// Cap of each PKI PEM value (ADR-0026 §1: 64 KiB each).
pub const MAX_PKI_PEM: usize = 64 * 1024;

/// The lease part of a dynamic response.
#[derive(Debug)]
pub struct LeaseInfo {
    /// Lease id (`None` when Vault created no lease).
    pub id: Option<SecretValue>,
    /// Remaining lifetime, capped at [`MAX_LEASE`].
    pub ttl: Duration,
    /// `sys/leases/renew` allowed.
    pub renewable: bool,
}

fn lease_id<'de, D: Deserializer<'de>>(d: D) -> Result<Option<SecretValue>, D::Error> {
    let v: Option<SecretValue> = Option::deserialize(d)?;
    match v {
        Some(v) if v.expose().is_empty() => Ok(None),
        Some(v)
            if v.expose().len() > MAX_LEASE_ID
                || !v.expose().bytes().all(|b| b.is_ascii_graphic()) =>
        {
            Err(de::Error::custom("bad lease id"))
        }
        other => Ok(other),
    }
}

/// `{ lease_id, lease_duration, renewable, data }`.
#[derive(Debug, Deserialize)]
pub(crate) struct Envelope<T> {
    #[serde(default, deserialize_with = "lease_id")]
    pub lease_id: Option<SecretValue>,
    #[serde(default)]
    pub lease_duration: u64,
    #[serde(default)]
    pub renewable: bool,
    pub data: Option<T>,
}

impl<T> Envelope<T> {
    pub(crate) fn split(self) -> Result<(LeaseInfo, T), SecretsError> {
        let data = self.data.ok_or_else(|| SecretsError::shape("response without data"))?;
        let ttl = Duration::from_secs(self.lease_duration).min(MAX_LEASE);
        Ok((LeaseInfo { id: self.lease_id, ttl, renewable: self.renewable }, data))
    }
}

/// `database/creds/<role>` data.
#[derive(Debug, Deserialize)]
pub(crate) struct DbCreds {
    pub username: SecretValue,
    pub password: SecretValue,
}

/// `ssh/sign/<role>` data.
#[derive(Debug, Deserialize)]
pub(crate) struct SshSigned {
    pub signed_key: String,
}

/// `ssh/creds/<role>` (OTP) data.
#[derive(Debug, Deserialize)]
pub(crate) struct SshOtp {
    pub key: SecretValue,
    #[serde(default)]
    pub key_type: String,
    #[serde(default)]
    pub username: String,
}

fn chain<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    let v: Option<Vec<String>> = Option::deserialize(d)?;
    let v = v.unwrap_or_default();
    if v.len() > MAX_CHAIN || v.iter().any(|c| c.len() > MAX_PKI_PEM) {
        return Err(de::Error::custom("ca_chain too large"));
    }
    Ok(v)
}

/// `pki/issue/<role>` data.
#[derive(Debug, Deserialize)]
pub(crate) struct PkiIssued {
    pub certificate: String,
    pub private_key: SecretValue,
    #[serde(default, deserialize_with = "chain")]
    pub ca_chain: Vec<String>,
    #[serde(default)]
    pub serial_number: String,
}

/// `sys/leases/renew` response (top level, no `data`).
#[derive(Debug, Deserialize)]
pub(crate) struct Renewed {
    #[serde(default, deserialize_with = "lease_id")]
    pub lease_id: Option<SecretValue>,
    #[serde(default)]
    pub lease_duration: u64,
    #[serde(default)]
    pub renewable: bool,
}

/// A Vault certificate serial (`xx:xx:…`, hex pairs), ≤ 128 bytes.
pub(crate) fn serial_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.split(':').all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mooring_http::decode_json;

    #[test]
    fn database_shapes() {
        let ok: Envelope<DbCreds> = decode_json(
            br#"{"lease_id":"database/creds/ro/abc","lease_duration":3600,"renewable":true,
                 "data":{"username":"v-ro-x","password":"A1a-test"}}"#,
        )
        .expect("ok");
        let (lease, d) = ok.split().expect("split");
        assert_eq!(lease.ttl, Duration::from_secs(3600));
        assert!(lease.renewable && lease.id.is_some());
        assert_eq!(d.password.expose(), "A1a-test");
        let none: Envelope<DbCreds> = decode_json(
            br#"{"lease_id":"","lease_duration":3600,"data":{"username":"u","password":"p"}}"#,
        )
        .expect("no lease");
        assert!(none.split().expect("split").0.id.is_none(), "empty id = no lease");
        let long: Envelope<DbCreds> = decode_json(
            br#"{"lease_id":"x","lease_duration":99999999999,"data":{"username":"u","password":"p"}}"#,
        )
        .expect("long");
        assert_eq!(long.split().expect("s").0.ttl, MAX_LEASE, "capped");
        for bad in [
            &br#"{"data":{"username":"u"}}"#[..],
            br#"{"data":{"username":"u","password":5}}"#,
            br#"{"lease_id":5,"data":{"username":"u","password":"p"}}"#,
            br#"{"lease_id":"a b","data":{"username":"u","password":"p"}}"#,
            br#"{"lease_duration":-1,"data":{"username":"u","password":"p"}}"#,
            br#"{"data":[]}"#,
        ] {
            assert!(decode_json::<Envelope<DbCreds>>(bad).is_err(), "{bad:?}");
        }
        let empty: Envelope<DbCreds> = decode_json(br#"{"data":null}"#).expect("parses");
        assert!(empty.split().is_err());
        let id = format!(
            r#"{{"lease_id":"{}","data":{{"username":"u","password":"p"}}}}"#,
            "l".repeat(1025)
        );
        assert!(decode_json::<Envelope<DbCreds>>(id.as_bytes()).is_err());
    }

    #[test]
    #[allow(clippy::many_single_char_names)] // one short name per response shape
    fn pki_ssh_and_renew_shapes() {
        let p: Envelope<PkiIssued> = decode_json(
            br#"{"data":{"certificate":"C","private_key":"K","ca_chain":["A","B"],"serial_number":"0a:1b"}}"#,
        )
        .expect("pki");
        let (_, d) = p.split().expect("s");
        assert_eq!(d.ca_chain.len(), 2);
        assert!(serial_ok(&d.serial_number));
        let many: Vec<String> = (0..17).map(|_| "\"x\"".to_owned()).collect();
        let body = format!(
            r#"{{"data":{{"certificate":"C","private_key":"K","ca_chain":[{}]}}}}"#,
            many.join(",")
        );
        assert!(decode_json::<Envelope<PkiIssued>>(body.as_bytes()).is_err());
        let s: Envelope<SshSigned> =
            decode_json(br#"{"data":{"signed_key":"ssh-ed25519-cert-v01@openssh.com AAAA","serial_number":"1"}}"#)
                .expect("sign");
        assert!(s.split().is_ok());
        assert!(decode_json::<Envelope<SshSigned>>(br#"{"data":{"signed_key":1}}"#).is_err());
        let o: Envelope<SshOtp> =
            decode_json(br#"{"lease_id":"ssh/creds/otp/1","data":{"key":"k-1","key_type":"otp","username":"u"}}"#)
                .expect("otp");
        assert!(!format!("{o:?}").contains("k-1"), "no values in Debug");
        assert_eq!(o.split().expect("s").1.key_type, "otp");
        let r: Renewed =
            decode_json(br#"{"lease_id":"a/b","lease_duration":60,"renewable":true}"#).expect("r");
        assert_eq!(r.lease_duration, 60);
        for s in ["", "0a:", "zz", "0a:1", &"0a:".repeat(60)] {
            assert!(!serial_ok(s), "{s}");
        }
    }
}
