//! Fuzz entries for QA's cargo-fuzz targets (ADR-0016 test plan): `vault_kv_response`,
//! `vault_login_response`, `oidc_callback_url`; `external_ref_parse` is
//! `mooring_core::credential::fuzz_external_ref`. None may panic.

use mooring_core::CredentialKind;
use mooring_http::decode_json;

use crate::wire::{AuthResponse, DataResponse, KvData, LookupData};

/// A KV v2 read body, then the mapping into every target kind.
pub fn fuzz_kv_response(data: &[u8]) {
    let Ok(r) = decode_json::<DataResponse<KvData>>(data) else { return };
    let Some(d) = r.data else { return };
    let Some(map) = d.data else { return };
    for kind in CredentialKind::ALL.into_iter().filter(|k| k.is_ref_target()) {
        let _ = crate::resolve::build(kind, None, &map, 1);
    }
}

/// Login / renew / lookup bodies.
pub fn fuzz_login_response(data: &[u8]) {
    let _ = decode_json::<AuthResponse>(data);
    let _ = decode_json::<DataResponse<LookupData>>(data);
}

/// The OIDC redirect and `auth_url` parsers.
pub fn fuzz_oidc_callback_url(data: &[u8]) {
    crate::oidc::fuzz_oidc_callback_url(data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn seeds() {
        for s in [
            &br#"{"data":{"data":{"username":"u","password":"p"},"metadata":{"version":1}}}"#[..],
            br#"{"data":{"data":{"token":"t"}}}"#,
            br#"{"auth":{"client_token":"t","policies":["root"]}}"#,
            br#"{"data":{"policies":null,"ttl":1}}"#,
            b"\xff",
            b"",
        ] {
            fuzz_kv_response(s);
            fuzz_login_response(s);
            fuzz_oidc_callback_url(s);
        }
    }

    proptest! {
        #[test]
        fn never_panic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            fuzz_kv_response(&data);
            fuzz_login_response(&data);
            fuzz_oidc_callback_url(&data);
        }

        #[test]
        fn kv_objects_never_panic(pairs in proptest::collection::vec(("[a-z_]{1,12}", ".{0,40}"), 0..8)) {
            let obj: serde_json::Map<String, serde_json::Value> =
                pairs.into_iter().map(|(k, v)| (k, serde_json::Value::String(v))).collect();
            let body = serde_json::json!({"data": {"data": obj, "metadata": {"version": 2}}});
            fuzz_kv_response(body.to_string().as_bytes());
        }
    }
}
