//! Fuzz entries for QA's cargo-fuzz targets (ADR-0016 test plan): `vault_kv_response`,
//! `vault_login_response`, `oidc_callback_url`; `external_ref_parse` is
//! `mooring_core::credential::fuzz_external_ref`. ADR-0026: `vault_db_creds`,
//! `vault_ssh_sign`, `vault_pki_issue`, `connect_item_json`, `bws_secret_json`;
//! `op_reference_parse` is `mooring_core::credential::fuzz_op_reference`. None may panic.

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

/// `database/creds` (and `ssh/creds` OTP, `sys/leases/renew`) bodies, then the mapping.
pub fn fuzz_vault_db_creds(data: &[u8]) {
    use crate::wire_dynamic::{DbCreds, Envelope, Renewed, SshOtp};
    if let Ok(e) = decode_json::<Envelope<DbCreds>>(data) {
        if let Ok((_, d)) = e.split() {
            let map = crate::wire::SecretMap::from_values(vec![
                ("username".to_owned(), d.username),
                ("password".to_owned(), d.password),
            ]);
            let _ = crate::resolve::build(CredentialKind::UserPassword, None, &map, 0);
        }
    }
    let _ = decode_json::<Envelope<SshOtp>>(data).map(Envelope::split);
    let _ = decode_json::<Renewed>(data);
}

/// `ssh/sign` bodies, then the certificate check against a fixed key.
pub fn fuzz_vault_ssh_sign(data: &[u8]) {
    use crate::wire_dynamic::{Envelope, SshSigned};
    if let Ok(Ok((_, d))) = decode_json::<Envelope<SshSigned>>(data).map(Envelope::split) {
        let key = mooring_core::credential::testdata::SSH_CA_SUBJECT_PUB;
        let _ = mooring_core::credential::check_signed_certificate(&d.signed_key, key, 1);
    }
}

/// `pki/issue` bodies, then the `x509` validators.
pub fn fuzz_vault_pki_issue(data: &[u8]) {
    use crate::wire_dynamic::{serial_ok, Envelope, PkiIssued};
    if let Ok(Ok((_, d))) = decode_json::<Envelope<PkiIssued>>(data).map(Envelope::split) {
        let _ = serial_ok(&d.serial_number);
        let map = crate::wire::SecretMap::from_values(vec![
            (
                "cert_pem".to_owned(),
                crate::wire::SecretValue(zeroize::Zeroizing::new(d.certificate)),
            ),
            ("key_pem".to_owned(), d.private_key),
        ]);
        let _ = crate::resolve::build(CredentialKind::X509, None, &map, 0);
    }
}

/// A Connect item (and summary lists), then the mapping onto every target kind, both as
/// a whole item and as one field.
pub fn fuzz_connect_item_json(data: &[u8]) {
    use crate::op_wire::{item_values, Capped, Item, ItemSummary, VaultSummary};
    let _ = decode_json::<Capped<VaultSummary, 1000>>(data);
    let _ = decode_json::<Capped<ItemSummary, 1000>>(data);
    let Ok(item) = decode_json::<Item>(data) else { return };
    let whole = mooring_core::credential::OpReference {
        vault: "v".into(),
        item: "i".into(),
        section: None,
        field: None,
    };
    let field =
        mooring_core::credential::OpReference { field: Some("password".into()), ..whole.clone() };
    for kind in CredentialKind::ALL.into_iter().filter(|k| k.is_ref_target()) {
        for r in [&whole, &field] {
            if let Ok(map) = item_values(&item, r, kind, None) {
                let _ = crate::resolve::build(kind, None, &map, 0);
            }
        }
    }
}

/// `bws secret get` / `secret list` / `project list` output, then the value mapping.
pub fn fuzz_bws_secret_json(data: &[u8]) {
    use crate::bws_wire::{by_key, one_secret, resolve_value, BwsProjects};
    let _ = decode_json::<BwsProjects>(data);
    let _ = by_key(data, "k");
    if let Ok(s) = one_secret(data, "3b5c1e02-1d2a-4c8e-9f00-0123456789ab") {
        for kind in [CredentialKind::ApiToken, CredentialKind::UserPassword, CredentialKind::SshKey]
        {
            let _ = resolve_value(&s.value, kind, None);
        }
    }
    let _ = crate::bws::fuzz_version(data);
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
            dynamic(s);
        }
        for s in [
            &br#"{"lease_id":"database/creds/r/1","lease_duration":60,"data":{"username":"u","password":"p"}}"#[..],
            br#"{"data":{"signed_key":"ssh-ed25519-cert-v01@openssh.com AAAA"}}"#,
            br#"{"data":{"certificate":"-----BEGIN CERTIFICATE-----","private_key":"k","ca_chain":[]}}"#,
            br#"{"id":"abcdefghijklmnopqrstuvwxyz","fields":[{"id":"password","label":"password","value":"p"},{"id":"x","label":"password","value":"q"}]}"#,
            br#"{"id":"3b5c1e02-1d2a-4c8e-9f00-0123456789ab","key":"k","value":"{\"username\":\"u\"}"}"#,
            br#"[{"id":"a","key":"k","value":"v"}]"#,
            b"bws 1.0.0",
        ] {
            dynamic(s);
        }
    }

    fn dynamic(s: &[u8]) {
        fuzz_vault_db_creds(s);
        fuzz_vault_ssh_sign(s);
        fuzz_vault_pki_issue(s);
        fuzz_connect_item_json(s);
        fuzz_bws_secret_json(s);
    }

    proptest! {
        #[test]
        fn never_panic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            fuzz_kv_response(&data);
            fuzz_login_response(&data);
            fuzz_oidc_callback_url(&data);
            dynamic(&data);
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
