//! Tests of the kind table.

use super::*;

#[test]
fn every_kind_has_one_row() {
    for k in K::ALL {
        assert_eq!(KINDS.iter().filter(|s| s.kind == k).count(), 1, "{k:?}");
        assert_eq!(schema_of(k).kind, k);
    }
}

#[test]
fn secret_fields_are_known_secret_names_and_plain_fields_are_not() {
    for s in credential_kinds() {
        for f in s.fields {
            assert_eq!(
                f.secret,
                SecretName::parse(f.name).is_some(),
                "{}.{}",
                s.kind.name(),
                f.name
            );
            assert!(f.copyable <= f.secret, "only secrets copy");
        }
        assert_eq!(s.secret(SecretName::OtpSeed).is_some(), s.supports_otp);
    }
}

#[test]
fn wire_shape_is_camel_case_with_protocol_wire_names() {
    let json = serde_json::to_value(credential_kinds()).expect("json");
    let ua = &json[1];
    assert_eq!(ua["kind"], "domain_user");
    assert_eq!(ua["supportsOtp"], true);
    assert_eq!(ua["protocols"][3]["protocol"], "vsphere-console");
    assert_eq!(ua["protocols"][1]["roles"], serde_json::json!(["primary", "gateway"]));
    assert_eq!(ua["fields"][0]["validation"]["format"], "netbios_or_upn");
    assert_eq!(ua["fields"][0]["validation"]["maxBytes"], 256);
    assert!(ua["fields"][0]["validation"].get("options").is_none());
    let kube = &json[8];
    assert_eq!(kube["fields"][1]["validation"]["format"], "enum");
    assert!(kube["fields"][1]["validation"].get("options").is_none(), "options come from contexts");
}
