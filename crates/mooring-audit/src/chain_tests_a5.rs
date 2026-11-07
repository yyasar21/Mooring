//! ADR-0026 audit rows: lease and `bws` events keep stable wire names, and an A3
//! `secret_resolved` row (no provider / engine) reads back byte-identically.

use super::*;

#[test]
fn dynamic_secret_events_have_stable_wire_names() {
    let s = |v: &str| v.to_owned();
    let cases = [
        (
            AuditEvent::SecretLeaseIssued {
                session: Some(s("s1")),
                source: s("s"),
                engine: s("database"),
                ttl: 60,
                renewable: true,
            },
            "secret_lease_issued",
        ),
        (
            AuditEvent::SecretLeaseRenewed { session: s("s1"), source: s("s"), ttl: 60 },
            "secret_lease_renewed",
        ),
        (
            AuditEvent::SecretLeaseRenewFailed {
                session: s("s1"),
                source: s("s"),
                category: s("network"),
            },
            "secret_lease_renew_failed",
        ),
        (
            AuditEvent::SecretLeaseRevoked {
                session: None,
                source: s("s"),
                reason: s("locked"),
                ok: true,
            },
            "secret_lease_revoked",
        ),
        (
            AuditEvent::SecretToolSpawned {
                provider: s("bitwarden"),
                action: s("secret_get"),
                exit: Some(0),
            },
            "secret_tool_spawned",
        ),
        (
            AuditEvent::SecretToolChanged { provider: s("bitwarden"), sha256: s("00") },
            "secret_tool_changed",
        ),
    ];
    for (e, name) in cases {
        let v = serde_json::to_value(&e).expect("json");
        assert_eq!(v["event"], name, "{v}");
    }
    // An A3 row (no provider / engine) reads back and re-serialises byte-identically.
    let a3 = r#"{"event":"secret_resolved","connection":null,"credential":"r","source":"s","reference":"secret/x","version":1,"target_kind":"api_token","fields":["token"]}"#;
    let e: AuditEvent = serde_json::from_str(a3).expect("A3 row");
    assert_eq!(serde_json::to_string(&e).expect("json"), a3);
}
