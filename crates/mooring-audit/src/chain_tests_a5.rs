//! ADR-0024 / ADR-0026 audit rows: lease and `bws` events keep stable wire names, and an A3
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

/// ADR-0024: the security-key rows carry a fingerprint and codes only.
#[test]
fn security_key_events_have_stable_wire_names() {
    let s = |v: &str| v.to_owned();
    let cases = [
        (
            AuditEvent::SessionSkAuth {
                connection: s("c"),
                fingerprint: s("SHA256:x"),
                backend: s("agent"),
                outcome: s("touch_timeout"),
            },
            serde_json::json!({"event": "session.auth_sk", "connection": "c",
                               "fingerprint": "SHA256:x", "backend": "agent",
                               "outcome": "touch_timeout"}),
        ),
        (
            AuditEvent::CredentialSkConverted { id: s("k") },
            serde_json::json!({"event": "credential.sk_converted", "id": "k"}),
        ),
        (
            AuditEvent::SessionRdpGateway {
                connection: s("c"),
                host: s("gw:443"),
                auth: s("ntlm"),
                outcome: s("ok"),
                tunnel_id: 7,
            },
            serde_json::json!({"event": "session.rdp.gateway", "connection": "c", "host": "gw:443",
                               "auth": "ntlm", "outcome": "ok", "tunnel_id": 7}),
        ),
        (
            AuditEvent::SessionRdpGatewayBasic { connection: s("c"), host: s("gw:443") },
            serde_json::json!({"event": "session.rdp.gateway_basic", "connection": "c", "host": "gw:443"}),
        ),
        (
            AuditEvent::CredentialPinPrompted {
                connection: s("c"),
                fingerprint: s("SHA256:x"),
                outcome: s("cancelled"),
            },
            serde_json::json!({"event": "credential.pin_prompted", "connection": "c",
                               "fingerprint": "SHA256:x", "outcome": "cancelled"}),
        ),
    ];
    for (e, want) in cases {
        let v = serde_json::to_value(&e).expect("json");
        assert_eq!(v, want);
        let back: AuditEvent = serde_json::from_value(v).expect("round trip");
        assert_eq!(back, e);
    }
}
