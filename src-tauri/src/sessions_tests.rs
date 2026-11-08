use super::*;

#[test]
fn wire_events_are_base64_and_snake_case() {
    let e = WireEvent::from(SessionEvent::Bytes { data: b"hi\r\n".to_vec() });
    assert_eq!(
        serde_json::to_string(&e).expect("json"),
        r#"{"kind":"bytes","data":"aGkNCg=="}"#
    );
    let e = WireEvent::from(SessionEvent::Connected {
        protocol: Protocol::Rdp,
        peer_identity: Some("x509 SHA256:ab".into()),
        security: Some("nla".into()),
        hop: None,
    });
    let json = serde_json::to_string(&e).expect("json");
    assert!(json.contains(r#""protocol":"rdp""#), "{json}");
    assert!(json.contains(r#""security":"nla""#), "{json}");
    let e = WireEvent::from(SessionEvent::Closed {
        reason: "gone".into(),
        code: CloseCode::TrustMismatch,
    });
    assert_eq!(
        serde_json::to_string(&e).expect("json"),
        r#"{"kind":"closed","reason":"gone","code":"trust_mismatch"}"#
    );
    let e = WireEvent::Reconnecting { attempt: 2, delay_ms: 1900 };
    assert_eq!(
        serde_json::to_string(&e).expect("json"),
        r#"{"kind":"reconnecting","attempt":2,"delay_ms":1900}"#
    );
    let e = WireEvent::from(SessionEvent::DesktopResized { width: 1280, height: 720 });
    assert_eq!(
        serde_json::to_string(&e).expect("json"),
        r#"{"kind":"desktop_resized","width":1280,"height":720}"#
    );
}

#[test]
fn phases_round_trip() {
    for p in [Phase::Connecting, Phase::Connected, Phase::Closed, Phase::Reconnecting] {
        assert_eq!(Phase::from_u8(p as u8), p);
    }
    assert_eq!(Phase::Reconnecting.as_str(), "reconnecting");
    assert_eq!(Phase::from_u8(9), Phase::Closed);
}

#[test]
fn the_cap_is_rechecked_under_the_registry_lock() {
    let max = crate::commands::sessions::MAX_SESSIONS;
    assert!(super::room_for_one(max - 1).is_ok());
    assert_eq!(super::room_for_one(max).expect_err("full").code, "session.failed");
}

#[test]
fn gateway_status_reaches_the_wire() {
    let e = WireEvent::from(SessionEvent::GatewayStatus {
        host: "gw01.example.test:443".into(),
        state: mooring_core::HopState::Authenticating,
        peer_identity: Some("x509 SHA256:ab".into()),
    });
    assert_eq!(
        serde_json::to_value(&e).expect("json"),
        serde_json::json!({"kind": "gateway_status", "host": "gw01.example.test:443",
                           "state": "authenticating", "peer_identity": "x509 SHA256:ab"})
    );
}
