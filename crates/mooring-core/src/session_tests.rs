use super::*;

#[test]
fn prompt_purpose_is_snake_case_on_the_wire() {
    for (p, wire) in [
        (PromptPurpose::HostKeyTrust, "\"host_key_trust\""),
        (PromptPurpose::CertificateTrust, "\"certificate_trust\""),
        (PromptPurpose::KeyboardInteractive, "\"keyboard_interactive\""),
        (PromptPurpose::Credential, "\"credential\""),
        (PromptPurpose::Other, "\"other\""),
    ] {
        assert_eq!(serde_json::to_string(&p).expect("ser"), wire);
        assert_eq!(serde_json::from_str::<PromptPurpose>(wire).expect("de"), p);
    }
}

#[test]
fn secrets_never_print() {
    let s = ConnectSecret::Password(SecretString::from("hunter2".to_owned()));
    let shown = format!("{s:?}");
    assert!(!shown.contains("hunter2"));
    assert!(shown.contains("redacted"));
}

#[test]
fn answer_text_never_prints_or_serialises() {
    let input: SessionInput =
        serde_json::from_str(r#"{"kind":"answer","id":7,"text":"otp-314159"}"#)
            .expect("answer deserialises");
    let SessionInput::Answer { id, ref text } = input else {
        panic!("expected Answer");
    };
    assert_eq!(id, 7);
    assert_eq!(secrecy::ExposeSecret::expose_secret(text), "otp-314159");

    let debug = format!("{input:?}");
    assert!(!debug.contains("otp-314159"), "{debug}");
    assert!(debug.contains("<redacted>") && debug.contains('7'));

    let json = serde_json::to_string(&input).expect("serialises");
    assert!(!json.contains("otp-314159"), "{json}");
    assert!(json.contains(r#""text":"<redacted>""#), "{json}");

    let cloned = format!("{:?}", input.clone());
    assert!(!cloned.contains("otp-314159"));
}

#[test]
fn credential_answer_never_prints_or_serialises_the_password() {
    let input: SessionInput = serde_json::from_str(
        r#"{"kind":"credential_answer","id":3,"username":"CORP\\bob","domain":null,"password":"pw-271828"}"#,
    )
    .expect("deserialises");
    let SessionInput::CredentialAnswer { id, ref username, ref domain, ref password } = input
    else {
        panic!("expected CredentialAnswer");
    };
    assert_eq!((id, username.as_str(), domain.as_deref()), (3, "CORP\\bob", None));
    assert_eq!(secrecy::ExposeSecret::expose_secret(password), "pw-271828");
    let debug = format!("{input:?}");
    assert!(!debug.contains("pw-271828") && debug.contains("<redacted>"), "{debug}");
    let json = serde_json::to_string(&input).expect("ser");
    assert!(!json.contains("pw-271828"), "{json}");
    let no_domain: SessionInput =
        serde_json::from_str(r#"{"kind":"credential_answer","id":1,"username":"","password":""}"#)
            .expect("domain optional");
    assert!(matches!(no_domain, SessionInput::CredentialAnswer { domain: None, .. }));
}

#[test]
fn credential_prompt_wire_shape() {
    let e = SessionEvent::Prompt {
        id: 1,
        message: "Sign in".into(),
        secret: true,
        purpose: PromptPurpose::Credential,
        account: Some(PromptAccount {
            username: Some("alice".into()),
            domain: None,
            needs_username: false,
            needs_domain: true,
        }),
        certificate: None,
        hop: None,
    };
    let v = serde_json::to_value(&e).expect("json");
    assert_eq!(v["purpose"], "credential");
    assert_eq!(v["account"]["needs_domain"], true);
}

#[test]
fn other_inputs_keep_their_debug_and_wire_form() {
    let input = SessionInput::Bytes { data: vec![1, 2] };
    assert_eq!(format!("{input:?}"), "Bytes { data: [1, 2] }");
    let json = serde_json::to_string(&input).expect("serialises");
    assert_eq!(json, r#"{"kind":"bytes","data":[1,2]}"#);
    let resize: SessionInput =
        serde_json::from_str(r#"{"kind":"resize","size":{"width":80,"height":24}}"#)
            .expect("resize deserialises");
    assert!(format!("{resize:?}").contains("width: 80"));
}

#[test]
fn closed_carries_a_code_and_connected_a_security() {
    let e = SessionEvent::Closed { reason: "x".into(), code: CloseCode::TrustMismatch };
    let v = serde_json::to_value(&e).expect("json");
    assert_eq!(v["code"], "trust_mismatch");
    for (c, wire, retry) in [
        (CloseCode::User, "user", false),
        (CloseCode::Network, "network", true),
        (CloseCode::AuthFailed, "auth_failed", false),
        (CloseCode::TrustRejected, "trust_rejected", false),
        (CloseCode::TrustMismatch, "trust_mismatch", false),
        (CloseCode::TrustConflict, "trust_conflict", false),
        (CloseCode::ServerEnded, "server_ended", true),
        (CloseCode::ProtocolError, "protocol_error", false),
        (CloseCode::VaultLocked, "vault_locked", false),
        (CloseCode::HopFailed, "hop_failed", false),
        (CloseCode::HopLost, "hop_lost", true),
    ] {
        assert_eq!(serde_json::to_value(c).expect("json"), wire);
        assert_eq!(c.is_retryable(), retry, "{wire}");
    }
    let c = SessionEvent::Connected {
        protocol: Protocol::Rdp,
        peer_identity: Some("x509 SHA256:00".into()),
        security: Some("nla".into()),
        hop: None,
    };
    let v = serde_json::to_value(&c).expect("json");
    assert_eq!((v["kind"].as_str(), v["security"].as_str()), (Some("connected"), Some("nla")));
    let r = serde_json::to_value(SessionEvent::DesktopResized { width: 1920, height: 1080 })
        .expect("json");
    assert_eq!(r, serde_json::json!({"kind": "desktop_resized", "width": 1920, "height": 1080}));
}

#[test]
fn certificate_prompt_wire_shape() {
    let t = time::OffsetDateTime::UNIX_EPOCH;
    let cert = CertificateInfo::new(
        b"der",
        "CN=rdp.example.test",
        "CN=rdp.example.test",
        t,
        t,
        &["rdp.example.test".to_owned()],
        vec![crate::known_certs::CertProblem::SelfSigned],
    );
    let e = SessionEvent::Prompt {
        id: 4,
        message: "Unknown certificate".into(),
        secret: false,
        purpose: PromptPurpose::CertificateTrust,
        account: None,
        certificate: Some(cert),
        hop: None,
    };
    let v = serde_json::to_value(&e).expect("json");
    assert_eq!(v["purpose"], "certificate_trust");
    assert_eq!(v["certificate"]["problems"][0], "self_signed");
    assert_eq!(v["certificate"]["sha256"].as_str().map(str::len), Some(64));
}

#[test]
fn graphical_inputs_wire_and_validation() {
    let parse = |s: &str| serde_json::from_str::<SessionInput>(s).expect(s);
    let key = parse(r#"{"kind":"key","code":"KeyA","key":"a","pressed":true}"#);
    assert!(key.validate().is_ok());
    let shown = format!("{key:?}");
    assert!(!shown.contains("KeyA") && shown.contains(REDACTED), "{shown}");
    let wheel = parse(r#"{"kind":"wheel","dx":0,"dy":-120}"#);
    assert!(matches!(wheel, SessionInput::Wheel { dx: 0, dy: -120 }));
    assert!(matches!(parse(r#"{"kind":"release_all"}"#), SessionInput::ReleaseAll));
    assert!(matches!(parse(r#"{"kind":"clipboard_offer"}"#), SessionInput::ClipboardOffer));
    let uni = parse(r#"{"kind":"unicode","text":"ğüşİ"}"#);
    assert!(uni.validate().is_ok());
    assert!(!format!("{uni:?}").contains('ğ'));
    assert!(
        serde_json::from_str::<SessionInput>(r#"{"kind":"key","scancode":1,"pressed":true}"#)
            .is_err(),
        "the A1 scancode form is gone"
    );

    let key = |code: &str, k: &str| SessionInput::Key {
        code: code.into(),
        key: k.into(),
        pressed: false,
    };
    assert!(key("", "a").validate().is_err());
    assert!(key(&"A".repeat(MAX_KEY_CODE + 1), "a").validate().is_err());
    assert!(key("Key-A", "a").validate().is_err());
    assert!(key("KeyA", &"x".repeat(MAX_KEY_KEY + 1)).validate().is_err());
    assert!(key("KeyA", "\u{7}").validate().is_err());
    assert!(key("Enter", "Enter").validate().is_ok());
    let text = |t: &str| SessionInput::Unicode { text: t.into() };
    assert!(text("").validate().is_err());
    assert!(text(&"ş".repeat(MAX_UNICODE_CHARS)).validate().is_ok());
    assert!(text(&"ş".repeat(MAX_UNICODE_CHARS + 1)).validate().is_err());
    assert!(text("a\nb").validate().is_err());
}

#[test]
fn audit_events_default_to_empty() {
    struct Dummy;
    #[async_trait]
    impl Session for Dummy {
        fn protocol(&self) -> Protocol {
            Protocol::Vnc
        }
        async fn send(&mut self, _input: SessionInput) -> Result<()> {
            Ok(())
        }
        async fn next_event(&mut self) -> Result<Option<SessionEvent>> {
            Ok(None)
        }
        async fn close(&mut self) -> Result<()> {
            Ok(())
        }
    }
    assert!(Dummy.take_audit_events().is_empty());
}

#[test]
fn hop_status_and_hop_tagged_prompt_wire_shape() {
    let e = SessionEvent::HopStatus {
        hop: 1,
        of: 2,
        state: HopState::Up,
        host: "bastion.example.test:22".into(),
        peer_identity: Some("ssh-ed25519 SHA256:00".into()),
    };
    let v = serde_json::to_value(&e).expect("json");
    assert_eq!(v["kind"], "hop_status");
    assert_eq!((v["hop"].as_u64(), v["of"].as_u64()), (Some(1), Some(2)));
    assert_eq!(v["state"], "up");
    for (s, wire) in [
        (HopState::Connecting, "connecting"),
        (HopState::Authenticating, "authenticating"),
        (HopState::Up, "up"),
        (HopState::Failed, "failed"),
    ] {
        assert_eq!(serde_json::to_value(s).expect("json"), wire);
        assert_eq!(s.as_str(), wire);
    }
    let p = SessionEvent::Prompt {
        id: 7,
        message: "Hop 1 — trust?".into(),
        secret: false,
        purpose: PromptPurpose::HostKeyTrust,
        account: None,
        certificate: None,
        hop: Some(0),
    };
    let v = serde_json::to_value(&p).expect("json");
    assert_eq!(v["hop"], 0);
    // The target's events carry no `hop` field at all (old UI builds keep working).
    let p = SessionEvent::Prompt {
        id: 8,
        message: "trust?".into(),
        secret: false,
        purpose: PromptPurpose::HostKeyTrust,
        account: None,
        certificate: None,
        hop: None,
    };
    assert!(serde_json::to_value(&p).expect("json").get("hop").is_none());
}
