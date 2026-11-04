use super::*;
use crate::credential::testdata::{placeholder_key_pem, CERT_PEM};
use serde_json::json;

#[test]
fn empty_object_gives_owner_defaults() {
    let rdp = ProtocolOptions::from_json(Protocol::Rdp, "{}").expect("rdp");
    assert_eq!(rdp, ProtocolOptions::Rdp(RdpConnOptions::default()));
    let ProtocolOptions::Vnc(vnc) = ProtocolOptions::from_json(Protocol::Vnc, "{}").expect("vnc")
    else {
        panic!("vnc");
    };
    assert_eq!(vnc.security, VncSecurity::PreferTls, "owner decision 4");
    assert!(vnc.shared && !vnc.view_only);
    assert_eq!(vnc.clipboard, ClipboardPolicy::Both);
    assert!(ProtocolOptions::from_json(Protocol::Ssh, "{}").is_ok());
    assert!(ProtocolOptions::from_json(Protocol::Web, "{}").is_err(), "web needs a url");
    let web = WebConnOptions { url: "https://app.example.test".into(), ..Default::default() };
    assert!(!web.persistent, "ephemeral by default (owner decision 7)");
}

#[test]
fn wire_is_camel_case_and_round_trips() {
    let o = ProtocolOptions::Rdp(RdpConnOptions {
        keyboard_layout: 0x1_041F,
        clipboard: ClipboardPolicy::ToRemote,
        allow_tls_without_nla: true,
        ca_pem: None,
        max_fps: MaxFps::Sixty,
    });
    let text = o.to_json().expect("json");
    assert_eq!(
        text,
        r#"{"keyboardLayout":66591,"clipboard":"to_remote","allowTlsWithoutNla":true,"caPem":null,"maxFps":60}"#
    );
    assert_eq!(ProtocolOptions::from_json(Protocol::Rdp, &text).expect("back"), o);
    let vnc = ProtocolOptions::Vnc(VncConnOptions::default()).to_json().expect("json");
    assert!(vnc.contains(r#""security":"prefer_tls""#) && vnc.contains(r#""viewOnly":false"#));
    assert_eq!(ProtocolOptions::default_for(Protocol::Ssh).to_json().expect("json"), "{}");
    assert_eq!(MaxFps::Thirty.interval(), Duration::from_millis(33));
    assert_eq!(MaxFps::Sixty.interval(), Duration::from_millis(16));
}

#[test]
fn unknown_fields_wrong_protocol_and_closed_lists_are_refused() {
    let e = ProtocolOptions::from_value(Protocol::Rdp, json!({"jpeg": true}))
        .expect_err("unknown field");
    assert!(e.to_string().contains("unknown field jpeg"), "{e}");
    // VNC options under an RDP connection: `security` is not an RDP field.
    assert!(ProtocolOptions::from_value(Protocol::Rdp, json!({"security": "require_tls"})).is_err());
    assert!(ProtocolOptions::from_value(Protocol::Ssh, json!({"maxFps": 30})).is_err());
    assert!(ProtocolOptions::from_value(Protocol::Rdp, json!({"keyboardLayout": 1234})).is_err());
    let e = ProtocolOptions::from_value(Protocol::Vnc, json!({"maxFps": 45})).expect_err("fps");
    assert!(e.to_string().contains("30 or 60"), "{e}");
    let e = ProtocolOptions::from_value(Protocol::Vnc, json!({"security": "<script>"}))
        .expect_err("variant");
    assert!(!e.to_string().contains("script"), "no echo: {e}");
    assert!(ProtocolOptions::from_value(Protocol::Vnc, json!([])).is_err());
    assert!(ProtocolOptions::from_json(Protocol::Vnc, "not json").is_err());
    let big = format!(r#"{{"caPem":"{}"}}"#, "A".repeat(MAX_OPTIONS_JSON));
    assert!(ProtocolOptions::from_json(Protocol::Vnc, &big).is_err());
    for kl in KEYBOARD_LAYOUTS {
        assert!(ProtocolOptions::from_value(Protocol::Rdp, json!({ "keyboardLayout": kl })).is_ok());
    }
    assert!(ProtocolOptions::default_for(Protocol::Vnc).fits(Protocol::Vnc));
    assert!(!ProtocolOptions::default_for(Protocol::Vnc).fits(Protocol::Rdp));
    assert!(!ProtocolOptions::default_for(Protocol::VsphereConsole).fits(Protocol::Ssh));
    assert!(!ProtocolOptions::default_for(Protocol::Kubernetes).fits(Protocol::Ssh));
}

#[test]
fn ca_pem_accepts_certificates_only() {
    let ok = json!({ "caPem": CERT_PEM });
    assert!(ProtocolOptions::from_value(Protocol::Rdp, ok.clone()).is_ok());
    assert!(ProtocolOptions::from_value(Protocol::Vnc, ok).is_ok());
    let bundle = format!("{CERT_PEM}{}", placeholder_key_pem());
    let e = ProtocolOptions::from_value(Protocol::Rdp, json!({ "caPem": bundle }))
        .expect_err("key refused");
    assert!(e.to_string().starts_with("invalid caPem"), "{e}");
    assert!(!e.to_string().contains("PRIVATE"), "{e}");
    assert!(ProtocolOptions::from_value(Protocol::Vnc, json!({"caPem": "hello"})).is_err());
}

#[test]
fn web_url_and_origin_rules() {
    let web = |v: serde_json::Value| ProtocolOptions::from_value(Protocol::Web, v);
    assert!(web(json!({"url": "https://app.example.test/login?x=1"})).is_ok());
    assert!(web(json!({"url": "https://192.0.2.7:8443/"})).is_ok());
    assert!(web(json!({"url": "https://[2001:db8::1]:8443/"})).is_ok());
    assert!(web(json!({"url": "http://app.example.test"})).is_err());
    assert!(web(json!({"url": "http://app.example.test", "allowHttp": true})).is_ok());
    for bad in [
        "ftp://app.example.test",
        "https://user:pw@app.example.test",
        "https://",
        "https://app.example.test:0/",
        "https://app.example.test:99999/",
        "https://[2001:db8::1/",
        "https://*.example.test",
        "https://app.example.test/ space",
        "javascript:alert(1)",
        "app.example.test",
        // review 5 N-31: the RFC 6761 localhost zone is app surface on Windows.
        "https://tauri.localhost/",
        "https://ipc.localhost/",
        "https://IPC.LocalHost:8443/",
        "https://a.b.localhost./",
    ] {
        assert!(web(json!({ "url": bad })).is_err(), "{bad}");
    }
    assert!(
        web(json!({"url": "http://localhost:1420/", "allowHttp": true})).is_ok(),
        "plain localhost"
    );
    assert!(web(
        json!({"url": "https://a.example.test", "allowedOrigins": ["https://ipc.localhost"]})
    )
    .is_err());
    assert!(web(json!({"url": "https://a.example.test", "allowedOrigins": ["https://localhost"]}))
        .is_ok());
    for (host, sub) in [
        ("localhost", false),
        ("localhost.", false),
        ("tauri.localhost", true),
        ("TAURI.LOCALHOST.", true),
        ("a.b.localhost", true),
        (".localhost", false),
        ("notlocalhost", false),
        ("localhost.example.test", false),
    ] {
        assert_eq!(is_localhost_subdomain(host), sub, "{host}");
    }
    let origins: Vec<String> = (0..17).map(|i| format!("https://sso{i}.example.test")).collect();
    assert!(web(json!({"url": "https://a.example.test", "allowedOrigins": origins[..16]})).is_ok());
    assert!(web(json!({"url": "https://a.example.test", "allowedOrigins": origins})).is_err());
    assert!(web(json!({"url": "https://a.example.test",
                       "allowedOrigins": ["https://sso.example.test/path"]}))
    .is_err());
    let o = WebConnOptions { url: "HTTPS://App.Example.test:8443/x".into(), ..Default::default() };
    assert_eq!(o.origin().as_deref(), Some("https://app.example.test:8443"));
}

#[test]
fn clipboard_policy_directions() {
    use ClipboardPolicy as C;
    assert!(C::Both.allows_to_remote() && C::Both.allows_from_remote());
    assert!(C::ToRemote.allows_to_remote() && !C::ToRemote.allows_from_remote());
    assert!(!C::FromRemote.allows_to_remote() && C::FromRemote.allows_from_remote());
    assert!(!C::Off.allows_to_remote() && !C::Off.allows_from_remote());
}
