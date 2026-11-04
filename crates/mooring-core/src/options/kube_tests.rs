//! `KubeConnOptions` (ADR-0014 §3, owner decisions 2 and 3).

use super::*;
use crate::credential::testdata::{placeholder_key_pem, CERT_PEM};
use crate::CredentialKind;
use proptest::prelude::*;
use serde_json::json;

fn kube(v: serde_json::Value) -> Result<ProtocolOptions> {
    ProtocolOptions::from_value(Protocol::Kubernetes, v)
}

fn opts(v: serde_json::Value) -> KubeConnOptions {
    match kube(v).expect("valid") {
        ProtocolOptions::Kube(o) => o,
        other => panic!("{other:?}"),
    }
}

#[test]
fn empty_object_gives_owner_defaults() {
    let o = opts(json!({}));
    assert_eq!(o, KubeConnOptions::default());
    assert_eq!(o.exec_command, ExecCommand::BinSh);
    assert_eq!((o.log_tail_lines, o.max_log_bytes), (1000, 8 * 1024 * 1024));
    assert!(o.port_forward_enabled && o.allowed_namespaces.is_empty());
    assert!(ProtocolOptions::default_for(Protocol::Kubernetes).fits(Protocol::Kubernetes));
    assert_eq!(
        ProtocolOptions::from_json(Protocol::Kubernetes, "{}").expect("migration"),
        ProtocolOptions::Kube(o)
    );
}

#[test]
fn wire_is_camel_case_and_round_trips() {
    let o = ProtocolOptions::Kube(KubeConnOptions {
        context: Some("lab".into()),
        namespace: Some("apps".into()),
        allowed_namespaces: vec!["apps".into(), "web".into()],
        exec_command: ExecCommand::BinBash,
        ..KubeConnOptions::default()
    });
    let text = o.to_json().expect("json");
    assert_eq!(
        text,
        r#"{"context":"lab","server":null,"caPem":null,"tlsServerName":null,"namespace":"apps","allowedNamespaces":["apps","web"],"execCommand":"/bin/bash","logTailLines":1000,"maxLogBytes":8388608,"portForwardEnabled":true}"#
    );
    assert_eq!(ProtocolOptions::from_json(Protocol::Kubernetes, &text).expect("back"), o);
    for c in ExecCommand::ALL {
        let v = serde_json::to_value(c).expect("ser");
        assert_eq!(v, json!(c.as_str()));
        assert_eq!(ExecCommand::parse(c.as_str()), Some(c));
        assert!(kube(json!({ "execCommand": c.as_str() })).is_ok());
    }
}

#[test]
fn validation_table() {
    let ok = [
        json!({"server": "https://k8s.example.test:6443", "caPem": CERT_PEM}),
        json!({"server": "https://192.0.2.10/k8s/clusters/c-1"}),
        json!({"tlsServerName": "api.example.test"}),
        json!({"logTailLines": 1}),
        json!({"logTailLines": 100_000}),
        json!({"maxLogBytes": 1}),
        json!({"maxLogBytes": 64 * 1024 * 1024}),
        json!({"portForwardEnabled": false}),
        json!({"allowedNamespaces": (0..64).map(|i| format!("ns{i}")).collect::<Vec<_>>()}),
    ];
    for v in ok {
        assert!(kube(v.clone()).is_ok(), "{v}");
    }
    let bad = [
        (json!({"execCommand": "/bin/zsh"}), "exec allow-list"),
        (json!({"execCommand": "sh -c id"}), "no custom argv"),
        (json!({"execCommand": ["/bin/sh", "-c", "id"]}), "argv array"),
        (json!({"logTailLines": 0}), "tail 0"),
        (json!({"logTailLines": 100_001}), "tail max"),
        (json!({"logTailLines": -1}), "tail negative"),
        (json!({"maxLogBytes": 0}), "bytes 0"),
        (json!({"maxLogBytes": 64 * 1024 * 1024 + 1}), "bytes max"),
        (json!({"server": "http://k8s.example.test"}), "http"),
        (json!({"server": "https://u:p@k8s.example.test"}), "userinfo"),
        (json!({"caPem": "hello"}), "ca not pem"),
        (json!({"caPem": format!("{CERT_PEM}{}", placeholder_key_pem())}), "key in ca"),
        (json!({"namespace": "Kube_System"}), "namespace"),
        (json!({"tlsServerName": "API.example.test"}), "sni upper"),
        (json!({"allowedNamespaces": ["a", "a"]}), "dup ns"),
        (
            json!({"allowedNamespaces": (0..65).map(|i| format!("ns{i}")).collect::<Vec<_>>()}),
            "65 ns",
        ),
        (json!({"context": ""}), "empty context"),
        (json!({"context": "a\u{202e}b"}), "bidi context"),
        (json!({"insecureSkipTlsVerify": true}), "no skip option"),
        (json!({"customArgv": ["/bin/sh"]}), "unknown field"),
    ];
    for (v, why) in bad {
        let e = kube(v).expect_err(why);
        let msg = e.to_string();
        assert!(
            !msg.contains("zsh") && !msg.contains("u:p") && !msg.contains("PRIVATE"),
            "{why}: {msg}"
        );
    }
}

#[test]
fn credential_kind_rules() {
    let token = opts(json!({"server": "https://k8s.example.test", "caPem": CERT_PEM}));
    assert!(token.check_credential(CredentialKind::KubeToken).is_ok());
    assert_eq!(token.server_url().map(|s| s.port()), Some(443));
    assert!(
        token.check_credential(CredentialKind::Kubeconfig).is_err(),
        "server refused for kubeconfig"
    );
    let no_ca = opts(json!({"server": "https://k8s.example.test"}));
    assert!(no_ca.check_credential(CredentialKind::KubeToken).is_err(), "caPem required");
    let none = KubeConnOptions::default();
    assert!(none.check_credential(CredentialKind::KubeToken).is_err(), "server required");
    assert!(none.check_credential(CredentialKind::Kubeconfig).is_ok());
    let ctx =
        opts(json!({"server": "https://k8s.example.test", "caPem": CERT_PEM, "context": "x"}));
    assert!(ctx.check_credential(CredentialKind::KubeToken).is_err(), "no context for a token");
    assert!(opts(json!({"context": "x"})).check_credential(CredentialKind::Kubeconfig).is_ok());
}

#[test]
fn kube_credentials_fill_kubernetes_sign_in_only() {
    use crate::credential::{incompatibility_reason, valid_for};
    use crate::Role;
    for k in [CredentialKind::Kubeconfig, CredentialKind::KubeToken] {
        assert!(valid_for(k, Protocol::Kubernetes, Role::Primary), "{k:?}");
        assert!(!valid_for(k, Protocol::Kubernetes, Role::Gateway), "{k:?}");
        assert!(!valid_for(k, Protocol::Kubernetes, Role::Become), "{k:?}");
        for p in
            [Protocol::Ssh, Protocol::Rdp, Protocol::Vnc, Protocol::Web, Protocol::VsphereConsole]
        {
            assert!(!valid_for(k, p, Role::Primary), "{k:?} {p:?}");
        }
    }
    assert!(valid_for(CredentialKind::X509, Protocol::Kubernetes, Role::Primary));
    let r =
        incompatibility_reason(CredentialKind::UserPassword, Protocol::Kubernetes, Role::Primary);
    assert_eq!(r.as_deref(), Some("Kubernetes removed static basic auth."));
}

proptest! {
    #[test]
    fn tail_and_bytes_ranges(tail in 0u32..200_000, bytes in 0u64..(70 * 1024 * 1024)) {
        let ok = kube(json!({"logTailLines": tail, "maxLogBytes": bytes})).is_ok();
        prop_assert_eq!(ok, LOG_TAIL_LINES.contains(&tail) && MAX_LOG_BYTES.contains(&bytes));
    }

    #[test]
    fn exec_command_is_closed(s in "\\PC{0,24}") {
        let ok = kube(json!({"execCommand": s})).is_ok();
        prop_assert_eq!(ok, ExecCommand::parse(&s).is_some());
    }
}
