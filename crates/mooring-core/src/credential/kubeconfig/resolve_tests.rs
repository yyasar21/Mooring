//! `resolve` tests (ADR-0014 §3, K2): one valid shape per auth kind, and every refusal.

use super::*;
use crate::credential::testdata::{placeholder_key_pem, CERT_PEM, KUBECONFIG};
use data_encoding::BASE64;
use proptest::prelude::*;
use secrecy::ExposeSecret;

fn b64(s: &str) -> String {
    BASE64.encode(s.as_bytes())
}

/// Two clusters, two users (token, client cert), three contexts.
fn config() -> String {
    format!(
        "apiVersion: v1
kind: Config
current-context: lab
clusters:
- name: lab
  cluster:
    server: https://K8S.example.test:6443/
    certificate-authority-data: {ca}
    tls-server-name: api.example.test
- name: edge
  cluster:
    server: https://192.0.2.10
    insecure-skip-tls-verify: true
    disable-compression: true
contexts:
- name: lab
  context: {{cluster: lab, user: ops}}
- name: lab-cert
  context: {{cluster: lab, user: cert, namespace: kube-system}}
- name: edge
  context: {{cluster: edge, user: ops}}
users:
- name: ops
  user:
    token: test-only-token
- name: cert
  user:
    client-certificate-data: {cert}
    client-key-data: {key}
",
        ca = b64(CERT_PEM),
        cert = b64(CERT_PEM),
        key = b64(&placeholder_key_pem()),
    )
}

fn res(yaml: &str, ctx: Option<&str>) -> Result<Resolved, KubeResolveError> {
    resolve(yaml.as_bytes(), ctx)
}

#[test]
fn token_context_and_current_context_default() {
    let r = res(&config(), None).expect("current-context");
    assert_eq!(r.context_name, "lab");
    assert_eq!(r.server.as_str(), "https://k8s.example.test:6443");
    assert_eq!((r.server.host(), r.server.port(), r.server.path()), ("k8s.example.test", 6443, ""));
    assert_eq!(r.ca, CaSource::Pem(CERT_PEM.as_bytes().to_vec()));
    assert_eq!(r.tls_server_name.as_deref(), Some("api.example.test"));
    assert!(!r.insecure_skip && r.namespace.is_none());
    let KubeAuth::Token(t) = &r.auth else { panic!("token") };
    assert_eq!(t.expose_secret(), "test-only-token");
    let shown = format!("{r:?}");
    assert!(!shown.contains("test-only-token") && !shown.contains("BEGIN"), "{shown}");
}

#[test]
fn client_cert_and_named_contexts() {
    let r = res(&config(), Some("lab-cert")).expect("cert");
    assert_eq!(r.namespace.as_deref(), Some("kube-system"));
    let KubeAuth::ClientCert { cert_pem, key_pem } = &r.auth else { panic!("cert") };
    assert_eq!(cert_pem, CERT_PEM);
    assert_eq!(key_pem.expose_secret(), placeholder_key_pem().trim());
    assert!(!format!("{:?}", r.auth).contains("PRIVATE"));
    let e = res(&config(), Some("edge")).expect("edge");
    assert!(e.insecure_skip, "caller turns this into a TOFU prompt");
    assert_eq!(e.ca, CaSource::None);
    assert_eq!((e.server.host(), e.server.port()), ("192.0.2.10", 443));
    let not_found = Some(KubeResolveError::NotFound("context"));
    assert_eq!(res(&config(), Some("nope")).err(), not_found);
    let no_current = config().replace("current-context: lab\n", "");
    assert_eq!(res(&no_current, None).err(), Some(KubeResolveError::NoContext));
    let dangling = config().replace("current-context: lab", "current-context: gone");
    assert_eq!(res(&dangling, None).err(), Some(KubeResolveError::NoContext));
    assert!(res(&config(), Some("bad\u{7}name")).is_err());
}

#[test]
fn parser_refusals_still_apply() {
    let user = "    token: test-only-token";
    for (to, why) in [
        ("    exec:\n      command: /bin/sh", "exec"),
        ("    auth-provider:\n      name: oidc", "auth-provider"),
        ("    tokenFile: /var/run/token", "tokenFile"),
        ("    client-certificate: /home/u/c.crt", "client-certificate path"),
        ("    client-key: /home/u/c.key", "client-key path"),
        ("    Exec: {command: /bin/sh}", "case variant"),
        ("    to\u{212A}enFile: /var/run/token", "M-12 non-ASCII key"),
        ("    <<: {exec: {command: x}}", "merge key"),
    ] {
        let yaml = config().replace(user, to);
        let e = res(&yaml, None).expect_err(why);
        assert!(matches!(e, KubeResolveError::Rejected(_)), "{why}: {e:?}");
        assert_eq!(e.code(), "credential.kubeconfig_rejected");
        let msg = e.to_string();
        assert!(!msg.contains("/bin") && !msg.contains("/var") && !msg.contains("/home"), "{msg}");
    }
    let ca = config()
        .replace("    tls-server-name: api.example.test", "    certificate-authority: /etc/ca");
    assert!(matches!(res(&ca, None), Err(KubeResolveError::Rejected(_))), "CA path");
}

#[test]
fn unsupported_auth_is_typed() {
    let user = "    token: test-only-token";
    for (to, why) in [
        ("    username: admin\n    password: hunter2", "basic auth"),
        ("    password: hunter2", "password alone"),
        ("    token: t\n    as: system:admin", "impersonation"),
        ("    token: t\n    impersonate-groups: [system:masters]", "impersonation groups"),
        ("    token: t\n    Token2: x", "unknown field"),
        ("    extensions: []", "no auth at all"),
        ("    token: \"\"", "empty token"),
    ] {
        let e = res(&config().replace(user, to), None).expect_err(why);
        assert!(matches!(e, KubeResolveError::UnsupportedAuth(_)), "{why}: {e:?}");
        assert_eq!(e.code(), "kube.unsupported_auth");
        assert!(!e.to_string().contains("hunter2") && !e.to_string().contains("system:"), "{e}");
    }
    let both = config().replace(
        "    token: test-only-token",
        &format!("    token: t\n    client-certificate-data: {}", b64(CERT_PEM)),
    );
    assert!(matches!(res(&both, None), Err(KubeResolveError::UnsupportedAuth(_))), "ambiguous");
}

#[test]
fn field_refusals() {
    let c = config();
    let cases: Vec<(String, &str)> = vec![
        (c.replace("https://K8S.example.test:6443/", "http://k8s.example.test"), "http"),
        (c.replace("https://K8S.example.test:6443/", "https://u:p@k8s.example.test"), "userinfo"),
        (c.replace("https://K8S.example.test:6443/", "https://k8s.example.test/?a=1"), "query"),
        (c.replace("https://K8S.example.test:6443/", "https://k8s.example.test/../x"), "dots"),
        (c.replace("https://K8S.example.test:6443/", "https://k8s.example.test:0"), "port 0"),
        (
            c.replace(
                "    tls-server-name: api.example.test",
                "    proxy-url: http://192.0.2.1:3128",
            ),
            "proxy",
        ),
        (c.replace("    tls-server-name: api.example.test", "    extra: 1"), "unknown cluster key"),
        (
            c.replace("    tls-server-name: api.example.test", "    tls-server-name: bad name"),
            "sni",
        ),
        (c.replace("insecure-skip-tls-verify: true", "insecure-skip-tls-verify: yes"), "bool"),
        (c.replace("namespace: kube-system", "namespace: Kube_System"), "namespace"),
        (c.replace("{cluster: lab, user: ops}", "{cluster: lab, user: ops, extra: 1}"), "ctx key"),
        (c.replace("{cluster: lab, user: ops}", "{cluster: gone, user: ops}"), "cluster"),
        (c.replace("{cluster: lab, user: ops}", "{cluster: lab, user: gone}"), "user"),
        (c.replace("{cluster: lab, user: ops}", "{user: ops}"), "no cluster"),
        (c.replace("    token: test-only-token", "    token: \"a b\""), "token space"),
        (c.replace("    token: test-only-token", "    token: [a]"), "token list"),
        (c.replace("- name: edge\n  cluster:", "- name: lab\n  cluster:"), "dup"),
        (c.replace(&b64(CERT_PEM), "not=base64%"), "base64"),
        (c.replacen(&b64(CERT_PEM), &b64("hello"), 1), "CA not PEM"),
        (
            c.replacen(&b64(CERT_PEM), &b64(&format!("{CERT_PEM}{}", placeholder_key_pem())), 1),
            "key in CA",
        ),
        (
            c.replace(
                "    insecure-skip-tls-verify: true",
                &format!(
                    "    insecure-skip-tls-verify: true\n    certificate-authority-data: {}",
                    b64(CERT_PEM)
                ),
            ),
            "CA + skip",
        ),
    ];
    for (yaml, why) in &cases {
        let ctx = if *why == "namespace" { Some("lab-cert") } else { None };
        let ctx = if why.contains("bool") || why.contains("skip") { Some("edge") } else { ctx };
        let e = res(yaml, ctx).expect_err(why);
        assert!(!matches!(e, KubeResolveError::UnsupportedAuth(_)), "{why}: {e:?}");
        let msg = e.to_string();
        assert!(!msg.contains("192.0.2") && !msg.contains("test-only"), "{why}: {msg}");
    }
    let key = |k: &str| c.replace(&b64(&placeholder_key_pem()), &b64(k));
    assert!(res(&key(CERT_PEM), Some("lab-cert")).is_err(), "certificate as key");
    let enc = placeholder_key_pem().replace("PRIVATE KEY", "ENCRYPTED PRIVATE KEY");
    assert!(res(&key(&enc), Some("lab-cert")).is_err(), "encrypted key");
    let two = format!("{0}{0}", placeholder_key_pem());
    assert!(res(&key(&two), Some("lab-cert")).is_err(), "two keys");
    let only_cert =
        c.replace(&format!("    client-key-data: {}\n", b64(&placeholder_key_pem())), "");
    assert!(matches!(res(&only_cert, Some("lab-cert")), Err(KubeResolveError::Invalid(_))));
}

#[test]
fn inline_data_is_capped() {
    let big = format!("{CERT_PEM}{}", "#".repeat(MAX_CA_PEM));
    let yaml = config().replacen(&b64(CERT_PEM), &b64(&big), 1);
    let e = res(&yaml, None).expect_err("oversized CA");
    assert!(e.to_string().contains("larger than 64 KiB"), "{e}");
    let long = config().replace("test-only-token", &"t".repeat(MAX_TOKEN + 1));
    assert!(res(&long, None).is_err(), "oversized token");
    let max = config().replace("test-only-token", &"t".repeat(MAX_TOKEN));
    assert!(res(&max, None).is_ok(), "token at the cap");
    // base64 split over lines (folded) still decodes
    let folded = b64(CERT_PEM)
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n      ");
    let yaml = config().replacen(&b64(CERT_PEM), &format!("|\n      {folded}"), 1);
    assert!(res(&yaml, None).is_ok(), "multi-line base64");
}

#[test]
fn shared_fixture_resolves_except_its_fake_ca() {
    // `testdata::KUBECONFIG` carries `AAAA` as CA data: valid for `parse`, not for `resolve`.
    assert!(super::parse(KUBECONFIG.as_bytes()).is_ok());
    let e = resolve(KUBECONFIG.as_bytes(), None).expect_err("fake CA");
    assert!(e.to_string().contains("certificate-authority-data"), "{e}");
    let fixed = KUBECONFIG.replace("    certificate-authority-data: AAAA\n", "");
    let r = resolve(fixed.as_bytes(), Some("lab-admin")).expect("no CA");
    assert_eq!((r.ca, r.namespace.as_deref()), (CaSource::None, Some("kube-system")));
}

#[test]
fn names_and_servers() {
    for ok in ["default", "a", "kube-system", "a1-b2", &"a".repeat(63)] {
        assert!(is_dns_label(ok), "{ok}");
    }
    for bad in ["", "-a", "a-", "A", "a_b", "a.b", &"a".repeat(64)] {
        assert!(!is_dns_label(bad), "{bad}");
    }
    assert!(is_dns_subdomain("api.example.test") && !is_dns_subdomain("a..b"));
    let s = KubeServer::parse("HTTPS://[2001:DB8::1]:8443/k8s/clusters/c-1/").expect("v6");
    assert_eq!(s.as_str(), "https://[2001:db8::1]:8443/k8s/clusters/c-1");
    assert_eq!((s.host(), s.port(), s.path()), ("2001:db8::1", 8443, "/k8s/clusters/c-1"));
    for bad in [
        "https://",
        "https://:443",
        "https://a:99999",
        "https://a:+1",
        "https://[::1",
        "https://*.example.test",
        "https://a\\b",
        "https://ex\u{e4}mple.test",
        "ftp://a",
    ] {
        assert!(KubeServer::parse(bad).is_err(), "{bad}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    #[test]
    fn resolve_never_panics(s in "[a-z:\\- \\[\\]{}\n\"'#]{0,300}", ctx in proptest::option::of("[a-z-]{0,8}")) {
        let _ = resolve(format!("{}{s}", config()).as_bytes(), ctx.as_deref());
        let _ = resolve(s.as_bytes(), ctx.as_deref());
    }

    #[test]
    fn any_visible_ascii_token_round_trips(t in "[!-~&&[^'\"#\\\\{}\\[\\],&*!|>%@`:]]{1,200}") {
        let yaml = config().replace("test-only-token", &format!("'{t}'"));
        let r = resolve(yaml.as_bytes(), None).expect("token");
        let KubeAuth::Token(got) = r.auth else { panic!("token") };
        prop_assert_eq!(got.expose_secret(), t.as_str());
    }

    #[test]
    fn server_parse_never_panics(s in "\\PC{0,80}") {
        let _ = KubeServer::parse(&s);
        let _ = KubeServer::parse(&format!("https://{s}"));
    }
}
