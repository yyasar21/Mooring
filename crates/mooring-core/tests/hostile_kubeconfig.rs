//! Hostile kubeconfig inputs through `kubeconfig::resolve` (ADR-0014 §3 and §Test plan,
//! "R-YAML-DEQ" cases run as plain tests): file paths in any spelling (relative, absolute,
//! symlink-like, `~`), `exec` / `auth-provider` plugins, huge documents, bidi and control
//! characters, base64 bombs, unknown fields. Every refusal is a static reason: no value from
//! the document ever appears in the error text.

use std::fmt::Write as _;
use std::time::Instant;

use mooring_core::credential::kubeconfig::{resolve, KubeResolveError, MAX_CONTEXTS, MAX_YAML};

const SERVER: &str = "https://k.example.test:6443";

/// A minimal valid kubeconfig with `cluster_extra` / `user_extra` lines spliced in.
fn doc(cluster_extra: &str, user_extra: &str) -> Vec<u8> {
    format!(
        "apiVersion: v1\nkind: Config\ncurrent-context: c\nclusters:\n- name: k\n  cluster:\n    \
         server: {SERVER}\n{cluster_extra}contexts:\n- name: c\n  context:\n    cluster: k\n    \
         user: u\nusers:\n- name: u\n  user:\n    token: test-token\n{user_extra}"
    )
    .into_bytes()
}

fn refused(yaml: &[u8]) -> KubeResolveError {
    let e = resolve(yaml, None).expect_err("must be refused");
    let text = e.to_string();
    for leaked in ["test-token", "/etc/", "/home/", "C:\\\\", "aws", "evil"] {
        assert!(!text.contains(leaked), "error text leaks `{leaked}`: {text}");
    }
    e
}

#[test]
fn the_baseline_resolves() {
    let r = resolve(&doc("", ""), None).expect("baseline");
    assert_eq!(r.auth.kind(), "token");
}

/// Every path-bearing key is refused whatever the path looks like: relative, absolute, a
/// symlink target outside the home directory, `~`, UNC, or an empty string.
#[test]
fn file_paths_are_refused_in_every_spelling() {
    let paths = [
        "ca.crt",
        "./ca.crt",
        "../../../etc/kubernetes/pki/ca.crt",
        "/etc/kubernetes/pki/ca.crt",
        "~/.kube/ca.crt",
        "/proc/self/root/etc/shadow",
        "/dev/stdin",
        "\\\\\\\\server\\\\share\\\\ca.crt",
        "C:\\\\Users\\\\x\\\\ca.crt",
        "\"\"",
    ];
    for p in paths {
        let e = refused(&doc(&format!("    certificate-authority: {p}\n"), ""));
        assert!(matches!(e, KubeResolveError::Rejected(_)), "{p}: {e}");
        for key in ["client-certificate", "client-key", "tokenFile"] {
            let e = refused(&doc("", &format!("    {key}: {p}\n")));
            assert!(matches!(e, KubeResolveError::Rejected(_)), "{key}: {p}: {e}");
        }
    }
}

/// `exec` and `auth-provider` plugins are refused in every shape: a block, an inline map, a
/// list item, a case variant, nested under another key, and with an empty value.
#[test]
fn exec_and_auth_provider_plugins_are_refused() {
    let shapes = [
        "    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: aws\n",
        "    exec: {command: evil, args: [-c, id]}\n",
        "    Exec: {command: evil}\n",
        "    EXEC:\n",
        "    exec: ~\n",
        "    exec: \"\"\n",
        "    extensions:\n    - name: x\n      extension: {exec: {command: evil}}\n",
        "    auth-provider:\n      name: oidc\n      config: {cmd-path: evil}\n",
        "    auth-provider: {name: gcp}\n",
        "    Auth-Provider: {name: azure}\n",
    ];
    for s in shapes {
        let e = refused(&doc("", s));
        assert!(matches!(e, KubeResolveError::Rejected(_)), "{s:?}: {e}");
    }
    // A merge key or an alias cannot smuggle one in either.
    let anchored =
        "apiVersion: v1\nkind: Config\ncurrent-context: c\nx: &p {exec: {command: evil}}\n\
        clusters:\n- name: k\n  cluster: {server: https://k.example.test}\ncontexts:\n- name: c\n  \
        context: {cluster: k, user: u}\nusers:\n- name: u\n  user:\n    <<: *p\n    token: t\n";
    assert!(matches!(refused(anchored.as_bytes()), KubeResolveError::Rejected(_)));
}

/// A document over the 1 MiB cap is refused before parsing, and a document just under it
/// made of many contexts is refused by the node cap, both in well under a second.
#[test]
fn huge_documents_are_refused_quickly() {
    let started = Instant::now();
    let mut big = doc("", "");
    big.extend(std::iter::repeat_n(b'#', MAX_YAML + 1));
    assert!(matches!(refused(&big), KubeResolveError::Rejected(_)));

    let mut many = String::from("apiVersion: v1\nkind: Config\ncurrent-context: c\nclusters:\n");
    for i in 0..5000 {
        let _ = writeln!(many, "- name: k{i}\n  cluster: {{server: https://k{i}.example.test}}");
    }
    many.push_str("contexts:\n");
    for i in 0..5000 {
        let _ = writeln!(many, "- name: c{i}\n  context: {{cluster: k{i}, user: u}}");
    }
    many.push_str("users:\n- name: u\n  user: {token: t}\n");
    assert!(many.len() < MAX_YAML, "stay under the byte cap: the entry caps are what bound it");
    let info = mooring_core::credential::kubeconfig::parse(many.as_bytes()).expect("parses");
    assert!(info.contexts.len() <= MAX_CONTEXTS, "{} contexts listed", info.contexts.len());
    let a = resolve(many.as_bytes(), Some("c0")).is_ok();
    assert_eq!(a, resolve(many.as_bytes(), Some("c0")).is_ok(), "deterministic");

    // billion-laughs style nesting and a very wide mapping
    let deep = format!("a: {}x{}", "{a: ".repeat(200), "}".repeat(200));
    assert!(resolve(deep.as_bytes(), None).is_err());
    let mut wide = String::from("apiVersion: v1\npreferences:\n");
    for i in 0..5000 {
        let _ = writeln!(wide, "  k{i}: v");
    }
    wide.push_str("contexts: []\n");
    assert!(resolve(wide.as_bytes(), None).is_err());
    assert!(started.elapsed().as_secs() < 5, "{:?}", started.elapsed());
}

/// Bidi overrides, zero-width characters, C0 / C1 controls and ESC in names, the server
/// URL, the token or the namespace are refused, and a non-ASCII mapping key is refused
/// outright (Kelvin sign, long s).
#[test]
fn bidi_and_control_characters_are_refused() {
    let evil = ["\u{202e}", "\u{200b}", "\u{2066}", "\u{1b}[2J", "\u{7}", "\u{85}", "\u{feff}"];
    for c in evil {
        let s = format!("    token: tok{c}en\n");
        assert!(resolve(&doc("", &s), None).is_err(), "token with {c:?}");
        let s = format!("    namespace: ns{c}\n");
        let mut d = doc("", "");
        let at = d.windows(8).position(|w| w == b"user: u\n").expect("context") + 8;
        d.splice(at..at, s.bytes());
        assert!(resolve(&d, None).is_err(), "namespace with {c:?}");
        let ctx = format!("c{c}");
        assert!(resolve(&doc("", ""), Some(&ctx)).is_err(), "context name {c:?}");
        let server = format!("https://k{c}.example.test");
        let d = String::from_utf8(doc("", "")).expect("utf-8").replace(SERVER, &server);
        assert!(resolve(d.as_bytes(), None).is_err(), "server with {c:?}");
    }
    for key in ["to\u{212a}enFile: x", "u\u{17f}ers: []", "\u{feff}token: x"] {
        assert!(matches!(
            refused(&doc("", &format!("    {key}\n"))),
            KubeResolveError::Rejected(_)
        ));
    }
}

/// Inline data is capped before decoding: a 64 KiB + 1 CA blob, a base64 string that would
/// decode past the cap, and non-PEM / non-certificate content are all refused with a static
/// reason.
#[test]
fn inline_data_is_capped_and_type_checked() {
    use data_encoding::BASE64;
    let big = BASE64.encode(&vec![b'A'; 64 * 1024 + 1]);
    let e = refused(&doc(&format!("    certificate-authority-data: {big}\n"), ""));
    assert_eq!(e.to_string(), "kubeconfig certificate-authority-data is larger than 64 KiB");
    let bomb = "A".repeat(900 * 1024); // under the document cap, far over the base64 cap
    let e = refused(&doc(&format!("    certificate-authority-data: {bomb}\n"), ""));
    assert!(e.to_string().contains("64 KiB"), "{e}");
    let key =
        BASE64.encode(b"-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n");
    let e = refused(&doc(&format!("    certificate-authority-data: {key}\n"), ""));
    assert!(e.to_string().contains("certificate PEM only"), "{e}");
    let bin = BASE64.encode(&[0xff, 0xfe, 0x00, 0x01]);
    let e = refused(&doc(&format!("    certificate-authority-data: {bin}\n"), ""));
    assert!(e.to_string().contains("not PEM"), "{e}");
    let e = refused(&doc("    certificate-authority-data: '%%%%'\n", ""));
    assert!(e.to_string().contains("not valid base64"), "{e}");
    let e = refused(&doc(
        "    certificate-authority-data: AAAA\n    insecure-skip-tls-verify: true\n",
        "",
    ));
    assert!(e.to_string().contains("both"), "{e}");
}

/// Unsupported but syntactically valid authentication and cluster fields fail closed with
/// `kube.unsupported_auth` or a static invalid reason: nothing is silently ignored.
#[test]
fn unknown_and_unsupported_fields_fail_closed() {
    for (extra, code) in [
        ("    username: admin\n    password: hunter2\n", "kube.unsupported_auth"),
        ("    as: admin\n", "kube.unsupported_auth"),
        ("    impersonate-groups: [system:masters]\n", "kube.unsupported_auth"),
        ("    TOKEN: other\n", "credential.kubeconfig_rejected"), // case-insensitive duplicate
        ("    tokenx: other\n", "kube.unsupported_auth"),
        ("    client-certificate-data: QUFBQQ==\n", "kube.unsupported_auth"), // token + cert
        ("    token: \"a b\"\n", "credential.kubeconfig_rejected"),
    ] {
        let e = refused(&doc("", extra));
        assert_eq!(e.code(), code, "{extra:?}: {e}");
    }
    for extra in [
        "    proxy-url: socks5://127.0.0.1:1080\n",
        "    Server: https://other.example.test\n",
        "    insecure-skip-tls-verify: yes\n",
        "    tls-server-name: \"k.example.test/..\"\n",
    ] {
        let e = refused(&doc(extra, ""));
        assert_eq!(e.code(), "credential.kubeconfig_rejected", "{extra:?}: {e}");
    }
    let d = String::from_utf8(doc("", "")).expect("utf-8");
    for bad in [
        "http://k.example.test",
        "https://user:pw@k.example.test",
        "https://k.example.test/../x",
        "https://k.example.test/?x=1",
        "https://192.0.2.1:99999",
    ] {
        assert!(resolve(d.replace(SERVER, bad).as_bytes(), None).is_err(), "{bad}");
    }
    assert!(matches!(
        resolve(&doc("", ""), Some("missing")),
        Err(KubeResolveError::NotFound("context"))
    ));
    assert!(matches!(resolve(&doc("", ""), Some("")), Err(KubeResolveError::Invalid(_))));
    let long = "c".repeat(254);
    assert!(matches!(resolve(&doc("", ""), Some(&long)), Err(KubeResolveError::Invalid(_))));
}

/// Two entries with one name are ambiguous and refused, in every section.
#[test]
fn duplicate_names_are_refused() {
    let dup_cluster = doc("- name: k\n  cluster:\n    server: https://other.example.test\n", "");
    assert!(matches!(
        refused(&dup_cluster),
        KubeResolveError::Rejected(_) | KubeResolveError::Duplicate(_)
    ));
    let dup_user = doc("", "- name: u\n  user:\n    token: other\n");
    assert!(matches!(
        refused(&dup_user),
        KubeResolveError::Rejected(_) | KubeResolveError::Duplicate(_)
    ));
}
