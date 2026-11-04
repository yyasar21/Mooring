//! Parser tests (moved from `kubeconfig.rs`).

use super::*;
use crate::credential::testdata::KUBECONFIG;
use proptest::prelude::*;

#[test]
fn extracts_contexts_and_current() {
    let info = parse(KUBECONFIG.as_bytes()).expect("valid");
    assert_eq!(info.contexts, ["lab", "lab-admin"]);
    assert_eq!(info.current_context.as_deref(), Some("lab"));
}

#[test]
fn rejects_code_execution_and_file_references() {
    for (needle, replacement) in [
        ("    token: test-only-token", "    exec:\n      command: /bin/sh"),
        ("    token: test-only-token", "    auth-provider:\n      name: oidc"),
        ("    token: test-only-token", "    tokenFile: /var/run/token"),
        ("    token: test-only-token", "    client-certificate: /home/u/.kube/c.crt"),
        ("    token: test-only-token", "    client-key: /home/u/.kube/c.key"),
        ("    certificate-authority-data: AAAA", "    certificate-authority: /etc/ca.crt"),
    ] {
        let yaml = KUBECONFIG.replace(needle, replacement);
        let e = parse(yaml.as_bytes()).expect_err(replacement);
        assert!(matches!(e, CredentialError::KubeconfigRejected(_)), "{e:?}");
        assert!(!e.to_string().contains("/bin/sh") && !e.to_string().contains("/etc"));
    }
}

#[test]
fn rejects_merge_keys_and_case_variants() {
    let user = "    token: test-only-token";
    for (replacement, why) in [
        ("    <<: {exec: {command: /bin/sh}}", "merge key with an inline mapping"),
        ("    token: x\n    <<: {name: y}", "merge key anywhere, harmless body"),
        ("    Exec:\n      command: /bin/sh", "Exec"),
        ("    AUTH-PROVIDER:\n      name: oidc", "AUTH-PROVIDER"),
        ("    TokenFile: /var/run/token", "TokenFile"),
        ("    token: x\n    nested:\n      exec: {command: /bin/sh}", "nested under user"),
    ] {
        let yaml = KUBECONFIG.replace(user, replacement);
        let e = parse(yaml.as_bytes()).expect_err(why);
        assert!(matches!(e, CredentialError::KubeconfigRejected(_)), "{why}: {e:?}");
        assert!(!e.to_string().contains("/bin/sh"), "{why}: no value echo");
    }
    let top =
        KUBECONFIG.replace("users:\n- name: ops\n", "users:\n- name: ops\n  exec: {command: x}\n");
    assert!(parse(top.as_bytes()).is_err(), "a key beside `user` under users[]");
    let merge_top = format!("{KUBECONFIG}<<: {{preferences: {{}}}}\n");
    let e = parse(merge_top.as_bytes()).expect_err("top-level merge");
    assert!(e.to_string().contains("merge"), "{e}");
    let ca = KUBECONFIG
        .replace("    certificate-authority-data: AAAA", "    Certificate-Authority: /etc/ca.crt");
    assert!(parse(ca.as_bytes()).is_err(), "cluster key case variant");
    assert!(parse(KUBECONFIG.as_bytes()).is_ok(), "certificate-authority-data still fine");
}

/// `fuzz/regressions/kubeconfig_parse/qa-f2-section-key-case` (QA-F2).
const QA_F2: &str = "apiVersion: v1\nkind: Config\ncontexts:\n- name: lab\n  context: {cluster: lab, user: ops}\nUsers:\n- name: ops\n  user:\n    exec: {command: /bin/sh}\nClusters:\n- name: lab\n  cluster: {server: \"https://k8s.example.test\", certificate-authority: /tmp/ca}\n";

#[test]
fn section_key_case_variants_and_case_duplicates_are_rejected() {
    let e = parse(QA_F2.as_bytes()).expect_err("QA-F2 reproducer");
    assert!(!e.to_string().contains("/bin/sh") && !e.to_string().contains("/tmp"), "{e}");
    for (from, to) in [
        ("users:", "Users:"),
        ("users:", "USERS:"),
        ("clusters:", "Clusters:"),
        ("contexts:", "Contexts:"),
    ] {
        let yaml = KUBECONFIG.replacen(from, to, 1);
        assert_ne!(yaml, KUBECONFIG, "{to} applied");
        let e = parse(yaml.as_bytes()).expect_err(to);
        assert!(e.to_string().contains("lower case"), "{to}: {e}");
    }
    // a hostile variant beside a clean section: caught as a duplicate before anything else
    let mixed = format!("{KUBECONFIG}Users:\n- name: x\n  user: {{exec: {{command: x}}}}\n");
    let e = parse(mixed.as_bytes()).expect_err("mixed-case duplicate");
    assert!(e.to_string().contains("duplicate key"), "{e}");
    // nested duplicates too
    let nested = KUBECONFIG.replacen("    token: test-only-token", "    token: a\n    Token: b", 1);
    let e = parse(nested.as_bytes()).expect_err("nested case duplicate");
    assert!(e.to_string().contains("duplicate key"), "{e}");
    assert!(parse(KUBECONFIG.as_bytes()).is_ok());
}

/// M-12: Unicode-folding lookalikes of forbidden or section keys, at any level.
#[test]
fn non_ascii_keys_are_rejected_anywhere_with_position_only() {
    let user = "    token: test-only-token";
    for (yaml, line, col) in [
        (KUBECONFIG.replace(user, "    to\u{212A}enFile: /var/run/token"), None, 5),
        (KUBECONFIG.replace(user, "    client-\u{212A}ey: /home/u/c.key"), None, 5),
        (KUBECONFIG.replace(user, "    \"to\\u212AenFile\": /var/run/token"), None, 5),
        (
            format!("{KUBECONFIG}u\u{017F}ers:\n- name: x\n  user: {{exec: {{command: x}}}}\n"),
            None,
            1,
        ),
        (format!("{KUBECONFIG}cluster\u{017F}: []\n"), None, 1),
        (format!("{KUBECONFIG}preferences: {{caf\u{e9}: x}}\n"), None, 15),
        ("k\u{e9}y: v\ncontexts: [{name: c}]\n".to_owned(), Some(1), 1),
    ] {
        let e = parse(yaml.as_bytes()).expect_err(&yaml);
        let msg = e.to_string();
        assert!(matches!(e, CredentialError::KubeconfigRejected(_)), "{e:?}");
        assert!(msg.contains("keys must be ASCII"), "{msg}");
        assert!(msg.contains(&format!("column {col})")), "{msg}");
        if let Some(line) = line {
            assert!(msg.contains(&format!("line {line},")), "{msg}");
        }
        assert!(msg.is_ascii() && !msg.contains("/var") && !msg.contains("/home"), "{msg}");
    }
    // non-ASCII names and values are still fine
    let named = KUBECONFIG.replace("- name: lab-admin", "- name: lab-\u{e9}");
    assert_ne!(named, KUBECONFIG);
    let info = parse(named.as_bytes()).expect("non-ASCII context name");
    assert_eq!(info.contexts, ["lab", "lab-\u{e9}"]);
    let value = KUBECONFIG.replace("test-only-token", "t\u{212A}n");
    assert!(parse(value.as_bytes()).is_ok(), "non-ASCII value");
}

#[test]
fn rejects_yaml_tricks() {
    let alias =
        KUBECONFIG.replace("users:\n- name: ops\n  user:", "users:\n- name: ops\n  user: &u");
    assert!(parse(alias.as_bytes()).is_err(), "anchor");
    let two_docs = format!("{KUBECONFIG}---\n{KUBECONFIG}");
    assert!(parse(two_docs.as_bytes()).is_err(), "two documents");
    let dup = format!("{KUBECONFIG}kind: Config\n");
    assert!(parse(dup.as_bytes()).is_err(), "duplicate key");
    assert!(parse(b"- a\n- b\n").is_err(), "not a mapping");
    assert!(parse(b"").is_err(), "empty");
    assert!(parse(b"apiVersion: v1\nkind: Config\n").is_err(), "no contexts");
    let deep = format!("a: {}{}", "[".repeat(100), "]".repeat(100));
    assert!(parse(deep.as_bytes()).is_err(), "depth");
    assert!(parse(&vec![b'#'; MAX_YAML + 1]).is_err(), "size");
    assert!(parse(b"a: !!binary AAAA\ncontexts: [{name: x}]\n").is_err(), "tag");
    assert!(parse(&[0xff, 0xfe]).is_err(), "utf-8");
}

#[test]
fn wide_mappings_are_capped_and_checked_in_n_log_n() {
    use std::fmt::Write as _;
    // ~1 MiB, one flat mapping: rejected by the per-mapping cap, fast (review 3, L-10)
    let mut yaml = String::with_capacity(MAX_YAML);
    let mut i = 0;
    while yaml.len() < MAX_YAML - 32 {
        let _ = writeln!(yaml, "k{i}: v");
        i += 1;
    }
    let t = std::time::Instant::now();
    let e = parse(yaml.as_bytes()).expect_err("too many keys");
    assert!(e.to_string().contains("too many keys"), "{e}");
    // debug build bound; the review's release-mode target is < 200 ms
    assert!(t.elapsed() < std::time::Duration::from_secs(2), "{:?}", t.elapsed());
    // the largest accepted mapping still parses and still finds a late duplicate
    let mut wide = String::from("contexts: [{name: x}]\nm:\n");
    for i in 0..MAX_MAP_ENTRIES - 1 {
        let _ = writeln!(wide, "  k{i}: v");
    }
    assert!(parse(wide.as_bytes()).is_ok(), "{MAX_MAP_ENTRIES} entries are fine");
    wide.push_str("  k0: again\n");
    let e = parse(wide.as_bytes()).expect_err("duplicate");
    assert!(e.to_string().contains("duplicate key"), "{e}");
}

#[test]
fn contexts_are_capped_and_deduplicated() {
    let mut yaml = String::from("contexts:\n");
    for i in 0..100 {
        let line = format!("- name: c{i}\n");
        yaml.push_str(&line);
        yaml.push_str(&line);
    }
    let info = parse(yaml.as_bytes()).expect("valid");
    assert_eq!(info.contexts.len(), MAX_CONTEXTS);
    assert_eq!(info.contexts[1], "c1");
    assert_eq!(info.current_context, None);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]
    #[test]
    fn never_panics(s in "\\PC{0,300}") {
        let _ = parse(s.as_bytes());
    }

    #[test]
    fn never_panics_on_yaml_shaped_noise(s in "[a-z:\\- \\[\\]{}&*!|>'\"\n#]{0,300}") {
        let _ = parse(s.as_bytes());
        let _ = parse(format!("{KUBECONFIG}{s}").as_bytes());
    }
}
