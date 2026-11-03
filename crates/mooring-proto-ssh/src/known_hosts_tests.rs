use super::*;
use proptest::prelude::*;
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::ssh_key::PrivateKey;

fn key(seed: u8) -> PublicKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32])).public_key().clone()
}

fn key_line(k: &PublicKey) -> String {
    k.to_openssh().expect("encode")
}

#[test]
fn plain_entry_known_unknown_mismatch() {
    let k1 = key(1);
    let text = format!("example.org,10.0.0.1 {}\n", key_line(&k1));
    let store = KnownHosts::parse_bytes(text.as_bytes());
    assert_eq!(store.len(), 1);
    assert_eq!(store.check("example.org", 22, &k1), TrustDecision::Known);
    assert_eq!(store.check("EXAMPLE.org", 22, &k1), TrustDecision::Known);
    assert_eq!(store.check("10.0.0.1", 22, &k1), TrustDecision::Known);
    assert_eq!(store.check("other.org", 22, &k1), TrustDecision::Unknown);
    // Non-default port is a different host for OpenSSH.
    assert_eq!(store.check("example.org", 2222, &k1), TrustDecision::Unknown);
    assert_eq!(
        store.check("example.org", 22, &key(2)),
        TrustDecision::Mismatch { expected_fp: fingerprint(&k1) }
    );
}

#[test]
fn bracketed_port_form() {
    let k = key(3);
    assert_eq!(host_pattern("Host.Example", 2222), "[host.example]:2222");
    assert_eq!(host_pattern("h", 22), "h");
    let text = format!("[h.example]:2222 {}", key_line(&k));
    let store = KnownHosts::parse_bytes(text.as_bytes());
    assert_eq!(store.check("h.example", 2222, &k), TrustDecision::Known);
    assert_eq!(store.check("h.example", 22, &k), TrustDecision::Unknown);
}

#[test]
fn openssh_hashed_vector_matches() {
    // Produced by `ssh-keygen -H` semantics: HMAC-SHA1(key = salt, msg = host).
    let k = key(4);
    let salt = [7u8; 20];
    let hash = hmac_host(&salt, "server.lan").expect("hmac");
    let line = format!(
        "|1|{}|{} {}",
        Base64::encode_string(&salt),
        Base64::encode_string(&hash),
        key_line(&k)
    );
    let store = KnownHosts::parse_bytes(line.as_bytes());
    assert_eq!(store.check("server.lan", 22, &k), TrustDecision::Known);
    assert_eq!(store.check("server.lan2", 22, &k), TrustDecision::Unknown);
}

#[test]
fn known_hmac_sha1_vector() {
    // RFC 2202 test case 2: key "Jefe", data "what do ya want for nothing?".
    let got = hmac_host(b"Jefe", "what do ya want for nothing?").expect("hmac");
    let hex = got.iter().fold(String::new(), |mut s, b| {
        let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}"));
        s
    });
    assert_eq!(hex, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
}

#[test]
fn add_hashed_round_trips_and_hides_host() {
    let k = key(5);
    let mut store = KnownHosts::new();
    store.add_hashed("secret-host.lan", 2200, &k).expect("add");
    let text = store.to_file_string();
    assert!(text.starts_with("|1|"));
    assert!(!text.contains("secret-host"));
    let reparsed = KnownHosts::parse_bytes(text.as_bytes());
    assert_eq!(reparsed.check("secret-host.lan", 2200, &k), TrustDecision::Known);
    assert_eq!(reparsed.check("secret-host.lan", 22, &k), TrustDecision::Unknown);
}

#[test]
fn malformed_and_unknown_lines_are_skipped_but_kept() {
    let k = key(6);
    let text = format!(
        "# comment\n\ngarbage\nhost ssh-ed25519 !!!notbase64\n|1|xx|yy {kl}\n\
         @cert-authority *.lan {kl}\nhost ssh-unknown-type AAAA\ngood {kl}\n",
        kl = key_line(&k)
    );
    let store = KnownHosts::parse_bytes(text.as_bytes());
    assert_eq!(store.len(), 1);
    assert_eq!(store.check("good", 22, &k), TrustDecision::Known);
    // Rewriting preserves every original line.
    assert_eq!(store.to_file_string(), text);
}

#[test]
fn revoked_key_is_a_mismatch() {
    let k = key(7);
    let text = format!("@revoked * {}\nhost {}\n", key_line(&k), key_line(&k));
    let store = KnownHosts::parse_bytes(text.as_bytes());
    assert_eq!(
        store.check("host", 22, &k),
        TrustDecision::Mismatch { expected_fp: "revoked".into() }
    );
}

#[test]
fn patterns_and_negation() {
    let k = key(8);
    let text = format!("*.lan,!bad.lan,h?st {}", key_line(&k));
    let store = KnownHosts::parse_bytes(text.as_bytes());
    assert_eq!(store.check("a.lan", 22, &k), TrustDecision::Known);
    assert_eq!(store.check("bad.lan", 22, &k), TrustDecision::Unknown);
    assert_eq!(store.check("host", 22, &k), TrustDecision::Known);
    assert_eq!(store.check("hoost", 22, &k), TrustDecision::Unknown);
    assert!(glob(b"a*b*c", b"aXXbYYc"));
    assert!(!glob(b"a*b*c", b"aXXbYY"));
    assert!(glob(b"***", b""));
}

#[test]
fn caps_mark_store_truncated_and_block_save() {
    let long = "a".repeat(MAX_LINE + 1);
    let store = KnownHosts::parse_bytes(long.as_bytes());
    assert!(store.is_empty());
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("known_hosts");
    assert!(matches!(store.save(&path), Err(KnownHostsError::Truncated)));
    assert!(!path.exists());

    let many = "#\n".repeat(MAX_LINES + 5);
    let store = KnownHosts::parse_bytes(many.as_bytes());
    assert!(store.truncated);
}

#[test]
fn fingerprint_is_openssh_form() {
    let fp = fingerprint(&key(9));
    assert!(fp.starts_with("SHA256:"));
    assert!(!fp.ends_with('='));
    assert_eq!(fp.len(), "SHA256:".len() + 43);
    assert!(describe_key(&key(9)).starts_with("ssh-ed25519 SHA256:"));
}

#[test]
fn save_is_atomic_and_load_round_trips() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("sub").join("known_hosts");
    assert!(KnownHosts::load(&path).expect("missing is empty").is_empty());
    let mut store = KnownHosts::new();
    store.add_hashed("a", 22, &key(10)).expect("add");
    store.save(&path).expect("save");
    store.add_hashed("b", 22, &key(11)).expect("add");
    store.save(&path).expect("save again");
    let loaded = KnownHosts::load(&path).expect("load");
    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded.check("b", 22, &key(11)), TrustDecision::Known);
    let leftovers = std::fs::read_dir(path.parent().expect("parent")).expect("readdir").count();
    assert_eq!(leftovers, 1, "no temp files left behind");
}

proptest! {
    #[test]
    fn random_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let store = KnownHosts::parse_bytes(&bytes);
        let _ = store.check("host", 22, &key(1));
        let _ = store.to_file_string();
    }

    #[test]
    fn random_lines_never_panic(lines in proptest::collection::vec("[ -~|@!*?,\\[\\]:]{0,200}", 0..50)) {
        let text = lines.join("\n");
        let store = KnownHosts::parse_bytes(text.as_bytes());
        let _ = store.check("h", 2222, &key(2));
    }

    #[test]
    fn hashed_entries_round_trip(
        hosts in proptest::collection::vec(("[a-z0-9.-]{1,40}", any::<u16>(), any::<u8>()), 1..8)
    ) {
        let mut store = KnownHosts::new();
        for (h, port, seed) in &hosts {
            store.add_hashed(h, *port, &key(*seed)).expect("add");
        }
        let reparsed = KnownHosts::parse_bytes(store.to_file_string().as_bytes());
        prop_assert_eq!(reparsed.len(), hosts.len());
        for (h, port, seed) in &hosts {
            prop_assert_eq!(reparsed.check(h, *port, &key(*seed)), TrustDecision::Known);
        }
    }
}
