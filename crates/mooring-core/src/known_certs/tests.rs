use super::*;
use proptest::prelude::*;

const T0: OffsetDateTime = time::macros::datetime!(2026-11-04 12:00 UTC);

fn fp(seed: u8) -> [u8; 32] {
    fingerprint(&[seed; 40])
}

#[test]
fn decision_table_has_four_rows() {
    let e = fp(9);
    assert_eq!(decide(CertTrust::Trusted, true), CertVerdict::AcceptPinned { chain_valid: true });
    assert_eq!(
        decide(CertTrust::Trusted, false),
        CertVerdict::AcceptPinned { chain_valid: false },
        "the pin wins over a failing chain"
    );
    for chain in [true, false] {
        assert_eq!(
            decide(CertTrust::Mismatch { expected: e }, chain),
            CertVerdict::Mismatch { expected: e },
            "a changed pin is a hard stop even with a valid CA chain"
        );
    }
    assert_eq!(decide(CertTrust::Unknown, true), CertVerdict::AcceptCa);
    assert_eq!(decide(CertTrust::Unknown, false), CertVerdict::Prompt);
}

#[test]
fn add_check_remove_list() {
    let mut s = KnownCerts::new();
    s.add("RDP.Example.test", 3389, &fp(1), T0);
    assert_eq!(s.check("rdp.example.test", 3389, &fp(1)), CertTrust::Trusted);
    assert_eq!(s.check("rdp.example.test", 3390, &fp(1)), CertTrust::Unknown, "port matters");
    assert_eq!(s.check("rdp.example.test", 3389, &fp(2)), CertTrust::Mismatch { expected: fp(1) });
    assert!(s.has_pin("rdp.example.test", 3389));
    s.add("2001:db8::1", 5900, &fp(3), T0);
    assert_eq!(s.check("[2001:DB8::1]", 5900, &fp(3)), CertTrust::Trusted);

    let listed = s.list();
    assert_eq!(listed.len(), 2);
    assert!(listed[0].host_hash.starts_with("|2|"));
    assert!(!listed[0].host_hash.contains("example"), "hashed: no host name in the list");
    assert_eq!(listed[0].fingerprint, display_fingerprint(&fp(1)));
    assert_eq!(listed[0].added_at, "2026-11-04T12:00:00Z");
    let json = serde_json::to_value(&listed[0]).expect("json");
    assert!(json.get("hostHash").is_some() && json.get("addedAt").is_some());

    let file = s.to_file_string();
    assert!(!file.contains("example"), "the file never holds the host in clear");
    assert_eq!(s.remove("rdp.example.test", 3389), 1);
    assert_eq!(s.remove("rdp.example.test", 3389), 0);
    assert_eq!(s.check("rdp.example.test", 3389, &fp(1)), CertTrust::Unknown);
    assert_eq!(s.len(), 1);
}

#[test]
fn file_round_trip_keeps_comments_and_unknown_types() {
    let pin = BASE64.encode(&fp(4));
    let text = format!(
        "# managed by Mooring\n\
         \n\
         host.example.test:3389 {KEY_TYPE} {pin} 2026-01-01T00:00:00Z\n\
         [2001:db8::2]:3389 {KEY_TYPE} {pin} 2026-01-01T00:00:00+03:00\n\
         other.example.test:3389 x509-sha512 AAAA 2026-01-01T00:00:00Z\n\
         garbage line\n"
    );
    let s = KnownCerts::parse_bytes(text.as_bytes());
    assert_eq!(s.len(), 2);
    assert_eq!(s.check("HOST.example.test", 3389, &fp(4)), CertTrust::Trusted);
    assert_eq!(s.check("2001:db8::2", 3389, &fp(4)), CertTrust::Trusted);
    assert_eq!(s.to_file_string(), text, "verbatim, including skipped lines");
    let again = KnownCerts::parse_bytes(s.to_file_string().as_bytes());
    assert_eq!(again.to_file_string(), text);
}

#[test]
fn malformed_lines_are_skipped() {
    let pin = BASE64.encode(&fp(5));
    for bad in [
        format!("h:3389 {KEY_TYPE} {pin}"),
        format!("h:3389 {KEY_TYPE} {pin} not-a-date"),
        format!("h:3389 {KEY_TYPE} {pin} 2026-01-01T00:00:00Z extra"),
        format!("h:0 {KEY_TYPE} {pin} 2026-01-01T00:00:00Z"),
        format!("h {KEY_TYPE} {pin} 2026-01-01T00:00:00Z"),
        format!(":3389 {KEY_TYPE} {pin} 2026-01-01T00:00:00Z"),
        format!("::1:3389 {KEY_TYPE} {pin} 2026-01-01T00:00:00Z"),
        format!("h:3389 {KEY_TYPE} AAAA 2026-01-01T00:00:00Z"),
        format!("|2||AAAA {KEY_TYPE} {pin} 2026-01-01T00:00:00Z"),
        format!("|2|AAAA|{pin}x {KEY_TYPE} {pin} 2026-01-01T00:00:00Z"),
        format!("|2|{}|{pin} {KEY_TYPE} {pin} 2026-01-01T00:00:00Z", "A".repeat(200)),
    ] {
        let s = KnownCerts::parse_bytes(bad.as_bytes());
        assert!(s.is_empty(), "{bad}");
        assert!(!s.is_truncated());
    }
}

#[test]
fn caps_mark_the_store_truncated() {
    let long = "#".repeat(MAX_LINE + 1);
    let s = KnownCerts::parse_bytes(long.as_bytes());
    assert!(s.is_truncated());
    assert!(matches!(s.save(Path::new("unused")), Err(KnownCertsError::Truncated)));
    let many = "# c\n".repeat(MAX_LINES + 1);
    assert!(KnownCerts::parse_bytes(many.as_bytes()).is_truncated());
    assert!(KnownCerts::parse_bytes(b"\xff\xfe").is_truncated(), "non-UTF-8 is not rewritten");
}

#[test]
fn save_load_and_locked_updates() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("sub").join(CertProtocol::Rdp.file_name());
    assert!(KnownCerts::load(&path).expect("missing is empty").is_empty());
    KnownCerts::add_and_save(&path, "a.example.test", 3389, &fp(6), T0).expect("add");
    KnownCerts::add_and_save(&path, "b.example.test", 3389, &fp(7), T0).expect("add");
    let s = KnownCerts::load(&path).expect("load");
    assert_eq!(s.check("a.example.test", 3389, &fp(6)), CertTrust::Trusted);
    assert_eq!(s.check("b.example.test", 3389, &fp(7)), CertTrust::Trusted);
    assert_eq!(KnownCerts::remove_and_save(&path, "a.example.test", 3389).expect("rm"), 1);
    assert_eq!(KnownCerts::remove_and_save(&path, "a.example.test", 3389).expect("rm"), 0);
    assert_eq!(KnownCerts::load(&path).expect("load").len(), 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    assert_eq!(CertProtocol::Vnc.file_name(), "known_vnc_certs");
}

proptest! {
    /// The parser never panics on hostile bytes (the `known_certs_parse` fuzz property), and
    /// anything it accepts survives a write/read cycle byte for byte.
    #[test]
    fn hostile_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let s = KnownCerts::parse_bytes(&bytes);
        let _ = s.list();
        let _ = s.check("h.example.test", 1, &[0; 32]);
        if !s.is_truncated() {
            let text = s.to_file_string();
            prop_assert_eq!(KnownCerts::parse_bytes(text.as_bytes()).to_file_string(), text);
        }
    }

    #[test]
    fn added_pins_round_trip(
        hosts in proptest::collection::vec(("[a-z]{1,12}\\.example\\.test", 1..=65535u16, any::<u8>()), 1..12),
    ) {
        let mut s = KnownCerts::new();
        for (h, p, seed) in &hosts {
            if !s.has_pin(h, *p) {
                s.add(h, *p, &fp(*seed), T0);
            }
        }
        let back = KnownCerts::parse_bytes(s.to_file_string().as_bytes());
        prop_assert_eq!(back.len(), s.len());
        for (h, p, _) in &hosts {
            prop_assert_eq!(back.check(h, *p, &[0xAA; 32]), s.check(h, *p, &[0xAA; 32]));
            let mismatch = matches!(back.check(h, *p, &[0xAA; 32]), CertTrust::Mismatch { .. });
            prop_assert!(mismatch, "a pinned host refuses another certificate");
        }
    }
}
