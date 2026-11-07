//! Tests of the `sk-*` parser (ADR-0024): vectors and hostile input.

use proptest::prelude::*;

use super::*;
use crate::credential::testdata::{
    public_line, sk_ecdsa_public, sk_ed25519_public, sk_key_handle_pem, ED25519_PUB,
};

fn s(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&u32::try_from(b.len()).expect("len").to_be_bytes());
    out.extend_from_slice(b);
}

fn ed_blob(point: &[u8], app: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    s(&mut b, SK_ED25519.as_bytes());
    s(&mut b, point);
    s(&mut b, app);
    b
}

fn ed() -> ssh_key::PublicKey {
    sk_ed25519_public([7; 32], "ssh:")
}

#[test]
fn ed25519_line_vector() {
    let key = ed();
    let parsed = parse_sk_public_line(&public_line(&key)).expect("parses");
    assert_eq!(parsed.algorithm, SkAlgorithm::Ed25519);
    assert_eq!(parsed.application, "ssh:");
    assert_eq!(parsed.fingerprint, key.fingerprint(ssh_key::HashAlg::Sha256).to_string());
    assert_eq!(parsed.blob, key.to_bytes().expect("blob"));
    let with_comment = format!("  {} yubikey@example.test\n", public_line(&key));
    assert_eq!(parse_sk_public_line(&with_comment).expect("comment"), parsed);
}

#[test]
fn ecdsa_line_vector() {
    let key = sk_ecdsa_public("ssh:mooring");
    let parsed = parse_sk_public_line(&public_line(&key)).expect("parses");
    assert_eq!(parsed.algorithm, SkAlgorithm::EcdsaP256);
    assert_eq!(parsed.application, "ssh:mooring");
    assert_eq!(parsed.fingerprint, key.fingerprint(ssh_key::HashAlg::Sha256).to_string());
}

#[test]
fn non_sk_and_mismatched_lines_are_refused() {
    let e = parse_sk_public_line(ED25519_PUB).expect_err("plain ed25519").to_string();
    assert!(e.contains("not a FIDO2"), "{e}");
    let ecdsa_line = public_line(&sk_ecdsa_public("ssh:"));
    let body = ecdsa_line.split(' ').nth(1).expect("b64");
    let e = parse_sk_public_line(&format!("{SK_ED25519} {body}")).expect_err("alg").to_string();
    assert!(e.contains("another algorithm"), "{e}");
    assert!(parse_sk_public_line("").is_err());
    assert!(parse_sk_public_line(SK_ED25519).is_err(), "no key data");
    assert!(parse_sk_public_line(&format!("{SK_ED25519} !!!")).is_err(), "not base64");
    let two = format!("{}\n{}", public_line(&ed()), public_line(&ed()));
    assert!(parse_sk_public_line(&two).is_err(), "one line");
}

#[test]
fn hostile_blobs() {
    let good = ed_blob(&[7; 32], b"ssh:");
    assert!(parse_sk_public_blob(&good).is_ok());
    for n in 0..good.len() {
        assert!(parse_sk_public_blob(&good[..n]).is_err(), "truncated at {n}");
    }
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(parse_sk_public_blob(&trailing)
        .expect_err("trailing")
        .to_string()
        .contains("trailing"));
    assert!(parse_sk_public_blob(&ed_blob(&[7; 31], b"ssh:")).is_err(), "short point");
    let e = parse_sk_public_blob(&ed_blob(&[7; 32], b"")).expect_err("no app").to_string();
    assert!(e.contains("no FIDO application"), "{e}");
    assert!(parse_sk_public_blob(&ed_blob(&[7; 32], b"https://x")).is_err(), "ssh: only");
    assert!(parse_sk_public_blob(&ed_blob(&[7; 32], b"ssh:\x1b[31m")).is_err(), "control");
    let long_app = [b"ssh:".as_slice(), &[b'a'; 300]].concat();
    assert!(parse_sk_public_blob(&ed_blob(&[7; 32], &long_app)).is_err(), "oversized app");
    assert!(parse_sk_public_blob(&vec![0u8; MAX_SK_BLOB + 1]).is_err(), "oversized blob");
    let mut huge_len = Vec::new();
    huge_len.extend_from_slice(&u32::MAX.to_be_bytes());
    assert!(parse_sk_public_blob(&huge_len).is_err());
}

#[test]
fn wrong_curve_and_point_form() {
    let g = sk_ecdsa_public("ssh:").to_bytes().expect("blob");
    let mut r = Reader::new(&g, "t");
    r.string(64).expect("alg");
    r.string(64).expect("curve");
    let q = r.string(133).expect("q").to_vec();
    let mk = |curve: &[u8], q: &[u8]| {
        let mut b = Vec::new();
        s(&mut b, SK_ECDSA_P256.as_bytes());
        s(&mut b, curve);
        s(&mut b, q);
        s(&mut b, b"ssh:");
        b
    };
    assert!(parse_sk_public_blob(&mk(b"nistp256", &q)).is_ok());
    let e = parse_sk_public_blob(&mk(b"nistp384", &q)).expect_err("curve").to_string();
    assert!(e.contains("nistp256"), "{e}");
    let mut compressed = q.clone();
    compressed[0] = 0x02;
    assert!(parse_sk_public_blob(&mk(b"nistp256", &compressed)).is_err());
    // On-curve validation is the signer's and the server's: no P-256 arithmetic here.
    assert_eq!(q.len(), 65);
}

#[test]
fn key_handle_vectors_and_flags() {
    for (flags, resident) in [(0x01, false), (0x21, true), (0x25, true)] {
        let pem = sk_key_handle_pem(&ed(), flags, b"handle-bytes");
        let h = parse_sk_key_handle(pem.as_bytes()).expect("parses");
        assert!(!h.encrypted);
        assert_eq!(h.flags, Some(flags));
        assert_eq!(h.resident(), Some(resident));
        assert_eq!(h.public.fingerprint, ed().fingerprint(ssh_key::HashAlg::Sha256).to_string());
    }
    let pem = sk_key_handle_pem(&sk_ecdsa_public("ssh:x"), 0x01, b"h");
    assert_eq!(parse_sk_key_handle(pem.as_bytes()).expect("ecdsa").public.application, "ssh:x");
    let (h, blob) = sk_helper_key_blob(pem.as_bytes()).expect("helper blob");
    assert_eq!(h.public.algorithm, SkAlgorithm::EcdsaP256);
    assert!(blob.starts_with(&[0, 0, 0, 34]) && blob[4..38] == *SK_ECDSA_P256.as_bytes());
}

/// Build an `openssh-key-v1` file around `public` / `private` sections (test only).
fn file(cipher: &str, kdf: &str, public: &[u8], private: &[u8]) -> String {
    let mut body = b"openssh-key-v1\0".to_vec();
    s(&mut body, cipher.as_bytes());
    s(&mut body, kdf.as_bytes());
    s(&mut body, b"");
    body.extend_from_slice(&1u32.to_be_bytes());
    s(&mut body, public);
    s(&mut body, private);
    wrap(&body)
}

fn wrap(body: &[u8]) -> String {
    let b64 = data_encoding::BASE64.encode(body);
    let lines: Vec<&str> =
        b64.as_bytes().chunks(70).map(|c| std::str::from_utf8(c).expect("ascii")).collect();
    format!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
        lines.join("\n")
    )
}

fn unwrap_body(pem: &str) -> Vec<u8> {
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    data_encoding::BASE64.decode(b64.as_bytes()).expect("b64")
}

fn section(point: &[u8], app: &[u8], handle: &[u8], pad: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&[1, 2, 3, 4, 1, 2, 3, 4]);
    s(&mut p, SK_ED25519.as_bytes());
    s(&mut p, point);
    s(&mut p, app);
    p.push(0x01);
    s(&mut p, handle);
    s(&mut p, b"");
    s(&mut p, b"c");
    p.extend_from_slice(pad);
    p
}

#[test]
fn hostile_key_handles() {
    let public = ed_blob(&[7; 32], b"ssh:");
    let ok = file("none", "none", &public, &section(&[7; 32], b"ssh:", b"h", &[1, 2, 3]));
    assert!(parse_sk_key_handle(ok.as_bytes()).is_ok());
    let cases = [
        ("other key", section(&[8; 32], b"ssh:", b"h", &[1, 2, 3])),
        ("other app", section(&[7; 32], b"ssh:other", b"h", &[1, 2, 3])),
        ("empty handle", section(&[7; 32], b"ssh:", b"", &[1, 2, 3])),
        ("bad padding", section(&[7; 32], b"ssh:", b"h", &[1, 3])),
        ("long padding", section(&[7; 32], b"ssh:", b"h", &[1, 2, 3, 4, 5, 6, 7, 8])),
    ];
    for (what, priv_section) in cases {
        let f = file("none", "none", &public, &priv_section);
        assert!(parse_sk_key_handle(f.as_bytes()).is_err(), "{what}");
    }
    let mut bad_check = section(&[7; 32], b"ssh:", b"h", &[1, 2, 3]);
    bad_check[7] = 9;
    assert!(parse_sk_key_handle(file("none", "none", &public, &bad_check).as_bytes()).is_err());
    let enc = file("aes256-ctr", "bcrypt", &public, &[0xAA; 64]);
    let h = parse_sk_key_handle(enc.as_bytes()).expect("encrypted");
    assert!(h.encrypted && h.flags.is_none() && h.resident().is_none());
    assert!(sk_helper_key_blob(enc.as_bytes()).is_err(), "helper needs it decrypted");
    assert!(parse_sk_key_handle(file("aes256-ctr", "scrypt", &public, &[0; 8]).as_bytes()).is_err());
    let plain = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[1; 32]));
    let plain = plain.to_openssh(ssh_key::LineEnding::LF).expect("pem");
    assert!(parse_sk_key_handle(plain.as_bytes()).is_err(), "not an sk key");
    assert!(parse_sk_key_handle(
        b"-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----"
    )
    .is_err());
}

#[test]
fn sk_certificate_line() {
    use ssh_key::certificate::{Builder, CertType};
    let ca = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[9; 32]));
    let mut b = Builder::new([1; 16], ed().key_data().clone(), 0, u64::MAX).expect("builder");
    b.cert_type(CertType::User).expect("type");
    b.valid_principal("alice").expect("principal");
    let line = b.sign(&ca).expect("sign").to_openssh().expect("line");
    assert!(line.starts_with("sk-ssh-ed25519-cert-v01@openssh.com "), "{line}");
    let key = parse_sk_certificate_line(&line).expect("parses");
    assert_eq!(key.blob, ed().to_bytes().expect("blob"));
    assert!(parse_sk_certificate_line(&public_line(&ed())).is_err(), "not a certificate");
    assert!(parse_sk_public_line(&line).is_err(), "certificate in public_key");
    let plain = crate::credential::testdata::SSH_CA_CERT;
    assert!(parse_sk_certificate_line(plain).is_err(), "certifies a plain key");
}

proptest! {
    #[test]
    fn never_panics(data in proptest::collection::vec(any::<u8>(), 0..600)) {
        fuzz_sk_key_parse(&data);
    }

    #[test]
    fn never_panics_on_framed_noise(body in "[A-Za-z0-9+/=]{0,400}") {
        fuzz_sk_key_parse(format!("{SK_ED25519} {body}").as_bytes());
        fuzz_sk_key_parse(format!("sk-ssh-ed25519-cert-v01@openssh.com {body}").as_bytes());
        fuzz_sk_key_parse(
            format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----")
                .as_bytes(),
        );
    }

    #[test]
    fn mutated_handle_files_never_panic(i in 0usize..400, b in any::<u8>()) {
        let pem = sk_key_handle_pem(&ed(), 0x21, b"handle");
        let mut body = unwrap_body(&pem);
        let n = body.len();
        body[i % n] = b;
        fuzz_sk_key_parse(wrap(&body).as_bytes());
        fuzz_sk_key_parse(wrap(&body[..i % n]).as_bytes());
    }
}
