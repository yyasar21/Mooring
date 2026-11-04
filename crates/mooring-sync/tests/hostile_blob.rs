//! Hostile `MSY1` objects (ADR-0017 §2 and §Test plan): truncation at every length, size
//! overflow, a tampered header field, nonce, ciphertext byte or AEAD tag, a stripped tag, a
//! foreign vault id, and a header that re-encodes differently. The header is checked before
//! any body is touched, an AEAD failure is `sync.tampered` and never a panic, and no error
//! text carries bytes of the blob.

use mooring_sync::blob::{
    decode_msy1, encode_msy1, open_msy1, sync_key, BlobHeader, AAD_LEN, MAX_BLOB, MIN_BLOB,
    NONCE_LEN, TAG_LEN,
};
use mooring_sync::SyncError;
use mooring_vault::{KdfParams, Vault};
use secrecy::SecretString;
use uuid::Uuid;

type Mutate = Box<dyn Fn(&mut BlobHeader)>;

fn vault() -> Vault {
    Vault::create(&SecretString::from("test-password-only".to_owned()), KdfParams::TEST)
        .expect("vault")
}

fn header(vault: &Vault) -> BlobHeader {
    BlobHeader {
        vault_id: vault.vault_id(),
        device_id: Uuid::from_u128(0x6465_7669_6365),
        counter: 7,
        parent_counter: 6,
        parent_hash: [0x5a; 32],
        header_hash: [0x1f; 32],
        created_unix: 1_793_786_400,
    }
}

const PLAINTEXT: &[u8] = br#"{"connections":{},"credentials":{},"device_name":"laptop","folders":{},"tombstones":{},"trust":{},"vault_id":"00000000-0000-0000-0000-000000000001","version":1}"#;

fn blob(vault: &Vault) -> Vec<u8> {
    let key = sync_key(vault).expect("key");
    encode_msy1(&header(vault), &key, PLAINTEXT).expect("encode")
}

fn open(vault: &Vault, bytes: &[u8]) -> Result<Vec<u8>, SyncError> {
    let key = sync_key(vault).expect("key");
    let m = decode_msy1(bytes)?;
    open_msy1(&m, &key).map(|p| p.to_vec())
}

#[test]
fn the_baseline_opens() {
    let v = vault();
    assert_eq!(open(&v, &blob(&v)).expect("opens"), PLAINTEXT);
}

/// Every prefix of a valid blob is refused: a short one as `sync.format`, one that keeps the
/// full fixed header but loses ciphertext as `sync.tampered`. Nothing panics.
#[test]
fn every_truncation_is_refused() {
    let v = vault();
    let b = blob(&v);
    for n in 0..b.len() {
        let e = open(&v, &b[..n]).expect_err("truncated");
        if n < MIN_BLOB {
            assert_eq!(e.code(), "sync.format", "{n}: {e}");
        } else {
            assert_eq!(e.code(), "sync.tampered", "{n}: {e}");
        }
    }
}

/// Over the cap the blob is refused before any header parsing; one byte over a valid blob
/// (an appended byte) is an AEAD failure; `MIN_BLOB` exactly (an empty plaintext) parses.
#[test]
fn length_bounds_are_enforced_before_the_body() {
    let v = vault();
    let mut big = vec![0u8; MAX_BLOB + 1];
    big[..4].copy_from_slice(b"MSY1");
    assert_eq!(decode_msy1(&big).expect_err("too large").code(), "sync.too_large");
    let mut b = blob(&v);
    b.push(0);
    assert_eq!(open(&v, &b).expect_err("appended").code(), "sync.tampered");
    let key = sync_key(&v).expect("key");
    let empty = encode_msy1(&header(&v), &key, b"").expect("encode");
    assert_eq!(empty.len(), MIN_BLOB);
    assert_eq!(open(&v, &empty).expect("opens"), b"");
    let m = decode_msy1(&empty).expect("decodes");
    assert_eq!(m.ciphertext.len(), TAG_LEN);
}

/// Flipping any header byte is caught: structural fields by `decode_msy1` (static reason),
/// the rest by the AEAD (`sync.tampered`). A header that passes `check` re-encodes to its AAD.
#[test]
fn every_header_byte_is_authenticated() {
    let v = vault();
    let b = blob(&v);
    for i in 0..AAD_LEN {
        let mut t = b.clone();
        t[i] ^= 0x01;
        let e = open(&v, &t).expect_err("tampered header byte");
        let text = e.to_string();
        assert!(matches!(e.code(), "sync.format" | "sync.tampered"), "{i}: {e}");
        assert!(!text.contains("MSY1") && !text.contains("laptop"), "{text}");
        if let Ok(m) = decode_msy1(&t) {
            assert_eq!(&m.header.to_bytes()[..], m.aad, "{i}: header re-encodes to its AAD");
        }
    }
    // magic and version are static format errors, not AEAD failures
    let mut t = b.clone();
    t[0] = b'X';
    assert!(decode_msy1(&t).expect_err("magic").to_string().contains("bad magic"));
    let mut t = b.clone();
    t[4] = 2;
    assert_eq!(decode_msy1(&t).expect_err("version").code(), "sync.format");
}

/// A flipped nonce byte, ciphertext byte or tag byte, a tag stripped off and a tag moved
/// to the front: every one is `sync.tampered`.
#[test]
fn nonce_ciphertext_and_tag_are_authenticated() {
    let v = vault();
    let b = blob(&v);
    for i in AAD_LEN..b.len() {
        let mut t = b.clone();
        t[i] ^= 0x80;
        assert_eq!(open(&v, &t).expect_err("tampered").code(), "sync.tampered", "{i}");
    }
    let mut stripped = b.clone();
    stripped.truncate(b.len() - TAG_LEN);
    assert_eq!(open(&v, &stripped).expect_err("no tag").code(), "sync.tampered");
    let mut rotated = b[..AAD_LEN + NONCE_LEN].to_vec();
    rotated.extend_from_slice(&b[b.len() - TAG_LEN..]);
    rotated.extend_from_slice(&b[AAD_LEN + NONCE_LEN..b.len() - TAG_LEN]);
    assert_eq!(open(&v, &rotated).expect_err("rotated").code(), "sync.tampered");
    assert_eq!(open(&v, &vec![0xaa; MIN_BLOB + 64]).expect_err("random").code(), "sync.format");
}

/// A blob sealed by another vault (another DEK) decodes structurally but never opens; a
/// header swapped between two valid blobs fails too (the header is AAD).
#[test]
fn another_vault_or_a_swapped_header_never_opens() {
    let a = vault();
    let b = vault();
    let from_b = blob(&b);
    assert_eq!(open(&a, &from_b).expect_err("foreign key").code(), "sync.tampered");
    let from_a = blob(&a);
    let mut swapped = from_b[..AAD_LEN].to_vec();
    swapped.extend_from_slice(&from_a[AAD_LEN..]);
    assert_eq!(open(&a, &swapped).expect_err("swapped header").code(), "sync.tampered");
    assert_eq!(open(&b, &swapped).expect_err("swapped header").code(), "sync.tampered");
}

/// Structural header rules fire with a static reason: a nil id, counter 0, parent ≥ counter,
/// a parent hash without a parent, and a zero header hash.
#[test]
fn header_rules_are_static_reasons() {
    let v = vault();
    let key = sync_key(&v).expect("key");
    let good = header(&v);
    let cases: [(&str, Mutate); 6] = [
        ("nil vault", Box::new(|h| h.vault_id = Uuid::nil())),
        ("nil device", Box::new(|h| h.device_id = Uuid::nil())),
        ("counter 0", Box::new(|h| h.counter = 0)),
        ("parent ≥ counter", Box::new(|h| h.parent_counter = 7)),
        ("orphan parent hash", Box::new(|h| h.parent_counter = 0)),
        ("zero header hash", Box::new(|h| h.header_hash = [0; 32])),
    ];
    for (what, mutate) in cases {
        let mut h = good;
        mutate(&mut h);
        // encode refuses it, and so does decode of the raw bytes
        assert!(encode_msy1(&h, &key, b"").is_err(), "{what}: encode");
        let mut raw = h.to_bytes().to_vec();
        raw.extend_from_slice(&[0u8; NONCE_LEN + TAG_LEN]);
        let e = decode_msy1(&raw).expect_err(what);
        assert_eq!(e.code(), "sync.format", "{what}: {e}");
    }
}
