//! `MSY1` vectors, round trip, tamper, HKDF domain separation, caps, decoder proptests.

use std::collections::{BTreeMap, BTreeSet};

use mooring_store::{ConnectionRow, CredentialRow, FolderRow};
use mooring_vault::Vault;
use proptest::prelude::*;
use secrecy::SecretString;
use uuid::Uuid;

use super::{vaults, vectors_dir, VECTOR_PASSWORD};
use crate::blob::{
    blob_hash, decode_msy1, encode_msy1, encode_msy1_with_nonce, open_msy1, sync_key, BlobHeader,
    AAD_LEN, MAX_BLOB, MAX_PLAINTEXT, MIN_BLOB, NONCE_LEN, SYNC_INFO,
};
use crate::snapshot::{tomb_key, RecordKind, Snapshot, Tombstone};
use crate::SyncError;

const TS: &str = "2026-11-04T10:00:00Z";
const FOLDER: &str = "6e657875-0000-4000-8000-00000000f001";
const CONN: &str = "6e657875-0000-4000-8000-00000000c001";
const CRED: &str = "6e657875-0000-4000-8000-00000000a001";

fn vector_vault() -> Vault {
    let bytes = std::fs::read(vectors_dir().join("vault-header.json")).expect("vault header");
    let mut v = Vault::from_header_bytes(&bytes).expect("header");
    v.unlock(&SecretString::from(VECTOR_PASSWORD.to_owned())).expect("unlock");
    v
}

fn vector_snapshot(vault_id: Uuid) -> Snapshot {
    let mut s = Snapshot::empty(vault_id, "vector-device");
    let folder = FolderRow {
        created_at: TS.into(),
        default_credential_id: Some(CRED.into()),
        id: FOLDER.into(),
        name: "All connections".into(),
        parent_id: None,
        sort: 0,
        updated_at: TS.into(),
    };
    let conn = ConnectionRow {
        created_at: TS.into(),
        credential_id: Some(CRED.into()),
        domain_override: None,
        folder_id: FOLDER.into(),
        host: "vector.example.test".into(),
        id: CONN.into(),
        name: "vector ssh".into(),
        options_json: "{}".into(),
        port: Some(22),
        protocol: "ssh".into(),
        roles: BTreeMap::new(),
        tags: vec!["lab".into(), "vector".into()],
        updated_at: TS.into(),
        username_override: None,
    };
    // An opaque sealed value: the snapshot never opens it.
    let sealed =
        r#"{"nonce":"000102030405060708090a0b0c0d0e0f1011121314151617","ciphertext":"00"}"#;
    let cred = CredentialRow {
        created_at: TS.into(),
        fields_json: r#"{"username":"ops"}"#.into(),
        id: CRED.into(),
        kind: "user_password".into(),
        name: "vector credential".into(),
        secrets: [("password".to_owned(), sealed.to_owned())].into_iter().collect(),
        updated_at: TS.into(),
    };
    s.folders.insert(FOLDER.into(), folder);
    s.connections.insert(CONN.into(), conn);
    s.credentials.insert(CRED.into(), cred);
    let hosts: BTreeSet<String> =
        ["vector.example.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHZlY3Rvcg=="]
            .into_iter()
            .map(str::to_owned)
            .collect();
    s.trust.insert("known_hosts".into(), hosts);
    let gone = "6e657875-0000-4000-8000-00000000c002";
    s.tombstones.insert(
        tomb_key(RecordKind::Connection, gone),
        Tombstone { deleted_at: TS.into(), id: gone.into(), kind: RecordKind::Connection },
    );
    s
}

fn vector_header(vault_id: Uuid, header_hash: [u8; 32]) -> BlobHeader {
    BlobHeader {
        vault_id,
        device_id: Uuid::from_u128(0x6e65_7875_0000_4000_8000_6465_7669_6365),
        counter: 7,
        parent_counter: 6,
        parent_hash: [0x5a; 32],
        header_hash,
        created_unix: 1_793_786_400,
    }
}

fn nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[..12].copy_from_slice(b"msy1-vector-");
    n
}

/// Regenerate with `MOORING_BLESS=1 cargo test -p mooring-sync vectors`.
#[test]
fn committed_vectors_match_and_open() {
    let v = vector_vault();
    let header_bytes = std::fs::read(vectors_dir().join("vault-header.json")).expect("header");
    let snap = vector_snapshot(v.vault_id());
    let plaintext = snap.encode().expect("encode");
    let key = sync_key(&v).expect("key");
    let bh = vector_header(v.vault_id(), blob_hash(&header_bytes));
    let blob = encode_msy1_with_nonce(&bh, &key, nonce(), &plaintext).expect("blob");
    let blob_hex = format!("{}\n", hex::encode(&blob));
    if std::env::var("MOORING_BLESS").as_deref() == Ok("1") {
        std::fs::write(vectors_dir().join("snapshot.json"), plaintext.as_slice()).expect("w");
        std::fs::write(vectors_dir().join("blob-v1.hex"), &blob_hex).expect("w");
    }
    let on_disk_snap = std::fs::read(vectors_dir().join("snapshot.json")).expect("snapshot.json");
    let on_disk_blob = std::fs::read_to_string(vectors_dir().join("blob-v1.hex")).expect("hex");
    assert_eq!(on_disk_snap, plaintext.as_slice(), "snapshot.json drifted");
    assert_eq!(on_disk_blob, blob_hex, "blob-v1.hex drifted");

    let bytes = hex::decode(on_disk_blob.trim()).expect("hex");
    let m = decode_msy1(&bytes).expect("decode");
    assert_eq!(m.header, bh);
    assert_eq!(&bytes[..4], b"MSY1");
    let opened = open_msy1(&m, &key).expect("open");
    assert_eq!(Snapshot::decode(&opened, v.vault_id()).expect("snapshot"), snap);
}

#[test]
fn canonical_encoding_is_sorted_and_stable() {
    let s = vector_snapshot(Uuid::from_u128(9));
    let a = s.encode().expect("a");
    let via_value =
        serde_json::to_vec(&serde_json::to_value(&s).expect("value")).expect("value bytes");
    assert_eq!(a.as_slice(), via_value.as_slice(), "struct field order is alphabetical");
    assert_eq!(s.clone().encode().expect("b").as_slice(), a.as_slice());
    assert!(matches!(Snapshot::decode(&a, Uuid::from_u128(8)), Err(SyncError::WrongVault)));
    let mut extra: serde_json::Value = serde_json::from_slice(&a).expect("json");
    extra["unexpected"] = serde_json::json!(1);
    let extra = serde_json::to_vec(&extra).expect("bytes");
    assert!(Snapshot::decode(&extra, Uuid::from_u128(9)).is_err(), "unknown fields refused");
}

fn sample() -> (Vault, BlobHeader, Vec<u8>) {
    let v = vaults(1).remove(0);
    let h = BlobHeader {
        vault_id: v.vault_id(),
        device_id: Uuid::new_v4(),
        counter: 1,
        parent_counter: 0,
        parent_hash: [0; 32],
        header_hash: [1; 32],
        created_unix: 1,
    };
    let blob = encode_msy1(&h, &sync_key(&v).expect("key"), b"{\"x\":1}").expect("blob");
    (v, h, blob)
}

fn shared() -> &'static (Vault, BlobHeader, Vec<u8>) {
    static S: std::sync::OnceLock<(Vault, BlobHeader, Vec<u8>)> = std::sync::OnceLock::new();
    S.get_or_init(sample)
}

#[test]
fn round_trip_and_random_nonces() {
    let (v, h, blob) = sample();
    let key = sync_key(&v).expect("key");
    let m = decode_msy1(&blob).expect("decode");
    assert_eq!(m.header, h);
    assert_eq!(open_msy1(&m, &key).expect("open").as_slice(), b"{\"x\":1}");
    let again = encode_msy1(&h, &key, b"{\"x\":1}").expect("again");
    assert_ne!(again, blob, "fresh nonce per blob");
    assert_eq!(blob.len(), MIN_BLOB + 7);
}

#[test]
fn every_header_field_and_the_body_are_authenticated() {
    let (v, _, blob) = sample();
    let key = sync_key(&v).expect("key");
    // Byte offsets of vault_id, device_id, counter, parent_counter, header_hash, created,
    // nonce, ciphertext, tag.
    for at in [5, 21, 44, 85, 120, AAD_LEN, AAD_LEN + NONCE_LEN, blob.len() - 1] {
        let mut t = blob.clone();
        t[at] ^= 0x01;
        match decode_msy1(&t) {
            Ok(m) => assert!(
                matches!(open_msy1(&m, &key), Err(SyncError::Tampered)),
                "flip at {at} must fail authentication"
            ),
            Err(SyncError::Format(_)) => {} // e.g. counter invariants
            Err(e) => panic!("unexpected {e:?} at {at}"),
        }
    }
    let mut counter_bump = blob.clone();
    counter_bump[44] = 2; // counter 1 → 2 stays well-formed
    let m = decode_msy1(&counter_bump).expect("well-formed");
    assert_eq!(m.header.counter, 2);
    assert!(matches!(open_msy1(&m, &key), Err(SyncError::Tampered)));
}

#[test]
fn hkdf_domain_separation() {
    let mut vs = vaults(2);
    let other_vault = vaults(1).remove(0);
    let v = vs.remove(0);
    let (_, _, blob) = shared();
    let m = decode_msy1(blob).expect("decode");
    // `sample` used its own vault: neither this vault nor another opens it.
    assert!(matches!(open_msy1(&m, &sync_key(&v).expect("k")), Err(SyncError::Tampered)));
    assert!(matches!(open_msy1(&m, &sync_key(&other_vault).expect("k")), Err(SyncError::Tampered)));
    // Same DEK, other info / salt → other key.
    let k = sync_key(&v).expect("k");
    let sealed = k.seal(b"aad", b"x").expect("seal");
    let other_info = v.derive_subkey(v.vault_id().as_bytes(), b"mooring sync v2").expect("k2");
    let other_salt = v.derive_subkey(Uuid::new_v4().as_bytes(), SYNC_INFO).expect("k3");
    assert!(other_info.open(b"aad", &sealed).is_err());
    assert!(other_salt.open(b"aad", &sealed).is_err());
    assert!(vs[0]
        .derive_subkey(v.vault_id().as_bytes(), SYNC_INFO)
        .expect("k")
        .open(b"aad", &sealed)
        .is_ok());
}

#[test]
fn caps_and_invariants() {
    assert!(matches!(decode_msy1(&vec![0u8; MAX_BLOB + 1]), Err(SyncError::TooLarge)));
    assert!(matches!(decode_msy1(&[0u8; MIN_BLOB - 1]), Err(SyncError::Format(_))));
    let (v, h, blob) = sample();
    let mut bad = blob.clone();
    bad[4] = 2;
    assert!(matches!(decode_msy1(&bad), Err(SyncError::Format("unsupported version"))));
    let key = sync_key(&v).expect("k");
    for broken in [
        BlobHeader { counter: 0, ..h },
        BlobHeader { parent_counter: 1, ..h },
        BlobHeader { counter: 2, parent_counter: 1, ..h },
        BlobHeader { parent_hash: [3; 32], ..h },
        BlobHeader { header_hash: [0; 32], ..h },
        BlobHeader { device_id: Uuid::nil(), ..h },
    ] {
        assert!(encode_msy1(&broken, &key, b"{}").is_err(), "{broken:?}");
    }
    let big = vec![b' '; MAX_PLAINTEXT + 1];
    assert!(matches!(encode_msy1(&h, &key, &big), Err(SyncError::TooLarge)));
    assert!(matches!(Snapshot::decode(&big, v.vault_id()), Err(SyncError::TooLarge)));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn decode_never_panics(data in proptest::collection::vec(any::<u8>(), 0..400)) {
        crate::fuzz::fuzz_msy1(&data);
        crate::fuzz::fuzz_snapshot_json(&data);
    }

    #[test]
    fn any_bit_flip_is_rejected(at in 0usize..(MIN_BLOB + 7), bit in 0u8..8) {
        let (v, _, blob) = shared();
        let key = sync_key(v).expect("key");
        let mut t = blob.clone();
        t[at] ^= 1 << bit;
        if let Ok(m) = decode_msy1(&t) {
            prop_assert!(open_msy1(&m, &key).is_err());
        }
    }

    #[test]
    fn prefixed_valid_headers_decode(counter in 1u64..u64::MAX, created in any::<u64>(), tail in 0usize..64) {
        let h = BlobHeader {
            vault_id: Uuid::from_u128(1), device_id: Uuid::from_u128(2), counter,
            parent_counter: counter - 1,
            parent_hash: if counter == 1 { [0; 32] } else { [7; 32] },
            header_hash: [9; 32], created_unix: created,
        };
        let mut bytes = h.to_bytes().to_vec();
        bytes.resize(MIN_BLOB + tail, 0);
        let m = decode_msy1(&bytes).expect("decodes");
        prop_assert_eq!(m.header, h);
    }
}
