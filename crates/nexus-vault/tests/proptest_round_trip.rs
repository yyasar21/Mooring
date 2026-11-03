//! Property tests: any plaintext round-trips; any single-bit flip is detected.

use nexus_vault::{KdfParams, Vault, VaultError};
use proptest::prelude::*;
use secrecy::SecretString;

fn vault() -> Vault {
    Vault::create(&SecretString::from("property test password".to_owned()), KdfParams::TEST)
        .expect("create")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn round_trips_any_bytes(record in "[a-z0-9-]{1,40}", field in "[a-z_]{1,20}", data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let v = vault();
        let s = v.seal(&record, &field, &data).expect("seal");
        let opened = v.open(&record, &field, &s).expect("open");
        prop_assert_eq!(opened.as_slice(), data.as_slice());
    }

    #[test]
    fn any_bit_flip_is_detected(data in proptest::collection::vec(any::<u8>(), 1..256), bit in 0usize..2048) {
        let v = vault();
        let mut s = v.seal("r", "f", &data).expect("seal");
        let total_bits = s.ciphertext.len() * 8;
        let b = bit % total_bits;
        s.ciphertext[b / 8] ^= 1 << (b % 8);
        prop_assert_eq!(v.open("r", "f", &s), Err(VaultError::Tampered));
    }
}
