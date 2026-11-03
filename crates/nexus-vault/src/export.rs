//! Portable backup: an `age` (v1, scrypt passphrase recipient, ASCII-armored) file around a
//! JSON document whose secret fields are still sealed per field (ADR-0006).
//!
//! The export passphrase is separate from the master password (the caller must not reuse it).
//! Errors are fixed strings: they never contain the passphrase or any plaintext.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::iter;

use age::armor::{ArmoredReader, ArmoredWriter, Format};
use age::scrypt;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::VaultError;
use crate::format::{Header, Sealed};

/// Minimum export passphrase length (characters).
pub const MIN_EXPORT_PASSPHRASE_CHARS: usize = 12;
/// Largest armored input accepted by [`import_age`], and largest decrypted payload.
pub const MAX_EXPORT_BYTES: usize = 64 * 1024 * 1024;
/// Highest scrypt work factor (`N = 2^n`) accepted on import: about 1 GiB of memory with
/// age's `r = 8`. Bounds what a hostile file can make us spend.
pub const MAX_IMPORT_SCRYPT_LOG_N: u8 = 20;

/// One credential record: its id and every sealed field by name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedRecord {
    /// Record id (the AAD prefix of every field).
    pub record_id: String,
    /// Sealed fields keyed by field name (the AAD suffix).
    pub fields: BTreeMap<String, Sealed>,
}

/// Everything a backup holds. Folders and connections stay opaque JSON until `nexus-store`
/// defines them (ADR-0005).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExportDocument {
    /// Vault header (v2). Needed to unlock the sealed fields after import.
    pub header: Header,
    /// Credential records with their sealed fields.
    pub credentials: Vec<ExportedRecord>,
    /// Folder tree, opaque here.
    pub folders: serde_json::Value,
    /// Connections, opaque here.
    pub connections: serde_json::Value,
}

fn check_passphrase(passphrase: &SecretString) -> Result<(), VaultError> {
    if passphrase.expose_secret().chars().count() < MIN_EXPORT_PASSPHRASE_CHARS {
        return Err(VaultError::WeakPassword { min: MIN_EXPORT_PASSPHRASE_CHARS });
    }
    Ok(())
}

/// Encrypt `doc` to an armored `age` file. The scrypt work factor is age's own (~1 s here).
pub fn export_age(doc: &ExportDocument, passphrase: &SecretString) -> Result<Vec<u8>, VaultError> {
    export_age_inner(doc, passphrase, None)
}

/// [`export_age`] with a fixed scrypt work factor; only for fast tests and test vectors.
pub(crate) fn export_age_inner(
    doc: &ExportDocument,
    passphrase: &SecretString,
    log_n: Option<u8>,
) -> Result<Vec<u8>, VaultError> {
    check_passphrase(passphrase)?;
    doc.header.check().map_err(|_| VaultError::Export("invalid vault header in export"))?;
    let json = Zeroizing::new(
        serde_json::to_vec(doc).map_err(|_| VaultError::Export("could not serialise export"))?,
    );
    if json.len() > MAX_EXPORT_BYTES / 2 {
        return Err(VaultError::Export("export too large"));
    }

    let mut recipient = scrypt::Recipient::new(age::secrecy::SecretString::from(
        passphrase.expose_secret().to_owned(),
    ));
    if let Some(n) = log_n {
        if !(1..64).contains(&n) {
            return Err(VaultError::Export("invalid work factor"));
        }
        recipient.set_work_factor(n);
    }
    let encryptor = age::Encryptor::with_recipients(iter::once(&recipient as &dyn age::Recipient))
        .map_err(|_| VaultError::Export("could not set up age encryption"))?;

    let io = |_| VaultError::Export("age write failed");
    let mut out = Vec::with_capacity(json.len() * 4 / 3 + 512);
    let armor = ArmoredWriter::wrap_output(&mut out, Format::AsciiArmor).map_err(io)?;
    let mut writer = encryptor.wrap_output(armor).map_err(io)?;
    writer.write_all(&json).map_err(io)?;
    writer.finish().and_then(ArmoredWriter::finish).map_err(io)?;
    tracing::info!(records = doc.credentials.len(), bytes = out.len(), "vault exported");
    Ok(out)
}

/// Decrypt and parse an `age` export (armored or binary). Refuses inputs over
/// [`MAX_EXPORT_BYTES`], scrypt work factors over [`MAX_IMPORT_SCRYPT_LOG_N`], and headers that
/// fail the structural / KDF-floor checks.
pub fn import_age(bytes: &[u8], passphrase: &SecretString) -> Result<ExportDocument, VaultError> {
    check_passphrase(passphrase)?;
    if bytes.len() > MAX_EXPORT_BYTES {
        return Err(VaultError::Export("export file too large"));
    }
    let decryptor = age::Decryptor::new_buffered(ArmoredReader::new(bytes))
        .map_err(|_| VaultError::Export("not an age file"))?;
    if !decryptor.is_scrypt() {
        return Err(VaultError::Export("export is not passphrase-encrypted"));
    }
    let mut identity = scrypt::Identity::new(age::secrecy::SecretString::from(
        passphrase.expose_secret().to_owned(),
    ));
    identity.set_max_work_factor(MAX_IMPORT_SCRYPT_LOG_N);
    let reader = decryptor.decrypt(iter::once(&identity as &dyn age::Identity)).map_err(|e| {
        match e {
            age::DecryptError::ExcessiveWork { .. } => {
                VaultError::Export("export work factor too high")
            }
            // Wrong passphrase and a tampered stanza are deliberately one message.
            _ => VaultError::Export("wrong passphrase or corrupted export"),
        }
    })?;

    let mut json = Zeroizing::new(Vec::new());
    let limit = u64::try_from(MAX_EXPORT_BYTES).unwrap_or(u64::MAX) + 1;
    reader
        .take(limit)
        .read_to_end(&mut json)
        .map_err(|_| VaultError::Export("wrong passphrase or corrupted export"))?;
    if json.len() > MAX_EXPORT_BYTES {
        return Err(VaultError::Export("export payload too large"));
    }
    let doc: ExportDocument = serde_json::from_slice(&json)
        .map_err(|_| VaultError::Export("export payload is not a Nexus document"))?;
    doc.header.check().map_err(|_| VaultError::Export("invalid vault header in export"))?;
    tracing::info!(records = doc.credentials.len(), "vault export imported");
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::KdfParams;
    use crate::vault::Vault;

    const PASS: &str = "an export passphrase";
    /// Low scrypt cost so unit tests stay fast; production uses age's calibrated default.
    const FAST: Option<u8> = Some(10);

    fn s(v: &str) -> SecretString {
        SecretString::from(v.to_owned())
    }

    fn doc() -> (Vault, ExportDocument) {
        let v = Vault::create(&s("correct horse battery"), KdfParams::TEST).expect("create");
        let mut fields = BTreeMap::new();
        fields.insert("password".to_owned(), v.seal("cred-1", "password", b"hunter2").expect("s"));
        let doc = ExportDocument {
            header: v.header().clone(),
            credentials: vec![ExportedRecord { record_id: "cred-1".into(), fields }],
            folders: serde_json::json!([{ "id": "f1", "name": "Lab" }]),
            connections: serde_json::json!([{ "id": "c1", "host": "db.example.test" }]),
        };
        (v, doc)
    }

    #[test]
    fn round_trip_and_fields_still_open() {
        let (v, d) = doc();
        let bytes = export_age_inner(&d, &s(PASS), FAST).expect("export");
        let text = String::from_utf8(bytes.clone()).expect("armored is ascii");
        assert!(text.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
        assert!(!text.contains("hunter2") && !text.contains("db.example.test"));

        let back = import_age(&bytes, &s(PASS)).expect("import");
        assert_eq!(back, d);
        let sealed = &back.credentials[0].fields["password"];
        assert_eq!(v.open("cred-1", "password", sealed).expect("open").as_slice(), b"hunter2");
    }

    #[test]
    fn default_work_factor_round_trips() {
        let (_, d) = doc();
        let bytes = export_age(&d, &s(PASS)).expect("export");
        assert_eq!(import_age(&bytes, &s(PASS)).expect("import"), d);
    }

    #[test]
    fn passphrase_policy_and_wrong_passphrase() {
        let (_, d) = doc();
        let min = MIN_EXPORT_PASSPHRASE_CHARS;
        assert_eq!(export_age(&d, &s("short")), Err(VaultError::WeakPassword { min }));
        let bytes = export_age_inner(&d, &s(PASS), FAST).expect("export");
        assert_eq!(import_age(&bytes, &s("short")), Err(VaultError::WeakPassword { min }));
        let err = import_age(&bytes, &s("not the passphrase")).expect_err("wrong");
        assert_eq!(err, VaultError::Export("wrong passphrase or corrupted export"));
        let shown = err.to_string();
        assert!(!shown.contains("not the passphrase") && !shown.contains(PASS));
    }

    #[test]
    fn hostile_inputs_are_refused() {
        let pass = s(PASS);
        let big = vec![b'a'; MAX_EXPORT_BYTES + 1];
        assert_eq!(import_age(&big, &pass), Err(VaultError::Export("export file too large")));
        assert_eq!(import_age(b"garbage", &pass), Err(VaultError::Export("not an age file")));

        let (_, d) = doc();
        let bytes = export_age_inner(&d, &pass, FAST).expect("export");
        // flip one base64 char in the body: header MAC or payload fails
        let mut t = bytes.clone();
        let i = t.len() / 2;
        t[i] = if t[i] == b'A' { b'B' } else { b'A' };
        assert!(matches!(import_age(&t, &pass), Err(VaultError::Export(_))));

        // A work factor above the cap is refused before any scrypt work. Build a binary age file
        // at log_n = 10 and rewrite the stanza's work factor (age checks it before the MAC).
        let mut recipient = scrypt::Recipient::new(age::secrecy::SecretString::from(PASS));
        recipient.set_work_factor(10);
        let enc = age::Encryptor::with_recipients(iter::once(&recipient as &dyn age::Recipient))
            .expect("encryptor");
        let mut bin = Vec::new();
        let mut w = enc.wrap_output(&mut bin).expect("wrap");
        w.write_all(b"{}").expect("write");
        w.finish().expect("finish");
        let text = String::from_utf8_lossy(&bin).into_owned();
        let header_end = text.find("\n---").expect("age header");
        let patched = text[..header_end].replacen(" 10\n", " 30\n", 1);
        assert_ne!(patched, text[..header_end], "work factor field found");
        let mut costly = patched.into_bytes();
        costly.extend_from_slice(&bin[header_end..]);
        assert_eq!(
            import_age(&costly, &pass),
            Err(VaultError::Export("export work factor too high"))
        );
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        /// Stand-in until a cargo-fuzz target exists: arbitrary bytes never panic either parser.
        #[test]
        fn arbitrary_input_never_panics(
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2048),
            prefix in proptest::sample::select(vec![
                &b""[..],
                b"-----BEGIN AGE ENCRYPTED FILE-----\n",
                b"age-encryption.org/v1\n-> scrypt ",
                b"{\"magic\":\"NEXUSVAULT\",\"version\":2,",
            ]),
        ) {
            let mut input = prefix.to_vec();
            input.extend_from_slice(&bytes);
            let _ = import_age(&input, &s(PASS));
            let _ = Header::from_bytes(&input);
        }
    }

    /// Encrypt arbitrary bytes with age directly, bypassing `export_age`'s header check.
    fn raw_age(payload: &[u8]) -> Vec<u8> {
        let mut recipient = scrypt::Recipient::new(age::secrecy::SecretString::from(PASS));
        recipient.set_work_factor(10);
        let enc = age::Encryptor::with_recipients(iter::once(&recipient as &dyn age::Recipient))
            .expect("encryptor");
        let mut out = Vec::new();
        let mut w = enc.wrap_output(&mut out).expect("wrap");
        w.write_all(payload).expect("write");
        w.finish().expect("finish");
        out
    }

    #[test]
    fn import_refuses_hostile_kdf_cost_in_header() {
        let (_, d) = doc();
        for params in [
            KdfParams { m_kib: u32::MAX, t: 1, p: 1 },
            KdfParams { m_kib: KdfParams::TEST.m_kib, t: u32::MAX, p: 1 },
            KdfParams { m_kib: KdfParams::TEST.m_kib, t: 1, p: 0x00FF_FFFF },
            KdfParams { m_kib: u32::MAX, t: u32::MAX, p: 0x00FF_FFFF },
        ] {
            let mut hostile = d.clone();
            hostile.header.kdf_params = params;
            let bytes = raw_age(&serde_json::to_vec(&hostile).expect("json"));
            assert_eq!(
                import_age(&bytes, &s(PASS)),
                Err(VaultError::Export("invalid vault header in export")),
                "{params:?}"
            );
        }
        // the same path accepts a sane header
        let ok = raw_age(&serde_json::to_vec(&d).expect("json"));
        assert_eq!(import_age(&ok, &s(PASS)).expect("import"), d);
    }

    #[test]
    fn payload_must_be_a_valid_document() {
        let pass = s(PASS);
        let (_, mut d) = doc();
        d.header.kdf_params.m_kib = 64; // below the floor
        assert_eq!(
            export_age_inner(&d, &pass, FAST),
            Err(VaultError::Export("invalid vault header in export"))
        );
    }
}
