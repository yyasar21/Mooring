//! The `MSY1` blob (ADR-0017 §2). All integers big-endian.
//!
//! ```text
//! offset  len  field
//!      0    4  magic "MSY1"
//!      4    1  version = 1
//!      5   16  vault_id        (UUID bytes, must equal the local vault id)
//!     21   16  device_id       (UUID bytes of the writer)
//!     37    8  counter         u64, ≥ 1, +1 per push
//!     45    8  parent_counter  u64, < counter; 0 = no parent
//!     53   32  parent_hash     SHA-256 of the parent blob's full bytes; zero ⇔ no parent
//!     85   32  header_hash     SHA-256 of the remote `header` object (vault header bytes)
//!    117    8  created_unix    u64 seconds
//!    125   24  nonce           XChaCha20-Poly1305, random
//!    149    …  ciphertext ‖ 16-byte tag   (plaintext = canonical snapshot JSON ≤ 64 MiB)
//! ```
//!
//! * `key = HKDF-SHA256(ikm = DEK, salt = vault_id bytes, info = "mooring sync v1")`
//!   ([`sync_key`]); AAD = bytes `0..125` (every byte before the nonce).
//! * [`decode_msy1`] is a pure function over `&[u8]`: it checks the length window, magic,
//!   version and the counter/parent invariants before anything is decrypted or allocated.
//! * The blob hash used as `parent_hash` is [`blob_hash`] over the complete encoded bytes.

use mooring_vault::{Sealed, SubKey, Vault};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{Result, SyncError};

/// Magic bytes.
pub const MAGIC: [u8; 4] = *b"MSY1";
/// Format version.
pub const VERSION: u8 = 1;
/// Length of the authenticated fixed header (the AAD).
pub const AAD_LEN: usize = 125;
/// `XChaCha20` nonce length.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;
/// Largest snapshot plaintext (ADR-0017 §1).
pub const MAX_PLAINTEXT: usize = 64 << 20;
/// Smallest well-formed blob.
pub const MIN_BLOB: usize = AAD_LEN + NONCE_LEN + TAG_LEN;
/// Largest blob accepted anywhere (download cap and decoder cap).
pub const MAX_BLOB: usize = MIN_BLOB + MAX_PLAINTEXT;
/// HKDF `info` of the sync key.
pub const SYNC_INFO: &[u8] = b"mooring sync v1";

/// The authenticated fixed header of a blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobHeader {
    /// Vault the blob belongs to.
    pub vault_id: Uuid,
    /// Writer device.
    pub device_id: Uuid,
    /// Sync generation.
    pub counter: u64,
    /// Generation of the blob this one was built on (0 = none).
    pub parent_counter: u64,
    /// SHA-256 of the parent blob (zero = none).
    pub parent_hash: [u8; 32],
    /// SHA-256 of the remote vault header object.
    pub header_hash: [u8; 32],
    /// Creation time, Unix seconds.
    pub created_unix: u64,
}

impl BlobHeader {
    /// The 125 AAD bytes.
    pub fn to_bytes(&self) -> [u8; AAD_LEN] {
        let mut b = [0u8; AAD_LEN];
        b[0..4].copy_from_slice(&MAGIC);
        b[4] = VERSION;
        b[5..21].copy_from_slice(self.vault_id.as_bytes());
        b[21..37].copy_from_slice(self.device_id.as_bytes());
        b[37..45].copy_from_slice(&self.counter.to_be_bytes());
        b[45..53].copy_from_slice(&self.parent_counter.to_be_bytes());
        b[53..85].copy_from_slice(&self.parent_hash);
        b[85..117].copy_from_slice(&self.header_hash);
        b[117..125].copy_from_slice(&self.created_unix.to_be_bytes());
        b
    }

    fn check(&self) -> Result<()> {
        let fmt = SyncError::Format;
        if self.vault_id.is_nil() || self.device_id.is_nil() {
            return Err(fmt("nil vault or device id"));
        }
        if self.counter == 0 || self.parent_counter >= self.counter {
            return Err(fmt("counter must be ≥ 1 and above parent_counter"));
        }
        if (self.parent_counter == 0) != (self.parent_hash == [0u8; 32]) {
            return Err(fmt("parent_counter and parent_hash disagree"));
        }
        if self.header_hash == [0u8; 32] {
            return Err(fmt("zero header_hash"));
        }
        Ok(())
    }
}

/// A decoded, not yet authenticated blob borrowing the input.
#[derive(Debug, Clone, Copy)]
pub struct Msy1<'a> {
    /// Parsed fixed header.
    pub header: BlobHeader,
    /// The AAD bytes (`0..125`).
    pub aad: &'a [u8],
    /// Nonce.
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext with tag.
    pub ciphertext: &'a [u8],
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_be_bytes(a)
}

fn arr<const N: usize>(b: &[u8], at: usize) -> [u8; N] {
    let mut a = [0u8; N];
    a.copy_from_slice(&b[at..at + N]);
    a
}

/// Parse an `MSY1` blob. Pure, total, allocation-free; never panics (fuzz target).
pub fn decode_msy1(bytes: &[u8]) -> Result<Msy1<'_>> {
    if bytes.len() > MAX_BLOB {
        return Err(SyncError::TooLarge);
    }
    if bytes.len() < MIN_BLOB {
        return Err(SyncError::Format("blob too short"));
    }
    if bytes[0..4] != MAGIC {
        return Err(SyncError::Format("bad magic"));
    }
    if bytes[4] != VERSION {
        return Err(SyncError::Format("unsupported version"));
    }
    let header = BlobHeader {
        vault_id: Uuid::from_bytes(arr(bytes, 5)),
        device_id: Uuid::from_bytes(arr(bytes, 21)),
        counter: u64_at(bytes, 37),
        parent_counter: u64_at(bytes, 45),
        parent_hash: arr(bytes, 53),
        header_hash: arr(bytes, 85),
        created_unix: u64_at(bytes, 117),
    };
    header.check()?;
    Ok(Msy1 {
        header,
        aad: &bytes[..AAD_LEN],
        nonce: arr(bytes, AAD_LEN),
        ciphertext: &bytes[AAD_LEN + NONCE_LEN..],
    })
}

/// The sync key of `vault` (unlocked).
pub fn sync_key(vault: &Vault) -> Result<SubKey> {
    let id = vault.vault_id();
    if id.is_nil() {
        return Err(SyncError::Invalid("vault header has no id yet; unlock once first"));
    }
    Ok(vault.derive_subkey(id.as_bytes(), SYNC_INFO)?)
}

/// Encrypt `plaintext` under a fresh random nonce.
pub fn encode_msy1(header: &BlobHeader, key: &SubKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    encode(header, plaintext, |aad| key.seal(aad, plaintext))
}

/// Encrypt with a caller-chosen nonce (test vectors only).
pub fn encode_msy1_with_nonce(
    header: &BlobHeader,
    key: &SubKey,
    nonce: [u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    encode(header, plaintext, |aad| key.seal_with_nonce(nonce, aad, plaintext))
}

fn encode(
    header: &BlobHeader,
    plaintext: &[u8],
    seal: impl FnOnce(&[u8]) -> Result<Sealed, mooring_vault::VaultError>,
) -> Result<Vec<u8>> {
    header.check()?;
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(SyncError::TooLarge);
    }
    let aad = header.to_bytes();
    let sealed = seal(&aad)?;
    if sealed.nonce.len() != NONCE_LEN {
        return Err(SyncError::Format("nonce length"));
    }
    let mut out = Vec::with_capacity(MIN_BLOB + plaintext.len());
    out.extend_from_slice(&aad);
    out.extend_from_slice(&sealed.nonce);
    out.extend_from_slice(&sealed.ciphertext);
    Ok(out)
}

/// Authenticate and decrypt a decoded blob. Plaintext is zeroized on drop.
pub fn open_msy1(blob: &Msy1<'_>, key: &SubKey) -> Result<Zeroizing<Vec<u8>>> {
    let sealed = Sealed { nonce: blob.nonce.to_vec(), ciphertext: blob.ciphertext.to_vec() };
    key.open(blob.aad, &sealed).map_err(|_| SyncError::Tampered)
}

/// SHA-256 of a blob's (or header object's) full bytes.
pub fn blob_hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
