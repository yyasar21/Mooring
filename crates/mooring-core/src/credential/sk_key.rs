//! FIDO2 / `sk-*` OpenSSH keys (ADR-0024 §1): a bounded, hand-written parser for the public
//! key blob, the public key line, the user certificate line and the key-handle file
//! (`id_*_sk`, an `openssh-key-v1` private key that holds only the authenticator's handle).
//!
//! Every input is hostile: lengths are checked before every read, every string has a cap,
//! trailing bytes are refused, and nothing panics (proptest + the `sk_key_parse` fuzz entry
//! [`fuzz_sk_key_parse`]). Errors name the field, never a value.

use sha2_next::{Digest, Sha256};
use zeroize::Zeroizing;

use super::fingerprint::{MAX_PEM, MAX_PUBLIC_KEY};
use super::CredentialError;

/// `sk-ssh-ed25519@openssh.com`.
pub const SK_ED25519: &str = "sk-ssh-ed25519@openssh.com";
/// `sk-ecdsa-sha2-nistp256@openssh.com`.
pub const SK_ECDSA_P256: &str = "sk-ecdsa-sha2-nistp256@openssh.com";
/// Largest public key blob we accept (bytes).
pub const MAX_SK_BLOB: usize = 4096;
/// Longest FIDO application string (bytes, `ssh:` prefixed).
pub const MAX_APPLICATION: usize = 256;
/// Longest key handle (FIDO credential ids are at most 1023 bytes).
pub const MAX_KEY_HANDLE: usize = 1024;
/// Authenticator flag: user presence (touch) was tested.
pub const SK_FLAG_USER_PRESENCE: u8 = 0x01;
/// Authenticator flag: user verification (PIN / biometry) is required.
pub const SK_FLAG_USER_VERIFICATION: u8 = 0x04;
/// Key flag: the credential is resident (discoverable) on the authenticator.
pub const SK_FLAG_RESIDENT: u8 = 0x20;

const MAX_RESERVED: usize = 256;
const MAX_COMMENT: usize = 1024;
const MAX_NAME: usize = 64;
const AUTH_MAGIC: &[u8] = b"openssh-key-v1\0";

/// The two FIDO2 key types OpenSSH knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkAlgorithm {
    /// `sk-ssh-ed25519@openssh.com`.
    Ed25519,
    /// `sk-ecdsa-sha2-nistp256@openssh.com`.
    EcdsaP256,
}

impl SkAlgorithm {
    /// Wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => SK_ED25519,
            Self::EcdsaP256 => SK_ECDSA_P256,
        }
    }

    /// Parse a wire name (`None` for anything else, certificates included).
    #[must_use]
    pub fn parse(name: &[u8]) -> Option<Self> {
        match name {
            n if n == SK_ED25519.as_bytes() => Some(Self::Ed25519),
            n if n == SK_ECDSA_P256.as_bytes() => Some(Self::EcdsaP256),
            _ => None,
        }
    }
}

/// A parsed `sk-*` public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkPublicKey {
    /// Key type.
    pub algorithm: SkAlgorithm,
    /// FIDO application (relying party id), `ssh:` by default.
    pub application: String,
    /// The SSH wire blob (what the agent lists and the server sees).
    pub blob: Vec<u8>,
    /// OpenSSH `SHA256:` fingerprint of the blob.
    pub fingerprint: String,
}

impl SkPublicKey {
    /// The OpenSSH public key line (`<algorithm> <base64>`, no comment).
    #[must_use]
    pub fn line(&self) -> String {
        format!("{} {}", self.algorithm.name(), data_encoding::BASE64.encode(&self.blob))
    }
}

/// What a key-handle file reveals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkKeyHandle {
    /// The public half (always clear text in the file).
    pub public: SkPublicKey,
    /// The private section is passphrase-protected (flags are then unknown).
    pub encrypted: bool,
    /// Key flags (`SK_FLAG_*`), when the file is not encrypted.
    pub flags: Option<u8>,
}

impl SkKeyHandle {
    /// Whether the key is resident (only known for an unencrypted file).
    #[must_use]
    pub fn resident(&self) -> Option<bool> {
        self.flags.map(|f| f & SK_FLAG_RESIDENT != 0)
    }
}

fn bad(field: &'static str, reason: &'static str) -> CredentialError {
    CredentialError::invalid(field, reason)
}

/// Bounded big-endian SSH wire reader (RFC 4251 §5). Never panics.
#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    field: &'static str,
}

impl<'a> Reader<'a> {
    /// A reader over `buf`; errors name `field`.
    #[must_use]
    pub const fn new(buf: &'a [u8], field: &'static str) -> Self {
        Self { buf, field }
    }

    fn short(&self) -> CredentialError {
        bad(self.field, "is truncated")
    }

    /// Next `n` raw bytes.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], CredentialError> {
        if n > self.buf.len() {
            return Err(self.short());
        }
        let (head, rest) = self.buf.split_at(n);
        self.buf = rest;
        Ok(head)
    }

    /// One byte.
    pub fn u8(&mut self) -> Result<u8, CredentialError> {
        Ok(self.take(1)?.first().copied().unwrap_or_default())
    }

    /// Big-endian `uint32`.
    pub fn u32(&mut self) -> Result<u32, CredentialError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A length-prefixed `string` of at most `max` bytes.
    pub fn string(&mut self, max: usize) -> Result<&'a [u8], CredentialError> {
        let len = usize::try_from(self.u32()?).map_err(|_| self.short())?;
        if len > max {
            return Err(bad(self.field, "has an oversized field"));
        }
        self.take(len)
    }

    /// Bytes left.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len()
    }

    /// Refuse trailing bytes.
    pub fn finish(&self) -> Result<(), CredentialError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(bad(self.field, "has trailing bytes"))
        }
    }
}

/// OpenSSH `SHA256:` fingerprint of a key blob.
#[must_use]
pub fn blob_fingerprint(blob: &[u8]) -> String {
    format!("SHA256:{}", data_encoding::BASE64_NOPAD.encode(&Sha256::digest(blob)))
}

fn application(field: &'static str, raw: &[u8]) -> Result<String, CredentialError> {
    if raw.is_empty() {
        return Err(bad(field, "has no FIDO application"));
    }
    let ok = raw.iter().all(u8::is_ascii_graphic);
    let text = std::str::from_utf8(raw).ok().filter(|_| ok);
    match text {
        Some(t) if t.starts_with("ssh:") => Ok(t.to_owned()),
        _ => Err(bad(field, "has an application that is not ssh:…")),
    }
}

/// Read the key part of an `sk-*` blob after its algorithm name (shared by the public blob
/// and the private section of a key-handle file). Returns the application.
fn read_key_body(
    r: &mut Reader<'_>,
    algorithm: SkAlgorithm,
    field: &'static str,
) -> Result<String, CredentialError> {
    match algorithm {
        SkAlgorithm::Ed25519 => {
            if r.string(64)?.len() != 32 {
                return Err(bad(field, "has an Ed25519 point of the wrong size"));
            }
        }
        SkAlgorithm::EcdsaP256 => {
            if r.string(MAX_NAME)? != b"nistp256" {
                return Err(bad(field, "is not on the nistp256 curve"));
            }
            let q = r.string(133)?;
            if q.len() != 65 || q.first() != Some(&0x04) {
                return Err(bad(field, "has a P-256 point that is not uncompressed"));
            }
        }
    }
    application(field, r.string(MAX_APPLICATION)?)
}

/// Parse an `sk-*` public key blob (SSH wire form).
pub fn parse_sk_public_blob(blob: &[u8]) -> Result<SkPublicKey, CredentialError> {
    const F: &str = "public_key";
    if blob.len() > MAX_SK_BLOB {
        return Err(bad(F, "is too long"));
    }
    let mut r = Reader::new(blob, F);
    let algorithm = SkAlgorithm::parse(r.string(MAX_NAME)?)
        .ok_or_else(|| bad(F, "is not a FIDO2 (sk-*) key"))?;
    let application = read_key_body(&mut r, algorithm, F)?;
    r.finish()?;
    // Second opinion from ssh-key (framing only: it does not check that a P-256 point is on
    // the curve; the agent and the server do).
    if ssh_key::PublicKey::from_bytes(blob).is_err() {
        return Err(bad(F, "is not a valid OpenSSH public key"));
    }
    Ok(SkPublicKey {
        algorithm,
        application,
        blob: blob.to_vec(),
        fingerprint: blob_fingerprint(blob),
    })
}

fn split_line(
    field: &'static str,
    text: &str,
    max: usize,
) -> Result<(String, Vec<u8>), CredentialError> {
    if text.len() > max {
        return Err(bad(field, "is too long"));
    }
    let line = text.trim();
    if line.is_empty() || line.contains(['\n', '\r']) {
        return Err(bad(field, "must be one OpenSSH line"));
    }
    let mut parts = line.split_ascii_whitespace();
    let alg = parts.next().unwrap_or_default().to_owned();
    let b64 = parts.next().ok_or_else(|| bad(field, "has no key data"))?;
    let blob =
        data_encoding::BASE64.decode(b64.as_bytes()).map_err(|_| bad(field, "is not base64"))?;
    Ok((alg, blob))
}

/// Parse an OpenSSH `sk-*` public key line (`sk-ssh-ed25519@openssh.com AAAA… comment`).
pub fn parse_sk_public_line(text: &str) -> Result<SkPublicKey, CredentialError> {
    let (alg, blob) = split_line("public_key", text, MAX_PUBLIC_KEY)?;
    if alg.ends_with("-cert-v01@openssh.com") {
        return Err(bad("public_key", "this is a certificate; put it in certificate"));
    }
    let key = parse_sk_public_blob(&blob)?;
    if alg != key.algorithm.name() {
        return Err(bad("public_key", "names another algorithm than its key data"));
    }
    Ok(key)
}

/// Parse an `sk-*` user certificate line (`sk-ssh-ed25519-cert-v01@openssh.com …`) and return
/// the certified key. Certificate validity is the server's and `check_signed_certificate`'s
/// business; this only proves it certifies an `sk-*` key.
pub fn parse_sk_certificate_line(text: &str) -> Result<SkPublicKey, CredentialError> {
    const F: &str = "certificate";
    let (alg, _) = split_line(F, text, MAX_PEM)?;
    let base = alg
        .strip_suffix("-cert-v01@openssh.com")
        .and_then(|a| SkAlgorithm::parse(format!("{a}@openssh.com").as_bytes()))
        .ok_or_else(|| bad(F, "is not a FIDO2 (sk-*) certificate"))?;
    let cert = ssh_key::Certificate::from_openssh(text.trim())
        .map_err(|_| bad(F, "not an OpenSSH certificate"))?;
    let blob = ssh_key::PublicKey::from(cert.public_key().clone())
        .to_bytes()
        .map_err(|_| bad(F, "certified key is not encodable"))?;
    let key = parse_sk_public_blob(&blob).map_err(|_| bad(F, "does not certify a FIDO2 key"))?;
    if key.algorithm != base {
        return Err(bad(F, "names another algorithm than its key"));
    }
    Ok(key)
}

/// The decoded `openssh-key-v1` body of a key-handle file.
fn openssh_body(pem: &[u8]) -> Result<Vec<u8>, CredentialError> {
    const F: &str = "private_key";
    const BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
    const END: &str = "-----END OPENSSH PRIVATE KEY-----";
    if pem.len() > MAX_PEM {
        return Err(bad(F, "larger than 64 KiB"));
    }
    let not_file = || bad(F, "must be an OpenSSH private key file");
    let text = std::str::from_utf8(pem).map_err(|_| bad(F, "must be PEM text"))?.trim();
    // OpenSSH wraps at 70 columns (not RFC 7468's 64), so the body is read leniently.
    let inner = text.strip_prefix(BEGIN).and_then(|t| t.strip_suffix(END)).ok_or_else(not_file)?;
    if inner.contains("-----") {
        return Err(not_file());
    }
    let b64: Vec<u8> = inner.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    data_encoding::BASE64.decode(&b64).map_err(|_| not_file())
}

/// Parse a key-handle file (`id_ed25519_sk` / `id_ecdsa_sk`). The public half must be an
/// `sk-*` key; an unencrypted private section must repeat it and its flags are reported.
pub fn parse_sk_key_handle(pem: &[u8]) -> Result<SkKeyHandle, CredentialError> {
    const F: &str = "private_key";
    let body = Zeroizing::new(openssh_body(pem)?);
    let mut r = Reader::new(&body, F);
    if r.take(AUTH_MAGIC.len())? != AUTH_MAGIC {
        return Err(bad(F, "must be an OpenSSH private key file"));
    }
    let cipher = r.string(MAX_NAME)?;
    let kdf = r.string(MAX_NAME)?;
    let _kdf_options = r.string(1024)?;
    if r.u32()? != 1 {
        return Err(bad(F, "must hold exactly one key"));
    }
    let public = parse_sk_public_blob(r.string(MAX_SK_BLOB)?)?;
    let private = r.string(MAX_PEM)?;
    r.finish()?;
    if cipher != b"none" {
        if kdf != b"bcrypt" {
            return Err(bad(F, "uses an unknown key derivation"));
        }
        return Ok(SkKeyHandle { public, encrypted: true, flags: None });
    }
    if kdf != b"none" {
        return Err(bad(F, "is malformed"));
    }
    let section = read_private_section(private, &public)?;
    Ok(SkKeyHandle { public, encrypted: false, flags: Some(section.flags) })
}

struct PrivateSection<'a> {
    flags: u8,
    /// `keytype … reserved` as `sshkey_private_serialize` writes it (ssh-sk-helper input).
    serialized: &'a [u8],
}

fn read_private_section<'a>(
    private: &'a [u8],
    public: &SkPublicKey,
) -> Result<PrivateSection<'a>, CredentialError> {
    const F: &str = "private_key";
    let mut r = Reader::new(private, F);
    if r.u32()? != r.u32()? {
        return Err(bad(F, "has a bad check value"));
    }
    let start = r.remaining();
    let algorithm = SkAlgorithm::parse(r.string(MAX_NAME)?)
        .ok_or_else(|| bad(F, "is not a FIDO2 (sk-*) key handle"))?;
    if algorithm != public.algorithm {
        return Err(bad(F, "names another algorithm than its public key"));
    }
    let app = read_key_body(&mut r, algorithm, F)?;
    if app != public.application {
        return Err(bad(F, "names another application than its public key"));
    }
    let flags = r.u8()?;
    if r.string(MAX_KEY_HANDLE)?.is_empty() {
        return Err(bad(F, "has an empty key handle"));
    }
    let _reserved = r.string(MAX_RESERVED)?;
    let used = start - r.remaining();
    let serialized = private.get(8..8 + used).ok_or_else(|| bad(F, "is truncated"))?;
    let _comment = r.string(MAX_COMMENT)?;
    // Padding is 1, 2, 3, … up to the cipher block size (8 for `none`).
    let pad = r.take(r.remaining())?;
    if pad.len() >= 8 || pad.iter().zip(1u8..).any(|(b, i)| *b != i) {
        return Err(bad(F, "has bad padding"));
    }
    // The private section's key fields must be the public blob's.
    let mut check = Vec::with_capacity(public.blob.len());
    let mut pr = Reader::new(serialized, F);
    let name = pr.string(MAX_NAME)?;
    check.extend_from_slice(&u32::try_from(name.len()).unwrap_or(0).to_be_bytes());
    check.extend_from_slice(name);
    let key_len = public.blob.len() - check.len();
    check.extend_from_slice(pr.take(key_len)?);
    if check != public.blob {
        return Err(bad(F, "does not match its public key"));
    }
    Ok(PrivateSection { flags, serialized })
}

/// The key as `sshkey_private_serialize` writes it (`keytype … reserved`), from an
/// **unencrypted** key-handle file: what `ssh-sk-helper` takes in a sign request
/// (ADR-0024 §3). The handle is not secret by FIDO design, but stays zeroized anyway.
pub fn sk_helper_key_blob(
    pem: &[u8],
) -> Result<(SkKeyHandle, Zeroizing<Vec<u8>>), CredentialError> {
    const F: &str = "private_key";
    let body = Zeroizing::new(openssh_body(pem)?);
    let handle = parse_sk_key_handle(pem)?;
    if handle.encrypted {
        return Err(bad(F, "must be decrypted first"));
    }
    let mut r = Reader::new(&body, F);
    r.take(AUTH_MAGIC.len())?;
    for _ in 0..3 {
        r.string(1024)?;
    }
    r.u32()?;
    r.string(MAX_SK_BLOB)?;
    let section = read_private_section(r.string(MAX_PEM)?, &handle.public)?;
    Ok((handle, Zeroizing::new(section.serialized.to_vec())))
}

/// Fuzz entry `sk_key_parse` (qa wires it in `fuzz/`): every parser of this module on the same
/// bytes. Never panics.
pub fn fuzz_sk_key_parse(data: &[u8]) {
    let _ = parse_sk_public_blob(data);
    let _ = parse_sk_key_handle(data);
    let _ = sk_helper_key_blob(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = parse_sk_public_line(text);
        let _ = parse_sk_certificate_line(text);
    }
}

#[cfg(test)]
#[path = "sk_key_tests.rs"]
mod tests;
