//! Certificate TOFU trust store shared by RDP, VNC and the HTTPS clients (ADR-0011 §Trust,
//! ADR-0012 §Trust, ADR-0014 §1).
//!
//! One file per protocol (`$APP_DATA/known_rdp_certs`, `$APP_DATA/known_kube_certs`, …, see
//! [`CertProtocol::file_name`]), one entry per line:
//!
//! ```text
//! |2|<salt b64>|<HMAC-SHA256(salt, "host:port") b64> x509-sha256 <b64 SHA-256(leaf DER)> <added RFC 3339>
//! ```
//!
//! * Entries are always **written** hashed (32-byte random salt). For hand-made files the
//!   parser also **reads** a plain `host:port` (or `[v6]:port`) in place of the hashed field;
//!   the protocol is implied by the file, so a line carries no protocol token.
//! * `host:port` always carries the port (unlike `known_hosts`), host lowercased, IPv6 in
//!   brackets ([`host_key`]). Base64 is standard with padding.
//! * The file is untrusted input: lines over [`MAX_LINE`] bytes and lines past [`MAX_LINES`]
//!   are not parsed; malformed lines are skipped with a `tracing::warn!` naming the line
//!   number only; `#` comments, blank lines and lines with an unknown key type are kept
//!   verbatim so a rewrite never drops them. A store loaded over the caps refuses to save.
//! * [`KnownCerts::parse_bytes`] never fails and never panics (fuzz target
//!   `known_certs_parse`).

mod info;
mod marker;
mod named;
mod protocol;

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use data_encoding::BASE64;
use hmac::{KeyInit, Mac};
use rand_core::{OsRng, RngCore};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub use info::{
    display_fingerprint, fingerprint, hex, peer_identity, CertProblem, CertificateInfo, MAX_DN,
    MAX_SAN, MAX_SAN_LEN,
};
pub use marker::TLS_MARKER;
pub use protocol::CertProtocol;

type HmacSha256 = hmac::Hmac<sha2_next::Sha256>;

/// Longest line that is parsed, in bytes.
pub const MAX_LINE: usize = 8 * 1024;
/// Most lines read from a file.
pub const MAX_LINES: usize = 10_000;
/// Key type token of a SHA-256 leaf pin.
pub const KEY_TYPE: &str = "x509-sha256";
const HASH_MAGIC: &str = "|2|";
const SALT_LEN: usize = 32;

/// Result of looking a presented leaf up in the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertTrust {
    /// A pin for this `host:port` matches.
    Trusted,
    /// No pin names this `host:port`.
    Unknown,
    /// Pinned with a different certificate: hard stop.
    Mismatch {
        /// The (first) stored pin.
        expected: [u8; 32],
    },
    /// More than one distinct pin names this `host:port` (review 6b L-35: two devices accepted
    /// different certificates and the sync merge kept both): hard stop until the user removes
    /// the pins in the known-certificates manager. The presented certificate is not consulted.
    Conflict,
}

/// What the verifier does: the ADR-0011 four-row decision table (the pin wins over the CA).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertVerdict {
    /// Pin matches: accept, even when the chain fails (`chain_valid == false` is shown as a
    /// warning, e.g. expiry).
    AcceptPinned {
        /// Whether the chain also validated.
        chain_valid: bool,
    },
    /// No pin, valid chain: accept and audit `trust.cert.ca_valid`. No pin is written.
    AcceptCa,
    /// Pin differs: close with `trust_mismatch` and audit `trust.cert.mismatch`.
    Mismatch {
        /// Stored pin.
        expected: [u8; 32],
    },
    /// No pin, invalid chain: fail the handshake, prompt `certificate_trust`, reconnect on yes.
    Prompt,
    /// Conflicting pins (L-35): close with `trust_conflict`; never promptable.
    Conflict,
}

/// The decision table. Pure, so RDP and VNC share it exactly.
pub const fn decide(trust: CertTrust, chain_valid: bool) -> CertVerdict {
    match (trust, chain_valid) {
        (CertTrust::Trusted, chain_valid) => CertVerdict::AcceptPinned { chain_valid },
        (CertTrust::Mismatch { expected }, _) => CertVerdict::Mismatch { expected },
        (CertTrust::Unknown, true) => CertVerdict::AcceptCa,
        (CertTrust::Unknown, false) => CertVerdict::Prompt,
        (CertTrust::Conflict, _) => CertVerdict::Conflict,
    }
}

/// One listed pin (IPC `KnownCert { hostHash, fingerprint, addedAt }`). Hashed entries cannot
/// be reversed to a host name, so the host is shown only as its hash field.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownCert {
    /// `|2|salt|hash`, or the plain `host:port` of a hand-written line.
    pub host_hash: String,
    /// `SHA256:<hex>`.
    pub fingerprint: String,
    /// RFC 3339.
    pub added_at: String,
    /// `host` of a known connection whose `host:port` matches the hash ([`KnownCerts::list_named`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Its port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

/// Errors of the trust store. They carry no file content.
#[derive(Debug, thiserror::Error)]
pub enum KnownCertsError {
    /// Reading or writing the file failed.
    #[error("known_certs I/O: {}", .0.kind())]
    Io(#[from] std::io::Error),
    /// The file exceeded the caps on load; rewriting it would drop entries.
    #[error("known_certs exceeds the size cap; not rewritten")]
    Truncated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HostField {
    Plain(String),
    Hashed { salt: Vec<u8>, hash: [u8; 32] },
}

#[derive(Debug, Clone)]
struct Entry {
    host: HostField,
    raw_host: String,
    sha256: [u8; 32],
    added: String,
}

#[derive(Debug, Clone)]
struct Line {
    text: String,
    entry: Option<Entry>,
    /// A "TLS seen" marker for this host (M-13, [`marker`]).
    marker: Option<HostField>,
}

/// A parsed `known_*_certs` file.
#[derive(Debug, Clone, Default)]
pub struct KnownCerts {
    lines: Vec<Line>,
    truncated: bool,
}

/// `host:port` as hashed and matched: host lowercased, IPv6 (any `:` in the host) bracketed.
pub fn host_key(host: &str, port: u16) -> String {
    let host = host.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

impl KnownCerts {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse file bytes. Never fails; anything unusable is skipped.
    pub fn parse_bytes(bytes: &[u8]) -> Self {
        let mut store = Self::default();
        for (idx, raw) in bytes.split(|b| *b == b'\n').enumerate() {
            if idx >= MAX_LINES {
                tracing::warn!(max = MAX_LINES, "known_certs: line cap reached; rest ignored");
                store.truncated = true;
                break;
            }
            let mut raw = raw;
            while let Some(r) = raw.strip_suffix(b"\r") {
                raw = r;
            }
            if raw.len() > MAX_LINE {
                tracing::warn!(line = idx + 1, "known_certs: line too long; skipped");
                store.truncated = true;
                continue;
            }
            let Ok(text) = std::str::from_utf8(raw) else {
                tracing::warn!(line = idx + 1, "known_certs: not UTF-8; skipped");
                store.truncated = true;
                continue;
            };
            let (entry, marker) = match parse_line(text) {
                Parsed::Entry(e) => (Some(*e), None),
                Parsed::Marker(m) => (None, Some(m)),
                Parsed::Ignored => (None, None),
                Parsed::Malformed => {
                    tracing::warn!(line = idx + 1, "known_certs: malformed line; skipped");
                    (None, None)
                }
            };
            store.lines.push(Line { text: text.to_owned(), entry, marker });
        }
        while store.lines.last().is_some_and(|l| l.text.is_empty()) {
            store.lines.pop();
        }
        store
    }

    /// Load a file; a missing file is an empty store. Reads at most the capped size.
    pub fn load(path: &Path) -> Result<Self, KnownCertsError> {
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::new()),
            Err(e) => return Err(e.into()),
        };
        let cap = (MAX_LINE + 2) * MAX_LINES;
        let mut buf = Vec::new();
        file.take(cap as u64 + 1).read_to_end(&mut buf)?;
        let over = buf.len() > cap;
        buf.truncate(cap);
        let mut store = Self::parse_bytes(&buf);
        if over {
            tracing::warn!("known_certs: file size cap reached; rest ignored");
            store.truncated = true;
        }
        Ok(store)
    }

    fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.lines.iter().filter_map(|l| l.entry.as_ref())
    }

    /// Number of usable pins.
    pub fn len(&self) -> usize {
        self.entries().count()
    }

    /// Whether there are no usable pins.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether the load hit a cap (the store then refuses to save).
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Look `sha256` up for `host:port`. One distinct pin: trusted when it matches, else a
    /// mismatch. More than one distinct pin (review 6b L-35: a sync merge kept two devices'
    /// different answers): [`CertTrust::Conflict`], whatever is presented, until the user
    /// removes the pins. Duplicate lines of one pin are not a conflict.
    pub fn check(&self, host: &str, port: u16, sha256: &[u8; 32]) -> CertTrust {
        if self.distinct_pins(host, port) > 1 {
            return CertTrust::Conflict;
        }
        let name = host_key(host, port);
        let mut first = None;
        for e in self.entries().filter(|e| host_matches(&e.host, &name)) {
            if &e.sha256 == sha256 {
                return CertTrust::Trusted;
            }
            first.get_or_insert(e.sha256);
        }
        first.map_or(CertTrust::Unknown, |expected| CertTrust::Mismatch { expected })
    }

    /// Number of **distinct** fingerprints pinned for `host:port` (review 6 L-35: more than
    /// one after a sync merge means two devices accepted different certificates).
    pub fn distinct_pins(&self, host: &str, port: u16) -> usize {
        let name = host_key(host, port);
        let mut seen: Vec<[u8; 32]> =
            self.entries().filter(|e| host_matches(&e.host, &name)).map(|e| e.sha256).collect();
        seen.sort_unstable();
        seen.dedup();
        seen.len()
    }

    /// Whether any pin names `host:port` (VNC downgrade guard, ADR-0012).
    pub fn has_pin(&self, host: &str, port: u16) -> bool {
        let name = host_key(host, port);
        self.entries().any(|e| host_matches(&e.host, &name))
    }

    /// Add a hashed pin with a fresh random salt, dated `added`.
    pub fn add(&mut self, host: &str, port: u16, sha256: &[u8; 32], added: OffsetDateTime) {
        let mut salt = vec![0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let hash = hmac_host(&salt, &host_key(host, port));
        let added = added.format(&Rfc3339).unwrap_or_else(|_| "1970-01-01T00:00:00Z".into());
        let raw_host = format!("{HASH_MAGIC}{}|{}", BASE64.encode(&salt), BASE64.encode(&hash));
        let text = format!("{raw_host} {KEY_TYPE} {} {added}", BASE64.encode(sha256));
        let entry =
            Entry { host: HostField::Hashed { salt, hash }, raw_host, sha256: *sha256, added };
        self.lines.push(Line { text, entry: Some(entry), marker: None });
    }

    /// Remove every pin and "TLS seen" marker for `host:port`; returns how many pins.
    /// Comments and other lines stay.
    pub fn remove(&mut self, host: &str, port: u16) -> usize {
        self.remove_lines(host, port).0
    }

    /// `(pins, markers)` removed.
    fn remove_lines(&mut self, host: &str, port: u16) -> (usize, usize) {
        let name = host_key(host, port);
        let pins = self.entries().filter(|e| host_matches(&e.host, &name)).count();
        let before = self.lines.len();
        self.lines.retain(|l| {
            !l.entry.as_ref().is_some_and(|e| host_matches(&e.host, &name))
                && !l.marker.as_ref().is_some_and(|m| host_matches(m, &name))
        });
        (pins, before - self.lines.len() - pins)
    }

    /// Usable pins in file order.
    pub fn list(&self) -> Vec<KnownCert> {
        self.entries()
            .map(|e| KnownCert {
                host_hash: e.raw_host.clone(),
                fingerprint: display_fingerprint(&e.sha256),
                added_at: e.added.clone(),
                host: None,
                port: None,
            })
            .collect()
    }

    /// File content, one line per entry, newline-terminated.
    pub fn to_file_string(&self) -> String {
        let mut out = String::new();
        for l in &self.lines {
            out.push_str(&l.text);
            out.push('\n');
        }
        out
    }

    /// Write atomically (temp file in the same directory, fsync, rename), mode 0600 on unix.
    /// Refuses when the loaded file exceeded the caps.
    pub fn save(&self, path: &Path) -> Result<(), KnownCertsError> {
        if self.truncated {
            return Err(KnownCertsError::Truncated);
        }
        let dir = match path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => Path::new("."),
        };
        std::fs::create_dir_all(dir)?;
        let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
        tmp.write_all(self.to_file_string().as_bytes())?;
        tmp.as_file().sync_all()?;
        tmp.persist(path).map_err(|e| KnownCertsError::Io(e.error))?;
        Ok(())
    }

    /// Load, add a pin and save under a process-wide per-path lock (concurrent TOFU accepts
    /// never lose an entry). Blocking: call from `spawn_blocking`.
    pub fn add_and_save(
        path: &Path,
        host: &str,
        port: u16,
        sha256: &[u8; 32],
        added: OffsetDateTime,
    ) -> Result<(), KnownCertsError> {
        let lock = path_lock(path);
        let _guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
        let mut store = Self::load(path)?;
        store.add(host, port, sha256, added);
        store.save(path)
    }

    /// Load, remove every pin for `host:port` and save (when anything was removed) under the
    /// same lock. Returns the count for `known_certs_remove`.
    pub fn remove_and_save(path: &Path, host: &str, port: u16) -> Result<usize, KnownCertsError> {
        let lock = path_lock(path);
        let _guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
        let mut store = Self::load(path)?;
        let (removed, markers) = store.remove_lines(host, port);
        if removed + markers > 0 {
            store.save(path)?;
        }
        Ok(removed)
    }
}

/// The process-wide write lock of one trust file (`known_hosts`, `known_*_certs`). Every
/// writer holds it for its load-modify-save: the TOFU accepts here, the SSH `known_hosts`
/// writer and the vault-sync apply (ADR-0017, owner decision 10), so no write is lost or torn.
pub fn write_lock(path: &Path) -> Arc<Mutex<()>> {
    path_lock(path)
}

fn path_lock(path: &Path) -> Arc<Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();
    let mut map = LOCKS.get_or_init(Mutex::default).lock().unwrap_or_else(PoisonError::into_inner);
    Arc::clone(map.entry(path.to_path_buf()).or_default())
}

enum Parsed {
    Entry(Box<Entry>),
    Marker(HostField),
    Ignored,
    Malformed,
}

fn parse_line(line: &str) -> Parsed {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Parsed::Ignored;
    }
    let mut fields = trimmed.split_ascii_whitespace();
    let (Some(host), Some(kind), Some(fp), Some(added), None) =
        (fields.next(), fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return Parsed::Malformed;
    };
    let Some(host_field) = parse_host(host) else {
        return Parsed::Malformed;
    };
    if kind == TLS_MARKER {
        let dated = added.len() <= 64 && OffsetDateTime::parse(added, &Rfc3339).is_ok();
        return if fp == "-" && dated { Parsed::Marker(host_field) } else { Parsed::Malformed };
    }
    if kind != KEY_TYPE {
        // A future pin type: kept verbatim, not used.
        return Parsed::Ignored;
    }
    let Some(sha256) = decode_fixed::<32>(fp) else {
        return Parsed::Malformed;
    };
    if added.len() > 64 || OffsetDateTime::parse(added, &Rfc3339).is_err() {
        return Parsed::Malformed;
    }
    Parsed::Entry(Box::new(Entry {
        host: host_field,
        raw_host: host.to_owned(),
        sha256,
        added: added.to_owned(),
    }))
}

fn decode_fixed<const N: usize>(b64: &str) -> Option<[u8; N]> {
    if b64.len() > 4 * N.div_ceil(3) {
        return None;
    }
    BASE64.decode(b64.as_bytes()).ok()?.try_into().ok()
}

fn parse_host(field: &str) -> Option<HostField> {
    if let Some(rest) = field.strip_prefix(HASH_MAGIC) {
        let (salt, hash) = rest.split_once('|')?;
        if salt.len() > 128 {
            return None;
        }
        let salt = BASE64.decode(salt.as_bytes()).ok()?;
        if salt.is_empty() {
            return None;
        }
        return Some(HostField::Hashed { salt, hash: decode_fixed::<32>(hash)? });
    }
    // Plain `host:port` / `[v6]:port`: needs a numeric port 1..=65535 and a non-empty host.
    let (host, port) = field.rsplit_once(':')?;
    let port: u16 = port.parse().ok().filter(|p| *p != 0)?;
    if host.is_empty() || host.contains('|') || host == "[]" {
        return None;
    }
    if !host.starts_with('[') && host.contains(':') {
        return None;
    }
    Some(HostField::Plain(host_key(host, port)))
}

fn hmac_host(salt: &[u8], name: &str) -> [u8; 32] {
    // HMAC accepts keys of any length, so `new_from_slice` cannot fail; the fallback is
    // unreachable and would only make the entry unmatchable, never trusted.
    let Ok(mac) = <HmacSha256 as KeyInit>::new_from_slice(salt) else {
        return [0; 32];
    };
    mac.chain_update(name.as_bytes()).finalize().into_bytes().into()
}

fn host_matches(host: &HostField, name: &str) -> bool {
    match host {
        HostField::Plain(p) => p == name,
        HostField::Hashed { salt, hash } => <HmacSha256 as KeyInit>::new_from_slice(salt)
            .is_ok_and(|mac| mac.chain_update(name.as_bytes()).verify_slice(hash).is_ok()),
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
