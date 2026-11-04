//! OpenSSH `known_hosts` trust store (ADR-0007).
//!
//! The file is untrusted input: lines longer than [`MAX_LINE`] bytes and lines past
//! [`MAX_LINES`] are not parsed, malformed lines are skipped with a `tracing::warn!` (the line
//! number only, never its content), and unknown key types are ignored. Plain host patterns
//! (with `*`, `?` and `!` negation) and `|1|` HMAC-SHA1 hashed host names are both read; new
//! entries are always written hashed. Lines are kept verbatim so a rewrite never loses entries
//! Mooring does not understand.

use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use hmac::{KeyInit, Mac};
use rand_core::{OsRng, RngCore};
use russh::keys::ssh_encoding::base64::{Base64, Encoding};
use russh::keys::ssh_key::{Algorithm, HashAlg, PublicKey};

type HmacSha1 = hmac::Hmac<sha1::Sha1>;

/// Longest line that is parsed, in bytes.
pub const MAX_LINE: usize = 8 * 1024;
/// Most lines read from a file.
pub const MAX_LINES: usize = 10_000;
/// Default SSH port; other ports are written as `[host]:port`.
pub const DEFAULT_PORT: u16 = 22;
const SALT_LEN: usize = 20;
const HASH_LEN: usize = 20;
const HASH_MAGIC: &str = "|1|";

/// Outcome of looking a presented host key up in the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustDecision {
    /// The key matches a stored entry for this host.
    Known,
    /// No entry names this host.
    Unknown,
    /// The host is known with a different key (or the key is `@revoked`): hard stop.
    Mismatch {
        /// Fingerprint of the stored key, `SHA256:<base64>` (or `revoked`).
        expected_fp: String,
    },
}

/// Errors of the trust store. They carry no file content.
#[derive(Debug)]
pub enum KnownHostsError {
    /// Reading or writing the file failed.
    Io(std::io::Error),
    /// The file exceeded the caps on load; rewriting it would drop entries.
    Truncated,
    /// The key could not be encoded.
    Encode,
}

impl std::fmt::Display for KnownHostsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "known_hosts I/O: {}", e.kind()),
            Self::Truncated => f.write_str("known_hosts exceeds the size cap; not rewritten"),
            Self::Encode => f.write_str("known_hosts: key could not be encoded"),
        }
    }
}

impl std::error::Error for KnownHostsError {}

impl From<std::io::Error> for KnownHostsError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Hosts {
    Patterns(Vec<String>),
    Hashed { salt: Vec<u8>, hash: [u8; HASH_LEN] },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Marker {
    None,
    Revoked,
}

#[derive(Debug, Clone)]
struct Entry {
    marker: Marker,
    hosts: Hosts,
    key: PublicKey,
}

/// A parsed `known_hosts` file.
#[derive(Debug, Clone, Default)]
pub struct KnownHosts {
    /// Original lines, kept verbatim for rewriting.
    lines: Vec<String>,
    entries: Vec<Entry>,
    truncated: bool,
}

/// `host` for port 22, `[host]:port` otherwise (OpenSSH form).
pub fn host_pattern(host: &str, port: u16) -> String {
    if port == DEFAULT_PORT {
        host.to_ascii_lowercase()
    } else {
        format!("[{}]:{port}", host.to_ascii_lowercase())
    }
}

/// OpenSSH `SHA256:<base64 without padding>` fingerprint.
pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

/// `"<key type> SHA256:<fp>"`, the form shown to the user.
pub fn describe_key(key: &PublicKey) -> String {
    format!("{} {}", key.algorithm().as_str(), fingerprint(key))
}

impl KnownHosts {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse file bytes. Never fails; anything unusable is skipped.
    pub fn parse_bytes(bytes: &[u8]) -> Self {
        let mut store = Self::default();
        for (idx, raw) in bytes.split(|b| *b == b'\n').enumerate() {
            if idx >= MAX_LINES {
                tracing::warn!(max = MAX_LINES, "known_hosts: line cap reached; rest ignored");
                store.truncated = true;
                break;
            }
            // Strip every trailing CR so the written form is a byte fixed point (QA-F1).
            let mut raw = raw;
            while let Some(r) = raw.strip_suffix(b"\r") {
                raw = r;
            }
            if raw.len() > MAX_LINE {
                tracing::warn!(line = idx + 1, "known_hosts: line too long; skipped");
                store.truncated = true;
                continue;
            }
            let Ok(line) = std::str::from_utf8(raw) else {
                tracing::warn!(line = idx + 1, "known_hosts: not UTF-8; skipped");
                store.truncated = true;
                continue;
            };
            match parse_line(line) {
                LineParse::Entry(entry) => store.entries.push(*entry),
                LineParse::Ignored => {}
                LineParse::Malformed => {
                    tracing::warn!(line = idx + 1, "known_hosts: malformed line; skipped");
                }
            }
            store.lines.push(line.to_owned());
        }
        while store.lines.last().is_some_and(String::is_empty) {
            store.lines.pop();
        }
        store
    }

    /// Load a file; a missing file is an empty store. Reads at most the capped size.
    pub fn load(path: &Path) -> Result<Self, KnownHostsError> {
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
            tracing::warn!("known_hosts: file size cap reached; rest ignored");
            store.truncated = true;
        }
        Ok(store)
    }

    /// Number of usable entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no usable entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Decide whether `key` is trusted for `host:port`.
    pub fn check(&self, host: &str, port: u16, key: &PublicKey) -> TrustDecision {
        let name = host_pattern(host, port);
        let matching: Vec<&Entry> =
            self.entries.iter().filter(|e| hosts_match(&e.hosts, &name)).collect();
        if matching
            .iter()
            .any(|e| e.marker == Marker::Revoked && e.key.key_data() == key.key_data())
        {
            return TrustDecision::Mismatch { expected_fp: "revoked".to_owned() };
        }
        let mut stored = matching.iter().filter(|e| e.marker == Marker::None);
        let Some(first) = stored.clone().next() else {
            return TrustDecision::Unknown;
        };
        if stored.any(|e| e.key.key_data() == key.key_data()) {
            TrustDecision::Known
        } else {
            TrustDecision::Mismatch { expected_fp: fingerprint(&first.key) }
        }
    }

    /// Add a hashed entry for `host:port` with a fresh random salt.
    pub fn add_hashed(
        &mut self,
        host: &str,
        port: u16,
        key: &PublicKey,
    ) -> Result<(), KnownHostsError> {
        let mut salt = vec![0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let hash = hmac_host(&salt, &host_pattern(host, port)).ok_or(KnownHostsError::Encode)?;
        let mut plain = key.clone();
        plain.set_comment("");
        let key_text =
            plain.to_openssh().map_err(|_| KnownHostsError::Encode)?.trim_end().to_owned();
        let mut line = String::from(HASH_MAGIC);
        let _ = write!(
            line,
            "{}|{} {key_text}",
            Base64::encode_string(&salt),
            Base64::encode_string(&hash)
        );
        self.entries.push(Entry {
            marker: Marker::None,
            hosts: Hosts::Hashed { salt, hash },
            key: plain,
        });
        self.lines.push(line);
        Ok(())
    }

    /// Load `path`, add a hashed entry for `host:port` and save, holding a process-wide lock
    /// for that path so concurrent TOFU accepts never lose an entry (security review 2, L-5).
    /// Blocking: call from `spawn_blocking`.
    pub fn add_and_save(
        path: &Path,
        host: &str,
        port: u16,
        key: &PublicKey,
    ) -> Result<(), KnownHostsError> {
        let lock = path_lock(path);
        let _guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
        let mut store = Self::load(path)?;
        store.add_hashed(host, port, key)?;
        store.save(path)
    }

    /// File content, one entry per line, newline-terminated.
    pub fn to_file_string(&self) -> String {
        let mut out = String::new();
        for line in &self.lines {
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    /// Write atomically (temp file in the same directory, fsync, rename), mode 0600 on unix.
    /// Refuses when the loaded file exceeded the caps, so entries are never silently dropped.
    pub fn save(&self, path: &Path) -> Result<(), KnownHostsError> {
        if self.truncated {
            return Err(KnownHostsError::Truncated);
        }
        let dir = match path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => Path::new("."),
        };
        std::fs::create_dir_all(dir)?;
        let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
        tmp.write_all(self.to_file_string().as_bytes())?;
        tmp.as_file().sync_all()?;
        tmp.persist(path).map_err(|e| KnownHostsError::Io(e.error))?;
        Ok(())
    }
}

/// One mutex per `known_hosts` path, shared by every session in the process and by the
/// vault-sync apply (the registry of `mooring_core::known_certs::write_lock`).
fn path_lock(path: &Path) -> Arc<Mutex<()>> {
    mooring_core::known_certs::write_lock(path)
}

enum LineParse {
    Entry(Box<Entry>),
    Ignored,
    Malformed,
}

fn parse_line(line: &str) -> LineParse {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return LineParse::Ignored;
    }
    let mut fields = trimmed.split_ascii_whitespace();
    let Some(mut first) = fields.next() else {
        return LineParse::Ignored;
    };
    let marker = match first {
        "@revoked" => Marker::Revoked,
        // Host CA trust is not supported in A1; such lines are kept but not used.
        "@cert-authority" => return LineParse::Ignored,
        m if m.starts_with('@') => return LineParse::Malformed,
        _ => Marker::None,
    };
    if marker != Marker::None {
        match fields.next() {
            Some(f) => first = f,
            None => return LineParse::Malformed,
        }
    }
    let Some(hosts) = parse_hosts(first) else {
        return LineParse::Malformed;
    };
    let (Some(kind), Some(b64)) = (fields.next(), fields.next()) else {
        return LineParse::Malformed;
    };
    let Ok(key) = PublicKey::from_openssh(&format!("{kind} {b64}")) else {
        return LineParse::Malformed;
    };
    if matches!(key.algorithm(), Algorithm::Other(_)) {
        return LineParse::Ignored;
    }
    LineParse::Entry(Box::new(Entry { marker, hosts, key }))
}

fn parse_hosts(field: &str) -> Option<Hosts> {
    if let Some(rest) = field.strip_prefix(HASH_MAGIC) {
        let (salt, hash) = rest.split_once('|')?;
        if salt.len() > 128 || hash.len() > 64 {
            return None;
        }
        let salt = Base64::decode_vec(salt).ok()?;
        let mut out = [0u8; HASH_LEN];
        let decoded = Base64::decode(hash, &mut out).ok()?;
        if decoded.len() != HASH_LEN || salt.is_empty() {
            return None;
        }
        return Some(Hosts::Hashed { salt, hash: out });
    }
    let patterns: Vec<String> =
        field.split(',').filter(|p| !p.is_empty()).map(str::to_ascii_lowercase).collect();
    (!patterns.is_empty()).then_some(Hosts::Patterns(patterns))
}

fn hmac_host(salt: &[u8], name: &str) -> Option<[u8; HASH_LEN]> {
    let mac = HmacSha1::new_from_slice(salt).ok()?;
    let out = mac.chain_update(name.as_bytes()).finalize().into_bytes();
    let mut hash = [0u8; HASH_LEN];
    hash.copy_from_slice(out.as_slice());
    Some(hash)
}

fn hosts_match(hosts: &Hosts, name: &str) -> bool {
    match hosts {
        Hosts::Hashed { salt, hash } => HmacSha1::new_from_slice(salt)
            .is_ok_and(|mac| mac.chain_update(name.as_bytes()).verify_slice(hash).is_ok()),
        Hosts::Patterns(patterns) => {
            let mut positive = false;
            for p in patterns {
                if let Some(neg) = p.strip_prefix('!') {
                    if glob(neg.as_bytes(), name.as_bytes()) {
                        return false;
                    }
                } else if glob(p.as_bytes(), name.as_bytes()) {
                    positive = true;
                }
            }
            positive
        }
    }
}

/// `*` / `?` glob, iterative (no recursion, linear backtracking).
fn glob(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some(b'*') => {
                star = Some((p, t));
                p += 1;
            }
            Some(&c) if c == b'?' || Some(&c) == text.get(t) => {
                p += 1;
                t += 1;
            }
            _ => match star {
                Some((sp, st)) => {
                    p = sp + 1;
                    t = st + 1;
                    star = Some((sp, st + 1));
                }
                None => return false,
            },
        }
    }
    pattern.get(p..).is_some_and(|rest| rest.iter().all(|c| *c == b'*'))
}

#[cfg(test)]
#[path = "known_hosts_tests.rs"]
mod tests;
