//! Hash-chained JSONL audit log.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;

pub use crate::event::AuditEvent;

/// Hash of "nothing": the `prev` of the first entry.
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Audit errors.
#[derive(Debug, Error)]
pub enum AuditError {
    /// I/O.
    #[error("audit io: {0}")]
    Io(#[from] std::io::Error),
    /// A line could not be parsed.
    #[error("audit line {line}: malformed")]
    Malformed {
        /// 1-based line number.
        line: usize,
    },
}

/// One line of the log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Sequence number, starting at 1.
    pub seq: u64,
    /// UTC timestamp.
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    /// SHA-256 hex of the previous entry's canonical bytes; [`GENESIS`] for the first.
    pub prev: String,
    /// The event.
    #[serde(flatten)]
    pub event: AuditEvent,
}

impl AuditEntry {
    /// Canonical bytes hashed into the next entry: the JSON line without the trailing newline.
    fn canonical(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    pub(crate) fn digest(&self) -> String {
        hex::encode(Sha256::digest(self.canonical()))
    }
}

/// Result of [`AuditLog::verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Entries checked.
    pub entries: usize,
    /// First line (1-based) where the chain breaks, if any.
    pub broken_at: Option<usize>,
}

impl VerifyReport {
    /// Whether the chain is intact.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.broken_at.is_none()
    }
}

/// Append-only log on disk.
#[derive(Debug)]
pub struct AuditLog {
    path: PathBuf,
    last_seq: u64,
    last_hash: String,
    /// Optional syslog mirror, fed after each successful local write (ADR-0010).
    mirror: Option<crate::syslog::SyslogMirror>,
}

impl AuditLog {
    /// Open (or create) the log and scan it to find the chain tail.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, AuditError> {
        let path = path.into();
        let (last_seq, last_hash) = match File::open(&path) {
            Ok(f) => {
                let mut seq = 0;
                let mut hash = GENESIS.to_owned();
                for (i, line) in BufReader::new(f).lines().enumerate() {
                    let line = line?;
                    if line.trim().is_empty() {
                        continue;
                    }
                    let e: AuditEntry = serde_json::from_str(&line)
                        .map_err(|_| AuditError::Malformed { line: i + 1 })?;
                    seq = e.seq;
                    hash = e.digest();
                }
                (seq, hash)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (0, GENESIS.to_owned()),
            Err(e) => return Err(e.into()),
        };
        Ok(Self { path, last_seq, last_hash, mirror: None })
    }

    /// Path on disk.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one event. The file is created `0600` on Unix.
    pub fn record(&mut self, event: AuditEvent) -> Result<AuditEntry, AuditError> {
        let entry = AuditEntry {
            seq: self.last_seq + 1,
            at: OffsetDateTime::now_utc(),
            prev: self.last_hash.clone(),
            event,
        };
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&self.path)?;
        f.write_all(&entry.canonical())?;
        f.write_all(b"\n")?;
        f.sync_data()?;
        self.last_seq = entry.seq;
        self.last_hash = entry.digest();
        if let Some(m) = &self.mirror {
            m.send(&entry); // never blocks, never fails the local write
        }
        Ok(entry)
    }

    /// Install (or with `None` remove) the syslog mirror; returns the previous one.
    pub fn set_mirror(
        &mut self,
        mirror: Option<crate::syslog::SyslogMirror>,
    ) -> Option<crate::syslog::SyslogMirror> {
        std::mem::replace(&mut self.mirror, mirror)
    }

    /// The running syslog mirror, if any (telemetry: `dropped`, `sent`).
    #[must_use]
    pub fn mirror(&self) -> Option<&crate::syslog::SyslogMirror> {
        self.mirror.as_ref()
    }

    /// Walk the whole file and check every `prev` and `seq`.
    pub fn verify(path: impl AsRef<Path>) -> Result<VerifyReport, AuditError> {
        let f = File::open(path)?;
        let mut expected_prev = GENESIS.to_owned();
        let mut expected_seq = 1;
        let mut entries = 0;
        for (i, line) in BufReader::new(f).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let Ok(e) = serde_json::from_str::<AuditEntry>(&line) else {
                return Ok(VerifyReport { entries, broken_at: Some(i + 1) });
            };
            if e.prev != expected_prev || e.seq != expected_seq {
                return Ok(VerifyReport { entries, broken_at: Some(i + 1) });
            }
            expected_prev = e.digest();
            expected_seq += 1;
            entries += 1;
        }
        Ok(VerifyReport { entries, broken_at: None })
    }
}

#[cfg(test)]
#[path = "chain_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "chain_tests_a5.rs"]
mod tests_a5;
