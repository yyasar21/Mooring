//! Hash-chained JSONL audit log.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;

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

/// What happened. Variants carry identifiers, never secret values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent {
    /// Vault created.
    VaultCreated,
    /// Vault unlocked.
    VaultUnlocked,
    /// Vault locked (`reason`: `user`, `idle`, `screen_lock`, `sleep`).
    VaultLocked {
        /// Why.
        reason: String,
    },
    /// Master password changed.
    PasswordChanged,
    /// A credential was read for use (connect, copy, reveal).
    CredentialUsed {
        /// Credential id.
        credential: String,
        /// `connect` | `copy` | `reveal`.
        purpose: String,
        /// Connection id when relevant.
        connection: Option<String>,
    },
    /// Session opened.
    SessionOpened {
        /// Connection id.
        connection: String,
        /// Protocol name.
        protocol: String,
        /// Peer identity (fingerprint / cert subject) as shown to the user.
        peer_identity: Option<String>,
    },
    /// Session closed.
    SessionClosed {
        /// Connection id.
        connection: String,
        /// Reason safe to show.
        reason: String,
    },
    /// A secret was put on the clipboard (ADR-0009): `name` is the secret name, or `otp` for
    /// a TOTP code. Never the value.
    CredentialCopied {
        /// Credential id.
        credential: String,
        /// Secret name (`password`, `token`, ...) or `otp`.
        name: String,
    },
    /// A TOTP seed was attached to a credential (ADR-0009 security consequences).
    CredentialOtpAttached {
        /// Credential id.
        credential: String,
    },
    /// The user answered a connect-time sign-in form (`prompt` kind). The username is
    /// inventory-class metadata (R-INV), never the password.
    CredentialPrompted {
        /// Connection id.
        connection: String,
        /// Username typed.
        username: String,
    },
    /// Credentials migrated from schema v2 were re-sealed under their ADR-0009 secret names
    /// on unlock. Written only when `count > 0`.
    CredentialResealed {
        /// How many credentials were converted.
        count: u64,
    },
    /// A `become` (sudo / su / doas) escalation was refused by the server and interrupted; the
    /// session stayed the login user (review 3, M-6).
    BecomeFailed {
        /// Connection id.
        connection: String,
    },
    /// Vault exported (`format`: `age`, `json`, ...).
    VaultExported {
        /// Export format.
        format: String,
    },
    /// Trust decision (host key / certificate) recorded.
    TrustDecision {
        /// Host.
        host: String,
        /// Fingerprint presented by the host.
        fingerprint: String,
        /// `accepted` | `accepted_session_only` | `rejected` | `changed`.
        decision: String,
        /// For `changed`: the stored fingerprint the host no longer matches (review 2, L-6).
        /// Absent otherwise, so older entries keep their canonical bytes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected: Option<String>,
    },

    // --- ADR-0010 §Port forwarding / §SFTP (rust-core, forward + SFTP IPC) ---
    /// A port forward started (ADR-0010 `session.forward.open { exposure }`).
    ForwardOpened {
        /// Connection id.
        connection: String,
        /// Session-local forward id, e.g. `fwd-1`.
        id: String,
        /// `local` | `remote` | `dynamic`.
        kind: String,
        /// Bound `host:port`.
        bind: String,
        /// Target `host:port`, or `socks5`.
        target: String,
        /// `loopback` | `external`.
        exposure: String,
    },
    /// A port forward stopped (closed by the user or with its session).
    ForwardClosed {
        /// Connection id.
        connection: String,
        /// Session-local forward id.
        id: String,
        /// `local` | `remote` | `dynamic`.
        kind: String,
        /// Bound `host:port`.
        bind: String,
        /// Target `host:port`, or `socks5`.
        target: String,
    },
    /// An SFTP transfer ended (ADR-0010 `session.sftp.transfer`). Never file contents.
    SftpTransfer {
        /// Connection id.
        connection: String,
        /// Transfer id.
        transfer: String,
        /// `download` | `upload`.
        direction: String,
        /// Bytes moved.
        bytes: u64,
        /// `done` | `failed` | `cancelled`.
        outcome: String,
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

    fn digest(&self) -> String {
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
        Ok(Self { path, last_seq, last_hash })
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
        Ok(entry)
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
mod tests {
    use super::*;
    use std::fs;

    fn three(path: &Path) {
        let mut log = AuditLog::open(path).expect("open");
        log.record(AuditEvent::VaultCreated).expect("1");
        log.record(AuditEvent::VaultUnlocked).expect("2");
        log.record(AuditEvent::VaultLocked { reason: "idle".into() }).expect("3");
    }

    #[test]
    fn trust_decision_expected_is_optional_and_keeps_old_lines_verifiable() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("audit.jsonl");
        let mut log = AuditLog::open(&p).expect("open");
        log.record(AuditEvent::TrustDecision {
            host: "h:22".into(),
            fingerprint: "SHA256:new".into(),
            decision: "accepted".into(),
            expected: None,
        })
        .expect("1");
        log.record(AuditEvent::TrustDecision {
            host: "h:22".into(),
            fingerprint: "SHA256:new".into(),
            decision: "changed".into(),
            expected: Some("SHA256:old".into()),
        })
        .expect("2");
        let text = fs::read_to_string(&p).expect("read");
        let lines: Vec<&str> = text.lines().collect();
        assert!(!lines[0].contains("expected"), "{}", lines[0]);
        assert!(lines[1].contains(r#""expected":"SHA256:old""#), "{}", lines[1]);
        assert!(AuditLog::verify(&p).expect("verify").ok());
    }

    #[test]
    fn credential_events_have_stable_wire_names() {
        let cases = [
            (
                AuditEvent::CredentialCopied { credential: "c".into(), name: "otp".into() },
                "credential_copied",
            ),
            (
                AuditEvent::CredentialOtpAttached { credential: "c".into() },
                "credential_otp_attached",
            ),
            (
                AuditEvent::CredentialPrompted { connection: "x".into(), username: "u".into() },
                "credential_prompted",
            ),
            (AuditEvent::CredentialResealed { count: 3 }, "credential_resealed"),
            (AuditEvent::BecomeFailed { connection: "x".into() }, "become_failed"),
        ];
        for (e, name) in cases {
            let v = serde_json::to_value(&e).expect("json");
            assert_eq!(v["event"], name);
        }
    }

    #[test]
    fn forward_and_sftp_events_have_stable_wire_names() {
        let (c, s) = (|| "x".to_owned(), |v: &str| v.to_owned());
        let cases = [
            (
                AuditEvent::ForwardOpened {
                    connection: c(),
                    id: s("fwd-1"),
                    kind: s("local"),
                    bind: s("127.0.0.1:1"),
                    target: s("db.example.test:5432"),
                    exposure: s("external"),
                },
                "forward_opened",
            ),
            (
                AuditEvent::ForwardClosed {
                    connection: c(),
                    id: s("fwd-1"),
                    kind: s("dynamic"),
                    bind: s("127.0.0.1:1"),
                    target: s("socks5"),
                },
                "forward_closed",
            ),
            (
                AuditEvent::SftpTransfer {
                    connection: c(),
                    transfer: s("t"),
                    direction: s("upload"),
                    bytes: 7,
                    outcome: s("done"),
                },
                "sftp_transfer",
            ),
        ];
        for (e, name) in cases {
            let v = serde_json::to_value(&e).expect("json");
            assert_eq!(v["event"], name);
            assert_eq!(serde_json::from_value::<AuditEvent>(v).expect("round trip"), e);
        }
    }

    #[test]
    fn chain_verifies_and_survives_reopen() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("audit.jsonl");
        three(&p);
        let mut again = AuditLog::open(&p).expect("reopen");
        let e = again.record(AuditEvent::PasswordChanged).expect("4");
        assert_eq!(e.seq, 4);
        let r = AuditLog::verify(&p).expect("verify");
        assert!(r.ok());
        assert_eq!(r.entries, 4);
    }

    #[test]
    fn deleting_or_editing_a_line_breaks_the_chain() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("audit.jsonl");
        three(&p);
        let text = fs::read_to_string(&p).expect("read");
        let lines: Vec<&str> = text.lines().collect();

        // delete the middle line
        fs::write(&p, format!("{}\n{}\n", lines[0], lines[2])).expect("write");
        assert_eq!(AuditLog::verify(&p).expect("v").broken_at, Some(2));

        // edit the first line's event
        let edited = lines[0].replace("vault_created", "vault_unlocked");
        fs::write(&p, format!("{}\n{}\n{}\n", edited, lines[1], lines[2])).expect("write");
        assert_eq!(AuditLog::verify(&p).expect("v").broken_at, Some(2));
    }

    #[cfg(unix)]
    #[test]
    fn file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("audit.jsonl");
        three(&p);
        let mode = fs::metadata(&p).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
