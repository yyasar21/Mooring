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
    // ---- ADR-0010 (A1 exit): auto-lock policy and syslog mirror -------------------------
    /// The auto-lock policy was changed (`autolock_set`).
    VaultPolicyChanged {
        /// Idle timeout in minutes; `None` = idle trigger off.
        idle_minutes: Option<u32>,
        /// Lock on OS screen lock.
        on_screen_lock: bool,
        /// Lock on OS sleep.
        on_sleep: bool,
        /// Lock when the main window is hidden / loses focus.
        on_window_hidden: bool,
    },
    /// The syslog mirror configuration was changed (`syslog_set`). The host is not a secret
    /// (inventory-class, like a connection host) and is recorded so a redirected mirror is
    /// visible in the chain.
    AuditSyslogChanged {
        /// Mirror on or off.
        enabled: bool,
        /// Collector host.
        host: String,
        /// Collector port.
        port: u16,
        /// `udp` | `tcp` | `tls`.
        transport: String,
        /// Syslog facility 0..=23.
        facility: u8,
    },
    /// The app started with a stored syslog configuration (review 4, L-18). Recorded after the
    /// mirror started when `enabled`, so the collector sees each start; with `enabled: false`
    /// it is the "disabled at startup" entry that makes an edited plaintext setting visible in
    /// the chain.
    AuditSyslogStarted {
        /// Whether the stored configuration has the mirror on.
        enabled: bool,
        /// Collector host.
        host: String,
        /// Collector port.
        port: u16,
        /// `udp` | `tcp` | `tls`.
        transport: String,
    },
    /// Hourly liveness entry while the mirror runs (L-18): collectors alert when it is missing.
    AuditHeartbeat {
        /// Heartbeat number since this process started the mirror loop (1, 2, ...).
        seq: u64,
    },
    // ---- ADR-0011 / ADR-0012 (A2): graphical sessions ----------------------------------
    /// A TLS certificate trust decision for RDP / VNC (`trust.cert.*`).
    CertDecision {
        /// `rdp` | `vnc`.
        protocol: String,
        /// `host:port`.
        host: String,
        /// `SHA256:<hex>` presented.
        fingerprint: String,
        /// `accepted` | `accepted_session_only` | `rejected` | `changed` | `ca_valid`.
        decision: String,
        /// For `changed`: the pinned fingerprint.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected: Option<String>,
    },
    /// Pins for `host:port` were removed from a certificate store (`known_certs_remove`,
    /// ADR-0011 `trust.cert.removed`).
    CertRemoved {
        /// `rdp` | `vnc`.
        protocol: String,
        /// `host:port`.
        host: String,
        /// Pins removed (0 when none matched).
        removed: u64,
    },
    /// A session negotiated weaker transport security than the default (RDP TLS without
    /// NLA, VNC without TLS): audited on every connect.
    SessionWeakSecurity {
        /// Connection id.
        connection: String,
        /// `rdp` | `vnc`.
        protocol: String,
        /// Security in effect (`tls`, `vnc-auth`, `none`, ...).
        security: String,
    },
    /// Clipboard text crossed a session boundary (coalesced, ≤ 1/s per direction). Never the
    /// text itself.
    SessionClipboard {
        /// Connection id.
        connection: String,
        /// `to_remote` | `from_remote`.
        direction: String,
        /// UTF-8 bytes transferred.
        bytes: u64,
    },
    /// The framebuffer of a session was copied to the OS clipboard as an image.
    SessionScreenshot {
        /// Connection id.
        connection: String,
        /// Width in pixels.
        width: u32,
        /// Height in pixels.
        height: u32,
    },
    /// `session_set_view_only` toggled a session's view-only switch (ADR-0012 §IPC, L-26).
    SessionViewOnly {
        /// Connection id.
        connection: String,
        /// The new state.
        view_only: bool,
    },
    /// `connection_options_set` changed stored options (review 5 L-22). Field **names** only;
    /// no values except the SHA-256 fingerprints of a new `caPem`.
    ConnectionOptionsChanged {
        /// Connection id.
        connection: String,
        /// `rdp` | `vnc` | `web` | ...
        protocol: String,
        /// camelCase option names whose value changed.
        changed: Vec<String>,
        /// `SHA256:<hex>` of every certificate in a new or changed `caPem`.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        ca_pem: Vec<String>,
        /// Whether the change weakens security (warning severity).
        weakened: bool,
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
