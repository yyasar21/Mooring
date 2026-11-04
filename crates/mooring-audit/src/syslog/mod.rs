//! Syslog mirror of the audit log (ADR-0010 item 5). Pure Rust, no C dependency.
//!
//! [`SyslogMirror::start`] spawns one sender thread fed by a bounded channel
//! ([`QUEUE_CAPACITY`]). [`SyslogMirror::send`] formats the entry on the caller's thread and
//! `try_send`s it: a full queue, a dead thread, a failed connect or a failed write all
//! increment [`SyslogMirror::dropped`] and never block or fail the local audit write.
//!
//! The local hash-chained file stays the source of truth; the mirror is best effort.

mod format;
mod transport;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::chain::AuditEntry;

pub use format::{
    format_entry, format_test, header_field, sd_escape, APP_NAME, MAX_MESSAGE, SD_ID,
};
pub use transport::{connect, octet_frame, Conn, TlsRoots, IO_TIMEOUT};

/// Messages waiting for the sender thread before new ones are dropped.
pub const QUEUE_CAPACITY: usize = 1024;
/// After a failed connect, messages are dropped without retrying for this long.
pub const RECONNECT_BACKOFF: Duration = Duration::from_secs(2);
/// Longest host accepted (DNS limit).
pub const MAX_HOST: usize = 253;
/// Largest facility code (local7).
pub const MAX_FACILITY: u8 = 23;

/// Wire transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// RFC 5426.
    Udp,
    /// RFC 6587, octet counting.
    Tcp,
    /// RFC 5425 over rustls, system roots.
    Tls,
}

impl Transport {
    /// Wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Tls => "tls",
        }
    }
}

/// Collector settings. Nothing in here is secret: the host is inventory-class metadata and is
/// written to the audit log when it changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SyslogConfig {
    /// DNS name or IP literal (IPv6 without brackets).
    pub host: String,
    /// 1..=65535.
    pub port: u16,
    /// Wire transport.
    pub transport: Transport,
    /// 0..=23. On the wire (IPC, stored JSON) this is the RFC 5424 keyword (`"local4"`);
    /// a numeric code is accepted on input for compatibility.
    #[serde(with = "facility_serde")]
    pub facility: u8,
    /// Whether entries are mirrored.
    pub enabled: bool,
}

/// RFC 5424 facility keywords, in code order (0..=23).
pub const FACILITY_KEYWORDS: [&str; 24] = [
    "kern",
    "user",
    "mail",
    "daemon",
    "auth",
    "syslog",
    "lpr",
    "news",
    "uucp",
    "cron",
    "authpriv",
    "ftp",
    "ntp",
    "security",
    "console",
    "solaris-cron",
    "local0",
    "local1",
    "local2",
    "local3",
    "local4",
    "local5",
    "local6",
    "local7",
];

/// Keyword for a facility code (`None` above 23).
pub fn facility_keyword(code: u8) -> Option<&'static str> {
    FACILITY_KEYWORDS.get(usize::from(code)).copied()
}

/// Facility code for a keyword or decimal string (`None` when unknown).
pub fn facility_from_str(s: &str) -> Option<u8> {
    FACILITY_KEYWORDS
        .iter()
        .position(|k| *k == s)
        .and_then(|p| u8::try_from(p).ok())
        .or_else(|| s.parse::<u8>().ok().filter(|c| *c <= MAX_FACILITY))
}

mod facility_serde {
    use serde::{de, Deserialize, Deserializer, Serializer};

    #[allow(clippy::trivially_copy_pass_by_ref)] // serde `with` signature
    pub fn serialize<S: Serializer>(code: &u8, s: S) -> Result<S::Ok, S::Error> {
        match super::facility_keyword(*code) {
            Some(k) => s.serialize_str(k),
            None => s.serialize_u8(*code),
        }
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Code(i64),
        Keyword(String),
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u8, D::Error> {
        // Out-of-range values are mapped to `u8::MAX` so `validated()` reports them as a
        // typed `input.invalid` instead of a deserialisation failure.
        Ok(match Raw::deserialize(d)? {
            Raw::Code(c) => u8::try_from(c).unwrap_or(u8::MAX),
            Raw::Keyword(k) => super::facility_from_str(&k)
                .ok_or_else(|| de::Error::custom("facility: unknown keyword"))?,
        })
    }
}

/// Mirror errors. Messages are safe to show: they name the failing step, never data.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SyslogError {
    /// Invalid setting.
    #[error("invalid {field}: {reason}")]
    Invalid {
        /// Field name.
        field: &'static str,
        /// Why.
        reason: &'static str,
    },
    /// DNS lookup failed or returned nothing.
    #[error("the collector host could not be resolved")]
    Resolve,
    /// Socket error.
    #[error("network error: {0:?}")]
    Io(std::io::ErrorKind),
    /// TLS setup, handshake or certificate verification failed.
    #[error("TLS error: {0}")]
    Tls(String),
}

impl SyslogError {
    pub(crate) fn invalid(field: &'static str, reason: &'static str) -> Self {
        Self::Invalid { field, reason }
    }

    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn io(e: std::io::Error) -> Self {
        Self::Io(e.kind())
    }

    /// rustls reports handshake and certificate failures as `io::Error(InvalidData, rustls::Error)`.
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn tls_io(e: std::io::Error) -> Self {
        match e.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>()) {
            Some(tls) => Self::Tls(tls.to_string()),
            None => Self::Io(e.kind()),
        }
    }
}

fn valid_dns_name(h: &str) -> bool {
    h.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

impl SyslogConfig {
    /// Validate and normalise (host trimmed and lower-cased). The host must be an IP literal
    /// or a DNS name of LDH labels; URLs, ports, brackets, spaces and control characters are
    /// refused.
    pub fn validated(mut self) -> Result<Self, SyslogError> {
        let host = self.host.trim().to_ascii_lowercase();
        if host.is_empty() || host.len() > MAX_HOST {
            return Err(SyslogError::invalid("host", "must be 1..=253 characters"));
        }
        if host.parse::<std::net::IpAddr>().is_err() && !valid_dns_name(&host) {
            return Err(SyslogError::invalid("host", "must be a DNS name or an IP address"));
        }
        if self.port == 0 {
            return Err(SyslogError::invalid("port", "must be 1..=65535"));
        }
        if self.facility > MAX_FACILITY {
            return Err(SyslogError::invalid("facility", "must be 0..=23"));
        }
        self.host = host;
        Ok(self)
    }
}

/// Send one synthetic test message synchronously (connect + write, bounded by
/// [`IO_TIMEOUT`]). For UDP success only means the datagram left this host.
pub fn send_test(cfg: &SyslogConfig, hostname: &str, roots: &TlsRoots) -> Result<(), SyslogError> {
    let msg =
        format_test(cfg.facility, hostname, std::process::id(), time::OffsetDateTime::now_utc());
    connect(cfg, roots)?.send(msg.as_bytes())
}

/// Running mirror: queue, sender thread and counters. Dropping it closes the queue; the thread
/// drains what is queued and exits.
pub struct SyslogMirror {
    config: SyslogConfig,
    hostname: String,
    tx: SyncSender<Vec<u8>>,
    dropped: Arc<AtomicU64>,
    sent: Arc<AtomicU64>,
}

impl std::fmt::Debug for SyslogMirror {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyslogMirror")
            .field("transport", &self.config.transport)
            .field("dropped", &self.dropped())
            .field("sent", &self.sent())
            .finish_non_exhaustive()
    }
}

impl SyslogMirror {
    /// Start mirroring to a validated `config` with the given trust anchors.
    pub fn start(
        config: SyslogConfig,
        hostname: &str,
        roots: TlsRoots,
    ) -> Result<Self, SyslogError> {
        let config = config.validated()?;
        let (tx, rx) = sync_channel::<Vec<u8>>(QUEUE_CAPACITY);
        let dropped = Arc::new(AtomicU64::new(0));
        let sent = Arc::new(AtomicU64::new(0));
        let (cfg, d, s) = (config.clone(), Arc::clone(&dropped), Arc::clone(&sent));
        std::thread::Builder::new()
            .name("mooring-syslog".into())
            .spawn(move || {
                let mut conn: Option<Conn> = None;
                let mut failed_at: Option<Instant> = None;
                for msg in rx {
                    if conn.is_none() {
                        if failed_at.is_some_and(|t| t.elapsed() < RECONNECT_BACKOFF) {
                            d.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        match connect(&cfg, &roots) {
                            Ok(c) => {
                                conn = Some(c);
                                failed_at = None;
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "syslog connect failed");
                                failed_at = Some(Instant::now());
                                d.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                        }
                    }
                    if let Some(c) = conn.as_mut() {
                        match c.send(&msg) {
                            Ok(()) => {
                                s.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "syslog send failed");
                                d.fetch_add(1, Ordering::Relaxed);
                                conn = None;
                            }
                        }
                    }
                }
            })
            .map_err(SyslogError::io)?;
        Ok(Self { config, hostname: hostname.to_owned(), tx, dropped, sent })
    }

    /// The validated configuration this mirror runs with.
    #[must_use]
    pub fn config(&self) -> &SyslogConfig {
        &self.config
    }

    /// Queue one entry. Never blocks; a full or closed queue counts as dropped.
    pub fn send(&self, entry: &AuditEntry) {
        let msg = format_entry(entry, self.config.facility, &self.hostname, std::process::id());
        match self.tx.try_send(msg.into_bytes()) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Messages lost so far (queue full, connect or write failure).
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Messages written to the collector so far.
    #[must_use]
    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests;
