//! Audit log and log redaction.
//!
//! * [`AuditLog`] — append-only JSON Lines, each entry carrying the SHA-256 of the previous
//!   entry, so a deleted or edited line breaks the chain at verification time.
//! * [`redact`] — scrubs values of well-known secret keys (`password=`, `token:`, PEM blocks,
//!   `Authorization:` headers) from free text before it reaches any log sink.
//! * [`syslog`] — best-effort RFC 5424 mirror of every entry over UDP / TCP / TLS (ADR-0010).

#![forbid(unsafe_code)]

mod chain;
mod event;
mod redact;
pub mod syslog;

pub use chain::{AuditEntry, AuditError, AuditLog, VerifyReport};
pub use event::AuditEvent;
pub use redact::redact;
