//! Error type shared by the core and the protocol crates.
//!
//! Rule (CLAUDE.md): an error's `Display` never contains secret material. Variants carry
//! identifiers and short reasons, not passwords, keys or full remote banners.

use thiserror::Error;

/// Errors produced by the domain model and by protocol implementations.
#[derive(Debug, Error)]
pub enum MooringError {
    /// A connection, folder or credential id was not found.
    #[error("not found: {kind} {id}")]
    NotFound {
        /// What kind of object was looked up (`connection`, `folder`, `credential`).
        kind: &'static str,
        /// The id that was looked up.
        id: String,
    },

    /// The input failed validation at a system boundary (IPC, file import).
    #[error("invalid {field}: {reason}")]
    Invalid {
        /// Field that failed validation.
        field: &'static str,
        /// Human-readable reason. Must not echo the offending value when it may be secret.
        reason: String,
    },

    /// A folder operation would create a cycle or orphan.
    #[error("tree integrity: {0}")]
    Tree(String),

    /// The protocol implementation refused to continue (e.g. host key changed).
    #[error("protocol {protocol}: {reason}")]
    Protocol {
        /// Protocol name (`ssh`, `rdp`, ...).
        protocol: &'static str,
        /// Short reason safe to show to the user.
        reason: String,
    },

    /// Transport-level failure (DNS, TCP, TLS). The source is kept for logs, not for display.
    #[error("transport: {0}")]
    Transport(String),

    /// The session was closed by the peer or by the user.
    #[error("session closed")]
    Closed,
}

/// Convenience alias used across the workspace.
pub type Result<T> = std::result::Result<T, MooringError>;
