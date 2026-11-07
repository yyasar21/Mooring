//! Mooring domain model.
//!
//! This crate knows nothing about the UI, the vault file format or any wire protocol.
//! It defines the shapes every other crate agrees on:
//!
//! * [`model`] — folders, connections, credential *references* (never secret material)
//! * [`session`] — the [`session::Session`] trait that SSH / RDP / VNC / K8s implement
//! * [`error`] — the error type shared by the core and the protocol crates
//! * [`frame`] — the RGBA framebuffer, `FrameSink` and the `MFR1` wire format (ADR-0011)
//! * [`known_certs`] — certificate TOFU store and `CertificateInfo` (RDP, VNC)
//! * [`options`] — per-protocol connection options (`connection.options_json`)
//! * [`audit`] — security events a session reports to the audit log
//! * [`clipboard`] — the text clipboard bridge graphical sessions use
//! * [`secret_source`] — Vault / `OpenBao` secret sources (ADR-0016)
//! * [`transport`] — the [`transport::Dialer`] a protocol reaches its peer through (ADR-0025)
//!
//! Secret material lives only in `mooring-vault`; here a credential is an opaque [`model::CredentialId`].

#![forbid(unsafe_code)]

pub mod audit;
pub mod clipboard;
pub mod connect;
pub mod credential;
pub mod driver_task;
pub mod error;
pub mod frame;
pub mod known_certs;
pub mod model;
pub mod options;
pub mod secret_source;
pub mod session;
pub mod transport;
pub mod tree;

pub use audit::{AuditBuffer, AuthMethod, ClipboardDirection, SessionAudit};
pub use credential::{CredentialFields, CredentialKind, Role, SecretName};
pub use error::MooringError;
pub use frame::FrameSink;
pub use model::{
    is_bidi_or_invisible, validate_host, validate_name, validate_tag, validate_via, Connection,
    ConnectionId, CredentialId, Folder, FolderId, Protocol, SecretSourceId, MAX_HOST, MAX_NAME,
    MAX_TAG, MAX_TAGS, MAX_VIA,
};
pub use options::ProtocolOptions;
pub use session::{CloseCode, HopState, PromptPurpose, Session, SessionEvent, SessionInput};
pub use transport::{BoxedStream, Dialer, Erased, SharedDialer, TcpDialer};
pub use tree::ConnectionTree;
