//! Mooring domain model.
//!
//! This crate knows nothing about the UI, the vault file format or any wire protocol.
//! It defines the shapes every other crate agrees on:
//!
//! * [`model`] — folders, connections, credential *references* (never secret material)
//! * [`session`] — the [`session::Session`] trait that SSH / RDP / VNC / K8s implement
//! * [`error`] — the error type shared by the core and the protocol crates
//!
//! Secret material lives only in `mooring-vault`; here a credential is an opaque [`model::CredentialId`].

#![forbid(unsafe_code)]

pub mod error;
pub mod model;
pub mod session;
pub mod tree;

pub use error::MooringError;
pub use model::{
    is_bidi_or_invisible, validate_host, validate_name, validate_tag, Connection, ConnectionId,
    CredentialId, Folder, FolderId, Protocol, MAX_HOST, MAX_NAME, MAX_TAG, MAX_TAGS,
};
pub use session::{PromptPurpose, Session, SessionEvent, SessionInput};
pub use tree::ConnectionTree;
