//! SSH session for Mooring, built on russh (ADR-0004, ADR-0007).
//!
//! Every byte from the remote side is hostile: russh parses the wire protocol, and the only
//! parser here is the `known_hosts` trust store, which treats its file as untrusted input.
//! No `unsafe`.

#![forbid(unsafe_code)]

pub mod known_hosts;

use async_trait::async_trait;
use nexus_core::session::{ConnectParams, Session, SessionEvent, SessionInput};
use nexus_core::{NexusError, Protocol};

/// SSH session handle.
#[derive(Debug)]
pub struct SshSession {
    _params: ConnectParams,
}

impl SshSession {
    /// Open a session. Not implemented in Phase A0.
    #[allow(clippy::unused_async)] // the real implementation awaits the handshake
    pub async fn connect(params: ConnectParams) -> Result<Self, NexusError> {
        Err(NexusError::Protocol {
            protocol: "ssh",
            reason: format!("not implemented yet (host {})", params.host),
        })
    }
}

#[async_trait]
impl Session for SshSession {
    fn protocol(&self) -> Protocol {
        Protocol::Ssh
    }

    async fn send(&mut self, _input: SessionInput) -> Result<(), NexusError> {
        Err(NexusError::Closed)
    }

    async fn next_event(&mut self) -> Result<Option<SessionEvent>, NexusError> {
        Ok(None)
    }

    async fn close(&mut self) -> Result<(), NexusError> {
        Ok(())
    }
}
