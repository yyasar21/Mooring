//! VNC session for Mooring, built on an RFB 3.8 client.
//!
//! Phase A0 ships the crate boundary only; the implementation lands in the phase that owns it
//! (see docs/adr/0004-session-abstraction.md). Rules that already apply here:
//! every byte from the remote side is hostile, parsers get fuzz targets, no `unsafe`.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use mooring_core::session::{ConnectParams, Session, SessionEvent, SessionInput};
use mooring_core::{MooringError, Protocol};

/// VNC session handle.
#[derive(Debug)]
pub struct VncSession {
    _params: ConnectParams,
}

impl VncSession {
    /// Open a session. Not implemented in Phase A0.
    #[allow(clippy::unused_async)] // the real implementation awaits the handshake
    pub async fn connect(params: ConnectParams) -> Result<Self, MooringError> {
        Err(MooringError::Protocol {
            protocol: "vnc",
            reason: format!("not implemented yet (host {})", params.host),
        })
    }
}

#[async_trait]
impl Session for VncSession {
    fn protocol(&self) -> Protocol {
        Protocol::Vnc
    }

    async fn send(&mut self, _input: SessionInput) -> Result<(), MooringError> {
        Err(MooringError::Closed)
    }

    async fn next_event(&mut self) -> Result<Option<SessionEvent>, MooringError> {
        Ok(None)
    }

    async fn close(&mut self) -> Result<(), MooringError> {
        Ok(())
    }
}
