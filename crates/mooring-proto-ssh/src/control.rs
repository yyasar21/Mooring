//! [`SshControl`]: a cheap, cloneable handle to a live session's forwards and SFTP.
//!
//! The `SshSession` itself is owned by one task (it pumps the event stream), so other callers
//! (IPC commands) reach forwards and SFTP through a control obtained with
//! [`SshSession::control`]. A control never keeps the connection alive: once the session
//! closes, every call fails with `MooringError::Closed` and the forwards are already gone.

use std::net::SocketAddr;
use std::sync::Arc;

use mooring_core::MooringError;

use crate::audit::TrustEvent;
use crate::driver::HandleSlot;
use crate::forward::{Exposure, ForwardId, ForwardInfo};
use crate::session::SshSession;
use crate::sftp::SftpClient;
use crate::shared::Shared;

/// Forward and SFTP access to one session, usable from any task.
#[derive(Clone)]
pub struct SshControl {
    pub(crate) shared: Arc<Shared>,
    pub(crate) handle: HandleSlot,
}

impl std::fmt::Debug for SshControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshControl")
            .field("connected", &self.handle.get().is_some())
            .field("closing", &self.shared.is_closing())
            .finish_non_exhaustive()
    }
}

impl SshControl {
    /// Drain the audit events recorded so far (same queue as
    /// [`SshSession::take_audit_events`]).
    pub fn take_audit_events(&self) -> Vec<TrustEvent> {
        self.shared.audit.take()
    }

    /// Whether the session is closing or closed.
    pub fn is_closed(&self) -> bool {
        self.shared.is_closing()
    }
}

impl SshSession {
    /// A control for this session's forwards and SFTP.
    pub fn control(&self) -> SshControl {
        SshControl { shared: Arc::clone(&self.shared), handle: Arc::clone(&self.handle) }
    }

    /// See [`SshControl::forward_local`].
    pub async fn forward_local(
        &self,
        bind_addr: SocketAddr,
        target: (String, u16),
        exposure: Exposure,
    ) -> Result<ForwardId, MooringError> {
        self.control().forward_local(bind_addr, target, exposure).await
    }

    /// See [`SshControl::forward_dynamic`].
    pub async fn forward_dynamic(
        &self,
        bind_addr: SocketAddr,
        exposure: Exposure,
    ) -> Result<ForwardId, MooringError> {
        self.control().forward_dynamic(bind_addr, exposure).await
    }

    /// See [`SshControl::forward_remote`].
    pub async fn forward_remote(
        &self,
        remote_bind: (String, u16),
        target: SocketAddr,
        exposure: Exposure,
    ) -> Result<ForwardId, MooringError> {
        self.control().forward_remote(remote_bind, target, exposure).await
    }

    /// See [`SshControl::forward_close`].
    pub async fn forward_close(&self, id: ForwardId) -> Result<(), MooringError> {
        self.control().forward_close(id).await
    }

    /// Live forwards, ordered by id.
    pub fn forwards(&self) -> Vec<ForwardInfo> {
        self.shared.forwards.list()
    }

    /// See [`SshControl::sftp`].
    pub async fn sftp(&self) -> Result<SftpClient, MooringError> {
        self.control().sftp().await
    }
}
