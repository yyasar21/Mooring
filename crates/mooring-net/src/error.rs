//! Errors of the network tools. Messages never echo the input (a host is inventory, but the
//! text may come from a hostile tool output or a pasted string).

/// Why a tool could not run or a target was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetError {
    /// The host is not a valid RFC 1123 name or IP literal (ADR-0020 §1).
    #[error("invalid host: {0}")]
    InvalidHost(&'static str),
    /// The port is 0.
    #[error("invalid port: must be 1..=65535")]
    InvalidPort,
    /// No binary of the tool exists at any of the fixed absolute paths.
    #[error("tool not installed at a known path")]
    ToolMissing,
    /// The tool refused for lack of rights (`wg` needs root or `CAP_NET_ADMIN`).
    #[error("WireGuard status needs elevated rights; Mooring does not elevate")]
    PermissionDenied,
    /// The process could not be started (the binary exists but `exec` failed).
    #[error("the tool could not be started")]
    Spawn,
    /// A `wg` interface name from the tool output is not `[A-Za-z0-9_=+.-]{1,15}`.
    #[error("invalid interface name")]
    InvalidInterface,
}
