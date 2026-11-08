//! SSH session for Mooring, built on russh (ADR-0004, ADR-0007).
//!
//! Every byte from the remote side is hostile: russh parses the wire protocol, and the only
//! parser here is the `known_hosts` trust store, which treats its file as untrusted input.
//! No `unsafe`.
//!
//! Layout:
//! * [`known_hosts`] — trust store; [`algos`] — algorithm policy; [`audit`] — trust events
//! * `handler` — russh client handler (host-key decision, forwarded channels);
//!   `auth`/`agent` — login methods
//! * `channel` — PTY shell pump; `driver` — per-connection task; [`session`] — the front
//! * [`SshControl`] — forwards and SFTP from tasks that do not own the session
//! * [`hops`] — jump-host chains: SSH-over-SSH through `direct-tcpip`, no listener (ADR-0025);
//!   [`ViaSession`] wraps an RDP / VNC session behind one
//! * [`forward`] (+ `forward_io`, [`socks`]) — local / remote / dynamic port forwarding
//! * [`sftp`] (+ `sftp_transfer`, [`LocalPath`]) — SFTP client on the same connection.
//! * `sk_auth` (+ `sk_agent`, `agent_wire`, [`sk_helper`]) — FIDO2 `sk-*` keys (ADR-0024).

#![forbid(unsafe_code)]

mod agent;
mod agent_wire;
pub mod algos;
pub mod audit;
mod auth;
mod become_;
mod chain_proxy;
mod channel;
mod control;
mod driver;
mod exposure;
pub mod forward;
mod forward_io;
mod handler;
pub mod hops;
pub mod known_hosts;
mod local_path;
mod piv_auth;
pub mod session;
pub mod sftp;
mod sftp_transfer;
mod sftp_upload;
mod shared;
mod sk_agent;
mod sk_auth;
pub mod sk_helper;
pub mod socks;
mod via_session;

pub use audit::{AuditLog, AuthMethod, TrustEvent};
pub use chain_proxy::ChainProxy;
pub use channel::{MAX_CHUNK, TERM};
pub use control::SshControl;
pub use forward::{Exposure, ForwardId, ForwardInfo, ForwardKind};
pub use handler::ClientHandler;
pub use hops::{Hop, HopChain, HopError, HopEvents, HopStream, CHAIN_DEADLINE, MAX_HOPS};
pub use known_hosts::{KnownHosts, TrustDecision};
pub use local_path::{LocalPath, MAX_LOCAL_PATH, TARGET_EXISTS};
pub use session::{SshOptions, SshSession};
pub use sftp::{Entry, EntryKind, Listing, SftpClient};
pub use shared::{PromptBroker, HOP_PROMPT_ID_BASE};
pub use via_session::{TargetFuture, ViaSession};

pub use agent_wire::fuzz_agent_identities;
pub use piv_auth::{
    module_candidates as piv_module_candidates, module_path as piv_module_path, MAX_PIN,
};
pub use sk_agent::{agent_holds, agent_holds_key};
pub use sk_auth::SK_TOUCH_TIMEOUT;
pub use sk_helper::fuzz_sk_helper_reply;
