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
//! * [`forward`] (+ `forward_io`, [`socks`]) — local / remote / dynamic port forwarding

#![forbid(unsafe_code)]

mod agent;
pub mod algos;
pub mod audit;
mod auth;
mod channel;
mod driver;
pub mod forward;
mod forward_io;
mod handler;
pub mod known_hosts;
pub mod session;
mod shared;
pub mod socks;

pub use audit::{AuthMethod, TrustEvent};
pub use channel::{MAX_CHUNK, TERM};
pub use forward::{ForwardId, ForwardInfo, ForwardKind};
pub use handler::ClientHandler;
pub use known_hosts::{KnownHosts, TrustDecision};
pub use session::{SshOptions, SshSession};
