//! Mooring network tools (ADR-0020): a TCP port check in plain Rust, and `ping` /
//! `traceroute` / `wg show` through the OS binaries at fixed absolute paths with fixed argv,
//! no shell, capped and sanitised output, and hostile parsers.
//!
//! No raw sockets, no elevation, ever (ADR-0020 §5). The only user-influenced argv element is
//! a [`Target`], which can never start with `-`. `wg` runs only the read-only [`WgQuery`]
//! subcommands; the key-printing ones cannot be expressed.

#![forbid(unsafe_code)]

pub mod error;
pub mod fuzz;
pub mod ping;
pub mod run;
pub mod runner;
pub mod sanitize;
pub mod target;
pub mod tcp;
pub mod tools;
pub mod traceroute;
pub mod wg;

pub use error::NetError;
pub use ping::{parse_ping, PingReply, PingResult};
pub use runner::{PingRun, Runner, Tools, TraceRun};
pub use target::Target;
pub use tcp::{tcp_check, TcpResult};
pub use tools::{argv, Iface, Os, Tool, ToolPaths, TraceFlavour, WgQuery};
pub use traceroute::{parse_traceroute, Hop, TraceResult};
pub use wg::{parse_wg, WgInterface, WgPeer, WgResult, WgStatus};
