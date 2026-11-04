//! Dev-only loopback test servers for Mooring's protocol clients (A2 task Q2).
//!
//! - [`rfb`]: an in-process RFB 3.8 server (None / VNC auth / VeNCrypt, Raw / ZRLE / Tight basic).
//! - [`rdp`]: an `ironrdp-acceptor` based RDP server (TLS or NLA, bitmap updates, input,
//!   clipboard, display control).
//!
//! Never a product dependency: product crates use it as a `[dev-dependencies]` entry only.
//! Every server binds `127.0.0.1` only. Run them by hand with the `rfb-testsrv` and
//! `rdp-testsrv` binaries (docs/qa/test-servers.md).

#![forbid(unsafe_code)]
// Pedantic allow-list for this dev-only crate, each with a reason:
// protocol message names (VeNCrypt, ServerInit, CopyRect, ...) are spec terms, not code items;
// geometry code uses x / y / w / h / r like the specs do.
#![allow(clippy::doc_markdown, clippy::many_single_char_names)]

pub mod cli;
pub mod rdp;
pub mod rfb;
pub mod tls;
