//! Dev-only loopback test servers for Mooring's protocol and API clients.
//!
//! - [`rfb`]: an in-process RFB 3.8 server (None / VNC auth / VeNCrypt, Raw / ZRLE / Tight basic).
//! - [`rdp`]: an `ironrdp-acceptor` based RDP server (TLS or NLA, bitmap updates, input,
//!   clipboard, display control).
//! - A3 Q1 mock API servers over TLS (hyper 1), each with a request [`http::Recorder`]:
//!   [`kube`] (ADR-0014), [`vcenter`] (ADR-0015), [`vault`] (ADR-0016), [`s3`] (ADR-0017).
//!
//! Never a product dependency: product crates use it as a `[dev-dependencies]` entry only.
//! Every server binds `127.0.0.1` only. Run them by hand with the `*-testsrv` binaries
//! (docs/qa/test-servers.md).

#![forbid(unsafe_code)]
// Pedantic allow-list for this dev-only crate, each with a reason:
// protocol message names (VeNCrypt, ServerInit, CopyRect, ...) are spec terms, not code items;
// geometry code uses x / y / w / h / r like the specs do; knob structs are flat bags of
// independent switches by design (one per hostile behaviour).
#![allow(clippy::doc_markdown, clippy::many_single_char_names, clippy::struct_excessive_bools)]

pub mod cli;
pub mod http;
pub mod kube;
pub mod rdp;
pub mod rfb;
pub mod s3;
pub mod tls;
pub mod vault;
pub mod vcenter;
