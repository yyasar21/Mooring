//! VNC session for Mooring: our own RFB 3.8 client (ADR-0012).
//!
//! * Security: `VeNCrypt` X509 (rustls, ring) with certificate TOFU through
//!   `mooring_core::known_certs`, VNC Authentication (`RustCrypto` `des`), None; policy
//!   `prefer_tls` (default) / `require_tls` / `allow_plaintext`; a pinned host behaves as
//!   `require_tls` (TLS-strip hard stop).
//! * Encodings: Raw, `CopyRect`, ZRLE, Tight basic (no JPEG, owner decision 5), plus
//!   `DesktopSize`, `ExtendedDesktopSize`, `LastRect`, Cursor and QEMU Extended Key Event.
//! * Every server byte is hostile: the parsers are pure functions over `&[u8]`
//!   ([`parse_server_message`], [`parse_rect`], [`decode_zrle`], [`decode_tight`], the
//!   handshake parsers) with caps checked before allocation, for the fuzz targets. No `unsafe`.

#![forbid(unsafe_code)]

pub mod conn;
mod connect;
pub mod decode;
mod driver;
pub mod error;
pub mod handshake;
pub mod input;
pub mod messages;
mod reader;
pub mod scancode;
pub mod security;
mod session;
mod shared;
pub mod tls;
pub mod vencrypt;
pub mod wire;

pub use decode::{decode_cursor, decode_tight, decode_zrle, Decoders, RectOp, TightStreams};
pub use driver::{MAX_OUTSTANDING, RESIZE_DEBOUNCE};
pub use error::VncError;
pub use messages::{parse_rect, parse_server_message, RectFrame, ServerMessage};
pub use session::{Clipboard, NoClipboard, VncControl, VncOptions, VncSession, CHANNEL_CAPACITY};
pub use shared::AuditLog;
pub use wire::Parsed;

#[cfg(test)]
mod session_tests;
#[cfg(test)]
mod testsrv;
