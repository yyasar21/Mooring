//! RDP session for Mooring, built on `IronRDP` component crates (ADR-0011).
//!
//! - NLA (`CredSSP` / `NTLMv2`) is required; TLS-only only with `allowTlsWithoutNla` (audited as
//!   `session.rdp.legacy_security`); Standard RDP Security (RC4) is never offered; Kerberos
//!   is off (no KDC traffic).
//! - TLS is our own rustls (ring) client with a TOFU verifier over `known_rdp_certs`
//!   ([`mooring_core::known_certs`]): unknown + invalid chain → `Prompt { purpose:
//!   certificate_trust }` and a reconnect after `yes`; a changed pin → `trust_mismatch`.
//! - The active stage writes into a [`mooring_core::FrameSink`]; Display Control resizes,
//!   cliprdr carries text only, keys map from W3C `code` to scancodes.
//!
//! Constructor (R2):
//! ```ignore
//! let session = RdpSession::connect(params, RdpOptions::new(known_rdp_certs_path, conn_opts)
//!     .with_clipboard(os_clipboard), frame_sink, audit_sink).await?;
//! ```
//! Every byte from the server is hostile; our parsers have [`fuzz`] entry points.

#![forbid(unsafe_code)]

mod active;
mod active_clip;
pub mod cert;
pub mod clipboard;
mod connect;
mod creds;
mod driver;
mod errors;
pub mod fuzz;
pub mod input;
pub mod keymap;
mod options;
mod session;
mod shared;
mod tls;

#[cfg(test)]
mod test_certs;

pub use active::{to_rect, RESIZE_DEBOUNCE};
pub use cert::{CertParseError, MAX_CERT_DER};
pub use connect::clamp_desktop;
pub use options::{AuditSink, LocalClipboard, RdpOptions};
pub use session::{RdpSession, CHANNEL_CAPACITY};
