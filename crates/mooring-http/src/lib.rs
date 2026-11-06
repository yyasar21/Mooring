//! `mooring-http`: the one HTTPS client of Mooring (ADR-0014 §1), shared by Kubernetes (K3),
//! vSphere (V1), external secrets (E1) and sync (S1).
//!
//! * hyper 1 + hyper-util legacy pool, HTTP/1.1, connector = `TcpStream` + `tokio-rustls` with
//!   **our** verifier (ring only): pin before CA, host-name check, handshake signatures always
//!   verified, an anchored mode for explicit CAs. Unknown certificates fail fast with
//!   [`HttpError::TrustPrompt`]; the Tauri layer prompts and retries with
//!   [`HttpConfig::trusted_once`] or after the Gate wrote the pin. The verifier never blocks.
//! * Bodies are capped before parsing: `Content-Length` above the cap fails before reading,
//!   frames are counted before they are copied, buffers are `Zeroizing`.
//! * Token-bucket rate limit, concurrency slots, bounded jittered retries of idempotent
//!   requests, redirects refused unless same-origin is opted in, `https://` only (loopback
//!   plaintext behind an option), no proxy and no environment variables.
//! * Credentials in headers are marked sensitive and redacted in every `Debug`; `tracing`
//!   sees method and status only.
//! * [`tls`] lends the same verifier to a non-HTTP TLS client (ADR-0019 §4 LDAPS).

#![forbid(unsafe_code)]

mod body;
mod cert;
mod client;
mod config;
mod connect;
mod error;
pub mod fuzz;
mod headers;
mod parse;
mod policy;
mod service;
pub mod tls;
mod verify;
mod ws;

pub use body::{BodyStream, CappedBody};
pub use cert::{certificate_info, MAX_CERT_DER};
pub use client::{HttpClient, RawResponse};
pub use config::{
    ClientIdentity, HttpConfig, RateLimit, RedirectPolicy, RetryPolicy, Timeouts, DEFAULT_MAX_BODY,
    MAX_BODY_CEILING, MAX_CA_PEM, STREAM_CHUNK,
};
pub use error::{HttpError, StatusClass};
pub use headers::{is_sensitive, Headers, Redacted, SENSITIVE};
pub use parse::{content_length, decode_json, retry_after, MAX_PATH};
pub use service::HttpService;
pub use tls::{TlsClient, TlsTarget};
pub use verify::{TrustDecision, TrustVerdict};
pub use ws::{Message, WsIo, WsLimits, WsStream};

pub use http::{Method, StatusCode};
pub use mooring_core::known_certs::{CertProtocol, CertTrust, CertificateInfo};
