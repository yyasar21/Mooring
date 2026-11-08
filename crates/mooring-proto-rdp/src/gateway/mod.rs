//! RD Gateway (MS-TSGU over WebSocket, ADR-0027 §1): our own transport in front of the RDP
//! connector. `wss://<gw>/remoteDesktopGateway/` through our rustls (ring) client with the
//! ADR-0011 TOFU verifier over `known_rdg_certs` (unknown → `gateway_certificate_trust`
//! prompt and reconnect; changed pin → `trust_mismatch` hard stop), HTTP NTLM through
//! `sspi` (Basic only with `allowBasicGateway`, audited), then `HANDSHAKE` → `TUNNEL_CREATE`
//! → `TUNNEL_AUTHORIZE` → `CHANNEL_CREATE` and `DATA` packets carrying the RDP stream. The
//! gateway TCP goes through the connection's dialer, so a jump-host chain composes.
//! Legacy RPC-over-HTTP gateways are refused (`gateway_unsupported`, owner decision 41).
//!
//! Every byte from the gateway is hostile: [`http`], [`ws`] and [`pdu`] are bounded and have
//! fuzz entry points ([`fuzz_rdg_pdu`], [`fuzz_rdg_http_response`]).

mod conn;
pub mod http;
mod ntlm;
pub(crate) mod open;
pub mod pdu;
mod relay;
pub mod ws;

use std::path::PathBuf;
use std::sync::Arc;

use secrecy::SecretString;

pub(crate) use open::{open, Opened};

/// The account the gateway sees at the HTTP upgrade.
pub struct GatewayAccount {
    /// User (`alice`, `CORP\alice` or `alice@corp.example`).
    pub username: String,
    /// `NetBIOS` domain, if separate.
    pub domain: Option<String>,
    /// Password (NTLM input, or the Basic header inside TLS).
    pub password: SecretString,
}

impl std::fmt::Debug for GatewayAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayAccount")
            .field("username", &self.username)
            .field("domain", &self.domain)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Which credential signs in to the gateway (ADR-0009 §3 role `gateway`).
#[derive(Debug)]
pub enum GatewayCredential {
    /// The RDP sign-in credential (also after a `prompt` form).
    SameAsSignIn,
    /// The connection's `gateway` role credential.
    Account(GatewayAccount),
}

/// What the Tauri layer adds for a connection whose `RdpConnOptions.gateway` is set.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// `$APP_DATA/known_rdg_certs` (`CertProtocol::Rdg.file_name()`; read only here).
    pub known_certs: PathBuf,
    /// The gateway credential.
    pub credential: Arc<GatewayCredential>,
    /// The gateway leaf accepted once (prompt `once`, or a pin that could not be written).
    pub trusted_once: Option<[u8; 32]>,
}

/// `host:port`, IPv6 in brackets (the pin key / label).
pub(crate) fn host_port(host: &str, port: u16) -> String {
    mooring_core::known_certs::host_key(host, port)
}

/// Fuzz entry `rdg_pdu`: MS-TSGU packets and WebSocket frames from hostile bytes. Never
/// panics; work is bounded by the caps.
pub fn fuzz_rdg_pdu(data: &[u8]) {
    let mut rest = data;
    while let Ok(Some(n)) = pdu::peek_len(rest) {
        if rest.len() < n {
            break;
        }
        let _ = pdu::decode(&rest[..n]);
        if let Ok((t, body)) = pdu::split(&rest[..n]) {
            if t == pdu::ty::CHANNEL_CREATE {
                let _ = pdu::parse_channel_create(body);
            }
        }
        rest = &rest[n..];
    }
    for masked in [false, true] {
        let mut d = ws::Decoder::new(masked);
        let mut rest = data;
        while let Ok(Some((_, used))) = d.decode(rest) {
            rest = &rest[used..];
        }
    }
}

/// Fuzz entry `rdg_http_response`: the upgrade response head, its body length and the
/// `WWW-Authenticate` challenges (with the NTLM token's base64).
pub fn fuzz_rdg_http_response(data: &[u8]) {
    if let Ok(Some(end)) = http::head_end(data) {
        if let Ok(head) = http::parse_head(&data[..end]) {
            let _ = head.body_len();
            let _ = http::challenges(&head);
            let _ = head.has_token("upgrade", "websocket");
        }
    }
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = http::decode_base64(s, http::MAX_TOKEN);
    }
}

#[cfg(test)]
#[path = "gateway_tests.rs"]
mod tests;
