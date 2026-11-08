//! The protocol-agnostic session contract (ADR-0004, amended by ADR-0011).
//!
//! A protocol crate implements [`Session`]; the Tauri layer drives it and forwards
//! [`SessionEvent`]s to the UI over a Tauri channel. The UI never sees credentials:
//! the protocol crate receives already-resolved secret material from the vault at
//! `connect` time and drops it as soon as the handshake is done. Graphical sessions do not
//! send pixels as events: they write into a [`crate::frame::FrameSink`] (ADR-0011 frame path).

use async_trait::async_trait;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::audit::SessionAudit;
use crate::error::{MooringError, Result};
use crate::known_certs::CertificateInfo;
use crate::model::Protocol;

pub use crate::connect::{Become, ConnectParams, ConnectSecret, PivLogin, PromptAccount, SkLogin};

/// Longest `Key.code` (`KeyboardEvent.code`, ASCII), in bytes.
pub const MAX_KEY_CODE: usize = 32;
/// Longest `Key.key` (`KeyboardEvent.key`), in bytes.
pub const MAX_KEY_KEY: usize = 32;
/// Longest `Unicode.text`, in characters.
pub const MAX_UNICODE_CHARS: usize = 64;

/// Terminal columns×rows or screen width×height.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Size {
    /// Columns or pixels wide.
    pub width: u32,
    /// Rows or pixels high.
    pub height: u32,
}

/// Input from the user to the remote side.
///
/// `Debug` is hand-written: `Answer.text` and `CredentialAnswer.password` are secrets
/// (they also serialise as `"<redacted>"`), and keyboard input (`Key`, `Unicode`) may be a
/// password typed into a remote login screen, so its content is never printed either. Only
/// ever deserialised from the UI; call [`SessionInput::validate`] at the IPC boundary.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionInput {
    /// Raw bytes (terminal keystrokes).
    Bytes {
        /// Payload.
        data: Vec<u8>,
    },
    /// Window / terminal resized.
    Resize {
        /// New size.
        size: Size,
    },
    /// Pointer position and buttons (1 = left, 2 = middle, 4 = right, 8 = back, 16 = forward).
    Pointer {
        /// X in framebuffer pixels.
        x: u32,
        /// Y in framebuffer pixels.
        y: u32,
        /// Button bitmask.
        buttons: u8,
    },
    /// Physical key (graphical protocols): mapped to a scancode from `code`, which does not
    /// depend on the local layout; `key` is the layout-dependent value (VNC keysyms).
    Key {
        /// `KeyboardEvent.code`, ≤ 32 ASCII bytes (e.g. `KeyA`, `ShiftLeft`).
        code: String,
        /// `KeyboardEvent.key`, ≤ 32 bytes (e.g. `a`, `Enter`).
        key: String,
        /// Pressed or released.
        pressed: bool,
    },
    /// Wheel, 120 per notch (positive `dy` = down, positive `dx` = right).
    Wheel {
        /// Horizontal delta.
        dx: i16,
        /// Vertical delta.
        dy: i16,
    },
    /// Text composed by an IME, sent as Unicode key events. ≤ 64 characters.
    Unicode {
        /// Composed text.
        text: String,
    },
    /// Release every pressed key and button (sent on blur so nothing stays stuck).
    ReleaseAll,
    /// The session tab gained focus: Rust reads the OS clipboard and announces it to the
    /// remote side (policy permitting). The text never crosses IPC.
    ClipboardOffer,
    /// Answer to a [`SessionEvent::Prompt`] (TOFU decision, keyboard-interactive response).
    Answer {
        /// Id of the prompt being answered.
        id: u32,
        /// The answer. Never printed, never serialised back.
        #[serde(serialize_with = "serialize_redacted")]
        text: SecretString,
    },
    /// Answer to a `credential` prompt (ADR-0009 `prompt` kind): one form, one answer. An empty
    /// username and password means the user cancelled.
    CredentialAnswer {
        /// Id of the prompt being answered.
        id: u32,
        /// Username as typed (may be `DOMAIN\user`).
        username: String,
        /// Domain, when asked.
        #[serde(default)]
        domain: Option<String>,
        /// Password. Never printed, never serialised back.
        #[serde(serialize_with = "serialize_redacted")]
        password: SecretString,
    },
}

/// Placeholder written instead of secret answer text.
pub const REDACTED: &str = "<redacted>";

fn serialize_redacted<S: serde::Serializer>(
    _secret: &SecretString,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(REDACTED)
}

impl SessionInput {
    /// The ADR-0011 input caps: `Key.code` 1..=32 ASCII alphanumerics, `Key.key` ≤ 32 bytes
    /// without control characters, `Unicode.text` 1..=64 characters without control
    /// characters. Other variants are checked where they are used (sizes by the IPC
    /// layer, coordinates by the protocol against its framebuffer).
    pub fn validate(&self) -> Result<()> {
        let bad = |field: &'static str, reason: &str| MooringError::Invalid {
            field,
            reason: reason.to_owned(),
        };
        match self {
            Self::Key { code, key, .. } => {
                if code.is_empty()
                    || code.len() > MAX_KEY_CODE
                    || !code.bytes().all(|b| b.is_ascii_alphanumeric())
                {
                    return Err(bad("code", "must be 1-32 ASCII letters or digits"));
                }
                if key.len() > MAX_KEY_KEY || key.chars().any(char::is_control) {
                    return Err(bad("key", "must be at most 32 bytes without control characters"));
                }
            }
            Self::Unicode { text } => {
                let n = text.chars().count();
                if n == 0 || n > MAX_UNICODE_CHARS || text.chars().any(char::is_control) {
                    return Err(bad("text", "must be 1-64 characters without control characters"));
                }
            }
            _ => {}
        }
        Ok(())
    }
}

impl std::fmt::Debug for SessionInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bytes { data } => f.debug_struct("Bytes").field("data", data).finish(),
            Self::Resize { size } => f.debug_struct("Resize").field("size", size).finish(),
            Self::Pointer { x, y, buttons } => f
                .debug_struct("Pointer")
                .field("x", x)
                .field("y", y)
                .field("buttons", buttons)
                .finish(),
            Self::Key { pressed, .. } => f
                .debug_struct("Key")
                .field("code", &REDACTED)
                .field("key", &REDACTED)
                .field("pressed", pressed)
                .finish(),
            Self::Wheel { dx, dy } => {
                f.debug_struct("Wheel").field("dx", dx).field("dy", dy).finish()
            }
            Self::Unicode { .. } => f.debug_struct("Unicode").field("text", &REDACTED).finish(),
            Self::ReleaseAll => f.write_str("ReleaseAll"),
            Self::ClipboardOffer => f.write_str("ClipboardOffer"),
            Self::Answer { id, .. } => {
                f.debug_struct("Answer").field("id", id).field("text", &REDACTED).finish()
            }
            Self::CredentialAnswer { id, username, domain, .. } => f
                .debug_struct("CredentialAnswer")
                .field("id", id)
                .field("username", username)
                .field("domain", domain)
                .field("password", &REDACTED)
                .finish(),
        }
    }
}

/// Why a session ended (ADR-0011). The UI and the reconnect policy decide from this, never
/// from `reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseCode {
    /// Closed by the user (or the UI went away).
    User,
    /// Transport failure (DNS, TCP, TLS I/O, connection lost).
    Network,
    /// Every authentication method failed.
    AuthFailed,
    /// The user declined an unknown host key / certificate.
    TrustRejected,
    /// A pinned host key / certificate changed, or TLS was stripped after a pin: hard stop.
    TrustMismatch,
    /// The trust store holds conflicting pins for the host (review 6b L-35, after a sync
    /// merge): hard stop until the user removes them in the known-certificates manager.
    TrustConflict,
    /// The server ended the session.
    ServerEnded,
    /// The peer violated the protocol, or a parser/decoder refused its data.
    ProtocolError,
    /// The vault was locked (credential could not be resolved).
    VaultLocked,
    /// A jump host of the chain could not be opened (ADR-0025): its TCP, handshake, trust or
    /// authentication failed, or its `direct-tcpip` was refused. The target was never tried.
    HopFailed,
    /// A jump host of an open chain went away; everything above it closed with it.
    HopLost,
    /// ADR-0027: the RD Gateway refused our credentials (HTTP 401 after the last round, or
    /// Basic needed but not allowed). IPC code `rdp.gateway_auth`.
    GatewayAuth,
    /// ADR-0027: the RD Gateway refused the tunnel, its authorization or the channel to the
    /// target (`rdp.gateway_refused`).
    GatewayRefused,
    /// ADR-0027: the gateway has no MS-TSGU WebSocket endpoint (legacy RPC-over-HTTP only)
    /// or speaks another protocol version (`rdp.gateway_unsupported`).
    GatewayUnsupported,
}

impl CloseCode {
    /// Whether the Tauri reconnect loop may retry (ADR-0011: only `network` and
    /// `server_ended`, and only after `Connected`; ADR-0025: `hop_lost`, which rebuilds the
    /// whole chain. `hop_failed` is not retried: a hop that never came up needs the user).
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::Network | Self::ServerEnded | Self::HopLost)
    }
}

/// Events from the remote side to the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionEvent {
    /// Handshake finished; the session is interactive.
    Connected {
        /// Protocol.
        protocol: Protocol,
        /// Server identity shown to the user (host key fingerprint, `x509 SHA256:<hex>`).
        peer_identity: Option<String>,
        /// Transport security in effect: RDP `nla` / `tls`, VNC `vencrypt-x509` / `vnc-auth`
        /// / `none`; `None` for SSH (always encrypted).
        #[serde(default)]
        security: Option<String>,
        /// ADR-0025: the hop this event is about (0-based), `None` = the target. Hop
        /// `Connected` events are not emitted today (`HopStatus` carries them); the field
        /// exists so the UI contract is one shape.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hop: Option<u8>,
    },
    /// Terminal output.
    Bytes {
        /// Payload.
        data: Vec<u8>,
    },
    /// The remote desktop size changed (server-initiated or after a `Resize`).
    DesktopResized {
        /// Width in pixels.
        width: u32,
        /// Height in pixels.
        height: u32,
    },
    /// The peer asked a question the user must answer (TOFU prompt, keyboard-interactive).
    Prompt {
        /// Stable prompt id to answer with.
        id: u32,
        /// Text safe to show.
        message: String,
        /// Whether the answer must be hidden in the UI.
        secret: bool,
        /// Who asks and why. The UI picks the dialog from this, never from `message`, which a
        /// server can control (ADR-0007, security review 2 L-2).
        purpose: PromptPurpose,
        /// What to ask, for `purpose: credential` only (ADR-0009); `null` otherwise.
        account: Option<PromptAccount>,
        /// The certificate, for `purpose: certificate_trust` only (ADR-0011); `null`
        /// otherwise.
        #[serde(default)]
        certificate: Option<CertificateInfo>,
        /// ADR-0025: which jump host asks (0-based), `None` = the target. The UI titles the
        /// dialog "Hop N of M — host" from it; the answer goes through the same `Answer { id }`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hop: Option<u8>,
    },
    /// ADR-0025: progress of one jump host of the chain. Emitted in hop order; `failed` is
    /// followed by `Closed { code: hop_failed }` (or `hop_lost` after `Connected`). Never
    /// carries a secret.
    HopStatus {
        /// 0-based position in the chain.
        hop: u8,
        /// Number of hops in the chain.
        of: u8,
        /// Where the hop stands.
        state: HopState,
        /// `host:port` of the hop as configured (safe to show).
        host: String,
        /// Host key fingerprint once known (`up`), `None` before.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer_identity: Option<String>,
    },
    /// ADR-0027: progress of the RD Gateway in front of an RDP target ("via RD Gateway
    /// gw01"). Emitted before the target's events; `failed` is followed by `Closed`.
    GatewayStatus {
        /// `host:port` of the gateway as configured (safe to show).
        host: String,
        /// Where the gateway stands (`connecting`, `authenticating`, `up`, `failed`).
        state: HopState,
        /// Gateway certificate fingerprint once the TLS handshake passed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer_identity: Option<String>,
    },
    /// ADR-0024: a FIDO2 key is about to sign; the UI shows "Touch your security key".
    /// Informational (no answer). Followed by `TouchCleared` or `TouchTimeout` with this id.
    TouchRequired {
        /// Id shared with the follow-up event.
        id: u32,
        /// `SHA256:` of the key (safe to show).
        fingerprint: String,
        /// How long the authenticator is waited for.
        timeout_seconds: u32,
        /// ADR-0025: the jump host signing, `None` = the target.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hop: Option<u8>,
    },
    /// The authenticator answered (or the attempt ended): hide the banner.
    TouchCleared {
        /// Id of the `TouchRequired`.
        id: u32,
        /// The hop, as in `TouchRequired`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hop: Option<u8>,
    },
    /// No touch within the timeout: the attempt is abandoned and `Closed { auth_failed }`
    /// follows (never a password fallback, ADR-0024 decision 30).
    TouchTimeout {
        /// Id of the `TouchRequired`.
        id: u32,
        /// The hop, as in `TouchRequired`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hop: Option<u8>,
    },
    /// Session ended. Always the last event.
    Closed {
        /// Reason safe to show.
        reason: String,
        /// Machine-readable cause.
        code: CloseCode,
    },
}

/// State of one jump host (ADR-0025 `HopStatus.state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HopState {
    /// TCP (hop 0) or `direct-tcpip` of the previous hop is being opened, then the handshake.
    Connecting,
    /// Host key accepted; authentication in progress.
    Authenticating,
    /// Authenticated; the next hop (or the target) is opened through it.
    Up,
    /// The hop failed or was lost; the chain is being torn down.
    Failed,
}

impl HopState {
    /// Wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::Authenticating => "authenticating",
            Self::Up => "up",
            Self::Failed => "failed",
        }
    }
}

/// Why a [`SessionEvent::Prompt`] was raised. Set by the protocol crate, never derived from
/// server text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptPurpose {
    /// Unknown host key: the answer is `yes` or `no` (TOFU).
    HostKeyTrust,
    /// Unknown server certificate (RDP, VNC `VeNCrypt`): `yes` pins it and reconnects, anything
    /// else closes with `trust_rejected`. `Prompt.certificate` is set.
    CertificateTrust,
    /// A server keyboard-interactive prompt (server-controlled text).
    KeyboardInteractive,
    /// Sign-in form for a `prompt` credential: answered with `SessionInput::CredentialAnswer`.
    Credential,
    /// ADR-0027: unknown RD Gateway certificate (`known_rdg_certs`): `yes` pins it for the
    /// gateway's `host:port`, `once` trusts it for this connect. `Prompt.certificate` is set;
    /// the dialog is titled "RD Gateway certificate".
    GatewayCertificateTrust,
    /// ADR-0027: the PIN of a smart card (secret answer, used once, never stored). An empty
    /// answer or a closed dialog cancels the sign-in.
    SmartCardPin,
    /// Anything else.
    Other,
}

/// A live connection to a remote system.
#[async_trait]
pub trait Session: Send {
    /// Protocol spoken.
    fn protocol(&self) -> Protocol;

    /// Feed user input to the remote side.
    async fn send(&mut self, input: SessionInput) -> Result<()>;

    /// Wait for the next event. `Ok(None)` means the stream ended cleanly.
    async fn next_event(&mut self) -> Result<Option<SessionEvent>>;

    /// Close the session and release resources.
    async fn close(&mut self) -> Result<()>;

    /// Drain the audit events recorded so far (trust decisions, authentication outcome,
    /// clipboard transfers) for the Tauri layer to log.
    fn take_audit_events(&mut self) -> Vec<SessionAudit> {
        Vec::new()
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
