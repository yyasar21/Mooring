//! The protocol-agnostic session contract (ADR-0004).
//!
//! A protocol crate implements [`Session`]; the Tauri layer drives it and forwards
//! [`SessionEvent`]s to the UI over a Tauri channel. The UI never sees credentials:
//! the protocol crate receives already-resolved secret material from the vault at
//! `connect` time and drops it as soon as the handshake is done.

use async_trait::async_trait;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::model::Protocol;

/// Secret material handed to a session for the duration of the handshake only.
///
/// `Debug` is implemented by hand so the secret can never be printed.
pub enum ConnectSecret {
    /// Password / passphrase.
    Password(SecretString),
    /// PEM-encoded private key and optional passphrase.
    PrivateKey {
        /// PEM text.
        pem: SecretString,
        /// Passphrase for the key, if any.
        passphrase: Option<SecretString>,
    },
    /// No secret (e.g. agent authentication or anonymous VNC).
    None,
}

impl std::fmt::Debug for ConnectSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            Self::Password(_) => "password",
            Self::PrivateKey { .. } => "private-key",
            Self::None => "none",
        };
        write!(f, "ConnectSecret(<{kind}, redacted>)")
    }
}

/// Everything a protocol crate needs to open a session.
#[derive(Debug)]
pub struct ConnectParams {
    /// Host or URL.
    pub host: String,
    /// Port.
    pub port: u16,
    /// User name, when the protocol has one.
    pub username: Option<String>,
    /// Secret material (dropped after the handshake).
    pub secret: ConnectSecret,
    /// Initial terminal / screen size.
    pub size: Size,
}

/// Terminal columns×rows or screen width×height.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Size {
    /// Columns or pixels wide.
    pub width: u32,
    /// Rows or pixels high.
    pub height: u32,
}

/// Input from the user to the remote side.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Pointer event for graphical protocols.
    Pointer {
        /// X.
        x: u32,
        /// Y.
        y: u32,
        /// Button bitmask.
        buttons: u8,
    },
    /// Key event for graphical protocols.
    Key {
        /// Scancode.
        scancode: u32,
        /// Pressed or released.
        pressed: bool,
    },
}

/// Events from the remote side to the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionEvent {
    /// Handshake finished; the session is interactive.
    Connected {
        /// Protocol.
        protocol: Protocol,
        /// Server identity shown to the user (host key fingerprint, cert subject...).
        peer_identity: Option<String>,
    },
    /// Terminal output.
    Bytes {
        /// Payload.
        data: Vec<u8>,
    },
    /// A rectangle of the remote screen changed (graphical protocols).
    Frame {
        /// X.
        x: u32,
        /// Y.
        y: u32,
        /// Width.
        width: u32,
        /// Height.
        height: u32,
        /// RGBA pixels, row-major.
        rgba: Vec<u8>,
    },
    /// The peer asked a question the user must answer (TOFU prompt, keyboard-interactive).
    Prompt {
        /// Stable prompt id to answer with.
        id: u32,
        /// Text safe to show.
        message: String,
        /// Whether the answer must be hidden in the UI.
        secret: bool,
    },
    /// Session ended.
    Closed {
        /// Reason safe to show.
        reason: String,
    },
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_never_print() {
        let s = ConnectSecret::Password(SecretString::from("hunter2".to_owned()));
        let shown = format!("{s:?}");
        assert!(!shown.contains("hunter2"));
        assert!(shown.contains("redacted"));
    }
}
