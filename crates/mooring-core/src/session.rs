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
///
/// `Debug` is hand-written and `Answer.text` serialises as `"<redacted>"`: the answer may be a
/// keyboard-interactive password or OTP (ADR-0007). It is only ever deserialised from the UI.
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
    /// Answer to a [`SessionEvent::Prompt`] (TOFU decision, keyboard-interactive response).
    Answer {
        /// Id of the prompt being answered.
        id: u32,
        /// The answer. Never printed, never serialised back.
        #[serde(serialize_with = "serialize_redacted")]
        text: SecretString,
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
            Self::Key { scancode, pressed } => {
                f.debug_struct("Key").field("scancode", scancode).field("pressed", pressed).finish()
            }
            Self::Answer { id, .. } => {
                f.debug_struct("Answer").field("id", id).field("text", &REDACTED).finish()
            }
        }
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
        /// Who asks and why. The UI picks the dialog from this, never from `message`, which a
        /// server can control (ADR-0007, security review 2 L-2).
        purpose: PromptPurpose,
    },
    /// Session ended.
    Closed {
        /// Reason safe to show.
        reason: String,
    },
}

/// Why a [`SessionEvent::Prompt`] was raised. Set by the protocol crate, never derived from
/// server text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptPurpose {
    /// Unknown host key: the answer is `yes` or `no` (TOFU).
    HostKeyTrust,
    /// A server keyboard-interactive prompt (server-controlled text).
    KeyboardInteractive,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_purpose_is_snake_case_on_the_wire() {
        for (p, wire) in [
            (PromptPurpose::HostKeyTrust, "\"host_key_trust\""),
            (PromptPurpose::KeyboardInteractive, "\"keyboard_interactive\""),
            (PromptPurpose::Other, "\"other\""),
        ] {
            assert_eq!(serde_json::to_string(&p).expect("ser"), wire);
            assert_eq!(serde_json::from_str::<PromptPurpose>(wire).expect("de"), p);
        }
    }

    #[test]
    fn secrets_never_print() {
        let s = ConnectSecret::Password(SecretString::from("hunter2".to_owned()));
        let shown = format!("{s:?}");
        assert!(!shown.contains("hunter2"));
        assert!(shown.contains("redacted"));
    }

    #[test]
    fn answer_text_never_prints_or_serialises() {
        let input: SessionInput =
            serde_json::from_str(r#"{"kind":"answer","id":7,"text":"otp-314159"}"#)
                .expect("answer deserialises");
        let SessionInput::Answer { id, ref text } = input else {
            panic!("expected Answer");
        };
        assert_eq!(id, 7);
        assert_eq!(secrecy::ExposeSecret::expose_secret(text), "otp-314159");

        let debug = format!("{input:?}");
        assert!(!debug.contains("otp-314159"), "{debug}");
        assert!(debug.contains("<redacted>") && debug.contains('7'));

        let json = serde_json::to_string(&input).expect("serialises");
        assert!(!json.contains("otp-314159"), "{json}");
        assert!(json.contains(r#""text":"<redacted>""#), "{json}");

        let cloned = format!("{:?}", input.clone());
        assert!(!cloned.contains("otp-314159"));
    }

    #[test]
    fn other_inputs_keep_their_debug_and_wire_form() {
        let input = SessionInput::Bytes { data: vec![1, 2] };
        assert_eq!(format!("{input:?}"), "Bytes { data: [1, 2] }");
        let json = serde_json::to_string(&input).expect("serialises");
        assert_eq!(json, r#"{"kind":"bytes","data":[1,2]}"#);
        let resize: SessionInput =
            serde_json::from_str(r#"{"kind":"resize","size":{"width":80,"height":24}}"#)
                .expect("resize deserialises");
        assert!(format!("{resize:?}").contains("width: 80"));
    }
}
