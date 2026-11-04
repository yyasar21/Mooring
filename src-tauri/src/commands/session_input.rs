//! `SessionInput` as the UI sends it (ADR-0008, ADR-0011) and its validation at the IPC
//! boundary. Coordinates are checked against the largest framebuffer here and against the
//! real one by the protocol crate.

use base64::Engine as _;
use mooring_core::frame::MAX_DIM;
use mooring_core::session::{SessionInput, Size};
use secrecy::SecretString;
use serde::Deserialize;

use crate::error::{IpcError, IpcResult};

/// Largest terminal size accepted (columns / rows).
pub const MAX_DIMENSION: u32 = 16_384;
/// Largest `Bytes` input per call (decoded).
pub const MAX_INPUT_BYTES: usize = 64 * 1024;
/// Longest prompt answer (bytes).
pub const MAX_ANSWER_BYTES: usize = 4096;
/// Smallest graphical desktop edge (ADR-0011 dynamic resolution).
pub const MIN_DESKTOP: u32 = 200;
/// Pointer button bits defined by ADR-0011 (left, middle, right, back, forward).
pub const POINTER_BUTTONS: u8 = 0b1_1111;

/// `SessionInput` as the UI sends it: `kind` tag, base64 bytes, answer text wrapped at once.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WireInput {
    /// Keystrokes, base64.
    Bytes {
        /// Payload.
        data: String,
    },
    /// New size (terminal cells, or desktop CSS pixels for RDP/VNC).
    Resize {
        /// Size.
        size: Size,
    },
    /// Pointer in framebuffer pixels.
    Pointer {
        /// X.
        x: u32,
        /// Y.
        y: u32,
        /// Buttons (1 left, 2 middle, 4 right, 8 back, 16 forward).
        buttons: u8,
    },
    /// Physical key; never logged.
    Key {
        /// `KeyboardEvent.code`.
        code: String,
        /// `KeyboardEvent.key`.
        key: String,
        /// Pressed or released.
        pressed: bool,
    },
    /// Wheel, 120 per notch, DOM sign (positive `dy` = down); passed through unchanged.
    Wheel {
        /// Horizontal.
        dx: i16,
        /// Vertical.
        dy: i16,
    },
    /// IME text; never logged.
    Unicode {
        /// Text.
        text: String,
    },
    /// Release every key and button (blur).
    ReleaseAll {},
    /// Tab focused: Rust may announce the local clipboard to the remote.
    ClipboardOffer {},
    /// Prompt answer; never logged or echoed.
    Answer {
        /// Prompt id.
        id: u32,
        /// Answer.
        text: SecretString,
    },
    /// Sign-in form answer for a `credential` prompt (ADR-0009). Empty username and password
    /// mean the user cancelled.
    CredentialAnswer {
        /// Prompt id.
        id: u32,
        /// Username as typed.
        username: String,
        /// Domain, when asked.
        #[serde(default)]
        domain: Option<String>,
        /// Password; never logged or echoed.
        password: SecretString,
    },
}

impl std::fmt::Debug for WireInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            Self::Bytes { .. } => "bytes",
            Self::Resize { .. } => "resize",
            Self::Pointer { .. } => "pointer",
            Self::Key { .. } => "key",
            Self::Wheel { .. } => "wheel",
            Self::Unicode { .. } => "unicode",
            Self::ReleaseAll {} => "release_all",
            Self::ClipboardOffer {} => "clipboard_offer",
            Self::Answer { .. } => "answer",
            Self::CredentialAnswer { .. } => "credential_answer",
        };
        write!(f, "WireInput({kind}, <redacted>)")
    }
}

/// Terminal size: 1..=16384 each.
pub fn check_size(size: Size) -> IpcResult<Size> {
    if size.width == 0
        || size.height == 0
        || size.width > MAX_DIMENSION
        || size.height > MAX_DIMENSION
    {
        return Err(IpcError::invalid("size", "width and height must be 1..=16384"));
    }
    Ok(size)
}

/// Graphical desktop size (ADR-0011): 200..=8192 each, even width.
pub fn check_desktop(size: Size) -> IpcResult<Size> {
    let max = u32::from(MAX_DIM);
    let edge = |v: u32| (MIN_DESKTOP..=max).contains(&v);
    if !edge(size.width) || !edge(size.height) || !size.width.is_multiple_of(2) {
        return Err(IpcError::invalid("size", "desktop must be 200..=8192 with an even width"));
    }
    Ok(size)
}

/// Validate and decode one input. Graphical caps come from `SessionInput::validate`.
pub fn decode_input(input: WireInput) -> IpcResult<SessionInput> {
    let input = match input {
        WireInput::Bytes { data } => {
            // base64 is 4/3 the decoded size; refuse before allocating.
            if data.len() > MAX_INPUT_BYTES.div_ceil(3) * 4 {
                return Err(IpcError::invalid("data", "larger than 64 KiB"));
            }
            let data = base64::engine::general_purpose::STANDARD
                .decode(data.as_bytes())
                .map_err(|_| IpcError::invalid("data", "not base64"))?;
            SessionInput::Bytes { data }
        }
        WireInput::Resize { size } => SessionInput::Resize { size: check_size(size)? },
        WireInput::Pointer { x, y, buttons } => {
            let max = u32::from(MAX_DIM);
            if x >= max || y >= max {
                return Err(IpcError::invalid("pointer", "outside the largest desktop"));
            }
            if buttons & !POINTER_BUTTONS != 0 {
                return Err(IpcError::invalid("buttons", "unknown button bits"));
            }
            SessionInput::Pointer { x, y, buttons }
        }
        WireInput::Key { code, key, pressed } => SessionInput::Key { code, key, pressed },
        WireInput::Wheel { dx, dy } => SessionInput::Wheel { dx, dy },
        WireInput::Unicode { text } => SessionInput::Unicode { text },
        WireInput::ReleaseAll {} => SessionInput::ReleaseAll,
        WireInput::ClipboardOffer {} => SessionInput::ClipboardOffer,
        WireInput::Answer { id, text } => {
            if secrecy::ExposeSecret::expose_secret(&text).len() > MAX_ANSWER_BYTES {
                return Err(IpcError::invalid("text", "longer than 4096 bytes"));
            }
            SessionInput::Answer { id, text }
        }
        WireInput::CredentialAnswer { id, username, domain, password } => {
            if secrecy::ExposeSecret::expose_secret(&password).len() > MAX_ANSWER_BYTES {
                return Err(IpcError::invalid("password", "longer than 4096 bytes"));
            }
            let username = username.trim().to_owned();
            let domain = domain.map(|d| d.trim().to_owned()).filter(|d| !d.is_empty());
            let bad = |s: &str, max: usize| {
                s.len() > max || s.chars().any(mooring_core::credential::is_forbidden)
            };
            if bad(&username, 256) || domain.as_deref().is_some_and(|d| bad(d, 253)) {
                return Err(IpcError::invalid("username", "too long or has control characters"));
            }
            SessionInput::CredentialAnswer { id, username, domain, password }
        }
    };
    // `MooringError::Invalid` names the field only, never the keystroke.
    input.validate()?;
    Ok(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> IpcResult<SessionInput> {
        decode_input(serde_json::from_str(json).expect("shape"))
    }

    #[test]
    fn graphical_inputs_parse_and_validate() {
        assert!(matches!(
            parse(r#"{"kind":"key","code":"KeyA","key":"a","pressed":true}"#),
            Ok(SessionInput::Key { pressed: true, .. })
        ));
        assert!(matches!(
            parse(r#"{"kind":"wheel","dx":0,"dy":120}"#),
            Ok(SessionInput::Wheel { dx: 0, dy: 120 })
        ));
        assert!(matches!(parse(r#"{"kind":"release_all"}"#), Ok(SessionInput::ReleaseAll)));
        assert!(matches!(parse(r#"{"kind":"clipboard_offer"}"#), Ok(SessionInput::ClipboardOffer)));
        assert!(matches!(
            parse(r#"{"kind":"pointer","x":8191,"y":0,"buttons":31}"#),
            Ok(SessionInput::Pointer { x: 8191, .. })
        ));
        assert!(matches!(parse(r#"{"kind":"unicode","text":"ğüş"}"#), Ok(SessionInput::Unicode { .. })));
    }

    #[test]
    fn hostile_inputs_are_refused_without_echo() {
        for json in [
            r#"{"kind":"key","code":"","key":"a","pressed":true}"#,
            r#"{"kind":"key","code":"Key-A","key":"a","pressed":true}"#,
            r#"{"kind":"key","code":"KeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","key":"a","pressed":true}"#,
            r#"{"kind":"key","code":"KeyA","key":"\u0007","pressed":true}"#,
            r#"{"kind":"unicode","text":""}"#,
            r#"{"kind":"unicode","text":"pw\nsecret-typed"}"#,
            r#"{"kind":"pointer","x":8192,"y":0,"buttons":1}"#,
            r#"{"kind":"pointer","x":0,"y":0,"buttons":32}"#,
        ] {
            let e = parse(json).expect_err(json);
            assert_eq!(e.code, "input.invalid", "{json}");
            assert!(!e.message.contains("secret-typed"), "{}", e.message);
        }
        let long = format!(r#"{{"kind":"unicode","text":"{}"}}"#, "x".repeat(65));
        assert_eq!(parse(&long).expect_err("65").code, "input.invalid");
        for json in [
            r#"{"kind":"wheel","dx":0,"dy":40000}"#,
            r#"{"kind":"pointer","x":-1,"y":0,"buttons":1}"#,
            r#"{"kind":"release_all","extra":1}"#,
            r#"{"kind":"frame","rgba":"AAAA"}"#,
        ] {
            assert!(serde_json::from_str::<WireInput>(json).is_err(), "{json}");
        }
        let k: WireInput =
            serde_json::from_str(r#"{"kind":"key","code":"KeyP","key":"p","pressed":true}"#)
                .expect("key");
        assert_eq!(format!("{k:?}"), "WireInput(key, <redacted>)");
    }

    #[test]
    fn desktop_sizes_follow_the_adr() {
        let s = |width, height| Size { width, height };
        assert!(check_desktop(s(1280, 800)).is_ok());
        assert!(check_desktop(s(200, 200)).is_ok());
        assert!(check_desktop(s(8192, 8192)).is_ok());
        for bad in [s(199, 800), s(1281, 800), s(1280, 8193), s(8194, 800), s(0, 0)] {
            assert_eq!(check_desktop(bad).expect_err("bad").code, "input.invalid", "{bad:?}");
        }
    }
}
