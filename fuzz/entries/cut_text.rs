//! Fuzz entry `cut_text` (review 5 L-28, ADR-0012 §Tests): the `ServerCutText` path of a
//! T3 server through the real message parser and the Latin-1 converters. Byte 0 is the
//! selector (even: framed as a `ServerCutText` message with the real length; odd: converter
//! round trip only), the rest is the text.

use mooring_proto_vnc::messages::{latin1_to_string, string_to_latin1, MAX_CUT_TEXT};
use mooring_proto_vnc::{parse_server_message, Parsed, ServerMessage};

/// Latin-1 bytes a session may show: no control character except tab and newline.
fn check_converted(text: &str, input: &[u8]) {
    assert!(
        text.chars().all(|c| !c.is_control() || matches!(c, '\t' | '\n')),
        "control character survived the conversion"
    );
    assert!(text.chars().count() <= input.len(), "conversion grew the text");
    // Every kept character is one input byte, so the text re-encodes to the filtered input.
    let kept: Vec<u8> = input
        .iter()
        .copied()
        .filter(|&b| {
            let c = char::from(b);
            !c.is_control() || matches!(c, '\t' | '\n')
        })
        .collect();
    assert_eq!(string_to_latin1(text).as_deref(), Some(kept.as_slice()), "round trip");
}

/// Never panics; a framed message yields the converted text or `CutTextTooLong` for a
/// length over the cap, and the converters round-trip.
pub fn run(data: &[u8]) {
    let Some((&sel, text)) = data.split_first() else { return };
    let converted = latin1_to_string(text);
    check_converted(&converted, text);
    if sel % 2 == 1 {
        return;
    }
    // `ServerCutText`: type 3, 3 bytes padding, u32 length, text. A claimed length over the
    // cap must be reported as too long without reading the body; a claim beyond the buffer
    // must ask for more, never index past it.
    let claimed = u32::try_from(text.len()).unwrap_or(u32::MAX);
    let claimed = if sel % 4 == 2 { claimed.saturating_mul(3) } else { claimed };
    let mut msg = vec![3, 0, 0, 0];
    msg.extend_from_slice(&claimed.to_be_bytes());
    msg.extend_from_slice(text);
    match parse_server_message(&msg) {
        Ok(Parsed::Done(ServerMessage::CutText(t), used)) => {
            assert_eq!(used, 8 + text.len());
            assert_eq!(t, converted);
        }
        Ok(Parsed::Done(ServerMessage::CutTextTooLong { len }, used)) => {
            assert!(len > MAX_CUT_TEXT, "too long below the cap");
            assert_eq!(used, 8, "the body is not consumed with the header");
        }
        Ok(Parsed::Need(n)) => assert!(n > msg.len(), "Need({n}) with {} bytes", msg.len()),
        Ok(Parsed::Done(other, _)) => panic!("cut text parsed as {other:?}"),
        Err(e) => panic!("a well-formed ServerCutText header was refused: {e}"),
    }
}
