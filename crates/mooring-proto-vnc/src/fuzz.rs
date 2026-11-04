//! Pure, panic-free entry points for the cargo-fuzz targets (ADR-0012 §Tests). Each takes
//! arbitrary bytes and must never panic, hang or allocate beyond the documented caps.
//!
//! | target | entry |
//! | --- | --- |
//! | `rfb_server_msg` (server messages after `ServerInit` → `FrameSink`) | [`server_messages`] |
//! | `vnc_zrle` (one ZRLE rect payload) | [`zrle`] |
//! | `vnc_tight` (one Tight rect payload) | [`tight`] |
//! | `rfb_handshake` (version, security list / reason, `ServerInit`; pre-TLS, T3) | [`handshake`] |
//! | `vencrypt_negotiation` (`VeNCrypt` version, ack, subtypes, subtype ack) | [`vencrypt`] |

use mooring_core::frame::{FrameSink, PixelOrder};

use crate::decode::{decode_tight, decode_zrle, Decoders, RectOp, TightStreams};
use crate::messages::{parse_rect, parse_server_message, ServerMessage, MAX_CUT_TEXT};
use crate::wire::Parsed;

/// Initial framebuffer of the harness (the first two bytes may change it, see below).
const START: (u16, u16) = (64, 48);

/// Bytes 0–1 pick a starting framebuffer (`w = 1 + b0`, `h = 1 + b1`, ≤ 256²); the rest is a
/// stream of server messages, processed the way the session's reader does: each
/// `FramebufferUpdate` frames its rectangles with [`parse_rect`], decodes them with one
/// persistent [`Decoders`] and applies them to a [`FrameSink`]. Ends at the first error or
/// when more bytes would be needed.
pub fn server_messages(data: &[u8]) {
    let (size, mut buf) = match data {
        [w, h, rest @ ..] => ((1 + u16::from(*w), 1 + u16::from(*h)), rest),
        _ => (START, data),
    };
    let sink = FrameSink::new();
    if sink.resize(size.0, size.1).is_err() {
        return;
    }
    let mut dec = Decoders::default();
    while !buf.is_empty() {
        let Ok(Parsed::Done(msg, used)) = parse_server_message(buf) else { return };
        buf = &buf[used..];
        match msg {
            ServerMessage::FramebufferUpdate { rects } => {
                let Some(rest) = update(&sink, &mut dec, buf, rects) else { return };
                buf = rest;
            }
            ServerMessage::CutText(text) => assert!(text.len() <= 2 * MAX_CUT_TEXT),
            ServerMessage::CutTextTooLong { len } => {
                assert!(len > MAX_CUT_TEXT);
                return;
            }
            ServerMessage::Bell | ServerMessage::SetColourMapEntries => {}
        }
    }
}

fn update<'a>(
    sink: &FrameSink,
    dec: &mut Decoders,
    mut buf: &'a [u8],
    rects: u16,
) -> Option<&'a [u8]> {
    for _ in 0..rects {
        let (fw, fh) = sink.size();
        let Ok(Parsed::Done(frame, used)) = parse_rect(buf, fw, fh) else { return None };
        let op = dec.decode(&frame, buf).ok()?;
        buf = &buf[used..];
        let ok = match op {
            RectOp::Blit { rect, rgbx } => {
                assert_eq!(rgbx.len(), usize::from(rect.w) * usize::from(rect.h) * 4);
                sink.blit(rect, &rgbx, usize::from(rect.w) * 4, PixelOrder::Rgbx).is_ok()
            }
            RectOp::Fill { rect, rgba } => sink.fill(rect, rgba).is_ok(),
            RectOp::Copy { rect, src_x, src_y } => sink.copy(rect, src_x, src_y).is_ok(),
            RectOp::Resize { w, h, .. } => sink.resize(w, h).is_ok(),
            RectOp::Cursor(c) => {
                sink.cursor(c);
                true
            }
            RectOp::LastRect => break,
            RectOp::ExtDesktopRefused { .. } | RectOp::QemuExtKey | RectOp::Nothing => true,
        };
        if !ok {
            return None;
        }
    }
    let _ = sink.take_frame(1);
    Some(buf)
}

fn dims(data: &[u8]) -> Option<(u16, u16, &[u8])> {
    let [w, h, rest @ ..] = data else { return None };
    Some((1 + u16::from(*w % 64), 1 + u16::from(*h % 64), rest))
}

/// Bytes 0–1 pick the rect size (≤ 64²); the rest is a ZRLE payload (after the length field),
/// decoded twice with one persistent stream.
pub fn zrle(data: &[u8]) {
    let Some((w, h, payload)) = dims(data) else { return };
    let mut z = crate::decode::ZStream::new();
    for _ in 0..2 {
        if let Ok(px) = decode_zrle(&mut z, payload, w, h) {
            assert_eq!(px.len(), usize::from(w) * usize::from(h) * 4);
        }
    }
}

/// Bytes 0–1 pick the rect size (≤ 64²); the rest is a Tight payload from the control byte
/// on, decoded twice with persistent streams.
pub fn tight(data: &[u8]) {
    let Some((w, h, payload)) = dims(data) else { return };
    let mut streams = TightStreams::default();
    for _ in 0..2 {
        if let Ok(crate::decode::TightOutput::Pixels(px)) =
            decode_tight(&mut streams, payload, w, h)
        {
            assert_eq!(px.len(), usize::from(w) * usize::from(h) * 4);
        }
    }
}

/// Run `parse` on `buf`; on `Done` return the rest. `Need` must ask for more than it has.
fn step<'a, T>(
    buf: &'a [u8],
    parse: impl Fn(&[u8]) -> crate::wire::PResult<T>,
) -> Option<(T, &'a [u8])> {
    match parse(buf) {
        Ok(Parsed::Done(v, used)) => {
            assert!(used <= buf.len(), "a parser consumed more than it was given");
            Some((v, &buf[used..]))
        }
        Ok(Parsed::Need(n)) => {
            assert!(n > buf.len(), "Need({n}) with {} bytes", buf.len());
            None
        }
        Err(_) => None,
    }
}

/// The pre-TLS RFB handshake as a T3 sees it: `ProtocolVersion`, the security type list
/// (or a refusal reason), a security selection for every credential kind and policy, a
/// `SecurityResult`, then `ServerInit` (≤ 8192², name ≤ 4096 bytes).
pub fn handshake(data: &[u8]) {
    use crate::handshake::{
        parse_security_result, parse_security_types, parse_server_init, parse_version,
    };
    use crate::security::{select_security, CredKind, SecPolicy};
    use mooring_core::options::VncSecurity;
    let Some((_, rest)) = step(data, parse_version) else { return };
    let Some((offered, rest)) = step(rest, parse_security_types) else { return };
    for cred in [CredKind::None, CredKind::Password, CredKind::UserPassword] {
        for security in
            [VncSecurity::AllowPlaintext, VncSecurity::PreferTls, VncSecurity::RequireTls]
        {
            for (pinned, allow_no_auth) in [(false, false), (true, false), (false, true)] {
                let policy = SecPolicy { security, pinned, allow_no_auth, skip_vencrypt: pinned };
                if let Ok(choice) = select_security(&offered, cred, policy) {
                    assert!(offered.contains(&choice.byte()), "chose a type not offered");
                    assert!(!(pinned && choice.byte() != crate::security::SEC_VENCRYPT));
                }
            }
        }
    }
    let Some(((), rest)) = step(rest, parse_security_result) else { return };
    if let Some((init, _)) = step(rest, parse_server_init) {
        let max = mooring_core::frame::MAX_DIM;
        assert!(init.width >= 1 && init.height >= 1 && init.width <= max && init.height <= max);
    }
}

/// The `VeNCrypt` 0.2 sub-negotiation: version, version ack, subtype list (subtype selection
/// for every credential kind), subtype ack.
pub fn vencrypt(data: &[u8]) {
    use crate::security::CredKind;
    use crate::vencrypt::{parse_subtype_ack, parse_subtypes, parse_version, parse_version_ack};
    let Some(((), rest)) = step(data, parse_version) else { return };
    let Some(((), rest)) = step(rest, parse_version_ack) else { return };
    let Some((subtypes, rest)) = step(rest, parse_subtypes) else { return };
    for cred in [CredKind::None, CredKind::Password, CredKind::UserPassword] {
        if let Ok(s) = crate::vencrypt::select_subtype(&subtypes, cred) {
            assert!(subtypes.contains(&s), "chose a subtype not offered");
        }
    }
    let _ = step(rest, parse_subtype_ack);
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn never_panic(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
            super::server_messages(&data);
            super::zrle(&data);
            super::tight(&data);
            super::handshake(&data);
            super::vencrypt(&data);
        }
    }

    #[test]
    fn a_raw_update_reaches_the_sink() {
        // 2×1 framebuffer, one update with one Raw rect, then Bell and cut text.
        let mut d = vec![1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0, 1, 0, 0, 0, 0];
        d.extend_from_slice(&[1, 2, 3, 0, 4, 5, 6, 0, 2, 3, 0, 0, 0, 0, 0, 0, 1, b'x']);
        super::server_messages(&d);
        super::server_messages(&[]);
        super::zrle(&[0, 0]);
        super::tight(&[0, 0, 0x80, 1, 2, 3]);
    }
}
