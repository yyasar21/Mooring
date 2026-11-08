//! Pure, panic-free entry points for QA's cargo-fuzz targets (Q1, ADR-0011 §Tests). Each one
//! takes arbitrary bytes and must never panic, hang or allocate beyond the input bounds.
//!
//! | target | entry |
//! | --- | --- |
//! | `certificate_info` (hostile DER) | [`certificate_info`] |
//! | `cliprdr_text` | [`cliprdr_text`] |
//! | `rdp_active_stage` (bytes → `ActiveStage::process` at 1024×768 → `FrameSink`) | [`active_stage`] |
//! | `rdp_input` (bytes → input events) | [`input_sequence`] |
//! | `rdp_reassembly` (frames → the M-14 reassembly caps) | [`reassembly`] |
//! | `rdp_reactivation` (frames → Deactivation-Reactivation Sequence) | [`reactivation`] |

use std::time::Duration;

use ironrdp_connector::connection_activation::{
    ConnectionActivationSequence, ConnectionActivationState,
};
use ironrdp_connector::{DesktopSize, Sequence as _};
use ironrdp_core::WriteBuf;
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput};
use ironrdp_svc::StaticChannelSet;
use mooring_core::FrameSink;
use time::OffsetDateTime;

use crate::input::InputMapper;

/// Leaf DER → `CertificateInfo` and the `CredSSP` public key.
pub fn certificate_info(data: &[u8]) {
    let _ =
        crate::cert::certificate_info(data, "rdp.example.test", OffsetDateTime::UNIX_EPOCH, &[]);
    let _ = crate::cert::certificate_info(data, "192.0.2.1", OffsetDateTime::UNIX_EPOCH, &[]);
    let _ = crate::cert::server_public_key(data);
}

/// First byte picks the format (even: `CF_UNICODETEXT`, odd: `CF_TEXT`), the rest is the
/// format-data payload.
pub fn cliprdr_text(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else { return };
    let format =
        if sel % 2 == 0 { crate::clipboard::CF_UNICODETEXT } else { crate::clipboard::CF_TEXT };
    if let Some(text) = crate::clipboard::decode_text(format, rest) {
        assert!(text.len() <= crate::clipboard::MAX_CLIPBOARD_TEXT);
    }
}

const USER_CHANNEL: u16 = 1002;
const IO_CHANNEL: u16 = 1003;

/// A fresh active stage with the ids every entry here uses, no static channels.
fn fresh_stage() -> ActiveStage {
    ActiveStageBuilder {
        static_channels: StaticChannelSet::new(),
        user_channel_id: USER_CHANNEL,
        io_channel_id: IO_CHANNEL,
        message_channel_id: None,
        share_id: 0x0001_03EA,
        compression_type: None,
        enable_server_pointer: true,
        pointer_software_rendering: false,
    }
    .build()
}

/// First byte picks fast-path (even) or X.224 (odd); the rest is one server frame processed
/// by a fresh active stage at 1024×768, with every graphics update copied into a sink.
pub fn active_stage(data: &[u8]) {
    let Some((&sel, frame)) = data.split_first() else { return };
    let mut stage = fresh_stage();
    let mut image = DecodedImage::new(PixelFormat::RgbA32, 1024, 768);
    let sink = FrameSink::new();
    if sink.resize(1024, 768).is_err() {
        return;
    }
    let action =
        if sel % 2 == 0 { ironrdp_pdu::Action::FastPath } else { ironrdp_pdu::Action::X224 };
    if let Ok(outputs) = stage.process(&mut image, action, frame, None) {
        for out in outputs {
            match out {
                ActiveStageOutput::GraphicsUpdate(r) => crate::active::blit(&sink, &image, &r),
                ActiveStageOutput::PointerBitmap(p) => sink.cursor(crate::active::cursor(&p)),
                _ => {}
            }
        }
    }
}

/// Bytes → server frames through the interim reassembly guard (review 5 M-14): each frame
/// is `[action, len_lo, len_hi, bytes…]` (action bit 0: fast-path / X.224). The guard must
/// never panic, and must refuse before its own count passes the cap.
pub fn reassembly(data: &[u8]) {
    let mut guard = crate::reassembly::Reassembly::new(1003, Some(1006), Some(1005));
    let mut rest = data;
    while let [action, lo, hi, tail @ ..] = rest {
        let n = usize::from(u16::from_le_bytes([*lo, *hi])).min(tail.len());
        let (frame, next) = tail.split_at(n);
        let action =
            if action % 2 == 0 { ironrdp_pdu::Action::FastPath } else { ironrdp_pdu::Action::X224 };
        if guard.check(action, frame).is_err() {
            return;
        }
        rest = next;
    }
}

/// Bytes → the Deactivation-Reactivation Sequence (MS-RDPBCGR 1.3.1.3, review 5 L-28) the
/// way `active::reactivate` drives it after a server `DeactivateAll`, without a socket: each
/// `[len_lo, len_hi, bytes…]` frame is one hostile server PDU stepped through a fresh
/// `ConnectionActivationSequence` (Demand Active → capability exchange → finalization), and
/// a finalized sequence goes through the same desktop-size check and `ActiveStage::reactivate`
/// as the live path. The sequence must never panic, and a finalized desktop outside
/// `MAX_DIM` must be refused before anything allocates for it.
pub fn reactivation(data: &[u8]) {
    let _ = reactivation_outcome(data);
}

/// [`reactivation`] with its result: the reactivated desktop size, or `None` when the
/// stream never finalizes or the size is refused. Lets the seed test pin that the fuzzer
/// starts past the refusal branches.
pub fn reactivation_outcome(data: &[u8]) -> Option<(u16, u16)> {
    let target = crate::connect::Target {
        host: "rdp.example.test".into(),
        port: 3389,
        conn: mooring_core::options::RdpConnOptions::default(),
        known_certs: "/nonexistent/known_rdp_certs".into(),
        connect_timeout: Duration::from_secs(1),
        dialer: std::sync::Arc::new(crate::connect::TcpKeepaliveDialer { keepalive: None }),
        client_name: "fuzz".into(),
        desktop: DesktopSize { width: 1024, height: 768 },
        session_pin: None,
        gateway: None,
    };
    let creds = crate::creds::Creds {
        username: "fuzz".into(),
        domain: None,
        password: String::new().into(),
    };
    let config = crate::connect::config(&target, &creds);
    let mut seq = ConnectionActivationSequence::new(config, IO_CHANNEL, USER_CHANNEL);
    let mut buf = WriteBuf::new();
    let mut rest = data;
    while !seq.state().is_terminal() {
        buf.clear();
        // Same rule as `single_sequence_step_read`: no PDU hint means the client's own turn.
        if seq.next_pdu_hint().is_none() {
            seq.step_no_input(&mut buf).ok()?;
            continue;
        }
        let [lo, hi, tail @ ..] = rest else { return None };
        let n = usize::from(u16::from_le_bytes([*lo, *hi])).min(tail.len());
        let (frame, next) = tail.split_at(n);
        seq.step(frame, None, &mut buf).ok()?;
        rest = next;
    }
    let ConnectionActivationState::Finalized {
        desktop_size,
        share_id,
        static_channel_chunk_size,
        enable_server_pointer,
        pointer_software_rendering,
        ..
    } = seq.connection_activation_state()
    else {
        return None;
    };
    crate::active::check_desktop(desktop_size).ok()?;
    let mut stage = fresh_stage();
    if !stage.reactivate(
        seq.io_channel_id(),
        seq.user_channel_id(),
        share_id,
        enable_server_pointer,
        pointer_software_rendering,
        static_channel_chunk_size,
    ) {
        return None;
    }
    let _ = DecodedImage::new(PixelFormat::RgbA32, desktop_size.width, desktop_size.height);
    Some((desktop_size.width, desktop_size.height))
}

/// Bytes → a sequence of pointer / key / wheel / unicode / release operations.
pub fn input_sequence(data: &[u8]) {
    const CODES: [&str; 6] =
        ["KeyA", "ShiftLeft", "NumpadEnter", "IntlBackslash", "MetaLeft", "Nope"];
    let mut m = InputMapper::new();
    for chunk in data.chunks(5) {
        let b = |i: usize| chunk.get(i).copied().unwrap_or(0);
        let word = |i: usize| i16::from_le_bytes([b(i), b(i + 1)]);
        let _ = match b(0) % 5 {
            0 => m.pointer(u32::from(b(1)) * 40, u32::from(b(2)) * 40, b(3), 1024, 768),
            1 => m.key(CODES[usize::from(b(1)) % CODES.len()], b(2) % 2 == 0),
            2 => m.wheel(word(1), word(3)),
            3 => m.unicode(&String::from_utf8_lossy(&chunk[1.min(chunk.len())..])),
            _ => m.release_all(),
        };
    }
    let _ = m.release_all();
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn never_panic(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
            super::certificate_info(&data);
            super::cliprdr_text(&data);
            super::active_stage(&data);
            super::input_sequence(&data);
            super::reassembly(&data);
            super::reactivation(&data);
        }
    }

    #[test]
    fn real_certificate_and_edge_inputs() {
        let (der, _) = crate::test_certs::self_signed(&["rdp.example.test"]);
        super::certificate_info(&der);
        for data in [&[][..], &[0], &[1], &[0, 0x30, 0x80], &[1, 3, 0, 0, 4]] {
            super::active_stage(data);
            super::cliprdr_text(data);
            super::reactivation(data);
        }
    }
}
