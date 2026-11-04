//! Pure, panic-free entry points for QA's cargo-fuzz targets (Q1, ADR-0011 §Tests). Each one
//! takes arbitrary bytes and must never panic, hang or allocate beyond the input bounds.
//!
//! | target | entry |
//! | --- | --- |
//! | `certificate_info` (hostile DER) | [`certificate_info`] |
//! | `cliprdr_text` | [`cliprdr_text`] |
//! | `rdp_active_stage` (bytes → `ActiveStage::process` at 1024×768 → `FrameSink`) | [`active_stage`] |
//! | `rdp_input` (bytes → input events) | [`input_sequence`] |

use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStageBuilder, ActiveStageOutput};
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

/// First byte picks fast-path (even) or X.224 (odd); the rest is one server frame processed
/// by a fresh active stage at 1024×768, with every graphics update copied into a sink.
pub fn active_stage(data: &[u8]) {
    let Some((&sel, frame)) = data.split_first() else { return };
    let mut stage = ActiveStageBuilder {
        static_channels: StaticChannelSet::new(),
        user_channel_id: 1002,
        io_channel_id: 1003,
        message_channel_id: None,
        share_id: 0x0001_03EA,
        compression_type: None,
        enable_server_pointer: true,
        pointer_software_rendering: false,
    }
    .build();
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
        }
    }

    #[test]
    fn real_certificate_and_edge_inputs() {
        let (der, _) = crate::test_certs::self_signed(&["rdp.example.test"]);
        super::certificate_info(&der);
        for data in [&[][..], &[0], &[1], &[0, 0x30, 0x80], &[1, 3, 0, 0, 4]] {
            super::active_stage(data);
            super::cliprdr_text(data);
        }
    }
}
