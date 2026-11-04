use std::borrow::Cow;

use ironrdp_core::encode_vec;
use ironrdp_pdu::fast_path::{EncryptionFlags, UpdateCode};
use ironrdp_pdu::mcs::{McsMessage, SendDataIndication};
use ironrdp_pdu::x224::X224;

use super::*;

const IO: u16 = 1003;
const CLIP: u16 = 1004;
const DRDYNVC: u16 = 1005;
const CHUNK: usize = 1600;

fn guard() -> Reassembly {
    Reassembly::new(IO, Some(1006), Some(DRDYNVC))
}

fn svc(channel: u16, declared: u32, flags: ChannelControlFlags, data: &[u8]) -> Vec<u8> {
    let mut user = declared.to_le_bytes().to_vec();
    user.extend_from_slice(&flags.bits().to_le_bytes());
    user.extend_from_slice(data);
    let pdu =
        SendDataIndication { initiator_id: 1002, channel_id: channel, user_data: Cow::Owned(user) };
    encode_vec(&X224(McsMessage::SendDataIndication(pdu))).expect("encode")
}

fn fastpath(fragmentation: Fragmentation, data: &[u8]) -> Vec<u8> {
    let update = FastPathUpdatePdu {
        fragmentation,
        update_code: UpdateCode::Bitmap,
        compression_flags: None,
        compression_type: None,
        data,
    };
    let body = encode_vec(&update).expect("update");
    let mut frame =
        encode_vec(&FastPathHeader::new(EncryptionFlags::empty(), body.len())).expect("h");
    frame.extend_from_slice(&body);
    frame
}

const FIRST: ChannelControlFlags = ChannelControlFlags::FLAG_FIRST;
const LAST: ChannelControlFlags = ChannelControlFlags::FLAG_LAST;

#[test]
fn svc_declared_length_over_the_cap_is_refused_up_front() {
    let mut g = guard();
    let f = svc(CLIP, u32::MAX, FIRST, &[0; 16]);
    assert_eq!(g.check(Action::X224, &f).expect_err("4 GiB declared").0, CloseCode::ProtocolError);
    let ok = svc(CLIP, 16, FIRST | LAST, &[0; 16]);
    g.check(Action::X224, &ok).expect("small message");
    // The I/O channel carries no channel PDU header and is never inspected.
    g.check(Action::X224, &svc(IO, u32::MAX, FIRST, &[0; 16])).expect("io channel");
}

#[test]
fn svc_chunks_past_the_cap_are_refused() {
    let mut g = guard();
    let declared = u32::try_from(MAX_REASSEMBLY).expect("u32");
    g.check(Action::X224, &svc(CLIP, declared, FIRST, &[0; CHUNK])).expect("first");
    let chunk = svc(CLIP, declared, ChannelControlFlags::empty(), &[0; CHUNK]);
    let mut sent = CHUNK;
    let err = loop {
        match g.check(Action::X224, &chunk) {
            Ok(()) => sent += CHUNK,
            Err(e) => break e,
        }
        assert!(sent <= MAX_REASSEMBLY + CHUNK, "cap not enforced");
    };
    assert_eq!(err.0, CloseCode::ProtocolError);
    assert!(sent <= MAX_REASSEMBLY && sent + CHUNK > MAX_REASSEMBLY, "{sent}");
    // FLAG_LAST resets the count for the next message.
    let mut g = guard();
    for _ in 0..3 {
        g.check(Action::X224, &svc(CLIP, 8, FIRST, &[0; 4])).expect("first");
        g.check(Action::X224, &svc(CLIP, 8, LAST, &[0; 4])).expect("last");
    }
}

fn dvc_data_first(channel: u8, length: u32, payload: &[u8]) -> Vec<u8> {
    // Cmd 2 (DataFirst), Sp 2 (4-byte length), cbChId 0 (1-byte id).
    let mut d = vec![(DVC_DATA_FIRST << 4) | (2 << 2), channel];
    d.extend_from_slice(&length.to_le_bytes());
    d.extend_from_slice(payload);
    d
}

fn whole(data: &[u8]) -> Vec<u8> {
    svc(DRDYNVC, u32::try_from(data.len()).expect("len"), FIRST | LAST, data)
}

#[test]
fn dvc_data_first_over_the_cap_is_refused() {
    let mut g = guard();
    let e = g.check(Action::X224, &whole(&dvc_data_first(3, u32::MAX, &[0; 8]))).expect_err("big");
    assert_eq!(e.0, CloseCode::ProtocolError);
    let mut compressed = dvc_data_first(3, u32::MAX, &[0; 8]);
    compressed[0] = (DVC_DATA_FIRST_COMPRESSED << 4) | (2 << 2);
    assert!(g.check(Action::X224, &whole(&compressed)).is_err(), "compressed variant");
    let declared = u32::try_from(MAX_REASSEMBLY).expect("u32");
    g.check(Action::X224, &whole(&dvc_data_first(3, declared, &[0; 8]))).expect("at the cap");
    // Other channels with the same bytes are not parsed as DVC PDUs.
    g.check(Action::X224, &svc(CLIP, 16, FIRST | LAST, &dvc_data_first(3, u32::MAX, &[])))
        .expect("svc");
}

#[test]
fn fastpath_fragment_runs_are_capped() {
    let mut g = guard();
    let piece = vec![0u8; 16_000];
    g.check(Action::FastPath, &fastpath(Fragmentation::First, &piece)).expect("first");
    let next = fastpath(Fragmentation::Next, &piece);
    let mut sent = piece.len();
    let err = loop {
        match g.check(Action::FastPath, &next) {
            Ok(()) => sent += piece.len(),
            Err(e) => break e,
        }
        assert!(sent <= MAX_REASSEMBLY + piece.len(), "cap not enforced");
    };
    assert_eq!(err.0, CloseCode::ProtocolError);
    // Single and Last end a run.
    let mut g = guard();
    for _ in 0..1000 {
        g.check(Action::FastPath, &fastpath(Fragmentation::First, &piece)).expect("first");
        g.check(Action::FastPath, &fastpath(Fragmentation::Last, &piece)).expect("last");
        g.check(Action::FastPath, &fastpath(Fragmentation::Single, &piece)).expect("single");
    }
    // Garbage passes through (IronRDP refuses it itself).
    g.check(Action::FastPath, &[0xff]).expect("undecodable");
    g.check(Action::X224, &[3, 0, 0, 4]).expect("undecodable");
}
