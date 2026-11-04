//! Interim reassembly caps (review 5 M-14) until `IronRDP` bounds its own buffers.
//!
//! `ironrdp-svc` (`dechunkify`), `ironrdp-dvc` (`CompleteData`) and the fast-path assembler of
//! `ironrdp-session` grow a buffer up to a server-declared `u32`, or without any limit. Each
//! server PDU is therefore inspected here **before** `ActiveStage::process`:
//!
//! - static virtual channels (every channel except I/O and message): a `CHANNEL_FLAG_FIRST`
//!   chunk that declares more than [`MAX_REASSEMBLY`] is refused, and the bytes since the first
//!   chunk are counted;
//! - `drdynvc`: a `DataFirst` (or `DataFirstCompressed`) declaring more than
//!   [`MAX_REASSEMBLY`] is refused (`CompleteData` refuses blocks past the declared total, so
//!   that bounds every dynamic channel);
//! - fast-path: the bytes of a `First`/`Next`/`Last` fragment run are counted.
//!
//! Any refusal closes the session with `protocol_error`. Undecodable PDUs pass through:
//! `IronRDP` rejects them itself.

use std::collections::HashMap;

use ironrdp_core::{decode, decode_cursor, ReadCursor};
use ironrdp_pdu::fast_path::{FastPathHeader, FastPathUpdatePdu, Fragmentation};
use ironrdp_pdu::rdp::vc::{ChannelControlFlags, ChannelPduHeader};
use ironrdp_pdu::Action;
use mooring_core::session::CloseCode;

use crate::errors::{end, End};

/// Largest reassembled message on any channel, and largest fast-path fragment run.
pub const MAX_REASSEMBLY: usize = 8 * 1024 * 1024;
const DVC_DATA_FIRST: u8 = 0x02;
const DVC_DATA_FIRST_COMPRESSED: u8 = 0x06;

fn too_large() -> End {
    end(CloseCode::ProtocolError, "the server sent an oversized channel message")
}

/// Per-session reassembly accounting.
#[derive(Debug, Default)]
pub(crate) struct Reassembly {
    io_channel: u16,
    message_channel: Option<u16>,
    drdynvc: Option<u16>,
    /// Static channel id → bytes since `CHANNEL_FLAG_FIRST`.
    svc: HashMap<u16, usize>,
    /// Bytes of the current fast-path fragment run.
    fastpath: Option<usize>,
}

impl Reassembly {
    pub(crate) fn new(io_channel: u16, message_channel: Option<u16>, drdynvc: Option<u16>) -> Self {
        Self { io_channel, message_channel, drdynvc, ..Self::default() }
    }

    /// Account one server PDU; `Err` = close with `protocol_error`.
    pub(crate) fn check(&mut self, action: Action, frame: &[u8]) -> Result<(), End> {
        match action {
            Action::FastPath => self.fastpath(frame),
            Action::X224 => self.x224(frame),
        }
    }

    fn fastpath(&mut self, frame: &[u8]) -> Result<(), End> {
        let mut cur = ReadCursor::new(frame);
        if decode_cursor::<FastPathHeader>(&mut cur).is_err() {
            return Ok(());
        }
        while !cur.is_empty() {
            let Ok(update) = decode_cursor::<FastPathUpdatePdu<'_>>(&mut cur) else {
                return Ok(());
            };
            let n = update.data.len();
            self.fastpath = match (update.fragmentation, self.fastpath) {
                (Fragmentation::First, _) => Some(n),
                (Fragmentation::Next | Fragmentation::Last, Some(sum)) => {
                    let sum = sum.saturating_add(n);
                    if sum > MAX_REASSEMBLY {
                        return Err(too_large());
                    }
                    (update.fragmentation == Fragmentation::Next).then_some(sum)
                }
                // Single ends any run; IronRDP refuses a continuation without a first fragment.
                (Fragmentation::Single, _) | (Fragmentation::Next | Fragmentation::Last, None) => {
                    None
                }
            };
            if self.fastpath.is_some_and(|sum| sum > MAX_REASSEMBLY) {
                return Err(too_large());
            }
        }
        Ok(())
    }

    fn x224(&mut self, frame: &[u8]) -> Result<(), End> {
        let Ok(ctx) = ironrdp_pdu::mcs::decode_send_data_indication(frame) else {
            return Ok(());
        };
        let id = ctx.channel_id;
        if id == self.io_channel || self.message_channel == Some(id) {
            return Ok(());
        }
        let Ok(header) = decode::<ChannelPduHeader>(ctx.user_data) else {
            return Ok(());
        };
        let chunk = ctx.user_data.get(8..).unwrap_or_default();
        let first = header.flags.contains(ChannelControlFlags::FLAG_FIRST);
        let last = header.flags.contains(ChannelControlFlags::FLAG_LAST);
        let declared = usize::try_from(header.length).unwrap_or(usize::MAX);
        if first {
            if declared > MAX_REASSEMBLY {
                return Err(too_large());
            }
            if self.drdynvc == Some(id) {
                Self::dvc_pdu(chunk)?;
            }
            self.svc.insert(id, chunk.len());
        } else if let Some(sum) = self.svc.get_mut(&id) {
            *sum = sum.saturating_add(chunk.len());
            if *sum > MAX_REASSEMBLY {
                return Err(too_large());
            }
        }
        if self.svc.get(&id).is_some_and(|sum| *sum > MAX_REASSEMBLY) {
            return Err(too_large());
        }
        if last {
            self.svc.remove(&id);
        }
        Ok(())
    }

    /// The start of one `drdynvc` message: refuse a `DataFirst` over the cap.
    fn dvc_pdu(data: &[u8]) -> Result<(), End> {
        let Some((&head, rest)) = data.split_first() else { return Ok(()) };
        if !matches!(head >> 4, DVC_DATA_FIRST | DVC_DATA_FIRST_COMPRESSED) {
            return Ok(());
        }
        let width = |bits: u8| match bits & 0b11 {
            0 => 1,
            1 => 2,
            _ => 4,
        };
        let id_len = width(head);
        let Some(length) = rest.get(id_len..).and_then(|r| read_uint(r, width(head >> 2))) else {
            return Ok(());
        };
        if usize::try_from(length).unwrap_or(usize::MAX) > MAX_REASSEMBLY {
            return Err(too_large());
        }
        Ok(())
    }
}

fn read_uint(b: &[u8], len: usize) -> Option<u32> {
    let b = b.get(..len)?;
    Some(match len {
        1 => u32::from(b[0]),
        2 => u32::from(u16::from_le_bytes([b[0], b[1]])),
        _ => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
    })
}

#[cfg(test)]
#[path = "reassembly_tests.rs"]
mod tests;
