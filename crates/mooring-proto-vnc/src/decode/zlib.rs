//! Persistent zlib inflate streams for ZRLE and Tight, on `miniz_oxide` directly (M-15).
//!
//! `flate2` picks one backend for the whole build, and the app tree turns on its C zlib
//! (`libz-sys`, via `winscard`). Hostile RFB bytes must never reach C, so this module does
//! not depend on `flate2` at all: `miniz_oxide` is pure Rust and `forbid(unsafe_code)`.

use miniz_oxide::inflate::stream::InflateState;
use miniz_oxide::{DataFormat, MZError, MZFlush, MZStatus};

use crate::error::VncError;

/// One zlib stream that lives as long as the RFB connection (sync-flushed per rectangle).
pub struct ZStream(Box<InflateState>);

impl ZStream {
    pub fn new() -> Self {
        Self(InflateState::new_boxed(DataFormat::Zlib))
    }

    /// Back to a fresh stream (Tight's per-stream reset bits).
    pub fn reset(&mut self) {
        self.0.reset(DataFormat::Zlib);
    }
}

impl Default for ZStream {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ZStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ZStream")
    }
}

/// Inflate `input` on a persistent stream with a hard output cap. More than `limit` bytes of
/// output is a protocol error (zlib bomb); so is corrupt data.
pub fn inflate(z: &mut ZStream, input: &[u8], limit: usize) -> Result<Vec<u8>, VncError> {
    const STEP: usize = 64 * 1024;
    let bomb = || VncError::protocol("zlib output exceeds the cap");
    let mut out: Vec<u8> = Vec::new();
    let mut used = 0usize;
    loop {
        let filled = out.len();
        // Allow one byte past the limit so that "exactly limit" and "more" differ.
        let room = (limit + 1).saturating_sub(filled);
        if room == 0 {
            return Err(bomb());
        }
        let add = room.min(STEP.max(filled));
        out.resize(filled + add, 0);
        let r = miniz_oxide::inflate::stream::inflate(
            &mut z.0,
            &input[used..],
            &mut out[filled..],
            MZFlush::Sync,
        );
        used += r.bytes_consumed;
        out.truncate(filled + r.bytes_written);
        if out.len() > limit {
            return Err(bomb());
        }
        let progressed = r.bytes_consumed > 0 || r.bytes_written > 0;
        match r.status {
            // End of stream, or no progress possible (input exhausted): not an error.
            Ok(MZStatus::StreamEnd) | Err(MZError::Buf) => break,
            Ok(_) => {}
            Err(_) => return Err(VncError::protocol("corrupt zlib data")),
        }
        let done_input = used >= input.len();
        if (done_input && r.bytes_written < add) || !progressed {
            break;
        }
    }
    if used < input.len() {
        return Err(VncError::protocol("zlib stream ended early"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use flate2::{Compress, Compression, FlushCompress};

    use super::*;

    fn chunk(c: &mut Compress, raw: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(raw.len() + 1024);
        c.compress_vec(raw, &mut out, FlushCompress::Sync).expect("compress");
        out
    }

    #[test]
    fn persistent_stream_across_rects_and_large_outputs() {
        let mut c = Compress::new(Compression::default(), true);
        let mut z = ZStream::new();
        let big: Vec<u8> = (0..300_000u32).map(|i| u8::try_from(i % 251).expect("byte")).collect();
        for raw in [&big[..], &[1, 2, 3][..], &big[..1000]] {
            let out = inflate(&mut z, &chunk(&mut c, raw), raw.len()).expect("inflate");
            assert_eq!(out, raw);
        }
    }

    #[test]
    fn corrupt_and_reset() {
        let mut z = ZStream::new();
        assert!(inflate(&mut z, &[0x78, 0x9c, 0xff, 0xff, 0xff, 0xff], 100).is_err());
        z.reset();
        let mut c = Compress::new(Compression::default(), true);
        assert_eq!(inflate(&mut z, &chunk(&mut c, b"ok"), 2).expect("after reset"), b"ok");
    }
}
