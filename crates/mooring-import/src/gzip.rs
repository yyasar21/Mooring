//! Capped gzip inflate for Royal TS `.rtsz` (ADR-0019 §3): decompressed size ≤
//! `max_decompressed` and ≤ `max_ratio` × the input, checked while streaming so a bomb is
//! refused before it is materialised. A ZIP container is refused outright (owner decision:
//! no new zip dependency).

use std::io::Read;

use flate2::read::GzDecoder;

use crate::error::{ImportError, Result};
use crate::limits::Limits;

/// gzip magic.
pub const GZIP_MAGIC: [u8; 2] = [0x1F, 0x8B];
/// ZIP local-file-header magic.
pub const ZIP_MAGIC: [u8; 4] = [b'P', b'K', 3, 4];

/// Whether `bytes` start with the gzip magic.
#[must_use]
pub fn is_gzip(bytes: &[u8]) -> bool {
    bytes.starts_with(&GZIP_MAGIC)
}

/// Whether `bytes` start with a ZIP local file header.
#[must_use]
pub fn is_zip(bytes: &[u8]) -> bool {
    bytes.starts_with(&ZIP_MAGIC)
}

/// Inflate a gzip member under the caps.
pub fn inflate(bytes: &[u8], limits: &Limits) -> Result<Vec<u8>> {
    if is_zip(bytes) {
        return Err(ImportError::UnsupportedContainer { what: "zip" });
    }
    let cap = limits.max_decompressed.min(bytes.len().saturating_mul(limits.max_ratio));
    let mut out = Vec::new();
    let mut dec = GzDecoder::new(bytes);
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = dec.read(&mut buf).map_err(|_| {
            ImportError::format("royal_ts", "corrupt gzip stream", out.len() as u64)
        })?;
        if n == 0 {
            break;
        }
        if out.len() + n > cap {
            return Err(ImportError::limits("decompressed size"));
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::write::GzEncoder;
    use flate2::Compression;

    use super::*;

    fn gz(data: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).expect("write");
        e.finish().expect("finish")
    }

    #[test]
    fn round_trips_and_caps() {
        let data: Vec<u8> =
            (0..400u32).flat_map(|i| format!("<Node id=\"{}\"/>", i * 7919).into_bytes()).collect();
        let z = gz(&data);
        assert!(is_gzip(&z));
        assert_eq!(inflate(&z, &Limits::DEFAULT).expect("inflate"), data);
        let mut l = Limits::DEFAULT;
        l.max_decompressed = 100;
        assert_eq!(inflate(&z, &l), Err(ImportError::limits("decompressed size")));
        // A bomb: 4 MiB of zeros compress to a few KiB; the 20:1 ratio refuses it.
        let bomb = gz(&vec![0u8; 4 * 1024 * 1024]);
        assert!(bomb.len() < 64 * 1024);
        assert_eq!(inflate(&bomb, &Limits::DEFAULT), Err(ImportError::limits("decompressed size")));
    }

    #[test]
    fn zip_and_garbage_are_refused() {
        assert_eq!(
            inflate(b"PK\x03\x04rest", &Limits::DEFAULT),
            Err(ImportError::UnsupportedContainer { what: "zip" })
        );
        assert!(matches!(
            inflate(b"\x1F\x8B\x08garbage", &Limits::DEFAULT),
            Err(ImportError::Format { .. })
        ));
    }
}
