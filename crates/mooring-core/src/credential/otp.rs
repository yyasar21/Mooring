//! TOTP (RFC 6238 over RFC 4226 HOTP) with the `RustCrypto` `hmac` + `sha1`/`sha2`, and the
//! base32 seed decoder (RFC 4648, `data-encoding`). The seed is a secret: decoded bytes and
//! the generated code live in `Zeroizing` buffers.

use hmac::{KeyInit, Mac};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::CredentialError;

/// Largest seed text accepted (bytes, ADR-0009 §5).
pub const MAX_SEED_TEXT: usize = 128;
/// Smallest decoded seed (bytes, ADR-0009 §1).
pub const MIN_SEED_BYTES: usize = 10;

/// HMAC hash of the TOTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OtpAlgorithm {
    /// HMAC-SHA1 (RFC 6238 default, what most authenticators use).
    #[default]
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512.
    Sha512,
}

/// Plain TOTP parameters stored in `fields.otp`: `{digits: 6|8, period: 30|60, algorithm}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawOtp")]
pub struct OtpParams {
    /// 6 or 8.
    pub digits: u8,
    /// 30 or 60 seconds.
    pub period: u16,
    /// HMAC hash.
    pub algorithm: OtpAlgorithm,
}

impl Default for OtpParams {
    fn default() -> Self {
        Self { digits: 6, period: 30, algorithm: OtpAlgorithm::Sha1 }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOtp {
    digits: u8,
    period: u16,
    algorithm: OtpAlgorithm,
}

impl TryFrom<RawOtp> for OtpParams {
    type Error = String;
    fn try_from(r: RawOtp) -> Result<Self, String> {
        if !matches!(r.digits, 6 | 8) {
            return Err("otp.digits must be 6 or 8".into());
        }
        if !matches!(r.period, 30 | 60) {
            return Err("otp.period must be 30 or 60".into());
        }
        Ok(Self { digits: r.digits, period: r.period, algorithm: r.algorithm })
    }
}

/// Decode a base32 seed as authenticator apps show it: spaces and hyphens ignored, case
/// insensitive, padding optional. Text at most [`MAX_SEED_TEXT`] bytes, decoded at least
/// [`MIN_SEED_BYTES`]. Errors never echo the seed.
pub fn decode_seed(text: &[u8]) -> Result<Zeroizing<Vec<u8>>, CredentialError> {
    let bad = |reason: &str| CredentialError::invalid("otp_seed", reason);
    if text.len() > MAX_SEED_TEXT {
        return Err(bad("longer than 128 bytes"));
    }
    let mut clean = Zeroizing::new(Vec::with_capacity(text.len()));
    for &b in text {
        match b {
            b' ' | b'-' | b'\t' | b'=' => {}
            b'a'..=b'z' => clean.push(b.to_ascii_uppercase()),
            b'A'..=b'Z' | b'2'..=b'7' => clean.push(b),
            _ => return Err(bad("must be base32 (A-Z, 2-7)")),
        }
    }
    let mut spec = data_encoding::BASE32_NOPAD.specification();
    spec.check_trailing_bits = false;
    let enc = spec.encoding().map_err(|_| bad("decoder unavailable"))?;
    let out = Zeroizing::new(enc.decode(&clean).map_err(|_| bad("must be base32 (A-Z, 2-7)"))?);
    if out.len() < MIN_SEED_BYTES {
        return Err(bad("must decode to at least 10 bytes"));
    }
    Ok(out)
}

fn hmac_digest(alg: OtpAlgorithm, key: &[u8], msg: &[u8]) -> Zeroizing<Vec<u8>> {
    // `new_from_slice` accepts any key length for HMAC; the fallbacks are unreachable.
    match alg {
        OtpAlgorithm::Sha1 => hmac::Hmac::<sha1::Sha1>::new_from_slice(key)
            .map(|m| Zeroizing::new(m.chain_update(msg).finalize().into_bytes().to_vec()))
            .unwrap_or_default(),
        OtpAlgorithm::Sha256 => hmac::Hmac::<sha2_next::Sha256>::new_from_slice(key)
            .map(|m| Zeroizing::new(m.chain_update(msg).finalize().into_bytes().to_vec()))
            .unwrap_or_default(),
        OtpAlgorithm::Sha512 => hmac::Hmac::<sha2_next::Sha512>::new_from_slice(key)
            .map(|m| Zeroizing::new(m.chain_update(msg).finalize().into_bytes().to_vec()))
            .unwrap_or_default(),
    }
}

/// RFC 4226 HOTP value for `counter`, as `digits` decimal digits.
#[must_use]
pub fn hotp(seed: &[u8], counter: u64, digits: u8, alg: OtpAlgorithm) -> Zeroizing<String> {
    let mac = hmac_digest(alg, seed, &counter.to_be_bytes());
    let Some(&last) = mac.last() else {
        return Zeroizing::new(String::new());
    };
    let off = usize::from(last & 0x0f);
    let Some(b) = mac.get(off..off + 4) else {
        return Zeroizing::new(String::new());
    };
    let bin = u32::from_be_bytes([b[0] & 0x7f, b[1], b[2], b[3]]);
    let modulo = 10u32.pow(u32::from(digits));
    Zeroizing::new(format!("{:0width$}", bin % modulo, width = usize::from(digits)))
}

/// TOTP code for `unix_ms` (milliseconds since the epoch) and how long it stays valid (ms).
#[must_use]
pub fn totp_now(seed: &[u8], params: OtpParams, unix_ms: u64) -> (Zeroizing<String>, u64) {
    let period_ms = u64::from(params.period) * 1000;
    let counter = unix_ms / period_ms;
    let valid_for = period_ms - unix_ms % period_ms;
    (hotp(seed, counter, params.digits, params.algorithm), valid_for)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// RFC 6238 Appendix B, 8 digits, 30 s.
    #[test]
    fn rfc6238_vectors() {
        let s1 = b"12345678901234567890";
        let s256 = b"12345678901234567890123456789012";
        let s512 = b"1234567890123456789012345678901234567890123456789012345678901234";
        let table: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        let p = |algorithm| OtpParams { digits: 8, period: 30, algorithm };
        for (t, a, b, c) in table {
            let ms = t * 1000;
            assert_eq!(totp_now(s1, p(OtpAlgorithm::Sha1), ms).0.as_str(), a, "sha1 {t}");
            assert_eq!(totp_now(s256, p(OtpAlgorithm::Sha256), ms).0.as_str(), b, "sha256 {t}");
            assert_eq!(totp_now(s512, p(OtpAlgorithm::Sha512), ms).0.as_str(), c, "sha512 {t}");
        }
    }

    /// RFC 4226 Appendix D, 6 digits.
    #[test]
    fn rfc4226_vectors() {
        let want = ["755224", "287082", "359152", "969429", "338314", "254676"];
        for (i, w) in want.iter().enumerate() {
            let c = u64::try_from(i).expect("small");
            assert_eq!(hotp(b"12345678901234567890", c, 6, OtpAlgorithm::Sha1).as_str(), *w);
        }
    }

    #[test]
    fn validity_window() {
        let p = OtpParams::default();
        assert_eq!(totp_now(b"12345678901234567890", p, 30_000).1, 30_000);
        assert_eq!(totp_now(b"12345678901234567890", p, 59_999).1, 1);
        let p60 = OtpParams { period: 60, ..p };
        assert_eq!(totp_now(b"12345678901234567890", p60, 61_000).1, 59_000);
    }

    #[test]
    fn seed_decoding() {
        // "12345678901234567890" in base32
        let want = b"12345678901234567890";
        for text in [
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "gezd gnbv gy3t qojq gezd gnbv gy3t qojq",
            "GEZD-GNBV-GY3T-QOJQ-GEZD-GNBV-GY3T-QOJQ",
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ====",
        ] {
            assert_eq!(decode_seed(text.as_bytes()).expect(text).as_slice(), want);
        }
        assert!(decode_seed(b"GEZDGNBV").is_err(), "5 bytes is too short");
        assert!(decode_seed(b"GEZDGNBVGY3TQOJ1").is_err(), "1 is not base32");
        assert!(decode_seed(&[b'A'; 129]).is_err(), "cap");
        let e = decode_seed(b"NOTBASE32!!!!!!!!!!").expect_err("bad");
        assert!(!e.to_string().contains("NOTBASE32"));
    }

    #[test]
    fn params_wire_shape() {
        let p: OtpParams =
            serde_json::from_str(r#"{"digits":8,"period":60,"algorithm":"sha256"}"#).expect("ok");
        assert_eq!(p, OtpParams { digits: 8, period: 60, algorithm: OtpAlgorithm::Sha256 });
        assert_eq!(
            serde_json::to_string(&OtpParams::default()).expect("ser"),
            r#"{"digits":6,"period":30,"algorithm":"sha1"}"#
        );
        for bad in [
            r#"{"digits":7,"period":30,"algorithm":"sha1"}"#,
            r#"{"digits":6,"period":45,"algorithm":"sha1"}"#,
            r#"{"digits":6,"period":30,"algorithm":"md5"}"#,
            r#"{"digits":6,"period":30,"algorithm":"sha1","x":1}"#,
        ] {
            assert!(serde_json::from_str::<OtpParams>(bad).is_err(), "{bad}");
        }
    }

    proptest! {
        #[test]
        fn seed_decoder_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
            let _ = decode_seed(&bytes);
        }

        #[test]
        fn codes_have_the_requested_width(seed in proptest::collection::vec(any::<u8>(), 10..64),
                                          t in any::<u64>(), eight in any::<bool>()) {
            let digits = if eight { 8 } else { 6 };
            let p = OtpParams { digits, period: 30, algorithm: OtpAlgorithm::Sha512 };
            let (code, valid) = totp_now(&seed, p, t);
            prop_assert_eq!(code.len(), usize::from(digits));
            prop_assert!(code.bytes().all(|b| b.is_ascii_digit()));
            prop_assert!((1..=30_000).contains(&valid));
        }
    }
}
