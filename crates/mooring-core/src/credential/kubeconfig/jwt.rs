//! JWT `exp` peek (ADR-0014 §3): the payload of a bearer token that looks like a JWT is read
//! **without verifying** anything, for display ("expires in 42 min") and to fail an already
//! expired token early with `kube.auth_failed`. Never used for a trust decision; a token that
//! is not a JWT (or has no usable `exp`) simply has no expiry. Lives here (not in the Tauri
//! shell) so the `jwt_exp_peek` fuzz target can reach it.

use data_encoding::BASE64URL_NOPAD;
use time::OffsetDateTime;

use super::MAX_TOKEN;

/// Latest `exp` accepted: 9999-12-31T23:59:59Z.
const MAX_EXP: i64 = 253_402_300_799;

/// `exp` of a JWT-shaped token, unverified. `None` for anything that is not a three-part
/// base64url token with a numeric `exp` in `0..=253_402_300_799`, or longer than
/// [`MAX_TOKEN`].
#[must_use]
pub fn peek_exp(token: &str) -> Option<OffsetDateTime> {
    if token.len() > MAX_TOKEN {
        return None;
    }
    let mut parts = token.split('.');
    let (header, payload, _sig) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || header.is_empty() || payload.is_empty() {
        return None;
    }
    let raw = payload.trim_end_matches('=');
    let bytes = BASE64URL_NOPAD.decode(raw.as_bytes()).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let exp = claims.get("exp")?;
    #[allow(clippy::cast_possible_truncation)] // range-checked below; fractional seconds dropped
    let secs = exp.as_i64().or_else(|| exp.as_f64().filter(|f| f.is_finite()).map(|f| f as i64))?;
    if !(0..=MAX_EXP).contains(&secs) {
        return None;
    }
    OffsetDateTime::from_unix_timestamp(secs).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt(payload: &str) -> String {
        let e = |s: &str| BASE64URL_NOPAD.encode(s.as_bytes());
        format!("{}.{}.sig", e(r#"{"alg":"RS256"}"#), e(payload))
    }

    #[test]
    fn reads_exp_and_ignores_everything_else() {
        let t = peek_exp(&jwt(r#"{"sub":"x","exp":1893456000}"#)).expect("exp");
        assert_eq!(t.unix_timestamp(), 1_893_456_000);
        assert_eq!(
            peek_exp(&jwt(r#"{"exp":1893456000.9}"#)).expect("f").unix_timestamp(),
            1_893_456_000
        );
        for bad in [
            "not-a-jwt".to_owned(),
            "a.b".to_owned(),
            "a.b.c.d".to_owned(),
            ".x.y".to_owned(),
            jwt(r#"{"sub":"x"}"#),
            jwt(r#"{"exp":"soon"}"#),
            jwt(r#"{"exp":-1}"#),
            jwt(r#"{"exp":1e300}"#),
            jwt("not json"),
            "eyJ.%%%.x".to_owned(),
            format!("a.{}.c", "A".repeat(MAX_TOKEN)),
        ] {
            assert!(peek_exp(&bad).is_none(), "{bad:.40}");
        }
    }

    #[test]
    fn padded_payloads_are_accepted() {
        let p = data_encoding::BASE64URL.encode(br#"{"exp":1}"#);
        assert_eq!(peek_exp(&format!("h.{p}.s")).expect("exp").unix_timestamp(), 1);
    }
}
