//! OIDC sign-in (ADR-0016 §4). Rust asks Vault for `auth_url` with a random 32-byte
//! `client_nonce`, E2 opens it in a zero-capability window `oidc-<sourceId>` and calls
//! [`OidcFlow::navigation`] from `on_navigation`. A navigation to [`OIDC_REDIRECT_URI`] is
//! intercepted (never loaded; no listener exists): its `code` and `state` go to
//! `oidc/callback` only when `state` equals the one Vault put into `auth_url`.

use std::time::Duration;

use mooring_core::secret_source::{validate_origin, OIDC_REDIRECT_URI};
use mooring_core::SecretSourceId;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::error::{Category, SecretsError};

/// One flow per source, at most this long (ADR-0016 §4).
pub const OIDC_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Longest URL we parse.
pub const MAX_URL: usize = 8 * 1024;
/// Longest `code` / `state`.
pub const MAX_PARAM: usize = 2048;

/// What the window may do with a navigation.
#[derive(Debug, PartialEq, Eq)]
pub enum Navigation {
    /// `IdP` or an allowed origin: let it load.
    Allow,
    /// The redirect: refuse the navigation, close the window, exchange `code`.
    Callback {
        /// Authorization code (single use, short-lived).
        code: Zeroizing<String>,
    },
    /// Anything else: refuse.
    Deny,
}

/// An OIDC flow in progress. The nonce never leaves Rust.
pub struct OidcFlow {
    /// Source.
    pub source: SecretSourceId,
    /// Auth mount.
    pub mount: String,
    /// URL to open in the window.
    pub auth_url: String,
    /// Origins the window may load (`IdP` origin first).
    pub allowed_origins: Vec<String>,
    pub(crate) state: Zeroizing<String>,
    pub(crate) nonce: Zeroizing<String>,
    pub(crate) started: Duration,
    /// Lock epoch the flow began in (L-34): a lock in between voids it.
    pub epoch: u64,
}

impl std::fmt::Debug for OidcFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcFlow")
            .field("source", &self.source)
            .field("allowed_origins", &self.allowed_origins)
            .finish_non_exhaustive()
    }
}

/// 32 random bytes, hex.
pub(crate) fn new_nonce() -> Zeroizing<String> {
    let mut b = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *b);
    Zeroizing::new(hex::encode(*b))
}

fn hexval(b: u8) -> Option<u8> {
    char::from(b).to_digit(16).and_then(|d| u8::try_from(d).ok())
}

/// Strict percent-decoding (`+` is a space, as in `application/x-www-form-urlencoded`).
pub(crate) fn pct_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hi = hexval(*b.get(i + 1)?)?;
                let lo = hexval(*b.get(i + 2)?)?;
                out.push(hi << 4 | lo);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    let s = String::from_utf8(out).ok()?;
    (!s.chars().any(char::is_control)).then_some(s)
}

/// Split `url` into `(origin, path, query)`; `None` when it is not a plain absolute URL.
fn split(url: &str) -> Option<(&str, &str, &str)> {
    if url.len() > MAX_URL || url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    let url = url.split_once('#').map_or(url, |(u, _)| u);
    let (scheme, rest) = url.split_once("://")?;
    if scheme != "https" && scheme != "http" {
        return None;
    }
    let auth_end = rest.find(['/', '?']).unwrap_or(rest.len());
    if rest[..auth_end].contains('@') || auth_end == 0 {
        return None;
    }
    let origin = &url[..scheme.len() + 3 + auth_end];
    let after = &rest[auth_end..];
    let (path, query) = after.split_once('?').unwrap_or((after, ""));
    Some((origin, if path.is_empty() { "/" } else { path }, query))
}

/// One query parameter (must appear exactly once).
fn param(query: &str, name: &str) -> Result<Option<Zeroizing<String>>, ()> {
    let mut found = None;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == name {
            if found.is_some() {
                return Err(());
            }
            let v = Zeroizing::new(pct_decode(v).ok_or(())?);
            if v.is_empty() || v.len() > MAX_PARAM {
                return Err(());
            }
            found = Some(v);
        }
    }
    Ok(found)
}

/// `(idp_origin, state)` of Vault's `auth_url` (https only).
pub(crate) fn parse_auth_url(url: &str) -> Result<(String, Zeroizing<String>), SecretsError> {
    let bad = || SecretsError::unavailable(Category::AuthFailed, "OIDC auth_url malformed");
    let (origin, _, query) = split(url).ok_or_else(bad)?;
    let origin = validate_origin(origin).map_err(|_| bad())?;
    let state = param(query, "state").map_err(|()| bad())?.ok_or_else(bad)?;
    Ok((origin, state))
}

/// `(code, state)` of the redirect.
pub type CodeState = (Zeroizing<String>, Zeroizing<String>);

/// `Some(Ok((code, state)))` when `url` is the redirect, `Some(Err)` when it is the redirect
/// but malformed (error / missing / duplicated parameters), `None` otherwise.
pub fn parse_callback(url: &str) -> Option<Result<CodeState, ()>> {
    let (origin, path, query) = split(url)?;
    let (r_origin, r_path, _) = split(OIDC_REDIRECT_URI)?;
    if !origin.eq_ignore_ascii_case(r_origin) || path != r_path {
        return None;
    }
    let parsed = (|| {
        if param(query, "error")?.is_some() {
            return Err(());
        }
        let code = param(query, "code")?.ok_or(())?;
        let state = param(query, "state")?.ok_or(())?;
        Ok((code, state))
    })();
    Some(parsed)
}

fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl OidcFlow {
    /// Classify a navigation of the window. A redirect whose `state` differs is `Deny`.
    #[must_use]
    pub fn navigation(&self, url: &str) -> Navigation {
        match parse_callback(url) {
            Some(Ok((code, state))) if same(state.as_bytes(), self.state.as_bytes()) => {
                Navigation::Callback { code }
            }
            Some(_) => Navigation::Deny,
            None => match split(url).and_then(|(o, _, _)| validate_origin(o).ok()) {
                Some(o) if self.allowed_origins.contains(&o) => Navigation::Allow,
                _ => Navigation::Deny,
            },
        }
    }

    pub(crate) fn expired(&self, now: Duration) -> bool {
        now.saturating_sub(self.started) > OIDC_TIMEOUT
    }

    /// The `state` Vault bound to this flow (for the callback request).
    pub(crate) fn state(&self) -> &str {
        &self.state
    }
}

/// Fuzz entry (`fuzz/fuzz_targets/oidc_callback_url.rs`). Never panics.
pub fn fuzz_oidc_callback_url(data: &[u8]) {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_callback(s);
        let _ = parse_auth_url(s);
        let _ = pct_decode(s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn flow() -> OidcFlow {
        OidcFlow {
            source: SecretSourceId::new(),
            mount: "oidc".into(),
            auth_url: "https://idp.example.test/authorize?state=st-1".into(),
            allowed_origins: vec!["https://idp.example.test".into()],
            state: Zeroizing::new("st-1".into()),
            nonce: new_nonce(),
            started: Duration::ZERO,
            epoch: 0,
        }
    }

    #[test]
    fn auth_url_state() {
        let (o, s) =
            parse_auth_url("https://IdP.example.test/authorize?client_id=x&state=a%2Bb&nonce=n")
                .expect("ok");
        assert_eq!((o.as_str(), s.as_str()), ("https://idp.example.test", "a+b"));
        for bad in [
            "http://idp.example.test/a?state=x",
            "https://idp.example.test/a",
            "https://idp.example.test/a?state=",
            "https://idp.example.test/a?state=x&state=y",
            "https://u@idp.example.test/a?state=x",
            "https://idp.example.test/a?state=%zz",
            "https://idp.example.test/a?state=%00",
        ] {
            assert!(parse_auth_url(bad).is_err(), "{bad}");
        }
        let n = new_nonce();
        assert_eq!(n.len(), 64);
        assert_ne!(*n, *new_nonce());
    }

    #[test]
    fn navigation_is_bound_to_state() {
        let f = flow();
        let ok = f.navigation("http://localhost:8250/oidc/callback?code=c-1&state=st-1");
        assert_eq!(ok, Navigation::Callback { code: Zeroizing::new("c-1".into()) });
        assert_eq!(
            f.navigation("http://localhost:8250/oidc/callback?code=c-1&state=st-2"),
            Navigation::Deny,
            "foreign state"
        );
        assert_eq!(
            f.navigation("http://LOCALHOST:8250/oidc/callback?code=c&state=st-1#x"),
            Navigation::Callback { code: Zeroizing::new("c".into()) }
        );
        for deny in [
            "http://localhost:8250/oidc/callback?state=st-1",
            "http://localhost:8250/oidc/callback?code=a&code=b&state=st-1",
            "http://localhost:8250/oidc/callback?error=access_denied&state=st-1",
            "http://localhost:8251/oidc/callback?code=c&state=st-1",
            "http://localhost:8250/oidc/callbackx?code=c&state=st-1",
            "https://evil.example.test/",
            "javascript:alert(1)",
            "https://idp.example.test.evil.example/",
        ] {
            assert_eq!(f.navigation(deny), Navigation::Deny, "{deny}");
        }
        assert_eq!(f.navigation("https://idp.example.test/login?x=1"), Navigation::Allow);
        assert!(!f.expired(OIDC_TIMEOUT));
        assert!(f.expired(OIDC_TIMEOUT + Duration::from_secs(1)));
        assert!(!format!("{f:?}").contains("st-1"));
    }

    proptest! {
        #[test]
        fn fuzz_never_panics(s in ".{0,300}") {
            fuzz_oidc_callback_url(s.as_bytes());
        }
    }
}
