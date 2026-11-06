//! [`Target`]: the only host shape that reaches an argv or a socket (ADR-0020 §1).
//!
//! A target is 1..=253 bytes of ASCII, either a hostname (RFC 1123 labels of `[A-Za-z0-9-]`,
//! 1..=63 bytes each, no leading or trailing `-`) or an IPv4 / IPv6 literal without a zone
//! id. It never starts with `-` or `/`, so it can never be read as an option by a tool that
//! does not understand `--` (Windows), and it never contains whitespace or control characters.

use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;

use crate::error::NetError;

/// Longest hostname (RFC 1035 §2.3.4 presentation form).
pub const MAX_TARGET: usize = 253;

/// A validated host: hostname or IP literal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target(String);

impl Target {
    /// Validate `host` (trimmed) into a target.
    pub fn parse(host: &str) -> Result<Self, NetError> {
        let h = host.trim();
        if h.is_empty() {
            return Err(NetError::InvalidHost("empty"));
        }
        if h.len() > MAX_TARGET {
            return Err(NetError::InvalidHost("longer than 253 bytes"));
        }
        if !h.is_ascii() || h.bytes().any(|b| b.is_ascii_control() || b.is_ascii_whitespace()) {
            return Err(NetError::InvalidHost("must be ASCII without spaces or controls"));
        }
        if h.starts_with('-') || h.starts_with('/') {
            return Err(NetError::InvalidHost("must not start with '-' or '/'"));
        }
        if h.contains('%') {
            return Err(NetError::InvalidHost("zone ids are not allowed"));
        }
        let literal = h.strip_prefix('[').and_then(|r| r.strip_suffix(']')).unwrap_or(h);
        if let Ok(ip) = IpAddr::from_str(literal) {
            return Ok(Self(ip.to_string()));
        }
        if h.contains(':') {
            return Err(NetError::InvalidHost("not an IPv6 literal"));
        }
        let name = h.strip_suffix('.').unwrap_or(h);
        if name.is_empty() || !name.split('.').all(valid_label) {
            return Err(NetError::InvalidHost("not a valid hostname"));
        }
        Ok(Self(h.to_owned()))
    }

    /// The host as it goes into argv or `lookup_host`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The IP literal, when the target is one.
    #[must_use]
    pub fn ip(&self) -> Option<IpAddr> {
        IpAddr::from_str(&self.0).ok()
    }

    /// Whether the target is an IPv6 literal (macOS needs `ping6` / `traceroute6`).
    #[must_use]
    pub fn is_ipv6(&self) -> bool {
        Ipv6Addr::from_str(&self.0).is_ok()
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn accepts_names_and_literals() {
        for ok in [
            "example.test",
            " host01.example.test ",
            "a",
            "192.0.2.5",
            "2001:db8::1",
            "[2001:db8::1]",
            "x-y.example.test.",
            "x-y-z",
            "255.255.255.255",
        ] {
            assert!(Target::parse(ok).is_ok(), "{ok:?}");
        }
        assert_eq!(Target::parse("[2001:db8::1]").expect("v6").as_str(), "2001:db8::1");
        assert!(Target::parse("2001:db8::1").expect("v6").is_ipv6());
        assert!(!Target::parse("192.0.2.5").expect("v4").is_ipv6());
        assert_eq!(Target::parse("example.test").expect("name").ip(), None);
    }

    #[test]
    fn refuses_option_injection_and_junk() {
        for bad in [
            "",
            "-c",
            "-192.0.2.1",
            "--help",
            "/etc/passwd",
            "a b",
            "a\tb",
            "a\nb",
            "host\u{1b}[31m",
            "ünïcode.test",
            "fe80::1%eth0",
            "a_b.test",
            "-a.test",
            "a-.test",
            "a..b",
            ".a",
            "2001:db8::zz",
            "a:b",
            "[192.0.2.1]x",
        ] {
            assert!(Target::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn length_bounds() {
        let label = "a".repeat(63);
        let long = format!("{label}.{label}.{label}.{}", "a".repeat(61));
        assert_eq!(long.len(), 253);
        assert!(Target::parse(&long).is_ok());
        assert!(Target::parse(&format!("{long}a")).is_err());
        assert!(Target::parse(&"a".repeat(64)).is_err(), "label > 63");
    }

    proptest! {
        #[test]
        fn never_starts_with_dash_or_slash(s in "\\PC{0,64}") {
            if let Ok(t) = Target::parse(&s) {
                prop_assert!(!t.as_str().starts_with('-'));
                prop_assert!(!t.as_str().starts_with('/'));
                prop_assert!(t.as_str().is_ascii());
                prop_assert!(!t.as_str().contains(char::is_whitespace));
            }
        }
    }
}
