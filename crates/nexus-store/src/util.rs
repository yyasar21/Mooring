//! Small conversions between SQL text and domain types.

use std::str::FromStr;

use nexus_core::{NexusError, Protocol};
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

use crate::error::{invalid, Result, StoreError};

/// Every protocol the store can persist. Kept next to [`protocol_from_str`] so a new
/// `Protocol` variant fails the round-trip test until it is added here.
pub(crate) const PROTOCOLS: [Protocol; 6] = [
    Protocol::Ssh,
    Protocol::Rdp,
    Protocol::Vnc,
    Protocol::Web,
    Protocol::Kubernetes,
    Protocol::VsphereConsole,
];

pub(crate) fn protocol_from_str(s: &str) -> Result<Protocol> {
    PROTOCOLS.into_iter().find(|p| p.name() == s).ok_or(StoreError::Corrupt { what: "protocol" })
}

pub(crate) fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

/// RFC 3339 in UTC.
pub(crate) fn fmt_ts(t: OffsetDateTime) -> Result<String> {
    t.to_offset(UtcOffset::UTC).format(&Rfc3339).map_err(|_| invalid("timestamp", "not RFC 3339"))
}

pub(crate) fn parse_ts(s: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(s, &Rfc3339).map_err(|_| StoreError::Corrupt { what: "timestamp" })
}

/// Parse an id read back from the database.
pub(crate) fn parse_id<T: FromStr<Err = NexusError>>(s: &str) -> Result<T> {
    s.parse().map_err(|_| StoreError::Corrupt { what: "id" })
}

pub(crate) fn parse_opt_id<T: FromStr<Err = NexusError>>(s: Option<&str>) -> Result<Option<T>> {
    s.map(parse_id).transpose()
}

/// Name rules shared with `nexus_core::model` (1..=120 chars after trim, no control chars).
pub(crate) fn check_name(field: &'static str, name: &str) -> Result<String> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > crate::MAX_NAME {
        return Err(invalid(field, "must be 1..=120 characters"));
    }
    if n.chars().any(char::is_control) {
        return Err(invalid(field, "contains control characters"));
    }
    Ok(n.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_protocol_round_trips() {
        for p in PROTOCOLS {
            assert_eq!(protocol_from_str(p.name()).expect("known"), p);
        }
        assert!(protocol_from_str("telnet").is_err());
    }

    #[test]
    fn timestamps_round_trip_in_utc() {
        let t = now();
        assert_eq!(parse_ts(&fmt_ts(t).expect("fmt")).expect("parse"), t);
        assert!(parse_ts("yesterday").is_err());
    }

    #[test]
    fn names_are_trimmed_and_bounded() {
        assert_eq!(check_name("name", "  a ").expect("ok"), "a");
        assert!(check_name("name", "").is_err());
        assert!(check_name("name", &"x".repeat(121)).is_err());
        assert!(check_name("name", "a\nb").is_err());
    }
}
