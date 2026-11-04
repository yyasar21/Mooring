//! Query-string allow-list of the [`crate::ReadOnlyGuard`]. Keys are raw ASCII names (no
//! percent-encoding), each allowed at most once; values are percent-decoded (and `+` as
//! space) into UTF-8 and then checked by kind. An empty query (`path?`) is accepted because
//! `kube-core` emits one; an empty pair (`&&`) or a key without `=` is not.

use mooring_core::credential::kubeconfig::is_dns_label;

use crate::guard::{is_allowed_command, GuardPolicy, MAX_LIST_LIMIT, MAX_TAIL_LINES};

/// Longest `continue` token.
pub const MAX_CONTINUE: usize = 4096;
/// Longest `labelSelector`.
pub const MAX_SELECTOR: usize = 1024;
/// Largest `sinceSeconds` / `timeoutSeconds` (one year).
pub const MAX_SECONDS: u64 = 365 * 24 * 3600;

/// How a value is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleKind {
    /// `1..=500`.
    ListLimit,
    /// Opaque list continuation token (base64 alphabet).
    Continue,
    /// Label selector (`app=web,tier in (a,b)`).
    Selector,
    /// `true` / `false` / `1` / `0`.
    Bool,
    /// Digits / letters, ≤ 64.
    ResourceVersion,
    /// `1..=MAX_SECONDS`.
    Seconds,
    /// `0..=10 000`.
    TailLines,
    /// `1..=maxLogBytes`.
    LimitBytes,
    /// RFC 1123 label.
    Container,
    /// One of the owner-approved shells.
    Command,
    /// `1..=65535`.
    Port,
}

/// One allowed key.
#[derive(Debug, Clone, Copy)]
pub(crate) struct QueryRule {
    pub(crate) key: &'static str,
    pub(crate) kind: RuleKind,
}

/// Check `query` (without `?`) against `rules`.
pub(crate) fn parse_query(
    query: &str,
    rules: &[QueryRule],
    policy: GuardPolicy,
) -> Result<(), &'static str> {
    if query.is_empty() {
        return Ok(());
    }
    let mut seen = [false; 16];
    for pair in query.split('&') {
        let (key, raw) = pair.split_once('=').ok_or("query parameter without a value")?;
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err("query parameter name is not plain ASCII");
        }
        let (idx, rule) = rules
            .iter()
            .enumerate()
            .find(|(_, r)| r.key == key)
            .ok_or("query parameter not allowed")?;
        if std::mem::replace(&mut seen[idx], true) {
            return Err("query parameter repeated");
        }
        let value = decode(raw).ok_or("query value is not valid percent-encoded UTF-8")?;
        check_value(rule.kind, &value, policy)?;
    }
    Ok(())
}

fn number(v: &str, range: std::ops::RangeInclusive<u64>) -> bool {
    !v.is_empty()
        && v.len() <= 20
        && v.bytes().all(|b| b.is_ascii_digit())
        && v.parse::<u64>().is_ok_and(|n| range.contains(&n))
}

fn check_value(kind: RuleKind, v: &str, policy: GuardPolicy) -> Result<(), &'static str> {
    let ok = match kind {
        RuleKind::ListLimit => number(v, 1..=MAX_LIST_LIMIT),
        RuleKind::Continue => {
            (1..=MAX_CONTINUE).contains(&v.len())
                && v.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_=+/.".contains(&b))
        }
        RuleKind::Selector => {
            (1..=MAX_SELECTOR).contains(&v.len())
                && v.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_./=!,() ".contains(&b))
        }
        RuleKind::Bool => matches!(v, "true" | "false" | "1" | "0"),
        RuleKind::ResourceVersion => {
            (1..=64).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_alphanumeric())
        }
        RuleKind::Seconds => number(v, 1..=MAX_SECONDS),
        RuleKind::TailLines => number(v, 0..=MAX_TAIL_LINES),
        RuleKind::LimitBytes => number(v, 1..=policy.max_log_bytes),
        RuleKind::Container => is_dns_label(v),
        RuleKind::Command => is_allowed_command(v),
        RuleKind::Port => number(v, 1..=65_535),
    };
    if ok {
        Ok(())
    } else {
        Err("query value out of range or malformed")
    }
}

/// `application/x-www-form-urlencoded` value decoding, strict: `%` must be followed by two
/// hex digits; the result must be UTF-8 without control characters.
pub(crate) fn decode(raw: &str) -> Option<String> {
    let b = raw.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hex = b.get(i + 1..i + 3)?;
                let s = std::str::from_utf8(hex).ok()?;
                out.push(u8::from_str_radix(s, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c if c.is_ascii_graphic() => {
                out.push(c);
                i += 1;
            }
            _ => return None,
        }
    }
    let s = String::from_utf8(out).ok()?;
    (!s.chars().any(char::is_control)).then_some(s)
}

/// `application/x-www-form-urlencoded` encoding of one value (unreserved bytes kept).
pub(crate) fn encode(v: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(v.len());
    for b in v.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}
