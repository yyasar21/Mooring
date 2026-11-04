//! RFC 5424 rendering of an [`AuditEntry`].
//!
//! ```text
//! <PRI>1 TIMESTAMP HOSTNAME mooring PROCID MSGID [mooring@32473 seq="N" hash="H" trunc="1"? redacted="1"?] MSG
//! ```
//!
//! * `SD-ID` uses 32473, the RFC 5612 documentation enterprise number, until Mooring's own
//!   IANA PEN is assigned (review 4, N-12); it is not part of the hashed entry.
//!
//! * `PRI` = facility × 8 + severity (notice, or warning for trust changes/refusals).
//! * `TIMESTAMP` is the entry's UTC time with microseconds (RFC 5424 allows at most six digits).
//! * `HOSTNAME` / `MSGID` are reduced to PRINTUSASCII and their RFC length; empty → `-`.
//! * `MSGID` is the event name (`vault_locked`, ...).
//! * `hash` is the SHA-256 of this entry's canonical line: the next entry's `prev`, so a
//!   collector can re-verify the `prev` → `hash` linkage from the mirror alone. Content
//!   verification (`SHA-256(MSG) == hash`) holds only for lines without `trunc="1"` or
//!   `redacted="1"`; for those the local entry is needed (review 4, N-13).
//! * `MSG` is the entry's compact JSON passed through [`crate::redact`] (MSG-ANY, no BOM). JSON
//!   escapes every control character, so a message is always a single line. Events carry no
//!   secret values by construction; redaction is defence in depth.
//!
//! The whole message is capped at [`MAX_MESSAGE`] bytes (cut at a UTF-8 boundary). The
//! SD-PARAM `trunc="1"` marks a cut message and `redacted="1"` one whose MSG differs from the
//! entry's JSON because redaction applied.

use time::macros::format_description;
use time::UtcOffset;

use crate::chain::{AuditEntry, AuditEvent};
use crate::redact;

/// `APP-NAME`.
pub const APP_NAME: &str = "mooring";
/// `SD-ID` of the structured-data element.
pub const SD_ID: &str = "mooring@32473";
/// Largest message produced (header + SD + MSG). Fits common collector limits for TCP/TLS;
/// UDP receivers must accept 2048 (RFC 5426) and in practice accept this too.
pub const MAX_MESSAGE: usize = 8192;
/// RFC 5424 §6.3.1 longest `HOSTNAME`.
const MAX_HOSTNAME: usize = 255;
/// RFC 5424 §6.2.7 longest `MSGID`.
const MAX_MSGID: usize = 32;

/// Severity code (RFC 5424 table 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// 4.
    Warning = 4,
    /// 5.
    Notice = 5,
}

/// Severity of an audit event: refused or changed trust and a refused escalation are warnings;
/// everything else is a notice.
#[must_use]
pub fn severity(event: &AuditEvent) -> Severity {
    match event {
        AuditEvent::TrustDecision { decision, .. }
            if decision == "rejected" || decision == "changed" =>
        {
            Severity::Warning
        }
        AuditEvent::CertDecision { decision, .. }
            if decision == "rejected" || decision == "changed" =>
        {
            Severity::Warning
        }
        // ADR-0015 §3: a hard power-off / reset of a VM.
        AuditEvent::VspherePower { action, .. } if action == "stop" || action == "reset" => {
            Severity::Warning
        }
        AuditEvent::BecomeFailed { .. }
        | AuditEvent::CertRemoved { .. }
        | AuditEvent::SessionWeakSecurity { .. }
        | AuditEvent::CredentialSentToRemote { .. }
        | AuditEvent::ConnectionOptionsChanged { weakened: true, .. } => Severity::Warning,
        _ => Severity::Notice,
    }
}

/// Keep PRINTUSASCII (`!`..=`~`) only, at most `max` bytes; `-` (NILVALUE) when nothing is left.
#[must_use]
pub fn header_field(raw: &str, max: usize) -> String {
    let s: String = raw.chars().filter(|c| matches!(c, '!'..='~')).take(max).collect();
    if s.is_empty() {
        "-".to_owned()
    } else {
        s
    }
}

/// Escape an SD-PARAM value (RFC 5424 §6.3.3: `"`, `\` and `]`).
#[must_use]
pub fn sd_escape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        if matches!(c, '"' | '\\' | ']') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Cut `s` to at most `max` bytes on a character boundary.
fn truncate(s: &mut String, max: usize) {
    if s.len() > max {
        let mut cut = max;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
}

fn timestamp(entry: &AuditEntry) -> String {
    let fmt =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z");
    entry.at.to_offset(UtcOffset::UTC).format(&fmt).unwrap_or_else(|_| "-".to_owned())
}

/// Render one entry. `facility` must already be validated (0..=23); larger values are clamped.
#[must_use]
pub fn format_entry(entry: &AuditEntry, facility: u8, hostname: &str, procid: u32) -> String {
    let json = serde_json::to_string(entry).unwrap_or_default();
    let event_name = serde_json::to_value(&entry.event)
        .ok()
        .and_then(|v| v.get("event").and_then(|e| e.as_str()).map(str::to_owned))
        .unwrap_or_default();
    let pri = u16::from(facility.min(23)) * 8 + severity(&entry.event) as u16;
    let msg = redact(&json);
    let redacted = if msg == json { "" } else { " redacted=\"1\"" };
    let render = |trunc: &str| {
        format!(
            "<{pri}>1 {ts} {host} {APP_NAME} {procid} {msgid} [{SD_ID} seq=\"{seq}\" hash=\"{hash}\"{trunc}{redacted}] {msg}",
            ts = timestamp(entry),
            host = header_field(hostname, MAX_HOSTNAME),
            msgid = header_field(&event_name, MAX_MSGID),
            seq = entry.seq,
            hash = sd_escape(&entry.digest()),
        )
    };
    let mut out = render("");
    if out.len() > MAX_MESSAGE {
        // The header and SD stay far below the cap (hostname ≤ 255 bytes), so only MSG is cut.
        out = render(" trunc=\"1\"");
        truncate(&mut out, MAX_MESSAGE);
    }
    out
}

/// The synthetic message `syslog_test` sends: `MSGID=test`, `seq="0"`, no hash.
#[must_use]
pub fn format_test(facility: u8, hostname: &str, procid: u32, at: time::OffsetDateTime) -> String {
    let fmt =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z");
    let ts = at.to_offset(UtcOffset::UTC).format(&fmt).unwrap_or_else(|_| "-".to_owned());
    let pri = u16::from(facility.min(23)) * 8 + Severity::Notice as u16;
    format!(
        "<{pri}>1 {ts} {host} {APP_NAME} {procid} test [{SD_ID} seq=\"0\" hash=\"-\"] {{\"event\":\"syslog_test\"}}",
        host = header_field(hostname, MAX_HOSTNAME),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    fn entry(seq: u64, event: AuditEvent) -> AuditEntry {
        AuditEntry {
            seq,
            // 2026-11-04T10:20:30.123456789Z
            at: OffsetDateTime::from_unix_timestamp_nanos(1_793_787_630_123_456_789).expect("ts"),
            prev: "0".repeat(64),
            event,
        }
    }

    #[test]
    fn golden_vault_locked() {
        let e = entry(7, AuditEvent::VaultLocked { reason: "idle".into() });
        let got = format_entry(&e, 13, "ws01.example.test", 4242);
        let want = format!(
            "<109>1 2026-11-04T10:20:30.123456Z ws01.example.test mooring 4242 vault_locked \
             [mooring@32473 seq=\"7\" hash=\"{}\"] \
             {{\"seq\":7,\"at\":\"2026-11-04T10:20:30.123456789Z\",\"prev\":\"{}\",\"event\":\"vault_locked\",\"reason\":\"idle\"}}",
            e.digest(),
            "0".repeat(64)
        );
        assert_eq!(got, want);
    }

    #[test]
    fn graphical_trust_and_weak_security_are_warnings() {
        let cert = |decision: &str| AuditEvent::CertDecision {
            protocol: "rdp".into(),
            host: "192.0.2.10:3389".into(),
            fingerprint: "SHA256:00".into(),
            decision: decision.into(),
            expected: None,
        };
        assert_eq!(severity(&cert("changed")), Severity::Warning);
        assert_eq!(severity(&cert("rejected")), Severity::Warning);
        assert_eq!(severity(&cert("ca_valid")), Severity::Notice);
        let removed =
            AuditEvent::CertRemoved { protocol: "vnc".into(), host: "h:1".into(), removed: 1 };
        assert_eq!(severity(&removed), Severity::Warning);
        let weak = AuditEvent::SessionWeakSecurity {
            connection: "c".into(),
            protocol: "vnc".into(),
            security: "none".into(),
        };
        assert_eq!(severity(&weak), Severity::Warning);
        let shot = AuditEvent::SessionScreenshot { connection: "c".into(), width: 1, height: 1 };
        assert_eq!(severity(&shot), Severity::Notice);
        let opts = |weakened| AuditEvent::ConnectionOptionsChanged {
            connection: "c".into(),
            protocol: "rdp".into(),
            changed: vec!["caPem".into()],
            ca_pem: vec!["SHA256:00".into()],
            weakened,
        };
        assert_eq!(severity(&opts(true)), Severity::Warning);
        assert_eq!(severity(&opts(false)), Severity::Notice);
        let sent =
            AuditEvent::CredentialSentToRemote { credential: "k".into(), connection: "c".into() };
        assert_eq!(severity(&sent), Severity::Warning);
    }

    #[test]
    fn golden_trust_changed_is_a_warning_and_test_message() {
        let e = entry(
            1,
            AuditEvent::TrustDecision {
                host: "192.0.2.10:22".into(),
                fingerprint: "SHA256:new".into(),
                decision: "changed".into(),
                expected: Some("SHA256:old".into()),
            },
        );
        let got = format_entry(&e, 4, "-", 1);
        assert!(got.starts_with("<36>1 2026-11-04T10:20:30.123456Z - mooring 1 trust_decision [mooring@32473 seq=\"1\" hash=\""), "{got}");
        let at = OffsetDateTime::from_unix_timestamp(0).expect("epoch");
        assert_eq!(
            format_test(1, "h", 9, at),
            "<13>1 1970-01-01T00:00:00.000000Z h mooring 9 test [mooring@32473 seq=\"0\" hash=\"-\"] {\"event\":\"syslog_test\"}"
        );
    }

    #[test]
    fn hash_is_the_next_prev() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut log = crate::AuditLog::open(dir.path().join("a.jsonl")).expect("open");
        let first = log.record(AuditEvent::VaultCreated).expect("1");
        let second = log.record(AuditEvent::VaultUnlocked).expect("2");
        let line = format_entry(&first, 1, "h", 1);
        assert!(line.contains(&format!("hash=\"{}\"", second.prev)), "{line}");
    }

    #[test]
    fn hostile_fields_stay_on_one_line_and_secrets_are_redacted() {
        let nasty = "a\r\nb\0c\u{1b}[31m] \"q\" \\ \u{202e}password=hunter2 Bearer abc.def";
        let e = entry(
            3,
            AuditEvent::CredentialPrompted { connection: nasty.into(), username: nasty.into() },
        );
        let got = format_entry(&e, 1, "evil host\nname]", 1);
        assert!(!got.contains('\n') && !got.contains('\r') && !got.contains('\0'), "{got:?}");
        assert!(!got.contains('\u{1b}'), "control chars escaped by JSON");
        assert!(!got.contains("hunter2") && !got.contains("abc.def"), "{got}");
        assert!(got.contains(" evilhostname] mooring "), "hostname reduced to PRINTUSASCII");
        // the structured-data element is intact and closes before MSG
        let sd = format!("[mooring@32473 seq=\"3\" hash=\"{}\" redacted=\"1\"] {{", e.digest());
        assert!(got.contains(&sd), "{got}");
    }

    #[test]
    fn oversized_entries_are_capped_on_a_char_boundary() {
        let big = "é".repeat(MAX_MESSAGE);
        let e = entry(1, AuditEvent::CredentialPrompted { connection: big.clone(), username: big });
        let got = format_entry(&e, 1, &"h".repeat(1000), 1);
        assert!(got.len() <= MAX_MESSAGE);
        assert!(got.contains(&format!(" {} mooring", "h".repeat(255))), "hostname capped");
        assert!(got.contains(&format!("hash=\"{}\" trunc=\"1\"] ", e.digest())), "{}", &got[..400]);
        assert!(!got.contains("redacted="), "nothing was redacted");
    }

    #[test]
    fn redaction_and_truncation_are_flagged_and_clean_lines_are_not() {
        let clean = format_entry(&entry(1, AuditEvent::VaultCreated), 1, "h", 1);
        assert!(!clean.contains("trunc=") && !clean.contains("redacted="), "{clean}");
        let e = entry(
            2,
            AuditEvent::CredentialPrompted {
                connection: "password=hunter2".into(),
                username: "u".into(),
            },
        );
        let got = format_entry(&e, 1, "h", 1);
        assert!(got.contains(&format!("hash=\"{}\" redacted=\"1\"] ", e.digest())), "{got}");
        assert!(!got.contains("hunter2"));
        let both = entry(
            3,
            AuditEvent::CredentialPrompted {
                connection: format!("password=hunter2 {}", "x".repeat(MAX_MESSAGE)),
                username: "u".into(),
            },
        );
        let got = format_entry(&both, 1, "h", 1);
        assert!(got.contains(" trunc=\"1\" redacted=\"1\"] "), "{}", &got[..300]);
    }

    #[test]
    fn header_and_sd_helpers() {
        assert_eq!(header_field("", 5), "-");
        assert_eq!(header_field(" \t\u{7f}é", 5), "-");
        assert_eq!(header_field("abcdefgh", 3), "abc");
        assert_eq!(sd_escape(r#"a"b\c]d"#), r#"a\"b\\c\]d"#);
        let e = entry(1, AuditEvent::VaultCreated);
        assert!(format_entry(&e, 200, "h", 1).starts_with("<189>"), "facility clamped to 23");
    }
}
