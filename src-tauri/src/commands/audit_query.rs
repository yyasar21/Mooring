//! Filtered audit reads shared by `audit_tail` and `audit_export` (A5 Harbor W3 L4).
//!
//! * [`AuditFilterInput`] is the IPC shape; [`AuditFilter::compile`] validates it (≤ 32 known
//!   event names, a connection id, a `since <= until` window in Unix milliseconds, ≤ 128
//!   characters of free text).
//! * [`Redacted`] is what leaves the process: every detail value runs through
//!   [`mooring_audit::redact`] as a rendered `key=value` line (so a secret-named key loses its
//!   value as well), and the free-text filter matches those rendered, redacted lines only.
//! * [`scan_page`] bounds the cost of one `audit_tail` call: at most [`SCAN_CAP`] candidate
//!   rows (`seq < before`) are parsed and tested, newest first; `scannedTo` tells the UI where
//!   to continue.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{IpcError, IpcResult};

/// Most candidate rows one filtered `audit_tail` call parses and tests.
pub const SCAN_CAP: usize = 50_000;
/// Most event names in one filter.
pub const MAX_FILTER_EVENTS: usize = 32;
/// Longest free-text filter, in characters.
pub const MAX_FILTER_TEXT: usize = 128;
/// Longest connection id accepted by the filter.
const MAX_CONNECTION_ID: usize = 128;
/// Longest line read from the log; longer lines are skipped (the file is ours, but bounded).
pub const MAX_LINE_BYTES: usize = 64 * 1024;
/// Fields of an entry that are not details.
const ENVELOPE: [&str; 4] = ["seq", "at", "prev", "event"];

/// `filter` of `audit_tail` / `audit_export`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditFilterInput {
    /// Event wire names (any of).
    #[serde(default)]
    pub events: Option<Vec<String>>,
    /// Connection id: the entry's `connection` detail.
    #[serde(default)]
    pub connection: Option<String>,
    /// Unix milliseconds, inclusive.
    #[serde(default)]
    pub since: Option<u64>,
    /// Unix milliseconds, exclusive.
    #[serde(default)]
    pub until: Option<u64>,
    /// Case-insensitive substring of the redacted rendered details.
    #[serde(default)]
    pub text: Option<String>,
}

fn bad(reason: &str) -> IpcError {
    IpcError::invalid("filter", reason)
}

/// A validated filter.
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    events: Option<BTreeSet<String>>,
    connection: Option<String>,
    since: Option<i128>,
    until: Option<i128>,
    text: Option<String>,
}

impl AuditFilter {
    /// Validate the IPC input. Empty lists and blank text mean "no constraint".
    pub fn compile(input: Option<&AuditFilterInput>) -> IpcResult<Self> {
        let Some(input) = input else { return Ok(Self::default()) };
        let events = match input.events.as_deref() {
            None | Some([]) => None,
            Some(list) if list.len() > MAX_FILTER_EVENTS => {
                return Err(bad("too many event names"));
            }
            Some(list) => {
                if !list.iter().all(|n| mooring_audit::is_known_event(n)) {
                    return Err(bad("unknown event name"));
                }
                Some(list.iter().cloned().collect())
            }
        };
        let connection = match input.connection.as_deref() {
            None | Some("") => None,
            Some(c) if c.len() > MAX_CONNECTION_ID || c.chars().any(char::is_control) => {
                return Err(bad("connection id"));
            }
            Some(c) => Some(c.to_owned()),
        };
        if let (Some(s), Some(u)) = (input.since, input.until) {
            if s > u {
                return Err(bad("since is after until"));
            }
        }
        let text = match input.text.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(t) if t.chars().count() > MAX_FILTER_TEXT => return Err(bad("text too long")),
            Some(t) if t.chars().any(char::is_control) => return Err(bad("text")),
            Some(t) => Some(t.to_lowercase()),
        };
        Ok(Self {
            events,
            connection,
            since: input.since.map(i128::from),
            until: input.until.map(i128::from),
            text,
        })
    }

    /// Whether the filter constrains anything.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_none()
            && self.connection.is_none()
            && self.since.is_none()
            && self.until.is_none()
            && self.text.is_none()
    }

    /// Whether `e` passes.
    #[must_use]
    pub fn matches(&self, e: &Redacted) -> bool {
        if self.events.as_ref().is_some_and(|set| !set.contains(&e.event)) {
            return false;
        }
        if let Some(c) = &self.connection {
            if e.details.get("connection").and_then(Value::as_str) != Some(c.as_str()) {
                return false;
            }
        }
        if self.since.is_some_and(|s| e.at_ms < s) || self.until.is_some_and(|u| e.at_ms >= u) {
            return false;
        }
        match &self.text {
            Some(t) => e.rendered_details().iter().any(|l| l.to_lowercase().contains(t.as_str())),
            None => true,
        }
    }
}

/// An entry as it leaves the process (`audit_tail`, `audit_export`): the envelope, and the
/// details with every value redacted. Serialises flattened, like `AuditEntry`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Redacted {
    /// Sequence number.
    pub seq: u64,
    /// RFC 3339 UTC timestamp, as stored.
    pub at: String,
    /// Hash of the previous stored entry.
    pub prev: String,
    /// Event wire name.
    pub event: String,
    /// Redacted details (no `null`s dropped: the shape of the stored entry).
    #[serde(flatten)]
    pub details: Map<String, Value>,
    #[serde(skip)]
    at_ms: i128,
}

/// The display text of a detail value: strings as they are, everything else as JSON.
fn value_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Redact one detail: render `key=value`, scrub it, and take the value back. A changed value
/// becomes a string; an unchanged one keeps its JSON type.
fn redact_value(key: &str, v: Value) -> Value {
    if v.is_null() {
        return v;
    }
    let text = value_text(&v);
    let scrubbed = mooring_audit::redact(&format!("{key}={text}"));
    match scrubbed.strip_prefix(key).and_then(|r| r.strip_prefix('=')) {
        Some(r) if r == text => v,
        Some(r) => Value::String(r.to_owned()),
        None => Value::String("[REDACTED]".to_owned()),
    }
}

impl Redacted {
    /// Parse one stored line. `None` for anything that is not a well-formed `AuditEntry`.
    pub fn parse(line: &str) -> Option<Self> {
        // Typed parse first: the same acceptance as `audit_tail` always had.
        let entry: mooring_audit::AuditEntry = serde_json::from_str(line).ok()?;
        let at_ms = entry.at.unix_timestamp_nanos() / 1_000_000;
        let Value::Object(mut map) = serde_json::to_value(&entry).ok()? else { return None };
        let at = map.remove("at").as_ref().and_then(Value::as_str)?.to_owned();
        let event = map.remove("event").as_ref().and_then(Value::as_str)?.to_owned();
        for k in ENVELOPE {
            map.remove(k);
        }
        let details = map
            .into_iter()
            .map(|(k, v)| {
                let v = redact_value(&k, v);
                (k, v)
            })
            .collect();
        Some(Self { seq: entry.seq, at, prev: entry.prev, event, details, at_ms })
    }

    /// `key=value` per non-null detail: what the free-text filter searches and what the CSV
    /// `details` column holds. The values were redacted as exactly these lines in
    /// [`Self::parse`] (`redact` is not idempotent on its own marker, so it is not run twice).
    #[must_use]
    pub fn rendered_details(&self) -> Vec<String> {
        self.details
            .iter()
            .filter(|(_, v)| !v.is_null())
            .map(|(k, v)| format!("{k}={}", value_text(v)))
            .collect()
    }
}

/// The `seq` of a stored line without a full parse (the canonical bytes start with
/// `{"seq":N,`); other shapes fall back to a minimal serde parse.
fn line_seq(line: &str) -> Option<u64> {
    #[derive(Deserialize)]
    struct SeqOnly {
        seq: u64,
    }
    if let Some(rest) = line.strip_prefix("{\"seq\":") {
        let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        if end > 0 && rest[end..].starts_with(',') {
            return rest[..end].parse().ok();
        }
    }
    serde_json::from_str::<SeqOnly>(line).ok().map(|s| s.seq)
}

/// Stream the usable lines of `file` with their seq (oversized and blank lines skipped).
fn for_each_line(
    path: &Path,
    mut f: impl FnMut(u64, &str),
) -> Result<bool, std::io::Error> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.len() > MAX_LINE_BYTES || line.trim().is_empty() {
            continue;
        }
        if let Some(seq) = line_seq(&line) {
            f(seq, &line);
        }
    }
    Ok(true)
}

/// One page of a filtered tail.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TailPage {
    /// Matches, newest first.
    pub entries: Vec<Redacted>,
    /// Pass as `before` to continue: the oldest returned seq when the page is full, otherwise
    /// the oldest seq scanned. `null` when nothing was scanned.
    pub scanned_to: Option<u64>,
    /// No older candidate rows remain: the filter has been applied to the whole log.
    pub done: bool,
}

/// Newest-first page of entries with `seq < before` passing `filter`, at most `limit` matches,
/// testing at most `cap` candidate rows (the newest ones). Two passes over the file: a cheap
/// one that counts candidates, then a full parse of the newest `cap` only. The caller holds
/// the audit mutex.
pub fn scan_page(
    path: &Path,
    filter: &AuditFilter,
    limit: usize,
    before: Option<u64>,
    cap: usize,
) -> Result<TailPage, std::io::Error> {
    let is_candidate = |seq: u64| before.is_none_or(|b| seq < b);
    let mut total = 0_usize;
    if !for_each_line(path, |seq, _| total += usize::from(is_candidate(seq)))? {
        return Ok(TailPage { entries: Vec::new(), scanned_to: None, done: true });
    }
    let skip = total.saturating_sub(cap);
    let mut index = 0_usize;
    let mut oldest_scanned = None;
    let mut window = std::collections::VecDeque::with_capacity(limit.min(1024));
    for_each_line(path, |seq, line| {
        if !is_candidate(seq) {
            return;
        }
        index += 1;
        if index <= skip {
            return;
        }
        oldest_scanned = Some(oldest_scanned.map_or(seq, |o: u64| o.min(seq)));
        let Some(entry) = Redacted::parse(line) else { return };
        if !filter.matches(&entry) {
            return;
        }
        if window.len() == limit {
            window.pop_front();
        }
        window.push_back(entry);
    })?;
    let full = window.len() == limit;
    let entries: Vec<Redacted> = window.into_iter().rev().collect();
    let scanned_to = if full { entries.last().map(|e| e.seq) } else { oldest_scanned };
    Ok(TailPage { entries, scanned_to, done: skip == 0 && !full })
}

/// Every entry passing `filter`, oldest first, handed to `sink` (export; no scan cap: the
/// export streams the whole log). The caller holds the audit mutex. A missing log yields none.
pub fn for_each_match(
    path: &Path,
    filter: &AuditFilter,
    mut sink: impl FnMut(&Redacted) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let mut failed = None;
    for_each_line(path, |_, line| {
        if failed.is_some() {
            return;
        }
        if let Some(e) = Redacted::parse(line).filter(|e| filter.matches(e)) {
            if let Err(err) = sink(&e) {
                failed = Some(err);
            }
        }
    })?;
    failed.map_or(Ok(()), Err)
}

#[cfg(test)]
#[path = "audit_query_tests.rs"]
mod tests;
