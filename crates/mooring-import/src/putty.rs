//! PuTTY sessions (ADR-0019 §2): a `.reg` export (UTF-16LE BOM or UTF-8) with
//! `[HKEY_…\PuTTY\Sessions\<%-encoded name>]` sections, or the files of `~/.putty/sessions/`
//! (`Key=Value` lines, %-encoded file names). `Protocol` must be `ssh`; raw, telnet, rlogin,
//! serial, supdup and "Default Settings" are skipped. `HostName` may be `user@host`;
//! `UserName` wins over it. `PublicKeyFile` (PPK) → warning, never read. PuTTY stores no
//! passwords, so nothing secret exists here.

use std::collections::BTreeMap;

use mooring_core::Protocol;

use crate::error::{ImportError, Result};
use crate::plan::{NewConnection, PlanBuilder, SkipReason, WarningCode};
use crate::{creds, text, ImportFormat, ImportOptions, ImportSource, Importer};

const FORMAT: &str = "putty";
const REG_HEADER: &str = "Windows Registry Editor Version";
const SESSIONS_PATH: &str = "\\PuTTY\\Sessions\\";

/// The importer.
#[derive(Debug, Clone, Copy, Default)]
pub struct Putty;

impl Importer for Putty {
    fn format(&self) -> ImportFormat {
        ImportFormat::Putty
    }

    fn sniff(&self, head: &[u8]) -> bool {
        let s = match text::decode(head, FORMAT) {
            Ok(s) => s.into_owned(),
            Err(_) => String::from_utf8_lossy(head).into_owned(),
        };
        s.trim_start().starts_with(REG_HEADER) || s.contains("REGEDIT4")
    }

    fn parse(&self, src: ImportSource<'_>, opts: &ImportOptions) -> Result<crate::ImportPlan> {
        let mut b = PlanBuilder::new(&opts.limits);
        match src {
            ImportSource::File { bytes, .. } => {
                let text = text::decode(bytes, FORMAT)?;
                for (n, (name, values)) in reg_sessions(&text, &opts.limits)?.into_iter().enumerate() {
                    session(&name, &values, &mut b, &format!("session #{}", n + 1))?;
                }
            }
            ImportSource::Dir(files) => {
                for (n, (file, bytes)) in files.iter().enumerate() {
                    let src = format!("session #{}", n + 1);
                    let Ok(text) = text::decode(bytes, FORMAT) else {
                        b.skip(src, SkipReason::Invalid);
                        continue;
                    };
                    let Some(name) = percent_decode(file) else {
                        b.skip(src, SkipReason::Invalid);
                        continue;
                    };
                    let mut values = BTreeMap::new();
                    for line in text::lines(&text, opts.limits.max_text) {
                        let (_, line) = line?;
                        if let Some((k, v)) = line.split_once('=') {
                            values.insert(k.trim().to_owned(), v.to_owned());
                        }
                    }
                    session(&name, &values, &mut b, &src)?;
                }
            }
        }
        Ok(b.finish())
    }
}

/// Sessions of a `.reg` text in file order: `(decoded name, values)`.
fn reg_sessions(text: &str, limits: &crate::Limits) -> Result<Vec<(String, BTreeMap<String, String>)>> {
    let mut out: Vec<(String, BTreeMap<String, String>)> = Vec::new();
    let mut current: Option<usize> = None;
    let mut seen_header = false;
    for line in text::lines(text, limits.max_text) {
        let (no, line) = line?;
        let line = line.trim();
        if no == 1 && !(line.starts_with(REG_HEADER) || line == "REGEDIT4") {
            return Err(ImportError::format(FORMAT, "not a registry export", 1));
        }
        seen_header = true;
        if let Some(path) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            current = match path.find(SESSIONS_PATH) {
                Some(i) => {
                    let raw = &path[i + SESSIONS_PATH.len()..];
                    let name = percent_decode(raw).unwrap_or_default();
                    out.push((name, BTreeMap::new()));
                    Some(out.len() - 1)
                }
                None => None,
            };
            continue;
        }
        let (Some(i), Some(rest)) = (current, line.strip_prefix('"')) else {
            continue;
        };
        let Some((key, value)) = rest.split_once("\"=") else {
            continue;
        };
        let value = if let Some(s) = value.strip_prefix('"') {
            unescape_reg(s.strip_suffix('"').unwrap_or(s))
        } else if let Some(d) = value.strip_prefix("dword:") {
            u32::from_str_radix(d.trim(), 16).map(|n| n.to_string()).unwrap_or_default()
        } else {
            continue; // hex:, binary and other types are not session fields we read
        };
        out[i].1.insert(key.to_owned(), value);
    }
    if !seen_header {
        return Err(ImportError::format(FORMAT, "empty file", 0));
    }
    Ok(out)
}

fn unescape_reg(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(n) => out.push(n),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// PuTTY's `%XX` name encoding; `None` when the result is not UTF-8.
fn percent_decode(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok()?;
            if let Ok(v) = u8::from_str_radix(hex, 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).ok()
}

fn session(name: &str, v: &BTreeMap<String, String>, b: &mut PlanBuilder, src: &str) -> Result<()> {
    if name.is_empty() || name == "Default Settings" {
        b.skip(src, SkipReason::Unsupported);
        return Ok(());
    }
    let protocol = v.get("Protocol").map(|p| p.trim().to_ascii_lowercase()).unwrap_or_else(|| "ssh".into());
    if protocol != "ssh" {
        b.skip(src, SkipReason::Unsupported);
        return Ok(());
    }
    let raw_host = v.get("HostName").map(|h| h.trim()).unwrap_or_default();
    let (host_user, host) = match raw_host.rsplit_once('@') {
        Some((u, h)) if !u.is_empty() => (Some(u), h),
        _ => (None, raw_host),
    };
    let user = v.get("UserName").map(|u| u.trim()).filter(|u| !u.is_empty()).or(host_user);
    if v.get("PublicKeyFile").is_some_and(|k| !k.trim().is_empty()) {
        b.warn(WarningCode::PpkKey, src);
    }
    if mooring_core::validate_host(host).is_err() {
        b.skip(src, SkipReason::Invalid);
        return Ok(());
    }
    let port = b.port(v.get("PortNumber").map(String::as_str), src);
    let credential = match user {
        Some(u) => b.credential(creds::prompt(u, None), src)?,
        None => None,
    };
    b.connection(
        NewConnection {
            name: name.to_owned(),
            protocol: Some(Protocol::Ssh),
            host: host.to_owned(),
            port,
            user: user.map(str::to_owned),
            domain: None,
            folder: None,
            credential,
            tags: Vec::new(),
        },
        src,
    )?;
    Ok(())
}

#[cfg(test)]
#[path = "putty_tests.rs"]
mod tests;
