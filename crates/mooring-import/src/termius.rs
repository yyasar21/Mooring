//! Termius CSV and JSON exports (ADR-0019 §2). Both are plaintext formats: a `password`
//! column / field becomes a `user_password` secret and a private key an `ssh_key` secret
//! **only** with `include_plaintext_secrets` (owner decision 16); otherwise the username
//! becomes a `prompt` credential and the plan warns `password_dropped`. Groups (`A/B`) →
//! folders; protocol `ssh` only (telnet, mosh, serial → skipped).
//!
//! CSV columns are matched by header name (case-insensitive aliases, any order): `label` /
//! `name`, `hostname/ip` / `hostname` / `address` / `host`, `port`, `username` / `user`,
//! `password`, `group` / `groups`, `tags`, `protocol`, `key` / `private_key` / `keys`.

use serde_json::Value;
use zeroize::Zeroizing;

use crate::csv;
use crate::error::{ImportError, Result};
use crate::plan::{NewConnection, PlanBuilder, SkipReason, WarningCode};
use crate::{creds, text, ImportFormat, ImportOptions, ImportSource, Importer};

const FORMAT_CSV: &str = "termius_csv";
const FORMAT_JSON: &str = "termius_json";

/// The importer.
#[derive(Debug, Clone, Copy, Default)]
pub struct Termius;

impl Importer for Termius {
    fn format(&self) -> ImportFormat {
        ImportFormat::Termius
    }

    fn sniff(&self, head: &[u8]) -> bool {
        let s = String::from_utf8_lossy(head);
        let t = s.trim_start_matches('\u{FEFF}').trim_start();
        if t.starts_with('{') || t.starts_with('[') {
            return t.contains("\"hosts\"") || t.contains("\"address\"");
        }
        let header = t.lines().next().unwrap_or_default().to_ascii_lowercase();
        header.contains(',') && (header.contains("hostname") || header.contains("address")) && header.contains("label")
    }

    fn parse(&self, src: ImportSource<'_>, opts: &ImportOptions) -> Result<crate::ImportPlan> {
        let ImportSource::File { bytes, name } = src else {
            return Err(ImportError::format(FORMAT_CSV, "expected one file", 0));
        };
        let json = name.to_ascii_lowercase().ends_with(".json") || looks_json(bytes);
        if json {
            parse_json(bytes, opts)
        } else {
            parse_csv(bytes, opts)
        }
    }
}

fn looks_json(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(64)];
    let s = String::from_utf8_lossy(head);
    let t = s.trim_start_matches('\u{FEFF}').trim_start();
    t.starts_with('{') || t.starts_with('[')
}

/// One host as either format reads it; strings are owned and bounded by `max_text`.
#[derive(Debug, Default)]
struct Host {
    label: String,
    address: String,
    port: Option<String>,
    username: Option<String>,
    password: Option<Zeroizing<String>>,
    key: Option<Zeroizing<String>>,
    groups: Vec<String>,
    tags: Vec<String>,
    protocol: Option<String>,
}

fn emit(h: Host, b: &mut PlanBuilder, opts: &ImportOptions, src: &str) -> Result<()> {
    if h.protocol.as_deref().is_some_and(|p| !p.trim().is_empty() && !p.trim().eq_ignore_ascii_case("ssh")) {
        b.skip(src, SkipReason::Unsupported);
        return Ok(());
    }
    if mooring_core::validate_host(&h.address).is_err() {
        // Decided before any credential is created, so a skipped host leaves no orphan.
        b.skip(src, SkipReason::Invalid);
        return Ok(());
    }
    let folder = b.folder_path(h.groups.iter().map(String::as_str), src)?;
    let port = b.port(h.port.as_deref(), src);
    let user = h.username.as_deref().map(str::trim).filter(|u| !u.is_empty());
    let has_password = h.password.as_deref().is_some_and(|p| !p.is_empty());
    let has_key = h.key.as_deref().is_some_and(|k| !k.trim().is_empty());
    let credential = match user {
        Some(u) if has_key && opts.include_plaintext_secrets => {
            let key: &str = h.key.as_deref().map_or("", |k| k.as_str());
            b.credential(creds::ssh_key(u, "Termius key", key.trim().as_bytes()), src)?
        }
        Some(u) if has_password && opts.include_plaintext_secrets => {
            let pw: &str = h.password.as_deref().map_or("", |p| p.as_str());
            b.credential(creds::user_password(u, None, pw.as_bytes()), src)?
        }
        Some(u) => {
            if has_password || has_key {
                b.warn(WarningCode::PasswordDropped, src);
            }
            b.credential(creds::prompt(u, None), src)?
        }
        None => {
            if has_password || has_key {
                b.warn(WarningCode::PasswordDropped, src);
            }
            None
        }
    };
    let name = if h.label.trim().is_empty() { h.address.clone() } else { h.label.clone() };
    b.connection(
        NewConnection {
            name,
            protocol: Some(mooring_core::Protocol::Ssh),
            host: h.address.clone(),
            port,
            user: user.map(str::to_owned),
            domain: None,
            folder,
            credential,
            tags: h.tags.clone(),
        },
        src,
    )?;
    Ok(())
}

fn split_list(raw: &str, seps: &[char]) -> Vec<String> {
    raw.split(seps).map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned).collect()
}

fn column(header: &[String], aliases: &[&str]) -> Option<usize> {
    header.iter().position(|h| {
        let h = h.trim().trim_start_matches('\u{FEFF}').to_ascii_lowercase();
        aliases.contains(&h.as_str())
    })
}

fn parse_csv(bytes: &[u8], opts: &ImportOptions) -> Result<crate::ImportPlan> {
    let text = text::decode(bytes, FORMAT_CSV)?;
    let table = csv::parse(&text, &opts.limits)?;
    let Some((header, rows)) = table.records.split_first() else {
        return Err(ImportError::format(FORMAT_CSV, "no header row", 0));
    };
    let col_label = column(header, &["label", "name"]);
    let col_host = column(header, &["hostname/ip", "hostname", "address", "host", "ip"]);
    let Some(col_host) = col_host else {
        return Err(ImportError::format(FORMAT_CSV, "no hostname column", 1));
    };
    let col_port = column(header, &["port"]);
    let col_user = column(header, &["username", "user"]);
    let col_pass = column(header, &["password", "pass"]);
    let col_group = column(header, &["groups", "group", "folder"]);
    let col_tags = column(header, &["tags", "tag"]);
    let col_proto = column(header, &["protocol", "type"]);
    let col_key = column(header, &["key", "keys", "private_key", "ssh_key"]);
    let mut b = PlanBuilder::new(&opts.limits);
    for (i, row) in rows.iter().enumerate() {
        let src = format!("record {}", i + 2);
        let get = |c: Option<usize>| c.and_then(|c| row.get(c)).map(|s| s.trim()).filter(|s| !s.is_empty());
        let h = Host {
            label: get(col_label).unwrap_or_default().to_owned(),
            address: get(Some(col_host)).unwrap_or_default().to_owned(),
            port: get(col_port).map(str::to_owned),
            username: get(col_user).map(str::to_owned),
            password: get(col_pass).map(|p| Zeroizing::new(p.to_owned())),
            key: get(col_key).map(|k| Zeroizing::new(k.to_owned())),
            groups: get(col_group).map(|g| split_list(g, &['/', '\\'])).unwrap_or_default(),
            tags: get(col_tags).map(|t| split_list(t, &[',', ';'])).unwrap_or_default(),
            protocol: get(col_proto).map(str::to_owned),
        };
        emit(h, &mut b, opts, &src)?;
    }
    Ok(b.finish())
}

fn str_of(v: &Value, keys: &[&str], max: usize) -> Result<Option<String>> {
    for k in keys {
        match v.get(k) {
            Some(Value::String(s)) if !s.trim().is_empty() => {
                if s.len() > max {
                    return Err(ImportError::limits("json string length"));
                }
                return Ok(Some(s.clone()));
            }
            Some(Value::Number(n)) => return Ok(Some(n.to_string())),
            _ => {}
        }
    }
    Ok(None)
}

fn list_of(v: &Value, key: &str, max: usize) -> Result<Vec<String>> {
    match v.get(key) {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(|s| if s.len() > max { Err(ImportError::limits("json string length")) } else { Ok(s.to_owned()) })
            .collect(),
        Some(Value::String(s)) => Ok(split_list(s, &[',', ';', '/'])),
        _ => Ok(Vec::new()),
    }
}

fn parse_json(bytes: &[u8], opts: &ImportOptions) -> Result<crate::ImportPlan> {
    let text = text::decode(bytes, FORMAT_JSON)?;
    let doc: Value = serde_json::from_str(&text)
        .map_err(|e| ImportError::format(FORMAT_JSON, "malformed JSON", e.line() as u64))?;
    let hosts: &[Value] = match &doc {
        Value::Array(a) => a,
        Value::Object(_) => doc.get("hosts").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]),
        _ => return Err(ImportError::format(FORMAT_JSON, "not an object or array", 0)),
    };
    let max = opts.limits.max_text;
    // Group ids → labels (and parents) when the export lists groups separately.
    let groups: Vec<(String, String, Option<String>)> = doc
        .get("groups")
        .and_then(Value::as_array)
        .map(|gs| {
            gs.iter()
                .filter_map(|g| {
                    let id = str_of(g, &["id", "uuid"], max).ok()??;
                    let label = str_of(g, &["label", "name"], max).ok()??;
                    let parent = str_of(g, &["parent_group_id", "parent_id", "parent"], max).ok()?;
                    Some((id, label, parent))
                })
                .collect()
        })
        .unwrap_or_default();
    let mut b = PlanBuilder::new(&opts.limits);
    for (i, h) in hosts.iter().enumerate() {
        let src = format!("hosts[{i}]");
        if !h.is_object() {
            b.skip(&src, SkipReason::Invalid);
            continue;
        }
        let mut path = list_of(h, "groups", max)?;
        if let Some(group) = str_of(h, &["group", "group_id", "parent_group_id"], max)? {
            path = group_path(&groups, &group);
        }
        let key = match h.get("ssh_key").or_else(|| h.get("key")) {
            Some(Value::Object(k)) => str_of(&Value::Object(k.clone()), &["private_key", "privateKey"], max)?,
            Some(Value::String(s)) if s.contains("PRIVATE KEY") => Some(s.clone()),
            _ => None,
        };
        let host = Host {
            label: str_of(h, &["label", "name"], max)?.unwrap_or_default(),
            address: str_of(h, &["address", "hostname", "host"], max)?.unwrap_or_default(),
            port: str_of(h, &["port"], max)?,
            username: str_of(h, &["username", "user"], max)?,
            password: str_of(h, &["password"], max)?.map(Zeroizing::new),
            key: key.map(Zeroizing::new),
            groups: path,
            tags: list_of(h, "tags", max)?,
            protocol: str_of(h, &["protocol", "type"], max)?,
        };
        emit(host, &mut b, opts, &src)?;
    }
    Ok(b.finish())
}

/// Group label path by id (bounded walk), else the value itself as one segment.
fn group_path(groups: &[(String, String, Option<String>)], id: &str) -> Vec<String> {
    let mut path = Vec::new();
    let mut cur = Some(id.to_owned());
    for _ in 0..32 {
        let Some(c) = cur.take() else { break };
        match groups.iter().find(|(gid, _, _)| *gid == c) {
            Some((_, label, parent)) => {
                path.push(label.clone());
                cur.clone_from(parent);
            }
            // A free-form path (`A/B`) rather than an id: stored root-last, reversed below.
            None if path.is_empty() => path.extend(split_list(&c, &['/', '\\']).into_iter().rev()),
            None => {}
        }
    }
    path.reverse();
    path
}

#[cfg(test)]
#[path = "termius_tests.rs"]
mod tests;
