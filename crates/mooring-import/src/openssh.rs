//! OpenSSH `~/.ssh/config` (ADR-0019 §2): every literal `Host` alias becomes an SSH
//! connection from `HostName` (default: the alias), `User`, `Port` and `IdentityFile`
//! (→ an `ssh_agent` credential per `(user, key)`; the key file is only named here, the
//! §3 opt-in read happens in `src-tauri`). Wildcard / negated patterns and `Match` blocks are
//! warnings (a `Host *` block still supplies defaults), `Include` is not followed, `%` tokens
//! stay literal, `ProxyJump` becomes the tag `jump:<value>` plus a warning (no jump-host
//! model yet, Left open).

use crate::error::Result;
use crate::plan::{NewConnection, PlanBuilder, SkipReason, WarningCode};
use crate::{creds, text, ImportFormat, ImportOptions, ImportSource, Importer};

const FORMAT: &str = "openssh";

/// The importer.
#[derive(Debug, Clone, Copy, Default)]
pub struct Openssh;

/// Options collected for one `Host` block (or the global / `Host *` defaults).
#[derive(Debug, Clone, Default)]
struct Block {
    hostname: Option<String>,
    user: Option<String>,
    port: Option<String>,
    identity: Option<String>,
    proxy_jump: Option<String>,
}

impl Block {
    fn set(&mut self, key: &str, value: &str) {
        let slot = match key.to_ascii_lowercase().as_str() {
            "hostname" => &mut self.hostname,
            "user" => &mut self.user,
            "port" => &mut self.port,
            "identityfile" => &mut self.identity,
            "proxyjump" => &mut self.proxy_jump,
            _ => return,
        };
        // ssh_config: the first obtained value wins.
        if slot.is_none() {
            *slot = Some(value.to_owned());
        }
    }

    fn or(&self, fallback: &Block) -> Block {
        Block {
            hostname: self.hostname.clone().or_else(|| fallback.hostname.clone()),
            user: self.user.clone().or_else(|| fallback.user.clone()),
            port: self.port.clone().or_else(|| fallback.port.clone()),
            identity: self.identity.clone().or_else(|| fallback.identity.clone()),
            proxy_jump: self.proxy_jump.clone().or_else(|| fallback.proxy_jump.clone()),
        }
    }
}

/// One `Host` line's literal aliases and its options.
#[derive(Debug, Clone, Default)]
struct HostBlock {
    line: usize,
    aliases: Vec<String>,
    patterns: usize,
    /// Exactly `Host *`: its options are defaults for every host.
    is_star: bool,
    block: Block,
}

fn is_pattern(alias: &str) -> bool {
    alias.contains(['*', '?', '!'])
}

/// `Key Value`, `Key=Value`, quoted values, `#` comments.
fn split_line(line: &str) -> Option<(&str, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (key, rest) = line.split_once(|c: char| c.is_whitespace() || c == '=')?;
    let rest = rest.trim_start_matches(|c: char| c.is_whitespace() || c == '=').trim();
    let value = rest.strip_prefix('"').and_then(|r| r.strip_suffix('"')).unwrap_or(rest);
    Some((key, value.to_owned()))
}

impl Importer for Openssh {
    fn format(&self) -> ImportFormat {
        ImportFormat::Openssh
    }

    fn sniff(&self, head: &[u8]) -> bool {
        let s = String::from_utf8_lossy(head);
        s.lines().any(|l| {
            let l = l.trim_start();
            l.len() > 5 && l[..5].eq_ignore_ascii_case("host ")
                || l.len() > 9 && l[..9].eq_ignore_ascii_case("hostname ")
        })
    }

    fn parse(&self, src: ImportSource<'_>, opts: &ImportOptions) -> Result<crate::ImportPlan> {
        let mut b = PlanBuilder::new(&opts.limits);
        let ImportSource::File { bytes, .. } = src else {
            return Err(crate::ImportError::format(FORMAT, "expected one file", 0));
        };
        let text = text::decode(bytes, FORMAT)?;
        let mut global = Block::default();
        let mut star = Block::default();
        let mut hosts: Vec<HostBlock> = Vec::new();
        // `None` = global section, `Some(None)` = inside a Match block (ignored).
        let mut current: Option<Option<usize>> = None;
        for line in text::lines(&text, opts.limits.max_text) {
            let (no, line) = line?;
            let Some((key, value)) = split_line(line) else { continue };
            match key.to_ascii_lowercase().as_str() {
                "host" => {
                    let mut hb = HostBlock {
                        line: no,
                        is_star: value.trim() == "*",
                        ..HostBlock::default()
                    };
                    for alias in value.split_whitespace() {
                        if is_pattern(alias) {
                            hb.patterns += 1;
                        } else {
                            hb.aliases.push(alias.to_owned());
                        }
                    }
                    if hb.patterns > 0 {
                        b.warn(WarningCode::HostPattern, format!("line {no}"));
                    }
                    hosts.push(hb);
                    current = Some(Some(hosts.len() - 1));
                }
                "match" => {
                    b.warn(WarningCode::MatchBlock, format!("line {no}"));
                    current = Some(None);
                }
                "include" => b.warn(WarningCode::IncludeIgnored, format!("line {no}")),
                _ => match current {
                    None => global.set(key, &value),
                    Some(None) => {}
                    Some(Some(i)) => hosts[i].block.set(key, &value),
                },
            }
        }
        for hb in &hosts {
            if hb.is_star {
                // `Host *` supplies defaults after the explicit blocks (first one wins).
                star = star.or(&hb.block);
            }
        }
        for hb in &hosts {
            let src = format!("line {}", hb.line);
            if hb.aliases.is_empty() {
                if hb.patterns > 0 {
                    b.skip(&src, SkipReason::Unsupported);
                }
                continue;
            }
            // First obtained value wins: the global section, then the block, then `Host *`.
            let o = global.or(&hb.block).or(&star);
            for alias in &hb.aliases {
                emit(alias, &o, &mut b, &src)?;
            }
        }
        Ok(b.finish())
    }
}

fn emit(alias: &str, o: &Block, b: &mut PlanBuilder, src: &str) -> Result<()> {
    let host = o.hostname.as_deref().unwrap_or(alias);
    if mooring_core::validate_host(host).is_err() {
        b.skip(src, SkipReason::Invalid);
        return Ok(());
    }
    let port = b.port(o.port.as_deref(), src);
    let user = o.user.as_deref().map(str::trim).filter(|u| !u.is_empty());
    let credential = match (user, o.identity.as_deref()) {
        (Some(u), Some(key)) => b.credential(creds::ssh_agent(u, Some(key)), src)?,
        (Some(u), None) => b.credential(creds::prompt(u, None), src)?,
        (None, _) => None,
    };
    let mut tags = Vec::new();
    if let Some(jump) = o.proxy_jump.as_deref().filter(|j| !j.trim().is_empty()) {
        b.warn(WarningCode::ProxyJump, src);
        tags.push(format!("jump:{}", jump.trim()));
    }
    b.connection(
        NewConnection {
            name: alias.to_owned(),
            protocol: Some(mooring_core::Protocol::Ssh),
            host: host.to_owned(),
            port,
            user: user.map(str::to_owned),
            domain: None,
            folder: None,
            credential,
            tags,
        },
        src,
    )?;
    Ok(())
}

#[cfg(test)]
#[path = "openssh_tests.rs"]
mod tests;
