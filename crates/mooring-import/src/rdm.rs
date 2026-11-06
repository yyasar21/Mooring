//! Remote Desktop Manager `.rdm` XML export (ADR-0019 §2): `ArrayOfConnection` →
//! `Connection` entries. `Group` holds the folder path `A\B`; `ConnectionType` picks the
//! protocol (`RDP*`, `SSHShell`, `VNC`, `WebBrowser`; `Group` entries are folders). Host, port and
//! username are read from the known per-type sub-elements. `SafePassword` is encrypted and
//! never decrypted (warning); nothing secret is imported.

use mooring_core::Protocol;

use crate::error::{ImportError, Result};
use crate::plan::{NewConnection, PlanBuilder, SkipReason, WarningCode};
use crate::xml::{self, Node};
use crate::{creds, text, ImportFormat, ImportOptions, ImportSource, Importer};

const FORMAT: &str = "rdm";

/// The importer.
#[derive(Debug, Clone, Copy, Default)]
pub struct Rdm;

impl Importer for Rdm {
    fn format(&self) -> ImportFormat {
        ImportFormat::Rdm
    }

    fn sniff(&self, head: &[u8]) -> bool {
        let s = String::from_utf8_lossy(head);
        s.contains("<ArrayOfConnection")
            || (s.contains("<Connection>") && s.contains("<ConnectionType>"))
    }

    fn parse(&self, src: ImportSource<'_>, opts: &ImportOptions) -> Result<crate::ImportPlan> {
        let ImportSource::File { bytes, .. } = src else {
            return Err(ImportError::format(FORMAT, "expected one file", 0));
        };
        let text = text::decode(bytes, FORMAT)?;
        let root = xml::parse(&text, &opts.limits, FORMAT)?;
        if !matches!(root.name.as_str(), "ArrayOfConnection" | "Connections") {
            return Err(ImportError::format(FORMAT, "root is not ArrayOfConnection", 0));
        }
        let mut b = PlanBuilder::new(&opts.limits);
        for (i, node) in root.children_named("Connection").enumerate() {
            let src = format!("Connection #{}", i + 1);
            entry(node, &mut b, &src)?;
        }
        Ok(b.finish())
    }
}

/// What a `ConnectionType` maps to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Folder,
    Connection(Protocol),
    Unsupported,
}

fn kind_of(kind: &str) -> Kind {
    let k = kind.to_ascii_lowercase();
    if k == "group" || k == "folder" {
        return Kind::Folder;
    }
    if k.starts_with("rdp") {
        Kind::Connection(Protocol::Rdp)
    } else if k == "sshshell" || k == "ssh" {
        Kind::Connection(Protocol::Ssh)
    } else if k == "vnc" {
        Kind::Connection(Protocol::Vnc)
    } else if k.starts_with("web") {
        Kind::Connection(Protocol::Web)
    } else {
        Kind::Unsupported
    }
}

fn entry(node: &Node, b: &mut PlanBuilder, src: &str) -> Result<()> {
    let kind = node.child_text("ConnectionType").unwrap_or_default();
    let group = node.child_text("Group").unwrap_or_default();
    let name = node.child_text("Name").unwrap_or_default();
    let protocol = match kind_of(kind) {
        Kind::Connection(p) => p,
        Kind::Unsupported => {
            b.skip(src, SkipReason::Unsupported);
            return Ok(());
        }
        Kind::Folder => {
            // A group entry names its own full path in `Group`, or `Name` under `Group`.
            let mut segs: Vec<&str> = group.split('\\').filter(|s| !s.trim().is_empty()).collect();
            if segs.last() != Some(&name) {
                segs.push(name);
            }
            b.folder_path(segs, src)?;
            return Ok(());
        }
    };
    let folder = b.folder_path(group.split('\\'), src)?;
    let host = match protocol {
        Protocol::Web => node.first_text(&["WebBrowserUrl", "Url", "URL"]).map(str::to_owned),
        _ => node
            .first_text(&["Url", "Host", "HostName"])
            .or_else(|| node.path_text(&["Terminal", "Host"]))
            .or_else(|| node.path_text(&["VNC", "Host"]))
            .or_else(|| node.path_text(&["RDP", "Host"]))
            .map(str::to_owned),
    };
    let port = match protocol {
        Protocol::Web => None,
        _ => b.port(
            node.path_text(&["Terminal", "HostPort"])
                .or_else(|| node.path_text(&["VNC", "Port"]))
                .or_else(|| node.path_text(&["RDP", "Port"]))
                .or_else(|| node.first_text(&["Port", "HostPort"])),
            src,
        ),
    };
    let user = node
        .first_text(&["UserName", "Username"])
        .or_else(|| node.path_text(&["Terminal", "Username"]))
        .or_else(|| node.path_text(&["RDP", "UserName"]));
    let domain = node.first_text(&["Domain"]).or_else(|| node.path_text(&["RDP", "Domain"]));
    if has_descendant(node, "SafePassword") {
        b.warn(WarningCode::SecretEncrypted, src);
    }
    let credential = match (user, protocol) {
        (Some(u), Protocol::Rdp | Protocol::Ssh | Protocol::Vnc) => {
            b.credential(creds::prompt(u, domain), src)?
        }
        _ => None,
    };
    b.connection(
        NewConnection {
            name: name.to_owned(),
            protocol: Some(protocol),
            host: host.unwrap_or_default(),
            port,
            user: user.map(str::to_owned),
            domain: domain.map(str::to_owned),
            folder,
            credential,
            tags: Vec::new(),
        },
        src,
    )?;
    Ok(())
}

fn has_descendant(node: &Node, name: &str) -> bool {
    node.children.iter().any(|c| (c.name == name && !c.text.is_empty()) || has_descendant(c, name))
}

#[cfg(test)]
#[path = "rdm_tests.rs"]
mod tests;
