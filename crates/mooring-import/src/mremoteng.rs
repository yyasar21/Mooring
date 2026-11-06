//! mRemoteNG `confCons.xml` (ADR-0019 §2): `Node Type="Container"` → folders,
//! `Type="Connection"` with `Protocol` RDP / SSH2 / VNC / HTTP / HTTPS → connections,
//! `Username` + `Domain` → a `prompt` credential. **Passwords are never imported** (owner
//! decision 17): the `Password` attribute is dropped at parse with a warning;
//! `FullFileEncryption="true"` → `import.encrypted`.

use mooring_core::Protocol;

use crate::error::{ImportError, Result};
use crate::plan::{NewConnection, PlanBuilder, SkipReason, WarningCode};
use crate::xml::{self, Node};
use crate::{creds, text, ImportFormat, ImportOptions, ImportSource, Importer};

const FORMAT: &str = "mremoteng";

/// The importer.
#[derive(Debug, Clone, Copy, Default)]
pub struct Mremoteng;

impl Importer for Mremoteng {
    fn format(&self) -> ImportFormat {
        ImportFormat::Mremoteng
    }

    fn sniff(&self, head: &[u8]) -> bool {
        let s = String::from_utf8_lossy(head);
        s.contains("mrng:Connections") || (s.contains("<Connections") && s.contains("ConfVersion"))
    }

    fn parse(&self, src: ImportSource<'_>, opts: &ImportOptions) -> Result<crate::ImportPlan> {
        let ImportSource::File { bytes, .. } = src else {
            return Err(ImportError::format(FORMAT, "expected one file", 0));
        };
        let text = text::decode(bytes, FORMAT)?;
        let root = xml::parse(&text, &opts.limits, FORMAT)?;
        if root.name != "Connections" {
            return Err(ImportError::format(FORMAT, "root is not Connections", 0));
        }
        if root.attr("FullFileEncryption").is_some_and(|v| v.eq_ignore_ascii_case("true")) {
            return Err(ImportError::Encrypted);
        }
        let mut b = PlanBuilder::new(&opts.limits);
        let mut ordinal = 0usize;
        walk(&root, None, &mut b, &mut ordinal)?;
        Ok(b.finish())
    }
}

fn walk(
    parent: &Node,
    folder: Option<&str>,
    b: &mut PlanBuilder,
    ordinal: &mut usize,
) -> Result<()> {
    for node in parent.children_named("Node") {
        *ordinal += 1;
        let src = format!("Node #{ordinal}");
        let name = node.attr("Name").unwrap_or_default();
        match node.attr("Type").unwrap_or("Connection") {
            "Container" => {
                let key = b.folder(folder, name, &src)?;
                // An invalid folder name drops its subtree into the parent folder.
                let next = key.as_deref().or(folder);
                walk(node, next, b, ordinal)?;
            }
            "Connection" => connection(node, folder, b, &src)?,
            _ => b.skip(src, SkipReason::Unsupported),
        }
    }
    Ok(())
}

fn connection(node: &Node, folder: Option<&str>, b: &mut PlanBuilder, src: &str) -> Result<()> {
    if node.attr("Password").is_some_and(|p| !p.is_empty()) {
        b.warn(WarningCode::PasswordDropped, src);
    }
    let protocol = node.attr("Protocol").unwrap_or_default();
    let host = node.attr("Hostname").unwrap_or_default().trim();
    let port = b.port(node.attr("Port"), src);
    let (protocol, host) = match protocol.to_ascii_uppercase().as_str() {
        "RDP" => (Protocol::Rdp, host.to_owned()),
        "SSH2" => (Protocol::Ssh, host.to_owned()),
        "VNC" => (Protocol::Vnc, host.to_owned()),
        "HTTP" | "HTTPS" => {
            let scheme = protocol.to_ascii_lowercase();
            let url = if host.contains("://") {
                host.to_owned()
            } else {
                match port {
                    Some(p) => format!("{scheme}://{host}:{p}/"),
                    None => format!("{scheme}://{host}/"),
                }
            };
            (Protocol::Web, url)
        }
        _ => {
            b.skip(src, SkipReason::Unsupported);
            return Ok(());
        }
    };
    let user = node.attr("Username").map(str::trim).filter(|u| !u.is_empty());
    let domain = node.attr("Domain").map(str::trim).filter(|d| !d.is_empty());
    let credential = match (user, protocol) {
        (Some(u), Protocol::Rdp | Protocol::Ssh | Protocol::Vnc) => {
            b.credential(creds::prompt(u, domain), src)?
        }
        _ => None,
    };
    let port = if protocol == Protocol::Web { None } else { port };
    b.connection(
        NewConnection {
            name: node.attr("Name").unwrap_or_default().to_owned(),
            protocol: Some(protocol),
            host,
            port,
            user: user.map(str::to_owned),
            domain: domain.map(str::to_owned),
            folder: folder.map(str::to_owned),
            credential,
            tags: Vec::new(),
        },
        src,
    )?;
    Ok(())
}

#[cfg(test)]
#[path = "mremoteng_tests.rs"]
mod tests;
