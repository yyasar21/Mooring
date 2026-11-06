//! Royal TS `.rtsx` (XML) and `.rtsz` (gzip-compressed `.rtsx`; a ZIP container is refused,
//! owner decision) (ADR-0019 §2). Objects are `Royal*` elements with `ID`, `ParentID` and
//! `Name` children, either nested or flat under the document: `RoyalFolder` → folder,
//! `RoyalRDSConnection` → RDP, `RoyalSSHConnection` / `RoyalTerminalConnection` (type SSH) →
//! SSH, `RoyalVNCConnection` → VNC, `RoyalWebConnection` → web, `RoyalCredential` → a `prompt`
//! credential with the username. Secrets are never imported; a password-protected document
//! (`RoyalTSDocument` with `Encrypted` / `PasswordProtected` true) → `import.encrypted`.
//!
//! Element names follow the Royal TS XML schema as known to I1 and are tolerant of the known
//! variants; owner samples confirm them (handoff, Left open).

use std::collections::HashMap;

use mooring_core::Protocol;

use crate::error::{ImportError, Result};
use crate::plan::{NewConnection, PlanBuilder, SkipReason, WarningCode};
use crate::xml::{self, Node};
use crate::{creds, gzip, text, ImportFormat, ImportOptions, ImportSource, Importer};

const FORMAT: &str = "royal_ts";

/// The importer.
#[derive(Debug, Clone, Copy, Default)]
pub struct RoyalTs;

impl Importer for RoyalTs {
    fn format(&self) -> ImportFormat {
        ImportFormat::RoyalTs
    }

    fn sniff(&self, head: &[u8]) -> bool {
        if gzip::is_gzip(head) {
            return true;
        }
        let s = String::from_utf8_lossy(head);
        s.contains("<RTSDocument") || s.contains("<RoyalTSDocument")
    }

    fn parse(&self, src: ImportSource<'_>, opts: &ImportOptions) -> Result<crate::ImportPlan> {
        let ImportSource::File { bytes, .. } = src else {
            return Err(ImportError::format(FORMAT, "expected one file", 0));
        };
        if gzip::is_zip(bytes) {
            return Err(ImportError::UnsupportedContainer { what: "zip" });
        }
        let inflated;
        let bytes = if gzip::is_gzip(bytes) {
            inflated = gzip::inflate(bytes, &opts.limits)?;
            inflated.as_slice()
        } else {
            bytes
        };
        let text = text::decode(bytes, FORMAT)?;
        let root = xml::parse(&text, &opts.limits, FORMAT)?;
        if !matches!(root.name.as_str(), "RTSDocument" | "RoyalTSDocument") {
            return Err(ImportError::format(FORMAT, "root is not a Royal TS document", 0));
        }
        let mut objects = Vec::new();
        collect(&root, None, &mut objects);
        if objects.iter().any(|o| o.node.name == "RoyalTSDocument" && is_protected(o.node)) {
            return Err(ImportError::Encrypted);
        }
        let mut b = PlanBuilder::new(&opts.limits);
        let folder_keys = pass_folders(&objects, &mut b)?;
        let cred_keys = pass_credentials(&objects, &mut b)?;
        pass_connections(&objects, &folder_keys, &cred_keys, &mut b)?;
        Ok(b.finish())
    }
}

/// Pass 1: folders, parents before children (document order with `ParentID` links); a cycle
/// or a dangling parent keeps the folder at the root.
fn pass_folders<'a>(
    objects: &'a [Object<'a>],
    b: &mut PlanBuilder,
) -> Result<HashMap<&'a str, String>> {
    let mut folder_keys: HashMap<&str, String> = HashMap::new();
    let mut pending: Vec<&Object<'_>> =
        objects.iter().filter(|o| o.node.name == "RoyalFolder").collect();
    let mut progress = true;
    while progress && !pending.is_empty() {
        progress = false;
        let mut rest = Vec::new();
        for o in pending {
            let parent_key = match o.parent_id() {
                Some(p) if is_folder(objects, p) => {
                    let Some(k) = folder_keys.get(p) else {
                        rest.push(o);
                        continue;
                    };
                    Some(k.clone())
                }
                _ => None,
            };
            if let Some(k) = b.folder(parent_key.as_deref(), o.name(), &o.src)? {
                if let Some(id) = o.id() {
                    folder_keys.insert(id, k);
                }
            }
            progress = true;
        }
        pending = rest;
    }
    for o in pending {
        if let (Some(id), Some(k)) = (o.id(), b.folder(None, o.name(), &o.src)?) {
            folder_keys.insert(id, k);
        }
    }
    Ok(folder_keys)
}

/// Pass 2: credential objects by ID (a `prompt` with the username; nothing secret).
fn pass_credentials<'a>(
    objects: &'a [Object<'a>],
    b: &mut PlanBuilder,
) -> Result<HashMap<&'a str, String>> {
    let mut cred_keys: HashMap<&str, String> = HashMap::new();
    for o in objects.iter().filter(|o| o.node.name == "RoyalCredential") {
        if o.node.child_text("Password").is_some() {
            b.warn(WarningCode::PasswordDropped, &o.src);
        }
        let Some(user) = o.node.first_text(&["UserName", "Username"]) else {
            b.skip(&o.src, SkipReason::Unsupported);
            continue;
        };
        let domain = o.node.child_text("Domain");
        if let (Some(id), Some(k)) = (o.id(), b.credential(creds::prompt(user, domain), &o.src)?) {
            cred_keys.insert(id, k);
        }
    }
    Ok(cred_keys)
}

/// Pass 3: connections; other `Royal*` objects are skipped as unsupported.
fn pass_connections(
    objects: &[Object<'_>],
    folder_keys: &HashMap<&str, String>,
    cred_keys: &HashMap<&str, String>,
    b: &mut PlanBuilder,
) -> Result<()> {
    for o in objects {
        let Some((protocol, host)) = connection_target(o.node) else {
            if o.node.name.starts_with("Royal")
                && !matches!(
                    o.node.name.as_str(),
                    "RoyalFolder" | "RoyalCredential" | "RoyalTSDocument"
                )
            {
                b.skip(&o.src, SkipReason::Unsupported);
            }
            continue;
        };
        let folder = o.parent_id().and_then(|p| folder_keys.get(p)).cloned();
        let port = if protocol == Protocol::Web {
            None
        } else {
            b.port(o.node.child_text("Port"), &o.src)
        };
        let user = o.node.first_text(&["CredentialUsername", "UserName", "Username"]);
        let domain = o.node.first_text(&["CredentialDomain", "Domain"]);
        if o.node.first_text(&["CredentialPassword", "Password"]).is_some() {
            b.warn(WarningCode::PasswordDropped, &o.src);
        }
        let credential =
            match (o.node.child_text("CredentialID").and_then(|id| cred_keys.get(id)), user) {
                (Some(k), _) => Some(k.clone()),
                (None, Some(u)) if protocol != Protocol::Web => {
                    b.credential(creds::prompt(u, domain), &o.src)?
                }
                _ => None,
            };
        b.connection(
            NewConnection {
                name: o.name().to_owned(),
                protocol: Some(protocol),
                host,
                port,
                user: user.map(str::to_owned),
                domain: domain.map(str::to_owned),
                folder,
                credential,
                tags: Vec::new(),
            },
            &o.src,
        )?;
    }
    Ok(())
}

/// One `Royal*` element with its position and (for nested documents) the enclosing folder.
struct Object<'a> {
    node: &'a Node,
    src: String,
    nested_parent: Option<&'a str>,
}

impl Object<'_> {
    fn id(&self) -> Option<&str> {
        self.node.child_text("ID")
    }

    fn name(&self) -> &str {
        self.node.child_text("Name").unwrap_or_default()
    }

    /// `ParentID`, else the enclosing folder's ID when the object is nested.
    fn parent_id(&self) -> Option<&str> {
        self.node.child_text("ParentID").or(self.nested_parent)
    }
}

fn is_folder(objects: &[Object<'_>], id: &str) -> bool {
    objects.iter().any(|o| o.node.name == "RoyalFolder" && o.id() == Some(id))
}

fn is_protected(doc: &Node) -> bool {
    ["Encrypted", "IsEncrypted", "PasswordProtected", "IsPasswordProtected"]
        .iter()
        .any(|k| doc.child_text(k).is_some_and(|v| v.eq_ignore_ascii_case("true")))
}

/// Depth-first collection of `Royal*` objects; children of a folder inherit its ID as the
/// nested parent, other containers (the document, `Objects`) are transparent.
fn collect<'a>(node: &'a Node, enclosing: Option<&'a str>, out: &mut Vec<Object<'a>>) {
    for child in &node.children {
        let is_object = child.name.starts_with("Royal") && child.child("ID").is_some();
        let next = if is_object {
            let src = format!("{} #{}", child.name, out.len() + 1);
            out.push(Object { node: child, src, nested_parent: enclosing });
            if child.name == "RoyalFolder" {
                child.child_text("ID")
            } else {
                enclosing
            }
        } else {
            enclosing
        };
        collect(child, next, out);
    }
}

fn connection_target(node: &Node) -> Option<(Protocol, String)> {
    let uri = || node.first_text(&["URI", "Uri", "Host", "HostName"]).map(str::to_owned);
    match node.name.as_str() {
        "RoyalRDSConnection" => Some((Protocol::Rdp, uri()?)),
        "RoyalSSHConnection" => Some((Protocol::Ssh, uri()?)),
        "RoyalVNCConnection" => Some((Protocol::Vnc, uri()?)),
        "RoyalWebConnection" => {
            Some((Protocol::Web, node.first_text(&["URL", "Url", "URI"])?.to_owned()))
        }
        "RoyalTerminalConnection" => {
            let kind =
                node.first_text(&["TerminalConnectionType", "ConnectionType"]).unwrap_or("SSH");
            if !kind.eq_ignore_ascii_case("ssh") {
                return None;
            }
            Some((Protocol::Ssh, uri()?))
        }
        _ => None,
    }
}

#[cfg(test)]
#[path = "royalts_tests.rs"]
mod tests;
