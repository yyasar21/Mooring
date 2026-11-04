//! Kubeconfig validation (ADR-0009 §1): the file must be self-contained. Parsed from hostile
//! input with an event-level YAML parser (`saphyr-parser`) into a small, capped tree; no serde
//! type magic, no anchors/aliases, no tags, at most one document.
//!
//! Rejected: `exec`, `auth-provider`, `tokenFile`, `client-certificate`, `client-key` (file
//! paths) in any mapping under `users[]`, and any cluster `certificate-authority` file path,
//! compared ASCII case-insensitively (lenient decoders match JSON field names that way), and
//! YAML merge keys (`<<`) anywhere: go-yaml applies them, so a merge could smuggle `exec` in.
//! Running a command or reading a file named by imported YAML is code execution / disclosure.
//! Keys are also unique ASCII case-insensitively at every level, and a top-level section key
//! (`users`, `clusters`, `contexts`) in any other case (`Users:`, `CLUSTERS:`) is rejected
//! outright rather than checked under its variant spelling (QA-F2): a lenient decoder may read
//! it as the real section, and rejecting is simpler than proving every lookup case-blind.
//! Every mapping key anywhere in the document must be ASCII (review 4, M-12): Go's
//! `encoding/json` matches field names with Unicode simple case folding, so `U+212A KELVIN SIGN`
//! reads as `k` and `U+017F LATIN SMALL LETTER LONG S` as `s` (`to\u{212A}enFile`,
//! `u\u{017F}ers`), which no ASCII-insensitive comparison can see. Real kubeconfig keys are all
//! ASCII; names and values are unaffected. The error names the key's line and column only.
//! Extracted: context names (capped) and `current-context`. [`resolve`] (ADR-0014 §3) then
//! reads one context's cluster and user out of the same validated tree.

use std::collections::{BTreeSet, HashSet};

use saphyr_parser::{Event, Parser, Span};

use super::CredentialError;

mod names;
mod resolve;

pub use names::{is_dns_label, is_dns_subdomain, KubeServer};
pub use resolve::{resolve, CaSource, KubeAuth, KubeResolveError, Resolved, MAX_CA_PEM, MAX_TOKEN};

/// Largest kubeconfig accepted (bytes).
pub const MAX_YAML: usize = 1024 * 1024;
/// Most contexts kept.
pub const MAX_CONTEXTS: usize = 64;
/// Longest context name (bytes).
pub const MAX_CONTEXT_NAME: usize = 253;
/// Deepest nesting accepted.
const MAX_DEPTH: usize = 32;
/// Most YAML nodes accepted (bounds memory independently of byte size).
const MAX_NODES: usize = 100_000;
/// Most entries in one mapping (review 3, L-10).
const MAX_MAP_ENTRIES: usize = 4096;

/// Keys that make a kubeconfig run something or read a file.
const FORBIDDEN_USER_KEYS: &[&str] =
    &["exec", "auth-provider", "tokenFile", "client-certificate", "client-key"];
const FORBIDDEN_CLUSTER_KEYS: &[&str] = &["certificate-authority"];

/// Top-level section keys that must be spelled exactly (QA-F2).
const SECTION_KEYS: &[&str] = &["users", "clusters", "contexts"];

/// What a valid kubeconfig yields in plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubeconfigInfo {
    /// Context names in file order (deduplicated, capped).
    pub contexts: Vec<String>,
    /// `current-context`, when set and present in `contexts`.
    pub current_context: Option<String>,
}

#[derive(Debug)]
enum Node {
    Scalar(String),
    Seq(Vec<Node>),
    Map(Vec<(String, Node)>),
}

impl Node {
    fn get(&self, key: &str) -> Option<&Node> {
        match self {
            Self::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn str(&self) -> Option<&str> {
        match self {
            Self::Scalar(s) => Some(s),
            _ => None,
        }
    }

    fn items(&self) -> &[Node] {
        match self {
            Self::Seq(v) => v,
            _ => &[],
        }
    }
}

fn rejected(reason: &str) -> CredentialError {
    CredentialError::KubeconfigRejected(reason.to_owned())
}

/// M-12: position only (1-based line and column), never the key's bytes.
fn non_ascii_key(span: Span) -> CredentialError {
    rejected(&format!(
        "kubeconfig keys must be ASCII (key at line {}, column {})",
        span.start.line(),
        span.start.col() + 1
    ))
}

struct Builder<'a> {
    parser: Parser<'a, saphyr_parser::StrInput<'a>>,
    nodes: usize,
}

impl<'a> Builder<'a> {
    fn next(&mut self) -> Result<Event<'a>, CredentialError> {
        self.next_spanned().map(|(ev, _)| ev)
    }

    fn next_spanned(&mut self) -> Result<(Event<'a>, Span), CredentialError> {
        match self.parser.next_event() {
            Some(Ok(pair)) => Ok(pair),
            Some(Err(_)) | None => Err(rejected("kubeconfig is not valid YAML")),
        }
    }

    fn node(&mut self, ev: Event<'a>, depth: usize) -> Result<Node, CredentialError> {
        self.nodes += 1;
        if self.nodes > MAX_NODES || depth > MAX_DEPTH {
            return Err(rejected("kubeconfig is too large or too deeply nested"));
        }
        match ev {
            Event::Scalar(v, _, anchor, tag) => {
                if anchor != 0 || tag.is_some() {
                    return Err(rejected("kubeconfig may not use YAML anchors or tags"));
                }
                Ok(Node::Scalar(v.into_owned()))
            }
            Event::SequenceStart(anchor, tag) => {
                if anchor != 0 || tag.is_some() {
                    return Err(rejected("kubeconfig may not use YAML anchors or tags"));
                }
                let mut items = Vec::new();
                loop {
                    match self.next()? {
                        Event::SequenceEnd => return Ok(Node::Seq(items)),
                        ev => items.push(self.node(ev, depth + 1)?),
                    }
                }
            }
            Event::MappingStart(anchor, tag) => {
                if anchor != 0 || tag.is_some() {
                    return Err(rejected("kubeconfig may not use YAML anchors or tags"));
                }
                let mut entries: Vec<(String, Node)> = Vec::new();
                // duplicate check in O(1) per key (was a linear scan: quadratic per mapping),
                // ASCII case-insensitive: a clean `users:` may not sit beside `Users:` (QA-F2)
                let mut keys: HashSet<String> = HashSet::new();
                loop {
                    let (key, span) = match self.next_spanned()? {
                        (Event::MappingEnd, _) => return Ok(Node::Map(entries)),
                        (Event::Scalar(k, _, 0, None), span) => (k.into_owned(), span),
                        _ => return Err(rejected("kubeconfig keys must be plain text")),
                    };
                    // the resolved key (escapes applied), so `"to\u212AenFile"` is caught too
                    if !key.is_ascii() {
                        return Err(non_ascii_key(span));
                    }
                    if key == "<<" {
                        return Err(rejected("kubeconfig may not use YAML merge keys"));
                    }
                    let ev = self.next()?;
                    let value = self.node(ev, depth + 1)?;
                    if entries.len() >= MAX_MAP_ENTRIES {
                        return Err(rejected("kubeconfig has too many keys in one mapping"));
                    }
                    if !keys.insert(key.to_ascii_lowercase()) {
                        return Err(rejected("kubeconfig has a duplicate key"));
                    }
                    entries.push((key, value));
                }
            }
            Event::Alias(_) => Err(rejected("kubeconfig may not use YAML aliases")),
            _ => Err(rejected("kubeconfig is not valid YAML")),
        }
    }
}

fn parse_tree(yaml: &str) -> Result<Node, CredentialError> {
    let mut b = Builder { parser: Parser::new_from_str(yaml), nodes: 0 };
    if !matches!(b.next()?, Event::StreamStart) {
        return Err(rejected("kubeconfig is not valid YAML"));
    }
    if !matches!(b.next()?, Event::DocumentStart(_)) {
        return Err(rejected("kubeconfig is empty"));
    }
    let ev = b.next()?;
    let root = b.node(ev, 0)?;
    if !matches!(b.next()?, Event::DocumentEnd) || !matches!(b.next()?, Event::StreamEnd) {
        return Err(rejected("kubeconfig must be a single YAML document"));
    }
    Ok(root)
}

/// The first forbidden key (canonical spelling) in any mapping inside `node`, compared ASCII
/// case-insensitively.
fn find_forbidden(node: &Node, keys: &[&'static str]) -> Option<&'static str> {
    match node {
        Node::Scalar(_) => None,
        Node::Seq(items) => items.iter().find_map(|n| find_forbidden(n, keys)),
        Node::Map(entries) => entries.iter().find_map(|(k, v)| {
            keys.iter()
                .copied()
                .find(|f| f.eq_ignore_ascii_case(k))
                .or_else(|| find_forbidden(v, keys))
        }),
    }
}

fn check_forbidden(
    section: &Node,
    inner: &str,
    keys: &[&'static str],
    what: &str,
) -> Result<(), CredentialError> {
    for item in section.items() {
        if item.get(inner).is_some_and(|body| !matches!(body, Node::Map(_))) {
            return Err(rejected(&format!("{what} entry is malformed")));
        }
        // every mapping under the entry, not only the `user` / `cluster` body
        if let Some(k) = find_forbidden(item, keys) {
            return Err(rejected(&format!(
                "{what} uses `{k}`; only self-contained kubeconfigs (inline data, tokens) are accepted"
            )));
        }
    }
    Ok(())
}

/// Validate a kubeconfig and extract its context names. Errors are `KubeconfigRejected` with a
/// reason naming at most a YAML key from the fixed forbidden list, never a value.
pub fn parse(yaml: &[u8]) -> Result<KubeconfigInfo, CredentialError> {
    validate(yaml).map(|(_, info)| info)
}

/// [`parse`], also returning the validated tree for [`resolve`] (which reads nothing else).
fn validate(yaml: &[u8]) -> Result<(Node, KubeconfigInfo), CredentialError> {
    if yaml.len() > MAX_YAML {
        return Err(rejected("kubeconfig is larger than 1 MiB"));
    }
    let text = std::str::from_utf8(yaml).map_err(|_| rejected("kubeconfig is not UTF-8 text"))?;
    if text.chars().any(|c| !matches!(c, '\n' | '\r' | '\t') && super::is_forbidden(c)) {
        return Err(rejected("kubeconfig contains control or invisible characters"));
    }
    let root = parse_tree(text)?;
    if !matches!(root, Node::Map(_)) {
        return Err(rejected("kubeconfig must be a mapping"));
    }
    if let Node::Map(entries) = &root {
        let variant = entries
            .iter()
            .any(|(k, _)| SECTION_KEYS.iter().any(|s| s.eq_ignore_ascii_case(k) && *s != k));
        if variant {
            return Err(rejected("kubeconfig section keys must be lower case"));
        }
    }
    if let Some(kind) = root.get("kind").and_then(Node::str) {
        if kind != "Config" {
            return Err(rejected("kubeconfig kind must be Config"));
        }
    }
    let users = root.get("users");
    if let Some(users) = users {
        check_forbidden(users, "user", FORBIDDEN_USER_KEYS, "a user")?;
    }
    if let Some(clusters) = root.get("clusters") {
        check_forbidden(clusters, "cluster", FORBIDDEN_CLUSTER_KEYS, "a cluster")?;
    }
    let mut contexts: Vec<String> = Vec::new();
    let mut seen = BTreeSet::new();
    for item in root.get("contexts").map(Node::items).unwrap_or_default() {
        let Some(name) = item.get("name").and_then(Node::str) else {
            return Err(rejected("a context has no name"));
        };
        if name.is_empty() || name.len() > MAX_CONTEXT_NAME || name.chars().any(super::is_forbidden)
        {
            return Err(rejected("a context name is empty, too long or has control characters"));
        }
        if seen.insert(name.to_owned()) && contexts.len() < MAX_CONTEXTS {
            contexts.push(name.to_owned());
        }
    }
    if contexts.is_empty() {
        return Err(rejected("kubeconfig has no contexts"));
    }
    let current_context = root
        .get("current-context")
        .and_then(Node::str)
        .filter(|c| contexts.iter().any(|x| x == c))
        .map(str::to_owned);
    Ok((root, KubeconfigInfo { contexts, current_context }))
}

#[cfg(test)]
mod resolve_tests;
#[cfg(test)]
mod tests;
