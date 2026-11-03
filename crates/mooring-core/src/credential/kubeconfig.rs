//! Kubeconfig validation (ADR-0009 §1): the file must be self-contained. Parsed from hostile
//! input with an event-level YAML parser (`saphyr-parser`) into a small, capped tree; no serde
//! type magic, no anchors/aliases, no tags, at most one document.
//!
//! Rejected: `exec`, `auth-provider`, `tokenFile`, `client-certificate`, `client-key` (file
//! paths) anywhere under `users[].user`, and any cluster `certificate-authority` file path.
//! Running a command or reading a file named by imported YAML is code execution / disclosure.
//! Extracted: context names (capped) and `current-context`.

use std::collections::BTreeSet;

use saphyr_parser::{Event, Parser};

use super::CredentialError;

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

/// Keys that make a kubeconfig run something or read a file.
const FORBIDDEN_USER_KEYS: &[&str] =
    &["exec", "auth-provider", "tokenFile", "client-certificate", "client-key"];
const FORBIDDEN_CLUSTER_KEYS: &[&str] = &["certificate-authority"];

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

struct Builder<'a> {
    parser: Parser<'a, saphyr_parser::StrInput<'a>>,
    nodes: usize,
}

impl<'a> Builder<'a> {
    fn next(&mut self) -> Result<Event<'a>, CredentialError> {
        match self.parser.next_event() {
            Some(Ok((ev, _))) => Ok(ev),
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
                loop {
                    let key = match self.next()? {
                        Event::MappingEnd => return Ok(Node::Map(entries)),
                        Event::Scalar(k, _, 0, None) => k.into_owned(),
                        _ => return Err(rejected("kubeconfig keys must be plain text")),
                    };
                    let ev = self.next()?;
                    let value = self.node(ev, depth + 1)?;
                    if entries.iter().any(|(k, _)| *k == key) {
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

fn check_forbidden(
    section: &Node,
    inner: &str,
    keys: &[&str],
    what: &str,
) -> Result<(), CredentialError> {
    for item in section.items() {
        if let Some(body) = item.get(inner) {
            if let Node::Map(entries) = body {
                if let Some((k, _)) = entries.iter().find(|(k, _)| keys.contains(&k.as_str())) {
                    return Err(rejected(&format!(
                        "{what} uses `{k}`; only self-contained kubeconfigs (inline data, tokens) are accepted"
                    )));
                }
            } else {
                return Err(rejected(&format!("{what} entry is malformed")));
            }
        }
    }
    Ok(())
}

/// Validate a kubeconfig and extract its context names. Errors are `KubeconfigRejected` with a
/// reason naming at most a YAML key from the fixed forbidden list, never a value.
pub fn parse(yaml: &[u8]) -> Result<KubeconfigInfo, CredentialError> {
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
    Ok(KubeconfigInfo { contexts, current_context })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::testdata::KUBECONFIG;
    use proptest::prelude::*;

    #[test]
    fn extracts_contexts_and_current() {
        let info = parse(KUBECONFIG.as_bytes()).expect("valid");
        assert_eq!(info.contexts, ["lab", "lab-admin"]);
        assert_eq!(info.current_context.as_deref(), Some("lab"));
    }

    #[test]
    fn rejects_code_execution_and_file_references() {
        for (needle, replacement) in [
            ("    token: test-only-token", "    exec:\n      command: /bin/sh"),
            ("    token: test-only-token", "    auth-provider:\n      name: oidc"),
            ("    token: test-only-token", "    tokenFile: /var/run/token"),
            ("    token: test-only-token", "    client-certificate: /home/u/.kube/c.crt"),
            ("    token: test-only-token", "    client-key: /home/u/.kube/c.key"),
            ("    certificate-authority-data: AAAA", "    certificate-authority: /etc/ca.crt"),
        ] {
            let yaml = KUBECONFIG.replace(needle, replacement);
            let e = parse(yaml.as_bytes()).expect_err(replacement);
            assert!(matches!(e, CredentialError::KubeconfigRejected(_)), "{e:?}");
            assert!(!e.to_string().contains("/bin/sh") && !e.to_string().contains("/etc"));
        }
    }

    #[test]
    fn rejects_yaml_tricks() {
        let alias =
            KUBECONFIG.replace("users:\n- name: ops\n  user:", "users:\n- name: ops\n  user: &u");
        assert!(parse(alias.as_bytes()).is_err(), "anchor");
        let two_docs = format!("{KUBECONFIG}---\n{KUBECONFIG}");
        assert!(parse(two_docs.as_bytes()).is_err(), "two documents");
        let dup = format!("{KUBECONFIG}kind: Config\n");
        assert!(parse(dup.as_bytes()).is_err(), "duplicate key");
        assert!(parse(b"- a\n- b\n").is_err(), "not a mapping");
        assert!(parse(b"").is_err(), "empty");
        assert!(parse(b"apiVersion: v1\nkind: Config\n").is_err(), "no contexts");
        let deep = format!("a: {}{}", "[".repeat(100), "]".repeat(100));
        assert!(parse(deep.as_bytes()).is_err(), "depth");
        assert!(parse(&vec![b'#'; MAX_YAML + 1]).is_err(), "size");
        assert!(parse(b"a: !!binary AAAA\ncontexts: [{name: x}]\n").is_err(), "tag");
        assert!(parse(&[0xff, 0xfe]).is_err(), "utf-8");
    }

    #[test]
    fn contexts_are_capped_and_deduplicated() {
        let mut yaml = String::from("contexts:\n");
        for i in 0..100 {
            let line = format!("- name: c{i}\n");
            yaml.push_str(&line);
            yaml.push_str(&line);
        }
        let info = parse(yaml.as_bytes()).expect("valid");
        assert_eq!(info.contexts.len(), MAX_CONTEXTS);
        assert_eq!(info.contexts[1], "c1");
        assert_eq!(info.current_context, None);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]
        #[test]
        fn never_panics(s in "\\PC{0,300}") {
            let _ = parse(s.as_bytes());
        }

        #[test]
        fn never_panics_on_yaml_shaped_noise(s in "[a-z:\\- \\[\\]{}&*!|>'\"\n#]{0,300}") {
            let _ = parse(s.as_bytes());
            let _ = parse(format!("{KUBECONFIG}{s}").as_bytes());
        }
    }
}
