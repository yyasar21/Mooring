//! Fuzz entry `kubeconfig_parse`: hostile kubeconfig YAML pasted or imported by the user
//! (ADR-0009). Shared by `fuzz/fuzz_targets/kubeconfig_parse.rs` and
//! `crates/mooring-core/tests/fuzz_corpus.rs`.
//!
//! Besides caps and determinism, an accepted file must satisfy the security property of the
//! parser (review 3 M-5, review 4 M-11). An independent oracle re-scans the input with the
//! same YAML event parser (`saphyr-parser`, version from the lockfile) and panics when the
//! parser accepted a file that a lenient consumer (go-yaml, case-insensitive JSON decoding)
//! could read as running a command or reading a file. Every mapping key of an accepted file
//! must also be ASCII (review 4 M-12): Go's `encoding/json` folds `U+212A` to `k` and `U+017F`
//! to `s`, which an ASCII case-insensitive comparison cannot see.

use std::collections::BTreeSet;

use mooring_core::credential::kubeconfig::{self, MAX_CONTEXTS, MAX_CONTEXT_NAME, MAX_YAML};
use saphyr_parser::{Event, Parser, StrInput, Tag};

/// Independent copy of the parser's forbidden `users[]` keys (`kubeconfig.rs`
/// `FORBIDDEN_USER_KEYS`). Kept separate on purpose: the oracle must not share the code it
/// checks. Compared ASCII case-insensitively.
const USER_KEYS: &[&str] =
    &["exec", "auth-provider", "tokenFile", "client-certificate", "client-key"];
/// Independent copy of `FORBIDDEN_CLUSTER_KEYS` (file path under `clusters[]`).
const CLUSTER_KEYS: &[&str] = &["certificate-authority"];

/// Never panics on a rejected file; an accepted file honours the documented caps, is parsed
/// deterministically and carries no merge key and no forbidden `users[]` / `clusters[]` key.
pub fn run(data: &[u8]) {
    let Ok(info) = kubeconfig::parse(data) else {
        return;
    };
    assert!(data.len() <= MAX_YAML, "accepted an over-size kubeconfig");
    assert!(info.contexts.len() <= MAX_CONTEXTS, "context cap exceeded");
    let mut seen = BTreeSet::new();
    for name in &info.contexts {
        assert!(!name.is_empty() && name.len() <= MAX_CONTEXT_NAME, "context name out of bounds");
        assert!(seen.insert(name), "duplicate context name");
    }
    if let Some(current) = &info.current_context {
        assert!(info.contexts.contains(current), "current-context not among the contexts");
    }
    assert_eq!(kubeconfig::parse(data).ok(), Some(info), "parse is not deterministic");

    let text = std::str::from_utf8(data).expect("accepted a kubeconfig that is not UTF-8");
    if let Some(v) = violations(text).into_iter().next() {
        panic!("kubeconfig::parse accepted a forbidden construct: {v}");
    }
}

/// Where a node sits, as far as the security property cares.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ctx {
    /// The root node of a document.
    Root,
    /// The value of a top-level `users` key (any ASCII case).
    UsersValue,
    /// Inside an item of the `users` sequence, at any depth.
    InUser,
    /// The value of a top-level `clusters` key (any ASCII case).
    ClustersValue,
    /// Inside an item of the `clusters` sequence, at any depth.
    InCluster,
    /// Anywhere else.
    Other,
}

impl Ctx {
    fn forbidden(self) -> &'static [&'static str] {
        match self {
            Self::InUser => USER_KEYS,
            Self::InCluster => CLUSTER_KEYS,
            _ => &[],
        }
    }

    /// Context of an item of a sequence in `self`.
    fn item(self) -> Self {
        match self {
            Self::UsersValue | Self::InUser => Self::InUser,
            Self::ClustersValue | Self::InCluster => Self::InCluster,
            _ => Self::Other,
        }
    }

    /// Context of the value of mapping key `key` in a mapping in `self`.
    fn value(self, key: Option<&str>) -> Self {
        match (self, key) {
            (Self::Root, Some(k)) if k.eq_ignore_ascii_case("users") => Self::UsersValue,
            (Self::Root, Some(k)) if k.eq_ignore_ascii_case("clusters") => Self::ClustersValue,
            (Self::InUser | Self::InCluster, _) => self,
            _ => Self::Other,
        }
    }

    /// Whether this is inside a `users[]` / `clusters[]` item.
    fn guarded(self) -> bool {
        matches!(self, Self::InUser | Self::InCluster)
    }
}

/// Re-scan `text` with the raw event stream and list every violation of the property: a
/// mapping key `<<` (or `!!merge`) anywhere; a non-ASCII mapping key anywhere; a forbidden key, ASCII case-insensitively, in any
/// mapping under `users[]` / `clusters[]`; and, under those, anything whose key name the
/// oracle cannot see (tagged keys, aliases), since a consumer may resolve it to a forbidden
/// name. Every document of the stream is scanned. A stream the event parser rejects yields a
/// violation too: the parser must never accept what its own YAML layer cannot read.
pub fn violations(text: &str) -> Vec<String> {
    let mut scan = Scan { parser: Parser::new_from_str(text), found: Vec::new(), depth: 0 };
    loop {
        match scan.next() {
            None | Some(Event::StreamEnd) => break,
            Some(Event::StreamStart | Event::DocumentStart(_) | Event::DocumentEnd) => {}
            Some(ev) => {
                if scan.node(&ev, Ctx::Root).is_none() {
                    break;
                }
            }
        }
    }
    scan.found
}

/// Generous bound on oracle recursion (the parser caps depth at 32).
const ORACLE_DEPTH: usize = 512;

struct Scan<'a> {
    parser: Parser<'a, StrInput<'a>>,
    found: Vec<String>,
    depth: usize,
}

fn is_merge_tag(tag: Option<&Tag>) -> bool {
    tag.is_some_and(|t| t.suffix == "merge" || t.suffix.ends_with(":merge"))
}

impl<'a> Scan<'a> {
    fn next(&mut self) -> Option<Event<'a>> {
        match self.parser.next_event() {
            Some(Ok((ev, _))) => Some(ev),
            Some(Err(e)) => {
                self.found.push(format!("event parser rejects the accepted input ({e})"));
                None
            }
            None => None,
        }
    }

    /// Consume the node that starts with `ev`. `None` ends the scan (stream error or depth).
    fn node(&mut self, ev: &Event<'a>, ctx: Ctx) -> Option<()> {
        self.depth += 1;
        if self.depth > ORACLE_DEPTH {
            self.found.push("nesting deeper than the oracle bound".to_owned());
            return None;
        }
        let out = match ev {
            Event::Alias(_) if ctx.guarded() => {
                self.found
                    .push("alias under users[]/clusters[] (may carry a forbidden key)".into());
                Some(())
            }
            Event::SequenceStart(..) => self.seq(ctx.item()),
            Event::MappingStart(..) => self.map(ctx),
            _ => Some(()),
        };
        self.depth -= 1;
        out
    }

    fn seq(&mut self, item: Ctx) -> Option<()> {
        loop {
            match self.next()? {
                Event::SequenceEnd => return Some(()),
                ev => self.node(&ev, item)?,
            }
        }
    }

    fn map(&mut self, ctx: Ctx) -> Option<()> {
        loop {
            let key_ev = self.next()?;
            let key: Option<String> = match key_ev {
                Event::MappingEnd => return Some(()),
                Event::Scalar(ref k, _, _, ref tag) => {
                    self.check_key(k, tag.as_deref(), ctx);
                    Some(k.to_string())
                }
                // complex key (`? {exec: …}` / `? [exec]`): scan it in the same context, so
                // keys inside it are checked like any other key there
                other => {
                    if ctx.guarded() {
                        self.found.push("non-scalar key under users[]/clusters[]".into());
                    }
                    self.node(&other, ctx)?;
                    None
                }
            };
            let value = self.next()?;
            self.node(&value, ctx.value(key.as_deref()))?;
        }
    }

    fn check_key(&mut self, key: &str, tag: Option<&Tag>, ctx: Ctx) {
        if !key.is_ascii() {
            // byte-free: the key may be arbitrary hostile text
            self.found.push("non-ASCII mapping key (Unicode case folding, M-12)".to_owned());
        }
        if key == "<<" || is_merge_tag(tag) {
            self.found.push(format!("merge key `{key}`"));
        }
        if let Some(f) = ctx.forbidden().iter().find(|f| f.eq_ignore_ascii_case(key)) {
            self.found.push(format!("forbidden key `{key}` (matches `{f}`)"));
        }
        if tag.is_some() && ctx.guarded() {
            // `!!binary ZXhlYw==` etc.: the consumer decodes a name the oracle cannot compare
            self.found.push(format!("tagged key `{key}` under users[]/clusters[]"));
        }
    }
}
