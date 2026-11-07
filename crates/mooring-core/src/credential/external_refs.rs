//! Reference grammars of the non-Vault providers (ADR-0026 §3, §4), strict and capped:
//!
//! * 1Password Connect: `op://<vault>/<item>` (the whole item, fields by label) or
//!   `op://<vault>/<item>[/<section>]/<field>` (one field). Titles or UUIDs; no `?`, `#`,
//!   `\` or `/` inside a segment, no control or invisible characters.
//! * Bitwarden Secrets Manager: `<secret uuid>` or `<project uuid>/<key>`.
//!
//! Both are inventory-class strings (R-INV-CRED), never secrets.

use super::CredentialError;

/// Longest segment of an `op://` reference (bytes).
pub const MAX_OP_SEGMENT: usize = 256;
/// Longest Bitwarden secret key (bytes).
pub const MAX_BWS_KEY: usize = 256;

/// A parsed `op://` reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpReference {
    /// Vault title or UUID.
    pub vault: String,
    /// Item title or UUID.
    pub item: String,
    /// Section label or id (only with a field).
    pub section: Option<String>,
    /// Field label or id; `None` = the whole item (fields by the target kind's names).
    pub field: Option<String>,
}

impl OpReference {
    /// The reference text again.
    #[must_use]
    pub fn render(&self) -> String {
        let mut s = format!("op://{}/{}", self.vault, self.item);
        for p in [&self.section, &self.field].into_iter().flatten() {
            s.push('/');
            s.push_str(p);
        }
        s
    }
}

fn op_segment_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_OP_SEGMENT
        && s.trim() == s
        && !s.chars().any(|c| matches!(c, '?' | '#' | '\\') || super::is_forbidden(c))
}

/// Parse an `op://` reference strictly (no trimming, no percent decoding).
pub fn parse_op_reference(reference: &str) -> Result<OpReference, CredentialError> {
    let bad = |reason: &'static str| CredentialError::invalid("reference", reason);
    if reference.len() > super::external::MAX_REFERENCE {
        return Err(bad("longer than 1024 bytes"));
    }
    let rest = reference.strip_prefix("op://").ok_or(bad("must start with op://"))?;
    let segs: Vec<&str> = rest.split('/').collect();
    if !segs.iter().all(|s| op_segment_ok(s)) {
        return Err(bad("segments must be 1..=256 bytes of visible text without ?, # or \\"));
    }
    let own = |s: &str| s.to_owned();
    Ok(match segs.as_slice() {
        [v, i] => OpReference { vault: own(v), item: own(i), section: None, field: None },
        [v, i, f] => {
            OpReference { vault: own(v), item: own(i), section: None, field: Some(own(f)) }
        }
        [v, i, s, f] => {
            OpReference { vault: own(v), item: own(i), section: Some(own(s)), field: Some(own(f)) }
        }
        _ => return Err(bad("must be op://<vault>/<item>[/<section>]/<field>")),
    })
}

/// A parsed Bitwarden Secrets Manager reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BwsReference {
    /// `secret get <uuid>`.
    Id(String),
    /// `secret list <project>`, then the one secret whose `key` matches.
    ProjectKey {
        /// Project UUID.
        project: String,
        /// Secret key.
        key: String,
    },
}

/// `8-4-4-4-12` hexadecimal (any case), returned lower-cased.
#[must_use]
pub fn uuid_text(s: &str) -> Option<String> {
    let groups: Vec<&str> = s.split('-').collect();
    let ok = groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(g, n)| g.len() == n && g.bytes().all(|b| b.is_ascii_hexdigit()));
    ok.then(|| s.to_ascii_lowercase())
}

/// Parse a Bitwarden reference strictly.
pub fn parse_bws_reference(reference: &str) -> Result<BwsReference, CredentialError> {
    let bad = |reason: &'static str| CredentialError::invalid("reference", reason);
    match reference.split_once('/') {
        None => uuid_text(reference)
            .map(BwsReference::Id)
            .ok_or(bad("must be a secret UUID or <project UUID>/<key>")),
        Some((project, key)) => {
            let project = uuid_text(project).ok_or(bad("the project must be a UUID"))?;
            let key_ok = !key.is_empty()
                && key.len() <= MAX_BWS_KEY
                && key.trim() == key
                && !key.chars().any(|c| c == '/' || super::is_forbidden(c));
            if !key_ok {
                return Err(bad("the key must be 1..=256 bytes of visible text without /"));
            }
            Ok(BwsReference::ProjectKey { project, key: key.to_owned() })
        }
    }
}

/// Fuzz entry (`op_reference_parse`): both grammars; a parsed `op://` reference renders back
/// to its input. Never panics.
pub fn fuzz_op_reference(data: &[u8]) {
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Ok(r) = parse_op_reference(s) {
        assert_eq!(r.render(), s, "round trip");
    }
    let _ = parse_bws_reference(s);
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn op_grammar() {
        let r = parse_op_reference("op://Infra/DB prod/password").expect("3");
        assert_eq!(
            (r.vault.as_str(), r.item.as_str(), r.field.as_deref()),
            ("Infra", "DB prod", Some("password"))
        );
        let r = parse_op_reference("op://Infra/DB/admin/password").expect("4");
        assert_eq!(r.section.as_deref(), Some("admin"));
        let r = parse_op_reference("op://abcdefghijklmnopqrstuvwxyz/item").expect("2");
        assert!(r.field.is_none());
        for bad in [
            "",
            "op://",
            "op://v",
            "op:///i",
            "op://v//f",
            "op://v/i/s/f/x",
            "op://v/i?attribute=otp",
            "op://v/i#f",
            "op://v/ i",
            "op://v/i\u{202e}",
            "op://v/i\n",
            "vault://v/i",
            "OP://v/i",
        ] {
            assert!(parse_op_reference(bad).is_err(), "{bad:?}");
        }
        assert!(parse_op_reference(&format!("op://v/{}", "i".repeat(257))).is_err());
    }

    #[test]
    fn bws_grammar() {
        let id = "3B5C1E02-1D2A-4C8E-9F00-0123456789AB";
        assert_eq!(parse_bws_reference(id).expect("id"), BwsReference::Id(id.to_ascii_lowercase()));
        let r = parse_bws_reference(&format!("{id}/db.password")).expect("pk");
        assert!(matches!(r, BwsReference::ProjectKey { key, .. } if key == "db.password"));
        for bad in [
            "",
            "not-a-uuid",
            "3b5c1e02-1d2a-4c8e-9f00-0123456789a",
            "3b5c1e02-1d2a-4c8e-9f00-0123456789abc",
            "3b5c1e021d2a4c8e9f000123456789ab",
            "proj/key",
            "3b5c1e02-1d2a-4c8e-9f00-0123456789ab/",
            "3b5c1e02-1d2a-4c8e-9f00-0123456789ab/a/b",
            "3b5c1e02-1d2a-4c8e-9f00-0123456789ab/ k",
            "3b5c1e02-1d2a-4c8e-9f00-0123456789ab/k\u{7}",
            "3b5c1e02-1d2a-4c8e-9f00-01234567890g",
        ] {
            assert!(parse_bws_reference(bad).is_err(), "{bad:?}");
        }
    }

    proptest! {
        #[test]
        fn fuzz_never_panics(data in proptest::collection::vec(any::<u8>(), 0..300)) {
            fuzz_op_reference(&data);
        }

        #[test]
        fn op_round_trips(segs in proptest::collection::vec("[A-Za-z0-9][A-Za-z0-9 ._-]{0,10}[A-Za-z0-9]", 2..5)) {
            let s = format!("op://{}", segs.join("/"));
            let r = parse_op_reference(&s).expect("valid");
            prop_assert_eq!(r.render(), s);
        }
    }
}
