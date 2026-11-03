//! Full-text search and credential inheritance.
//!
//! Search goes through the FTS5 `search` table. User input is never passed to `MATCH` as
//! syntax: it is split on whitespace, every token is wrapped as an FTS5 string literal
//! (`"` doubled), and a `*` prefix operator is appended outside the quotes. Operators such as
//! `OR`, `NEAR`, `-`, `:` or `^` in the input therefore match as plain text.

use nexus_core::{ConnectionId, CredentialId, FolderId, Protocol};
use rusqlite::{params, OptionalExtension};

use crate::error::{not_found, Result, StoreError};
use crate::util::{parse_id, parse_opt_id, protocol_from_str};
use crate::Store;

/// Hard cap on [`Store::search`] results.
pub const MAX_SEARCH_LIMIT: usize = 200;
/// Longest query accepted (characters); longer input is truncated.
const MAX_QUERY_CHARS: usize = 256;
/// Most tokens used from one query.
const MAX_QUERY_TOKENS: usize = 16;

/// One search result: enough for the UI list, no credential details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionHit {
    /// Connection id.
    pub id: ConnectionId,
    /// Folder that contains it.
    pub folder: FolderId,
    /// Display name.
    pub name: String,
    /// Host.
    pub host: String,
    /// Protocol.
    pub protocol: Protocol,
}

/// Turn free text into a safe FTS5 query: every token a quoted prefix term, joined by AND.
/// Returns `None` when nothing searchable remains.
pub(crate) fn fts_query(input: &str) -> Option<String> {
    let input: String = input.chars().take(MAX_QUERY_CHARS).collect();
    let terms: Vec<String> = input
        .split_whitespace()
        .map(|t| t.chars().filter(|c| !c.is_control()).collect::<String>())
        .filter(|t| t.chars().any(char::is_alphanumeric))
        .take(MAX_QUERY_TOKENS)
        .map(|t| format!("\"{}\"*", t.replace('"', "\"\"")))
        .collect();
    if terms.is_empty() {
        None
    } else {
        Some(terms.join(" "))
    }
}

impl Store {
    /// Prefix search over connection name, host and tags, best match first.
    /// `limit` is clamped to `1..=200`.
    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<ConnectionHit>> {
        let Some(q) = fts_query(query) else {
            return Ok(Vec::new());
        };
        let limit = i64::try_from(limit.clamp(1, MAX_SEARCH_LIMIT)).unwrap_or(1);
        let mut stmt = self.conn.prepare(
            "SELECT c.id, c.folder_id, c.name, c.host, c.protocol
             FROM search JOIN connection c ON c.rowid = search.rowid
             WHERE search MATCH ?1
             ORDER BY bm25(search), c.name, c.id
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![q, limit], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?;
        rows.map(|r| {
            let (id, folder, name, host, protocol) = r?;
            Ok(ConnectionHit {
                id: parse_id(&id)?,
                folder: parse_id(&folder)?,
                name,
                host,
                protocol: protocol_from_str(&protocol)?,
            })
        })
        .collect()
    }

    /// Credential a connection will use: its own override, else the nearest ancestor
    /// folder's `default_credential`, else `None`. Mirrors
    /// `nexus_core::ConnectionTree::effective_credential`, including its cycle guard.
    pub fn effective_credential(&self, id: ConnectionId) -> Result<Option<CredentialId>> {
        let row: Option<(Option<String>, String)> = self
            .conn
            .query_row(
                "SELECT credential_id, folder_id FROM connection WHERE id = ?1",
                [id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (own, folder) = row.ok_or_else(|| not_found("connection", &id))?;
        if let Some(c) = parse_opt_id(own.as_deref())? {
            return Ok(Some(c));
        }
        // Walk the parent chain; depth bounded by the folder count so a corrupt (cyclic)
        // chain cannot loop forever.
        let (cred, depth, total): (Option<String>, i64, i64) = self.conn.query_row(
            "WITH RECURSIVE
               bound(n) AS (SELECT count(*) FROM folder),
               chain(id, parent_id, cred, depth) AS (
                 SELECT id, parent_id, default_credential_id, 0 FROM folder WHERE id = ?1
                 UNION ALL
                 SELECT f.id, f.parent_id, f.default_credential_id, chain.depth + 1
                 FROM folder f JOIN chain ON f.id = chain.parent_id, bound
                 WHERE chain.cred IS NULL AND chain.depth <= bound.n
               )
             SELECT (SELECT cred FROM chain WHERE cred IS NOT NULL ORDER BY depth LIMIT 1),
                    coalesce(max(depth), 0), (SELECT n FROM bound)
             FROM chain",
            [folder],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        if cred.is_none() && depth >= total && total > 0 {
            return Err(StoreError::Tree("cycle detected while resolving credential".into()));
        }
        parse_opt_id(cred.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_tokens_are_quoted_prefix_terms() {
        assert_eq!(fts_query("xinfra 10.10").as_deref(), Some("\"xinfra\"* \"10.10\"*"));
        assert_eq!(fts_query("a\"b").as_deref(), Some("\"a\"\"b\"*"));
        assert_eq!(fts_query("NEAR( x OR y").as_deref(), Some("\"NEAR(\"* \"x\"* \"OR\"* \"y\"*"));
        assert_eq!(fts_query("  * - \" ()  "), None);
        assert_eq!(fts_query(""), None);
    }

    #[test]
    fn query_is_bounded() {
        let long = "ab ".repeat(1000);
        let q = fts_query(&long).expect("some");
        assert_eq!(q.matches('*').count(), MAX_QUERY_TOKENS);
    }
}
