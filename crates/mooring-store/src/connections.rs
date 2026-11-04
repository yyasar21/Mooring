//! Connection and tag CRUD.

use std::collections::BTreeSet;

use mooring_core::{Connection, ConnectionId, FolderId, Protocol, Role};
use rusqlite::{params, OptionalExtension, Row};

use crate::error::{invalid, not_found, Result, StoreError};
use crate::folders::folder_exists;
use crate::sync::{connection_source, ensure_folder_editable};
use crate::util::{check_name, fmt_ts, now, parse_id, parse_opt_id, parse_ts, protocol_from_str};
use crate::{Store, MAX_TAGS};

const CONN_COLS: &str = "id, folder_id, name, protocol, host, port, credential_id, created_at, \
                         username_override, domain_override";

struct RawConn {
    id: String,
    folder: String,
    name: String,
    protocol: String,
    host: String,
    port: Option<u16>,
    credential: Option<String>,
    created: String,
    username_override: Option<String>,
    domain_override: Option<String>,
}

fn row_to_raw(r: &Row<'_>) -> rusqlite::Result<RawConn> {
    Ok(RawConn {
        id: r.get(0)?,
        folder: r.get(1)?,
        name: r.get(2)?,
        protocol: r.get(3)?,
        host: r.get(4)?,
        port: r.get(5)?,
        credential: r.get(6)?,
        created: r.get(7)?,
        username_override: r.get(8)?,
        domain_override: r.get(9)?,
    })
}

/// Host rules from [`mooring_core::validate_host`].
fn check_host(host: &str) -> Result<String> {
    Ok(mooring_core::validate_host(host)?)
}

/// Trim, validate and de-duplicate tags (order-preserving set semantics via `BTreeSet`).
pub(crate) fn normalise_tags(tags: &[String]) -> Result<Vec<String>> {
    if tags.len() > MAX_TAGS {
        return Err(invalid("tags", &format!("at most {MAX_TAGS} tags")));
    }
    let mut out = BTreeSet::new();
    for t in tags {
        out.insert(mooring_core::validate_tag(t)?);
    }
    Ok(out.into_iter().collect())
}

struct Validated {
    name: String,
    host: String,
    tags: Vec<String>,
    username_override: Option<String>,
    domain_override: Option<String>,
}

fn validate(c: &Connection) -> Result<Validated> {
    if c.port == Some(0) {
        return Err(invalid("port", "must be 1..=65535"));
    }
    let (username_override, domain_override) = crate::roles::check_overrides(c)?;
    Ok(Validated {
        name: check_name("name", &c.name)?,
        host: check_host(&c.host)?,
        tags: normalise_tags(&c.tags)?,
        username_override,
        domain_override,
    })
}

impl Store {
    /// Checks shared by create and update: folder exists, linked credentials exist and fit
    /// the protocol and role, overrides fit the effective credential.
    fn check_links(&self, c: &Connection, v: &Validated) -> Result<()> {
        if !folder_exists(&self.conn, c.folder)? {
            return Err(not_found("folder", &c.folder));
        }
        self.ensure_role_credentials(c)?;
        let mut normalised = c.clone();
        normalised.username_override.clone_from(&v.username_override);
        normalised.domain_override.clone_from(&v.domain_override);
        self.check_override_fit(&normalised)
    }
}

impl Store {
    /// ADR-0015 §2: a synced connection keeps its folder, name, protocol, host and port (only
    /// the overlays change); an ordinary connection may not move into a synced folder.
    fn ensure_update_allowed(&self, c: &Connection, v: &Validated) -> Result<()> {
        if connection_source(&self.conn, c.id)?.is_none() {
            return ensure_folder_editable(&self.conn, c.folder);
        }
        let old = self.get_connection(c.id)?;
        let same = old.folder == c.folder
            && old.name == v.name
            && old.host == v.host
            && old.port == c.port
            && old.protocol == c.protocol;
        if same {
            Ok(())
        } else {
            Err(StoreError::SyncedReadOnly)
        }
    }

    /// Insert a connection (validated again here; fields of `Connection` are public).
    /// Returns the stored form (trimmed name/host, normalised tags).
    pub fn create_connection(&self, c: &Connection) -> Result<Connection> {
        let v = validate(c)?;
        self.check_links(c, &v)?;
        ensure_folder_editable(&self.conn, c.folder)?;
        let tx = self.conn.unchecked_transaction()?;
        let created = fmt_ts(c.created_at)?;
        tx.execute(
            "INSERT INTO connection (id, folder_id, name, protocol, host, port, credential_id,
                                     created_at, updated_at, username_override, domain_override)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                c.id.to_string(),
                c.folder.to_string(),
                v.name,
                c.protocol.name(),
                v.host,
                c.port,
                c.credential.map(|x| x.to_string()),
                created,
                fmt_ts(now())?,
                v.username_override,
                v.domain_override,
            ],
        )?;
        write_tags(&tx, c.id, &v.tags)?;
        Self::write_roles(&tx, c)?;
        tx.commit()?;
        self.get_connection(c.id)
    }

    /// Replace every mutable field of an existing connection, including its tags. A protocol
    /// change resets the connection's options to `{}` (they belong to the old protocol).
    pub fn update_connection(&self, c: &Connection) -> Result<Connection> {
        let v = validate(c)?;
        self.check_links(c, &v)?;
        self.ensure_update_allowed(c, &v)?;
        let tx = self.conn.unchecked_transaction()?;
        let n = tx.execute(
            "UPDATE connection SET folder_id = ?2, name = ?3, protocol = ?4, host = ?5, port = ?6,
                                   credential_id = ?7, updated_at = ?8, username_override = ?9,
                                   domain_override = ?10,
                                   options_json = CASE WHEN protocol = ?4 THEN options_json
                                                       ELSE '{}' END
             WHERE id = ?1",
            params![
                c.id.to_string(),
                c.folder.to_string(),
                v.name,
                c.protocol.name(),
                v.host,
                c.port,
                c.credential.map(|x| x.to_string()),
                fmt_ts(now())?,
                v.username_override,
                v.domain_override,
            ],
        )?;
        if n == 0 {
            return Err(not_found("connection", &c.id));
        }
        write_tags(&tx, c.id, &v.tags)?;
        Self::write_roles(&tx, c)?;
        tx.commit()?;
        self.get_connection(c.id)
    }

    /// Replace a connection's tags.
    pub fn set_tags(&self, id: ConnectionId, tags: &[String]) -> Result<Vec<String>> {
        let tags = normalise_tags(tags)?;
        let tx = self.conn.unchecked_transaction()?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM connection WHERE id = ?1)",
            [id.to_string()],
            |r| r.get(0),
        )?;
        if !exists {
            return Err(not_found("connection", &id));
        }
        write_tags(&tx, id, &tags)?;
        tx.commit()?;
        Ok(tags)
    }

    /// Delete a connection and its tags.
    pub fn delete_connection(&self, id: ConnectionId) -> Result<()> {
        if connection_source(&self.conn, id)?.is_some() {
            return Err(StoreError::SyncedReadOnly);
        }
        let n = self.conn.execute("DELETE FROM connection WHERE id = ?1", [id.to_string()])?;
        if n == 0 {
            return Err(not_found("connection", &id));
        }
        Ok(())
    }

    /// Look up one connection with its tags.
    pub fn get_connection(&self, id: ConnectionId) -> Result<Connection> {
        let sql = format!("SELECT {CONN_COLS} FROM connection WHERE id = ?1");
        let raw = self.conn.query_row(&sql, [id.to_string()], row_to_raw).optional()?;
        self.decode(raw.ok_or_else(|| not_found("connection", &id))?)
    }

    /// Connections directly inside a folder, sorted by name.
    pub fn list_connections(&self, folder: FolderId) -> Result<Vec<Connection>> {
        let sql =
            format!("SELECT {CONN_COLS} FROM connection WHERE folder_id = ?1 ORDER BY name, id");
        let mut stmt = self.conn.prepare(&sql)?;
        let raws = stmt
            .query_map([folder.to_string()], row_to_raw)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        raws.into_iter().map(|r| self.decode(r)).collect()
    }

    /// Ids of every connection of `protocol` inside `folder` or any folder below it (one
    /// recursive query, bounded by the folder count), sorted. `folder_delete` uses it to find
    /// the web stores and windows the SQL cascade would otherwise leave behind (review 5 L-30).
    pub fn connection_ids_under(
        &self,
        folder: FolderId,
        protocol: Protocol,
    ) -> Result<Vec<ConnectionId>> {
        let mut stmt = self.conn.prepare(
            "WITH RECURSIVE
               bound(n) AS (SELECT count(*) FROM folder),
               sub(id, depth) AS (
                 SELECT id, 0 FROM folder WHERE id = ?1
                 UNION ALL
                 SELECT f.id, sub.depth + 1 FROM folder f JOIN sub ON f.parent_id = sub.id, bound
                 WHERE sub.depth <= bound.n
               )
             SELECT c.id FROM connection c JOIN sub ON c.folder_id = sub.id
             WHERE c.protocol = ?2 ORDER BY c.id",
        )?;
        let ids = stmt
            .query_map(params![folder.to_string(), protocol.name()], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        ids.iter().map(|id| parse_id(id)).collect()
    }

    pub(crate) fn tags_of(&self, id: &str) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT tag FROM connection_tag WHERE connection_id = ?1 ORDER BY tag")?;
        let tags =
            stmt.query_map([id], |r| r.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
        Ok(tags)
    }

    fn decode(&self, raw: RawConn) -> Result<Connection> {
        let tags = self.tags_of(&raw.id)?;
        Ok(Connection {
            id: parse_id(&raw.id)?,
            folder: parse_id(&raw.folder)?,
            name: raw.name,
            protocol: protocol_from_str(&raw.protocol)?,
            host: raw.host,
            port: raw.port,
            credential: parse_opt_id(raw.credential.as_deref())?,
            username_override: raw.username_override,
            domain_override: raw.domain_override,
            gateway_credential: self.role_credential(&raw.id, Role::Gateway)?,
            become_credential: self.role_credential(&raw.id, Role::Become)?,
            tags,
            created_at: parse_ts(&raw.created)?,
        })
    }
}

/// Replace tags inside the caller's transaction. Triggers keep the FTS row in sync.
fn write_tags(conn: &rusqlite::Connection, id: ConnectionId, tags: &[String]) -> Result<()> {
    let id = id.to_string();
    conn.execute("DELETE FROM connection_tag WHERE connection_id = ?1", [&id])?;
    let mut stmt =
        conn.prepare("INSERT INTO connection_tag (connection_id, tag) VALUES (?1, ?2)")?;
    for t in tags {
        stmt.execute([&id, t])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_normalised_and_capped() {
        let t = normalise_tags(&[" b ".into(), "a".into(), "b".into()]).expect("ok");
        assert_eq!(t, vec!["a".to_owned(), "b".to_owned()]);
        assert!(normalise_tags(&["x".repeat(65)]).is_err());
        assert!(normalise_tags(&[" ".into()]).is_err());
        assert!(normalise_tags(&vec!["t".to_owned(); 51]).is_err());
        assert!(normalise_tags(&vec!["t".to_owned(); 50]).is_ok());
    }

    #[test]
    fn hosts_are_checked() {
        assert!(check_host("192.0.2.5").is_ok());
        assert!(check_host("a b").is_err());
        assert!(check_host("").is_err());
        assert!(check_host(&"h".repeat(2049)).is_err());
        assert!(check_host("h\u{7}").is_err());
    }

    #[test]
    fn connection_ids_under_walks_the_subtree_by_protocol() {
        let s = Store::open_in_memory().expect("open");
        let root = s.create_folder(None, "root").expect("root");
        let a = s.create_folder(Some(root.id), "a").expect("a");
        let b = s.create_folder(Some(a.id), "b").expect("b");
        let other = s.create_folder(Some(root.id), "other").expect("other");
        let mk = |folder: FolderId, name: &str, p: Protocol| {
            let c = Connection::new(folder, name, p, "h.example.test").expect("valid");
            s.create_connection(&c).expect("create").id
        };
        let web_a = mk(a.id, "wa", Protocol::Web);
        let web_b = mk(b.id, "wb", Protocol::Web);
        mk(b.id, "ssh", Protocol::Ssh);
        let web_other = mk(other.id, "wo", Protocol::Web);
        let mut want = vec![web_a, web_b];
        want.sort();
        assert_eq!(s.connection_ids_under(a.id, Protocol::Web).expect("under a"), want);
        assert!(s.connection_ids_under(b.id, Protocol::Ssh).expect("ssh").len() == 1);
        assert_eq!(s.connection_ids_under(root.id, Protocol::Web).expect("root").len(), 3);
        assert_eq!(s.connection_ids_under(other.id, Protocol::Web).expect("other"), [web_other]);
        assert!(s
            .connection_ids_under(FolderId::new(), Protocol::Web)
            .expect("missing")
            .is_empty());
    }

    #[test]
    fn store_and_core_agree_on_limits() {
        // Same rules as mooring-core: a value core accepts the store accepts, and vice versa.
        for host in ["192.0.2.5", "a b", "", "h\u{0}", &"h".repeat(2049)] {
            assert_eq!(
                check_host(host).is_ok(),
                mooring_core::validate_host(host).is_ok(),
                "{host}"
            );
        }
        for tag in ["x", " ", &"t".repeat(mooring_core::MAX_TAG + 1)] {
            let t = [tag.to_owned()];
            assert_eq!(
                normalise_tags(&t).is_ok(),
                mooring_core::validate_tag(tag).is_ok(),
                "{tag}"
            );
        }
        assert_eq!(crate::MAX_NAME, mooring_core::MAX_NAME);
    }
}
