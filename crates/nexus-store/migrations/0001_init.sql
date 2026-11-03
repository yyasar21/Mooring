-- Schema v1 (ADR-0005). Applied inside one transaction by `schema::migrate`;
-- `setting.schema_version` is written by the runner after the last script.
-- All ids are UUID text, timestamps RFC 3339 UTC.

CREATE TABLE setting (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
);

-- Secret columns hold the JSON encoding of `nexus_vault::Sealed`, sealed with
-- record id = credential id and field = column name ("secret" / "secret2").
CREATE TABLE credential (
    id         TEXT PRIMARY KEY NOT NULL,
    name       TEXT NOT NULL,
    kind       TEXT NOT NULL CHECK (kind IN ('password', 'ssh_key', 'certificate')),
    username   TEXT,
    secret     BLOB NOT NULL,
    secret2    BLOB,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE folder (
    id                    TEXT PRIMARY KEY NOT NULL,
    parent_id             TEXT REFERENCES folder (id) ON DELETE CASCADE,
    name                  TEXT NOT NULL,
    default_credential_id TEXT REFERENCES credential (id) ON DELETE SET NULL,
    sort                  INTEGER NOT NULL DEFAULT 0,
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL
);
CREATE INDEX folder_parent_idx ON folder (parent_id);
-- nexus_core::tree invariant: exactly one root folder.
CREATE UNIQUE INDEX folder_single_root_idx ON folder (parent_id IS NULL) WHERE parent_id IS NULL;
CREATE INDEX folder_default_credential_idx ON folder (default_credential_id);

CREATE TABLE connection (
    id            TEXT PRIMARY KEY NOT NULL,
    folder_id     TEXT NOT NULL REFERENCES folder (id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    protocol      TEXT NOT NULL,
    host          TEXT NOT NULL,
    port          INTEGER CHECK (port IS NULL OR port BETWEEN 1 AND 65535),
    credential_id TEXT REFERENCES credential (id) ON DELETE SET NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
CREATE INDEX connection_folder_idx ON connection (folder_id);
CREATE INDEX connection_credential_idx ON connection (credential_id);

CREATE TABLE connection_tag (
    connection_id TEXT NOT NULL REFERENCES connection (id) ON DELETE CASCADE,
    tag           TEXT NOT NULL,
    PRIMARY KEY (connection_id, tag)
) WITHOUT ROWID;

-- Contentless full-text index over connection name + host + tags. The FTS rowid is the
-- connection's implicit rowid; VACUUM may renumber those, so the migration runner rebuilds
-- the index on every open (`schema::rebuild_search`).
CREATE VIRTUAL TABLE search USING fts5 (
    name, host, tags,
    content = '',
    contentless_delete = 1,
    tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TRIGGER connection_search_ai AFTER INSERT ON connection BEGIN
    INSERT INTO search (rowid, name, host, tags)
    VALUES (new.rowid, new.name, new.host,
            (SELECT coalesce(group_concat(tag, ' '), '') FROM connection_tag
             WHERE connection_id = new.id));
END;

CREATE TRIGGER connection_search_au AFTER UPDATE OF name, host ON connection BEGIN
    DELETE FROM search WHERE rowid = old.rowid;
    INSERT INTO search (rowid, name, host, tags)
    VALUES (new.rowid, new.name, new.host,
            (SELECT coalesce(group_concat(tag, ' '), '') FROM connection_tag
             WHERE connection_id = new.id));
END;

CREATE TRIGGER connection_search_ad AFTER DELETE ON connection BEGIN
    DELETE FROM search WHERE rowid = old.rowid;
END;

CREATE TRIGGER connection_tag_search_ai AFTER INSERT ON connection_tag BEGIN
    DELETE FROM search WHERE rowid = (SELECT rowid FROM connection WHERE id = new.connection_id);
    INSERT INTO search (rowid, name, host, tags)
    SELECT c.rowid, c.name, c.host,
           (SELECT coalesce(group_concat(tag, ' '), '') FROM connection_tag
            WHERE connection_id = c.id)
    FROM connection c WHERE c.id = new.connection_id;
END;

CREATE TRIGGER connection_tag_search_ad AFTER DELETE ON connection_tag BEGIN
    DELETE FROM search WHERE rowid = (SELECT rowid FROM connection WHERE id = old.connection_id);
    INSERT INTO search (rowid, name, host, tags)
    SELECT c.rowid, c.name, c.host,
           (SELECT coalesce(group_concat(tag, ' '), '') FROM connection_tag
            WHERE connection_id = c.id)
    FROM connection c WHERE c.id = old.connection_id;
END;
