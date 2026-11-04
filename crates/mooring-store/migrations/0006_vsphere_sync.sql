-- Schema v6 (ADR-0015 §2): synced, read-only vSphere subtrees.
--
-- `sync_source` is the id of the vCenter connection that owns the row; it is set on the
-- synced root folder (external_id NULL) and on every folder and VM connection below it.
-- Deleting the vCenter connection deletes its subtree. `external_id` is the vCenter
-- managed-object id (`datacenter-3`, `domain-c8`, `standalone-datacenter-3`, `host-7`,
-- `vm-42`), unique per source. `sync_kind` is the inventory level, `sync_data` the last
-- fetched item (name as vCenter reports it, power state, CPU, memory: inventory-class
-- metadata, no secrets), `missing_streak` the consecutive refreshes the item was absent.
-- Ordinary edits inside a synced subtree are refused by the store (`tree.synced_readonly`);
-- the user's overlays (credential, tags, username/domain overrides, role credentials,
-- options, a folder's default credential) live in the ordinary columns and survive refreshes.

ALTER TABLE folder ADD COLUMN sync_source TEXT REFERENCES connection (id) ON DELETE CASCADE;
ALTER TABLE folder ADD COLUMN external_id TEXT;
ALTER TABLE folder ADD COLUMN sync_kind TEXT
    CHECK (sync_kind IS NULL OR sync_kind IN ('datacenter', 'cluster', 'standalone_hosts', 'host'));
ALTER TABLE folder ADD COLUMN sync_data TEXT
    CHECK (sync_data IS NULL OR (json_valid(sync_data) AND length(CAST(sync_data AS BLOB)) <= 4096));
ALTER TABLE folder ADD COLUMN missing_streak INTEGER NOT NULL DEFAULT 0
    CHECK (missing_streak BETWEEN 0 AND 255);
CREATE INDEX folder_sync_source_idx ON folder (sync_source);
CREATE UNIQUE INDEX folder_sync_external_idx ON folder (sync_source, external_id)
    WHERE sync_source IS NOT NULL AND external_id IS NOT NULL;
-- One synced root per vCenter connection.
CREATE UNIQUE INDEX folder_sync_root_idx ON folder (sync_source)
    WHERE sync_source IS NOT NULL AND external_id IS NULL;

ALTER TABLE connection ADD COLUMN sync_source TEXT REFERENCES connection (id) ON DELETE CASCADE;
ALTER TABLE connection ADD COLUMN external_id TEXT;
ALTER TABLE connection ADD COLUMN sync_state TEXT
    CHECK (sync_state IS NULL OR sync_state IN ('present', 'missing'));
ALTER TABLE connection ADD COLUMN sync_data TEXT
    CHECK (sync_data IS NULL OR (json_valid(sync_data) AND length(CAST(sync_data AS BLOB)) <= 4096));
ALTER TABLE connection ADD COLUMN missing_streak INTEGER NOT NULL DEFAULT 0
    CHECK (missing_streak BETWEEN 0 AND 255);
CREATE INDEX connection_sync_source_idx ON connection (sync_source);
CREATE UNIQUE INDEX connection_sync_external_idx ON connection (sync_source, external_id)
    WHERE sync_source IS NOT NULL;
