-- Review L4: the `secure_delete` pragma wipes freed b-tree pages, but FTS5 keeps deleted
-- tokens in its segment pages until a merge. The FTS5 'secure-delete' option (SQLite >= 3.42)
-- removes them on delete for tables that know the deleted tokens. Persistent (`search_config`).
-- The `search` table is contentless_delete = 1 (tombstones), where the option has no effect;
-- `Store::checkpoint` / `close` / drop therefore also run an FTS 'optimize' merge. The option
-- is kept so that any later rebuild without contentless_delete is covered from the start.
INSERT INTO search (search, rank) VALUES ('secure-delete', 1);
