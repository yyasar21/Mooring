-- Schema v8 (ADR-0025 §1): jump hosts. The chain is explicit on the leaf connection: position
-- 0 is reached directly, the target through the last position. A hop's own chain is ignored
-- (no recursion). Deleting a connection that others use as a hop is refused: the store reports
-- `InUse { kind: "connection" }` first, and SQLite's NO ACTION check backs it up at the end of
-- the statement (the ADR's RESTRICT, but deferred to statement end so a folder delete whose
-- subtree holds a whole chain, hop and leaf, cascades cleanly). Deleting the leaf removes its
-- chain (CASCADE). Depth, self, duplicates and the hop's protocol are checked in Rust.
-- The ADR names this script 0010; the sequence here is contiguous, so it is 0008.

CREATE TABLE connection_via (
    connection_id     TEXT NOT NULL REFERENCES connection (id) ON DELETE CASCADE,
    position          INTEGER NOT NULL CHECK (position BETWEEN 0 AND 2),
    hop_connection_id TEXT NOT NULL REFERENCES connection (id) ON DELETE NO ACTION,
    PRIMARY KEY (connection_id, position),
    CHECK (connection_id <> hop_connection_id)
);
CREATE INDEX connection_via_hop_idx ON connection_via (hop_connection_id);
