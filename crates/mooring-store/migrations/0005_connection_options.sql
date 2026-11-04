-- Schema v5 (ADR-0011 §IPC, ADR-0012, ADR-0013): per-protocol connection options. The column
-- holds the inner options object of `mooring_core::options::ProtocolOptions` for the row's
-- protocol (camelCase, deny_unknown_fields). '{}' is the default for every protocol: RDP and
-- VNC read it as their owner defaults, web needs a URL before it validates. The store
-- re-validates the text on every read; the CHECK only keeps it a JSON object of <= 128 KiB.
ALTER TABLE connection ADD COLUMN options_json TEXT NOT NULL DEFAULT '{}'
    CHECK (json_valid(options_json)
           AND json_type(options_json) = 'object'
           AND length(CAST(options_json AS BLOB)) <= 131072);
