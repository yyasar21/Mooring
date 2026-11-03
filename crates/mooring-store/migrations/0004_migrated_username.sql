-- Schema v4: a v2 `password` / `ssh_key` row without a username no longer carries the visible
-- placeholder '(unset)' written by 0003. The username stays empty and the row is marked
-- `migrated: true`; validation accepts the empty username only while that flag is set, and the
-- next field update must supply one (ADR-0009 §4, handoff a1-rust-core-credentials).
UPDATE credential
SET fields_json = json_set(fields_json, '$.username', '', '$.migrated', json('true'))
WHERE kind IN ('user_password', 'ssh_key')
  AND json_extract(fields_json, '$.username') = '(unset)';
