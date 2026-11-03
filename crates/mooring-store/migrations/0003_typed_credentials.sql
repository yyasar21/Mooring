-- mooring:foreign_keys=off
-- Schema v3 (ADR-0009): typed credentials. The `kind` CHECK changes, so `credential` is
-- rebuilt (SQLite 12-step procedure). The runner turns foreign keys off before BEGIN for this
-- script (the directive above), so dropping the old table does not fire ON DELETE SET NULL on
-- folder/connection references, and runs `PRAGMA foreign_key_check` before COMMIT.

CREATE TABLE credential_new (
    id          TEXT PRIMARY KEY NOT NULL,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN (
                    'user_password', 'domain_user', 'ssh_key', 'ssh_agent', 'x509',
                    'api_token', 'oauth_client', 'kubeconfig', 'kube_token', 'vsphere_user',
                    'vnc_password', 'vnc_user_password', 'prompt', 'external_ref',
                    'sudo_become')),
    fields_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(fields_json)),
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

-- Row move: password -> user_password, ssh_key -> ssh_key, certificate -> x509. The legacy
-- username goes into fields_json. `user_password` and `ssh_key` require a username; a legacy
-- row without one gets the visible placeholder '(unset)' for the user to correct (handoff:
-- Decision needed). x509 `cert_pem` is still sealed here, so it holds a placeholder until
-- `Store::reseal_legacy` moves the certificate into it on the first unlock.
INSERT INTO credential_new (id, name, kind, fields_json, created_at, updated_at)
SELECT id, name,
       CASE kind WHEN 'password' THEN 'user_password'
                 WHEN 'ssh_key' THEN 'ssh_key'
                 ELSE 'x509' END,
       CASE WHEN kind = 'certificate' THEN
                CASE WHEN username IS NULL OR trim(username) = ''
                     THEN json_object('cert_pem', '(sealed until the next unlock)')
                     ELSE json_object('username', trim(username),
                                      'cert_pem', '(sealed until the next unlock)') END
            ELSE json_object('username', coalesce(nullif(trim(username), ''), '(unset)')) END,
       created_at, updated_at
FROM credential;

-- One sealed secret per row. AAD = credential id || 0x1F || name (ADR-0002); legacy rows keep
-- the names they were sealed under ('secret' / 'secret2') until the first unlock reseals them.
CREATE TABLE credential_secret (
    credential_id TEXT NOT NULL REFERENCES credential (id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    sealed        BLOB NOT NULL,
    PRIMARY KEY (credential_id, name)
) WITHOUT ROWID;

INSERT INTO credential_secret (credential_id, name, sealed)
SELECT id, 'secret', secret FROM credential;
INSERT INTO credential_secret (credential_id, name, sealed)
SELECT id, 'secret2', secret2 FROM credential WHERE secret2 IS NOT NULL;

DROP TABLE credential;
ALTER TABLE credential_new RENAME TO credential;

-- Per-connection overrides of the effective credential's username / domain (ADR-0009 §3).
ALTER TABLE connection ADD COLUMN username_override TEXT;
ALTER TABLE connection ADD COLUMN domain_override TEXT;

-- Secondary roles, per connection only (no inheritance yet).
CREATE TABLE connection_credential (
    connection_id TEXT NOT NULL REFERENCES connection (id) ON DELETE CASCADE,
    role          TEXT NOT NULL CHECK (role IN ('gateway', 'become')),
    credential_id TEXT NOT NULL REFERENCES credential (id) ON DELETE CASCADE,
    PRIMARY KEY (connection_id, role)
) WITHOUT ROWID;
CREATE INDEX connection_credential_cred_idx ON connection_credential (credential_id);

INSERT INTO setting (key, value)
SELECT 'credential_reseal_pending', '1'
WHERE EXISTS (SELECT 1 FROM credential_secret WHERE name IN ('secret', 'secret2'));
