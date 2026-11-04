-- mooring:foreign_keys=off
-- Schema v7 (ADR-0016 §1, ADR-0017 §4): two new credential kinds (`vault_approle`,
-- `s3_access_key`) and the `secret_source` table. The `kind` CHECK changes, so `credential` is
-- rebuilt (SQLite 12-step procedure, as in 0003); the runner turns foreign keys off for this
-- script and requires `PRAGMA foreign_key_check` to be empty before COMMIT.
-- Version 6 is reserved for `0006_vsphere_sync.sql` (A3 V2).

CREATE TABLE credential_new (
    id          TEXT PRIMARY KEY NOT NULL,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN (
                    'user_password', 'domain_user', 'ssh_key', 'ssh_agent', 'x509',
                    'api_token', 'oauth_client', 'kubeconfig', 'kube_token', 'vsphere_user',
                    'vnc_password', 'vnc_user_password', 'prompt', 'external_ref',
                    'sudo_become', 'vault_approle', 's3_access_key')),
    fields_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(fields_json)),
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

INSERT INTO credential_new (id, name, kind, fields_json, created_at, updated_at)
SELECT id, name, kind, fields_json, created_at, updated_at FROM credential;

DROP TABLE credential;
ALTER TABLE credential_new RENAME TO credential;

-- A Vault / OpenBao server that `external_ref` credentials resolve from. No secret material:
-- the login is a credential id (`api_token` for token, `vault_approle` for approle) or an OIDC
-- role. A credential in use by a source cannot be deleted (RESTRICT; the store reports
-- `InUse` before SQLite does).
CREATE TABLE secret_source (
    id            TEXT PRIMARY KEY NOT NULL,
    name          TEXT NOT NULL,
    kind          TEXT NOT NULL CHECK (kind = 'vault'),
    address       TEXT NOT NULL CHECK (length(address) BETWEEN 1 AND 2048),
    namespace     TEXT CHECK (namespace IS NULL OR length(namespace) BETWEEN 1 AND 256),
    auth_method   TEXT NOT NULL CHECK (auth_method IN ('token', 'approle', 'oidc')),
    auth_mount    TEXT NOT NULL CHECK (length(auth_mount) BETWEEN 1 AND 256),
    credential_id TEXT REFERENCES credential (id) ON DELETE RESTRICT,
    oidc_role     TEXT CHECK (oidc_role IS NULL OR length(oidc_role) BETWEEN 1 AND 256),
    options_json  TEXT NOT NULL DEFAULT '{}'
                  CHECK (json_valid(options_json)
                         AND json_type(options_json) = 'object'
                         AND length(CAST(options_json AS BLOB)) <= 131072),
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    CHECK ((auth_method = 'oidc') = (credential_id IS NULL)),
    CHECK ((auth_method = 'oidc') = (oidc_role IS NOT NULL))
);
CREATE INDEX secret_source_credential_idx ON secret_source (credential_id);
