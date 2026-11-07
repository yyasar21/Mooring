-- mooring:foreign_keys=off
-- Schema v9 (ADR-0026): the `bitwarden_access_token` kind, secret sources of kind
-- `onepassword` (Connect) and `bitwarden` (Secrets Manager via `bws`), and the per-connection
-- role `certificate` (a Vault `ssh_sign` reference on the SSH key credential). Three CHECKs
-- change, so `credential`, `secret_source` and `connection_credential` are rebuilt (SQLite
-- 12-step procedure, as in 0003 / 0007); the runner turns foreign keys off for this script and
-- requires `PRAGMA foreign_key_check` to be empty before COMMIT. ADR-0024's `ssh_sk_key` kind
-- follows in a later script.

CREATE TABLE credential_new (
    id          TEXT PRIMARY KEY NOT NULL,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN (
                    'user_password', 'domain_user', 'ssh_key', 'ssh_agent', 'x509',
                    'api_token', 'oauth_client', 'kubeconfig', 'kube_token', 'vsphere_user',
                    'vnc_password', 'vnc_user_password', 'prompt', 'external_ref',
                    'sudo_become', 'vault_approle', 's3_access_key',
                    'bitwarden_access_token')),
    fields_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(fields_json)),
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
INSERT INTO credential_new (id, name, kind, fields_json, created_at, updated_at)
SELECT id, name, kind, fields_json, created_at, updated_at FROM credential;
DROP TABLE credential;
ALTER TABLE credential_new RENAME TO credential;

-- `namespace` and the `approle` / `oidc` methods stay Vault-only (checked in Rust as well);
-- 1Password and Bitwarden log in with a token credential (`api_token` /
-- `bitwarden_access_token`).
CREATE TABLE secret_source_new (
    id            TEXT PRIMARY KEY NOT NULL,
    name          TEXT NOT NULL,
    kind          TEXT NOT NULL CHECK (kind IN ('vault', 'onepassword', 'bitwarden')),
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
    CHECK ((auth_method = 'oidc') = (oidc_role IS NOT NULL)),
    CHECK (kind = 'vault' OR (auth_method = 'token' AND namespace IS NULL))
);
INSERT INTO secret_source_new (id, name, kind, address, namespace, auth_method, auth_mount,
                               credential_id, oidc_role, options_json, created_at, updated_at)
SELECT id, name, kind, address, namespace, auth_method, auth_mount, credential_id, oidc_role,
       options_json, created_at, updated_at FROM secret_source;
DROP TABLE secret_source;
ALTER TABLE secret_source_new RENAME TO secret_source;
CREATE INDEX secret_source_credential_idx ON secret_source (credential_id);

CREATE TABLE connection_credential_new (
    connection_id TEXT NOT NULL REFERENCES connection (id) ON DELETE CASCADE,
    role          TEXT NOT NULL CHECK (role IN ('gateway', 'become', 'certificate')),
    credential_id TEXT NOT NULL REFERENCES credential (id) ON DELETE CASCADE,
    PRIMARY KEY (connection_id, role)
) WITHOUT ROWID;
INSERT INTO connection_credential_new (connection_id, role, credential_id)
SELECT connection_id, role, credential_id FROM connection_credential;
DROP TABLE connection_credential;
ALTER TABLE connection_credential_new RENAME TO connection_credential;
CREATE INDEX connection_credential_cred_idx ON connection_credential (credential_id);
