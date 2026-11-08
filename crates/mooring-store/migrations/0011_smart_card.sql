-- mooring:foreign_keys=off
-- Schema v11 (ADR-0027 §2): the `smart_card` kind (smart card / PIV key; nothing is sealed,
-- the PIN is asked at every use). The `kind` CHECK changes, so `credential` is rebuilt (SQLite
-- 12-step procedure, as in 0003 / 0007 / 0009 / 0010); the runner turns foreign keys off for
-- this script and requires `PRAGMA foreign_key_check` to be empty before COMMIT.

CREATE TABLE credential_new (
    id          TEXT PRIMARY KEY NOT NULL,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN (
                    'user_password', 'domain_user', 'ssh_key', 'ssh_agent', 'x509',
                    'api_token', 'oauth_client', 'kubeconfig', 'kube_token', 'vsphere_user',
                    'vnc_password', 'vnc_user_password', 'prompt', 'external_ref',
                    'sudo_become', 'vault_approle', 's3_access_key', 'ssh_sk_key',
                    'bitwarden_access_token', 'smart_card')),
    fields_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(fields_json)),
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
INSERT INTO credential_new (id, name, kind, fields_json, created_at, updated_at)
SELECT id, name, kind, fields_json, created_at, updated_at FROM credential;
DROP TABLE credential;
ALTER TABLE credential_new RENAME TO credential;
