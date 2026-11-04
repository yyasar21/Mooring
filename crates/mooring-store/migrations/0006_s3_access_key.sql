-- mooring:foreign_keys=off
-- Schema v6 (ADR-0017 §4): the `s3_access_key` credential kind (vault sync). The `kind` CHECK
-- changes, so `credential` is rebuilt with the SQLite 12-step procedure, as in 0003. The
-- runner turns foreign keys off for this script and checks them before COMMIT.

CREATE TABLE credential_new (
    id          TEXT PRIMARY KEY NOT NULL,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN (
                    'user_password', 'domain_user', 'ssh_key', 'ssh_agent', 'x509',
                    'api_token', 'oauth_client', 'kubeconfig', 'kube_token', 'vsphere_user',
                    'vnc_password', 'vnc_user_password', 'prompt', 'external_ref',
                    'sudo_become', 's3_access_key')),
    fields_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(fields_json)),
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

INSERT INTO credential_new (id, name, kind, fields_json, created_at, updated_at)
SELECT id, name, kind, fields_json, created_at, updated_at FROM credential;

DROP TABLE credential;
ALTER TABLE credential_new RENAME TO credential;
