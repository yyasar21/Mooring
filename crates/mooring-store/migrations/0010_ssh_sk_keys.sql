-- mooring:foreign_keys=off
-- Schema v10 (ADR-0024): the `ssh_sk_key` kind (FIDO2 / hardware-key OpenSSH keys). The
-- `kind` CHECK changes, so `credential` is rebuilt (SQLite 12-step procedure, as in 0003 /
-- 0007 / 0009); the runner turns foreign keys off for this script and requires
-- `PRAGMA foreign_key_check` to be empty before COMMIT.
--
-- Existing `ssh_key` rows whose sealed `private_key` is an `sk-*` key handle cannot be told
-- apart in SQL (the key is sealed): the flag below makes the first unlock inspect them and
-- convert them to `ssh_sk_key` (`Store::convert_sk_keys`, audited `credential_sk_converted`).

CREATE TABLE credential_new (
    id          TEXT PRIMARY KEY NOT NULL,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN (
                    'user_password', 'domain_user', 'ssh_key', 'ssh_agent', 'x509',
                    'api_token', 'oauth_client', 'kubeconfig', 'kube_token', 'vsphere_user',
                    'vnc_password', 'vnc_user_password', 'prompt', 'external_ref',
                    'sudo_become', 'vault_approle', 's3_access_key', 'ssh_sk_key',
                    'bitwarden_access_token')),
    fields_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(fields_json)),
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
INSERT INTO credential_new (id, name, kind, fields_json, created_at, updated_at)
SELECT id, name, kind, fields_json, created_at, updated_at FROM credential;
DROP TABLE credential;
ALTER TABLE credential_new RENAME TO credential;

INSERT INTO setting (key, value)
SELECT 'credential_sk_scan_pending', '1'
WHERE EXISTS (SELECT 1 FROM credential WHERE kind = 'ssh_key');
