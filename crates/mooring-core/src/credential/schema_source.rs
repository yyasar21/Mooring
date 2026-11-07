//! Kind rows for non-connection consumers: the Vault `AppRole` login of a secret source
//! (ADR-0016 §1), the Bitwarden Secrets Manager access token (ADR-0026 §4) and the S3 sync key
//! (ADR-0017 §4). None is valid for any protocol.

use super::{ph, plain, sec, v, Consumer, FieldFormat::Text, KindSchema, K, KIB};

/// `vault_approle`: `role_id` and `secret_id`, both sealed (a `role_id` is half the login).
pub(super) const VAULT_APPROLE: KindSchema = KindSchema {
    kind: K::VaultApprole,
    label: "Vault AppRole",
    group: "Secret sources",
    protocols: &[],
    consumers: &[Consumer::SecretSource],
    supports_otp: false,
    fields: &[
        sec(plain("role_id", "Role ID", true, v(256, Text)), false),
        sec(plain("secret_id", "Secret ID", true, v(4 * KIB, Text)), false),
    ],
};

/// `s3_access_key`: `access_key_id`, `region?`; secrets `secret_access_key`, `session_token?`.
pub(super) const S3_ACCESS_KEY: KindSchema = KindSchema {
    kind: K::S3AccessKey,
    label: "S3 access key",
    group: "Sync",
    protocols: &[],
    consumers: &[Consumer::Sync],
    supports_otp: false,
    fields: &[
        ph(plain("access_key_id", "Access key ID", true, v(128, Text)), "AKIA…"),
        ph(plain("region", "Region", false, v(64, Text)), "us-east-1"),
        sec(plain("secret_access_key", "Secret access key", true, v(256, Text)), false),
        ph(
            sec(plain("session_token", "Session token", false, v(8 * KIB, Text)), false),
            "optional",
        ),
    ],
};

/// `bitwarden_access_token`: the `bws` machine access token (sealed; passed to the child
/// process in `BWS_ACCESS_TOKEN` only, ADR-0026 §4).
pub(super) const BITWARDEN_ACCESS_TOKEN: KindSchema = KindSchema {
    kind: K::BitwardenAccessToken,
    label: "Bitwarden access token",
    group: "Secret sources",
    protocols: &[],
    consumers: &[Consumer::SecretSource],
    supports_otp: false,
    fields: &[sec(plain("access_token", "Access token", true, v(4 * KIB, Text)), false)],
};
