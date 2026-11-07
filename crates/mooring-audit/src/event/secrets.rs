//! External secret sources (ADR-0016 E2): ids, names, counts, categories; never a value.
//!
//! `secrets_variants!` appends this phase's `AuditEvent` variants to the chain assembled in
//! `event/mod.rs`; the wire names come from the enum's `serde` attributes there.

macro_rules! secrets_variants {
    ([$next:ident $(, $rest:ident)*] $($acc:tt)*) => {
        $next! { [$($rest),*] $($acc)*
        /// Logged in to a secret source, or renewed its token (`secret.login`).
        SecretLogin {
            /// Source id.
            source: String,
            /// `token` | `approle` | `oidc` | `renew`.
            method: String,
            /// Cached lifetime (s).
            ttl: u64,
        },
        /// An `external_ref` was resolved (`secret.resolved`; the reference is inventory class).
        SecretResolved {
            /// Connection id, when resolved for a connect.
            connection: Option<String>,
            /// The `external_ref` credential.
            credential: String,
            /// Source id.
            source: String,
            /// `<mount>/<path>`.
            reference: String,
            /// KV version read.
            version: u64,
            /// Target kind.
            target_kind: String,
            /// Field and secret names filled.
            fields: Vec<String>,
            /// ADR-0026: `vault` | `onepassword` | `bitwarden` (absent on A3 rows).
            #[serde(default, skip_serializing_if = "Option::is_none")]
            provider: Option<String>,
            /// ADR-0026: `kv2` | `database` | `ssh_sign` | `ssh_otp` | `pki` (absent on A3 rows).
            #[serde(default, skip_serializing_if = "Option::is_none")]
            engine: Option<String>,
        },
        /// A dynamic secret came with a lease (`secret.lease_issued`, ADR-0026 §2).
        SecretLeaseIssued {
            /// Session id; `None` for a test resolve (revoked at once).
            session: Option<String>,
            /// Source id.
            source: String,
            /// Engine.
            engine: String,
            /// Lease duration (s).
            ttl: u64,
            /// Renewable.
            renewable: bool,
        },
        /// A lease was renewed at 2/3 of its TTL (`secret.lease_renewed`).
        SecretLeaseRenewed {
            /// Session id.
            session: String,
            /// Source id.
            source: String,
            /// New duration (s).
            ttl: u64,
        },
        /// A renewal failed; the session keeps running (`secret.lease_renew_failed`).
        SecretLeaseRenewFailed {
            /// Session id.
            session: String,
            /// Source id.
            source: String,
            /// Failure category.
            category: String,
        },
        /// A lease (or a PKI certificate) was revoked, best effort (`secret.lease_revoked`).
        SecretLeaseRevoked {
            /// Session id; `None` for a test resolve.
            session: Option<String>,
            /// Source id.
            source: String,
            /// `closed` | `locked` | `exit` | `reconnect` | `test` | `refused`.
            reason: String,
            /// The server confirmed.
            ok: bool,
        },
        /// The `bws` CLI ran (`secret.tool_spawned`; never its output).
        SecretToolSpawned {
            /// `bitwarden`.
            provider: String,
            /// `version` | `secret_get` | `secret_list` | `project_list`.
            action: String,
            /// Exit code (`None`: killed or ended by a signal).
            exit: Option<i32>,
        },
        /// The pinned `bws` binary changed (`secret.tool_changed`, warning, R-SEC-CLI).
        SecretToolChanged {
            /// `bitwarden`.
            provider: String,
            /// Hex SHA-256 of the new binary.
            sha256: String,
        },
        /// A login, resolution or OIDC flow failed (`secret.failed`).
        SecretFailed {
            /// Connection id, when resolving for a connect.
            connection: Option<String>,
            /// Source id.
            source: String,
            /// `network | tls | auth_failed | forbidden | not_found | shape | locked | …`.
            category: String,
        },
        /// A cached token was dropped, and revoked when Mooring minted it (`secret.revoked`).
        SecretRevoked {
            /// Source id.
            source: String,
        },
        /// A source was created, changed or deleted (`secret.source_changed`). Field **names**
        /// only (the fields actually set or changed, review 6 N-42); no values except the
        /// SHA-256 fingerprints of a new `caPem`.
        SecretSourceChanged {
            /// Source id.
            source: String,
            /// Changed field names, or `created` / `deleted`.
            changed: Vec<String>,
            /// `SHA256:<hex>` of every certificate in a new or changed `caPem`.
            #[serde(default, skip_serializing_if = "Vec::is_empty")]
            ca_pem: Vec<String>,
            /// `caPem` or `allowHttp` changed, or an `allowedOrigins` entry was added (a trust
            /// change).
            warning: bool,
        },
        /// A secret-source action was refused (`secret.refused`: OIDC navigation, delete in use).
        SecretRefused {
            /// Source id, when known.
            source: Option<String>,
            /// `oidc_navigation` | `delete` | `resolve` | ….
            action: String,
            /// Error code, or the refused origin of a navigation.
            detail: String,
        },
        /// Refusals of one OIDC window beyond the first 16, counted and written once when the
        /// window closes (`secret.refused_suppressed`, review 6 N-43).
        SecretRefusedSuppressed {
            /// Source id.
            source: String,
            /// `oidc_navigation`.
            action: String,
            /// Refusals that got no row of their own.
            count: u64,
        },
        }
    };
}
pub(crate) use secrets_variants;
