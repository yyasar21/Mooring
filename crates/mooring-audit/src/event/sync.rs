//! Vault sync (ADR-0017, A3 S2).
//!
//! `sync_variants!` appends this phase's `AuditEvent` variants to the chain assembled in
//! `event/mod.rs`; the wire names come from the enum's `serde` attributes there.

macro_rules! sync_variants {
    ([$next:ident $(, $rest:ident)*] $($acc:tt)*) => {
        $next! { [$($rest),*] $($acc)*
        /// Sync settings stored (`sync_configure`). Never the access key or its secrets.
        #[serde(rename = "sync.configured")]
        SyncConfigured {
            /// Endpoint origin (`https://host[:port]`).
            endpoint: String,
            /// Bucket name.
            bucket: String,
            /// Key prefix.
            prefix: String,
            /// Credential id (`s3_access_key`).
            credential: String,
            /// Interval of the background run; `None` = manual only.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            interval_minutes: Option<u32>,
        },
        /// Sync turned off on this device (`sync_disable`).
        #[serde(rename = "sync.disabled")]
        SyncDisabled {
            /// Whether the remote objects were deleted too.
            delete_remote: bool,
        },
        /// Local changes published as generation `counter`.
        #[serde(rename = "sync.pushed")]
        SyncPushed {
            /// Generation.
            counter: u64,
            /// Blob size.
            bytes: u64,
        },
        /// A remote generation fast-forwarded onto this device.
        #[serde(rename = "sync.pulled")]
        SyncPulled {
            /// Generation.
            counter: u64,
        },
        /// Both sides changed: merged and published.
        #[serde(rename = "sync.merged")]
        SyncMerged {
            /// Generation published.
            counter: u64,
            /// Conflict copies / reported conflicts.
            conflicts: u64,
        },
        /// Hard stop: diverging histories.
        #[serde(rename = "sync.fork_detected")]
        SyncForkDetected {
            /// Remote generation.
            remote: u64,
            /// Last generation this device saw.
            last: u64,
        },
        /// Hard stop: the remote generation went backwards (never applied).
        #[serde(rename = "sync.rollback_detected")]
        SyncRollbackDetected {
            /// Remote generation (0 = vanished).
            remote: u64,
            /// Last generation this device saw.
            last: u64,
        },
        /// A fork or rollback resolved by the user (`sync_resolve_fork`); the other side is gone.
        #[serde(rename = "sync.fork_resolved")]
        SyncForkResolved {
            /// `local` | `remote`.
            keep: String,
            /// Generation after the resolution.
            counter: u64,
        },
        /// This device joined a synced vault (`vault_join`).
        #[serde(rename = "sync.joined")]
        SyncJoined {
            /// Vault id.
            vault: String,
            /// Generation pulled.
            counter: u64,
        },
        }
    };
}
pub(crate) use sync_variants;
