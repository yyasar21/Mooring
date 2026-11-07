//! A5: biometric unlock (ADR-0022 §2) and vault export / import (ADR-0023 §2). Platforms,
//! reasons, modes and counts only: never key material, a file name, a path or a passphrase
//! outcome beyond success / refusal.
//!
//! `a5_variants!` appends this phase's `AuditEvent` variants to the chain assembled in
//! `event/mod.rs`; the wire names come from the enum's `serde` attributes there.

macro_rules! a5_variants {
    ([$next:ident $(, $rest:ident)*] $($acc:tt)*) => {
        $next! { [$($rest),*] $($acc)*
        /// Biometric unlock was enrolled (`biometric_enroll`): the wrap key now lives behind
        /// the OS gesture (`platform`: `macos` | `windows`).
        #[serde(rename = "vault.biometric_enabled")]
        BiometricEnabled {
            /// OS.
            platform: String,
        },
        /// The vault was unlocked through the OS biometric prompt.
        #[serde(rename = "vault.unlock_biometric")]
        BiometricUnlocked {
            /// OS.
            platform: String,
        },
        /// A biometric unlock attempt failed or was cancelled (`reason`: `cancelled` |
        /// `failed` | `biometry_changed` | `not_found`).
        #[serde(rename = "vault.biometric_failed")]
        BiometricFailed {
            /// OS.
            platform: String,
            /// Why.
            reason: String,
        },
        /// Biometric unlock was switched off without the password (ADR-0022 §2 auto-disable;
        /// `reason`: `failed_attempts` | `password_changed` | `biometry_changed` |
        /// `vault_rotated`). The OS item or key is deleted at once.
        #[serde(rename = "vault.biometric_suspended")]
        BiometricSuspended {
            /// Why.
            reason: String,
        },
        /// Biometric unlock was switched off by the user (`biometric_disable`, password).
        #[serde(rename = "vault.biometric_disabled")]
        BiometricDisabled,
        /// A legacy ADR-0006 keyring wrap (the `keyring` crate, never wired to a command) was
        /// found in the header and dropped on a password unlock (ADR-0022, owner decision 25).
        #[serde(rename = "keyring.removed")]
        KeyringRemoved,
        /// A backup file was written (`vault_export_age`). Counts only; no path.
        #[serde(rename = "vault.exported")]
        VaultExported {
            /// Credentials in the file.
            credentials: u64,
            /// Connections in the file.
            connections: u64,
            /// Folders in the file.
            folders: u64,
        },
        /// A backup file was applied (`vault_import_age`): `mode` is `merge` | `replace`
        /// (`replace` is the warning row of ADR-0023 §2), `foreign` whether the source vault
        /// differed from ours (secrets re-sealed).
        #[serde(rename = "vault.import")]
        VaultImported {
            /// `merge` | `replace`.
            mode: String,
            /// Source vault differed.
            foreign: bool,
            /// Records added.
            added: u64,
            /// Records updated.
            updated: u64,
            /// Conflicts reported (both copies kept).
            conflicts: u64,
            /// Records skipped.
            skipped: u64,
        },
        /// A backup file was refused (`code` is the IPC error code, e.g. `vault.import_format`).
        #[serde(rename = "vault.import_refused")]
        VaultImportRefused {
            /// Error code.
            code: String,
        },
        }
    };
}
pub(crate) use a5_variants;
