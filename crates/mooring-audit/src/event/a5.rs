//! A5: biometric unlock (ADR-0022 §2), vault export / import (ADR-0023 §2) and FIDO2 SSH
//! keys (ADR-0024). Platforms,
//! reasons, modes and counts only: never key material, a file name, a path or a passphrase
//! outcome beyond success / refusal.
//! A5 also carries Move to Applications (ADR-0028 §2): locations, targets, flags and codes
//! only — no path ever reaches those rows (the volume name and the user's home are personal data).
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
        /// The move dialog was shown to a normally started process.
        #[serde(rename = "install.move_offered")]
        InstallMoveOffered {
            /// `disk_image` | `downloads`.
            location: String,
        },
        /// A copy relaunched by a move started (written by the new copy).
        #[serde(rename = "install.moved")]
        InstallMoved {
            /// `applications` | `user_applications` | `other`.
            target: String,
            /// An older copy of ours was replaced.
            replaced: bool,
            /// The disk image the old copy ran from was detached.
            detached: bool,
        },
        /// The user refused the move; `remember` = "Not now" (not offered again for this version).
        #[serde(rename = "install.move_declined")]
        InstallMoveDeclined {
            /// Stored for this version.
            remember: bool,
        },
        /// The move did not happen (`code`: `install.not_ours` | `install.running` |
        /// `install.copy_failed` | `install.not_writable`).
        #[serde(rename = "install.move_failed")]
        InstallMoveFailed {
            /// Error code.
            code: String,
        },
        /// ADR-0024: one FIDO2 (`sk-*`) sign-in attempt. Key fingerprint only; `outcome` is
        /// `ok` | `refused` | `not_in_agent` | `no_agent` | `touch_timeout` | `no_presence`
        /// | `bad_signature` | `bad_key` | `helper_disabled` | `helper_missing` |
        /// `helper_version` | `helper_failed`.
        #[serde(rename = "session.auth_sk")]
        SessionSkAuth {
            /// Connection id.
            connection: String,
            /// `SHA256:` of the key.
            fingerprint: String,
            /// `agent` | `helper`.
            backend: String,
            /// Outcome.
            outcome: String,
        },
        /// ADR-0024 §1: an `ssh_key` holding an `sk-*` key handle became `ssh_sk_key`.
        #[serde(rename = "credential.sk_converted")]
        CredentialSkConverted {
            /// Credential id.
            id: String,
        },
        /// ADR-0027: one RD Gateway tunnel attempt. `auth`: `ntlm` | `basic` | `none`
        /// (`if_unreachable` went direct); `outcome`: `ok` | `direct` | `auth_failed` |
        /// `refused` | `unsupported` | `trust` | `protocol` | `network`.
        #[serde(rename = "session.rdp.gateway")]
        SessionRdpGateway {
            /// Connection id.
            connection: String,
            /// Gateway `host:port`.
            host: String,
            /// Gateway authentication.
            auth: String,
            /// Outcome.
            outcome: String,
            /// Tunnel id the gateway assigned (`0` before it did).
            tunnel_id: u32,
        },
        /// ADR-0027: HTTP Basic was sent to the gateway (`allowBasicGateway`): a warning row.
        #[serde(rename = "session.rdp.gateway_basic")]
        SessionRdpGatewayBasic {
            /// Connection id.
            connection: String,
            /// Gateway `host:port`.
            host: String,
        },
        /// ADR-0027 §2: a smart-card PIN was asked (`outcome`: `entered` | `cancelled`); never
        /// the PIN.
        #[serde(rename = "credential.pin_prompted")]
        CredentialPinPrompted {
            /// Connection id.
            connection: String,
            /// `SHA256:` of the card key.
            fingerprint: String,
            /// Outcome.
            outcome: String,
        },
        }
    };
}
pub(crate) use a5_variants;
