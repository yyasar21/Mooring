//! Vault lifecycle, credential use, trust decisions, auto-lock policy, the syslog mirror and
//! native-confirmation refusals (A1, ADR-0010, review 6).
//!
//! `vault_variants!` appends this phase's `AuditEvent` variants to the chain assembled in
//! `event/mod.rs`; the wire names come from the enum's `serde` attributes there.

macro_rules! vault_variants {
    ([$next:ident $(, $rest:ident)*] $($acc:tt)*) => {
        $next! { [$($rest),*] $($acc)*
        /// Vault created.
        VaultCreated,
        /// Vault unlocked.
        VaultUnlocked,
        /// Vault locked (`reason`: `user`, `idle`, `screen_lock`, `sleep`).
        VaultLocked {
            /// Why.
            reason: String,
        },
        /// Master password changed.
        PasswordChanged,
        /// A credential was read for use (connect, copy, reveal).
        CredentialUsed {
            /// Credential id.
            credential: String,
            /// `connect` | `copy` | `reveal`.
            purpose: String,
            /// Connection id when relevant.
            connection: Option<String>,
        },
        /// A secret was put on the clipboard (ADR-0009): `name` is the secret name, or `otp` for
        /// a TOTP code. Never the value.
        CredentialCopied {
            /// Credential id.
            credential: String,
            /// Secret name (`password`, `token`, ...) or `otp`.
            name: String,
        },
        /// A TOTP seed was attached to a credential (ADR-0009 security consequences).
        CredentialOtpAttached {
            /// Credential id.
            credential: String,
        },
        /// The user answered a connect-time sign-in form (`prompt` kind). The username is
        /// inventory-class metadata (R-INV), never the password.
        CredentialPrompted {
            /// Connection id.
            connection: String,
            /// Username typed.
            username: String,
        },
        /// Credentials migrated from schema v2 were re-sealed under their ADR-0009 secret names
        /// on unlock. Written only when `count > 0`.
        CredentialResealed {
            /// How many credentials were converted.
            count: u64,
        },
        /// A `become` (sudo / su / doas) escalation was refused by the server and interrupted; the
        /// session stayed the login user (review 3, M-6).
        BecomeFailed {
            /// Connection id.
            connection: String,
        },
        /// Trust decision (host key / certificate) recorded.
        TrustDecision {
            /// Host.
            host: String,
            /// Fingerprint presented by the host.
            fingerprint: String,
            /// `accepted` | `accepted_session_only` | `rejected` | `changed`.
            decision: String,
            /// For `changed`: the stored fingerprint the host no longer matches (review 2, L-6).
            /// Absent otherwise, so older entries keep their canonical bytes.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            expected: Option<String>,
        },
        /// The auto-lock policy was changed (`autolock_set`).
        VaultPolicyChanged {
            /// Idle timeout in minutes; `None` = idle trigger off.
            idle_minutes: Option<u32>,
            /// Lock on OS screen lock.
            on_screen_lock: bool,
            /// Lock on OS sleep.
            on_sleep: bool,
            /// Lock when the main window is hidden / loses focus.
            on_window_hidden: bool,
        },
        /// The syslog mirror configuration was changed (`syslog_set`). The host is not a secret
        /// (inventory-class, like a connection host) and is recorded so a redirected mirror is
        /// visible in the chain.
        AuditSyslogChanged {
            /// Mirror on or off.
            enabled: bool,
            /// Collector host.
            host: String,
            /// Collector port.
            port: u16,
            /// `udp` | `tcp` | `tls`.
            transport: String,
            /// Syslog facility 0..=23.
            facility: u8,
        },
        /// The app started with a stored syslog configuration (review 4, L-18). Recorded after the
        /// mirror started when `enabled`, so the collector sees each start; with `enabled: false`
        /// it is the "disabled at startup" entry that makes an edited plaintext setting visible in
        /// the chain.
        AuditSyslogStarted {
            /// Whether the stored configuration has the mirror on.
            enabled: bool,
            /// Collector host.
            host: String,
            /// Collector port.
            port: u16,
            /// `udp` | `tcp` | `tls`.
            transport: String,
        },
        /// Hourly liveness entry while the mirror runs (L-18): collectors alert when it is missing.
        AuditHeartbeat {
            /// Heartbeat number since this process started the mirror loop (1, 2, ...).
            seq: u64,
        },
        /// A trust file holds more than one fingerprint for one `host:port` after a sync apply
        /// (review 6 L-35, `trust_conflict`): two devices accepted different certificates. Names
        /// only; nothing is resolved automatically.
        TrustConflict {
            /// Trust file name (`known_rdp_certs`, …).
            file: String,
            /// `host:port` of the user's connection.
            host: String,
        },
        /// A Rust-native confirmation was refused without a dialog (review 6 M-16,
        /// `confirm_refused`): `busy` (one open at a time) or `cooldown` (the same destructive
        /// action was cancelled less than 10 s ago).
        ConfirmRefused {
            /// Dialog kind (`vsphere_power`, `vsphere_trust`, `vmrc`, `sync_trust`, `sync_fork`).
            kind: String,
            /// Target names only (connection id, `vm-42`, `host:port`), never a secret.
            target: String,
            /// `busy` | `cooldown`.
            reason: String,
        },
        /// Native-confirmation refusals beyond the first 16 of an hour of process uptime, counted
        /// and written once per hour (`confirm_refused_suppressed`, review 6b N-47).
        ConfirmRefusedSuppressed {
            /// Refusals that got no row of their own.
            count: u64,
        },
        }
    };
}
pub(crate) use vault_variants;
