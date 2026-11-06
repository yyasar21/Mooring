//! A4: in-app updates (ADR-0018 §3), network tools (ADR-0020 §6), the importer and the
//! LDAP directory source (ADR-0019 §4, §6). Versions, codes, hosts and counts only.
//!
//! `a4_variants!` appends this phase's `AuditEvent` variants to the chain assembled in
//! `event/mod.rs`; the wire names come from the enum's `serde` attributes there.

macro_rules! a4_variants {
    ([$next:ident $(, $rest:ident)*] $($acc:tt)*) => {
        $next! { [$($rest),*] $($acc)*
        /// An update check finished (`update_check`, or the opt-in background check).
        #[serde(rename = "update.check")]
        UpdateCheck {
            /// Running version.
            current: String,
            /// Version offered by the manifest, if newer.
            available: Option<String>,
        },
        /// A verified bundle is about to be installed (`update_install`); the app restarts after.
        #[serde(rename = "update.install")]
        UpdateInstall {
            /// Running version.
            from: String,
            /// Version being installed.
            to: String,
        },
        /// An install was refused (`code` is the IPC error code, e.g. `update.manual_only`).
        #[serde(rename = "update.refused")]
        UpdateRefused {
            /// Error code.
            code: String,
        },
        /// The update settings changed (`update_settings_set`).
        #[serde(rename = "update.settings_changed")]
        UpdateSettingsChanged {
            /// Opt-in background check on or off.
            background_check: bool,
        },
        /// A TCP port check ran (ADR-0020 §6, `net_tcp_check`). Host and port are inventory;
        /// `outcome` is `open` | `closed` | `timeout` | `unreachable` | `dns_failed`.
        NetTcpCheck {
            /// Target host as typed or taken from the connection.
            host: String,
            /// Port.
            port: u16,
            /// Outcome.
            outcome: String,
        },
        /// A `ping` run ended (`net_ping`): names and counts only, never the tool output.
        NetPing {
            /// Target host.
            host: String,
            /// Requests sent.
            sent: u32,
            /// Replies received.
            received: u32,
        },
        /// A trace run ended (`net_traceroute`).
        NetTraceroute {
            /// Target host.
            host: String,
            /// Hops printed.
            hops: u32,
        },
        /// `wg show` status was read (`net_wg_status`): interface names only, never keys.
        NetWgStatus {
            /// Interface names.
            interfaces: Vec<String>,
        },
        /// An import file was parsed into a plan (ADR-0019 §6). Format only: no file name, host
        /// or count leaves the parser here.
        ImportPreviewed {
            /// Wire name of the format (`royal_ts`, `termius`, …).
            format: String,
        },
        /// A plan was written to the store in one transaction (`import_applied`).
        ImportApplied {
            /// Format.
            format: String,
            /// Folders created.
            folders: u64,
            /// Connections created.
            connections: u64,
            /// Credentials created.
            credentials: u64,
            /// Secrets sealed (plaintext opt-in).
            secrets: u64,
            /// Items left out (parser skips, exclusions, duplicates).
            skipped: u64,
        },
        /// An import file was refused (`code` is the IPC error code, e.g. `import.doctype`).
        ImportRefused {
            /// Error code.
            code: String,
        },
        /// A directory bind was attempted (ADR-0019 §4, `ldap_import_*`): host only, never the
        /// bind name, the password, a DN or an entry.
        LdapBind {
            /// `host:port` of the directory.
            host: String,
            /// Whether the server accepted the bind.
            success: bool,
        },
        }
    };
}
pub(crate) use a4_variants;
