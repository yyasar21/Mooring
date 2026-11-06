//! vCenter inventory refresh, VM power actions and consoles (ADR-0015).
//!
//! `vsphere_variants!` appends this phase's `AuditEvent` variants to the chain assembled in
//! `event/mod.rs`; the wire names come from the enum's `serde` attributes there.

macro_rules! vsphere_variants {
    ([$next:ident $(, $rest:ident)*] $($acc:tt)*) => {
        $next! { [$($rest),*] $($acc)*
        /// A vCenter inventory refresh started (ADR-0015 §2). `trigger`: `manual` | `schedule` |
        /// `import`.
        VsphereSyncStarted {
            /// vCenter connection id.
            connection: String,
            /// What started it.
            trigger: String,
        },
        /// A refresh was written in one transaction.
        VsphereSyncFinished {
            /// vCenter connection id.
            connection: String,
            /// New items.
            added: u64,
            /// Renamed / moved / details changed.
            changed: u64,
            /// Missing once (kept, marked `missing`).
            missing: u64,
            /// Removed after two consecutive misses.
            removed: u64,
            /// Duration in milliseconds.
            ms: u64,
        },
        /// A refresh failed and changed nothing (`code` is the IPC error code).
        VsphereSyncFailed {
            /// vCenter connection id.
            connection: String,
            /// Error code.
            code: String,
        },
        /// A VM power action (ADR-0015 §3), recorded before (`outcome: requested`) and after
        /// (`done` | `already` | `cancelled` | an error code).
        VspherePower {
            /// vCenter connection id.
            connection: String,
            /// VM managed-object id (`vm-42`).
            vm: String,
            /// `start` | `shutdown` | `reboot` | `stop` | `reset`.
            action: String,
            /// Outcome.
            outcome: String,
        },
        /// A VM console was opened (`kind`: `client` | `vmrc`). The VMRC ticket is never recorded.
        VsphereConsole {
            /// vCenter connection id.
            connection: String,
            /// VM managed-object id.
            vm: String,
            /// Console path.
            kind: String,
        },
        }
    };
}
pub(crate) use vsphere_variants;
