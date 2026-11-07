//! A5: Move to Applications (ADR-0028 §2). Locations, targets, flags and codes only: no path
//! ever reaches these rows (the volume name and the user's home are personal data).
//!
//! `a5_variants!` appends this phase's `AuditEvent` variants to the chain assembled in
//! `event/mod.rs`; the wire names come from the enum's `serde` attributes there.

macro_rules! a5_variants {
    ([$next:ident $(, $rest:ident)*] $($acc:tt)*) => {
        $next! { [$($rest),*] $($acc)*
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
        }
    };
}
pub(crate) use a5_variants;
