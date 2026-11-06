//! Web connections in their own window (ADR-0013).
//!
//! `web_variants!` appends this phase's `AuditEvent` variants to the chain assembled in
//! `event/mod.rs`; the wire names come from the enum's `serde` attributes there.

macro_rules! web_variants {
    ([$next:ident $(, $rest:ident)*] $($acc:tt)*) => {
        $next! { [$($rest),*] $($acc)*
        /// A web connection was opened in its own window (ADR-0013 `web.opened`).
        WebOpened {
            /// Connection id.
            connection: String,
            /// Start origin (`scheme://host[:port]`), never a path.
            origin: String,
            /// Cookies kept on disk for this connection (opt-in).
            persistent: bool,
        },
        /// A web window closed (`web.closed`).
        WebClosed {
            /// Connection id.
            connection: String,
        },
        /// A top-level navigation outside the allow-list was refused (`web.navigation_blocked`).
        WebNavigationBlocked {
            /// Connection id.
            connection: String,
            /// Refused origin only: paths may carry tokens.
            origin: String,
        },
        /// Refused navigations of a web window beyond the first 16, counted and written once
        /// when the window closes (`web.navigation_blocked_suppressed`, review 6 N-43).
        WebNavigationBlockedSuppressed {
            /// Connection id.
            connection: String,
            /// Refusals that got no row of their own.
            count: u64,
        },
        /// A download from a web window was refused (`web.download_blocked`).
        WebDownloadBlocked {
            /// Connection id.
            connection: String,
            /// Origin of the download URL.
            origin: String,
        },
        /// The browsing data of a web connection was wiped (`web.data_cleared`).
        WebDataCleared {
            /// Connection id.
            connection: String,
        },
        }
    };
}
pub(crate) use web_variants;
