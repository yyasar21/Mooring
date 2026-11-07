//! Terminal and graphical sessions: open / close, port forwards and SFTP (ADR-0010),
//! certificate trust, clipboard, screenshots, view-only and option changes (ADR-0011 / 0012).
//!
//! `sessions_variants!` appends this phase's `AuditEvent` variants to the chain assembled in
//! `event/mod.rs`; the wire names come from the enum's `serde` attributes there.

macro_rules! sessions_variants {
    ([$next:ident $(, $rest:ident)*] $($acc:tt)*) => {
        $next! { [$($rest),*] $($acc)*
        /// Session opened.
        SessionOpened {
            /// Connection id.
            connection: String,
            /// Protocol name.
            protocol: String,
            /// Peer identity (fingerprint / cert subject) as shown to the user.
            peer_identity: Option<String>,
        },
        /// Session closed.
        SessionClosed {
            /// Connection id.
            connection: String,
            /// Reason safe to show.
            reason: String,
        },
        /// A port forward started (ADR-0010 `session.forward.open { exposure }`).
        ForwardOpened {
            /// Connection id.
            connection: String,
            /// Session-local forward id, e.g. `fwd-1`.
            id: String,
            /// `local` | `remote` | `dynamic`.
            kind: String,
            /// Bound `host:port`.
            bind: String,
            /// Target `host:port`, or `socks5`.
            target: String,
            /// `loopback` | `external`.
            exposure: String,
        },
        /// A port forward stopped (closed by the user or with its session).
        ForwardClosed {
            /// Connection id.
            connection: String,
            /// Session-local forward id.
            id: String,
            /// `local` | `remote` | `dynamic`.
            kind: String,
            /// Bound `host:port`.
            bind: String,
            /// Target `host:port`, or `socks5`.
            target: String,
        },
        /// An SFTP transfer ended (ADR-0010 `session.sftp.transfer`). Never file contents.
        SftpTransfer {
            /// Connection id.
            connection: String,
            /// Transfer id.
            transfer: String,
            /// `download` | `upload`.
            direction: String,
            /// Bytes moved.
            bytes: u64,
            /// `done` | `failed` | `cancelled`.
            outcome: String,
        },
        /// A TLS certificate trust decision for RDP / VNC (`trust.cert.*`).
        CertDecision {
            /// `rdp` | `vnc`.
            protocol: String,
            /// `host:port`.
            host: String,
            /// `SHA256:<hex>` presented.
            fingerprint: String,
            /// `accepted` | `accepted_session_only` | `rejected` | `changed` | `ca_valid`.
            decision: String,
            /// For `changed`: the pinned fingerprint.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            expected: Option<String>,
        },
        /// Pins for `host:port` were removed from a certificate store (`known_certs_remove`,
        /// ADR-0011 `trust.cert.removed`).
        CertRemoved {
            /// `rdp` | `vnc`.
            protocol: String,
            /// `host:port`.
            host: String,
            /// Pins removed (0 when none matched).
            removed: u64,
        },
        /// A session negotiated weaker transport security than the default (RDP TLS without
        /// NLA, VNC without TLS): audited on every connect.
        SessionWeakSecurity {
            /// Connection id.
            connection: String,
            /// `rdp` | `vnc`.
            protocol: String,
            /// Security in effect (`tls`, `vnc-auth`, `none`, ...).
            security: String,
        },
        /// Clipboard text crossed a session boundary (coalesced, ≤ 1/s per direction). Never the
        /// text itself.
        SessionClipboard {
            /// Connection id.
            connection: String,
            /// `to_remote` | `from_remote`.
            direction: String,
            /// UTF-8 bytes transferred.
            bytes: u64,
        },
        /// The framebuffer of a session was copied to the OS clipboard as an image.
        SessionScreenshot {
            /// Connection id.
            connection: String,
            /// Width in pixels.
            width: u32,
            /// Height in pixels.
            height: u32,
        },
        /// The local clipboard text was offered to a remote session (`ClipboardOffer`, L-25).
        SessionClipboardOffer {
            /// Connection id.
            connection: String,
            /// UTF-8 bytes offered.
            bytes: u64,
        },
        /// The offered text is a vault secret Mooring copied (`credential_copy_*`, L-25).
        CredentialSentToRemote {
            /// Credential id.
            credential: String,
            /// Connection id.
            connection: String,
        },
        /// Remote clipboard writes were refused while the vault was locked (L-25); one entry per
        /// locked period and session.
        SessionClipboardBlocked {
            /// Connection id.
            connection: String,
        },
        /// `session_set_view_only` toggled a session's view-only switch (ADR-0012 §IPC, L-26).
        SessionViewOnly {
            /// Connection id.
            connection: String,
            /// The new state.
            view_only: bool,
        },
        /// `connection_options_set` changed stored options (review 5 L-22). Field **names** only;
        /// no values except the SHA-256 fingerprints of a new `caPem`.
        ConnectionOptionsChanged {
            /// Connection id.
            connection: String,
            /// `rdp` | `vnc` | `web` | ...
            protocol: String,
            /// camelCase option names whose value changed.
            changed: Vec<String>,
            /// `SHA256:<hex>` of every certificate in a new or changed `caPem`.
            #[serde(default, skip_serializing_if = "Vec::is_empty")]
            ca_pem: Vec<String>,
            /// Whether the change weakens security (warning severity).
            weakened: bool,
        },
        /// ADR-0025: a jump host of the session's chain authenticated (`session.hop.open`).
        SessionHopOpen {
            /// The leaf connection id.
            connection: String,
            /// 0-based position in the chain.
            hop: u8,
            /// The hop's own connection id.
            hop_connection: String,
            /// Host key fingerprint of the hop.
            peer_identity: Option<String>,
            /// `password`, `publickey`, `agent`, `keyboard-interactive`, ...
            auth_method: String,
        },
        /// ADR-0025: a jump host closed (`session.hop.close`): `closed`, `hop_failed` or
        /// `hop_lost`.
        SessionHopClose {
            /// The leaf connection id.
            connection: String,
            /// 0-based position in the chain.
            hop: u8,
            /// The hop's own connection id.
            hop_connection: String,
            /// Why.
            code: String,
        },
        /// A session tab moved to its own window (`session.detached`).
        SessionDetached {
            /// Connection id.
            connection: String,
            /// Session id.
            session: String,
        },
        /// A detached session came back to the main window (`session.attached`).
        SessionAttached {
            /// Connection id.
            connection: String,
            /// Session id.
            session: String,
        },
        }
    };
}
pub(crate) use sessions_variants;
