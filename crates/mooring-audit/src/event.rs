//! The audit event vocabulary (one JSON object per entry, tagged by `event`).

use serde::{Deserialize, Serialize};

/// What happened. Variants carry identifiers, never secret values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent {
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
    /// Vault exported (`format`: `age`, `json`, ...).
    VaultExported {
        /// Export format.
        format: String,
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

    // --- ADR-0010 §Port forwarding / §SFTP (rust-core, forward + SFTP IPC) ---
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
    // ---- ADR-0010 (A1 exit): auto-lock policy and syslog mirror -------------------------
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
    // ---- ADR-0011 / ADR-0012 (A2): graphical sessions ----------------------------------
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
    // --- ADR-0014 K4: Kubernetes sessions (no token, body, query or log byte is recorded) ---
    /// A cluster session connected (`kube.cluster.opened`).
    KubeClusterOpened {
        /// Connection id.
        connection: String,
        /// API server URL.
        server: String,
        /// `SelfSubjectReview` user, when allowed.
        identity: Option<String>,
    },
    /// A cluster session ended (`kube.cluster.closed`).
    KubeClusterClosed {
        /// Connection id.
        connection: String,
        /// Safe reason.
        reason: String,
    },
    /// The read-only guard refused a request before it left the process (`kube.refused`).
    KubeRequestRefused {
        /// Connection id.
        connection: String,
        /// Upper-case method.
        method: String,
        /// Route template or `unlisted`.
        template: String,
    },
    /// An exec shell opened (`kube.exec.opened`).
    KubeExecOpened {
        /// Connection id.
        connection: String,
        /// Namespace.
        namespace: String,
        /// Pod.
        pod: String,
        /// Container, `None` = the pod's default.
        container: Option<String>,
        /// The shell (closed list).
        argv0: String,
    },
    /// An exec shell ended (`kube.exec.closed`).
    KubeExecClosed {
        /// Connection id.
        connection: String,
        /// Namespace.
        namespace: String,
        /// Pod.
        pod: String,
        /// Container.
        container: Option<String>,
        /// Close code name.
        code: String,
    },
    /// A log stream opened (`kube.logs.opened`).
    KubeLogsOpened {
        /// Connection id.
        connection: String,
        /// Stream id.
        stream: String,
        /// Namespace.
        namespace: String,
        /// Pod.
        pod: String,
        /// Container.
        container: Option<String>,
        /// `follow=true`.
        follow: bool,
    },
    /// A log stream ended (`kube.logs.closed`).
    KubeLogsClosed {
        /// Connection id.
        connection: String,
        /// Stream id.
        stream: String,
        /// Namespace.
        namespace: String,
        /// Pod.
        pod: String,
        /// Container.
        container: Option<String>,
        /// Stopped at the byte cap.
        truncated: bool,
        /// `end`, `user`, `session_closed`, `vault_locked`, or an error code.
        reason: String,
    },
    /// A pod port-forward opened (`kube.forward.opened`, ADR-0010 fields).
    KubeForwardOpened {
        /// Connection id.
        connection: String,
        /// `fwd-<n>`.
        id: String,
        /// Local listener.
        bind: String,
        /// `ns/pod:port`.
        target: String,
        /// Always `loopback` in A3.
        exposure: String,
    },
    /// A pod port-forward closed (`kube.forward.closed`).
    KubeForwardClosed {
        /// Connection id.
        connection: String,
        /// `fwd-<n>`.
        id: String,
        /// Local listener.
        bind: String,
        /// `ns/pod:port`.
        target: String,
    },
}
