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
    // --- ADR-0016 E2: external secrets (ids, names, counts, categories; never a value) ---
    /// Logged in to a secret source, or renewed its token (`secret.login`).
    SecretLogin {
        /// Source id.
        source: String,
        /// `token` | `approle` | `oidc` | `renew`.
        method: String,
        /// Cached lifetime (s).
        ttl: u64,
    },
    /// An `external_ref` was resolved (`secret.resolved`; the reference is inventory class).
    SecretResolved {
        /// Connection id, when resolved for a connect.
        connection: Option<String>,
        /// The `external_ref` credential.
        credential: String,
        /// Source id.
        source: String,
        /// `<mount>/<path>`.
        reference: String,
        /// KV version read.
        version: u64,
        /// Target kind.
        target_kind: String,
        /// Field and secret names filled.
        fields: Vec<String>,
    },
    /// A login, resolution or OIDC flow failed (`secret.failed`).
    SecretFailed {
        /// Connection id, when resolving for a connect.
        connection: Option<String>,
        /// Source id.
        source: String,
        /// `network | tls | auth_failed | forbidden | not_found | shape | locked | …`.
        category: String,
    },
    /// A cached token was dropped, and revoked when Mooring minted it (`secret.revoked`).
    SecretRevoked {
        /// Source id.
        source: String,
    },
    /// A source was created, changed or deleted (`secret.source_changed`). Field **names**
    /// only (the fields actually set or changed, review 6 N-42); no values except the
    /// SHA-256 fingerprints of a new `caPem`.
    SecretSourceChanged {
        /// Source id.
        source: String,
        /// Changed field names, or `created` / `deleted`.
        changed: Vec<String>,
        /// `SHA256:<hex>` of every certificate in a new or changed `caPem`.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        ca_pem: Vec<String>,
        /// `caPem` or `allowHttp` changed, or an `allowedOrigins` entry was added (a trust
        /// change).
        warning: bool,
    },
    /// A secret-source action was refused (`secret.refused`: OIDC navigation, delete in use).
    SecretRefused {
        /// Source id, when known.
        source: Option<String>,
        /// `oidc_navigation` | `delete` | `resolve` | ….
        action: String,
        /// Error code, or the refused origin of a navigation.
        detail: String,
    },
    /// Refusals of one OIDC window beyond the first 16, counted and written once when the
    /// window closes (`secret.refused_suppressed`, review 6 N-43).
    SecretRefusedSuppressed {
        /// Source id.
        source: String,
        /// `oidc_navigation`.
        action: String,
        /// Refusals that got no row of their own.
        count: u64,
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
    // ---- ADR-0017 (A3 S2): vault sync -----------------------------------------------------
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
}
