# ADR-0013: Web sessions in isolated windows, and detaching a tab to a window

Status: Accepted · 2026-11-04 (Phase A2; extends ADR-0003, ADR-0008 `window_detach`, ADR-0011)

## Context
Admin consoles (vCenter, Grafana, OPNsense, Rancher, Argo CD) are web pages. Rendering them in
the `main` WebView would expose the IPC bridge to remote script (T5). Tauri 2.12.5 injects
`__TAURI_INTERNALS__` into every webview, so the isolation must come from ACL, labels,
navigation and storage, not from hiding the bridge. Today there is no `AppManifest`. That means
every app command is allowed for every window with a local origin. Remote origins are refused
for app commands (`webview/mod.rs`, test
`remote_origin_blocked_for_custom_commands_without_app_manifest`), with one exception: the
channel `fetch` command, whose data queue is scoped per webview in 2.12.5 (`ipc/channel.rs`).
ADR-0008 reserved `window_detach` for A2.

## Decision

### One window per web connection
- `web_open` creates a `WebviewWindow` with label `web-<connectionId>` (one per connection;
  opening again focuses the existing window). The UI shows a tab placeholder (title, origin,
  focus, close). Embedding the page inside `main` needs Tauri's `unstable` multi-webview and is
  deferred.
- Builder settings, applied in Rust only:
  - `devtools(false)` and `zoom_hotkeys_enabled(false)`: the macOS/Linux zoom polyfill would
    need an IPC permission, so zoom goes through `web_zoom` → `set_zoom` instead.
  - `general_autofill_enabled(false)` on Windows.
  - `on_permission_request` → `Deny` for every kind: camera, mic, geolocation, notifications,
    clipboard read, MIDI.
  - `on_download` → `false` (deny) and audit `web.download_blocked { connection, origin }`.
  - `on_new_window` → `Deny`. When the URL is inside the allow-list, Rust navigates the same
    window there instead.
  - `on_document_title_changed` → the native window title "Mooring · <connection name> ·
    <origin>". The page title (sanitised: controls and bidi stripped, 256 chars) goes to the
    main UI only as an event.
  - `disable_drag_drop_handler` is left at its default, so Tauri swallows OS file drops (with
    no capability, nothing can listen to them).
- **No IPC bridge at all.** Title and close need no JS: the title comes from the Rust callback
  above, and closing happens through the native window chrome, `web_close` or the window's
  `CloseRequested`, which notifies `main`. The web window's capability grants nothing.
- Initialization script (best effort, the ACL is the boundary): it disables `<input
  type=file>` activation and `showOpenFilePicker`/`showSaveFilePicker` (uploads denied by
  policy), and `window.print` is left to the native print path.

### Capabilities and command ACL (capability change, security review required)
- `src-tauri/build.rs` adopts `tauri_build::AppManifest::new().commands(&[…every command…])`.
  From then on every app command needs an explicit `allow-<command>` permission in a matching
  capability, local origin or not.
- `capabilities/main.json` grants `core:default` plus the permission set `mooring-main` (all app
  commands) to `windows: ["main"]`.
- `capabilities/detached.json` grants `windows: ["detached-*"]` only `allow-session-attach`,
  `allow-session-send`, `allow-session-close`, `allow-session-frame-ack`,
  `allow-session-screenshot` and `allow-window-attach`.
- `capabilities/web.json` grants `windows: ["web-*"]`, `permissions: []` and no `remote`
  block. It exists so that a test can assert it stays empty.
- Defence in depth in Rust: every command takes `webview: tauri::Webview` and calls
  `guard::caller(&webview)`, which returns `Main` or `Detached(sessionId)` and refuses
  `web-*`/unknown labels with `ipc.forbidden`. A detached window may act on its own `sessionId`
  only.
- Pin `tauri = "=2.12.5"`, or ≥ it with a test: the per-webview channel queue and the remote
  ACL check are part of the boundary.

### Navigation guard and origin allow-list
- `WebConnOptions.url` must be `https://`. `http://` is allowed only with
  `allowHttp: true` (audited, warning badge). An IP literal or a DNS name is fine, and
  credentials in the URL (`user:pass@`) are refused.
- `on_navigation` (top-level frame) allows `scheme://host:port` ∈ {origin of `url`} ∪
  `allowedOrigins` (≤ 16, exact origins, no wildcards; SSO such as `https://sso.example.test`
  must be listed). It always refuses the app origin (`tauri://localhost`,
  `http(s)://tauri.localhost`, `ipc:`, the dev URL) and `file:`, `data:`, `javascript:` and
  `blob:` top-level navigations. A refusal emits `blocked { origin }` to `main` (origin only:
  paths may carry tokens), and the user can add that origin to the connection.
- Subresources (XHR, images, iframes) are the page's business, as in a browser. We do not inject
  CSP into remote pages: `on_web_resource_request` sees only the `tauri` scheme. The ADR-0003
  CSP stays for `main` and `detached-*`.

### Storage partitioning
- Default **ephemeral**: `incognito(true)`, so nothing reaches disk and closing the window
  forgets the login.
- Opt-in `persistent: true` ("keep me signed in") uses one store per connection:
  - Windows and Linux: `data_directory($APP_DATA/web/<connectionId>)`.
  - macOS ≥ 14: `data_store_identifier` = the 16 bytes of the connection UUID.
  - macOS 11–13 has no per-webview store, so there `persistent` is refused and the window falls
    back to ephemeral with a notice.
  The store is wiped (`clear_all_browsing_data`, then the directory is removed) by `web_clear_data`
  and by `connection_delete`.
- Cookies in a persistent store are plaintext on disk (T1/T2): R-WEB-COOKIE, accepted per
  connection by the user.
- On vault lock, every `web-*` and `detached-*` window is **hidden**, and shown again after
  unlock. ADR-0010 keeps sessions alive across a lock, but an OS window outside the lock screen
  would bypass it.

### Credentials and certificates
- **No auto-fill in A2.** Injecting a secret into a remote DOM would hand it to page script
  (T5), and form detection is server-controlled text. The connection's credential (`user_password`,
  `domain_user`, `vsphere_user`, `api_token`) gets **copy username / copy password / copy OTP**
  buttons in the placeholder tab (`credential_copy_secret`, ADR-0009; 30 s clear, audited).
  `x509` mTLS and `api_token` headers need the engines' client-certificate and header hooks,
  which Tauri does not expose: deferred.
- TLS uses **the OS trust only**, the WebView's own validation (Keychain, Windows cert store,
  system CA bundle for WebKitGTK). A custom CA is installed into the OS store by the user;
  Mooring injects none and offers no "proceed anyway". Self-signed consoles therefore fail until
  the user trusts them in the OS (see open questions: a rustls TOFU proxy via `proxy_url`).
- `proxy_url` is reserved for a later "via SSH connection" option (dynamic forward, ADR-0010).

### What a compromised page (T5) can and cannot do
It **can**:
- run script in its own origin and partition;
- phish inside its window (the native title shows the real origin);
- use the network like any browser tab;
- exploit WebView engine bugs (mitigated only by OS WebView updates).
It **cannot**:
- call any Mooring command (no capability, `AppManifest`, label guard);
- read other webviews' channel data;
- navigate to the app origin to become "local";
- open windows;
- download files;
- open file pickers (best effort);
- get camera, mic or location;
- read other connections' cookies;
- see any secret Mooring did not put on the clipboard at the user's request.

### Detach a session tab to a window (ADR-0008 reservation)
- `window_detach({ sessionId })` creates `detached-<sessionId>`. It loads the bundled app at
  `#/detached/<sessionId>`, with the same CSP, navigation guard (`navigation.rs`) and
  `devtools(false)`. The new view calls `session_attach`, which moves the session's
  `onEvent`/`onFrame` sinks to the new view. The old view receives `{ kind: "detached" }` and
  shows a placeholder. Only one view is attached at a time, and a re-attach resends one full
  frame.
- `window_attach({ sessionId })` (from either window) closes the detached window and attaches
  `main`. Closing the detached window re-attaches automatically and does not close the session.
- Web sessions are always windows, so `window_detach` refuses them (`input.invalid`).

### IPC (ADR-0008 style)
```
web_open({ connectionId, onEvent: Channel<WebEvent> })  -> { windowLabel }
web_close / web_focus / web_reload / web_print / web_clear_data({ connectionId }) -> void
web_zoom({ connectionId, factor })              -> void          # 0.25..=5.0
web_list()                                      -> { connectionId, windowLabel, origin, title, persistent, openedAt }[]   # passive
WebEvent = { kind: "title", title } | { kind: "navigated", origin } | { kind: "blocked", origin }
         | { kind: "download_blocked", origin } | { kind: "closed" }
WebConnOptions = { url, allowedOrigins: string[], persistent: bool, allowHttp: bool }   # connection.options
window_detach({ sessionId })                    -> { windowLabel }
window_attach({ sessionId })                    -> void
session_attach({ sessionId, onEvent, onFrame? }) -> { protocol, state, size }   # detached-* or main
```
New error codes are `ipc.forbidden` and `web.origin_refused`. Audit events:
- `web.opened { connection, origin, persistent }` and `web.closed`;
- `web.navigation_blocked { connection, origin }` and `web.download_blocked`;
- `web.data_cleared`;
- `session.detached` and `session.attached`.

## Alternatives considered
- Web content in an `<iframe>` in `main`: shares the IPC origin rules with the app. On Linux,
  Tauri cannot tell frame requests from the window's own requests. Rejected.
- `remote` capability with a narrow bridge for title/close: native callbacks already cover it,
  and any remote IPC is attack surface. Rejected.
- Auto-fill by injected script: the secret enters page context. Rejected for A2.
- A rustls MITM proxy for TOFU on web certificates: solves self-signed consoles, but terminates
  TLS in our process for every subresource. It needs its own ADR.

## Security consequences
`AppManifest` turns "allowed unless remote" into "denied unless granted", which also hardens
`main` against a future second local window. New risks: R-WEB-ENGINE (OS WebView bugs),
R-WEB-COOKIE (persistent partitions), R-WEB-UPLOAD (the picker block is a script, not a
boundary). T5 in `main` is unchanged.

## Test plan
- Rust: `guard::caller` matrix (main / detached own and other session / web / unknown → codes);
  navigation allow-list (app origin, look-alikes, `data:`, ports, IDN); URL validation; options
  serde; the detach/attach state machine; lock hides and unlock shows the windows.
- Capability snapshot tests:
  - `web.json` has no permissions and no `remote`;
  - `detached.json` has exactly the six permissions;
  - every registered command appears in `AppManifest`.
- E2E (qa, real app on each OS): a local test page served on `127.0.0.1`
  (`allowHttp`) tries `invoke`, the channel fetch, `location = "tauri://localhost"`,
  `window.open`, a download, a file input and `getUserMedia`. Each attempt must fail and the
  matching audit entry must appear.

## Owner decisions (2026-11-04)
6. Certificates: OS trust only in A2. A self-signed console fails until the user trusts the CA in
   the OS store; a rustls TOFU proxy is an A3 ADR candidate.
7. Storage is ephemeral by default; persistent cookies are a per-connection opt-in shown in the
   connection form and audited when enabled.

## Sources
Tauri 2.12.5 source (`webview/mod.rs` remote-origin ACL check and its test, `ipc/channel.rs`
per-webview queue, `WebviewWindowBuilder::{on_permission_request, on_download,
on_document_title_changed, data_store_identifier, incognito}`, `clear_all_browsing_data`,
`set_zoom`, `print`); docs.rs `tauri` 2.12.5 `WebviewWindowBuilder` platform notes (macOS ≥ 14
for `data_store_identifier`, zoom polyfill permission); v2.tauri.app/security/capabilities
(AppManifest, `remote`, the Linux iframe caveat); wry 0.57.1 permission handler.
