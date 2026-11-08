# A5 security review 9 — v0.2.0 phase exit (ADR-0022..0028, ADR-0018 A1–A2)

Reviewer: security-reviewer · 2026-11-08 · Range `git diff 6d14701..HEAD` (A4.1 exit = merge of
fix round F2 → `main` @ `0eaafdb`; 698 files, +41 922 / −2 331: rust-core R1–R6 + 0028,
ui U0–U7, release-engineer 0028 + A1/A2, qa W4). Scoped to the A5 areas below; tests, fixtures
and the landing site were read only where a claim depended on them.

Read in full: `crates/mooring-proto-rdp/src/gateway/{mod,http,ws,conn,open,ntlm,relay}.rs`
(+ `pdu.rs` bounds), `crates/mooring-core/src/options/gateway.rs`,
`crates/mooring-proto-ssh/src/{chain_proxy,sk_auth,piv_auth}.rs` (+ `agent_wire`, `sk_agent`,
`hops` entry points), `src-tauri/src/web/via.rs` and its wiring in `commands/web.rs` /
`web/window.rs`, `src-tauri/src/{install_move,install_location}.rs` (+ `install_flow` order),
`src-tauri/src/biometric/{mod,windows,macos}.rs`, `commands/vault_biometric.rs` (unlock path),
`commands/vault_export.rs`, the trust handling of `commands/vault_import.rs` +
`mooring-sync::merge`, `mooring-vault::export` caps, `crates/mooring-secrets/src/bws.rs`,
`src-tauri/src/updater/install_mode.rs` (winget marker), `.github/workflows/{release,
release-winget}.yml` (jobs, secrets, `if:`, pins), `scripts/release/macos-sign.sh` (secret
handling), `apps/desktop/src/components/{terminal/SmartCardPinDialog,settings/{SecurityCard,
ExportDialog,ImportDialog}}.tsx`, the capability / permission / manifest / lockfile diff.

Inputs: ADR-0021..0028, ADR-0018 A1–A2, handoffs `a5-*.md` (architect, rust-core r1–r6 + 0028,
release-engineer 0028 + a5, ui u0–u7, qa), [review 8](a4-1-review-8.md), the
[threat model](threat-model.md) (A5 section added with this review).

Evidence gathered here (Linux x86_64, `CARGO_INCREMENTAL=0`, shared `CARGO_TARGET_DIR`):
- Supply chain: `git diff 6d14701..HEAD -- Cargo.lock` → **removals only** (`keyring`,
  `zbus` and its async tree, 37 packages); `hkdf 0.13` was already in the lock. New direct
  edges: `security-framework` 3.7 (macOS, `OSX_10_15`), `windows` 0.62 (`Security_Credentials`,
  `Foundation`, `Storage_Streams`), `hkdf`, `sha1` in `mooring-proto-rdp`, `serde_json` as a
  build-dependency. All RustCrypto / already in the tree; **approved**. No `macos-proxy`
  feature (macOS web-via refused, see below).
- `cargo deny --offline check` → advisories ok, bans ok, licenses ok, sources ok.
  `cargo audit --no-fetch` → RUSTSEC-2023-0071 `rsa` (R-RSA) and the accepted
  RUSTSEC-2024-0429 `glib`; unmaintained warnings drop from 7 to 5 with `zbus` gone. Nothing new.
- `grep unsafe` over `src-tauri/src` and `crates/*/src` → only `forbid(unsafe_code)`.
- Capabilities: **no capability file changed**. `mooring-main.toml` +9 `Scope::Main`
  permissions (`biometric_*`, `vault_export_*`, `vault_import_*`); `biometric_status` added to
  `ipc-passive.json` (status only, no prompt). No new window label, no new remote-content
  permission.
- Tests run here: `mooring-proto-rdp --test gateway` 6/6 and `--lib gateway` 15/15;
  `mooring-proto-ssh --test chain_proxy` 2, `hops` 8, `sk_keys` 10, `smart_card` 4;
  `mooring-secrets` all (42 + 30 integration); `mooring-sync` all (41 lib + 38 integration);
  `mooring-app --lib` (biometric / vault_import / vault_export / install_ / web::via / winget /
  build_identity / sk_keys filters, see Test evidence); `scripts/release/tests/run.sh` 9 suites,
  0 failed; `lint-workflows.sh .github/workflows` ok.
- **Not run:** any macOS or Windows build (Touch ID, Windows Hello, `ditto`/`codesign`/`hdiutil`,
  WebView2 proxy, `icacls`), the release / winget workflows, `actionlint`, `pnpm test`
  (U5–U7 / QA evidence taken as reported), the lab gates (`MOORING_LAB_RDG_HOST`,
  `MOORING_LAB_JUMP_HOST`, YubiKey PIV), real nightly fuzzing.

## Verdict: `PASS with conditions` — merge stands; the `v0.2.0` tag waits for the gate below

No Critical, no High. The phase holds the properties its ADRs made central:

- **Jump hosts never bypass trust.** Every hop has its own `known_hosts` TOFU / mismatch hard
  stop and its own credential; a failing hop ends with `hop_failed` before a `direct-tcpip`
  to the target is sent (pinned by `hops` 8/8). Web windows open the chain **unattended**: the
  first hop prompt shuts the broker and the open fails with `session.hop_failed`
  (`web/via.rs:62-96`), so nothing is trusted on the user's behalf; the window is only built
  with `proxy_url` set and `window::build` fails closed without it (`web/window.rs:125-130`).
  macOS refuses web-via outright because `macos-proxy` is off (`web/via.rs:34-46`) — the right
  call, since `proxy_url` is silently ignored there.
- **RD Gateway parsers are bounded.** Head 16 KiB / 64 headers, bodies ≤ 64 KiB and never
  chunked (`http.rs:11-15`, `:59-70`), strict base64 with a decoded cap, WebSocket frames
  ≤ 128 KiB, server frames must be unmasked, control frames ≤ 125 and final, text refused
  (`ws.rs:61-132`), MS-TSGU length checked before buffering (`pdu.rs:130-139`), the reassembly
  buffer capped at 2 × `MAX_PACKET` (`conn.rs:366`). `Sec-WebSocket-Accept` is verified exactly
  (`open.rs:303-311`). The pin is checked **before any HTTP byte**; a changed pin is a
  `trust_mismatch` hard stop; Basic needs `allowBasicGateway`, is audited, and an NTLM leg
  already sent can never fall back to Basic (`open.rs:319-331`). Close reasons are fixed text
  plus an HRESULT / HTTP status, never server text.
- **Security keys and smart cards sign only with presence.** `SkSigner::sign` checks the
  algorithm, the UP flag, the layout and **verifies the signature against the pinned key**
  before anything reaches the server (`sk_auth.rs:131-159`); no password or
  keyboard-interactive fallback (decision 30). The PIV path verifies the agent's signature the
  same way; the PIN never enters React state (`SmartCardPinDialog.tsx:12-38`, uncontrolled,
  cleared on send and unmount) and never reaches the audit log (E2E asserts it).
- **Biometric unlock never hands out the key silently.** macOS: data-protection keychain,
  `BiometryCurrentSet` + `WhenUnlockedThisDeviceOnly`, only in a `mooring_signed_build`
  (`biometric/macos.rs:46-58`, `:102-104`). Windows: the key never leaves the KSP; the wrap key
  is HKDF over a gesture-gated signature (`biometric/windows.rs:76-84`). 3 failures in 10 min,
  password change, biometry change and vault rotation suspend and delete the OS item. Residual
  is R-BIO-PROMPT (accepted, threat model).
- **Backups.** Import caps (64 MiB before read, scrypt log N ≤ 20, foreign header checked
  against the ADR-0002 floor/ceiling before any KDF), whole-file refusal on any structural
  error, single-use 10 min holds cleared on lock, `REPLACE` enforced in Rust, the
  per-device `keyring_wrap` never exported.
- **Spawned tools use fixed paths and argv, no shell.** `ditto`, `codesign`, `open`,
  `hdiutil`, `PlistBuddy`, `ps` (`install_move.rs:49-89`: `env_clear` + `LC_ALL=C`, null stdin,
  256 KiB cap, deadline + kill; every path argument is absolute, so no option injection);
  `bws` (`bws.rs:140-197`: `env_clear`, token in the child env only, pinned argv, stdout 1 MiB,
  stderr never surfaced, 30 s); `ssh-sk-helper` off by default with no IPC to switch it on.
  `hdiutil detach` only for an exact `/Volumes/<name>` image mount that holds our bundle and no
  vault or marker.
- **Release.** The `build` job holds no platform signing secret; `sign-macos` /
  `sign-windows` run in `environment: release`, gated on repo variables, never on secrets in
  `if:`; every `uses:` is pinned to a 40-hex SHA; `wingetcreate.exe` is SHA-256 checked;
  `winget-releaser` was rejected for the right reason (unpinned inner tools next to the token).
  No `pull_request_target` / `workflow_run` anywhere.

There is **one Medium, M-19** (RD Gateway NTLM without channel binding — the EPA / CBT status
the brief asked for), and it is a tag condition because it is cheap: `sspi` already exposes
`Ntlm::set_channel_bindings`. The Lows are mostly hardening of new local surfaces (the web
SOCKS port, smart-card agent lifetime, `bws` change handling, the backup `.part` file, trust
union on import) and two workflow / UI consistency items.

## Findings

Numbering continues from review 8 (last used: M-18, L-46, N-71).

| ID | Sev | Where | Finding | Exact fix | Owner |
| --- | --- | --- | --- | --- | --- |
| **M-19** | Medium (tag condition) | `crates/mooring-proto-rdp/src/gateway/ntlm.rs:477-490` (`NtlmClient::new`: no channel bindings), `open.rs:287-291`, `:319-327` (NEGOTIATE / AUTHENTICATE over the pinned TLS) | **RD Gateway NTLM is sent without channel binding (no EPA / CBT).** The `AUTHENTICATE_MESSAGE` carries no `MsvAvChannelBindings`, so it is not tied to the TLS session it travels in. Two consequences: (a) a gateway that requires Extended Protection (IIS `extendedProtection tokenChecking="Require"`, increasingly the hardening default for RD Web / RDG) refuses every Mooring sign-in with `gateway_auth`; (b) whoever terminates the TLS — a TOFU-accepted impostor at first contact, or any holder of a CA-valid certificate for the gateway name (CA-valid gateways are accepted without a prompt) — can **relay** the NTLMv2 exchange to another NTLM service of the domain (LDAP, SMB, AD CS web enrolment) as the user. With "same as sign-in" this is the domain account. The pin itself is correct (mismatch is a hard stop), so the window is first contact or a mis-issued certificate, which is why this is Medium, not High | **rust-core:** after the handshake, take the gateway leaf (`tls.get_ref().1.peer_certificates()[0]`), compute the RFC 5929 `tls-server-end-point` hash (SHA-256 of the DER for SHA-1/SHA-256/MD5 signature algorithms, the signature's own hash for SHA-384/512), and call `ntlm.set_channel_bindings(b"tls-server-end-point:" ‖ hash)` before `negotiate`. Pass the leaf into `upgrade` (it already has the `Decision` fingerprint, which is the SHA-256 of the DER — reuse it when the signature hash is SHA-256). Test: the mock gateway's sspi server with channel bindings set accepts us and rejects a wrong binding. **docs:** ADR-0027 §1 records "NTLM with CBT; Kerberos (Negotiate) still unsupported" | rust-core, architect |
| L-47 | Low | `src-tauri/src/web/window.rs:125-126` (`proxy_url` only), `web/via.rs:1-10` ("not one request leaves directly") | **The SOCKS proxy covers TCP only.** WebView2 (Chromium) sends WebRTC UDP (STUN / TURN-over-UDP, host candidates) outside a SOCKS proxy unless told otherwise, and Chromium bypasses the proxy for loopback. A page in a web-via window can therefore reach the network **from the user's machine**, not from the bastion, and leak the local addresses — the ADR's "every request goes through the chain" is not what the engine does. WebKitGTK disables WebRTC by default; not verified | **rust-core:** on Windows add the WebView2 browser argument `--force-webrtc-ip-handling-policy=disable_non_proxied_udp` (or `--webrtc-ip-handling-policy=…`) for every web window (not only via ones, keeps one environment), and keep WebKitGTK's `enable-webrtc` off explicitly. **qa:** the manual gate opens a WebRTC test page through a bastion and checks no direct UDP leaves (Wireshark). Docs: R-WEB-VIA records the loopback bypass | rust-core, qa |
| L-48 | Low | `crates/mooring-proto-ssh/src/chain_proxy.rs:38-48` (`dynamic_loop` with no target filter), `web/via.rs:115-140` | **The web SOCKS port reaches anything the last hop reaches, for anyone on loopback.** It is unauthenticated (by design, R-WEB-VIA) and opens automatically with the window, not by an explicit forward. Any same-user process (T2) — and on a multi-user host any local user — can tunnel into the bastion's network under the user's SSH identity while the window is open; the remote page itself can also issue sub-resource requests to any internal host behind the bastion (navigation is policed, `fetch`/`img` are not) | Give `ChainProxy` a target allow-list: the start URL's `host:port` plus the hosts of the connection's `NavPolicy` allow-list (exact names, ports 80/443 and the start port); refuse other CONNECTs with SOCKS reply `0x02` and count them (`forward_refused`, first 16 audited). Optionally a random SOCKS5 username/password passed in `proxy_url` where the engine supports it. Test: a CONNECT to a host outside the list is refused | rust-core |
| L-49 | Low | `crates/mooring-proto-ssh/src/piv_auth.rs:206` (`add_smartcard`), `agent_wire.rs:12-13` (`ADD_SMARTCARD_KEY` = 20, unconstrained) | **The PIN-unlocked card stays loaded in the user's ssh-agent indefinitely.** `SSH_AGENTC_ADD_SMARTCARD_KEY` without constraints keeps the PKCS#11 session logged in until the agent exits: after the Mooring session closes, after the vault locks, any same-user process can sign with the card through `SSH_AUTH_SOCK` without the PIN. "PIN asked per use, never stored" (ADR-0027 §2) is true for Mooring but not for the effect | Send `SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED` (26) with `SSH_AGENT_CONSTRAIN_LIFETIME` (e.g. 3600 s, or the auto-lock interval) and remove the key on vault lock where the agent allows it (`REMOVE_SMARTCARD_KEY` needs the PIN, so lifetime is the practical bound). Say in the PIN dialog that the card stays loaded in ssh-agent for N minutes. Test with the fake PIV agent asserting the constraint bytes | rust-core, ui |
| L-50 | Low | `crates/mooring-secrets/src/bws.rs:199-217` (`ensure_checked`) | **The `bws` "SHA-256 pin" is a change log, not a gate.** On a hash change it audits `secret.tool_changed`, re-runs `--version` and then hands `BWS_ACCESS_TOKEN` to the changed binary in the same call. The pin is per process (R3 left open), and the file is hashed by path and then executed by path (swap window). On Intel Homebrew `/usr/local/bin` is user-owned, so T2 replacing `bws` is a one-line operation; T2 is accepted, but the audit row promises more than the code does | Persist the pin (`app_settings` `secret.bws_sha256:<path>`); on a mismatch refuse with an IpcError `secret.tool_changed` ("bws at … changed since it was last trusted; run Test on the secret source to trust it again") and re-pin only from `secret_source_test`. Keep the audit row. Test with the fake `bws` swapped between two resolves | rust-core |
| L-51 | Low | `src-tauri/src/commands/vault_export.rs:174-190` (`write_atomic`: `<name>.age.part`), `src-tauri/src/state.rs:436-445` (`create_private`: `create(true).truncate(true)`, no `create_new`, follows links) | **The backup temp file follows a pre-existing link and inherits a foreign file's mode.** The user may save into a shared or world-writable directory. A pre-planted `<name>.age.part` symlink makes Mooring truncate and overwrite the link target (any file the user can write) with the backup; a pre-planted regular file owned by another user keeps that user's ownership and mode (0600 applies on creation only), so they can read the encrypted backup (still behind a ≥ 12-character passphrase and scrypt N = 2¹⁸). `check_target` checks the final name only | Create the temp as `.<name>.<random 64-bit>.part` with `create_new(true)` (O_EXCL; and `O_NOFOLLOW` via `custom_flags` on unix) in the same directory; on `AlreadyExists` retry with a new nonce. Same helper for every `.part` writer in `state.rs`. Test: a symlink and a foreign-mode file at the old `.part` name are left untouched | rust-core |
| L-52 | Low | `crates/mooring-sync/src/merge.rs:246-322` (trust line-set union with `base = None`), `src-tauri/src/commands/vault_import.rs:12` | **A merge import can add trust for hosts the user already pinned.** The union keeps both sides' lines. A same-type second key fails closed (`trust_conflict`, L-35), but a line of **another key type** for an already pinned SSH host is "normal, no conflict", so a crafted backup (attacker's own vault, both passwords handed over with the file) silently adds an `ssh-rsa` / `ecdsa` key that a later MITM can present. The result lists row conflicts only, never trust lines | For a host:port that already has a local `known_hosts` line, drop imported lines of other key types (keep local), and report them as conflicts `{ kind: "trust", id: "<host:port>", resolution: "kept_local" }`. Same for `known_*_certs`: an imported pin for a host with a local pin is not added (today it becomes a fail-closed `trust_conflict`, a denial of service). Count added trust lines in the result and show them in the import summary. Test with a backup carrying an RSA key for a host pinned with Ed25519 | rust-core, ui |
| L-53 | Low | `apps/desktop/src/components/settings/ExportDialog.tsx:15-17`, `ImportDialog.tsx:24-29` | **Master password, export passphrase and source master password live in React state** for the dialog's lifetime (controlled inputs, re-rendered on every keystroke), unlike `SecurityCard`'s and the PIN dialog's uncontrolled inputs. R-IPC-BUF covers the IPC copy; the state copy is avoidable and contradicts the UI rule (cf. review 3 N-6) | Use uncontrolled `<input type=password>` with refs, read once on submit, clear the field after the IPC call and on unmount (the `SecurityCard` / `SmartCardPinDialog` pattern). Keep a boolean `empty` state for the button. Vitest: no secret string in the component's state after submit | ui-engineer |
| L-54 | Low | `.github/workflows/release-winget.yml:115-127`, `:179-188` (`submit` job: repository secret `WINGET_TOKEN`, no `environment`); `on: workflow_dispatch` | **The winget PAT is reachable from any branch.** A repository secret is available to `workflow_dispatch` runs of any ref; anyone with write access can dispatch a modified copy of this workflow from a branch and read the token (a PAT on the owner's `winget-pkgs` fork). `sign-*` and `sign-updater` are already behind `environment: release` | Put `submit` in `environment: release` (or a `winget` environment) with deployment rules limited to tags `v*` and move `WINGET_TOKEN` there (handoff decision 4: environment). `lint-workflows.sh` rule 7 then also requires the environment on the job | release-engineer, owner |
| N-72 | Nit | `crates/mooring-proto-rdp/src/gateway/conn.rs:236-242` | `random()` logs and returns zeros when the ring RNG fails; the WebSocket key, masks and `RDG-Connection-Id` become constant. No confidentiality depends on them (TLS carries them), but a failed system RNG should end the open | Return `Result` and fail the open with `protocol_error` ("system random source failed") | rust-core |
| N-73 | Nit | `crates/mooring-proto-rdp/src/gateway/http.rs:183-184` | For an IPv6 literal on port 443 the `Host` header is the bare address (`Host: 2001:db8::1`), not `[2001:db8::1]` (RFC 7230 §5.4); `host_port` is only used for other ports | Always build the header with `host_key` brackets for IPv6, omitting `:443` | rust-core |
| N-74 | Nit | `src-tauri/src/updater/install_mode.rs:169-179` | `winget_marker` follows links and reparse points (`File::open`); the release-engineer contract says "never follow a reparse point". Fail-safe (worst case: updates become manual) | `symlink_metadata` first; require `is_file()` and no `FILE_ATTRIBUTE_REPARSE_POINT` (reuse `dirs::is_link`) | rust-core |
| N-75 | Nit | `src-tauri/src/install_location.rs:437-441` (`codesign --verify --deep --strict`, no requirement) | The copy is checked for *a* valid signature, not for ours; any validly or ad-hoc signed bundle passes. The source is our own running bundle, so this is an integrity check, not authentication | Once Developer ID ships, add `-R="anchor apple generic and certificate leaf[subject.OU] = \"<TEAMID>\""` in signed builds (`cfg(mooring_signed_build)`) | rust-core |
| N-76 | Nit | `.github/workflows/release-winget.yml:162-164` | `Get-AuthenticodeSignature … -eq 'Valid'` accepts any trusted signer | Also compare `$sig.SignerCertificate.Subject` (or the Trusted Signing publisher) with a repository variable | release-engineer |
| N-77 | Nit | `src-tauri/src/biometric/mod.rs:31` (`SERVICE` constant) | The keychain service / Hello key name is not derived from the build identifier (ADR-0028 §1, 0028 handoff "Left open"). Dev and release share `io.github.yyasar21.mooring/<vault_id>`; a dev build that opens a same-vault backup and enrols replaces the release key (`ReplaceExisting`) → the release suspends with `biometry_changed`. Availability only | `SERVICE = app.config().identifier` (or `Channel::CURRENT`-suffixed) | rust-core |
| N-78 | Nit | `crates/mooring-proto-rdp/src/gateway/open.rs:97-109` | `usage: if_unreachable` takes the direct path when *any* TCP answer comes back within 3 s; a network attacker who can answer on the target port moves the session off the gateway (the RDP target's own TLS / NLA pin still applies, so no trust is lost — only the gateway's policy). Audited `outcome: direct` | Document in ADR-0027 and the UI hint ("for laptops that are sometimes on the internal network; the target's certificate pin still protects the session") | architect, ui |

### Answers to the focus questions

1. **Secret material reaching frontend / logs / errors / audit.** Not found. `GatewayAccount`,
   `SkLogin`, `PivLogin` and `ConnectSecret` debug-redact; NTLM / Basic headers are `Zeroizing`;
   `bws` stderr is dropped unread; lease ids are never sent (`session_list().leases[]` carries
   engine / expiry / state / `ttlSeconds`); `credential.pin_prompted` carries a fingerprint and
   an outcome; Hello / Keychain failures log an HRESULT / OSStatus only; the RDG close reasons are
   fixed strings + status codes. Inward secrets cross IPC as before (R-IPC-BUF): enrol/disable
   password, export passphrase, source password, PIN. L-53 for the two backup dialogs' React
   state.
2. **Unbounded parsing / allocation.** RDG head / body / frame / packet caps hold (above);
   `Conn.buf` is bounded by one frame plus one read; relay back-pressure through the 128 KiB
   duplex. Agent wire ≤ 256 KiB / 64 identities, sk blob ≤ 4 KiB, helper reply ≤ 64 KiB, `bws`
   stdout 1 MiB, 1Password lists capped, Vault lease id ≤ 1 KiB, PKI chain ≤ 16 × 64 KiB,
   `hdiutil` / `PlistBuddy` / `ps` output 256 KiB, winget marker 64 B, export 64 MiB + scrypt
   ceiling. 12 new fuzz targets (66) with the nightly-matrix inventory gate. `parse_hdiutil_info`
   has no fuzz target (qa decision needed): it is total, bounded and reads local tool output —
   the in-crate junk test is acceptable for 0.2.0.
3. **TOFU / pin bypasses.** Gateway pin: checked in the TLS verifier before any HTTP byte;
   mismatch hard stop; `trusted_once` only for the leaf the user saw; a Basic `Reopen`
   re-verifies the new TLS session. Hops: per-hop TOFU, mismatch → `hop_failed`, no direct-tcpip
   sent. Web-via: hop prompts are refused, never auto-answered. Kube: hop prompts go to the
   cluster channel and are answered through `session_send`. **Backup import** can add pins
   (L-52). **NTLM relay** past a first-contact TOFU (M-19).
4. **TLS verification gaps.** RDG uses the ADR-0011 `TofuVerifier` with system roots +
   `caPem`; 1Password Connect uses `mooring-http` pins, redirects refused. `bws` does its own TLS
   (R-SEC-CLI, documented). The RDP target keeps its own TLS / NLA pin inside the tunnel.
5. **Command / argv injection.** None: every tool is a fixed absolute path, explicit argv, no
   shell, `env_clear`; every path argument is absolute (starts with `/` or a drive), the `bws`
   arguments are validated UUIDs / project ids, `hdiutil detach` takes only a listed
   `/Volumes/<name>`, `open` passes our own flags after `--args`. `wingetcreate` gets the token
   in argv on an ephemeral runner (masked).
6. **Path traversal.** Export / import paths come from the Rust dialog (B-4 `pickId`), the app
   data dir is refused, names starting with `.` or holding control characters are refused (L-51
   for the `.part`). The winget marker is a fixed name in the exe directory (N-74). Portable
   roots unchanged since review 8 (M-18 / L-44..L-46 fixed in `173f740`).
7. **Downgrades.** Basic: opt-in per connection, audited, never after an NTLM leg, only inside
   pinned TLS. **EPA / CBT: not implemented** (M-19). Kerberos/Negotiate-only gateways are
   refused, not downgraded. `if_unreachable` (N-78). Updater: `DevBuild` → `Portable` →
   `Winget` → matrix, all fail to *manual*, never to an unsigned path.
8. **Move to Applications TOCTOU.** `existing` → `running` → `ditto` into a random-nonce temp
   → `codesign` → rename-aside / rename-in / rollback. Between the checks and the renames a
   writer of the target directory can swap entries; on `/Applications` that is an admin (the
   user, T2-equivalent) and on `~/Applications` the user, so nothing crosses a privilege
   boundary. `rename` and `remove_dir_all` do not follow a swapped-in link (std ≥ 1.58.1). The
   offer dialog runs before any window exists, so no unlock can race it. Accepted; N-75 for the
   signature requirement.
9. **Workflows.** No `pull_request_target`, no `workflow_run`; jobs default to
   `contents: read`; platform secrets only in `environment: release` jobs (lint rules 6/7);
   `mooring_signed_build` is set by a repo variable in the secret-free `build` job; the macOS
   signing keychain and the `.p8` are temp files removed by `trap`. L-54 (`WINGET_TOKEN` scope),
   N-76.
10. **IPC.** The nine new commands validate input (`pickId`, `mode`, `confirm`, password
    length / distinctness) and return `IpcError` codes from `ipc-codes.json` without secret
    text; `biometric_unlock` takes no argument and is rate-limited by the 3-in-10-min suspend.
    `session_send` answers stay id-routed (hop ids above `HOP_PROMPT_ID_BASE`). No capability
    widened.

### Carried items

| ID | Status | Evidence |
| --- | --- | --- |
| M-18 translocation refusal | **fixed** (`173f740`), extended by ADR-0028's move offer | `dirs.rs:203` `translocated`, `portable.translocated` code; `install_flow` ends every refusing slot in the same refusal |
| L-44 `$APPIMAGE` | **fixed** | `dirs.rs:207-241` (Linux only, `$APPDIR` / `/tmp/.mount_*`) |
| L-45 FAT/exFAT chmod | **fixed in code**; macOS exFAT/FAT32 gate still owed | `lib.rs:388` (`PermissionDenied`/`Unsupported` → `acl_unavailable`) |
| L-46 README over-claims | **fixed** | `packaging/portable/README.txt:15-18` (master password, cloud-sync warning) |
| N-65, N-66, N-68, N-70 | **fixed** (`173f740`) | as listed in that commit |
| N-67 icacls `/T` | open (nit) | `portable_acl.rs` unchanged |
| N-69 zip symlink targets | open (nit) | `portable-zip.py:58-97` unchanged |
| N-71 verify-release zip listing | open (nit) | `verify-release.sh` unchanged |
| **L-40 in-flight manifest cap** | **overdue** — accepted "until 0.1.1" under R-UPD; 0.1.1 and 0.1.2 shipped without it | `updater/download.rs:59-62` still post-parse. Fix or record an explicit R-UPD extension before `v0.2.0` |
| M-17 (3), L-14, L-42 remainder, L-28, G-1, per-OS dialog runs (7b) | unchanged, owner / gate items | — |

Left-open items of the A5 handoffs that are **not** findings (accepted for 0.2.0 as recorded):
`external_ref` credentials refused on hops; PKI has no connect consumer
(`revokeCertOnDisconnect` unwired, default off anyway); `database/creds` GET retry may orphan
one lease until its TTL; helper PIN unsupported (helper off); P-256 on-curve check left to agent
and server; `session_hops` re-adoption command absent; vSphere / Vault via chains refused at
save.

## Release gate for v0.2.0

Code (before the tag):
- [ ] **M-19** channel binding for RDG NTLM, with the mock-gateway test; ADR-0027 records EPA.
- [ ] L-47, L-48, L-49, L-50, L-51, L-52, L-53 fixed, or each explicitly accepted by the owner
      into the threat-model row named in its fix (R-WEB-VIA, R-SEC-CLI, R-PIV-AGENT, R-IMPORT-TRUST).
- [ ] **L-40** fixed, or R-UPD extended in writing with a new expiry.
- [ ] Nits N-72..N-78 scheduled (none blocks).

Release pipeline:
- [ ] **L-54**: `WINGET_TOKEN` in an environment with tag-only deployment rules before the
      secret is created.
- [ ] rc dry run (`v0.2.0-rc.1`) with `MACOS_SIGNING` / `WINDOWS_SIGNING` **unset**: sign jobs
      skipped, `sign-updater` / `publish` / `finalize` still run, `verify-release.sh` green,
      release identity asserted (`Info.plist` id, `dpkg-deb -f Package`, no `mooring-dev`
      asset), `release-winget` renders and validates and does not submit.
- [ ] If Touch ID ships: `keychain-access-groups` enabled in `packaging/macos/entitlements.plist`
      (+ provisioning profile if required), a signed rc built with `MACOS_SIGNING=true`,
      notarization `Accepted`, `spctl -a -vv` passes, and `security find-generic-password` for
      the item **fails** from Terminal. Otherwise the release notes say Touch ID needs a
      signed build (the app already answers `unsigned_build`).
- [ ] `SECURITY.md` supported-versions table gains `0.2.x` at publication.

Manual per-OS gate (fresh non-admin accounts, recorded in `docs/qa/`):
- [ ] **Windows Hello**: enrol, lock, unlock with Hello twice (signature determinism on the
      machine's KSP — the derivation depends on it), cancel ×3 → `vault.biometric_suspended`,
      password change → suspended, Hello PIN reset → `biometry_changed`.
- [ ] **Touch ID** (only with a signed build): as above plus enrolling a new finger →
      `biometry_changed`.
- [ ] **RD Gateway** against the lab gateway (`MOORING_LAB_RDG_HOST`, read-only): NTLM sign-in,
      TOFU prompt, pin change → hard stop, Basic refused without the option, an EPA-`Require`
      gateway after M-19, RDG through one jump host.
- [ ] **Web via** (Windows + Linux): a name only the bastion resolves loads; the L-47 WebRTC
      check; an unknown bastion key → `session.hop_failed`, nothing pinned; a lost hop closes the
      window; macOS → `web.via_unsupported`.
- [ ] **Security key**: YubiKey (Ed25519-sk, ECDSA-sk, resident) through the agent on all
      three OSes; touch banner; no touch → `touch_timeout`; key not in agent → the `ssh-add`
      hint, no password prompt.
- [ ] **Smart card / PIV**: YubiKey PIV via `ssh-add -s` and via the PIN dialog (opensc,
      ykcs11) on Linux and macOS; wrong PIN → `card_refused`; after L-49 the key leaves the
      agent at the lifetime; Windows OpenSSH agent behaviour recorded.
- [ ] **Backup**: export → import on a second machine (foreign vault, source password), merge
      and `REPLACE`; a 64 MiB+ file and a log N = 21 file are refused before any KDF; the L-52
      trust case.
- [ ] **Move to Applications** (macOS 26, release rc): every dialog slot from the DMG, from
      `~/Downloads` and translocated; `~/Applications` as a standard user; replace of 0.1.2;
      the relaunched copy is not re-translocated (or ends in the M-18 text); the volume
      detaches only when ours; audit rows carry no path.
- [ ] Carried from review 8: the portable gate (Windows NTFS / FAT32 / OneDrive, macOS exFAT and
      FAT32 launched in place) for the 0.2.0 portable zips.

## Test evidence
```
Linux x86_64, 2026-11-08, main @ 0eaafdb, CARGO_TARGET_DIR=/home/claude/nexus/target, CARGO_INCREMENTAL=0
git diff 6d14701..HEAD -- Cargo.lock                                   removals only (keyring, zbus tree)
cargo deny --offline check                                             advisories ok, bans ok, licenses ok, sources ok
cargo audit --no-fetch --db ~/.cargo/advisory-db/advisory-db-3157b0e258782691
                                                                       RUSTSEC-2023-0071 rsa (R-RSA); RUSTSEC-2024-0429 glib (accepted);
                                                                       unmaintained ×5 (was 7)
grep unsafe src-tauri/src crates/*/src                                 forbid(unsafe_code) only
cargo test -p mooring-proto-rdp --test gateway                         6 passed
cargo test -p mooring-proto-rdp --lib gateway                          15 passed
cargo test -p mooring-proto-ssh --test chain_proxy/hops/sk_keys/smart_card   2 / 8 / 10 / 4 passed
cargo test -p mooring-secrets                                          all passed (42 lib + 30 integration)
cargo test -p mooring-sync                                             all passed (41 lib + 38 integration)
cargo test -p mooring-app --lib (A5 filters)                           80 passed, 0 failed (384 filtered out)
bash scripts/release/tests/run.sh                                      9 suites, 0 failed
bash scripts/release/lint-workflows.sh .github/workflows               ok
```
Not run: macOS / Windows builds and every OS-specific path (Keychain, Hello, WebView2,
`ditto`/`codesign`/`hdiutil`), the workflows, `actionlint`, `pnpm test`, lab gates, real nightly
fuzzing.
