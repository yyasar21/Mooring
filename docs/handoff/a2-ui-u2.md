# A2 · ui-engineer · U2: connection options, certificate TOFU, known certificates, reconnect

Worktree `agent-a38a26a9fa293496c`, branch `worktree-agent-a38a26a9fa293496c`, from `a2` @ `f85a319`. Not merged.
Built against the real IPC JSON from `a2-rust-core-r2.md` and `a2-integration.md`. Checked in the browser with `MockTransport`.

## Done

| Commit | What |
| --- | --- |
| `2c93f08` | **Options IPC and validators.** `connectionOptionsGet/Set` are in `RemoteIpc` and `TauriTransport`. `CertificateInfo` gains `san` (decoded, at most 64 entries).<br>`lib/validate.options.ts` mirrors `mooring_core::options` with the same order and outcome as Rust's `check_url`. It covers: the closed KLID list, `maxFps ∈ {30, 60}`, CA PEM (certificate blocks only, no `PRIVATE KEY`, ≤ 64 KiB), web URL/origin rules (https, or http with `allowHttp`; no `user@`, no wildcards, port 1–65535, origins without a path, ≤ 16, ≤ 2048 bytes), serde-default normalisation and `deny_unknown_fields`.<br>`lib/hostHash.ts` recomputes `|2|salt|HMAC-SHA256(salt, host_key)` with WebCrypto, so a pin can be labelled with the user's own connection.<br>`lib/ipc.mock.options.ts` (`MockOptionsBase`) refuses what Rust refuses: unknown field (name only, no value), maxFps, wrong type, invalid value, 128 KiB. The mock drops stored options when the protocol changes, as `connections.rs` does. Mock pins now use real salted HMAC host fields.<br>`stores/connOptions.ts` is a per-connection options cache. **Rust `tree_list` rows carry no `options`**, so the initial VNC view-only (`sessions.ts`) and the clipboard policy (`RemoteSessionTab`) now read the cache. `open()` loads the cache before creating an rdp/vnc tab. |
| `d62e7d5` | **Connection form** (`components/dialogs/options/*`). A per-protocol section is loaded with `connection_options_get` and saved with `connection_options_set` after `connection_create/update`.<br>**RDP:** keyboard layout (9 KLIDs), clipboard policy, 30/60 fps, **Allow TLS without NLA**, and an extra CA PEM. When the TLS toggle is on, the box turns magenta and shows a warning. Read-only notes cover resolution (fit + Display Control), 32-bit colour and audio off.<br>**VNC:** security require/prefer/plaintext. A plaintext warning shows for prefer and allow, worded differently for each. Also view-only (default from options), shared, clipboard, fps, the read-only encodings list and an extra CA.<br>**Web:** start URL, an http opt-in with a warning, an origin allow-list editor (add with Enter or the button, duplicate and own-origin check, remove per row, n/16 counter), and persistent storage with the plaintext-on-disk, audit, clear-on-delete and macOS 11–13 note. A read-only note says the session always opens in its own window.<br>A protocol switch starts from that protocol's defaults. If an options save fails after a create, the dialog stays open and the next submit updates the created row, so no duplicate is made. Stored options that failed to load are **not** overwritten unless the user edits them. |
| `2acbefd` | **Certificate trust dialog** (`remote/CertificateTrustDialog.tsx`; `PromptModal` routes `certificate_trust` to it). It shows:<br>- the protocol chip and `host:port`;<br>- each problem with a one-line explanation;<br>- subject and issuer ("same as subject");<br>- validity in UTC, with the expired or not-yet-valid bound in magenta and a flag;<br>- SANs;<br>- SHA-256 as 8 groups of 4 bytes, with a full colon form as the aria-label.<br>The dialog turns magenta when there are problems. Focus starts on **Reject**, Escape rejects, Tab is trapped, and it answers only once. `name_mismatch`, `expired` and `not_yet_valid` need an "I compared the fingerprint" checkbox before **Trust and remember** is enabled. Trust is disabled when no certificate is present. Answers are R2's exact strings (`CERT_ANSWER = { trust: "yes", reject: "no" }`).<br>**Settings → Trust** (`settings/KnownCertsCard.tsx` and `useKnownCerts.ts`): an RDP/VNC switch, then `known_certs_list` with each hashed host matched against that protocol's connections. A row shows `host:port` and the connection names, or "Host not in your connections (stored hashed)". It also shows the grouped fingerprint and the first-seen date. There is a search over name, host:port, fingerprint (with or without colons) and date, an empty state, and a locked vault shown as an error, not as an empty list. **Remove…** opens a confirm dialog with focus on Cancel. An unmatched pin asks for host and port, and `removed: 0` says nothing matched. It calls `known_certs_remove`, which Rust audits as `cert_removed`.<br>**Errors:** `FRIENDLY` has entries for `session.trust_rejected`, `session.trust_mismatch` (the "remove the stored certificate in Settings → Trust if the server was reinstalled" guidance), `session.unsupported_security`, `protocol.unavailable`, `ipc.forbidden` and `clipboard.unavailable`. A `session_open` failure now shows `describeError`. `session.trust_mismatch` and `session.trust_rejected` keep their close code, so the banner title is right.<br>**Reconnect banner:** reads `{attempt, delay_ms}` (camelCase `delayMs` is still accepted) and shows a countdown, a 6-pip attempt meter and a progress bar (no transition under reduced motion). **Cancel reconnect** (`stores/sessions.reconnect.ts`) calls `session_close` and keeps the tab closed with code `user` and a Reconnect button. "Close tab" is still there. |

Screenshots in `docs/handoff/img/a2-ui/`, dark and light, 1440×860. They were taken with playwright-core and Chrome against `vite dev` (seeded mock).
- `06-rdp-options`: Edit dc01 with Turkish Q selected and TLS without NLA turned on.
- `07-cert-trust`: the first connect to dc01.
- `08-known-certs`: the pin after trusting.
- `08-known-certs-remove`: the confirm dialog.

## Left open
- **SSH `known_hosts`:** there is no list or remove command, so `KnownCertsCard.tsx` carries a TODO for it.
- **The brief's fields that Rust does not have.** None of them is in `RdpConnOptions`, `VncConnOptions` or `WebConnOptions`, so each is a read-only note or left out:
  - resolution mode fit/fixed and size;
  - colour depth;
  - audio;
  - VNC encodings;
  - web "detach by default".

  The RDP legacy toggle is Rust's `allowTlsWithoutNla`; there is no field called `allowLegacySecurity`.
- `connection_create/update` still ignore `options`, so there are two IPC calls per save. If the second call fails, the row exists without its options, and the dialog says so.
- The host-hash matching runs one HMAC per (pin × connection of that protocol). This is fine for hundreds of pins. For very large stores, cache by salt.
- The mock never produces `session.unsupported_security` or `trust_mismatch` on its own. Tests inject them with spies.

## Decision needed
1. **"Trust once"** is not offered. R2's gate treats every answer other than `yes` as a rejection, and `trusted_once` is set only when the pin cannot be written. A "Trust once" button that sent `once` would quietly reject. Rust would need a third answer, `once` → `trusted_once` without writing the pin and audited as `accepted_session_only`, before the UI can offer it. Architect and rust-core to decide.
2. **Security-reviewer: local host-hash matching.** The UI recomputes the HMAC with hosts it already has, in order to label pins. Nothing new leaves the WebView, and an unmatched pin stays anonymous. Please confirm this is acceptable under the ADR-0011 "hosts stored hashed" intent.
3. `connection_options_set` is still not audited, for example when `allowTlsWithoutNla` or `persistent` is turned on (R2 open item). The UI warns, but the change itself leaves no audit trail.

## Test evidence
- `pnpm install --frozen-lockfile`, `pnpm lint`, `pnpm typecheck`, `pnpm test` and `pnpm build` are green from the worktree root.
- **Vitest: 38 files, 279 passed, 0 skipped.** The baseline was 33 files and 242 tests.
- **New test files:**
  - `lib/validate.options.test.ts` (9): the URL cases copied from `options/tests.rs`, CA PEM, KLID/fps, normalisation and unknown fields, HMAC host matching (including IPv6 and plain lines), and the mock options round trip and refusals, including dropping options on a protocol change.
  - `components/dialogs/options/options.test.tsx` (8): RDP load, edit and save; CA PEM blocking; VNC warnings; the web origin editor and persistent note; options on create; protocol switch; a failed save making no duplicate; no blind overwrite.
  - `components/remote/CertificateTrustDialog.test.tsx` (8): content, focus, `yes`/`no`, Escape, the serious-problem check, the Tab trap, no-cert, end to end with the mock, and helpers.
  - `components/settings/KnownCertsCard.test.tsx` (5): empty state, labelling, search, confirmed audited removal, the unmatched pin, the locked vault, and `filterPins`.
  - `stores/sessions.trust.test.ts` (6): friendly texts, the trust close code on an open failure, view-only from `connection_options_get`, cancel reconnect, and backoff maths.
- **Extended tests:**
  - `ipc.remote.test.ts`: `delay_ms` and `delayMs`, `san`.
  - `ipc.tauri.remote.test.ts`: `connection_options_get/set` names and arguments.
  - `RemoteSessionTab.test.tsx`: Trust and remember, the attempt meter, Cancel reconnect.
- `errors.codes.test.ts` (N-14) is green: every new `FRIENDLY` key is in `src-tauri/ipc-codes.json`, and the new mock file throws only `input.invalid`.
- **File sizes:**
  - `ipc.mock.ts`: 495 lines.
  - `stores/sessions.ts`: 475 lines. The cancel logic lives in `sessions.reconnect.ts` to keep it under the limit.
  - Every other file is under 450 lines.
