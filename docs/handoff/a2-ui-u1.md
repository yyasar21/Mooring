# A2 · ui-engineer · U1: IPC clients, MFR1 decoder, RemoteCanvas, RDP/VNC tab

Branch `worktree-agent-af044065a68a71b0f`, on top of `main` @ `5f4f393` (ADR-0011/0012/0013 accepted).
Built against `MockTransport`. Nothing here talks to the Rust A2 commands yet.

## Done

| Commit | What |
| --- | --- |
| `52fc548` | **MFR1 decoder** `lib/frame/mfr1.ts`. A pure decoder for the ADR-0011 layout: a 16 B header, then 10 B records with kind-specific fields. Pixel views are zero-copy. It throws a typed `Mfr1Error` (`truncated`, `bad_magic`, `bad_flags`, `bad_kind`, `reserved`, `limit`, `out_of_bounds`, `trailing`) and checks every length before reading. The loop is bounded by `n ≤ 256`. `peekSeq` reads the seq of an undecodable message so its credit can still be returned. `mfr1.encode.ts` (encoder) and `synthetic.ts` (a moving-gradient desktop) are for the mock and tests only. |
| `8636998` | **Typed IPC and mock.** `lib/ipc.types.remote.ts` defines `ProtocolOptions` (`RdpConnOptions`, `VncConnOptions`, `WebConnOptions` and defaults), `CloseCode`, `CertificateInfo`, `KnownCert`, `WebEvent`, `RemoteIpc` and the limits. **New `SessionEvent` members:** `connected.security`, `closed.code`, `prompt.certificate` (`purpose: "certificate_trust"`), `desktop_resized`, `reconnecting {attempt, delayMs}` and `detached`. **Changes to `SessionInput`:** `frame` is removed and `key` becomes `{code, key, pressed}`. New inputs: `wheel`, `unicode`, `release_all` and `clipboard_offer`. **`TauriTransport` clients:** `session_open` (+ raw `onFrame` Channel, rdp/vnc only), `session_frame_ack`, `session_screenshot`, `session_set_view_only`, `known_certs_list/remove`, `web_open/close/focus/reload/print/clear_data/zoom/list`, `window_detach` (now returns `{windowLabel}`), `window_attach` and `session_attach`. Decoders live in `lib/ipc.decode.session.ts`. **MockTransport additions:** `ipc.mock.remote.ts` (cert TOFU, frames at about 30 fps under a 2-credit limit, view-only drops, clipboard offer, screenshot, known-certs store, `dropLink` reconnect) and `ipc.mock.web.ts` (web window stubs, `session_attach`, audit commands). The `flaky` tag on the seed `lobby-kiosk` drops the link once, 4 s after connect, for the demo. `POLLED_COMMANDS` gains `session_frame_ack`. **Sessions store:** new tab fields (`protocol`, `security`, `closeCode`, `reconnect`, `desktop`, `viewOnly`) and states `reconnecting` / `detached`. Frames go to a per-tab queue (`stores/frames.ts`). Frames that arrive while the vault is locked are acked and dropped. After an unlock, a graphical session is re-attached (`session_attach`) so Rust resends a full frame. Events from a replaced channel are ignored (sink generation). |
| `84464e4` | **`components/remote/RemoteCanvas.tsx`.** **Rendering:** one RGBA8 texture the size of the framebuffer, with one `texSubImage2D` per RGBA rect. Fill rects use a scissored clear on an FBO. Copy rects go through a scratch texture, so overlaps stay correct. Then one quad per animation frame. Canvas 2D `putImageData` is the fallback, and context loss/restore is handled. **Credits:** each message is acked only after the frame that drew it is presented. Undecodable messages are acked as well. Received-but-undrawn messages are acked on unmount. **Layout:** letterbox, shrink to fit, never enlarged. The WebGL backing store is display size × `devicePixelRatio` (capped at 4). The filter is NEAREST at integer scale, LINEAR otherwise. A container change asks for a new desktop size after 300 ms (even width, 200–8192). **Input:** pointer in framebuffer pixels with ADR button bits. Wheel in 120-per-notch steps, with fractions carried and an i16 clamp. Keys by `code` through a hidden textarea; keyup is sent only for keys we pressed, and modifiers are resynced on key and pointer events. IME: keydowns with `isComposing`/229 are skipped and `compositionend` text is sent as `unicode` (≤ 64 code points per message). Blur sends `release_all`, and focus sends `clipboard_offer` when the policy allows. `Ctrl+K/W/I` belong to the remote, as in a terminal (`useShortcuts`). **Overlay:** fps, MB/s, size and renderer. |
| `32be939` | **`RemoteSessionTab`**, used by `Workspace` for rdp/vnc. **Toolbar:** a security badge (NLA / TLS without NLA / Unencrypted), the VNC view-only chip and toggle, Send clipboard (respects the `clipboard` policy and is disabled in view-only), a "Remote copies: automatic/off" note, Screenshot and Stats. **`ConnectionBanner`:** connecting; reconnecting with a ticking countdown and "Attempt n of 6"; detached; closed, with a title and hint per close code, the reason, Close tab and Reconnect. `PromptModal` handles `certificate_trust` with `CertificateDetails` (subject, issuer, validity, SHA-256 in byte pairs, problems). |
| `4c8ae8f` | Fix: the desktop size the canvas asked for while the TOFU prompt was open is now sent once the session connects, and again after each reconnect. |
| `9a9038d` | Screenshots. |

## Left open
- **U2 scope, not done here:** RDP/VNC connection forms from `ProtocolOptions`, the full TOFU dialog, the known-certs manager UI, and friendly texts for the new IpcError codes. `session.trust_mismatch`, `session.trust_rejected`, `session.unsupported_security`, `ipc.forbidden` and `web.origin_refused` are not in `src-tauri/ipc-codes.json` yet, so the mock does not throw them (N-14 guard). The certificate prompt in `PromptModal` is a minimal version.
- **U3 scope:** web session tabs, detach/attach UI and the "bring back" button on the detached placeholder. The web and attach commands are typed and mocked only.
- **No full-frame request after WebGL context loss.** The texture is rebuilt black and stays partly black until Rust next sends a full rect. A `refresh` input or using `session_attach` for this would fix it.
- **The mock RDP host does not ask for `prompt` credentials** (`needs_domain`). It always uses the effective credential.
- **Coalescing pointer moves:** identical positions are dropped, but moves are not yet throttled to one per animation frame. With 1 kHz mice this is up to 1000 `session_send` calls per second. Measure with R2 before adding a throttle.
- **No resize test:** jsdom has no `ResizeObserver` or layout, so the debounced desktop request is covered only by the pure `desktopRequest` test and the screenshots.
- `polled.test.ts` traces only `setInterval`. Acks run from `requestAnimationFrame` through a callback, so they are not traced; the constant is asserted directly instead.

## Decision needed
1. **Receive-clipboard button.** ADR-0011 has no command to pull the remote clipboard: remote → local is automatic on a format-list announcement. The UI shows a status note instead of a "receive" button. If an explicit pull is wanted, the ADR needs a `ClipboardFetch` input.
2. **Wheel sign.** The UI sends the DOM sign (`dy > 0` = scroll down/towards the user). R3/R4 must negate it for RDP (positive = away from the user) and map it to VNC buttons 8/16. The alternative is to fix the sign in the ADR.
3. **Credits after `session_attach` and `window_detach`.** The mock resets in-flight credits on attach. Rust should do the same, because the old view's unacked frames are never acked.
4. **Should `web_list` also be in `POLLED_COMMANDS`?** ADR-0013 marks it passive. Nothing polls it yet.

## Contract assumptions for R2
- `session_open({connectionId, size, onEvent, onFrame?})`: `onFrame` is a separate `Channel` whose messages are raw binary MFR1 (one message = one `ArrayBuffer`). The UI also tolerates typed arrays and number arrays. `size` for rdp/vnc is in **CSS pixels** (even width, 200–8192); the initial request is 1280×800 until the canvas measures itself.
- `session_frame_ack({sessionId, seq})`: **one ack per message**, with that message's `seq`, sent after it is drawn (or after it failed to decode, or was dropped while locked or unmounted). It must be passive: **add it to `src-tauri/ipc-passive.json`**. The guard test `session_frame_ack is passive in Rust` is skipped with a message until the file lists it.
- **MFR1 strictness** (UI decoder): `fbW`/`fbH` ≥ 1; unknown flag bits are refused; the reserved byte must be 0. For kinds 1–3 the rect must lie inside the framebuffer (and so must the copy source). For cursor records, `x`/`y` are ignored, `w`,`h` ≤ 384 and the hotspot ≤ `w`/`h`. Kinds 5/6 have no extra fields. No trailing bytes are allowed. The first message after open, reconnect or attach should be `full`.
- **Event wire shapes** (snake_case, camelCase tolerated): `connected {protocol, peer_identity, security}`, `prompt {…, purpose: "certificate_trust", certificate: {subject, issuer, not_before, not_after, sha256 /* hex */, problems: [...]}}`, `desktop_resized {width, height}`, `reconnecting {attempt, delay_ms}`, `detached {}`, `closed {reason, code}`. An unknown `code` is shown as "Disconnected".
- **Certificate answer:** `answer {id, text: "yes" | "no"}`, as for SSH TOFU.
- **Inputs:** `key {code, key, pressed}`, `wheel {dx, dy}`, `unicode {text}`, `release_all {}`, `clipboard_offer {}`, `pointer {x, y, buttons}`, `resize {size}`. `release_all` is also sent in view-only mode and must not be dropped by the view-only filter.
- `known_certs_list` returns `[{hostHash, fingerprint, addedAt}]`; `known_certs_remove` returns `{removed}`. `session_screenshot` returns `{width, height}`. `window_detach` returns `{windowLabel}`. `session_attach` returns `{protocol, state, size}`, and the old view gets `detached`.
- `connection.options` is the plain per-protocol object (camelCase fields as in the ADRs), absent or `{}` for others.

## Test evidence
- `pnpm lint && pnpm typecheck && pnpm test && pnpm build` green from the worktree root.
- **Vitest: 33 files, 241 passed, 1 skipped.** The baseline was 26 files, 185 tests. The skip is `session_frame_ack is passive in Rust`, pending R2.
- **New test files:**
  - `lib/frame/mfr1.test.ts` (8): hand-built LE vectors, every kind, the limits, hostile and mutated input never throws anything but `Mfr1Error`.
  - `lib/ipc.remote.test.ts` (8): decoders and mock RDP/VNC/web behaviour.
  - `lib/ipc.tauri.remote.test.ts` (4): command names and argument shapes.
  - `components/remote/input.test.ts` (10).
  - `components/remote/RemoteCanvas.test.tsx` (12): a mocked WebGL2 or 2D context and manual rAF; `texSubImage2D` per rect, acks after `drawArrays`, copy via scratch, 2D fallback, cursor, pointer/wheel/keys/IME/modifiers/focus/blur, view-only.
  - `stores/sessions.remote.test.ts` (6): the tab state machine.
  - `components/remote/RemoteSessionTab.test.tsx` (6).
- **Screenshots** in `docs/handoff/img/a2-ui/`, dark and light, 1440×860, taken with `playwright-core` from `/opt/node-tools` driving Chrome (SwiftShader WebGL2) against `vite preview`:
  - `01-rdp-certificate`
  - `02-rdp-connected`: stats overlay at 19 fps, 834×704. SwiftShader is software rendering, so this is not a benchmark.
  - `03-vnc-view-only`
  - `04-vnc-reconnecting`
  - `05-rdp-closed`
- `ipc.mock.ts` is 491 lines and `stores/sessions.ts` is 466. Both are close to the 500-line limit, so the next additions belong in new modules.
