# A5 · ui-engineer · U1–U3: jump hosts, biometric unlock, backups, Mooring Dev

Worktree `/home/claude/nexus/.claude/worktrees/agent-a965dd76203e05f41`, branch
`worktree-agent-a965dd76203e05f41`, from `main` @ `eea1e00`. Not merged. No cargo run, no manifest,
lockfile or capability change. The contracts are the "UI contract" sections of
`a5-rust-core-r1.md` (ADR-0025), `a5-rust-core-r2.md` (ADR-0022/0023) and `a5-rust-core-0028.md`
(ADR-0028). Every code the UI shows text for was checked against `src-tauri/ipc-codes.json`
(`errors.codes.test.ts` enforces it).

Harbor note (`docs/design/review-2026-11/README.md`): the screens use today's tokens and
primitives (`btn`, `field`, `field-label`, `Toggle`, `SettingsCard`, `Modal`). The new CSS
(`styles/a5.css`) adds no HUD brackets and no tracked caps. All new text is sentence case in
the sans face, and every colour is a token. The new Settings cards leave out the `m-micro`
kicker (`SettingsCard.kicker` is optional now). The Harbor reskin is therefore a token and
primitive swap.

## Done

### U1 — jump hosts (ADR-0025)
- **Types / IPC.** `lib/ipc.types.a5.ts`: `HopStatus`, `HopState`, `MAX_VIA`. `ConnectionSummary.via?` and `ConnectionFields.via?` (omitted on update = keep the chain, `[]` = clear it). `SessionEvent` adds `hop_status` and `prompt.hop?`. `CloseCode` adds `hop_failed` and `hop_lost`. `decodeSessionEvent` handles `hop_status`: an out-of-range hop or `of`, or an unknown state, decodes to a `closed/unknown` event, the same as any other event it cannot read. A `hop` value is attached to a prompt only when it is a valid index.
- **Connection form.** `components/dialogs/ViaSection.tsx` adds a "Connect via" section: an ordered list with Up / Down / Remove per row and an "Add jump host" picker. The picker offers SSH connections only and leaves out the connection itself, hosts already in the list, and any host whose own chain goes through this connection (a loop). It stops at 3 ("At most 3 jump hosts"). A route line shows `you → bastion01 → … → target`. Web connections get the note "cannot open through a jump host yet". vCenter connections get no section. A VNC connection with `allow_plaintext` gets an ADR-0025 T8 warning. The form always sends `via` (`[]` for protocols without chains). The picker rules are in `lib/via.ts`. `ConnectionDraft.via` survives the "New credential…" round trip.
- **Errors.** `stores/errors.ts` has friendly text for `connection.via_invalid`, `connection.in_use_as_hop`, `session.hop_failed` and `web.via_unsupported`. The tree store uses the friendly text for the two `connection.*` codes; other codes keep Rust's specific message, as before. When a delete is refused because the connection is a jump host, the dialog adds "Used by: stage-app." It works this out from the tree.
- **Session tab.** `withHop` in `stores/sessions.ts` keeps the latest `hop_status` per hop on `Tab.hops`. A hop-0 `connecting` event starts a new chain, which covers reconnects. `components/terminal/HopStrip.tsx` shows one chip per hop: connecting, signing in, connected or failed, with `host:port`. The chips show while the chain comes up and after a failure, and hide once the target connects. `PromptModal` and `CredentialPrompt` name the hop: "Jump host bastion01: verify host identity", "Jump host bastion01: sign in" and "Jump host bastion01 asks". Rust's "Hop 1 of 1 — host:port" stays in the body. The closed-tab text for `hop_failed` and `hop_lost` is in `CLOSE_TEXT` (remote banner) and in the SSH "Link lost" overlay.
- **Tree / details.** A tree row shows "via bastion01" (and adds ", via …" to its accessible name). The details pane has a "Connect via" row: `bastion01 → bastion02`.
- **To keep files under 500 lines:** tab and prompt types moved from `stores/sessions.ts` to `stores/sessions.types.ts` (re-exported). The mock tree and credential commands moved from `ipc.mock.ts` to `ipc.mock.tree.ts` (class `MockTreeBase`).
- **Mock.** `ipc.mock.tree.ts` validates `via` the way R1's `validate_via` and the store do: depth, self, duplicate, missing, non-SSH, two-way cycle and vCenter. Messages never echo an id. A delete or folder delete that would remove a hop still in use is refused (`connection.in_use_as_hop`); a subtree holding the whole chain cascades. `ipc.mock.hops.ts` (`MockHopChain`) brings each hop up in order: connecting → hop TOFU (id 1000+i, `hop: i`) → authenticating → hop credential prompt for a `prompt` kind (id 2000+i) → up. It then hands over to the target's usual flow. A rejected hop key, a failed hop sign-in or a hop tagged `hop-fail` ends the session with `hop_failed`, and the target is never asked anything. RDP/VNC targets get quiet `connecting`/`up` events before their own. Seed: new `bastion01` (`c-bastion`, Staging), and `stage-app` goes via it.

### U2 — biometric unlock (ADR-0022) and backups (ADR-0023)
- **IPC.** `TauriTransport` gains `biometric_status/enroll/unlock/disable`, `vault_export_pick/age` and `vault_import_pick/inspect/age` with camelCase args (`ipc.tauri.a5.test.ts`). None of them is polled.
- **Settings → Security** (`SecurityCard.tsx`, `stores/biometric.ts`). The "Unlock with Touch ID / Windows Hello" toggle (Linux: "biometrics") reads `biometric_status`. Turning it on or off opens an inline master-password step, and only then do `biometric_enroll` / `biometric_disable` (and the OS prompt) run. Unavailable reasons show as helper text with the switch disabled:
  - `unsigned_build` → "Touch ID needs a signed build of Mooring…"
  - `no_acl` → "Not available on Linux…"
  - `keychain_unavailable` and `not_enrolled` have their own texts.

  A suspended enrolment shows "… unlock was turned off because <reason>". Friendly texts cover every `biometric.*` code; `vault.unlock` in these flows reads "The master password is wrong."
- **Unlock screen.** `VaultGate` reads the passive status. It shows "Unlock with Windows Hello" (or Touch ID) only when the feature is available, enabled and not suspended, and never starts a prompt on its own. `useApp.unlockBiometric()` unlocks and loads the vault. After a password unlock, a suspended enrolment raises one toast per reason per window ("… See Settings → Security"), as the contract asks.
- **Settings → Backup** (`BackupCard`, `ExportDialog`, `ImportDialog`, `lib/passphrase.ts`).
  - **Export:** master password, then the backup passphrase twice with a strength hint (length and word count; under 12 is blocked; it must differ from the master password). Then Rust's native save dialog (`vault_export_pick`), then `vault_export_age`, and a summary with counts and size. A refused export keeps the pick (the file is not asked for again). Password fields are cleared after every attempt.
  - **Import:** the native open dialog first. Then the passphrase → inspect (exported at, app version, counts, same or another vault). A foreign vault shows a notice and asks for the source vault's master password. Merge is the default; Replace needs `REPLACE` typed exactly and offers "Export a backup first…", which opens the export dialog on top. Then the master password → result (added / updated / skipped, plus the conflict list with plain-English resolutions). The tree and credentials reload after an import. After 3 wrong passphrases the pick is gone, and the dialog says to choose the file again.
- **Mock** (`ipc.mock.a5.ts`, `MockA5Base`):
  - Biometric knobs: platform, unavailable reason, enabled, suspended, and the next OS outcome. The third failure within 10 minutes suspends with `failed_attempts`. `vault_change_password` suspends with `password_changed`; a foreign Replace suspends with `vault_rotated`. `biometric.sync_enabled` is returned while sync is configured.
  - Backup knobs: pick OK or cancel, the backup file (foreign, version, passphrase), and the 3-try passphrase rule. Picks are single use and dropped on lock.
  - Each step writes the R2 audit events.
  - `masterPassword` is set by `vault_create`.

### U3 — Mooring Dev (ADR-0028)
- `AppInfo.channel?` and `identifier?`; `UpdateManualReason` adds `dev_build` (decoder too).
- When `channel === "dev"`, a "Dev" badge (`DevBadge.tsx`) appears next to the wordmark and next to the name in About. About also adds "Mooring Dev — development build, separate data from Mooring (io.github.yyasar21.mooring.dev)."
- In dev, Settings → Updates shows "Updates are disabled in development builds. Install a release from the Releases page." The Check button and the background switch are disabled. `MANUAL_REASON_TEXT.dev_build` uses the same text.
- The mock has a `buildChannel` knob. In dev, check, install and background-on are refused with `update.manual_only` / "development build: updates come from your own builds"; settings get and background-off still work.
- Release builds are unchanged (tested).

## Left open
- **Kubernetes cluster tabs through a chain.** R1 sends hop prompts and `hop_status` on the `kube_open` channel, but the UI's `kubeOpen` takes no event channel today. A cluster behind a jump host therefore cannot answer a hop prompt from the UI. The fix is a channel argument on `kube_open` (a shared rust-core + UI change). Exec shells use `session_open` and are covered.
- **Graphical hop prompts in the mock.** RDP/VNC chains come up without hop questions in the mock (quiet `connecting`/`up`). The UI path is the same `PromptModal` as SSH, so the hop naming is covered by the SSH tests.
- **`session_hops` re-adoption** is not there (R1 left it open). After an unlock, an adopted tab has no chips until the next `hop_status`, which is harmless.
- **`ImportResult.added/updated/skipped`** are typed as numbers. The R2 contract lists the names without types; if Rust sends per-kind counts, change `ImportResult` and the one summary line.
- **The Rust message for a dropped import pick** is assumed to contain "pick" (`input.invalid`, field `pick`). The dialog uses it to say "choose the file again"; any other message shows as is.
- **e2e:** `apps/desktop/e2e/a5.e2e.mjs` (5 flows) follows the a4 harness style, and `e2e/boot.ts` accepts `?channel=dev`. **`make e2e` does not run it yet.** The Makefile is outside my scope; add `node --test --test-concurrency=1 --test-reporter=spec apps/desktop/e2e/a5.e2e.mjs`. qa can extend it.
- **Screenshots:** in this worktree the fonts fell back to system faces, because `node_modules` is a symlink outside Vite's `fs.allow`. Layout and colours are correct.

## Decision needed
- **Seed change.** `bastion01` was added and `stage-app` now goes through it, so `pnpm dev` and the e2e flows show a chain without setup. Opening stage-app now asks for bastion01's host key first. No existing test depended on the old behaviour; qa should confirm that is fine for their flows.
- **Settings card kickers.** The new Security and Backup cards have no `m-micro` kicker, in line with Harbor. Until the reskin they look slightly plainer than their neighbours. The alternative is to add kickers now and remove them all in the Harbor wave.

## Test evidence
Linux x86_64, 2026-11-08, worktree @ this branch, `node_modules` symlinked from `/home/claude/nexus`.

```
pnpm typecheck   ok (packages/ui, apps/desktop)
pnpm lint        ok (eslint src, 0 problems)
pnpm test        Test Files 84 passed (84) · Tests 622 passed (622)    (main: 76 files / 576 tests)
pnpm build       ok (mock stays in its own lazy chunk)
make e2e         flows 5/5 · kube 6/6 · vsphere 4/4 · secrets-sync 7/7 · a4 11/11 — 33 passed, 0 failed
a5.e2e.mjs       5/5 (jump host, Connect via, Windows Hello, backup export+merge, Mooring Dev)
```

New vitest files (46 tests):
- `lib/via.test.ts`: picker rules, chain text, the mock store checks, keep/clear `via`, and hop-in-use refusals for a connection and a folder.
- `lib/ipc.hops.test.ts`: the decoder (valid and hostile `hop_status`, hop-tagged prompts, `hop_failed`/`hop_lost`), `withHop`, and the mock chain order. Also covers a hop TOFU reject giving `hop_failed` without the target ever being asked, a hop credential prompt, a `hop-fail` hop, and graphical hop events.
- `lib/ipc.tauri.a5.test.ts`: command names and arguments, `via` on create/update, none polled.
- `components/dialogs/via.test.tsx`: add / reorder / remove / route / save, then the tree row and details. Also the cap of 3, the `via_invalid` text, the delete refusal with "Used by", and web/vCenter.
- `components/terminal/hops.test.tsx`: the hop prompt naming the hop, chips through connecting → connected → hidden, a failed chip with the `hop_failed` text, and a jump-host credential prompt.
- `components/settings/security.test.tsx`: enrol and disable behind the password, cancel, empty password, `unsigned_build` / `no_acl` / `keychain_unavailable`, and suspended. On the unlock screen: the button only when enabled, a click unlocks, the third failure suspends, and the next password unlock shows the notice.
- `components/settings/backup.test.tsx`: strength and form rules; export (mismatch, success counts, cancelled pick, wrong master keeping the pick); import (wrong passphrase, merge with conflicts, Replace gated on `REPLACE` and "Export first", foreign vault with the source password, v1 refused, cancelled pick).
- `components/settings/devbuild.test.tsx`: the Dev badge in the title bar and About only in dev, the Updates text and disabled controls, and the mock refusals.

Changed existing tests: `RemoteSessionTab.test.tsx` (the `CLOSE_TEXT` key list gains the two hop codes, plus one hint assertion). `test/harness.ts` resets the biometric store.

Screenshots (dark and light, 1280×800, mock transport) are in `docs/handoff/img/a5-ui/`:
- `01-connect-via`
- `02-hop-prompt`
- `03-hop-failed`
- `04-security-enrol`
- `05-export`
- `06-import-review` (foreign vault + Replace)
- `07-import-result`
- `08-unlock-hello`
- `09-dev-about`
