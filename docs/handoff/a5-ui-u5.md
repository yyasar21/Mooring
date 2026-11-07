# A5 · ui-engineer · U5: security-key SSH credentials and the touch banner (ADR-0024)

Worktree `/home/claude/nexus/.claude/worktrees/agent-a419d74f7d4412b86`, branch
`worktree-agent-a419d74f7d4412b86`, from `main` @ `fee0bd0` (R4 merged, ADR-0024 accepted). Not
merged. No cargo run, no manifest, lockfile or capability change. The contract is the "UI contract
(U4)" section of `a5-rust-core-r4.md`.

Harbor note: the new CSS (`styles/a5-sk.css`) uses today's tokens only. Text is sentence case in
the sans face, with plain borders. There are no HUD brackets and no new `m-micro` labels: the new
headings are `.sk-heading` and the close titles `.dropped-title`. The touch indicator's ring
animation is switched off under `prefers-reduced-motion`.

## Done

### 1. Failing test on main
- `ipc.kinds.ts` gains the `ssh_sk_key` row, byte for byte as in `kinds.snapshot.json`.
  - The table position follows the snapshot: 5th, after `ssh_agent`, in the SSH group. The
    brief said "18th, before `bitwarden_access_token`". That is the `CredentialKind::ALL` order,
    and `CREDENTIAL_KINDS` follows it.
  - `ipc.kinds.test.ts` passes.
  - The kind counts in `ipc.test.ts` and `stores/credentials.test.ts` went from 18 to 19.
  - The ADR matrix table in `lib/credentials.test.ts` gained the `ssh_sk_key: ["ssh"]` row.

### 2. Credential form, card, refusal, audit
- **Form** (`SkKeySection.tsx`). It replaces the generic plain-field section for `ssh_sk_key`.
  - **Username.**
  - **Public key.** Paste it, or use "Open .pub file…" (a page-side file read, capped at 16 KiB).
    A file that contains `PRIVATE KEY` is refused with a pointer to the key handle input, so a
    private key never lands in a plain field.
  - **Live preview of the public key.** Type (Ed25519 / ECDSA P-256 security key), the FIDO
    application read from the blob, and the real `SHA256:` fingerprint.
  - **Signing.**
    - "Through your ssh-agent" is the default.
    - "Directly with ssh-sk-helper" is disabled, with "Direct security-key access (without
      ssh-agent) is coming later".
    - A stored `helper` value stays selected, with a warning.
  - **Resident key.** A checkbox (`"true"` / `"false"`).
  - **OpenSSH certificate.**
  - The key handle file and its passphrase are the generic secret inputs, with a hint: both are
    optional, and only needed for direct signing.
  - The stored `application` is shown read-only when editing.
  - Contract note: `application` is derived in Rust and refused on input (R4), so it is shown,
    never edited. The brief's "application string" input does not exist.
  - There is no Rust-side file pick for the handle, so it is pasted.
- **Client-side shape checks** (`lib/credentials.sk.ts`, wired into `formModel.validate`). Rust
  decides; these only catch the obvious mistakes:
  - the two `sk-*` types and their base64;
  - the wire strings match the type, with no trailing bytes;
  - `ssh:` application, 4 KiB blob and 256 B application caps;
  - a regular `ssh-*` key or a certificate pasted as the key is named as such;
  - the certificate must be `sk-*-cert-v01`.
- **Paste routing** (`detectKind`):
  - An `sk-*` public line picks `ssh_sk_key` (into `public_key`).
  - An `openssh-key-v1` file whose clear-text key type is `sk-*` picks `ssh_sk_key` (into the
    `private_key` secret input).
  - Any other OpenSSH key still picks `ssh_key`.
- **Detail card** (`SkKeyDetail.tsx`):
  - "Signs through your ssh-agent. Touch the key when Mooring asks; there is never a password
    fallback."
  - Type, application, resident (with the matching `ssh-add` form), whether a certificate is
    stored, and the fingerprint (in the card's Credential section).
  - The **certificate role** lines (`CertificateSection`) now also show for `ssh_sk_key`.
- **`credential.use_sk_kind`** on the `ssh_key` form (`UseSkKindNote.tsx`):
  - When Rust refuses, the form shows "This is a security-key key — create a Security key
    (FIDO2) credential instead", with a button "Create Security key (FIDO2) credential". The
    button opens the new form pre-filled with name, username, the `sk-*` public key and the
    certificate.
  - `Seed.values` (plain values only). The handle is a secret and is never carried over; the
    note says so.
  - The same note appears before saving when the typed public key or certificate is `sk-*`.
  - `useCredentials` now keeps `errorCode` next to `error`.
- **Audit view.**
  - `credential.sk_converted` → "SSH key converted to a security-key credential", with the `id`
    resolved to "credential: <name>".
  - `session.auth_sk` → "Security-key sign-in".
- `supportsOverride` lets a connection override the username of an `ssh_sk_key`.
- `FieldValue` admits `boolean`, because Rust serves `resident: true`. The form reads a boolean
  as its enum text.

### 3. Session
- **Wire.**
  - `decodeSessionEvent` reads `touch_required { id, fingerprint, timeout_seconds, hop? }`,
    `touch_cleared` and `touch_timeout`. Before this change they fell into the "unrecognised →
    closed" branch.
  - The timeout is clamped to 1..600 s (30 by default), and the fingerprint is capped at
    128 chars.
- **Store.** `Tab.touch` is `{ id, fingerprint, timeoutSeconds, hop, since, timedOut }`.
  - `touch_cleared` with the same id clears it; another id is ignored.
  - `touch_timeout` marks it `timedOut`, and that state survives the `closed { auth_failed }`
    that follows.
  - `connected` and Reconnect clear it.
  - `Tab.openError` keeps the `session_open` IpcError code.
- **`TouchBanner.tsx`.** A non-modal banner over the terminal, top centre, below the hop strip
  when there is one. It takes no focus, so the terminal stays usable.
  - "Touch your security key to continue" (`role=status`; "Hop N:" with a hop).
  - "Key SHA256:0f/IntG4…rdDv4": the short form, with the full value in the tooltip.
  - A seconds-left countdown, and a pulsing ring (`aria-hidden`, still under reduced motion).
  - After `touch_timeout`: "No touch within 30 seconds — Mooring stopped signing in with … and
    did not try a password", plus **Retry** (reconnect) once the tab has closed. The generic
    "Link lost" strip is hidden then.
- **Pre-flight refusals** (`session_open` errors), as readable close reasons. Each strip has its
  own title, the friendly reason and a next step:
  - `ssh.sk_key_not_in_agent` → "Security key not in ssh-agent". The reason ends "Add the key to
    your ssh-agent: ssh-add -K or ssh-add <handle file>." The hint explains both forms.
  - `ssh.sk_helper_disabled` → "Direct security-key signing is off".
  - `ssh.sk_helper_missing` → "ssh-sk-helper not found".
  - `FRIENDLY` has English text for all four R4 codes.

### 4. Settings → SSH
- New `SshCard`, after Security. It has two informational rows and no toggle and no button:
  - "Security keys (FIDO2) sign through your ssh-agent": where the agent is looked for, that
    Pageant has no sk support, the `ssh-add` forms and no password fallback. State: On.
  - "Direct security-key access (without ssh-agent) — coming later" (`aria-disabled`). State:
    Not available.

### 5. Mock transport
- New `ipc.mock.sk.ts` (82 lines):
  - `refuseSkInSshKey` (`credential.use_sk_kind` for an `sk-*` public key, certificate or handle).
  - `deriveSk`:
    - `application` comes from the blob.
    - `fingerprint` is stable but fake.
    - `resident` is `true` or absent.
    - `backend` defaults to `agent`.
  - `skPreflight`.
  - `signWithTouch`.
- Knobs: `mock.sk = { agentHolds, touch: "touch" | "timeout", touchMs: 1500 }`.
- `ipc.mock.creds.ts` calls these on create, update and replace. `ipc.mock.ts` runs the
  pre-flight before the session exists. After the host key it emits `touch_required`, then after
  `touchMs` either `touch_cleared` + `connected`, or `touch_timeout` + `closed { auth_failed }`.
  Each path writes `session.auth_sk`.
- Seed:
  - credential `cr-yubi` "yubikey ops" (resident Ed25519 `sk-*` key; real blob, made-up key bytes,
    real fingerprint);
  - connection `c-yubi` "build-runner" (SSH, Staging, `runner.example.test`);
  - one `credential.sk_converted` audit row.
- Largest mock file: `ipc.mock.ts` at 347 lines; all are under 500.

## Left open
- **No `sshSkHelper` command** (decision pending, R4). Settings shows the row only. The form's
  helper option stays disabled. When a command lands, enable it there and in Settings.
- **The macOS reason for greying out helper** (contract: "Grey out `helper` with the reason on
  macOS") is not shown separately: helper is greyed out everywhere for now.
- **The helper PIN dialog** does not exist (R4). The agent path asks for the PIN through
  OpenSSH's askpass, outside Mooring.
- The **`.pub` file read** is a WebView `<input type=file>` (public data). If security review
  prefers a Rust-side pick, it is one button.
- The detached window ignores touch events: they only happen during connect, before a tab can
  be detached.

## Decision needed
- **Seed change (qa).** The new seed credential and connection change counts in existing tests.
  I updated `backup.test.tsx`: the export now reports 13 connections and 16 credentials.
- **e2e (qa scope).** One new flow in `apps/desktop/e2e/a5.e2e.mjs`, as the brief asks.
- **Copy.** The kind label Rust serves is "SSH security key (FIDO2)". The brief's refusal and
  button copy say "Security key (FIDO2)". I kept both as given.

## Test evidence
Linux x86_64, 2026-11-08. `node_modules` is symlinked from `/home/claude/nexus` and not
committed.

```
pnpm typecheck   ok (packages/ui, apps/desktop)
pnpm lint        ok (0 problems)
pnpm test        Test Files 91 passed (91) · Tests 672 passed (672)   (main: kinds snapshot test failing)
pnpm build       ok
make e2e         flows 5/5 · kube 6/6 · vsphere 4/4 · secrets-sync 7/7 · a4 11/11 · a5 7/7 — 40 passed, 0 failed
```

New vitest files (22 tests):
- `lib/credentials.sk.test.ts`:
  - the shape rules for both key types, the certificate, and a wrong blob or type;
  - the live fingerprint equals the real SHA-256;
  - `isSkMaterial` for a public line, a certificate and an `openssh-key-v1` sk handle header;
  - paste routing;
  - the short fingerprint;
  - the touch decoders;
  - the mock refusal, derivation and pre-flight;
  - copy for the four R4 codes.
- `components/credentials/skKey.test.tsx`:
  - create from a pasted key (preview, agent default, helper disabled, resident, the stored
    shape, the card);
  - the shape errors;
  - `use_sk_kind` refusal → pre-filled form, with no handle carried over;
  - the live note for an sk public key in `ssh_key`;
  - the seeded card and the audit label.
- `components/terminal/touch.test.tsx`:
  - the banner with the short fingerprint and the countdown, no dialog;
  - a foreign id is ignored; cleared → connected;
  - timeout → alert, then Retry connects;
  - the `not_in_agent` and `helper_disabled` close reasons;
  - the countdown math;
  - Settings → SSH has no switch and no button.
- New e2e flow: "security key: the touch banner shows while the key signs, then the session
  connects". Event order `touch_required → touch_cleared → connected`, no alertdialog for the
  touch, `session.auth_sk` audited.

Screenshots (dark and light, 1280×800, mock transport, JPEG) in `docs/handoff/img/a5-ui-u5/`:
- `01-new-sk-key`
- `02-sk-detail`
- `03-use-sk-kind`
- `04-touch-banner`
- `05-touch-timeout`
- `06-not-in-agent`
- `07-settings-ssh`
