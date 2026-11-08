# A5 · ui-engineer · U6: RD Gateway and smart card UI (ADR-0027)

Worktree `/home/claude/nexus/.claude/worktrees/agent-ac374d85628a22789`, branch
`worktree-agent-ac374d85628a22789`, from `main` @ `0ab159c` (R5). Not merged. No cargo run, and no
manifest, lockfile or capability change. The contract is the "UI contract (U5)" section of
`a5-rust-core-r5.md`. ADR-0027 is still *Proposed*; I followed R5's applied defaults (39/40/41).

The new CSS (`styles/a5-rdg.css`) uses today's tokens only, like `a5-sk.css`. Text is sentence
case in the sans face, with plain borders.

## Done

### 1. Kinds snapshot test
- `ipc.kinds.ts` has the `smart_card` row, byte for byte as in `kinds.snapshot.json`. It is last
  in both orders: the snapshot table and `CREDENTIAL_KINDS` (`CredentialKind::ALL`).
- `KindGroup` gains `"Smart card"`. The kind picker has a new "Smart card" section after SSH. The
  badge is `PIV`.
- Kind counts went from 19 to 20 (`ipc.test.ts`, `stores/credentials.test.ts`). The matrix test
  has `smart_card: ["ssh"]`.
- Matrix footnote: `x509 → rdp` and `smart_card → rdp` both read "Smart-card logon over RDP needs
  Kerberos PKINIT (planned)." This is `SMART_CARD_RDP`.

### 2. `smart_card` credential and the PIN dialog
- **Form.** The schema-driven plain fields:
  - username, domain, reader and public key (multiline, with the live `SHA256:` preview);
  - PKCS#11 module, a segmented control labelled "OpenSC", "YubiKey (ykcs11)" and "Windows smart
    card (no module)".
- There is no Secrets section. `SmartCardNote` shows:
  - "PIN asked at connect, never stored.";
  - the contract's `ssh-add -s` hint;
  - the derived fingerprint, read-only, when editing. Before the first save it says the
    fingerprint is computed then.
- **Detail card** (`SmartCardDetail`): how the card signs in, the reader, the module (or "none:
  the key must already be in ssh-agent"), whether the public key is stored, the domain, the PKINIT
  sentence and the `ssh-add -s` hint. The fingerprint is in the card's Credential section.
- **PIN dialog** (`SmartCardPinDialog`, `purpose: "smart_card_pin"`):
  - The decoder forces `secret: true` for this purpose.
  - The input is masked, `autocomplete=off` and uncontrolled. The PIN never enters React state:
    it is read once on submit and the input is emptied before `session_send { kind: "answer" }`,
    and again on unmount. "Unlock card" is disabled until something is typed, and a second click
    sends nothing.
  - Cancel and Escape send the empty answer, which Rust treats as a cancel (`closed { user,
    "smart card PIN cancelled" }`).
  - It logs nothing. The tests assert that the PIN is in no store and no audit row.
- **Pre-flight.** `ssh.piv_key_not_in_agent` gets its own close strip, "Smart card key not in
  ssh-agent", with the `ssh-add -s <module>` next step. It is in `SK_CLOSE`, next to the R4 codes.
- **Copy.** `rdp.smart_card_unsupported` uses the PKINIT sentence. `credential.incompatible` whose
  message names PKINIT (the matrix refusal) shows the same sentence instead of the generic text.

### 3. RDP form: the RD Gateway section
- `RdpConnOptions.gateway: RdGatewayOptions | null`. The default and normalised value is `null`,
  so existing rows stay compatible. `normalizeGateway` fills the serde defaults (443, `always`,
  Basic off, no CA).
- `RdpGatewaySection`, at the end of "RDP options":
  - "Connect through an RD Gateway" switch. Off stores `null`; the fields typed so far come back
    when it is switched on again.
  - Gateway host and port.
  - "Use the gateway": Always, or Only when the computer is unreachable. The second shows the 3 s
    probe note.
  - "Allow Basic authentication", in the danger box. When it is on, it shows the contract copy
    "Sends the password in an HTTP header (inside TLS). Audited."
  - An extra CA (PEM).
- Validation (`validate.rdg.ts`) mirrors `RdGatewayOptions::validate`:
  - the host: not empty, at most 253 bytes, no whitespace or invisible characters, none of
    `/?#@\`;
  - the port: 1..65535;
  - the usage enum;
  - the CA PEM (`checkCaPem`).
  - Errors are keyed `gateway.*` and block Save.
- **The gateway credential stays the existing "RD Gateway credential" picker**
  (`gatewayCredentialId`), in the credential section, so stored rows and the U0 "New…" return flow
  are unchanged.
  - The empty choice now reads "Same as sign-in".
  - A `prompt` credential is greyed with a reason. `credential_kinds()` lists `prompt` with role
    `gateway`, but R5 refuses it with `rdp.gateway_auth`, so `gatewayPickerOptions` disables it.
  - The gateway section says which credential signs in.

### 4. Session: trust, status, security, close codes
- **`gateway_certificate_trust`** opens the existing `CertificateTrustDialog` in gateway mode:
  - the title is "RD Gateway certificate", the chip is "RD Gateway", and the target is the
    gateway's `host:port` from `gateway_status`;
  - the same problems, details, serious-problem checkbox and focus rules apply;
  - the buttons are **Reject / Trust once / Trust and remember** (`no` / `once` / `yes`).
  - "Trust once" is offered for the gateway only, because the contract lists `once` for it. The
    server dialog still has two buttons, and the existing test asserts that.
- **`gateway_status`** is decoded; an unknown state closes the tab, like `hop_status`.
  - `Tab.gateway` keeps the latest status. Reconnect clears it.
  - The connecting banner shows the step, for example "Signing in to the RD Gateway
    gw01.example.test:443".
  - The toolbar shows the chip "via RD Gateway gw01" while the state is `up`. `:443` is dropped;
    the certificate fingerprint is in the tooltip.
- **Security badge.** `nla+rdg` shows "NLA", and `tls+rdg` shows "TLS without NLA" (hot). The
  gateway chip names the gateway.
- **Close codes** `gateway_auth`, `gateway_refused` and `gateway_unsupported` are in
  `CLOSE_CODES` and `CLOSE_TEXT`:
  - "The RD Gateway refused the credentials" (the next step names Same as sign-in, Allow Basic
    and Kerberos);
  - "The RD Gateway refused the connection" (send the HRESULT in the reason to the admin);
  - "RD Gateway not supported" (the contract sentence plus "Windows Server 2016 or later").
- `trust_mismatch` whose reason starts "RD GATEWAY CERTIFICATE CHANGED" is titled "RD Gateway
  certificate changed". It points at Settings → Trust → RD Gateway (`closeTextFor`).
- `session_open` refusals:
  - `rdp.gateway_*` map to the matching close code;
  - `rdp.smart_card_unsupported` gets "Smart-card logon over RDP is not available" plus a next
    step.
- `FRIENDLY` has English text for all five new R5 codes. The guard test checks them against
  `ipc-codes.json`.
- Audit labels: "RD Gateway sign-in", "RD Gateway used Basic authentication" and "Smart card PIN
  asked".

### 5. Known certificates
- Settings → Trust has a third store, **RD Gateway** (`protocol: "rdg"`). The empty state, list
  label and remove dialog name it.
- Pins are listed hashed, as "RD Gateway (host stored hashed)", because R5 does not join gateway
  hosts yet.
- Removing one asks for the host. The port defaults to 443.

### 6. Mock backend
- `ipc.mock.gateway.ts`: for an RDP connection with `options.gateway`, the sequence is:
  1. `gateway_status connecting`;
  2. the gateway trust prompt (id 2) when there is no `rdg|host:port` pin. `yes` pins and
     reconnects, `once` goes on without pinning, anything else is `trust_rejected`;
  3. `authenticating`, then `up` and the target's own certificate flow, ending with `connected`
     and `security: "nla+rdg"`.
  - Knob `mock.rdg.outcome = ok | auth | refused | unsupported | mismatch | basic`.
  - `basic` without `allowBasicGateway` is refused as `gateway_auth`, with the reason naming the
    option.
  - Audit rows: `session.rdp.gateway`, `session.rdp.gateway_basic` and `trust_decision` with
    `protocol: rdg`.
- `ipc.mock.piv.ts`:
  - `smart_card` derives `fingerprint` and refuses `sk-*` lines with `credential.use_sk_kind`.
  - The pre-flight refuses with `ssh.piv_key_not_in_agent` when there is no public key, or when
    the agent lacks the key and there is no module (or the module is `cryptoapi`).
  - The PIN prompt has id 4. An empty answer → `user`; a refused PIN → `auth_failed`.
  - Audit rows: `credential.pin_prompted` (entered or cancelled, never the PIN) and
    `session.auth_sk` with `backend: piv`.
  - Knob `mock.piv = { agentHolds: false, pin: "accept" | "refuse" }`.
- Seed:
  - connection **`c-rdg` "finance-desk"** (RDP, Desktops, `fin01.example.test`). It signs in with
    `cr-ad` through gateway `gw01.example.test:443`, with Same as sign-in.
  - credential **`cr-piv` "piv badge"** (`smart_card`, ykcs11, reader "Yubico YubiKey"). Its
    P-256 line has made-up bytes and a real fingerprint.
  - The backup export now counts 14 connections and 17 credentials. "domain admin" is used 3
    times.

## Left open
- **e2e (qa scope).** I did not touch `apps/desktop/e2e/`. Two flows are suggested for qa:
  1. Open "finance-desk": the RD Gateway certificate, Trust once, the server certificate, Trust
     and remember, `connected` with `nla+rdg`, and the chip "via RD Gateway gw01.example.test".
  2. Point web01 at `cr-piv`: the PIN dialog, the answer, and `connected`; Escape gives `user`.
- **Gateway pins are hashed only.** When rust-core joins gateway hosts from connection options in
  `known_certs_list({protocol:"rdg"})` (R5 Left open), the card shows them named with no UI
  change: `host` and `port` are already read. Mapping a pin to connection names for `rdg` would
  need the gateway host in the tree rows; today it maps only by `protocol`.
- **No "Trust once" on the server certificate dialog**, although `Gate` accepts `once` there too.
  U2 chose two answers; I kept them.
- **Using a smart card for an RDP connection** is shown greyed in the picker, with the PKINIT
  reason. No "smart-card logon" switch exists.
- **The `sk-*` refusal on a `smart_card` form** shows Rust's message in the form's error line.
  There is no "convert to Security key" button, as there is from `ssh_key`.
- **The PIN dialog reuses the session prompt modal layer**, so a detached window (which never sees
  connect-time prompts) does not show it.
- No screenshots this round.

## Decision needed
- **Copy.** I added "Windows Server 2016 or later" to the `gateway_unsupported` hint. The contract
  sentence is kept verbatim at its start.
- **Seed change (qa).** The new connection and credential change the counts in existing tests. I
  updated `backup.test.tsx` and `credentials.test.tsx`.
- **The empty gateway picker label** changed from "Same as the session credential" to "Same as
  sign-in" (the contract wording). No test depended on the old text.

## Test evidence
Linux x86_64, 2026-11-08. `node_modules` is symlinked from `/home/claude/nexus` and not committed.

```
pnpm typecheck   ok (packages/ui, apps/desktop)
pnpm lint        ok (0 problems)
pnpm test        Test Files 95 passed (95) · Tests 699 passed (699)   (main: kinds snapshot test failing)
pnpm build       ok (index chunk 466 kB)
```

New vitest files (25 tests):
- `lib/ipc.rdg.test.ts`:
  - `gateway_status` decode and its unknown-state close;
  - the gateway trust prompt carries a certificate; the PIN prompt is forced secret;
  - the three close codes;
  - `RdGatewayOptions` defaults, normalisation and every Rust host rule;
  - the gateway picker greys `prompt`;
  - `FRIENDLY` copy for the five codes and the PKINIT `credential.incompatible`;
  - `closeTextFor` for the gateway mismatch and the pre-flight;
  - the `nla+rdg` badge and the chip;
  - mock `derivePiv`, the pre-flight and the PIN outcome;
  - audit labels.
- `components/remote/gateway.test.tsx`:
  - the gateway prompt first, Trust once (no pin, audited `rdg`), then the server dialog without
    Trust once, then `connected` with `nla+rdg`, the chip and the audit row;
  - Trust and remember pins, then Settings → Trust → RD Gateway lists it hashed, with port 443
    defaulted, and removes it;
  - `auth`, `refused` (HRESULT in the reason) and `unsupported` close with their titles, and no
    target prompt;
  - the gateway mismatch hard stop;
  - Basic refused without the option, with no Basic audit row;
  - the form: the switch, host errors, the Basic warning, usage, and `options.gateway` saved.
- `components/terminal/smartCard.test.tsx`:
  - the PIN dialog is masked and focused; Unlock is disabled while empty; the PIN is sent once
    and cleared, and is in no store or audit row; then `connected`;
  - Escape → `user`, "smart card PIN cancelled", and `pin_prompted cancelled`;
  - an agent-held key asks for no PIN; no module → the pre-flight strip with the `ssh-add -s`
    hint;
  - create from the kind picker: no Secrets section, the PIN note, the module labels, and the
    detail card;
  - edit shows the derived fingerprint read-only; an `sk-*` line → `credential.use_sk_kind`.

Updated: `options.test.tsx` (`gateway: null` in the saved RDP options),
`CertificateTrustDialog.test.tsx` (`CERT_ANSWER.once`), and `RemoteSessionTab.test.tsx` (the close
code list).
