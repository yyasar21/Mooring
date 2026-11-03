# Security review process

Every pull request is security-reviewed before merge. The reviewer has a veto: a **blocker**
stops the merge until it is fixed and re-reviewed.

## Checklist (every pull request)

1. **Secret flow** — can any secret reach the WebView, a log line, an error `Display`, a test
   fixture or git? Search the diff for `password`, `secret`, `key`, `token`.
2. **Trust boundary** — new or changed `#[tauri::command]`: input validated and size-capped?
   Error mapped to `IpcError` without leaking detail? Capabilities still least-privilege? CSP
   unchanged or tightened?
3. **Crypto** — only RustCrypto, `ring` or `rustls`; nonces random per use; AAD binds context;
   keys zeroized; KDF floor enforced.
4. **Parsers** — code reading bytes from a peer or a file has bounds checks, length caps and a
   fuzz target.
5. **Dependencies** — license, maintenance, `unsafe` footprint, duplicate functionality;
   `cargo deny` clean.
6. **Tests prove the property** — tamper detection, rejection of bad input — not only the happy
   path.

## Verdicts

| Verdict | Meaning |
| --- | --- |
| `APPROVE` | Merge. |
| `APPROVE WITH NITS` | Merge; findings are tracked with an owner and a deadline (usually phase exit). |
| `BLOCKER` | Do not merge. The finding names the exact `file:line` and the required fix. |

Findings are labelled by severity (`B` blocker, `M` medium, `L` low, `N` note) and numbered,
for example `M-2`. A finding can also set a **gate**: a capability may not be exposed (for
example "no SFTP IPC before M-3 is fixed") until it is resolved.

## Automated checks

On every pull request, the `security` workflow runs:

- `cargo-deny` — licenses, banned crates (`openssl`, `native-tls`, `md5`), advisories, sources
  (exactly one allowed git source);
- `cargo-audit` — RustSec advisories, weekly re-check on a schedule;
- `pnpm audit --audit-level=high`;
- gitleaks over the full history;
- Semgrep (`p/rust`, `p/typescript`, `p/secrets`) with SARIF upload;
- a check that every crate root contains `forbid(unsafe_code)`.

## Threat model and phase reviews

- [`docs/security/threat-model.md`](../security/threat-model.md) lists assets, attackers
  (T1–T6), STRIDE mitigations with status, risks and accepted risks. It is updated whenever the
  attack surface changes and at every phase exit.
- Each phase ends with a written review in `docs/security/<phase>-review*.md`, for example
  [a1-review.md](../security/a1-review.md) and [a1-review-2.md](../security/a1-review-2.md).
- Accepted risks are named (`R-INV`, `R-AGE-PIN`, `R-RSA`, …), justified and given a revisit
  condition.

## Reporting vulnerabilities

External reports follow [SECURITY.md](../../SECURITY.md).
