# A1 · security-reviewer · review 3 (ADR-0009 credentials, release pipeline, scrub)

Worktree `.claude/worktrees/agent-a7520825ff820d3dc`, branch
`worktree-agent-a7520825ff820d3dc`. Reviewed range `effedb4..e7a9154`. Full report:
[docs/security/a1-review-3.md](../security/a1-review-3.md). Not merged.

## Verdict: `BLOCKER` (one: B-3)

**B-3.** `x509.cert_pem` is a plaintext field, but it accepts any PEM text that contains one
certificate block. A cert + private-key bundle (the UI paste detector sends it there) therefore
stores the key in clear in `mooring.db` and sends it to the WebView. Separately, a DB writer can
flip a migrated `ssh_key` row to `x509` and make `reseal_legacy` decrypt the private key into
that same field.

Fix (rust-core + ui-engineer):
- **Core** (`validate.rs`): `cert_pem` may contain CERTIFICATE blocks only, and `x509_pem` must
  succeed.
- **Store** (`legacy.rs::move_certificate`): fail closed before writing anything.
- **UI** (`detectKind`): split a cert + key paste.

Tests are listed in the review. Only the B-3 diff needs re-review.

## Done
- Reviewed the ADR-0009 implementation end to end in core, store, proto-ssh, src-tauri and the
  UI.
- AAD binding, closed secret names, `deny_unknown_fields` on every read, and the matrix
  enforced in Rust (create, update, role set, resolve, inherited credentials): all hold.
- The OTP code never crosses IPC. Clipboard copies go through the cleared, history-excluded
  path. `credential_answer` is redacted. Migration 0003 handles foreign keys correctly.
- Hostile-input checks with a scratch harness (outside the repo) found:
  - B-3;
  - **M-5**: kubeconfig `<<` merge keys and `Exec` case variants are accepted;
  - **L-10**: the duplicate-key check is quadratic; a 709 KB file takes 10.3 s on the
    sync-command main thread.
- Found **M-6**: the `become` prompt is matched in the command echo, and a failed escalation is
  not detected (ruled Medium).
- Found **M-7**: in the release workflow, build jobs hold `contents: write`, and the signing job
  runs `cargo install` and syft while holding `id-token: write`.
- Low findings L-11..L-14; nits N-5..N-9; history finding G-1.
- Approved the new dependencies: `saphyr-parser`, `arraydeque` (accepted risk R-YAML-DEQ),
  `ssh-key` rc, `pem-rfc7468`, `data-encoding`, `hmac` 0.13, `sha1` 0.11, and `sha2-next` (with
  a removal condition).
- Rulings, all in the review:
  - Placeholders: keep.
  - Reseal: call it from `vault_unlock` (L-11).
  - `credential_answer` and `connection_set_role_credential`: keep.
  - cosign keyless instead of minisign: approved.
  - tauri-action v1: no objection.
  - Updater plugin: needs its own review.
- Updated `docs/security/threat-model.md`:
  - new assets: credential metadata, release signing identity;
  - new mitigation rows: credential fields, kubeconfig, `become`, matrix, release pipeline;
  - new risks: R-INV-CRED, R-YAML-DEQ, R-REL;
  - M-1 and M-4 marked fixed; open items updated.
- Amended `SECURITY.md`:
  - The signing claim now matches the pipeline: cosign keyless `SHA256SUMS`, platform signing
    only where configured, verify script.
  - Scope: release workflows and credential parsers added.
  - New embargo-extension clause, and a maintainer note to enable private vulnerability
    reporting.
  - Supported versions, reporting channel and timeline approved unchanged.
- Scrub:
  - The tree is clean.
  - Git history still holds 77 lines with the private zone, 14 host names, 13 RFC 1918
    addresses and 3 commit messages. **Recommendation G-1:** publish a new repository from one
    squashed commit, and never flip the existing private repository to public (GitHub keeps PR
    refs and SHA-reachable objects even after a force-push). `filter-repo` only if history must
    be kept, and then into a new repository too.

## Left open
- **Merge gate:** B-3 fixed and re-reviewed. `security.yml` must be green (cargo-deny,
  cargo-audit, gitleaks with the new rule, semgrep), because none of them could run here.
- **Before the first public release:**
  - M-6, L-11, G-1;
  - L-12 (`verify-release.sh` must fail closed);
  - SECURITY.md: enable private vulnerability reporting.
- **Before the first signed release:** M-7, L-13.
- **Before any Kubernetes session or kubeconfig import:** M-5, L-10, and a `kubeconfig_parse`
  fuzz target (the other parser fuzz targets are owed too).
- L-14 (pin `ci.yml`, `security.yml` and `test-vectors.yml` by SHA): qa-engineer / orchestrator.
- The pinned action SHAs were not re-verified (no GitHub API access in this session).
- `.claude/agents/release-engineer.md` and A4.md still say minisign; their owners should switch
  them to cosign keyless.

## Decision needed (orchestrator / owner)
1. G-1: a new repository from a squashed commit (recommended), or `filter-repo` into a new
   repository.
2. L-13: keep the community `artifact-signing-cli`, or switch to Microsoft's
   `trusted-signing-action` / .NET `sign`.

## Test evidence
```
CARGO_INCREMENTAL=0 cargo test --offline -p mooring-core -p mooring-store      all ok
CARGO_INCREMENTAL=0 cargo test --offline -p mooring-proto-ssh --lib become_    3 passed
scratch harness: B-3 accepted=true; M-5 `<<`/`Exec` accepted=true; L-10 60k keys 10.3 s;
                 200k nested flow sequences rejected in 1.6 ms
not run: cargo-deny, cargo-audit, gitleaks, actionlint, pnpm, mooring-app
```
