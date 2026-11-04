# Handoff index

One line per note, newest first. Every agent reads this before starting and appends when done.
Format of a note: **Done / Left open / Decision needed / Test evidence**.

| Date | Phase | Role | Note |
| --- | --- | --- | --- |
| 2026-11-04 | A3 | architect | ADR-0014/0015/0016/0017 (accepted with owner decisions) |
| 2026-11-04 | A3 | rust-core | [a3-rust-core-k1.md](a3-rust-core-k1.md) · [k2](a3-rust-core-k2.md) · [k3](a3-rust-core-k3.md) · [k4](a3-rust-core-k4.md) · [v1](a3-rust-core-v1.md) · [v2](a3-rust-core-v2.md) · [e1](a3-rust-core-e1.md) · [e2](a3-rust-core-e2.md) · [s1](a3-rust-core-s1.md) · [s2 + integration](a3-rust-core-s2.md) |
| 2026-11-04 | A3 | ui-engineer | [a3-ui-u1.md](a3-ui-u1.md) — typed IPC, Kubernetes cluster browser, exec, logs, pod forwards |
| 2026-11-05 | A3 | orchestrator | [a3-orchestrator.md](a3-orchestrator.md) — Kubernetes, vSphere, external secrets, vault sync; review 6 → B-6 → fix 8 → re-review 6c APPROVE WITH NITS |
| 2026-11-05 | A3 | security-reviewer | re-review 6b (BLOCKER B-6: Escape confirmed native dialogs via the plugin's cancel-slot remap) → fix round 8 → re-review 6c APPROVE WITH NITS (N-50); see [a3-review-6.md](../security/a3-review-6.md) |
| 2026-11-05 | A3 | rust-core | [a3-rust-core-fix-7.md](a3-rust-core-fix-7.md) · [fix-8](a3-rust-core-fix-8.md) — M-16 confirm gate, L-33/L-34/L-35 (fail closed, `http.trust_conflict`)/L-37, N-39..N-49, B-6 three-slot dialogs |
| 2026-11-05 | A3 | ui-engineer | [a3-ui-u5.md](a3-ui-u5.md) — trust-conflict DTOs, `trust_conflict` close code, known-certs grouping, three-button dialog copy |
| 2026-11-04 | A3 | qa-engineer | [a3-qa-q3.md](a3-qa-q3.md) — L-38 gate matrix vs manifest, 11 E2E flows (vSphere, secrets, sync, join, banner), native-dialog checklist |
| 2026-11-04 | A3 | security-reviewer | [../security/a3-review-6.md](../security/a3-review-6.md) — review 6: APPROVE WITH NITS (M-16, L-33..L-38, N-39..N-46); threat model A3 surface; [handoff](a3-security-reviewer.md) |
| 2026-11-04 | A3 | ui-engineer | [a3-ui-u4.md](a3-ui-u4.md) — global sync alarm banner, N-33/N-34/N-36, lazy mock chunk (bundle < 500 kB) |
| 2026-11-04 | A3 | rust-core | [a3-rust-core-f1.md](a3-rust-core-f1.md) — credential.external_* in ipc-codes.json, 44 vault-gated commands, kube body deadline (QA-Q2-1), peek_exp → core, fuzz_pod_list_json |
| 2026-11-04 | A3 | qa-engineer | [a3-qa-q2.md](a3-qa-q2.md) — 17 fuzz targets live (3 gated), hostile suites, assert_no_violations everywhere, kube E2E; QA-Q2-1 kube body deadline; Cargo.lock: 4 dev edges on mooring-testsrv |
| 2026-11-04 | A3 | ui-engineer | [a3-ui-u3.md](a3-ui-u3.md) — secret sources, external_ref form, vault sync settings, join flow |
| 2026-11-04 | A3 | ui-engineer | [a3-ui-u2.md](a3-ui-u2.md) — vSphere import wizard, synced-tree badges, VM power/consoles, sync panel |
| 2026-11-04 | A2 | rust-core | [a2-rust-core-review5-nits.md](a2-rust-core-review5-nits.md) — review 5 L-29, L-30, N-30..N-32, N-35, N-37, N-38 closed; ADR-0014 amendment (`kube.refused`); Cargo.lock: russh `flate2` feature dropped |
| 2026-11-04 | A3 | qa-engineer | [a3-qa.md](a3-qa.md) — kube/vcenter/vault/s3 mock servers, fuzz scaffolding (Cargo.lock: +httpdate 1.0.3) |
| 2026-11-04 | A2 | orchestrator | [a2-orchestrator.md](a2-orchestrator.md) — RDP, VNC, frame path, web windows, detach; review 5 BLOCKER B-5 → fixed; re-review APPROVE WITH NITS |
| 2026-11-04 | A2 | architect | ADR-0011/0012/0013 (accepted with owner decisions) |
| 2026-11-04 | A2 | rust-core | [a2-rust-core-r1.md](a2-rust-core-r1.md) · [r2](a2-rust-core-r2.md) · [r3](a2-rust-core-r3.md) · [r4](a2-rust-core-r4.md) · [r5](a2-rust-core-r5.md) · [integration + fix round 6](a2-integration.md) |
| 2026-11-04 | A2 | ui-engineer | [a2-ui-u1.md](a2-ui-u1.md) · [u2](a2-ui-u2.md) · [u3](a2-ui-u3.md) |
| 2026-11-04 | A2 | qa-engineer | [a2-qa.md](a2-qa.md) — RFB/RDP test servers, fuzz scaffolding |
| 2026-11-04 | A2 | security-reviewer | [../security/a2-review-5.md](../security/a2-review-5.md) |
| 2026-11-04 | A1 exit | orchestrator | [a1-orchestrator.md](a1-orchestrator.md) — round 4: ADR-0010 forwarding/SFTP/auto-lock/syslog over IPC, fuzz + E2E, review 4 |
| 2026-11-04 | A1 exit | security-reviewer | [../security/a1-review-4.md](../security/a1-review-4.md) — review 4: BLOCKER B-4 → fixed; re-review APPROVE WITH NITS (M-12, L-19 open) |
| 2026-11-04 | A1 exit | rust-core | [a1-exit-rust-core-forward-sftp.md](a1-exit-rust-core-forward-sftp.md) — forward_*/sftp_* commands, Rust-side pick dialog (B-4) |
| 2026-11-04 | A1 exit | rust-core | [a1-exit-rust-core-autolock-syslog.md](a1-exit-rust-core-autolock-syslog.md) — auto-lock wiring, RFC 5424 mirror, heartbeat |
| 2026-11-04 | A1 exit | ui-engineer | [a1-exit-ui.md](a1-exit-ui.md) — Forwards/SFTP panels, settings cards, lock survival |
| 2026-11-04 | A1 exit | qa-engineer | [a1-exit-qa.md](a1-exit-qa.md) — cargo-fuzz workspace (5 targets), nightly job, Playwright E2E, QA-F1/F2 |
| 2026-11-04 | pub | ui-engineer | [public-site.md](public-site.md) — GitHub Pages landing site (site/, pages.yml) |
| 2026-11-03 | A1+ | orchestrator | [a1-orchestrator.md](a1-orchestrator.md) — round 3: ADR-0009 credentials, public launch prep, reviews |
| 2026-11-03 | A1+ | rust-core | [a1-rust-core-fixes-3.md](a1-rust-core-fixes-3.md) — review-3 fix round (B-3, M-5..M-7, L-*, N-*) |
| 2026-11-03 | A1+ | security-reviewer | [a1-security-reviewer-3.md](a1-security-reviewer-3.md) — review 3 (credentials, release, docs): BLOCKER → fixed |
| 2026-11-03 | A1+ | rust-core | [a1-rust-core-credentials.md](a1-rust-core-credentials.md) — ADR-0009 backend + reseal on unlock |
| 2026-11-03 | A1+ | ui-engineer | [a1-ui-engineer-credentials.md](a1-ui-engineer-credentials.md) — ADR-0009 credential UI |
| 2026-11-03 | pub | release-engineer | [public-release.md](public-release.md) — dmg/pkg/brew, exe/msi, deb/rpm/AppImage pipeline |
| 2026-11-03 | pub | docs | [public-docs.md](public-docs.md) — README, guides, community files, github-setup |
| 2026-11-03 | pub | privacy | [public-scrub.md](public-scrub.md) — private infrastructure scrub; history decision |
| 2026-11-03 | A1 | orchestrator | [a1-orchestrator.md](a1-orchestrator.md) — round 2: SSH, Tauri layer, UI v2, rename, reviews |
| 2026-11-03 | A1 | rust-core | [a1-rust-core-fixes-2.md](a1-rust-core-fixes-2.md) — review-2 fix round (QA-4, M-1..M-4, L-*, N-3, test-util) |
| 2026-11-03 | A1 | security-reviewer | [a1-security-reviewer-2.md](a1-security-reviewer-2.md) — review 2 (SSH, Tauri, UI): APPROVE WITH NITS |
| 2026-11-03 | A1 | qa-engineer | [a1-qa-engineer-2.md](a1-qa-engineer-2.md) — exit audit, e2e IPC flow, hostile inputs |
| 2026-11-03 | A1 | rust-core | [a1-rust-core-ssh-b.md](a1-rust-core-ssh-b.md) — port forwarding + SFTP |
| 2026-11-03 | A1 | rust-core | [a1-rust-core-tauri.md](a1-rust-core-tauri.md) — ADR-0008 command layer (30 commands) |
| 2026-11-03 | A1 | ui-engineer | [a1-ui-engineer-v2.md](a1-ui-engineer-v2.md) — bridge-console redesign |
| 2026-11-03 | A1 | rust-core | [a1-rust-core-ssh.md](a1-rust-core-ssh.md) — SSH core (ADR-0007) |
| 2026-11-03 | A1 | ui-engineer | [a1-ui-engineer.md](a1-ui-engineer.md) — ADR-0008 UI with mock transport |
| 2026-11-03 | A1 | orchestrator | [a1-orchestrator.md](a1-orchestrator.md) — items 1–2 merged; what must run on the Mac |
| 2026-11-03 | A1 | security-reviewer | [a1-security-reviewer.md](a1-security-reviewer.md) — review + re-review, threat model v1 |
| 2026-11-03 | A1 | rust-core | [a1-rust-core-fixes.md](a1-rust-core-fixes.md) — fix round for B1/B2/QA bugs/L1–L5/M2 |
| 2026-11-03 | A1 | qa-engineer | [a1-qa-engineer.md](a1-qa-engineer.md) — gates, integration tests, vectors CI, 3 bugs |
| 2026-11-03 | A1 | rust-core | [a1-rust-core-store.md](a1-rust-core-store.md) — mooring-store crate (ADR-0005) |
| 2026-11-03 | A1 | rust-core | [a1-rust-core-vault.md](a1-rust-core-vault.md) — vault lifecycle (ADR-0006) |
| 2026-11-03 | A0 | orchestrator | [a0-orchestrator.md](a0-orchestrator.md) — skeleton, crates, UI shell, gates, team |
