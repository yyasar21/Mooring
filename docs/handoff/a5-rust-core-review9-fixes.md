# A5 rust-core (+ release-engineer) — review 9 fix round

Spec: [review 9](../security/a5-review-9.md) (M-19, L-47..L-52, L-54, N-72..N-77) and
[review 8](../security/a4-1-review-8.md) carried L-40. Branch
`worktree-agent-a690dac3c1a8cd5f0`, base `6b9d5c5`.

## Done

| Finding | Commit | Change | Test |
| --- | --- | --- | --- |
| **M-19** RDG NTLM channel binding | `9167233` | `gateway/ntlm.rs`: `NtlmClient::new(account, leaf_der)` calls `Ntlm::set_channel_bindings(b"tls-server-end-point:" ‖ hash)` before `NEGOTIATE`. The hash follows RFC 5929 §4.1: SHA-384 / SHA-512 for those signature algorithms (ECDSA, PKCS#1, RSASSA-PSS hash parameter), SHA-256 for everything else. `open.rs` takes the leaf from `peer_certificates()[0]` of the pinned TLS session. New edge `sha2` (workspace, already in the tree) in `mooring-proto-rdp` | `--test gateway` `ntlm_is_bound_to_the_gateway_tls_session` (the mock runs NTLM with Extended Protection; `Mode::WrongBinding` expects another leaf's binding and refuses → `gateway_auth`; every other mock test now passes through the correct binding). Checked that the test fails with the binding removed (sspi skips the check when the AV pair is absent, so the refusal also proves the client sends it). `--lib gateway` `channel_binding_uses_the_rfc5929_end_point_hash` (P-256 → SHA-256 = fingerprint, P-384 → SHA-384, Ed25519 / junk → SHA-256) |
| N-72 RNG failure | `9167233` | `conn::random()` returns `Result`; a failed ring RNG ends the open with `protocol_error` ("system random source failed"); the best-effort close frame is skipped | `a_failed_rng_fails_instead_of_returning_zeros` (`random_from` with a failing `SecureRandom`) |
| N-73 IPv6 `Host` | `9167233` | `http::request` builds `Host` from `host_key` (brackets) and drops `:443` | `request_carries_the_rdg_headers` (`[2001:db8::1]`, `[2001:db8::1]:8443`) |
| L-48 web SOCKS targets | `23fd4f1` | `ChainProxy::open(chain, ProxyAllow)`; `forward_io::dynamic_loop` gets an optional gate; refused CONNECTs get SOCKS `0x02` (`REP_NOT_ALLOWED`) before any `direct-tcpip`, are counted (`refused()`), and the first 16 per proxy are kept (`take_refused()`). `web::via::proxy_allow(url, policy)`: start host + every `allowedOrigins` host, each on 80, 443, its own port and the start port; exact names (case, trailing dot, IPv6 brackets normalised). New audit row `forward_refused { connection, id: "web-via", target }`, flushed by the window watch (1 s) and at shutdown | `tests/chain_proxy.rs` `connect_outside_the_allow_list_is_refused_before_the_hop`; `chain_proxy` unit test (exact match, cap 16 over the proxy's life); `web::via` `proxy_allow_is_the_start_host_and_the_allowed_origins`, and `web_via_browses_…` now refuses a CONNECT outside the list and asserts the `forward_refused` row; `mooring-audit` wire-name test |
| L-47 WebRTC UDP | `23fd4f1` | `web/window.rs::webview2_args`: every web window passes `--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection` (wry's defaults, which custom arguments replace) `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`; a web-via window also gets `--proxy-server=socks5://127.0.0.1:<port> --proxy-bypass-list=<-loopback>` — **wry only adds `--proxy-server` when it builds the default string**, so dropping this would silently send the page around the chain. `proxy_url` is still set (fail closed). Linux: WebKitGTK ships `enable-webrtc` off and wry 0.57.1 never touches it, so pages have no `RTCPeerConnection` (documented in the module header, not set explicitly: that would need a `webkit2gtk` dependency) | `webview2_args_keep_webrtc_on_the_proxy_and_wry_defaults` |
| L-49 smart-card lifetime | `d1f2c02` | `SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED` (26) + `SSH_AGENT_CONSTRAIN_LIFETIME` `CARD_LIFETIME_SECS` = 3600 s (1 h: a reconnect in the same work session needs no second PIN; `REMOVE_SMARTCARD_KEY` needs the PIN, so the lifetime is the bound). The unconstrained form is never sent; an agent that refuses 26 ends in `card_refused` (no fallback) | `tests/smart_card.rs` `pin_loads_the_card_into_the_agent_then_signs` asserts the constraint bytes `[1, 0, 0, 0x0e, 0x10]`; the fake agent answers the old type 20 with failure |
| L-50 bws pin | `a3280c5` | `bws_pins.rs`: pins persist in `$APP_DATA/bws_pins.json` (`BwsConfig::with_pins`, set by `SecretsRuntime`), atomic write (random temp, `create_new`, 0600, rename). A changed binary — or an unreadable pin file, never "no pin" — is audited `secret.tool_changed` and refused with the new `SecretsError::ToolChanged` / IpcError `secret.tool_changed`: "the bws CLI changed since it was last trusted; test the secret source in Settings → Secret sources to trust it again". Only `secret_source_test` (`ensure_checked(.., trust: true)`) re-pins. `ipc-codes.json` blessed (+`secret.tool_changed`; `bws_pins.json` added to the scanner's `NOT_CODES`) | `bws_fake.rs` `deadline_version_missing_and_changed` (changed binary refused, never run, Test re-trusts) and `the_bws_pin_persists_across_restarts` (two engines over one pin file); `bws_pins` unit test (restart, change, corrupt file); `secrets_runtime` code table |
| L-51 backup `.part` | `965f4bb` | `state::create_part(target)`: `.<name>.<random 64-bit hex>.part`, `create_new` (`O_CREAT|O_EXCL` / `CREATE_NEW` — never an existing file, never follows a link at that name, so no `O_NOFOLLOW` / `libc` needed), 0600, retry on clash. Used by the backup export and the vault header write (`state.rs`); `create_private` stays for the staged join header (fixed name in the owner-only data dir) | `vault_export_tests` `the_part_file_is_fresh_private_and_follows_no_link` (`#[cfg(unix)]`: a symlink at `<name>.part` and a 0644 foreign file at `.<name>.part` are untouched, result 0600); export / header tests check no `.part` is left |
| L-52 import trust | `e02983f` | `commands/vault_import_trust.rs::guard` before the merge: imported lines (known_hosts and every `known_*_certs`) naming a `host:port` this device already pins are dropped and reported as `{ kind: "trust", id: "<host:port>", name: "<trust file>", resolution: "kept_local" }`; `ImportReport.trustAdded` counts the lines that are added. Lines are hashed, so hosts are matched over the `host:port` of every connection on either side (port or protocol default). New `KnownHosts::has_entry` | `vault_import_tests` `merge_import_never_adds_trust_for_a_pinned_host` (ECDSA for an Ed25519-pinned host and a second RDP cert pin are dropped and reported; the unpinned host's key is added; afterwards the ECDSA key is a `Mismatch`, one distinct cert pin) |
| N-74 winget marker | `ae5b19f` | `symlink_metadata` first; a non-file, symlink or reparse point (`dirs::is_link`, now `pub(crate)`) is not a marker | `winget_tests` `a_linked_marker_is_not_a_marker` (`#[cfg(unix)]`) |
| N-77 biometric service | `ae5b19f` | `biometric::SERVICE = build_identity::EFFECTIVE_IDENTIFIER` (release value unchanged, so no enrolment moves; dev builds get the dev identifier) | `service_is_the_build_identifier` |
| L-40 manifest cap | follow-up commit `fix(updater): bounded latest.json fetch` | `updater/manifest.rs`: own reqwest client (`=0.13.5`, `rustls-no-provider` + `system-proxy`, the features the plugin already enables; ring installed as rustls default), `https_only`, OS / env proxy honoured, at most 5 redirects, 30 s for the whole exchange; the body is read chunk by chunk and refused with `update.manifest` past `MANIFEST_CAP` (64 KiB) or on a declared `Content-Length` over it; `204` = no update. `PluginSource::check_inner` passes the JSON to `Updater::restore_update` (same target / comparator, `require_signed_version` forced; the package signature check is unchanged). Endpoint = `plugins.updater.endpoints[0]`, plain `https` only (templates refused). New edges `reqwest`, `rustls` in `src-tauri/Cargo.toml` (orchestrator decision); `Cargo.lock` gains only the two edge lines | `updater::manifest` tests against a local server named `updates.example.test`: normal manifest through a redirect; oversize declared / streamed (1x and 8x the cap) → `update.manifest`; 204 → none; redirect loop → `update.network`; endpoint validation |
| L-54 winget token | `368321c` | `release-winget.yml` `submit` job: `environment: release` (header comment: tag-only environment secret, dispatch from the tag); `lint-workflows.sh` rule 7 requires the environment on the job; `docs/release.md` secrets table | `lint-workflows.test.sh` new negative case (submit without the environment); real workflows lint ok |
| N-75 codesign requirement | `368321c` | `macos-sign.sh` takes the team id from `APPLE_SIGNING_IDENTITY` (`… (<TEAMID>)`, 10 chars, must match `APPLE_TEAM_ID` when set) and verifies the `.app` and the `.dmg` with `codesign --verify -R=` a Developer ID requirement naming that team. (The review row also names `install_location.rs`'s copy check; that one waits for Developer ID as the row says) | `macos-sign.test.sh`: team printed in the dry run; identity without a team and a different `APPLE_TEAM_ID` refused |

## Left open

- **L-53** (export/import dialogs in React state): UI, not in this round.
- **N-76** (winget `Get-AuthenticodeSignature` accepts any trusted signer): note only. Fix when
  the Trusted Signing publisher is known: compare `$sig.SignerCertificate.Subject` with a
  repository variable (e.g. `WINDOWS_PUBLISHER_SUBJECT`) in the `Installers are signed` step.
- **N-78**: architect / UI (ADR-0027 + hint text).
- **UI follow-ups** (ui-engineer): `AuditView` label for `forward_refused`; friendly text for
  `secret.tool_changed` (the Rust message is already actionable); the PIN dialog line "the card
  stays loaded in ssh-agent for 60 minutes" (`CARD_LIFETIME_SECS`); the import summary can show
  `trustAdded` and `trust` conflicts (`kind: "trust"`, `resolution: "kept_local"`).
- **Docs** (architect): ADR-0027 §1 "NTLM with CBT (`tls-server-end-point`); Kerberos /
  Negotiate still unsupported"; R-WEB-VIA: the allow-list, the loopback bypass closed on
  Windows via `<-loopback>`; R-SEC-CLI: the hash-then-exec-by-path window remains (T2).
- L-52 limit: a pinned host that no connection row names (a gateway / kube / vCenter address
  that lives only in options) is not recognised and keeps the union behaviour.
- L-50: a same-user writer racing hash and exec of `bws` is still possible (T2, R-SEC-CLI).

## Decision needed

None (L-40: the orchestrator chose the `reqwest` route, implemented below).

## Test evidence

```
Linux x86_64, 2026-11-08, CARGO_INCREMENTAL=0, CARGO_TARGET_DIR=/home/claude/nexus/target
cargo fmt --all --check                                         ok
cargo clippy --workspace --all-targets -- -D warnings           ok
cargo test -p mooring-proto-rdp                                 all passed (79 lib, gateway 7, loopback 7, fuzz_corpus 12)
cargo test -p mooring-proto-ssh                                 all passed (79 lib; chain_proxy 3, smart_card 4, hops …)
cargo test -p mooring-secrets                                   all passed (43 lib; bws_fake 5, …)
cargo test -p mooring-audit                                     42 passed
cargo test -p mooring-app --lib / --tests                       469 passed (1 ignored) / 55 passed
MOORING_BLESS=1 cargo test -p mooring-app golden                ipc-codes.json +secret.tool_changed
cargo deny --offline check                                      advisories ok, bans ok, licenses ok, sources ok
bash scripts/release/tests/run.sh                               9 suites, 0 failed
bash scripts/release/lint-workflows.sh .github/workflows        ok
```

Not run: semgrep (registry rules not reachable offline here), macOS / Windows builds
(WebView2 arguments, Hello / Keychain service name, reparse-point check, `codesign -R`), the
release workflows, `pnpm test`.
