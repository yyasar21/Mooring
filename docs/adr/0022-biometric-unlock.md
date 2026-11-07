# ADR-0022: Biometric unlock — Touch ID and Windows Hello

Status: Proposed · 2026-11-07 (Phase A5 / v0.2.0; amends ADR-0006 §Keyring wrap, lifts the
R-T2-KR HOLD; builds on ADR-0002, ADR-0003, ADR-0017 §1, ADR-0018 §2)

## Context
ADR-0006 shipped the vault side: `Vault::enable_keyring_unlock / unlock_with_keyring /
disable_keyring_unlock` over the `WrapKeyStore` trait (`crates/mooring-vault/src/keyring.rs`),
with `keyring_wrap: Option<Sealed>` in the v2 header (AAD = header AAD ‖ 0x1F ‖ `keyring`).
`src-tauri/src/keyring_store.rs` (`OsWrapKeyStore`, `keyring` 4.2.0) exists but no command
calls it: review 1 ruling M1 and R-T2-KR put the OS side on **HOLD** because a same-user
process (T2) could read the item silently on Windows (Credential Manager) and Linux (Secret
Service), and on macOS the legacy keychain item protects against other *apps*, not against
code running in our process. The roadmap carries "opt-in Touch ID / Windows Hello unlock 🚧
held until each platform has a biometric ACL". The master password remains the only key to the
DEK; `change_password` drops the wrap (`vault.rs`, ruling c). The `keyring` crate's Apple store
(`apple-native-keyring-store` 1.0.2, `protected.rs`) knows only `RequireUserPresence`, not
`BiometryCurrentSet`.

## Decision

### 1. What is protected, and by what
The OS never holds the master password or the DEK. It holds (macOS) or derives (Windows) the
32-byte **`WrapKey`** of ADR-0006; `WrapKey` + header = DEK, so the question is only who can
obtain `WrapKey` without the user's gesture. The hold is lifted because each platform now has
a path where **no process, ours included, obtains it without a fresh biometric gesture**:

| Platform | Mechanism | Silent read by T2 (same user) | By code in our process (T5) |
| --- | --- | --- | --- |
| macOS | Data-protection keychain item, `SecAccessControl(kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecAccessControlBiometryCurrentSet)` | No: the item belongs to our keychain access group; other apps cannot query it; any read needs Touch ID | No: a read triggers Touch ID; cancelling yields nothing |
| Windows | `KeyCredentialManager` key named `io.github.yyasar21.mooring/<vault_id>`; `WrapKey = HKDF-SHA256(ikm = RequestSignAsync(challenge).Result, salt = vault_id, info = "mooring hello v1")` | No: nothing readable is stored; a signature needs the Hello gesture every time (TPM/KSP-bound RSA key) | No: same |
| Linux | **not offered**: Secret Service has no biometric ACL; `fprintd` gates sessions, not items | — | — |

- macOS via `security-framework` 3.7.0 (MIT OR Apache-2.0, 2026-02-20, already in the tree
  as a transitive dependency): `PasswordOptions::new_generic_password(SERVICE, vault_id)`,
  `use_protected_keychain()`, `set_access_control(SecAccessControl::create_with_protection(
  Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly), AccessControlOptions::
  BIOMETRY_CURRENT_SET.bits()))`, then `set_generic_password_options` / `generic_password` /
  `delete_generic_password_options`. The crate exposes all of this as safe Rust; the `unsafe`
  is inside the crate's FFI layer (like `keyring`). **No `objc2` wrapper and no `unsafe` in our
  code.** The `keyring` crate stays for nothing else: `OsWrapKeyStore` is replaced by
  `BiometricWrapKeyStore` (macOS, Windows) and `keyring` is removed from `mooring-app`.
- **macOS gate:** the data-protection keychain needs a code signature with an application
  identifier (`keychain-access-groups` entitlement, `$(TeamIdentifierPrefix)io.github.yyasar21.mooring`).
  An ad-hoc signed build (ADR-0018 §2) gets `errSecMissingEntitlement`. So Touch ID ships
  **only in Developer-ID-signed builds** (ADR-0018 amendment, signing hooks); other builds
  show "Touch ID needs a signed build" in Settings. `RequireUserPresence` on the legacy
  keychain is not an acceptable substitute (no ACL against our own process).
- Windows via the `windows` crate 0.62.2 (MIT OR Apache-2.0, already in the tree through
  `sspi`), feature `Security_Credentials`: `KeyCredentialManager::IsSupportedAsync`,
  `RequestCreateAsync(name, ReplaceExisting)`, `OpenAsync`, `RequestSignAsync`, `DeleteAsync`
  are **safe** WinRT projections (no raw pointers). The challenge is the fixed string
  `"mooring-hello-v1" ‖ vault_id`; Hello's RSA-2048 PKCS#1 v1.5 signature is deterministic, so
  no new header field is needed and header v2 stays. The HKDF step is `hkdf` 0.13 (in the tree).
- The biometric item is per device and never synced (ADR-0017 §2 strips `keyring_wrap`).

### 2. Lifecycle (src-tauri `commands/vault_biometric.rs`, rust-core)
```
vault_biometric_status() -> { available: bool, enabled: bool, reason: "ok"|"unsupported_os"|
                              "unsigned_build"|"not_enrolled"|"suspended"|"keychain_unavailable" }  # passive
vault_biometric_enable({ password })  -> VaultStatus   # master password required (ADR-0006)
vault_biometric_unlock()              -> VaultStatus   # OS prompt; no secret crosses IPC
vault_biometric_disable({ password }) -> VaultStatus
```
- Enable: `Vault::enable_keyring_unlock(store, password)` with the biometric store; the OS
  gesture is required at enrolment too (macOS: `SecItemAdd` with the ACL prompts; Windows:
  `RequestCreateAsync` prompts). Audit `vault.biometric_enabled { platform }`.
- Unlock: `unlock_with_keyring`; the gesture happens inside `store.get()`. Success audits
  `vault.unlock { method: biometric }`; cancel/failure audits `vault.biometric_failed`.
- **Auto-disable** (`vault.biometric_suspended { reason }`), no password needed: the OS item or
  key is deleted at once and `setting.biometric_suspended = reason` is written; the stale
  `keyring_wrap` ciphertext without its key is inert and is cleared on the next successful
  *password* unlock (as the v1→v2 header upgrade of ADR-0006). Reasons: `failed_attempts`
  (3 consecutive OS failures or cancellations within 10 min), `password_changed`
  (`change_password` already drops the wrap; the command now also deletes the OS item),
  `biometry_changed` (macOS: `BiometryCurrentSet` invalidates the item when fingers are
  re-enrolled → `errSecItemNotFound`/`errSecAuthFailed`; Windows: Hello container reset →
  `KeyCredentialStatus::NotFound`), `vault_rotated` (vault id changed by import/join).
  Re-enabling is a fresh enrolment with the master password.
- Lock state is unchanged: biometric unlock is an unlock method, not a bypass of auto-lock,
  export, change password or disable (all still need the password, ADR-0006).
- Portable mode (ADR-0021): offered; the item is bound to this machine and user, so the README
  states that a moved folder needs re-enrolment (status `keychain_unavailable`).

## Alternatives considered
- `keyring` 4 with `RequireUserPresence` (passcode or biometry) on the legacy keychain: the
  prompt can be satisfied with the login password and the ACL does not bind our process.
  Rejected.
- Windows DPAPI (`CryptProtectData`) or Credential Manager with `Local` persistence: readable by
  any same-user process, no gesture. Rejected (R-T2-KR).
- Windows Hello only as a UI gate (`UserConsentVerifier`) in front of a stored key: the key is
  still readable without the gate. Rejected.
- Linux `fprintd` + Secret Service: the gesture is not tied to the item. Not offered; Settings
  explains why.
- Storing the DEK in the OS store instead of `WrapKey`: ADR-0006 rejected (the wrap keeps the
  header AAD binding).
- `objc2-local-authentication` + Secure Enclave key: more code, same entitlement gate, and
  `security-framework` already covers the need.
- FIDO2 `hmac-secret` as a vault second factor (ADR-0017 §7): needs in-process FIDO2 access,
  which ADR-0024 §4 rejects (C/`unsafe` on every OS) and a header v3. Stays deferred.

## Security consequences
- **T-BIO (threat-model delta):** a new trust boundary App → OS biometric store. T2 cannot read
  or derive `WrapKey` silently on either platform; a T2 process can *trigger* a Hello/Touch ID
  prompt by naming our item/key, and a user who accepts a prompt they did not initiate has
  handed over the unlock. Mitigation: the OS prompt names Mooring (macOS: our app; Windows:
  the key name), auto-disable after 3 failures, audit of every attempt. Residual risk
  **R-BIO-PROMPT** (accepted, opt-in).
- T1 (stolen disk): unchanged; Touch ID items are `ThisDeviceOnly`, Hello keys are TPM-bound.
- T5 (compromised WebView): can call `vault_biometric_unlock`, which only prompts the user — the
  same thing the user does by clicking; it never receives key material.
- The `keyring` crate and `zbus` leave the tree (fewer dependencies); `security-framework` and
  `windows` gain one feature each, no new crate. `unsafe` footprint of our code: 0.
- Lifting the hold is per platform: Linux keeps R-T2-KR's "off" row permanently.

## UI
Settings → Security → "Unlock with Touch ID / Windows Hello" toggle (English), disabled with
the `reason` text when unavailable; a "Use Touch ID" / "Use Windows Hello" button on the
unlock screen when enabled; the suspension reason shown once after a password unlock. No
biometric prompt is ever started without a user action in `main`.

## Test plan
- Unit (`mooring-vault`): unchanged wrap tests; new: suspended flag cleared on password unlock.
- Unit (src-tauri, mock store): failure counter (3 within 10 min → suspend, reset on success),
  `password_changed` deletes the item, `biometry_changed` mapping, status matrix per OS and
  signing state, HKDF vector for the Windows derivation (fixed signature bytes → key).
- Integration (manual gate, signed macOS build): enrol, unlock, cancel ×3 → suspended, re-enrol
  a finger → `biometry_changed`; `security find-generic-password` from Terminal must fail.
  Windows 11: enrol, unlock, PIN reset → `NotFound`; a PowerShell `KeyCredentialManager.OpenAsync`
  + sign from another process must raise the Hello prompt (never silent).
- Capability test: no new permission; the four commands join `mooring-main` only.

## Owner decisions needed
23. Ship Touch ID only in Developer-ID-signed builds (requires buying the certificate), or
    hold macOS until then and ship Windows Hello first. Default: both gated; Windows first.
24. Failure threshold 3 within 10 minutes. Default: yes.
25. Remove the `keyring` crate (and `zbus`) from `mooring-app` since no platform uses it.
    Default: yes.
