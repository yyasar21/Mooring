//! Review 6 L-38: the locked-vault matrix is checked against `src-tauri/ipc-manifest.json`.
//! Every command in the manifest must be in exactly one of three lists: the vault-gated matrix
//! ([`support::vault_gated_codes`], `vault.locked`), the session-bound kube list
//! ([`support::kube_session_bound_codes`], `session.not_found` after the lock) or [`NOT_GATED`]
//! with a one-line reason. A new command in none of them fails [`matrix_covers_manifest`].

use std::collections::BTreeSet;

use crate::support;

/// Commands that are not refused with `vault.locked` and why. Each reason is what the
/// security reviewer reads; a command moves out of this list the moment its gate is pinned
/// by a row in the matrix.
pub const NOT_GATED: &[(&str, &str)] = &[
    ("app_info", "version, platform and the portable data dir (ADR-0021), no store; pinned in `a4_1_portable`"),
    ("autolock_get", "reads the in-memory policy; `autolock_set` is gated (unit test)"),
    (
        "autolock_set",
        "gated by `with_ready` (unit test `set_is_refused_while_locked_...`); needs an `AutoLock` clock, not driven here",
    ),
    ("credential_kinds", "static catalogue, no store"),
    ("credential_parse_account", "pure parser of the typed text, no store"),
    ("vault_create", "vault lifecycle: only valid while no vault exists"),
    ("vault_unlock", "vault lifecycle: the way out of the locked state"),
    ("vault_lock", "vault lifecycle: idempotent while locked"),
    ("vault_status", "vault lifecycle: reports locked / unlocked"),
    ("vault_change_password", "re-proves the current password (`change_password_while_locked`)"),
    ("session_list", "reports the live sessions; ADR-0006 keeps them open across a lock"),
    ("session_attach", "session-bound (SSH/graphical sessions survive a lock, ADR-0006): `session.not_found` otherwise"),
    ("session_send", "session-bound (ADR-0006), see `open_session_survives_vault_lock`"),
    ("session_close", "session-bound (ADR-0006), see `open_session_survives_vault_lock`"),
    ("session_frame_ack", "session-bound (ADR-0006): graphical back-pressure only"),
    ("forward_open", "session-bound (ADR-0006): SSH control of an open session"),
    ("forward_close", "session-bound (ADR-0006)"),
    ("forward_list", "session-bound (ADR-0006)"),
    ("sftp_list", "session-bound (ADR-0006): SFTP on an open session"),
    ("sftp_stat", "session-bound (ADR-0006)"),
    ("sftp_mkdir", "session-bound (ADR-0006)"),
    ("sftp_rename", "session-bound (ADR-0006)"),
    ("sftp_remove", "session-bound (ADR-0006)"),
    ("sftp_download", "session-bound (ADR-0006); the local path comes from a Rust-side pick"),
    ("sftp_upload", "session-bound (ADR-0006); the local path comes from a Rust-side pick"),
    ("sftp_cancel", "session-bound (ADR-0006)"),
    ("sftp_transfers", "session-bound (ADR-0006)"),
    ("sftp_pick_local", "gated by `vault::status` before the dialog (unit tests in `sftp_pick_tests`); needs a picker"),
    ("window_attach", "window routing: re-attaches a detached session view; session-bound"),
    ("web_close", "window-bound: closes an open web window (`session.not_found` otherwise)"),
    ("web_focus", "gated in the Tauri wrapper (`unlocked`), needs an `AppHandle`"),
    ("web_reload", "window-bound, needs an `AppHandle`"),
    ("web_print", "gated in the Tauri wrapper (`unlocked`), needs an `AppHandle`"),
    ("web_zoom", "window-bound, needs an `AppHandle`"),
    ("web_list", "reports the open web windows (labels only)"),
    ("syslog_set", "gated by `with_ready` (unit tests in `syslog_tests`); needs a `TlsRoots` fixture"),
    ("secret_source_revoke", "drops in-memory tokens only; must stay callable while locked"),
    ("secret_source_oidc_status", "reports in-memory OIDC state only; no store, no I/O"),
    // ADR-0018 §3 (A4 U0): `update_check`, `update_install`, `update_settings_get` and
    // `update_settings_set` are rows of the matrix (`support::vault_gated_codes_a4_update`).
    // ADR-0019 (A4 I1): the other four import commands are in the matrix (`vault_gated_codes_a4`).
    ("import_formats", "static catalogue of importers, no store, no I/O"),
    // ADR-0022 (A5 R2): the backup and enrolment commands are rows (`vault_gated_codes_a5_vault`).
    ("biometric_status", "passive: platform, availability and enrolment marker; the unlock screen reads it"),
    ("biometric_unlock", "vault lifecycle: an unlock method, the way out of the locked state (ADR-0022 §2)"),
    (
        "biometric_disable",
        "re-proves the master password (`disable_needs_the_password_and_removes_everything`); works locked",
    ),
];

/// The command names of `src-tauri/ipc-manifest.json` (the golden copy of `guard::COMMANDS`).
pub fn manifest_commands() -> BTreeSet<String> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/ipc-manifest.json");
    let raw = std::fs::read_to_string(path).expect("ipc-manifest.json");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("manifest json");
    v.as_object().expect("object").keys().cloned().collect()
}

/// Fail unless every manifest command is in exactly one list.
pub fn matrix_covers_manifest(gated: &[(&str, &str)], session_bound: &[(&str, &str)]) {
    let manifest = manifest_commands();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let lists: [(&str, Vec<&str>); 3] = [
        ("vault_gated_codes", gated.iter().map(|(n, _)| *n).collect()),
        ("kube_session_bound_codes", session_bound.iter().map(|(n, _)| *n).collect()),
        ("NOT_GATED", NOT_GATED.iter().map(|(n, _)| *n).collect()),
    ];
    for (list, names) in &lists {
        for name in names {
            assert!(seen.insert(name), "{name} is listed twice (second time in {list})");
            assert!(manifest.contains(*name), "{name} in {list} is not in ipc-manifest.json");
        }
    }
    for (name, reason) in NOT_GATED {
        assert!(!reason.trim().is_empty(), "{name}: NOT_GATED needs a reason");
    }
    let missing: Vec<&str> =
        manifest.iter().map(String::as_str).filter(|n| !seen.contains(n)).collect();
    assert!(
        missing.is_empty(),
        "commands in ipc-manifest.json that are neither in the locked-vault matrix nor in \
         NOT_GATED (add a row or an allow-list reason, review 6 L-38): {missing:?}"
    );
}

#[test]
fn not_gated_list_names_only_manifest_commands() {
    let manifest = manifest_commands();
    for (name, _) in NOT_GATED {
        assert!(manifest.contains(*name), "{name} is in NOT_GATED but not in ipc-manifest.json");
    }
    let unique: BTreeSet<&str> = NOT_GATED.iter().map(|(n, _)| *n).collect();
    assert_eq!(unique.len(), NOT_GATED.len(), "duplicate NOT_GATED rows");
}

#[tokio::test]
async fn locked_matrix_covers_the_manifest() {
    // A locked fixture: every gated row must answer `vault.locked`, the session-bound rows
    // `session.not_found` (no cluster exists), and the union must be the manifest.
    let f = crate::state::testing::unlocked();
    let st = &f.state;
    let root = crate::commands::tree::list(st).expect("tree").folders[0].id.clone();
    let cred = crate::commands::credentials::create(
        st,
        crate::commands::credentials::NewCredential::password_for_tests("c"),
    )
    .expect("credential")
    .id;
    let conn = crate::commands::tree::create_connection(
        st,
        crate::commands::tree::ConnectionFields::basic(&root, "n", "ssh", "h.example.test"),
    )
    .expect("connection")
    .id;
    crate::commands::vault::lock(st, None).expect("lock");
    let gated = support::vault_gated_codes(st, &root, &cred, &conn).await;
    for (name, code) in &gated {
        assert_eq!(*code, "vault.locked", "{name} after lock");
    }
    let bound = support::kube_session_bound_codes(st, "no-such-cluster").await;
    for (name, code) in &bound {
        assert_eq!(*code, "session.not_found", "{name} without a cluster");
    }
    matrix_covers_manifest(&gated, &bound);
}
