//! Sync commands against `mooring-testsrv::s3` (SigV4-verifying, conditional writes,
//! rollback / fork knobs) on loopback TLS with a self-signed certificate (Gate prompt).

use mooring_sync::{Alarm, Outcome, SyncError};
use mooring_testsrv::s3::{self as srv, S3Knobs, S3Server};
use serde_json::json;

use super::*;
use crate::commands::credentials::{self, NewCredential, WireSecrets};
use crate::commands::sync_gate::{ScriptedPrompter, TrustAnswer};
use crate::commands::sync_join::{self, join, JoinInput};
use crate::commands::tree::{self, ConnectionFields};
use crate::commands::vault;
use crate::state::testing::{self, audit_events, Fixture, MASTER};

const PREFIX: &str = "t";

pub(crate) struct Dev {
    pub f: Fixture,
    pub hub: SyncHub,
    pub p: ScriptedPrompter,
}

pub(crate) fn dev(name: &str) -> Dev {
    Dev { f: testing::unlocked(), hub: SyncHub::new(name), p: ScriptedPrompter::new(TrustAnswer::Pin, true) }
}

pub(crate) async fn server() -> S3Server {
    srv::start(srv::S3Config::default(), 0).await.expect("s3 mock")
}

pub(crate) fn backend(s: &S3Server) -> BackendInput {
    BackendInput {
        kind: "s3".into(),
        endpoint: s.endpoint(),
        region: "us-east-1".into(),
        bucket: s.bucket(),
        prefix: PREFIX.into(),
        path_style: Some(true),
    }
}

/// The device's S3 key (created on first use).
pub(crate) fn add_key(state: &AppState, s: &S3Server) -> String {
    let existing = credentials::list(state).expect("list").into_iter().find(|c| c.kind == "s3_access_key");
    if let Some(c) = existing {
        return c.id;
    }
    let c = s.credentials();
    let key = NewCredential {
        name: "sync key".into(),
        kind: "s3_access_key".into(),
        fields: json!({ "access_key_id": c.access_key }),
        secrets: WireSecrets::of(&[("secret_access_key", &c.secret_key)]),
    };
    credentials::create(state, key).expect("s3 key").id
}

impl Dev {
    pub async fn configure(&self, s: &S3Server) -> IpcResult<SyncConfig> {
        let input = ConfigureInput {
            backend: backend(s),
            credential_id: add_key(&self.f.state, s),
            interval_minutes: Some(15),
        };
        configure(&self.f.state, &self.hub, Some(&self.p), None, input).await
    }
    pub async fn now(&self) -> IpcResult<Outcome> {
        run_once(&self.f.state, &self.hub, Some(&self.p), None).await
    }
    pub fn status(&self) -> SyncStatus {
        status(&self.f.state, &self.hub).expect("status")
    }
    pub fn root(&self) -> String {
        let t = tree::list(&self.f.state).expect("tree");
        t.folders.into_iter().find(|f| f.parent_id.is_none()).expect("root").id
    }
    pub fn add(&self, name: &str, host: &str) -> String {
        let f = ConnectionFields::basic(&self.root(), name, "ssh", host);
        tree::create_connection(&self.f.state, f).expect("conn").id
    }
    fn set_host(&self, id: &str, name: &str, host: &str) {
        let f = ConnectionFields::basic(&self.root(), name, "ssh", host);
        tree::update_connection(&self.f.state, id, f).expect("update");
    }
    fn names(&self) -> Vec<String> {
        let mut n: Vec<String> =
            tree::list(&self.f.state).expect("tree").connections.into_iter().map(|c| c.name).collect();
        n.sort();
        n
    }
    fn audits(&self) -> Vec<String> {
        audit_events(&self.f.state)
    }
    pub async fn join_from(&self, s: &S3Server, vault_id: &str, password: &str) -> IpcResult<vault::VaultStatus> {
        let input = JoinInput {
            backend: backend(s),
            credential_id: add_key(&self.f.state, s),
            vault_id: vault_id.to_owned(),
            password: password.to_owned(),
            interval_minutes: None,
        };
        join(&self.f.state, &self.hub, Some(&self.p), None, input).await
    }
}

fn current_key(vault_id: &str) -> String {
    format!("{PREFIX}/{vault_id}/current")
}

#[tokio::test]
async fn two_devices_push_pull_merge_fork_and_rollback() {
    let s3 = server().await;
    let a = dev("device-a");
    // Configure: the self-signed endpoint goes through the Gate and is pinned.
    let cfg = a.configure(&s3).await.expect("configure");
    assert_eq!(cfg.interval_minutes, Some(15));
    assert_eq!(a.p.asked().len(), 1, "one certificate prompt");
    assert!(a.audits().contains(&"cert_decision".to_owned()));
    assert!(a.audits().contains(&"sync.configured".to_owned()));
    assert_eq!(a.status().state, "idle");
    let db = a.add("db", "192.0.2.10");
    assert_eq!(a.now().await.expect("push"), Outcome::Pushed { counter: 1 });
    assert_eq!(a.p.asked().len(), 1, "pinned: no second prompt");
    let vault_id = a.status().vault_id;

    // Second device: bootstrap vault + key, then join.
    let b = dev("device-b");
    assert_eq!(b.join_from(&s3, &vault_id, MASTER).await.expect("join"), vault::VaultStatus::Unlocked);
    assert_eq!(b.status().vault_id, vault_id);
    assert_eq!(b.status().counter, 1);
    assert_eq!(b.names(), ["db"]);
    let ev = b.audits();
    assert!(ev.contains(&"sync.pulled".to_owned()) && ev.contains(&"sync.joined".to_owned()), "{ev:?}");
    assert!(b.status().config.is_some(), "join stores the settings");

    // Concurrent edits of the same row: B merges and keeps both copies.
    a.set_host(&db, "db", "192.0.2.11");
    b.set_host(&db, "db", "192.0.2.12");
    b.add("web", "192.0.2.20");
    assert_eq!(a.now().await.expect("a push"), Outcome::Pushed { counter: 2 });
    let Outcome::Merged { counter: 3, conflicts } = b.now().await.expect("b merge") else { panic!("merge") };
    assert!(!conflicts.is_empty());
    assert_eq!(b.names().len(), 3, "{:?}", b.names());
    assert!(b.names().iter().any(|n| n.contains("conflict")), "{:?}", b.names());
    assert!(b.audits().contains(&"sync.merged".to_owned()));
    let listed: Vec<_> = conflicts.iter().cloned().map(super::sync_trust::StatusConflict::Merge).collect();
    assert_eq!(b.status().conflicts, listed);
    assert_eq!(a.now().await.expect("a pull"), Outcome::Pulled { counter: 3 });
    assert_eq!(a.names(), b.names());

    // Fork: generation 4 published twice (the bucket served an old `current` to B).
    let v3 = s3.object(&current_key(&vault_id)).expect("v3");
    a.add("fork-a", "192.0.2.30");
    assert_eq!(a.now().await.expect("a 4"), Outcome::Pushed { counter: 4 });
    s3.put_object(&current_key(&vault_id), &v3);
    b.add("fork-b", "192.0.2.31");
    assert_eq!(b.now().await.expect("b 4"), Outcome::Pushed { counter: 4 });
    assert_eq!(a.now().await.expect_err("fork").code, "sync.fork");
    assert_eq!(a.status().state, "fork");
    assert_eq!(a.status().alarm, Some(Alarm::Fork { remote: 4 }));
    assert!(a.audits().contains(&"sync.fork_detected".to_owned()));
    assert_eq!(a.now().await.expect_err("sticky").code, "sync.fork", "hard stop until resolved");
    assert!(schedule_inputs(&a.f.state).expect("inputs").1, "the runner stays off");

    // Resolve: the native confirmation decides; cancelling keeps the alarm.
    let no = ScriptedPrompter::new(TrustAnswer::Pin, false);
    let e = resolve_fork(&a.f.state, &a.hub, Some(&no), None, "remote").await.expect_err("cancel");
    assert_eq!(e.code, "sync.cancelled");
    assert_eq!(no.asked(), ["confirm:Resolve sync fork"]);
    assert_eq!(a.status().state, "fork");
    let bad = resolve_fork(&a.f.state, &a.hub, Some(&a.p), None, "both").await.expect_err("keep");
    assert_eq!(bad.code, "input.invalid");
    // M-16: the cancelled resolution cools down; the other side is a different target.
    let cool = resolve_fork(&a.f.state, &a.hub, Some(&a.p), None, "remote").await.expect_err("cool-down");
    assert_eq!(cool.code, "confirm.cooldown");
    assert!(a.audits().contains(&"confirm_refused".to_owned()));
    a.f.state.confirm.clear_cooldowns();
    let r = resolve_fork(&a.f.state, &a.hub, Some(&a.p), None, "remote").await.expect("resolve");
    assert_eq!(r, Outcome::Pulled { counter: 4 });
    assert_eq!(a.names(), b.names());
    assert!(a.names().contains(&"fork-b".to_owned()) && !a.names().contains(&"fork-a".to_owned()));
    assert!(a.audits().contains(&"sync.fork_resolved".to_owned()));
    assert_eq!(a.status().state, "idle");

    // Rollback: the bucket serves the previous generation → hard stop, never applied.
    a.add("after", "192.0.2.40");
    assert_eq!(a.now().await.expect("a 5"), Outcome::Pushed { counter: 5 });
    s3.set_knobs(S3Knobs { rollback: 1, fork: false });
    assert_eq!(a.now().await.expect_err("rollback").code, "sync.rollback");
    assert_eq!(a.status().state, "rollback");
    assert_eq!(a.status().alarm, Some(Alarm::Rollback { remote: 4, last: 5 }));
    assert!(a.audits().contains(&"sync.rollback_detected".to_owned()));
    assert!(a.names().contains(&"after".to_owned()));

    // Lost-update knob: every `If-Match` fails → `sync.conflict`, nothing applied on B.
    s3.set_knobs(S3Knobs { rollback: 0, fork: true });
    b.add("late", "192.0.2.50");
    assert_eq!(b.now().await.expect_err("cas").code, "sync.conflict");
    assert!(!b.names().contains(&"after".to_owned()), "a merge is applied only after the write");
    assert_eq!(b.status().state, "error");
    s3.recorder().assert_no_violations();
}

#[tokio::test]
async fn configure_refusals_trust_rejection_and_disable() {
    let s3 = server().await;
    let a = dev("device-a");
    assert_eq!(a.now().await.expect_err("unconfigured").code, "sync.not_configured");
    let key = add_key(&a.f.state, &s3);
    let mut input = ConfigureInput { backend: backend(&s3), credential_id: key.clone(), interval_minutes: Some(3) };
    let st = &a.f.state;
    assert_eq!(configure(st, &a.hub, Some(&a.p), None, input.clone()).await.expect_err("interval").code, "input.invalid");
    input.interval_minutes = None;
    let mut plain = input.clone();
    plain.backend.endpoint = "http://192.0.2.1".into();
    assert_eq!(configure(st, &a.hub, Some(&a.p), None, plain).await.expect_err("http").code, "input.invalid");
    let mut wrong = input.clone();
    wrong.credential_id = credentials::create(st, NewCredential::password_for_tests("pw")).expect("pw").id;
    assert_eq!(configure(st, &a.hub, Some(&a.p), None, wrong).await.expect_err("kind").code, "credential.incompatible");
    // Rejecting the certificate stores nothing and pins nothing.
    let reject = ScriptedPrompter::new(TrustAnswer::Reject, true);
    let e = configure(st, &a.hub, Some(&reject), None, input.clone()).await.expect_err("reject");
    assert_eq!(e.code, "http.trust_prompt");
    assert_eq!(a.status().state, "disabled");
    let pins = || crate::commands::known_certs::list(st, mooring_core::known_certs::CertProtocol::Sync).expect("l");
    assert!(pins().is_empty());
    // M-16: the rejected host cools down before it can be asked again.
    let once = ScriptedPrompter::new(TrustAnswer::Once, true);
    assert_eq!(configure(st, &a.hub, Some(&once), None, input.clone()).await.expect_err("cool").code, "confirm.cooldown");
    assert!(once.asked().is_empty());
    st.confirm.clear_cooldowns();
    // "Trust once" works for this run and pins nothing.
    configure(st, &a.hub, Some(&once), None, input.clone()).await.expect("once");
    assert!(pins().is_empty());
    assert_eq!(a.status().next_run_unix, None, "manual only");
    // Single flight.
    let flight = a.hub.try_begin().expect("hold");
    assert_eq!(a.now().await.expect_err("busy").code, "sync.in_progress");
    drop(flight);
    // Background runs never prompt: the unpinned endpoint is reported in the status.
    assert_eq!(run_once(st, &a.hub, None, None).await.expect_err("bg").code, "http.trust_prompt");
    assert_eq!(a.status().last_error.expect("err").code, "http.trust_prompt");
    assert_eq!(a.status().state, "error");
    // Without conditional writes the backend is refused.
    s3.set_conditional_writes(false);
    let e = configure(st, &a.hub, Some(&once), None, input.clone()).await.expect_err("probe");
    assert_eq!(e.code, "sync.unsupported_backend");
    s3.set_conditional_writes(true);
    // Disable.
    disable(st, &a.hub, None, None, false).await.expect("disable");
    assert_eq!(a.status().state, "disabled");
    assert!(a.audits().contains(&"sync.disabled".to_owned()));
    assert_eq!(disable(st, &a.hub, None, None, false).await.expect_err("again").code, "sync.not_configured");
    s3.recorder().assert_no_violations();
}

#[tokio::test]
async fn vault_join_refusals() {
    let s3 = server().await;
    let a = dev("device-a");
    a.configure(&s3).await.expect("configure");
    a.now().await.expect("push");
    let vault_id = a.status().vault_id;
    // A store with data cannot join.
    let c = dev("device-c");
    c.add("mine", "192.0.2.60");
    assert_eq!(c.join_from(&s3, &vault_id, MASTER).await.expect_err("data").code, "sync.store_not_empty");
    // Wrong master password: nothing changes on the bootstrap device.
    let d = dev("device-d");
    let boot = d.status().vault_id;
    assert_eq!(d.join_from(&s3, &vault_id, "wrong test-only pw").await.expect_err("pw").code, "vault.unlock");
    assert_eq!(d.status().vault_id, boot);
    assert!(d.status().config.is_none());
    // Unknown vault, unsupported backend, own vault.
    let other = mooring_vault::Uuid::new_v4().to_string();
    assert_eq!(d.join_from(&s3, &other, MASTER).await.expect_err("none").code, "sync.invalid");
    assert_eq!(d.join_from(&s3, "not-a-uuid", MASTER).await.expect_err("id").code, "input.invalid");
    assert_eq!(d.join_from(&s3, &boot, MASTER).await.expect_err("own").code, "sync.store_not_empty");
    let mut input = JoinInput {
        backend: backend(&s3),
        credential_id: add_key(&d.f.state, &s3),
        vault_id: vault_id.clone(),
        password: MASTER.into(),
        interval_minutes: None,
    };
    input.backend.kind = "webdav".into();
    assert_eq!(join(&d.f.state, &d.hub, None, None, input).await.expect_err("kind").code, "sync.backend_unsupported");
    // A device that already synced cannot join again.
    assert_eq!(a.join_from(&s3, &vault_id, MASTER).await.expect_err("synced").code, "sync.store_not_empty");
    // Locked.
    vault::lock(&d.f.state, None).expect("lock");
    let e = d.join_from_locked(&s3, &vault_id).await;
    assert_eq!(e.code, "vault.locked");
    s3.recorder().assert_no_violations();
}

impl Dev {
    async fn join_from_locked(&self, s: &S3Server, vault_id: &str) -> IpcError {
        let input = JoinInput {
            backend: backend(s),
            credential_id: mooring_vault::Uuid::new_v4().to_string(),
            vault_id: vault_id.to_owned(),
            password: MASTER.into(),
            interval_minutes: None,
        };
        join(&self.f.state, &self.hub, Some(&self.p), None, input).await.expect_err("locked")
    }
}

#[tokio::test]
async fn locked_vault_refuses_every_command_and_stops_the_runner() {
    let s3 = server().await;
    let a = dev("device-a");
    a.configure(&s3).await.expect("configure");
    // The runner's in-flight task is aborted by the first tick after a lock.
    let task = tokio::spawn(std::future::pending::<()>());
    a.hub.set_task(task.abort_handle());
    let flight = a.hub.try_begin().expect("runner flight");
    vault::lock(&a.f.state, None).expect("lock");
    assert_eq!(crate::sync_runner::runner_tick(&a.f.state, &a.hub, std::time::Instant::now()), crate::sync_runner::Tick::Abort);
    assert!(task.await.expect_err("aborted").is_cancelled());
    drop(flight);
    assert_eq!(crate::sync_runner::runner_tick(&a.f.state, &a.hub, std::time::Instant::now()), crate::sync_runner::Tick::Idle);
    let st = &a.f.state;
    assert_eq!(status(st, &a.hub).expect_err("status").code, "vault.locked");
    assert_eq!(a.now().await.expect_err("now").code, "vault.locked");
    assert_eq!(resolve_fork(st, &a.hub, Some(&a.p), None, "local").await.expect_err("r").code, "vault.locked");
    assert_eq!(disable(st, &a.hub, None, None, true).await.expect_err("d").code, "vault.locked");
    let input = ConfigureInput { backend: backend(&s3), credential_id: mooring_vault::Uuid::new_v4().to_string(), interval_minutes: None };
    assert_eq!(configure(st, &a.hub, Some(&a.p), None, input).await.expect_err("c").code, "vault.locked");
    s3.recorder().assert_no_violations();
}

#[test]
fn engine_errors_map_to_listed_codes_without_detail() {
    use mooring_http::HttpError;
    for e in [
        SyncError::Format("x"),
        SyncError::TooLarge,
        SyncError::Tampered,
        SyncError::WrongVault,
        SyncError::HeaderMismatch("x"),
        SyncError::Rollback { remote: 1, last: 2 },
        SyncError::Fork { remote: 1 },
        SyncError::Conflict,
        SyncError::UnsupportedBackend,
        SyncError::Backend { status: 500 },
        SyncError::KeyringHeader,
        SyncError::Invalid("x"),
        SyncError::Io(std::io::ErrorKind::Other),
        SyncError::Vault(mooring_vault::VaultError::Locked),
        SyncError::Http(HttpError::Timeout),
        SyncError::Http(HttpError::Tls("detail from the peer".into())),
    ] {
        let ipc = sync_error(&e);
        assert_eq!(ipc.code, e.code(), "{e:?}");
        assert!(ipc.code == "vault.locked" || SYNC_CODES.contains(&ipc.code), "{e:?}");
        assert!(!ipc.message.contains("detail from the peer"));
    }
}

/// A header writer that fails at one of its two steps (review 6 L-37).
pub(crate) struct FailingWriter {
    pub stage: bool,
    pub commit: bool,
}

impl sync_join::HeaderWriter for FailingWriter {
    fn stage(&self, state: &AppState, header: &mooring_vault::Header) -> IpcResult<()> {
        if self.stage {
            return Err(IpcError::new("state.io", "injected"));
        }
        sync_join::FsHeaderWriter.stage(state, header)
    }
    fn commit(&self, state: &AppState) -> IpcResult<()> {
        if self.commit {
            return Err(IpcError::new("state.io", "injected"));
        }
        sync_join::FsHeaderWriter.commit(state)
    }
}

pub(crate) fn header_on_disk(state: &AppState) -> String {
    let bytes = std::fs::read(state.data_dir.join(AppState::HEADER_FILE)).expect("header");
    mooring_vault::Vault::from_header_bytes(&bytes).expect("parse").vault_id().to_string()
}

/// Review 6 L-37: a header write failure never strands the device. Staging fails → nothing
/// changed (bootstrap header, store, no settings). The rename fails → the joined vault is live
/// and the staged header is installed at the next start.
#[tokio::test]
async fn vault_join_header_write_failures_never_strand_the_device() {
    let s3 = server().await;
    let a = dev("device-a");
    a.add("shared", "192.0.2.70");
    a.configure(&s3).await.expect("configure");
    a.now().await.expect("push");
    let vault_id = a.status().vault_id;
    let input = |st: &AppState| JoinInput {
        backend: backend(&s3),
        credential_id: add_key(st, &s3),
        vault_id: vault_id.clone(),
        password: MASTER.into(),
        interval_minutes: None,
    };
    let tmp = |st: &AppState| st.data_dir.join(sync_join::JOIN_TMP);

    let dd = dev("device-d");
    let boot = dd.status().vault_id;
    let writer = FailingWriter { stage: true, commit: false };
    let e = sync_join::join_with(&dd.f.state, &dd.hub, Some(&dd.p), None, input(&dd.f.state), &writer).await.expect_err("stage");
    assert_eq!(e.code, "state.io");
    assert_eq!((dd.status().vault_id, header_on_disk(&dd.f.state)), (boot.clone(), boot.clone()));
    assert!(dd.status().config.is_none() && dd.names().is_empty() && !tmp(&dd.f.state).exists());
    vault::lock(&dd.f.state, None).expect("lock");
    vault::unlock(&dd.f.state, secrecy::SecretString::from(MASTER.to_owned())).expect("bootstrap still opens");
    assert_eq!(dd.join_from(&s3, &vault_id, MASTER).await.expect("retry"), vault::VaultStatus::Unlocked);
    assert_eq!(dd.names(), a.names());

    let e2 = dev("device-e");
    let boot = e2.status().vault_id;
    let writer = FailingWriter { stage: false, commit: true };
    let r = sync_join::join_with(&e2.f.state, &e2.hub, Some(&e2.p), None, input(&e2.f.state), &writer).await;
    assert_eq!(r.expect("the join completes"), vault::VaultStatus::Unlocked);
    assert_eq!((e2.status().vault_id, e2.names()), (vault_id.clone(), a.names()));
    assert!(tmp(&e2.f.state).exists(), "the staged header waits for the next start");
    assert_eq!(header_on_disk(&e2.f.state), boot, "the bootstrap header is untouched");
    // Restart: the store is bound to the staged header's vault, so the rename completes.
    let Dev { f: Fixture { dir, state, clipboard }, .. } = e2;
    drop(state);
    let st = AppState::new(testing::dirs(dir.path()), testing::settings(clipboard)).expect("restart");
    assert!(!tmp(&st).exists());
    assert_eq!(header_on_disk(&st), vault_id);
    vault::unlock(&st, secrecy::SecretString::from(MASTER.to_owned())).expect("the joined vault opens");
    assert_eq!(st.with_ready(|v, _| Ok(v.vault_id().to_string())).expect("bound"), vault_id);
    // A stale staged header (store bound elsewhere) is removed at start, not installed.
    let other = dev("device-f");
    let Dev { f: Fixture { dir, state, clipboard }, .. } = other;
    let boot = state.with_ready(|v, _| Ok(v.vault_id().to_string())).expect("id");
    std::fs::copy(st.data_dir.join(AppState::HEADER_FILE), dir.path().join(sync_join::JOIN_TMP)).expect("stale");
    drop(state);
    let st2 = AppState::new(testing::dirs(dir.path()), testing::settings(clipboard)).expect("restart");
    assert!(!tmp(&st2).exists());
    assert_eq!(header_on_disk(&st2), boot);
    s3.recorder().assert_no_violations();
}

#[path = "sync_tests_6b.rs"]
mod tests_6b;
