//! Engine scenarios on the in-memory bucket: first push, pull, merge with a secret conflict,
//! CAS races of two engines, fork / rollback hard stops and their resolution, tamper,
//! header pairing, unsupported backends.

use mooring_core::SecretName;

use super::{remote, vaults, Device};
use crate::{Alarm, Keep, MemoryStore, Outcome, Resolution, SyncEngine, SyncError, VecAudit};

fn pair() -> (Device, Device, MemoryStore) {
    let mut vs = vaults(2);
    let b = Device::new(vs.remove(1), "laptop");
    let a = Device::new(vs.remove(0), "desktop");
    (a, b, MemoryStore::new())
}

async fn run(d: &Device, m: &MemoryStore, audit: &VecAudit) -> crate::Result<Outcome> {
    SyncEngine::default().run(&d.local(), &remote(m, &d.vault), audit).await
}

fn current_key(d: &Device) -> String {
    format!("team/sync/{}/current", d.vault.vault_id())
}

#[tokio::test]
async fn push_pull_and_no_change() {
    let (a, b, m) = pair();
    let audit = VecAudit::default();
    a.conn("web", "web.example.test");
    std::fs::write(a.dir.path().join("known_hosts"), "web.example.test ssh-ed25519 AAAA\n")
        .expect("trust");
    assert_eq!(run(&a, &m, &audit).await.expect("push"), Outcome::Pushed { counter: 1 });
    assert_eq!(run(&b, &m, &audit).await.expect("pull"), Outcome::Pulled { counter: 1 });
    assert_eq!(b.names(), ["web"]);
    assert_eq!(b.trust("known_hosts"), "web.example.test ssh-ed25519 AAAA\n", "trust synced");
    assert_eq!(run(&b, &m, &audit).await.expect("again"), Outcome::NoChange { counter: 1 });
    assert_eq!(run(&a, &m, &audit).await.expect("a again"), Outcome::NoChange { counter: 1 });
    b.conn("db", "db.example.test");
    assert_eq!(run(&b, &m, &audit).await.expect("push 2"), Outcome::Pushed { counter: 2 });
    assert_eq!(run(&a, &m, &audit).await.expect("pull 2"), Outcome::Pulled { counter: 2 });
    assert_eq!(a.names(), ["db", "web"]);
    assert_eq!(audit.names(), ["sync.push", "sync.pull", "sync.push", "sync.pull"]);
    let keys = m.keys();
    assert!(keys.iter().any(|k| k.ends_with("/header")));
    assert!(keys.iter().any(|k| k.ends_with("/history/00000000000000000002")));
    let blob = m.raw_get(&current_key(&a)).expect("current");
    assert!(!blob.windows(3).any(|w| w == b"web"), "bucket sees ciphertext only");
}

#[tokio::test]
async fn concurrent_edits_merge_and_secret_conflicts_keep_both() {
    let (a, b, m) = pair();
    let audit = VecAudit::default();
    let cred = a.password("ops", b"pw-0");
    run(&a, &m, &audit).await.expect("push");
    run(&b, &m, &audit).await.expect("pull");
    let pw = |p: &'static [u8]| -> mooring_store::Secrets<'static> {
        [(SecretName::Password, p)].into_iter().collect()
    };
    a.store.replace_secrets(&a.vault, cred.id, &pw(b"pw-a"), &[]).expect("a edit");
    b.store.replace_secrets(&b.vault, cred.id, &pw(b"pw-b"), &[]).expect("b edit");
    a.conn("only-a", "a.example.test");
    run(&a, &m, &audit).await.expect("a push");
    let Outcome::Merged { counter, conflicts } = run(&b, &m, &audit).await.expect("merge") else {
        panic!("expected a merge");
    };
    assert_eq!(counter, 3);
    assert_eq!(conflicts.len(), 1);
    let Resolution::KeptBoth { copy_id } = &conflicts[0].resolution else { panic!("both") };
    assert_eq!(b.names(), ["only-a"]);
    run(&a, &m, &audit).await.expect("a pulls merge");
    for d in [&a, &b] {
        let creds = d.store.list_credentials().expect("list");
        assert_eq!(creds.len(), 2);
        let mine = d.store.open_secret(&d.vault, cred.id, SecretName::Password).expect("open");
        assert_eq!(mine.as_slice(), b"pw-b", "B merged: its copy keeps the id");
        let copy = creds.iter().find(|c| c.id.to_string() == *copy_id).expect("copy");
        assert_eq!(copy.name, "ops (conflict from desktop)");
        let theirs = d.store.open_secret(&d.vault, copy.id, SecretName::Password).expect("copy");
        assert_eq!(theirs.as_slice(), b"pw-a");
    }
    assert!(audit.names().contains(&"sync.merge"));
}

#[tokio::test]
async fn two_engines_racing_converge_through_conditional_writes() {
    let (a, b, m) = pair();
    m.set_yield(true);
    let audit = VecAudit::default();
    a.conn("from-a", "a.example.test");
    b.conn("from-b", "b.example.test");
    let (ra, rb) = tokio::join!(run(&a, &m, &audit), run(&b, &m, &audit));
    let (ra, rb) = (ra.expect("a"), rb.expect("b"));
    let pushed = [&ra, &rb].iter().filter(|o| matches!(o, Outcome::Pushed { counter: 1 })).count();
    assert_eq!(pushed, 1, "exactly one first push wins If-None-Match: {ra:?} {rb:?}");
    assert!([&ra, &rb].iter().any(|o| matches!(o, Outcome::Merged { counter: 2, .. })));
    run(&a, &m, &audit).await.expect("a settles");
    run(&b, &m, &audit).await.expect("b settles");
    // Each side has its own root folder from first start; both connections survive.
    let mut names_a = a.names();
    names_a.dedup();
    assert_eq!(names_a, ["from-a", "from-b"]);
    assert_eq!(a.names(), b.names());
}

#[tokio::test]
async fn equal_counter_with_another_hash_is_a_fork_until_resolved() {
    let (a, b, m) = pair();
    let audit = VecAudit::default();
    a.conn("base", "base.example.test");
    run(&a, &m, &audit).await.expect("push 1");
    run(&b, &m, &audit).await.expect("pull 1");
    let gen1 = m.raw_get(&current_key(&a)).expect("gen1");
    a.conn("a-side", "a.example.test");
    run(&a, &m, &audit).await.expect("a push 2");
    m.raw_put(&current_key(&a), gen1); // the bucket loses A's generation 2
    b.conn("b-side", "b.example.test");
    run(&b, &m, &audit).await.expect("b push 2");
    let err = run(&a, &m, &audit).await.expect_err("fork");
    assert!(matches!(err, SyncError::Fork { remote: 2 }), "{err:?}");
    assert!(err.is_alarm());
    assert!(matches!(run(&a, &m, &audit).await, Err(SyncError::Fork { .. })), "sticky");
    let st = crate::load_state(&a.store).expect("state").expect("some");
    assert_eq!(st.alarm, Some(Alarm::Fork { remote: 2 }));
    assert!(audit.names().contains(&"sync.fork"));

    let e = SyncEngine::default();
    let out = e.resolve_fork(&a.local(), &remote(&m, &a.vault), Keep::Remote, &audit).await;
    assert_eq!(out.expect("resolve"), Outcome::Pulled { counter: 2 });
    assert_eq!(a.names(), ["b-side", "base"]);
    assert_eq!(run(&a, &m, &audit).await.expect("clear"), Outcome::NoChange { counter: 2 });
}

#[tokio::test]
async fn foreign_history_is_a_fork_and_keep_local_republishes() {
    let (a, b, m) = pair();
    let audit = VecAudit::default();
    a.conn("base", "base.example.test");
    run(&a, &m, &audit).await.expect("1");
    run(&b, &m, &audit).await.expect("pull");
    let gen1 = m.raw_get(&current_key(&a)).expect("gen1");
    a.conn("a2", "a.example.test");
    run(&a, &m, &audit).await.expect("a 2");
    m.raw_put(&current_key(&a), gen1);
    b.conn("b2", "b.example.test");
    run(&b, &m, &audit).await.expect("b 2");
    b.conn("b3", "b3.example.test");
    run(&b, &m, &audit).await.expect("b 3");
    assert!(matches!(run(&a, &m, &audit).await, Err(SyncError::Fork { remote: 3 })));
    let e = SyncEngine::default();
    let out = e.resolve_fork(&a.local(), &remote(&m, &a.vault), Keep::Local, &audit).await;
    assert_eq!(out.expect("keep local"), Outcome::Pushed { counter: 4 });
    assert_eq!(run(&b, &m, &audit).await.expect("b pulls"), Outcome::Pulled { counter: 4 });
    assert_eq!(b.names(), ["a2", "base"]);
    assert!(audit.names().contains(&"sync.alarm_resolved"));
}

#[tokio::test]
async fn rollback_is_refused_and_never_applied() {
    let (a, b, m) = pair();
    let audit = VecAudit::default();
    a.conn("one", "one.example.test");
    run(&a, &m, &audit).await.expect("1");
    let gen1 = m.raw_get(&current_key(&a)).expect("gen1");
    a.conn("two", "two.example.test");
    run(&a, &m, &audit).await.expect("2");
    run(&b, &m, &audit).await.expect("b at 2");
    m.raw_put(&current_key(&a), gen1);
    let err = run(&b, &m, &audit).await.expect_err("rollback");
    assert!(matches!(err, SyncError::Rollback { remote: 1, last: 2 }), "{err:?}");
    assert_eq!(err.code(), "sync.rollback");
    assert_eq!(b.names(), ["one", "two"], "never applied");
    assert!(audit.names().contains(&"sync.rollback_refused"));
    // A vanished object is a rollback to 0.
    let (c, _, m2) = pair();
    c.conn("x", "x.example.test");
    run(&c, &m2, &audit).await.expect("push");
    m2.delete_raw(&current_key(&c));
    assert!(matches!(run(&c, &m2, &audit).await, Err(SyncError::Rollback { remote: 0, last: 1 })));
}

#[tokio::test]
async fn tampered_blobs_and_swapped_headers_are_rejected() {
    let (a, b, m) = pair();
    let audit = VecAudit::default();
    a.conn("one", "one.example.test");
    run(&a, &m, &audit).await.expect("1");
    let key = current_key(&a);
    let good = m.raw_get(&key).expect("blob");
    let mut bad = good.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    m.raw_put(&key, bad);
    assert!(matches!(run(&b, &m, &audit).await, Err(SyncError::Tampered)));
    m.raw_put(&key, good);
    let header_key = key.replace("/current", "/header");
    let other = vaults(1).remove(0);
    m.raw_put(&header_key, other.header().to_bytes().expect("hdr"));
    assert!(matches!(run(&b, &m, &audit).await, Err(SyncError::HeaderMismatch(_))));
    // A blob of another vault under this vault's key.
    let (c, _, m3) = pair();
    c.conn("c", "c.example.test");
    run(&c, &m3, &audit).await.expect("c");
    m.raw_put(&key, m3.raw_get(&current_key(&c)).expect("c blob"));
    assert!(matches!(run(&b, &m, &audit).await, Err(SyncError::WrongVault)));
    assert!(b.names().is_empty());
}

#[tokio::test]
async fn probe_refuses_backends_without_conditional_writes() {
    let (a, _, m) = pair();
    let r = remote(&m, &a.vault);
    assert!(r.probe().await.expect("probe"));
    assert!(m.keys().iter().all(|k| !k.contains(".probe")), "probe object removed");
    m.set_ignore_conditionals(true);
    assert!(!r.probe().await.expect("probe"));
    let err = r.require_conditional_writes().await.expect_err("refused");
    assert_eq!(err.code(), "sync.unsupported_backend");
}

#[tokio::test]
async fn locked_vault_and_keyring_header_are_refused() {
    let (mut a, _, m) = pair();
    a.vault.lock();
    let err = run(&a, &m, &VecAudit::default()).await.expect_err("locked");
    assert_eq!(err.code(), "vault.locked");
    assert!(crate::Remote::new(m.clone(), "../x", a.vault.vault_id()).is_err());
    assert!(crate::Remote::new(m, "a//b", a.vault.vault_id()).is_err());
}
