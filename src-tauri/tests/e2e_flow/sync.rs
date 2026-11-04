//! ADR-0017 S2 user flow through the command plain functions, against the SigV4-verifying S3
//! mock on loopback TLS: configure (certificate pinned through the Gate) → push → a second
//! device joins → it edits and pushes → the first pulls → lock refuses sync → unlock → the
//! audit chains verify. No secret value is ever returned by a command.

use mooring_sync::Outcome;
use mooring_testsrv::s3 as srv;
use serde_json::json;

use crate::commands::audit;
use crate::commands::credentials::{self, NewCredential, WireSecrets};
use crate::commands::sync::{self, ConfigureInput};
use crate::commands::sync_config::BackendInput;
use crate::commands::sync_gate::{ScriptedPrompter, TrustAnswer};
use crate::commands::sync_join::{self, JoinInput};
use crate::commands::tree::{self, ConnectionFields};
use crate::commands::vault::{self, VaultStatus};
use crate::state::testing::{self, MASTER};
use crate::sync_runner::SyncHub;

fn backend(s: &srv::S3Server) -> BackendInput {
    BackendInput {
        kind: "s3".into(),
        endpoint: s.endpoint(),
        region: "us-east-1".into(),
        bucket: s.bucket(),
        prefix: "e2e".into(),
        path_style: None,
    }
}

fn key(st: &crate::state::AppState, s: &srv::S3Server) -> String {
    let c = s.credentials();
    let dto = credentials::create(
        st,
        NewCredential {
            name: "sync key".into(),
            kind: "s3_access_key".into(),
            fields: json!({ "access_key_id": c.access_key, "region": "us-east-1" }),
            secrets: WireSecrets::of(&[("secret_access_key", &c.secret_key)]),
        },
    )
    .expect("key");
    let wire = serde_json::to_string(&dto).expect("dto");
    assert!(!wire.contains(&c.secret_key), "the secret never leaves Rust");
    dto.id
}

fn root(st: &crate::state::AppState) -> String {
    tree::list(st)
        .expect("tree")
        .folders
        .into_iter()
        .find(|f| f.parent_id.is_none())
        .expect("root")
        .id
}

fn names(st: &crate::state::AppState) -> Vec<String> {
    let mut n: Vec<String> =
        tree::list(st).expect("tree").connections.into_iter().map(|c| c.name).collect();
    n.sort();
    n
}

#[tokio::test]
async fn configure_push_join_edit_pull_and_lock() {
    let s3 = srv::start(srv::S3Config::default(), 0).await.expect("s3");
    let pin = ScriptedPrompter::new(TrustAnswer::Pin, true);

    // Device A.
    let a = testing::unlocked();
    let hub_a = SyncHub::new("laptop");
    let input = ConfigureInput {
        backend: backend(&s3),
        credential_id: key(&a.state, &s3),
        interval_minutes: Some(30),
    };
    sync::configure(&a.state, &hub_a, Some(&pin), None, input).await.expect("configure");
    let conn = ConnectionFields::basic(&root(&a.state), "bastion", "ssh", "192.0.2.5");
    let id = tree::create_connection(&a.state, conn).expect("conn").id;
    assert_eq!(
        sync::run_once(&a.state, &hub_a, Some(&pin), None).await.expect("push"),
        Outcome::Pushed { counter: 1 }
    );
    let status = sync::status(&a.state, &hub_a).expect("status");
    assert_eq!(status.state, "idle");
    assert!(status.next_run_unix.is_none(), "nothing scheduled before the runner ticks");
    crate::sync_runner::runner_tick(&a.state, &hub_a, std::time::Instant::now());
    let status = sync::status(&a.state, &hub_a).expect("status");
    assert!(status.next_run_unix.is_some(), "the 30 min interval is scheduled");
    let wire = serde_json::to_string(&status).expect("json");
    assert!(!wire.contains(&s3.credentials().secret_key));
    // The bucket holds ciphertext only.
    let blob = s3.object(&format!("e2e/{}/current", status.vault_id)).expect("blob");
    assert!(blob.starts_with(b"MSY1"));
    assert!(!blob.windows(7).any(|w| w == b"bastion"));

    // Device B joins.
    let b = testing::unlocked();
    let hub_b = SyncHub::new("desktop");
    let join = JoinInput {
        backend: backend(&s3),
        credential_id: key(&b.state, &s3),
        vault_id: status.vault_id.clone(),
        password: MASTER.into(),
        interval_minutes: None,
    };
    assert_eq!(
        sync_join::join(&b.state, &hub_b, Some(&pin), None, join).await.expect("join"),
        VaultStatus::Unlocked
    );
    assert_eq!(names(&b.state), ["bastion"]);

    // B renames, pushes; A pulls.
    let renamed = ConnectionFields::basic(&root(&b.state), "bastion-2", "ssh", "192.0.2.5");
    tree::update_connection(&b.state, &id, renamed).expect("rename");
    assert_eq!(
        sync::run_once(&b.state, &hub_b, Some(&pin), None).await.expect("b push"),
        Outcome::Pushed { counter: 2 }
    );
    assert_eq!(
        sync::run_once(&a.state, &hub_a, Some(&pin), None).await.expect("a pull"),
        Outcome::Pulled { counter: 2 }
    );
    assert_eq!(names(&a.state), ["bastion-2"]);
    let st = sync::status(&a.state, &hub_a).expect("status");
    assert_eq!(st.remote_device.as_deref(), Some("desktop"), "last pushed by");

    // Lock refuses; unlock resumes.
    vault::lock(&a.state, None).expect("lock");
    assert_eq!(
        sync::run_once(&a.state, &hub_a, Some(&pin), None).await.expect_err("locked").code,
        "vault.locked"
    );
    vault::unlock(&a.state, secrecy::SecretString::from(MASTER.to_owned())).expect("unlock");
    assert_eq!(
        sync::run_once(&a.state, &hub_a, Some(&pin), None).await.expect("again"),
        Outcome::NoChange { counter: 2 }
    );

    for s in [&a.state, &b.state] {
        let v = audit::verify(s).expect("verify");
        assert!(v.ok, "{v:?}");
    }
    let events = testing::audit_events(&b.state);
    for want in ["sync.pulled", "sync.joined", "sync.pushed"] {
        assert!(events.iter().any(|e| e == want), "{want}: {events:?}");
    }
}
