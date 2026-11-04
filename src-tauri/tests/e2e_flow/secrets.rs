//! ADR-0016 E2 end to end: an SSH connection whose credential is an `external_ref` resolves
//! its password from QA's Vault mock at connect time and logs in to the in-process SSH server.
//! Nothing of the secret reaches disk, the audit log or any IPC result; lock and exit drop the
//! Vault token; a sealed Vault or a root token fails the connect without fallback.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::SystemTime;

use mooring_core::session::Size;
use mooring_testsrv::tls::TestCert;
use mooring_testsrv::vault::{self, KvSecret, KvVersion, VaultConfig, VaultKnobs};
use serde_json::json;

use crate::commands::credentials::{self, NewCredential, WireSecrets};
use crate::commands::secret_sources;
use crate::commands::sessions as sess;
use crate::commands::tree::{self, ConnectionFields};
use crate::commands::vault as vault_cmd;
use crate::state::{testing, AppState};
use crate::support::{next, read_until, sink, wait_until_empty};
use crate::test_ssh_server::{self as server, PASSWORD, USER};

const SIZE: Size = Size { width: 80, height: 24 };

fn files(dir: &Path) -> BTreeMap<String, (u64, SystemTime)> {
    let mut out = BTreeMap::new();
    for e in std::fs::read_dir(dir).expect("dir") {
        let e = e.expect("entry");
        let name = e.file_name().to_string_lossy().into_owned();
        if name == AppState::AUDIT_FILE {
            continue; // append-only audit log, checked for secrets below
        }
        let m = e.metadata().expect("meta");
        out.insert(name, (m.len(), m.modified().expect("mtime")));
    }
    out
}

fn audit(st: &AppState) -> String {
    std::fs::read_to_string(st.data_dir.join(AppState::AUDIT_FILE)).expect("audit")
}

#[tokio::test]
async fn ssh_password_resolved_from_vault_at_connect() {
    let ssh = server::start(51).await;
    let (cert, ca) = TestCert::generate_ca_issued(&["localhost", "127.0.0.1"]).expect("cert");
    let kv = vec![KvSecret {
        mount: "secret".into(),
        path: "ssh/web01".into(),
        versions: vec![KvVersion::new(json!({ "username": USER, "password": PASSWORD }))],
    }];
    let vlt = vault::start(VaultConfig { cert: Some(cert), kv, ..VaultConfig::default() }, 0)
        .await
        .expect("vault mock");
    let f = testing::unlocked();
    let st = &f.state;

    let token = credentials::create(
        st,
        NewCredential {
            name: "vault token".into(),
            kind: "api_token".into(),
            fields: json!({}),
            secrets: WireSecrets::of(&[("token", "hvs.test-token")]),
        },
    )
    .expect("token credential");
    let source = secret_sources::create(
        st,
        &json!({
            "name": "lab vault", "address": vlt.base_url(), "authMethod": "token",
            "credentialId": token.id, "options": { "caPem": ca },
        }),
    )
    .expect("source");
    let reference = credentials::create(st, NewCredential {
        name: "web01 via vault".into(),
        kind: "external_ref".into(),
        fields: json!({ "provider": "vault", "source": source.id, "reference": "secret/ssh/web01",
                        "target_kind": "user_password" }),
        secrets: WireSecrets::default(),
    })
    .expect("external_ref");
    let root = tree::list(st).expect("tree").folders[0].id.clone();
    let conn = tree::create_connection(
        st,
        ConnectionFields {
            port: Some(u32::from(ssh.port)),
            credential_id: Some(reference.id.clone()),
            ..ConnectionFields::basic(&root, "web01", "ssh", "127.0.0.1")
        },
    )
    .expect("connection");
    let mut kh = mooring_proto_ssh::KnownHosts::new();
    kh.add_hashed("127.0.0.1", ssh.port, &ssh.host_public).expect("add");
    kh.save(&st.known_hosts_path()).expect("save");

    let names = secret_sources::external_test(st, &reference.id).await.expect("ref test");
    assert!(names.ok && names.present.len() == 2 && names.missing.is_empty(), "{names:?}");

    let before = files(f.dir.path());
    let (events, mut rx) = sink();
    let opened = sess::open(st, &conn.id, SIZE, events).await.expect("open via vault");
    assert_eq!(next(&mut rx).await["kind"], "connected");
    read_until(&mut rx, "welcome").await;
    assert_eq!(files(f.dir.path()), before, "resolution wrote nothing to disk");
    sess::close(st, &opened.session_id).await.expect("close");
    while next(&mut rx).await["kind"] != "closed" {}
    wait_until_empty(st).await;

    let log = audit(st);
    assert!(
        !log.contains(PASSWORD) && !log.contains("hvs.test-token"),
        "no secret in the audit log"
    );
    let resolved: Vec<serde_json::Value> = log
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["event"] == "secret_resolved")
        .collect();
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0]["connection"], conn.id.as_str());
    assert_eq!(resolved[0]["source"], source.id.as_str());
    assert_eq!(resolved[0]["target_kind"], "user_password");
    assert_eq!(resolved[0]["fields"], json!(["password", "username"]));
    assert_eq!(st.secrets.engine().cache().len(), 1, "the Vault token is cached, the value is not");

    // Sealed: connect fails closed; no cached value is used.
    vlt.set_knobs(VaultKnobs { sealed: true, ..VaultKnobs::default() });
    let (events, _rx) = sink();
    let e = sess::open(st, &conn.id, SIZE, events).await.expect_err("sealed");
    assert_eq!(e.code, "credential.external_unavailable", "{e:?}");
    assert!(!e.message.contains(PASSWORD));
    vlt.set_knobs(VaultKnobs::default());

    // Lock: the token is forgotten (the user's token is not revoked); connect needs unlock.
    vault_cmd::lock(st, None).expect("lock");
    st.secrets.flush().await;
    assert!(st.secrets.engine().cache().is_empty());
    let (events, _rx) = sink();
    assert_eq!(
        sess::open(st, &conn.id, SIZE, events).await.expect_err("locked").code,
        "vault.locked"
    );
    vault_cmd::unlock(st, secrecy::SecretString::from(testing::MASTER.to_owned())).expect("unlock");

    // Root token on the source: refused at connect.
    vlt.set_knobs(VaultKnobs { root_token: true, ..VaultKnobs::default() });
    let (events, _rx) = sink();
    let e = sess::open(st, &conn.id, SIZE, events).await.expect_err("root");
    assert_eq!(e.code, "credential.external_root_token");
    vlt.recorder().assert_no_violations();
}
