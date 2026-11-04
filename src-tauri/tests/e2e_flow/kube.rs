//! A3 K4 end to end: a Kubernetes cluster through the IPC command functions against QA's
//! loopback kube mock (`mooring_testsrv::kube`): kube_token credential → connection options →
//! kube_open → `connected` (RBAC) → namespaces / pods → exec shell echo → pod forward echo →
//! vault lock ends everything → unlock → the cluster opens again. Every request the mock saw
//! is inside the ADR-0014 §4 allow-list.

use std::sync::Arc;
use std::time::Duration;

use mooring_testsrv::kube::{self as mock, KubeConfig};
use mooring_testsrv::tls::TestCert;
use serde_json::json;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::mpsc;

use crate::commands::credentials::{self, NewCredential, WireSecrets};
use crate::commands::kube::{self, ExecRequest};
use crate::commands::sessions as sess;
use crate::commands::tree::{self, ConnectionFields};
use crate::commands::{conn_options, forward, vault};
use crate::state::testing::{self, MASTER};
use crate::support::{self, b64, next, read_until, sink, wait_until_empty, Events};

async fn cluster_open(st: &crate::state::AppState, conn: &str) -> (String, Events) {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let s = Arc::new(move |e: mooring_app_lib::commands::kube_wire::ClusterEvent| {
        tx.send(serde_json::to_value(&e).expect("json")).is_ok()
    });
    let id = kube::open(st, conn, s).expect("kube_open").session_id;
    let e = next(&mut rx).await;
    assert_eq!(e["kind"], "connected", "{e}");
    assert_eq!(e["rbac"]["exec"], true);
    (id, rx)
}

#[tokio::test]
async fn kube_cluster_exec_forward_lock_unlock() {
    let (cert, ca) = TestCert::generate_ca_issued(&["localhost", "127.0.0.1"]).expect("cert");
    let srv = mock::start(KubeConfig { cert: Some(cert), ..KubeConfig::default() }, 0)
        .await
        .expect("mock");
    let f = testing::unlocked();
    let st = &f.state;
    let cred = credentials::create(
        st,
        NewCredential {
            name: "cluster token".into(),
            kind: "kube_token".into(),
            fields: json!({ "subject": "alice" }),
            secrets: WireSecrets::of(&[("token", "test-token")]),
        },
    )
    .expect("credential");
    let root = tree::list(st).expect("tree").folders[0].id.clone();
    let conn = tree::create_connection(
        st,
        ConnectionFields {
            credential_id: Some(cred.id),
            ..ConnectionFields::basic(&root, "mock cluster", "kubernetes", "127.0.0.1")
        },
    )
    .expect("connection");
    conn_options::set(
        st,
        &conn.id,
        json!({ "server": srv.base_url(), "caPem": ca, "execCommand": "sh" }),
    )
    .expect("options");

    let (cid, mut cluster) = cluster_open(st, &conn.id).await;
    assert_eq!(kube::namespaces(st, &cid).await.expect("ns").items.len(), 3);
    assert_eq!(kube::pods(st, &cid, "default", None).await.expect("pods").items.len(), 2);

    let (s, mut term) = sink();
    let req = ExecRequest {
        namespace: "default".into(),
        pod: "db-0".into(),
        container: None,
        command: None,
        size: mooring_core::session::Size { width: 100, height: 30 },
    };
    let xid = kube::exec_open(st, &cid, req, s).await.expect("exec").session_id;
    assert_eq!(next(&mut term).await["kind"], "connected");
    sess::send(st, &xid, sess::WireInput::Bytes { data: b64(b"echo e2e\n") }).await.expect("send");
    read_until(&mut term, "echo e2e").await;
    assert_eq!(srv.exec_sessions()[0].command, ["sh"], "the connection's execCommand");

    let target = Some(json!({ "namespace": "default", "pod": "web-0", "port": 8080 }));
    let bind = forward::WireEndpoint { host: "localhost".into(), port: 0 };
    let forward::AnyForward::Pod(fwd) =
        forward::open_any(st, &cid, "pod".into(), bind, target, None).await.expect("fwd")
    else {
        panic!("pod forward")
    };
    let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", fwd.bind.port)).await.expect("tcp");
    tcp.write_all(b"e2e!").await.expect("write");
    let mut buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(10), tcp.read_exact(&mut buf))
        .await
        .expect("in time")
        .expect("read");
    assert_eq!(&buf, b"e2e!");

    vault::lock(st, None).expect("lock");
    loop {
        let e = next(&mut cluster).await;
        if e["kind"] == "closed" {
            assert_eq!(e["code"], "vault_locked");
            break;
        }
    }
    loop {
        if next(&mut term).await["kind"] == "closed" {
            break;
        }
    }
    wait_until_empty(st).await;
    // Review 6 L-38: the cluster id used after the lock gets `session.not_found` for each of
    // the session-bound kube commands (close_all ended the cluster).
    for (name, code) in support::kube_session_bound_codes(st, &cid).await {
        assert_eq!(code, "session.not_found", "{name} with the ended cluster id");
    }
    let (tx, _rx2) = mpsc::unbounded_channel::<serde_json::Value>();
    let locked = kube::open(
        st,
        &conn.id,
        Arc::new(move |e| tx.send(serde_json::to_value(&e).expect("json")).is_ok()),
    );
    assert_eq!(locked.expect_err("locked").code, "vault.locked");

    vault::unlock(st, secrecy::SecretString::from(MASTER.to_owned())).expect("unlock");
    let (cid, _cluster) = cluster_open(st, &conn.id).await;
    sess::close(st, &cid).await.expect("close");
    wait_until_empty(st).await;
    srv.recorder().assert_no_violations();
}
