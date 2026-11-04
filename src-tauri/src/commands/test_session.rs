//! Shared fixture for the forward / SFTP command tests: an unlocked state with one SSH
//! connection to the in-process server, its host key already trusted, and a live session.

use std::sync::Arc;
use std::time::Duration;

use mooring_core::session::Size;
use tokio::sync::mpsc;

use crate::commands::credentials::{self, NewCredential};
use crate::commands::sessions as sess;
use crate::commands::tree::{self, ConnectionFields};
use crate::sessions::EventSink;
use crate::state::testing::{unlocked, Fixture};
use crate::test_ssh_server::{TestServer, PASSWORD, USER};

/// A connected session; `events` must stay alive or the session closes.
pub struct Live {
    pub f: Fixture,
    pub session_id: String,
    #[allow(dead_code)] // held so the session channel stays open
    pub events: mpsc::UnboundedReceiver<serde_json::Value>,
}

impl std::fmt::Debug for Live {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Live").field("session_id", &self.session_id).finish_non_exhaustive()
    }
}

/// Open a session to `srv` and wait for `connected`.
pub async fn connect(srv: &TestServer) -> Live {
    let f = unlocked();
    let cred =
        credentials::create(&f.state, NewCredential::user_password("alice", USER, PASSWORD))
            .expect("cred");
    let root = f.state.with_ready(|_, s| Ok(tree::root_id(s).to_string())).expect("root");
    let conn = tree::create_connection(
        &f.state,
        ConnectionFields {
            port: Some(u32::from(srv.port)),
            credential_id: Some(cred.id),
            ..ConnectionFields::basic(&root, "test server", "ssh", "127.0.0.1")
        },
    )
    .expect("connection");
    let mut kh = mooring_proto_ssh::KnownHosts::new();
    kh.add_hashed("127.0.0.1", srv.port, &srv.host_public).expect("add");
    kh.save(&f.state.known_hosts_path()).expect("save");
    let (tx, mut events) = mpsc::unbounded_channel();
    let sink: EventSink =
        Arc::new(move |e| tx.send(serde_json::to_value(&e).expect("json")).is_ok());
    let size = Size { width: 80, height: 24 };
    let opened = sess::open(&f.state, &conn.id, size, sink).await.expect("open");
    loop {
        let e = tokio::time::timeout(Duration::from_secs(20), events.recv())
            .await
            .expect("event within 20 s")
            .expect("channel open");
        if e["kind"] == "connected" {
            break;
        }
        assert_ne!(e["kind"], "closed", "{e}");
    }
    Live { f, session_id: opened.session_id, events }
}

/// Close the session and wait until the registry is empty.
pub async fn close(live: &Live) {
    sess::close(&live.f.state, &live.session_id).await.expect("close");
    for _ in 0..200 {
        if sess::list(&live.f.state).expect("list").is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("session did not leave the registry");
}

/// Raw audit log text.
pub fn audit_text(live: &Live) -> String {
    std::fs::read_to_string(live.f.dir.path().join(crate::state::AppState::AUDIT_FILE))
        .unwrap_or_default()
}
