//! Read-only lab check (ADR-0004 test plan): connect to xinfra01, run `uname -a`, close.
//!
//! Skipped by default. Run on a machine in the home lab with:
//! `MOORING_LAB=1 MOORING_LAB_USER=<user> cargo test -p mooring-proto-ssh --test lab -- --ignored`
//! Auth uses the ssh-agent; the host key must already be in `MOORING_LAB_KNOWN_HOSTS`
//! (default `~/.ssh/known_hosts`, read-only here: a TOFU prompt fails the test).

use std::time::Duration;

use mooring_core::session::{
    ConnectParams, ConnectSecret, Session, SessionEvent, SessionInput, Size,
};
use mooring_proto_ssh::{SshOptions, SshSession};

#[tokio::test]
#[ignore = "needs the home lab: MOORING_LAB=1"]
async fn xinfra01_uname() {
    if std::env::var("MOORING_LAB").as_deref() != Ok("1") {
        return;
    }
    let user = std::env::var("MOORING_LAB_USER").expect("MOORING_LAB_USER");
    let kh = std::env::var("MOORING_LAB_KNOWN_HOSTS")
        .unwrap_or_else(|_| format!("{}/.ssh/known_hosts", std::env::var("HOME").expect("HOME")));
    let params = ConnectParams {
        host: "xinfra01.homelab.xyz".into(),
        port: 22,
        username: Some(user),
        secret: ConnectSecret::None,
        size: Size { width: 120, height: 40 },
    };
    let mut s = SshSession::connect(params, SshOptions::new(kh)).await.expect("tcp");
    let step = Duration::from_secs(30);
    loop {
        match tokio::time::timeout(step, s.next_event()).await {
            Ok(Ok(Some(SessionEvent::Connected { .. }))) => break,
            Ok(Ok(Some(SessionEvent::Prompt { message, .. }))) => {
                panic!("unexpected prompt (host key not pre-trusted?): {message}")
            }
            Ok(Ok(Some(SessionEvent::Closed { reason }))) => panic!("closed: {reason}"),
            Ok(Ok(Some(_))) => {}
            other => panic!("no Connected: {other:?}"),
        }
    }
    s.send(SessionInput::Bytes { data: b"uname -a\r".to_vec() }).await.expect("send");
    let mut out = String::new();
    while !out.contains("Linux") {
        match tokio::time::timeout(step, s.next_event()).await {
            Ok(Ok(Some(SessionEvent::Bytes { data }))) => {
                out.push_str(&String::from_utf8_lossy(&data));
            }
            other => panic!("no uname output: {other:?}"),
        }
    }
    s.close().await.expect("close");
}
