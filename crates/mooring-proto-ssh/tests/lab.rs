//! Read-only lab check (ADR-0004 test plan): connect to `MOORING_LAB_HOST`, run `uname -a`, close.
//!
//! Skipped by default. Run against an SSH server you control with:
//! `MOORING_LAB_HOST=<lab-host> MOORING_LAB_USER=<user> cargo test -p mooring-proto-ssh --test lab -- --ignored`
//! (`MOORING_LAB_PORT` defaults to 22; see `.env.example`). With `MOORING_LAB_HOST` unset the
//! test prints why and returns. Auth uses the ssh-agent; the host key must already be in
//! `MOORING_LAB_KNOWN_HOSTS` (default `~/.ssh/known_hosts`, read-only here: a TOFU prompt fails
//! the test). Real hosts never go in the repository.

use std::time::Duration;

use mooring_core::session::{
    ConnectParams, ConnectSecret, Session, SessionEvent, SessionInput, Size,
};
use mooring_proto_ssh::{SshOptions, SshSession};

#[tokio::test]
#[ignore = "needs a lab SSH server: set MOORING_LAB_HOST / MOORING_LAB_USER"]
async fn lab_host_uname() {
    let (Some(host), Some(user)) = (lab_var("MOORING_LAB_HOST"), lab_var("MOORING_LAB_USER"))
    else {
        // The skip reason must be visible in `--nocapture` output; this is a test, not app logging.
        #[allow(clippy::print_stderr)]
        {
            eprintln!("skipping lab test: MOORING_LAB_HOST and MOORING_LAB_USER must be set (see .env.example)");
        }
        return;
    };
    let port = lab_var("MOORING_LAB_PORT")
        .map_or(22, |p| p.parse::<u16>().expect("MOORING_LAB_PORT must be a port number"));
    let kh = std::env::var("MOORING_LAB_KNOWN_HOSTS")
        .unwrap_or_else(|_| format!("{}/.ssh/known_hosts", std::env::var("HOME").expect("HOME")));
    let params = ConnectParams {
        host,
        port,
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

fn lab_var(name: &str) -> Option<String> {
    std::env::var(name).ok().map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
}
