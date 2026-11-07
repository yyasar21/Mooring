use super::*;
use mooring_core::session::{ConnectSecret, Size};

fn hop(index: u8, host: &str, port: u16) -> Hop {
    Hop {
        params: ConnectParams {
            host: host.into(),
            port,
            username: Some("u".into()),
            secret: ConnectSecret::None,
            r#become: None,
            size: Size { width: 80, height: 24 },
        },
        options: SshOptions::new("/nonexistent/known_hosts"),
        index,
        connection: "c".into(),
    }
}

#[tokio::test]
async fn shape_rules_are_checked_before_any_io() {
    let (ev, _rx) = HopEvents::new(8);
    let e = HopChain::open(vec![], ("h.example.test", 22), &ev).await.err();
    assert_eq!(e, Some(HopError::Invalid("no jump host")));
    let four = (0..4).map(|i| hop(i, "192.0.2.1", 22)).collect();
    let e = HopChain::open(four, ("h.example.test", 22), &ev).await.err();
    assert_eq!(e, Some(HopError::Invalid("at most 3 jump hosts")));
    let e = HopChain::open(vec![hop(1, "192.0.2.1", 22)], ("h", 22), &ev).await.err();
    assert_eq!(e, Some(HopError::Invalid("hop indices must be 0, 1, 2 in order")));
    let e = HopChain::open(vec![hop(0, "192.0.2.1", 22)], ("h", 0), &ev).await.err();
    assert_eq!(e, Some(HopError::Invalid("target host or port")));
    let e = HopChain::open(vec![hop(0, "bad host", 22)], ("h", 22), &ev).await.err();
    assert_eq!(e, Some(HopError::Invalid("hop host or port")));
    assert_eq!(HopError::Deadline.close_code(), CloseCode::HopFailed);
    assert_eq!(HopError::Cancelled.close_code(), CloseCode::User);
    assert!(HopError::Invalid("shape").reason().contains("shape"));
}

#[tokio::test]
async fn hop_zero_refused_reports_failed_status_and_network() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    let (ev, mut rx) = HopEvents::new(8);
    let e = HopChain::open(vec![hop(0, "127.0.0.1", port)], ("h", 22), &ev).await.err();
    let Some(HopError::Failed { hop: 0, code: CloseCode::Network, reason }) = e else {
        panic!("{e:?}");
    };
    assert!(reason.starts_with("connection failed"), "{reason}");
    let Some(SessionEvent::HopStatus { state: HopState::Connecting, of: 1, .. }) = rx.recv().await
    else {
        panic!("connecting first");
    };
    let Some(SessionEvent::HopStatus { state: HopState::Failed, hop: 0, .. }) = rx.recv().await
    else {
        panic!("then failed");
    };
    assert!(ev.audit.take().is_empty(), "no hop opened, nothing audited");
}
