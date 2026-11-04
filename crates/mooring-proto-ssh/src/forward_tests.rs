//! Unit tests of the forward registry.

use super::*;

fn entry(registry: &ForwardRegistry, remote: Option<(&str, u32)>) -> Entry {
    let (cancel, rx) = watch::channel(false);
    let id = registry.next_id();
    let route = Route {
        target: SocketAddr::from(([127, 0, 0, 1], 9)),
        cancel: rx,
        limit: Arc::new(Semaphore::new(1)),
    };
    Entry {
        info: ForwardInfo {
            id,
            kind: ForwardKind::Remote,
            bind: "b".into(),
            port: 1,
            bind_host: "b".into(),
            target: "t".into(),
            target_addr: None,
            exposure: Exposure::Loopback,
            opened_at: SystemTime::UNIX_EPOCH,
            connections: 0,
        },
        cancel,
        task: None,
        limit: Arc::new(Semaphore::new(MAX_CONNECTIONS_PER_FORWARD)),
        remote: remote.map(|(a, p)| (a.to_owned(), p, route)),
    }
}

#[test]
fn ids_display_and_order() {
    let r = ForwardRegistry::default();
    let (a, b) = (r.next_id(), r.next_id());
    assert_eq!(a.to_string(), "fwd-1");
    assert!(a < b);
    assert_eq!(b.get(), 2);
    assert_eq!("fwd-2".parse::<ForwardId>().expect("parse"), b);
    for bad in [
        "",
        "fwd-",
        "fwd-x",
        "2",
        "fwd--1",
        "fwd-+1",
        "FWD-1",
        "fwd-1 ",
        "fwd-99999999999999999999",
    ] {
        assert!(bad.parse::<ForwardId>().is_err(), "{bad:?}");
    }
    assert_eq!(host_port("::1", 22), "[::1]:22");
    assert_eq!(host_port("h", 22), "h:22");
}

#[test]
fn routes_and_close_all() {
    let r = ForwardRegistry::default();
    let audit = AuditLog::default();
    r.insert(entry(&r, Some(("127.0.0.1", 4000))), &audit).expect("insert");
    r.insert(entry(&r, Some(("localhost", 4001))), &audit).expect("insert");
    assert!(r.route("127.0.0.1", 4000).is_some());
    assert!(r.route("0.0.0.0", 4001).is_some(), "unique port fallback");
    assert!(r.route("127.0.0.1", 4002).is_none());
    assert_eq!(r.list().len(), 2);
    r.close_all(&audit);
    r.close_all(&audit);
    assert!(r.list().is_empty());
    let actions: Vec<_> = audit.take().iter().map(TrustEvent::action).collect();
    assert_eq!(actions.iter().filter(|a| **a == "session.forward.close").count(), 2);
    assert!(matches!(r.insert(entry(&r, None), &audit), Err(MooringError::Closed)));
}

#[test]
fn caps_forward_count() {
    let r = ForwardRegistry::default();
    let audit = AuditLog::default();
    for _ in 0..MAX_FORWARDS {
        r.insert(entry(&r, None), &audit).expect("insert");
    }
    assert!(matches!(r.insert(entry(&r, None), &audit), Err(MooringError::Invalid { .. })));
}
