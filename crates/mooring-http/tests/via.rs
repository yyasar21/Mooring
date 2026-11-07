//! ADR-0025: `HttpConfig::via` hands every connection to the dialer (a jump-host chain in the
//! app); TLS, the pin and the host name are unchanged. A failing dialer is a connect error.

mod common;

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::*;
use mooring_core::transport::{DialFuture, Dialer, TcpDialer};
use mooring_http::{Headers, HttpClient, HttpError};

/// Counts dials and connects to `to` whatever host it is asked for (like a hop would).
#[derive(Debug)]
struct Relay {
    to: u16,
    dials: AtomicUsize,
    fail: bool,
}

impl Dialer for Relay {
    fn dial(self: Arc<Self>, host: &str, port: u16) -> DialFuture {
        self.dials.fetch_add(1, Ordering::SeqCst);
        let (host, to, fail) = (host.to_owned(), self.to, self.fail);
        Box::pin(async move {
            assert_eq!((host.as_str(), port), ("127.0.0.1", to), "the origin's own name and port");
            if fail {
                return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "hop refused"));
            }
            Arc::new(TcpDialer::new(Duration::from_secs(5))).dial("127.0.0.1", to).await
        })
    }

    fn kind(&self) -> &'static str {
        "via"
    }
}

#[tokio::test]
async fn requests_ride_the_dialer_with_tls_and_pins_unchanged() {
    let (s, der) = self_signed_server(ok_json()).await;
    pin(&s, &der);
    let relay = Arc::new(Relay { to: s.addr.port(), dials: AtomicUsize::new(0), fail: false });
    let cfg = s.config().via(relay.clone());
    let c = HttpClient::new(cfg).expect("client");
    c.get_json::<serde_json::Value>("/x", &Headers::new()).await.expect("through the dialer");
    assert!(relay.dials.load(Ordering::SeqCst) >= 1);

    let refused = Arc::new(Relay { to: s.addr.port(), dials: AtomicUsize::new(0), fail: true });
    let c = HttpClient::new(s.config().via(refused.clone())).expect("client");
    let err = c.get_json::<serde_json::Value>("/x", &Headers::new()).await.expect_err("refused");
    assert!(matches!(err, HttpError::Connect(io::ErrorKind::ConnectionRefused)), "{err:?}");
    // The client's bounded GET retry applies to the dialer like to TCP; it never loops.
    let n = refused.dials.load(Ordering::SeqCst);
    assert!((1..=3).contains(&n), "{n} dials");
}
