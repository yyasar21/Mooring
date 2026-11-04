//! The Kubernetes client against QA's `mooring-testsrv::kube` mock (ADR-0014 §Test plan):
//! an oversized list body, a log stream far past `limitBytes`, forced 401 / 403, a
//! slow-loris response, and the read-only contract. Every test ends with
//! `assert_no_violations()`: the forbidden-call trap (`Secrets`, `ConfigMaps`, any write,
//! `dryRun`, exec over POST) never fires, and the bearer token never shows in a recorded
//! line (the recorder redacts it; the assertion is that nothing else carries it).

use std::time::Duration;

use mooring_http::{CertProtocol, HttpClient, HttpConfig};
use mooring_proto_kube::{AuditSink, KubeClient, KubeLimits, LogChunk, LogParams};
use mooring_testsrv::http::HttpKnobs;
use mooring_testsrv::kube::{self, KubeConfig, KubeKnobs, KubeServer};
use mooring_testsrv::tls::TestCert;
use secrecy::SecretString;

const TOKEN: &str = "test-token";

struct Mock {
    srv: KubeServer,
    dir: tempfile::TempDir,
    ca: String,
}

async fn start(knobs: KubeKnobs) -> Mock {
    let (cert, ca) = TestCert::generate_ca_issued(&["127.0.0.1"]).expect("cert");
    let config = KubeConfig { knobs, cert: Some(cert), ..KubeConfig::default() };
    let srv = kube::start(config, 0).await.expect("kube mock");
    Mock { srv, dir: tempfile::tempdir().expect("tempdir"), ca }
}

impl Mock {
    fn client(&self, max_log_bytes: u64) -> KubeClient {
        let known = self.dir.path().join(CertProtocol::Kube.file_name());
        let mut c = HttpConfig::new(CertProtocol::Kube, &self.srv.base_url(), known);
        c.extra_ca_pem = Some(self.ca.clone());
        c.ca_exclusive = true;
        c.use_system_roots = false;
        c.retry.base_delay = Duration::from_millis(1);
        c.retry.max_delay = Duration::from_millis(5);
        c.timeouts.request = Duration::from_millis(800);
        let http = HttpClient::new(c).expect("http");
        let limits = KubeLimits {
            max_log_bytes,
            log_tail_lines: 100,
            allowed_namespaces: vec![],
            port_forward_enabled: true,
        };
        KubeClient::with_http(
            &http,
            &self.srv.base_url(),
            Some(SecretString::from(TOKEN.to_owned())),
            limits,
            Some("default".into()),
            AuditSink::default(),
        )
        .expect("client")
    }

    fn read_only(&self) {
        self.srv.recorder().assert_no_violations();
        for line in self.srv.recorder().lines() {
            assert!(!line.contains(TOKEN), "token in a recorded line: {line}");
        }
        assert_eq!(
            self.srv.recorder().count("POST", "/api/"),
            0,
            "{:?}",
            self.srv.recorder().lines()
        );
        assert_eq!(self.srv.recorder().count("DELETE", "/"), 0);
        assert_eq!(self.srv.recorder().count("PUT", "/"), 0);
        assert_eq!(self.srv.recorder().count("PATCH", "/"), 0);
    }
}

/// The baseline: version, namespaces and the default pods list come back over GETs only.
#[tokio::test]
async fn baseline_reads_are_gets_only() {
    let m = start(KubeKnobs::default()).await;
    let c = m.client(1 << 20);
    assert!(c.version().await.expect("version").starts_with('v'));
    let ns = c.namespaces().await.expect("namespaces");
    assert!(ns.items.contains(&"default".to_owned()) && !ns.truncated);
    let pods = c.pods("default", None).await.expect("pods");
    assert!(pods.items.iter().any(|p| p.name == "web-0"), "{:?}", pods.items);
    let pods = c.pods("default", Some("app=web")).await.expect("selector");
    assert!(pods.items.len() <= 2);
    m.read_only();
}

/// A list body padded past the 16 MiB JSON cap is refused as a transport size error, never
/// buffered whole; one padded to 15 MiB is parsed.
#[tokio::test]
async fn an_oversized_list_body_is_refused() {
    let m = start(KubeKnobs { oversized_body: Some(16 * 1024 * 1024 + 1), ..KubeKnobs::default() })
        .await;
    let c = m.client(1 << 20);
    let e = c.pods("default", None).await.expect_err("16 MiB + 1");
    assert!(e.code().starts_with("http.") || e.code() == "kube.protocol", "{} {e}", e.code());
    assert!(!e.to_string().contains("web-0"), "{e}");
    m.srv.set_knobs(KubeKnobs { oversized_body: Some(15 * 1024 * 1024), ..KubeKnobs::default() });
    assert!(!c.pods("default", None).await.expect("15 MiB").items.is_empty());
    m.read_only();
}

/// A kubelet that ignores `limitBytes` and streams 4 MiB: the client stops at its own cap,
/// reports `truncated` with `kube.stream_limit`, and the delivered text is clean.
#[tokio::test]
async fn a_huge_log_stream_stops_at_the_cap() {
    let m = start(KubeKnobs { huge_log: Some(4 * 1024 * 1024), ..KubeKnobs::default() }).await;
    let cap = 64 * 1024;
    let c = m.client(cap);
    let params = LogParams { container: Some("app".into()), ..LogParams::default() };
    let mut s = c.logs("default", "web-0", params).await.expect("stream");
    let mut total = 0usize;
    let mut end = None;
    while let Some(chunk) = s.next().await.expect("chunk") {
        match chunk {
            LogChunk::Data(d) => {
                total += d.len();
                let text = String::from_utf8(d).expect("utf-8");
                assert!(!text.contains('\u{1b}') && !text.contains('\u{202e}'), "{text}");
            }
            LogChunk::End { truncated, reason } => end = Some((truncated, reason)),
        }
    }
    assert_eq!(end, Some((true, Some("kube.stream_limit"))));
    assert!(total <= usize::try_from(cap).expect("fits") + 4096, "{total}");
    m.read_only();
}

/// Forced 401 is `kube.auth_failed` and forced 403 is `kube.rbac_denied`; neither leaks the
/// server's message and neither triggers a retry with different credentials.
#[tokio::test]
async fn forced_401_and_403_map_to_codes() {
    let m = start(KubeKnobs { force_401: true, ..KubeKnobs::default() }).await;
    let c = m.client(1 << 20);
    assert_eq!(c.pods("default", None).await.expect_err("401").code(), "kube.auth_failed");
    m.read_only();
    let m = start(KubeKnobs { force_403: true, ..KubeKnobs::default() }).await;
    let c = m.client(1 << 20);
    assert_eq!(c.pods("default", None).await.expect_err("403").code(), "kube.rbac_denied");
    assert_eq!(c.namespaces().await.expect_err("403").code(), "kube.rbac_denied");
    m.read_only();
}

/// Hostile names and selectors never reach the wire: the guard refuses them locally.
#[tokio::test]
async fn hostile_names_never_reach_the_server() {
    let m = start(KubeKnobs::default()).await;
    let c = m.client(1 << 20);
    for ns in [
        "kube-system/../default",
        "Default",
        "a b",
        "",
        "ns\u{202e}",
        "%2e%2e",
        "x".repeat(64).as_str(),
    ] {
        assert!(c.pods(ns, None).await.is_err(), "{ns:?}");
    }
    for sel in ["app=web;rm", "a\u{0}b", "app=web&dryRun=All", "x".repeat(5000).as_str()] {
        assert!(c.pods("default", Some(sel)).await.is_err(), "{sel:?}");
    }
    assert!(m.srv.recorder().is_empty(), "{:?}", m.srv.recorder().lines());
    m.read_only();
}

/// A slow-loris server (one byte every 50 ms) should hit a body deadline instead of holding
/// the caller for as long as the body cap allows. Today only the response *head* has a
/// deadline on the kube tower path (`mooring_http::HttpService`); a 1.4 KB pod list dripped
/// at 50 ms/byte completes after ~70 s instead of failing. Decision needed (Q2 handoff,
/// QA-Q2-1): a body deadline for buffered JSON calls in `mooring-proto-kube` / `mooring-http`.
#[tokio::test]
#[ignore = "QA-Q2-1: no body deadline on the kube JSON path (docs/handoff/a3-qa-q2.md)"]
async fn slow_loris_times_out() {
    let m = start(KubeKnobs::default()).await;
    m.srv.set_http_knobs(HttpKnobs {
        drip: Some(Duration::from_millis(50)),
        ..HttpKnobs::default()
    });
    let c = m.client(1 << 20);
    let started = std::time::Instant::now();
    let e = c.pods("default", None).await.expect_err("drip");
    assert!(e.code().starts_with("http.") || e.code() == "kube.protocol", "{} {e}", e.code());
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
    m.read_only();
}
