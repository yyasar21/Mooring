//! ADR-0020 §6: target resolution, vault gate, port check + rate limit, OS tools through the
//! `mooring-net` shell shims (Unix), process cap, permission refusal, audit rows.

use std::path::PathBuf;
use std::time::Duration;

use serde_json::json;

use super::*;
use crate::commands::{credentials, tree, vault};
use crate::state::testing::{audit_events, unlocked, Fixture};
use crate::test_secrets::audit_rows;

fn conn(f: &Fixture, protocol: &str, host: &str) -> String {
    let st = &f.state;
    let root = tree::list(st).expect("tree").folders[0].id.clone();
    let _ = credentials::create(st, credentials::NewCredential::password_for_tests("c"));
    tree::create_connection(st, tree::ConnectionFields::basic(&root, "n", protocol, host))
        .expect("connection")
        .id
}

fn host(h: &str, port: Option<i64>) -> TargetArg {
    TargetArg::Host { host: h.into(), port }
}

fn by_id(id: &str) -> TargetArg {
    TargetArg::Connection { connection_id: id.into() }
}

fn no_tools() -> NetRuntime {
    NetRuntime::with_paths(
        ToolPaths::custom(Os::Linux, vec![PathBuf::from("/nonexistent/ping")], Vec::new(), Vec::new(), Vec::new()),
        Duration::ZERO,
    )
}

#[test]
fn target_arg_deserialises_both_shapes() {
    let c: TargetArg = serde_json::from_value(json!({ "connectionId": "x" })).expect("conn");
    assert!(matches!(c, TargetArg::Connection { connection_id } if connection_id == "x"));
    let h: TargetArg = serde_json::from_value(json!({ "host": "h.example.test", "port": 22 })).expect("host");
    assert!(matches!(h, TargetArg::Host { host, port: Some(22) } if host == "h.example.test"));
    let h: TargetArg = serde_json::from_value(json!({ "host": "h" })).expect("host only");
    assert!(matches!(h, TargetArg::Host { port: None, .. }));
    assert!(serde_json::from_value::<TargetArg>(json!({ "port": 22 })).is_err());
}

#[test]
fn resolve_validates_hosts_and_connections() {
    let f = unlocked();
    let st = &f.state;
    let r = resolve(st, &host(" h.example.test ", Some(443))).expect("host");
    assert_eq!((r.target.as_str(), r.port), ("h.example.test", Some(443)));
    for bad in ["-c", "--help", "/etc/passwd", "a b", "fe80::1%eth0", "ünï.test", ""] {
        let e = resolve(st, &host(bad, None)).expect_err(bad);
        assert!(e.code == "net.invalid_host" || e.code == "input.invalid", "{bad}: {}", e.code);
        assert!(!e.message.contains(bad.trim()) || bad.is_empty(), "message echoes the host: {}", e.message);
    }
    assert_eq!(resolve(st, &host("h", Some(0))).expect_err("port 0").code, "input.invalid");
    assert_eq!(resolve(st, &host("h", Some(70000))).expect_err("port range").code, "input.invalid");

    let ssh = conn(&f, "ssh", "192.0.2.10");
    let r = resolve(st, &by_id(&ssh)).expect("ssh");
    assert_eq!((r.target.as_str(), r.port), ("192.0.2.10", Some(22)));
    let web = conn(&f, "web", "https://[2001:db8::7]:8443/app?x=1");
    let r = resolve(st, &by_id(&web)).expect("web");
    assert_eq!((r.target.as_str(), r.port), ("2001:db8::7", Some(8443)));
    let web_default = conn(&f, "web", "https://portal.example.test/");
    assert_eq!(resolve(st, &by_id(&web_default)).expect("web").port, Some(443));
    let kube = conn(&f, "kubernetes", "ctx");
    assert_eq!(resolve(st, &by_id(&kube)).expect_err("kube").code, "net.invalid_host");
    assert_eq!(resolve(st, &by_id("not-a-uuid")).expect_err("id").code, "input.invalid");
    let missing = mooring_core::ConnectionId::new().to_string();
    assert_eq!(resolve(st, &by_id(&missing)).expect_err("missing").code, "tree.not_found");
}

#[tokio::test]
async fn every_command_is_vault_gated() {
    let f = unlocked();
    let st = &f.state;
    let id = conn(&f, "ssh", "192.0.2.10");
    vault::lock(st, None).expect("lock");
    let rt = no_tools();
    assert_eq!(tools(st, &rt).expect_err("tools").code, "vault.locked");
    assert_eq!(resolve(st, &host("h", None)).expect_err("host").code, "vault.locked");
    assert_eq!(port_check(st, &rt, &by_id(&id), None).await.expect_err("tcp").code, "vault.locked");
    assert_eq!(ping(st, &rt, &host("h", None), None).await.expect_err("ping").code, "vault.locked");
    assert_eq!(traceroute(st, &rt, &host("h", None), None).await.expect_err("trace").code, "vault.locked");
    assert_eq!(wg_show(st, &rt).await.expect_err("wg").code, "vault.locked");
    assert!(audit_rows(st, "net_tcp_check").is_empty());
}

#[tokio::test]
async fn port_check_against_loopback_audits_and_rate_limits() {
    let f = unlocked();
    let st = &f.state;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = i64::from(listener.local_addr().expect("addr").port());
    let rt = NetRuntime::with_paths(ToolPaths::for_os(Os::Linux), Duration::from_secs(30));
    let r = port_check(st, &rt, &host("127.0.0.1", Some(port)), Some(2000)).await.expect("check");
    assert!(matches!(r, TcpResult::Open { .. }), "{r:?}");
    let rows = audit_rows(st, "net_tcp_check");
    assert_eq!(rows.len(), 1);
    assert_eq!((rows[0]["host"].clone(), rows[0]["port"].clone(), rows[0]["outcome"].clone()), (json!("127.0.0.1"), json!(port), json!("open")));
    // Second check within the interval: refused before any connect, no audit row.
    let e = port_check(st, &rt, &host("127.0.0.1", Some(port)), None).await.expect_err("rate");
    assert_eq!(e.code, "net.rate_limited");
    assert_eq!(audit_rows(st, "net_tcp_check").len(), 1);
    // A port is required and validated; a bad timeout is refused.
    let fast = NetRuntime::with_paths(ToolPaths::for_os(Os::Linux), Duration::ZERO);
    assert_eq!(port_check(st, &fast, &host("127.0.0.1", None), None).await.expect_err("port").code, "input.invalid");
    assert_eq!(port_check(st, &fast, &host("127.0.0.1", Some(port)), Some(-1)).await.expect_err("timeout").code, "input.invalid");
    // The connection form uses the connection's port.
    let dropped = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let closed_port = dropped.local_addr().expect("addr").port();
    drop(dropped);
    let st2 = &f.state;
    let root = tree::list(st2).expect("tree").folders[0].id.clone();
    let mut fields = tree::ConnectionFields::basic(&root, "loop", "ssh", "127.0.0.1");
    fields.port = Some(u32::from(closed_port));
    let id = tree::create_connection(st2, fields).expect("conn").id;
    let r = port_check(st2, &fast, &by_id(&id), None).await.expect("check");
    assert_eq!(r, TcpResult::Closed);
}

/// Review 7 N-52: `net_*` rows are bounded like `confirm_refused` (N-47): 32 per hour of
/// uptime, then one `net_suppressed { count }` row when the next hour starts.
#[tokio::test]
async fn net_audit_rows_are_bounded_per_hour_of_uptime() {
    let f = unlocked();
    let st = &f.state;
    let rt = NetRuntime::with_paths(ToolPaths::for_os(Os::Linux), Duration::ZERO);
    let t0 = Instant::now();
    let row = || AuditEvent::NetTcpCheck { host: "127.0.0.1".into(), port: 22, outcome: "closed".into() };
    for _ in 0..100 {
        rt.audit_at(st, row(), t0 + Duration::from_secs(1));
    }
    assert_eq!(audit_rows(st, "net_tcp_check").len(), 32);
    assert!(audit_rows(st, "net_suppressed").is_empty(), "still the same hour: counted only");
    // The next hour: one summary for the 68 counted runs, then a fresh budget.
    rt.audit_at(st, row(), t0 + crate::audit_budget::WINDOW);
    let summary = audit_rows(st, "net_suppressed");
    assert_eq!(summary.len(), 1);
    assert_eq!(summary[0]["count"], json!(68));
    assert_eq!(audit_rows(st, "net_tcp_check").len(), 33);
    // The budget is shared by every net_* row of the process.
    rt.audit_at(st, AuditEvent::NetWgStatus { interfaces: vec![] }, t0 + crate::audit_budget::WINDOW);
    assert_eq!(audit_rows(st, "net_wg_status").len(), 1);
    // A real port check goes through the same budget.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = i64::from(listener.local_addr().expect("addr").port());
    port_check(st, &rt, &host("127.0.0.1", Some(port)), Some(2000)).await.expect("check");
    assert_eq!(audit_rows(st, "net_tcp_check").len(), 34);
    let text = std::fs::read_to_string(st.data_dir.join(AppState::AUDIT_FILE)).expect("audit");
    assert_eq!(text.matches("\"event\":\"net_").count(), 36, "32 + 1 + 1 + 1 rows, 1 summary");
}

#[tokio::test]
async fn missing_tools_are_reported_not_searched() {
    let f = unlocked();
    let st = &f.state;
    let rt = no_tools();
    let t = tools(st, &rt).expect("tools");
    assert!(!t.ping && t.traceroute.is_none() && !t.wg);
    assert_eq!(ping(st, &rt, &host("192.0.2.1", None), None).await.expect_err("ping").code, "net.tool_missing");
    assert_eq!(traceroute(st, &rt, &host("192.0.2.1", None), None).await.expect_err("trace").code, "net.tool_missing");
    assert_eq!(wg_show(st, &rt).await.expect_err("wg").code, "net.tool_missing");
    assert_eq!(ping(st, &rt, &host("192.0.2.1", None), Some(0)).await.expect_err("count").code, "input.invalid");
    assert_eq!(ping(st, &rt, &host("192.0.2.1", None), Some(11)).await.expect_err("count").code, "input.invalid");
    assert_eq!(traceroute(st, &rt, &host("192.0.2.1", None), Some(31)).await.expect_err("hops").code, "input.invalid");
    assert!(audit_events(st).iter().all(|e| !e.starts_with("net_")));
}

#[cfg(unix)]
mod shims {
    use super::*;
    use std::path::Path;

    fn shim_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/mooring-net/tests/shims")
    }

    /// Executable copies of the shims (git may not keep the mode bit).
    /// Copied once per test process (see `mooring-net/tests/shim_runner.rs`: a concurrent copy
    /// plus a fork in another test thread makes `execve` fail with `ETXTBSY` on Linux).
    fn install() -> &'static Path {
        static DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
        DIR.get_or_init(|| {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().expect("tmp");
            for name in ["ping.sh", "traceroute.sh", "tracepath.sh", "wg.sh", "slow.sh"] {
                let to = dir.path().join(name);
                std::fs::copy(shim_dir().join(name), &to).expect("copy");
                std::fs::set_permissions(&to, std::fs::Permissions::from_mode(0o755))
                    .expect("chmod");
            }
            dir
        })
        .path()
    }

    fn runtime(dir: &Path, ping: &str) -> NetRuntime {
        NetRuntime::with_paths(
            ToolPaths::custom(
                Os::Linux,
                vec![dir.join(ping)],
                vec![dir.join("traceroute.sh")],
                vec![dir.join("tracepath.sh")],
                vec![dir.join("wg.sh")],
            ),
            Duration::ZERO,
        )
    }

    #[tokio::test]
    async fn ping_and_traceroute_run_and_audit_names_only() {
        let f = unlocked();
        let st = &f.state;
        let dir = install();
        let rt = runtime(dir, "ping.sh");
        let t = tools(st, &rt).expect("tools");
        assert!(t.ping && t.traceroute == Some("traceroute") && t.wg);
        let id = conn(&f, "rdp", "192.0.2.1");
        let run = ping(st, &rt, &by_id(&id), Some(3)).await.expect("ping");
        assert_eq!((run.result.sent, run.result.received), (4, 3));
        assert_eq!(run.exit_code, Some(1));
        let rows = audit_rows(st, "net_ping");
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0]["host"].clone(), rows[0]["sent"].clone(), rows[0]["received"].clone()), (json!("192.0.2.1"), json!(4), json!(3)));
        assert!(rows[0].get("lines").is_none(), "tool output never reaches the audit log");
        let argv = std::fs::read_to_string(dir.join("ping.sh.argv")).expect("argv");
        assert_eq!(argv.lines().collect::<Vec<_>>(), ["-n", "-c", "3", "-W", "2", "--", "192.0.2.1"]);

        let run = traceroute(st, &rt, &host("192.0.2.1", None), Some(7)).await.expect("trace");
        assert_eq!(run.tool, "traceroute");
        assert_eq!(run.result.hops.len(), 3);
        let rows = audit_rows(st, "net_traceroute");
        assert_eq!((rows.len(), rows[0]["hops"].clone()), (1, json!(3)));
        let wire = serde_json::to_value(&run).expect("json");
        assert!(wire["result"]["hops"][0]["rttsMs"].is_array());
    }

    #[tokio::test]
    async fn wg_show_without_rights_is_permission_denied_and_not_retried() {
        let f = unlocked();
        let st = &f.state;
        let dir = install();
        let rt = runtime(dir, "ping.sh");
        let e = wg_show(st, &rt).await.expect_err("wg");
        assert_eq!(e.code, "net.permission_denied");
        assert!(e.message.contains("does not elevate"), "{}", e.message);
        let argv = std::fs::read_to_string(dir.join("wg.sh.argv")).expect("argv");
        for forbidden in ["dump", "showconf", "private-key", "preshared-keys", "sudo", "pkexec"] {
            assert!(!argv.contains(forbidden), "{argv}");
        }
        assert!(audit_rows(st, "net_wg_status").is_empty(), "no row for a refused status");
    }

    #[tokio::test]
    async fn at_most_two_tool_processes_run_at_once() {
        let f = unlocked();
        let st = &f.state;
        let dir = install();
        let rt = runtime(dir, "slow.sh");
        let target = host("192.0.2.1", None);
        let slow = |_: u8| tokio::time::timeout(Duration::from_secs(2), ping(st, &rt, &target, None));
        let probe = async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            let third = ping(st, &rt, &target, None).await.expect_err("busy");
            let wg = wg_show(st, &rt).await.expect_err("busy");
            (third.code, wg.code)
        };
        let (a, b, codes) = tokio::join!(slow(1), slow(2), probe);
        assert!(a.is_err() && b.is_err(), "the two slow runs were still in flight");
        assert_eq!(codes, ("net.busy", "net.busy"));
        // Permits are released with the dropped runs: a later call is accepted again.
        let rt2 = runtime(dir, "ping.sh");
        assert!(ping(st, &rt2, &target, None).await.is_ok());
        assert_eq!(rt.permit().map(|_| ()).expect("permit free"), ());
    }
}
