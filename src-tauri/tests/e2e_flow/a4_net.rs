//! A4 Q1 (ADR-0020 test plan): the network tools through the `net_*` commands with the shell
//! shims of `crates/mooring-net/tests/shims/` injected through `ToolPaths::custom` (never
//! `PATH`): a flooding tool is cut at the output cap, a hanging one holds a process slot until
//! the deadline so the third caller sees `net.busy`, missing binaries are reported by
//! `net_tools` and refused by code, `wg` is hidden when absent, the port check is rate
//! limited and resolves a stored connection. Every row of the audit log carries host names
//! and counts only, never tool output. Unix only (the shims are `sh`).

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use mooring_net::{Os, TcpResult, ToolPaths};

use crate::a4_support::{assert_audit_free_of, audit_rows};
use crate::commands::net::{self, NetRuntime, TargetArg};
use crate::commands::tree::{self, ConnectionFields};
use crate::state::testing::{self, Fixture};

fn shim_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/mooring-net/tests/shims")
}

/// Executable copies of the shims (git may not keep the mode bit).
fn install() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tmp");
    for name in ["ping.sh", "traceroute.sh", "tracepath.sh", "wg.sh", "slow.sh", "flood.sh"] {
        let to = dir.path().join(name);
        std::fs::copy(shim_dir().join(name), &to).expect("copy");
        std::fs::set_permissions(&to, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }
    dir
}

fn runtime(dir: &Path, ping: &str, wg: Option<&str>) -> NetRuntime {
    NetRuntime::with_paths(
        ToolPaths::custom(
            Os::Linux,
            vec![dir.join("missing-ping"), dir.join(ping)],
            vec![dir.join("traceroute.sh")],
            vec![dir.join("tracepath.sh")],
            wg.map(|w| vec![dir.join(w)]).unwrap_or_default(),
        ),
        Duration::from_millis(300),
    )
}

fn host(h: &str, port: Option<i64>) -> TargetArg {
    TargetArg::Host { host: h.into(), port }
}

fn connection(f: &Fixture, protocol: &str, host: &str, port: u32) -> String {
    let root = tree::list(&f.state).expect("tree").folders[0].id.clone();
    let fields = ConnectionFields {
        port: Some(port),
        ..ConnectionFields::basic(&root, "probe target", protocol, host)
    };
    tree::create_connection(&f.state, fields).expect("connection").id
}

#[tokio::test]
async fn flooding_tool_is_cut_at_the_cap_and_audited_by_counts_only() {
    let f = testing::unlocked();
    let st = &f.state;
    let dir = install();
    let rt = runtime(dir.path(), "flood.sh", Some("wg.sh"));
    let started = std::time::Instant::now();
    let run = net::ping(st, &rt, &host("192.0.2.1", None), Some(4)).await.expect("ping");
    assert!(run.truncated, "the 64 KiB cap must cut the flood");
    assert!(!run.timed_out);
    assert!(started.elapsed() < Duration::from_secs(20), "killed at the cap, not at the deadline");
    assert_eq!(run.result.lines.len(), mooring_net::sanitize::MAX_LINES);
    assert!(run.result.lines.iter().all(|l| l.len() <= 512 && l.chars().all(|c| !c.is_control())));
    assert!(run.result.received <= run.result.sent.max(run.result.received));
    let rows = audit_rows(st, "net_ping");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["host"], "192.0.2.1");
    assert!(rows[0].get("lines").is_none() && rows[0].get("result").is_none(), "{:?}", rows[0]);
    assert_audit_free_of(st, &["icmp_seq", "bytes from"]);
}

#[tokio::test]
async fn two_hanging_tools_fill_the_slots_and_the_third_caller_is_busy() {
    let f = testing::unlocked();
    let st = &f.state;
    let dir = install();
    let rt = runtime(dir.path(), "slow.sh", Some("wg.sh"));
    let target = host("192.0.2.1", None);
    let slow =
        |_: u8| tokio::time::timeout(Duration::from_secs(2), net::ping(st, &rt, &target, None));
    let probe = async {
        tokio::time::sleep(Duration::from_millis(400)).await;
        let ping = net::ping(st, &rt, &target, None).await.expect_err("busy");
        let trace = net::traceroute(st, &rt, &target, None).await.expect_err("busy");
        let wg = net::wg_show(st, &rt).await.expect_err("busy");
        // The port check does not take a tool slot: it is a socket, not a process.
        let port = net::port_check(st, &rt, &host("127.0.0.1", Some(9)), Some(300)).await;
        (ping.code, trace.code, wg.code, port.is_ok())
    };
    let (a, b, codes) = tokio::join!(slow(1), slow(2), probe);
    assert!(a.is_err() && b.is_err(), "both slow runs were still in flight");
    assert_eq!(codes, ("net.busy", "net.busy", "net.busy", true));
    assert!(audit_rows(st, "net_ping").is_empty(), "a refused run writes no row");
    assert_eq!(audit_rows(st, "net_tcp_check").len(), 1);
}

#[tokio::test]
async fn missing_binaries_are_reported_not_searched_and_wg_is_hidden() {
    let f = testing::unlocked();
    let st = &f.state;
    let dir = install();
    // No wg at any fixed path: the tool table says so and the card hides the section.
    let rt = runtime(dir.path(), "ping.sh", None);
    let t = net::tools(st, &rt).expect("tools");
    assert!(t.ping && t.traceroute == Some("traceroute") && !t.wg);
    assert_eq!(net::wg_show(st, &rt).await.expect_err("wg").code, "net.tool_missing");
    // Nothing at all: every tool is absent, every command refuses by code before spawning.
    let none = NetRuntime::with_paths(
        ToolPaths::custom(Os::Linux, vec![dir.path().join("nope")], vec![], vec![], vec![]),
        Duration::ZERO,
    );
    let t = net::tools(st, &none).expect("tools");
    assert!(!t.ping && t.traceroute.is_none() && !t.wg);
    for (name, code) in [
        ("ping", net::ping(st, &none, &host("192.0.2.1", None), None).await.err().map(|e| e.code)),
        (
            "traceroute",
            net::traceroute(st, &none, &host("192.0.2.1", None), None).await.err().map(|e| e.code),
        ),
        ("wg", net::wg_show(st, &none).await.err().map(|e| e.code)),
    ] {
        assert_eq!(code, Some("net.tool_missing"), "{name}");
    }
    // `PATH` is never consulted: a `ping` on PATH (if any) does not make the tool appear.
    assert!(!net::tools(st, &none).expect("tools").ping);
    // tracepath is the fallback when traceroute is absent.
    let fallback = NetRuntime::with_paths(
        ToolPaths::custom(
            Os::Linux,
            vec![dir.path().join("ping.sh")],
            vec![dir.path().join("no-traceroute")],
            vec![dir.path().join("tracepath.sh")],
            vec![],
        ),
        Duration::ZERO,
    );
    assert_eq!(net::tools(st, &fallback).expect("tools").traceroute, Some("tracepath"));
    let run =
        net::traceroute(st, &fallback, &host("192.0.2.1", None), Some(5)).await.expect("tracepath");
    assert_eq!(run.tool, "tracepath");
    assert!(run.result.reached);
    assert!(audit_rows(st, "net_ping").is_empty() && audit_rows(st, "net_wg_status").is_empty());
    assert_eq!(audit_rows(st, "net_traceroute").len(), 1);
}

#[tokio::test]
async fn port_check_resolves_a_connection_is_rate_limited_and_never_opens_kube_or_vsphere() {
    let f = testing::unlocked();
    let st = &f.state;
    let dir = install();
    let rt = runtime(dir.path(), "ping.sh", Some("wg.sh"));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
    let port = listener.local_addr().expect("addr").port();
    let ssh = connection(&f, "ssh", "127.0.0.1", u32::from(port));
    let open =
        net::port_check(st, &rt, &TargetArg::Connection { connection_id: ssh.clone() }, None)
            .await
            .expect("open");
    assert!(
        matches!(&open, TcpResult::Open { addr, .. } if *addr == format!("127.0.0.1:{port}")),
        "{open:?}"
    );
    // One per interval: the second call inside 300 ms is rate limited, after it accepted.
    let again = net::port_check(st, &rt, &host("127.0.0.1", Some(i64::from(port))), None)
        .await
        .expect_err("rate");
    assert_eq!(again.code, "net.rate_limited");
    tokio::time::sleep(Duration::from_millis(350)).await;
    drop(listener);
    let closed = net::port_check(st, &rt, &host("127.0.0.1", Some(i64::from(port))), None)
        .await
        .expect("closed");
    assert_eq!(closed, TcpResult::Closed);
    // Kubernetes and vSphere rows have no probe host.
    tokio::time::sleep(Duration::from_millis(350)).await;
    let kube = connection(&f, "kubernetes", "kube.example.test", 6443);
    let e = net::port_check(st, &rt, &TargetArg::Connection { connection_id: kube }, None)
        .await
        .expect_err("kube");
    assert_eq!(e.code, "net.invalid_host");
    // A port is required, and a shell-shaped host never reaches a tool.
    let e =
        net::port_check(st, &rt, &host("h.example.test", None), None).await.expect_err("no port");
    assert_eq!(e.code, "input.invalid");
    for bad in
        ["-c", "--", "h;id", "h`id`", "$(id)", "h example.test", "fe80::1%eth0", "/etc/passwd"]
    {
        let e = net::ping(st, &rt, &host(bad, None), Some(1)).await.expect_err(bad);
        assert!(matches!(e.code, "net.invalid_host" | "input.invalid"), "{bad}: {}", e.code);
        assert!(!e.message.contains(bad), "{bad}: the message echoes the input");
    }
    assert!(!dir.path().join("ping.sh.argv").exists(), "no shim ran for a refused host");
    let rows = audit_rows(st, "net_tcp_check");
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(
        (rows[0]["outcome"].as_str(), rows[1]["outcome"].as_str()),
        (Some("open"), Some("closed"))
    );
    assert_audit_free_of(st, &["id)", "passwd", "eth0"]);
}
