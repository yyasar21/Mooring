//! ADR-0020 §3–4 integration against the shell shims in `tests/shims/` (copied into a temp
//! dir, never on `PATH`): argv golden, cleared environment, exit code as data, deadline kill,
//! output cap, `wg` allow-list and permission refusal. Unix only (the shims are `sh`); on
//! Windows the path table is shape-tested in the crate.

#![cfg(unix)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use mooring_net::run::run_tool;
use mooring_net::{NetError, Os, Runner, Target, ToolPaths, TraceFlavour, WgQuery};

struct Shims {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Shims {
    fn install() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tmp");
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/shims");
        for name in ["ping.sh", "traceroute.sh", "tracepath.sh", "wg.sh", "slow.sh", "flood.sh"] {
            let to = dir.path().join(name);
            std::fs::copy(src.join(name), &to).expect("copy shim");
            std::fs::set_permissions(&to, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }
        Self { root: dir.path().to_path_buf(), _dir: dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn argv_of(&self, name: &str) -> Vec<String> {
        let text =
            std::fs::read_to_string(self.root.join(format!("{name}.argv"))).expect("argv file");
        text.lines().map(str::to_owned).collect()
    }

    fn runner(&self) -> Runner {
        Runner::new(ToolPaths::custom(
            Os::Linux,
            vec![self.path("missing-ping"), self.path("ping.sh")],
            vec![self.path("traceroute.sh")],
            vec![self.path("tracepath.sh")],
            vec![self.path("wg.sh")],
        ))
    }
}

fn t(s: &str) -> Target {
    Target::parse(s).expect("target")
}

#[tokio::test]
async fn ping_runs_the_shim_with_fixed_argv_and_a_clean_environment() {
    let shims = Shims::install();
    let run = shims.runner().ping(&t("192.0.2.1"), 4).await.expect("ping");
    assert_eq!(shims.argv_of("ping.sh"), ["-n", "-c", "4", "-W", "2", "--", "192.0.2.1"]);
    assert_eq!((run.result.sent, run.result.received), (4, 3));
    assert_eq!(run.exit_code, Some(1), "loss exit code is data");
    assert!(!run.timed_out && !run.truncated);
    // stderr is kept in the plain lines (ICMP errors land there on some tools).
    let env_line = run.result.lines.iter().find(|l| l.starts_with("LC_ALL=")).expect("env line");
    // (`PATH` is synthesised by `sh` itself when unset, so it is not asserted.)
    assert_eq!(env_line, "LC_ALL=C HOME=unset");
}

#[tokio::test]
async fn ping_count_is_clamped_and_target_is_last() {
    let shims = Shims::install();
    shims.runner().ping(&t("example.test"), 99).await.expect("ping");
    assert_eq!(shims.argv_of("ping.sh"), ["-n", "-c", "10", "-W", "2", "--", "example.test"]);
}

#[tokio::test]
async fn traceroute_prefers_traceroute_then_tracepath() {
    let shims = Shims::install();
    let run = shims.runner().traceroute(&t("192.0.2.1"), 12).await.expect("trace");
    assert_eq!(run.tool, "traceroute");
    assert_eq!(
        shims.argv_of("traceroute.sh"),
        ["-n", "-q", "1", "-w", "2", "-m", "12", "--", "192.0.2.1"]
    );
    assert_eq!(run.result.hops.len(), 3);
    assert!(run.result.reached);

    let only_tracepath = Runner::new(ToolPaths::custom(
        Os::Linux,
        vec![shims.path("ping.sh")],
        vec![shims.path("missing-traceroute")],
        vec![shims.path("tracepath.sh")],
        Vec::new(),
    ));
    let run = only_tracepath.traceroute(&t("192.0.2.1"), 5).await.expect("tracepath");
    assert_eq!(run.tool, "tracepath");
    assert_eq!(shims.argv_of("tracepath.sh"), ["-n", "-m", "5", "192.0.2.1"]);
    assert_eq!(run.result.hops.len(), 2);
    assert_eq!(run.result.hops[1].note.as_deref(), Some("reached"));
    assert_eq!(only_tracepath.tools().traceroute, Some("tracepath"));
    assert!(!only_tracepath.tools().wg);
}

#[tokio::test]
async fn missing_tool_is_tool_missing_not_a_path_lookup() {
    let shims = Shims::install();
    let none = Runner::new(ToolPaths::custom(
        Os::Linux,
        vec![shims.path("nope")],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    ));
    assert_eq!(none.ping(&t("192.0.2.1"), 1).await.err(), Some(NetError::ToolMissing));
    assert_eq!(none.traceroute(&t("192.0.2.1"), 1).await.err(), Some(NetError::ToolMissing));
    assert_eq!(none.wg_status().await.err(), Some(NetError::ToolMissing));
    let tools = none.tools();
    assert!(!tools.ping && tools.traceroute.is_none() && !tools.wg);
    let full = shims.runner().tools();
    assert!(full.ping && full.traceroute == Some("traceroute") && full.wg);
}

#[tokio::test]
async fn deadline_kills_a_hanging_tool_and_keeps_partial_output() {
    let shims = Shims::install();
    let started = std::time::Instant::now();
    let out = run_tool(&shims.path("slow.sh"), &[], Duration::from_millis(500)).await.expect("run");
    assert!(out.timed_out);
    assert!(out.exit_code.is_none());
    assert!(started.elapsed() < Duration::from_secs(10), "child was killed, not awaited");
    assert!(String::from_utf8_lossy(&out.stdout).contains("icmp_seq=1"), "partial output kept");
}

#[tokio::test]
async fn output_cap_cuts_a_flooding_tool() {
    let shims = Shims::install();
    let started = std::time::Instant::now();
    let out = run_tool(&shims.path("flood.sh"), &[], Duration::from_secs(20)).await.expect("run");
    assert!(out.truncated);
    assert!(!out.timed_out);
    assert_eq!(out.stdout.len(), mooring_net::sanitize::MAX_BYTES);
    assert!(started.elapsed() < Duration::from_secs(15), "killed once the cap was hit");
    let parsed = mooring_net::parse_ping(&out.stdout);
    assert_eq!(parsed.lines.len(), mooring_net::sanitize::MAX_LINES);
}

#[tokio::test]
async fn wg_status_runs_only_the_allowed_queries() {
    let shims = Shims::install();
    // The shim's `wg1` behaves like a non-root run: the whole status is refused.
    let err = shims.runner().wg_status().await.err();
    assert_eq!(err, Some(NetError::PermissionDenied));
    let argv = shims.argv_of("wg.sh");
    assert_eq!(&argv[..2], ["show", "interfaces"]);
    let joined = argv.join(" ");
    for forbidden in ["dump", "showconf", "private-key", "preshared-keys", "set", "syncconf"] {
        assert!(!joined.contains(forbidden), "{joined}");
    }
    // A single interface that answers merges into the status.
    let runner = shims.runner();
    let wg0 = mooring_net::Iface::parse("wg0").expect("iface");
    let port = runner.wg(&WgQuery::ListenPort(wg0.clone())).await.expect("port");
    let endpoints = runner.wg(&WgQuery::Endpoints(wg0.clone())).await.expect("endpoints");
    let hs = runner.wg(&WgQuery::LatestHandshakes(wg0.clone())).await.expect("handshakes");
    let tr = runner.wg(&WgQuery::Transfer(wg0.clone())).await.expect("transfer");
    let iface = mooring_net::wg::merge_interface(&wg0, &port, &endpoints, &hs, &tr);
    assert_eq!(iface.listen_port, Some(51820));
    assert_eq!(iface.peers.len(), 2);
    assert_eq!(iface.peers[0].endpoint.as_deref(), Some("192.0.2.7:51820"));
    assert_eq!(iface.peers[0].last_handshake_secs, Some(1_700_000_000));
    assert_eq!((iface.peers[0].rx_bytes, iface.peers[0].tx_bytes), (1024, 2048));
    assert!(
        iface.peers.iter().all(|p| !p.public_key.contains("AAAAAAAAAAAAAAAAAAAAAAAA")),
        "keys are shortened"
    );
}

#[test]
fn argv_golden_matches_the_shim_contract() {
    // The argv the shims assert is exactly what `tools::argv` produces for Linux.
    let a: Vec<OsString> = mooring_net::argv(
        &mooring_net::Tool::Ping { count: 4, wait_secs: 2 },
        Some(&t("192.0.2.1")),
        Os::Linux,
        TraceFlavour::Traceroute,
    );
    let a: Vec<String> = a.iter().map(|s| s.to_string_lossy().into_owned()).collect();
    assert_eq!(a, ["-n", "-c", "4", "-W", "2", "--", "192.0.2.1"]);
}
