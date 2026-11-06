use std::ffi::OsString;
use std::path::Path;

use super::*;

fn strs(v: &[OsString]) -> Vec<String> {
    v.iter().map(|s| s.to_string_lossy().into_owned()).collect()
}

fn t(s: &str) -> Target {
    Target::parse(s).expect("target")
}

#[test]
fn ping_argv_golden_per_os() {
    let ping = Tool::Ping { count: 4, wait_secs: 2 };
    let f = TraceFlavour::Traceroute;
    assert_eq!(
        strs(&argv(&ping, Some(&t("example.test")), Os::Linux, f)),
        ["-n", "-c", "4", "-W", "2", "--", "example.test"]
    );
    assert_eq!(
        strs(&argv(&ping, Some(&t("192.0.2.1")), Os::MacOs, f)),
        ["-n", "-c", "4", "-t", "8", "--", "192.0.2.1"]
    );
    assert_eq!(
        strs(&argv(&ping, Some(&t("example.test")), Os::Windows, f)),
        ["-n", "4", "-w", "2000", "example.test"]
    );
}

#[test]
fn ping_argv_clamps_count_and_wait() {
    let big = Tool::Ping { count: 200, wait_secs: 90 };
    let zero = Tool::Ping { count: 0, wait_secs: 0 };
    let f = TraceFlavour::Traceroute;
    assert_eq!(strs(&argv(&big, None, Os::Linux, f)), ["-n", "-c", "10", "-W", "5", "--"]);
    assert_eq!(strs(&argv(&zero, None, Os::Linux, f)), ["-n", "-c", "1", "-W", "1", "--"]);
    assert_eq!(strs(&argv(&big, None, Os::MacOs, f)), ["-n", "-c", "10", "-t", "50", "--"]);
    assert_eq!(strs(&argv(&big, None, Os::Windows, f)), ["-n", "10", "-w", "5000"]);
}

#[test]
fn traceroute_argv_golden_per_os_and_flavour() {
    let tr = Tool::Traceroute { max_hops: 20 };
    let host = t("example.test");
    assert_eq!(
        strs(&argv(&tr, Some(&host), Os::Linux, TraceFlavour::Traceroute)),
        ["-n", "-q", "1", "-w", "2", "-m", "20", "--", "example.test"]
    );
    assert_eq!(
        strs(&argv(&tr, Some(&host), Os::Linux, TraceFlavour::Tracepath)),
        ["-n", "-m", "20", "example.test"]
    );
    assert_eq!(
        strs(&argv(&tr, Some(&host), Os::MacOs, TraceFlavour::Traceroute)),
        ["-n", "-q", "1", "-w", "2", "-m", "20", "--", "example.test"]
    );
    assert_eq!(
        strs(&argv(&tr, Some(&host), Os::Windows, TraceFlavour::Traceroute)),
        ["-d", "-h", "20", "-w", "2000", "example.test"]
    );
    let many = Tool::Traceroute { max_hops: 255 };
    assert_eq!(
        strs(&argv(&many, None, Os::Linux, TraceFlavour::Traceroute)),
        ["-n", "-q", "1", "-w", "2", "-m", "30", "--"]
    );
    assert_eq!(
        strs(&argv(&Tool::Traceroute { max_hops: 0 }, None, Os::Windows, TraceFlavour::Traceroute)),
        ["-d", "-h", "1", "-w", "2000"]
    );
}

#[test]
fn wg_argv_only_read_only_subcommands() {
    let i = Iface::parse("wg0").expect("iface");
    let f = TraceFlavour::Traceroute;
    let a = |q: WgQuery| strs(&argv(&Tool::Wg(q), None, Os::Linux, f));
    assert_eq!(a(WgQuery::Interfaces), ["show", "interfaces"]);
    assert_eq!(a(WgQuery::Endpoints(i.clone())), ["show", "wg0", "endpoints"]);
    assert_eq!(a(WgQuery::LatestHandshakes(i.clone())), ["show", "wg0", "latest-handshakes"]);
    assert_eq!(a(WgQuery::Transfer(i.clone())), ["show", "wg0", "transfer"]);
    assert_eq!(a(WgQuery::ListenPort(i)), ["show", "wg0", "listen-port"]);
}

/// Exhaustive: every `WgQuery` variant names one of the five allowed subcommands, so `dump`,
/// `showconf`, `private-key`, `preshared-keys`, `set` and `syncconf` are unreachable.
#[test]
fn wg_query_cannot_express_key_subcommands() {
    const FORBIDDEN: &[&str] =
        &["dump", "showconf", "private-key", "preshared-keys", "set", "syncconf", "setconf"];
    let i = Iface::parse("wg0").expect("iface");
    let all = [
        WgQuery::Interfaces,
        WgQuery::Endpoints(i.clone()),
        WgQuery::LatestHandshakes(i.clone()),
        WgQuery::Transfer(i.clone()),
        WgQuery::ListenPort(i),
    ];
    for q in &all {
        // A new variant must be added here (the match is exhaustive).
        let last = match q {
            WgQuery::Interfaces => "interfaces",
            WgQuery::Endpoints(_) => "endpoints",
            WgQuery::LatestHandshakes(_) => "latest-handshakes",
            WgQuery::Transfer(_) => "transfer",
            WgQuery::ListenPort(_) => "listen-port",
        };
        let args = q.args();
        assert_eq!(args.last().copied(), Some(last));
        assert!(args.iter().all(|a| !FORBIDDEN.contains(a)));
    }
}

#[test]
fn iface_names_are_validated_before_argv() {
    let x15 = "x".repeat(15);
    let x16 = "x".repeat(16);
    for ok in ["wg0", "wg-home", "a.b_c=d+e", x15.as_str()] {
        assert!(Iface::parse(ok).is_ok(), "{ok}");
    }
    for bad in ["", "-wg0", "wg 0", "wg0\n", x16.as_str(), "wg/0", "ünï"] {
        assert!(Iface::parse(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn target_is_always_the_last_single_element() {
    let host = t("192.0.2.9");
    for os in [Os::Linux, Os::MacOs, Os::Windows] {
        for tool in [Tool::Ping { count: 1, wait_secs: 1 }, Tool::Traceroute { max_hops: 3 }] {
            let a = argv(&tool, Some(&host), os, TraceFlavour::Traceroute);
            assert_eq!(
                a.last().map(|s| s.to_string_lossy().into_owned()).as_deref(),
                Some("192.0.2.9")
            );
            assert!(a.iter().all(|s| !s.to_string_lossy().contains(' ')), "{a:?}");
        }
    }
}

#[test]
fn path_tables_are_absolute_and_fixed() {
    for os in [Os::Linux, Os::MacOs, Os::Windows] {
        let table = ToolPaths::for_os(os);
        assert_eq!(table.os(), os);
        for tool in [
            Tool::Ping { count: 1, wait_secs: 1 },
            Tool::Traceroute { max_hops: 1 },
            Tool::Wg(WgQuery::Interfaces),
        ] {
            for ipv6 in [false, true] {
                let c = table.candidates(&tool, ipv6);
                assert!(!c.is_empty(), "{os:?} {tool:?}");
                for p in c {
                    let s = p.to_string_lossy();
                    let absolute = s.starts_with('/') || s.as_bytes().get(1) == Some(&b':');
                    assert!(absolute, "{os:?}: {s}");
                }
            }
        }
        if os == Os::Linux {
            assert!(!table.tracepath_candidates().is_empty());
        }
    }
    let linux = ToolPaths::for_os(Os::Linux);
    assert_eq!(
        linux.candidates(&Tool::Ping { count: 1, wait_secs: 1 }, false)[0],
        Path::new("/usr/bin/ping")
    );
    let mac = ToolPaths::for_os(Os::MacOs);
    assert_eq!(
        mac.candidates(&Tool::Ping { count: 1, wait_secs: 1 }, true)[0],
        Path::new("/sbin/ping6")
    );
    let win = ToolPaths::for_os(Os::Windows);
    let ping = win.candidates(&Tool::Ping { count: 1, wait_secs: 1 }, false)[0]
        .to_string_lossy()
        .into_owned();
    assert!(ping.ends_with("PING.EXE") && ping.contains("System32"), "{ping}");
    let wg =
        win.candidates(&Tool::Wg(WgQuery::Interfaces), false)[0].to_string_lossy().into_owned();
    assert!(wg.ends_with("wg.exe") && wg.contains("WireGuard"), "{wg}");
}

#[test]
fn resolve_reports_missing_and_falls_back_to_tracepath() {
    let dir = tempfile::tempdir().expect("tmp");
    let shim = dir.path().join("shim");
    std::fs::write(&shim, b"#!/bin/sh\n").expect("write");
    let none = ToolPaths::custom(
        Os::Linux,
        vec![dir.path().join("nope")],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    assert_eq!(
        none.resolve(&Tool::Ping { count: 1, wait_secs: 1 }, false),
        Err(NetError::ToolMissing)
    );
    assert_eq!(none.available(), (false, None, false));
    let only_tracepath = ToolPaths::custom(
        Os::Linux,
        Vec::new(),
        vec![dir.path().join("nope")],
        vec![shim.clone()],
        Vec::new(),
    );
    assert_eq!(
        only_tracepath.resolve(&Tool::Traceroute { max_hops: 1 }, false),
        Ok((shim.clone(), TraceFlavour::Tracepath))
    );
    assert_eq!(only_tracepath.available(), (false, Some(TraceFlavour::Tracepath), false));
    // A directory is not a binary.
    let dir_only = ToolPaths::custom(
        Os::Linux,
        vec![dir.path().to_path_buf()],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    assert_eq!(
        dir_only.resolve(&Tool::Ping { count: 1, wait_secs: 1 }, false),
        Err(NetError::ToolMissing)
    );
}
