//! The OS tools Mooring may run (ADR-0020 §3–4): fixed absolute paths, fixed argv, no shell.
//!
//! [`ToolPaths`] holds the candidate binaries per tool for one [`Os`]; the first one that
//! exists is used, there is no `PATH` lookup. Tests inject a shim through
//! [`ToolPaths::custom`]. [`argv`] builds the full command line; the only user-influenced
//! element is the [`Target`], which can never start with `-`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::error::NetError;
use crate::target::Target;

/// Which path and argv table applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    /// iputils `ping`, Dmitry Butskoy `traceroute` or iputils `tracepath`.
    Linux,
    /// BSD `ping` / `ping6`, `traceroute` / `traceroute6`.
    MacOs,
    /// `PING.EXE`, `TRACERT.EXE`, `wg.exe`.
    Windows,
}

impl Os {
    /// The build target's OS.
    #[must_use]
    pub fn current() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Linux
        }
    }
}

/// A `WireGuard` interface name as printed by `wg show interfaces`, validated
/// (`[A-Za-z0-9_=+.-]{1,15}`) before it is used in argv.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Iface(String);

impl Iface {
    /// Validate an interface name.
    pub fn parse(name: &str) -> Result<Self, NetError> {
        let ok = !name.is_empty()
            && name.len() <= 15
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"_=+.-".contains(&b))
            && !name.starts_with('-');
        if ok {
            Ok(Self(name.to_owned()))
        } else {
            Err(NetError::InvalidInterface)
        }
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The read-only `wg show` subcommands. `dump`, `showconf`, `private-key`, `preshared-keys`,
/// `set`, `syncconf` cannot be expressed: they print or change private material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WgQuery {
    /// `wg show interfaces`.
    Interfaces,
    /// `wg show <if> endpoints`.
    Endpoints(Iface),
    /// `wg show <if> latest-handshakes`.
    LatestHandshakes(Iface),
    /// `wg show <if> transfer`.
    Transfer(Iface),
    /// `wg show <if> listen-port`.
    ListenPort(Iface),
}

impl WgQuery {
    /// The `wg show` arguments after `show`.
    #[must_use]
    pub fn args(&self) -> Vec<&str> {
        match self {
            Self::Interfaces => vec!["interfaces"],
            Self::Endpoints(i) => vec![i.as_str(), "endpoints"],
            Self::LatestHandshakes(i) => vec![i.as_str(), "latest-handshakes"],
            Self::Transfer(i) => vec![i.as_str(), "transfer"],
            Self::ListenPort(i) => vec![i.as_str(), "listen-port"],
        }
    }
}

/// Echo requests per `ping` run, 1..=[`MAX_PING_COUNT`].
pub const MAX_PING_COUNT: u8 = 10;
/// Default `ping` count.
pub const DEFAULT_PING_COUNT: u8 = 4;
/// Longest per-reply wait for `ping`, in seconds (Linux `-W`, Windows `-w` × 1000).
pub const MAX_PING_WAIT_SECS: u8 = 5;
/// Most hops for `traceroute`, 1..=[`MAX_HOPS`].
pub const MAX_HOPS: u8 = 30;
/// Default `traceroute` hop limit.
pub const DEFAULT_HOPS: u8 = 20;
/// Per-hop wait for `traceroute`, in seconds (fixed).
pub const TRACE_WAIT_SECS: u8 = 2;

/// What to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tool {
    /// `ping` with `count` requests (clamped to 1..=10) and `wait_secs` per reply (1..=5).
    Ping {
        /// Echo requests.
        count: u8,
        /// Per-reply wait in seconds.
        wait_secs: u8,
    },
    /// `traceroute` / `tracepath` / `tracert` up to `max_hops` (clamped to 1..=30).
    Traceroute {
        /// Hop limit.
        max_hops: u8,
    },
    /// `wg show …`.
    Wg(WgQuery),
}

/// Which traceroute flavour a path table resolved to (`tracepath` has a different argv).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceFlavour {
    /// `traceroute` (Linux, macOS) or `TRACERT.EXE`.
    Traceroute,
    /// iputils `tracepath` (Linux fallback).
    Tracepath,
}

/// Candidate absolute paths per tool for one OS. Order is preference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolPaths {
    os: Os,
    ping: Vec<PathBuf>,
    ping6: Vec<PathBuf>,
    traceroute: Vec<PathBuf>,
    traceroute6: Vec<PathBuf>,
    tracepath: Vec<PathBuf>,
    wg: Vec<PathBuf>,
}

impl ToolPaths {
    /// The fixed table of ADR-0020 §3–4 for `os`. Windows paths use `%SystemRoot%` and
    /// `%ProgramFiles%` as given, falling back to the standard locations when unset.
    #[must_use]
    pub fn for_os(os: Os) -> Self {
        let p = |s: &[&str]| s.iter().map(PathBuf::from).collect::<Vec<_>>();
        match os {
            Os::Linux => Self {
                os,
                ping: p(&["/usr/bin/ping", "/bin/ping"]),
                ping6: p(&["/usr/bin/ping", "/bin/ping"]),
                traceroute: p(&["/usr/bin/traceroute", "/usr/sbin/traceroute"]),
                traceroute6: p(&["/usr/bin/traceroute", "/usr/sbin/traceroute"]),
                tracepath: p(&["/usr/bin/tracepath", "/usr/sbin/tracepath", "/bin/tracepath"]),
                wg: p(&["/usr/bin/wg", "/usr/local/bin/wg"]),
            },
            Os::MacOs => Self {
                os,
                ping: p(&["/sbin/ping"]),
                ping6: p(&["/sbin/ping6"]),
                traceroute: p(&["/usr/sbin/traceroute"]),
                traceroute6: p(&["/usr/sbin/traceroute6"]),
                tracepath: Vec::new(),
                wg: p(&["/usr/local/bin/wg", "/opt/homebrew/bin/wg"]),
            },
            Os::Windows => {
                let root = windows_env("SystemRoot", r"C:\Windows");
                let pf = windows_env("ProgramFiles", r"C:\Program Files");
                let sys32 = |exe: &str| vec![Path::new(&root).join("System32").join(exe)];
                Self {
                    os,
                    ping: sys32("PING.EXE"),
                    ping6: sys32("PING.EXE"),
                    traceroute: sys32("TRACERT.EXE"),
                    traceroute6: sys32("TRACERT.EXE"),
                    tracepath: Vec::new(),
                    wg: vec![Path::new(&pf).join("WireGuard").join("wg.exe")],
                }
            }
        }
    }

    /// A table pointing at test shims (never `PATH`). Every tool uses `ping` for IPv6 and
    /// `traceroute` for both flavours too; `tracepath` is only used when `traceroute` is empty.
    #[must_use]
    pub fn custom(
        os: Os,
        ping: Vec<PathBuf>,
        traceroute: Vec<PathBuf>,
        tracepath: Vec<PathBuf>,
        wg: Vec<PathBuf>,
    ) -> Self {
        Self {
            os,
            ping6: ping.clone(),
            ping,
            traceroute6: traceroute.clone(),
            traceroute,
            tracepath,
            wg,
        }
    }

    /// The OS of the table.
    #[must_use]
    pub fn os(&self) -> Os {
        self.os
    }

    /// The candidate paths (shape tests on macOS / Windows, where nothing is run).
    #[must_use]
    pub fn candidates(&self, tool: &Tool, ipv6: bool) -> Vec<&Path> {
        let list = match (tool, ipv6) {
            (Tool::Ping { .. }, false) => &self.ping,
            (Tool::Ping { .. }, true) => &self.ping6,
            (Tool::Traceroute { .. }, false) => &self.traceroute,
            (Tool::Traceroute { .. }, true) => &self.traceroute6,
            (Tool::Wg(_), _) => &self.wg,
        };
        list.iter().map(PathBuf::as_path).collect()
    }

    /// The `tracepath` candidates.
    #[must_use]
    pub fn tracepath_candidates(&self) -> Vec<&Path> {
        self.tracepath.iter().map(PathBuf::as_path).collect()
    }

    /// First existing binary for `tool`, with the traceroute flavour it resolved to.
    pub fn resolve(&self, tool: &Tool, ipv6: bool) -> Result<(PathBuf, TraceFlavour), NetError> {
        if let Some(p) = first_file(&self.candidates(tool, ipv6)) {
            return Ok((p, TraceFlavour::Traceroute));
        }
        if matches!(tool, Tool::Traceroute { .. }) {
            if let Some(p) = first_file(&self.tracepath_candidates()) {
                return Ok((p, TraceFlavour::Tracepath));
            }
        }
        Err(NetError::ToolMissing)
    }

    /// Which tools exist: `(ping, traceroute flavour, wg)`.
    #[must_use]
    pub fn available(&self) -> (bool, Option<TraceFlavour>, bool) {
        let ping = self.resolve(&Tool::Ping { count: 1, wait_secs: 1 }, false).is_ok();
        let trace = self.resolve(&Tool::Traceroute { max_hops: 1 }, false).ok().map(|(_, f)| f);
        let wg = self.resolve(&Tool::Wg(WgQuery::Interfaces), false).is_ok();
        (ping, trace, wg)
    }
}

fn first_file(candidates: &[&Path]) -> Option<PathBuf> {
    candidates.iter().find(|p| p.is_file()).map(|p| p.to_path_buf())
}

fn windows_env(name: &str, default: &str) -> String {
    std::env::var(name).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| default.to_owned())
}

/// The argv for `tool` against `target` on `os`, given the resolved `flavour`. The target is
/// always one element, last; `--` precedes it where the tool's parser accepts it.
#[must_use]
pub fn argv(tool: &Tool, target: Option<&Target>, os: Os, flavour: TraceFlavour) -> Vec<OsString> {
    let mut a: Vec<String> = Vec::new();
    match tool {
        Tool::Ping { count, wait_secs } => {
            let c = (*count).clamp(1, MAX_PING_COUNT);
            let n = c.to_string();
            let w = (*wait_secs).clamp(1, MAX_PING_WAIT_SECS);
            match os {
                Os::Linux => {
                    a.extend(["-n", "-c", &n, "-W", &w.to_string(), "--"].map(String::from));
                }
                Os::MacOs => {
                    // `-t` is the overall deadline on BSD ping: count × wait.
                    let deadline = (u32::from(w) * u32::from(c)).to_string();
                    a.extend(["-n", "-c", &n, "-t", &deadline, "--"].map(String::from));
                }
                Os::Windows => {
                    let ms = (u32::from(w) * 1000).to_string();
                    a.extend(["-n", &n, "-w", &ms].map(String::from));
                }
            }
        }
        Tool::Traceroute { max_hops } => {
            let m = (*max_hops).clamp(1, MAX_HOPS).to_string();
            let w = TRACE_WAIT_SECS.to_string();
            match (os, flavour) {
                (Os::Windows, _) => {
                    let ms = (u32::from(TRACE_WAIT_SECS) * 1000).to_string();
                    a.extend(["-d", "-h", &m, "-w", &ms].map(String::from));
                }
                (_, TraceFlavour::Tracepath) => a.extend(["-n", "-m", &m].map(String::from)),
                (_, TraceFlavour::Traceroute) => {
                    a.extend(["-n", "-q", "1", "-w", &w, "-m", &m, "--"].map(String::from));
                }
            }
        }
        Tool::Wg(q) => {
            a.push("show".into());
            a.extend(q.args().into_iter().map(String::from));
        }
    }
    let mut out: Vec<OsString> = a.into_iter().map(OsString::from).collect();
    if let Some(t) = target {
        out.push(OsString::from(t.as_str()));
    }
    out
}

#[cfg(test)]
mod tests;
