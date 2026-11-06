//! The typed front door: resolve the binary from a [`ToolPaths`] table, build the argv, run
//! under the tool's deadline, parse the sanitised output.

use crate::error::NetError;
use crate::ping::{parse_ping, PingResult};
use crate::run::{run_tool, RunOutput, PING_DEADLINE, TRACE_DEADLINE, WG_DEADLINE};
use crate::target::Target;
use crate::tools::{argv, Tool, ToolPaths, TraceFlavour, WgQuery};
use crate::traceroute::{parse_traceroute, TraceResult};
use crate::wg::{
    is_permission_denied, merge_interface, parse_wg, WgResult, WgStatus, MAX_INTERFACES,
};

/// Which tools a table resolves (`net_tools()` DTO).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tools {
    /// `ping` exists.
    pub ping: bool,
    /// `traceroute`, `tracepath` or none.
    pub traceroute: Option<&'static str>,
    /// `wg` exists.
    pub wg: bool,
}

/// A finished `ping` run.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PingRun {
    /// Parsed summary.
    pub result: PingResult,
    /// The deadline passed; `result` is partial.
    pub timed_out: bool,
    /// The output cap was hit; `result` is partial.
    pub truncated: bool,
    /// Exit code (`ping` exits 1 on loss: data, not an error).
    pub exit_code: Option<i32>,
}

/// A finished trace run.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceRun {
    /// Parsed hops.
    pub result: TraceResult,
    /// Which tool ran (`traceroute` | `tracepath`).
    pub tool: &'static str,
    /// The deadline passed; `result` is partial.
    pub timed_out: bool,
    /// The output cap was hit; `result` is partial.
    pub truncated: bool,
    /// Exit code.
    pub exit_code: Option<i32>,
}

/// Runs the OS tools of one [`ToolPaths`] table.
#[derive(Debug, Clone)]
pub struct Runner {
    paths: ToolPaths,
}

impl Runner {
    /// A runner over `paths` (the fixed table of the current OS in production, a shim table in
    /// tests).
    #[must_use]
    pub fn new(paths: ToolPaths) -> Self {
        Self { paths }
    }

    /// The table.
    #[must_use]
    pub fn paths(&self) -> &ToolPaths {
        &self.paths
    }

    /// Which tools exist right now.
    #[must_use]
    pub fn tools(&self) -> Tools {
        let (ping, trace, wg) = self.paths.available();
        Tools { ping, traceroute: trace.map(flavour_name), wg }
    }

    /// `ping` `target` `count` times (clamped to 1..=10, 2 s per reply).
    pub async fn ping(&self, target: &Target, count: u8) -> Result<PingRun, NetError> {
        let tool = Tool::Ping { count, wait_secs: 2 };
        let (path, flavour) = self.paths.resolve(&tool, target.is_ipv6())?;
        let args = argv(&tool, Some(target), self.paths.os(), flavour);
        let out = run_tool(&path, &args, PING_DEADLINE).await?;
        let result = parse_ping(&joined(&out));
        Ok(PingRun {
            result,
            timed_out: out.timed_out,
            truncated: out.truncated,
            exit_code: out.exit_code,
        })
    }

    /// Trace the route to `target` up to `max_hops` (clamped to 1..=30).
    pub async fn traceroute(&self, target: &Target, max_hops: u8) -> Result<TraceRun, NetError> {
        let tool = Tool::Traceroute { max_hops };
        let (path, flavour) = self.paths.resolve(&tool, target.is_ipv6())?;
        let args = argv(&tool, Some(target), self.paths.os(), flavour);
        let out = run_tool(&path, &args, TRACE_DEADLINE).await?;
        let result = parse_traceroute(&joined(&out));
        Ok(TraceRun {
            result,
            tool: flavour_name(flavour),
            timed_out: out.timed_out,
            truncated: out.truncated,
            exit_code: out.exit_code,
        })
    }

    /// One `wg show` query. A non-zero exit with a permission message is
    /// [`NetError::PermissionDenied`]; any other failure yields an empty result.
    pub async fn wg(&self, q: &WgQuery) -> Result<WgResult, NetError> {
        let tool = Tool::Wg(q.clone());
        let (path, flavour) = self.paths.resolve(&tool, false)?;
        let args = argv(&tool, None, self.paths.os(), flavour);
        let out = run_tool(&path, &args, WG_DEADLINE).await?;
        if out.exit_code != Some(0) && is_permission_denied(&out.stderr) {
            return Err(NetError::PermissionDenied);
        }
        Ok(parse_wg(q, &out.stdout))
    }

    /// `wg show interfaces`, then the four read-only queries per interface (ADR-0020 §4).
    pub async fn wg_status(&self) -> Result<WgStatus, NetError> {
        let WgResult::Interfaces(names) = self.wg(&WgQuery::Interfaces).await? else {
            return Ok(WgStatus { interfaces: Vec::new() });
        };
        let mut interfaces = Vec::with_capacity(names.len().min(MAX_INTERFACES));
        for iface in names.into_iter().take(MAX_INTERFACES) {
            let port = self.wg(&WgQuery::ListenPort(iface.clone())).await?;
            let endpoints = self.wg(&WgQuery::Endpoints(iface.clone())).await?;
            let handshakes = self.wg(&WgQuery::LatestHandshakes(iface.clone())).await?;
            let transfer = self.wg(&WgQuery::Transfer(iface.clone())).await?;
            interfaces.push(merge_interface(&iface, &port, &endpoints, &handshakes, &transfer));
        }
        Ok(WgStatus { interfaces })
    }
}

fn flavour_name(f: TraceFlavour) -> &'static str {
    match f {
        TraceFlavour::Traceroute => "traceroute",
        TraceFlavour::Tracepath => "tracepath",
    }
}

/// stdout then stderr (ICMP errors go to stderr on some tools); the parsers cap again.
fn joined(out: &RunOutput) -> Vec<u8> {
    let mut v = out.stdout.clone();
    if !out.stderr.is_empty() {
        v.push(b'\n');
        v.extend_from_slice(&out.stderr);
    }
    v
}
