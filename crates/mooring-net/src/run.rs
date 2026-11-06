//! Runs one OS tool (ADR-0020 §3): a fixed absolute path, explicit argv, no shell, cleared
//! environment, null stdin, capped output and a wall-clock deadline after which the child is
//! killed. The caller gets the raw bytes plus whether the run was cut short.

use std::ffi::OsString;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};

use crate::error::NetError;
use crate::sanitize::MAX_BYTES;

/// Wall clock for one `ping` run.
pub const PING_DEADLINE: Duration = Duration::from_secs(30);
/// Wall clock for one `traceroute` run (30 hops × 2 s, one probe each, fits with margin).
pub const TRACE_DEADLINE: Duration = Duration::from_secs(60);
/// Wall clock for one `wg show` query.
pub const WG_DEADLINE: Duration = Duration::from_secs(5);

/// What a run produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutput {
    /// Captured stdout, ≤ [`MAX_BYTES`].
    pub stdout: Vec<u8>,
    /// Captured stderr, ≤ [`MAX_BYTES`] (shared budget with stdout).
    pub stderr: Vec<u8>,
    /// Exit status code (`None` when killed or ended by a signal).
    pub exit_code: Option<i32>,
    /// The deadline passed and the child was killed; the output is partial.
    pub timed_out: bool,
    /// The output cap was hit and the child was killed.
    pub truncated: bool,
}

/// Spawn `path` with `args`, wait at most `deadline`. `args` must come from
/// [`crate::tools::argv`]; `path` from [`crate::tools::ToolPaths::resolve`].
pub async fn run_tool(
    path: &Path,
    args: &[OsString],
    deadline: Duration,
) -> Result<RunOutput, NetError> {
    let mut cmd = Command::new(path);
    cmd.args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    cmd.env("LC_ALL", "C");
    #[cfg(windows)]
    {
        if let Some(root) = std::env::var_os("SystemRoot") {
            cmd.env("SystemRoot", root);
        }
        // CREATE_NO_WINDOW: no console flashes up behind the app.
        cmd.creation_flags(0x0800_0000);
    }
    let mut child = cmd.spawn().map_err(|e| {
        tracing::warn!(tool = %path.display(), error = %e.kind(), "net tool spawn failed");
        NetError::Spawn
    })?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let collect = collect(stdout, stderr, &mut out, &mut err);
    match tokio::time::timeout(deadline, collect).await {
        Ok(truncated) => {
            let exit_code =
                if truncated { kill(&mut child).await } else { wait(&mut child, deadline).await };
            Ok(RunOutput { stdout: out, stderr: err, exit_code, timed_out: false, truncated })
        }
        Err(_elapsed) => {
            let _ = kill(&mut child).await;
            Ok(RunOutput {
                stdout: out,
                stderr: err,
                exit_code: None,
                timed_out: true,
                truncated: false,
            })
        }
    }
}

/// Read both pipes until EOF or until either hits its cap (then stop reading both, so a
/// flooding child blocks on a full pipe until it is killed). Returns whether a cap was hit.
/// Partial output stays in the buffers when the future is dropped at the deadline.
async fn collect<O: tokio::io::AsyncRead + Unpin, E: tokio::io::AsyncRead + Unpin>(
    stdout: Option<O>,
    stderr: Option<E>,
    out: &mut Vec<u8>,
    err: &mut Vec<u8>,
) -> bool {
    let (mut stdout, mut stderr) = (stdout, stderr);
    let (mut chunk_out, mut chunk_err) = ([0u8; 4096], [0u8; 4096]);
    loop {
        tokio::select! {
            n = read_some(&mut stdout, &mut chunk_out), if stdout.is_some() => {
                match push(out, &chunk_out, n, MAX_BYTES) {
                    Push::More => {}
                    Push::Eof => stdout = None,
                    Push::Capped => return true,
                }
            }
            n = read_some(&mut stderr, &mut chunk_err), if stderr.is_some() => {
                match push(err, &chunk_err, n, MAX_BYTES / 4) {
                    Push::More => {}
                    Push::Eof => stderr = None,
                    Push::Capped => return true,
                }
            }
            else => return false,
        }
    }
}

enum Push {
    More,
    Eof,
    Capped,
}

/// One read; a read error counts as EOF.
async fn read_some<R: tokio::io::AsyncRead + Unpin>(r: &mut Option<R>, chunk: &mut [u8]) -> usize {
    match r {
        Some(r) => r.read(chunk).await.unwrap_or(0),
        None => 0,
    }
}

fn push(buf: &mut Vec<u8>, chunk: &[u8], n: usize, cap: usize) -> Push {
    if n == 0 {
        return Push::Eof;
    }
    let room = cap.saturating_sub(buf.len());
    buf.extend_from_slice(&chunk[..n.min(room)]);
    if n > room {
        Push::Capped
    } else {
        Push::More
    }
}

async fn kill(child: &mut Child) -> Option<i32> {
    let _ = child.kill().await;
    None
}

/// Wait for the exit status after the pipes closed; a child that lingers (a grandchild holds
/// the pipe) is killed at the deadline.
async fn wait(child: &mut Child, deadline: Duration) -> Option<i32> {
    match tokio::time::timeout(deadline, child.wait()).await {
        Ok(Ok(status)) => status.code(),
        _ => kill(child).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn collect_stops_both_pipes_at_the_first_cap() {
        let big = vec![b'a'; MAX_BYTES + 10];
        let small = b"err".to_vec();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert!(collect(Some(&big[..]), Some(&small[..]), &mut out, &mut err).await);
        assert_eq!(out.len(), MAX_BYTES);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert!(!collect(Some(&small[..]), Some(&small[..]), &mut out, &mut err).await);
        assert_eq!((out.as_slice(), err.as_slice()), (&b"err"[..], &b"err"[..]));
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert!(!collect::<&[u8], &[u8]>(None, None, &mut out, &mut err).await);
        assert!(out.is_empty() && err.is_empty());
    }

    #[tokio::test]
    async fn missing_binary_is_spawn_error() {
        let dir = tempfile::tempdir().expect("tmp");
        let r = run_tool(&dir.path().join("nope"), &[], Duration::from_secs(1)).await;
        assert_eq!(r, Err(NetError::Spawn));
    }
}
