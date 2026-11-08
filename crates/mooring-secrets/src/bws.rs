//! Bitwarden Secrets Manager through the `bws` CLI (ADR-0026 §4, the ADR-0020 §3 process
//! pattern, R-SEC-CLI): an absolute path from a fixed list (no `PATH` lookup, no shell), a
//! pinned argv, `stdin` null, the environment **cleared** except `BWS_ACCESS_TOKEN` and
//! `BWS_SERVER_URL` (plus `SystemRoot` on Windows), a 30 s deadline after which the child is
//! killed, stdout capped at 1 MiB and stderr at 16 KiB (never echoed: it may quote a value).
//! `bws --version` must report 1.0 or later, checked once per path and process; the binary's
//! SHA-256 is pinned on first use, persisted ([`BwsConfig::with_pins`], review 9 L-50), and a
//! changed binary is audited as `secret.tool_changed` and **refused** with that code until
//! `secret_source_test` trusts it again. The file is hashed and then executed by path, so a
//! same-user writer racing the two is not covered (T2, R-SEC-CLI).

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use mooring_core::secret_source::BWS_PATHS;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use zeroize::Zeroizing;

use crate::audit::{SecretEvent, SecretsAudit};
use crate::bws_pins::{Known, Pins};
use crate::error::SecretsError;

/// Deadline of one run.
pub const BWS_DEADLINE: Duration = Duration::from_secs(30);
/// stdout cap.
pub const BWS_MAX_STDOUT: usize = 1024 * 1024;
/// stderr cap.
pub const BWS_MAX_STDERR: usize = 16 * 1024;
/// Largest binary hashed for the pin.
const MAX_BINARY: u64 = 512 * 1024 * 1024;

/// Expand one [`BWS_PATHS`] template (`%VAR%\rest`) into an absolute path of this OS.
#[must_use]
pub fn expand(template: &str) -> Option<PathBuf> {
    let path = match template.strip_prefix('%').and_then(|t| t.split_once('%')) {
        Some((var, rest)) => {
            let mut p = PathBuf::from(std::env::var_os(var)?);
            for seg in rest.split('\\').filter(|s| !s.is_empty()) {
                p.push(seg);
            }
            p
        }
        None => PathBuf::from(template),
    };
    path.is_absolute().then_some(path)
}

/// Where `bws` may be.
#[derive(Debug, Clone)]
pub struct BwsConfig {
    candidates: Vec<PathBuf>,
    custom: bool,
    /// Where the SHA-256 pins persist (`None`: this process only).
    pins: Option<PathBuf>,
    /// Deadline of one run.
    pub deadline: Duration,
}

impl BwsConfig {
    /// The fixed list of ADR-0026 §4, expanded for this OS.
    #[must_use]
    pub fn system() -> Self {
        Self {
            candidates: BWS_PATHS.iter().filter_map(|t| expand(t)).collect(),
            custom: false,
            pins: None,
            deadline: BWS_DEADLINE,
        }
    }

    /// Persist the binary pins in `file` (the app data directory's `bws_pins.json`).
    #[must_use]
    pub fn with_pins(mut self, file: PathBuf) -> Self {
        self.pins = Some(file);
        self
    }

    /// Tests only: one fake `bws` (the source's `bwsPath` is then ignored).
    #[must_use]
    pub fn custom(path: PathBuf) -> Self {
        Self { candidates: vec![path], custom: true, pins: None, deadline: BWS_DEADLINE }
    }

    /// The binary for a source whose `bwsPath` is `wanted`: that one (it is one of the fixed
    /// templates, the store refused anything else), or the first fixed path that exists.
    pub fn locate(&self, wanted: Option<&str>) -> Result<PathBuf, SecretsError> {
        let pick = match wanted.filter(|_| !self.custom) {
            Some(t) if BWS_PATHS.contains(&t) => expand(t).filter(|p| p.is_file()),
            Some(_) => None,
            None => self.candidates.iter().find(|p| p.is_file()).cloned(),
        };
        pick.ok_or(SecretsError::ToolMissing)
    }
}

/// What one run produced.
pub(crate) struct Output {
    pub stdout: Zeroizing<Vec<u8>>,
}

/// The runner: version checks per path and process, binary pins per path (persisted).
pub struct BwsRunner {
    cfg: BwsConfig,
    audit: Arc<dyn SecretsAudit>,
    /// Hash whose `--version` passed in this process, per path.
    checked: Mutex<HashMap<PathBuf, [u8; 32]>>,
    pins: Pins,
}

impl std::fmt::Debug for BwsRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BwsRunner").field("cfg", &self.cfg).finish_non_exhaustive()
    }
}

fn hash_file(path: &Path) -> Option<[u8; 32]> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > MAX_BINARY {
        return None;
    }
    std::fs::read(path).ok().map(|b| mooring_core::credential::fingerprint::sha256(&b))
}

/// Fuzz entry of the version parser.
pub(crate) fn fuzz_version(data: &[u8]) -> bool {
    version_ok(data)
}

/// `bws 1.2.3` (or `1.2.3`) → major ≥ 1.
pub(crate) fn version_ok(stdout: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(stdout) else { return false };
    let v = text.trim().rsplit(' ').next().unwrap_or("");
    let mut parts = v.split('.');
    let major = parts.next().and_then(|m| m.parse::<u32>().ok());
    let minor_ok =
        parts.next().is_some_and(|m| m.bytes().all(|b| b.is_ascii_digit()) && !m.is_empty());
    matches!(major, Some(m) if m >= 1) && minor_ok
}

impl BwsRunner {
    /// A runner over `cfg`.
    pub fn new(cfg: BwsConfig, audit: Arc<dyn SecretsAudit>) -> Self {
        let pins = Pins::new(cfg.pins.clone());
        Self { cfg, audit, checked: Mutex::new(HashMap::new()), pins }
    }

    /// The configuration.
    pub fn config(&self) -> &BwsConfig {
        &self.cfg
    }

    /// Run `bws <args>` with the token and server URL in the child's environment only.
    pub(crate) async fn run(
        &self,
        path: &Path,
        action: &'static str,
        args: &[&str],
        token: &str,
        server_url: &str,
    ) -> Result<Output, SecretsError> {
        let mut cmd = Command::new(path);
        cmd.args(args.iter().map(OsString::from))
            .env_clear()
            .env("BWS_ACCESS_TOKEN", token)
            .env("BWS_SERVER_URL", server_url)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(windows)]
        {
            if let Some(root) = std::env::var_os("SystemRoot") {
                cmd.env("SystemRoot", root);
            }
            cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        let mut child = cmd.spawn().map_err(|e| {
            tracing::warn!(error = %e.kind(), "bws spawn failed");
            SecretsError::ToolMissing
        })?;
        let (stdout, stderr) = (child.stdout.take(), child.stderr.take());
        let mut out = Zeroizing::new(Vec::new());
        let mut err = Zeroizing::new(Vec::new());
        let read = async {
            let a = read_capped(stdout, &mut out, BWS_MAX_STDOUT);
            let b = read_capped(stderr, &mut err, BWS_MAX_STDERR);
            let (a, b) = tokio::join!(a, b);
            a || b
        };
        let result = match tokio::time::timeout(self.cfg.deadline, read).await {
            Err(_) => Err(SecretsError::ToolFailed { exit: None, detail: "timed out" }),
            Ok(true) => Err(SecretsError::ToolFailed { exit: None, detail: "output too large" }),
            Ok(false) => match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
                Ok(Ok(status)) => Ok(status.code()),
                _ => Err(SecretsError::ToolFailed { exit: None, detail: "did not exit" }),
            },
        };
        if result.is_err() {
            let _ = child.kill().await;
        }
        let exit = result.as_ref().ok().copied().flatten();
        self.audit.record(SecretEvent::ToolSpawned { provider: "bitwarden", action, exit });
        drop(err); // stderr is never surfaced (it may quote a value)
        let code = result?;
        if code != Some(0) {
            return Err(SecretsError::ToolFailed { exit: code, detail: "non-zero exit" });
        }
        Ok(Output { stdout: out })
    }

    /// The SHA-256 pin and `bws --version` (once per path, hash and process). A binary that
    /// differs from its pin is audited `tool_changed` and refused with
    /// [`SecretsError::ToolChanged`], unless `trust` (only `secret_source_test` passes it):
    /// then it is version-checked and pinned anew.
    pub(crate) async fn ensure_checked(
        &self,
        path: &Path,
        server_url: &str,
        trust: bool,
    ) -> Result<(), SecretsError> {
        let hash = hash_file(path).ok_or(SecretsError::ToolMissing)?;
        let known = self.pins.check(path, &hash);
        if known == Known::Changed {
            self.audit.record(SecretEvent::ToolChanged {
                provider: "bitwarden",
                sha256: hex::encode(hash),
            });
            if !trust {
                return Err(SecretsError::ToolChanged);
            }
        }
        let checked =
            self.checked.lock().unwrap_or_else(PoisonError::into_inner).get(path) == Some(&hash);
        if !checked {
            // `--version` needs no token; an empty one keeps argv and env identical in shape.
            let out = self.run(path, "version", &["--version"], "", server_url).await?;
            if !version_ok(&out.stdout) {
                return Err(SecretsError::ToolVersion);
            }
            self.checked
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(path.to_owned(), hash);
        }
        if known != Known::Same {
            self.pins.pin(path, &hash);
        }
        Ok(())
    }
}

/// Read until EOF or the cap; `true` when the cap was hit (the child is then killed).
async fn read_capped<R: tokio::io::AsyncRead + Unpin>(
    r: Option<R>,
    buf: &mut Vec<u8>,
    cap: usize,
) -> bool {
    let Some(mut r) = r else { return false };
    let mut chunk = Zeroizing::new([0u8; 4096]);
    loop {
        match r.read(&mut chunk[..]).await {
            Ok(0) | Err(_) => return false,
            Ok(n) => {
                if buf.len() + n > cap {
                    return true;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        for ok in [&b"bws 1.0.0\n"[..], b"bws 2.1.0", b"1.0.0", b"bws 10.3"] {
            assert!(version_ok(ok), "{ok:?}");
        }
        for bad in [&b"bws 0.5.0"[..], b"", b"bws", b"bws x.y", b"bws 1", b"\xff", b"bws 1."] {
            assert!(!version_ok(bad), "{bad:?}");
        }
    }

    #[test]
    fn templates_expand_to_absolute_paths_only() {
        for t in BWS_PATHS {
            if let Some(p) = expand(t) {
                assert!(p.is_absolute(), "{t}");
            }
        }
        assert!(expand("bws").is_none(), "relative");
        assert!(expand("%MOORING_SURELY_UNSET_VAR%\\bws.exe").is_none());
        let sys = BwsConfig::system();
        assert!(sys.candidates.iter().all(|p| p.is_absolute()));
        assert!(
            matches!(sys.locate(Some("/tmp/bws")), Err(SecretsError::ToolMissing)),
            "not in the list"
        );
    }
}
