//! `ssh-sk-helper` backend (ADR-0024 §3, flagged stretch, off by default: setting
//! `sshSkHelper`). Drives OpenSSH's own helper binary from a **fixed absolute path** (ADR-0020
//! §3 process pattern): no shell, no `PATH` lookup, the environment cleared (no
//! `SSH_SK_PROVIDER`: the built-in provider only; `SystemRoot` on Windows), stdin/stdout pipes,
//! stderr discarded, a 30 s deadline, the reply capped at 64 KiB. The helper protocol is
//! OpenSSH-internal and unversioned in public: version [`SK_HELPER_VERSION`] only, anything
//! else fails closed (`ssh.sk_helper_version`, residue R-SK-HELPER).
//!
//! Request (`ssh-sk-client.c` `client_converse` + `sshsk_sign`), framed by `ssh_msg_send`:
//! `uint32 len, byte version, uint32 SIGN, byte log_on, uint32 log_level, string key,
//! string provider, string data, string alg, uint32 compat, string pin`. Reply: `uint32 len,
//! byte version, uint32 type, (SIGN: string signature | ERROR: uint32 code)`.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use mooring_core::credential::sk_key::{sk_helper_key_blob, Reader, SkPublicKey};
use mooring_core::session::SkLogin;
use secrecy::ExposeSecret;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::agent_wire::put_string;
use crate::sk_auth::{SkFailure, SkOptions};

/// The helper protocol version implemented (OpenSSH 8.4–9.9).
pub const SK_HELPER_VERSION: u8 = 5;
const SK_HELPER_ERROR: u32 = 0;
const SK_HELPER_SIGN: u32 = 1;
/// Largest helper reply (bytes).
pub const MAX_HELPER_REPLY: usize = 64 * 1024;
const DEADLINE: Duration = Duration::from_secs(30);

/// Fixed helper locations (ADR-0024 §3); `%SystemRoot%` is expanded at run time. macOS: none
/// (Apple's OpenSSH ships no helper).
pub const SK_HELPER_PATHS: &[&str] = if cfg!(windows) {
    &[r"%SystemRoot%\System32\OpenSSH\ssh-sk-helper.exe"]
} else if cfg!(target_os = "linux") {
    &["/usr/lib/openssh/ssh-sk-helper", "/usr/libexec/openssh/ssh-sk-helper"]
} else {
    &[]
};

/// The first fixed helper path that exists, `None` when the OS has none.
#[must_use]
pub fn system_helper() -> Option<PathBuf> {
    SK_HELPER_PATHS.iter().map(|t| expand(t)).find(|p| p.is_absolute() && p.is_file())
}

fn expand(template: &str) -> PathBuf {
    match template.strip_prefix("%SystemRoot%") {
        Some(rest) => {
            let root = std::env::var_os("SystemRoot").unwrap_or_default();
            let mut p = PathBuf::from(root);
            p.push(rest.trim_start_matches('\\'));
            p
        }
        None => PathBuf::from(template),
    }
}

/// Signs through one helper process per signature.
pub(crate) struct HelperSigner<'a> {
    path: &'a Path,
    key: Zeroizing<Vec<u8>>,
}

impl<'a> HelperSigner<'a> {
    /// Check the setting, the binary and the key handle (decrypted with its passphrase).
    pub(crate) fn new(
        login: &SkLogin,
        public: &SkPublicKey,
        options: &'a SkOptions,
    ) -> Result<Self, SkFailure> {
        let path = options.helper.as_deref().ok_or(SkFailure::HelperDisabled)?;
        if !path.is_absolute() || !path.is_file() {
            return Err(SkFailure::HelperMissing);
        }
        let handle = login.key_handle.as_ref().ok_or(SkFailure::BadKey)?;
        let clear = match russh::keys::decode_secret_key(
            handle.expose_secret(),
            login.passphrase.as_ref().map(ExposeSecret::expose_secret),
        ) {
            Ok(k) => Zeroizing::new(
                k.to_openssh(russh::keys::ssh_key::LineEnding::LF)
                    .map_err(|_| SkFailure::BadKey)?
                    .to_string(),
            ),
            Err(_) => return Err(SkFailure::BadKey),
        };
        let (h, key) = sk_helper_key_blob(clear.as_bytes()).map_err(|_| SkFailure::BadKey)?;
        if h.public.blob != public.blob {
            return Err(SkFailure::BadKey);
        }
        Ok(Self { path, key })
    }

    /// One signature over `data`. The touch banner is raised by the caller.
    pub(crate) async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SkFailure> {
        let request = Zeroizing::new(sign_request(&self.key, data));
        let reply = tokio::time::timeout(DEADLINE, run(self.path, &request))
            .await
            .map_err(|_| SkFailure::TouchTimeout)??;
        parse_reply(&reply)
    }
}

/// The framed sign request (no PIN: `verify-required` keys are refused by the helper).
pub(crate) fn sign_request(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(key.len() + data.len() + 64);
    body.extend_from_slice(&SK_HELPER_SIGN.to_be_bytes());
    body.push(0); // log to stderr: off
    body.extend_from_slice(&0u32.to_be_bytes()); // log level: quiet
    put_string(&mut body, key);
    put_string(&mut body, b"internal");
    put_string(&mut body, data);
    put_string(&mut body, b""); // alg: the key's own
    body.extend_from_slice(&0u32.to_be_bytes()); // compat
    put_string(&mut body, b""); // pin
    let mut frame = Vec::with_capacity(body.len() + 5);
    frame.extend_from_slice(&u32::try_from(body.len() + 1).unwrap_or(u32::MAX).to_be_bytes());
    frame.push(SK_HELPER_VERSION);
    frame.extend_from_slice(&body);
    frame
}

async fn run(path: &Path, request: &[u8]) -> Result<Vec<u8>, SkFailure> {
    let mut cmd = tokio::process::Command::new(path);
    cmd.env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(windows)]
    {
        if let Some(root) = std::env::var_os("SystemRoot") {
            cmd.env("SystemRoot", root);
        }
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = cmd.spawn().map_err(|e| {
        tracing::warn!(error = %e.kind(), "ssh-sk-helper spawn failed");
        SkFailure::HelperMissing
    })?;
    let mut stdin = child.stdin.take().ok_or(SkFailure::HelperFailed)?;
    let stdout = child.stdout.take().ok_or(SkFailure::HelperFailed)?;
    stdin.write_all(request).await.map_err(|_| SkFailure::HelperFailed)?;
    drop(stdin);
    let mut out = Vec::new();
    stdout
        .take(u64::try_from(MAX_HELPER_REPLY + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut out)
        .await
        .map_err(|_| SkFailure::HelperFailed)?;
    let _ = child.kill().await;
    if out.len() > MAX_HELPER_REPLY {
        return Err(SkFailure::HelperFailed);
    }
    Ok(out)
}

/// Parse a helper reply into the signature blob (checked by the caller like an agent's).
pub(crate) fn parse_reply(reply: &[u8]) -> Result<Vec<u8>, SkFailure> {
    let mut r = Reader::new(reply, "ssh-sk-helper reply");
    let len = r.u32().map_err(|_| SkFailure::HelperFailed)?;
    if usize::try_from(len).map_or(true, |l| l != r.remaining() || l == 0) {
        return Err(SkFailure::HelperFailed);
    }
    if r.u8().map_err(|_| SkFailure::HelperFailed)? != SK_HELPER_VERSION {
        tracing::warn!("ssh-sk-helper answered with another protocol version");
        return Err(SkFailure::HelperVersion);
    }
    match r.u32().map_err(|_| SkFailure::HelperFailed)? {
        SK_HELPER_SIGN => {
            let sig = r.string(1024).map_err(|_| SkFailure::HelperFailed)?.to_vec();
            r.finish().map_err(|_| SkFailure::HelperFailed)?;
            Ok(sig)
        }
        SK_HELPER_ERROR => {
            let code = r.u32().map_err(|_| SkFailure::HelperFailed)?;
            tracing::debug!(code, "ssh-sk-helper reported an error");
            Err(SkFailure::HelperFailed)
        }
        _ => Err(SkFailure::HelperFailed),
    }
}

/// Fuzz entry `sk_helper_reply` (qa wires it in `fuzz/`). Never panics.
pub fn fuzz_sk_helper_reply(data: &[u8]) {
    let _ = parse_reply(data);
}

#[cfg(test)]
#[path = "sk_helper_tests.rs"]
mod tests;
