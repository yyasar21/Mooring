//! A minimal ssh-agent client for the FIDO2 path (ADR-0024 §2): list identities and sign,
//! with our own bounded framing and parsers ([`crate::agent_wire`]) so a hostile agent reply
//! is checked before anything reaches the server, and the touch wait can be timed.
//!
//! Unix: `SSH_AUTH_SOCK` (or the test override). Windows: the OpenSSH agent named pipe
//! (Pageant has no `sk-*` support, ADR-0024 §2).

use std::path::Path;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::agent_wire::{
    parse_identities, parse_sign_response, put_string, Identity, WireError, MAX_AGENT_MESSAGE,
    REQUEST_IDENTITIES, SIGN_REQUEST,
};

trait Io: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> Io for T {}

/// One connection to the agent.
pub(crate) struct SkAgent {
    io: Box<dyn Io>,
}

impl std::fmt::Debug for SkAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SkAgent")
    }
}

/// Why the agent could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AgentError {
    /// Socket / pipe I/O failed.
    Io,
    /// The reply was refused by a parser (or the agent answered `FAILURE`).
    Wire(WireError),
}

impl From<std::io::Error> for AgentError {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}

impl From<WireError> for AgentError {
    fn from(e: WireError) -> Self {
        Self::Wire(e)
    }
}

/// The OpenSSH agent pipe on Windows.
#[cfg(windows)]
const WINDOWS_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

impl SkAgent {
    /// Connect to `path` (test override) or the user's agent. `None` when none is reachable.
    pub(crate) async fn connect(path: Option<&Path>) -> Option<Self> {
        let io = open(path).await;
        if io.is_none() {
            tracing::debug!("no ssh-agent reachable for the security key");
        }
        io.map(|io| Self { io })
    }

    async fn request(&mut self, msg: &[u8]) -> Result<Vec<u8>, AgentError> {
        let mut frame = Vec::with_capacity(msg.len() + 4);
        put_string(&mut frame, msg);
        self.io.write_all(&frame).await?;
        self.io.flush().await?;
        let mut len = [0u8; 4];
        self.io.read_exact(&mut len).await?;
        let len = usize::try_from(u32::from_be_bytes(len)).map_err(|_| AgentError::Io)?;
        if len == 0 || len > MAX_AGENT_MESSAGE {
            return Err(WireError::Malformed.into());
        }
        let mut body = vec![0u8; len];
        self.io.read_exact(&mut body).await?;
        Ok(body)
    }

    /// `SSH_AGENTC_REQUEST_IDENTITIES`.
    pub(crate) async fn identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        let reply = self.request(&[REQUEST_IDENTITIES]).await?;
        Ok(parse_identities(&reply)?)
    }

    /// `SSH_AGENTC_SIGN_REQUEST` for the key (or certificate) `blob`; returns the raw
    /// signature blob (checked by the caller).
    pub(crate) async fn sign(&mut self, blob: &[u8], data: &[u8]) -> Result<Vec<u8>, AgentError> {
        let mut msg = vec![SIGN_REQUEST];
        put_string(&mut msg, blob);
        put_string(&mut msg, data);
        msg.extend_from_slice(&0u32.to_be_bytes());
        let reply = self.request(&msg).await?;
        Ok(parse_sign_response(&reply)?)
    }
}

#[cfg(unix)]
async fn open(path: Option<&Path>) -> Option<Box<dyn Io>> {
    let env = std::env::var_os("SSH_AUTH_SOCK");
    let path = path.map(Path::to_path_buf).or_else(|| env.map(Into::into))?;
    let s = tokio::net::UnixStream::connect(path).await.ok()?;
    Some(Box::new(s))
}

#[cfg(windows)]
async fn open(path: Option<&Path>) -> Option<Box<dyn Io>> {
    let name = path.map_or_else(|| WINDOWS_PIPE.into(), |p| p.as_os_str().to_owned());
    for _ in 0..20 {
        match tokio::net::windows::named_pipe::ClientOptions::new().open(&name) {
            Ok(c) => return Some(Box::new(c)),
            // ERROR_PIPE_BUSY: every instance is in use; retry shortly.
            Err(e) if e.raw_os_error() == Some(231) => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(_) => return None,
        }
    }
    None
}

#[cfg(not(any(unix, windows)))]
async fn open(_path: Option<&Path>) -> Option<Box<dyn Io>> {
    None
}

/// What the agent holds for one `sk-*` key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Held {
    /// The key itself, plus a certificate identity of it if one is loaded.
    Key { certificate: Option<Vec<u8>> },
    /// Only a certificate of the key.
    CertificateOnly(Vec<u8>),
    /// Neither.
    Missing,
}

/// Find `key_blob` among the identities: a plain identity with exactly this blob, or a
/// certificate identity that certifies it.
pub(crate) fn find(identities: &[Identity], key_blob: &[u8]) -> Held {
    let plain = identities.iter().any(|i| i.blob == key_blob);
    let cert = identities.iter().find_map(|i| {
        let cert = russh::keys::Certificate::from_bytes(&i.blob).ok()?;
        let certified = russh::keys::PublicKey::from(cert.public_key().clone()).to_bytes().ok()?;
        (certified == key_blob).then(|| i.blob.clone())
    });
    match (plain, cert) {
        (true, certificate) => Held::Key { certificate },
        (false, Some(c)) => Held::CertificateOnly(c),
        (false, None) => Held::Missing,
    }
}

/// Whether the user's agent (or `path`) holds `public_key_line` (an `sk-*` key): `Some(true)`
/// / `Some(false)`, `None` when no agent answers. For the app's pre-flight
/// (`ssh.sk_key_not_in_agent`) before a session is opened.
pub async fn agent_holds(public_key_line: &str, path: Option<&Path>) -> Option<bool> {
    let key = mooring_core::credential::sk_key::parse_sk_public_line(public_key_line).ok()?;
    let mut agent = SkAgent::connect(path).await?;
    let ids = agent.identities().await.ok()?;
    Some(find(&ids, &key.blob) != Held::Missing)
}
