//! Minimal in-process russh server for the `session_open` tests (loopback only): password
//! auth, PTY shell that echoes input, `exit\r` ends the session. Trimmed copy of
//! `crates/mooring-proto-ssh/tests/common/mod.rs`, which is not reachable from here.
//! For the forward / SFTP commands (ADR-0010) it also serves `direct-tcpip` (connect and
//! splice) and, with [`start_with_sftp`], an `sftp` subsystem over a temp directory (the
//! proto-ssh test server's `SftpFs`, included by path so there is one copy).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::{PrivateKey, PublicKey};
use russh::server::{self, Auth, Msg, Session as ServerSession};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use tokio::net::{TcpListener, TcpStream};

#[allow(dead_code, clippy::pedantic)] // shared with the proto-ssh tests, which read its stats
#[path = "../../crates/mooring-proto-ssh/tests/common/sftp_server.rs"]
mod sftp_server;

/// Accepted user.
pub const USER: &str = "alice";
/// Accepted password (synthetic test value).
pub const PASSWORD: &str = "test-only ssh pw";

/// A running server.
#[derive(Debug)]
pub struct TestServer {
    /// Loopback port.
    pub port: u16,
    /// Host key presented to clients.
    pub host_public: PublicKey,
}

/// Start a server with host key from `seed`.
pub async fn start(seed: u8) -> TestServer {
    start_inner(seed, None).await
}

/// Like [`start`], with an `sftp` subsystem rooted at `root`.
pub async fn start_with_sftp(seed: u8, root: PathBuf) -> TestServer {
    start_inner(seed, Some(root)).await
}

async fn start_inner(seed: u8, sftp_root: Option<PathBuf>) -> TestServer {
    let host_key = PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]));
    let host_public = host_key.public_key().clone();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let config = Arc::new(server::Config {
        keys: vec![host_key],
        methods: MethodSet::from(&[MethodKind::Password][..]),
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::ZERO),
        inactivity_timeout: Some(Duration::from_secs(30)),
        ..Default::default()
    });
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let config = Arc::clone(&config);
            let sftp_root = sftp_root.clone();
            tokio::spawn(async move {
                let handler = Handler { sftp_root, channels: HashMap::new(), shells: Vec::new() };
                if let Ok(running) = server::run_stream(config, stream, handler).await {
                    let _ = running.await;
                }
            });
        }
    });
    TestServer { port, host_public }
}

struct Handler {
    sftp_root: Option<PathBuf>,
    /// Session channels not yet claimed by a subsystem.
    channels: HashMap<ChannelId, Channel<Msg>>,
    /// Channels running the echo shell.
    shells: Vec<ChannelId>,
}

impl server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(if user == USER && password == PASSWORD { Auth::Accept } else { Auth::reject() })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        match (name, self.sftp_root.clone(), self.channels.remove(&channel)) {
            ("sftp", Some(root), Some(ch)) => {
                session.channel_success(channel)?;
                let fs = sftp_server::SftpFs::new(root, None, Arc::default());
                russh_sftp::server::run(ch.into_stream(), fs).await;
                Ok(())
            }
            _ => session.channel_failure(channel),
        }
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        let host = host_to_connect.to_owned();
        tokio::spawn(async move {
            let Ok(port) = u16::try_from(port_to_connect) else {
                reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
                return;
            };
            match TcpStream::connect((host.as_str(), port)).await {
                Ok(mut stream) => {
                    reply.accept().await;
                    let mut ch = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut ch).await;
                }
                Err(_) => reply.reject(russh::ChannelOpenFailure::ConnectFailed).await,
            }
        });
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        // The shell is served through handler callbacks; an unread `Channel` would fill up.
        self.channels.remove(&channel);
        self.shells.push(channel);
        session.channel_success(channel)?;
        session.data(channel, b"welcome\r\n".to_vec())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        // Only the shell echoes; subsystem and forwarded channels are served by their streams.
        if !self.shells.contains(&channel) {
            return Ok(());
        }
        if data == b"exit\r" {
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            return session.close(channel);
        }
        session.data(channel, data.to_vec())
    }
}
