//! Minimal in-process russh server for the `session_open` tests (loopback only): password
//! auth, PTY shell that echoes input, `exit\r` ends the session. Trimmed copy of
//! `crates/mooring-proto-ssh/tests/common/mod.rs`, which is not reachable from here.

use std::sync::Arc;
use std::time::Duration;

use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::{PrivateKey, PublicKey};
use russh::server::{self, Auth, Msg, Session as ServerSession};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use tokio::net::TcpListener;

/// Accepted user.
pub const USER: &str = "alice";
/// Accepted password (synthetic test value).
pub const PASSWORD: &str = "test-only ssh pw";

/// A running server.
pub struct TestServer {
    /// Loopback port.
    pub port: u16,
    /// Host key presented to clients.
    pub host_public: PublicKey,
}

/// Start a server with host key from `seed`.
pub async fn start(seed: u8) -> TestServer {
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
            tokio::spawn(async move {
                if let Ok(running) = server::run_stream(config, stream, Handler).await {
                    let _ = running.await;
                }
            });
        }
    });
    TestServer { port, host_public }
}

struct Handler;

impl server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(if user == USER && password == PASSWORD { Auth::Accept } else { Auth::reject() })
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
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
        session.channel_success(channel)?;
        session.data(channel, b"welcome\r\n".to_vec())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        if data == b"exit\r" {
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            return session.close(channel);
        }
        session.data(channel, data.to_vec())
    }
}
