//! In-process russh server for the SSH integration tests (loopback only, no lab).
//!
//! Supports password, publickey and keyboard-interactive auth, and a PTY shell that echoes
//! input and reports `window_change` as `RESIZE <cols>x<rows>\r\n`. Also `direct-tcpip`,
//! `tcpip-forward` (→ `forwarded-tcpip` channels).

#![allow(dead_code)] // each test binary uses a different subset

pub mod forwarding;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mooring_core::session::{
    ConnectParams, ConnectSecret, Session, SessionEvent, SessionInput, Size,
};
use mooring_proto_ssh::{SshOptions, SshSession};
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::ssh_key::LineEnding;
use russh::keys::{PrivateKey, PublicKey};
use russh::server::{self, Auth, Msg, Session as ServerSession, VerifiedPublicKey};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use secrecy::SecretString;
use tokio::net::TcpListener;

pub const USER: &str = "alice";
pub const PASSWORD: &str = "correct horse";
pub const OTP: &str = "424242";

/// Deterministic test key from a seed byte.
pub fn ed25519(seed: u8) -> PrivateKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
}

/// Unencrypted OpenSSH PEM of a test key (test material only).
pub fn pem(key: &PrivateKey) -> SecretString {
    SecretString::from(key.to_openssh(LineEnding::LF).expect("encode test key").to_string())
}

/// What the server accepts.
#[derive(Clone)]
pub struct ServerSpec {
    pub host_key: PrivateKey,
    pub methods: Vec<MethodKind>,
    pub password: Option<String>,
    pub authorized_key: Option<PublicKey>,
    /// Keyboard-interactive: first prompt "Password: " (no echo), then "Verification code: ".
    pub kbd_two_step: bool,
}

impl ServerSpec {
    pub fn new(methods: &[MethodKind]) -> Self {
        Self {
            host_key: ed25519(200),
            methods: methods.to_vec(),
            password: Some(PASSWORD.to_owned()),
            authorized_key: None,
            kbd_two_step: true,
        }
    }
}

/// Things the server saw, for assertions.
#[derive(Default)]
pub struct Seen {
    pub resizes: Vec<(u32, u32)>,
    pub pty: Option<(String, u32, u32)>,
    pub kbd_responses: Vec<String>,
    /// `direct-tcpip` targets requested.
    pub direct: Vec<(String, u32)>,
    /// `cancel-tcpip-forward` requests honoured.
    pub cancelled_forwards: Vec<(String, u32)>,
}

pub struct TestServer {
    pub port: u16,
    pub seen: Arc<Mutex<Seen>>,
    pub host_public: PublicKey,
}

pub async fn start(spec: ServerSpec) -> TestServer {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let host_public = spec.host_key.public_key().clone();
    let config = Arc::new(server::Config {
        keys: vec![spec.host_key.clone()],
        methods: MethodSet::from(&spec.methods[..]),
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::ZERO),
        inactivity_timeout: Some(Duration::from_secs(30)),
        ..Default::default()
    });
    let seen2 = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let listeners = forwarding::Listeners::default();
            let handler = Handler {
                spec: spec.clone(),
                seen: Arc::clone(&seen2),
                kbd_step: 0,
                sessions: HashMap::new(),
                shells: Vec::new(),
                listeners: Arc::clone(&listeners),
            };
            let config = Arc::clone(&config);
            tokio::spawn(async move {
                if let Ok(running) = server::run_stream(config, stream, handler).await {
                    let _ = running.await;
                }
                // Like sshd: remote-forward listeners die with the connection.
                for (_, task) in listeners.lock().expect("lock").drain() {
                    task.abort();
                }
            });
        }
    });
    TestServer { port, seen, host_public }
}

struct Handler {
    spec: ServerSpec,
    seen: Arc<Mutex<Seen>>,
    kbd_step: u8,
    /// Session channels not yet claimed by a subsystem.
    sessions: HashMap<ChannelId, Channel<Msg>>,
    /// Channels running the echo shell.
    shells: Vec<ChannelId>,
    listeners: forwarding::Listeners,
}

fn reject() -> Auth {
    Auth::reject()
}

impl server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        let ok = self.spec.methods.contains(&MethodKind::Password)
            && user == USER
            && self.spec.password.as_deref() == Some(password);
        Ok(if ok { Auth::Accept } else { reject() })
    }

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        offer: server::PublicKeyOffer<'_>,
    ) -> Result<Auth, Self::Error> {
        let ok = self
            .spec
            .authorized_key
            .as_ref()
            .is_some_and(|k| k.key_data() == offer.public_key.key_data());
        Ok(if ok { Auth::Accept } else { reject() })
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        let ok = user == USER
            && self
                .spec
                .authorized_key
                .as_ref()
                .is_some_and(|k| k.key_data() == key.public_key.key_data());
        Ok(if ok { Auth::Accept } else { reject() })
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        user: &str,
        _submethods: &str,
        response: Option<server::Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        if user != USER || !self.spec.methods.contains(&MethodKind::KeyboardInteractive) {
            return Ok(reject());
        }
        let answers: Vec<String> = response
            .map(|r| r.map(|b| String::from_utf8_lossy(&b).into_owned()).collect())
            .unwrap_or_default();
        self.seen.lock().expect("lock").kbd_responses.extend(answers.iter().cloned());
        match self.kbd_step {
            0 => {
                self.kbd_step = 1;
                Ok(Auth::Partial {
                    name: "Mooring test".into(),
                    instructions: "".into(),
                    prompts: vec![("Password: ".into(), false)].into(),
                })
            }
            1 if answers.first().map(String::as_str) == self.spec.password.as_deref() => {
                if self.spec.kbd_two_step {
                    self.kbd_step = 2;
                    Ok(Auth::Partial {
                        name: "".into(),
                        instructions: "".into(),
                        prompts: vec![("Verification code: ".into(), true)].into(),
                    })
                } else {
                    Ok(Auth::Accept)
                }
            }
            2 if answers.first().map(String::as_str) == Some(OTP) => Ok(Auth::Accept),
            _ => {
                self.kbd_step = 0;
                Ok(reject())
            }
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        self.sessions.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
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
        self.seen.lock().expect("lock").direct.push((host_to_connect.to_owned(), port_to_connect));
        forwarding::direct(channel, host_to_connect.to_owned(), port_to_connect, reply);
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut ServerSession,
    ) -> Result<bool, Self::Error> {
        Ok(forwarding::listen(&self.listeners, session.handle(), address, port).await)
    }

    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut ServerSession,
    ) -> Result<bool, Self::Error> {
        let ok = forwarding::cancel(&self.listeners, address, port);
        if ok {
            self.seen.lock().expect("lock").cancelled_forwards.push((address.to_owned(), port));
        }
        Ok(ok)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        self.seen.lock().expect("lock").pty = Some((term.to_owned(), col_width, row_height));
        session.channel_success(channel)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        // The shell is served through handler callbacks; an unread `Channel` would fill up.
        self.sessions.remove(&channel);
        self.shells.push(channel);
        session.channel_success(channel)?;
        session.data(channel, b"welcome\r\n".to_vec())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        // Only the shell echoes; forwarded and subsystem channels are served by their streams.
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

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        self.seen.lock().expect("lock").resizes.push((col_width, row_height));
        session.data(channel, format!("RESIZE {col_width}x{row_height}\r\n").into_bytes())
    }
}

// ---------------------------------------------------------------- client helpers

pub fn params(port: u16, secret: ConnectSecret) -> ConnectParams {
    ConnectParams {
        host: "127.0.0.1".to_owned(),
        port,
        username: Some(USER.to_owned()),
        secret,
        size: Size { width: 80, height: 24 },
    }
}

/// Options with the agent off (tests must not depend on the developer's agent).
pub fn options(known_hosts: &std::path::Path) -> SshOptions {
    let mut o = SshOptions::new(known_hosts);
    o.allow_agent = false;
    o
}

pub async fn connect(port: u16, secret: ConnectSecret, kh: &std::path::Path) -> SshSession {
    SshSession::connect(params(port, secret), options(kh)).await.expect("tcp connect")
}

pub async fn next(s: &mut SshSession) -> SessionEvent {
    tokio::time::timeout(Duration::from_secs(20), s.next_event())
        .await
        .expect("event within 20 s")
        .expect("no error")
        .expect("stream not ended")
}

pub async fn answer(s: &mut SshSession, id: u32, text: &str) {
    s.send(SessionInput::Answer { id, text: SecretString::from(text) })
        .await
        .expect("answer accepted");
}

/// Answer the TOFU prompt with "yes" and return its message.
pub async fn accept_tofu(s: &mut SshSession) -> String {
    match next(s).await {
        SessionEvent::Prompt { id, message, secret } => {
            assert!(!secret);
            answer(s, id, "yes").await;
            message
        }
        other => panic!("expected TOFU prompt, got {other:?}"),
    }
}

/// The next event must be `Connected`; returns its peer identity.
pub async fn expect_connected(s: &mut SshSession) -> Option<String> {
    match next(s).await {
        SessionEvent::Connected { peer_identity, .. } => peer_identity,
        other => panic!("expected Connected, got {other:?}"),
    }
}

pub async fn expect_closed(s: &mut SshSession) -> String {
    loop {
        match next(s).await {
            SessionEvent::Closed { reason } => return reason,
            SessionEvent::Bytes { .. } => {}
            other => panic!("expected Closed, got {other:?}"),
        }
    }
}

/// Collect output until it contains `needle`.
pub async fn read_until(s: &mut SshSession, needle: &str) -> String {
    let mut out = String::new();
    while !out.contains(needle) {
        match next(s).await {
            SessionEvent::Bytes { data } => out.push_str(&String::from_utf8_lossy(&data)),
            other => panic!("expected bytes, got {other:?} after {out:?}"),
        }
    }
    out
}

/// Pre-trust the server key in a fresh `known_hosts` file.
pub fn trust(kh: &std::path::Path, port: u16, key: &PublicKey) {
    let mut store = mooring_proto_ssh::KnownHosts::new();
    store.add_hashed("127.0.0.1", port, key).expect("add");
    store.save(kh).expect("save");
}

/// A password session against `spec`, connected with the shell banner consumed.
pub async fn connected(spec: ServerSpec) -> (SshSession, TestServer, tempfile::TempDir) {
    let server = start(spec).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let kh = dir.path().join("known_hosts");
    trust(&kh, server.port, &server.host_public);
    let secret = ConnectSecret::Password(SecretString::from(PASSWORD));
    let mut s = connect(server.port, secret, &kh).await;
    expect_connected(&mut s).await;
    read_until(&mut s, "welcome").await;
    (s, server, dir)
}
