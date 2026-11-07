//! A minimal fake ssh-agent on a Unix socket that holds one FIDO2 key (ADR-0024 test plan):
//! it lists `sk-ssh-ed25519@openssh.com` identities and signs with a plain Ed25519 key under
//! the `sk` wire format (`sha256(application) ‖ flags ‖ counter ‖ sha256(data)`), the way
//! `ssh-agent` + an authenticator would. Test material only. Knobs model a hostile or slow
//! agent.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::keys::signature::Signer;
use russh::keys::ssh_key::sha2::{Digest, Sha256};
use russh::keys::PrivateKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

/// How the fake behaves.
#[derive(Clone)]
pub struct Behaviour {
    /// Key blobs listed by `REQUEST_IDENTITIES`.
    pub listed: Vec<Vec<u8>>,
    /// The Ed25519 key that signs (its point is the sk key's).
    pub signer: PrivateKey,
    /// FIDO application signed over.
    pub application: String,
    /// Flags byte of every signature (0x01 = user present).
    pub flags: u8,
    /// Wait this long before answering a sign request (touch timeout tests).
    pub delay: Duration,
    /// Answer sign requests with `SSH_AGENT_FAILURE`.
    pub refuse: bool,
}

/// A running fake agent.
pub struct FakeAgent {
    pub path: PathBuf,
    /// Blobs of every sign request received.
    pub signed: Arc<Mutex<Vec<Vec<u8>>>>,
    _dir: tempfile::TempDir,
}

fn put(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&u32::try_from(b.len()).expect("len").to_be_bytes());
    out.extend_from_slice(b);
}

fn take<'a>(buf: &mut &'a [u8]) -> &'a [u8] {
    let len = u32::from_be_bytes(buf[..4].try_into().expect("4")) as usize;
    let (s, rest) = buf[4..].split_at(len);
    *buf = rest;
    s
}

fn sk_signature(b: &Behaviour, data: &[u8]) -> Vec<u8> {
    let counter = 42u32;
    let mut msg = Sha256::digest(b.application.as_bytes()).to_vec();
    msg.push(b.flags);
    msg.extend_from_slice(&counter.to_be_bytes());
    msg.extend_from_slice(&Sha256::digest(data));
    let raw: russh::keys::ssh_key::Signature = b.signer.try_sign(&msg).expect("sign");
    let mut sig = Vec::new();
    put(&mut sig, b"sk-ssh-ed25519@openssh.com");
    put(&mut sig, raw.as_bytes());
    sig.push(b.flags);
    sig.extend_from_slice(&counter.to_be_bytes());
    sig
}

async fn serve(mut s: tokio::net::UnixStream, b: Behaviour, signed: Arc<Mutex<Vec<Vec<u8>>>>) {
    loop {
        let mut len = [0u8; 4];
        if s.read_exact(&mut len).await.is_err() {
            return;
        }
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        if s.read_exact(&mut body).await.is_err() {
            return;
        }
        let reply = match body[0] {
            11 => {
                let mut r = vec![12u8];
                r.extend_from_slice(&u32::try_from(b.listed.len()).expect("n").to_be_bytes());
                for blob in &b.listed {
                    put(&mut r, blob);
                    put(&mut r, b"fake sk key");
                }
                r
            }
            13 => {
                let mut rest = &body[1..];
                let blob = take(&mut rest).to_vec();
                let data = take(&mut rest).to_vec();
                signed.lock().expect("lock").push(blob);
                tokio::time::sleep(b.delay).await;
                if b.refuse {
                    vec![5u8]
                } else {
                    let mut r = vec![14u8];
                    put(&mut r, &sk_signature(&b, &data));
                    r
                }
            }
            _ => vec![5u8],
        };
        let mut frame = Vec::new();
        put(&mut frame, &reply);
        if s.write_all(&frame).await.is_err() {
            return;
        }
    }
}

/// Start the fake on a socket in a fresh temp dir.
pub fn start(b: Behaviour) -> FakeAgent {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&path).expect("bind");
    let signed = Arc::new(Mutex::new(Vec::new()));
    let s2 = Arc::clone(&signed);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(serve(stream, b.clone(), Arc::clone(&s2)));
        }
    });
    FakeAgent { path, signed, _dir: dir }
}

impl FakeAgent {
    pub fn path(&self) -> &Path {
        &self.path
    }
}
