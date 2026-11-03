//! The russh client handler: host-key trust decision (ADR-0007 §Host-key trust).
//!
//! Also routes server-opened `forwarded-tcpip` channels to their remote forward.

use std::path::PathBuf;
use std::sync::Arc;

use russh::client;
use russh::keys::{PublicKey, PublicKeyOrCertificate};
use secrecy::ExposeSecret;

use crate::audit::TrustEvent;
use crate::known_hosts::{describe_key, fingerprint, KnownHosts, TrustDecision};
use crate::shared::Shared;

/// russh `client::Handler` for one Mooring SSH connection.
pub struct ClientHandler {
    host: String,
    port: u16,
    known_hosts_path: PathBuf,
    shared: Arc<Shared>,
    /// Key the user trusted in this connection (re-key must not prompt again).
    accepted: Option<PublicKey>,
}

impl std::fmt::Debug for ClientHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientHandler")
            .field("host", &self.host)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl ClientHandler {
    pub(crate) fn new(
        host: String,
        port: u16,
        known_hosts_path: PathBuf,
        shared: Arc<Shared>,
    ) -> Self {
        Self { host, port, known_hosts_path, shared, accepted: None }
    }

    async fn decide(&mut self, key: &PublicKey) -> bool {
        if self.accepted.as_ref().is_some_and(|k| k.key_data() == key.key_data()) {
            return true;
        }
        let described = describe_key(key);
        self.shared.set_peer(described.clone());
        let path = self.known_hosts_path.clone();
        let Ok(Ok(store)) = tokio::task::spawn_blocking(move || KnownHosts::load(&path)).await
        else {
            tracing::warn!("known_hosts could not be read");
            self.shared.set_reason("known_hosts could not be read");
            return false;
        };
        match store.check(&self.host, self.port, key) {
            TrustDecision::Known => {
                self.accepted = Some(key.clone());
                true
            }
            TrustDecision::Mismatch { expected_fp } => {
                let presented = fingerprint(key);
                self.shared.audit.push(TrustEvent::HostKeyMismatch {
                    host: self.host.clone(),
                    port: self.port,
                    expected: expected_fp.clone(),
                    presented: presented.clone(),
                });
                self.shared.set_reason(format!(
                    "HOST KEY CHANGED for {}: expected {expected_fp}, got {presented}",
                    self.host
                ));
                false
            }
            TrustDecision::Unknown => self.ask_trust(key, described).await,
        }
    }

    async fn ask_trust(&mut self, key: &PublicKey, described: String) -> bool {
        let message = format!("{}:{} {described}  — trust this host?", self.host, self.port);
        let answer = self.shared.broker.ask(&self.shared.events, message, false).await;
        if self.shared.is_closing() {
            self.shared.set_reason("closed by user");
            return false;
        }
        let yes = answer.is_some_and(|a| a.expose_secret().trim().eq_ignore_ascii_case("yes"));
        if !yes {
            self.shared.audit.push(TrustEvent::HostKeyRejected {
                host: self.host.clone(),
                port: self.port,
                fingerprint: fingerprint(key),
            });
            self.shared.set_reason("host key not trusted");
            return false;
        }
        let (path, host, port, k) =
            (self.known_hosts_path.clone(), self.host.clone(), self.port, key.clone());
        let saved = tokio::task::spawn_blocking(move || {
            let mut store = KnownHosts::load(&path)?;
            store.add_hashed(&host, port, &k)?;
            store.save(&path)
        })
        .await;
        if !matches!(saved, Ok(Ok(()))) {
            tracing::warn!("host key trusted for this session but could not be stored");
        }
        self.shared.audit.push(TrustEvent::HostKeyAdded {
            host: self.host.clone(),
            port: self.port,
            key_type: key.algorithm().as_str().to_owned(),
            fingerprint: fingerprint(key),
        });
        self.accepted = Some(key.clone());
        true
    }
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = server_public_key else {
            self.shared.set_reason("host certificates are not supported yet");
            return Ok(false);
        };
        Ok(self.decide(key).await)
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<client::Msg>,
        connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let route = self.shared.forwards.route(connected_address, connected_port);
        crate::forward_io::accept_forwarded(route, channel, reply);
        Ok(())
    }

    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        names: &russh::Names,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        tracing::info!(
            kex = names.kex.as_ref(),
            host_key = %names.key,
            cipher = names.cipher.as_ref(),
            mac = names.client_mac.as_ref(),
            "ssh algorithms negotiated"
        );
        Ok(())
    }
}
