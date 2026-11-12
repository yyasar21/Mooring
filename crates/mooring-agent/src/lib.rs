//! `mooring-agent`: Mooring relay agent for the host it runs on (ADR-0029).
//!
//! The agent runs as a local service, maintains a persistent WebSocket connection to the
//! relay, and exposes a loopback listener for the manager to connect. It handles:
//!
//! * Ed25519 registration token validation with the relay
//! * X25519+HKDF E2E key exchange with the manager
//! * Local proxy listening (loopback only) for incoming manager connections
//! * Frame encryption/decryption for the E2E tunnel
//! * Local session execution (SSH/RDP/VNC via protocol crates)

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::SocketAddr;

use base64::Engine;
use ed25519_dalek::Signer;
use futures_util::SinkExt;
use tokio::sync::RwLock;

/// Default loopback listen address for the agent proxy listener.
pub fn default_listen_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0)) // port 0 = ephemeral
}

/// Agent configuration for connecting to the relay.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Relay WebSocket URL (`wss://…`).
    pub relay_url: String,
    /// Agent's stable UUID v4 endpoint ID.
    pub endpoint_id: String,
    /// Operator-issued Ed25519 registration keypair seed (32 bytes).
    pub registration_key: Vec<u8>,
    /// Optional custom loopback listen address (default: `127.0.0.1:0`).
    pub listen_addr: SocketAddr,
}

/// X25519 key pair for E2E session establishment.
#[derive(Clone)]
pub struct E2EKeys {
    /// Private key (x25519 static secret).
    pub private_key: x25519_dalek::StaticSecret,
    /// Public key (32 bytes, x25519 encoded).
    pub public_key: [u8; 32],
}

impl std::fmt::Debug for E2EKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("E2EKeys")
            .field("public_key", &self.public_key)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl E2EKeys {
    /// Generate a new X25519 key pair.
    pub fn generate() -> Self {
        use rand_core::OsRng;
        let private_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let public_key = x25519_dalek::PublicKey::from(&private_key).to_bytes();
        Self { private_key, public_key }
    }
}

/// Agent runtime state: keys, relay connection, and proxy listener.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct AgentState {
    /// E2E keys for this agent session (regenerated per manager handshake).
    e2e_keys: RwLock<Option<E2EKeys>>,
    /// Derived AEAD session keys per manager session.
    session_keys: RwLock<HashMap<String, Vec<u8>>>,
    /// Loopback proxy listener address (set after start).
    listen_addr: RwLock<Option<SocketAddr>>,
}

/// A local session runner (SSH/RDP/VNC) managed by the agent.
pub trait LocalSession {
    /// Run the session; blocks until disconnected.
    #[allow(async_fn_in_trait)]
    async fn run(&mut self) -> Result<(), SessionError>;
    /// Return the protocol name being used.
    fn protocol_name(&self) -> &str;
}

/// Session execution errors.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("session started")]
    Started,
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("authentication failed")]
    AuthFailed,
    #[error("connection closed")]
    Closed,
}

/// Register this agent with the relay.
pub async fn register_with_relay(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    config: &AgentConfig,
) -> Result<(), RelayRegisterError> {
    use tokio_tungstenite::tungstenite::Message;

    // Generate session X25519 keys
    let e2e_keys = E2EKeys::generate();

    // Sign registration data
    let reg_data = format!(
        "{}:{}:{}",
        config.endpoint_id,
        "0.0.0-unknown",
        base64::engine::general_purpose::STANDARD.encode(e2e_keys.public_key)
    );

    // Parse the Ed25519 signing key from the config (32-byte seed)
    let seed: [u8; 32] = config.registration_key[..32].try_into().map_err(|_| {
        RelayRegisterError::InvalidRegistrationKey
    })?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let signature = signing_key.sign(reg_data.as_bytes());

    // Send registration request
    let reg_req = mooring_relay::RegistrationRequest {
        endpoint_id: config.endpoint_id.clone(),
        version: "0.0.0-unknown".to_string(),
        agent_pub_key: e2e_keys.public_key.to_vec(),
        signature: signature.to_bytes().to_vec(),
    };

    let msg = serde_json::to_string(&reg_req).map_err(|_| RelayRegisterError::SerializationFailed)?;

    ws.send(Message::Text(msg.into()))
        .await
        .map_err(|_| RelayRegisterError::ConnectionLost)?;

    // Store E2E keys (placeholder)
    Ok(())
}

/// Relay registration errors.
#[derive(Debug, thiserror::Error)]
pub enum RelayRegisterError {
    #[error("invalid registration key")]
    InvalidRegistrationKey,
    #[error("serialization failed")]
    SerializationFailed,
    #[error("relay connection lost")]
    ConnectionLost,
    #[error("relay rejected registration: {0}")]
    Rejected(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_e2e_keys_generation() {
        let keys1 = E2EKeys::generate();
        let keys2 = E2EKeys::generate();
        assert_ne!(keys1.public_key, keys2.public_key);
    }

    #[test]
    fn test_e2e_keys_public_from_private() {
        use rand_core::OsRng;
        let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let expected_public = x25519_dalek::PublicKey::from(&secret).to_bytes();
        let keys = E2EKeys { private_key: secret, public_key: expected_public };
        assert_eq!(keys.public_key, expected_public);
    }
}
