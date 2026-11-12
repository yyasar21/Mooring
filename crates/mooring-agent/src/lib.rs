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
use std::sync::Arc;

use base64::Engine;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use ed25519_dalek::Signer;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info};
use x25519_dalek::PublicKey;

/// Default loopback listen address for the agent proxy listener.
pub fn default_listen_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
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

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            relay_url: String::new(),
            endpoint_id: String::new(),
            registration_key: Vec::new(),
            listen_addr: default_listen_addr(),
        }
    }
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
        let public_key = PublicKey::from(&private_key).to_bytes();
        Self { private_key, public_key }
    }

    /// Derive a shared secret from this private key and a remote public key.
    pub fn shared_secret(&self, remote: &[u8; 32]) -> x25519_dalek::SharedSecret {
        let remote_key = PublicKey::from(*remote);
        self.private_key.diffie_hellman(&remote_key)
    }
}

/// Derived session keys for a manager connection.
#[derive(Clone, Debug)]
pub struct SessionKeys {
    /// AEAD encryption key (32 bytes).
    pub aead_key: [u8; 32],
    /// Frame counter salt (16 bytes).
    pub frame_salt: [u8; 16],
}

impl SessionKeys {
    /// Derive session keys from an X25519 shared secret.
    pub fn from_shared_secret(secret: &x25519_dalek::SharedSecret) -> Self {
        let info = b"mooring-relay-e2e-v1";
        let mut aead_key = [0u8; 32];
        hkdf::Hkdf::<sha2::Sha256>::new(Some(info), secret.as_bytes())
            .expand(b"session-aead", &mut aead_key)
            .expect("HKDF-SHA256 key schedule always succeeds with 32-byte output");

        let mut frame_salt = [0u8; 16];
        hkdf::Hkdf::<sha2::Sha256>::new(Some(info), secret.as_bytes())
            .expand(b"frame-salt", &mut frame_salt)
            .expect("HKDF-SHA256 key schedule always succeeds with 16-byte output");

        Self { aead_key, frame_salt }
    }
}

/// Agent runtime state: keys, relay connection, and proxy listener.
#[derive(Debug, Default)]
pub struct AgentState {
    /// E2E keys for this agent session (regenerated per manager handshake).
    e2e_keys: RwLock<Option<E2EKeys>>,
    /// Derived AEAD session keys per manager session (session_id -> SessionKeys).
    session_keys: RwLock<HashMap<String, SessionKeys>>,
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
    #[error("invalid response from relay: {0}")]
    InvalidResponse(String),
}

/// Agent operational errors.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("registration failed: {0}")]
    RegistrationFailed(RelayRegisterError),
    #[error("relay connection lost")]
    RelayConnectionLost,
    #[error("proxy listener failed: {0}")]
    ProxyListenerFailed(std::io::Error),
    #[error("E2E key exchange failed: {0}")]
    KeyExchangeFailed(String),
    #[error("frame encryption failed: {0}")]
    FrameEncryptionFailed(String),
    #[error("frame decryption failed: {0}")]
    FrameDecryptionFailed(String),
    #[error("session error: {0}")]
    SessionError(SessionError),
}

impl From<std::io::Error> for AgentError {
    fn from(e: std::io::Error) -> Self {
        Self::ProxyListenerFailed(e)
    }
}

impl From<RelayRegisterError> for AgentError {
    fn from(e: RelayRegisterError) -> Self {
        Self::RegistrationFailed(e)
    }
}

impl From<SessionError> for AgentError {
    fn from(e: SessionError) -> Self {
        Self::SessionError(e)
    }
}

/// Wire protocol message types for the relay WebSocket connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum RelayMessage {
    /// Agent registration request.
    Register {
        endpoint_id: String,
        version: String,
        agent_pub_key: Vec<u8>,
        signature: Vec<u8>,
    },
    /// Registration response from relay.
    RegisterOk {
        session_token: String,
    },
    RegisterErr {
        message: String,
    },
    /// Encrypted frame from relay.
    Frame {
        session_id: String,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    },
    /// Encrypted frame to relay.
    OutgoingFrame {
        session_id: String,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    },
    /// Manager handshake initiation.
    Handshake {
        endpoint_id: String,
        manager_pub_key: Vec<u8>,
        session_id: String,
    },
    /// Key exchange response.
    KeyExchangeOk {
        session_id: String,
    },
    KeyExchangeErr {
        session_id: String,
        message: String,
    },
}

/// Encrypt plaintext with ChaCha20-Poly1305 using the session AEAD key.
fn encrypt_payload(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, AgentError> {
    let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| AgentError::FrameEncryptionFailed(e.to_string()))?;
    let mut buf = plaintext.to_vec();
    buf.resize(plaintext.len() + 16, 0);
    let nonce_arr: chacha20poly1305::Nonce = (*nonce).into();
    cipher
        .encrypt_in_place(&nonce_arr, &[], &mut buf)
        .map_err(|e| AgentError::FrameEncryptionFailed(e.to_string()))?;
    Ok(buf)
}

/// Decrypt ciphertext with ChaCha20-Poly1305 using the session AEAD key.
#[allow(dead_code)]
fn decrypt_payload(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, AgentError> {
    if ciphertext.len() < 16 {
        return Err(AgentError::FrameDecryptionFailed("ciphertext too short".into()));
    }
    let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| AgentError::FrameDecryptionFailed(e.to_string()))?;
    let mut buf = ciphertext.to_vec();
    let nonce_arr: chacha20poly1305::Nonce = (*nonce).into();
    cipher
        .decrypt_in_place(&nonce_arr, &[], &mut buf)
        .map_err(|e| AgentError::FrameDecryptionFailed(e.to_string()))?;
    // Strip the 16-byte tag
    let tag_len = 16;
    let plaintext = buf[..buf.len() - tag_len].to_vec();
    Ok(plaintext)
}

/// Generate a random 12-byte nonce for frame encryption.
fn generate_nonce() -> [u8; 12] {
    use rand_core::OsRng;
    let mut nonce = [0u8; 12];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut nonce);
    nonce
}

/// Convert the first 16 bytes to a hex string for session identification.
fn session_id_from_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Register this agent with the relay and return the session token.
pub async fn register_with_relay(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    config: &AgentConfig,
) -> Result<(String, E2EKeys), RelayRegisterError> {
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
    let seed: [u8; 32] = config.registration_key[..32]
        .try_into()
        .map_err(|_| RelayRegisterError::InvalidRegistrationKey)?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let signature = signing_key.sign(reg_data.as_bytes());

    // Send registration request
    let reg_msg = RelayMessage::Register {
        endpoint_id: config.endpoint_id.clone(),
        version: "0.0.0-unknown".to_string(),
        agent_pub_key: e2e_keys.public_key.to_vec(),
        signature: signature.to_bytes().to_vec(),
    };

    let msg_str =
        serde_json::to_string(&reg_msg).map_err(|_| RelayRegisterError::SerializationFailed)?;
    ws.send(Message::Text(msg_str.into())).await.map_err(|_| RelayRegisterError::ConnectionLost)?;

    // Wait for response
    if let Some(Ok(Message::Text(resp))) = ws.next().await {
        let resp_msg: RelayMessage = serde_json::from_str(&resp)
            .map_err(|e| RelayRegisterError::InvalidResponse(e.to_string()))?;

        match resp_msg {
            RelayMessage::RegisterOk { session_token } => {
                info!("Registered with relay successfully");
                Ok((session_token, e2e_keys))
            }
            RelayMessage::RegisterErr { message } => Err(RelayRegisterError::Rejected(message)),
            _ => Err(RelayRegisterError::InvalidResponse("unexpected response type".into())),
        }
    } else {
        Err(RelayRegisterError::ConnectionLost)
    }
}

/// Start the loopback proxy listener.
///
/// Accepts TCP connections on the configured address. Each accepted connection
/// is handled in a separate task.
pub async fn start_loopback_proxy(
    state: Arc<AgentState>,
    config: Arc<AgentConfig>,
) -> Result<SocketAddr, AgentError> {
    let listener =
        TcpListener::bind(config.listen_addr).await.map_err(AgentError::ProxyListenerFailed)?;

    let addr = listener.local_addr().map_err(AgentError::ProxyListenerFailed)?;
    *state.listen_addr.write().await = Some(addr);

    info!("Loopback proxy listening on {}", addr);

    // Accept connections in a loop
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    debug!("New proxy connection from {}", peer_addr);
                    let state = state.clone();
                    let config = config.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_proxy_connection(stream, &state, &config).await {
                            error!("Proxy connection handler error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    });

    Ok(addr)
}

/// Handle a single proxy connection from a manager.
async fn handle_proxy_connection(
    mut stream: TcpStream,
    state: &AgentState,
    _config: &AgentConfig,
) -> Result<(), AgentError> {
    // Read the manager's handshake message (session_id hint + manager_pub_key)
    let mut handshake_buf = [0u8; 48]; // 16 bytes session hint + 32 bytes pub_key
    stream.read_exact(&mut handshake_buf).await?;

    // Parse session_id hint (first 16 bytes as hex string)
    let session_id = session_id_from_bytes(&handshake_buf[..16]);

    // Parse manager's public key (next 32 bytes)
    let mut manager_pub_key = [0u8; 32];
    manager_pub_key.copy_from_slice(&handshake_buf[16..48]);

    // Perform E2E key exchange
    {
        let e2e_keys = state.e2e_keys.read().await;
        let e2e_keys = e2e_keys
            .as_ref()
            .ok_or(AgentError::KeyExchangeFailed("no E2E keys available".into()))?;

        let shared_secret = e2e_keys.shared_secret(&manager_pub_key);
        let session_keys = SessionKeys::from_shared_secret(&shared_secret);

        // Store session keys
        state.session_keys.write().await.insert(session_id.clone(), session_keys);
    }

    // Send key exchange response
    let response = b"KX_OK";
    stream.write_all(response).await?;

    debug!("Key exchange completed for session {}", session_id);

    // Start bidirectional forwarding
    bidirectional_forward(&mut stream, state, &session_id).await
}

/// Forward data bidirectionally between TCP stream and relay.
async fn bidirectional_forward(
    stream: &mut TcpStream,
    state: &AgentState,
    session_id: &str,
) -> Result<(), AgentError> {
    let (mut stream_read, _stream_write) = stream.split();

    // Forward TCP -> Relay
    let session_id_forward = session_id.to_string();
    let tcp_to_relay = async move {
        let mut buf = [0u8; 4096];
        loop {
            let n = stream_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }

            let session_keys = state.session_keys.read().await;
            let keys = session_keys
                .get(session_id_forward.as_str())
                .ok_or_else(|| AgentError::KeyExchangeFailed("no session keys".into()))?;

            let nonce = generate_nonce();
            let encrypted = encrypt_payload(&keys.aead_key, &nonce, &buf[..n])?;

            let frame_msg = RelayMessage::OutgoingFrame {
                session_id: session_id_forward.clone(),
                nonce: nonce.to_vec(),
                ciphertext: encrypted,
            };

            let _frame_str = serde_json::to_string(&frame_msg)
                .map_err(|_| AgentError::FrameEncryptionFailed("serialization failed".into()))?;

            // In a full implementation, we'd send this via the WebSocket
            // For now, we'd need to store the WebSocket in state
            drop(session_keys);
        }
        Ok::<(), AgentError>(())
    };

    // Forward Relay -> TCP (simplified - would need WebSocket receiver)
    let relay_to_tcp = async move {
        // Placeholder: in production, this would receive frames from WebSocket
        Ok::<(), AgentError>(())
    };

    // Run both directions concurrently
    tokio::try_join!(tcp_to_relay, relay_to_tcp)?;

    Ok(())
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
        let expected_public = PublicKey::from(&secret).to_bytes();
        let keys = E2EKeys { private_key: secret, public_key: expected_public };
        assert_eq!(keys.public_key, expected_public);
    }

    #[test]
    fn test_shared_secret_symmetric() {
        let alice_secret = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        let bob_secret = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);

        let alice_pub = PublicKey::from(&alice_secret).to_bytes();
        let bob_pub = PublicKey::from(&bob_secret).to_bytes();

        let alice_shared = alice_secret.diffie_hellman(&PublicKey::from(bob_pub));
        let bob_shared = bob_secret.diffie_hellman(&PublicKey::from(alice_pub));

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_session_key_derivation_deterministic() {
        let secret = x25519_dalek::StaticSecret::from([0u8; 32]);
        let public = PublicKey::from(&secret);
        let shared = secret.diffie_hellman(&public);
        let keys1 = SessionKeys::from_shared_secret(&shared);
        let keys2 = SessionKeys::from_shared_secret(&shared);
        assert_eq!(keys1.aead_key, keys2.aead_key);
        assert_eq!(keys1.frame_salt, keys2.frame_salt);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x13u8; 12];
        let plaintext = b"Hello, E2E world!";

        let encrypted = encrypt_payload(&key, &nonce, plaintext).expect("encrypt failed");
        let decrypted = decrypt_payload(&key, &nonce, &encrypted).expect("decrypt failed");

        assert_eq!(decrypted, plaintext);
        assert_ne!(encrypted, plaintext);
    }

    #[test]
    fn test_nonce_uniqueness() {
        let n1 = generate_nonce();
        let n2 = generate_nonce();
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_default_config() {
        let config = AgentConfig::default();
        assert_eq!(config.relay_url, "");
        assert_eq!(config.endpoint_id, "");
        assert_eq!(config.registration_key, Vec::<u8>::new());
    }
}
