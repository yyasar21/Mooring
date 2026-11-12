//! `mooring-relay`: stateless relay proxy for Mooring agent connections (ADR-0029).
//!
//! The relay accepts WebSocket connections from agents (authenticated with an Ed25519
//! registration token) and from managers (authenticated with a per-session token). It
//! routes frames between a manager and the agent identified by `endpoint_id`, using an
//! X25519+HKDF E2E key exchange so the relay never sees plaintext.
//!
//! ## Architecture
//!
//! * Stateless: no disk state, in-memory endpoint registry with TTL.
//! * E2E only: relay sees ciphertext frames (plaintext header with `endpoint_id` +
//!   AEAD-encrypted payload, ADR-0029 §4.2).
//! * Registration: operators sign short-lived Ed25519 tokens distributed to agents
//!   out-of-band. The relay validates the signature before accepting registration.
//! * Audit: every connect/disconnect/forward event is logged via `mooring-audit`.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::time::Duration;

use base64::Engine;
use tokio::sync::RwLock;

/// Maximum time an agent stays in the registry after last activity (30 min).
const AGENT_TTL: Duration = Duration::from_secs(30 * 60);

/// Endpoint ID type alias (UUID v4 string).
pub type EndpointId = String;

/// Session token type alias (opaque string, issued by relay after key exchange).
pub type SessionToken = String;

/// Agent registration payload sent by an agent during handshake.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRequest {
    /// Agent UUID v4 (stable across reboots).
    pub endpoint_id: EndpointId,
    /// Agent version string.
    pub version: String,
    /// Ed25519 public key for this session's key exchange (DER-encoded).
    pub agent_pub_key: Vec<u8>,
    /// Ed25519 signature over `endpoint_id` + `version` + `agent_pub_key`,
    /// signed with the operator-issued registration key.
    pub signature: Vec<u8>,
}

/// Manager handshake payload.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagerHandshake {
    /// Target agent endpoint ID.
    pub endpoint_id: EndpointId,
    /// Manager's X25519 public key (DER-encoded).
    pub manager_pub_key: Vec<u8>,
}

/// Relay frame wire format: `endpoint_id` header + AEAD-encrypted payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayFrame {
    /// Target endpoint ID (visible to relay for routing; always lowercase).
    pub endpoint_id: EndpointId,
    /// AEAD-encrypted payload (chacha20poly1305).
    pub ciphertext: Vec<u8>,
    /// Nonce used for this frame (96-bit, stored separately from ciphertext).
    pub nonce: [u8; 12],
}

/// In-memory agent registry entry.
#[derive(Debug, Clone)]
struct AgentEntry {
    /// Agent's X25519 public key (for key exchange).
    agent_pub_key: Vec<u8>,
    /// Last activity timestamp.
    last_seen: std::time::Instant,
}

/// Stateful relay runtime (endpoint registry, key material, session tracking).
#[derive(Debug, Default)]
pub struct RelayState {
    /// Registered agents: `endpoint_id -> AgentEntry`.
    agents: RwLock<HashMap<EndpointId, AgentEntry>>,
    /// Operator Ed25519 public key for validating registration tokens.
    operator_pub_key: RwLock<Option<Vec<u8>>>,
}

impl RelayState {
    /// Create a new relay state with the operator's Ed25519 public key.
    pub fn new(operator_pub_key: Vec<u8>) -> Self {
        Self {
            agents: RwLock::new(HashMap::new()),
            operator_pub_key: RwLock::new(Some(operator_pub_key)),
        }
    }

    /// Set the operator public key (called at startup from config).
    pub async fn set_operator_key(&self, key: Vec<u8>) {
        *self.operator_pub_key.write().await = Some(key);
    }

    /// Validate and register an agent.
    pub async fn register_agent(&self, req: &RegistrationRequest) -> Result<(), RelayError> {
        let op_key = self.operator_pub_key.read().await;
        let op_key = op_key.as_ref().ok_or(RelayError::OperatorKeyMissing)?;

        if !validate_ed25519(op_key, &req.signature, &RelayState::serialize_reg_data(req)) {
            return Err(RelayError::InvalidSignature);
        }

        let mut agents = self.agents.write().await;
        agents.insert(
            req.endpoint_id.clone(),
            AgentEntry {
                agent_pub_key: req.agent_pub_key.clone(),
                last_seen: std::time::Instant::now(),
            },
        );
        Ok(())
    }

    /// Look up an agent entry, updating its TTL. Returns `None` if not registered.
    pub async fn get_agent(&self, endpoint_id: &str) -> Option<Vec<u8>> {
        let mut agents = self.agents.write().await;
        if let Some(entry) = agents.get_mut(endpoint_id) {
            entry.last_seen = std::time::Instant::now();
            Some(entry.agent_pub_key.clone())
        } else {
            None
        }
    }

    /// Remove expired agents from the registry.
    pub async fn prune_expired(&self) -> usize {
        let now = std::time::Instant::now();
        let mut agents = self.agents.write().await;
        let before = agents.len();
        agents.retain(|_, entry| now.duration_since(entry.last_seen) < AGENT_TTL);
        before - agents.len()
    }

    /// Serialize registration data for signature verification.
    fn serialize_reg_data(req: &RegistrationRequest) -> Vec<u8> {
        format!(
            "{}:{}:{}",
            req.endpoint_id,
            req.version,
            base64::engine::general_purpose::STANDARD.encode(&req.agent_pub_key)
        )
        .into_bytes()
    }
}

/// Relay errors.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("operator key not configured")]
    OperatorKeyMissing,
    #[error("invalid registration signature")]
    InvalidSignature,
    #[error("agent not registered: {0}")]
    AgentNotFound(EndpointId),
    #[error("E2E key exchange failed: {0}")]
    KeyExchangeFailed(String),
    #[error("frame decrypt error")]
    DecryptFailed,
    #[error("connection limit reached")]
    ConnectionLimit,
    #[error("invalid frame format")]
    InvalidFrame,
}

/// Validate an Ed25519 signature.
fn validate_ed25519(public_key: &[u8], signature: &[u8], message: &[u8]) -> bool {
    use ed25519_dalek::Verifier;

    // Ed25519 public keys are 32 bytes, signatures are 64 bytes
    let Ok(pub_key_bytes): Result<[u8; 32], _> = public_key.try_into() else {
        return false;
    };
    let Ok(sig_bytes): Result<[u8; 64], _> = signature.try_into() else {
        return false;
    };
    let Ok(pub_key) = ed25519_dalek::VerifyingKey::from_bytes(&pub_key_bytes) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    pub_key.verify(message, &sig).is_ok()
}

/// Derive a per-session AEAD key from the X25519 shared secret (HKDF-SHA256).
pub fn derive_session_key(shared_secret: &[u8]) -> [u8; 32] {
    let info = b"mooring-relay-e2e-v1";
    let mut okm = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(Some(info), shared_secret)
        .expand(b"session-aead", &mut okm)
        .expect("HKDF-SHA256 key schedule always succeeds with 32-byte output");
    okm
}

/// Derive a frame counter salt (HKDF-SHA256, separate info context).
pub fn derive_frame_salt(shared_secret: &[u8]) -> [u8; 16] {
    let info = b"mooring-relay-e2e-v1";
    let mut salt = [0u8; 16];
    hkdf::Hkdf::<sha2::Sha256>::new(Some(info), shared_secret)
        .expand(b"frame-salt", &mut salt)
        .expect("HKDF-SHA256 key schedule always succeeds with 16-byte output");
    salt
}

/// Encrypt a plaintext frame payload with ChaCha20-Poly1305.
pub fn encrypt_frame(
    key: &[u8],
    nonce: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, RelayError> {
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};

    let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| RelayError::KeyExchangeFailed(e.to_string()))?;
    let mut buf = plaintext.to_vec();
    buf.resize(plaintext.len() + 16, 0); // AEAD appends 16-byte tag
    let nonce_arr: chacha20poly1305::Nonce = (*nonce).into();
    cipher
        .encrypt_in_place(&nonce_arr, &[], &mut buf)
        .map_err(|_| RelayError::DecryptFailed)?;
    Ok(buf)
}

/// Decrypt a ciphertext frame with ChaCha20-Poly1305.
pub fn decrypt_frame(
    key: &[u8],
    nonce: &[u8; 12],
    ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>, RelayError> {
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};

    if ciphertext_with_tag.len() < 16 {
        return Err(RelayError::DecryptFailed);
    }
    let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| RelayError::KeyExchangeFailed(e.to_string()))?;
    let mut buf = ciphertext_with_tag.to_vec();
    let nonce_arr: chacha20poly1305::Nonce = (*nonce).into();
    cipher
        .decrypt_in_place(&nonce_arr, &[], &mut buf)
        .map_err(|_| RelayError::DecryptFailed)?;
    // Strip the 16-byte tag
    buf.truncate(buf.len() - 16);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_session_key_deterministic() {
        let secret = [0xABu8; 32];
        let key1 = derive_session_key(&secret);
        let key2 = derive_session_key(&secret);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_frame_salt_deterministic() {
        let secret = [0xCDu8; 32];
        let salt1 = derive_frame_salt(&secret);
        let salt2 = derive_frame_salt(&secret);
        assert_eq!(salt1, salt2);
    }
}
