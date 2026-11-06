//! Secret bundles and raw inputs of the [`PlanBuilder`](crate::PlanBuilder).

use mooring_core::{CredentialKind, Protocol, SecretName};
use zeroize::{Zeroize, Zeroizing};

/// Plaintext secrets of one credential, only for plaintext sources with the opt-in
/// (owner decision 16). Zeroized on drop, never serialised, `Debug` prints names only.
#[derive(Default, PartialEq, Eq)]
pub struct SecretBundle {
    entries: Vec<(SecretName, Zeroizing<Vec<u8>>)>,
}

impl SecretBundle {
    /// Add one secret.
    pub fn push(&mut self, name: SecretName, value: Zeroizing<Vec<u8>>) {
        self.entries.push((name, value));
    }

    /// `(name, bytes)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (SecretName, &[u8])> {
        self.entries.iter().map(|(n, v)| (*n, v.as_slice()))
    }

    /// Whether any secret is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl std::fmt::Debug for SecretBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.entries.iter().map(|(n, _)| n.as_str()).collect();
        f.debug_struct("SecretBundle").field("names", &names).finish()
    }
}

impl Drop for SecretBundle {
    fn drop(&mut self) {
        for (_, v) in &mut self.entries {
            v.zeroize();
        }
    }
}

/// Input of [`PlanBuilder::connection`]; everything raw, validated by the builder.
#[derive(Debug, Clone, Default)]
pub struct NewConnection {
    /// Display name.
    pub name: String,
    /// Protocol.
    pub protocol: Option<Protocol>,
    /// Host or URL.
    pub host: String,
    /// Port, already parsed by [`PlanBuilder::port`].
    pub port: Option<u16>,
    /// Username.
    pub user: Option<String>,
    /// Domain.
    pub domain: Option<String>,
    /// Folder key.
    pub folder: Option<String>,
    /// Credential key.
    pub credential: Option<String>,
    /// Tags.
    pub tags: Vec<String>,
}

/// Input of [`PlanBuilder::credential`].
#[derive(Debug)]
pub struct NewCredential {
    /// Display name.
    pub name: String,
    /// Kind.
    pub kind: CredentialKind,
    /// Plaintext fields.
    pub fields: serde_json::Value,
    /// Secrets.
    pub secrets: Option<SecretBundle>,
    /// OpenSSH key file path.
    pub key_file: Option<String>,
}
