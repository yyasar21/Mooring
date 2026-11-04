//! `IpcError { code, message }`: the only error shape that crosses IPC (ADR-0003, ADR-0008).
//!
//! `code` is a stable `<area>.<reason>` string the UI switches on. `message` is short,
//! user-facing and never contains secret material or internal detail (SQL, paths, OS errors):
//! internal causes are logged with `tracing` and replaced by a fixed sentence.

use mooring_core::credential::CredentialError;
use mooring_core::MooringError;
use mooring_store::StoreError;
use mooring_vault::VaultError;
use serde::Serialize;

/// Error shape sent to the `WebView`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IpcError {
    /// Stable code, e.g. `tree.not_found`.
    pub code: &'static str,
    /// Safe, user-facing message.
    pub message: String,
}

/// Result alias for every command.
pub type IpcResult<T> = Result<T, IpcError>;

impl IpcError {
    /// Build an error from a code and a safe message.
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }

    /// `input.invalid` with a message naming the field, never the value.
    pub fn invalid(field: &str, reason: &str) -> Self {
        Self::new("input.invalid", format!("invalid {field}: {reason}"))
    }

    /// A poisoned mutex: some earlier panic left state inconsistent.
    pub fn poisoned() -> Self {
        tracing::error!("state mutex poisoned");
        Self::new("state.poisoned", "internal error")
    }

    /// `vault.locked`.
    pub fn locked() -> Self {
        Self::new("vault.locked", "unlock the vault first")
    }

    /// `session.failed` with a safe reason.
    pub fn session_failed(reason: impl Into<String>) -> Self {
        Self::new("session.failed", reason)
    }
}

impl From<VaultError> for IpcError {
    fn from(e: VaultError) -> Self {
        use VaultError as V;
        let code = match e {
            V::Unlock => "vault.unlock",
            V::Tampered => "vault.tampered",
            V::Locked => "vault.locked",
            V::Format(_) => "vault.format",
            V::KdfParams(_) => "vault.kdf",
            V::WeakPassword { .. } => "vault.weak_password",
            V::KeyringUnavailable => "vault.keyring_unavailable",
            V::Keyring(_) => "vault.keyring",
            V::Export(_) => "vault.export",
            V::Seal => "vault.seal",
        };
        // VaultError messages are secret-free by construction (mooring-vault/src/error.rs).
        Self::new(code, e.to_string())
    }
}

impl From<StoreError> for IpcError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::Invalid { field, reason } => Self::invalid(field, &reason),
            StoreError::NotFound { kind: "credential" | "secret", .. } => {
                Self::new("credential.not_found", "credential not found")
            }
            StoreError::NotFound { kind, .. } => {
                Self::new("tree.not_found", format!("{kind} not found"))
            }
            StoreError::Tree(reason) => tree_error(&reason),
            StoreError::SyncedReadOnly => Self::new(
                "tree.synced_readonly",
                "this item is synced from vCenter; only credentials, tags and options can change",
            ),
            StoreError::Vault(v) => v.into(),
            StoreError::Credential(c) => c.into(),
            StoreError::Corrupt { what } => {
                tracing::error!(what, "corrupt store row");
                Self::new("store.corrupt", "a stored record is damaged and was not used")
            }
            StoreError::InUse { kind: "secret_source", .. } => {
                Self::new("source.in_use", "the secret source is used by a reference")
            }
            StoreError::InUse { .. } => {
                Self::new("credential.in_use", "the credential is used by a secret source")
            }
            StoreError::VaultIdMismatch => Self::new(
                "store.vault_mismatch",
                "the connection database belongs to a different vault",
            ),
            other @ (StoreError::Sqlite(_) | StoreError::Downgrade { .. }) => {
                tracing::error!(error = %other, "store error");
                Self::new("store.io", "the connection database could not be read or written")
            }
        }
    }
}

impl From<CredentialError> for IpcError {
    fn from(e: CredentialError) -> Self {
        // CredentialError messages are value-free by construction (mooring-core credential).
        match e {
            CredentialError::Invalid { field, reason } => Self::invalid(field, &reason),
            CredentialError::KubeconfigRejected(m) => Self::new("credential.kubeconfig_rejected", m),
            CredentialError::Incompatible(m) => Self::new("credential.incompatible", m),
            CredentialError::KindUnsupported(m) => Self::new("credential.kind_unsupported", m),
            e @ CredentialError::SecretMissing(_) => {
                Self::new("credential.secret_missing", e.to_string())
            }
        }
    }
}

/// Map the store's tree-integrity reasons to the ADR-0008 codes.
fn tree_error(reason: &str) -> IpcError {
    if reason.contains("root") {
        IpcError::new("tree.root", reason.to_owned())
    } else if reason.contains("cycle") {
        IpcError::new("tree.cycle", reason.to_owned())
    } else {
        IpcError::new("tree.invalid", reason.to_owned())
    }
}

impl From<MooringError> for IpcError {
    fn from(e: MooringError) -> Self {
        match e {
            MooringError::Invalid { field, reason } => Self::invalid(field, &reason),
            MooringError::NotFound { kind, .. } => {
                Self::new("tree.not_found", format!("{kind} not found"))
            }
            MooringError::Tree(reason) => tree_error(&reason),
            MooringError::Closed => Self::new("session.not_found", "session is closed"),
            // Protocol and transport messages are built secret-free by the protocol crates.
            MooringError::Protocol { reason, .. } | MooringError::Transport(reason) => {
                Self::session_failed(reason)
            }
        }
    }
}

impl From<crate::state::StateError> for IpcError {
    fn from(e: crate::state::StateError) -> Self {
        tracing::error!(error = %e, "state error");
        Self::new("state.io", "could not persist application state")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_errors_map_to_stable_codes() {
        let cases: Vec<(StoreError, &str)> = vec![
            (StoreError::Invalid { field: "name", reason: "too long".into() }, "input.invalid"),
            (StoreError::NotFound { kind: "folder", id: "x".into() }, "tree.not_found"),
            (StoreError::NotFound { kind: "connection", id: "x".into() }, "tree.not_found"),
            (StoreError::NotFound { kind: "credential", id: "x".into() }, "credential.not_found"),
            (StoreError::NotFound { kind: "secret", id: "x".into() }, "credential.not_found"),
            (StoreError::Tree("the root folder cannot be moved".into()), "tree.root"),
            (StoreError::Tree("only one root folder is allowed".into()), "tree.root"),
            (StoreError::Tree("move would create a cycle".into()), "tree.cycle"),
            (StoreError::Vault(VaultError::Locked), "vault.locked"),
            (StoreError::Vault(VaultError::Tampered), "vault.tampered"),
            (StoreError::VaultIdMismatch, "store.vault_mismatch"),
            (StoreError::InUse { kind: "secret_source", id: "x".into() }, "source.in_use"),
            (StoreError::InUse { kind: "credential", id: "x".into() }, "credential.in_use"),
            (StoreError::Corrupt { what: "id" }, "store.corrupt"),
            (
                StoreError::Credential(CredentialError::Incompatible("x".into())),
                "credential.incompatible",
            ),
            (
                StoreError::Credential(CredentialError::KubeconfigRejected("x".into())),
                "credential.kubeconfig_rejected",
            ),
            (
                StoreError::Credential(CredentialError::KindUnsupported("x".into())),
                "credential.kind_unsupported",
            ),
            (
                StoreError::Credential(CredentialError::SecretMissing(
                    mooring_core::SecretName::Token,
                )),
                "credential.secret_missing",
            ),
            (StoreError::Downgrade { found: 9, supported: 1 }, "store.io"),
            (StoreError::SyncedReadOnly, "tree.synced_readonly"),
        ];
        for (e, code) in cases {
            assert_eq!(IpcError::from(e).code, code);
        }
    }

    #[test]
    fn internal_detail_is_not_forwarded() {
        let sql = rusqlite_like_error();
        let e = IpcError::from(sql);
        assert_eq!(e.code, "store.corrupt");
        assert!(!e.message.contains("SELECT"), "{}", e.message);
        let not_found = IpcError::from(StoreError::NotFound { kind: "folder", id: "abc".into() });
        assert!(!not_found.message.contains("abc"), "ids of missing rows are not echoed");
    }

    fn rusqlite_like_error() -> StoreError {
        // A Corrupt error stands in for any internal failure; its Display is not forwarded.
        StoreError::Corrupt { what: "SELECT secret FROM credential" }
    }

    #[test]
    fn core_errors_map() {
        let e = IpcError::from(MooringError::Transport("connection failed: refused".into()));
        assert_eq!(e.code, "session.failed");
        let e = IpcError::from(MooringError::Invalid { field: "port", reason: "bad".into() });
        assert_eq!(e.code, "input.invalid");
        assert_eq!(IpcError::from(MooringError::Closed).code, "session.not_found");
    }

    #[test]
    fn serialises_as_code_and_message() {
        let json = serde_json::to_string(&IpcError::locked()).expect("json");
        assert_eq!(json, r#"{"code":"vault.locked","message":"unlock the vault first"}"#);
    }
}
