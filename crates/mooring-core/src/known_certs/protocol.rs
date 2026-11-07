//! [`CertProtocol`]: which `known_*_certs` file a pin lives in (ADR-0011, ADR-0014 §1).

use crate::model::Protocol;

/// Which store a certificate pin belongs to.
///
/// `Kube`, `Vsphere`, `Vault` and `Sync` are the HTTPS clients of A3 (`mooring-http`). For them
/// TLS is never optional, so a "TLS seen" marker ([`super::TLS_MARKER`]) is a downgrade guard
/// too: a host with a pin or a marker is never contacted in plaintext, even where a loopback
/// `allow_plaintext` would otherwise permit it.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CertProtocol {
    /// `known_rdp_certs`.
    Rdp,
    /// `known_vnc_certs`.
    Vnc,
    /// `known_kube_certs`: Kubernetes API servers (ADR-0014).
    Kube,
    /// `known_vsphere_certs`: vCenter REST endpoints (ADR-0015).
    Vsphere,
    /// `known_vault_certs`: `HashiCorp` Vault / `OpenBao` (ADR-0016).
    Vault,
    /// `known_sync_certs`: S3-compatible sync endpoints (ADR-0017).
    Sync,
    /// `known_ldap_certs`: LDAPS directory servers of the importer (ADR-0019 §4).
    Ldap,
    /// `known_onepassword_certs`: 1Password Connect servers (ADR-0026 §3).
    Onepassword,
}

impl CertProtocol {
    /// Every store, in a stable order.
    pub const ALL: [Self; 8] = [
        Self::Rdp,
        Self::Vnc,
        Self::Kube,
        Self::Vsphere,
        Self::Vault,
        Self::Sync,
        Self::Ldap,
        Self::Onepassword,
    ];

    /// File name under the app data directory.
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::Rdp => "known_rdp_certs",
            Self::Vnc => "known_vnc_certs",
            Self::Kube => "known_kube_certs",
            Self::Vsphere => "known_vsphere_certs",
            Self::Vault => "known_vault_certs",
            Self::Sync => "known_sync_certs",
            Self::Ldap => "known_ldap_certs",
            Self::Onepassword => "known_onepassword_certs",
        }
    }

    /// Stable lowercase name: the IPC value and the audit `protocol` field.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Rdp => "rdp",
            Self::Vnc => "vnc",
            Self::Kube => "kube",
            Self::Vsphere => "vsphere",
            Self::Vault => "vault",
            Self::Sync => "sync",
            Self::Ldap => "ldap",
            Self::Onepassword => "onepassword",
        }
    }

    /// The connection protocol whose `host:port` names pins of this store, when there is one
    /// (`known_certs_list` joins host names from these connections). Vault sources, the
    /// sync endpoint and LDAP directories are not connections.
    pub const fn connection_protocol(self) -> Option<Protocol> {
        match self {
            Self::Rdp => Some(Protocol::Rdp),
            Self::Vnc => Some(Protocol::Vnc),
            Self::Kube => Some(Protocol::Kubernetes),
            Self::Vsphere => Some(Protocol::VsphereConsole),
            Self::Vault | Self::Sync | Self::Ldap | Self::Onepassword => None,
        }
    }

    /// Whether TLS is mandatory for every host of this store (the HTTPS clients). RDP and
    /// VNC negotiate it, so only their pins and markers make it mandatory.
    pub const fn tls_always(self) -> bool {
        !matches!(self, Self::Rdp | Self::Vnc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_files_are_distinct_and_stable() {
        let files: std::collections::HashSet<_> =
            CertProtocol::ALL.iter().map(|p| p.file_name()).collect();
        assert_eq!(files.len(), CertProtocol::ALL.len());
        assert_eq!(CertProtocol::Kube.file_name(), "known_kube_certs");
        assert_eq!(CertProtocol::Vsphere.file_name(), "known_vsphere_certs");
        assert_eq!(CertProtocol::Vault.file_name(), "known_vault_certs");
        assert_eq!(CertProtocol::Sync.file_name(), "known_sync_certs");
        assert_eq!(CertProtocol::Ldap.file_name(), "known_ldap_certs");
        assert_eq!(CertProtocol::Onepassword.file_name(), "known_onepassword_certs");
        for p in CertProtocol::ALL {
            let json = serde_json::to_value(p).expect("json");
            assert_eq!(json, serde_json::json!(p.name()));
            assert_eq!(serde_json::from_value::<CertProtocol>(json).expect("back"), p);
            assert_eq!(p.file_name(), format!("known_{}_certs", p.name()));
        }
        assert!(serde_json::from_value::<CertProtocol>(serde_json::json!("ssh")).is_err());
        assert!(!CertProtocol::Rdp.tls_always() && CertProtocol::Sync.tls_always());
        assert!(
            CertProtocol::Ldap.tls_always() && CertProtocol::Ldap.connection_protocol().is_none()
        );
        assert_eq!(CertProtocol::Kube.connection_protocol(), Some(Protocol::Kubernetes));
        assert_eq!(CertProtocol::Vault.connection_protocol(), None);
    }
}
