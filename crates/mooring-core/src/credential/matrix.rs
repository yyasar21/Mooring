//! Protocol compatibility matrix (ADR-0009 §2). The `protocols` rows of the kind table are the
//! only source of truth; this module answers questions about them and phrases refusals the way
//! the UI shows them verbatim ("SSH key is for SSH, not RDP sign-in.").

use super::{CredentialError, CredentialFields, CredentialKind, Role};
use crate::model::Protocol;

/// UI label of a protocol.
#[must_use]
pub const fn protocol_label(p: Protocol) -> &'static str {
    match p {
        Protocol::Ssh => "SSH",
        Protocol::Rdp => "RDP",
        Protocol::Vnc => "VNC",
        Protocol::Web => "Web",
        Protocol::Kubernetes => "Kubernetes",
        Protocol::VsphereConsole => "vSphere console",
    }
}

const fn role_label(r: Role) -> &'static str {
    match r {
        Role::Primary => "sign-in",
        Role::Gateway => "RD Gateway",
        Role::Become => "become / sudo",
    }
}

/// Footnotes of the ADR matrix: why an obvious-looking pairing is refused.
fn footnote(kind: CredentialKind, p: Protocol) -> Option<&'static str> {
    use CredentialKind as K;
    match (kind, p) {
        (K::UserPassword | K::DomainUser, Protocol::Kubernetes) => {
            Some("Kubernetes removed static basic auth.")
        }
        (K::X509, Protocol::Rdp) => Some("Smart-card RDP is planned for later."),
        (K::X509, Protocol::Vnc) => Some("VeNCrypt X.509 is planned for later."),
        _ => None,
    }
}

/// Can `kind` fill `role` on `protocol`? (`external_ref` has no row of its own: use
/// [`check_compatible`] with its fields, which follows `target_kind`.)
#[must_use]
pub fn valid_for(kind: CredentialKind, protocol: Protocol, role: Role) -> bool {
    kind.schema().protocols.iter().any(|p| p.protocol == protocol && p.roles.contains(&role))
}

/// The refusal sentence for an invalid pairing, `None` when it is valid.
#[must_use]
pub fn incompatibility_reason(
    kind: CredentialKind,
    protocol: Protocol,
    role: Role,
) -> Option<String> {
    if valid_for(kind, protocol, role) {
        return None;
    }
    if let Some(note) = footnote(kind, protocol) {
        return Some(note.to_owned());
    }
    let schema = kind.schema();
    let uses: Vec<String> = schema
        .protocols
        .iter()
        .flat_map(|p| {
            p.roles.iter().map(move |r| match r {
                Role::Primary => protocol_label(p.protocol).to_owned(),
                other => format!("{} {}", protocol_label(p.protocol), role_label(*other)),
            })
        })
        .collect();
    if uses.is_empty() {
        return Some(format!("{} has no supported protocol yet.", schema.label));
    }
    Some(format!(
        "{} is for {}, not {} {}.",
        schema.label,
        uses.join(", "),
        protocol_label(protocol),
        role_label(role)
    ))
}

/// Check a stored credential against a protocol and role; `external_ref` follows its
/// `target_kind`. `Err(Incompatible(reason))` otherwise.
pub fn check_compatible(
    fields: &CredentialFields,
    protocol: Protocol,
    role: Role,
) -> Result<(), CredentialError> {
    let kind = match fields {
        CredentialFields::ExternalRef(f) => f.target_kind,
        other => other.kind(),
    };
    match incompatibility_reason(kind, protocol, role) {
        None => Ok(()),
        Some(reason) => Err(CredentialError::Incompatible(reason)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use CredentialKind as K;
    use Protocol::{Kubernetes as Kube, Rdp, Ssh, Vnc, VsphereConsole as Vsc, Web};

    /// The ADR-0009 §2 table, transcribed: (kind, [ssh, rdp, vnc, web, kubernetes, vsphere]),
    /// each cell = (primary, gateway, become).
    const T: (bool, bool, bool) = (true, false, false);
    const G: (bool, bool, bool) = (true, true, false);
    const B: (bool, bool, bool) = (false, false, true);
    const N: (bool, bool, bool) = (false, false, false);
    type Row = [(bool, bool, bool); 6];
    const ADR: [(K, Row); 15] = [
        (K::UserPassword, [T, G, N, T, N, T]),
        (K::DomainUser, [T, G, N, T, N, T]),
        (K::SshKey, [T, N, N, N, N, N]),
        (K::SshAgent, [T, N, N, N, N, N]),
        (K::X509, [N, N, N, T, T, N]),
        (K::ApiToken, [N, N, N, T, N, N]),
        (K::OauthClient, [N, N, N, T, N, N]),
        (K::Kubeconfig, [N, N, N, N, T, N]),
        (K::KubeToken, [N, N, N, N, T, N]),
        (K::VsphereUser, [N, N, N, T, N, T]),
        (K::VncPassword, [N, N, T, N, N, N]),
        (K::VncUserPassword, [N, N, T, N, N, N]),
        (K::Prompt, [T, G, T, T, N, T]),
        (K::SudoBecome, [B, N, N, N, N, N]),
        (K::S3AccessKey, [N, N, N, N, N, N]),
    ];
    const PROTOCOLS: [Protocol; 6] = [Ssh, Rdp, Vnc, Web, Kube, Vsc];

    #[test]
    fn matrix_matches_the_adr_exhaustively() {
        for (kind, row) in ADR {
            for (p, (pri, gw, bec)) in PROTOCOLS.into_iter().zip(row) {
                assert_eq!(valid_for(kind, p, Role::Primary), pri, "{kind:?} {p:?} primary");
                assert_eq!(valid_for(kind, p, Role::Gateway), gw, "{kind:?} {p:?} gateway");
                assert_eq!(valid_for(kind, p, Role::Become), bec, "{kind:?} {p:?} become");
                let ok = [pri, gw, bec];
                for (r, ok) in [Role::Primary, Role::Gateway, Role::Become].into_iter().zip(ok) {
                    assert_eq!(incompatibility_reason(kind, p, r).is_none(), ok);
                }
            }
        }
        for p in PROTOCOLS {
            for r in [Role::Primary, Role::Gateway, Role::Become] {
                assert!(!valid_for(K::ExternalRef, p, r), "external_ref has no own row");
            }
        }
    }

    #[test]
    fn reasons_read_like_the_ui() {
        let r = |k, p, role| incompatibility_reason(k, p, role).expect("refused");
        assert_eq!(r(K::SshKey, Rdp, Role::Primary), "SSH key is for SSH, not RDP sign-in.");
        assert_eq!(
            r(K::UserPassword, Kube, Role::Primary),
            "Kubernetes removed static basic auth."
        );
        assert_eq!(r(K::X509, Rdp, Role::Primary), "Smart-card RDP is planned for later.");
        assert_eq!(
            r(K::SudoBecome, Ssh, Role::Primary),
            "Become (sudo, su, doas) is for SSH become / sudo, not SSH sign-in."
        );
        assert_eq!(
            r(K::UserPassword, Ssh, Role::Become),
            "Username and password is for SSH, RDP, RDP RD Gateway, Web, vSphere console, not SSH become / sudo."
        );
        assert_eq!(
            r(K::ExternalRef, Ssh, Role::Primary),
            "Secret manager reference has no supported protocol yet."
        );
    }
}
