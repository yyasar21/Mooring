//! The audit event vocabulary (one JSON object per entry, tagged by `event`). The variants
//! live in one `pub enum AuditEvent` whose body is assembled from per-phase lists
//! (`vault`, `sessions`, `web`, `kube`, `vsphere`, `secrets`, `sync`, `a4`, `a5`) so each file
//! stays small; the wire format (`event` tag, `snake_case` names, per-variant renames) is
//! unchanged — every phase macro appends its variants and hands the chain to the next.

use serde::{Deserialize, Serialize};

mod a4;
mod a5;
mod kube;
mod secrets;
mod sessions;
mod sync;
mod vault;
mod vsphere;
mod web;

use a4::a4_variants;
use a5::a5_variants;
use kube::kube_variants;
use secrets::secrets_variants;
use sessions::sessions_variants;
use sync::sync_variants;
use vault::vault_variants;
use vsphere::vsphere_variants;
use web::web_variants;

/// The end of the chain: the full variant list becomes the enum.
macro_rules! define_audit_event {
    ([] $($body:tt)*) => {
        /// What happened. Variants carry identifiers, never secret values.
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(tag = "event", rename_all = "snake_case")]
        pub enum AuditEvent {
            $($body)*
        }
    };
}

vault_variants! {
    [
        sessions_variants,
        web_variants,
        kube_variants,
        vsphere_variants,
        secrets_variants,
        sync_variants,
        a4_variants,
        a5_variants,
        define_audit_event
    ]
}

/// Longest event wire name accepted by [`is_known_event`].
const MAX_EVENT_NAME: usize = 64;

/// Whether `name` is the wire name (`event` tag) of a current [`AuditEvent`] variant. Probed
/// through serde so the answer cannot drift from the enum: an unknown tag fails with serde's
/// fixed `unknown variant` message; a known one parses or only misses a field.
#[must_use]
pub fn is_known_event(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_EVENT_NAME {
        return false;
    }
    let probe = serde_json::json!({ "event": name });
    match serde_json::from_value::<AuditEvent>(probe) {
        Ok(_) => true,
        Err(e) => !e.to_string().starts_with("unknown variant"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_event_names_follow_the_enum() {
        for name in ["vault_created", "vault_locked", "audit.exported", "session.rdp.gateway"] {
            assert!(is_known_event(name), "{name}");
        }
        let long = "x".repeat(MAX_EVENT_NAME + 1);
        for name in ["", "nope", "Vault_Created", "vault_created ", "event", long.as_str()] {
            assert!(!is_known_event(name), "{name}");
        }
    }

    #[test]
    fn audit_exported_wire_shape() {
        let e = AuditEvent::AuditExported { format: "csv".into(), count: 3 };
        assert_eq!(
            serde_json::to_string(&e).expect("json"),
            r#"{"event":"audit.exported","format":"csv","count":3}"#
        );
    }
}
