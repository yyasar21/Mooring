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
