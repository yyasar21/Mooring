//! `mooring-vsphere`: a thin vCenter REST client (vSphere Automation API `/api`, vCenter 7.0+)
//! on [`mooring_http`] (ADR-0015, task V1).
//!
//! * [`VsphereClient::login`] → [`Session`]: `vmware-api-session-id` held in `Zeroizing`
//!   memory only, one re-login on 401 with a credential from a caller closure (never stored),
//!   [`Session::logout`]. TLS trust is mooring-http's (`CertProtocol::Vsphere`, TOFU, pins).
//! * Inventory: [`Session::datacenters`], [`Session::clusters`], [`Session::hosts`],
//!   [`Session::vms`] with [`VmFilter`], [`Session::vm`], [`Session::inventory`] with
//!   [`Caps`]; the pure [`diff`] with missing-streaks.
//! * Power: [`Session::power_state`], [`Session::power`] with [`PowerAction`], a
//!   [`PowerApproval`] the Tauri layer builds after its native dialog, and [`PowerAudit`].
//! * Console: [`vsphere_client_url`] and [`Session::vmrc_ticket`].
//! * Every body is capped (8 MiB) before parsing; every id, name and list is bounded.
//!   Errors carry stable `vsphere.*` codes ([`VsphereError::code`]) and no server text.

#![forbid(unsafe_code)]

mod console;
mod diff;
mod error;
pub mod fuzz;
mod ids;
mod inventory;
mod model;
mod power;
mod session;

pub use console::{
    parse_vmrc_ticket, parse_vmrc_ticket_for, vsphere_client_url, VmrcUrl, MAX_TICKET_URL,
    VMRC_TICKET_TTL,
};
pub use diff::{
    diff, Change, ExternalId, Inventory, InventoryDiff, InventoryItem, ItemKind,
    DELETE_AFTER_MISSES,
};
pub use error::VsphereError;
pub use ids::{is_uuid, Capped, MoId, Name, MAX_ID, MAX_NAME};
pub use inventory::{
    standalone_id, Caps, HostScope, VmDetails, VmFilter, DEFAULT_MAX_VMS, MAX_FILTER_VALUES,
    MAX_VMS_CEILING,
};
pub use model::{
    ApplianceVersion, ClusterSummary, DatacenterSummary, GuestIdentity, HostConnectionState,
    HostPowerState, HostSummary, Localizable, PowerState, VmCpu, VmIdentity, VmInfo, VmMemory,
    VmSummary, MAX_CLUSTERS, MAX_DATACENTERS, MAX_HOSTS, MAX_LIST,
};
pub use power::{PowerAction, PowerApproval, PowerAudit, PowerOutcome};
pub use session::{
    parse_session_token, Credential, CredentialSource, Session, VsphereClient, MAX_BODY,
    MAX_RETRY_AFTER, MAX_TOKEN, MAX_UPN,
};
