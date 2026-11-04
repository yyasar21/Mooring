//! VM commands (ADR-0015 §3–5): `vsphere_vm_power` (passive), `vsphere_vm_action`,
//! `vsphere_vm_identity`, `vsphere_console`. `connectionId` is the synced VM row; its vCenter
//! and managed-object id come from the store.
//!
//! A power action needs the vCenter's `allowPowerActions` opt-in **and** a "yes" in the
//! Rust-native dialog naming the VM, the action and the vCenter (power off / reset add the
//! data-loss warning); only then is a [`PowerApproval`] built. Audited `vsphere_power` before
//! (`requested`) and after (`done` | `already` | `cancelled` | error code). M-16: the dialog
//! goes through `AppState::confirm` (`confirm.busy`; `confirm.cooldown` for 10 s after a
//! cancelled power off / reset of the same VM).

use std::sync::{Arc, Mutex};

use mooring_audit::{AuditEvent, AuditLog};
use mooring_core::ConnectionId;
use mooring_vsphere::{InventoryItem, MoId, PowerAction, PowerApproval, PowerAudit, PowerOutcome, PowerState};
use serde::Serialize;
use time::OffsetDateTime;

use crate::commands::vsphere_confirm::{Ask, Prompt, UrlOpener};
use crate::commands::vsphere_login::{self, map_error, Target};
use crate::confirm_gate::Scope;
use crate::dto;
use crate::error::{IpcError, IpcResult};
use crate::state::{record_audit, AppState};
use crate::vsphere_sync::{self, VsCtx};

/// A synced VM row resolved to its vCenter.
#[derive(Debug, Clone)]
pub struct VmTarget {
    /// vCenter connection id.
    pub source: ConnectionId,
    /// Managed-object id.
    pub vm: MoId,
    /// Display name of the row.
    pub name: String,
    /// The last synced item.
    pub item: Option<InventoryItem>,
    /// The vCenter.
    pub target: Target,
}

/// Resolve `connection_id` (a synced VM row).
pub fn vm_target(ctx: &VsCtx, connection_id: &str) -> IpcResult<VmTarget> {
    let id = dto::connection_id("connectionId", connection_id)?;
    let (source, ext, name, data) = ctx.ready.with_ready(|_, store| {
        let c = store.get_connection(id)?;
        let flags = store.connection_sync(id)?.ok_or_else(not_vm)?;
        let ext = flags.external_id.ok_or_else(not_vm)?;
        Ok((flags.source, ext, c.name, flags.data))
    })?;
    let source: ConnectionId = dto::connection_id("connectionId", &source)?;
    let vm = MoId::new(&ext).map_err(|_| not_vm())?;
    let item = data.and_then(|d| serde_json::from_str::<InventoryItem>(&d).ok());
    let target = vsphere_login::target(&ctx.ready, source)?;
    Ok(VmTarget { source, vm, name, item, target })
}

fn not_vm() -> IpcError {
    IpcError::invalid("connectionId", "not a synced VM")
}

/// `{ state }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PowerDto {
    /// `POWERED_ON` | `POWERED_OFF` | `SUSPENDED`.
    pub state: PowerState,
}

/// `vsphere_vm_power` (passive): the 10 s cache, else a live read when a session is already
/// open (never a login), else the state of the last refresh.
pub async fn power_state(state: &AppState, connection_id: &str) -> IpcResult<PowerDto> {
    let ctx = VsCtx::of(state);
    let t = vm_target(&ctx, connection_id)?;
    let src = t.source.to_string();
    if let Some(p) = ctx.hub.cached_power(&src, t.vm.as_str()) {
        return Ok(PowerDto { state: p });
    }
    if let Some(session) = ctx.hub.session(&src) {
        if let Ok(p) = session.power_state(&t.vm).await {
            ctx.hub.cache_power(&src, t.vm.as_str(), p);
            return Ok(PowerDto { state: p });
        }
    }
    t.item
        .and_then(|i| i.power_state)
        .map(|state| PowerDto { state })
        .ok_or_else(|| IpcError::new("vsphere.not_found", "no power state known for this VM"))
}

/// `{ outcome }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ActionDto {
    /// `done` | `cancelled`.
    pub outcome: &'static str,
}

struct Hook {
    audit: Arc<Mutex<AuditLog>>,
    connection: String,
}

impl Hook {
    fn record(&self, vm: &str, action: PowerAction, outcome: &str) {
        record_audit(
            &self.audit,
            AuditEvent::VspherePower {
                connection: self.connection.clone(),
                vm: vm.to_owned(),
                action: action.as_str().to_owned(),
                outcome: outcome.to_owned(),
            },
        );
    }
}

impl PowerAudit for Hook {
    fn before(&self, vm: &MoId, action: PowerAction) {
        self.record(vm.as_str(), action, "requested");
    }

    fn after(&self, vm: &MoId, action: PowerAction, outcome: Result<PowerOutcome, &'static str>) {
        let o = match outcome {
            Ok(PowerOutcome::Done) => "done",
            Ok(PowerOutcome::AlreadyInState) => "already",
            Err(code) => code,
        };
        self.record(vm.as_str(), action, o);
    }
}

fn action_label(a: PowerAction) -> &'static str {
    match a {
        PowerAction::On => "Power on",
        PowerAction::ShutdownGuest => "Shut down the guest OS of",
        PowerAction::RebootGuest => "Restart the guest OS of",
        PowerAction::Off => "Power off",
        PowerAction::Reset => "Reset",
    }
}

/// The dialog text for `a` on `t` (tests check it names the VM, action and vCenter).
pub fn power_question(t: &VmTarget, a: PowerAction) -> Ask {
    let mut text = format!(
        "{} the virtual machine \"{}\" ({}) on vCenter \"{}\" ({})?",
        action_label(a),
        t.name,
        t.vm,
        t.target.name,
        t.target.host
    );
    if a.is_destructive() {
        text.push_str(
            "\n\nThis is like pulling the plug: unsaved data in the guest may be lost.",
        );
    }
    let ok = match a {
        PowerAction::On => "Power on",
        PowerAction::ShutdownGuest => "Shut down",
        PowerAction::RebootGuest => "Restart",
        PowerAction::Off => "Power off",
        PowerAction::Reset => "Reset",
    };
    Ask { title: "Mooring \u{b7} VM power action".to_owned(), text, ok: ok.to_owned(), warning: a.is_destructive() }
}

/// `vsphere_vm_action({ connectionId, action })`.
pub async fn action(state: &AppState, prompt: Prompt<'_>, connection_id: &str, action: &str) -> IpcResult<ActionDto> {
    let a = PowerAction::parse(action).map_err(|_| IpcError::invalid("action", "start, shutdown, reboot, stop or reset"))?;
    let ctx = VsCtx::of(state);
    let t = vm_target(&ctx, connection_id)?;
    let hook = Hook { audit: Arc::clone(&ctx.audit), connection: t.source.to_string() };
    if !t.target.options.allow_power_actions {
        hook.record(t.vm.as_str(), a, "power_disabled");
        return Err(map_error(&mooring_vsphere::VsphereError::PowerDisabled));
    }
    let target = format!("{}/{}", t.source, t.vm);
    let scope = Scope { kind: "vsphere_power", target: &target, destructive: a.is_destructive() };
    let yes = prompt.ask(&ctx.confirm, scope, power_question(&t, a)).await?;
    if !yes {
        hook.record(t.vm.as_str(), a, "cancelled");
        return Ok(ActionDto { outcome: "cancelled" });
    }
    let approval = PowerApproval::new(&t.vm, a, t.target.options.allow_power_actions, yes).map_err(|e| map_error(&e))?;
    let session = vsphere_sync::session(&ctx, t.source, Some(prompt)).await?;
    match session.power(&t.vm, approval, &hook).await {
        Ok(_) => {
            if let Ok(p) = session.power_state(&t.vm).await {
                ctx.hub.cache_power(&t.source.to_string(), t.vm.as_str(), p);
            }
            Ok(ActionDto { outcome: "done" })
        }
        Err(mooring_vsphere::VsphereError::Forbidden) => {
            Err(IpcError::new("vsphere.power_denied", "vCenter refused the power action for this account"))
        }
        Err(e) => Err(map_error(&e)),
    }
}

/// `{ hostName, ip, family }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityDto {
    /// Guest host name.
    pub host_name: Option<String>,
    /// Primary IP.
    pub ip: Option<String>,
    /// OS family.
    pub family: Option<String>,
}

/// `vsphere_vm_identity({ connectionId })`: live, needs `VMware` Tools (`vsphere.tools_missing`).
pub async fn identity(state: &AppState, prompt: Prompt<'_>, connection_id: &str) -> IpcResult<IdentityDto> {
    let ctx = VsCtx::of(state);
    let t = vm_target(&ctx, connection_id)?;
    let session = vsphere_sync::session(&ctx, t.source, Some(prompt)).await?;
    let g = session.guest_identity(&t.vm).await.map_err(|e| map_error(&e))?;
    let g = g.ok_or_else(|| map_error(&mooring_vsphere::VsphereError::ToolsMissing))?;
    Ok(IdentityDto {
        host_name: g.host_name.map(|n| n.as_str().to_owned()),
        ip: g.ip_address.map(|ip| ip.to_string()),
        family: g.family.map(|n| n.as_str().to_owned()),
    })
}

/// VMRC hand-off: opt-in, the native confirmation, a fresh single-use ticket, the OS URL
/// handler. The ticket never reaches the `WebView` or a log. `false` = cancelled.
pub async fn vmrc(state: &AppState, prompt: Prompt<'_>, opener: &dyn UrlOpener, t: &VmTarget) -> IpcResult<bool> {
    if !t.target.options.allow_vmrc {
        return Err(IpcError::new("vsphere.vmrc_disabled", "VMRC hand-off is off for this vCenter"));
    }
    let ask = Ask {
        title: "Mooring \u{b7} VMware Remote Console".to_owned(),
        text: format!(
            "Open the console of \"{}\" ({}) on vCenter \"{}\" in VMware Remote Console?\n\nA single-use ticket is handed to that application.",
            t.name, t.vm, t.target.name
        ),
        ok: "Open".to_owned(),
        warning: false,
    };
    let ctx = VsCtx::of(state);
    let target = format!("{}/{}", t.source, t.vm);
    if !prompt.ask(&ctx.confirm, Scope { kind: "vmrc", target: &target, destructive: false }, ask).await? {
        return Ok(false);
    }
    let session = vsphere_sync::session(&ctx, t.source, Some(prompt)).await?;
    let ticket = session.vmrc_ticket(&t.vm).await.map_err(|e| map_error(&e))?;
    let url = ticket.expose_for_open(OffsetDateTime::now_utc()).map_err(|e| map_error(&e))?;
    opener.open(url).map_err(|_| IpcError::new("vsphere.vmrc_unavailable", "VMware Remote Console could not be started"))?;
    ctx.audit(AuditEvent::VsphereConsole { connection: t.source.to_string(), vm: t.vm.as_str().to_owned(), kind: "vmrc".to_owned() });
    Ok(true)
}

/// `vsphere_console({ kind })` kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleKind {
    /// vSphere Client in an isolated web window.
    Client,
    /// `VMware` Remote Console hand-off.
    Vmrc,
}

impl ConsoleKind {
    /// Parse the IPC value.
    pub fn parse(raw: &str) -> IpcResult<Self> {
        match raw {
            "client" => Ok(Self::Client),
            "vmrc" => Ok(Self::Vmrc),
            _ => Err(IpcError::invalid("kind", "client or vmrc")),
        }
    }
}
