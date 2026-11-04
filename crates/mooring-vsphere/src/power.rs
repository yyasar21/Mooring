//! Power state and the five A3 actions (ADR-0015 §3, owner decision 6). Nothing here
//! confirms anything: [`Session::power`] needs a [`PowerApproval`] that the Tauri layer builds
//! only after the per-connection opt-in check and its Rust-native dialog; the call is wrapped
//! in [`PowerAudit`] hooks and at most one action per VM is in flight.

use crate::error::{api_error_type, status_error, ApiErrorType, VsphereError};
use crate::ids::MoId;
use crate::model::{PowerInfo, PowerState};
use crate::session::{Session, MAX_RETRY_AFTER};
use mooring_http::{retry_after, Method};

/// A power action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PowerAction {
    /// Power on (`POST /vm/{vm}/power?action=start`).
    On,
    /// Guest OS shutdown (`POST /vm/{vm}/guest/power?action=shutdown`, needs `VMware` Tools).
    ShutdownGuest,
    /// Guest OS reboot (`…/guest/power?action=reboot`, needs `VMware` Tools).
    RebootGuest,
    /// Hard power off (`…/power?action=stop`): like pulling the plug.
    Off,
    /// Hard reset (`…/power?action=reset`).
    Reset,
}

impl PowerAction {
    /// All five, in UI order.
    pub const ALL: [Self; 5] =
        [Self::On, Self::ShutdownGuest, Self::RebootGuest, Self::Off, Self::Reset];

    /// Off / Reset may lose data: the dialog adds the "may lose data" warning.
    pub const fn is_destructive(self) -> bool {
        matches!(self, Self::Off | Self::Reset)
    }

    /// Every action needs the native confirmation (owner decision 6).
    pub const fn requires_confirmation(self) -> bool {
        true
    }

    /// Guest operations need running `VMware` Tools.
    pub const fn requires_tools(self) -> bool {
        matches!(self, Self::ShutdownGuest | Self::RebootGuest)
    }

    /// IPC / audit name (ADR-0015 §5).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::On => "start",
            Self::ShutdownGuest => "shutdown",
            Self::RebootGuest => "reboot",
            Self::Off => "stop",
            Self::Reset => "reset",
        }
    }

    /// Parse an IPC name.
    pub fn parse(s: &str) -> Result<Self, VsphereError> {
        Self::ALL
            .into_iter()
            .find(|a| a.as_str() == s)
            .ok_or(VsphereError::Invalid("unknown power action"))
    }

    fn path(self, vm: &MoId) -> String {
        if self.requires_tools() {
            format!("/api/vcenter/vm/{vm}/guest/power?action={}", self.as_str())
        } else {
            format!("/api/vcenter/vm/{vm}/power?action={}", self.as_str())
        }
    }
}

/// Proof that one action on one VM passed the opt-in and the confirmation. Single use.
#[derive(Debug)]
pub struct PowerApproval {
    vm: MoId,
    action: PowerAction,
}

impl PowerApproval {
    /// `allow_power_actions` is the connection's opt-in (`VsphereConnOptions`); `confirmed`
    /// is the answer of the native dialog naming the VM and the vCenter.
    pub fn new(
        vm: &MoId,
        action: PowerAction,
        allow_power_actions: bool,
        confirmed: bool,
    ) -> Result<Self, VsphereError> {
        if !allow_power_actions {
            return Err(VsphereError::PowerDisabled);
        }
        if action.requires_confirmation() && !confirmed {
            return Err(VsphereError::NotConfirmed);
        }
        Ok(Self { vm: vm.clone(), action })
    }
}

/// Result of an action that vCenter accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerOutcome {
    /// Accepted.
    Done,
    /// The VM already was in the requested state (`ALREADY_IN_DESIRED_STATE`).
    AlreadyInState,
}

/// Audit hooks around an action (`vsphere.power { connection, vm, action, outcome }`).
pub trait PowerAudit: Send + Sync {
    /// Before the request is sent.
    fn before(&self, vm: &MoId, action: PowerAction);
    /// After it finished; `Err` carries the error code.
    fn after(&self, vm: &MoId, action: PowerAction, outcome: Result<PowerOutcome, &'static str>);
}

struct InFlight<'a> {
    session: &'a Session,
    vm: MoId,
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.session
            .power_in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.vm);
    }
}

fn map_power_error(
    action: PowerAction,
    status: u16,
    body: &[u8],
) -> Option<Result<PowerOutcome, VsphereError>> {
    match api_error_type(body) {
        ApiErrorType::AlreadyInDesiredState => Some(Ok(PowerOutcome::AlreadyInState)),
        ApiErrorType::NotAllowedInCurrentState => Some(Err(VsphereError::WrongState)),
        ApiErrorType::ServiceUnavailable if action.requires_tools() => {
            Some(Err(VsphereError::ToolsMissing))
        }
        _ if status == 503 && action.requires_tools() => Some(Err(VsphereError::ToolsMissing)),
        _ => None,
    }
}

impl Session {
    /// `GET /api/vcenter/vm/{vm}/power` (V2 caches it for 10 s).
    pub async fn power_state(&self, vm: &MoId) -> Result<PowerState, VsphereError> {
        Ok(self.get::<PowerInfo>(&format!("/api/vcenter/vm/{vm}/power")).await?.state)
    }

    /// Run `approval`'s action on `vm`. Never retried (POST); a 401 re-logs in and resends
    /// once, which is safe because vCenter did not run it.
    pub async fn power(
        &self,
        vm: &MoId,
        approval: PowerApproval,
        audit: &dyn PowerAudit,
    ) -> Result<PowerOutcome, VsphereError> {
        if approval.vm != *vm {
            return Err(VsphereError::Invalid("approval is for another VM"));
        }
        let action = approval.action;
        let inserted = self
            .power_in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(vm.clone());
        if !inserted {
            return Err(VsphereError::Busy);
        }
        let _guard = InFlight { session: self, vm: vm.clone() };
        audit.before(vm, action);
        let result = self.power_request(vm, action).await;
        audit.after(vm, action, result.as_ref().map(|o| *o).map_err(VsphereError::code));
        result
    }

    async fn power_request(
        &self,
        vm: &MoId,
        action: PowerAction,
    ) -> Result<PowerOutcome, VsphereError> {
        let r = self.call_any(Method::POST, &action.path(vm), None).await?;
        if r.status.is_success() {
            return Ok(PowerOutcome::Done);
        }
        let status = r.status.as_u16();
        if let Some(mapped) = map_power_error(action, status, &r.body) {
            return mapped;
        }
        Err(status_error(status, &r.body, retry_after(&r.headers, MAX_RETRY_AFTER)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_table() {
        let names: Vec<_> = PowerAction::ALL.iter().map(|a| a.as_str()).collect();
        assert_eq!(names, ["start", "shutdown", "reboot", "stop", "reset"]);
        for a in PowerAction::ALL {
            assert_eq!(PowerAction::parse(a.as_str()).expect("parse"), a);
            assert!(a.requires_confirmation());
        }
        let destructive: Vec<_> =
            PowerAction::ALL.into_iter().filter(|a| a.is_destructive()).collect();
        assert_eq!(destructive, [PowerAction::Off, PowerAction::Reset]);
        assert!(PowerAction::parse("suspend").is_err());
        let vm = MoId::new("vm-7").expect("id");
        assert_eq!(PowerAction::On.path(&vm), "/api/vcenter/vm/vm-7/power?action=start");
        assert_eq!(
            PowerAction::RebootGuest.path(&vm),
            "/api/vcenter/vm/vm-7/guest/power?action=reboot"
        );
    }

    #[test]
    fn approval_needs_opt_in_and_confirmation() {
        let vm = MoId::new("vm-7").expect("id");
        let code = |r: Result<PowerApproval, VsphereError>| r.map(|_| ()).map_err(|e| e.code());
        assert_eq!(
            code(PowerApproval::new(&vm, PowerAction::On, false, true)),
            Err("vsphere.power_disabled")
        );
        assert_eq!(
            code(PowerApproval::new(&vm, PowerAction::Off, true, false)),
            Err("vsphere.not_confirmed")
        );
        assert_eq!(code(PowerApproval::new(&vm, PowerAction::Reset, true, true)), Ok(()));
    }

    #[test]
    fn guest_errors_map_to_tools_missing() {
        let su = br#"{"error_type":"SERVICE_UNAVAILABLE"}"#;
        let code = |a, s, b: &[u8]| map_power_error(a, s, b).map(|r| r.map_err(|e| e.code()));
        assert_eq!(code(PowerAction::ShutdownGuest, 503, su), Some(Err("vsphere.tools_missing")));
        assert_eq!(code(PowerAction::RebootGuest, 503, b""), Some(Err("vsphere.tools_missing")));
        assert_eq!(code(PowerAction::Off, 503, su), None);
        let st = br#"{"error_type":"ALREADY_IN_DESIRED_STATE"}"#;
        assert_eq!(code(PowerAction::On, 400, st), Some(Ok(PowerOutcome::AlreadyInState)));
        let na = br#"{"error_type":"NOT_ALLOWED_IN_CURRENT_STATE"}"#;
        assert_eq!(code(PowerAction::ShutdownGuest, 400, na), Some(Err("vsphere.wrong_state")));
    }
}
