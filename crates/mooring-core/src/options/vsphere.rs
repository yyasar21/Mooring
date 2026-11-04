//! `VsphereConnOptions` of a vCenter connection (`vsphere-console`, ADR-0015 §2, owner
//! decisions 6–7). The VM rows of a synced subtree share the protocol and use the defaults.

use serde::{Deserialize, Serialize};

use super::{check_ca_pem, invalid};
use crate::error::Result;

/// Shortest scheduled refresh, minutes (ADR-0015 §2).
pub const MIN_REFRESH_MINUTES: u32 = 15;
/// Longest scheduled refresh, minutes (one day).
pub const MAX_REFRESH_MINUTES: u32 = 1440;
/// Default scheduled refresh, minutes.
pub const DEFAULT_REFRESH_MINUTES: u32 = 60;

#[allow(clippy::unnecessary_wraps)]
const fn default_refresh() -> Option<u32> {
    Some(DEFAULT_REFRESH_MINUTES)
}

/// `{ syncFolderId|null, refreshMinutes: 15..=1440|null, allowPowerActions, allowVmrc,
/// caPem|null }`. `syncFolderId` is owned by the store: it is filled from the synced folder
/// on read and ignored on write. `refreshMinutes: null` = manual refresh only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VsphereConnOptions {
    /// Root folder of the synced subtree (read-only; set by `vsphere_sync_enable`).
    #[serde(default)]
    pub sync_folder_id: Option<String>,
    /// Scheduled refresh interval in minutes, `null` = manual only (default 60).
    #[serde(default = "default_refresh")]
    pub refresh_minutes: Option<u32>,
    /// Power actions (all five, each behind the native dialog). Default off; audited.
    #[serde(default)]
    pub allow_power_actions: bool,
    /// VMRC hand-off (owner decision 7). Default off; audited.
    #[serde(default)]
    pub allow_vmrc: bool,
    /// The VMCA root (PEM, certificates only, ≤ 64 KiB).
    #[serde(default)]
    pub ca_pem: Option<String>,
}

impl Default for VsphereConnOptions {
    fn default() -> Self {
        Self {
            sync_folder_id: None,
            refresh_minutes: default_refresh(),
            allow_power_actions: false,
            allow_vmrc: false,
            ca_pem: None,
        }
    }
}

impl VsphereConnOptions {
    /// Ranges, the folder id shape and the CA PEM rule.
    pub fn validate(&self) -> Result<()> {
        if let Some(m) = self.refresh_minutes {
            if !(MIN_REFRESH_MINUTES..=MAX_REFRESH_MINUTES).contains(&m) {
                return Err(invalid("refreshMinutes must be 15..=1440 or null"));
            }
        }
        if let Some(id) = &self.sync_folder_id {
            if id.len() != 36 || !id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
                return Err(invalid("syncFolderId is not a folder id"));
            }
        }
        check_ca_pem(self.ca_pem.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::model::Protocol;
    use crate::options::ProtocolOptions;

    fn parse(v: serde_json::Value) -> crate::error::Result<ProtocolOptions> {
        ProtocolOptions::from_value(Protocol::VsphereConsole, v)
    }

    #[test]
    fn defaults_ranges_and_unknown_fields() {
        let ProtocolOptions::Vsphere(d) = parse(json!({})).expect("{}") else { panic!("variant") };
        assert_eq!(d, super::VsphereConnOptions::default());
        assert_eq!(d.refresh_minutes, Some(60));
        assert!(!d.allow_power_actions && !d.allow_vmrc);
        assert!(parse(json!({"refreshMinutes": null})).is_ok());
        assert!(parse(json!({"refreshMinutes": 15})).is_ok());
        assert!(parse(json!({"refreshMinutes": 1440})).is_ok());
        assert!(parse(json!({"refreshMinutes": 14})).is_err());
        assert!(parse(json!({"refreshMinutes": 1441})).is_err());
        assert!(parse(json!({"allowPowerActions": true, "allowVmrc": true})).is_ok());
        assert!(parse(json!({"syncFolderId": "../x"})).is_err());
        assert!(parse(json!({"bogus": 1})).is_err());
        assert!(
            ProtocolOptions::default_for(Protocol::VsphereConsole).fits(Protocol::VsphereConsole)
        );
        assert!(!ProtocolOptions::default_for(Protocol::VsphereConsole).fits(Protocol::Ssh));
        let text = parse(json!({})).expect("ok").to_json().expect("json");
        assert!(text.contains("\"allowPowerActions\":false"), "{text}");
    }
}
