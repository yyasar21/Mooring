//! Wire models of the vSphere Automation REST API (`/api`, vCenter 7.0+), deserialised from
//! the capped body into **our** types. Unknown fields are ignored (ADR-0015 §1: vCenter adds
//! fields between updates and a refresh must not break on them); every string, id and array is
//! bounded and every type is checked, so a wrong type fails the whole response.

use serde::{Deserialize, Serialize};

use crate::ids::{Capped, MoId, Name};

/// Most datacenters per vCenter (ADR-0015 §2).
pub const MAX_DATACENTERS: usize = 64;
/// Most clusters per vCenter.
pub const MAX_CLUSTERS: usize = 512;
/// Most hosts per vCenter.
pub const MAX_HOSTS: usize = 2_000;
/// The API's own per-list result limit (`/api/vcenter/vm` refuses above it).
pub const MAX_LIST: usize = 4_000;

/// VM power state (`Vm.Power.State`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PowerState {
    /// Running.
    PoweredOn,
    /// Off.
    PoweredOff,
    /// Suspended.
    Suspended,
}

/// `GET /api/vcenter/datacenter` element.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DatacenterSummary {
    /// `datacenter-3`.
    pub datacenter: MoId,
    /// Display name.
    pub name: Name,
}

/// `GET /api/vcenter/cluster` element.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ClusterSummary {
    /// `domain-c8`.
    pub cluster: MoId,
    /// Display name.
    pub name: Name,
    /// vSphere HA.
    #[serde(default)]
    pub ha_enabled: Option<bool>,
    /// DRS.
    #[serde(default)]
    pub drs_enabled: Option<bool>,
}

/// Host connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostConnectionState {
    /// Connected.
    Connected,
    /// Disconnected.
    Disconnected,
    /// Not responding.
    NotResponding,
}

/// Host power state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostPowerState {
    /// On.
    PoweredOn,
    /// Off.
    PoweredOff,
    /// Standby.
    Standby,
}

/// `GET /api/vcenter/host` element.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HostSummary {
    /// `host-7`.
    pub host: MoId,
    /// Display name (usually the `ESXi` FQDN).
    pub name: Name,
    /// Connection state.
    pub connection_state: HostConnectionState,
    /// Power state (absent while disconnected).
    #[serde(default)]
    pub power_state: Option<HostPowerState>,
}

/// `GET /api/vcenter/vm` element.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct VmSummary {
    /// `vm-42`.
    pub vm: MoId,
    /// Display name.
    pub name: Name,
    /// Power state.
    pub power_state: PowerState,
    /// vCPUs.
    #[serde(default)]
    pub cpu_count: Option<u32>,
    /// Memory in MiB.
    #[serde(default, rename = "memory_size_MiB")]
    pub memory_size_mib: Option<u64>,
}

/// `Vm.IdentityInfo` (vCenter 7.0 U1+).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct VmIdentity {
    /// The VM's instance UUID (not the vCenter's).
    #[serde(default)]
    pub instance_uuid: Option<Name>,
    /// BIOS UUID.
    #[serde(default)]
    pub bios_uuid: Option<Name>,
}

/// `Vm.CpuInfo`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct VmCpu {
    /// vCPUs.
    pub count: u32,
    /// Cores per socket.
    #[serde(default)]
    pub cores_per_socket: Option<u32>,
}

/// `Vm.MemoryInfo`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct VmMemory {
    /// MiB.
    #[serde(rename = "size_MiB")]
    pub size_mib: u64,
}

/// `GET /api/vcenter/vm/{vm}` (`Vm.Info`). Only the fields the inspector shows are read;
/// disks, NICs, CD-ROMs and the rest are skipped without being kept.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct VmInfo {
    /// Display name.
    pub name: Name,
    /// Power state.
    pub power_state: PowerState,
    /// Guest OS identifier (`RHEL_9_64`, `WINDOWS_SERVER_2022`, …), as configured.
    #[serde(default, rename = "guest_OS")]
    pub guest_os: Option<Name>,
    /// CPU.
    #[serde(default)]
    pub cpu: Option<VmCpu>,
    /// Memory.
    #[serde(default)]
    pub memory: Option<VmMemory>,
    /// Identity (UUIDs), when the vCenter reports it.
    #[serde(default)]
    pub identity: Option<VmIdentity>,
}

/// `GET /api/vcenter/vm/{vm}/power`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PowerInfo {
    /// State.
    pub state: PowerState,
}

/// Localizable message (`std.LocalizableMessage`): only the default text, bounded.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Localizable {
    /// English text.
    #[serde(default)]
    pub default_message: Option<Name>,
}

/// `GET /api/vcenter/vm/{vm}/guest/identity` (needs `VMware` Tools).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct GuestIdentity {
    /// Guest host name.
    #[serde(default)]
    pub host_name: Option<Name>,
    /// Primary IP address, validated as an IPv4 / IPv6 literal.
    #[serde(default, deserialize_with = "ip_opt")]
    pub ip_address: Option<std::net::IpAddr>,
    /// OS family (`LINUX`, `WINDOWS`, …), as reported.
    #[serde(default)]
    pub family: Option<Name>,
    /// Full OS name.
    #[serde(default, skip_serializing)]
    pub full_name: Option<Localizable>,
}

fn ip_opt<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<std::net::IpAddr>, D::Error> {
    let s: Option<Name> = Option::deserialize(d)?;
    match s {
        None => Ok(None),
        Some(s) if s.as_str().is_empty() => Ok(None),
        Some(s) => s.as_str().parse().map(Some).map_err(serde::de::Error::custom),
    }
}

/// `POST /api/vcenter/vm/{vm}/console/tickets` response.
#[derive(Deserialize)]
pub(crate) struct TicketResponse {
    /// Wrapped into `Zeroizing` right after decoding.
    pub(crate) ticket: String,
}

/// List types with their caps.
pub(crate) type DatacenterList = Capped<DatacenterSummary, MAX_DATACENTERS>;
pub(crate) type ClusterList = Capped<ClusterSummary, MAX_CLUSTERS>;
pub(crate) type HostList = Capped<HostSummary, MAX_HOSTS>;
pub(crate) type VmList = Capped<VmSummary, MAX_LIST>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixtures_parse_and_ignore_unknown_fields() {
        let dc: DatacenterList =
            serde_json::from_str(r#"[{"datacenter":"datacenter-3","name":"DC1","x":{"y":[1]}}]"#)
                .expect("dc");
        assert_eq!(dc.items[0].datacenter.as_str(), "datacenter-3");
        let h: HostList = serde_json::from_str(
            r#"[{"host":"host-7","name":"esx01.example.test","connection_state":"CONNECTED","power_state":"POWERED_ON"},
                {"host":"host-9","name":"esx02.example.test","connection_state":"NOT_RESPONDING"}]"#,
        )
        .expect("hosts");
        assert_eq!(h.items[1].power_state, None);
        let vm: VmList = serde_json::from_str(
            r#"[{"vm":"vm-42","name":"web-01","power_state":"POWERED_ON","cpu_count":2,"memory_size_MiB":4096,"new_field":true}]"#,
        )
        .expect("vms");
        assert_eq!(vm.items[0].memory_size_mib, Some(4096));
        let info: VmInfo = serde_json::from_str(
            r#"{"name":"web-01","power_state":"POWERED_OFF","guest_OS":"RHEL_9_64",
                "cpu":{"count":4,"cores_per_socket":2,"hot_add_enabled":false},
                "memory":{"size_MiB":8192,"hot_add_enabled":false},
                "identity":{"name":"web-01","instance_uuid":"5003a1b2-0000-4000-8000-000000000001"},
                "disks":{"2000":{"label":"Hard disk 1"}},"nics":{},"boot":{"type":"BIOS"}}"#,
        )
        .expect("info");
        assert_eq!(info.memory.map(|m| m.size_mib), Some(8192));
        let g: GuestIdentity = serde_json::from_str(
            r#"{"name":"RHEL_9_64","family":"LINUX","host_name":"web-01","ip_address":"192.0.2.10",
                "full_name":{"args":[],"default_message":"Red Hat Enterprise Linux 9 (64-bit)","id":"x"}}"#,
        )
        .expect("guest");
        assert_eq!(g.ip_address, Some("192.0.2.10".parse().expect("ip")));
    }

    #[test]
    fn hostile_fixtures_are_refused() {
        // wrong types
        assert!(serde_json::from_str::<VmList>(
            r#"[{"vm":42,"name":"a","power_state":"POWERED_ON"}]"#
        )
        .is_err());
        assert!(serde_json::from_str::<VmList>(r#"{"vm":"vm-1"}"#).is_err());
        assert!(serde_json::from_str::<VmList>(
            r#"[{"vm":"vm-1","name":"a","power_state":"MELTED"}]"#
        )
        .is_err());
        assert!(serde_json::from_str::<VmList>(
            r#"[{"vm":"vm-1","name":"a","power_state":"POWERED_ON","cpu_count":-1}]"#
        )
        .is_err());
        // bad ids / names
        assert!(serde_json::from_str::<VmList>(
            r#"[{"vm":"vm-1/../x","name":"a","power_state":"POWERED_ON"}]"#
        )
        .is_err());
        let long = "n".repeat(300);
        assert!(serde_json::from_str::<DatacenterList>(&format!(
            r#"[{{"datacenter":"d-1","name":"{long}"}}]"#
        ))
        .is_err());
        // huge arrays: refused as too large, the tail is never decoded
        let one = r#"{"datacenter":"d-1","name":"a"}"#;
        let many = format!("[{},{{\"junk\":1}}]", vec![one; MAX_DATACENTERS].join(","));
        let parsed = serde_json::from_str::<DatacenterList>(&many).expect("parsed");
        assert_eq!(
            parsed.into_vec("datacenters").map_err(|e| e.code()).err(),
            Some("vsphere.too_large")
        );
        let ok = format!("[{}]", vec![one; MAX_DATACENTERS].join(","));
        assert!(serde_json::from_str::<DatacenterList>(&ok).expect("ok").into_vec("dc").is_ok());
        // bad IP
        assert!(serde_json::from_str::<GuestIdentity>(r#"{"ip_address":"192.0.2.1; rm"}"#).is_err());
        assert_eq!(
            serde_json::from_str::<GuestIdentity>(r#"{"ip_address":""}"#).expect("g").ip_address,
            None
        );
    }
}
