//! Inventory calls (ADR-0015 §2): datacenters → clusters → hosts → VMs, one list per host so
//! each stays under the API's 4 000-result limit, hard caps checked before anything is
//! returned, and lazy per-VM details / guest identity for the inspector.

use url::form_urlencoded::byte_serialize;

use crate::diff::{Inventory, InventoryItem, ItemKind};
use crate::error::VsphereError;
use crate::ids::{MoId, Name};
use crate::model::{
    ClusterList, ClusterSummary, DatacenterList, DatacenterSummary, GuestIdentity, HostList,
    HostSummary, PowerState, VmInfo, VmList, VmSummary, MAX_CLUSTERS, MAX_DATACENTERS, MAX_HOSTS,
};
use crate::session::Session;

/// Hard ceiling for [`Caps::vms`] (ADR-0015 §2: 20 000 VMs per vCenter).
pub const MAX_VMS_CEILING: usize = 20_000;
/// Default VMs per import (V1 task; configurable up to [`MAX_VMS_CEILING`]).
pub const DEFAULT_MAX_VMS: usize = 5_000;
/// Most values per filter field.
pub const MAX_FILTER_VALUES: usize = 1_000;

/// Size limits of one import; above any of them the refresh fails with `vsphere.too_large`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// Datacenters (≤ 64).
    pub datacenters: usize,
    /// Clusters (≤ 512).
    pub clusters: usize,
    /// Hosts (≤ 2 000).
    pub hosts: usize,
    /// VMs (≤ 20 000, default 5 000).
    pub vms: usize,
}

impl Default for Caps {
    fn default() -> Self {
        Self {
            datacenters: MAX_DATACENTERS,
            clusters: MAX_CLUSTERS,
            hosts: MAX_HOSTS,
            vms: DEFAULT_MAX_VMS,
        }
    }
}

impl Caps {
    /// Refuse caps above the ADR ceilings or zero.
    pub fn validate(&self) -> Result<(), VsphereError> {
        let ok = (1..=MAX_DATACENTERS).contains(&self.datacenters)
            && (1..=MAX_CLUSTERS).contains(&self.clusters)
            && (1..=MAX_HOSTS).contains(&self.hosts)
            && (1..=MAX_VMS_CEILING).contains(&self.vms);
        if ok {
            Ok(())
        } else {
            Err(VsphereError::Invalid("inventory caps out of range"))
        }
    }
}

/// Host list scope.
#[derive(Debug, Clone, Copy)]
pub enum HostScope<'a> {
    /// Hosts of one cluster.
    Cluster(&'a MoId),
    /// Hosts of a datacenter that are in no cluster (`standalone=true`).
    Standalone(&'a MoId),
    /// All hosts of a datacenter.
    Datacenter(&'a MoId),
}

/// `/api/vcenter/vm` filter (`VM.FilterSpec`). Empty = all VMs (API limit 4 000).
#[derive(Debug, Clone, Default)]
pub struct VmFilter {
    /// Specific VMs.
    pub vms: Vec<MoId>,
    /// Exact names.
    pub names: Vec<Name>,
    /// VM folders.
    pub folders: Vec<MoId>,
    /// Datacenters.
    pub datacenters: Vec<MoId>,
    /// Hosts.
    pub hosts: Vec<MoId>,
    /// Clusters.
    pub clusters: Vec<MoId>,
    /// Resource pools.
    pub resource_pools: Vec<MoId>,
    /// Power states.
    pub power_states: Vec<PowerState>,
}

fn power_name(p: PowerState) -> &'static str {
    match p {
        PowerState::PoweredOn => "POWERED_ON",
        PowerState::PoweredOff => "POWERED_OFF",
        PowerState::Suspended => "SUSPENDED",
    }
}

impl VmFilter {
    /// The query string (`?hosts=host-1&names=web%2001…`, empty when no filter is set).
    pub fn query(&self) -> Result<String, VsphereError> {
        let ids = [
            ("vms", &self.vms),
            ("folders", &self.folders),
            ("datacenters", &self.datacenters),
            ("hosts", &self.hosts),
            ("clusters", &self.clusters),
            ("resource_pools", &self.resource_pools),
        ];
        let too_many = ids.iter().any(|(_, v)| v.len() > MAX_FILTER_VALUES)
            || self.names.len() > MAX_FILTER_VALUES
            || self.power_states.len() > 3;
        if too_many {
            return Err(VsphereError::Invalid("too many filter values"));
        }
        let mut parts: Vec<String> = Vec::new();
        for (k, v) in ids {
            parts.extend(v.iter().map(|id| format!("{k}={id}"))); // MoId needs no encoding
        }
        for n in &self.names {
            parts.push(format!(
                "names={}",
                byte_serialize(n.as_str().as_bytes()).collect::<String>()
            ));
        }
        parts.extend(self.power_states.iter().map(|p| format!("power_states={}", power_name(*p))));
        Ok(if parts.is_empty() { String::new() } else { format!("?{}", parts.join("&")) })
    }
}

/// `GET /api/vcenter/vm/{vm}` plus the guest identity, for the inspector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmDetails {
    /// `vm-42`.
    pub id: MoId,
    /// Name.
    pub name: String,
    /// Power state.
    pub power_state: PowerState,
    /// Configured guest OS id.
    pub guest_os: Option<String>,
    /// vCPUs.
    pub cpu_count: Option<u32>,
    /// MiB.
    pub memory_mib: Option<u64>,
    /// The VM's instance UUID, when reported.
    pub instance_uuid: Option<String>,
    /// Guest identity (`None` without running `VMware` Tools).
    pub guest: Option<GuestIdentity>,
}

fn node(id: &str, kind: ItemKind, name: &str, parent: Option<&str>) -> InventoryItem {
    InventoryItem {
        external_id: id.to_owned(),
        kind,
        name: name.to_owned(),
        parent: parent.map(str::to_owned),
        power_state: None,
        cpu_count: None,
        memory_mib: None,
    }
}

/// `external_id` of a datacenter's "Standalone hosts" pseudo-cluster.
pub fn standalone_id(dc: &MoId) -> String {
    format!("standalone-{dc}")
}

impl Session {
    /// `GET /api/vcenter/datacenter`.
    pub async fn datacenters(&self) -> Result<Vec<DatacenterSummary>, VsphereError> {
        self.get::<DatacenterList>("/api/vcenter/datacenter").await?.into_vec("datacenters")
    }

    /// `GET /api/vcenter/cluster?datacenters=<dc>`.
    pub async fn clusters(&self, dc: &MoId) -> Result<Vec<ClusterSummary>, VsphereError> {
        let path = format!("/api/vcenter/cluster?datacenters={dc}");
        self.get::<ClusterList>(&path).await?.into_vec("clusters")
    }

    /// `GET /api/vcenter/host?…`.
    pub async fn hosts(&self, scope: HostScope<'_>) -> Result<Vec<HostSummary>, VsphereError> {
        let path = match scope {
            HostScope::Cluster(c) => format!("/api/vcenter/host?clusters={c}"),
            HostScope::Standalone(dc) => {
                format!("/api/vcenter/host?datacenters={dc}&standalone=true")
            }
            HostScope::Datacenter(dc) => format!("/api/vcenter/host?datacenters={dc}"),
        };
        self.get::<HostList>(&path).await?.into_vec("hosts")
    }

    /// `GET /api/vcenter/vm?<filter>`; more than 4 000 results → `vsphere.too_large`.
    pub async fn vms(&self, filter: &VmFilter) -> Result<Vec<VmSummary>, VsphereError> {
        let path = format!("/api/vcenter/vm{}", filter.query()?);
        self.get::<VmList>(&path).await?.into_vec("VM list")
    }

    /// `GET /api/vcenter/vm/{vm}/guest/identity`; `None` while `VMware` Tools are not running
    /// (the API answers 503 `SERVICE_UNAVAILABLE`).
    pub async fn guest_identity(&self, vm: &MoId) -> Result<Option<GuestIdentity>, VsphereError> {
        match self.get::<GuestIdentity>(&format!("/api/vcenter/vm/{vm}/guest/identity")).await {
            Ok(g) => Ok(Some(g)),
            Err(VsphereError::Unavailable) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `GET /api/vcenter/vm/{vm}` and its guest identity.
    pub async fn vm(&self, vm: &MoId) -> Result<VmDetails, VsphereError> {
        let info: VmInfo = self.get(&format!("/api/vcenter/vm/{vm}")).await?;
        let guest = self.guest_identity(vm).await?;
        Ok(VmDetails {
            id: vm.clone(),
            name: info.name.as_str().to_owned(),
            power_state: info.power_state,
            guest_os: info.guest_os.map(|g| g.as_str().to_owned()),
            cpu_count: info.cpu.map(|c| c.count),
            memory_mib: info.memory.map(|m| m.size_mib),
            instance_uuid: info
                .identity
                .and_then(|i| i.instance_uuid)
                .map(|u| u.as_str().to_owned()),
            guest,
        })
    }

    /// Fetch the whole tree. Any cap above `caps` fails with `vsphere.too_large` and returns
    /// nothing, so the store is never half-written.
    pub async fn inventory(&self, caps: &Caps) -> Result<Inventory, VsphereError> {
        caps.validate()?;
        let mut inv = Inventory::new();
        let (mut n_clusters, mut n_hosts, mut n_vms) = (0usize, 0usize, 0usize);
        let dcs = self.datacenters().await?;
        if dcs.len() > caps.datacenters {
            return Err(VsphereError::TooLarge("datacenters"));
        }
        for dc in &dcs {
            let dc_id = dc.datacenter.as_str();
            inv.insert(node(dc_id, ItemKind::Datacenter, dc.name.as_str(), None))?;
            let mut groups: Vec<(String, Vec<HostSummary>)> = Vec::new();
            for c in self.clusters(&dc.datacenter).await? {
                n_clusters += 1;
                if n_clusters > caps.clusters {
                    return Err(VsphereError::TooLarge("clusters"));
                }
                let id = c.cluster.as_str();
                inv.insert(node(id, ItemKind::Cluster, c.name.as_str(), Some(dc_id)))?;
                groups.push((id.to_owned(), self.hosts(HostScope::Cluster(&c.cluster)).await?));
            }
            let standalone = self.hosts(HostScope::Standalone(&dc.datacenter)).await?;
            if !standalone.is_empty() {
                let sid = standalone_id(&dc.datacenter);
                let pseudo = node(&sid, ItemKind::StandaloneHosts, "Standalone hosts", Some(dc_id));
                inv.insert(pseudo)?;
                groups.push((sid, standalone));
            }
            for (parent, hosts) in groups {
                for h in hosts {
                    n_hosts += 1;
                    if n_hosts > caps.hosts {
                        return Err(VsphereError::TooLarge("hosts"));
                    }
                    let hid = h.host.as_str();
                    inv.insert(node(hid, ItemKind::Host, h.name.as_str(), Some(&parent)))?;
                    let filter = VmFilter { hosts: vec![h.host.clone()], ..VmFilter::default() };
                    for vm in self.vms(&filter).await? {
                        n_vms += 1;
                        if n_vms > caps.vms {
                            return Err(VsphereError::TooLarge("VMs"));
                        }
                        let mut item =
                            node(vm.vm.as_str(), ItemKind::Vm, vm.name.as_str(), Some(hid));
                        item.power_state = Some(vm.power_state);
                        item.cpu_count = vm.cpu_count;
                        item.memory_mib = vm.memory_size_mib;
                        inv.insert(item)?;
                    }
                }
            }
        }
        Ok(inv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_query_encodes_names_only() {
        let f = VmFilter {
            hosts: vec![MoId::new("host-1").expect("id"), MoId::new("host-2").expect("id")],
            names: vec![Name::new("web 01&x=y/../#").expect("name")],
            power_states: vec![PowerState::PoweredOn],
            ..VmFilter::default()
        };
        let q = f.query().expect("query");
        assert_eq!(
            q,
            "?hosts=host-1&hosts=host-2&names=web+01%26x%3Dy%2F..%2F%23&power_states=POWERED_ON"
        );
        assert_eq!(VmFilter::default().query().expect("empty"), "");
        let many =
            VmFilter { hosts: vec![MoId::new("h-1").expect("id"); 1001], ..VmFilter::default() };
        assert!(many.query().is_err());
    }

    #[test]
    fn caps_bounds() {
        assert!(Caps::default().validate().is_ok());
        assert_eq!(Caps::default().vms, 5_000);
        assert!(Caps { vms: 20_001, ..Caps::default() }.validate().is_err());
        assert!(Caps { hosts: 0, ..Caps::default() }.validate().is_err());
    }
}
