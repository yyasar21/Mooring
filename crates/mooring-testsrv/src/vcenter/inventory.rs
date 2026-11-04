//! Synthetic vCenter inventory: datacenters → clusters → hosts → VMs, plus standalone hosts.

use serde_json::{json, Value};

/// Shape of the generated inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InventorySpec {
    pub datacenters: usize,
    pub clusters_per_dc: usize,
    pub hosts_per_cluster: usize,
    /// Hosts per datacenter outside any cluster ("Standalone hosts" in ADR-0015 §2).
    pub standalone_hosts_per_dc: usize,
    pub vms_per_host: usize,
}

impl Default for InventorySpec {
    fn default() -> Self {
        Self {
            datacenters: 1,
            clusters_per_dc: 2,
            hosts_per_cluster: 2,
            standalone_hosts_per_dc: 1,
            vms_per_host: 3,
        }
    }
}

impl InventorySpec {
    /// One datacenter, one cluster, one host carrying `n` VMs (the 4 000-result cap test).
    pub fn one_host(n: usize) -> Self {
        Self {
            datacenters: 1,
            clusters_per_dc: 1,
            hosts_per_cluster: 1,
            standalone_hosts_per_dc: 0,
            vms_per_host: n,
        }
    }

    /// About `total` VMs spread over 1 datacenter, 4 clusters × 5 hosts (cap / scale tests).
    pub fn total_vms(total: usize) -> Self {
        Self {
            datacenters: 1,
            clusters_per_dc: 4,
            hosts_per_cluster: 5,
            standalone_hosts_per_dc: 0,
            vms_per_host: total.div_ceil(20),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datacenter {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cluster {
    pub id: String,
    pub name: String,
    pub datacenter: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    pub id: String,
    pub name: String,
    pub datacenter: String,
    pub cluster: Option<String>,
}

/// `POWERED_ON`, `POWERED_OFF` or `SUSPENDED`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vm {
    pub id: String,
    pub name: String,
    pub host: String,
    pub power_state: String,
    /// VMware Tools running (guest power and `guest/identity` need it).
    pub tools: bool,
    pub ip: String,
}

/// The whole inventory; mutated by power actions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inventory {
    pub datacenters: Vec<Datacenter>,
    pub clusters: Vec<Cluster>,
    pub hosts: Vec<Host>,
    pub vms: Vec<Vm>,
}

impl Inventory {
    /// Deterministic inventory: every third VM is off; every fifth has no Tools.
    pub fn generate(spec: InventorySpec) -> Self {
        let mut inv = Self::default();
        let (mut c, mut h) = (0usize, 0usize);
        for d in 1..=spec.datacenters {
            let dc = format!("datacenter-{d}");
            inv.datacenters.push(Datacenter { id: dc.clone(), name: format!("dc-{d}") });
            let mut hosts_here = Vec::new();
            for _ in 0..spec.clusters_per_dc {
                c += 1;
                let cl = format!("domain-c{c}");
                inv.clusters.push(Cluster {
                    id: cl.clone(),
                    name: format!("cluster-{c}"),
                    datacenter: dc.clone(),
                });
                for _ in 0..spec.hosts_per_cluster {
                    h += 1;
                    hosts_here.push((h, Some(cl.clone())));
                }
            }
            for _ in 0..spec.standalone_hosts_per_dc {
                h += 1;
                hosts_here.push((h, None));
            }
            for (n, cluster) in hosts_here {
                let id = format!("host-{n}");
                let name = format!("esx-{n}.example.test");
                inv.hosts.push(Host { id, name, datacenter: dc.clone(), cluster });
            }
        }
        let mut v = 0usize;
        for host in &inv.hosts {
            for _ in 0..spec.vms_per_host {
                v += 1;
                let on = !v.is_multiple_of(3);
                inv.vms.push(Vm {
                    id: format!("vm-{v}"),
                    name: format!("vm-{v:05}"),
                    host: host.id.clone(),
                    power_state: if on { "POWERED_ON" } else { "POWERED_OFF" }.to_owned(),
                    tools: on && !v.is_multiple_of(5),
                    ip: format!("198.51.100.{}", v % 254 + 1),
                });
            }
        }
        inv
    }

    pub fn host(&self, id: &str) -> Option<&Host> {
        self.hosts.iter().find(|h| h.id == id)
    }

    pub fn vm_mut(&mut self, id: &str) -> Option<&mut Vm> {
        self.vms.iter_mut().find(|v| v.id == id)
    }
}

impl Datacenter {
    pub fn to_json(&self) -> Value {
        json!({ "datacenter": self.id, "name": self.name })
    }
}

impl Cluster {
    pub fn to_json(&self) -> Value {
        json!({ "cluster": self.id, "name": self.name, "ha_enabled": true, "drs_enabled": true })
    }
}

impl Host {
    pub fn to_json(&self) -> Value {
        json!({ "host": self.id, "name": self.name, "connection_state": "CONNECTED",
                "power_state": "POWERED_ON" })
    }
}

impl Vm {
    pub fn to_json(&self) -> Value {
        json!({ "vm": self.id, "name": self.name, "power_state": self.power_state,
                "cpu_count": 2, "memory_size_MiB": 4096 })
    }

    pub fn detail_json(&self) -> Value {
        json!({ "name": self.name, "power_state": self.power_state, "guest_OS": "OTHER_LINUX_64",
                "cpu": { "count": 2, "cores_per_socket": 1 }, "memory": { "size_MiB": 4096 },
                "identity": { "name": self.name, "instance_uuid": format!("uuid-{}", self.id) } })
    }
}

#[cfg(test)]
mod tests {
    use super::{Inventory, InventorySpec};

    #[test]
    fn default_and_large_shapes() {
        let inv = Inventory::generate(InventorySpec::default());
        assert_eq!((inv.datacenters.len(), inv.clusters.len(), inv.hosts.len()), (1, 2, 5));
        assert_eq!(inv.vms.len(), 15);
        assert_eq!(inv.hosts.iter().filter(|h| h.cluster.is_none()).count(), 1);
        let big = Inventory::generate(InventorySpec::total_vms(5000));
        assert_eq!(big.vms.len(), 5000);
        assert!(big.vms.iter().all(|v| v.ip.starts_with("198.51.100.")));
    }
}
