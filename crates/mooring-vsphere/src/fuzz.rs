//! Panic-free entry points for QA's cargo-fuzz targets (ADR-0015 §Test plan).
//!
//! | target | entry |
//! | --- | --- |
//! | `vsphere_inventory_json` | [`fuzz_inventory_json`] |
//! | `vsphere_session_token` | [`fuzz_session_token`] |
//! | `vsphere_ticket_url` | [`fuzz_ticket_url`] |

use crate::ids::MoId;
use crate::model::{
    ClusterList, DatacenterList, GuestIdentity, HostList, PowerInfo, VmInfo, VmList,
};

/// The first byte selects the model, the rest is the (≤ 8 MiB) body. Every accepted model
/// must satisfy the caps.
pub fn fuzz_inventory_json(data: &[u8]) {
    let Some((sel, body)) = data.split_first() else { return };
    if body.len() > crate::session::MAX_BODY {
        return;
    }
    match sel % 7 {
        0 => {
            if let Ok(l) = serde_json::from_slice::<DatacenterList>(body) {
                assert!(l.items.len() <= crate::model::MAX_DATACENTERS);
            }
        }
        1 => {
            if let Ok(l) = serde_json::from_slice::<ClusterList>(body) {
                assert!(l.items.len() <= crate::model::MAX_CLUSTERS);
            }
        }
        2 => {
            if let Ok(l) = serde_json::from_slice::<HostList>(body) {
                assert!(l.items.len() <= crate::model::MAX_HOSTS);
            }
        }
        3 => {
            if let Ok(l) = serde_json::from_slice::<VmList>(body) {
                assert!(l.items.len() <= crate::model::MAX_LIST);
                for v in &l.items {
                    assert!(MoId::new(v.vm.as_str()).is_ok());
                    assert!(crate::ids::valid_name(v.name.as_str()));
                }
            }
        }
        4 => {
            let _ = serde_json::from_slice::<VmInfo>(body);
        }
        5 => {
            let _ = serde_json::from_slice::<GuestIdentity>(body);
        }
        _ => {
            let _ = serde_json::from_slice::<PowerInfo>(body);
        }
    }
}

/// `POST /api/session` body.
pub fn fuzz_session_token(data: &[u8]) {
    if let Ok(t) = crate::session::parse_session_token(data) {
        assert!(!t.is_empty() && t.len() <= crate::session::MAX_TOKEN);
        assert!(t.bytes().all(|b| b.is_ascii_graphic()));
    }
}

/// VMRC ticket URL against a fixed host and VM.
pub fn fuzz_ticket_url(data: &[u8]) {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let Ok(vm) = MoId::new("vm-42") else { return };
    if let Ok(u) = crate::console::parse_vmrc_ticket(s, "vc.example.test", &vm) {
        assert!(u.starts_with("vmrc:") && u.len() <= crate::console::MAX_TICKET_URL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn entries_never_panic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            fuzz_inventory_json(&data);
            fuzz_session_token(&data);
            fuzz_ticket_url(&data);
        }

        #[test]
        fn json_shaped_inputs(sel in 0u8..7, s in r#"[\[\]{}",:a-z0-9_ ]{0,200}"#) {
            let mut d = vec![sel];
            d.extend_from_slice(s.as_bytes());
            fuzz_inventory_json(&d);
        }
    }
}
