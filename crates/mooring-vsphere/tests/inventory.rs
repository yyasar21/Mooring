//! Inventory walk, caps, hostile bodies, rate limiting.

mod common;

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::{reply, serve, with_header};
use mooring_vsphere::{diff, Caps, ItemKind, MoId, PowerState, VmFilter};

#[tokio::test]
async fn full_tree_with_standalone_hosts() {
    let m = serve().await;
    let s = m.login().await;
    let inv = s.inventory(&Caps::default()).await.expect("inventory");
    assert_eq!(inv.vm_count(), 6);
    let dc = inv.get("datacenter-1").expect("dc");
    assert_eq!((dc.kind, dc.name.as_str()), (ItemKind::Datacenter, "DC-Istanbul"));
    let pseudo = inv.get("standalone-datacenter-1").expect("pseudo");
    assert_eq!(pseudo.kind, ItemKind::StandaloneHosts);
    assert_eq!(
        inv.get("host-3").and_then(|h| h.parent.as_deref()),
        Some("standalone-datacenter-1")
    );
    let vm = inv.get("vm-201").expect("vm");
    assert_eq!(vm.parent.as_deref(), Some("host-2"));
    assert_eq!(
        (vm.power_state, vm.cpu_count, vm.memory_mib),
        (Some(PowerState::PoweredOn), Some(2), Some(2048))
    );
    // one VM list per host, never an unfiltered list
    assert_eq!(m.vc.count("GET", "/api/vcenter/vm?hosts="), 3);
    assert_eq!(m.vc.count("GET", "/api/vcenter/vm?"), 3);

    // a second identical refresh diffs to nothing
    let again = s.inventory(&Caps::default()).await.expect("inventory");
    assert!(diff(&inv, &again, &BTreeMap::new()).is_empty());
}

#[tokio::test]
async fn caps_fail_the_whole_refresh() {
    let m = serve().await;
    let s = m.login().await;
    let e = s.inventory(&Caps { vms: 5, ..Caps::default() }).await.expect_err("cap");
    assert_eq!(e.code(), "vsphere.too_large");
    let e = s.inventory(&Caps { hosts: 2, ..Caps::default() }).await.expect_err("cap");
    assert_eq!(e.code(), "vsphere.too_large");
    assert!(s.inventory(&Caps { vms: 20_001, ..Caps::default() }).await.is_err());
}

#[tokio::test]
async fn more_than_4000_vms_on_one_host_is_too_large() {
    let m = serve().await;
    m.vc.vms_per_host.store(4_001, Ordering::SeqCst);
    let s = m.login().await;
    let f = VmFilter { hosts: vec![MoId::new("host-1").expect("id")], ..VmFilter::default() };
    assert_eq!(s.vms(&f).await.expect_err("4001").code(), "vsphere.too_large");
    m.vc.vms_per_host.store(4_000, Ordering::SeqCst);
    assert_eq!(s.vms(&f).await.expect("4000").len(), 4_000);
}

#[tokio::test]
async fn ten_megabyte_body_is_refused() {
    let m = serve().await;
    m.vc.on("/api/vcenter/datacenter", |_, _| reply(200, vec![b' '; 10 * 1024 * 1024]));
    let s = m.login().await;
    assert_eq!(s.datacenters().await.expect_err("10 MB").code(), "vsphere.too_large");
}

#[tokio::test]
async fn hostile_documents_are_bad_responses() {
    let m = serve().await;
    let s = m.login().await;
    for body in [
        r#"[{"datacenter":42,"name":"x"}]"#,
        r#"{"datacenter":"datacenter-1"}"#,
        r#"[{"datacenter":"datacenter-1/../x","name":"x"}]"#,
        r#"[{"datacenter":"datacenter-1","name":"a\u001b[2J"}]"#,
        "[",
    ] {
        let b = body.to_owned();
        m.vc.on("/api/vcenter/datacenter", move |_, _| reply(200, b.clone()));
        let e = s.datacenters().await.expect_err(body);
        assert_eq!(e.code(), "vsphere.failed", "{body}");
        assert!(!e.to_string().contains("datacenter-1"), "no server text in errors");
    }
    // a VM listed under two hosts is refused instead of silently picked
    m.vc.on("/api/vcenter/datacenter", |_, _| {
        reply(200, r#"[{"datacenter":"datacenter-1","name":"DC"}]"#)
    });
    m.vc.on("/api/vcenter/vm?hosts=", |_, _| {
        reply(200, r#"[{"vm":"vm-1","name":"dup","power_state":"POWERED_OFF"}]"#)
    });
    assert_eq!(s.inventory(&Caps::default()).await.expect_err("dup").code(), "vsphere.failed");
}

#[tokio::test]
async fn vm_details_and_guest_identity() {
    let m = serve().await;
    // overrides match by prefix, latest first
    m.vc.on("/api/vcenter/vm/vm-10", |_, _| {
        reply(200, r#"{"name":"web-01","power_state":"POWERED_ON","guest_OS":"RHEL_9_64","cpu":{"count":4},"memory":{"size_MiB":8192},"identity":{"instance_uuid":"5003a1b2-0000-4000-8000-000000000001"},"nics":{"4000":{}}}"#)
    });
    m.vc.on("/api/vcenter/vm/vm-101/guest/identity", |_, _| {
        reply(200, r#"{"family":"LINUX","host_name":"web-01","ip_address":"192.0.2.10","name":"RHEL_9_64"}"#)
    });
    m.vc.on("/api/vcenter/vm/vm-102/guest/identity", |_, _| {
        reply(503, r#"{"error_type":"SERVICE_UNAVAILABLE","messages":[]}"#)
    });
    let s = m.login().await;
    let d = s.vm(&MoId::new("vm-101").expect("id")).await.expect("details");
    assert_eq!((d.cpu_count, d.memory_mib), (Some(4), Some(8192)));
    assert_eq!(
        d.guest.and_then(|g| g.ip_address).map(|ip| ip.to_string()).as_deref(),
        Some("192.0.2.10")
    );
    let d = s.vm(&MoId::new("vm-102").expect("id")).await.expect("details");
    assert!(d.guest.is_none(), "tools not running → no identity");
    assert_eq!(
        s.vm(&MoId::new("vm-999").expect("id")).await.expect_err("404").code(),
        "vsphere.not_found"
    );
}

#[tokio::test]
async fn rate_limit_backs_off_then_reports_retry_after() {
    let m = serve().await;
    m.vc.on("/api/vcenter/datacenter", |_, n| {
        if n < 2 {
            with_header(reply(429, ""), "retry-after", "0")
        } else {
            reply(200, r#"[{"datacenter":"datacenter-1","name":"DC"}]"#)
        }
    });
    let s = m.login().await;
    assert_eq!(s.datacenters().await.expect("after backoff").len(), 1);
    assert_eq!(m.vc.count("GET", "/api/vcenter/datacenter"), 3);

    m.vc.on("/api/vcenter/cluster", |_, _| with_header(reply(429, ""), "retry-after", "7"));
    let e = s.clusters(&MoId::new("datacenter-1").expect("id")).await.expect_err("429");
    assert_eq!(e.code(), "vsphere.rate_limited");
    assert_eq!(e.retry_after(), Some(Duration::from_secs(7)));
    assert_eq!(m.vc.count("GET", "/api/vcenter/cluster"), 3, "bounded retries");
}

#[tokio::test]
async fn filters_reach_the_api() {
    let m = serve().await;
    m.vc.on("/api/vcenter/vm?", |_, _| reply(200, "[]"));
    let s = m.login().await;
    let f = VmFilter {
        clusters: vec![MoId::new("domain-c1").expect("id")],
        power_states: vec![PowerState::PoweredOff, PowerState::Suspended],
        ..VmFilter::default()
    };
    assert!(s.vms(&f).await.expect("vms").is_empty());
    let last = m.vc.requests().pop().expect("req");
    assert_eq!(
        last.path,
        "/api/vcenter/vm?clusters=domain-c1&power_states=POWERED_OFF&power_states=SUSPENDED"
    );
}
