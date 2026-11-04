use super::*;

fn item(id: &str, kind: ItemKind, name: &str, parent: Option<&str>) -> InventoryItem {
    InventoryItem {
        external_id: id.into(),
        kind,
        name: name.into(),
        parent: parent.map(Into::into),
        power_state: (kind == ItemKind::Vm).then_some(PowerState::PoweredOn),
        cpu_count: None,
        memory_mib: None,
    }
}

fn base() -> Vec<InventoryItem> {
    vec![
        item("datacenter-1", ItemKind::Datacenter, "DC", None),
        item("domain-c1", ItemKind::Cluster, "C1", Some("datacenter-1")),
        item("host-1", ItemKind::Host, "esx1", Some("domain-c1")),
        item("host-2", ItemKind::Host, "esx2", Some("domain-c1")),
        item("vm-1", ItemKind::Vm, "web", Some("host-1")),
        item("vm-2", ItemKind::Vm, "db", Some("host-1")),
    ]
}

fn inv(items: Vec<InventoryItem>) -> Inventory {
    Inventory::from_items(items).expect("valid")
}

#[test]
fn snapshot_validation() {
    assert!(Inventory::from_items(vec![item("vm-1", ItemKind::Vm, "x", Some("host-9"))]).is_err());
    let mut dup = base();
    dup.push(item("vm-1", ItemKind::Vm, "again", Some("host-2")));
    assert!(Inventory::from_items(dup).is_err());
    let wrong = vec![
        item("datacenter-1", ItemKind::Datacenter, "DC", None),
        item("vm-1", ItemKind::Vm, "x", Some("datacenter-1")),
    ];
    assert!(Inventory::from_items(wrong).is_err());
    let i = inv(base());
    assert_eq!((i.len(), i.vm_count()), (6, 2));
}

#[test]
fn add_rename_move_and_details() {
    let old = inv(base());
    let mut next = base();
    next[4].name = "web-renamed".into(); // vm-1 renamed
    next[5].parent = Some("host-2".into()); // vm-2 vMotion
    next.push(item("vm-3", ItemKind::Vm, "new", Some("host-2")));
    next.push(item(
        "standalone-datacenter-1",
        ItemKind::StandaloneHosts,
        "Standalone hosts",
        Some("datacenter-1"),
    ));
    next.push(item("host-3", ItemKind::Host, "esx3", Some("standalone-datacenter-1")));
    next[3].name = "esx2".into();
    let mut off = next[4].clone();
    off.power_state = Some(PowerState::PoweredOff);
    off.name = "web".into();
    let d = diff(&old, &inv(next.clone()), &BTreeMap::new());
    let added: Vec<_> = d.added.iter().map(|i| i.external_id.as_str()).collect();
    assert_eq!(added, ["standalone-datacenter-1", "host-3", "vm-3"], "parents first");
    assert_eq!(d.changed.len(), 2);
    assert!(d.changed.iter().any(|c| c.new.external_id == "vm-1" && c.renamed && !c.moved));
    assert!(d.changed.iter().any(|c| c.new.external_id == "vm-2" && c.moved && !c.renamed));
    assert!(d.removed.is_empty() && d.missing.is_empty());

    next[4] = off;
    let d = diff(&old, &inv(next), &BTreeMap::new());
    assert!(d.changed.iter().any(|c| c.new.external_id == "vm-1" && c.details_only));
}

#[test]
fn missing_twice_deletes_and_streak_round_trips() {
    let full = inv(base());
    let without_vm2 = inv(base().into_iter().filter(|i| i.external_id != "vm-2").collect());

    // refresh 1: vm-2 gone → missing, streak 1, not deleted
    let d1 = diff(&full, &without_vm2, &BTreeMap::new());
    assert_eq!(d1.missing, ["vm-2"]);
    assert!(d1.removed.is_empty());
    assert_eq!(d1.missing_streak.get("vm-2"), Some(&1));

    // the store keeps vm-2 (marked missing); refresh 2: still gone → removed
    let d2 = diff(&full, &without_vm2, &d1.missing_streak);
    assert_eq!(d2.removed, ["vm-2"]);
    assert!(d2.missing.is_empty() && d2.missing_streak.is_empty());

    // back after one miss → restored, streak cleared
    let d3 = diff(&full, &full, &d1.missing_streak);
    assert_eq!(d3.restored, ["vm-2"]);
    assert!(d3.missing_streak.is_empty() && d3.removed.is_empty());

    // a miss, a present refresh, a miss again: never two *consecutive* → kept
    let d4 = diff(&full, &without_vm2, &d3.missing_streak);
    assert_eq!((d4.missing.as_slice(), d4.removed.len()), (&["vm-2".to_owned()][..], 0));
}

#[test]
fn removals_are_children_first() {
    let full = inv(base());
    let only_dc = inv(vec![item("datacenter-1", ItemKind::Datacenter, "DC", None)]);
    let streak: BTreeMap<_, _> = ["domain-c1", "host-1", "host-2", "vm-1", "vm-2"]
        .iter()
        .map(|s| ((*s).to_owned(), 1))
        .collect();
    let d = diff(&full, &only_dc, &streak);
    assert_eq!(d.removed, ["vm-1", "vm-2", "host-1", "host-2", "domain-c1"]);
    assert!(!d.is_empty());
    assert!(diff(&full, &full, &BTreeMap::new()).is_empty());
}
