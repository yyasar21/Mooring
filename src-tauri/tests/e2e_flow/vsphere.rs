//! ADR-0015 V2 flow through the command plain functions against QA's vCenter mock:
//! vault → `vsphere_user` credential → vCenter connection → options (power opt-in) →
//! `vsphere_sync_enable` (TOFU in the Rust dialog, import) → tree shows the read-only subtree
//! → power action approved in the dialog → refresh after a VM vanished twice → lock refuses
//! everything and logs the session out.

use std::time::Duration;

use mooring_testsrv::vcenter::{self, InventorySpec, VcenterConfig};
use secrecy::SecretString;
use serde_json::json;

use crate::commands::credentials::{self, NewCredential, WireSecrets};
use crate::commands::tree::{self, ConnectionFields};
use crate::commands::vsphere::{self as vs};
use crate::commands::vsphere_confirm::{FixedConfirm, Prompt};
use crate::commands::{conn_options, vault, vsphere_vm};
use crate::state::testing::{audit_events, unlocked};

#[tokio::test]
async fn vcenter_import_power_refresh_and_lock() {
    let srv = vcenter::start(
        VcenterConfig { inventory: InventorySpec::one_host(3), ..VcenterConfig::default() },
        0,
    )
    .await
    .expect("vcenter mock");
    let f = unlocked();
    let secrets = WireSecrets(
        std::iter::once(("password".to_owned(), SecretString::from("testpass".to_owned())))
            .collect(),
    );
    let cred = credentials::create(
        &f.state,
        NewCredential {
            name: "vc".into(),
            kind: "vsphere_user".into(),
            fields: json!({"upn": "alice@example.test"}),
            secrets,
        },
    )
    .expect("credential");
    let root = tree::list(&f.state).expect("tree").folders[0].id.clone();
    let vc = tree::create_connection(
        &f.state,
        ConnectionFields {
            port: Some(u32::from(srv.addr().port())),
            credential_id: Some(cred.id),
            ..ConnectionFields::basic(&root, "vc-e2e", "vsphere-console", "127.0.0.1")
        },
    )
    .expect("vCenter");
    conn_options::set(&f.state, &vc.id, json!({"allowPowerActions": true, "refreshMinutes": null}))
        .expect("options");

    let yes = FixedConfirm::new(true);
    let synced = vs::sync_enable(&f.state, Prompt::new(&yes), &vc.id, &root).await.expect("import");
    assert_eq!(yes.asked().len(), 1, "one TOFU prompt for the self-signed vCenter");
    let t = tree::list(&f.state).expect("tree");
    let vms: Vec<_> =
        t.connections.iter().filter(|c| c.sync_source.as_deref() == Some(vc.id.as_str())).collect();
    assert_eq!(vms.len(), 3);
    assert!(t.folders.iter().any(|f| f.id == synced.id && f.external_id.is_none()));
    let e = tree::rename_folder(&f.state, &synced.id, "mine").expect_err("read-only");
    assert_eq!(e.code, "tree.synced_readonly");

    let vm1 =
        vms.iter().find(|c| c.external_id.as_deref() == Some("vm-1")).expect("vm-1").id.clone();
    let out = vsphere_vm::action(&f.state, Prompt::new(&yes), &vm1, "reset").await.expect("reset");
    assert_eq!(out.outcome, "done");
    assert_eq!(srv.power_actions().len(), 1);
    assert!(yes.asked()[1].text.contains("pulling the plug"));

    let mut inv = srv.inventory();
    inv.vms.retain(|v| v.id != "vm-2");
    srv.set_inventory(inv);
    let first = vs::refresh(&f.state, Prompt::new(&yes), &vc.id).await.expect("refresh 1");
    let second = vs::refresh(&f.state, Prompt::new(&yes), &vc.id).await.expect("refresh 2");
    assert_eq!((first.missing, first.deleted, second.deleted), (1, 0, 1));

    vault::lock(&f.state, None).expect("lock");
    assert_eq!(
        vs::refresh(&f.state, Prompt::new(&yes), &vc.id).await.expect_err("locked").code,
        "vault.locked"
    );
    assert_eq!(
        vsphere_vm::action(&f.state, Prompt::new(&yes), &vm1, "start")
            .await
            .expect_err("locked")
            .code,
        "vault.locked"
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        while srv.session_count() > 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("logged out on lock");
    let events = audit_events(&f.state);
    for e in ["vsphere_sync_started", "vsphere_sync_finished", "vsphere_power", "cert_decision"] {
        assert!(events.iter().any(|x| x == e), "{e} audited");
    }
}
