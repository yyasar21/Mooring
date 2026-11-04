//! Sync, scheduler, power and console logic against QA's `mooring-testsrv::vcenter` mock.

use std::time::Duration;

use mooring_core::known_certs::{fingerprint, KnownCerts};
use mooring_testsrv::vcenter::{self, InventorySpec, VcenterConfig, VcenterKnobs, VcenterServer};
use secrecy::SecretString;
use serde_json::json;

use super::*;
use crate::commands::credentials::{self, NewCredential, WireSecrets};
use crate::commands::tree::{self, ConnectionFields};
use crate::commands::vsphere::{self as vs};
use crate::commands::vsphere_confirm::{FixedConfirm, Prompt, RecordingOpener};
use crate::commands::{conn_options, vsphere_console, vsphere_vm};
use crate::state::testing::{audit_events, unlocked, Fixture};

pub(crate) struct Vc {
    pub f: Fixture,
    pub srv: VcenterServer,
    pub id: String,
    pub root: String,
}

pub(crate) async fn vcenter(spec: InventorySpec, pin: bool) -> Vc {
    let cert = mooring_testsrv::tls::TestCert::generate(&["127.0.0.1", "vcenter.example.test"]).expect("cert");
    let config = VcenterConfig { inventory: spec, cert: Some(cert), ..VcenterConfig::default() };
    let srv = vcenter::start(config, 0).await.expect("vcenter mock");
    let f = unlocked();
    let secrets = WireSecrets(std::iter::once(("password".to_owned(), SecretString::from("testpass".to_owned()))).collect());
    let cred = credentials::create(
        &f.state,
        NewCredential { name: "vc login".into(), kind: "vsphere_user".into(), fields: json!({"upn": "alice@example.test"}), secrets },
    )
    .expect("credential");
    let root = tree::list(&f.state).expect("tree").folders[0].id.clone();
    let conn = tree::create_connection(
        &f.state,
        ConnectionFields {
            port: Some(u32::from(srv.addr().port())),
            credential_id: Some(cred.id),
            ..ConnectionFields::basic(&root, "vc-lab", "vsphere-console", "127.0.0.1")
        },
    )
    .expect("vCenter connection");
    if pin {
        let path = f.state.data_dir.join("known_vsphere_certs");
        let fp = fingerprint(srv.cert().cert_der().as_ref());
        KnownCerts::add_and_save(&path, "127.0.0.1", srv.addr().port(), &fp, OffsetDateTime::now_utc()).expect("pin");
    }
    Vc { f, srv, id: conn.id, root }
}

pub(crate) fn set_options(vc: &Vc, v: serde_json::Value) {
    conn_options::set(&vc.f.state, &vc.id, v).expect("options");
}

fn vm_row(vc: &Vc, ext: &str) -> Option<crate::dto::ConnectionDto> {
    tree::list(&vc.f.state).expect("tree").connections.into_iter().find(|c| c.external_id.as_deref() == Some(ext))
}

fn count(vc: &Vc, event: &str) -> usize {
    audit_events(&vc.f.state).iter().filter(|e| *e == event).count()
}

#[tokio::test]
async fn import_builds_tree_and_refresh_applies_diff_and_two_miss_rule() {
    let vc = vcenter(InventorySpec::default(), true).await;
    let yes = FixedConfirm::new(true);
    let root = vs::sync_enable(&vc.f.state, Prompt::new(&yes), &vc.id, &vc.root).await.expect("import");
    assert_eq!(root.sync_source.as_deref(), Some(vc.id.as_str()));
    assert!(yes.asked().is_empty(), "pinned: no prompt");
    let t = tree::list(&vc.f.state).expect("tree");
    let synced_folders = t.folders.iter().filter(|f| f.sync_source.is_some()).count();
    assert_eq!(synced_folders, 1 + 1 + 3 + 5, "root, dc, 2 clusters + standalone, 5 hosts");
    assert_eq!(t.connections.iter().filter(|c| c.external_id.is_some()).count(), 15);
    assert_eq!(vm_row(&vc, "vm-1").expect("vm-1").sync_state.as_deref(), Some("present"));
    // Second refresh: rename vm-1, move vm-2, drop vm-3, add vm-99.
    let mut inv = vc.srv.inventory();
    inv.vms.iter_mut().find(|v| v.id == "vm-1").expect("vm").name = "renamed-01".into();
    inv.vms.iter_mut().find(|v| v.id == "vm-2").expect("vm").host = "host-5".into();
    inv.vms.retain(|v| v.id != "vm-3");
    let mut extra = inv.vms[0].clone();
    extra.id = "vm-99".into();
    extra.name = "new-vm".into();
    inv.vms.push(extra);
    vc.srv.set_inventory(inv);
    let r = vs::refresh(&vc.f.state, Prompt::new(&yes), &vc.id).await.expect("refresh");
    assert_eq!((r.added, r.changed, r.missing, r.deleted), (1, 2, 1, 0), "{r:?}");
    assert_eq!(vm_row(&vc, "vm-1").expect("vm-1").name, "renamed-01");
    assert_eq!(vm_row(&vc, "vm-3").expect("kept once").sync_state.as_deref(), Some("missing"));
    let r = vs::refresh(&vc.f.state, Prompt::new(&yes), &vc.id).await.expect("refresh");
    assert_eq!((r.added, r.changed, r.missing, r.deleted), (0, 0, 0, 1), "{r:?}");
    assert!(vm_row(&vc, "vm-3").is_none(), "removed on the second miss");
    let st = vs::status(&vc.f.state, &vc.id).expect("status");
    assert!(st.last_refresh.is_some() && st.last_error.is_none() && !st.running);
    assert_eq!(count(&vc, "vsphere_sync_finished"), 3);
}

#[tokio::test]
async fn overlays_survive_and_ordinary_edits_are_refused() {
    let vc = vcenter(InventorySpec::default(), true).await;
    let yes = FixedConfirm::new(true);
    vs::sync_enable(&vc.f.state, Prompt::new(&yes), &vc.id, &vc.root).await.expect("import");
    let vm = vm_row(&vc, "vm-1").expect("vm");
    let mut fields = ConnectionFields::basic(&vm.folder_id, &vm.name, "vsphere-console", &vm.host);
    fields.port = vm.port.map(u32::from);
    fields.tags = vec!["prod".into()];
    tree::update_connection(&vc.f.state, &vm.id, fields.clone()).expect("tags are an overlay");
    fields.name = "mine".into();
    assert_eq!(tree::update_connection(&vc.f.state, &vm.id, fields).expect_err("rename").code, "tree.synced_readonly");
    assert_eq!(tree::rename_folder(&vc.f.state, &vm.folder_id, "x").expect_err("ro").code, "tree.synced_readonly");
    assert_eq!(tree::delete_connection(&vc.f.state, &vm.id).expect_err("ro").code, "tree.synced_readonly");
    assert_eq!(tree::create_folder(&vc.f.state, &vm.folder_id, "x").expect_err("ro").code, "tree.synced_readonly");
    vs::refresh(&vc.f.state, Prompt::new(&yes), &vc.id).await.expect("refresh");
    assert_eq!(vm_row(&vc, "vm-1").expect("vm").tags, vec!["prod".to_owned()], "overlay kept");
    vs::sync_disable(&vc.f.state, &vc.id, true).expect("detach");
    assert!(vm_row(&vc, "vm-1").is_none(), "no longer synced");
    tree::rename_folder(&vc.f.state, &vm.folder_id, "editable").expect("editable after detach");
}

#[tokio::test]
async fn unknown_certificate_prompts_in_rust_and_the_scheduler_never_does() {
    let vc = vcenter(InventorySpec::one_host(2), false).await;
    let no = FixedConfirm::new(false);
    let e = vs::test(&vc.f.state, Prompt::new(&no), &vc.id).await.expect_err("rejected");
    assert_eq!(e.code, "http.trust_rejected");
    assert!(no.asked()[0].text.contains("vc-lab") && no.asked()[0].text.contains("SHA256:"));
    let ctx = VsCtx::of(&vc.f.state);
    let source = source_id(&vc.id).expect("id");
    assert_eq!(session(&ctx, source, None).await.expect_err("no prompt").code, "http.trust_prompt");
    let yes = FixedConfirm::new(true);
    let r = vs::test(&vc.f.state, Prompt::new(&yes), &vc.id).await.expect("trusted");
    assert_eq!((r.version.as_str(), r.user.as_str()), ("8.0.3.00400", "alice@example.test"));
    assert!(audit_events(&vc.f.state).contains(&"cert_decision".to_owned()));
    vs::test(&vc.f.state, Prompt::new(&no), &vc.id).await.expect("pinned now: no second prompt");
    assert_eq!(vc.srv.session_count(), 0, "vsphere_test logs out");
}

#[tokio::test]
async fn power_needs_opt_in_and_the_native_dialog() {
    let vc = vcenter(InventorySpec::one_host(3), true).await;
    let yes = FixedConfirm::new(true);
    vs::sync_enable(&vc.f.state, Prompt::new(&yes), &vc.id, &vc.root).await.expect("import");
    let vm = vm_row(&vc, "vm-1").expect("vm").id;
    let e = vsphere_vm::action(&vc.f.state, Prompt::new(&yes), &vm, "stop").await.expect_err("off");
    assert_eq!(e.code, "vsphere.power_disabled");
    assert!(yes.asked().is_empty() && vc.srv.power_actions().is_empty(), "no dialog, no call");
    set_options(&vc, json!({"allowPowerActions": true}));
    let no = FixedConfirm::new(false);
    let out = vsphere_vm::action(&vc.f.state, Prompt::new(&no), &vm, "stop").await.expect("cancel");
    assert_eq!(out.outcome, "cancelled");
    assert!(vc.srv.power_actions().is_empty(), "cancelled: nothing sent");
    let ask = &no.asked()[0];
    assert!(ask.text.contains("vm-00001") && ask.text.contains("vc-lab") && ask.text.contains("may be lost"), "{}", ask.text);
    let out = vsphere_vm::action(&vc.f.state, Prompt::new(&yes), &vm, "stop").await.expect("approved");
    assert_eq!(out.outcome, "done");
    let sent = vc.srv.power_actions();
    assert_eq!((sent.len(), sent[0].action.as_str(), sent[0].vm.as_str()), (1, "stop", "vm-1"));
    assert!(!yes.asked()[0].text.is_empty());
    let p = vsphere_vm::power_state(&vc.f.state, &vm).await.expect("state");
    assert_eq!(p.state, PowerState::PoweredOff);
    assert!(count(&vc, "vsphere_power") >= 4, "disabled, cancelled, requested, done");
    assert!(vsphere_vm::action(&vc.f.state, Prompt::new(&yes), &vm, "suspend").await.is_err());
    assert!(vsphere_vm::action(&vc.f.state, Prompt::new(&yes), &vc.id, "start").await.is_err(), "not a VM row");
}

#[tokio::test]
async fn rate_limit_fails_cleanly_and_recovers() {
    let vc = vcenter(InventorySpec::one_host(2), true).await;
    let yes = FixedConfirm::new(true);
    vs::sync_enable(&vc.f.state, Prompt::new(&yes), &vc.id, &vc.root).await.expect("import");
    vc.f.state.vsphere.drop_session(&vc.id);
    vc.srv.set_knobs(VcenterKnobs { rate_limit_per_sec: Some(0), ..VcenterKnobs::default() });
    let e = vs::refresh(&vc.f.state, Prompt::new(&yes), &vc.id).await.expect_err("429");
    assert_eq!(e.code, "vsphere.rate_limited");
    let st = vs::status(&vc.f.state, &vc.id).expect("status");
    assert_eq!(st.last_error.as_deref(), Some("vsphere.rate_limited"));
    assert_eq!(count(&vc, "vsphere_sync_failed"), 1);
    assert!(vm_row(&vc, "vm-1").is_some(), "a failed refresh changes nothing");
    vc.srv.set_knobs(VcenterKnobs::default());
    vs::refresh(&vc.f.state, Prompt::new(&yes), &vc.id).await.expect("recovered");
    assert!(vs::status(&vc.f.state, &vc.id).expect("s").last_error.is_none());
}

#[tokio::test]
async fn refresh_is_single_flight() {
    let vc = vcenter(InventorySpec::default(), true).await;
    let yes = FixedConfirm::new(true);
    vs::sync_enable(&vc.f.state, Prompt::new(&yes), &vc.id, &vc.root).await.expect("import");
    let before = count(&vc, "vsphere_sync_started");
    let (a, b) = tokio::join!(
        vs::refresh(&vc.f.state, Prompt::new(&yes), &vc.id),
        vs::refresh(&vc.f.state, Prompt::new(&yes), &vc.id)
    );
    assert_eq!(a.expect("a"), b.expect("b"), "the second joined the first");
    assert_eq!(count(&vc, "vsphere_sync_started"), before + 1);
}

#[tokio::test]
async fn scheduler_runs_while_unlocked_and_lock_stops_it() {
    let vc = vcenter(InventorySpec::one_host(2), true).await;
    vc.f.state.vsphere.set_minute(Duration::from_millis(10));
    set_options(&vc, json!({"refreshMinutes": 15}));
    let yes = FixedConfirm::new(true);
    vs::sync_enable(&vc.f.state, Prompt::new(&yes), &vc.id, &vc.root).await.expect("import");
    assert!(vs::status(&vc.f.state, &vc.id).expect("s").scheduled);
    let scheduled = || audit_events(&vc.f.state).len();
    let start = scheduled();
    tokio::time::timeout(Duration::from_secs(20), async {
        while count(&vc, "vsphere_sync_finished") < 2 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("a scheduled refresh ran");
    assert!(scheduled() > start);
    crate::commands::vault::lock(&vc.f.state, None).expect("lock");
    assert!(!vs::status(&vc.f.state, &vc.id).is_ok_and(|s| s.scheduled), "stopped (or locked)");
    tokio::time::timeout(Duration::from_secs(10), async {
        while vc.srv.session_count() > 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("session logged out on lock");
    let after = count(&vc, "vsphere_sync_started");
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(count(&vc, "vsphere_sync_started"), after, "no refresh while locked");
    assert_eq!(vs::refresh(&vc.f.state, Prompt::new(&yes), &vc.id).await.expect_err("locked").code, "vault.locked");
}

#[tokio::test]
async fn consoles_client_plan_and_vmrc_opt_in() {
    let vc = vcenter(InventorySpec::one_host(2), true).await;
    let yes = FixedConfirm::new(true);
    vs::sync_enable(&vc.f.state, Prompt::new(&yes), &vc.id, &vc.root).await.expect("import");
    let vm = vm_row(&vc, "vm-1").expect("vm").id;
    let ctx = VsCtx::of(&vc.f.state);
    let t = vsphere_vm::vm_target(&ctx, &vm).expect("target");
    let plan = vsphere_console::client_plan(&t, None, crate::web::Storage::Ephemeral).expect("plan");
    assert_eq!(plan.label, format!("web-{}", vc.id), "keyed by the vCenter connection");
    assert_eq!(plan.url.as_str(), format!("https://127.0.0.1:{}/ui/", vc.srv.addr().port()));
    assert_eq!(plan.policy.allowed(), [format!("https://127.0.0.1:{}", vc.srv.addr().port())]);
    let opener = RecordingOpener::default();
    let e = vsphere_vm::vmrc(&vc.f.state, Prompt::new(&yes), &opener, &t).await.expect_err("opt-in");
    assert_eq!(e.code, "vsphere.vmrc_disabled");
    set_options(&vc, json!({"allowVmrc": true}));
    let t = vsphere_vm::vm_target(&ctx, &vm).expect("target");
    let no = FixedConfirm::new(false);
    assert!(!vsphere_vm::vmrc(&vc.f.state, Prompt::new(&no), &opener, &t).await.expect("cancel"));
    assert!(vc.srv.ticket_requests().is_empty(), "no ticket before the confirmation");
    assert!(vsphere_vm::vmrc(&vc.f.state, Prompt::new(&yes), &opener, &t).await.expect("open"));
    let urls = opener.0.lock().expect("m").clone();
    assert!(urls[0].starts_with("vmrc://") && urls[0].contains("@vcenter.example.test"), "SAN host accepted");
    let log = std::fs::read_to_string(vc.f.state.data_dir.join(crate::state::AppState::AUDIT_FILE)).expect("audit");
    assert!(log.contains("vsphere_console") && !log.contains("cst-"), "ticket never audited");
}
