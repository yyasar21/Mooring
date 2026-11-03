use super::*;
use crate::state::testing::*;

fn root(state: &AppState) -> String {
    state.with_ready(|_, s| Ok(root_id(s).to_string())).expect("root")
}

fn fields(folder: &str, name: &str, host: &str) -> ConnectionFields {
    ConnectionFields { tags: vec!["lab".to_owned()], ..ConnectionFields::basic(folder, name, "ssh", host) }
}

#[test]
fn locked_vault_refuses_tree_access() {
    let f = unlocked();
    let root = root(&f.state);
    crate::commands::vault::lock(&f.state, None).expect("lock");
    assert_eq!(list(&f.state).expect_err("locked").code, "vault.locked");
    assert_eq!(create_folder(&f.state, &root, "x").expect_err("locked").code, "vault.locked");
    let e = search(&f.state, "x", 10).expect_err("locked");
    assert_eq!(e.code, "vault.locked");
}

#[test]
fn folder_round_trip_and_tree_errors() {
    let f = unlocked();
    let root = root(&f.state);
    let a = create_folder(&f.state, &root, "  Servers ").expect("a");
    assert_eq!(a.name, "Servers");
    assert_eq!(a.parent_id.as_deref(), Some(root.as_str()));
    let b = create_folder(&f.state, &a.id, "kube").expect("b");
    assert_eq!(rename_folder(&f.state, &b.id, "KUBE").expect("rename").name, "KUBE");
    assert_eq!(move_folder(&f.state, &a.id, &b.id).expect_err("cycle").code, "tree.cycle");
    assert_eq!(move_folder(&f.state, &root, &a.id).expect_err("root").code, "tree.root");
    assert_eq!(delete_folder(&f.state, &root).expect_err("root").code, "tree.root");
    let missing = mooring_core::FolderId::new().to_string();
    assert_eq!(rename_folder(&f.state, &missing, "x").expect_err("nf").code, "tree.not_found");
    let moved = move_folder(&f.state, &b.id, &root).expect("move");
    assert_eq!(moved.parent_id.as_deref(), Some(root.as_str()));
    delete_folder(&f.state, &a.id).expect("delete");
    let tree = list(&f.state).expect("list");
    assert_eq!(tree.folders.len(), 2, "root + kube");
}

#[test]
fn input_validation() {
    let f = unlocked();
    let root = root(&f.state);
    let cases = [
        create_folder(&f.state, "not-a-uuid", "x").map(drop),
        create_folder(&f.state, &root, "").map(drop),
        create_folder(&f.state, &root, &"n".repeat(121)).map(drop),
        create_folder(&f.state, &root, "a\u{7}b").map(drop),
        create_connection(&f.state, fields(&root, "x", "bad host")).map(drop),
        create_connection(&f.state, fields(&root, "x", &"h".repeat(2049))).map(drop),
        create_connection(
            &f.state,
            ConnectionFields { port: Some(0), ..fields(&root, "x", "h") },
        )
        .map(drop),
        create_connection(
            &f.state,
            ConnectionFields { protocol: "telnet".into(), ..fields(&root, "x", "h") },
        )
        .map(drop),
        create_connection(
            &f.state,
            ConnectionFields { tags: vec!["t".into(); 51], ..fields(&root, "x", "h") },
        )
        .map(drop),
        create_connection(
            &f.state,
            ConnectionFields { tags: vec!["t".repeat(65)], ..fields(&root, "x", "h") },
        )
        .map(drop),
        search(&f.state, &"q".repeat(MAX_QUERY_BYTES + 1), 10).map(drop),
    ];
    for (i, r) in cases.into_iter().enumerate() {
        assert_eq!(r.expect_err("must fail").code, "input.invalid", "case {i}");
    }
    let unknown_cred = ConnectionFields {
        credential_id: Some(mooring_core::CredentialId::new().to_string()),
        ..fields(&root, "x", "h")
    };
    let e = create_connection(&f.state, unknown_cred).expect_err("unknown credential");
    assert_eq!(e.code, "credential.not_found");
}

#[test]
fn connection_round_trip_inheritance_and_search() {
    let f = unlocked();
    let root = root(&f.state);
    let prod = create_folder(&f.state, &root, "prod").expect("prod");
    let cred = crate::commands::credentials::create(
        &f.state,
        crate::commands::credentials::NewCredential::password_for_tests("ops"),
    )
    .expect("cred");
    set_default_credential(&f.state, &prod.id, Some(&cred.id)).expect("default");

    let c = create_connection(&f.state, fields(&prod.id, "web01", "192.0.2.5"))
        .expect("create");
    assert_eq!(c.credential_id, None);
    assert_eq!(c.effective_credential_id.as_deref(), Some(cred.id.as_str()), "inherited");
    assert_eq!(c.tags, ["lab"]);

    let mut upd = fields(&prod.id, "web01-new", "192.0.2.6");
    upd.port = Some(2222);
    let u = update_connection(&f.state, &c.id, upd).expect("update");
    assert_eq!(
        (u.name.as_str(), u.port, u.created_at.as_str()),
        ("web01-new", Some(2222), c.created_at.as_str())
    );

    let hits = search(&f.state, "web01", 0).expect("search");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].folder_id, prod.id);

    let m = move_connection(&f.state, &c.id, &root).expect("move");
    assert_eq!(m.folder_id, root);
    assert_eq!(m.effective_credential_id, None, "root has no default");

    let tree = list(&f.state).expect("list");
    assert_eq!(tree.connections.len(), 1);
    delete_connection(&f.state, &c.id).expect("delete");
    assert_eq!(delete_connection(&f.state, &c.id).expect_err("gone").code, "tree.not_found");
}

fn cred(state: &AppState, kind: &str, fields: serde_json::Value, secrets: &[(&str, &str)]) -> String {
    use crate::commands::credentials::{create, NewCredential, WireSecrets};
    let c = NewCredential {
        name: kind.into(),
        kind: kind.into(),
        fields,
        secrets: WireSecrets::of(secrets),
    };
    create(state, c).expect("credential").id
}

#[test]
fn overrides_and_roles_round_trip_and_incompatible_ids_fail() {
    use serde_json::json;
    let f = unlocked();
    let root = root(&f.state);
    let pw = cred(&f.state, "user_password", json!({"username": "shared"}), &[("password", "p")]);
    let sudo = cred(&f.state, "sudo_become", json!({"method": "sudo"}), &[]);
    let key = mooring_core::credential::testdata::placeholder_key_pem();
    let ssh_key = cred(&f.state, "ssh_key", json!({"username": "u"}), &[("private_key", &key)]);

    let c = create_connection(
        &f.state,
        ConnectionFields {
            credential_id: Some(pw.clone()),
            username_override: Some(" dba ".into()),
            domain_override: Some("CORP".into()),
            become_credential_id: Some(sudo.clone()),
            ..fields(&root, "db01", "db.example.test")
        },
    )
    .expect("create");
    assert_eq!(c.username_override.as_deref(), Some("dba"));
    assert_eq!(c.become_credential_id.as_deref(), Some(sudo.as_str()));
    let json = serde_json::to_value(&c).expect("json");
    for k in ["usernameOverride", "domainOverride", "gatewayCredentialId", "becomeCredentialId"] {
        assert!(json.get(k).is_some(), "{k} on the wire");
    }

    // incompatible ids: verbatim matrix sentence
    let rdp_fields = |cred: Option<String>| ConnectionFields {
        credential_id: cred,
        ..ConnectionFields::basic(&root, "w", "rdp", "w.example.test")
    };
    let e = create_connection(&f.state, rdp_fields(Some(ssh_key.clone()))).expect_err("ssh key");
    assert_eq!(e.code, "credential.incompatible");
    assert_eq!(e.message, "SSH key is for SSH, not RDP sign-in.");
    let e = set_role_credential(&f.state, &c.id, "gateway", Some(&pw)).expect_err("gateway on ssh");
    assert_eq!(e.code, "credential.incompatible");
    let e = set_role_credential(&f.state, &c.id, "primary", None).expect_err("role");
    assert_eq!(e.code, "input.invalid");
    let cleared = set_role_credential(&f.state, &c.id, "become", None).expect("clear");
    assert_eq!(cleared.become_credential_id, None);
    let rdp = create_connection(&f.state, rdp_fields(None)).expect("rdp");
    let g = set_role_credential(&f.state, &rdp.id, "gateway", Some(&pw)).expect("gateway");
    assert_eq!(g.gateway_credential_id.as_deref(), Some(pw.as_str()));

    // a domain override on a kind without a domain is input.invalid
    let bad = ConnectionFields {
        credential_id: Some(ssh_key),
        domain_override: Some("CORP".into()),
        ..fields(&root, "db01", "db.example.test")
    };
    assert_eq!(update_connection(&f.state, &c.id, bad).expect_err("domain").code, "input.invalid");
}
