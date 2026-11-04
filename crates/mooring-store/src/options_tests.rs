use super::*;
use mooring_core::options::{RdpConnOptions, VncConnOptions, VncSecurity, WebConnOptions};
use mooring_core::{Connection, Protocol};
use rusqlite::Connection as Raw;

use crate::error::StoreError;
use crate::schema;

const UP_TO_V4: [&str; 4] = [
    include_str!("../migrations/0001_init.sql"),
    include_str!("../migrations/0002_fts_secure_delete.sql"),
    include_str!("../migrations/0003_typed_credentials.sql"),
    include_str!("../migrations/0004_migrated_username.sql"),
];
const TS: &str = "2026-11-01T10:00:00Z";

fn store_with(protocol: Protocol) -> (Store, ConnectionId) {
    let s = Store::open_in_memory().expect("open");
    let root = s.create_folder(None, "root").expect("root");
    let c = Connection::new(root.id, "c", protocol, "host.example.test").expect("conn");
    let c = s.create_connection(&c).expect("create");
    (s, c.id)
}

#[test]
fn migration_0005_upgrades_a_v4_database() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mooring.db");
    let (folder, rdp, ssh) = ("f-1", ConnectionId::new(), ConnectionId::new());
    {
        let raw = Raw::open(&path).expect("raw");
        for sql in UP_TO_V4 {
            raw.execute_batch(sql).expect("v1..v4");
        }
        raw.execute("INSERT INTO setting (key, value) VALUES ('schema_version', '4')", [])
            .expect("version");
        let folder_id = uuid::Uuid::new_v4().to_string();
        raw.execute(
            "INSERT INTO folder (id, parent_id, name, created_at, updated_at)
             VALUES (?1, NULL, ?2, ?3, ?3)",
            (&folder_id, folder, TS),
        )
        .expect("folder");
        for (id, proto) in [(rdp, "rdp"), (ssh, "ssh")] {
            raw.execute(
                "INSERT INTO connection (id, folder_id, name, protocol, host, port, credential_id,
                                         created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?3, '192.0.2.9', NULL, NULL, ?4, ?4)",
                (id.to_string(), &folder_id, proto, TS),
            )
            .expect("connection");
        }
    }
    let s = Store::open(&path).expect("migrates");
    assert_eq!(s.schema_version().expect("v"), schema::LATEST);
    assert_eq!(schema::LATEST, 5);
    assert_eq!(
        s.connection_options(rdp).expect("rdp defaults"),
        ProtocolOptions::Rdp(RdpConnOptions::default())
    );
    assert!(s.connection_options(ssh).is_ok());
    assert_eq!(s.get_connection(rdp).expect("row survives").host, "192.0.2.9");
}

#[test]
fn check_constraint_keeps_options_a_bounded_json_object() {
    let (s, id) = store_with(Protocol::Vnc);
    for bad in
        ["not json".to_owned(), "[]".to_owned(), format!("{{\"a\":\"{}\"}}", "x".repeat(131_072))]
    {
        let r = s.conn.execute(
            "UPDATE connection SET options_json = ?2 WHERE id = ?1",
            (id.to_string(), bad),
        );
        assert!(r.is_err(), "CHECK refuses it");
    }
}

#[test]
fn set_and_read_back_options() {
    let (s, id) = store_with(Protocol::Vnc);
    let vnc = ProtocolOptions::Vnc(VncConnOptions {
        security: VncSecurity::RequireTls,
        view_only: true,
        ..VncConnOptions::default()
    });
    assert_eq!(s.set_connection_options(id, &vnc).expect("set"), vnc);
    assert_eq!(s.connection_options(id).expect("get"), vnc);
    let raw: String = s
        .conn
        .query_row("SELECT options_json FROM connection WHERE id = ?1", [id.to_string()], |r| {
            r.get(0)
        })
        .expect("raw");
    assert!(raw.contains(r#""security":"require_tls""#) && raw.contains(r#""viewOnly":true"#));

    let rdp = ProtocolOptions::Rdp(RdpConnOptions::default());
    assert!(matches!(
        s.set_connection_options(id, &rdp),
        Err(StoreError::Invalid { field: "options", .. })
    ));
    let missing = ConnectionId::new();
    assert!(matches!(s.connection_options(missing), Err(StoreError::NotFound { .. })));
    assert!(matches!(s.set_connection_options(missing, &vnc), Err(StoreError::NotFound { .. })));
}

#[test]
fn reads_revalidate_and_protocol_change_resets() {
    let (s, id) = store_with(Protocol::Rdp);
    // Valid JSON object, but not valid RDP options: written behind the store's back.
    s.conn
        .execute(
            "UPDATE connection SET options_json = '{\"keyboardLayout\": 1}' WHERE id = ?1",
            [id.to_string()],
        )
        .expect("raw write");
    assert!(matches!(s.connection_options(id), Err(StoreError::Invalid { field: "options", .. })));

    let web_opts = ProtocolOptions::Web(WebConnOptions {
        url: "https://app.example.test".into(),
        ..WebConnOptions::default()
    });
    let mut c = s.get_connection(id).expect("get");
    c.protocol = Protocol::Web;
    s.update_connection(&c).expect("protocol change");
    assert!(s.connection_options(id).is_err(), "reset to {{}}: a web URL is now required");
    s.set_connection_options(id, &web_opts).expect("set web");
    c.name = "renamed".into();
    s.update_connection(&c).expect("same protocol");
    assert_eq!(s.connection_options(id).expect("kept"), web_opts, "kept on same protocol");
}
