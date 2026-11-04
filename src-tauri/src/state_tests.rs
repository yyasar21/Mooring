//! Tests of the application state.

use super::testing::*;
use super::*;

#[test]
fn new_state_creates_root_and_private_db() {
    let f = empty();
    let slot = f.state.store.lock().expect("lock");
    let root = slot.store.as_ref().expect("store").root_folder().expect("q").expect("root");
    assert_eq!(root.name, ROOT_FOLDER_NAME);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(f.dir.path().join(AppState::DB_FILE))
            .expect("db")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn header_write_is_private_keeps_backup_and_backup_can_be_dropped() {
    let f = unlocked();
    let header = f.dir.path().join(AppState::HEADER_FILE);
    let bak = f.dir.path().join(AppState::HEADER_BACKUP);
    assert!(header.exists());
    assert!(!bak.exists(), "first write has nothing to back up");
    let before = std::fs::read(&header).expect("read");
    {
        let vault = f.state.vault().expect("vault");
        f.state.save_header(vault.as_ref().expect("v")).expect("second write");
    }
    assert_eq!(std::fs::read(&bak).expect("backup"), before);
    assert!(!f.dir.path().join("vault.header.json.tmp").exists(), "temp renamed away");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&header).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    f.state.drop_header_backup();
    assert!(!bak.exists());
}

#[test]
fn with_ready_requires_unlock_and_binds_vault_id() {
    let f = empty();
    assert_eq!(f.state.with_ready(|_, _| Ok(())).expect_err("missing").code, "vault.missing");
    crate::commands::vault::create(&f.state, secrecy::SecretString::from(MASTER.to_owned()))
        .expect("create");
    let id = f.state.vault().expect("v").as_ref().expect("v").vault_id();
    let bound = f.state.with_ready(|_, s| Ok(s.vault_id()?)).expect("ok");
    assert_eq!(bound, Some(id.to_string()));
    crate::commands::vault::lock(&f.state, None).expect("lock");
    assert_eq!(f.state.with_ready(|_, _| Ok(())).expect_err("locked").code, "vault.locked");
}

#[test]
fn shutdown_closes_the_store() {
    let f = unlocked();
    f.state.shutdown();
    assert!(f.state.store.lock().expect("lock").store.is_none());
    let e = f.state.with_ready(|_, _| Ok(())).expect_err("closed");
    assert_eq!(e.code, "store.io");
}
