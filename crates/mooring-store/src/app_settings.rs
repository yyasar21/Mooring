//! Application preferences in the `setting` table (ADR-0010: auto-lock policy, syslog mirror).
//!
//! Callers only reach keys under the [`APP_PREFIX`] namespace, so a preference can never
//! overwrite the store's own bookkeeping (`schema_version`, `vault_id`, reseal flag). Values are
//! small, non-secret strings (JSON in practice); the store does not interpret them.

use crate::error::invalid;
use crate::{schema, Result, Store};

/// Every application key starts with this prefix.
pub const APP_PREFIX: &str = "app.";
/// Longest key accepted, prefix included.
pub const MAX_APP_KEY: usize = 64;
/// Longest value accepted (bytes).
pub const MAX_APP_VALUE: usize = 16 * 1024;

fn check_key(key: &str) -> Result<()> {
    let rest = key.strip_prefix(APP_PREFIX).ok_or_else(|| invalid("key", "not an app key"))?;
    let ok = !rest.is_empty()
        && key.len() <= MAX_APP_KEY
        && rest
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.');
    if ok {
        Ok(())
    } else {
        Err(invalid("key", "must be app.[a-z0-9_.]+, at most 64 bytes"))
    }
}

impl Store {
    /// Read an application preference (`app.*`).
    pub fn app_setting(&self, key: &str) -> Result<Option<String>> {
        check_key(key)?;
        schema::get_setting(&self.conn, key)
    }

    /// Write (insert or replace) an application preference (`app.*`).
    pub fn set_app_setting(&self, key: &str, value: &str) -> Result<()> {
        check_key(key)?;
        if value.len() > MAX_APP_VALUE {
            return Err(invalid("value", "longer than 16 KiB"));
        }
        schema::put_setting(&self.conn, key, value)
    }
}

#[cfg(test)]
mod tests {
    use crate::{Store, StoreError};

    #[test]
    fn round_trip_and_overwrite() {
        let s = Store::open_in_memory().expect("open");
        assert_eq!(s.app_setting("app.autolock").expect("get"), None);
        s.set_app_setting("app.autolock", r#"{"a":1}"#).expect("set");
        s.set_app_setting("app.autolock", r#"{"a":2}"#).expect("replace");
        assert_eq!(s.app_setting("app.autolock").expect("get").as_deref(), Some(r#"{"a":2}"#));
    }

    #[test]
    fn store_keys_are_out_of_reach() {
        let s = Store::open_in_memory().expect("open");
        for key in [
            "schema_version",
            "vault_id",
            "credential_reseal_pending",
            "app.",
            "app.UPPER",
            "app.semi;colon",
            "app.x\0",
            "xapp.x",
            &format!("app.{}", "a".repeat(64)),
        ] {
            assert!(
                matches!(
                    s.set_app_setting(key, "1"),
                    Err(StoreError::Invalid { field: "key", .. })
                ),
                "{key:?}"
            );
            assert!(s.app_setting(key).is_err(), "{key:?}");
        }
        assert!(s.schema_version().expect("v") > 0, "bookkeeping untouched");
    }

    #[test]
    fn oversized_value_is_refused() {
        let s = Store::open_in_memory().expect("open");
        let big = "x".repeat(super::MAX_APP_VALUE + 1);
        assert!(matches!(
            s.set_app_setting("app.big", &big),
            Err(StoreError::Invalid { field: "value", .. })
        ));
    }
}
