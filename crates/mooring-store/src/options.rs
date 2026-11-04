//! Per-protocol connection options (`connection.options_json`, migration 0005).
//!
//! The options are not part of `mooring_core::Connection` (that would change every caller of
//! the A1 model); they are read and written per connection here. Writes validate and check
//! that the options fit the row's protocol; reads re-validate, so a value edited behind the
//! store's back is refused rather than handed to a protocol crate. When `update_connection`
//! changes a connection's protocol, its options are reset to `{}`.

use mooring_core::{ConnectionId, ProtocolOptions};
use rusqlite::OptionalExtension;

use crate::error::{invalid, not_found, Result};
use crate::util::{fmt_ts, now, protocol_from_str};
use crate::Store;

impl Store {
    /// Options of a connection, parsed for its protocol and re-validated.
    pub fn connection_options(&self, id: ConnectionId) -> Result<ProtocolOptions> {
        let row: Option<(String, String)> = self
            .conn
            .query_row(
                "SELECT protocol, options_json FROM connection WHERE id = ?1",
                [id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (protocol, json) = row.ok_or_else(|| not_found("connection", &id))?;
        Ok(ProtocolOptions::from_json(protocol_from_str(&protocol)?, &json)?)
    }

    /// Replace a connection's options. They must validate and fit its protocol.
    pub fn set_connection_options(
        &self,
        id: ConnectionId,
        options: &ProtocolOptions,
    ) -> Result<ProtocolOptions> {
        options.validate()?;
        let protocol: Option<String> = self
            .conn
            .query_row("SELECT protocol FROM connection WHERE id = ?1", [id.to_string()], |r| {
                r.get(0)
            })
            .optional()?;
        let protocol = protocol_from_str(&protocol.ok_or_else(|| not_found("connection", &id))?)?;
        if !options.fits(protocol) {
            return Err(invalid("options", "do not match the connection's protocol"));
        }
        self.conn.execute(
            "UPDATE connection SET options_json = ?2, updated_at = ?3 WHERE id = ?1",
            (id.to_string(), options.to_json()?, fmt_ts(now())?),
        )?;
        self.connection_options(id)
    }
}

#[cfg(test)]
#[path = "options_tests.rs"]
mod tests;
