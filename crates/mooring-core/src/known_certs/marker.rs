//! "TLS seen" markers (review 5 M-13): a host-only line that makes the VNC downgrade guard
//! hold for servers whose certificate validated against a CA and was therefore never pinned.
//!
//! ```text
//! |2|<salt b64>|<HMAC-SHA256(salt, "host:port") b64> tls-required - <added RFC 3339>
//! ```
//!
//! The marker carries no fingerprint, so a CA reissue never trips it; only a missing
//! `VeNCrypt` offer does. It is written by the Tauri layer only (single writer, R2 contract)
//! and removed together with the pins of the host.

use std::path::Path;
use std::sync::PoisonError;

use data_encoding::BASE64;
use rand_core::{OsRng, RngCore};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::{
    hmac_host, host_key, host_matches, path_lock, HostField, KnownCerts, KnownCertsError, Line,
    HASH_MAGIC, SALT_LEN,
};

/// Key type token of a "TLS seen" marker; its fingerprint field is always `-`.
pub const TLS_MARKER: &str = "tls-required";

impl KnownCerts {
    /// Whether a "TLS seen" marker names `host:port`.
    pub fn tls_marked(&self, host: &str, port: u16) -> bool {
        let name = host_key(host, port);
        self.lines.iter().filter_map(|l| l.marker.as_ref()).any(|m| host_matches(m, &name))
    }

    /// Whether TLS is mandatory for `host:port`: a pin or a marker (ADR-0012 downgrade guard).
    pub fn tls_expected(&self, host: &str, port: u16) -> bool {
        self.has_pin(host, port) || self.tls_marked(host, port)
    }

    /// Add a hashed marker for `host:port` unless one exists. `true` when a line was added.
    pub fn mark_tls(&mut self, host: &str, port: u16, added: OffsetDateTime) -> bool {
        if self.tls_marked(host, port) {
            return false;
        }
        let mut salt = vec![0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let hash = hmac_host(&salt, &host_key(host, port));
        let added = added.format(&Rfc3339).unwrap_or_else(|_| "1970-01-01T00:00:00Z".into());
        let raw = format!("{HASH_MAGIC}{}|{}", BASE64.encode(&salt), BASE64.encode(&hash));
        let text = format!("{raw} {TLS_MARKER} - {added}");
        self.lines.push(Line { text, entry: None, marker: Some(HostField::Hashed { salt, hash }) });
        true
    }

    /// Load, mark and save (only when a marker was added) under the per-path lock.
    /// Blocking: call from `spawn_blocking` or accept a short file write.
    pub fn mark_tls_and_save(
        path: &Path,
        host: &str,
        port: u16,
        added: OffsetDateTime,
    ) -> Result<bool, KnownCertsError> {
        let lock = path_lock(path);
        let _guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
        let mut store = Self::load(path)?;
        if !store.mark_tls(host, port, added) {
            return Ok(false);
        }
        store.save(path)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_round_trip_and_remove() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("known_vnc_certs");
        let now = OffsetDateTime::UNIX_EPOCH;
        assert!(KnownCerts::mark_tls_and_save(&path, "VNC.example.test", 5900, now).expect("mark"));
        assert!(
            !KnownCerts::mark_tls_and_save(&path, "vnc.example.test", 5900, now).expect("again")
        );
        let text = std::fs::read_to_string(&path).expect("read");
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains(" tls-required - 1970-01-01T00:00:00Z"), "{text}");
        assert!(!text.contains("example"), "the host is hashed: {text}");
        let k = KnownCerts::load(&path).expect("load");
        assert!(k.tls_marked("vnc.example.test", 5900));
        assert!(k.tls_expected("vnc.example.test", 5900));
        assert!(!k.has_pin("vnc.example.test", 5900), "a marker is not a pin");
        assert!(k.is_empty() && k.list().is_empty(), "markers are not listed as pins");
        assert!(!k.tls_expected("vnc.example.test", 5901));
        // known_certs_remove deletes the marker too.
        KnownCerts::remove_and_save(&path, "vnc.example.test", 5900).expect("remove");
        assert!(!KnownCerts::load(&path).expect("load").tls_marked("vnc.example.test", 5900));
    }

    #[test]
    fn plain_and_malformed_markers() {
        let k = KnownCerts::parse_bytes(
            b"vnc.example.test:5900 tls-required - 2026-01-01T00:00:00Z\n\
              other.example.test:5900 tls-required AAAA 2026-01-01T00:00:00Z\n",
        );
        assert!(k.tls_marked("vnc.example.test", 5900));
        assert!(!k.tls_marked("other.example.test", 5900), "a marker has no fingerprint");
        assert_eq!(k.to_file_string().lines().count(), 2, "kept verbatim");
    }
}
