//! `known_certs_list` with host names (U2): the UI no longer recomputes salted HMACs. Only a
//! `host:port` the caller already knows (its own connections) is joined; the file itself
//! still never names a host.

use super::{host_key, host_matches, KnownCert, KnownCerts};

impl KnownCerts {
    /// [`KnownCerts::list`], with `host` / `port` filled in where one of `candidates`
    /// matches the entry's (hashed or plain) host field.
    pub fn list_named(&self, candidates: &[(String, u16)]) -> Vec<KnownCert> {
        let keys: Vec<(String, &str, u16)> =
            candidates.iter().map(|(h, p)| (host_key(h, *p), h.as_str(), *p)).collect();
        self.entries()
            .zip(self.list())
            .map(|(e, mut listed)| {
                if let Some((_, h, p)) = keys.iter().find(|(k, _, _)| host_matches(&e.host, k)) {
                    listed.host = Some((*h).to_owned());
                    listed.port = Some(*p);
                }
                listed
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    #[test]
    fn only_known_connections_are_named() {
        let mut k = KnownCerts::new();
        let t = OffsetDateTime::UNIX_EPOCH;
        k.add("RDP.example.test", 3389, &[1; 32], t);
        k.add("other.example.test", 3389, &[2; 32], t);
        let named = k.list_named(&[
            ("rdp.example.test".to_owned(), 3389),
            ("other.example.test".to_owned(), 3390),
        ]);
        assert_eq!(named.len(), 2);
        assert_eq!(
            (named[0].host.as_deref(), named[0].port),
            (Some("rdp.example.test"), Some(3389))
        );
        assert_eq!((named[1].host.as_deref(), named[1].port), (None, None), "port differs");
        assert!(named[0].host_hash.starts_with("|2|"));
        let json = serde_json::to_value(&named[1]).expect("json");
        assert!(json.get("host").is_none(), "absent, not null: {json}");
    }
}
