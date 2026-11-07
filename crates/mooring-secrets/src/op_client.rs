//! [`ConnectClient`]: a self-hosted 1Password Connect server (ADR-0026 §3) over the hardened
//! `mooring-http` client (`CertProtocol::Onepassword`, `known_onepassword_certs`, our pins /
//! TOFU / `caPem`, 1 MiB cap, redirects refused). The Connect token travels as
//! `Authorization: Bearer` (a sensitive header, printed `<redacted>`).
//!
//! Resolution: vault by name (or UUID) → item by title (or UUID) → the item; exactly one match
//! at each step (none → `not_found`, several → `shape`).

use mooring_core::credential::OpReference;
use mooring_core::secret_source::SecretSource;
use mooring_http::{decode_json, CertProtocol, Headers, HttpClient, HttpConfig, Method};

use crate::client::{pct_encode, ClientConfig, MAX_RESPONSE};
use crate::error::{from_status, Ctx, SecretsError};
use crate::op_wire::{Capped, Item, ItemSummary, VaultSummary, MAX_SUMMARIES};

/// A 1Password id: 26 lowercase base32-ish characters.
#[must_use]
pub fn is_op_id(s: &str) -> bool {
    s.len() == 26 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// Client bound to one Connect source. Cheap to clone.
#[derive(Clone)]
pub struct ConnectClient {
    http: HttpClient,
}

impl std::fmt::Debug for ConnectClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectClient").field("http", &self.http).finish_non_exhaustive()
    }
}

fn filter(attr: &str, value: &str) -> Result<String, SecretsError> {
    if value.contains('"') {
        return Err(SecretsError::Invalid("reference (a title with a quote cannot be looked up)"));
    }
    Ok(format!("?filter={}", pct_encode(&format!("{attr} eq \"{value}\""))))
}

impl ConnectClient {
    /// Build the client for `source` (no I/O).
    pub fn new(source: &SecretSource, cfg: &ClientConfig) -> Result<Self, SecretsError> {
        let mut h = HttpConfig::new(
            CertProtocol::Onepassword,
            &source.address,
            cfg.onepassword_certs_path(),
        );
        h.extra_ca_pem.clone_from(&source.options.ca_pem);
        h.allow_plaintext = source.options.allow_http;
        h.trusted_once = cfg.trusted_once;
        h.timeouts = cfg.timeouts;
        h.retry = cfg.retry;
        h.max_body = MAX_RESPONSE;
        h.trust_events.clone_from(&cfg.trust_events);
        Ok(Self { http: HttpClient::new(h)? })
    }

    fn headers(token: Option<&str>) -> Result<Headers, SecretsError> {
        let h = Headers::new().insert("Accept", "application/json")?;
        match token {
            None => Ok(h),
            Some(t) => h
                .insert("Authorization", &format!("Bearer {t}"))
                .map_err(|_| SecretsError::Invalid("token")),
        }
    }

    async fn get(&self, path: &str, token: Option<&str>) -> Result<Vec<u8>, SecretsError> {
        let r = self
            .http
            .request(Method::GET, path, &Self::headers(token)?, None, MAX_RESPONSE)
            .await?;
        if !r.status.is_success() {
            return Err(from_status(r.status, Ctx::Read));
        }
        Ok(r.body.to_vec())
    }

    /// `GET /heartbeat` (no token).
    pub async fn heartbeat(&self) -> Result<(), SecretsError> {
        self.get("/heartbeat", None).await.map(drop)
    }

    /// `GET /v1/vaults`: how many vaults the token can read (`secret_source_test`).
    pub async fn vault_count(&self, token: &str) -> Result<usize, SecretsError> {
        let body = self.get("/v1/vaults", Some(token)).await?;
        let list: Capped<VaultSummary, MAX_SUMMARIES> = decode_json(&body)?;
        Ok(list.0.len())
    }

    async fn vault_id(&self, token: &str, vault: &str) -> Result<String, SecretsError> {
        if is_op_id(vault) {
            return Ok(vault.to_owned());
        }
        let body = self.get(&format!("/v1/vaults{}", filter("name", vault)?), Some(token)).await?;
        let list: Capped<VaultSummary, MAX_SUMMARIES> = decode_json(&body)?;
        let mut hits = list.0.into_iter().filter(|v| v.name.0 == vault);
        match (hits.next(), hits.next()) {
            (Some(v), None) if is_op_id(&v.id.0) => Ok(v.id.0),
            (Some(_), None) => Err(SecretsError::shape("vault id is malformed")),
            (Some(_), Some(_)) => Err(SecretsError::shape("two vaults have this name")),
            (None, _) => Err(SecretsError::NotFound),
        }
    }

    async fn item_id(&self, token: &str, vault: &str, item: &str) -> Result<String, SecretsError> {
        if is_op_id(item) {
            return Ok(item.to_owned());
        }
        let path = format!("/v1/vaults/{vault}/items{}", filter("title", item)?);
        let body = self.get(&path, Some(token)).await?;
        let list: Capped<ItemSummary, MAX_SUMMARIES> = decode_json(&body)?;
        let mut hits = list.0.into_iter().filter(|i| i.title.0 == item);
        match (hits.next(), hits.next()) {
            (Some(i), None) if is_op_id(&i.id.0) => Ok(i.id.0),
            (Some(_), None) => Err(SecretsError::shape("item id is malformed")),
            (Some(_), Some(_)) => Err(SecretsError::shape("two items have this title")),
            (None, _) => Err(SecretsError::NotFound),
        }
    }

    /// The item `r` names (fields and sections; values zeroized on drop).
    pub(crate) async fn item(&self, token: &str, r: &OpReference) -> Result<Item, SecretsError> {
        let vault = self.vault_id(token, &r.vault).await?;
        let id = self.item_id(token, &vault, &r.item).await?;
        let body = zeroize::Zeroizing::new(
            self.get(&format!("/v1/vaults/{vault}/items/{id}"), Some(token)).await?,
        );
        let item: Item = decode_json(&body)?;
        if item.id.0 != id {
            return Err(SecretsError::shape("the server returned another item"));
        }
        Ok(item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_filters() {
        assert!(is_op_id("abcdefghijklmnopqrstuvwxyz"));
        assert!(is_op_id("0123456789abcdefghijklmnop"));
        assert!(!is_op_id("ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
        assert!(!is_op_id("abc"));
        assert_eq!(filter("title", "DB prod").expect("f"), "?filter=title%20eq%20%22DB%20prod%22");
        assert!(filter("name", "a\"b").is_err());
        let h = ConnectClient::headers(Some("test-only-connect-token")).expect("h");
        let dump = format!("{:?}", mooring_http::Redacted(h.as_map()));
        assert!(!dump.contains("test-only-connect-token"), "{dump}");
        assert!(ConnectClient::headers(Some("bad\ntoken")).is_err());
    }
}
