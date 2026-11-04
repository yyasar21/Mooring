//! Sync settings (ADR-0017 §5, A3 S2): IPC input validation, the stored [`SyncConfig`]
//! (device-local `sync.config` setting, never synced), and building the S3 remote for one run
//! with the `s3_access_key` credential opened from the vault and dropped right after.

use mooring_core::credential::{CredentialFields, CredentialKind, SecretName};
use mooring_core::CredentialId;
use mooring_sync::{Remote, S3Backend, S3Config, S3Credentials};
use mooring_vault::Uuid;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::error::{IpcError, IpcResult};
use crate::state::{AppState, Ready};

/// Setting key of the stored config (device-local, like every `sync.*` key).
pub const CONFIG_KEY: &str = "sync.config";
/// Shortest background interval.
pub const MIN_INTERVAL_MINUTES: u32 = 5;
/// Longest background interval (one day).
pub const MAX_INTERVAL_MINUTES: u32 = 1440;

/// `backend` as the UI sends it. `kind` is checked by hand so an unknown kind is
/// `sync.backend_unsupported`, not a deserialisation error.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BackendInput {
    /// Only `s3`.
    pub kind: String,
    /// `https://host[:port]` (`http://` only for a loopback IP literal).
    pub endpoint: String,
    /// Signing region.
    pub region: String,
    /// Bucket name.
    pub bucket: String,
    /// Key prefix (`[A-Za-z0-9._-]` segments joined by `/`), may be empty.
    #[serde(default)]
    pub prefix: String,
    /// Path-style addressing (default `true`: custom endpoints rarely do virtual hosts).
    #[serde(default)]
    pub path_style: Option<bool>,
}

/// A validated S3 backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BackendConfig {
    /// `s3`.
    pub kind: String,
    /// Normalised origin, no trailing slash.
    pub endpoint: String,
    /// Region.
    pub region: String,
    /// Bucket.
    pub bucket: String,
    /// Prefix.
    pub prefix: String,
    /// Path-style addressing.
    pub path_style: bool,
}

/// What `sync_configure` stores and returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SyncConfig {
    /// Where the vault is synced.
    pub backend: BackendConfig,
    /// `s3_access_key` credential id.
    pub credential_id: String,
    /// Background interval; `None` = manual only (`sync_now`).
    pub interval_minutes: Option<u32>,
}

fn bad(field: &str, reason: &str) -> IpcError {
    IpcError::invalid(field, reason)
}

/// `true` for `127.0.0.0/8` and `[::1]` literals (with an optional port).
fn loopback_authority(authority: &str) -> bool {
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or_default()
    } else {
        authority.split(':').next().unwrap_or_default()
    };
    host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// `https://host[:port]`, or `http://` to a loopback IP literal. No user info, path, query or
/// fragment. Returns the normalised origin and whether it is plaintext.
pub fn check_endpoint(raw: &str) -> IpcResult<(String, bool)> {
    let raw = raw.trim().trim_end_matches('/');
    let (plain, authority) = match (raw.strip_prefix("https://"), raw.strip_prefix("http://")) {
        (Some(a), _) => (false, a),
        (None, Some(a)) => (true, a),
        _ => return Err(bad("endpoint", "must start with https://")),
    };
    let ok_chars =
        authority.bytes().all(|b| b.is_ascii_alphanumeric() || b"-.:[]".contains(&b));
    if authority.is_empty() || authority.len() > 255 || !ok_chars {
        return Err(bad("endpoint", "must be https://host[:port] without a path"));
    }
    if plain && !loopback_authority(authority) {
        return Err(bad("endpoint", "plain http:// is allowed only for a loopback address"));
    }
    let scheme = if plain { "http" } else { "https" };
    Ok((format!("{scheme}://{}", authority.to_ascii_lowercase()), plain))
}

fn check_bucket(b: &str) -> IpcResult<()> {
    let edge = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    let ok = (3..=63).contains(&b.len())
        && b.bytes().all(|c| edge(c) || c == b'-' || c == b'.')
        && b.bytes().next().is_some_and(edge)
        && b.bytes().last().is_some_and(edge)
        && !b.contains("..");
    if ok {
        Ok(())
    } else {
        Err(bad("bucket", "must be 3-63 lowercase letters, digits, '-' or '.'"))
    }
}

fn check_region(r: &str) -> IpcResult<()> {
    let ok = (1..=64).contains(&r.len())
        && r.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
    if ok {
        Ok(())
    } else {
        Err(bad("region", "must be like us-east-1"))
    }
}

/// Validate `backend`.
pub fn check_backend(input: &BackendInput) -> IpcResult<BackendConfig> {
    if input.kind != "s3" {
        return Err(IpcError::new("sync.backend_unsupported", "only S3-compatible storage is supported"));
    }
    let (endpoint, _) = check_endpoint(&input.endpoint)?;
    check_region(input.region.trim())?;
    check_bucket(input.bucket.trim())?;
    let prefix = input.prefix.trim().trim_matches('/').to_owned();
    mooring_sync::backend::check_prefix(&prefix)
        .map_err(|_| bad("prefix", "must be letters, digits, '.', '_' or '-' segments joined by /"))?;
    Ok(BackendConfig {
        kind: "s3".to_owned(),
        endpoint,
        region: input.region.trim().to_owned(),
        bucket: input.bucket.trim().to_owned(),
        prefix,
        path_style: input.path_style.unwrap_or(true),
    })
}

/// `intervalMinutes`: `null` (manual only) or 5..=1440.
pub fn check_interval(minutes: Option<u32>) -> IpcResult<Option<u32>> {
    match minutes {
        Some(m) if !(MIN_INTERVAL_MINUTES..=MAX_INTERVAL_MINUTES).contains(&m) => {
            Err(bad("intervalMinutes", "must be 5 to 1440 minutes, or null for manual only"))
        }
        m => Ok(m),
    }
}

/// Parse a credential id and require an `s3_access_key` credential.
pub fn check_credential(ready: &Ready, id: &str) -> IpcResult<CredentialId> {
    let id: CredentialId = id.parse().map_err(|_| bad("credentialId", "not a credential id"))?;
    ready.with_ready(|_, store| {
        if store.get_credential(id)?.kind == CredentialKind::S3AccessKey {
            Ok(id)
        } else {
            Err(IpcError::new("credential.incompatible", "sync needs an S3 access key credential"))
        }
    })
}

/// The stored config.
pub fn load(ready: &Ready) -> IpcResult<Option<SyncConfig>> {
    ready.with_ready(|_, store| {
        let Some(text) = store.sync_setting(CONFIG_KEY)? else { return Ok(None) };
        serde_json::from_str(&text).map(Some).map_err(|_| {
            tracing::error!("stored sync config is unreadable");
            IpcError::new("store.corrupt", "the stored sync settings are damaged")
        })
    })
}

/// Store (or with `None` remove) the config.
pub fn save(ready: &Ready, cfg: Option<&SyncConfig>) -> IpcResult<()> {
    let text = cfg.map(serde_json::to_string).transpose().map_err(|_| IpcError::poisoned())?;
    ready.with_ready(|_, store| Ok(store.set_sync_setting(CONFIG_KEY, text.as_deref())?))
}

/// Open the `s3_access_key` credential: the access key id, the region override and the
/// secrets, which live only in the returned value (zeroized when it is dropped).
pub fn open_credentials(ready: &Ready, id: CredentialId) -> IpcResult<(S3Credentials, Option<String>)> {
    ready.with_ready(|vault, store| {
        let meta = store.get_credential(id)?;
        let CredentialFields::S3AccessKey(f) = &meta.fields else {
            return Err(IpcError::new("credential.incompatible", "sync needs an S3 access key credential"));
        };
        let text = |name| -> IpcResult<SecretString> {
            let plain = store.open_secret(vault, id, name)?;
            let s = std::str::from_utf8(&plain).map_err(|_| bad("credential", "secret is not text"))?;
            Ok(SecretString::from(s.to_owned()))
        };
        let session_token = if meta.secret_names.contains(&SecretName::SessionToken) {
            Some(text(SecretName::SessionToken)?)
        } else {
            None
        };
        let creds = S3Credentials {
            access_key_id: f.access_key_id.clone(),
            secret_access_key: text(SecretName::SecretAccessKey)?,
            session_token,
        };
        Ok((creds, f.region.clone()))
    })
}

/// Build the remote of `vault_id` for one run. The credentials are dropped (zeroized) before
/// this returns; only the signer inside the backend keeps the key for the run.
pub fn remote(
    state: &AppState,
    ready: &Ready,
    cfg: &SyncConfig,
    vault_id: Uuid,
    trusted_once: Option<[u8; 32]>,
) -> IpcResult<Remote<S3Backend>> {
    let id: CredentialId =
        cfg.credential_id.parse().map_err(|_| bad("credentialId", "not a credential id"))?;
    let (creds, region) = open_credentials(ready, id)?;
    let (_, plain) = check_endpoint(&cfg.backend.endpoint)?;
    let s3 = S3Config {
        endpoint: cfg.backend.endpoint.clone(),
        region: region.unwrap_or_else(|| cfg.backend.region.clone()),
        bucket: cfg.backend.bucket.clone(),
        path_style: cfg.backend.path_style,
        known_certs_path: state.data_dir.join(mooring_core::known_certs::CertProtocol::Sync.file_name()),
        ca_pem: None,
        allow_plaintext_loopback: plain,
        trusted_once,
    };
    let backend = S3Backend::new(&s3, &creds).map_err(|e| crate::commands::sync::sync_error(&e))?;
    drop(creds);
    Remote::new(backend, &cfg.backend.prefix, vault_id).map_err(|e| crate::commands::sync::sync_error(&e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(endpoint: &str) -> BackendInput {
        BackendInput {
            kind: "s3".into(),
            endpoint: endpoint.into(),
            region: "us-east-1".into(),
            bucket: "mooring-sync".into(),
            prefix: "team/vaults".into(),
            path_style: None,
        }
    }

    #[test]
    fn endpoints_are_https_or_loopback_http() {
        assert_eq!(check_endpoint("https://S3.Example.test/").expect("ok").0, "https://s3.example.test");
        assert!(check_endpoint("http://127.0.0.1:9000").expect("loopback").1);
        assert!(check_endpoint("http://[::1]:9000").is_ok());
        for bad in [
            "http://s3.example.test",
            "http://192.0.2.1",
            "ftp://s3.example.test",
            "https://user@s3.example.test",
            "https://s3.example.test/path",
            "https://s3.example.test?x=1",
            "https://",
            "s3.example.test",
        ] {
            assert_eq!(check_endpoint(bad).expect_err(bad).code, "input.invalid", "{bad}");
        }
    }

    #[test]
    fn backend_fields_are_validated() {
        let ok = check_backend(&input("https://s3.example.test")).expect("ok");
        assert!(ok.path_style);
        assert_eq!(ok.prefix, "team/vaults");
        let mut i = input("https://s3.example.test");
        i.kind = "gcs".into();
        assert_eq!(check_backend(&i).expect_err("kind").code, "sync.backend_unsupported");
        for (field, value) in [("bucket", "Bad_Bucket"), ("bucket", "ab"), ("bucket", "-x-y"), ("region", "US EAST"), ("prefix", "../x"), ("prefix", "a//b")] {
            let mut i = input("https://s3.example.test");
            match field {
                "bucket" => i.bucket = value.into(),
                "region" => i.region = value.into(),
                _ => i.prefix = value.into(),
            }
            let e = check_backend(&i).expect_err(value);
            assert!(e.message.contains(field), "{value}: {}", e.message);
        }
    }

    #[test]
    fn interval_is_manual_or_at_least_five_minutes() {
        assert_eq!(check_interval(None).expect("manual"), None);
        assert_eq!(check_interval(Some(5)).expect("5"), Some(5));
        assert!(check_interval(Some(4)).is_err());
        assert!(check_interval(Some(0)).is_err());
        assert!(check_interval(Some(1441)).is_err());
    }
}
