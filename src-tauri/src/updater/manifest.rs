//! Review 7 / 9 L-40: `latest.json` through our own client, bounded **in flight**. The plugin's
//! `Updater::check` reads the body with `res.json()` (no cap), so Mooring fetches the manifest
//! itself and hands the parsed JSON to `Updater::restore_update`, which applies the same target
//! selection and version comparator and forces `require_signed_version`; the signature check
//! of the package by the plugin is unchanged.
//!
//! The client mirrors the plugin's: reqwest with rustls (ring) and the platform verifier, the
//! OS / environment proxy honoured (`system-proxy`), `https` only on every hop, at most
//! [`MAX_REDIRECTS`] redirects (GitHub sends `releases/latest/download/…` to its asset host),
//! one [`REQUEST_TIMEOUT`] for the whole exchange. The body is read chunk by chunk and refused
//! (`update.manifest`) as soon as it would pass [`download::MANIFEST_CAP`]; a declared
//! `Content-Length` over the cap is refused before any body byte is read.

use std::time::Duration;

use super::download::{self, MANIFEST_CAP};
use super::source::{SourceError, REQUEST_TIMEOUT};

/// Redirect hops followed for the manifest.
pub const MAX_REDIRECTS: usize = 5;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The client settings shared by production and the tests.
pub(crate) fn builder() -> reqwest::ClientBuilder {
    // reqwest is built with `rustls-no-provider`: install ring as the process default when
    // nothing is installed yet (the plugin does the same before its own requests).
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .user_agent(concat!("Mooring/", env!("CARGO_PKG_VERSION")))
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::limited(MAX_REDIRECTS))
}

/// The production client: `https` only on every hop, the system / env proxy honoured.
pub fn client() -> Result<reqwest::Client, SourceError> {
    builder().https_only(true).build().map_err(|e| {
        tracing::warn!(error = %e, "update manifest client not built");
        SourceError::Unconfigured
    })
}

/// The configured endpoint (`plugins.updater.endpoints[0]`). Templated endpoints are not used
/// by Mooring and are refused rather than half-expanded.
pub fn endpoint(plugins: &tauri::utils::config::PluginConfig) -> Result<String, SourceError> {
    let url = plugins
        .0
        .get("updater")
        .and_then(|u| u.get("endpoints"))
        .and_then(serde_json::Value::as_array)
        .and_then(|a| a.first())
        .and_then(serde_json::Value::as_str)
        .ok_or(SourceError::Unconfigured)?;
    if url.contains("{{") || !url.starts_with("https://") {
        tracing::warn!("update endpoint is templated or not https");
        return Err(SourceError::Unconfigured);
    }
    Ok(url.to_owned())
}

/// GET `url` and parse the body as JSON, reading at most `cap` bytes. `Ok(None)` on
/// `204 No Content` (no update, as for the plugin).
pub async fn fetch(
    client: &reqwest::Client,
    url: &str,
    cap: usize,
) -> Result<Option<serde_json::Value>, SourceError> {
    let network = |e: reqwest::Error| {
        tracing::warn!(timeout = e.is_timeout(), redirect = e.is_redirect(), "update manifest request failed");
        SourceError::Network
    };
    let mut resp = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(network)?;
    let status = resp.status();
    if status == reqwest::StatusCode::NO_CONTENT {
        return Ok(None);
    }
    if !status.is_success() {
        tracing::warn!(status = status.as_u16(), "update manifest status");
        return Err(SourceError::Network);
    }
    let over = || {
        tracing::warn!(cap, "update manifest over the cap");
        SourceError::Manifest
    };
    if resp.content_length().is_some_and(|n| n > cap as u64) {
        return Err(over());
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(network)? {
        if body.len() + chunk.len() > cap {
            return Err(over());
        }
        body.extend_from_slice(&chunk);
    }
    let value: serde_json::Value = serde_json::from_slice(&body).map_err(|_| {
        tracing::warn!("update manifest is not JSON");
        SourceError::Manifest
    })?;
    download::manifest_within_cap(&value)?;
    Ok(Some(value))
}

/// [`fetch`] of the production endpoint with [`MANIFEST_CAP`].
pub async fn fetch_configured(
    plugins: &tauri::utils::config::PluginConfig,
) -> Result<Option<serde_json::Value>, SourceError> {
    let url = endpoint(plugins)?;
    fetch(&client()?, &url, MANIFEST_CAP).await
}

#[cfg(test)]
#[path = "manifest_tests.rs"]
mod tests;
