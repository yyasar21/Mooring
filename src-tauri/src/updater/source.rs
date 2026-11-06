//! The update source behind the commands: the `tauri-plugin-updater` Rust API in the app
//! ([`PluginSource`]), a scripted fake in tests. The commands never see a URL, a signature or
//! the downloaded bytes; the plugin verifies the minisign signature against the compiled-in
//! public key before a single byte is written (trust chain, ADR-0018 §3):
//!
//! 1. `plugins.updater.pubkey` is compiled into the binary (release-engineer, `tauri.conf.json`).
//! 2. `latest.json` is fetched over HTTPS from the configured endpoint; it is **not** signed,
//!    so it can only name a version, a URL and a signature. Its parsed body is bounded by
//!    [`download::MANIFEST_CAP`] and the URL must sit under
//!    [`download::RELEASE_DOWNLOAD_PREFIX`] for the offered version (review 7 L-40).
//! 3. The asset is downloaded through [`download::capped`] (256 MiB, 10 min) and
//!    `Update::verify` checks the minisign signature of the bytes against the pubkey; a
//!    tampered asset, a wrong key or a swapped URL fails here. Review 7 L-39: the update is
//!    rebuilt with `Updater::restore_update`, which **requires** the signature's trusted
//!    comment to carry the version it was signed for and to equal the announced one — so a
//!    manifest cannot pair a higher version with an older, validly signed package, whatever
//!    `requireSignedVersion` says in the config (it is set there too).
//! 4. [`UpdateSource::install`] re-runs the check and installs only when the offered version
//!    equals the one the user confirmed (no renderer-supplied URL or bytes, no TOCTOU swap).

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use semver::Version;

use super::download;

/// Boxed future (no `async_trait` dependency).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What a manifest offered, already reduced to what the UI may see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteUpdate {
    /// Offered version.
    pub version: Version,
    /// RFC 3339 publish date, if the manifest has one.
    pub date: Option<String>,
    /// Raw release notes (sanitised by the caller).
    pub notes: Option<String>,
    /// Asset size in bytes when the manifest's platform entry carries `size`.
    pub size: Option<u64>,
}

/// Why a source call failed; each maps to one `update.*` code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceError {
    /// DNS, TCP, TLS, timeout, non-2xx.
    Network,
    /// The manifest could not be parsed, or has no entry for this target.
    Manifest,
    /// The bundle's signature did not verify against the compiled-in key.
    Signature,
    /// The re-check offered nothing, or a different version than requested.
    None,
    /// Writing the new install failed after verification.
    Install,
    /// No endpoint / pubkey, or the platform is not supported by the plugin.
    Unconfigured,
}

impl SourceError {
    /// The IPC code.
    pub fn code(self) -> &'static str {
        match self {
            Self::Network => "update.network",
            Self::Manifest => "update.manifest",
            Self::Signature => "update.signature",
            Self::None => "update.none",
            Self::Install => "update.install_failed",
            Self::Unconfigured => "update.unconfigured",
        }
    }

    /// A safe sentence for the UI.
    pub fn message(self) -> &'static str {
        match self {
            Self::Network => "the update server could not be reached",
            Self::Manifest => "the update manifest is invalid",
            Self::Signature => "the downloaded update failed signature verification",
            Self::None => "this version is no longer offered",
            Self::Install => "the update could not be installed",
            Self::Unconfigured => "updates are not configured for this build",
        }
    }
}

/// Called after the bytes are verified and before anything is written (the audit row).
pub type BeforeInstall = Box<dyn FnOnce() + Send>;

/// One network check, one verified install.
pub trait UpdateSource: Send + Sync {
    /// Fetch the manifest; `Ok(None)` when nothing newer is offered.
    fn check(&self) -> BoxFuture<'_, Result<Option<RemoteUpdate>, SourceError>>;

    /// Re-check, download, verify and install exactly `version`, then restart the app. On
    /// success this never returns in the real source (the process restarts); the fake returns.
    fn install<'a>(
        &'a self,
        version: &'a Version,
        before_install: BeforeInstall,
    ) -> BoxFuture<'a, Result<(), SourceError>>;
}

/// Request timeout for the manifest (same as `mooring-http`'s request deadline). The
/// download has its own [`download::DOWNLOAD_DEADLINE`].
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The plugin-backed source. Built only when the plugin is registered (pubkey configured).
pub struct PluginSource {
    app: tauri::AppHandle,
}

impl std::fmt::Debug for PluginSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PluginSource")
    }
}

impl PluginSource {
    /// Wrap the app handle.
    pub fn new(app: tauri::AppHandle) -> Self {
        Self { app }
    }

    /// The plugin updater with Mooring's policy: strict `offered > current` (semver, so a
    /// pre-release never "updates" a release), a 30 s deadline and `https` only on the reqwest
    /// client (GitHub redirects `releases/latest/download/…` to its asset host, so redirects
    /// stay on, at reqwest's default cap of 10, every hop `https`). `mooring-http` cannot be
    /// used here: the plugin owns its `reqwest` client and `UpdaterBuilder::configure_client`
    /// is the only hook, so its policy is mirrored instead.
    fn updater(&self) -> Result<tauri_plugin_updater::Updater, SourceError> {
        use tauri_plugin_updater::UpdaterExt;
        self.app
            .updater_builder()
            .version_comparator(|current, release| release.version > current)
            .timeout(REQUEST_TIMEOUT)
            .configure_client(|c| {
                c.https_only(true).user_agent(concat!("Mooring/", env!("CARGO_PKG_VERSION")))
            })
            .build()
            .map_err(|e| {
                tracing::warn!(error = %e, "updater not built");
                SourceError::Unconfigured
            })
    }

    /// Fetch the manifest and rebuild the update with the signed-version binding forced on
    /// (L-39), the manifest cap applied (L-40).
    async fn check_inner(&self) -> Result<Option<tauri_plugin_updater::Update>, SourceError> {
        let updater = self.updater()?;
        let Some(update) = updater.check().await.map_err(|e| map_err(&e))? else {
            return Ok(None);
        };
        download::manifest_within_cap(&update.raw_json)?;
        // `restore_update` applies the same target and comparator and sets
        // `require_signed_version` on the result unconditionally.
        updater.restore_update(update.raw_json).map_err(|e| map_err(&e))
    }
}

/// Plugin errors → [`SourceError`]; the plugin's messages carry URLs, so only the class is kept.
fn map_err(e: &tauri_plugin_updater::Error) -> SourceError {
    use tauri_plugin_updater::Error as E;
    tracing::warn!(error = %e, "updater");
    match e {
        E::Reqwest(_) | E::Network(_) | E::UrlParse(_) | E::Http(_) => SourceError::Network,
        E::ReleaseNotFound
        | E::Serialization(_)
        | E::Semver(_)
        | E::TargetNotFound(_)
        | E::TargetsNotFound(_)
        | E::FormatDate => SourceError::Manifest,
        E::Minisign(_)
        | E::Base64(_)
        | E::SignatureUtf8(_)
        | E::SignedVersionMismatch { .. }
        | E::MissingSignedVersion => SourceError::Signature,
        E::EmptyEndpoints | E::UnsupportedArch | E::UnsupportedOs | E::InsecureTransportProtocol => {
            SourceError::Unconfigured
        }
        _ => SourceError::Install,
    }
}

/// Reduce a plugin `Update` to the UI-safe shape.
fn remote(u: &tauri_plugin_updater::Update) -> Result<RemoteUpdate, SourceError> {
    let version = Version::parse(&u.version).map_err(|_| SourceError::Manifest)?;
    let date = u.date.and_then(|d| d.format(&time::format_description::well_known::Rfc3339).ok());
    let size = u.raw_json.get("platforms").and_then(|p| p.get(&u.target)).and_then(|p| p.get("size")).and_then(serde_json::Value::as_u64);
    Ok(RemoteUpdate { version, date, notes: u.body.clone(), size })
}

impl UpdateSource for PluginSource {
    fn check(&self) -> BoxFuture<'_, Result<Option<RemoteUpdate>, SourceError>> {
        Box::pin(async move { self.check_inner().await?.as_ref().map(remote).transpose() })
    }

    fn install<'a>(
        &'a self,
        version: &'a Version,
        before_install: BeforeInstall,
    ) -> BoxFuture<'a, Result<(), SourceError>> {
        Box::pin(async move {
            let mut update = self.check_inner().await?.ok_or(SourceError::None)?;
            if remote(&update)?.version != *version {
                return Err(SourceError::None);
            }
            // L-40: only this repository's release asset for exactly this version.
            download::check_download_url(update.download_url.as_str(), version)?;
            update.timeout = Some(download::DOWNLOAD_DEADLINE);
            // `download` verifies the signature (version-bound, L-39) before returning the
            // bytes; the capped reader drops it as soon as it runs past the package cap.
            let u = &update;
            let bytes = download::capped(download::PACKAGE_CAP, download::DOWNLOAD_DEADLINE, |mut on_chunk| async move {
                u.download(|len, declared| on_chunk(len, declared), || {}).await.map_err(|e| map_err(&e))
            })
            .await?;
            before_install();
            // `install` verifies again; the bytes are the verified ones.
            update.install(bytes).map_err(|e| map_err(&e))?;
            // Windows: the NSIS installer relaunches the app and the plugin has exited the
            // process already. macOS / Linux: relaunch the replaced binary.
            self.app.restart()
        })
    }
}
