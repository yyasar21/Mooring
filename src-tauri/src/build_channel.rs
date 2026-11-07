// ADR-0028 §1: which channel a build is. Plain code shared with `build.rs` through `include!`
// (so no inner attributes or `//!` docs) and compiled into the library's tests. The build
// script re-derives the effective identifier exactly as tauri-build does (the checked-in
// `tauri.conf.json`, the auto-read `tauri.<platform>.conf.json`, then `TAURI_CONFIG` as an
// RFC 7396 merge patch, tauri-build 2.7.4 `lib.rs:681`) and emits `cfg(mooring_release)` only
// when that identifier is the release one **and** `MOORING_RELEASE_BUILD=1`; exactly one of
// the two is a hard build error, so neither half alone produces a release build.

/// The release identifier (`tauri.release.conf.json`); every other identifier is dev.
pub const RELEASE_IDENTIFIER: &str = "io.github.yyasar21.mooring";
/// The variable `release.yml` sets on the tauri-action step only.
pub const RELEASE_ENV: &str = "MOORING_RELEASE_BUILD";

/// The channel of the build being compiled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // build.rs uses both; the lib's tests compare them
pub enum BuildChannel {
    /// Release identifier and `MOORING_RELEASE_BUILD=1`.
    Release,
    /// Everything else.
    Dev,
}

/// Why the channel could not be decided (a build error).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildChannelError {
    /// A config document is not JSON or has no string `identifier`.
    Config(String),
    /// `MOORING_RELEASE_BUILD` holds something other than unset, empty, `0` or `1`.
    Flag(String),
    /// The identifier says release and the variable does not, or the other way round.
    Mismatch {
        /// The effective identifier.
        identifier: String,
        /// Whether `MOORING_RELEASE_BUILD=1` was set.
        flag: bool,
    },
}

impl std::fmt::Display for BuildChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(m) => write!(f, "tauri config: {m}"),
            Self::Flag(v) => write!(f, "{RELEASE_ENV} must be unset, empty, 0 or 1 (got {v:?})"),
            Self::Mismatch { identifier, flag: true } => write!(
                f,
                "{RELEASE_ENV}=1 but the effective identifier is {identifier:?}, not {RELEASE_IDENTIFIER:?}: \
                 pass --config src-tauri/tauri.release.conf.json (ADR-0028)"
            ),
            Self::Mismatch { identifier, flag: false } => write!(
                f,
                "the effective identifier is the release one ({identifier:?}) but {RELEASE_ENV}=1 is not set: \
                 release-identity builds come from release.yml only (ADR-0028)"
            ),
        }
    }
}

/// RFC 7396 JSON merge patch (`json_patch::merge`, as tauri-build applies `TAURI_CONFIG`):
/// an object patch merges key by key, `null` removes a key, anything else replaces.
pub fn merge_patch(target: &mut serde_json::Value, patch: &serde_json::Value) {
    let serde_json::Value::Object(patch) = patch else {
        *target = patch.clone();
        return;
    };
    if !target.is_object() {
        *target = serde_json::Value::Object(serde_json::Map::new());
    }
    if let serde_json::Value::Object(map) = target {
        for (key, value) in patch {
            if value.is_null() {
                map.remove(key);
            } else {
                merge_patch(map.entry(key.clone()).or_insert(serde_json::Value::Null), value);
            }
        }
    }
}

fn parse(what: &str, text: &str) -> Result<serde_json::Value, BuildChannelError> {
    serde_json::from_str(text)
        .map_err(|e| BuildChannelError::Config(format!("{what} is not JSON: {e}")))
}

/// The merged config: `base`, then the platform file, then `TAURI_CONFIG` (inline JSON, the
/// only form tauri-build accepts).
pub fn effective_config(
    base: &str,
    platform: Option<&str>,
    tauri_config: Option<&str>,
) -> Result<serde_json::Value, BuildChannelError> {
    let mut config = parse("tauri.conf.json", base)?;
    if let Some(text) = platform {
        merge_patch(&mut config, &parse("the platform config", text)?);
    }
    if let Some(text) = tauri_config.filter(|t| !t.trim().is_empty()) {
        merge_patch(&mut config, &parse("TAURI_CONFIG", text)?);
    }
    Ok(config)
}

/// The top-level `identifier` of a merged config.
pub fn identifier(config: &serde_json::Value) -> Result<String, BuildChannelError> {
    config
        .get("identifier")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| BuildChannelError::Config("no string `identifier`".to_owned()))
}

/// `MOORING_RELEASE_BUILD`: unset, empty or `0` → off, `1` → on, anything else refused.
pub fn release_flag(raw: Option<&str>) -> Result<bool, BuildChannelError> {
    match raw.map(str::trim) {
        None | Some("" | "0") => Ok(false),
        Some("1") => Ok(true),
        Some(other) => Err(BuildChannelError::Flag(other.to_owned())),
    }
}

/// Release iff both halves say so; exactly one is an error.
pub fn decide(identifier: &str, flag: bool) -> Result<BuildChannel, BuildChannelError> {
    match (identifier == RELEASE_IDENTIFIER, flag) {
        (true, true) => Ok(BuildChannel::Release),
        (false, false) => Ok(BuildChannel::Dev),
        _ => Err(BuildChannelError::Mismatch { identifier: identifier.to_owned(), flag }),
    }
}

/// The whole build-script decision: the effective identifier and the channel.
pub fn channel_of(
    base: &str,
    platform: Option<&str>,
    tauri_config: Option<&str>,
    flag: Option<&str>,
) -> Result<(String, BuildChannel), BuildChannelError> {
    let id = identifier(&effective_config(base, platform, tauri_config)?)?;
    let channel = decide(&id, release_flag(flag)?)?;
    Ok((id, channel))
}

/// `tauri.<platform>.conf.json` for a `CARGO_CFG_TARGET_OS` value (tauri-utils `Target`).
#[allow(dead_code)] // build.rs only
pub fn platform_file(target_os: &str) -> Option<&'static str> {
    match target_os {
        "macos" => Some("tauri.macos.conf.json"),
        "windows" => Some("tauri.windows.conf.json"),
        "linux" => Some("tauri.linux.conf.json"),
        "ios" => Some("tauri.ios.conf.json"),
        "android" => Some("tauri.android.conf.json"),
        _ => None,
    }
}
