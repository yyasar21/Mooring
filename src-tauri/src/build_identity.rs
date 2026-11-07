//! Build identity (ADR-0028 §1): the release / dev channel this binary was compiled as, and
//! the start-up cross-check against the identifier Tauri runs with.
//!
//! `build.rs` emits `cfg(mooring_release)` only when the effective identifier is the release
//! one **and** `MOORING_RELEASE_BUILD=1` (see `build_channel.rs`). At setup the runtime
//! identifier (`app.config().identifier`) must agree with that channel; a stale build cache or
//! a hand-edited generated config is refused with `app.build_identity` (native box, exit 2, no
//! window). Everything identity-scoped follows the identifier without extra code: Tauri's
//! `app_data_dir` / `app_cache_dir` are `<os dir>/<identifier>`, `WKWebView` storage is
//! `~/Library/WebKit/<identifier>`, `WebView2` `%LOCALAPPDATA%\<identifier>`.

use serde::Serialize;

use crate::startup::Refusal;

/// The release identifier (`tauri.release.conf.json`).
pub const RELEASE_IDENTIFIER: &str = "io.github.yyasar21.mooring";
/// The identifier `build.rs` derived for this compilation (base config + `TAURI_CONFIG`).
pub const EFFECTIVE_IDENTIFIER: &str = env!("MOORING_EFFECTIVE_IDENTIFIER");

/// Release or development build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    /// Tag builds from `release.yml` (release identifier, signed updates).
    Release,
    /// Every other build ("Mooring Dev", own data, no updater).
    Dev,
}

impl Channel {
    /// The channel this binary was compiled as.
    pub const CURRENT: Self = if cfg!(mooring_release) { Self::Release } else { Self::Dev };

    /// `app_info.channel`: `"release"` | `"dev"`.
    pub fn wire(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::Dev => "dev",
        }
    }

    /// The channel an identifier belongs to: the release id is release, anything else dev.
    pub fn of_identifier(identifier: &str) -> Self {
        if identifier == RELEASE_IDENTIFIER {
            Self::Release
        } else {
            Self::Dev
        }
    }

    /// Whether this is a development build.
    pub fn is_dev(self) -> bool {
        self == Self::Dev
    }
}

/// `app.build_identity` when the runtime identifier disagrees with the compiled channel.
pub fn check(channel: Channel, identifier: &str) -> Result<(), Refusal> {
    if Channel::of_identifier(identifier) == channel {
        return Ok(());
    }
    let built = match channel {
        Channel::Release => "a release build",
        Channel::Dev => "a development build",
    };
    Err(Refusal {
        code: "app.build_identity",
        message: format!(
            "This copy of Mooring was compiled as {built} but runs with the identifier \
             {identifier}. Rebuild it from a clean tree (cargo clean) or install a release."
        ),
    })
}

#[cfg(test)]
#[path = "build_identity_tests.rs"]
mod tests;
