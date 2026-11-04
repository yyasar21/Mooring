//! Navigation guard of a web window (ADR-0013 §Navigation guard and origin allow-list).
//!
//! A top-level navigation is allowed only to an exact origin (`scheme://host[:port]`, as
//! serialised by the WHATWG URL parser: lowercase, IDN as punycode, default port dropped) in
//! {origin of `url`} ∪ `allowedOrigins`. The app origin, every non-http(s) scheme (`file:`,
//! `data:`, `javascript:`, `blob:`, `about:`, `tauri:`, `ipc:` ...) and URLs that carry
//! credentials (`user:pass@`) are always refused, even when listed.

use mooring_core::options::WebConnOptions;
use tauri::Url;

use crate::error::{IpcError, IpcResult};
use crate::navigation::is_app_url;

/// What to do with a top-level navigation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Nav {
    /// Load it.
    Allow,
    /// Refuse it; `origin` is what the UI and the audit log may show (never a path).
    Block {
        /// `scheme://host[:port]`, or `scheme:` for URLs without a host.
        origin: String,
    },
}

/// The allow-list of one web connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavPolicy {
    allowed: Vec<String>,
    dev_url: Option<Url>,
}

/// The origin of `url` as shown to the user: `scheme://host[:port]`, or `scheme:` when the
/// URL has no tuple origin (`data:`, `javascript:`, `file:` ...).
pub fn display_origin(url: &Url) -> String {
    let origin = url.origin();
    if origin.is_tuple() {
        origin.ascii_serialization()
    } else {
        format!("{}:", url.scheme())
    }
}

/// Exact origin of an `http(s)` URL without credentials, else `None`.
fn tuple_origin(url: &Url) -> Option<String> {
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    let origin = url.origin();
    origin.is_tuple().then(|| origin.ascii_serialization())
}

impl NavPolicy {
    /// The policy of validated options. `dev_url` is the app's dev server in a dev build (it is
    /// app origin too). Fails with `web.origin_refused` when the start URL itself is refused
    /// (app origin), `input.invalid` when the options do not validate.
    pub fn from_options(opts: &WebConnOptions, dev_url: Option<Url>) -> IpcResult<(Self, Url)> {
        opts.validate().map_err(IpcError::from)?;
        let start = Url::parse(&opts.url).map_err(|_| IpcError::invalid("url", "not a URL"))?;
        let parse = |raw: &str| {
            Url::parse(raw)
                .ok()
                .and_then(|u| tuple_origin(&u))
                .ok_or_else(|| IpcError::invalid("allowedOrigins", "not an http(s) origin"))
        };
        let mut allowed = vec![parse(&opts.url)?];
        for o in &opts.allowed_origins {
            let o = parse(o)?;
            if !allowed.contains(&o) {
                allowed.push(o);
            }
        }
        let policy = Self { allowed, dev_url };
        if policy.decide(&start) != Nav::Allow {
            return Err(IpcError::new("web.origin_refused", "this address cannot be opened"));
        }
        Ok((policy, start))
    }

    /// The allowed origins, the start origin first.
    pub fn allowed(&self) -> &[String] {
        &self.allowed
    }

    /// Decide a top-level navigation.
    pub fn decide(&self, url: &Url) -> Nav {
        let block = || Nav::Block { origin: display_origin(url) };
        if is_app_url(url, self.dev_url.as_ref()) {
            return block();
        }
        // Review 5 N-31: every Tauri custom protocol is served at `<scheme>.localhost` on
        // Windows (RFC 6761 zone); plain `localhost` is an ordinary host.
        if url.host_str().is_some_and(mooring_core::options::is_localhost_subdomain) {
            return block();
        }
        match tuple_origin(url) {
            Some(origin) if self.allowed.contains(&origin) => Nav::Allow,
            _ => block(),
        }
    }
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
