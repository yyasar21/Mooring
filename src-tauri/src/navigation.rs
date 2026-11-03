//! Navigation guard for the main window (security review 2, M-4).
//!
//! The main `WebView` holds the IPC bridge, so it may only ever show the app's own origin.
//! Remote content (an OSC 8 link in terminal output, a stray `location.href`, `window.open`)
//! is refused here even if a frontend handler misses it; A2 opens remote pages in their own
//! labelled window with their own capability (ADR-0003).

use tauri::webview::NewWindowResponse;
use tauri::{App, Runtime, Url, WebviewWindowBuilder};

/// Label of the main window in `tauri.conf.json`.
pub const MAIN_WINDOW: &str = "main";

/// Whether `url` is the bundled app origin: `tauri://localhost` (macOS, Linux) or
/// `http(s)://tauri.localhost` (Windows). In development the configured `devUrl` origin is
/// allowed as well.
pub fn is_app_url(url: &Url, dev_url: Option<&Url>) -> bool {
    let host = url.host_str();
    let bundled = match url.scheme() {
        "tauri" => host == Some("localhost"),
        "http" | "https" => host == Some("tauri.localhost") && url.port().is_none(),
        _ => false,
    };
    bundled || dev_url.is_some_and(|dev| same_origin(url, dev))
}

fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

/// Build the main window from its config entry (`"create": false` there) with the guard:
/// navigations outside the app origin are cancelled and new windows are denied.
pub fn create_main_window<R: Runtime>(app: &App<R>) -> tauri::Result<()> {
    let config = app
        .config()
        .app
        .windows
        .iter()
        .find(|w| w.label == MAIN_WINDOW)
        .cloned()
        .ok_or_else(|| tauri::Error::WindowNotFound)?;
    let dev_url = if cfg!(dev) { app.config().build.dev_url.clone() } else { None };
    WebviewWindowBuilder::from_config(app.handle(), &config)?
        .on_navigation(move |url| {
            let allowed = is_app_url(url, dev_url.as_ref());
            if !allowed {
                // Only the scheme: a URL from remote output may carry tokens.
                tracing::warn!(scheme = url.scheme(), "main window navigation blocked");
            }
            allowed
        })
        .on_new_window(|url, _| {
            tracing::warn!(scheme = url.scheme(), "main window new-window request denied");
            NewWindowResponse::Deny
        })
        .build()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).expect("url")
    }

    #[test]
    fn app_origin_is_allowed() {
        for ok in [
            "tauri://localhost",
            "tauri://localhost/index.html#/vault",
            "http://tauri.localhost/",
            "https://tauri.localhost/index.html",
        ] {
            assert!(is_app_url(&u(ok), None), "{ok}");
        }
    }

    #[test]
    fn remote_and_lookalike_urls_are_denied() {
        for bad in [
            "https://example.com",
            "http://localhost:1420/",
            "https://tauri.localhost.evil.example/",
            "http://tauri.localhost:8080/",
            "tauri://evil",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,hi",
            "about:blank",
            "ssh://host",
        ] {
            assert!(!is_app_url(&u(bad), None), "{bad}");
        }
    }

    #[test]
    fn dev_url_origin_only_when_configured() {
        let dev = u("http://localhost:1420");
        assert!(is_app_url(&u("http://localhost:1420/src/main.tsx"), Some(&dev)));
        assert!(!is_app_url(&u("http://localhost:1421/"), Some(&dev)));
        assert!(!is_app_url(&u("https://localhost:1420/"), Some(&dev)));
        assert!(!is_app_url(&u("https://example.com/"), Some(&dev)));
    }
}
