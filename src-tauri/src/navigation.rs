//! Navigation guard for the main and detached windows (security review 2, M-4; ADR-0013).
//!
//! The main `WebView` holds the IPC bridge, so it may only ever show the app's own origin.
//! Remote content (an OSC 8 link in terminal output, a stray `location.href`, `window.open`)
//! is refused here even if a frontend handler misses it; A2 opens remote pages in their own
//! labelled window with their own capability (ADR-0003).

use tauri::webview::NewWindowResponse;
use tauri::{App, AppHandle, Runtime, Url, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

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
/// navigations outside the app origin are cancelled and new windows are denied. `data_dir`
/// (ADR-0021, portable mode on Windows / Linux) relocates the `WebView` profile that would
/// otherwise land in `%LOCALAPPDATA%` / `$XDG_DATA_HOME`; the caller passes `None` on macOS
/// (`WKWebView` has no such knob).
pub fn create_main_window<R: Runtime>(
    app: &App<R>,
    data_dir: Option<std::path::PathBuf>,
) -> tauri::Result<()> {
    let config = app
        .config()
        .app
        .windows
        .iter()
        .find(|w| w.label == MAIN_WINDOW)
        .cloned()
        .ok_or_else(|| tauri::Error::WindowNotFound)?;
    let dev_url = if cfg!(dev) { app.config().build.dev_url.clone() } else { None };
    let mut builder = WebviewWindowBuilder::from_config(app.handle(), &config)?;
    if let Some(dir) = data_dir {
        builder = builder.data_directory(dir);
    }
    builder
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

/// The bundled-UI route of a detached session window (ADR-0013): `#/detached/<sessionId>`.
pub fn detached_route(session_id: &str) -> String {
    format!("index.html#/detached/{session_id}")
}

/// Build `detached-<sessionId>` on the bundled UI with the same guard as `main` (app origin
/// only, no new windows), the same CSP (it applies to every app page) and no devtools.
pub fn create_detached_window<R: Runtime>(
    app: &AppHandle<R>,
    label: &str,
    session_id: &str,
) -> tauri::Result<WebviewWindow<R>> {
    let dev_url = if cfg!(dev) { app.config().build.dev_url.clone() } else { None };
    WebviewWindowBuilder::new(app, label, WebviewUrl::App(detached_route(session_id).into()))
        .title("Mooring \u{b7} session")
        .inner_size(1100.0, 720.0)
        .min_inner_size(480.0, 320.0)
        .devtools(false)
        .on_navigation(move |url| {
            let allowed = is_app_url(url, dev_url.as_ref());
            if !allowed {
                tracing::warn!(scheme = url.scheme(), "detached window navigation blocked");
            }
            allowed
        })
        .on_new_window(|url, _| {
            tracing::warn!(scheme = url.scheme(), "detached window new-window request denied");
            NewWindowResponse::Deny
        })
        .build()
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
