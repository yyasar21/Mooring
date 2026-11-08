//! The Tauri side of a web window (ADR-0013 builder settings). Nothing here is reachable
//! from the page: every callback is native and the window's capability is empty.
//!
//! Per OS (Tauri 2.12.5 / wry 0.57.1):
//! * permission requests (camera, microphone, geolocation, notifications, clipboard read,
//!   MIDI): `Deny` through `WebView2` `PermissionRequested` (Windows), `WKUIDelegate` media
//!   capture (macOS; other kinds are not offered by `WKWebView`) and `WebKitGTK`
//!   `permission-request` (Linux).
//! * downloads: refused in `on_download` (`Requested` → `false`) on all three.
//! * new windows (`window.open`, `target=_blank`): always `Deny`; an allowed URL is opened in
//!   the same window instead.
//! * devtools: off; zoom hotkeys off (the macOS/Linux polyfill would need an IPC permission);
//!   Windows general autofill off (a no-op elsewhere).
//! * WebRTC (review 9 L-47): `WebView2` gets [`webview2_args`] on every web window, so WebRTC
//!   never sends UDP outside the proxy (`disable_non_proxied_udp`: no STUN, no host
//!   candidates; TCP through the SOCKS forward only) and, behind jump hosts, loopback is not
//!   exempt from the proxy (`<-loopback>`). `WebKitGTK` ships `enable-webrtc` off and wry
//!   0.57.1 never turns it on, so Linux pages have no `RTCPeerConnection` at all; macOS
//!   refuses web-via (`web.via_unsupported`).

use std::sync::{Arc, Mutex};

use mooring_audit::{AuditEvent, AuditLog};
use tauri::webview::{DownloadEvent, NewWindowResponse, PageLoadEvent, PermissionResponse};
use tauri::{AppHandle, Manager, Runtime, Url, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

use super::policy::{display_origin, Nav, NavPolicy};
use super::{native_title, sanitize_title, Storage, WebPlan, WebRegistry, WebSink};
use crate::state::record_audit;

/// Best effort only (the empty capability is the boundary): uploads are denied by policy, so
/// file inputs, `showPicker()` on them, file drops onto them and the File System Access
/// pickers do nothing (R-WEB-UPLOAD, review 5 N-32). Installed in every frame.
pub const INIT_SCRIPT: &str = r"(() => {
  const deny = () => Promise.reject(new DOMException('Uploads are disabled', 'NotAllowedError'));
  for (const name of ['showOpenFilePicker', 'showSaveFilePicker', 'showDirectoryPicker']) {
    try { Object.defineProperty(window, name, { value: deny, configurable: false }); } catch (_) {}
  }
  const isFile = (t) => t instanceof HTMLInputElement && t.type === 'file';
  try {
    const proto = HTMLInputElement.prototype;
    const showPicker = proto.showPicker;
    Object.defineProperty(proto, 'showPicker', { configurable: false, value: function () {
      if (isFile(this)) { throw new DOMException('Uploads are disabled', 'NotAllowedError'); }
      return showPicker ? showPicker.apply(this, arguments) : undefined;
    } });
  } catch (_) {}
  const stop = (e) => { e.preventDefault(); e.stopImmediatePropagation(); };
  document.addEventListener('click', (e) => { if (isFile(e.target)) stop(e); }, true);
  document.addEventListener('drop', (e) => { if (isFile(e.target)) stop(e); }, true);
})();";

/// What the callbacks share.
#[derive(Clone)]
struct Ctx {
    connection: String,
    name: String,
    policy: Arc<NavPolicy>,
    audit: Arc<Mutex<AuditLog>>,
    registry: WebRegistry,
    sink: WebSink,
}

impl Ctx {
    /// A refused navigation: audited and sent to the UI for the window's first 16 refusals,
    /// counted afterwards (N-43; the close writes the summary row).
    fn blocked(&self, origin: String) {
        if !super::refusal_audited(&self.registry, &self.connection) {
            tracing::debug!(origin = %origin, "web navigation blocked (counted)");
            return;
        }
        tracing::info!(origin = %origin, "web navigation blocked");
        record_audit(&self.audit, AuditEvent::WebNavigationBlocked {
            connection: self.connection.clone(),
            origin: origin.clone(),
        });
        (self.sink())(super::WebEvent::Blocked { origin });
    }

    fn update(&self, f: impl FnOnce(&mut super::WebEntry)) {
        if let Ok(mut map) = self.registry.lock() {
            if let Some(e) = map.get_mut(&self.connection) {
                f(e);
            }
        }
    }

    /// The registry's current sink (a re-open replaces it).
    fn sink(&self) -> WebSink {
        self.registry
            .lock()
            .ok()
            .and_then(|m| m.get(&self.connection).map(|e| Arc::clone(&e.sink)))
            .unwrap_or_else(|| Arc::clone(&self.sink))
    }
}

/// wry's own `WebView2` defaults; passing any browser arguments replaces them.
const WEBVIEW2_DEFAULT_ARGS: &str = "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection";

/// The `WebView2` browser arguments of a web window (review 9 L-47). Setting them replaces
/// wry's argument string, which is also where wry would put `--proxy-server`, so the proxy of
/// a web-via window is passed here too (fail closed: the builder still sets `proxy_url`).
/// No effect on macOS / Linux.
pub fn webview2_args(proxy: Option<&Url>) -> String {
    let mut args = format!(
        "{WEBVIEW2_DEFAULT_ARGS} --force-webrtc-ip-handling-policy=disable_non_proxied_udp"
    );
    if let Some(p) = proxy {
        if let (Some(host), Some(port)) = (p.host_str(), p.port()) {
            let scheme = p.scheme();
            args = format!(
                "{args} --proxy-server={scheme}://{host}:{port} --proxy-bypass-list=<-loopback>"
            );
        }
    }
    args
}

/// Build the window of `plan`. `sink` receives the `WebEvent`s; the caller registers the
/// entry right after (the callbacks look it up by connection id).
pub fn build<R: Runtime>(
    app: &AppHandle<R>,
    plan: &WebPlan,
    audit: Arc<Mutex<AuditLog>>,
    registry: WebRegistry,
    sink: WebSink,
) -> tauri::Result<WebviewWindow<R>> {
    let ctx = Ctx {
        connection: plan.connection_id.clone(),
        name: plan.name.clone(),
        policy: Arc::new(plan.policy.clone()),
        audit,
        registry,
        sink,
    };
    let mut builder =
        WebviewWindowBuilder::new(app, &plan.label, WebviewUrl::External(plan.url.clone()))
            .title(native_title(&plan.name, &plan.origin()))
            .inner_size(1280.0, 800.0)
            .devtools(false)
            .zoom_hotkeys_enabled(false)
            .general_autofill_enabled(false)
            .additional_browser_args(&webview2_args(plan.proxy.as_ref()))
            .initialization_script_for_all_frames(INIT_SCRIPT);
    builder = match &plan.storage {
        Storage::Ephemeral => builder.incognito(true),
        // L-29: an own WebView2 environment per ephemeral window, InPrivate inside it.
        Storage::EphemeralDirectory(dir) => builder.incognito(true).data_directory(dir.clone()),
        Storage::Directory(dir) => builder.data_directory(dir.clone()),
        Storage::Identifier(id) => builder.data_store_identifier(*id),
    };
    // ADR-0025 §3: every request of the page goes through the chain's SOCKS forward.
    if let Some(proxy) = &plan.proxy {
        builder = builder.proxy_url(proxy.clone());
    } else if plan.via {
        // Fail closed: a chain without its forward never yields a direct window.
        return Err(tauri::Error::InvalidWebviewUrl("web window with jump hosts but no proxy"));
    }
    let nav = ctx.clone();
    let popup = ctx.clone();
    let download = ctx.clone();
    let title = ctx.clone();
    let load = ctx.clone();
    let app_for_popup = app.clone();
    let label = plan.label.clone();
    let window = builder
        .on_navigation(move |url| match nav.policy.decide(url) {
            Nav::Allow => true,
            Nav::Block { origin } => {
                nav.blocked(origin);
                false
            }
        })
        .on_new_window(move |url, _features| {
            match popup.policy.decide(&url) {
                Nav::Allow => navigate_later(&app_for_popup, &label, url),
                Nav::Block { origin } => popup.blocked(origin),
            }
            NewWindowResponse::Deny
        })
        .on_download(move |_webview, event| {
            if let DownloadEvent::Requested { url, .. } = event {
                let origin = display_origin(&url);
                record_audit(&download.audit, AuditEvent::WebDownloadBlocked {
                    connection: download.connection.clone(),
                    origin: origin.clone(),
                });
                (download.sink())(super::WebEvent::DownloadBlocked { origin });
            }
            false
        })
        .on_permission_request(|_webview, kind| {
            tracing::info!(?kind, "web permission request denied");
            PermissionResponse::Deny
        })
        .on_document_title_changed(move |window, raw| {
            let clean = sanitize_title(&raw);
            let origin = window.url().map(|u| display_origin(&u)).unwrap_or_default();
            let _ = window.set_title(&native_title(&title.name, &origin));
            title.update(|e| e.title.clone_from(&clean));
            (title.sink())(super::WebEvent::Title { title: clean });
        })
        .on_page_load(move |window, payload| {
            if payload.event() != PageLoadEvent::Finished {
                return;
            }
            let origin = display_origin(payload.url());
            let _ = window.set_title(&native_title(&load.name, &origin));
            load.update(|e| e.origin.clone_from(&origin));
            (load.sink())(super::WebEvent::Navigated { origin });
        })
        .build()?;
    Ok(window)
}

/// Load `url` in the window `label` (an allowed `window.open` target), off the callback.
fn navigate_later<R: Runtime>(app: &AppHandle<R>, label: &str, url: Url) {
    let Some(window) = app.get_webview_window(label) else { return };
    tauri::async_runtime::spawn(async move {
        if let Err(e) = window.navigate(url) {
            tracing::warn!(error = %e, "web navigate failed");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webview2_args_keep_webrtc_on_the_proxy_and_wry_defaults() {
        let plain = webview2_args(None);
        assert!(plain.starts_with(WEBVIEW2_DEFAULT_ARGS), "{plain}");
        assert!(plain.contains("--force-webrtc-ip-handling-policy=disable_non_proxied_udp"));
        assert!(!plain.contains("--proxy-server"));
        let proxy = Url::parse("socks5://127.0.0.1:41234").expect("url");
        let via = webview2_args(Some(&proxy));
        assert!(via.contains("--force-webrtc-ip-handling-policy=disable_non_proxied_udp"));
        assert!(via.contains(" --proxy-server=socks5://127.0.0.1:41234"), "{via}");
        assert!(via.ends_with(" --proxy-bypass-list=<-loopback>"), "{via}");
    }
}
