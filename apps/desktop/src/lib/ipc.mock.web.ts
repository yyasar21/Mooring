// Mock web-session windows (ADR-0013), plus the audit commands. In the browser there is no second
// window: web_open only records the window and replays the events a real WebviewWindow sends
// (navigated, title, and with `webDemo` a refused navigation and a refused download).
// Methods stay `async` to mirror the IPC signature even when they do not await.
/* eslint-disable @typescript-eslint/require-await */
import type { Ipc, RemoteIpc, SessionEventHandler, WebConnOptions, WebEvent, WebEventHandler, WebWindowInfo } from "./ipc.types";
import { WEB_ZOOM } from "./ipc.types.remote";
import { IpcError } from "./ipc.error";
import { MockRemoteBase, type RemoteTarget } from "./ipc.mock.remote";
import type { MockHop, MockHopChain } from "./ipc.mock.hops";

/** R6 `web::via::supported` on macOS (the `macos-proxy` feature is off in this build). */
export const WEB_VIA_MACOS_TEXT = "web pages through jump hosts need macOS 14 and a build with proxy support";
/** R6 `open_chain`: the first hop question shuts the chain (nothing is trusted for the user). */
export const webHopAskText = (n: number) =>
  `jump host ${String(n)} asked a question a web window cannot answer (an unknown host key or a password); open it once as an SSH session, then try again`;

interface MockWebWindow {
  info: WebWindowInfo;
  emit: WebEventHandler;
  zoom: number;
}

export abstract class MockWebBase extends MockRemoteBase {
  web = new Map<string, MockWebWindow>();
  /** Browser demo: after opening, the page tries an SSO origin outside the allow-list and a download. */
  webDemo = false;

  /** R6: false = this "build" refuses web windows through jump hosts (`web.via_unsupported`, macOS). */
  webViaSupported = true;
  /** R6: how long `web_open` takes per jump host (the real chain may take up to 90 s). */
  webViaDelayMs = 0;

  /** The connection behind an id (throws `tree.not_found`). */
  protected abstract target(connectionId: string): RemoteTarget;
  /** ADR-0025: the resolved jump hosts of a connection, first hop first. */
  protected abstract viaHopsOf(connectionId: string): MockHop[];
  /** ADR-0025: a host key the mock already trusts (an SSH session to it was opened). */
  protected abstract hopTrusted(host: string): boolean;
  /** ADR-0025: an interactive chain for a session channel (null = direct). */
  protected abstract hopChainOf(connectionId: string, emit: SessionEventHandler, done: () => void, fail: (reason: string) => void): MockHopChain | null;

  /** R6 `web::via`: the chain opens unattended before the window; any hop question fails the open. */
  private async openVia(connectionId: string): Promise<number | undefined> {
    const hops = this.viaHopsOf(connectionId);
    if (hops.length === 0) return undefined;
    if (!this.webViaSupported) throw new IpcError("web.via_unsupported", WEB_VIA_MACOS_TEXT);
    if (this.webViaDelayMs > 0) await new Promise((r) => setTimeout(r, this.webViaDelayMs * hops.length));
    hops.forEach((h, i) => {
      if (h.fail || h.ask || !this.hopTrusted(h.host)) {
        this.record("session_hop_close", { connection: connectionId, hop: String(i), code: "hop_failed", protocol: "web" });
        throw new IpcError("session.hop_failed", h.fail ? `jump host ${String(i + 1)} refused the sign-in` : webHopAskText(i + 1));
      }
      this.record("session_hop_open", { connection: connectionId, hop: String(i), hop_connection: h.connectionId, protocol: "web" });
    });
    this.record("forward_opened", { id: "web-via", kind: "dynamic", target: "socks5", exposure: "loopback", reason: "web_via" });
    return hops.length;
  }

  private closeVia(w: MockWebWindow): void {
    if (w.info.viaHops) this.record("forward_closed", { id: "web-via", kind: "dynamic", reason: "web_via" });
  }

  /**
   * Tests: the web-via SOCKS proxy refused a CONNECT outside the start host and the allowed
   * origins (L-48). Rust audits it as `forward_refused` before any traffic reaches the hop.
   */
  webViaRefuse(connectionId: string, target: string): void {
    const w = this.web.get(connectionId);
    if (!w?.info.viaHops) return;
    this.record("forward_refused", { connection: connectionId, id: "web-via", target });
  }

  /** Tests: what the native callbacks of an open window would report (`blocked`, `title`, ...). */
  webSimulate(connectionId: string, event: WebEvent): void {
    const w = this.web.get(connectionId);
    if (!w) return;
    if (event.kind === "navigated") w.info.origin = event.origin;
    if (event.kind === "title") w.info.title = event.title;
    if (event.kind === "blocked") this.record("web_navigation_blocked", { connection: connectionId, origin: event.origin });
    if (event.kind === "download_blocked") this.record("web_download_blocked", { connection: connectionId, origin: event.origin });
    if (event.kind === "closed") {
      // the user closed the window natively
      this.web.delete(connectionId);
      this.closeVia(w);
      this.record("web_closed", { connection: connectionId });
    }
    w.emit(event);
  }

  private window(connectionId: string): MockWebWindow {
    const w = this.web.get(connectionId);
    if (!w) throw new IpcError("session.not_found", "no web window is open for this connection");
    return w;
  }

  webOpen: RemoteIpc["webOpen"] = async ({ connectionId, onEvent }) => {
    await this.unlocked();
    const t = this.target(connectionId);
    if (t.protocol !== "web") throw new IpcError("input.invalid", "invalid connectionId: not a web connection");
    const open = this.web.get(connectionId);
    if (open) {
      open.emit = onEvent; // opening again focuses the window; events move to the new channel
      return { windowLabel: open.info.windowLabel, ...(open.info.viaHops ? { viaHops: open.info.viaHops } : {}) };
    }
    const opts = t.options as Partial<WebConnOptions> | undefined;
    const url = opts?.url ?? (t.host.includes("://") ? t.host : `https://${t.host}`);
    let origin: string;
    try {
      origin = new URL(url).origin;
    } catch {
      throw new IpcError("input.invalid", "invalid url");
    }
    const viaHops = await this.openVia(connectionId);
    const info: WebWindowInfo = {
      connectionId,
      windowLabel: `web-${connectionId}`,
      origin,
      title: "",
      persistent: opts?.persistent === true,
      openedAt: new Date().toISOString(),
      ...(viaHops ? { viaHops } : {}),
    };
    this.web.set(connectionId, { info, emit: onEvent, zoom: 1 });
    this.record("web_opened", { connection: connectionId, origin, persistent: String(info.persistent) });
    this.later(() => {
      this.webSimulate(connectionId, { kind: "navigated", origin });
      this.webSimulate(connectionId, { kind: "title", title: `${t.name} console` });
    });
    if (this.webDemo) {
      setTimeout(() => { this.webSimulate(connectionId, { kind: "blocked", origin: "https://sso.example.test" }); }, 1500);
      setTimeout(() => { this.webSimulate(connectionId, { kind: "download_blocked", origin }); }, 2500);
    }
    return { windowLabel: info.windowLabel, ...(viaHops ? { viaHops } : {}) };
  };

  webClose: RemoteIpc["webClose"] = async ({ connectionId }) => {
    const w = this.window(connectionId);
    this.web.delete(connectionId);
    this.closeVia(w);
    this.record("web_closed", { connection: connectionId });
    this.later(() => { w.emit({ kind: "closed" }); });
  };

  webFocus: RemoteIpc["webFocus"] = async ({ connectionId }) => {
    await this.unlocked(); // the window stays hidden while locked
    this.window(connectionId);
  };

  webReload: RemoteIpc["webReload"] = async ({ connectionId }) => {
    const w = this.window(connectionId);
    this.later(() => { w.emit({ kind: "navigated", origin: w.info.origin }); });
  };

  webPrint: RemoteIpc["webPrint"] = async ({ connectionId }) => {
    await this.unlocked();
    this.window(connectionId);
  };

  webClearData: RemoteIpc["webClearData"] = async ({ connectionId }) => {
    await this.unlocked();
    this.target(connectionId);
    this.record("web_data_cleared", { connection: connectionId });
  };

  webZoom: RemoteIpc["webZoom"] = async ({ connectionId, factor }) => {
    const w = this.window(connectionId);
    if (!Number.isFinite(factor) || factor < WEB_ZOOM.min || factor > WEB_ZOOM.max) throw new IpcError("input.invalid", "invalid factor: 0.25 to 5");
    w.zoom = factor;
  };

  webList: RemoteIpc["webList"] = async () => [...this.web.values()].map((w) => ({ ...w.info }));

  // ---------- audit ----------

  auditTail: Ipc["auditTail"] = async ({ limit, before }) => {
    const capped = Math.max(1, Math.min(limit, 500));
    return this.audit
      .filter((e) => before === null || e.seq < before)
      .slice()
      .reverse()
      .slice(0, capped)
      .map((e) => ({ ...e, details: { ...e.details } }));
  };

  auditVerify: Ipc["auditVerify"] = async () => ({ ok: true, entries: this.audit.length, brokenAt: null });
}
