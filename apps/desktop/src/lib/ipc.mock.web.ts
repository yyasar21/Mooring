// Mock web-session windows (ADR-0013), plus the audit commands. In the browser there is no second
// window: web_open only records the window and replays the events a real WebviewWindow sends
// (navigated, title, and with `webDemo` a refused navigation and a refused download).
// Methods stay `async` to mirror the IPC signature even when they do not await.
/* eslint-disable @typescript-eslint/require-await */
import type { Ipc, RemoteIpc, WebConnOptions, WebEvent, WebEventHandler, WebWindowInfo } from "./ipc.types";
import { WEB_ZOOM } from "./ipc.types.remote";
import { IpcError } from "./ipc.error";
import { MockRemoteBase, type RemoteTarget } from "./ipc.mock.remote";

interface MockWebWindow {
  info: WebWindowInfo;
  emit: WebEventHandler;
  zoom: number;
}

export abstract class MockWebBase extends MockRemoteBase {
  web = new Map<string, MockWebWindow>();
  /** Browser demo: after opening, the page tries an SSO origin outside the allow-list and a download. */
  webDemo = false;

  /** The connection behind an id (throws `tree.not_found`). */
  protected abstract target(connectionId: string): RemoteTarget;

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
      return { windowLabel: open.info.windowLabel };
    }
    const opts = t.options as Partial<WebConnOptions> | undefined;
    const url = opts?.url ?? (t.host.includes("://") ? t.host : `https://${t.host}`);
    let origin: string;
    try {
      origin = new URL(url).origin;
    } catch {
      throw new IpcError("input.invalid", "invalid url");
    }
    const info: WebWindowInfo = {
      connectionId,
      windowLabel: `web-${connectionId}`,
      origin,
      title: "",
      persistent: opts?.persistent === true,
      openedAt: new Date().toISOString(),
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
    return { windowLabel: info.windowLabel };
  };

  webClose: RemoteIpc["webClose"] = async ({ connectionId }) => {
    const w = this.window(connectionId);
    this.web.delete(connectionId);
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
