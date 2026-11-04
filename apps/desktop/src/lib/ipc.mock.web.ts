// Mock web-session windows and session attach (ADR-0013), plus the audit commands. In the browser
// there is no second window: web_open only records the window and replays the events a real
// WebviewWindow would send, so U3 can be built against it.
// Methods stay `async` to mirror the IPC signature even when they do not await.
/* eslint-disable @typescript-eslint/require-await */
import type { AttachedSession, Ipc, RemoteIpc, SessionEventHandler, WebConnOptions, WebEventHandler, WebWindowInfo } from "./ipc.types";
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

  /** The connection behind an id (throws `tree.not_found`). */
  protected abstract target(connectionId: string): RemoteTarget;
  /** `session_attach` for a non-remote (SSH) session; null when there is no such session. */
  protected abstract attachOther(sessionId: string, onEvent: SessionEventHandler): AttachedSession | null;

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
    if (open) return { windowLabel: open.info.windowLabel };
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
      onEvent({ kind: "navigated", origin });
      info.title = `${t.name} console`;
      onEvent({ kind: "title", title: info.title });
    });
    return { windowLabel: info.windowLabel };
  };

  webClose: RemoteIpc["webClose"] = async ({ connectionId }) => {
    const w = this.window(connectionId);
    this.web.delete(connectionId);
    this.record("web_closed", { connection: connectionId });
    this.later(() => { w.emit({ kind: "closed" }); });
  };

  webFocus: RemoteIpc["webFocus"] = async ({ connectionId }) => {
    this.window(connectionId);
  };

  webReload: RemoteIpc["webReload"] = async ({ connectionId }) => {
    const w = this.window(connectionId);
    this.later(() => { w.emit({ kind: "navigated", origin: w.info.origin }); });
  };

  webPrint: RemoteIpc["webPrint"] = async ({ connectionId }) => {
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

  windowAttach: RemoteIpc["windowAttach"] = async ({ sessionId }) => {
    if (!this.remote.has(sessionId) && !this.attachOther(sessionId, () => undefined)) throw new IpcError("session.not_found", "session not found");
    this.record("session_attached", { session: sessionId });
  };

  /** The attaching view takes over both sinks; the old view gets `detached`; one full frame is resent. */
  sessionAttach: RemoteIpc["sessionAttach"] = async ({ sessionId, onEvent, onFrame }) => {
    const s = this.remote.get(sessionId);
    if (!s) {
      const other = this.attachOther(sessionId, onEvent);
      if (!other) throw new IpcError("session.not_found", "session not found");
      return other;
    }
    if (!onFrame) throw new IpcError("input.invalid", "invalid onFrame: required for rdp and vnc sessions");
    const old = s.emit;
    s.emit = onEvent;
    s.onFrame = onFrame;
    s.inFlight = 0;
    s.desktop.resize(s.desktop.width, s.desktop.height);
    this.later(() => { old({ kind: "detached" }); });
    return { protocol: s.info.protocol, state: s.info.state, size: { width: s.desktop.width, height: s.desktop.height } };
  };

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
