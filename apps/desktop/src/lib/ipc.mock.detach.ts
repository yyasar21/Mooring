// Mock detach / attach (ADR-0013, R5 `route.rs`) and the detached window's command ACL.
// Each session has a route: which view holds its sinks (`main` or `detached`). `session_attach`
// moves both sinks to the calling view and tells the view that lost them (`detached`); credits
// reset and the next frame is full. `window_attach` moves the session back to `main`, which gets
// `attached`. While detached, `closed` reaches `main` too.
//
// The browser has no second window, so `window_detach` simulates one (`phantomDetach`): a view that
// takes the sinks, acks every frame and shows nothing. Tests that drive a real detached view use
// `viewOf(sessionId)`, which enforces the `detached-*` capability: only the six session commands,
// only for its own session id; anything else is `ipc.forbidden`.
// Methods stay `async` to mirror the IPC signature even when they do not await.
/* eslint-disable @typescript-eslint/require-await */
import type { AttachedSession, FrameHandler, Ipc, Protocol, RemoteIpc, SessionEventHandler, SessionInfo, Size } from "./ipc.types";
import { IpcError } from "./ipc.error";
import { peekSeq } from "./frame/mfr1";
import { MockWebBase } from "./ipc.mock.web";

/** `capabilities/detached.json`: the only commands a `detached-<sessionId>` window may call. */
export const DETACHED_COMMANDS = [
  "session_attach",
  "session_send",
  "session_close",
  "session_frame_ack",
  "session_screenshot",
  "window_attach",
] as const;

/** `sessionFrameAck` → `session_frame_ack` (the TauriTransport naming rule). */
export const commandName = (method: string): string => method.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);

interface Sink {
  emit: SessionEventHandler;
  onFrame?: FrameHandler | undefined;
}

type View = "main" | "detached";

interface Route {
  holder: View;
  main: Sink;
  detached: Sink | null;
}

/** What attaching needs from a live mock session (SSH or remote). */
interface Attachable {
  sink: Sink;
  graphical: boolean;
  protocol: Protocol;
  state: string;
  size: Size;
  refresh: () => void;
}

export abstract class MockDetachBase extends MockWebBase {
  /** Session ids passed to `window_detach`, in order. */
  detached: string[] = [];
  routes = new Map<string, Route>();
  /** Commands a detached view tried and was refused (`ipc.forbidden`). */
  forbidden: string[] = [];
  /** Simulate the detached window's `session_attach` after `window_detach` (browser and store tests). */
  phantomDetach = true;

  /** The SSH session behind an id, or null. */
  protected abstract sshSession(sessionId: string): { emit: SessionEventHandler; info: SessionInfo } | null;

  private attachable(sessionId: string): Attachable | null {
    const r = this.remote.get(sessionId);
    if (r) {
      return {
        sink: r, graphical: true, protocol: r.info.protocol, state: r.info.state,
        size: { width: r.desktop.width, height: r.desktop.height },
        refresh: () => {
          r.inFlight = 0;
          r.desktop.resize(r.desktop.width, r.desktop.height); // next frame is full
        },
      };
    }
    const s = this.sshSession(sessionId);
    // R5: an SSH attach reports 0×0; the view sends its own resize.
    return s ? { sink: s, graphical: false, protocol: s.info.protocol, state: s.info.state, size: { width: 0, height: 0 }, refresh: () => undefined } : null;
  }

  private liveAttachable(sessionId: string): Attachable {
    const a = this.attachable(sessionId);
    if (!a) throw new IpcError("session.not_found", "session not found");
    return a;
  }

  /** Point the session's sinks at the route's holder; while detached, `closed` reaches main as well. */
  private install(a: Attachable, route: Route): void {
    const cur = route.holder === "main" || !route.detached ? route.main : route.detached;
    const main = route.main;
    a.sink.emit = cur === main ? cur.emit : (ev) => {
      cur.emit(ev);
      if (ev.kind === "closed") main.emit(ev);
    };
    if (a.graphical && cur.onFrame) a.sink.onFrame = cur.onFrame;
  }

  private routeOf(sessionId: string, a: Attachable): Route {
    const r = this.routes.get(sessionId) ?? { holder: "main", main: { emit: a.sink.emit, onFrame: a.sink.onFrame }, detached: null };
    this.routes.set(sessionId, r);
    return r;
  }

  /** `session_attach` from `view`: it takes both sinks; the view that loses them gets `detached`. */
  protected attachFrom(view: View, { sessionId, onEvent, onFrame }: { sessionId: string; onEvent: SessionEventHandler; onFrame?: FrameHandler | undefined }): AttachedSession {
    const a = this.liveAttachable(sessionId);
    if (a.graphical && !onFrame) throw new IpcError("input.invalid", "invalid onFrame: required for rdp and vnc sessions");
    if (!a.graphical && onFrame) throw new IpcError("input.invalid", "invalid onFrame: not accepted for ssh sessions");
    const route = this.routeOf(sessionId, a);
    const lost = route.holder === view ? null : route.holder === "main" ? route.main : route.detached;
    const next: Sink = { emit: onEvent, onFrame };
    if (view === "main") {
      route.main = next;
      route.detached = null;
    } else route.detached = next;
    route.holder = view;
    this.install(a, route);
    a.refresh();
    if (lost) {
      this.record(view === "main" ? "session_attached" : "session_detached", { session: sessionId });
      this.later(() => { lost.emit({ kind: "detached" }); });
    }
    return { protocol: a.protocol, state: a.state, size: a.size };
  }

  sessionAttach: RemoteIpc["sessionAttach"] = async (args) => this.attachFrom("main", args);

  windowDetach: Ipc["windowDetach"] = async ({ sessionId }) => {
    await this.unlocked();
    const a = this.liveAttachable(sessionId);
    if (a.protocol !== "ssh" && !a.graphical) throw new IpcError("input.invalid", "invalid sessionId: this session cannot be detached");
    this.detached.push(sessionId);
    const route = this.routes.get(sessionId);
    if (this.phantomDetach && route?.holder !== "detached") {
      // The new window loads and calls session_attach; it acks every frame so the pump keeps going.
      const phantom: Sink = { emit: () => undefined };
      if (a.graphical) {
        phantom.onFrame = (m) => {
          const seq = peekSeq(m);
          if (seq !== null) this.sessionFrameAck({ sessionId, seq }).catch(() => undefined);
        };
      }
      this.later(() => {
        if (this.attachable(sessionId)) this.attachFrom("detached", { sessionId, onEvent: phantom.emit, onFrame: phantom.onFrame });
      });
    }
    return { windowLabel: `detached-${sessionId}` };
  };

  /** From main or the detached view: the window closes and main gets `attached`. */
  windowAttach: RemoteIpc["windowAttach"] = async ({ sessionId }) => {
    const a = this.liveAttachable(sessionId);
    const route = this.routes.get(sessionId);
    if (route?.holder !== "detached") return;
    route.holder = "main";
    route.detached = null;
    this.install(a, route);
    a.refresh();
    this.record("session_attached", { session: sessionId });
    const main = route.main;
    this.later(() => { main.emit({ kind: "attached" }); });
  };

  /**
   * This mock as seen from `detached-<sessionId>`: the six session commands for that id only,
   * no `listen()`. `ready` delays every call (the browser demo sets its session up first).
   */
  viewOf(sessionId: string, ready: Promise<unknown> = Promise.resolve()): Ipc {
    const allowed = new Set<string>(DETACHED_COMMANDS);
    const deny = (cmd: string) => {
      this.forbidden.push(cmd);
      return new IpcError("ipc.forbidden", "this window may not call that command");
    };
    return new Proxy(this as unknown as Ipc, {
      get: (target, prop, receiver) => {
        const value: unknown = Reflect.get(target, prop, receiver);
        if (typeof prop !== "string" || typeof value !== "function") return value;
        if (prop === "onVaultLocked") {
          return () => { throw deny("listen"); };
        }
        const cmd = commandName(prop);
        return async (...args: unknown[]) => {
          await ready;
          const sid = (args[0] as { sessionId?: unknown } | undefined)?.sessionId;
          if (!allowed.has(cmd) || sid !== sessionId) throw deny(cmd);
          if (prop === "sessionAttach") return this.attachFrom("detached", args[0] as Parameters<RemoteIpc["sessionAttach"]>[0]);
          return (value as (...a: unknown[]) => unknown).apply(target, args);
        };
      },
    });
  }
}
