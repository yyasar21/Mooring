// The mock's ADR-0013 behaviour that U3 is built on: the web window lifecycle and its events, the
// detach/attach routes, and the detached window's command ACL (`ipc.forbidden`).
import { MockTransport } from "./ipc.mock";
import { commandName, DETACHED_COMMANDS } from "./ipc.mock.detach";
import type { SessionEvent, WebEvent } from "./ipc.types";
import { decodeMfr1 } from "./frame/mfr1";

const tick = () => new Promise((r) => setTimeout(r, 0));

async function vnc(m: MockTransport) {
  m.frameIntervalMs = 60_000;
  const events: SessionEvent[] = [];
  const frames: ArrayBuffer[] = [];
  const { sessionId } = await m.sessionOpen({
    connectionId: "c-kiosk", size: { width: 800, height: 600 }, onEvent: (e) => events.push(e), onFrame: (f) => frames.push(f),
  });
  await vi.waitFor(() => { expect(events.some((e) => e.kind === "desktop_resized")).toBe(true); });
  await tick();
  return { sessionId, events, frames };
}

describe("MockTransport · web window lifecycle", () => {
  it("reports navigated and title, then refused navigations and downloads with their origin, then closed", async () => {
    const m = new MockTransport();
    const seen: WebEvent[] = [];
    await m.webOpen({ connectionId: "c-lb", onEvent: (e) => seen.push(e) });
    await tick();
    expect(seen).toEqual([{ kind: "navigated", origin: "https://lb.example.test" }, { kind: "title", title: "edge-lb console" }]);
    m.webSimulate("c-lb", { kind: "blocked", origin: "https://evil.example.test" });
    m.webSimulate("c-lb", { kind: "download_blocked", origin: "https://lb.example.test" });
    expect(seen.slice(2)).toEqual([
      { kind: "blocked", origin: "https://evil.example.test" },
      { kind: "download_blocked", origin: "https://lb.example.test" },
    ]);
    expect(m.audit.slice(-2).map((e) => e.event)).toEqual(["web_navigation_blocked", "web_download_blocked"]);
    m.webSimulate("c-lb", { kind: "closed" }); // native close
    expect(seen.at(-1)).toEqual({ kind: "closed" });
    expect(await m.webList()).toEqual([]);
  });

  it("refuses focus and print while locked; reload and zoom still work", async () => {
    const m = new MockTransport();
    await m.webOpen({ connectionId: "c-lb", onEvent: () => undefined });
    m.vault = "locked";
    await expect(m.webFocus({ connectionId: "c-lb" })).rejects.toMatchObject({ code: "vault.locked" });
    await expect(m.webPrint({ connectionId: "c-lb" })).rejects.toMatchObject({ code: "vault.locked" });
    await m.webReload({ connectionId: "c-lb" });
    await m.webZoom({ connectionId: "c-lb", factor: 2 });
  });

  it("the browser demo reports an SSO origin outside the allow-list and a download", async () => {
    vi.useFakeTimers();
    try {
      const m = new MockTransport({ webDemo: true });
      const kinds: string[] = [];
      await m.webOpen({ connectionId: "c-lb", onEvent: (e) => kinds.push(e.kind) });
      await vi.advanceTimersByTimeAsync(3000);
      expect(kinds).toEqual(["navigated", "title", "blocked", "download_blocked"]);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("MockTransport · detach and attach", () => {
  it("window_detach: the simulated window takes the session, acks its frames; window_attach gives it back", async () => {
    const m = new MockTransport();
    const { sessionId, events, frames } = await vnc(m);
    expect(await m.windowDetach({ sessionId })).toEqual({ windowLabel: `detached-${sessionId}` });
    await vi.waitFor(() => { expect(events.at(-1)).toEqual({ kind: "detached" }); });
    const before = frames.length;
    for (let i = 0; i < 5; i++) {
      expect(m.pumpOnce(sessionId)).toBe(true); // the phantom view acks: credits never run out
      await tick();
    }
    expect(frames).toHaveLength(before);

    await m.windowAttach({ sessionId });
    await tick();
    expect(events.at(-1)).toEqual({ kind: "attached" });
    const fresh: SessionEvent[] = [];
    const next: ArrayBuffer[] = [];
    const a = await m.sessionAttach({ sessionId, onEvent: (e) => fresh.push(e), onFrame: (f) => next.push(f) });
    expect(a).toEqual({ protocol: "vnc", state: "connected", size: { width: 800, height: 600 } });
    await tick();
    expect(fresh).toEqual([]); // main re-attaching to itself is not a detach
    expect(m.pumpOnce(sessionId)).toBe(true);
    expect(decodeMfr1(next[0] ?? new ArrayBuffer(0)).full).toBe(true);
    expect(m.audit.map((e) => e.event)).toEqual(expect.arrayContaining(["session_detached", "session_attached"]));
    await m.sessionClose({ sessionId });
  });

  it("a real detached view: main gets detached, closed reaches both views", async () => {
    const m = new MockTransport();
    m.phantomDetach = false;
    const { sessionId, events } = await vnc(m);
    await m.windowDetach({ sessionId });
    const view = m.viewOf(sessionId);
    const viewEvents: SessionEvent[] = [];
    const viewFrames: ArrayBuffer[] = [];
    await view.sessionAttach({ sessionId, onEvent: (e) => viewEvents.push(e), onFrame: (f) => viewFrames.push(f) });
    await tick();
    expect(events.at(-1)).toEqual({ kind: "detached" });
    m.pumpOnce(sessionId);
    expect(viewFrames).toHaveLength(1);
    await view.sessionFrameAck({ sessionId, seq: decodeMfr1(viewFrames[0] ?? new ArrayBuffer(0)).seq });
    await view.sessionClose({ sessionId });
    expect(viewEvents.at(-1)).toMatchObject({ kind: "closed", code: "user" });
    expect(events.at(-1)).toMatchObject({ kind: "closed", code: "user" });
  });

  it("a detached view may call only the six commands, for its own session; anything else is ipc.forbidden", async () => {
    const m = new MockTransport();
    const { sessionId } = await vnc(m);
    const view = m.viewOf(sessionId);
    await expect(view.vaultStatus()).rejects.toMatchObject({ code: "ipc.forbidden" });
    await expect(view.appInfo()).rejects.toMatchObject({ code: "ipc.forbidden" });
    await expect(view.sessionSetViewOnly({ sessionId, viewOnly: true })).rejects.toMatchObject({ code: "ipc.forbidden" });
    await expect(view.sessionList()).rejects.toMatchObject({ code: "ipc.forbidden" });
    await expect(view.sessionSend({ sessionId: "r-other", input: { kind: "release_all" } })).rejects.toMatchObject({ code: "ipc.forbidden" });
    await expect(view.windowDetach({ sessionId })).rejects.toMatchObject({ code: "ipc.forbidden" });
    expect(() => view.onVaultLocked(() => undefined)).toThrow(expect.objectContaining({ code: "ipc.forbidden" }) as unknown);
    await view.sessionSend({ sessionId, input: { kind: "release_all" } });
    await view.sessionScreenshot({ sessionId });
    expect(m.forbidden).toEqual(["vault_status", "app_info", "session_set_view_only", "session_list", "session_send", "window_detach", "listen"]);
    expect(DETACHED_COMMANDS.map((c) => c)).toEqual(["session_attach", "session_send", "session_close", "session_frame_ack", "session_screenshot", "window_attach"]);
    expect(commandName("sessionFrameAck")).toBe("session_frame_ack");
    await m.sessionClose({ sessionId });
  });

  it("SSH: onFrame is refused, the attach reports 0×0; web sessions cannot be detached; locked refuses", async () => {
    const m = new MockTransport();
    m.trustedHosts.add("web01.example.test");
    const { sessionId } = await m.sessionOpen({ connectionId: "c-web01", size: { width: 80, height: 24 }, onEvent: () => undefined });
    await tick();
    const view = m.viewOf(sessionId);
    await expect(view.sessionAttach({ sessionId, onEvent: () => undefined, onFrame: () => undefined })).rejects.toMatchObject({ code: "input.invalid" });
    expect(await view.sessionAttach({ sessionId, onEvent: () => undefined })).toEqual({ protocol: "ssh", state: "connected", size: { width: 0, height: 0 } });
    await expect(m.windowDetach({ sessionId: "nope" })).rejects.toMatchObject({ code: "session.not_found" });
    m.vault = "locked";
    await expect(m.windowDetach({ sessionId })).rejects.toMatchObject({ code: "vault.locked" });
  });
});
