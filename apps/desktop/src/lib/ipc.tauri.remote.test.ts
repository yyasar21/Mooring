// The Tauri transport against a fake `invoke`: command names and argument shapes of ADR-0011..0013.
import type { SessionEvent, WebEvent } from "./ipc.types";

const calls: { cmd: string; args: Record<string, unknown> | undefined }[] = [];
let reply: unknown = undefined;

vi.mock("@tauri-apps/api/core", () => {
  class Channel {
    onmessage: (msg: unknown) => void = () => undefined;
  }
  return {
    Channel,
    invoke: (cmd: string, args?: Record<string, unknown>) => {
      calls.push({ cmd, args });
      return Promise.resolve(reply);
    },
  };
});

vi.mock("@tauri-apps/api/event", () => ({ listen: () => Promise.resolve(() => undefined) }));

const { TauriTransport } = await import("./ipc");

type Chan = { onmessage: (m: unknown) => void };

beforeEach(() => {
  calls.length = 0;
  reply = undefined;
});

describe("TauriTransport · ADR-0011/0012/0013", () => {
  it("opens rdp/vnc sessions with a raw frame channel and ssh without one", async () => {
    const t = new TauriTransport();
    reply = { sessionId: "s-1" };
    const frames: ArrayBuffer[] = [];
    const events: SessionEvent[] = [];
    await t.sessionOpen({ connectionId: "c-1", size: { width: 1280, height: 800 }, onEvent: (e) => events.push(e), onFrame: (f) => frames.push(f) });
    await t.sessionOpen({ connectionId: "c-2", size: { width: 80, height: 24 }, onEvent: () => undefined });
    const [rdp, ssh] = calls;
    expect(Object.keys(rdp?.args ?? {}).sort()).toEqual(["connectionId", "onEvent", "onFrame", "size"]);
    expect(Object.keys(ssh?.args ?? {}).sort()).toEqual(["connectionId", "onEvent", "size"]);

    const fc = rdp?.args?.onFrame as Chan;
    const buf = new Uint8Array([1, 2, 3]).buffer;
    fc.onmessage(buf);
    fc.onmessage(new Uint8Array([4, 5]));
    fc.onmessage([6]);
    fc.onmessage("not bytes");
    expect(frames.map((f) => [...new Uint8Array(f)])).toEqual([[1, 2, 3], [4, 5], [6]]);
    expect(frames[0]).toBe(buf); // zero-copy for the normal case

    const ec = rdp?.args?.onEvent as Chan;
    ec.onmessage({ kind: "reconnecting", attempt: 2, delay_ms: 2000 });
    ec.onmessage({ kind: "closed", reason: "x", code: "trust_mismatch" });
    expect(events).toEqual([
      { kind: "reconnecting", attempt: 2, delayMs: 2000 },
      { kind: "closed", reason: "x", code: "trust_mismatch" },
    ]);
  });

  it("names the frame, screenshot, view-only and trust-store commands", async () => {
    const t = new TauriTransport();
    await t.sessionFrameAck({ sessionId: "s", seq: 7 });
    reply = { width: 1920, height: 1080 };
    expect(await t.sessionScreenshot({ sessionId: "s" })).toEqual({ width: 1920, height: 1080 });
    await t.sessionSetViewOnly({ sessionId: "s", viewOnly: true });
    reply = [{ host_hash: "|2|a|b", fingerprint: "SHA256:f", added_at: "2026-11-04T00:00:00Z" }];
    expect(await t.knownCertsList({ protocol: "vnc" })).toEqual([{ hostHash: "|2|a|b", fingerprint: "SHA256:f", addedAt: "2026-11-04T00:00:00Z" }]);
    reply = { removed: 1 };
    expect(await t.knownCertsRemove({ protocol: "rdp", host: "dc01.example.test", port: 3389 })).toEqual({ removed: 1 });
    expect(calls.map((c) => [c.cmd, c.args])).toEqual([
      ["session_frame_ack", { sessionId: "s", seq: 7 }],
      ["session_screenshot", { sessionId: "s" }],
      ["session_set_view_only", { sessionId: "s", viewOnly: true }],
      ["known_certs_list", { protocol: "vnc" }],
      ["known_certs_remove", { protocol: "rdp", host: "dc01.example.test", port: 3389 }],
    ]);
  });

  it("sends the new inputs in the mooring_core shapes", async () => {
    const t = new TauriTransport();
    await t.sessionSend({ sessionId: "s", input: { kind: "key", code: "KeyA", key: "a", pressed: true } });
    await t.sessionSend({ sessionId: "s", input: { kind: "wheel", dx: 0, dy: -120 } });
    await t.sessionSend({ sessionId: "s", input: { kind: "unicode", text: "ğ" } });
    await t.sessionSend({ sessionId: "s", input: { kind: "release_all" } });
    await t.sessionSend({ sessionId: "s", input: { kind: "clipboard_offer" } });
    await t.sessionSend({ sessionId: "s", input: { kind: "pointer", x: 3, y: 4, buttons: 5 } });
    expect(calls.map((c) => c.args?.input)).toEqual([
      { kind: "key", code: "KeyA", key: "a", pressed: true },
      { kind: "wheel", dx: 0, dy: -120 },
      { kind: "unicode", text: "ğ" },
      { kind: "release_all" },
      { kind: "clipboard_offer" },
      { kind: "pointer", x: 3, y: 4, buttons: 5 },
    ]);
  });

  it("names the web-window and detach commands", async () => {
    const t = new TauriTransport();
    const seen: WebEvent[] = [];
    reply = { windowLabel: "web-c-lb" };
    expect(await t.webOpen({ connectionId: "c-lb", onEvent: (e) => seen.push(e) })).toEqual({ windowLabel: "web-c-lb" });
    (calls[0]?.args?.onEvent as Chan).onmessage({ kind: "blocked", origin: "https://sso.example.test" });
    (calls[0]?.args?.onEvent as Chan).onmessage({ kind: "weird" });
    expect(seen).toEqual([{ kind: "blocked", origin: "https://sso.example.test" }, { kind: "closed" }]);
    reply = undefined;
    for (const m of ["webClose", "webFocus", "webReload", "webPrint", "webClearData"] as const) await t[m]({ connectionId: "c-lb" });
    await t.webZoom({ connectionId: "c-lb", factor: 1.25 });
    reply = [{ connection_id: "c-lb", window_label: "web-c-lb", origin: "https://lb.example.test", title: "LB", persistent: false, opened_at: "t" }];
    expect((await t.webList())[0]).toMatchObject({ connectionId: "c-lb", windowLabel: "web-c-lb" });
    reply = { windowLabel: "detached-s" };
    await t.windowDetach({ sessionId: "s" });
    await t.windowAttach({ sessionId: "s" });
    reply = { protocol: "rdp", state: "connected", size: { width: 800, height: 600 } };
    await t.sessionAttach({ sessionId: "s", onEvent: () => undefined, onFrame: () => undefined });
    expect(calls.map((c) => c.cmd)).toEqual([
      "web_open", "web_close", "web_focus", "web_reload", "web_print", "web_clear_data", "web_zoom", "web_list",
      "window_detach", "window_attach", "session_attach",
    ]);
    expect(calls[6]?.args).toEqual({ connectionId: "c-lb", factor: 1.25 });
    expect(Object.keys(calls[10]?.args ?? {}).sort()).toEqual(["onEvent", "onFrame", "sessionId"]);
  });
});
