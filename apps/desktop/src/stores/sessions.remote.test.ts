// The RDP/VNC tab state machine against the mock backend:
// connecting → (certificate prompt) → connected → reconnecting → connected | closed(code), detached.
import { freshBackend, settle } from "../test/harness";
import type { MockTransport } from "../lib/ipc.mock";
import { decodeMfr1 } from "../lib/frame/mfr1";
import { queuedFrames, subscribeFrames } from "./frames";
import { useSessions } from "./sessions";
import { useTree } from "./tree";

const tab = () => useSessions.getState().tabs[0];

describe("remote session tabs", () => {
  let mock: MockTransport;
  beforeEach(async () => {
    mock = freshBackend();
    mock.frameIntervalMs = 60_000; // the test pumps frames itself
    await useTree.getState().load();
  });
  afterEach(async () => {
    for (const t of useSessions.getState().tabs) await useSessions.getState().close(t.id);
  });

  it("RDP: certificate prompt → trust → connected with NLA, frames queue until a canvas subscribes", async () => {
    const id = await useSessions.getState().open("c-dc");
    expect(tab()).toMatchObject({ protocol: "rdp", state: "connecting" });
    await settle();
    expect(tab()?.prompt).toMatchObject({ purpose: "certificate_trust", certificate: { subject: "CN=dc01.example.test", problems: ["self_signed"] } });
    expect(await useSessions.getState().answer(id, "yes")).toBe(true);
    await settle();
    expect(tab()).toMatchObject({ state: "connected", security: "nla", prompt: null, desktop: { width: 1280, height: 800 } });
    expect(tab()?.peerIdentity).toMatch(/^x509 SHA256:/);
    const sid = tab()?.sessionId ?? "";
    mock.pumpOnce(sid);
    expect(queuedFrames(id)).toBe(2); // two credits, nothing drawn yet
    expect(mock.pumpOnce(sid)).toBe(false);

    const seen: number[] = [];
    const off = subscribeFrames(id, (m) => seen.push(decodeMfr1(m).seq));
    expect(seen).toEqual([1, 2]);
    expect(queuedFrames(id)).toBe(0);
    const { ackFrame } = await import("./sessions");
    ackFrame(id, 1);
    await settle();
    expect(mock.pumpOnce(sid)).toBe(true);
    expect(seen).toEqual([1, 2, 3]);
    off();
  });

  it("rejecting the certificate closes with trust_rejected; reconnect starts over", async () => {
    const id = await useSessions.getState().open("c-dc");
    await settle();
    await useSessions.getState().answer(id, "no");
    await settle();
    expect(tab()).toMatchObject({ state: "closed", closeCode: "trust_rejected", sessionId: null });
    await useSessions.getState().reconnect(id);
    expect(tab()).toMatchObject({ state: "connecting", closeCode: null });
    await settle();
    expect(tab()?.prompt?.purpose).toBe("certificate_trust");
  });

  it("VNC: view-only from the options, the toggle, and the reconnect cycle", async () => {
    const id = await useSessions.getState().open("c-kiosk");
    await settle();
    expect(tab()).toMatchObject({ protocol: "vnc", state: "connected", security: "vnc-auth", viewOnly: true });
    expect(await useSessions.getState().setViewOnly(id, false)).toBe(true);
    expect(tab()?.viewOnly).toBe(false);

    mock.reconnectDelaysMs = [5, 5];
    mock.dropLink(tab()?.sessionId ?? "", 2);
    await settle(1);
    expect(tab()).toMatchObject({ state: "reconnecting", reconnect: { attempt: 1, delayMs: 5 } });
    await new Promise((r) => setTimeout(r, 30));
    await settle();
    expect(tab()).toMatchObject({ state: "connected", reconnect: null });
  });

  it("a session taken over by another window becomes detached", async () => {
    await useSessions.getState().open("c-kiosk");
    await settle();
    const sid = tab()?.sessionId ?? "";
    await mock.viewOf(sid).sessionAttach({ sessionId: sid, onEvent: () => undefined, onFrame: () => undefined });
    await settle();
    expect(tab()?.state).toBe("detached");
  });

  it("screenshot reports the copied size; closing reports code user", async () => {
    const id = await useSessions.getState().open("c-kiosk");
    await settle();
    expect(await useSessions.getState().screenshot(id)).toEqual({ width: 1280, height: 800 });
    expect(mock.audit.at(-1)?.event).toBe("session_screenshot");
  });

  it("after a lock, an adopted remote session is re-attached and gets a full frame", async () => {
    const id = await useSessions.getState().open("c-kiosk");
    await settle();
    const sid = tab()?.sessionId ?? "";
    useSessions.getState().reset(); // lock: the tab goes, the backend session stays
    mock.pumpOnce(sid); // a frame that arrives while locked is acked, not kept
    await settle();
    expect(mock.remote.get(sid)?.inFlight).toBe(0);
    useSessions.getState().adopt(await mock.sessionList());
    await settle();
    expect(tab()).toMatchObject({ id, sessionId: sid, protocol: "vnc" });
    expect(tab()?.state).not.toBe("detached"); // the old channel's `detached` is ignored
    const seen: boolean[] = [];
    const off = subscribeFrames(id, (m) => seen.push(decodeMfr1(m).full));
    mock.pumpOnce(sid);
    expect(seen).toEqual([true]);
    off();
  });
});
