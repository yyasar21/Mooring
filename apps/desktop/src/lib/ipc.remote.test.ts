// Wire decoders of the A2 events and the mock RDP/VNC/web backend (ADR-0011..0013).
import { decodeSessionEvent } from "./ipc";
import { MockTransport } from "./ipc.mock";
import type { SessionEvent } from "./ipc.types";
import { decodeMfr1 } from "./frame/mfr1";

describe("A2 session event decoding", () => {
  it("decodes `attached` as its own event and stays strict about every other kind (R5)", () => {
    expect(decodeSessionEvent({ kind: "attached" })).toEqual({ kind: "attached" });
    expect(decodeSessionEvent({ kind: "attached", sessionId: "x", reason: "r" })).toEqual({ kind: "attached" });
    expect(decodeSessionEvent({ kind: "detached", extra: 1 })).toEqual({ kind: "detached" });
    const unknown = { kind: "closed", reason: "unrecognised session event", code: "unknown" };
    for (const raw of [{ kind: "Attached" }, { kind: "attach" }, { kind: " attached" }, { kind: ["attached"] }, { kind: null }, {}, "attached", null, 7]) {
      expect(decodeSessionEvent(raw)).toEqual(unknown);
    }
  });

  it("decodes certificate prompts, resize, detach and close codes", () => {
    const cert = { subject: "CN=dc01.example.test", issuer: "CN=dc01.example.test", not_before: "a", not_after: "b", sha256: "ab", san: ["dc01.example.test", 7, "192.0.2.10"], problems: ["self_signed", "bogus", "expired"] };
    expect(decodeSessionEvent({ kind: "prompt", id: 1, message: "m", secret: false, purpose: "certificate_trust", certificate: cert })).toEqual({
      kind: "prompt", id: 1, message: "m", secret: false, purpose: "certificate_trust", account: null,
      certificate: { subject: "CN=dc01.example.test", issuer: "CN=dc01.example.test", notBefore: "a", notAfter: "b", sha256: "ab", san: ["dc01.example.test", "192.0.2.10"], problems: ["self_signed", "expired"] },
    });
    // A certificate on any other purpose is not shown.
    expect(decodeSessionEvent({ kind: "prompt", id: 1, purpose: "other", certificate: cert })).toMatchObject({ certificate: null });
    expect(decodeSessionEvent({ kind: "desktop_resized", width: 1024, height: 768 })).toEqual({ kind: "desktop_resized", width: 1024, height: 768 });
    expect(decodeSessionEvent({ kind: "detached" })).toEqual({ kind: "detached" });
    expect(decodeSessionEvent({ kind: "closed", reason: "r", code: "made_up" })).toEqual({ kind: "closed", reason: "r", code: "unknown" });
    expect(decodeSessionEvent({ kind: "connected", protocol: "rdp", peer_identity: "x509 SHA256:ab", security: "nla" })).toMatchObject({ security: "nla" });
    expect(decodeSessionEvent({ kind: "reconnecting", attempt: 1, delay_ms: Number.NaN })).toEqual({ kind: "reconnecting", attempt: 1, delayMs: 0 });
    // R2 sends snake_case `delay_ms`; the ADR's camelCase `delayMs` is accepted too.
    expect(decodeSessionEvent({ kind: "reconnecting", attempt: 2, delay_ms: 1043 })).toEqual({ kind: "reconnecting", attempt: 2, delayMs: 1043 });
    expect(decodeSessionEvent({ kind: "reconnecting", attempt: 3, delayMs: 3900 })).toEqual({ kind: "reconnecting", attempt: 3, delayMs: 3900 });
    // A certificate without `san` (older R1 payload) decodes with an empty list.
    expect(decodeSessionEvent({ kind: "prompt", id: 2, purpose: "certificate_trust", certificate: { sha256: "ab" } })).toMatchObject({ certificate: { san: [], problems: [] } });
  });
});

function harness(opts: { connectionId: string }) {
  const m = new MockTransport();
  m.frameIntervalMs = 60_000; // frames only when the test pumps
  const events: SessionEvent[] = [];
  const frames: ArrayBuffer[] = [];
  const open = () => m.sessionOpen({ connectionId: opts.connectionId, size: { width: 801, height: 600 }, onEvent: (e) => events.push(e), onFrame: (f) => frames.push(f) });
  return { m, events, frames, open };
}

const tick = () => new Promise((r) => setTimeout(r, 0));

describe("MockTransport · RDP/VNC", () => {
  it("asks for certificate trust, pins on yes, then streams frames under the 2-credit limit", async () => {
    const { m, events, frames, open } = harness({ connectionId: "c-dc" });
    const { sessionId } = await open();
    await tick();
    expect(events[0]).toMatchObject({ kind: "prompt", purpose: "certificate_trust", certificate: { problems: ["self_signed"] } });
    await m.sessionSend({ sessionId, input: { kind: "answer", id: 1, text: "yes" } });
    await vi.waitFor(() => { expect(events.some((e) => e.kind === "connected")).toBe(true); });
    expect(events.find((e) => e.kind === "connected")).toMatchObject({ security: "nla", peerIdentity: expect.stringMatching(/^x509 SHA256:/) as unknown });
    expect(events.find((e) => e.kind === "desktop_resized")).toEqual({ kind: "desktop_resized", width: 800, height: 600 }); // even width
    expect(frames).toHaveLength(1);
    expect(m.pumpOnce(sessionId)).toBe(true);
    expect(m.pumpOnce(sessionId)).toBe(false); // both credits in flight
    const first = decodeMfr1(frames[0] ?? new ArrayBuffer(0));
    expect(first).toMatchObject({ seq: 1, width: 800, height: 600, full: true });
    await m.sessionFrameAck({ sessionId, seq: 1 });
    expect(m.pumpOnce(sessionId)).toBe(true);
    expect(decodeMfr1(frames[2] ?? new ArrayBuffer(0)).full).toBe(false);
    await expect(m.sessionFrameAck({ sessionId, seq: 99 })).rejects.toMatchObject({ code: "input.invalid" });
    expect(await m.knownCertsList({ protocol: "rdp" })).toHaveLength(1);
    expect(await m.sessionScreenshot({ sessionId })).toEqual({ width: 800, height: 600 });
    await m.sessionClose({ sessionId });
    expect(events.at(-1)).toEqual({ kind: "closed", reason: "closed by user", code: "user" });
  });

  it("rejecting the certificate closes with trust_rejected; a pin can be removed", async () => {
    const { m, events, open } = harness({ connectionId: "c-dc" });
    const { sessionId } = await open();
    await tick();
    await m.sessionSend({ sessionId, input: { kind: "answer", id: 1, text: "no" } });
    await tick();
    expect(events.at(-1)).toMatchObject({ kind: "closed", code: "trust_rejected" });
    expect(await m.knownCertsRemove({ protocol: "rdp", host: "dc01.example.test", port: 3389 })).toEqual({ removed: 0 });
  });

  it("known_certs_list names a pin only when it matches one of the user's connections (list_named, N-33)", async () => {
    const m = new MockTransport();
    const t = (host: string, port: number) => ({ connectionId: "x", protocol: "rdp" as const, name: host, host, port, tags: [], options: undefined });
    await m.pin(t("DC01.example.test", 3389)); // seed c-dc, matched case-insensitively
    await m.pin(t("203.0.113.9", 3389)); // no such connection
    const rows = await m.knownCertsList({ protocol: "rdp" });
    expect(rows.map((r) => [r.hostHash.startsWith("|2|"), r.host, r.port])).toEqual([[true, "dc01.example.test", 3389], [true, undefined, undefined]]);
    expect(await m.knownCertsList({ protocol: "vnc" })).toEqual([]);
  });

  it("requires onFrame for rdp/vnc and refuses it for ssh", async () => {
    const m = new MockTransport();
    await expect(m.sessionOpen({ connectionId: "c-kiosk", size: { width: 800, height: 600 }, onEvent: () => undefined })).rejects.toMatchObject({ code: "input.invalid" });
    await expect(m.sessionOpen({ connectionId: "c-web01", size: { width: 80, height: 24 }, onEvent: () => undefined, onFrame: () => undefined })).rejects.toMatchObject({ code: "input.invalid" });
  });

  it("VNC view-only drops input, the toggle lifts it, and only VNC accepts the toggle", async () => {
    const { m, events, open } = harness({ connectionId: "c-kiosk" });
    const { sessionId } = await open();
    await tick();
    expect(events[0]).toMatchObject({ kind: "connected", security: "vnc-auth" });
    const s = m.remote.get(sessionId);
    await m.sessionSend({ sessionId, input: { kind: "pointer", x: 1, y: 1, buttons: 1 } });
    await m.sessionSend({ sessionId, input: { kind: "release_all" } });
    expect(s?.dropped).toBe(1);
    expect(s?.inputs).toEqual([{ kind: "release_all" }]);
    await m.sessionSetViewOnly({ sessionId, viewOnly: false });
    await m.sessionSend({ sessionId, input: { kind: "clipboard_offer" } });
    expect(s?.inputs.at(-1)).toEqual({ kind: "clipboard_offer" });
    expect((await m.auditTail({ limit: 1, before: null }))[0]?.event).toBe("session_clipboard");
    await expect(m.sessionSend({ sessionId, input: { kind: "key", code: "x".repeat(33), key: "x", pressed: true } })).rejects.toMatchObject({ code: "input.invalid" });
    await expect(m.sessionSend({ sessionId, input: { kind: "bytes", data: new Uint8Array(1) } })).rejects.toMatchObject({ code: "input.invalid" });
    m.reconnectDelaysMs = [0, 0];
    m.dropLink(sessionId);
    await tick();
    await tick();
    const kinds = events.map((e) => e.kind);
    expect(kinds.filter((k) => k === "reconnecting")).toHaveLength(2);
    expect(kinds.at(-1)).toBe("desktop_resized");
    await m.sessionClose({ sessionId });
  });

  it("refuses the view-only toggle for RDP", async () => {
    const { m, open } = harness({ connectionId: "c-dc" });
    const { sessionId } = await open();
    await expect(m.sessionSetViewOnly({ sessionId, viewOnly: true })).rejects.toMatchObject({ code: "input.invalid" });
    await m.sessionClose({ sessionId });
  });

  it("session_attach moves both sinks, tells the old view, and resends a full frame", async () => {
    const { m, events, open } = harness({ connectionId: "c-kiosk" });
    const { sessionId } = await open();
    await tick();
    const next: ArrayBuffer[] = [];
    const attached = await m.viewOf(sessionId).sessionAttach({ sessionId, onEvent: () => undefined, onFrame: (f) => next.push(f) });
    expect(attached).toEqual({ protocol: "vnc", state: "connected", size: { width: 800, height: 600 } });
    await tick();
    expect(events.at(-1)).toEqual({ kind: "detached" });
    m.pumpOnce(sessionId);
    expect(decodeMfr1(next[0] ?? new ArrayBuffer(0)).full).toBe(true);
    m.phantomDetach = false;
    expect(await m.windowDetach({ sessionId })).toEqual({ windowLabel: `detached-${sessionId}` });
    await m.sessionClose({ sessionId });
  });
});

describe("MockTransport · web windows (ADR-0013 stubs)", () => {
  it("opens one window per connection, lists, zooms and closes it", async () => {
    const m = new MockTransport();
    const first: string[] = [];
    const seen: string[] = [];
    const a = await m.webOpen({ connectionId: "c-lb", onEvent: (e) => first.push(e.kind) });
    // Opening again focuses the window and moves the events to the new channel (R5).
    const b = await m.webOpen({ connectionId: "c-lb", onEvent: (e) => seen.push(e.kind) });
    expect(a).toEqual({ windowLabel: "web-c-lb" });
    expect(b).toEqual(a);
    await tick();
    expect(seen).toEqual(["navigated", "title"]);
    expect(first).toEqual([]);
    expect(await m.webList()).toEqual([expect.objectContaining({ origin: "https://lb.example.test", title: "edge-lb console" })]);
    await expect(m.webZoom({ connectionId: "c-lb", factor: 9 })).rejects.toMatchObject({ code: "input.invalid" });
    await m.webZoom({ connectionId: "c-lb", factor: 1.5 });
    await m.webClose({ connectionId: "c-lb" });
    await tick();
    expect(seen.at(-1)).toBe("closed");
    await expect(m.webFocus({ connectionId: "c-lb" })).rejects.toMatchObject({ code: "session.not_found" });
    await expect(m.webOpen({ connectionId: "c-web01", onEvent: () => undefined })).rejects.toMatchObject({ code: "input.invalid" });
  });
});
