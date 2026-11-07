// ADR-0025 hop streams: `hop_status` and hop-tagged prompts on the wire, and the mock chain.
import { decodeSessionEvent } from "./ipc.decode.session";
import { MockTransport } from "./ipc.mock";
import { HOP_CREDENTIAL_ID, HOP_TRUST_ID } from "./ipc.mock.hops";
import type { SessionEvent } from "./ipc.types";
import { until } from "../test/ssh";
import { withHop } from "../stores/sessions";

describe("hop wire decoding", () => {
  it("decodes hop_status and tags prompts with their hop", () => {
    expect(decodeSessionEvent({ kind: "hop_status", hop: 1, of: 2, state: "authenticating", host: "b.example.test:22", peer_identity: null })).toEqual({
      kind: "hop_status", hop: 1, of: 2, state: "authenticating", host: "b.example.test:22", peerIdentity: null,
    });
    const p = decodeSessionEvent({ kind: "prompt", id: 1000, message: "Hop 1 of 1 — b:22", secret: false, purpose: "host_key_trust", hop: 0 });
    expect(p).toMatchObject({ kind: "prompt", hop: 0, purpose: "host_key_trust" });
    // absent / out of range = the target
    expect(decodeSessionEvent({ kind: "prompt", id: 1, message: "m", secret: false, purpose: "other" })).not.toHaveProperty("hop");
    expect(decodeSessionEvent({ kind: "prompt", id: 1, message: "m", secret: false, purpose: "other", hop: 7 })).not.toHaveProperty("hop");
    expect(decodeSessionEvent({ kind: "closed", reason: "r", code: "hop_failed" })).toEqual({ kind: "closed", reason: "r", code: "hop_failed" });
    expect(decodeSessionEvent({ kind: "closed", reason: "r", code: "hop_lost" })).toMatchObject({ code: "hop_lost" });
  });

  it("closes the tab on a hop_status it cannot show", () => {
    for (const bad of [
      { kind: "hop_status", hop: 3, of: 3, state: "up", host: "h:22" },
      { kind: "hop_status", hop: 0, of: 4, state: "up", host: "h:22" },
      { kind: "hop_status", hop: 0, of: 1, state: "dancing", host: "h:22" },
      { kind: "hop_status", hop: "0", of: 1, state: "up", host: "h:22" },
    ]) expect(decodeSessionEvent(bad)).toMatchObject({ kind: "closed", code: "unknown" });
  });

  it("keeps the latest status per hop and restarts on a new chain", () => {
    let hops = withHop([], { hop: 0, of: 2, state: "connecting", host: "a:22", peerIdentity: null });
    hops = withHop(hops, { hop: 0, of: 2, state: "up", host: "a:22", peerIdentity: "SHA256:a" });
    hops = withHop(hops, { hop: 1, of: 2, state: "failed", host: "b:22", peerIdentity: null });
    expect(hops.map((h) => h.state)).toEqual(["up", "failed"]);
    expect(withHop(hops, { hop: 0, of: 2, state: "connecting", host: "a:22", peerIdentity: null })).toHaveLength(1);
  });
});

describe("mock jump-host chain", () => {
  const open = async (m: MockTransport, connectionId: string) => {
    const events: SessionEvent[] = [];
    const { sessionId } = await m.sessionOpen({ connectionId, size: { width: 80, height: 24 }, onEvent: (e) => { events.push(e); } });
    return { sessionId, events };
  };

  it("brings each hop up in order, asking for the hop's host key first, before the target", async () => {
    const m = new MockTransport();
    const { sessionId, events } = await open(m, "c-stg");
    await until(() => events.some((e) => e.kind === "prompt"));
    const ask = events.find((e) => e.kind === "prompt");
    expect(ask).toMatchObject({ id: HOP_TRUST_ID, hop: 0, purpose: "host_key_trust" });
    expect(ask?.kind === "prompt" && ask.message).toMatch(/^Hop 1 of 1 — bastion\.stage\.example\.test:22/);
    await m.sessionSend({ sessionId, input: { kind: "answer", id: HOP_TRUST_ID, text: "yes" } });
    await until(() => events.filter((e) => e.kind === "prompt").length === 2);
    // the target's own TOFU comes only after hop 0 is up
    const kinds = events.map((e) => (e.kind === "hop_status" ? `hop:${e.state}` : e.kind));
    expect(kinds).toEqual(["hop:connecting", "prompt", "hop:authenticating", "hop:up", "prompt"]);
    expect(events.at(-1)).toMatchObject({ kind: "prompt", id: 1 });
    expect(m.audit.map((a) => a.event)).toContain("session_hop_open");
  });

  it("closes with hop_failed when the hop key is rejected: the target is never asked", async () => {
    const m = new MockTransport();
    const { sessionId, events } = await open(m, "c-stg");
    await until(() => events.some((e) => e.kind === "prompt"));
    await m.sessionSend({ sessionId, input: { kind: "answer", id: HOP_TRUST_ID, text: "no" } });
    await until(() => events.some((e) => e.kind === "closed"));
    expect(events.at(-1)).toMatchObject({ kind: "closed", code: "hop_failed" });
    expect(events.filter((e) => e.kind === "prompt")).toHaveLength(1);
    expect(events.some((e) => e.kind === "hop_status" && e.state === "failed")).toBe(true);
  });

  it("asks a prompt-credential hop to sign in, tagged with the hop", async () => {
    const m = new MockTransport();
    m.trustedHosts.add("jump.stage.example.test");
    const stg = m.connections.find((c) => c.id === "c-stg");
    if (stg) stg.via = ["c-jump"]; // ask-me: a `prompt` credential
    const { sessionId, events } = await open(m, "c-stg");
    await until(() => events.some((e) => e.kind === "prompt"));
    expect(events.find((e) => e.kind === "prompt")).toMatchObject({ id: HOP_CREDENTIAL_ID, hop: 0, purpose: "credential" });
    await m.sessionSend({ sessionId, input: { kind: "credential_answer", id: HOP_CREDENTIAL_ID, username: "ops", domain: null, password: "x" } });
    await until(() => events.some((e) => e.kind === "hop_status" && e.state === "up"));
    expect(events.some((e) => e.kind === "hop_status" && e.state === "up")).toBe(true);
  });

  it("a hop that refuses the sign-in ends the session with hop_failed", async () => {
    const m = new MockTransport();
    m.trustedHosts.add("bastion.stage.example.test");
    const b = m.connections.find((c) => c.id === "c-bastion");
    if (b) b.tags = ["hop-fail"];
    const { events } = await open(m, "c-stg");
    await until(() => events.some((e) => e.kind === "closed"));
    expect(events.at(-1)).toMatchObject({ kind: "closed", code: "hop_failed", reason: "jump host bastion01 refused the sign-in" });
  });

  it("graphical targets get their hop events before the target's", async () => {
    const m = new MockTransport();
    const dc = m.connections.find((c) => c.id === "c-dc");
    if (dc) dc.via = ["c-bastion"];
    const events: SessionEvent[] = [];
    await m.sessionOpen({ connectionId: "c-dc", size: { width: 1280, height: 800 }, onEvent: (e) => { events.push(e); }, onFrame: () => undefined });
    await until(() => events.length >= 3);
    expect(events.slice(0, 2).map((e) => e.kind === "hop_status" && e.state)).toEqual(["connecting", "up"]);
  });
});
