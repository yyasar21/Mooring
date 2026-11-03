import { base64ToBytes, bytesToBase64, decodeAuditEntry, decodeSessionEvent, encodeSessionInput } from "./ipc";
import { MockTransport } from "./ipc.mock";
import type { SessionEvent } from "./ipc.types";

const tick = () => new Promise((r) => setTimeout(r, 0));

describe("ipc wire codec", () => {
  it("round-trips bytes through base64", () => {
    const data = new Uint8Array([0, 1, 127, 128, 255, 27, 91]);
    expect(base64ToBytes(bytesToBase64(data))).toEqual(data);
  });

  it("decodes snake_case session events and base64 payloads", () => {
    expect(decodeSessionEvent({ kind: "connected", protocol: "ssh", peer_identity: "SHA256:x" })).toEqual({
      kind: "connected",
      protocol: "ssh",
      peerIdentity: "SHA256:x",
    });
    const ev = decodeSessionEvent({ kind: "bytes", data: btoa("hi") });
    expect(ev.kind === "bytes" && new TextDecoder().decode(ev.data)).toBe("hi");
    expect(decodeSessionEvent({ kind: "nonsense" }).kind).toBe("closed");
  });

  it("encodes bytes input as base64 and leaves answers alone", () => {
    expect(encodeSessionInput({ kind: "bytes", data: new TextEncoder().encode("ls") })).toEqual({ kind: "bytes", data: "bHM=" });
    expect(encodeSessionInput({ kind: "answer", id: 1, text: "yes" })).toEqual({ kind: "answer", id: 1, text: "yes" });
  });

  it("flattens audit entries into event + details", () => {
    const e = decodeAuditEntry({ seq: 3, at: "t", prev: "p", event: "vault_locked", reason: "idle", connection: null });
    expect(e).toEqual({ seq: 3, at: "t", prev: "p", event: "vault_locked", details: { reason: "idle" } });
  });
});

describe("MockTransport", () => {
  it("resolves credentials through folder inheritance", async () => {
    const m = new MockTransport();
    const { connections } = await m.treeList();
    expect(connections.find((c) => c.id === "c-web01")?.effectiveCredentialId).toBe("cr-ops");
    expect(connections.find((c) => c.id === "c-pg")?.effectiveCredentialId).toBe("cr-deploy");
  });

  it("refuses moving a folder into its own subtree", async () => {
    const m = new MockTransport();
    await expect(m.folderMove({ id: "f-prod", parentId: "f-web" })).rejects.toMatchObject({ code: "tree.cycle" });
  });

  it("prompts TOFU once per host, then echoes input", async () => {
    const m = new MockTransport();
    const events: SessionEvent[] = [];
    const { sessionId } = await m.sessionOpen({ connectionId: "c-web01", size: { width: 80, height: 24 }, onEvent: (e) => events.push(e) });
    await tick();
    expect(events[0]).toMatchObject({ kind: "prompt", id: 1, secret: false });
    await m.sessionSend({ sessionId, input: { kind: "answer", id: 1, text: "yes" } });
    await tick();
    expect(events.some((e) => e.kind === "connected")).toBe(true);
    await m.sessionSend({ sessionId, input: { kind: "bytes", data: new TextEncoder().encode("ok") } });
    await tick();
    const last = events.at(-1);
    expect(last?.kind === "bytes" && new TextDecoder().decode(last.data)).toBe("ok");

    const second: SessionEvent[] = [];
    await m.sessionOpen({ connectionId: "c-web01", size: { width: 80, height: 24 }, onEvent: (e) => second.push(e) });
    await tick();
    expect(second[0]?.kind).toBe("connected");
  });

  it("copy password audits and reports a 30 s clear", async () => {
    const m = new MockTransport();
    await expect(m.credentialCopyPassword({ id: "cr-ops" })).resolves.toEqual({ clearsInMs: 30000 });
    const [newest] = await m.auditTail({ limit: 1, before: null });
    expect(newest).toMatchObject({ event: "credential_used", details: { credential: "cr-ops", purpose: "copy" } });
  });

  it("search ranks by fuzzy score", async () => {
    const m = new MockTransport();
    const hits = await m.connectionSearch({ query: "pg", limit: 5 });
    expect(hits[0]?.id).toBe("c-pg");
  });
});
