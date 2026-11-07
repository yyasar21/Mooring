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
      security: null,
    });
    const ev = decodeSessionEvent({ kind: "bytes", data: btoa("hi") });
    expect(ev.kind === "bytes" && new TextDecoder().decode(ev.data)).toBe("hi");
    expect(decodeSessionEvent({ kind: "nonsense" }).kind).toBe("closed");
  });

  it("decodes every ADR-0011 close code, 6b's trust_conflict included; an unknown one is `unknown`", () => {
    for (const code of ["trust_mismatch", "trust_conflict", "vault_locked"]) {
      expect(decodeSessionEvent({ kind: "closed", reason: "r", code })).toEqual({ kind: "closed", reason: "r", code });
    }
    expect(decodeSessionEvent({ kind: "closed", reason: "r", code: "TrustConflict" })).toMatchObject({ code: "unknown" });
    expect(decodeSessionEvent({ kind: "closed", reason: "r" })).toMatchObject({ code: "unknown" });
  });

  it("decodes the prompt purpose and falls back to other, never to trust (L-2)", () => {
    const base = { kind: "prompt", id: 1, message: "Trust this host?", secret: false };
    expect(decodeSessionEvent({ ...base, purpose: "host_key_trust" })).toMatchObject({ purpose: "host_key_trust" });
    expect(decodeSessionEvent({ ...base, purpose: "keyboard_interactive" })).toMatchObject({ purpose: "keyboard_interactive" });
    expect(decodeSessionEvent({ ...base, purpose: "HostKeyTrust" })).toMatchObject({ purpose: "other" });
    expect(decodeSessionEvent(base)).toMatchObject({ purpose: "other" });
  });

  it("decodes a credential prompt's account and ignores it for other purposes", () => {
    const base = { kind: "prompt", id: 3, message: "Sign in", secret: true };
    expect(
      decodeSessionEvent({ ...base, purpose: "credential", account: { username: "ops", domain: null, needs_username: true, needs_domain: true } }),
    ).toMatchObject({ purpose: "credential", account: { username: "ops", domain: null, needsUsername: true, needsDomain: true } });
    expect(decodeSessionEvent({ ...base, purpose: "credential" })).toMatchObject({
      account: { username: null, domain: null, needsUsername: true, needsDomain: false },
    });
    expect(decodeSessionEvent({ ...base, purpose: "other", account: { username: "x" } })).toMatchObject({ account: null });
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

  it("copy secret audits {id, name} and reports a 30 s clear", async () => {
    const m = new MockTransport();
    await expect(m.credentialCopySecret({ id: "cr-deploy", name: "password" })).resolves.toEqual({ clearsInMs: 30000 });
    const [newest] = await m.auditTail({ limit: 1, before: null });
    expect(newest).toMatchObject({ event: "credential_copied", details: { credential: "cr-deploy", name: "password" } });
  });

  it("copy OTP reports how long the code stays valid", async () => {
    const m = new MockTransport();
    const r = await m.credentialCopyOtp({ id: "cr-deploy" });
    expect(r.validForMs).toBeGreaterThan(0);
    expect(r.validForMs).toBeLessThanOrEqual(30_000);
    expect(r.clearsInMs).toBeLessThanOrEqual(r.validForMs);
    await expect(m.credentialCopyOtp({ id: "cr-ops" })).rejects.toMatchObject({ code: "credential.secret_missing" });
  });

  it("serves all 18 kinds with English labels and the ADR matrix", async () => {
    const kinds = await new MockTransport().credentialKinds();
    expect(kinds.map((k) => k.kind).sort()).toHaveLength(18);
    const of = (k: string) => kinds.find((x) => x.kind === k);
    expect(of("user_password")?.protocols).toContainEqual({ protocol: "rdp", roles: ["primary", "gateway"] });
    expect(of("sudo_become")?.protocols).toEqual([{ protocol: "ssh", roles: ["become"] }]);
    expect(of("vnc_password")?.fields.find((f) => f.name === "password")?.validation.maxBytes).toBe(8);
    expect(of("kubeconfig")?.fields.find((f) => f.name === "kubeconfig_yaml")?.secret).toBe(true);
  });

  it("rejects a kubeconfig with an exec plugin", async () => {
    const m = new MockTransport();
    const yaml = "apiVersion: v1\nkind: Config\nclusters: []\nusers:\n- name: u\n  user:\n    exec:\n      command: aws\n";
    await expect(
      m.credentialCreate({ name: "k", kind: "kubeconfig", fields: {}, secrets: { kubeconfig_yaml: yaml } }),
    ).rejects.toMatchObject({ code: "credential.kubeconfig_rejected" });
  });

  it("asks for the account when the credential is prompt", async () => {
    const m = new MockTransport();
    m.trustedHosts.add("jump.stage.example.test");
    const events: SessionEvent[] = [];
    const { sessionId } = await m.sessionOpen({ connectionId: "c-jump", size: { width: 80, height: 24 }, onEvent: (e) => events.push(e) });
    await tick();
    expect(events[0]).toMatchObject({ kind: "prompt", purpose: "credential", account: { username: "ops", needsUsername: true } });
    await m.sessionSend({ sessionId, input: { kind: "credential_answer", id: 3, username: "ops", domain: null, password: "x" } });
    await tick();
    expect(events.some((e) => e.kind === "connected")).toBe(true);
  });

  it("search ranks by fuzzy score", async () => {
    const m = new MockTransport();
    const hits = await m.connectionSearch({ query: "pg", limit: 5 });
    expect(hits[0]?.id).toBe("c-pg");
  });
});
