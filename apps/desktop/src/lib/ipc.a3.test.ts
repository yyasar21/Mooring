// ADR-0016..0017 mock contract: secret sources and external_ref tests (names only), vault sync.
// ADR-0015 (vSphere) is covered by `ipc.vsphere.test.ts`.
import { IpcError, type SecretSourceInput } from "./ipc";
import { MockTransport } from "./ipc.mock";

const code = async (p: Promise<unknown>) => {
  try {
    await p;
    return "ok";
  } catch (e: unknown) {
    return e instanceof IpcError ? e.code : "not an IpcError";
  }
};

// The vSphere block lives in `ipc.vsphere.test.ts` (U2).

describe("mock · secret sources (ADR-0016)", () => {
  const input = (p: Partial<SecretSourceInput> = {}): SecretSourceInput => ({
    name: "ops vault", address: "https://vault.example.test:8200", namespace: null, authMethod: "approle", authMount: "approle",
    credentialId: "cr-ops", oidcRole: null, options: { caPem: null, allowHttp: false, allowedOrigins: [] }, ...p,
  });

  it("creates, tests, updates and deletes sources; nothing secret comes back", async () => {
    const m = new MockTransport();
    const s = await m.secretSourceCreate(input());
    expect(s).toMatchObject({ kind: "vault", name: "ops vault" });
    expect(JSON.stringify(await m.secretSourceList())).not.toMatch(/token|secret_id/i);
    expect(await m.secretSourceTest({ id: s.id })).toMatchObject({ ok: true, method: "approle", renewable: true });
    await m.secretSourceUpdate({ id: s.id, ...input({ name: "renamed", address: "https://down.invalid" }) });
    expect(await m.secretSourceTest({ id: s.id })).toMatchObject({ ok: false, error: "network" });
    expect(m.audit.some((a) => a.event === "secret.source_changed" && a.details.changed === "name,address")).toBe(true);
    await m.secretSourceLogout({ id: s.id });
    await m.secretSourceDelete({ id: s.id });
    expect(await code(m.secretSourceTest({ id: s.id }))).toBe("source.not_found");
  });

  it("validates addresses and the method/credential pairing", async () => {
    const m = new MockTransport();
    expect(await code(m.secretSourceCreate(input({ address: "http://vault.example.test" })))).toBe("input.invalid");
    expect(await code(m.secretSourceCreate(input({ address: "http://127.0.0.1:8200", options: { caPem: null, allowHttp: true, allowedOrigins: [] } })))).toBe("ok");
    expect(await code(m.secretSourceCreate(input({ authMethod: "oidc" })))).toBe("input.invalid");
    expect(await code(m.secretSourceCreate(input({ authMethod: "token", credentialId: null })))).toBe("input.invalid");
  });

  it("OIDC: one window per source, status goes waiting → done", async () => {
    const m = new MockTransport();
    const s = await m.secretSourceCreate(input({ authMethod: "oidc", authMount: "oidc", credentialId: null, oidcRole: "ops" }));
    expect(await m.secretSourceOidcStatus({ id: s.id })).toEqual({ state: "idle", error: null });
    expect(await m.secretSourceOidcStart({ id: s.id })).toEqual({ windowLabel: `oidc-${s.id}` });
    expect(await code(m.secretSourceOidcStart({ id: s.id }))).toBe("input.invalid");
    await new Promise((r) => setTimeout(r, 0));
    expect((await m.secretSourceOidcStatus({ id: s.id })).state).toBe("done");
  });

  it("external_ref_test returns key names only, and a used source cannot be deleted", async () => {
    const m = new MockTransport();
    const s = await m.secretSourceCreate(input());
    // The ADR-0016 `source` field joins the external_ref schema with U3/E2; the row is seeded directly.
    const ref = { id: "cr-ext", name: "db via vault", kind: "external_ref" as const, fields: { provider: "vault", source: s.id, reference: "kv/ops/db", target_kind: "user_password" }, secretNames: [], fingerprint: null, createdAt: "", updatedAt: "" };
    m.creds.items.push(ref);
    expect(await m.externalRefTest({ credentialId: ref.id })).toEqual({ ok: true, version: 3, present: ["username", "password"], missing: [], error: null });
    expect(await code(m.secretSourceDelete({ id: s.id }))).toBe("source.in_use");
    expect(await code(m.externalRefTest({ credentialId: "cr-ops" }))).toBe("input.invalid");
  });
});

describe("mock · vault sync (ADR-0017)", () => {
  const settings = { endpoint: "https://s3.example.test", bucket: "mooring-sync", prefix: "team", region: "eu-west-1", pathStyle: true, credentialId: "cr-ops", options: { caPem: null } };

  it("configures, probes, syncs and disables", async () => {
    const m = new MockTransport();
    expect(await m.syncGet()).toBeNull();
    expect((await m.syncStatus()).state).toBe("disabled");
    expect(await code(m.syncNow())).toBe("sync.not_configured");
    expect(await m.syncSet(settings)).toMatchObject({ bucket: "mooring-sync", deviceId: "dev-0001" });
    expect(await m.syncProbe()).toEqual({ conditionalWrites: true, error: null });
    expect(await m.syncNow()).toMatchObject({ pulled: true, pushed: true, conflicts: [] });
    expect((await m.syncStatus()).counter).toBe(1);
    await m.syncDisable({ deleteRemote: false });
    expect(await m.syncGet()).toBeNull();
  });

  it("refuses backends without conditional writes and bad settings", async () => {
    const m = new MockTransport();
    expect(await code(m.syncSet({ ...settings, bucket: "Bad_Bucket" }))).toBe("input.invalid");
    await m.syncSet({ ...settings, endpoint: "https://s3.invalid" });
    expect((await m.syncProbe()).conditionalWrites).toBe(false);
    expect(await code(m.syncNow())).toBe("sync.unsupported_backend");
  });

  it("vault_join works only on a fresh device", async () => {
    const join = { endpoint: settings.endpoint, bucket: "b-1", prefix: "team", region: "r", accessKeyId: "AKIAEXAMPLE", secretAccessKey: "x", password: "pw" };
    expect(await code(new MockTransport().vaultJoin(join))).toBe("vault.exists");
    const fresh = new MockTransport({ vault: "missing" });
    expect(await code(fresh.vaultJoin({ ...join, prefix: "empty" }))).toBe("sync.not_found");
    expect(await fresh.vaultJoin(join)).toBe("unlocked");
  });
});
