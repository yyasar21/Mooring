// ADR-0016 mock contract as rust-core E2 serves it: secret source CRUD, test, revoke, the OIDC
// window flow, and `credential_external_test` with key NAMES only. No fixture here holds a secret.
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

const input = (p: Partial<SecretSourceInput> = {}): SecretSourceInput => ({
  name: "team vault", address: "https://vault2.example.test:8200", namespace: null, authMethod: "approle", authMount: "",
  credentialId: "cr-approle", oidcRole: null, options: { caPem: null, allowHttp: false, allowedOrigins: [] }, ...p,
});
const oidc = (p: Partial<SecretSourceInput> = {}) => input({ authMethod: "oidc", authMount: "oidc", credentialId: null, oidcRole: "ops", ...p });

describe("mock · secret sources (ADR-0016, E2)", () => {
  it("creates, gets, tests, updates and deletes sources; nothing secret comes back", async () => {
    const m = new MockTransport();
    expect((await m.secretSourceList()).map((s) => s.id)).toEqual(["src-ops"]);
    const s = await m.secretSourceCreate(input());
    expect(s).toMatchObject({ kind: "vault", name: "team vault", authMount: "approle", credentialId: "cr-approle" });
    expect(await m.secretSourceGet({ id: s.id })).toEqual(s);
    expect(JSON.stringify(await m.secretSourceList())).not.toMatch(/token|secret_id|role_id/i);
    expect(await m.secretSourceTest({ id: s.id })).toEqual({ ok: true, method: "approle", ttlSeconds: 3600, renewable: true, policiesCount: 2, error: null, category: null });
    await m.secretSourceUpdate({ id: s.id, ...input({ name: "renamed", address: "https://down.invalid" }) });
    expect(await m.secretSourceTest({ id: s.id })).toMatchObject({ ok: false, error: "credential.external_unavailable", category: "network" });
    expect(m.audit.some((a) => a.event === "secret_source_changed" && a.details.changed === "name,address")).toBe(true);
    await m.secretSourceRevoke({ id: s.id });
    expect(m.audit.at(-1)?.event).toBe("secret_revoked");
    await m.secretSourceDelete({ id: s.id });
    expect(await code(m.secretSourceTest({ id: s.id }))).toBe("source.not_found");
    expect(await code(m.secretSourceGet({ id: "nope" }))).toBe("source.not_found");
  });

  it("validates addresses, mounts, the method/credential pairing and the credential kind", async () => {
    const m = new MockTransport();
    expect(await code(m.secretSourceCreate(input({ address: "http://vault.example.test" })))).toBe("input.invalid");
    expect(await code(m.secretSourceCreate(input({ address: "http://127.0.0.1:8200", options: { caPem: null, allowHttp: true, allowedOrigins: [] } })))).toBe("ok");
    expect(await code(m.secretSourceCreate(input({ address: "https://vault.example.test/v1" })))).toBe("input.invalid");
    expect(await code(m.secretSourceCreate(input({ authMethod: "oidc" })))).toBe("input.invalid");
    expect(await code(m.secretSourceCreate(input({ authMethod: "token", credentialId: null })))).toBe("input.invalid");
    expect(await code(m.secretSourceCreate(input({ authMethod: "token", authMount: "custom" })))).toBe("input.invalid");
    expect(await code(m.secretSourceCreate(input({ options: { caPem: null, allowHttp: false, allowedOrigins: ["https://idp.example.test"] } })))).toBe("input.invalid");
    // The token method needs an api_token, AppRole a vault_approle.
    expect(await code(m.secretSourceCreate(input({ authMethod: "token", credentialId: "cr-approle" })))).toBe("credential.incompatible");
    expect(await code(m.secretSourceCreate(input({ credentialId: "cr-ops" })))).toBe("credential.incompatible");
    expect(await code(m.secretSourceCreate(input({ credentialId: "cr-missing" })))).toBe("credential.not_found");
  });

  it("OIDC: begin returns a session, status goes pending → done, then the test passes", async () => {
    const m = new MockTransport();
    const s = await m.secretSourceCreate(oidc({ options: { caPem: null, allowHttp: false, allowedOrigins: ["https://idp.example.test"] } }));
    expect(await m.secretSourceTest({ id: s.id })).toMatchObject({ ok: false, category: "auth_failed" });
    const begin = await m.secretSourceOidcBegin({ id: s.id });
    expect(begin).toEqual({ sessionId: expect.stringMatching(/^oidc-/) as string, windowLabel: `oidc-${s.id}` });
    // One flow per source: a second begin returns the running session.
    expect(await m.secretSourceOidcBegin({ id: s.id })).toEqual(begin);
    expect(await m.secretSourceOidcStatus({ sessionId: begin.sessionId })).toEqual({ state: "pending", sourceId: s.id, error: null });
    await new Promise((r) => setTimeout(r, 0));
    expect((await m.secretSourceOidcStatus({ sessionId: begin.sessionId })).state).toBe("done");
    expect(await m.secretSourceTest({ id: s.id })).toMatchObject({ ok: true, method: "oidc" });
    expect(await code(m.secretSourceOidcStatus({ sessionId: "oidc-ffff" }))).toBe("session.not_found");
    expect(await code(m.secretSourceOidcBegin({ id: "src-ops" }))).toBe("input.invalid");
  });

  it("OIDC: timeout, closed, state mismatch, and a lock fail the flow", async () => {
    const m = new MockTransport();
    const s = await m.secretSourceCreate(oidc());
    for (const outcome of ["timeout", "closed", "state_mismatch"] as const) {
      m.oidcOutcome = outcome;
      const { sessionId } = await m.secretSourceOidcBegin({ id: s.id });
      await new Promise((r) => setTimeout(r, 0));
      expect(await m.secretSourceOidcStatus({ sessionId })).toEqual({ state: "failed", sourceId: s.id, error: outcome });
    }
    m.oidcOutcome = "done";
    const { sessionId } = await m.secretSourceOidcBegin({ id: s.id });
    await m.vaultLock("user");
    expect(await m.secretSourceOidcStatus({ sessionId })).toMatchObject({ state: "failed", error: "locked" });
    await new Promise((r) => setTimeout(r, 0));
    expect((await m.secretSourceOidcStatus({ sessionId })).error).toBe("locked");
    // Revoke works while locked; list does not.
    expect(await code(m.secretSourceRevoke({ id: s.id }))).toBe("ok");
    expect(await code(m.secretSourceList())).toBe("vault.locked");
  });

  it("credential_external_test returns key names only; present, missing and extra follow the field map", async () => {
    const m = new MockTransport();
    const r = await m.credentialExternalTest({ credentialId: "cr-ext" });
    expect(r).toEqual({ ok: true, version: 3, present: ["username", "password"], missing: [], extra: [], error: null, category: null });
    expect(JSON.stringify(r)).not.toMatch(/hunter|value/i);
    const legacy = await m.credentialCreate({
      name: "legacy", kind: "external_ref", secrets: {},
      fields: { provider: "vault", source: "src-ops", reference: "kv/ops/legacy", target_kind: "user_password", version: 2, field_map: { username: "user" } },
    });
    expect(legacy.fields).toEqual({ provider: "vault", source: "src-ops", reference: "kv/ops/legacy", target_kind: "user_password", version: 2, field_map: { username: "user" } });
    expect(await m.credentialExternalTest({ credentialId: legacy.id })).toEqual({ ok: false, version: 2, present: ["username"], missing: ["password"], extra: ["pass", "note"], error: null, category: null });
    await m.credentialUpdateFields({ id: legacy.id, name: "legacy", fields: { ...legacy.fields, field_map: { username: "user", password: "pass" } } });
    expect(await m.credentialExternalTest({ credentialId: legacy.id })).toMatchObject({ ok: false, present: ["username", "password"], missing: [], extra: ["note"] });
    const gone = await m.credentialCreate({ name: "gone", kind: "external_ref", secrets: {}, fields: { provider: "vault", source: "src-ops", reference: "kv/ops/gone", target_kind: "ssh_key" } });
    expect(await m.credentialExternalTest({ credentialId: gone.id })).toMatchObject({ ok: false, error: "credential.external_not_found", category: "not_found" });
    expect(await code(m.credentialExternalTest({ credentialId: "cr-ops" }))).toBe("input.invalid");
    expect(await code(m.credentialExternalTest({ credentialId: "cr-none" }))).toBe("credential.not_found");
  });

  it("external_ref fields are validated like Rust: source for Vault, reference grammar, version ≥ 1, field map caps", async () => {
    const m = new MockTransport();
    const base = { name: "x", kind: "external_ref" as const, secrets: {} };
    const bad = (fields: Record<string, unknown>) => code(m.credentialCreate({ ...base, fields: fields as never }));
    expect(await bad({ provider: "vault", reference: "kv/ops/db", target_kind: "user_password" })).toBe("input.invalid");
    expect(await bad({ provider: "vault", source: "src-ops", reference: "kv", target_kind: "user_password" })).toBe("input.invalid");
    expect(await bad({ provider: "vault", source: "src-ops", reference: "kv/../x", target_kind: "user_password" })).toBe("input.invalid");
    expect(await bad({ provider: "vault", source: "src-ops", reference: "kv/ops/db", target_kind: "user_password", version: 0 })).toBe("input.invalid");
    expect(await bad({ provider: "vault", source: "src-ops", reference: "kv/ops/db", target_kind: "user_password", version: "3" })).toBe("input.invalid");
    expect(await bad({ provider: "vault", source: "src-ops", reference: "kv/ops/db", target_kind: "user_password", field_map: { password: "" } })).toBe("input.invalid");
    expect(await bad({ provider: "onepassword", reference: "op://Infra/db/password", target_kind: "user_password" })).toBe("ok");
  });

  it("a used source cannot be deleted, and the refusal is audited", async () => {
    const m = new MockTransport();
    expect(await code(m.secretSourceDelete({ id: "src-ops" }))).toBe("source.in_use");
    expect(m.audit.at(-1)).toMatchObject({ event: "secret_refused", details: { source: "src-ops", action: "delete" } });
    await m.credentialDelete({ id: "cr-ext" });
    expect(await code(m.secretSourceDelete({ id: "src-ops" }))).toBe("ok");
  });
});
