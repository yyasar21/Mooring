import { freshBackend } from "../test/harness";
import { copyKey, useCredentials } from "./credentials";

describe("credentials store", () => {
  beforeEach(() => {
    freshBackend();
  });

  it("lists metadata only and loads the kind table", async () => {
    await useCredentials.getState().load();
    const { items, kinds } = useCredentials.getState();
    expect(items.length).toBeGreaterThan(3);
    expect(kinds).toHaveLength(15);
    for (const c of items) {
      expect(Object.keys(c).sort()).toEqual(["createdAt", "fields", "fingerprint", "id", "kind", "name", "secretNames", "updatedAt"]);
    }
  });

  it("creates a credential and keeps no secret in state", async () => {
    await useCredentials.getState().load();
    const meta = await useCredentials.getState().create({
      name: "test key",
      kind: "user_password",
      fields: { username: "tester" },
      secrets: { password: "fixture-value-not-a-secret" },
    });
    expect(meta?.name).toBe("test key");
    expect(meta?.secretNames).toEqual(["password"]);
    expect(JSON.stringify(useCredentials.getState())).not.toContain("fixture-value-not-a-secret");
  });

  it("records the clipboard clear deadline per secret name and expires it", async () => {
    await useCredentials.getState().load();
    const ok = await useCredentials.getState().copySecret("cr-ops", "passphrase", 1_000);
    expect(ok).toBe(true);
    const key = copyKey("cr-ops", "passphrase");
    expect(useCredentials.getState().copiedUntil[key]).toBe(31_000);
    useCredentials.getState().expireCopies(30_999);
    expect(useCredentials.getState().copiedUntil[key]).toBe(31_000);
    useCredentials.getState().expireCopies(31_000);
    expect(useCredentials.getState().copiedUntil[key]).toBeUndefined();
  });

  it("refuses to copy a secret that is not copyable or not stored", async () => {
    expect(await useCredentials.getState().copySecret("cr-ops", "private_key")).toBe(false);
    expect(useCredentials.getState().error).toMatch(/cannot be copied/);
    expect(await useCredentials.getState().copySecret("nope", "password")).toBe(false);
    expect(useCredentials.getState().error).toMatch(/not found/);
  });

  it("updates fields, replaces and clears secrets, and deletes", async () => {
    await useCredentials.getState().load();
    expect(await useCredentials.getState().updateFields("cr-deploy", "deploy", { username: "ci" })).toBe(true);
    expect(useCredentials.getState().items.find((c) => c.id === "cr-deploy")?.fields.username).toBe("ci");
    expect(await useCredentials.getState().replaceSecrets("cr-deploy", {}, ["otp_seed"])).toBe(true);
    expect(useCredentials.getState().items.find((c) => c.id === "cr-deploy")?.secretNames).toEqual(["password"]);
    expect(await useCredentials.getState().replaceSecrets("cr-deploy", {}, ["password"])).toBe(false);
    expect(useCredentials.getState().error).toMatch(/cannot be cleared/);
    const before = useCredentials.getState().items.length;
    expect(await useCredentials.getState().remove("cr-deploy")).toBe(true);
    expect(useCredentials.getState().items).toHaveLength(before - 1);
  });
});
