import { freshBackend } from "../test/harness";
import { useCredentials } from "./credentials";

describe("credentials store", () => {
  beforeEach(() => {
    freshBackend();
  });

  it("lists metadata only", async () => {
    await useCredentials.getState().load();
    const items = useCredentials.getState().items;
    expect(items).toHaveLength(3);
    for (const c of items) {
      expect(Object.keys(c).sort()).toEqual(["createdAt", "id", "kind", "name", "updatedAt", "username"]);
    }
  });

  it("creates a credential and keeps no secret in state", async () => {
    await useCredentials.getState().load();
    const meta = await useCredentials.getState().create({
      name: "test key",
      kind: "password",
      username: "tester",
      secret: "fixture-value-not-a-secret",
      secret2: null,
    });
    expect(meta?.name).toBe("test key");
    expect(JSON.stringify(useCredentials.getState())).not.toContain("fixture-value-not-a-secret");
  });

  it("records the clipboard clear deadline from the Rust answer and expires it", async () => {
    const ok = await useCredentials.getState().copyPassword("cr-ops", 1_000);
    expect(ok).toBe(true);
    expect(useCredentials.getState().copiedUntil["cr-ops"]).toBe(31_000);
    useCredentials.getState().expireCopies(30_999);
    expect(useCredentials.getState().copiedUntil["cr-ops"]).toBe(31_000);
    useCredentials.getState().expireCopies(31_000);
    expect(useCredentials.getState().copiedUntil["cr-ops"]).toBeUndefined();
  });

  it("reports unknown credentials", async () => {
    expect(await useCredentials.getState().copyPassword("nope")).toBe(false);
    expect(useCredentials.getState().error).toMatch(/not found/);
  });

  it("updates metadata and deletes", async () => {
    await useCredentials.getState().load();
    expect(await useCredentials.getState().updateMeta("cr-deploy", "deploy", "ci")).toBe(true);
    expect(useCredentials.getState().items.find((c) => c.id === "cr-deploy")?.username).toBe("ci");
    expect(await useCredentials.getState().remove("cr-deploy")).toBe(true);
    expect(useCredentials.getState().items).toHaveLength(2);
  });
});
