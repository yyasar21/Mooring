import { freshBackend } from "../test/harness";
import { folderPath, useTree, visibleRows } from "./tree";

describe("tree store", () => {
  beforeEach(() => {
    freshBackend();
  });

  it("loads folders and connections from the transport", async () => {
    await useTree.getState().load();
    const s = useTree.getState();
    expect(s.loaded).toBe(true);
    expect(s.folders.length).toBe(6);
    expect(s.connections.some((c) => c.host === "web01.example.test")).toBe(true);
  });

  it("flattens visible rows and hides collapsed children", async () => {
    await useTree.getState().load();
    const { folders, connections } = useTree.getState();
    const all = visibleRows(folders, connections, {});
    expect(all[0]?.ref).toEqual({ kind: "folder", id: "f-root" });
    expect(all.find((r) => r.ref.id === "c-web01")?.depth).toBe(3);
    useTree.getState().toggle("f-prod");
    const fewer = visibleRows(folders, connections, useTree.getState().collapsed);
    expect(fewer.some((r) => r.ref.id === "c-web01")).toBe(false);
    expect(fewer.length).toBeLessThan(all.length);
  });

  it("creates, renames and moves folders, reloading after each", async () => {
    await useTree.getState().load();
    const f = await useTree.getState().createFolder("f-root", "Edge");
    expect(f?.name).toBe("Edge");
    expect(await useTree.getState().renameFolder(f?.id ?? "", "Edge sites")).toBe(true);
    expect(await useTree.getState().moveFolder(f?.id ?? "", "f-prod")).toBe(true);
    const { folders } = useTree.getState();
    expect(folderPath(folders, f?.id ?? null)).toEqual(["Production", "Edge sites"]);
  });

  it("surfaces backend errors without throwing", async () => {
    await useTree.getState().load();
    expect(await useTree.getState().moveFolder("f-prod", "f-db")).toBe(false);
    expect(useTree.getState().error).toMatch(/itself/);
    expect(await useTree.getState().deleteFolder("f-root")).toBe(false);
  });

  it("creates and renames a connection and keeps inherited credentials", async () => {
    await useTree.getState().load();
    const c = await useTree.getState().createConnection({
      folderId: "f-web",
      name: "web03",
      protocol: "ssh",
      host: "web03.example.test",
      port: null,
      credentialId: null,
      usernameOverride: "root",
      domainOverride: null,
      gatewayCredentialId: null,
      becomeCredentialId: "cr-sudo",
      tags: [],
    });
    expect(c?.effectiveCredentialId).toBe("cr-ops");
    expect(await useTree.getState().renameConnection(c?.id ?? "", "web03-new")).toBe(true);
    const renamed = useTree.getState().connections.find((x) => x.id === c?.id);
    expect(renamed).toMatchObject({ name: "web03-new", usernameOverride: "root", becomeCredentialId: "cr-sudo" });
  });

  it("refuses an incompatible credential with credential.incompatible", async () => {
    await useTree.getState().load();
    const base = useTree.getState().connections.find((x) => x.id === "c-dc");
    expect(base).toBeDefined();
    if (!base) return;
    const ok = await useTree.getState().updateConnection("c-dc", { ...base, credentialId: "cr-ops" });
    expect(ok).toBeNull();
    expect(useTree.getState().error).toMatch(/SSH key is for SSH/);
    // a domain override on an SSH key is not applicable
    const web = useTree.getState().connections.find((x) => x.id === "c-web01");
    if (!web) return;
    expect(await useTree.getState().updateConnection("c-web01", { ...web, domainOverride: "CORP" })).toBeNull();
    expect(useTree.getState().error).toMatch(/no domain to override/);
  });

  it("searches through connection_search", async () => {
    const hits = await useTree.getState().search("kiosk");
    expect(hits[0]?.name).toBe("lobby-kiosk");
  });
});
