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
      tags: [],
    });
    expect(c?.effectiveCredentialId).toBe("cr-ops");
    expect(await useTree.getState().renameConnection(c?.id ?? "", "web03-new")).toBe(true);
    expect(useTree.getState().connections.find((x) => x.id === c?.id)?.name).toBe("web03-new");
  });

  it("searches through connection_search", async () => {
    const hits = await useTree.getState().search("kiosk");
    expect(hits[0]?.name).toBe("lobby-kiosk");
  });
});
