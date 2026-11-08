// ADR-0025 picker rules and the mock's jump-host store checks (R1 `validate_via` + store).
import { MockTransport } from "./ipc.mock";
import { connectionFields } from "../stores/tree";
import { chainText, moveItem, supportsVia, viaCandidates } from "./via";
import type { ConnectionSummary } from "./ipc.types";
import { IpcError } from "./ipc.error";

const code = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
    return "ok";
  } catch (e: unknown) {
    return e instanceof IpcError ? e.code : "?";
  }
};

describe("via picker rules", () => {
  const m = new MockTransport();
  const conns = (): ConnectionSummary[] => m.connections;

  it("offers SSH connections only, never the connection itself or one already chosen", () => {
    const names = viaCandidates(conns(), "c-web01", ["c-bastion"]).map((c) => c.id);
    expect(names).not.toContain("c-web01");
    expect(names).not.toContain("c-bastion");
    expect(names).not.toContain("c-dc"); // RDP
    expect(names).not.toContain("c-kiosk"); // VNC
    expect(names).toContain("c-web02");
    for (const c of viaCandidates(conns(), null, [])) expect(c.protocol).toBe("ssh");
  });

  it("leaves out a host whose own chain goes through this connection (a loop)", () => {
    // stage-app hops through bastion01: bastion01 may not hop through stage-app.
    expect(viaCandidates(conns(), "c-bastion", []).map((c) => c.id)).not.toContain("c-stg");
  });

  it("offers nothing once three hops are chosen", () => {
    expect(viaCandidates(conns(), null, ["c-web01", "c-web02", "c-pg"])).toEqual([]);
  });

  it("writes the chain as you → hops → target and moves rows", () => {
    expect(chainText(conns(), ["c-bastion", "c-web01"], "stage-app")).toBe("you → bastion01 → web01 → stage-app");
    expect(chainText(conns(), ["c-gone"], "")).toBe("you → missing jump host → this connection");
    expect(moveItem(["a", "b", "c"], 2, -1)).toEqual(["a", "c", "b"]);
    expect(moveItem(["a", "b", "c"], 0, -1)).toEqual(["a", "b", "c"]);
    expect(supportsVia("ssh") && supportsVia("rdp") && supportsVia("vnc") && supportsVia("kubernetes")).toBe(true);
    // R6: web windows go through the chain as a SOCKS proxy on the last hop; vCenter stays refused.
    expect(supportsVia("web")).toBe(true);
    expect(supportsVia("vsphere-console")).toBe(false);
  });
});

describe("mock via store checks", () => {
  it("refuses depth 4, self, duplicates, missing, non-SSH hops, loops and vCenter", async () => {
    const m = new MockTransport();
    const web01 = m.connections.find((c) => c.id === "c-web01");
    if (!web01) throw new Error("seed");
    const f = connectionFields(web01);
    const upd = (via: string[], over: Partial<typeof f> = {}) => m.connectionUpdate({ ...f, ...over, id: "c-web01", via });
    expect(await code(upd(["c-web02", "c-pg", "c-stg", "c-bastion"]))).toBe("connection.via_invalid");
    expect(await code(upd(["c-web01"]))).toBe("connection.via_invalid");
    expect(await code(upd(["c-web02", "c-web02"]))).toBe("connection.via_invalid");
    expect(await code(upd(["c-missing"]))).toBe("connection.via_invalid");
    expect(await code(upd(["c-dc"]))).toBe("connection.via_invalid");
    const bastion = m.connections.find((c) => c.id === "c-bastion");
    if (!bastion) throw new Error("seed");
    expect(await code(m.connectionUpdate({ ...connectionFields(bastion), id: "c-bastion", via: ["c-stg"] }))).toBe("connection.via_invalid");
    const vc = m.connections.find((c) => c.id === "c-vc");
    if (!vc) throw new Error("seed");
    expect(await code(m.connectionUpdate({ ...connectionFields(vc), id: "c-vc", via: ["c-bastion"] }))).toBe("connection.via_invalid");
    // the message never echoes an id
    try {
      await upd(["c-missing"]);
    } catch (e: unknown) {
      expect((e as Error).message).not.toMatch(/c-missing/);
    }
  });

  it("keeps the chain when via is omitted and clears it with []", async () => {
    const m = new MockTransport();
    const stg = m.connections.find((c) => c.id === "c-stg");
    if (!stg) throw new Error("seed");
    const kept = await m.connectionUpdate({ ...connectionFields(stg), id: "c-stg", name: "stage-app-2" });
    expect(kept.via).toEqual(["c-bastion"]);
    const cleared = await m.connectionUpdate({ ...connectionFields(stg), id: "c-stg", via: [] });
    expect(cleared.via).toEqual([]);
  });

  it("refuses to delete a hop in use, and a folder whose hop serves a connection outside it", async () => {
    const m = new MockTransport();
    expect(await code(m.connectionDelete({ id: "c-bastion" }))).toBe("connection.in_use_as_hop");
    // web01 (Production/Web tier) hops through pg-primary (Production/Databases): deleting Databases is refused.
    const web01 = m.connections.find((c) => c.id === "c-web01");
    if (!web01) throw new Error("seed");
    await m.connectionUpdate({ ...connectionFields(web01), id: "c-web01", via: ["c-pg"] });
    expect(await code(m.folderDelete({ id: "f-db" }))).toBe("connection.in_use_as_hop");
    // a subtree that holds the whole chain cascades
    expect(await code(m.folderDelete({ id: "f-prod" }))).toBe("ok");
    expect(await code(m.connectionDelete({ id: "c-stg" }))).toBe("ok");
    expect(await code(m.connectionDelete({ id: "c-bastion" }))).toBe("connection.in_use_as_hop"); // stage-wiki (web) too
    expect(await code(m.connectionDelete({ id: "c-wiki" }))).toBe("ok");
    expect(await code(m.connectionDelete({ id: "c-bastion" }))).toBe("ok");
  });
});
