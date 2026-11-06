// The mock side of ADR-0019 (I1): formats, picks, preview rules (opt-ins, duplicates, key files),
// plan lifetime, apply into a new root folder, discard. No secret exists anywhere in the mock.
import { IpcError } from "./ipc.error";
import { MockTransport } from "./ipc.mock";
import { IMPORT_PLAN_MAX } from "./ipc.mock.import";
import { IMPORT_FORMATS, type ImportFormat } from "./ipc.types.import";

const code = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
    return "ok";
  } catch (e: unknown) {
    return e instanceof IpcError ? e.code : "not-ipc";
  }
};

async function previewOf(mock: MockTransport, format: ImportFormat, opts: { secrets?: boolean; keys?: boolean } = {}) {
  const pick = await mock.importPick({ format });
  if (!pick) throw new Error("cancelled");
  return mock.importPreview({ source: { pickId: pick.pickId }, includePlaintextSecrets: opts.secrets ?? false, importKeyFiles: opts.keys ?? false });
}

describe("MockImportBase", () => {
  it("lists the six formats with labels, filters and known locations", async () => {
    const mock = new MockTransport();
    const rows = await mock.importFormats();
    expect(rows.map((r) => r.format)).toEqual(IMPORT_FORMATS);
    expect(rows.find((r) => r.format === "openssh")).toEqual({ format: "openssh", label: "OpenSSH config", extensions: [], knownLocation: "openssh", secretsPossible: true });
    expect(rows.find((r) => r.format === "putty")?.knownLocation).toBe("putty");
    expect(rows.filter((r) => r.secretsPossible).map((r) => r.format)).toEqual(["termius", "openssh"]);
  });

  it("picks the demo file, honours a queued name or a cancel, and gates on the vault", async () => {
    const mock = new MockTransport();
    expect(await mock.importPick({ format: "royal_ts" })).toMatchObject({ fileName: "ops-team.rtsz", size: 48_213 });
    mock.importPicks.push({ fileName: "mine.rtsx", size: 12 }, null);
    expect(await mock.importPick({ format: "royal_ts" })).toMatchObject({ fileName: "mine.rtsx", size: 12 });
    expect(await mock.importPick({ format: "royal_ts" })).toBeNull();
    const locked = new MockTransport({ vault: "locked" });
    expect(await code(locked.importPick({ format: "putty" }))).toBe("vault.locked");
    expect(await code(locked.importPreview({ source: { known: "openssh" }, includePlaintextSecrets: false, importKeyFiles: false }))).toBe("vault.locked");
    expect(await locked.importFormats()).toHaveLength(6); // static, not gated
  });

  it("previews every format with a plan id, counts that match the lists, and no secret field", async () => {
    const mock = new MockTransport();
    for (const format of IMPORT_FORMATS) {
      const p = await previewOf(mock, format);
      expect(p.format).toBe(format);
      expect(p.planId).toMatch(/^plan-/);
      expect(p.rootName).toMatch(/^Imported from .+ \(\d{4}-\d{2}-\d{2}\)$/);
      expect(p.counts.folders).toBe(p.items.filter((i) => i.kind === "folder").length);
      expect(p.counts.connections).toBe(p.items.filter((i) => i.kind === "connection").length);
      expect(p.counts.credentials).toBe(p.credentials.length);
      expect(p.counts.skipped).toBe(p.skipped.length);
      expect(p.counts.warnings).toBe(p.warnings.length);
      expect(JSON.stringify(p)).not.toMatch(/secret"?:\s*"[^"]+"|password"?:\s*"/i);
      for (const c of p.credentials) expect(Object.keys(c).sort()).toEqual(["hasSecret", "key", "kind", "name"]);
    }
  });

  it("flags duplicates against the store by protocol, host, port and user", async () => {
    const mock = new MockTransport();
    const p = await previewOf(mock, "royal_ts");
    expect(p.items.find((i) => i.name === "web01")?.duplicateOf).toBe("c-web01");
    expect(p.items.find((i) => i.name === "cache01")?.duplicateOf).toBeUndefined();
    const t = await previewOf(mock, "termius", { secrets: true });
    // pg01:2222 as deploy matches c-pg (credential cr-deploy, username deploy)
    expect(t.items.find((i) => i.name === "pg-primary")?.duplicateOf).toBe("c-pg");
  });

  it("drops plaintext secrets to prompt credentials unless opted in (Termius)", async () => {
    const mock = new MockTransport();
    const off = await previewOf(mock, "termius");
    expect(off.credentials.every((c) => !c.hasSecret)).toBe(true);
    expect(off.credentials.filter((c) => c.kind === "prompt")).toHaveLength(3);
    expect(off.warnings.filter((w) => w.code === "password_dropped")).toHaveLength(2);
    expect(off.counts.secrets).toBe(0);
    const on = await previewOf(mock, "termius", { secrets: true });
    expect(on.credentials.map((c) => [c.kind, c.hasSecret])).toEqual([["user_password", true], ["ssh_key", true], ["prompt", false]]);
    expect(on.counts.secrets).toBe(2);
    expect(on.warnings.some((w) => w.code === "password_dropped")).toBe(false);
  });

  it("never carries an mRemoteNG password: every credential is a prompt", async () => {
    const mock = new MockTransport();
    const p = await previewOf(mock, "mremoteng", { secrets: true });
    expect(p.credentials.every((c) => c.kind === "prompt" && !c.hasSecret)).toBe(true);
    expect(p.warnings.filter((w) => w.code === "password_dropped").length).toBeGreaterThan(0);
  });

  it("reads OpenSSH from the known location; key files only with the opt-in", async () => {
    const mock = new MockTransport();
    const agent = await mock.importPreview({ source: { known: "openssh" }, includePlaintextSecrets: false, importKeyFiles: false });
    expect(agent.format).toBe("openssh");
    expect(agent.credentials.filter((c) => c.kind === "ssh_agent")).toHaveLength(2);
    expect(agent.skipped).toEqual([]);
    const keys = await mock.importPreview({ source: { known: "openssh" }, includePlaintextSecrets: false, importKeyFiles: true });
    expect(keys.credentials.map((c) => [c.kind, c.hasSecret])).toEqual([["ssh_key", true], ["ssh_agent", false], ["prompt", false]]);
    expect(keys.skipped).toEqual([{ sourceRef: "deploy · id_rsa_old", reason: "key_unreadable" }]);
    expect(keys.warnings.map((w) => w.code)).toEqual(["host_pattern", "match_block", "include_ignored", "proxy_jump"]);
    mock.importKnown.openssh = false;
    expect(await code(mock.importPreview({ source: { known: "openssh" }, includePlaintextSecrets: false, importKeyFiles: false }))).toBe("import.not_found");
    expect(mock.audit.at(-1)).toMatchObject({ event: "import_refused", details: { code: "import.not_found" } });
  });

  it("refuses with the parser's code, audited without the file name", async () => {
    const mock = new MockTransport();
    mock.importPicks.push({ fileName: "locked.rtsz", error: "import.encrypted" }, { fileName: "bomb.xml", error: "import.doctype" });
    expect(await code(previewOf(mock, "royal_ts"))).toBe("import.encrypted");
    expect(await code(previewOf(mock, "mremoteng"))).toBe("import.doctype");
    expect(JSON.stringify(mock.audit)).not.toContain("locked.rtsz");
    expect(mock.audit.filter((a) => a.event === "import_refused")).toHaveLength(2);
  });

  it("a pick is single use", async () => {
    const mock = new MockTransport();
    const pick = await mock.importPick({ format: "putty" });
    const src = { source: { pickId: pick?.pickId ?? "" }, includePlaintextSecrets: false, importKeyFiles: false };
    await mock.importPreview(src);
    expect(await code(mock.importPreview(src))).toBe("input.invalid");
  });

  it("applies into a new root folder under the top folder, skipping duplicates by default", async () => {
    const mock = new MockTransport();
    const p = await previewOf(mock, "royal_ts");
    const before = { folders: mock.folders.length, connections: mock.connections.length, creds: mock.creds.items.length };
    const r = await mock.importApply({ planId: p.planId, exclude: [] });
    expect(r).toEqual({ rootFolderId: expect.stringMatching(/^f-imp-/) as string, folders: 3, connections: 4, credentials: 2, secrets: 0, skipped: 2 });
    const root = mock.folders.find((f) => f.id === r.rootFolderId);
    expect(root).toMatchObject({ parentId: "f-root", name: p.rootName });
    expect(mock.folders.length - before.folders).toBe(4);
    expect(mock.connections.length - before.connections).toBe(4);
    expect(mock.creds.items.length - before.creds).toBe(2);
    expect(mock.connections.some((c) => c.name === "web01" && c.folderId !== "f-web")).toBe(false); // the duplicate stayed out
    const linux = mock.folders.find((f) => f.name === "Linux");
    expect(mock.folders.find((f) => f.id === linux?.parentId)?.name).toBe("Datacenter A");
    expect(mock.connections.find((c) => c.name === "cache01")?.folderId).toBe(linux?.id);
    expect(mock.audit.at(-1)).toMatchObject({ event: "import_applied", details: { format: "royal_ts", connections: "4", skipped: "2" } });
    // a plan is single use
    expect(await code(mock.importApply({ planId: p.planId, exclude: [] }))).toBe("import.plan_expired");
  });

  it("imports duplicates on request, lifts the children of an excluded folder, unlinks an excluded credential", async () => {
    const mock = new MockTransport();
    const p = await previewOf(mock, "royal_ts");
    const r = await mock.importApply({ planId: p.planId, exclude: ["f2", "k2", "c4"], duplicates: "import" });
    expect(r).toMatchObject({ folders: 2, connections: 4, credentials: 1, skipped: 4 });
    const dc = mock.folders.find((f) => f.name === "Datacenter A");
    expect(mock.folders.some((f) => f.name === "Linux")).toBe(false);
    expect(mock.connections.find((c) => c.name === "cache01")?.folderId).toBe(dc?.id); // lifted from Linux
    expect(mock.connections.find((c) => c.name === "fs01")?.credentialId).toBeNull(); // k2 excluded
    expect(mock.connections.filter((c) => c.name === "web01")).toHaveLength(2); // duplicate imported
    expect(mock.connections.some((c) => c.name === "lobby display")).toBe(false);
  });

  it("writes secrets only with the opt-in and never an unreferenced prompt credential", async () => {
    const mock = new MockTransport();
    const p = await previewOf(mock, "termius", { secrets: true });
    const r = await mock.importApply({ planId: p.planId, exclude: ["c2"] });
    // c2 excluded, web01 and pg-primary duplicates: the prompt credential k3 is unreferenced and not written;
    // the ssh_key k2 holds a secret and is kept even without a connection.
    expect(r).toMatchObject({ credentials: 2, secrets: 2, skipped: 4 });
    const added = mock.creds.items.filter((c) => c.id.startsWith("cr-imp"));
    expect(added.map((c) => [c.kind, c.secretNames])).toEqual([["user_password", ["password"]], ["ssh_key", ["private_key"]]]);
  });

  it("plans expire, are capped, are dropped by a lock, and discard is silent", async () => {
    const mock = new MockTransport();
    const p = await previewOf(mock, "putty");
    mock.expireImportPlans();
    expect(await code(mock.importApply({ planId: p.planId, exclude: [] }))).toBe("import.plan_expired");
    await mock.importDiscard({ planId: "nope" });
    for (let i = 0; i < IMPORT_PLAN_MAX; i++) await previewOf(mock, "putty");
    expect(await code(previewOf(mock, "putty"))).toBe("import.limits");
    await mock.vaultLock("user");
    expect(mock.importPlans.size).toBe(0);
    await mock.vaultUnlock("correct horse battery");
    const q = await previewOf(mock, "rdm");
    await mock.importDiscard({ planId: q.planId });
    expect(await code(mock.importApply({ planId: q.planId, exclude: [] }))).toBe("import.plan_expired");
  });
});
