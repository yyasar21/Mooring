// The mock side of ADR-0019 §4 (I2): argument checks in Rust's order, the native trust dialog's
// outcomes, bind success / refusal and its audit row, the AD and OpenLDAP mappings, scope and
// filter, the size cap, and that the plan is held and applied like a file plan. Nothing about the
// bind name, the DN or an entry ever reaches the audit log.
import { IpcError } from "./ipc.error";
import { MockTransport } from "./ipc.mock";
import type { LdapImportPreviewArgs } from "./ipc.types.import";

const code = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
    return "ok";
  } catch (e: unknown) {
    return e instanceof IpcError ? e.code : "not-ipc";
  }
};

const BASE = "DC=example,DC=test";
const ok = (over: Partial<LdapImportPreviewArgs> = {}): LdapImportPreviewArgs => ({ url: "ldaps://dc01.example.test", baseDn: BASE, kind: "ad", credentialId: "cr-ad", ...over });

describe("MockImportBase · ldap_import_test", () => {
  it("binds as the credential's account and reports host, port and bind name", async () => {
    const mock = new MockTransport();
    expect(await mock.ldapImportTest(ok())).toEqual({ host: "dc01.example.test", port: 636, boundAs: "EXAMPLE\\admin" });
    expect(await mock.ldapImportTest(ok({ url: "ldaps://DC02.example.test:3269/", credentialId: "cr-deploy" }))).toEqual({ host: "dc02.example.test", port: 3269, boundAs: "deploy" });
    const bind = mock.audit.filter((a) => a.event === "ldap_bind");
    expect(bind.map((a) => a.details)).toEqual([{ host: "dc01.example.test:636", success: "true" }, { host: "dc02.example.test:3269", success: "true" }]);
    expect(JSON.stringify(mock.audit)).not.toMatch(/admin|deploy|DC=example/);
  });

  it("checks the arguments in Rust's order and audits only the code", async () => {
    const mock = new MockTransport();
    expect(await code(mock.ldapImportTest(ok({ url: "ldap://dc01.example.test" })))).toBe("ldap.insecure");
    expect(await code(mock.ldapImportTest(ok({ url: "ldapi:///" })))).toBe("ldap.insecure");
    expect(await code(mock.ldapImportTest(ok({ url: "ldaps://user@dc01.example.test" })))).toBe("ldap.invalid");
    expect(await code(mock.ldapImportTest(ok({ url: "ldaps://dc01.example.test/ou=x" })))).toBe("ldap.invalid");
    expect(await code(mock.ldapImportTest(ok({ url: "https://dc01.example.test" })))).toBe("ldap.invalid");
    expect(await code(mock.ldapImportTest(ok({ baseDn: "" })))).toBe("ldap.dn_invalid");
    expect(await code(mock.ldapImportTest(ok({ baseDn: "not a dn" })))).toBe("ldap.dn_invalid");
    expect(await code(mock.ldapImportTest(ok({ credentialId: "cr-none" })))).toBe("credential.not_found");
    expect(await code(mock.ldapImportTest(ok({ credentialId: "cr-ops" })))).toBe("credential.incompatible"); // ssh_key
    expect(await code(mock.ldapImportTest(ok({ credentialId: "cr-prompt" })))).toBe("credential.incompatible");
    expect(await code(mock.ldapImportTest(ok({ caPem: "x".repeat(64 * 1024 + 1) })))).toBe("input.invalid");
    expect(await code(mock.ldapImportTest({ ...ok(), kind: "nis" as "ad" }))).toBe("input.invalid");
    expect(mock.audit.filter((a) => a.event === "import_refused").map((a) => a.details.code)).toEqual([
      "ldap.insecure", "ldap.insecure", "ldap.invalid", "ldap.invalid", "ldap.invalid", "ldap.dn_invalid", "ldap.dn_invalid",
      "credential.not_found", "credential.incompatible", "credential.incompatible", "input.invalid", "input.invalid",
    ]);
    expect(mock.audit.some((a) => a.event === "ldap_bind")).toBe(false); // nothing reached the server
    const locked = new MockTransport({ vault: "locked" });
    expect(await code(locked.ldapImportTest(ok()))).toBe("vault.locked");
    expect(await code(locked.ldapImportPreview(ok()))).toBe("vault.locked");
  });

  it("refuses a wrong credential with ldap.bind and audits the failed bind", async () => {
    const mock = new MockTransport();
    expect(await code(mock.ldapImportTest(ok({ credentialId: "cr-legacy" })))).toBe("ldap.bind");
    expect(mock.audit.at(-2)?.details).toEqual({ host: "dc01.example.test:636", success: "false" });
    expect(mock.audit.at(-1)?.details).toEqual({ code: "ldap.bind" });
    mock.ldapRejects.add("cr-ad");
    expect(await code(mock.ldapImportPreview(ok()))).toBe("ldap.bind");
  });

  it("runs the native trust dialog once per host, pins on trust, refuses on reject, and reports a missing dialog", async () => {
    const mock = new MockTransport();
    mock.ldapTrust.push("reject", "no_dialog", "trust");
    expect(await code(mock.ldapImportTest(ok()))).toBe("http.trust_rejected");
    expect(await code(mock.ldapImportTest(ok()))).toBe("http.trust_prompt");
    expect(await code(mock.ldapImportTest(ok()))).toBe("ok");
    expect(await code(mock.ldapImportTest(ok()))).toBe("ok"); // pinned: no dialog
    expect(mock.ldapTrust).toEqual([]);
    expect(mock.ldapPinned.has("dc01.example.test:636")).toBe(true);
    expect(mock.audit.filter((a) => a.event === "cert_decision").map((a) => a.details)).toEqual([
      { protocol: "ldap", host: "dc01.example.test:636", decision: "rejected" },
      { protocol: "ldap", host: "dc01.example.test:636", decision: "trusted" },
    ]);
    // An extra CA that signs the certificate: accepted without a prompt and not pinned.
    mock.ldapTrust.push("reject");
    expect(await code(mock.ldapImportTest(ok({ url: "ldaps://dc09.example.test", caPem: "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----" })))).toBe("ok");
    expect(mock.ldapPinned.has("dc09.example.test:636")).toBe(false);
    expect(mock.ldapTrust).toEqual(["reject"]);
  });

  it("F2 (L-43): the first bind of a pair asks in the sign-in dialog; a refusal never binds; confirmed pairs last until lock", async () => {
    const mock = new MockTransport();
    mock.ldapSignIn.push("decline", "no_dialog", "confirm");
    expect(await code(mock.ldapImportTest(ok()))).toBe("ldap.bind_declined");
    expect(mock.audit.at(-2)).toMatchObject({ event: "confirm_refused", details: { kind: "ldap_bind", target: "dc01.example.test:636", reason: "declined" } });
    expect(mock.audit.at(-1)?.details).toEqual({ code: "ldap.bind_declined" });
    expect(await code(mock.ldapImportPreview(ok()))).toBe("ldap.confirm_required");
    expect(mock.audit.filter((a) => a.event === "ldap_bind")).toHaveLength(0); // the password never left
    expect(await code(mock.ldapImportTest(ok()))).toBe("ok");
    expect(mock.ldapSignIn).toEqual([]);
    expect(mock.ldapConfirmed.has("cr-ad@dc01.example.test:636")).toBe(true);
    // Remembered per (credential, host:port): the same pair is silent, another credential or host asks again.
    mock.ldapSignIn.push("decline");
    expect(await code(mock.ldapImportPreview(ok()))).toBe("ok");
    expect(mock.ldapSignIn).toEqual(["decline"]);
    expect(await code(mock.ldapImportTest(ok({ credentialId: "cr-deploy" })))).toBe("ldap.bind_declined");
    mock.ldapSignIn.push("decline");
    expect(await code(mock.ldapImportTest(ok({ url: "ldaps://dc02.example.test" })))).toBe("ldap.bind_declined");
    // The certificate dialog comes first (trust → confirm → bind): a rejected certificate never reaches the sign-in.
    mock.ldapTrust.push("reject");
    mock.ldapSignIn.push("decline");
    expect(await code(mock.ldapImportTest(ok({ url: "ldaps://dc03.example.test" })))).toBe("http.trust_rejected");
    expect(mock.ldapSignIn).toEqual(["decline"]);
    mock.ldapSignIn.length = 0;
    // Lock drops every confirmed pair; the next bind asks again.
    await mock.vaultLock("user");
    expect(mock.ldapConfirmed.size).toBe(0);
    await mock.vaultUnlock("correct horse battery");
    mock.ldapSignIn.push("decline");
    expect(await code(mock.ldapImportTest(ok()))).toBe("ldap.bind_declined");
    expect(JSON.stringify(mock.audit)).not.toMatch(/admin|DC=example|password/);
  });

  it("fakes transport faults before the bind", async () => {
    const mock = new MockTransport();
    mock.ldapFaults.push("ldap.unavailable", "ldap.timeout", "http.tls");
    expect(await code(mock.ldapImportTest(ok()))).toBe("ldap.unavailable");
    expect(await code(mock.ldapImportPreview(ok()))).toBe("ldap.timeout");
    expect(await code(mock.ldapImportTest(ok()))).toBe("http.tls");
    expect(await code(mock.ldapImportTest(ok()))).toBe("ok");
  });
});

describe("MockImportBase · ldap_import_preview", () => {
  it("maps the AD forest: OUs to folders (cut at 8), Windows to RDP, one prompt credential, duplicates, the stale account", async () => {
    const mock = new MockTransport();
    const p = await mock.ldapImportPreview(ok());
    expect(p.format).toBe("ldap");
    expect(p.rootName).toMatch(/^Imported from LDAP directory \(\d{4}-\d{2}-\d{2}\)$/);
    expect(p.counts).toEqual({ folders: 12, connections: 8, credentials: 1, secrets: 0, skipped: 1, warnings: 1 });
    const folders = p.items.filter((i) => i.kind === "folder");
    expect(folders.slice(0, 4).map((f) => [f.name, f.parent])).toEqual([["Servers", null], ["Web", "f1"], ["Database", "f1"], ["Workstations", null]]);
    expect(folders.filter((f) => f.name === "Old")).toHaveLength(0); // the ninth level was cut
    expect(folders.map((f) => f.name)).toContain("Bay-4");
    const conns = p.items.filter((i) => i.kind === "connection");
    expect(conns.map((c) => [c.name, c.protocol, c.host])).toEqual([
      ["DC01", "rdp", "dc01.example.test"], ["FS01", "rdp", "fs01.example.test"], ["WEB01", "ssh", "web01.example.test"], ["WEB03", "ssh", "web03.example.test"],
      ["PG02", "ssh", "pg02.example.test"], ["WS-OPS-01", "rdp", "ws-ops-01.example.test"], ["WS-DEV-02", "rdp", "ws-dev-02.example.test"],
      ["LEGACY-01", "rdp", "legacy-01.example.test"],
    ]);
    for (const c of conns) {
      expect(c.port).toBeUndefined();
      expect(c.username).toBeUndefined();
      expect(c.credentialKey).toBe("k-dir");
    }
    expect(conns.find((c) => c.name === "LEGACY-01")?.parent).toBe(folders.find((f) => f.name === "Bay-4")?.key);
    // dc01 in the store inherits the Desktops folder's domain credential (user admin), so it is no duplicate of a user-less entry.
    expect(conns.filter((c) => c.duplicateOf !== undefined).map((c) => [c.name, c.duplicateOf])).toEqual([["WEB01", "c-web01"]]);
    expect(p.credentials).toEqual([{ key: "k-dir", name: "Directory account (example.test)", kind: "prompt", hasSecret: false }]);
    expect(p.skipped).toEqual([{ sourceRef: "entry 8", reason: "invalid" }]); // no dNSHostName; never a DN
    expect(p.warnings).toEqual([{ code: "path_truncated", sourceRef: "entry 9" }]);
    expect(mock.importPlans.size).toBe(1);
    expect(mock.audit.filter((a) => a.event === "import_previewed").map((a) => a.details)).toEqual([{ format: "ldap" }]);
    expect(JSON.stringify(mock.audit)).not.toMatch(/DC=|OU=|dc01\.example\.test"|admin/);
  });

  it("narrows by base DN, one level, and the plain-text name filter", async () => {
    const mock = new MockTransport();
    const servers = await mock.ldapImportPreview(ok({ baseDn: `OU=Servers,${BASE}` }));
    expect(servers.items.filter((i) => i.kind === "folder").map((f) => f.name)).toEqual(["Web", "Database"]);
    expect(servers.counts.connections).toBe(5);
    const one = await mock.ldapImportPreview(ok({ baseDn: `ou=servers,${BASE}`, scope: "one" }));
    expect(one.items.map((i) => i.name)).toEqual(["DC01", "FS01"]);
    const web = await mock.ldapImportPreview(ok({ filter: "WEB" }));
    expect(web.items.filter((i) => i.kind === "connection").map((i) => i.name)).toEqual(["WEB01", "WEB03"]);
    expect(web.items.filter((i) => i.kind === "folder").map((f) => f.name)).toEqual(["Servers", "Web"]);
    const none = await mock.ldapImportPreview(ok({ filter: "*)(objectClass=*" })); // escaped, not interpreted
    expect(none.counts).toEqual({ folders: 0, connections: 0, credentials: 0, secrets: 0, skipped: 0, warnings: 0 });
    expect(await code(mock.ldapImportPreview(ok({ baseDn: "DC=corp,DC=example,DC=test" })))).toBe("ldap.dn_invalid"); // rc 32
    expect(await code(mock.ldapImportPreview(ok({ baseDn: `OU=Nowhere,${BASE}` })))).toBe("ldap.dn_invalid");
    expect(await code(mock.ldapImportPreview(ok({ scope: "all" as "sub" })))).toBe("input.invalid");
    expect(await code(mock.ldapImportPreview(ok({ filter: "x".repeat(257) })))).toBe("input.invalid");
    expect(await code(mock.ldapImportPreview(ok({ filter: "a\u0000b" })))).toBe("input.invalid");
  });

  it("reads ipHost / device objects as OpenLDAP and falls back to the address", async () => {
    const mock = new MockTransport();
    const p = await mock.ldapImportPreview(ok({ kind: "openldap", credentialId: "cr-deploy" }));
    expect(p.items.map((i) => [i.kind, i.name, i.host ?? null, i.protocol ?? null])).toEqual([
      ["folder", "Lab", null, null], ["connection", "lab-nas", "203.0.113.20", "ssh"], ["connection", "lab-switch", "203.0.113.21", "ssh"],
    ]);
    expect(p.credentials[0]?.name).toBe("Directory account");
  });

  it("stops with ldap.size_limit past the cap, clamps above 5000 and refuses 0", async () => {
    const mock = new MockTransport();
    expect(await code(mock.ldapImportPreview(ok({ sizeLimit: 3 })))).toBe("ldap.size_limit");
    expect(mock.audit.at(-1)?.details).toEqual({ code: "ldap.size_limit" });
    expect(mock.importPlans.size).toBe(0);
    expect(await code(mock.ldapImportPreview(ok({ sizeLimit: 8 })))).toBe("ldap.size_limit"); // nine entries match, the stale one included
    expect((await mock.ldapImportPreview(ok({ sizeLimit: 9 }))).counts.connections).toBe(8);
    expect((await mock.ldapImportPreview(ok({ sizeLimit: 99_999 }))).counts.connections).toBe(8);
    expect(await code(mock.ldapImportPreview(ok({ sizeLimit: 0 })))).toBe("ldap.invalid");
    expect(await code(mock.ldapImportPreview(ok({ sizeLimit: 1.5 })))).toBe("input.invalid");
  });

  it("holds the plan like a file plan: apply writes the OUs and the shared prompt once, discard drops it", async () => {
    const mock = new MockTransport();
    const p = await mock.ldapImportPreview(ok({ baseDn: `OU=Servers,${BASE}` }));
    const r = await mock.importApply({ planId: p.planId, exclude: [], duplicates: "skip" });
    expect(r).toMatchObject({ folders: 2, connections: 4, credentials: 1, secrets: 0, skipped: 1 }); // WEB01 is the duplicate
    const root = mock.folders.find((f) => f.id === r.rootFolderId);
    expect(root?.name).toMatch(/^Imported from LDAP directory/);
    const prompt = (await mock.credentialList()).filter((c) => c.name === "Directory account (example.test)");
    expect(prompt).toHaveLength(1);
    expect(prompt[0]?.kind).toBe("prompt");
    expect(mock.connections.filter((c) => c.credentialId === prompt[0]?.id).map((c) => c.name)).toEqual(["DC01", "FS01", "WEB03", "PG02"]);
    expect(mock.audit.at(-1)?.details.format).toBe("ldap");
    const q = await mock.ldapImportPreview(ok());
    await mock.importDiscard({ planId: q.planId });
    expect(mock.importPlans.size).toBe(0);
    expect(await code(mock.importApply({ planId: q.planId, exclude: [] }))).toBe("import.plan_expired");
  });
});
