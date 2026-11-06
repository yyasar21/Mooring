// The Tauri transport against a fake `invoke`: command names and argument shapes of ADR-0019 (I1),
// checked against the command list Rust generates (`src-tauri/ipc-manifest.json`).
import { RUST_MANIFEST } from "../test/rustContract";

const calls: { cmd: string; args: Record<string, unknown> | undefined }[] = [];
let reply: unknown = undefined;

vi.mock("@tauri-apps/api/core", () => ({
  Channel: class { onmessage: (msg: unknown) => void = () => undefined; },
  invoke: (cmd: string, args?: Record<string, unknown>) => {
    calls.push({ cmd, args });
    return Promise.resolve(reply);
  },
}));
vi.mock("@tauri-apps/api/event", () => ({ listen: () => Promise.resolve(() => undefined) }));

const { TauriTransport } = await import("./ipc");

beforeEach(() => {
  calls.length = 0;
  reply = undefined;
});

describe("TauriTransport · ADR-0019 import", () => {
  it("names the five commands with camelCase arguments and passes replies through", async () => {
    const t = new TauriTransport();
    reply = [];
    expect(await t.importFormats()).toEqual([]);
    reply = { pickId: "p-1", fileName: "a.rtsz", size: 10 };
    expect(await t.importPick({ format: "royal_ts" })).toEqual(reply);
    reply = null;
    expect(await t.importPick({ format: "putty" })).toBeNull();
    reply = { planId: "pl-1" };
    await t.importPreview({ source: { pickId: "p-1" }, includePlaintextSecrets: true, importKeyFiles: false });
    await t.importPreview({ source: { known: "openssh" }, includePlaintextSecrets: false, importKeyFiles: true });
    reply = { rootFolderId: "f-9", folders: 1, connections: 2, credentials: 0, secrets: 0, skipped: 0 };
    await t.importApply({ planId: "pl-1", exclude: ["c1"], duplicates: "import" });
    await t.importApply({ planId: "pl-1", exclude: [] });
    reply = undefined;
    await t.importDiscard({ planId: "pl-1" });
    expect(calls).toEqual([
      { cmd: "import_formats", args: undefined },
      { cmd: "import_pick", args: { format: "royal_ts" } },
      { cmd: "import_pick", args: { format: "putty" } },
      { cmd: "import_preview", args: { source: { pickId: "p-1" }, includePlaintextSecrets: true, importKeyFiles: false } },
      { cmd: "import_preview", args: { source: { known: "openssh" }, includePlaintextSecrets: false, importKeyFiles: true } },
      { cmd: "import_apply", args: { planId: "pl-1", exclude: ["c1"], duplicates: "import" } },
      { cmd: "import_apply", args: { planId: "pl-1", exclude: [] } },
      { cmd: "import_discard", args: { planId: "pl-1" } },
    ]);
  });

  it("names the two directory commands (I2) with the contract's argument shapes", async () => {
    const t = new TauriTransport();
    reply = { host: "dc01.example.test", port: 636, boundAs: "EXAMPLE\\admin" };
    expect(await t.ldapImportTest({ url: "ldaps://dc01.example.test", baseDn: "DC=example,DC=test", kind: "ad", credentialId: "cr-ad" })).toEqual(reply);
    reply = { planId: "pl-2" };
    await t.ldapImportPreview({
      url: "ldaps://dc01.example.test:636", baseDn: "OU=Servers,DC=example,DC=test", scope: "one", kind: "openldap", filter: "web", credentialId: "cr-deploy",
      caPem: "-----BEGIN CERTIFICATE-----", sizeLimit: 500,
    });
    expect(calls).toEqual([
      { cmd: "ldap_import_test", args: { url: "ldaps://dc01.example.test", baseDn: "DC=example,DC=test", kind: "ad", credentialId: "cr-ad" } },
      {
        cmd: "ldap_import_preview",
        args: {
          url: "ldaps://dc01.example.test:636", baseDn: "OU=Servers,DC=example,DC=test", scope: "one", kind: "openldap", filter: "web", credentialId: "cr-deploy",
          caPem: "-----BEGIN CERTIFICATE-----", sizeLimit: 500,
        },
      },
    ]);
  });

  it.skipIf(RUST_MANIFEST === null)("every import command exists in the Rust manifest for the main window", () => {
    for (const cmd of ["import_formats", "import_pick", "import_preview", "import_apply", "import_discard", "ldap_import_test", "ldap_import_preview"]) {
      expect({ cmd, labels: RUST_MANIFEST?.[cmd] }).toEqual({ cmd, labels: ["main"] });
    }
  });
});
