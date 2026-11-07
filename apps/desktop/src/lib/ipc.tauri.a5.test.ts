// The Tauri transport against a fake `invoke`: command names and argument shapes of the A5
// commands (ADR-0022 biometric, ADR-0023 backups) and `via` on connection_create/update.
import { POLLED_COMMANDS } from "./ipc";

const calls: { cmd: string; args: Record<string, unknown> | undefined }[] = [];
let reply: unknown = undefined;

vi.mock("@tauri-apps/api/core", () => {
  class Channel {
    onmessage: (msg: unknown) => void = () => undefined;
  }
  return {
    Channel,
    invoke: (cmd: string, args?: Record<string, unknown>) => {
      calls.push({ cmd, args });
      return Promise.resolve(reply);
    },
  };
});
vi.mock("@tauri-apps/api/event", () => ({ listen: () => Promise.resolve(() => undefined) }));

const { TauriTransport } = await import("./ipc");

beforeEach(() => {
  calls.length = 0;
  reply = undefined;
});

describe("TauriTransport · A5", () => {
  it("names every R2 command with camelCase arguments", async () => {
    const t = new TauriTransport();
    await t.biometricStatus();
    await t.biometricEnroll({ password: "pw" });
    await t.biometricUnlock();
    await t.biometricDisable({ password: "pw" });
    await t.vaultExportPick();
    await t.vaultExportAge({ pickId: "p1", password: "pw", exportPassphrase: "a long passphrase" });
    await t.vaultImportPick();
    await t.vaultImportInspect({ pickId: "p2", exportPassphrase: "a long passphrase" });
    await t.vaultImportAge({ pickId: "p2", password: "pw", sourcePassword: null, mode: "replace", confirm: "REPLACE" });
    expect(calls.map((c) => c.cmd)).toEqual([
      "biometric_status", "biometric_enroll", "biometric_unlock", "biometric_disable",
      "vault_export_pick", "vault_export_age", "vault_import_pick", "vault_import_inspect", "vault_import_age",
    ]);
    expect(calls[5]?.args).toEqual({ pickId: "p1", password: "pw", exportPassphrase: "a long passphrase" });
    expect(calls[8]?.args).toEqual({ pickId: "p2", password: "pw", sourcePassword: null, mode: "replace", confirm: "REPLACE" });
  });

  it("sends via on connection_create / connection_update and polls none of the A5 commands", async () => {
    const t = new TauriTransport();
    const fields = {
      folderId: "f", name: "n", protocol: "ssh" as const, host: "h.example.test", port: 22, credentialId: null,
      usernameOverride: null, domainOverride: null, gatewayCredentialId: null, becomeCredentialId: null, tags: [],
    };
    await t.connectionCreate({ ...fields, via: ["c-1"] });
    await t.connectionUpdate({ ...fields, id: "c-2", via: [] });
    expect(calls[0]?.args?.via).toEqual(["c-1"]);
    expect(calls[1]?.args?.via).toEqual([]);
    for (const c of ["biometric_status", "biometric_unlock", "vault_import_inspect"]) expect(POLLED_COMMANDS).not.toContain(c);
  });
});
