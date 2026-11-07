// The Tauri transport against a fake `invoke`: the R3 (ADR-0026) argument shapes the UI sends.
import { RUST_CODES } from "../test/rustContract";
import { FRIENDLY } from "../stores/errors";
import { POLLED_COMMANDS } from "./ipc";

const calls: { cmd: string; args: Record<string, unknown> | undefined }[] = [];

vi.mock("@tauri-apps/api/core", () => {
  class Channel {
    onmessage: (msg: unknown) => void = () => undefined;
  }
  return {
    Channel,
    invoke: (cmd: string, args?: Record<string, unknown>) => {
      calls.push({ cmd, args });
      return Promise.resolve(cmd === "session_list" ? [] : undefined);
    },
  };
});
vi.mock("@tauri-apps/api/event", () => ({ listen: () => Promise.resolve(() => undefined) }));

const { TauriTransport } = await import("./ipc");

beforeEach(() => { calls.length = 0; });

describe("TauriTransport · A5 U4", () => {
  it("sends the source kind and bwsPath, the certificate role, and polls session_list", async () => {
    const t = new TauriTransport();
    const options = { caPem: null, allowHttp: false, allowedOrigins: [], bwsPath: "/usr/local/bin/bws" };
    await t.secretSourceCreate({ kind: "bitwarden", name: "bw", address: "https://bw.example.test", namespace: null, authMethod: "token", authMount: "", credentialId: "c1", oidcRole: null, options });
    expect(calls[0]).toEqual({ cmd: "secret_source_create", args: expect.objectContaining({ kind: "bitwarden", authMethod: "token", options }) as unknown });
    await t.connectionSetRoleCredential({ id: "c-1", role: "certificate", credentialId: "cr-cert" });
    expect(calls[1]).toEqual({ cmd: "connection_set_role_credential", args: { id: "c-1", role: "certificate", credentialId: "cr-cert" } });
    await t.sessionList();
    expect(calls[2]?.cmd).toBe("session_list");
    expect(POLLED_COMMANDS).toContain("session_list");
  });

  it.skipIf(RUST_CODES === null)("every R3 error code has English copy", () => {
    for (const code of ["credential.external_engine", "secret.lease_failed", "secret.tool_missing", "secret.tool_version", "secret.tool_failed", "source.kind_unsupported"]) {
      expect(RUST_CODES?.has(code)).toBe(true);
      expect(FRIENDLY[code]).toMatch(/^[A-Za-z].+\.$/);
    }
  });
});
