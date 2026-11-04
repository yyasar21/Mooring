// The Tauri transport against a fake `invoke`: command names and argument shapes of ADR-0010.
import type { TransferProgress } from "./ipc.types";

const calls: { cmd: string; args: Record<string, unknown> | undefined }[] = [];
let reply: unknown = undefined;
let eventHandler: ((e: { payload: unknown }) => void) | null = null;
const unlisten = vi.fn();

vi.mock("@tauri-apps/api/core", () => {
  class Channel {
    onmessage: (msg: unknown) => void = () => undefined;
  }
  return {
    Channel,
    invoke: (cmd: string, args?: Record<string, unknown>) => {
      calls.push({ cmd, args });
      return reply instanceof Error ? Promise.reject(reply) : Promise.resolve(reply);
    },
  };
});

vi.mock("@tauri-apps/api/event", () => ({
  listen: (name: string, handler: (e: { payload: unknown }) => void) => {
    if (name === "vault:locked") eventHandler = handler;
    return Promise.resolve(unlisten);
  },
}));

const { TauriTransport } = await import("./ipc");

beforeEach(() => {
  calls.length = 0;
  reply = undefined;
});

describe("TauriTransport · ADR-0010", () => {
  it("names the commands and passes camelCase arguments", async () => {
    const t = new TauriTransport();
    const sessionId = "s-1";
    reply = [];
    await t.forwardList({ sessionId });
    await t.forwardClose({ sessionId, forwardId: "f-1" });
    await t.sftpMkdir({ sessionId, path: "/tmp/x" });
    await t.sftpRename({ sessionId, from: "/a", to: "/b" });
    await t.sftpRemove({ sessionId, path: "/a" });
    await t.sftpCancel({ sessionId, transferId: "t-1" });
    await t.autolockSet({ idleMinutes: null, onScreenLock: true, onSleep: false, onWindowHidden: true });
    await t.syslogSet({ host: "logs.example.test", port: 514, transport: "udp", facility: "local0", enabled: true });
    await t.syslogTest();
    expect(calls.map((c) => c.cmd)).toEqual([
      "forward_list", "forward_close", "sftp_mkdir", "sftp_rename", "sftp_remove", "sftp_cancel", "autolock_set", "syslog_set", "syslog_test",
    ]);
    expect(calls[1]?.args).toEqual({ sessionId, forwardId: "f-1" });
    expect(calls[6]?.args).toEqual({ policy: { idleMinutes: null, onScreenLock: true, onSleep: false, onWindowHidden: true } });
    expect(calls[7]?.args).toMatchObject({ host: "logs.example.test", transport: "udp", facility: "local0" });
  });

  it("decodes forward and listing replies", async () => {
    const t = new TauriTransport();
    reply = { id: "f", kind: "remote", bind: { host: "0.0.0.0", port: 9000 }, target: { host: "127.0.0.1", port: 80 }, exposure: "external", openedAt: "t", connections: 3 };
    const f = await t.forwardOpen({ sessionId: "s", kind: "remote", bind: { host: "0.0.0.0", port: 9000 }, target: { host: "127.0.0.1", port: 80 }, exposure: "external" });
    expect(f).toMatchObject({ kind: "remote", exposure: "external", connections: 3 });
    expect(calls[0]?.args).toMatchObject({ exposure: "external", target: { host: "127.0.0.1", port: 80 } });
    reply = { entries: [{ name: "a", kind: "file", size: 1, mtime: null, mode: 420 }], truncated: false };
    expect((await t.sftpList({ sessionId: "s", path: "/" })).entries[0]?.name).toBe("a");
  });

  it("hands a Channel to downloads and decodes its progress messages", async () => {
    const t = new TauriTransport();
    reply = { transferId: "t-9" };
    const seen: TransferProgress[] = [];
    const r = await t.sftpDownload({ sessionId: "s", remote: "/r", localDir: "/picked", onProgress: (p) => seen.push(p) });
    expect(r).toEqual({ transferId: "t-9" });
    const args = calls[0]?.args ?? {};
    expect(Object.keys(args).sort()).toEqual(["localDir", "onProgress", "remote", "sessionId"]);
    const channel = args.onProgress as { onmessage: (m: unknown) => void };
    channel.onmessage({ transferId: "t-9", bytesDone: 10, bytesTotal: 20, state: "running", error: null });
    expect(seen).toEqual([{ transferId: "t-9", bytesDone: 10, bytesTotal: 20, state: "running", error: null }]);
  });

  it("maps wire errors to IpcError", async () => {
    const t = new TauriTransport();
    reply = Object.assign(new Error("x"), { code: "forward.limit", message: "too many forwards" });
    await expect(t.forwardList({ sessionId: "s" })).rejects.toMatchObject({ name: "IpcError", code: "forward.limit" });
  });

  it("subscribes to vault:locked and unsubscribes", async () => {
    const t = new TauriTransport();
    const reasons: string[] = [];
    const off = t.onVaultLocked((e) => reasons.push(e.reason));
    await Promise.resolve();
    eventHandler?.({ payload: { reason: "screen_lock" } });
    eventHandler?.({ payload: { reason: "bogus" } });
    expect(reasons).toEqual(["screen_lock", "unknown"]);
    off();
    expect(unlisten).toHaveBeenCalled();
  });
});
