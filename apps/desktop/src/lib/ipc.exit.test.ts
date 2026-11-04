import { decodeEntry, decodeForward, decodeListing, decodeLockReason, decodeProgress } from "./ipc.decode.exit";
import { MockTransport } from "./ipc.mock";
import { normalizeRemote } from "./ipc.mock.fs";
import type { TransferProgress } from "./ipc.types";
import { connectedSsh, until } from "../test/ssh";
import { isLoopbackHost, isValidHost, validateForward, validateIdleMinutes, validateSyslog } from "./validate.exit";

describe("ADR-0010 decoders", () => {
  it("decodes progress in camelCase and snake_case; unknown states fail, never succeed", () => {
    expect(decodeProgress({ transferId: "t1", bytesDone: 5, bytesTotal: 10, state: "running", error: null })).toEqual({
      transferId: "t1", bytesDone: 5, bytesTotal: 10, state: "running", error: null,
    });
    expect(decodeProgress({ transfer_id: "t2", bytes_done: 7, bytes_total: null, state: "done" })).toMatchObject({
      transferId: "t2", bytesDone: 7, bytesTotal: null, state: "done", error: null,
    });
    expect(decodeProgress({ transferId: "t3", state: "Finished" })).toMatchObject({ state: "failed", error: "unrecognised transfer state" });
  });

  it("decodes entries and drops nameless ones", () => {
    expect(decodeEntry({ name: "a", kind: "Dir", size: 1, mtime: 2, mode: 0o755 })).toEqual({ name: "a", kind: "dir", size: 1, mtime: 2, mode: 0o755 });
    expect(decodeEntry({ name: "b", kind: "fifo" }).kind).toBe("other");
    expect(decodeListing({ entries: [{ name: "" }, { name: "x", kind: "file" }], truncated: true })).toMatchObject({
      entries: [{ name: "x" }],
      truncated: true,
    });
  });

  it("decodes forwards and never understates exposure", () => {
    const f = decodeForward({ id: "f", kind: "dynamic", bind: { host: "127.0.0.1", port: 1080 }, target: null, exposure: "loopback", openedAt: "t", connections: 2 });
    expect(f).toMatchObject({ kind: "dynamic", target: null, exposure: "loopback", connections: 2 });
    expect(decodeForward({ exposure: "lan" }).exposure).toBe("external");
  });

  it("decodes the vault:locked reason", () => {
    expect(decodeLockReason({ reason: "idle" })).toBe("idle");
    expect(decodeLockReason({ reason: "window_hidden" })).toBe("window_hidden");
    expect(decodeLockReason({ reason: "cosmic_ray" })).toBe("unknown");
    expect(decodeLockReason(null)).toBe("unknown");
  });
});

describe("ADR-0010 validation", () => {
  it("accepts names and IP literals, refuses schemes, ports and spaces", () => {
    for (const h of ["bastion.example.test", "localhost", "192.0.2.10", "::1", "2001:db8::5"]) expect(isValidHost(h)).toBe(true);
    for (const h of ["", " a", "https://x.example.test", "x.example.test:22", "999.1.1.1", "a b"]) expect(isValidHost(h)).toBe(false);
    expect(isLoopbackHost("127.0.0.1")).toBe(true);
    expect(isLoopbackHost("0.0.0.0")).toBe(false);
  });

  it("checks forward shape, ports and exposure", () => {
    const base = { kind: "local" as const, bind: { host: "127.0.0.1", port: 8080 }, target: { host: "db.example.test", port: 5432 }, exposure: "loopback" as const };
    expect(validateForward(base)).toEqual({});
    expect(validateForward({ ...base, bind: { host: "0.0.0.0", port: 8080 } }).exposure).toBeDefined();
    expect(validateForward({ ...base, bind: { host: "0.0.0.0", port: 8080 }, exposure: "external" })).toEqual({});
    expect(validateForward({ ...base, target: null }).targetHost).toBeDefined();
    expect(validateForward({ ...base, target: { host: "db.example.test", port: 0 } }).targetPort).toBeDefined();
    expect(validateForward({ ...base, kind: "dynamic", target: null })).toEqual({});
    expect(validateForward({ ...base, bind: { host: "127.0.0.1", port: 70000 } }).bindPort).toBeDefined();
  });

  it("bounds the idle timeout and syslog fields", () => {
    expect(validateIdleMinutes(null)).toBeNull();
    expect(validateIdleMinutes(15)).toBeNull();
    expect(validateIdleMinutes(0)).not.toBeNull();
    expect(validateIdleMinutes(2.5)).not.toBeNull();
    expect(validateIdleMinutes(1441)).not.toBeNull();
    const ok = { host: "logs.example.test", port: 6514, transport: "tls" as const, facility: "authpriv" as const, enabled: true };
    expect(validateSyslog(ok)).toEqual({});
    const bad = validateSyslog({ ...ok, host: "tcp://logs.example.test", port: 0 });
    expect(Object.keys(bad).sort()).toEqual(["host", "port"]);
  });

  it("normalises remote paths and refuses relative ones", () => {
    expect(normalizeRemote("/home//ops/./logs/..")).toBe("/home/ops");
    expect(normalizeRemote("/../..")).toBe("/");
    expect(() => normalizeRemote("home")).toThrow();
  });
});

describe("MockTransport · ADR-0010", () => {
  it("opens, lists and closes forwards; refuses non-SSH sessions", async () => {
    const { m, sessionId } = await connectedSsh();
    const f = await m.forwardOpen({ sessionId, kind: "local", bind: { host: "127.0.0.1", port: 0 }, target: { host: "db.example.test", port: 5432 }, exposure: "loopback" });
    expect(f.bind.port).toBeGreaterThan(0);
    expect(await m.forwardList({ sessionId })).toHaveLength(1);
    await expect(m.forwardOpen({ sessionId, kind: "local", bind: { host: "127.0.0.1", port: f.bind.port }, target: { host: "x.example.test", port: 1 }, exposure: "loopback" }))
      .rejects.toMatchObject({ code: "forward.bind_failed" });
    await m.forwardClose({ sessionId, forwardId: f.id });
    expect(await m.forwardList({ sessionId })).toEqual([]);
    await expect(m.forwardClose({ sessionId, forwardId: f.id })).rejects.toMatchObject({ code: "forward.not_found" });
    const [audit] = await m.auditTail({ limit: 1, before: null });
    expect(audit?.event).toBe("session.forward.close");

    const rdp = await m.sessionOpen({ connectionId: "c-dc", size: { width: 80, height: 24 }, onEvent: () => undefined });
    await expect(m.forwardList({ sessionId: rdp.sessionId })).rejects.toMatchObject({ code: "session.unsupported" });
  });

  it("caps forwards per session and drops them when the session ends", async () => {
    const { m, sessionId } = await connectedSsh();
    for (let i = 0; i < 64; i++) {
      await m.forwardOpen({ sessionId, kind: "dynamic", bind: { host: "127.0.0.1", port: 20000 + i }, target: null, exposure: "loopback" });
    }
    await expect(m.forwardOpen({ sessionId, kind: "dynamic", bind: { host: "127.0.0.1", port: 30000 }, target: null, exposure: "loopback" }))
      .rejects.toMatchObject({ code: "forward.limit" });
    await m.sessionClose({ sessionId });
    expect(m.forwards.has(sessionId)).toBe(false);
  });

  it("browses and edits the remote tree", async () => {
    const { m, sessionId } = await connectedSsh();
    const { entries } = await m.sftpList({ sessionId, path: "/home/ops" });
    expect(entries.map((e) => e.name)).toEqual(expect.arrayContaining(["releases", "README.md", "current"]));
    await m.sftpMkdir({ sessionId, path: "/home/ops/new" });
    await expect(m.sftpMkdir({ sessionId, path: "/home/ops/new" })).rejects.toMatchObject({ code: "sftp.exists" });
    await m.sftpRename({ sessionId, from: "/home/ops/new", to: "/home/ops/renamed" });
    expect((await m.sftpStat({ sessionId, path: "/home/ops/renamed" })).kind).toBe("dir");
    await expect(m.sftpRemove({ sessionId, path: "/home/ops/logs" })).rejects.toMatchObject({ code: "sftp.not_empty" });
    await m.sftpRemove({ sessionId, path: "/home/ops/renamed" });
    await expect(m.sftpStat({ sessionId, path: "/home/ops/renamed" })).rejects.toMatchObject({ code: "sftp.not_found" });
  });

  it("streams download progress to done and audits the transfer", async () => {
    const { m, sessionId } = await connectedSsh();
    const seen: TransferProgress[] = [];
    const { transferId } = await m.sftpDownload({ sessionId, remote: "/home/ops/README.md", localDir: "/picked/by/dialog", onProgress: (p) => seen.push(p) });
    await until(() => seen.at(-1)?.state === "done");
    expect(seen[0]).toMatchObject({ transferId, bytesDone: 0, bytesTotal: 1284, state: "running" });
    expect(seen.at(-1)).toMatchObject({ bytesDone: 1284, state: "done" });
    expect(seen.map((p) => p.bytesDone)).toEqual([...seen.map((p) => p.bytesDone)].sort((a, b) => a - b));
    expect(m.audit.at(-1)).toMatchObject({ event: "session.sftp.transfer", details: { direction: "download", outcome: "done" } });
    await expect(m.sftpDownload({ sessionId, remote: "/home/ops/logs", localDir: "/x", onProgress: () => undefined }))
      .rejects.toMatchObject({ code: "sftp.not_a_file" });
  });

  it("cancels, fails and lands uploads", async () => {
    const { m, sessionId } = await connectedSsh();
    const seen: TransferProgress[] = [];
    const { transferId } = await m.sftpUpload({ sessionId, localPath: "/picked/notes.txt", remoteDir: "/tmp", onProgress: (p) => seen.push(p) });
    await m.sftpCancel({ sessionId, transferId });
    await until(() => seen.at(-1)?.state === "cancelled");
    expect(seen.at(-1)?.state).toBe("cancelled");

    const up: TransferProgress[] = [];
    await m.sftpUpload({ sessionId, localPath: "C:\\picked\\notes.txt", remoteDir: "/tmp", onProgress: (p) => up.push(p) });
    await until(() => up.at(-1)?.state === "done");
    expect((await m.sftpList({ sessionId, path: "/tmp" })).entries.map((e) => e.name)).toContain("notes.txt");

    m.failTransfers = true;
    const bad: TransferProgress[] = [];
    await m.sftpDownload({ sessionId, remote: "/home/ops/README.md", localDir: "/x", onProgress: (p) => bad.push(p) });
    await until(() => bad.at(-1)?.state === "failed");
    expect(bad.at(-1)).toMatchObject({ state: "failed", error: "permission denied" });
  });

  it("stores the auto-lock policy and refuses an out-of-range idle time", async () => {
    const m = new MockTransport();
    expect(await m.autolockGet()).toEqual({ idleMinutes: 15, onScreenLock: true, onSleep: true, onWindowHidden: true });
    const next = { idleMinutes: null, onScreenLock: false, onSleep: true, onWindowHidden: false };
    expect(await m.autolockSet(next)).toEqual(next);
    await expect(m.autolockSet({ ...next, idleMinutes: 0 })).rejects.toMatchObject({ code: "input.invalid" });
    expect(m.audit.at(-1)?.event).toBe("vault.policy_changed");
  });

  it("stores syslog settings and tests delivery", async () => {
    const m = new MockTransport();
    expect(await m.syslogGet()).toBeNull();
    await expect(m.syslogTest()).rejects.toMatchObject({ code: "syslog.not_configured" });
    const cfg = { host: "logs.example.test", port: 6514, transport: "tls" as const, facility: "local4" as const, enabled: true };
    expect(await m.syslogSet(cfg)).toEqual(cfg);
    expect(await m.syslogTest()).toEqual({ ok: true, error: null });
    await m.syslogSet({ ...cfg, host: "down.invalid" });
    expect(await m.syslogTest()).toEqual({ ok: false, error: "connection refused" });
    await expect(m.syslogSet({ ...cfg, port: 0 })).rejects.toMatchObject({ code: "input.invalid" });
  });

  it("emits vault:locked on auto-lock and kills forwards and transfers", async () => {
    const { m, sessionId } = await connectedSsh();
    const reasons: string[] = [];
    const off = m.onVaultLocked((e) => reasons.push(e.reason));
    await m.forwardOpen({ sessionId, kind: "dynamic", bind: { host: "127.0.0.1", port: 1080 }, target: null, exposure: "loopback" });
    const seen: TransferProgress[] = [];
    await m.sftpDownload({ sessionId, remote: "/home/ops/README.md", localDir: "/x", onProgress: (p) => seen.push(p) });
    m.fireAutoLock("idle");
    expect(reasons).toEqual(["idle"]);
    expect(seen.at(-1)?.state).toBe("failed");
    expect(m.forwards.size).toBe(0);
    await expect(m.forwardList({ sessionId })).rejects.toMatchObject({ code: "vault.locked" });
    off();
    m.fireAutoLock("sleep");
    expect(reasons).toEqual(["idle"]);
  });
});
