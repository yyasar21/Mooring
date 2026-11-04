// B-4 (review 4): local picks are opaque, single-use, session-bound and cleared on lock.
import { MockTransport } from "./ipc.mock";
import { PICK_TTL_MS } from "./ipc.mock.picks";
import { connectedSsh, until } from "../test/ssh";

const noop = () => undefined;
const PICK_REFUSED = { code: "input.invalid", message: expect.stringContaining("pick") as unknown };

async function twoSessions() {
  const { m, sessionId } = await connectedSsh();
  const other = await m.sessionOpen({ connectionId: "c-web01", size: { width: 80, height: 24 }, onEvent: noop });
  await until(() => m.sessions.get(other.sessionId)?.info.state === "connected");
  return { m, sessionId, other: other.sessionId };
}

describe("sftp_pick_local · mock", () => {
  it("returns only a display name and an opaque id; null when cancelled", async () => {
    const { m, sessionId } = await connectedSsh();
    const p = await m.sftpPickLocal({ sessionId, mode: "folder" });
    expect(p).toEqual({ pickId: expect.any(String) as unknown, name: "Downloads" });
    expect(p?.pickId).not.toContain("/");
    m.picks.queue.push(null);
    expect(await m.sftpPickLocal({ sessionId, mode: "file" })).toBeNull();
  });

  it("refuses a reused pick", async () => {
    const { m, sessionId } = await connectedSsh();
    const p = await m.sftpPickLocal({ sessionId, mode: "file" });
    const pick = p?.pickId ?? "";
    await m.sftpUpload({ sessionId, pick, remoteDir: "/tmp", onProgress: noop });
    await expect(m.sftpUpload({ sessionId, pick, remoteDir: "/tmp", onProgress: noop })).rejects.toMatchObject(PICK_REFUSED);
  });

  it("refuses a pick from another session, a forged one and one of the wrong mode", async () => {
    const { m, sessionId, other } = await twoSessions();
    const p = await m.sftpPickLocal({ sessionId, mode: "folder" });
    const pick = p?.pickId ?? "";
    await expect(m.sftpDownload({ sessionId: other, remote: "/home/ops/README.md", pick, onProgress: noop })).rejects.toMatchObject(PICK_REFUSED);
    await expect(m.sftpDownload({ sessionId, remote: "/home/ops/README.md", pick: "forged", onProgress: noop })).rejects.toMatchObject(PICK_REFUSED);
    await expect(m.sftpUpload({ sessionId, pick, remoteDir: "/tmp", onProgress: noop })).rejects.toMatchObject(PICK_REFUSED);
    // A refusal for another session does not burn the owner's pick.
    await expect(m.sftpDownload({ sessionId, remote: "/home/ops/README.md", pick, onProgress: noop })).resolves.toHaveProperty("transferId");
  });

  it("refuses an existing target without consuming the pick, then overwrites on request", async () => {
    const { m, sessionId } = await connectedSsh();
    m.picks.localFiles.add("Downloads/README.md");
    const pick = (await m.sftpPickLocal({ sessionId, mode: "folder" }))?.pickId ?? "";
    await expect(m.sftpDownload({ sessionId, remote: "/home/ops/README.md", pick, onProgress: noop })).rejects.toMatchObject({ code: "sftp.exists" });
    await expect(m.sftpDownload({ sessionId, remote: "/home/ops/README.md", pick, overwrite: true, onProgress: noop })).resolves.toHaveProperty("transferId");
    await expect(m.sftpDownload({ sessionId, remote: "/home/ops/README.md", pick, overwrite: true, onProgress: noop })).rejects.toMatchObject(PICK_REFUSED);
  });

  it("forgets every pick on lock and refuses expired picks", async () => {
    const m = new MockTransport();
    const { sessionId } = await connectedSsh(m);
    const pick = (await m.sftpPickLocal({ sessionId, mode: "file" }))?.pickId ?? "";
    expect(m.picks.size).toBe(1);
    await m.vaultLock("user");
    expect(m.picks.size).toBe(0);
    await m.vaultUnlock("pw");
    await expect(m.sftpUpload({ sessionId, pick, remoteDir: "/tmp", onProgress: noop })).rejects.toMatchObject(PICK_REFUSED);

    const old = m.picks.open(sessionId, "file", Date.now() - PICK_TTL_MS - 1)?.pickId ?? "";
    await expect(m.sftpUpload({ sessionId, pick: old, remoteDir: "/tmp", onProgress: noop })).rejects.toMatchObject(PICK_REFUSED);
  });
});
