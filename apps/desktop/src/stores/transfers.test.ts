import { IpcError, type LocalPick } from "../lib/ipc";
import type { MockTransport } from "../lib/ipc.mock";
import { freshBackend } from "../test/harness";
import { connectedSsh, until } from "../test/ssh";
import { useTransfers } from "./transfers";

const first = () => useTransfers.getState().items[0];
const pick = (m: MockTransport, sessionId: string, mode: "folder" | "file" = "folder"): LocalPick => {
  const p = m.picks.open(sessionId, mode);
  if (!p) throw new Error("no pick");
  return p;
};

describe("transfers store", () => {
  it("cancels a transfer the user stopped before the backend returned its id", async () => {
    const mock = freshBackend({ transferStepMs: 30 });
    const { sessionId } = await connectedSsh(mock);
    const started = useTransfers.getState().download(sessionId, "/home/ops/README.md", pick(mock, sessionId));
    const key = first()?.key ?? "";
    expect(first()?.state).toBe("starting");
    await useTransfers.getState().cancel(key);
    expect(first()?.cancelRequested).toBe(true);
    await started;
    await until(() => first()?.state === "cancelled", 200);
    expect(first()?.state).toBe("cancelled");
  });

  it("marks a refused start as failed with a plain message and ignores late progress", async () => {
    const mock = freshBackend();
    const { sessionId } = await connectedSsh(mock);
    await useTransfers.getState().download(sessionId, "/home/ops/logs", pick(mock, sessionId));
    expect(first()).toMatchObject({ state: "failed", error: "only regular files can be transferred" });

    mock.sftpUpload = (a) => {
      a.onProgress({ transferId: "t", bytesDone: 1, bytesTotal: 2, state: "failed", error: "disk full" });
      a.onProgress({ transferId: "t", bytesDone: 2, bytesTotal: 2, state: "done", error: null });
      return Promise.resolve({ transferId: "t" });
    };
    await useTransfers.getState().upload(sessionId, { pickId: "p", name: "x.bin" }, "/tmp");
    expect(useTransfers.getState().items[1]).toMatchObject({ state: "failed", error: "disk full", name: "x.bin" });
    expect(useTransfers.getState().landed[sessionId]).toBeUndefined();
  });

  it("sends only the pick id and shows a refused pick as failed", async () => {
    const mock = freshBackend();
    const { sessionId } = await connectedSsh(mock);
    const sent: unknown[] = [];
    mock.sftpUpload = (a) => {
      sent.push(a);
      return Promise.reject(new IpcError("input.invalid", "invalid pick: unknown, used, expired or from another session"));
    };
    await useTransfers.getState().upload(sessionId, { pickId: "p-9", name: "report.pdf" }, "/tmp");
    expect(first()).toMatchObject({ name: "report.pdf", state: "failed", error: expect.stringContaining("pick") as unknown });
    expect(sent[0]).toMatchObject({ pick: "p-9", remoteDir: "/tmp" });
    expect(Object.keys(sent[0] as object)).not.toContain("localPath");
  });

  it("reports an existing local file instead of failing, and overwrites on request", async () => {
    const mock = freshBackend();
    const { sessionId } = await connectedSsh(mock);
    mock.picks.localFiles.add("Downloads/README.md");
    const folder = pick(mock, sessionId);
    expect(await useTransfers.getState().download(sessionId, "/home/ops/README.md", folder)).toBe("exists");
    expect(useTransfers.getState().items).toHaveLength(0);
    expect(await useTransfers.getState().download(sessionId, "/home/ops/README.md", folder, true)).toBe("started");
    await until(() => first()?.state === "done");
    expect(first()?.state).toBe("done");
  });

  it("clears finished transfers per session", async () => {
    const mock = freshBackend();
    const { sessionId } = await connectedSsh(mock);
    await useTransfers.getState().download(sessionId, "/home/ops/README.md", pick(mock, sessionId));
    await until(() => first()?.state === "done");
    useTransfers.getState().clearFinished("other-session");
    expect(useTransfers.getState().items).toHaveLength(1);
    useTransfers.getState().clearFinished(sessionId);
    expect(useTransfers.getState().items).toHaveLength(0);
  });
});
