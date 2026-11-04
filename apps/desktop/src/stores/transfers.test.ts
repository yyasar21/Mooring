import { IpcError } from "../lib/ipc";
import { freshBackend } from "../test/harness";
import { connectedSsh, until } from "../test/ssh";
import { useTransfers } from "./transfers";

const first = () => useTransfers.getState().items[0];

describe("transfers store", () => {
  it("cancels a transfer the user stopped before the backend returned its id", async () => {
    const mock = freshBackend({ transferStepMs: 30 });
    const { sessionId } = await connectedSsh(mock);
    const started = useTransfers.getState().download(sessionId, "/home/ops/README.md", "/picked");
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
    await useTransfers.getState().download(sessionId, "/home/ops/logs", "/picked");
    expect(first()).toMatchObject({ state: "failed", error: "Only regular files can be transferred." });

    mock.sftpUpload = (a) => {
      a.onProgress({ transferId: "t", bytesDone: 1, bytesTotal: 2, state: "failed", error: "disk full" });
      a.onProgress({ transferId: "t", bytesDone: 2, bytesTotal: 2, state: "done", error: null });
      return Promise.resolve({ transferId: "t" });
    };
    await useTransfers.getState().upload(sessionId, "/picked/x.bin", "/tmp");
    expect(useTransfers.getState().items[1]).toMatchObject({ state: "failed", error: "disk full", name: "x.bin" });
    expect(useTransfers.getState().landed[sessionId]).toBeUndefined();
  });

  it("keeps only the file name of a local path", async () => {
    const mock = freshBackend();
    const { sessionId } = await connectedSsh(mock);
    mock.sftpUpload = () => Promise.reject(new IpcError("sftp.local_path", "x"));
    await useTransfers.getState().upload(sessionId, "C:\\Users\\demo\\secret-plans\\report.pdf", "/tmp");
    expect(first()).toMatchObject({ name: "report.pdf", state: "failed" });
    expect(JSON.stringify(useTransfers.getState().items)).not.toContain("secret-plans");
  });

  it("clears finished transfers per session", async () => {
    const mock = freshBackend();
    const { sessionId } = await connectedSsh(mock);
    await useTransfers.getState().download(sessionId, "/home/ops/README.md", "/picked");
    await until(() => first()?.state === "done");
    useTransfers.getState().clearFinished("other-session");
    expect(useTransfers.getState().items).toHaveLength(1);
    useTransfers.getState().clearFinished(sessionId);
    expect(useTransfers.getState().items).toHaveLength(0);
  });
});
