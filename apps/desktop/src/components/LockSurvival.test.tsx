import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { App } from "../App";
import { useSessions } from "../stores/sessions";
import { useTransfers } from "../stores/transfers";
import { freshBackend, settle } from "../test/harness";
import { until } from "../test/ssh";

/** Review 4 M-10: what the backend keeps through a lock is shown again after unlock. */
describe("lock -> unlock re-adoption (M-10)", () => {
  it("shows the surviving session, its loopback forward and its running transfer", async () => {
    const mock = freshBackend({ transferStepMs: 60_000 });
    mock.trustedHosts.add("web01.example.test");
    render(<App />);
    await screen.findByText("Nothing open yet");
    await act(async () => { await useSessions.getState().open("c-web01"); });
    await until(() => useSessions.getState().tabs[0]?.state === "connected");
    const sessionId = useSessions.getState().tabs[0]?.sessionId ?? "";
    const tabId = useSessions.getState().tabs[0]?.id;
    expect(sessionId).not.toBe("");

    await mock.forwardOpen({ sessionId, kind: "local", bind: { host: "127.0.0.1", port: 15432 }, target: { host: "db.example.test", port: 5432 }, exposure: "loopback" });
    await mock.forwardOpen({ sessionId, kind: "dynamic", bind: { host: "0.0.0.0", port: 1080 }, target: null, exposure: "external" });
    const pick = await mock.sftpPickLocal({ sessionId, mode: "folder" });
    await act(async () => { await useTransfers.getState().download(sessionId, "/home/ops/README.md", pick ?? { pickId: "", name: "" }); });
    await until(() => useTransfers.getState().items[0]?.state === "running");
    const transferId = useTransfers.getState().items[0]?.transferId;
    expect(transferId).toBeTruthy();

    act(() => { mock.fireAutoLock("idle"); });
    expect(await screen.findByText("Unlock Mooring")).toBeInTheDocument();
    expect(useSessions.getState().tabs).toHaveLength(0);
    expect(useTransfers.getState().items).toHaveLength(0);

    fireEvent.change(screen.getByLabelText("Master password"), { target: { value: "correct horse" } });
    fireEvent.click(screen.getByRole("button", { name: "Unlock" }));
    await settle();

    // The session is a tab again, under the tab id its event channel still feeds.
    await waitFor(() => { expect(useSessions.getState().tabs).toHaveLength(1); });
    expect(useSessions.getState().tabs[0]).toMatchObject({ id: tabId, sessionId, state: "connected" });

    // Forwards panel: listed again through forward_list; the external forward was closed by the lock.
    fireEvent.click(await screen.findByRole("button", { name: "Forwards" }));
    await settle();
    const table = await screen.findByRole("table", { name: "Forwards on this session" });
    expect(within(table).getByText("127.0.0.1:15432")).toBeInTheDocument();
    expect(within(table).queryByText("0.0.0.0:1080")).toBeNull();

    // Files panel: the running transfer is re-keyed from sftp_transfers by its transfer id.
    fireEvent.click(screen.getByRole("button", { name: "Files" }));
    await settle();
    expect(useTransfers.getState().items).toEqual([expect.objectContaining({ sessionId, transferId, state: "running" })]);
    const drawer = screen.getByRole("region", { name: "Transfers" });
    expect(within(drawer).getByRole("listitem", { name: `Transfer ${transferId ?? ""}` })).toHaveTextContent("Running");
  });

  it("does not adopt a session twice when unlock data loads again", async () => {
    const mock = freshBackend();
    mock.trustedHosts.add("web01.example.test");
    await act(async () => { await useSessions.getState().open("c-web01"); });
    await until(() => useSessions.getState().tabs[0]?.state === "connected");
    useSessions.getState().adopt(await mock.sessionList());
    expect(useSessions.getState().tabs).toHaveLength(1);
  });
});
