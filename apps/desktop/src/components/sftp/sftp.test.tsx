import { act, fireEvent, render, screen, within } from "@testing-library/react";
import type { MockOptions } from "../../lib/ipc.mock";
import { freshBackend, settle } from "../../test/harness";
import { connectedSsh, until } from "../../test/ssh";
import { useTransfers } from "../../stores/transfers";
import { formatBytes, formatMode, formatMtime, percent } from "./format";
import { SftpPanel } from "./SftpPanel";

async function browser(opts: MockOptions = {}) {
  const mock = freshBackend(opts);
  const { sessionId } = await connectedSsh(mock);
  render(<SftpPanel sessionId={sessionId} />);
  await settle();
  return { mock, sessionId };
}

const list = () => screen.getByRole("listbox", { name: /^Remote files in / });
const option = (name: string) => within(list()).getByRole("option", { name: new RegExp(`^${name.replace(".", "\\.")},`) });

async function openOps() {
  fireEvent.doubleClick(option("ops"));
  await settle();
}

describe("SftpPanel · remote pane", () => {
  it("lists folders first and navigates with the keyboard", async () => {
    await browser();
    expect(list()).toHaveAccessibleName("Remote files in /home");
    act(() => { list().focus(); });
    expect(option("ops")).toHaveAttribute("aria-selected", "true");
    fireEvent.keyDown(list(), { key: "Enter" });
    await settle();
    expect(list()).toHaveAccessibleName("Remote files in /home/ops");
    const names = within(list()).getAllByRole("option").map((o) => o.getAttribute("aria-label"));
    expect(names.slice(0, 4)).toEqual(["empty, folder", "logs, folder", "releases, folder", "current, link"]);
    expect(names).toContain("README.md, 1.3 KiB");
    expect(within(list()).getByText("-rwxr-xr-x")).toBeInTheDocument();

    fireEvent.keyDown(list(), { key: "Backspace" });
    await settle();
    expect(list()).toHaveAccessibleName("Remote files in /home");
    fireEvent.click(within(screen.getByRole("navigation", { name: "Remote path" })).getByRole("button", { name: "/" }));
    await settle();
    expect(list()).toHaveAccessibleName("Remote files in /");
  });

  it("creates, renames and deletes with confirmation", async () => {
    const { mock, sessionId } = await browser();
    await openOps();
    fireEvent.click(screen.getByRole("button", { name: "New folder" }));
    let dialog = screen.getByRole("dialog", { name: "New folder" });
    fireEvent.change(within(dialog).getByRole("textbox"), { target: { value: "a/b" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(within(dialog).getByRole("alert")).toHaveTextContent("A name cannot contain /");
    fireEvent.change(within(dialog).getByRole("textbox"), { target: { value: "backups" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    await settle();
    expect(screen.queryByRole("dialog")).toBeNull();

    fireEvent.mouseDown(option("backups"));
    act(() => { list().focus(); });
    fireEvent.keyDown(list(), { key: "F2" });
    dialog = screen.getByRole("dialog", { name: "Rename" });
    fireEvent.change(within(dialog).getByRole("textbox"), { target: { value: "archive" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Rename" }));
    await settle();
    expect(option("archive")).toHaveAttribute("aria-selected", "true");

    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    dialog = screen.getByRole("dialog", { name: "Delete folder?" });
    expect(dialog).toHaveTextContent("/home/ops/archive");
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toHaveFocus();
    fireEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await settle();
    await expect(mock.sftpStat({ sessionId, path: "/home/ops/archive" })).rejects.toMatchObject({ code: "sftp.not_found" });
  });

  it("explains why a non-empty folder cannot be deleted", async () => {
    await browser();
    await openOps();
    fireEvent.mouseDown(option("logs"));
    act(() => { list().focus(); });
    fireEvent.keyDown(list(), { key: "Delete" });
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Delete" }));
    await settle();
    expect(screen.getByRole("alert")).toHaveTextContent("The folder is not empty.");
  });
});

describe("SftpPanel · transfers", () => {
  it("downloads through the picked folder and shows progress to done", async () => {
    await browser();
    await openOps();
    fireEvent.mouseDown(option("README.md"));
    fireEvent.click(screen.getByRole("button", { name: "Download" }));
    await until(() => useTransfers.getState().items[0]?.state === "done");
    await settle();
    const row = within(screen.getByRole("region", { name: "Transfers" })).getByRole("listitem", { name: "Download README.md" });
    expect(within(row).getByRole("progressbar")).toHaveAttribute("aria-valuenow", "100");
    expect(row).toHaveTextContent("Done");
    expect(screen.getByRole("complementary", { name: "This computer" })).toHaveTextContent("Downloads");
    fireEvent.click(within(row).getByRole("button", { name: "Dismiss README.md" }));
    expect(screen.getByText(/No transfers yet/)).toBeInTheDocument();
  });

  it("uploads a picked file and refreshes the listing", async () => {
    await browser();
    fireEvent.click(screen.getByRole("button", { name: "Upload a file…" }));
    await until(() => useTransfers.getState().items[0]?.state === "done");
    await settle();
    expect(option("notes.txt")).toBeInTheDocument();
    expect(screen.getByRole("complementary", { name: "This computer" })).toHaveTextContent("notes.txt");
  });

  it("cancels a running transfer", async () => {
    await browser({ transferStepMs: 40 });
    await openOps();
    fireEvent.mouseDown(option("README.md"));
    fireEvent.click(screen.getByRole("button", { name: "Download" }));
    await until(() => useTransfers.getState().items[0]?.state === "running");
    fireEvent.click(screen.getByRole("button", { name: "Cancel README.md" }));
    await until(() => useTransfers.getState().items[0]?.state === "cancelled", 200);
    await settle();
    expect(screen.getByRole("listitem", { name: "Download README.md" })).toHaveTextContent("Cancelled");
  });

  it("shows a failed transfer with the backend's reason", async () => {
    const { mock } = await browser();
    mock.failTransfers = true;
    await openOps();
    fireEvent.mouseDown(option("README.md"));
    fireEvent.click(screen.getByRole("button", { name: "Download" }));
    await until(() => useTransfers.getState().items[0]?.state === "failed");
    await settle();
    const row = screen.getByRole("listitem", { name: "Download README.md" });
    expect(row).toHaveTextContent("Failed");
    expect(row).toHaveTextContent("permission denied");
  });

  it("disables Download for folders", async () => {
    await browser();
    fireEvent.mouseDown(option("ops"));
    expect(screen.getByRole("button", { name: "Download" })).toBeDisabled();
  });
});

describe("SftpPanel · offline and formatting", () => {
  it("waits for a connected session", () => {
    freshBackend();
    render(<SftpPanel sessionId={null} />);
    expect(screen.getByText("The file browser is available once the session is connected.")).toBeInTheDocument();
  });

  it("formats sizes, modes, times and percentages", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1536)).toBe("1.5 KiB");
    expect(formatBytes(52_428_800)).toBe("50 MiB");
    expect(formatMode("dir", 0o755)).toBe("drwxr-xr-x");
    expect(formatMode("file", 0o4755)).toBe("-rwsr-xr-x");
    expect(formatMode("dir", 0o1777)).toBe("drwxrwxrwt");
    expect(formatMode("file", null)).toBe("-?????????");
    expect(formatMtime(null)).toBe("");
    expect(formatMtime(0)).toMatch(/^19(69|70)-/);
    expect(percent(5, 10)).toBe(50);
    expect(percent(5, null)).toBeNull();
  });
});
