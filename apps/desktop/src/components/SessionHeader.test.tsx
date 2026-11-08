import { act, fireEvent, render, screen, within } from "@testing-library/react";
import type { ConnectionSummary, Folder } from "../lib/ipc";
import { blankTab, useSessions, type Tab } from "../stores/sessions";
import { connectedSince, fmtDuration, sessionStatus, syncClock } from "../stores/sessionClock";
import { useTree } from "../stores/tree";
import { freshBackend } from "../test/harness";
import { SessionHeader, folderPath, hostLabel } from "./SessionHeader";
import { SessionToolbar } from "./SessionToolbar";

const folder = (id: string, parentId: string | null, name: string): Folder => ({ id, parentId, name, defaultCredentialId: null, sort: 0 });
const FOLDERS = [folder("root", null, "Root"), folder("prod", "root", "Production"), folder("web", "prod", "Web tier")];
const conn = { id: "c1", folderId: "web", name: "web01", protocol: "ssh", host: "web01.example.test", port: 2222 } as ConnectionSummary;

describe("session header helpers (M2)", () => {
  it("builds the breadcrumb from the top folder down, without the root, and survives a cycle", () => {
    expect(folderPath(FOLDERS, "web")).toEqual(["Production", "Web tier"]);
    expect(folderPath(FOLDERS, "root")).toEqual([]);
    expect(folderPath(FOLDERS, null)).toEqual([]);
    const loop = [folder("a", "b", "A"), folder("b", "a", "B")];
    expect(folderPath(loop, "a")).toEqual(["B", "A"]);
  });

  it("shows host:port, or the host alone for the default port", () => {
    expect(hostLabel(conn)).toBe("web01.example.test:2222");
    expect(hostLabel({ host: "dc01.example.test", port: null })).toBe("dc01.example.test");
    expect(hostLabel(undefined)).toBe("");
  });

  it("formats durations as hh:mm:ss", () => {
    expect(fmtDuration(0)).toBe("00:00:00");
    expect(fmtDuration(751_000)).toBe("00:12:31");
    expect(fmtDuration(100 * 3600_000 + 5000)).toBe("100:00:05");
    expect(fmtDuration(-5)).toBe("00:00:00");
  });

  it("names every state with a label and a tone", () => {
    const t = (p: Partial<Tab>) => sessionStatus({ state: "connected", prompt: null, closeCode: null, touch: null, ...p });
    expect(t({})).toMatchObject({ tone: "success", label: "Connected" });
    expect(t({ state: "connecting" })).toMatchObject({ tone: "info", dot: "busy", label: "Connecting" });
    expect(t({ state: "reconnecting" })).toMatchObject({ tone: "warning", label: "Reconnecting" });
    expect(t({ state: "detached" })).toMatchObject({ tone: "success", label: "In its own window" });
    expect(t({ prompt: { id: 1, message: "", secret: false, purpose: "host_key_trust" } })).toMatchObject({ tone: "warning", label: "Waiting for you" });
    expect(t({ state: "closed", closeCode: "user" })).toMatchObject({ tone: "neutral", label: "Closed" });
    expect(t({ state: "closed", closeCode: "network" })).toMatchObject({ tone: "danger", label: "Disconnected" });
  });

  it("stamps a tab when it comes up and forgets it when it goes down", () => {
    syncClock([{ id: "t1", state: "connecting" }], 1000);
    expect(connectedSince("t1")).toBeNull();
    syncClock([{ id: "t1", state: "connected" }], 2000);
    syncClock([{ id: "t1", state: "detached" }], 9000);
    expect(connectedSince("t1")).toBe(2000);
    syncClock([{ id: "t1", state: "reconnecting" }], 10_000);
    expect(connectedSince("t1")).toBeNull();
    syncClock([{ id: "t1", state: "connected" }], 11_000);
    syncClock([], 12_000);
    expect(connectedSince("t1")).toBeNull();
  });
});

describe("SessionHeader (M2)", () => {
  beforeEach(() => {
    freshBackend();
    useTree.setState({ folders: FOLDERS, connections: [conn], loaded: true });
  });

  it("shows the breadcrumb, the name, the mono host and a ticking status pill", () => {
    vi.useFakeTimers();
    try {
      const tab = blankTab("t-h", "c1", "ssh", { state: "connected", sessionId: "s1" });
      act(() => { useSessions.setState({ tabs: [tab], activeTab: tab.id }); });
      render(<SessionHeader tab={tab} connection={conn} />);
      const crumbs = screen.getByRole("navigation", { name: "Folder" });
      expect(within(crumbs).getAllByRole("listitem").map((li) => li.textContent)).toEqual(["Production", "Web tier"]);
      expect(screen.getByText("web01")).toHaveClass("session-name");
      expect(screen.getByText("web01.example.test:2222")).toHaveClass("mono");
      const pill = document.querySelector(".session-pill");
      expect(pill).toHaveAttribute("data-tone", "success");
      expect(pill).toHaveTextContent(/^Connected · 00:00:0\d$/);
      act(() => { vi.advanceTimersByTime(65_000); });
      expect(pill).toHaveTextContent(/^Connected · 00:01:0\d$/);
    } finally {
      vi.useRealTimers();
    }
  });

  it("a connecting tab has no timer", () => {
    const tab = blankTab("t-c", "c1", "ssh");
    act(() => { useSessions.setState({ tabs: [tab], activeTab: tab.id }); });
    render(<SessionHeader tab={tab} connection={conn} />);
    expect(document.querySelector(".session-pill")).toHaveTextContent(/^Connecting$/);
    expect(document.querySelector(".session-timer")).toBeNull();
  });

  it("keeps the toolbar contract: a segmented Session tools group and the Detach to window action", () => {
    const onTool = vi.fn();
    const onDetach = vi.fn();
    render(<SessionToolbar tool="terminal" onTool={onTool} onDetach={onDetach} />);
    const bar = screen.getByRole("toolbar", { name: "Session tools" });
    expect(bar).toHaveClass("segmented");
    expect(within(bar).getAllByRole("button").map((b) => b.textContent)).toEqual(["Terminal", "Forwards", "Files"]);
    expect(within(bar).getByRole("button", { name: "Terminal" })).toHaveAttribute("aria-pressed", "true");
    fireEvent.click(within(bar).getByRole("button", { name: "Files" }));
    expect(onTool).toHaveBeenCalledWith("files");
    const detach = screen.getByRole("button", { name: "Detach to window" });
    expect(detach).toHaveAttribute("title", "Detach to window");
    fireEvent.click(detach);
    expect(onDetach).toHaveBeenCalled();
  });
});
