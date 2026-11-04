// The web tab is a control card for the isolated `web-<connectionId>` window (ADR-0013).
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { freshBackend, settle } from "../../test/harness";
import type { MockTransport } from "../../lib/ipc.mock";
import { useApp } from "../../stores/app";
import { useSessions } from "../../stores/sessions";
import { useTree } from "../../stores/tree";
import { useUi } from "../../stores/ui";
import { adoptWeb, nextZoom, sanitizeTitle, useWebTabs } from "../../stores/web";
import { Workspace } from "../Workspace";

const tab = () => useSessions.getState().tabs[0];
const bar = () => screen.getByRole("toolbar", { name: "Web window controls" });
const button = (name: string | RegExp) => within(bar()).getByRole("button", { name });

describe("web session tab", () => {
  let mock: MockTransport;
  beforeEach(async () => {
    mock = freshBackend();
    useApp.setState({ vault: "unlocked" });
    await useTree.getState().load();
  });
  afterEach(async () => {
    for (const t of useSessions.getState().tabs) await useSessions.getState().close(t.id);
  });

  async function openLb() {
    await act(async () => { await useSessions.getState().open("c-lb"); });
    render(<Workspace />);
    await settle();
  }

  it("opens the window with web_open (no session_open) and shows title, origin and storage mode", async () => {
    const open = vi.spyOn(mock, "webOpen");
    const session = vi.spyOn(mock, "sessionOpen");
    await openLb();
    expect(open).toHaveBeenCalledWith(expect.objectContaining({ connectionId: "c-lb" }));
    expect(session).not.toHaveBeenCalled();
    expect(tab()).toMatchObject({ protocol: "web", state: "connected", sessionId: null });
    expect(screen.getByTestId("web-title")).toHaveTextContent("edge-lb console");
    expect(screen.getByTestId("web-origin")).toHaveTextContent("https://lb.example.test");
    expect(within(bar()).getByText("Ephemeral")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Detach/ })).toBeNull(); // web sessions are always windows
  });

  it("the title is page-controlled: controls and bidi overrides are stripped, length capped", async () => {
    await openLb();
    act(() => { mock.webSimulate("c-lb", { kind: "title", title: "Sign\u202e in\u0007 ​now\n\tplease" }); });
    expect(screen.getByTestId("web-title")).toHaveTextContent(/^Sign in now please$/);
    expect(Array.from(sanitizeTitle("x".repeat(400)))).toHaveLength(256);
  });

  it("the controls call web_focus / web_reload / web_print / web_zoom / web_close", async () => {
    await openLb();
    const calls = {
      focus: vi.spyOn(mock, "webFocus"), reload: vi.spyOn(mock, "webReload"), print: vi.spyOn(mock, "webPrint"),
      zoom: vi.spyOn(mock, "webZoom"), close: vi.spyOn(mock, "webClose"),
    };
    fireEvent.click(button("Focus"));
    fireEvent.click(button("Reload"));
    fireEvent.click(button("Print"));
    fireEvent.click(button("Zoom in"));
    await settle();
    expect(button("Reset zoom")).toHaveTextContent("110%");
    fireEvent.click(button("Zoom out"));
    fireEvent.click(button("Zoom out"));
    await settle();
    expect(button("Reset zoom")).toHaveTextContent("90%");
    fireEvent.click(button("Reset zoom"));
    await settle();
    expect(calls.zoom.mock.calls.map((c) => c[0].factor)).toEqual([1.1, 1, 0.9, 1]);
    for (const k of ["focus", "reload", "print"] as const) expect(calls[k]).toHaveBeenCalledWith({ connectionId: "c-lb" });
    fireEvent.click(button("Close window"));
    await settle();
    expect(calls.close).toHaveBeenCalledWith({ connectionId: "c-lb" });
    expect(tab()?.state).toBe("closed");
    expect(screen.getByText("Window closed")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Reopen window" }));
    await settle();
    expect(tab()?.state).toBe("connected");
    expect(nextZoom(5, 1)).toBe(5);
    expect(nextZoom(0.25, -1)).toBe(0.25);
  });

  it("Focus and Print are disabled while the vault is locked; Reload and zoom are not", async () => {
    await openLb();
    act(() => { useApp.setState({ vault: "locked" }); });
    expect(button("Focus")).toBeDisabled();
    expect(button("Print")).toBeDisabled();
    expect(button("Reload")).toBeEnabled();
    expect(button("Zoom in")).toBeEnabled();
  });

  it("Clear site data asks first (Cancel focused) and is audited", async () => {
    await openLb();
    const clear = vi.spyOn(mock, "webClearData");
    fireEvent.click(button("Clear site data…"));
    const dialog = screen.getByRole("dialog", { name: "Clear site data" });
    expect(dialog).toHaveTextContent("edge-lb");
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toHaveFocus();
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(clear).not.toHaveBeenCalled();
    fireEvent.click(button("Clear site data…"));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Clear site data" }));
    await settle();
    expect(clear).toHaveBeenCalledWith({ connectionId: "c-lb" });
    expect(mock.audit.at(-1)?.event).toBe("web_data_cleared");
    expect(screen.getByRole("status")).toHaveTextContent("Site data cleared");
  });

  it("shows blocked navigations and downloads with the refused origin; Edit connection opens the dialog", async () => {
    await openLb();
    act(() => {
      mock.webSimulate("c-lb", { kind: "blocked", origin: "https://sso.example.test" });
      mock.webSimulate("c-lb", { kind: "download_blocked", origin: "https://lb.example.test" });
    });
    const list = screen.getByRole("list", { name: "Refused by the window" });
    const items = within(list).getAllByRole("listitem");
    expect(items[0]).toHaveTextContent("Download blocked");
    expect(items[0]).toHaveTextContent("https://lb.example.test");
    expect(items[1]).toHaveTextContent("Blocked navigation");
    expect(items[1]).toHaveTextContent("https://sso.example.test");
    fireEvent.click(within(items[1] as HTMLElement).getByRole("button", { name: "Edit connection" }));
    expect(useUi.getState().dialog).toEqual({ kind: "connection", id: "c-lb", folderId: "f-web" });
    fireEvent.click(within(items[0] as HTMLElement).getByRole("button", { name: "Dismiss download blocked" }));
    expect(within(list).getAllByRole("listitem")).toHaveLength(1);
    for (let i = 0; i < 9; i++) act(() => { mock.webSimulate("c-lb", { kind: "blocked", origin: `https://o${String(i)}.example.test` }); });
    expect(useWebTabs.getState().byTab[tab()?.id ?? ""]?.notices).toHaveLength(5);
  });

  it("persistent storage shows a badge; a native close turns the tab closed", async () => {
    await mock.connectionOptionsSet({ connectionId: "c-lb", options: { url: "https://lb.example.test", allowedOrigins: [], persistent: true, allowHttp: false } });
    await openLb();
    expect(within(bar()).getByText("Persistent storage")).toBeInTheDocument();
    act(() => { mock.webSimulate("c-lb", { kind: "closed" }); });
    expect(tab()).toMatchObject({ state: "closed", reason: "The web window was closed." });
    expect(button("Focus")).toBeDisabled();
  });

  it("closing the tab closes the window; after a lock the window comes back as a tab on a new channel", async () => {
    await openLb();
    useSessions.getState().reset(); // lock: the tab goes, the window is only hidden
    await adoptWeb();
    await settle();
    expect(tab()).toMatchObject({ protocol: "web", connectionId: "c-lb", state: "connected" });
    expect(useWebTabs.getState().byTab[tab()?.id ?? ""]).toMatchObject({ title: "edge-lb console", origin: "https://lb.example.test" });
    act(() => { mock.webSimulate("c-lb", { kind: "blocked", origin: "https://x.example.test" }); });
    expect(useWebTabs.getState().byTab[tab()?.id ?? ""]?.notices).toHaveLength(1);
    const close = vi.spyOn(mock, "webClose");
    await act(async () => { await useSessions.getState().close(tab()?.id ?? ""); });
    expect(close).toHaveBeenCalledWith({ connectionId: "c-lb" });
    expect(await mock.webList()).toEqual([]);
  });
});
