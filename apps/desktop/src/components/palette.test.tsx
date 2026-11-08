// L3: the command palette as the hub: recent connections, actions with shortcuts, settings pages.
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { App } from "../App";
import { useApp } from "../stores/app";
import { clearRecent, recentConnections, trackTabs } from "../stores/recent";
import { useSessions } from "../stores/sessions";
import { useUi } from "../stores/ui";
import { freshBackend, settle } from "../test/harness";

async function boot() {
  render(<App />);
  await screen.findByText("Nothing open yet");
  await settle();
}

async function openPalette() {
  fireEvent.keyDown(window, { key: "k", ctrlKey: true });
  const input = await screen.findByLabelText("Search connections");
  await settle();
  return input;
}

const group = (name: string) => within(screen.getByRole("listbox", { name: "Results" })).getByRole("group", { name });
const groupNames = () => within(screen.getByRole("listbox", { name: "Results" })).getAllByRole("group").map((g) => g.getAttribute("aria-labelledby")?.replace("palette-g-", ""));

describe("recent connections", () => {
  beforeEach(() => { clearRecent(); });
  it("keeps the newest first, once each, and at most six", () => {
    trackTabs([{ id: "t1", connectionId: "a" }]);
    trackTabs([{ id: "t1", connectionId: "a" }, { id: "t2", connectionId: "b" }]);
    trackTabs([{ id: "t2", connectionId: "b" }, { id: "t3", connectionId: "a" }]);
    expect(recentConnections()).toEqual(["a", "b"]);
    trackTabs(["c", "d", "e", "f", "g"].map((c, i) => ({ id: `x${String(i)}`, connectionId: c })));
    expect(recentConnections()).toEqual(["g", "f", "e", "d", "c", "a"]);
  });
});

describe("command palette (L3)", () => {
  beforeEach(() => {
    freshBackend();
    clearRecent();
  });

  it("lists recent connections first, then connections and actions with their shortcuts", async () => {
    await boot();
    await act(async () => { await useSessions.getState().open("c-dc"); });
    await settle();
    await openPalette();
    expect(groupNames()).toEqual(["recent", "conns", "actions"]);
    expect(within(group("Recent")).getAllByRole("option")[0]).toHaveTextContent("dc01");
    expect(within(group("Connections")).queryByText("dc01")).toBeNull(); // not twice
    const lock = within(group("Actions")).getByRole("option", { name: /Lock vault/ });
    expect(within(lock).getByText("Ctrl ⇧ L")).toBeInTheDocument();
    expect(within(group("Actions")).getByRole("option", { name: /Go to Credentials/ })).toHaveTextContent("Ctrl 2");
    expect(within(group("Actions")).getByRole("option", { name: /Close tab/ })).toHaveTextContent("Ctrl W");
    for (const t of useSessions.getState().tabs) await act(async () => { await useSessions.getState().close(t.id); });
  });

  it("finds an action by its words and runs it", async () => {
    await boot();
    const input = await openPalette();
    fireEvent.change(input, { target: { value: "new credential" } });
    await settle();
    expect(screen.getAllByRole("option")[0]).toHaveTextContent("New credential");
    fireEvent.keyDown(input, { key: "Enter" });
    expect(useUi.getState().view).toBe("credentials");
    expect(useUi.getState().credentialPane).toEqual({ mode: "new" });
  });

  it("opens a settings page from the Settings group", async () => {
    await boot();
    const input = await openPalette();
    fireEvent.change(input, { target: { value: "syslog" } });
    await settle();
    const page = within(group("Settings")).getByRole("option", { name: /Syslog mirror/ });
    fireEvent.click(page);
    expect(useUi.getState().view).toBe("settings");
    expect(screen.queryByRole("dialog", { name: "Command palette" })).toBeNull();
  });

  it("forgets recent connections when the vault locks", async () => {
    await boot();
    await act(async () => { await useSessions.getState().open("c-web01"); });
    expect(recentConnections()).toContain("c-web01");
    await act(async () => { await useApp.getState().lock(); });
    expect(recentConnections()).toEqual([]);
  });
});
