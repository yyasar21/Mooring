import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { App } from "../App";
import { copyKey, useCredentials } from "../stores/credentials";
import { useSessions } from "../stores/sessions";
import { useTree } from "../stores/tree";
import { useUi } from "../stores/ui";
import type { MockTransport } from "../lib/ipc.mock";
import { freshBackend, settle } from "../test/harness";
import { fakeTerms } from "../test/fakeTerm";

async function boot() {
  render(<App />);
  await screen.findByText("Nothing open yet");
  await settle();
}

describe("connection tree keyboard navigation", () => {
  beforeEach(() => { freshBackend(); });

  it("moves with arrows, collapses with left, expands with right and opens with Enter", async () => {
    await boot();
    const tree = screen.getByRole("tree", { name: "Connections" });
    const root = within(tree).getByRole("treeitem", { name: "All connections" });
    act(() => { root.focus(); });
    fireEvent.keyDown(tree, { key: "ArrowDown" });
    expect(useTree.getState().selected).toEqual({ kind: "folder", id: "f-prod" });
    expect(within(tree).getByRole("treeitem", { name: "Production" })).toHaveFocus();

    fireEvent.keyDown(tree, { key: "ArrowLeft" });
    expect(within(tree).getByRole("treeitem", { name: "Production" })).toHaveAttribute("aria-expanded", "false");
    expect(within(tree).queryByRole("treeitem", { name: /web01/ })).toBeNull();

    fireEvent.keyDown(tree, { key: "ArrowRight" });
    fireEvent.keyDown(tree, { key: "ArrowRight" }); // into first child: Web tier
    fireEvent.keyDown(tree, { key: "ArrowRight" }); // its first child
    fireEvent.keyDown(tree, { key: "ArrowDown" });
    expect(useTree.getState().selected).toEqual({ kind: "connection", id: "c-web01" });

    fireEvent.keyDown(tree, { key: "ArrowLeft" }); // to parent folder
    expect(useTree.getState().selected).toEqual({ kind: "folder", id: "f-web" });
    fireEvent.keyDown(tree, { key: "ArrowDown" });
    fireEvent.keyDown(tree, { key: "ArrowDown" });
    fireEvent.keyDown(tree, { key: "Enter" });
    await settle();
    expect(screen.getByRole("tab", { name: /web01/ })).toHaveAttribute("aria-selected", "true");
  });

  it("renames inline with F2", async () => {
    await boot();
    act(() => { useTree.getState().select({ kind: "connection", id: "c-dc" }); });
    const tree = screen.getByRole("tree", { name: "Connections" });
    fireEvent.keyDown(tree, { key: "F2" });
    const field = screen.getByLabelText("New name");
    fireEvent.change(field, { target: { value: "dc01-renamed" } });
    fireEvent.keyDown(field, { key: "Enter" });
    await settle();
    expect(within(tree).getByRole("treeitem", { name: /dc01-renamed/ })).toBeInTheDocument();
  });
});

describe("command palette", () => {
  beforeEach(() => { freshBackend(); });

  it("opens a connection by fuzzy search through connection_search", async () => {
    await boot();
    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    const input = await screen.findByLabelText("Search connections");
    fireEvent.change(input, { target: { value: "lbkio" } });
    await settle();
    const options = screen.getAllByRole("option");
    expect(options[0]).toHaveTextContent("lobby-kiosk");
    fireEvent.keyDown(input, { key: "Enter" });
    await settle();
    expect(screen.queryByRole("dialog", { name: "Command palette" })).toBeNull();
    expect(screen.getByRole("tab", { name: /lobby-kiosk/ })).toHaveAttribute("aria-selected", "true");
  });
});

describe("inspector copy secret", () => {
  beforeEach(() => { freshBackend(); });

  it("lists copyable secretNames in the menu and shows a countdown after Rust copies", async () => {
    await boot();
    const writeText = vi.fn();
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    act(() => { useTree.getState().select({ kind: "connection", id: "c-stg" }); });
    const details = screen.getByRole("complementary", { name: "Details" });
    expect(details).toHaveTextContent("deploy bot");
    expect(details).toHaveTextContent("deploy");

    fireEvent.click(within(details).getByRole("button", { name: "Copy secret" }));
    const menu = within(details).getByRole("menu", { name: "Copy secret" });
    const entries = within(menu).getAllByRole("menuitem").map((m) => m.textContent);
    expect(entries).toEqual(["Copy password", "Copy OTP code"]);
    fireEvent.click(within(menu).getByRole("menuitem", { name: "Copy password" }));
    await settle();
    expect(within(details).getByRole("status", { name: /Clipboard clears in 30 seconds/ })).toBeInTheDocument();
    expect(useCredentials.getState().copiedUntil[copyKey("cr-deploy", "password")]).toBeGreaterThan(Date.now());
    expect(writeText).not.toHaveBeenCalled();
  });

  it("shows role rows: RD Gateway on RDP, become on SSH, and the username override", async () => {
    await boot();
    act(() => { useTree.getState().select({ kind: "connection", id: "c-dc" }); });
    const details = screen.getByRole("complementary", { name: "Details" });
    const signIn = within(details).getByRole("group", { name: "Sign-in credential" });
    expect(signIn).toHaveTextContent("EXAMPLE\\dc-adminoverride"); // override keeps the credential's domain
    expect(within(details).getByRole("group", { name: "RD Gateway credential" })).toHaveTextContent("domain admin");
    act(() => { useTree.getState().select({ kind: "connection", id: "c-pg" }); });
    expect(within(details).getByRole("group", { name: "Become credential" })).toHaveTextContent("sudo as root");
  });
});

describe("session prompt", () => {
  let mock: MockTransport;
  beforeEach(() => {
    mock = freshBackend();
    fakeTerms.length = 0;
  });

  it("answers TOFU then keyboard-interactive and the terminal echoes typed input", async () => {
    await boot();
    await act(async () => { await useSessions.getState().open("c-pg"); });
    await settle();
    const trust = await screen.findByRole("alertdialog", { name: "Verify host identity" });
    expect(trust).toHaveTextContent("pg01.example.test");
    fireEvent.click(within(trust).getByRole("button", { name: "Trust and connect" }));
    await settle();
    expect(mock.trustedHosts.has("pg01.example.test")).toBe(true);

    const otp = await screen.findByRole("alertdialog");
    const answer = within(otp).getByLabelText("Answer");
    expect(answer).toHaveAttribute("type", "password");
    fireEvent.change(answer, { target: { value: "123456" } });
    fireEvent.click(within(otp).getByRole("button", { name: "Send" }));
    await settle();
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(useSessions.getState().tabs[0]?.state).toBe("connected");

    const term = fakeTerms.at(-1);
    expect(term?.output).toMatch(/Mock shell on pg01/);
    act(() => { term?.type("whoami"); });
    await settle();
    expect(term?.output).toMatch(/whoami$/);
  });

  it("rejecting closes the session and offers reconnect", async () => {
    await boot();
    await act(async () => { await useSessions.getState().open("c-web02"); });
    await settle();
    const dlg = await screen.findByRole("alertdialog");
    fireEvent.click(within(dlg).getByRole("button", { name: "Reject and disconnect" }));
    await settle();
    expect(screen.getByText(/host key rejected/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reconnect" })).toBeInTheDocument();
  });
});

describe("audit viewer", () => {
  beforeEach(() => { freshBackend(); });

  it("lists entries newest first, filters, and shows the verify result", async () => {
    await boot();
    await act(async () => { await useCredentials.getState().copySecret("cr-ad", "password"); });
    act(() => { useUi.getState().setView("audit"); });
    await settle();
    const list = screen.getByRole("list", { name: "Entries, newest first" });
    const items = within(list).getAllByRole("listitem");
    expect(items[0]).toHaveTextContent("Secret copied");
    expect(items[0]).toHaveTextContent("domain admin");
    expect(screen.getByRole("status")).toHaveTextContent(/Chain intact/);

    fireEvent.change(screen.getByLabelText("Filter audit entries"), { target: { value: "closed" } });
    const filtered = within(list).getAllByRole("listitem");
    expect(filtered).toHaveLength(1);
    expect(filtered[0]).toHaveTextContent("Session closed");
  });
});
