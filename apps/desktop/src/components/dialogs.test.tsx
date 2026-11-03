import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { App } from "../App";
import { appCommandFor } from "../lib/shortcuts";
import { useCredentials } from "../stores/credentials";
import { useTree } from "../stores/tree";
import { useUi } from "../stores/ui";
import { freshBackend, settle } from "../test/harness";

const key = (k: string, mods: Partial<KeyboardEventInit> = {}) => new KeyboardEvent("keydown", { key: k, ...mods });

describe("shortcuts", () => {
  it("leaves Ctrl+K and Ctrl+W to the shell inside a terminal on Linux/Windows", () => {
    expect(appCommandFor(key("k", { ctrlKey: true }), true)).toBeNull();
    expect(appCommandFor(key("w", { ctrlKey: true }), true)).toBeNull();
    expect(appCommandFor(key("K", { ctrlKey: true, shiftKey: true }), true)).toBe("palette");
    expect(appCommandFor(key("k", { ctrlKey: true }), false)).toBe("palette");
    expect(appCommandFor(key("Tab", { ctrlKey: true }), true)).toBe("nextTab");
  });
});

describe("editor dialogs", () => {
  beforeEach(() => { freshBackend(); });

  async function boot() {
    render(<App />);
    await screen.findByText("Nothing open yet");
    await settle();
  }

  it("creates a credential and clears the secret field on submit", async () => {
    await boot();
    act(() => { useUi.getState().openDialog({ kind: "credential" }); });
    const dlg = screen.getByRole("dialog", { name: "New credential" });
    fireEvent.change(within(dlg).getByLabelText("Name"), { target: { value: "lab root" } });
    fireEvent.change(within(dlg).getByLabelText("Username"), { target: { value: "root" } });
    const secret = within(dlg).getByLabelText("Password");
    fireEvent.change(secret, { target: { value: "fixture-not-a-secret" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Create credential" }));
    expect(secret).toHaveValue("");
    await settle();
    expect(useCredentials.getState().items.some((c) => c.name === "lab root")).toBe(true);
    expect(screen.getByRole("dialog", { name: "Credentials" })).toHaveTextContent("lab root");
  });

  it("creates a connection in the selected folder and selects it", async () => {
    await boot();
    act(() => { useTree.getState().select({ kind: "folder", id: "f-staging" }); });
    const nav = screen.getByRole("navigation", { name: "Connection tree" });
    fireEvent.click(within(nav).getByRole("button", { name: "New connection" }));
    const dlg = screen.getByRole("dialog", { name: "New connection" });
    fireEvent.change(within(dlg).getByLabelText("Name"), { target: { value: "stage-db" } });
    fireEvent.change(within(dlg).getByLabelText("Host"), { target: { value: "db.stage.example.test" } });
    fireEvent.change(within(dlg).getByLabelText("Port"), { target: { value: "70000" } });
    expect(within(dlg).getByRole("button", { name: "Create connection" })).toBeDisabled();
    fireEvent.change(within(dlg).getByLabelText("Port"), { target: { value: "" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Create connection" }));
    await settle();
    const c = useTree.getState().connections.find((x) => x.name === "stage-db");
    expect(c?.folderId).toBe("f-staging");
    expect(useTree.getState().selected).toEqual({ kind: "connection", id: c?.id });
  });
});
