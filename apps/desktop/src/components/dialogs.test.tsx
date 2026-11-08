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

  it("mod+1…4 open the rail's views; inside a terminal only with Shift", () => {
    expect(appCommandFor(key("1", { ctrlKey: true }), false)).toBe("viewHosts");
    expect(appCommandFor(key("2", { ctrlKey: true }), false)).toBe("viewCredentials");
    expect(appCommandFor(key("3", { ctrlKey: true }), false)).toBe("viewAudit");
    expect(appCommandFor(key("4", { ctrlKey: true }), false)).toBe("viewSettings");
    expect(appCommandFor(key("5", { ctrlKey: true }), false)).toBeNull();
    expect(appCommandFor(key("1", { ctrlKey: true }), true)).toBeNull();
    expect(appCommandFor(key("!", { ctrlKey: true, shiftKey: true, code: "Digit1" }), true)).toBe("viewHosts");
  });
});

describe("navigation rail", () => {
  beforeEach(() => { freshBackend(); });

  it("switches views, marks the current one, returns to Hosts on a second press and answers mod+1…4", async () => {
    render(<App />);
    await screen.findByText("Nothing open yet");
    await settle();
    const rail = within(screen.getByRole("navigation", { name: "Views" }));
    expect(rail.getByRole("button", { name: "Hosts" })).toHaveAttribute("aria-current", "page");
    // Q7 / M1: only Hosts has the tree and the details pane.
    expect(screen.getByRole("complementary", { name: "Details" })).toBeInTheDocument();

    fireEvent.click(rail.getByRole("button", { name: "Audit log" }));
    expect(screen.getByRole("region", { name: "Audit log" })).toBeInTheDocument();
    expect(rail.getByRole("button", { name: "Audit log" })).toHaveAttribute("aria-current", "page");
    expect(screen.queryByRole("complementary", { name: "Details" })).toBeNull();
    expect(screen.queryByRole("tree", { name: "Connections" })).toBeNull();

    fireEvent.click(rail.getByRole("button", { name: "Audit log" }));
    expect(useUi.getState().view).toBe("workspace");
    expect(screen.getByRole("tree", { name: "Connections" })).toBeInTheDocument();

    fireEvent.keyDown(window, { key: "2", code: "Digit2", ctrlKey: true });
    expect(useUi.getState().view).toBe("credentials");
    fireEvent.keyDown(window, { key: "2", code: "Digit2", ctrlKey: true });
    expect(useUi.getState().view).toBe("credentials");
    fireEvent.keyDown(window, { key: "4", code: "Digit4", ctrlKey: true });
    expect(screen.getByRole("region", { name: "Settings" })).toBeInTheDocument();
    fireEvent.keyDown(window, { key: "1", code: "Digit1", ctrlKey: true });
    expect(useUi.getState().view).toBe("workspace");
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
    act(() => { useUi.getState().showCredentials({ mode: "new" }); });
    const view = screen.getByRole("region", { name: "Credentials" });
    fireEvent.click(within(view).getByRole("button", { name: "Username and password" }));
    const form = within(view).getByRole("form", { name: "New Username and password" });
    fireEvent.change(within(form).getByLabelText("Name"), { target: { value: "lab root" } });
    fireEvent.change(within(form).getByLabelText("Username"), { target: { value: "root" } });
    const secret = within(form).getByLabelText(/^Password/);
    fireEvent.change(secret, { target: { value: "fixture-not-a-secret" } });
    fireEvent.click(within(form).getByRole("button", { name: "Create credential" }));
    expect(secret).toHaveValue("");
    await settle();
    expect(useCredentials.getState().items.some((c) => c.name === "lab root")).toBe(true);
    expect(within(view).getByRole("list", { name: "Stored credentials" })).toHaveTextContent("lab root");
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
