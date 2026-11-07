import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { App } from "../../App";
import { useCredentials } from "../../stores/credentials";
import { useToasts } from "../../stores/toast";
import { useTree } from "../../stores/tree";
import { useUi } from "../../stores/ui";
import { freshBackend, settle } from "../../test/harness";

// Fixture value only; not a real secret.
const FIXTURE = "fixture-pw-u0-91c";

async function boot() {
  render(<App />);
  await screen.findByText("Nothing open yet");
  await settle();
}

const view = () => screen.getByRole("region", { name: "Credentials" });
const toasts = () => useToasts.getState().toasts.map((t) => t.text);

/** Fill and submit a new "Username and password" credential in the credentials view. */
async function createUserPassword(name: string) {
  fireEvent.click(within(view()).getByRole("button", { name: "Username and password" }));
  const form = within(view()).getByRole("form");
  fireEvent.change(within(form).getByLabelText("Name"), { target: { value: name } });
  fireEvent.change(within(form).getByLabelText("Username"), { target: { value: "deploy" } });
  fireEvent.change(within(form).getByLabelText(/^Password/), { target: { value: FIXTURE } });
  fireEvent.click(within(form).getByRole("button", { name: "Create credential" }));
  await settle();
}

describe("U0: back to the saved item", () => {
  beforeEach(() => { freshBackend(); });

  it("a created credential closes the editor, is selected in the list and shows its detail card", async () => {
    await boot();
    act(() => { useUi.getState().showCredentials({ mode: "new" }); });
    await createUserPassword("deploy pw");
    expect(within(view()).queryByRole("form")).toBeNull();
    const detail = within(view()).getByRole("article", { name: "deploy pw details" });
    expect(detail).toHaveTextContent("deploy");
    expect(detail).toHaveTextContent(/Used by\s*0 connections/);
    expect(within(detail).getByRole("list", { name: "Protocols" })).toHaveTextContent("SSH");
    for (const b of ["Edit", "Delete"]) expect(within(detail).getByRole("button", { name: b })).toBeInTheDocument();
    const row = within(view()).getAllByRole("listitem").find((li) => li.textContent.includes("deploy pw"));
    expect(row).toHaveAttribute("aria-selected", "true");
    expect(toasts()).toEqual(["Credential saved"]);
    expect(screen.getByTestId("toasts")).toHaveTextContent("Credential saved");
    expect(document.body.innerHTML).not.toContain(FIXTURE);
  });

  it("an edited credential also returns to its detail card", async () => {
    await boot();
    act(() => { useUi.getState().showCredentials({ mode: "view", id: "cr-ext" }); });
    await settle();
    fireEvent.click(within(view()).getByRole("button", { name: "Edit" }));
    const form = within(view()).getByRole("form", { name: "Edit db via vault" });
    fireEvent.change(within(form).getByLabelText(/^Reference/), { target: { value: "kv/ops/db2" } });
    fireEvent.click(within(form).getByRole("button", { name: "Save credential" }));
    await settle();
    expect(within(view()).queryByRole("form")).toBeNull();
    expect(within(view()).getByRole("article", { name: "db via vault details" })).toHaveTextContent("kv/ops/db2");
    expect(toasts()).toEqual(["Credential saved"]);
  });

  it("New… in the connection form returns to it with the draft kept and the new credential picked", async () => {
    await boot();
    act(() => { useUi.getState().openDialog({ kind: "connection", folderId: "f-web" }); });
    let dlg = screen.getByRole("dialog", { name: "New connection" });
    fireEvent.change(within(dlg).getByLabelText("Name"), { target: { value: "build box" } });
    fireEvent.change(within(dlg).getByLabelText("Host"), { target: { value: "build.example.test" } });
    fireEvent.change(within(dlg).getByLabelText("Tags"), { target: { value: "ci" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "New credential…" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    await createUserPassword("build pw");

    dlg = screen.getByRole("dialog", { name: "New connection" });
    expect(within(dlg).getByLabelText("Name")).toHaveValue("build box");
    expect(within(dlg).getByLabelText("Host")).toHaveValue("build.example.test");
    expect(within(dlg).getByLabelText("Tags")).toHaveValue("ci");
    expect(within(dlg).getByRole("button", { name: /^Credential/ })).toHaveTextContent("build pw");
    expect(useUi.getState().connectionResume).toBeNull();
    expect(toasts()).toContain("Credential saved");

    // 4: the saved connection is selected in the tree and shown in DETAILS
    fireEvent.click(within(dlg).getByRole("button", { name: "Create connection" }));
    await settle();
    const conn = useTree.getState().connections.find((c) => c.name === "build box");
    const id = useCredentials.getState().items.find((c) => c.name === "build pw")?.id;
    expect(conn?.credentialId).toBe(id);
    expect(useTree.getState().selected).toEqual({ kind: "connection", id: conn?.id });
    expect(screen.getByRole("complementary", { name: "Details" })).toHaveTextContent("build.example.test");
    expect(toasts()).toContain("Connection created");
  });

  it("cancelling the kind picker goes back to the connection form untouched", async () => {
    await boot();
    act(() => { useUi.getState().openDialog({ kind: "connection", id: "c-dc", folderId: "f-desk" }); });
    let dlg = screen.getByRole("dialog", { name: "Edit connection" });
    fireEvent.change(within(dlg).getByLabelText("Tags"), { target: { value: "changed" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "New RD Gateway credential…" }));
    fireEvent.click(within(view()).getByRole("button", { name: "Cancel" }));
    dlg = screen.getByRole("dialog", { name: "Edit connection" });
    expect(within(dlg).getByLabelText("Tags")).toHaveValue("changed");
  });

  it("the RD Gateway New… preselects the new credential in the gateway picker", async () => {
    await boot();
    act(() => { useUi.getState().openDialog({ kind: "connection", id: "c-dc", folderId: "f-desk" }); });
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "New RD Gateway credential…" }));
    await createUserPassword("gw pw");
    const dlg = screen.getByRole("dialog", { name: "Edit connection" });
    expect(within(dlg).getByRole("button", { name: /^RD Gateway credential/ })).toHaveTextContent("gw pw");
    expect(within(dlg).getByRole("button", { name: /^Credential/ })).not.toHaveTextContent("gw pw");
  });

  it("an existing connection saved from its form is selected and toasted", async () => {
    await boot();
    useTree.getState().select(null);
    act(() => { useUi.getState().openDialog({ kind: "connection", id: "c-web01", folderId: "f-web" }); });
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Save connection" }));
    await settle();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(useTree.getState().selected).toEqual({ kind: "connection", id: "c-web01" });
    expect(toasts()).toEqual(["Connection saved"]);
  });
});

describe("U0: AppRole → secret source guidance", () => {
  beforeEach(() => { freshBackend(); });

  it("the not-usable AppRole entry explains where it belongs and opens Settings → Secret sources", async () => {
    await boot();
    act(() => { useUi.getState().openDialog({ kind: "connection", id: "c-web01", folderId: "f-web" }); });
    const dlg = screen.getByRole("dialog");
    fireEvent.click(within(dlg).getByRole("button", { name: /^Credential/ }));
    const list = within(dlg).getByRole("listbox", { name: "Credential" });
    const opt = within(list).getAllByRole("option").find((o) => o.textContent.includes("vault approle"));
    expect(opt).toHaveAttribute("aria-disabled", "true");
    expect(opt).toHaveTextContent("Vault AppRole is only for secret sources.");
    expect(opt).toHaveTextContent("Use it in Settings → Secret sources, then create a Secret manager reference credential.");
    if (!opt) throw new Error("no AppRole option");
    fireEvent.click(within(opt).getByRole("button", { name: "Open Secret sources" }));
    await settle();
    expect(useUi.getState().view).toBe("settings");
    const form = screen.getByRole("dialog", { name: "New secret source" });
    expect(within(form).getByLabelText("AppRole credential")).toHaveValue("cr-approle");
  });

  it("the AppRole detail card shows the hint and Create secret source; creating one selects it in the list", async () => {
    await boot();
    act(() => { useUi.getState().showCredentials({ mode: "view", id: "cr-approle" }); });
    await settle();
    const detail = within(view()).getByRole("article", { name: "vault approle details" });
    expect(detail).toHaveTextContent("Use it in Settings → Secret sources, then create a Secret manager reference credential.");
    expect(within(detail).getByRole("list", { name: "Secret sources signing in with this AppRole" })).toHaveTextContent("ops vault");
    fireEvent.click(within(detail).getByRole("button", { name: "Create secret source" }));
    await settle();
    const form = screen.getByRole("dialog", { name: "New secret source" });
    expect(within(form).getByLabelText("AppRole credential")).toHaveValue("cr-approle");
    fireEvent.change(within(form).getByLabelText("Name"), { target: { value: "team vault" } });
    fireEvent.change(within(form).getByLabelText("Address"), { target: { value: "https://team.example.test:8200" } });
    fireEvent.click(within(form).getByRole("button", { name: "Create source" }));
    await settle();
    expect(screen.queryByRole("dialog")).toBeNull();
    const row = screen.getByRole("listitem", { name: "team vault" });
    expect(row).toHaveAttribute("data-selected", "true");
    expect(row).toHaveAttribute("aria-current", "true");
    expect(toasts()).toEqual(["Secret source saved"]);
  });

  it("an external_ref detail card shows its source and path, never a value", async () => {
    await boot();
    act(() => { useUi.getState().showCredentials({ mode: "view", id: "cr-ext" }); });
    await settle();
    const detail = within(view()).getByRole("article", { name: "db via vault details" });
    expect(detail).toHaveTextContent("ops vault");
    expect(detail).toHaveTextContent("https://vault.example.test:8200");
    expect(detail).toHaveTextContent("kv/ops/db");
    expect(detail).toHaveTextContent("Resolves to");
    // it signs in wherever its target kind (user_password) does
    expect(within(detail).getByRole("list", { name: "Protocols" })).toHaveTextContent("SSH");
    expect(within(detail).getByRole("button", { name: "Test" })).toBeInTheDocument();
  });
});
