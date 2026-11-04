// ADR-0015 UI: the import wizard, the sync status panel, the synced tree (badges, missing rows,
// read-only affordances with editable overlays) and the VM inspector (power, identity, consoles).
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { App } from "../../App";
import type { VsphereConnOptions } from "../../lib/ipc";
import type { MockTransport } from "../../lib/ipc.mock";
import { useConnOptions } from "../../stores/connOptions";
import { useTree } from "../../stores/tree";
import { useUi } from "../../stores/ui";
import { freshBackend, settle } from "../../test/harness";
import { POLL_MS } from "./useVsphere";

async function boot() {
  render(<App />);
  await screen.findByText("Nothing open yet");
  await settle();
}

const tree = () => screen.getByRole("tree", { name: "Connections" });
const details = () => screen.getByRole("complementary", { name: "Details" });
const row = (name: RegExp) => within(tree()).getByRole("treeitem", { name });

/** Enable sync through the mock, reload the tree and expand the synced subtree. */
async function syncedTree(mock: MockTransport) {
  const root = await mock.vsphereSyncEnable({ connectionId: "c-vc", parentFolderId: "f-staging" });
  await act(async () => { await useTree.getState().load(); });
  act(() => { for (const f of useTree.getState().folders) if (f.syncSource) useTree.getState().toggle(f.id, true); });
  await settle();
  return root;
}

const selectRow = (name: RegExp) => { fireEvent.click(row(name)); };
const vmId = (mock: MockTransport, ext: string) => mock.connections.find((c) => c.externalId === ext)?.id ?? "";

describe("vSphere · import wizard", () => {
  let mock: MockTransport;
  beforeEach(() => { mock = freshBackend(); });

  it("tests the sign-in, picks the parent folder, imports and shows the report", async () => {
    await boot();
    selectRow(/^stage-vcenter,/);
    await settle();
    expect(within(details()).queryByRole("button", { name: "Connect" })).toBeNull();
    fireEvent.click(within(details()).getByRole("button", { name: "Import inventory…" }));
    const dialog = screen.getByRole("dialog", { name: "Import vCenter inventory" });
    await settle();
    expect(within(dialog).getByRole("status")).toHaveTextContent("Signed in as administrator@vsphere.local · vCenter 8.0.3.00400 (build 24322831)");
    fireEvent.click(within(dialog).getByRole("button", { name: "Next" }));
    const parent = within(dialog).getByLabelText("Put the inventory under");
    expect(parent).toHaveValue("f-staging"); // the vCenter's own folder
    fireEvent.change(parent, { target: { value: "f-root" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Next" }));
    expect(within(dialog).getByText("Top level / stage-vcenter")).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole("button", { name: "Start import" }));
    await settle();
    expect(within(dialog).getByRole("status")).toHaveTextContent("Inventory imported into “stage-vcenter”.");
    expect(within(dialog).getByRole("group", { name: "Last refresh" })).toHaveTextContent("5added0changed0missing0deleted");
    const root = mock.folders.find((f) => f.syncSource === "c-vc" && !f.externalId);
    expect(root?.parentId).toBe("f-root");
    fireEvent.click(within(dialog).getByRole("button", { name: "Show the folder" }));
    await settle();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(useTree.getState().selected).toEqual({ kind: "folder", id: root?.id });
    expect(within(tree()).getByRole("treeitem", { name: /^app-vm-01, 192\.0\.2\.21, synced from stage-vcenter$/ })).toBeInTheDocument();
  });

  it("maps a failed sign-in and a failed import to plain text; a failed import leaves no folder", async () => {
    mock.vsphereDown.add("c-vc");
    await boot();
    selectRow(/^stage-vcenter,/);
    fireEvent.click(within(details()).getByRole("button", { name: "Import inventory…" }));
    const dialog = screen.getByRole("dialog", { name: "Import vCenter inventory" });
    await settle();
    expect(within(dialog).getByRole("alert")).toHaveTextContent("vCenter did not answer. Check the host, port and network, then try again.");
    expect(within(dialog).getByRole("button", { name: "Next" })).toBeDisabled();
    mock.vsphereDown.clear();
    fireEvent.click(within(dialog).getByRole("button", { name: "Test again" }));
    await settle();
    fireEvent.click(within(dialog).getByRole("button", { name: "Next" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "Next" }));
    mock.vsphereDown.add("c-vc");
    fireEvent.click(within(dialog).getByRole("button", { name: "Start import" }));
    await settle();
    expect(within(dialog).getByRole("alert")).toHaveTextContent("vCenter did not answer");
    expect(within(dialog).getByRole("button", { name: "Try again" })).toBeEnabled();
    expect(mock.folders.some((f) => f.syncSource === "c-vc")).toBe(false);
    expect(mock.vcenters.has("c-vc")).toBe(false);
  });
});

describe("vSphere · synced tree and read-only affordances", () => {
  let mock: MockTransport;
  beforeEach(() => { mock = freshBackend(); });

  it("badges the root and child folders, dims a missing VM, and refuses F2 / drag / drop / new items", async () => {
    await boot();
    await syncedTree(mock);
    const root = row(/^stage-vcenter, synced from stage-vcenter$/);
    expect(within(root).getByRole("img", { name: /Synced from stage-vcenter/ })).toHaveTextContent("stage-vcenter");
    const dc = row(/^DC-East, synced/);
    expect(within(dc).getByRole("img", { name: /Synced from stage-vcenter/ })).toHaveTextContent(""); // compact: glyph only
    expect(root).toHaveAttribute("aria-readonly", "true");
    expect(root).toHaveAttribute("draggable", "false");
    expect(row(/^web01,/)).toHaveAttribute("draggable", "true");

    // F2 on a synced row shows the reason instead of the rename field.
    fireEvent.click(root);
    fireEvent.keyDown(tree(), { key: "F2" });
    expect(screen.queryByLabelText("New name")).toBeNull();
    expect(within(screen.getByRole("navigation", { name: "Connection tree" })).getByRole("alert")).toHaveTextContent("Synced from vCenter: this item is read-only.");
    expect(useUi.getState().renaming).toBeNull();

    // Toolbar: nothing new inside the subtree.
    const toolbar = within(screen.getByRole("navigation", { name: "Connection tree" }));
    expect(toolbar.getByRole("button", { name: "New connection" })).toBeDisabled();
    expect(toolbar.getByRole("button", { name: "New folder" })).toHaveAttribute("title", expect.stringContaining("read-only"));
    expect(within(details()).getByRole("button", { name: "New connection" })).toBeDisabled();
    expect(within(details()).getByRole("button", { name: "Default credential…" })).toBeEnabled();

    // Dropping an ordinary row onto a synced folder is refused before any IPC call.
    const moveSpy = vi.spyOn(mock, "connectionMove");
    fireEvent.dragStart(row(/^web01,/), { dataTransfer: { effectAllowed: "" } });
    fireEvent.dragOver(dc);
    expect(dc).not.toHaveAttribute("data-drop");
    fireEvent.drop(dc);
    expect(moveSpy).not.toHaveBeenCalled();

    // A missing VM is dimmed and labelled.
    mock.vsphereHidden.add("vm-build-vm");
    await mock.vsphereRefresh({ connectionId: "c-vc" });
    await act(async () => { await useTree.getState().load(); });
    const missing = row(/^build-vm, .*, missing in vCenter$/);
    expect(missing).toHaveAttribute("data-sync", "missing");
    expect(within(missing).getByText("missing")).toBeInTheDocument();
    expect(row(/^app-vm-01,/)).toHaveAttribute("data-sync", "synced");
  });

  it("the folder dialog of a synced folder only edits the default credential", async () => {
    await boot();
    const root = await syncedTree(mock);
    selectRow(/^stage-vcenter, synced/);
    fireEvent.click(within(details()).getByRole("button", { name: "Default credential…" }));
    const dialog = screen.getByRole("dialog", { name: "Folder default credential" });
    expect(within(dialog).getByLabelText("Name")).toBeDisabled();
    expect(within(dialog).queryByRole("button", { name: /Delete folder/ })).toBeNull();
    fireEvent.change(within(dialog).getByLabelText("Default credential"), { target: { value: "cr-vc" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Save folder" }));
    await settle();
    expect(mock.folders.find((f) => f.id === root.id)?.defaultCredentialId).toBe("cr-vc");
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("the connection dialog of a VM row edits overlays only and saves them", async () => {
    await boot();
    await syncedTree(mock);
    selectRow(/^app-vm-01,/);
    await settle();
    fireEvent.click(within(details()).getByRole("button", { name: "Edit overlays" }));
    const dialog = screen.getByRole("dialog", { name: "Edit VM overlays" });
    await settle();
    expect(within(dialog).queryByRole("region", { name: "vCenter options" })).toBeNull(); // those belong to the vCenter row
    for (const label of ["Name", "Host", "Port", "Protocol", "Folder"]) expect(within(dialog).getByLabelText(label)).toBeDisabled();
    expect(within(dialog).getByRole("note")).toHaveTextContent("read-only");
    expect(within(dialog).queryByRole("button", { name: "Delete" })).toBeNull();
    fireEvent.change(within(dialog).getByLabelText("Tags"), { target: { value: "linux app" } });
    expect(within(dialog).getByRole("button", { name: "Save overlays" })).toBeEnabled();
    fireEvent.click(within(dialog).getByRole("button", { name: "Save overlays" }));
    await settle();
    expect(within(dialog).getByRole("alert")).toHaveTextContent("");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(mock.connections.find((c) => c.externalId === "vm-app-vm-01")?.tags).toEqual(["linux", "app"]);
  });
});

describe("vSphere · VM inspector", () => {
  let mock: MockTransport;
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    mock = freshBackend();
  });
  afterEach(() => { vi.useRealTimers(); });

  it("polls the power state only while visible, hides the power menu until the opt-in, flags stop/reset", async () => {
    const powerSpy = vi.spyOn(mock, "vsphereVmPower");
    await boot();
    await syncedTree(mock);
    selectRow(/^app-vm-01,/);
    await settle();
    const panel = within(details()).getByRole("region", { name: "Virtual machine" });
    expect(within(panel).getByRole("status")).toHaveTextContent("Powered on");
    expect(powerSpy).toHaveBeenCalledTimes(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(POLL_MS + 50); });
    expect(powerSpy).toHaveBeenCalledTimes(2);
    expect(powerSpy).toHaveBeenLastCalledWith({ connectionId: vmId(mock, "vm-app-vm-01") });

    const power = within(panel).getByRole("button", { name: "Power" });
    expect(power).toBeDisabled();
    expect(power).toHaveAttribute("title", "Power actions are off for stage-vcenter. Turn them on in its connection options.");
    expect(within(panel).getByRole("button", { name: "VMRC" })).toBeDisabled();
    expect(within(details()).getByRole("region", { name: "Guest identity" })).toHaveTextContent("app-vm-01.example.test");

    // Opt in (as the options form would) and open the menu.
    await act(async () => {
      const opts = (await mock.connectionOptionsGet({ connectionId: "c-vc" })) as VsphereConnOptions;
      await useConnOptions.getState().save("c-vc", "vsphere-console", { ...opts, allowPowerActions: true, allowVmrc: true });
    });
    expect(power).toBeEnabled();
    fireEvent.click(power);
    const menu = screen.getByRole("menu", { name: "Power actions" });
    const items = within(menu).getAllByRole("menuitem");
    expect(items.map((i) => i.textContent)).toEqual([
      "Power onAlready powered on.", "Shut down guestneeds VMware Tools", "Reboot guestneeds VMware Tools", "Power offmay lose data", "Resetmay lose data",
    ]);
    expect(items[0]).toHaveAttribute("aria-disabled", "true");
    expect(items[3]).toHaveAttribute("data-destructive", "true");
    expect(items[4]).toHaveAttribute("data-destructive", "true");
    expect(items[1]).toHaveFocus(); // first enabled item

    // Leaving the row stops the polling.
    selectRow(/^web01,/);
    await settle();
    const calls = powerSpy.mock.calls.length;
    await act(async () => { await vi.advanceTimersByTimeAsync(POLL_MS * 2); });
    expect(powerSpy).toHaveBeenCalledTimes(calls);
  });

  it("runs an action through the native dialog: done, cancelled and refused outcomes", async () => {
    await boot();
    await syncedTree(mock);
    await act(async () => {
      const opts = (await mock.connectionOptionsGet({ connectionId: "c-vc" })) as VsphereConnOptions;
      await useConnOptions.getState().save("c-vc", "vsphere-console", { ...opts, allowPowerActions: true });
    });
    selectRow(/^app-vm-01,/);
    await settle();
    const panel = () => within(details()).getByRole("region", { name: "Virtual machine" });
    const actionSpy = vi.spyOn(mock, "vsphereVmAction");

    // 6b B-6: the hints describe the three-button system dialog (only a click on the action confirms)
    expect(within(panel()).getByRole("button", { name: "Power" })).toHaveAttribute("title", expect.stringContaining("three buttons (Cancel, the action, Not now)"));
    fireEvent.click(within(panel()).getByRole("button", { name: "Power" }));
    fireEvent.click(within(screen.getByRole("menu")).getByRole("menuitem", { name: /^Power off/ }));
    await settle();
    expect(actionSpy).toHaveBeenLastCalledWith({ connectionId: vmId(mock, "vm-app-vm-01"), action: "stop" });
    expect(screen.queryByRole("dialog")).toBeNull(); // no second confirm in the UI
    expect(within(panel()).getAllByRole("status").map((s) => s.textContent)).toEqual(["Powered off", "Power off: requested from stage-vcenter."]);

    mock.confirmPower = false;
    fireEvent.click(within(panel()).getByRole("button", { name: "Power" }));
    fireEvent.click(within(screen.getByRole("menu")).getByRole("menuitem", { name: /^Power on/ }));
    await settle();
    expect(within(panel()).getAllByRole("status").map((s) => s.textContent)).toEqual(["Powered off", "Cancelled in the dialog. Nothing was done."]);

    mock.confirmPower = true;
    fireEvent.click(within(panel()).getByRole("button", { name: "Power" }));
    expect(within(screen.getByRole("menu")).getByRole("menuitem", { name: /^Shut down guest/ })).toHaveAttribute("aria-disabled", "true");
    fireEvent.keyDown(screen.getByRole("menu"), { key: "Escape" });
    expect(screen.queryByRole("menu")).toBeNull();
    expect(within(panel()).getByRole("button", { name: "Power" })).toHaveFocus();

    // Rust refuses after the dialog (opt-in switched off meanwhile): the code becomes plain text.
    await act(async () => {
      const opts = (await mock.connectionOptionsGet({ connectionId: "c-vc" })) as VsphereConnOptions;
      await mock.connectionOptionsSet({ connectionId: "c-vc", options: { ...opts, allowPowerActions: false } });
    });
    fireEvent.click(within(panel()).getByRole("button", { name: "Power" }));
    fireEvent.click(within(screen.getByRole("menu")).getByRole("menuitem", { name: /^Power on/ }));
    await settle();
    expect(within(panel()).getByRole("alert")).toHaveTextContent("Power actions are off for this vCenter.");
  });

  it("opens the vSphere Client window, hands off to VMRC only when opted in, and explains a missing VM", async () => {
    await boot();
    await syncedTree(mock);
    selectRow(/^app-vm-01,/);
    await settle();
    const consoleSpy = vi.spyOn(mock, "vsphereConsole");
    fireEvent.click(within(details()).getByRole("button", { name: "Open in vSphere Client" }));
    await settle();
    expect(consoleSpy).toHaveBeenLastCalledWith({ connectionId: vmId(mock, "vm-app-vm-01"), kind: "client" });
    expect(within(details()).getAllByRole("status").at(-1)).toHaveTextContent("Opened the vSphere Client window (web-c-vc).");
    expect(mock.audit.at(-1)).toMatchObject({ event: "vsphere_console", details: { kind: "client" } });

    const vmrc = within(details()).getByRole("button", { name: "VMRC" });
    expect(vmrc).toBeDisabled();
    expect(vmrc).toHaveAttribute("title", "VMware Remote Console is off for stage-vcenter. Turn it on in its connection options.");
    await act(async () => {
      const opts = (await mock.connectionOptionsGet({ connectionId: "c-vc" })) as VsphereConnOptions;
      await useConnOptions.getState().save("c-vc", "vsphere-console", { ...opts, allowVmrc: true });
    });
    expect(vmrc).toHaveAttribute("title", expect.stringContaining("three buttons (Cancel, Open, Not now)"));
    fireEvent.click(vmrc);
    await settle();
    expect(within(details()).getAllByRole("status").at(-1)).toHaveTextContent("Ticket handed to VMware Remote Console.");
    expect(JSON.stringify(mock.audit)).not.toMatch(/vmrc:\/\//);

    // Enter on the row opens the Client window too; a missing VM shows why nothing works.
    fireEvent.keyDown(tree(), { key: "Enter" });
    await settle();
    expect(consoleSpy).toHaveBeenCalledTimes(3);
    mock.vsphereHidden.add("vm-app-vm-01");
    await mock.vsphereRefresh({ connectionId: "c-vc" });
    await act(async () => { await useTree.getState().load(); });
    await settle();
    expect(within(details()).getByRole("region", { name: "Virtual machine" })).toHaveTextContent("stage-vcenter no longer reports this VM.");
    expect(within(details()).queryByRole("button", { name: "Power" })).toBeNull();
  });
});

describe("vSphere · sync status panel", () => {
  let mock: MockTransport;
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    mock = freshBackend();
  });
  afterEach(() => { vi.useRealTimers(); });

  it("shows last refresh, next scheduled, the last error and the counts; refreshes and disables with a confirm", async () => {
    await boot();
    const root = await syncedTree(mock);
    mock.vsphereHidden.add("vm-build-vm");
    mock.vsphereUntrusted.add("c-vc");
    await mock.vsphereScheduledTick("c-vc");
    selectRow(/^stage-vcenter,.*synced/);
    await settle();
    const panel = () => within(details()).getByRole("region", { name: "Inventory sync" });
    expect(panel()).toHaveTextContent("Refreshedjust now");
    expect(panel()).toHaveTextContent(/Nextabout in (59|60) min \(every 60 min\)/);
    expect(panel()).toHaveTextContent("The server's certificate is not trusted yet. Run Refresh now or Sync now to review and trust it; background runs cannot ask.");

    fireEvent.click(within(panel()).getByRole("button", { name: "Refresh now" }));
    await settle();
    expect(within(panel()).getByRole("status")).toHaveTextContent("Refreshed: 0 added, 0 changed, 1 missing, 0 deleted.");
    expect(panel()).toHaveTextContent("Last errornone");
    expect(within(panel()).getByRole("group", { name: "Last refresh" })).toHaveTextContent("0added0changed1missing0deleted");
    expect(within(tree()).getByRole("treeitem", { name: /^build-vm, .*missing in vCenter$/ })).toBeInTheDocument();

    // The status is polled while the panel is visible (passive command).
    const statusSpy = vi.spyOn(mock, "vsphereStatus");
    await act(async () => { await vi.advanceTimersByTimeAsync(POLL_MS + 50); });
    expect(statusSpy).toHaveBeenCalledWith({ connectionId: "c-vc" });

    // Manual-only schedule.
    await act(async () => {
      const opts = (await mock.connectionOptionsGet({ connectionId: "c-vc" })) as VsphereConnOptions;
      await useConnOptions.getState().save("c-vc", "vsphere-console", { ...opts, refreshMinutes: null });
    });
    await act(async () => { await vi.advanceTimersByTimeAsync(POLL_MS + 50); });
    expect(panel()).toHaveTextContent("Nextmanual only");

    // Disable: the confirm offers keep or remove; Cancel does nothing.
    const disableSpy = vi.spyOn(mock, "vsphereSyncDisable");
    fireEvent.click(within(panel()).getByRole("button", { name: "Disable sync…" }));
    const confirm = screen.getByRole("dialog", { name: "Disable inventory sync" });
    fireEvent.click(within(confirm).getByRole("button", { name: "Cancel" }));
    expect(disableSpy).not.toHaveBeenCalled();
    fireEvent.click(within(panel()).getByRole("button", { name: "Disable sync…" }));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Keep as ordinary folders" }));
    await settle();
    expect(disableSpy).toHaveBeenCalledWith({ connectionId: "c-vc", keep: true });
    expect(useTree.getState().folders.find((f) => f.id === root.id)?.syncSource).toBeNull();
    expect(useTree.getState().selected).toEqual({ kind: "connection", id: "c-vc" });
    expect(within(details()).queryByRole("region", { name: "Inventory sync" })).toBeNull();
    expect(within(details()).getByRole("button", { name: "Import inventory…" })).toBeInTheDocument();
    expect(row(/^stage-vcenter$/)).toHaveAttribute("draggable", "true");
  });

  it("removes the folder and VMs on the destructive choice", async () => {
    await boot();
    const root = await syncedTree(mock);
    selectRow(/^stage-vcenter, synced/); // the synced root folder shows the panel too
    await settle();
    fireEvent.click(within(details()).getByRole("button", { name: "Disable sync…" }));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Remove folder and VMs" }));
    await settle();
    expect(useTree.getState().folders.some((f) => f.id === root.id)).toBe(false);
    expect(useTree.getState().connections.some((c) => c.externalId === "vm-app-vm-01")).toBe(false);
    expect(useTree.getState().selected).toEqual({ kind: "connection", id: "c-vc" });
  });
});
