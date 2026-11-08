// M5: the synced root folder lists its imported VMs in a sortable grid.
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { App } from "../../App";
import { useTree } from "../../stores/tree";
import { freshBackend, settle } from "../../test/harness";

describe("vSphere · imported VMs table", () => {
  it("lists the VMs of the synced root, marks a missing one and selects a row in the tree on Enter", async () => {
    const mock = freshBackend();
    render(<App />);
    await screen.findByText("Nothing open yet");
    await settle();
    const root = await mock.vsphereSyncEnable({ connectionId: "c-vc", parentFolderId: "f-staging" });
    mock.vsphereHidden.add("vm-build-vm");
    await mock.vsphereRefresh({ connectionId: "c-vc" });
    await act(async () => { await useTree.getState().load(); });
    act(() => { useTree.getState().select({ kind: "folder", id: root.id }); });
    await settle();

    const details = screen.getByRole("complementary", { name: "Details" });
    const grid = within(details).getByRole("grid", { name: "Synced VMs" });
    const rows = within(grid).getAllByRole("row").slice(1);
    const vms = mock.connections.filter((c) => c.syncSource === "c-vc");
    expect(rows).toHaveLength(vms.length);
    const names = rows.map((r) => r.getAttribute("aria-label") ?? "");
    expect(names).toEqual([...names].sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" })));
    const missing = within(grid).getByRole("row", { name: "build-vm, missing" });
    expect(within(missing).getByText("Missing")).toBeInTheDocument();
    expect(within(grid).getByRole("columnheader", { name: "Name" })).toHaveAttribute("aria-sort", "ascending");

    fireEvent.click(missing);
    fireEvent.keyDown(grid, { key: "Enter" });
    const sel = useTree.getState().selected;
    expect(sel).toEqual({ kind: "connection", id: vms.find((c) => c.name === "build-vm")?.id });
  });
});
