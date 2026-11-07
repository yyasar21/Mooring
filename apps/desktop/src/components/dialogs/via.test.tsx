import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { App } from "../../App";
import { connectionFields, useTree } from "../../stores/tree";
import { useUi } from "../../stores/ui";
import { freshBackend, settle } from "../../test/harness";
import type { MockTransport } from "../../lib/ipc.mock";

async function boot() {
  render(<App />);
  await screen.findByText("Nothing open yet");
  await settle();
}

const editDialog = (id: string, folderId: string) => {
  act(() => { useUi.getState().openDialog({ kind: "connection", id, folderId }); });
  return screen.getByRole("dialog", { name: "Edit connection" });
};

describe("Connect via (ADR-0025)", () => {
  let mock: MockTransport;
  beforeEach(() => { mock = freshBackend(); });

  it("adds, reorders and removes jump hosts, shows the route and saves the chain", async () => {
    await boot();
    const dlg = editDialog("c-web01", "f-web");
    const group = within(dlg).getByRole("group", { name: "Connect via" });
    expect(within(group).getByText(/Direct connection/)).toBeInTheDocument();
    const pick = within(group).getByLabelText("Add jump host");
    const offered = within(pick).getAllByRole("option").map((o) => o.textContent);
    // SSH only, never itself
    expect(offered.some((t) => t.startsWith("bastion01"))).toBe(true);
    expect(offered.some((t) => t.startsWith("web01"))).toBe(false);
    expect(offered.some((t) => t.startsWith("dc01") || t.startsWith("lobby-kiosk") || t.startsWith("edge-lb"))).toBe(false);

    fireEvent.change(pick, { target: { value: "c-bastion" } });
    fireEvent.click(within(group).getByRole("button", { name: "Add" }));
    fireEvent.change(within(group).getByLabelText("Add jump host"), { target: { value: "c-web02" } });
    fireEvent.click(within(group).getByRole("button", { name: "Add" }));
    expect(within(group).getByLabelText("Route")).toHaveTextContent("you → bastion01 → web02 → web01");
    fireEvent.click(within(group).getByRole("button", { name: "Move web02 up" }));
    expect(within(group).getByLabelText("Route")).toHaveTextContent("you → web02 → bastion01 → web01");
    expect(within(group).getByRole("button", { name: "Move web02 up" })).toBeDisabled();
    fireEvent.click(within(group).getByRole("button", { name: "Remove web02" }));
    expect(within(group).getByLabelText("Route")).toHaveTextContent("you → bastion01 → web01");

    fireEvent.click(within(dlg).getByRole("button", { name: "Save connection" }));
    await settle();
    expect(mock.connections.find((c) => c.id === "c-web01")?.via).toEqual(["c-bastion"]);
    // tree row and details say how it connects
    const tree = screen.getByRole("tree", { name: "Connections" });
    expect(within(tree).getByRole("treeitem", { name: /^web01, web01\.example\.test, via bastion01/ })).toHaveTextContent("via bastion01");
    const details = screen.getByRole("complementary", { name: "Details" });
    expect(within(details).getByText("Connect via")).toBeInTheDocument();
  });

  it("caps the list at three hops", async () => {
    await boot();
    const dlg = editDialog("c-web01", "f-web");
    const group = within(dlg).getByRole("group", { name: "Connect via" });
    for (const id of ["c-bastion", "c-web02", "c-pg"]) {
      fireEvent.change(within(group).getByLabelText("Add jump host"), { target: { value: id } });
      fireEvent.click(within(group).getByRole("button", { name: "Add" }));
    }
    expect(within(group).getByLabelText("Add jump host")).toBeDisabled();
    expect(within(group).getByRole("option", { name: "At most 3 jump hosts" })).toBeInTheDocument();
    expect(within(group).getAllByRole("listitem")).toHaveLength(3);
  });

  it("shows the via_invalid refusal text when Rust refuses the chain", async () => {
    await boot();
    const dlg = editDialog("c-bastion", "f-staging");
    const group = within(dlg).getByRole("group", { name: "Connect via" });
    // the picker hides stage-app (it would loop), so force the stored chain the way an older form could
    expect(within(within(group).getByLabelText("Add jump host")).queryByRole("option", { name: /^stage-app/ })).toBeNull();
    const b = useTree.getState().connections.find((c) => c.id === "c-bastion");
    if (!b) throw new Error("seed");
    const ok = await act(() => useTree.getState().updateConnection("c-bastion", { ...connectionFields(b), via: ["c-stg"] }));
    expect(ok).toBeNull();
    expect(useTree.getState().error).toMatch(/jump host chain is not allowed/);
  });

  it("refuses to delete a connection used as a hop and names who uses it", async () => {
    await boot();
    const dlg = editDialog("c-bastion", "f-staging");
    fireEvent.click(within(dlg).getByRole("button", { name: "Delete" }));
    await settle();
    expect(within(dlg).getByRole("alert")).toHaveTextContent(/Another connection uses this one as a jump host/);
    expect(within(dlg).getByRole("alert")).toHaveTextContent("Used by: stage-app.");
    expect(mock.connections.some((c) => c.id === "c-bastion")).toBe(true);
  });

  it("explains that web connections connect directly and hides the picker for vCenter", async () => {
    await boot();
    let dlg = editDialog("c-lb", "f-web");
    expect(within(dlg).getByText(/Web connections cannot open through a jump host yet/)).toBeInTheDocument();
    expect(within(dlg).queryByLabelText("Add jump host")).toBeNull();
    fireEvent.click(within(dlg).getByRole("button", { name: "Cancel" }));
    dlg = editDialog("c-vc", "f-staging");
    expect(within(dlg).queryByRole("group", { name: "Connect via" })).toBeNull();
  });
});
