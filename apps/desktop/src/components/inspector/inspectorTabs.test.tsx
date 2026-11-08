import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { useTree } from "../../stores/tree";
import { freshBackend, settle } from "../../test/harness";
import { Inspector } from "./Inspector";

// M4: the inspector splits into Properties | Network | History tabs.

async function select(id: string) {
  act(() => { useTree.getState().select({ kind: "connection", id }); });
  await settle();
}

describe("inspector tabs (M4)", () => {
  beforeEach(async () => {
    freshBackend();
    await act(async () => { await useTree.getState().load(); });
  });

  it("opens on Properties with a tablist and linked panels", async () => {
    render(<Inspector />);
    await select("c-web01");
    const list = screen.getByRole("tablist", { name: "Details sections" });
    const tabs = within(list).getAllByRole("tab");
    expect(tabs.map((t) => t.textContent)).toEqual(["Properties", "Network", "History"]);
    expect(tabs[0]).toHaveAttribute("aria-selected", "true");
    expect(tabs.map((t) => t.tabIndex)).toEqual([0, -1, -1]);
    const panel = screen.getByRole("tabpanel");
    expect(panel).toHaveAttribute("aria-labelledby", tabs[0]?.id);
    expect(tabs[0]).toHaveAttribute("aria-controls", panel.id);
    expect(within(panel).getByText("Host")).toBeInTheDocument();
  });

  it("moves with the arrow keys, Home and End, and shows the History placeholder", async () => {
    render(<Inspector />);
    await select("c-web01");
    const props = screen.getByRole("tab", { name: "Properties" });
    props.focus();
    fireEvent.keyDown(props, { key: "ArrowRight" });
    expect(screen.getByRole("tab", { name: "Network" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tab", { name: "Network" })).toHaveFocus();
    expect(screen.getByRole("region", { name: "Network" })).toBeInTheDocument();
    fireEvent.keyDown(document.activeElement as Element, { key: "End" });
    expect(screen.getByRole("tabpanel")).toHaveTextContent(/Session history for this connection arrives in a later release/);
    fireEvent.keyDown(document.activeElement as Element, { key: "ArrowRight" });
    expect(screen.getByRole("tab", { name: "Properties" })).toHaveAttribute("aria-selected", "true");
    fireEvent.keyDown(document.activeElement as Element, { key: "ArrowLeft" });
    expect(screen.getByRole("tab", { name: "History" })).toHaveAttribute("aria-selected", "true");
    fireEvent.keyDown(document.activeElement as Element, { key: "Home" });
    expect(screen.getByRole("tab", { name: "Properties" })).toHaveFocus();
  });

  it("keeps the chosen tab across rows and falls back to Properties where Network does not exist", async () => {
    render(<Inspector />);
    await select("c-web01");
    fireEvent.click(screen.getByRole("tab", { name: "Network" }));
    await select("c-dc");
    expect(screen.getByRole("tab", { name: "Network" })).toHaveAttribute("aria-selected", "true");
    await select("c-k8s");
    expect(screen.queryByRole("tab", { name: "Network" })).toBeNull();
    expect(screen.getByRole("tab", { name: "Properties" })).toHaveAttribute("aria-selected", "true");
  });
});
