import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { App } from "../../App";
import { seedConnections, seedFolders } from "../../lib/ipc.seed";
import { useOnboarding } from "../../stores/onboarding";
import { useSessions } from "../../stores/sessions";
import { useUi } from "../../stores/ui";
import { freshBackend, settle } from "../../test/harness";
import { filterTree, matchesConnection, subtreeCounts } from "./treeFilter";

async function boot() {
  freshBackend();
  render(<App />);
  await screen.findByText("Nothing open yet");
  await settle();
  return within(screen.getByRole("navigation", { name: "Connection tree" }));
}

describe("tree filter and counts (M3)", () => {
  const folders = seedFolders();
  const conns = seedConnections();

  it("matches name, host or tag, every term", () => {
    const web01 = conns.find((c) => c.id === "c-web01");
    if (!web01) throw new Error("seed changed");
    expect(matchesConnection(web01, "web01")).toBe(true);
    expect(matchesConnection(web01, "EXAMPLE.test")).toBe(true);
    expect(matchesConnection(web01, "nginx web")).toBe(true);
    expect(matchesConnection(web01, "nginx postgres")).toBe(false);
  });

  it("keeps the folders on the way to a match, and a matching folder's subtree", () => {
    const byTag = filterTree(folders, conns, "postgres");
    expect(byTag.connections.map((c) => c.id).sort()).toEqual(["c-pg", "c-report"]);
    expect(byTag.folders.map((f) => f.id).sort()).toEqual(["f-db", "f-prod", "f-root"]);
    const byFolder = filterTree(folders, conns, "web tier");
    expect(byFolder.connections.map((c) => c.id).sort()).toEqual(["c-lb", "c-web01", "c-web02"]);
    expect(filterTree(folders, conns, "  ")).toEqual({ folders, connections: conns });
  });

  it("counts connections in each folder including sub-folders", () => {
    const n = subtreeCounts(folders, conns);
    expect(n.get("f-web")).toBe(3);
    expect(n.get("f-prod")).toBe(5);
    expect(n.get("f-root")).toBe(conns.length);
  });
});

describe("connection tree (M3)", () => {
  beforeEach(() => { useOnboarding.setState({ importing: false }); });

  it("shows protocol icons named like the old pips, folder counts, and unchanged treeitem names", async () => {
    const tree = await boot();
    const row = tree.getByRole("treeitem", { name: "web01, web01.example.test" });
    expect(within(row).getByRole("img", { name: "ssh" })).toBeInTheDocument();
    expect(row.querySelector(".m-pip")).toBeNull();
    const prod = tree.getByRole("treeitem", { name: "Production" });
    expect(prod.querySelector(".tree-count")).toHaveTextContent("5");
  });

  it("puts a labelled status dot on the icon of a host with a session", async () => {
    const tree = await boot();
    await act(async () => { await useSessions.getState().open("c-web01"); });
    await settle();
    const row = tree.getByRole("treeitem", { name: "web01, web01.example.test" });
    const dot = within(row).getByRole("img", { name: /^session / });
    expect(dot).toHaveClass("state-dot");
    expect(dot).toHaveAttribute("data-tone");
  });

  it("filters the tree and clears with Escape", async () => {
    const tree = await boot();
    const field = tree.getByRole("searchbox", { name: "Filter connections" });
    fireEvent.change(field, { target: { value: "postgres" } });
    expect(tree.getByRole("treeitem", { name: "pg-primary, pg01.example.test" })).toBeInTheDocument();
    expect(tree.queryByRole("treeitem", { name: "web01, web01.example.test" })).toBeNull();
    fireEvent.change(field, { target: { value: "no-such-host" } });
    expect(tree.getByRole("status")).toHaveTextContent("No connections match.");
    fireEvent.keyDown(field, { key: "Escape" });
    expect(field).toHaveValue("");
    expect(tree.getByRole("treeitem", { name: "web01, web01.example.test" })).toBeInTheDocument();
  });

  it("New creates a connection; its menu offers a folder and an import, and closes on Escape", async () => {
    const tree = await boot();
    fireEvent.click(tree.getByRole("button", { name: "New connection" }));
    expect(useUi.getState().dialog).toMatchObject({ kind: "connection" });
    act(() => { useUi.getState().closeDialog(); });

    const more = tree.getByRole("button", { name: "More ways to add" });
    expect(more).toHaveAttribute("aria-haspopup", "menu");
    fireEvent.click(more);
    const menu = tree.getByRole("menu", { name: "Add" });
    expect(more).toHaveAttribute("aria-expanded", "true");
    expect(within(menu).getAllByRole("menuitem").map((m) => m.textContent)).toEqual(["Connection…", "Folder…", "Import connections…"]);
    expect(document.activeElement).toBe(within(menu).getByRole("menuitem", { name: "Connection…" }));
    fireEvent.keyDown(menu, { key: "ArrowDown" });
    expect(document.activeElement).toBe(within(menu).getByRole("menuitem", { name: "Folder…" }));
    fireEvent.keyDown(menu, { key: "Escape" });
    expect(tree.queryByRole("menu")).toBeNull();
    expect(document.activeElement).toBe(more);

    fireEvent.click(more);
    fireEvent.click(within(tree.getByRole("menu")).getByRole("menuitem", { name: "Folder…" }));
    expect(useUi.getState().dialog).toMatchObject({ kind: "folder" });
    act(() => { useUi.getState().closeDialog(); });

    fireEvent.click(more);
    fireEvent.click(within(tree.getByRole("menu")).getByRole("menuitem", { name: "Import connections…" }));
    expect(useOnboarding.getState().importing).toBe(true);
  });
});
