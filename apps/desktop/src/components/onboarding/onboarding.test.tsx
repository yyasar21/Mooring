// First-run onboarding (ADR-0019 §6): shows on an empty tree, the three paths, dismissal
// remembered per vault, never again once the tree has a connection.
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { freshBackend, settle } from "../../test/harness";
import { MOCK_VAULT_ID } from "../../lib/ipc.mock.sync";
import { useApp } from "../../stores/app";
import { onboardingPending, useOnboarding } from "../../stores/onboarding";
import { useTree } from "../../stores/tree";
import { useUi } from "../../stores/ui";
import { Workspace } from "../Workspace";

async function emptyVault() {
  const mock = freshBackend();
  mock.connections = [];
  mock.folders = mock.folders.filter((f) => f.parentId === null);
  localStorage.removeItem("mooring.onboarding");
  await act(async () => { await useApp.getState().boot(); });
  await settle();
  return mock;
}

const card = () => screen.getByRole("region", { name: "Nothing is moored here yet" });

describe("OnboardingCard", () => {
  it("shows on an empty tree with the three paths and not on a filled one", async () => {
    await emptyVault();
    render(<Workspace />);
    await settle();
    const names = within(card()).getAllByRole("button").map((b) => b.textContent);
    expect(names.slice(0, 3)).toEqual([
      "Start from scratchOpen the new-connection dialog and add a host.",
      "Import from another toolRoyal TS, Remote Desktop Manager, Termius, mRemoteNG, PuTTY or an ssh config.",
      "Read the user guideCopies the guide's address; open it in your browser.",
    ]);
    expect(within(card()).getByRole("button", { name: "Not now" })).toBeInTheDocument();
    expect(useOnboarding.getState().vaultId).toBe(MOCK_VAULT_ID);
    expect(screen.queryByText("Nothing open yet")).toBeNull();
  });

  it("does not show when the tree has connections", async () => {
    freshBackend();
    await act(async () => { await useApp.getState().boot(); });
    render(<Workspace />);
    await settle();
    expect(screen.queryByRole("region", { name: "Nothing is moored here yet" })).toBeNull();
    expect(screen.getByText("Nothing open yet")).toBeInTheDocument();
  });

  it("start from scratch opens the connection dialog in the root folder and dismisses the card", async () => {
    await emptyVault();
    render(<Workspace />);
    await settle();
    fireEvent.click(within(card()).getByRole("button", { name: /^Start from scratch/ }));
    expect(useUi.getState().dialog).toEqual({ kind: "connection", folderId: "f-root" });
    expect(screen.queryByRole("region", { name: "Nothing is moored here yet" })).toBeNull();
  });

  it("import opens the wizard on the source grid; a finished import removes the card", async () => {
    const mock = await emptyVault();
    render(<Workspace />);
    await settle();
    fireEvent.click(within(card()).getByRole("button", { name: /^Import from another tool/ }));
    await settle();
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveAccessibleName("Import connections");
    const tiles = within(dialog).getByRole("list", { name: "Import sources" });
    expect(within(tiles).getByRole("button", { name: /Directory \(LDAPS\)/ })).toBeEnabled();
    fireEvent.click(within(tiles).getByRole("button", { name: "Import from ~/.ssh/config" }));
    await settle();
    expect(screen.getByRole("dialog")).toHaveAccessibleName("Import from OpenSSH config");
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: /^Import \d+ items/ }));
    await settle();
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Open folder" }));
    await settle();
    expect(mock.connections.length).toBeGreaterThan(0);
    expect(useTree.getState().connections.length).toBeGreaterThan(0);
    expect(screen.queryByRole("region", { name: "Nothing is moored here yet" })).toBeNull();
  });

  it("copies the user guide link like About", async () => {
    await emptyVault();
    const written: string[] = [];
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: (t: string) => { written.push(t); return Promise.resolve(); } } });
    render(<Workspace />);
    await settle();
    fireEvent.click(within(card()).getByRole("button", { name: "Copy User guide link" }));
    await settle();
    expect(written).toEqual(["https://github.com/yyasar21/Mooring/tree/main/docs/user-guide"]);
    expect(within(card()).getByRole("status")).toHaveTextContent("Link copied.");
    expect(within(card()).queryAllByRole("link")).toHaveLength(0);
  });

  it("Not now remembers the dismissal for this vault across unlocks, not for another vault", async () => {
    await emptyVault();
    render(<Workspace />);
    await settle();
    fireEvent.click(within(card()).getByRole("button", { name: "Not now" }));
    expect(screen.queryByRole("region", { name: "Nothing is moored here yet" })).toBeNull();
    expect(JSON.parse(localStorage.getItem("mooring.onboarding") ?? "[]")).toEqual([MOCK_VAULT_ID]);
    // lock + unlock: the stored dismissal holds
    await act(async () => { await useApp.getState().lock(); });
    expect(useOnboarding.getState().hidden).toBe(false);
    await act(async () => { await useApp.getState().unlock("correct horse battery"); });
    await settle();
    await act(async () => { await useOnboarding.getState().load(); });
    expect(onboardingPending(useOnboarding.getState())).toBe(false);
    // another vault id: pending again
    useOnboarding.setState({ vaultId: "0000-other" });
    expect(onboardingPending(useOnboarding.getState())).toBe(true);
  });

  it("the card is English only", async () => {
    await emptyVault();
    render(<Workspace />);
    await settle();
    expect(card().textContent).not.toMatch(/[çğışöüÇĞİŞÖÜ]/);
  });
});
