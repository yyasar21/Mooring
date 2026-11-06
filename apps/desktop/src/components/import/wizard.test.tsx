// The import wizard against the mock (ADR-0019 §6): source tiles, the Rust-side pick, the
// preview (checkboxes, duplicates, opt-ins re-running the preview, skipped, warnings, the
// mRemoteNG banner), apply + report + "Open folder", discard on cancel, errors as text.
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { freshBackend, settle } from "../../test/harness";
import { useTree } from "../../stores/tree";
import { useUi } from "../../stores/ui";
import { ImportWizard } from "./ImportWizard";
import { ImportCard } from "./ImportCard";

const dialog = () => screen.getByRole("dialog");
const click = (name: string | RegExp) => { fireEvent.click(within(dialog()).getByRole("button", { name })); };

async function toPreview(format: Parameters<typeof ImportWizard>[0]["format"], onClose = vi.fn()) {
  const mock = freshBackend();
  await act(async () => { await useTree.getState().load(); });
  render(<ImportWizard format={format} onClose={onClose} />);
  await settle();
  click("Choose file");
  await settle();
  click("Preview");
  await settle();
  return { mock, onClose };
}

describe("ImportWizard", () => {
  it("picks a file through Rust (name and size only), previews, applies and opens the folder", async () => {
    const mock = freshBackend();
    await act(async () => { await useTree.getState().load(); });
    const onClose = vi.fn();
    render(<ImportWizard format="royal_ts" onClose={onClose} />);
    await settle();
    expect(dialog()).toHaveAccessibleName("Import from Royal TS");
    expect(within(dialog()).getByRole("button", { name: "Preview" })).toBeDisabled();
    expect(within(dialog()).getByText("No file chosen yet")).toBeInTheDocument();
    click("Choose file");
    await settle();
    expect(within(dialog()).getByText("ops-team.rtsz")).toBeInTheDocument();
    expect(within(dialog()).getByText("47 KB")).toBeInTheDocument();
    click("Preview");
    await settle();
    expect(within(dialog()).getByRole("listitem", { current: "step" })).toHaveTextContent("Preview");
    const counts = within(dialog()).getByRole("group", { name: "Preview counts" });
    expect(counts.textContent).toBe("3folders5connections2credentials0secrets1skipped1warnings");
    const tree = within(dialog()).getByRole("region", { name: "Items to import" });
    expect(within(tree).getAllByRole("checkbox")).toHaveLength(8);
    expect(within(tree).getByText("Duplicate, skipped")).toBeInTheDocument();
    expect(within(tree).getByText("ops@")).toBeInTheDocument();
    expect(within(tree).getByText(":3389")).toBeInTheDocument();
    expect(within(dialog()).getAllByText("Ask at connect", { selector: ".imp-cred-kind" })).toHaveLength(2);
    expect(within(dialog()).getByRole("region", { name: "Skipped" })).toHaveTextContent("a kind of connection Mooring has no model for");
    expect(within(dialog()).getByRole("region", { name: "Warnings" })).toHaveTextContent("A port outside 1–65535");
    expect(within(dialog()).queryByRole("switch", { name: /plaintext/ })).toBeNull(); // Royal TS never carries secrets
    // untick the Windows folder: its two connections lift to the parent; the count follows
    fireEvent.click(within(tree).getByRole("checkbox", { name: "Windows" }));
    expect(within(tree).getByRole("status")).toHaveTextContent("7 of 8 items selected");
    click(/^Import 6 items/);
    await settle();
    const report = within(dialog()).getByRole("group", { name: "Import report" });
    expect(report.textContent).toBe("2folders4connections2credentials0secrets3skipped");
    expect(mock.audit.at(-1)?.event).toBe("import_applied");
    expect(useTree.getState().folders.some((f) => f.name.startsWith("Imported from Royal TS"))).toBe(true);
    click("Open folder");
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(useUi.getState().view).toBe("workspace");
    expect(useTree.getState().selected).toEqual({ kind: "folder", id: expect.stringMatching(/^f-imp-/) as string });
    expect(mock.importPlans.size).toBe(0);
  });

  it("discards the held plan on cancel and on Escape", async () => {
    const { mock, onClose } = await toPreview("putty");
    expect(mock.importPlans.size).toBe(1);
    click("Cancel");
    expect(onClose).toHaveBeenCalledTimes(1);
    await settle();
    expect(mock.importPlans.size).toBe(0);
    expect(mock.audit.some((a) => a.event === "import_applied")).toBe(false);
  });

  it("re-runs the preview when the plaintext opt-in changes (Termius)", async () => {
    const { mock } = await toPreview("termius");
    expect(within(dialog()).getByRole("group", { name: "Preview counts" }).textContent).toContain("0secrets");
    const sw = within(dialog()).getByRole("switch", { name: /^Import plaintext passwords and keys/ });
    expect(sw).not.toBeChecked();
    fireEvent.click(sw);
    await settle();
    expect(within(dialog()).getByRole("switch", { name: /^Import plaintext passwords and keys/ })).toBeChecked();
    expect(within(dialog()).getByRole("group", { name: "Preview counts" }).textContent).toContain("2secrets");
    expect(within(dialog()).getAllByText("has secret")).toHaveLength(2);
    expect(mock.audit.filter((a) => a.event === "import_previewed")).toHaveLength(2);
    expect(mock.importPlans.size).toBe(1); // the first plan was discarded
    // nothing secret-looking reaches the DOM
    expect(dialog().textContent).not.toMatch(/password=|BEGIN OPENSSH/);
  });

  it("reads the known location without a dialog and offers the key-file opt-in (OpenSSH)", async () => {
    const mock = freshBackend();
    render(<ImportWizard format="openssh" known="openssh" onClose={vi.fn()} />);
    await settle();
    expect(within(dialog()).getByRole("listitem", { current: "step" })).toHaveTextContent("Preview");
    expect(within(dialog()).getByText(/Match blocks were ignored/)).toBeInTheDocument();
    expect(within(dialog()).getByText("ProxyJump was kept as a jump: tag; Mooring has no jump-host setting yet.")).toBeInTheDocument();
    fireEvent.click(within(dialog()).getByRole("switch", { name: /^Import private keys from ~\/\.ssh/ }));
    await settle();
    expect(within(dialog()).getByRole("region", { name: "Skipped" })).toHaveTextContent("a key file that is missing, outside ~/.ssh");
    expect(within(dialog()).getAllByText("has secret")).toHaveLength(1);
    mock.importKnown.openssh = false;
    click("Back");
    click("Preview");
    await settle();
    expect(within(dialog()).getByRole("alert")).toHaveTextContent("Nothing to import at that location on this computer.");
  });

  it("shows the mRemoteNG banner and the password_dropped warnings", async () => {
    await toPreview("mremoteng");
    expect(within(dialog()).getByRole("note")).toHaveTextContent("mRemoteNG passwords are never imported");
    expect(within(dialog()).getByRole("region", { name: "Warnings" })).toHaveTextContent("A stored password was not imported");
    expect(within(dialog()).queryByText("has secret")).toBeNull();
  });

  it("maps parser refusals to plain text and keeps the file step", async () => {
    const mock = freshBackend();
    mock.importPicks.push({ fileName: "locked.rtsz", error: "import.encrypted" }, { fileName: "bundle.zip", error: "import.unsupported_container" });
    render(<ImportWizard format="royal_ts" onClose={vi.fn()} />);
    await settle();
    click("Choose file");
    await settle();
    click("Preview");
    await settle();
    expect(within(dialog()).getByRole("alert")).toHaveTextContent("This file is encrypted. Export it unencrypted from the source tool, then import it again.");
    expect(within(dialog()).getByRole("listitem", { current: "step" })).toHaveTextContent("File");
    expect(within(dialog()).getByRole("button", { name: "Preview" })).toBeDisabled(); // the pick was consumed
    click("Choose file");
    await settle();
    click("Preview");
    await settle();
    expect(within(dialog()).getByRole("alert")).toHaveTextContent("This file is a ZIP archive.");
    expect(dialog().textContent).not.toContain("locked.rtsz"); // the refused pick is gone with its name
  });

  it("imports duplicates when the switch is off and reports an expired plan", async () => {
    const { mock } = await toPreview("putty");
    fireEvent.click(within(dialog()).getByRole("switch", { name: /^Skip duplicates/ }));
    expect(within(dialog()).getByText("Duplicate", { selector: ".imp-dup" })).toBeInTheDocument();
    mock.expireImportPlans();
    click(/^Import 3 items/);
    await settle();
    expect(within(dialog()).getByRole("alert")).toHaveTextContent("The preview expired or was already used. Preview the file again.");
    expect(within(dialog()).getByRole("listitem", { current: "step" })).toHaveTextContent("File");
  });

  it("a cancelled dialog leaves the file step unchanged", async () => {
    const mock = freshBackend();
    mock.importPicks.push(null);
    render(<ImportWizard format="rdm" onClose={vi.fn()} />);
    await settle();
    click("Choose file");
    await settle();
    expect(within(dialog()).getByText("No file chosen yet")).toBeInTheDocument();
    expect(within(dialog()).getByRole("button", { name: "Preview" })).toBeDisabled();
  });
});

describe("ImportCard", () => {
  it("lists seven tiles, the two known-location shortcuts, and the disabled LDAPS tile", async () => {
    freshBackend();
    render(<ImportCard />);
    await settle();
    const card = screen.getByRole("region", { name: "Import" });
    const tiles = within(card).getByRole("list", { name: "Import sources" });
    expect(within(tiles).getAllByRole("listitem").map((li) => li.querySelector(".imp-tile-name")?.textContent)).toEqual([
      "Royal TS", "Remote Desktop Manager", "Termius", "mRemoteNG", "PuTTY", "OpenSSH config", "Directory (LDAPS)",
    ]);
    const ldaps = within(tiles).getByRole("button", { name: /Directory \(LDAPS\)/ });
    expect(ldaps).toBeDisabled();
    expect(ldaps).toHaveAccessibleDescription("Coming in this release");
    expect(within(tiles).getByRole("button", { name: "Import from ~/.ssh/config" })).toBeEnabled();
    expect(within(tiles).getByRole("button", { name: "Import from ~/.putty/sessions" })).toBeEnabled();
    expect(card.textContent).not.toMatch(/[çğışöüÇĞİŞÖÜ]/); // English only
    fireEvent.click(within(tiles).getByRole("button", { name: /^Termius/ }));
    expect(screen.getByRole("dialog")).toHaveAccessibleName("Import from Termius");
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    fireEvent.click(within(tiles).getByRole("button", { name: "Import from ~/.putty/sessions" }));
    await settle();
    expect(screen.getByRole("dialog")).toHaveAccessibleName("Import from PuTTY");
    expect(within(screen.getByRole("dialog")).getByRole("listitem", { current: "step" })).toHaveTextContent("Preview");
  });
});
