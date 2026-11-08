import { fireEvent, render, screen, within } from "@testing-library/react";
import { freshBackend, settle } from "../../test/harness";
import type { MockTransport } from "../../lib/ipc.mock";
import { MOCK_BACKUP_PASSPHRASE, MOCK_SOURCE_PASSWORD } from "../../lib/ipc.mock.a5";
import { exportFormProblem, passphraseStrength } from "../../lib/passphrase";
import { BackupCard } from "./BackupCard";

const MASTER = "correct master password";
const dialog = (name: string) => screen.getByRole("dialog", { name });
const type = (scope: HTMLElement, label: string | RegExp, value: string) => {
  fireEvent.change(within(scope).getByLabelText(label), { target: { value } });
};

describe("backup passphrase hint", () => {
  it("grades by length and words, and names what blocks the export", () => {
    expect(passphraseStrength("short").level).toBe("weak");
    expect(passphraseStrength("twelve chars").level).toBe("fair");
    expect(passphraseStrength("four whole words here").level).toBe("good");
    expect(passphraseStrength("correct horse battery staple again").level).toBe("strong");
    expect(exportFormProblem({ master: "", passphrase: "x", repeat: "x" })).toMatch(/master password/);
    expect(exportFormProblem({ master: "m", passphrase: "short", repeat: "short" })).toMatch(/12 characters/);
    expect(exportFormProblem({ master: "same password 1", passphrase: "same password 1", repeat: "same password 1" })).toMatch(/differs/);
    expect(exportFormProblem({ master: "m", passphrase: "long enough pass", repeat: "long enough pasx" })).toMatch(/differ/);
    expect(exportFormProblem({ master: "m", passphrase: "long enough pass", repeat: "long enough pass" })).toBeNull();
  });
});

describe("Settings → Backup export (ADR-0023)", () => {
  let mock: MockTransport;
  beforeEach(() => {
    mock = freshBackend();
    mock.masterPassword = MASTER;
  });

  it("asks for the passphrase twice with a hint, then the save dialog, then reports counts", async () => {
    render(<BackupCard />);
    fireEvent.click(screen.getByRole("button", { name: "Export backup…" }));
    const dlg = dialog("Export a backup");
    type(dlg, "Master password", MASTER);
    type(dlg, "Backup passphrase", "short");
    expect(within(dlg).getByText(/Too short/)).toHaveAttribute("data-level", "weak");
    type(dlg, "Backup passphrase", "harbour lights at dawn");
    type(dlg, "Repeat backup passphrase", "harbour lights at dusk");
    fireEvent.click(within(dlg).getByRole("button", { name: "Choose file and export…" }));
    await settle();
    expect(within(dlg).getByRole("alert")).toHaveTextContent("The two passphrases differ.");
    expect(mock.exports).toHaveLength(0);

    type(dlg, "Master password", MASTER);
    type(dlg, "Backup passphrase", "harbour lights at dawn");
    type(dlg, "Repeat backup passphrase", "harbour lights at dawn");
    fireEvent.click(within(dlg).getByRole("button", { name: "Choose file and export…" }));
    await settle();
    const done = dialog("Backup saved");
    expect(within(done).getByRole("status")).toHaveTextContent(/Saved mooring-backup\.age .*: 15 connections, 17 credentials and 6 folders\./);
    expect(mock.exports).toHaveLength(1);
  });

  it("a cancelled save dialog saves nothing; a wrong master password keeps the pick", async () => {
    render(<BackupCard />);
    fireEvent.click(screen.getByRole("button", { name: "Export backup…" }));
    const dlg = dialog("Export a backup");
    const fill = (master: string) => {
      type(dlg, "Master password", master);
      type(dlg, "Backup passphrase", "harbour lights at dawn");
      type(dlg, "Repeat backup passphrase", "harbour lights at dawn");
    };
    mock.exportPickOk = false;
    fill(MASTER);
    fireEvent.click(within(dlg).getByRole("button", { name: "Choose file and export…" }));
    await settle();
    expect(within(dlg).getByRole("alert")).toHaveTextContent("No file was chosen");
    mock.exportPickOk = true;
    fill("wrong");
    fireEvent.click(within(dlg).getByRole("button", { name: "Choose file and export…" }));
    await settle();
    expect(within(dlg).getByRole("alert")).toHaveTextContent("The master password is wrong.");
    // the fields were cleared; the file stays chosen
    expect(within(dlg).getByLabelText("Master password")).toHaveValue("");
    expect(within(dlg).getByText(/Saving to/)).toBeInTheDocument();
    fill(MASTER);
    fireEvent.click(within(dlg).getByRole("button", { name: "Export" }));
    await settle();
    expect(dialog("Backup saved")).toBeInTheDocument();
  });
});

describe("Settings → Backup import (ADR-0023)", () => {
  let mock: MockTransport;
  beforeEach(() => {
    mock = freshBackend();
    mock.masterPassword = MASTER;
  });

  async function openFile() {
    render(<BackupCard />);
    fireEvent.click(screen.getByRole("button", { name: "Import backup…" }));
    await settle();
    return dialog("Import a backup");
  }

  async function unlockFile(dlg: HTMLElement, passphrase = MOCK_BACKUP_PASSPHRASE) {
    type(dlg, "Backup passphrase", passphrase);
    fireEvent.click(within(dlg).getByRole("button", { name: "Open backup" }));
    await settle();
  }

  it("inspects, merges by default and lists the conflicts", async () => {
    const dlg = await openFile();
    expect(dlg).toHaveTextContent("mooring-2026-11-08.age");
    await unlockFile(dlg, "wrong passphrase");
    expect(within(dlg).getByRole("alert")).toHaveTextContent("That passphrase does not open this backup.");
    await unlockFile(dlg);
    expect(within(dlg).getByLabelText("Backup contents")).toHaveTextContent("11 connections, 9 credentials, 6 folders, 3 trusted host keys");
    expect(within(dlg).getByLabelText("Backup contents")).toHaveTextContent("This vault");
    expect(within(dlg).getByRole("radio", { name: /^Merge/ })).toBeChecked();
    expect(within(dlg).queryByLabelText(/other vault/)).toBeNull();
    type(dlg, "Master password of this vault", MASTER);
    fireEvent.click(within(dlg).getByRole("button", { name: "Merge into this vault" }));
    await settle();
    const done = dialog("Backup imported");
    expect(done).toHaveTextContent("Added 4, updated 2.");
    const list = within(done).getByRole("list", { name: "Conflicts" });
    expect(within(list).getAllByRole("listitem").map((li) => li.textContent)).toEqual([
      "web01 (imported 2026-11-08) (connection) — changed on both sides: both copies kept",
      "Production (folder) — changed on both sides: the newer one kept",
      // L-52: a pin for a host this device already trusts is never added
      "web01.example.test:22 (trust, known_hosts) — already trusted on this device: the local entry kept, the imported one dropped",
    ]);
    expect(done).toHaveTextContent("2 trusted host keys or certificates added.");
  });

  it("Replace stays disabled until REPLACE is typed and offers an export first", async () => {
    const dlg = await openFile();
    await unlockFile(dlg);
    fireEvent.click(within(dlg).getByRole("radio", { name: /^Replace/ }));
    type(dlg, "Master password of this vault", MASTER);
    const go = within(dlg).getByRole("button", { name: "Replace this vault" });
    expect(go).toBeDisabled();
    type(dlg, "Type REPLACE to confirm", "replace");
    expect(go).toBeDisabled();
    type(dlg, "Type REPLACE to confirm", "REPLACE");
    expect(go).toBeEnabled();
    fireEvent.click(within(dlg).getByRole("button", { name: "Export a backup first…" }));
    expect(dialog("Export a backup")).toBeInTheDocument();
    fireEvent.click(within(dialog("Export a backup")).getByRole("button", { name: "Cancel" }));
    fireEvent.click(go);
    await settle();
    expect(dialog("Backup imported")).toHaveTextContent("The vault now holds exactly what the backup held.");
    expect(dialog("Backup imported")).toHaveTextContent("3 trusted host keys or certificates added.");
    expect(mock.audit.find((a) => a.event === "vault.import")?.details.mode).toBe("replace");
  });

  it("a foreign backup asks for the other vault's master password", async () => {
    mock.backupFile = { ...mock.backupFile, foreign: true };
    const dlg = await openFile();
    await unlockFile(dlg);
    expect(within(dlg).getByRole("note")).toHaveTextContent("This backup comes from another vault.");
    expect(within(dlg).getByLabelText("Backup contents")).toHaveTextContent("Another vault");
    type(dlg, "Master password of this vault", MASTER);
    const go = within(dlg).getByRole("button", { name: "Merge into this vault" });
    expect(go).toBeDisabled();
    type(dlg, "Master password of the other vault", "not it");
    fireEvent.click(go);
    await settle();
    expect(within(dlg).getByRole("alert")).toHaveTextContent("That is not the master password of the vault this backup came from.");
    type(dlg, "Master password of this vault", MASTER);
    type(dlg, "Master password of the other vault", MOCK_SOURCE_PASSWORD);
    fireEvent.click(within(dlg).getByRole("button", { name: "Merge into this vault" }));
    await settle();
    expect(dialog("Backup imported")).toBeInTheDocument();
  });

  it("an old-format file is refused with a readable reason", async () => {
    mock.backupFile = { ...mock.backupFile, version: 1 };
    const dlg = await openFile();
    await unlockFile(dlg);
    expect(within(dlg).getByRole("alert")).toHaveTextContent("older format that cannot be imported");
  });

  it("a cancelled open dialog opens nothing", async () => {
    mock.importPickOk = false;
    render(<BackupCard />);
    fireEvent.click(screen.getByRole("button", { name: "Import backup…" }));
    await settle();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("an older backend without trustAdded shows no trust line; zero says so", async () => {
    const base = { mode: "merge" as const, added: 1, updated: 0, conflicts: [], skipped: 0 };
    const spy = vi.spyOn(mock, "vaultImportAge").mockResolvedValueOnce(base);
    let dlg = await openFile();
    await unlockFile(dlg);
    type(dlg, "Master password of this vault", MASTER);
    fireEvent.click(within(dlg).getByRole("button", { name: "Merge into this vault" }));
    await settle();
    expect(dialog("Backup imported")).not.toHaveTextContent(/trusted host key/);
    fireEvent.click(within(dialog("Backup imported")).getByRole("button", { name: "Close" }));

    spy.mockResolvedValueOnce({ ...base, trustAdded: 0 });
    fireEvent.click(screen.getByRole("button", { name: "Import backup…" }));
    await settle();
    dlg = dialog("Import a backup");
    await unlockFile(dlg);
    type(dlg, "Master password of this vault", MASTER);
    fireEvent.click(within(dlg).getByRole("button", { name: "Merge into this vault" }));
    await settle();
    expect(dialog("Backup imported")).toHaveTextContent("No trusted host keys or certificates were added.");
  });
});
