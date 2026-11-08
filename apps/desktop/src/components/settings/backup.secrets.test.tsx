import { useState } from "react";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { freshBackend, settle } from "../../test/harness";
import { reactStateHolds } from "../../test/reactState";
import type { MockTransport } from "../../lib/ipc.mock";
import { MOCK_BACKUP_PASSPHRASE, MOCK_SOURCE_PASSWORD } from "../../lib/ipc.mock.a5";
import { BackupCard } from "./BackupCard";

// L-53 (docs/security/a5-review-9.md): the backup dialogs keep no secret in React state.

const MASTER = "correct master password";
const PASS = "harbour lights at dawn";
const dialog = (name: string) => screen.getByRole("dialog", { name });
const type = (scope: HTMLElement, label: string, value: string) => {
  fireEvent.change(within(scope).getByLabelText(label), { target: { value } });
};

describe("L-53: backup secrets stay out of React state", () => {
  let mock: MockTransport;
  beforeEach(() => {
    mock = freshBackend();
    mock.masterPassword = MASTER;
  });

  it("the helper finds a secret held in state or in a controlled input (positive control)", () => {
    function Holder() {
      const [v] = useState(PASS);
      return <span>{v.length}</span>;
    }
    expect(reactStateHolds(render(<Holder />).container, PASS)).toBe(true);
    expect(reactStateHolds(render(<input aria-label="x" value={MASTER} readOnly />).container, MASTER)).toBe(true);
  });

  it("export: typed secrets are in no state or props, and every field is empty after an attempt and after close", async () => {
    const { container } = render(<BackupCard />);
    fireEvent.click(screen.getByRole("button", { name: "Export backup…" }));
    const dlg = dialog("Export a backup");
    const fields = ["Master password", "Backup passphrase", "Repeat backup passphrase"].map((l) => within(dlg).getByLabelText(l));
    type(dlg, "Master password", MASTER);
    type(dlg, "Backup passphrase", PASS);
    type(dlg, "Repeat backup passphrase", PASS);
    // the strength hint still follows the typing
    expect(within(dlg).getByText(/^Good\./)).toBeInTheDocument();
    expect(reactStateHolds(container, MASTER)).toBe(false);
    expect(reactStateHolds(container, PASS)).toBe(false);
    mock.exportPickOk = false;
    fireEvent.click(within(dlg).getByRole("button", { name: "Choose file and export…" }));
    await settle();
    for (const f of fields) expect(f).toHaveValue("");
    type(dlg, "Master password", MASTER);
    type(dlg, "Backup passphrase", PASS);
    fireEvent.click(within(dlg).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    for (const f of fields) expect(f).toHaveValue("");
    expect(reactStateHolds(container, MASTER)).toBe(false);
    expect(reactStateHolds(container, PASS)).toBe(false);
  });

  it("import: the passphrase and both master passwords are in no state or props, and the fields empty on close", async () => {
    mock.backupFile = { ...mock.backupFile, foreign: true };
    const { container } = render(<BackupCard />);
    fireEvent.click(screen.getByRole("button", { name: "Import backup…" }));
    await settle();
    const dlg = dialog("Import a backup");
    const pass = within(dlg).getByLabelText("Backup passphrase");
    type(dlg, "Backup passphrase", MOCK_BACKUP_PASSPHRASE);
    expect(reactStateHolds(container, MOCK_BACKUP_PASSPHRASE)).toBe(false);
    fireEvent.click(within(dlg).getByRole("button", { name: "Open backup" }));
    await settle();
    expect(pass).toHaveValue("");
    const master = within(dlg).getByLabelText("Master password of this vault");
    const source = within(dlg).getByLabelText("Master password of the other vault");
    type(dlg, "Master password of this vault", MASTER);
    type(dlg, "Master password of the other vault", MOCK_SOURCE_PASSWORD);
    expect(within(dlg).getByRole("button", { name: "Merge into this vault" })).toBeEnabled();
    for (const s of [MASTER, MOCK_SOURCE_PASSWORD, MOCK_BACKUP_PASSPHRASE]) expect(reactStateHolds(container, s)).toBe(false);
    fireEvent.click(within(dlg).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(master).toHaveValue("");
    expect(source).toHaveValue("");
  });
});
