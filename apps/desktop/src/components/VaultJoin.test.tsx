import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { App } from "../App";
import { MOCK_VAULT_ID } from "../lib/ipc.mock.sync";
import { useApp } from "../stores/app";
import { useCredentials } from "../stores/credentials";
import { freshBackend, settle } from "../test/harness";

const SECRET = "wJalrXUtnFEMI-FIXTURE-KEY";
const PASSWORD = "correct horse battery";

async function openJoin() {
  render(<App />);
  await screen.findByRole("heading", { name: "Create your vault" });
  fireEvent.click(screen.getByRole("button", { name: "Join a synced vault instead" }));
  return screen.getByRole("form", { name: "Join a synced vault" });
}

function fill(form: HTMLElement, vaultId = MOCK_VAULT_ID) {
  fireEvent.change(within(form).getByLabelText("Endpoint"), { target: { value: "https://s3.example.test" } });
  fireEvent.change(within(form).getByLabelText("Bucket"), { target: { value: "team-vault" } });
  fireEvent.change(within(form).getByLabelText("Region"), { target: { value: "eu-west-1" } });
  fireEvent.change(within(form).getByLabelText("Access key ID"), { target: { value: "AKIAEXAMPLE" } });
  fireEvent.change(within(form).getByLabelText("Secret access key"), { target: { value: SECRET } });
  fireEvent.change(within(form).getByLabelText("Vault id"), { target: { value: vaultId } });
  fireEvent.change(within(form).getByLabelText("Synced vault password"), { target: { value: PASSWORD } });
}

describe("join a synced vault (ADR-0017, first run)", () => {
  it("validates, then bootstraps, seals the key, joins and opens the shell", async () => {
    const mock = freshBackend({ vault: "missing" });
    const form = await openJoin();
    fireEvent.click(within(form).getByRole("button", { name: "Join vault" }));
    expect(within(form).getByRole("alert")).toHaveTextContent("Fix the highlighted fields.");
    expect(within(form).getByLabelText("Vault id")).toHaveAttribute("aria-invalid", "true");
    expect(mock.vault).toBe("missing");
    fill(form);
    fireEvent.click(within(form).getByRole("radio", { name: "Manual only" }));
    fireEvent.click(within(form).getByRole("button", { name: "Join vault" }));
    await settle(5);
    await screen.findByText("Nothing open yet");
    expect(useApp.getState().vault).toBe("unlocked");
    expect(mock.audit.map((a) => a.event)).toEqual(expect.arrayContaining(["vault_created", "sync.joined"]));
    expect(await mock.syncStatus()).toMatchObject({ state: "idle", deviceId: "dev-0002", config: { intervalMinutes: null, backend: { bucket: "team-vault" } } });
    const key = useCredentials.getState().items.find((c) => c.kind === "s3_access_key" && c.name === "Sync access key");
    expect(key?.secretNames).toEqual(["secret_access_key"]);
    // The secret and the password never linger in the DOM or the stores.
    expect(document.body.innerHTML).not.toContain(SECRET);
    expect(JSON.stringify([useApp.getState(), useCredentials.getState()])).not.toMatch(new RegExp(`${SECRET}|${PASSWORD}`));
  });

  it("a failed join keeps the bootstrap vault and the key, explains it, and a retry succeeds without retyping the key", async () => {
    const mock = freshBackend({ vault: "missing" });
    const form = await openJoin();
    fill(form, "00000000-0000-4000-8000-000000000000");
    fireEvent.click(within(form).getByRole("button", { name: "Join vault" }));
    await settle(5);
    expect(within(form).getByRole("alert")).toHaveTextContent("The bucket does not hold a vault with that id under that prefix.");
    expect(within(form).getByRole("note")).toHaveTextContent("The bootstrap vault and the access key are already on this device");
    expect(within(form).getByLabelText("Secret access key")).toBeDisabled();
    expect(within(form).getByRole("button", { name: "Create a local vault instead" })).toBeDisabled();
    expect(useApp.getState().vault).toBe("missing"); // the shell waits for the join
    expect(mock.vault).toBe("unlocked");
    fireEvent.change(within(form).getByLabelText("Vault id"), { target: { value: MOCK_VAULT_ID } });
    fireEvent.change(within(form).getByLabelText("Synced vault password"), { target: { value: PASSWORD } });
    fireEvent.click(within(form).getByRole("button", { name: "Join vault" }));
    await settle(5);
    await screen.findByText("Nothing open yet");
    expect(mock.audit.filter((a) => a.event === "vault_created")).toHaveLength(1);
    expect(useCredentials.getState().items.filter((c) => c.name === "Sync access key")).toHaveLength(1);
  });

  it("the create screen keeps working and the unlock screen has no join link", async () => {
    freshBackend({ vault: "missing" });
    const form = await openJoin();
    fireEvent.click(within(form).getByRole("button", { name: "Create a local vault instead" }));
    expect(screen.getByRole("heading", { name: "Create your vault" })).toBeInTheDocument();
    cleanup();
    freshBackend({ vault: "locked" });
    render(<App />);
    await screen.findByRole("heading", { name: "Unlock Mooring" });
    expect(screen.queryByRole("button", { name: "Join a synced vault instead" })).toBeNull();
  });
});
