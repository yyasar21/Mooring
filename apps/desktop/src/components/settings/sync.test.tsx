import { act, fireEvent, render, screen, within } from "@testing-library/react";
import type { MockTransport } from "../../lib/ipc.mock";
import { MOCK_VAULT_ID } from "../../lib/ipc.mock.sync";
import { useCredentials } from "../../stores/credentials";
import { describeOutcome, useSync } from "../../stores/sync";
import { freshBackend, settle } from "../../test/harness";
import { fmtUnix, resolutionText, SyncCard } from "./SyncCard";

const CONFIG = { backend: { kind: "s3" as const, endpoint: "https://s3.example.test", region: "eu-west-1", bucket: "team-vault", prefix: "mooring", pathStyle: true }, credentialId: "cr-s3", intervalMinutes: 15 };

describe("Settings → Vault sync (ADR-0017)", () => {
  let mock: MockTransport;
  beforeEach(async () => {
    mock = freshBackend();
    useSync.getState().reset();
    await useCredentials.getState().load();
  });

  async function card() {
    render(<SyncCard />);
    await vi.waitFor(() => { expect(screen.queryByText("Loading…")).toBeNull(); });
    return screen.getByRole("region", { name: "Vault sync" });
  }

  it("starts off, shows the vault id, and configures through the dialog", async () => {
    const c = await card();
    expect(within(c).getByLabelText("Sync status")).toHaveTextContent("Off");
    expect(c).toHaveTextContent(MOCK_VAULT_ID);
    expect(within(c).queryByRole("button", { name: "Sync now" })).toBeNull();
    fireEvent.click(within(c).getByRole("button", { name: "Set up…" }));
    const dlg = screen.getByRole("dialog", { name: "Set up vault sync" });
    // 6b B-6: the sync trust prompt is two three-button system dialogs
    expect(dlg).toHaveTextContent("two system dialogs with three buttons each: “Trust once (this sync only)”, then “Trust and remember”");
    fireEvent.click(within(dlg).getByRole("button", { name: "Save and check" }));
    expect(within(dlg).getByRole("alert")).toHaveTextContent("Fix the highlighted fields.");
    expect(within(dlg).getByLabelText("Endpoint")).toHaveAttribute("aria-invalid", "true");
    fireEvent.change(within(dlg).getByLabelText("Endpoint"), { target: { value: "https://S3.example.test/" } });
    fireEvent.change(within(dlg).getByLabelText("Bucket"), { target: { value: "team-vault" } });
    fireEvent.change(within(dlg).getByLabelText("Region"), { target: { value: "eu-west-1" } });
    fireEvent.change(within(dlg).getByLabelText("Access key"), { target: { value: "cr-s3" } });
    fireEvent.change(within(dlg).getByLabelText("Minutes between syncs"), { target: { value: "30" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Save and check" }));
    await settle();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect((await mock.syncStatus()).config).toEqual({ ...CONFIG, intervalMinutes: 30 });
    expect(within(c).getByRole("status")).toHaveTextContent("Saved. The storage answered and conditional writes work.");
    const status = within(c).getByLabelText("Sync status");
    expect(status).toHaveTextContent("Idle");
    expect(status).toHaveTextContent("https://s3.example.test / team-vault / mooring");
    expect(status).toHaveTextContent("team bucket key");
    expect(status).toHaveTextContent("every 30 min");
    expect(status).toHaveTextContent("dev-0001");
  });

  it("refuses a backend without conditional writes and explains it", async () => {
    const c = await card();
    fireEvent.click(within(c).getByRole("button", { name: "Set up…" }));
    const dlg = screen.getByRole("dialog");
    fireEvent.change(within(dlg).getByLabelText("Endpoint"), { target: { value: "https://s3.invalid" } });
    fireEvent.change(within(dlg).getByLabelText("Bucket"), { target: { value: "b-1" } });
    fireEvent.change(within(dlg).getByLabelText("Region"), { target: { value: "r1" } });
    fireEvent.change(within(dlg).getByLabelText("Access key"), { target: { value: "cr-s3" } });
    fireEvent.click(within(dlg).getByRole("radio", { name: "Manual only" }));
    fireEvent.click(within(dlg).getByRole("button", { name: "Save and check" }));
    await settle();
    expect(screen.getByRole("dialog")).toBeInTheDocument(); // stays open on failure
    expect(within(c).getByRole("alert")).toHaveTextContent("does not honour conditional writes");
  });

  it("Sync now reports the outcome; the event drives the status and the trust hint", async () => {
    await mock.syncConfigure(CONFIG);
    const c = await card();
    fireEvent.click(within(c).getByRole("button", { name: "Sync now" }));
    await settle();
    expect(within(c).getByRole("status")).toHaveTextContent("Pushed generation 1.");
    expect(within(c).getByLabelText("Sync status")).toHaveTextContent("gen 1");
    act(() => { mock.simulateTrustPrompt(); });
    const status = within(c).getByLabelText("Sync status");
    expect(status).toHaveTextContent("Error");
    expect(within(status).getByRole("alert")).toHaveTextContent("run Sync now to answer the certificate prompt");
    mock.remoteEdits = [{ kind: "credential", id: "cr-ops", name: "ops on-call", resolution: { type: "keptBoth", copyId: "cr-ops-2" } }];
    fireEvent.click(within(c).getByRole("button", { name: "Sync now" }));
    await settle();
    expect(within(c).getByRole("status")).toHaveTextContent("Merged into generation 2 with 1 conflict (listed below).");
    const list = within(c).getByRole("list", { name: "Merge conflicts" });
    expect(list).toHaveTextContent("credential");
    expect(list).toHaveTextContent("ops on-call");
    expect(list).toHaveTextContent("both copies kept");
  });

  it("a trust conflict after a two-device apply is a standing alarm with a link to the known-certificates manager (6b L-35)", async () => {
    const kiosk = { connectionId: "c-kiosk", protocol: "vnc" as const, name: "lobby-kiosk", host: "kiosk.example.test", port: 5900, tags: [], options: undefined };
    await mock.pin(kiosk);
    await mock.syncConfigure(CONFIG);
    await mock.syncNow();
    const c = await card();
    expect(within(c).queryByRole("alert")).toBeNull();
    mock.remoteTrust = [kiosk];
    fireEvent.click(within(c).getByRole("button", { name: "Sync now" }));
    await settle();
    const alarm = within(c).getByRole("alert", { name: "Certificate trust conflicts" });
    expect(alarm).toHaveTextContent("Certificate trust conflict");
    expect(alarm).toHaveTextContent("Two devices trust different certificates for kiosk.example.test:5900. Remove one in Settings → Trust.");
    expect(alarm).toHaveTextContent("known_vnc_certs");
    expect(alarm).not.toHaveTextContent("SHA256");
    expect(within(c).queryByRole("list", { name: "Merge conflicts" })).toBeNull(); // a trust entry is not a merge row
    // it stands across runs and is not dismissable here
    fireEvent.click(within(c).getByRole("button", { name: "Sync now" }));
    await settle();
    expect(within(c).getByRole("alert", { name: "Certificate trust conflicts" })).toBeInTheDocument();
    expect(within(alarm).queryByRole("button", { name: /Dismiss/ })).toBeNull();
    expect(within(alarm).getByRole("button", { name: "Open known certificates" })).toBeInTheDocument();
    // removing the pins clears it at once (the status event follows the removal)
    await act(async () => { await mock.knownCertsRemove({ protocol: "vnc", host: "kiosk.example.test", port: 5900 }); });
    expect(within(c).queryByRole("alert")).toBeNull();
  });

  it("a fork shows the banner; resolving goes through Rust's native confirmation", async () => {
    await mock.syncConfigure(CONFIG);
    await mock.syncNow();
    const c = await card();
    act(() => { mock.simulateAlarm("fork"); });
    const banner = within(c).getByRole("alert");
    expect(banner).toHaveTextContent("Fork detected");
    expect(banner).toHaveTextContent("Two devices published generation 2 by laptop.");
    expect(banner).toHaveTextContent("three buttons (Cancel, Discard and resolve, Not now)"); // 6b B-6
    expect(within(c).getByRole("button", { name: "Sync now" })).toBeDisabled();
    mock.confirmResolve = false;
    fireEvent.click(within(banner).getByRole("button", { name: "Resolve: keep remote" }));
    await settle();
    expect(within(c).getAllByRole("alert")[0]).toHaveTextContent("You cancelled the confirmation, so nothing was changed.");
    expect(within(c).getByRole("button", { name: "Resolve: keep local" })).toBeInTheDocument();
    mock.confirmResolve = true;
    fireEvent.click(within(c).getByRole("button", { name: "Resolve: keep local" }));
    await settle();
    expect(within(c).queryByRole("button", { name: "Resolve: keep local" })).toBeNull();
    expect(within(c).getByRole("status")).toHaveTextContent("Resolved, keeping the local copy. Pushed generation 3.");
    expect(within(c).getByLabelText("Sync status")).toHaveTextContent("Idle");
  });

  it("rollback banner and disable with or without deleting the bucket objects", async () => {
    await mock.syncConfigure(CONFIG);
    await mock.syncNow();
    const c = await card();
    act(() => { mock.simulateAlarm("rollback"); });
    expect(within(c).getByRole("alert")).toHaveTextContent("Rollback detected");
    expect(within(c).getByRole("alert")).toHaveTextContent("older than the 1 this device has seen");
    fireEvent.click(within(c).getByRole("button", { name: "Disable…" }));
    fireEvent.click(within(c).getByRole("button", { name: "Disable and delete remote" }));
    await settle();
    expect(within(c).getByRole("status")).toHaveTextContent("Sync is off and the bucket objects were deleted.");
    expect(within(c).getByLabelText("Sync status")).toHaveTextContent("Off");
    expect(mock.audit.at(-1)).toMatchObject({ event: "sync.disabled", details: { delete_remote: "true" } });
  });

  it("formats times, outcomes and resolutions", () => {
    const now = Date.parse("2026-11-01T10:00:00Z");
    expect(fmtUnix(null)).toBe("never");
    expect(fmtUnix(now / 1000 - 30, now)).toBe("just now");
    expect(fmtUnix(now / 1000 - 600, now)).toBe("2026-11-01 09:50 UTC (10 min ago)");
    expect(fmtUnix(now / 1000 + 7200, now)).toBe("2026-11-01 12:00 UTC (in 2 h)");
    expect(describeOutcome({ type: "noChange", counter: 4 })).toBe("Nothing to sync; generation 4 is current.");
    expect(describeOutcome({ type: "merged", counter: 5, conflicts: [] })).toBe("Merged both sides into generation 5.");
    expect(resolutionText({ type: "keptEdit" })).toMatch(/edit was kept/);
    expect(resolutionText({ type: "lastWriterWins" })).toMatch(/newer edit won/);
  });
});
