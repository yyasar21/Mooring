import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { App } from "../App";
import type { MockTransport } from "../lib/ipc.mock";
import { alarmKey, useSync } from "../stores/sync";
import { useUi } from "../stores/ui";
import { freshBackend, settle } from "../test/harness";

const CONFIG = { backend: { kind: "s3" as const, endpoint: "https://s3.example.test", region: "eu-west-1", bucket: "team-vault", prefix: "", pathStyle: true }, credentialId: "cr-s3", intervalMinutes: 15 };

describe("shell sync banner (ADR-0017)", () => {
  let mock: MockTransport;
  beforeEach(async () => {
    mock = freshBackend();
    await mock.syncConfigure(CONFIG);
    await mock.syncNow();
  });

  async function boot() {
    render(<App />);
    await screen.findByText("Nothing open yet");
    await settle();
  }

  const banner = () => document.querySelector(".sync-banner");

  it("stays silent while sync is healthy and shows a fork wherever the user is", async () => {
    await boot();
    expect(banner()).toBeNull();
    act(() => { mock.simulateAlarm("fork"); });
    const b = screen.getByRole("alert");
    expect(b).toHaveTextContent("Sync fork detected");
    expect(b).toHaveTextContent("Two devices published generation 2 by laptop. Sync is paused on this device");
    // the resolve controls stay on the card: the banner only jumps there
    expect(within(b).queryByRole("button", { name: /Resolve/ })).toBeNull();
    fireEvent.click(within(b).getByRole("button", { name: "Open Vault sync settings" }));
    expect(useUi.getState().view).toBe("settings");
    await settle();
    // one alert at a time: the banner yields to the card's own alarm
    const card = screen.getByRole("region", { name: "Vault sync" });
    expect(within(card).getByRole("alert")).toHaveTextContent("Fork detected");
    expect(banner()).toBeNull();
    expect(document.activeElement).toBe(screen.getByRole("heading", { name: "Vault sync" }));
    expect(within(card).getByRole("button", { name: "Resolve: keep local" })).toBeInTheDocument();
  });

  it("dismisses per alarm: the same alarm stays hidden, the next one shows, a lock clears the dismissal", async () => {
    await boot();
    act(() => { mock.simulateAlarm("rollback"); });
    expect(screen.getByRole("alert")).toHaveTextContent("Sync rollback detected");
    fireEvent.click(screen.getByRole("button", { name: "Dismiss sync notice" }));
    expect(banner()).toBeNull();
    expect(useSync.getState().dismissed).toBe(alarmKey(useSync.getState().status));

    mock.confirmResolve = true;
    await act(async () => { await mock.syncResolveFork({ keep: "local" }); });
    expect(banner()).toBeNull();
    act(() => { mock.simulateAlarm("fork"); });
    expect(screen.getByRole("alert")).toHaveTextContent("Sync fork detected");
    fireEvent.click(screen.getByRole("button", { name: "Dismiss sync notice" }));
    expect(banner()).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Lock" }));
    await settle();
    expect(useSync.getState().dismissed).toBeNull();
    expect(useSync.getState().status).toBeNull();
  });

  it("a failed background run is a banner too, with the trust-prompt hint", async () => {
    await boot();
    act(() => { mock.simulateTrustPrompt(); });
    const b = screen.getByRole("alert");
    expect(b).toHaveTextContent("Vault sync failed");
    expect(b).toHaveTextContent("The last run failed: the certificate is not trusted. Run Sync now from the settings to answer the certificate prompt.");
    expect(b).toHaveAttribute("data-kind", "error");
    await act(async () => { await mock.syncNow(); });
    expect(banner()).toBeNull();
  });

  it("shows a quiet Syncing… hint in the title bar only while a run is in progress", async () => {
    await boot();
    const hint = () => document.querySelector(".sync-indicator");
    expect(hint()).toBeNull();
    const status = useSync.getState().status;
    if (!status) throw new Error("status not loaded");
    act(() => { useSync.setState({ status: { ...status, state: "running" } }); });
    expect(hint()).toHaveAttribute("role", "status");
    expect(hint()).toHaveTextContent("Syncing…");
    expect(banner()).toBeNull();
    act(() => { useSync.setState({ status: { ...status, state: "idle" } }); });
    expect(hint()).toBeNull();
  });

  it("alarmKey tells alarms apart and is null when nothing is wrong", () => {
    const base = useSync.getState().status;
    expect(alarmKey(null)).toBeNull();
    if (!base) return;
    expect(alarmKey({ ...base, alarm: null, lastError: null })).toBeNull();
    expect(alarmKey({ ...base, alarm: { type: "fork", remote: 3 } })).toBe("fork:3");
    expect(alarmKey({ ...base, alarm: { type: "rollback", remote: 1, last: 4 } })).toBe("rollback:1:4");
    expect(alarmKey({ ...base, alarm: null, lastError: { code: "http.trust_prompt", message: "x" }, lastRunUnix: 7 })).toBe("error:http.trust_prompt:7");
  });
});
