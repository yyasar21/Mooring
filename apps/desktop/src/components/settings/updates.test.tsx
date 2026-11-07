import { act, fireEvent, render, screen, within } from "@testing-library/react";
import type { MockTransport } from "../../lib/ipc.mock";
import { MOCK_UPDATE_OFFER } from "../../lib/ipc.mock.update";
import { useApp } from "../../stores/app";
import { useSessions } from "../../stores/sessions";
import { useUi } from "../../stores/ui";
import { useUpdate } from "../../stores/update";
import { freshBackend, settle } from "../../test/harness";
import { Shell } from "../Shell";
import { SettingsView } from "./SettingsView";
import { fmtBytes, fmtDate, fmtStamp } from "../../lib/format";
import { MANUAL_REASON_TEXT, RELEASE_PAGE, UpdatesCard } from "./UpdatesCard";
import { PORTABLE_UPDATE_TEXT } from "./PortableLine";
import { PORTABLE_MANUAL_TEXT } from "../../lib/ipc.mock.update";

describe("Settings → Updates (ADR-0018 §3, U0)", () => {
  let mock: MockTransport;
  beforeEach(() => {
    mock = freshBackend();
    mock.updateRateWindowMs = 0;
  });

  async function card() {
    render(<UpdatesCard />);
    await settle();
    return screen.getByRole("region", { name: "Updates" });
  }

  it("shows the installed version, never checked, and the toggle off", async () => {
    await act(async () => { await useApp.getState().boot(); });
    const c = await card();
    expect(screen.getByTestId("update-current")).toHaveTextContent("dev"); // app_info before any check
    expect(c).toHaveTextContent("Last checked: never");
    expect(screen.queryByTestId("update-last-verified")).toBeNull(); // F2: null until the first verified install
    expect(within(c).getByRole("switch", { name: /^Check for updates in the background \(daily\)/ })).not.toBeChecked();
    expect(within(c).queryByLabelText("Available update")).toBeNull();
  });

  it("Check for updates: the offer with version, date, size, notes as text lines, and Install only in_app", async () => {
    const c = await card();
    fireEvent.click(within(c).getByRole("button", { name: "Check for updates" }));
    await settle();
    expect(screen.getByTestId("update-current")).toHaveTextContent("0.1.0");
    const offer = within(c).getByLabelText("Available update");
    expect(offer).toHaveTextContent("Update available");
    expect(offer).toHaveTextContent("0.2.0");
    expect(offer).toHaveTextContent("2026-11-20 · 48.2 MB");
    const notes = within(offer).getByLabelText("Release notes");
    expect(notes.querySelectorAll(".update-notes-line")).toHaveLength(MOCK_UPDATE_OFFER.notes.split("\n").length);
    expect(notes.querySelector("a, b, strong, em, h1, ul")).toBeNull(); // plain text, no markup
    expect(within(offer).getByRole("button", { name: "Install and restart" })).toBeEnabled();
    expect(c).toHaveTextContent(/Last checked: \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC/);
  });

  it("renders notes containing markup as literal text", async () => {
    mock.updateOffer = { ...MOCK_UPDATE_OFFER, notes: "<b>bold</b>\n[link](https://evil.example.test)" };
    const c = await card();
    fireEvent.click(within(c).getByRole("button", { name: "Check for updates" }));
    await settle();
    const notes = within(c).getByLabelText("Release notes");
    expect(notes.textContent).toBe("<b>bold</b>[link](https://evil.example.test)");
    expect(notes.querySelector("b, a")).toBeNull();
  });

  it("up to date, then the rate limit on a second check, then a network failure", async () => {
    mock.updateOffer = null;
    const c = await card();
    fireEvent.click(within(c).getByRole("button", { name: "Check for updates" }));
    await settle();
    expect(within(c).getByRole("status")).toHaveTextContent("Mooring is up to date.");
    mock.updateRateWindowMs = 60_000;
    fireEvent.click(within(c).getByRole("button", { name: "Check for updates" }));
    await settle();
    expect(within(c).getByRole("alert")).toHaveTextContent("You checked a moment ago. Wait a minute before checking again.");
    mock.updateRateWindowMs = 0;
    mock.updateCheckFails = "update.network";
    fireEvent.click(within(c).getByRole("button", { name: "Check for updates" }));
    await settle();
    expect(within(c).getByRole("alert")).toHaveTextContent("The update server did not answer.");
  });

  it("shows the busy state while a check runs", async () => {
    mock = freshBackend({ delayMs: 30 });
    mock.updateRateWindowMs = 0;
    const c = await card();
    fireEvent.click(within(c).getByRole("button", { name: "Check for updates" }));
    await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
    expect(within(c).getByRole("button", { name: "Checking…" })).toBeDisabled();
    await vi.waitFor(() => { expect(within(c).getByRole("button", { name: "Check for updates" })).toBeEnabled(); });
  });

  it("manual mode: no Install button, the reason text and a copyable release link", async () => {
    const written: string[] = [];
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: (t: string) => { written.push(t); return Promise.resolve(); } } });
    for (const reason of ["package_manager", "homebrew", "not_writable", "not_bundled", "portable"] as const) {
      mock = freshBackend();
      mock.updateRateWindowMs = 0;
      mock.updateMode = { installMode: "manual", manualReason: reason };
      const { unmount } = render(<UpdatesCard />);
      const c = screen.getByRole("region", { name: "Updates" });
      fireEvent.click(within(c).getByRole("button", { name: "Check for updates" }));
      await settle();
      expect(within(c).queryByRole("button", { name: "Install and restart" })).toBeNull();
      expect(within(c).getByLabelText("Available update")).toHaveTextContent(MANUAL_REASON_TEXT[reason]);
      expect(within(c).queryAllByRole("link")).toHaveLength(0);
      fireEvent.click(within(c).getByRole("button", { name: "Copy release page link" }));
      await settle();
      expect(written.at(-1)).toBe(RELEASE_PAGE);
      expect(within(c).getByRole("button", { name: "Copy release page link" })).toHaveTextContent("Copied");
      unmount();
    }
    expect(RELEASE_PAGE).toBe("https://github.com/yyasar21/Mooring/releases/latest");
  });

  it("ADR-0021: a portable build shows the data folder, disables the background toggle with the zip hint and still checks", async () => {
    mock.portableDataDir = "/media/stick/Mooring Data";
    mock.updateMode = { installMode: "manual", manualReason: "portable" };
    await act(async () => { await useApp.getState().boot(); });
    const c = await card();
    const line = within(c).getByTestId("portable-line");
    expect(line).toHaveTextContent("Portable build — data in /media/stick/Mooring Data");
    expect(line.querySelector("code")).toHaveTextContent("/media/stick/Mooring Data");
    const sw = within(c).getByRole("switch", { name: /^Check for updates in the background \(daily\)/ });
    expect(sw).toBeDisabled();
    expect(sw).not.toBeChecked();
    expect(sw.closest("label")).toHaveTextContent(PORTABLE_UPDATE_TEXT);
    expect(MANUAL_REASON_TEXT.portable).toBe(PORTABLE_UPDATE_TEXT);
    expect(PORTABLE_UPDATE_TEXT).toBe(PORTABLE_MANUAL_TEXT); // same text as Rust's `update.manual_only`
    expect(within(c).getByRole("button", { name: "Check for updates" })).toBeEnabled();
    fireEvent.click(within(c).getByRole("button", { name: "Check for updates" }));
    await settle();
    const offer = within(c).getByLabelText("Available update");
    expect(offer).toHaveTextContent(PORTABLE_UPDATE_TEXT);
    expect(within(offer).queryByRole("button", { name: "Install and restart" })).toBeNull();
    expect(mock.audit.filter((a) => a.event === "update.refused")).toHaveLength(0); // the toggle never fired update_settings_set
  });

  it("not portable: no portable line and the toggle keeps its own hint", async () => {
    await act(async () => { await useApp.getState().boot(); });
    const c = await card();
    expect(within(c).queryByTestId("portable-line")).toBeNull();
    const sw = within(c).getByRole("switch", { name: /^Check for updates in the background \(daily\)/ });
    expect(sw).toBeEnabled();
    expect(sw.closest("label")).not.toHaveTextContent(PORTABLE_UPDATE_TEXT);
  });

  it("Install and restart asks in the UI, names the open sessions, closes them and installs", async () => {
    mock.trustedHosts.add("web01.example.test");
    await useSessions.getState().open("c-web01");
    await settle();
    const c = await card();
    fireEvent.click(within(c).getByRole("button", { name: "Check for updates" }));
    await settle();
    fireEvent.click(within(c).getByRole("button", { name: "Install and restart" }));
    const dlg = screen.getByRole("dialog", { name: "Install 0.2.0 and restart?" });
    expect(dlg).toHaveTextContent("1 open session will be closed first");
    fireEvent.click(within(dlg).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(mock.restarted).toBeNull();
    fireEvent.click(within(c).getByRole("button", { name: "Install and restart" }));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Close sessions, install and restart" }));
    await settle();
    expect(mock.restarted).toBe("0.2.0");
    expect(await mock.sessionList()).toEqual([]);
    expect(within(c).getByRole("status")).toHaveTextContent("Downloading and verifying the update");
  });

  it("an install refusal is shown as friendly text", async () => {
    const c = await card();
    fireEvent.click(within(c).getByRole("button", { name: "Check for updates" }));
    await settle();
    mock.updateInstallFails = "update.signature";
    fireEvent.click(within(c).getByRole("button", { name: "Install and restart" }));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Install and restart" }));
    await settle();
    expect(within(c).getByRole("alert")).toHaveTextContent("The update's signature did not verify, so nothing was installed.");
    expect(mock.restarted).toBeNull();
  });

  it("F2 (L-39): the verified floor is shown once set and a downgrade offer is refused as friendly text", async () => {
    mock.updateSettings = { ...mock.updateSettings, lastVerified: "0.2.0" };
    mock.updateOffer = { ...MOCK_UPDATE_OFFER, version: "0.1.5" };
    const c = await card();
    expect(within(c).getByTestId("update-last-verified")).toHaveTextContent("Last verified update: 0.2.0");
    fireEvent.click(within(c).getByRole("button", { name: "Check for updates" }));
    await settle();
    expect(within(c).getByRole("alert")).toHaveTextContent("older than an update this install already verified");
    expect(within(c).queryByLabelText("Available update")).toBeNull();
    expect(mock.audit.at(-1)).toMatchObject({ event: "update.refused", details: { code: "update.downgrade" } });
  });

  it("the background toggle writes update_settings_set and reverts on failure", async () => {
    const c = await card();
    const sw = within(c).getByRole("switch", { name: /^Check for updates in the background \(daily\)/ });
    fireEvent.click(sw);
    await settle();
    expect((await mock.updateSettingsGet()).backgroundCheck).toBe(true);
    expect(sw).toBeChecked();
    expect(mock.audit.at(-1)).toMatchObject({ event: "update.settings_changed", details: { background_check: "true" } });
    mock.vault = "locked";
    fireEvent.click(sw);
    await settle();
    expect(sw).toBeChecked(); // reverted
    expect(within(c).getByRole("alert")).toHaveTextContent("The vault is locked.");
  });

  it("an unconfigured build says so and disables every control", async () => {
    mock.updateConfigured = false;
    const c = await card();
    expect(within(c).getByRole("status")).toHaveTextContent("Updates are not configured in this build.");
    expect(within(c).getByRole("button", { name: "Check for updates" })).toBeDisabled();
    expect(within(c).queryByRole("switch")).toBeNull();
  });

  it("sits directly above About in Settings", async () => {
    render(<SettingsView />);
    await settle();
    const regions = screen.getAllByRole("region").map((r) => r.getAttribute("aria-labelledby"));
    expect(regions.slice(-2)).toEqual(["updates-title", "about-title"]);
  });

  it("the update:available event shows the title-bar notice, which opens the card and clears", async () => {
    await mock.updateSettingsSet({ backgroundCheck: true });
    await act(async () => { await useApp.getState().boot(); });
    render(<Shell />);
    await settle();
    expect(screen.queryByRole("button", { name: /Update .* available/ })).toBeNull();
    await act(async () => { await mock.simulateBackgroundCheck(); });
    const badge = screen.getByRole("button", { name: "Update 0.2.0 available. Open update settings" });
    expect(badge).toHaveTextContent("Update 0.2.0");
    expect(mock.restarted).toBeNull();
    fireEvent.click(badge);
    await settle();
    expect(useUi.getState().view).toBe("settings");
    const c = screen.getByRole("region", { name: "Updates" });
    expect(within(c).getByLabelText("Available update")).toHaveTextContent("0.2.0");
    expect(useUpdate.getState().badge).toBeNull();
    act(() => { useUi.getState().setView("workspace"); });
    expect(screen.queryByRole("button", { name: /Update .* available/ })).toBeNull();
  });

  it("formatters", () => {
    expect(fmtBytes(null)).toBeNull();
    expect(fmtBytes(812)).toBe("812 B");
    expect(fmtBytes(812_000)).toBe("812 kB");
    expect(fmtBytes(48_234_496)).toBe("48.2 MB");
    expect(fmtBytes(1_250_000_000)).toBe("1.25 GB");
    expect(fmtDate(null)).toBeNull();
    expect(fmtDate("2026-11-20T09:00:00Z")).toBe("2026-11-20");
    expect(fmtDate("soon")).toBe("soon");
    expect(fmtStamp(null)).toBe("never");
    expect(fmtStamp("2026-11-06T10:42:31Z")).toBe("2026-11-06 10:42 UTC");
  });
});
