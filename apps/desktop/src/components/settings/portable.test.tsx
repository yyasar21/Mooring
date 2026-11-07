import { act, render, screen, within } from "@testing-library/react";
import { PORTABLE_MANUAL_TEXT } from "../../lib/ipc.mock.update";
import { useApp } from "../../stores/app";
import { FRIENDLY } from "../../stores/errors";
import { useUpdate } from "../../stores/update";
import { freshBackend, settle } from "../../test/harness";
import { AboutCard } from "./AboutCard";
import { PORTABLE_UPDATE_TEXT, PortableLine } from "./PortableLine";
import { UpdatesCard } from "./UpdatesCard";

/** A4.1 Q1 (ADR-0021): hostile paths, the refusal path the disabled toggle hides, About with null. */
describe("portable build badge — hostile cases (ADR-0021)", () => {
  it("PortableLine renders a path containing markup as literal text", () => {
    const path = "/media/<b>x</b>/<img src=x onerror=alert(1)>/Mooring Data";
    render(<PortableLine path={path} />);
    const line = screen.getByTestId("portable-line");
    expect(line.querySelector("b, img, script")).toBeNull();
    expect(line.querySelector("code")).toHaveTextContent(path);
    expect(line.querySelector("code")).toHaveAttribute("title", path);
    expect(screen.queryAllByRole("link")).toHaveLength(0);
    expect(within(line).getByRole("button", { name: "Copy portable data folder path" })).toBeInTheDocument();
  });

  it("PortableLine keeps a Windows path with backslashes, spaces and unicode verbatim", () => {
    const path = "D:\\Taşınabilir Dosyalar\\Mooring Data\\";
    render(<PortableLine path={path} />);
    expect(screen.getByTestId("portable-line").querySelector("code")).toHaveTextContent(path);
  });

  it("Updates: the toggle is disabled with the zip hint when portableDataDir is set, even with backgroundCheck stored on", async () => {
    const mock = freshBackend();
    mock.portableDataDir = "/media/stick/Mooring Data";
    mock.updateSettings = { ...mock.updateSettings, backgroundCheck: true }; // a setting stored before the folder went portable
    await act(async () => { await useApp.getState().boot(); });
    render(<UpdatesCard />);
    await settle();
    const c = screen.getByRole("region", { name: "Updates" });
    const sw = within(c).getByRole("switch", { name: /^Check for updates in the background \(daily\)/ });
    expect(sw).toBeDisabled();
    expect(sw).not.toBeChecked(); // shown off: no background task runs in a portable folder
    expect(sw.closest("label")).toHaveTextContent(PORTABLE_UPDATE_TEXT);
    expect(within(c).getByRole("button", { name: "Check for updates" })).toBeEnabled();
  });

  it("Updates: when the opt-in reaches the backend anyway and is refused, an alert is shown and the setting reverts", async () => {
    const mock = freshBackend();
    mock.portableDataDir = "/media/stick/Mooring Data";
    await act(async () => { await useApp.getState().boot(); });
    render(<UpdatesCard />);
    await settle();
    // Drive the store directly (a stale render or a keyboard event on a re-enabled switch).
    await act(async () => { await useUpdate.getState().setBackground(true); });
    await settle();
    const c = screen.getByRole("region", { name: "Updates" });
    expect(within(c).getByRole("alert")).toBeInTheDocument();
    expect(useUpdate.getState().settings?.backgroundCheck).toBe(false); // optimistic flip reverted
    expect(mock.audit.filter((a) => a.event === "update.refused").map((a) => a.details)).toEqual([{ code: "update.manual_only" }]);
    expect(within(c).getByRole("switch", { name: /^Check for updates in the background \(daily\)/ })).not.toBeChecked();
  });

  // BUG a4-1-qa-2 (ui-engineer, acknowledged in a4-1-ui-p1.md "Left open"): `describeError`
  // maps every `update.manual_only` to FRIENDLY's "managed by a package manager or Homebrew"
  // text, so the refusal a portable build gets back is shown with the wrong reason. Flip
  // `it.fails` to `it` once the portable message wins (e.g. FRIENDLY lookup after a
  // message-specific pass, or Rust's message shown when it is not the generic one).
  it.fails("Updates: the refusal alert carries the portable message, not the package-manager text", async () => {
    const mock = freshBackend();
    mock.portableDataDir = "/media/stick/Mooring Data";
    await act(async () => { await useApp.getState().boot(); });
    render(<UpdatesCard />);
    await settle();
    await act(async () => { await useUpdate.getState().setBackground(true); });
    await settle();
    const alert = within(screen.getByRole("region", { name: "Updates" })).getByRole("alert");
    expect(alert).toHaveTextContent(PORTABLE_MANUAL_TEXT);
    expect(alert).not.toHaveTextContent(FRIENDLY["update.manual_only"] ?? "package manager");
  });

  it("About shows no portable line when portableDataDir is null or app_info is not loaded yet", async () => {
    freshBackend();
    const { unmount } = render(<AboutCard />);
    expect(screen.queryByTestId("portable-line")).toBeNull(); // before boot: info === null
    expect(screen.getByRole("region", { name: "About" })).not.toHaveTextContent("Portable");
    await act(async () => { await useApp.getState().boot(); });
    await settle();
    expect(useApp.getState().info?.portableDataDir).toBeNull();
    expect(screen.queryByTestId("portable-line")).toBeNull();
    expect(screen.getByRole("region", { name: "About" })).not.toHaveTextContent("Portable");
    expect(screen.queryByRole("button", { name: "Copy portable data folder path" })).toBeNull();
    unmount();
  });
});
