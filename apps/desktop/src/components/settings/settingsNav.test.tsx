import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { freshBackend, settle } from "../../test/harness";
import { useUi } from "../../stores/ui";
import { openSettingsCard } from "../SyncBanner";
import { SettingsView } from "./SettingsView";
import { matchSections, SETTINGS_SECTIONS } from "./settingsSections";

// M6: Settings gets a section list with search; the card heading ids stay the contract.

const nav = () => screen.getByRole("navigation", { name: "Settings sections" });
const search = () => screen.getByRole("searchbox", { name: "Find a setting" });

describe("settings sections (M6)", () => {
  beforeEach(() => { freshBackend(); });

  it("matches titles, groups and extra terms, every word", () => {
    expect(matchSections("").length).toBe(SETTINGS_SECTIONS.length);
    expect(matchSections("THEME").map((s) => s.id)).toEqual(["appearance-title"]);
    expect(matchSections("fido2").map((s) => s.id)).toEqual(["ssh-title"]);
    expect(matchSections("trust audit syslog").map((s) => s.id)).toEqual(["syslog-title"]);
    expect(matchSections("zzz")).toEqual([]);
  });

  it("lists every card under its group and each heading id exists on the page", async () => {
    render(<SettingsView />);
    await settle();
    const groups = within(nav()).getAllByRole("list");
    expect(groups.map((g) => g.getAttribute("aria-labelledby") && document.getElementById(g.getAttribute("aria-labelledby") ?? "")?.textContent)).toEqual([
      "Vault", "Trust and audit", "Application",
    ]);
    expect(within(nav()).getAllByRole("button").map((b) => b.textContent)).toEqual(SETTINGS_SECTIONS.map((s) => s.title));
    for (const s of SETTINGS_SECTIONS) expect(document.getElementById(s.id), s.id).not.toBeNull();
  });

  it("a section click marks it current and focuses its card heading", async () => {
    render(<SettingsView />);
    await settle();
    const item = within(nav()).getByRole("button", { name: "Known certificates" });
    fireEvent.click(item);
    expect(item).toHaveAttribute("aria-current", "true");
    expect(document.getElementById("trust-title")).toHaveFocus();
  });

  it("search hides the other cards and their nav items; Escape clears it", async () => {
    render(<SettingsView />);
    await settle();
    fireEvent.change(search(), { target: { value: "theme" } });
    expect(within(nav()).getAllByRole("button").map((b) => b.textContent)).toEqual(["Appearance"]);
    expect(screen.getByRole("heading", { name: "Appearance" })).toBeVisible();
    expect(screen.queryByRole("region", { name: "Auto-lock" })).toBeNull();
    expect(document.querySelector('[data-section="autolock-title"]')).toHaveAttribute("hidden");
    fireEvent.change(search(), { target: { value: "no such thing" } });
    expect(within(nav()).getByRole("status")).toHaveTextContent("No setting matches “no such thing”.");
    fireEvent.keyDown(search(), { key: "Escape" });
    expect(search()).toHaveValue("");
    expect(screen.getByRole("region", { name: "Auto-lock" })).toBeInTheDocument();
  });

  it("opening a card from elsewhere clears the search so the card is shown", async () => {
    render(<SettingsView />);
    await settle();
    fireEvent.change(search(), { target: { value: "theme" } });
    act(() => { openSettingsCard("sync-title"); });
    expect(useUi.getState().settingsQuery).toBe("");
    expect(screen.getByRole("region", { name: "Vault sync" })).toBeInTheDocument();
  });
});
