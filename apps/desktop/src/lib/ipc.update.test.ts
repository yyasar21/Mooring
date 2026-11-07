// ADR-0018 §3 mock contract as rust-core U0 serves it: check (rate limit, busy, failures), the
// install matrix (manual reasons, open sessions, re-check), settings and the background event.
import { IpcError, type UpdateInfo } from "./ipc";
import { decodeUpdateInfo, decodeUpdateSettings } from "./ipc.decode.update";
import { MockTransport } from "./ipc.mock";
import { MOCK_CURRENT_VERSION, MOCK_UPDATE_OFFER, PORTABLE_MANUAL_TEXT, semverBelow } from "./ipc.mock.update";

const code = async (p: Promise<unknown>) => {
  try {
    await p;
    return "ok";
  } catch (e: unknown) {
    return e instanceof IpcError ? e.code : "not an IpcError";
  }
};

describe("mock · updater (ADR-0018 §3, U0)", () => {
  it("checks, rate-limits a second manual check, and records lastCheck", async () => {
    const m = new MockTransport();
    const info = await m.updateCheck();
    expect(info).toMatchObject({ current: MOCK_CURRENT_VERSION, available: MOCK_UPDATE_OFFER, installMode: "in_app" });
    expect(info.manualReason).toBeUndefined();
    expect(Date.parse(info.checkedAt)).not.toBeNaN();
    expect(m.audit.at(-1)).toMatchObject({ event: "update.check", details: { current: "0.1.0", available: "0.2.0" } });
    expect(await code(m.updateCheck())).toBe("update.rate_limited");
    expect((await m.updateSettingsGet()).lastCheck).not.toBeNull();
    m.updateRateWindowMs = 0;
    m.updateOffer = null;
    expect((await m.updateCheck()).available).toBeNull();
  });

  it("answers update.unconfigured everywhere without a pubkey, and vault.locked first", async () => {
    const m = new MockTransport();
    m.updateConfigured = false;
    expect(await code(m.updateCheck())).toBe("update.unconfigured");
    expect(await code(m.updateSettingsGet())).toBe("update.unconfigured");
    expect(await code(m.updateSettingsSet({ backgroundCheck: true }))).toBe("update.unconfigured");
    expect(await code(m.updateInstall({ version: "0.2.0" }))).toBe("update.unconfigured");
    const locked = new MockTransport({ vault: "locked" });
    locked.updateConfigured = false;
    expect(await code(locked.updateCheck())).toBe("vault.locked");
  });

  it("maps check failures to their codes", async () => {
    const m = new MockTransport();
    m.updateRateWindowMs = 0;
    for (const f of ["update.network", "update.manifest", "update.signature"] as const) {
      m.updateCheckFails = f;
      expect(await code(m.updateCheck())).toBe(f);
    }
    expect(await code(m.updateCheck())).toBe("ok");
  });

  it("installs only in_app, refuses manual modes and open sessions, and audits refusals", async () => {
    const m = new MockTransport();
    expect(await code(m.updateInstall({ version: "nope" }))).toBe("input.invalid");
    m.updateMode = { installMode: "manual", manualReason: "homebrew" };
    expect(await code(m.updateInstall({ version: "0.2.0" }))).toBe("update.manual_only");
    expect(m.audit.at(-1)).toMatchObject({ event: "update.refused", details: { code: "update.manual_only" } });
    m.updateMode = { installMode: "manual", manualReason: "not_writable" };
    expect(await code(m.updateInstall({ version: "0.2.0" }))).toBe("update.not_writable");
    m.updateMode = { installMode: "in_app" };
    expect(await code(m.updateInstall({ version: "0.3.0" }))).toBe("update.none");
    m.trustedHosts.add("web01.example.test");
    await m.sessionOpen({ connectionId: "c-web01", size: { width: 80, height: 24 }, onEvent: () => undefined });
    expect(await code(m.updateInstall({ version: "0.2.0" }))).toBe("update.sessions_open");
    expect(m.restarted).toBeNull();
    expect(await code(m.updateInstall({ version: "0.2.0", closeSessions: true }))).toBe("ok");
    expect(await m.sessionList()).toEqual([]);
    expect(m.restarted).toBe("0.2.0");
    expect(m.audit.some((e) => e.event === "update.install" && e.details.from === "0.1.0" && e.details.to === "0.2.0")).toBe(true);
    expect(JSON.stringify(m.audit)).not.toMatch(/https?:|signature=|\.sig/);
  });

  it("settings round-trip; only a real change is audited; the background check emits the event", async () => {
    const m = new MockTransport();
    const seen: UpdateInfo[] = [];
    const off = m.onUpdateAvailable((i) => seen.push(i));
    expect(await m.updateSettingsGet()).toEqual({ backgroundCheck: false, channel: "stable", lastCheck: null, lastVerified: null });
    await m.simulateBackgroundCheck();
    expect(seen).toHaveLength(0); // opt-in only
    const n = m.audit.length;
    expect(await m.updateSettingsSet({ backgroundCheck: true })).toMatchObject({ backgroundCheck: true });
    expect(m.audit.at(-1)).toMatchObject({ event: "update.settings_changed", details: { background_check: "true" } });
    await m.updateSettingsSet({ backgroundCheck: true });
    expect(m.audit).toHaveLength(n + 1);
    expect(await code(m.updateSettingsSet({ backgroundCheck: true, channel: "beta" as "stable" }))).toBe("input.invalid");
    await m.simulateBackgroundCheck();
    expect(seen).toHaveLength(1);
    expect(seen[0]?.available?.version).toBe("0.2.0");
    expect(m.restarted).toBeNull(); // never downloads or installs
    // a background check counts for the manual rate limit
    expect(await code(m.updateCheck())).toBe("update.rate_limited");
    off();
    m.updateRateWindowMs = 0;
    await m.simulateBackgroundCheck();
    expect(seen).toHaveLength(1);
  });

  it("decodeUpdateInfo normalises absent optional fields and unknown modes", () => {
    expect(decodeUpdateInfo({ current: "0.1.0", available: { version: "0.2.0", notes: "x" }, installMode: "in_app", checkedAt: "t" })).toEqual({
      current: "0.1.0", available: { version: "0.2.0", date: null, notes: "x", size: null }, installMode: "in_app", checkedAt: "t",
    });
    expect(decodeUpdateInfo({ current: "0.1.0", available: null, installMode: "manual", manualReason: "homebrew", checkedAt: "t" })).toMatchObject({ installMode: "manual", manualReason: "homebrew" });
    expect(decodeUpdateInfo({ installMode: "in_app", manualReason: "homebrew" }).manualReason).toBeUndefined();
    expect(decodeUpdateInfo({ installMode: "manual", manualReason: "portable" }).manualReason).toBe("portable"); // ADR-0021 §2
    expect(decodeUpdateInfo({ installMode: "manual", manualReason: "snap" }).manualReason).toBeUndefined();
    expect(decodeUpdateInfo(null)).toEqual({ current: "", available: null, installMode: "manual", checkedAt: "" });
  });

  it("L-39 (F2): the verified floor refuses a later downgrade offer from check and install, audited update.refused", async () => {
    const m = new MockTransport();
    m.updateRateWindowMs = 0;
    expect((await m.updateSettingsGet()).lastVerified).toBeNull();
    expect(await code(m.updateInstall({ version: "0.2.0" }))).toBe("ok");
    expect((await m.updateSettingsGet()).lastVerified).toBe("0.2.0");
    m.updateOffer = { ...MOCK_UPDATE_OFFER, version: "0.1.5" };
    expect(await code(m.updateCheck())).toBe("update.downgrade");
    expect(await code(m.updateInstall({ version: "0.1.5" }))).toBe("update.downgrade");
    expect(m.audit.filter((e) => e.event === "update.refused" && e.details.code === "update.downgrade")).toHaveLength(2);
    expect(m.audit.filter((e) => e.event === "update.check")).toHaveLength(0);
    // The floor is monotonic: a higher offer raises it, a failed write after verification still raises it.
    m.updateOffer = { ...MOCK_UPDATE_OFFER, version: "0.3.0" };
    m.updateInstallFails = "update.install_failed";
    expect(await code(m.updateInstall({ version: "0.3.0" }))).toBe("update.install_failed");
    expect((await m.updateSettingsGet()).lastVerified).toBe("0.3.0");
    m.updateOffer = { ...MOCK_UPDATE_OFFER, version: "0.4.0" };
    m.updateInstallFails = "update.signature";
    expect(await code(m.updateInstall({ version: "0.4.0" }))).toBe("update.signature");
    expect((await m.updateSettingsGet()).lastVerified).toBe("0.3.0"); // an unverified package never moves it
    expect(await m.updateSettingsSet({ backgroundCheck: true })).toMatchObject({ lastVerified: "0.3.0" });
  });

  it("semverBelow orders releases and pre-releases", () => {
    expect(semverBelow("0.1.5", "0.2.0")).toBe(true);
    expect(semverBelow("0.2.0", "0.2.0")).toBe(false);
    expect(semverBelow("1.0.0", "0.9.9")).toBe(false);
    expect(semverBelow("0.2.0-rc.1", "0.2.0")).toBe(true);
    expect(semverBelow("0.2.0", "0.2.0-rc.1")).toBe(false);
    expect(semverBelow("0.2.0+build.3", "0.2.0")).toBe(false);
  });

  it("decodeUpdateSettings normalises lastVerified (string, empty, absent, wrong type)", () => {
    expect(decodeUpdateSettings({ backgroundCheck: true, channel: "stable", lastCheck: "t", lastVerified: "0.2.0" })).toEqual({ backgroundCheck: true, channel: "stable", lastCheck: "t", lastVerified: "0.2.0" });
    expect(decodeUpdateSettings({ backgroundCheck: false, lastCheck: null, lastVerified: null })).toEqual({ backgroundCheck: false, channel: "stable", lastCheck: null, lastVerified: null });
    expect(decodeUpdateSettings({ lastVerified: "" }).lastVerified).toBeNull();
    expect(decodeUpdateSettings({ lastVerified: 3 }).lastVerified).toBeNull();
    expect(decodeUpdateSettings(null)).toEqual({ backgroundCheck: false, channel: "stable", lastCheck: null, lastVerified: null });
  });

  it("ADR-0021: a portable build reports its data folder, refuses the background opt-in and still checks on demand", async () => {
    const m = new MockTransport();
    expect((await m.appInfo()).portableDataDir).toBeNull();
    m.portableDataDir = "/media/stick/Mooring Data";
    m.updateMode = { installMode: "manual", manualReason: "portable" };
    expect((await m.appInfo()).portableDataDir).toBe("/media/stick/Mooring Data");
    await expect(m.updateSettingsSet({ backgroundCheck: true })).rejects.toMatchObject({ code: "update.manual_only", message: PORTABLE_MANUAL_TEXT });
    expect(m.audit.at(-1)).toMatchObject({ event: "update.refused", details: { code: "update.manual_only" } });
    expect((await m.updateSettingsGet()).backgroundCheck).toBe(false);
    expect((await m.updateSettingsSet({ backgroundCheck: false })).backgroundCheck).toBe(false);
    expect(await m.updateCheck()).toMatchObject({ installMode: "manual", manualReason: "portable" });
  });
});
