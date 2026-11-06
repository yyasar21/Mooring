// ADR-0018 §3 mock contract as rust-core U0 serves it: check (rate limit, busy, failures), the
// install matrix (manual reasons, open sessions, re-check), settings and the background event.
import { IpcError, type UpdateInfo } from "./ipc";
import { decodeUpdateInfo } from "./ipc.decode.update";
import { MockTransport } from "./ipc.mock";
import { MOCK_CURRENT_VERSION, MOCK_UPDATE_OFFER } from "./ipc.mock.update";

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
    expect(await m.updateSettingsGet()).toEqual({ backgroundCheck: false, channel: "stable", lastCheck: null });
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
    expect(decodeUpdateInfo(null)).toEqual({ current: "", available: null, installMode: "manual", checkedAt: "" });
  });
});
