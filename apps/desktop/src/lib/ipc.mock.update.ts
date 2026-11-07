// Mock ADR-0018 §3 updater as rust-core U0 serves it. No manifest is fetched: the offer, the
// install mode and the failure modes are knobs. Nothing here holds a URL, a signature or bytes;
// "installing" closes sessions (when asked), audits and flips `restarted`.
import type { BuildChannel, UpdateAvailable, UpdateAvailableHandler, UpdateInfo, UpdateInstallMode, UpdateIpc, UpdateManualReason, UpdateSettings } from "./ipc.types";
import { IpcError } from "./ipc.error";
import { MockSecretsBase } from "./ipc.mock.secrets";

export const MOCK_CURRENT_VERSION = "0.1.0";
/** ADR-0021 §2: the exact message Rust sends with `update.manual_only` in a portable build. */
export const PORTABLE_MANUAL_TEXT = "portable build: download the new zip and replace the folder";
/** ADR-0028: the exact message Rust sends with `update.manual_only` in a dev build. */
export const DEV_MANUAL_TEXT = "development build: updates come from your own builds";

/** The offer a fresh mock serves: one version up, dated, with notes that exercise line breaks. */
export const MOCK_UPDATE_OFFER: UpdateAvailable = {
  version: "0.2.0",
  date: "2026-11-20T09:00:00Z",
  notes: "Mooring 0.2.0\n\n- In-app updater (ADR-0018)\n- Network tools in the inspector (ADR-0020)\n- Fixes for RDP reconnects",
  size: 48_234_496,
};

/** Codes `update_check` and `update_install` can be made to fail with (network, manifest, signature). */
export type UpdateFailure = "update.network" | "update.manifest" | "update.signature" | "update.install_failed" | null;

const SEMVER = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/;

/** `a < b` on major.minor.patch; a pre-release sorts below the same release (enough for the floor). */
export function semverBelow(a: string, b: string): boolean {
  const parse = (v: string) => {
    const core = v.split("+")[0] ?? "";
    const [nums = "", pre] = core.split("-", 2);
    return { nums: nums.split(".").map(Number), pre: pre ?? null };
  };
  const x = parse(a);
  const y = parse(b);
  for (let i = 0; i < 3; i++) {
    const d = (x.nums[i] ?? 0) - (y.nums[i] ?? 0);
    if (d !== 0) return d < 0;
  }
  return x.pre !== null && y.pre === null;
}

export abstract class MockUpdateBase extends MockSecretsBase implements UpdateIpc {
  /** False = the build has no `plugins.updater.pubkey`: every command answers `update.unconfigured`. */
  updateConfigured = true;
  /** ADR-0021: a path makes the mock a portable build (`app_info.portableDataDir`; background checks refused). */
  portableDataDir: string | null = null;
  /** ADR-0028: `dev` = Mooring Dev; every update command answers `update.manual_only` (`dev_build`). */
  buildChannel: BuildChannel = "release";
  /** What the next check finds; null = up to date. */
  updateOffer: UpdateAvailable | null = structuredClone(MOCK_UPDATE_OFFER);
  updateMode: { installMode: UpdateInstallMode; manualReason?: UpdateManualReason } = { installMode: "in_app" };
  /** Makes the next check fail with this code (cleared after one use). */
  updateCheckFails: UpdateFailure = null;
  /** Makes the next install fail with this code after the re-check (cleared after one use). */
  updateInstallFails: UpdateFailure = null;
  /** Manual checks closer than this to the previous network check are `update.rate_limited`. */
  updateRateWindowMs = 60_000;
  /** Set once an install "restarted" the app (the mock never exits). */
  restarted: string | null = null;
  /** `lastVerified` is the L-39 floor (F2): set it to make the next offer a downgrade. */
  updateSettings: UpdateSettings = { backgroundCheck: false, channel: "stable", lastCheck: null, lastVerified: null };
  private updateHandlers = new Set<UpdateAvailableHandler>();
  private updateInFlight = false;
  private lastNetworkCheckMs: number | null = null;

  /** Sessions the install must close (`closeSessions`) or refuse over (`update.sessions_open`). */
  protected abstract liveSessionIds(): string[];
  protected abstract closeSessionForUpdate(sessionId: string): Promise<void>;

  /** Dev builds never register the updater (ADR-0028): check, install and turning the background check on are refused. */
  private notDev(): void {
    if (this.buildChannel !== "dev") return;
    this.record("update.refused", { code: "update.manual_only" });
    throw new IpcError("update.manual_only", DEV_MANUAL_TEXT);
  }

  private configured(): void {
    if (!this.updateConfigured) throw new IpcError("update.unconfigured", "updates are not configured in this build");
  }

  private info(now: number): UpdateInfo {
    return {
      current: MOCK_CURRENT_VERSION,
      available: this.updateOffer ? structuredClone(this.updateOffer) : null,
      installMode: this.updateMode.installMode,
      ...(this.updateMode.installMode === "manual" && this.updateMode.manualReason ? { manualReason: this.updateMode.manualReason } : {}),
      checkedAt: new Date(now).toISOString(),
    };
  }

  /** L-39: an offer below the verified floor is refused and audited `update.refused`, by check and install alike. */
  private checkFloor(offered: string): void {
    const floor = this.updateSettings.lastVerified;
    if (floor !== null && semverBelow(offered, floor)) {
      this.record("update.refused", { code: "update.downgrade" });
      throw new IpcError("update.downgrade", "the offered version is older than a release this install already verified");
    }
  }

  private async networkCheck(manual: boolean): Promise<UpdateInfo> {
    if (this.updateInFlight) throw new IpcError("update.busy", "an update check or install is already running");
    const now = Date.now();
    if (manual && this.lastNetworkCheckMs !== null && now - this.lastNetworkCheckMs < this.updateRateWindowMs) {
      const wait = Math.ceil((this.updateRateWindowMs - (now - this.lastNetworkCheckMs)) / 1000);
      throw new IpcError("update.rate_limited", `checked a moment ago; try again in ${wait} s`);
    }
    this.updateInFlight = true;
    try {
      await new Promise((r) => setTimeout(r, this.delayMs));
      this.lastNetworkCheckMs = now;
      this.updateSettings = { ...this.updateSettings, lastCheck: new Date(now).toISOString() };
      const fail = this.updateCheckFails;
      this.updateCheckFails = null;
      if (fail === "update.network") throw new IpcError("update.network", "the update server did not answer");
      if (fail === "update.manifest") throw new IpcError("update.manifest", "the update manifest could not be read");
      if (fail === "update.signature") throw new IpcError("update.signature", "the update signature did not verify");
      if (fail === "update.install_failed") throw new IpcError("update.install_failed", "the update could not be written");
      const info = this.info(now);
      if (info.available) this.checkFloor(info.available.version);
      this.record("update.check", { current: info.current, available: info.available?.version ?? "" });
      return info;
    } finally {
      this.updateInFlight = false;
    }
  }

  onUpdateAvailable(handler: UpdateAvailableHandler): () => void {
    this.updateHandlers.add(handler);
    return () => { this.updateHandlers.delete(handler); };
  }

  /** Test/dev hook: the background loop ticked (only emits when `backgroundCheck` is on and something is newer). */
  async simulateBackgroundCheck(): Promise<void> {
    if (!this.updateConfigured || !this.updateSettings.backgroundCheck || this.vault !== "unlocked") return;
    const info = await this.networkCheck(false);
    if (!info.available) return;
    for (const h of [...this.updateHandlers]) h(structuredClone(info));
  }

  updateCheck: UpdateIpc["updateCheck"] = async () => {
    await this.unlocked();
    this.notDev();
    this.configured();
    return this.networkCheck(true);
  };

  updateInstall: UpdateIpc["updateInstall"] = async ({ version, closeSessions }) => {
    await this.unlocked();
    this.notDev();
    this.configured();
    if (typeof version !== "string" || !SEMVER.test(version)) throw new IpcError("input.invalid", "invalid version");
    const refuse = (e: IpcError): never => {
      this.record("update.refused", { code: e.code });
      throw e;
    };
    if (this.updateMode.installMode === "manual") {
      if (this.updateMode.manualReason === "not_writable") refuse(new IpcError("update.not_writable", "the installed bundle is not writable by this user"));
      refuse(new IpcError("update.manual_only", "this install is managed outside Mooring"));
    }
    const live = this.liveSessionIds();
    if (live.length > 0 && !closeSessions) refuse(new IpcError("update.sessions_open", `${live.length} session(s) are open`));
    if (this.updateInFlight) throw new IpcError("update.busy", "an update check or install is already running");
    this.updateInFlight = true;
    try {
      await new Promise((r) => setTimeout(r, this.delayMs));
      const offer = this.updateOffer;
      if (!offer || offer.version !== version) return refuse(new IpcError("update.none", "that version is no longer offered"));
      this.checkFloor(offer.version);
      const fail = this.updateInstallFails;
      this.updateInstallFails = null;
      if (fail === "update.signature") refuse(new IpcError("update.signature", "the update signature did not verify"));
      // The package verified: the floor rises before anything is written (monotonic), even if the write then fails.
      const floor = this.updateSettings.lastVerified;
      if (floor === null || semverBelow(floor, offer.version)) this.updateSettings = { ...this.updateSettings, lastVerified: offer.version };
      if (fail === "update.install_failed") refuse(new IpcError("update.install_failed", "the update could not be written"));
      if (fail === "update.network") throw new IpcError("update.network", "the update server did not answer");
      if (fail === "update.manifest") throw new IpcError("update.manifest", "the update manifest could not be read");
      for (const id of live) await this.closeSessionForUpdate(id);
      this.record("update.install", { from: MOCK_CURRENT_VERSION, to: offer.version });
      this.restarted = offer.version;
    } finally {
      this.updateInFlight = false;
    }
  };

  updateSettingsGet: UpdateIpc["updateSettingsGet"] = async () => {
    await this.unlocked();
    this.configured();
    return { ...this.updateSettings };
  };

  updateSettingsSet: UpdateIpc["updateSettingsSet"] = async ({ backgroundCheck, channel }) => {
    await this.unlocked();
    this.configured();
    if (typeof backgroundCheck !== "boolean") throw new IpcError("input.invalid", "invalid backgroundCheck");
    if (channel !== undefined && (channel as string) !== "stable") throw new IpcError("input.invalid", "invalid channel");
    if (backgroundCheck) this.notDev();
    if (backgroundCheck && this.portableDataDir !== null) {
      this.record("update.refused", { code: "update.manual_only" });
      throw new IpcError("update.manual_only", PORTABLE_MANUAL_TEXT);
    }
    if (this.updateSettings.backgroundCheck !== backgroundCheck) this.record("update.settings_changed", { background_check: String(backgroundCheck) });
    this.updateSettings = { ...this.updateSettings, backgroundCheck };
    return { ...this.updateSettings };
  };
}
