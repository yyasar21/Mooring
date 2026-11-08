// DTOs of the ADR-0018 §3 in-app updater as rust-core U0 serves them (`docs/handoff/a4-rust-core-u0.md`).
// Nothing here carries a URL, a signature or bytes: the renderer only ever names a version.

/** `in_app` = the plugin can replace the bundle without elevation; `manual` = release page + package manager. */
export type UpdateInstallMode = "in_app" | "manual";
/** Why an install is manual (`update_check.manualReason`, only with `installMode: "manual"`). */
/** `dev_build` (ADR-0028): Mooring Dev; updates come from your own builds. */
export type UpdateManualReason = "package_manager" | "homebrew" | "not_writable" | "not_bundled" | "portable" | "dev_build" | "winget";

export interface UpdateAvailable {
  version: string;
  /** RFC 3339, when the manifest carries one. */
  date: string | null;
  /** Plain text, sanitised by Rust (controls, ANSI, bidi stripped; ≤ 4 KiB). Rendered as text only. */
  notes: string;
  /** Bytes of the bundle, when the manifest carries a size. */
  size: number | null;
}

export interface UpdateInfo {
  /** The running semver. */
  current: string;
  available: UpdateAvailable | null;
  installMode: UpdateInstallMode;
  manualReason?: UpdateManualReason;
  /** RFC 3339. */
  checkedAt: string;
}

export interface UpdateSettings {
  backgroundCheck: boolean;
  channel: "stable";
  /** RFC 3339 of the last network check (manual or background), null = never. */
  lastCheck: string | null;
  /**
   * Review 7 L-39 (F2): the semver of the highest package this install verified; an offer below
   * it is refused with `update.downgrade` by check and install. Null until the first verified install.
   */
  lastVerified: string | null;
}

export type UpdateAvailableHandler = (info: UpdateInfo) => void;

export interface UpdateIpc {
  /** Manual check: `update.rate_limited` within 60 s of the previous network check, `update.busy` while one runs. */
  updateCheck(): Promise<UpdateInfo>;
  /** Re-checks in Rust, verifies the signature and restarts; refuses with open sessions unless `closeSessions`. */
  updateInstall(args: { version: string; closeSessions?: boolean }): Promise<void>;
  /** Not polled: read once per mount (vault-gated, not in `ipc-passive.json`). */
  updateSettingsGet(): Promise<UpdateSettings>;
  updateSettingsSet(args: { backgroundCheck: boolean; channel?: "stable" }): Promise<UpdateSettings>;
  /** `update:available` event: the background check found something newer (never downloads). Returns unsubscribe. */
  onUpdateAvailable(handler: UpdateAvailableHandler): () => void;
}
