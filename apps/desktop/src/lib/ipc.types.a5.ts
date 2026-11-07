// DTOs of the A5 Rust features as rust-core serves them: jump-host chains (ADR-0025,
// `docs/handoff/a5-rust-core-r1.md`), biometric unlock and `age` backups (ADR-0022/0023,
// `a5-rust-core-r2.md`) and the build channel (ADR-0028, `a5-rust-core-0028.md`).
// Nothing here carries a secret outward: passwords and passphrases only travel inward.

/** ADR-0025: at most this many jump hosts before the target. */
export const MAX_VIA = 3;

/** One hop of a chain while it comes up (`hop_status` on the session channel). */
export type HopState = "connecting" | "authenticating" | "up" | "failed";
export const HOP_STATES: readonly HopState[] = ["connecting", "authenticating", "up", "failed"];

export interface HopStatus {
  /** 0-based, in chain order (first hop first). */
  hop: number;
  of: number;
  state: HopState;
  /** `host:port` of the hop. */
  host: string;
  peerIdentity: string | null;
}

// ---------- ADR-0022 biometric unlock ----------

export type BiometricPlatform = "macos" | "windows" | "linux";
export type BiometricReason = "ok" | "no_acl" | "unsigned_build" | "keychain_unavailable" | "not_enrolled" | "suspended";
export type BiometricSuspendedReason = "failed_attempts" | "password_changed" | "biometry_changed" | "vault_rotated";

export interface BiometricStatus {
  available: boolean;
  enabled: boolean;
  platform: BiometricPlatform;
  label: "Touch ID" | "Windows Hello" | null;
  reason: BiometricReason;
  suspendedReason: BiometricSuspendedReason | null;
}

// ---------- ADR-0023 backups ----------

export interface BackupPick {
  pickId: string;
  /** File name only (no directory). */
  name: string;
}

export interface ImportPickResult extends BackupPick {
  bytes: number;
}

export interface ExportResult {
  bytes: number;
  credentials: number;
  connections: number;
  folders: number;
}

export interface ImportInspect {
  vaultId: string;
  sameVault: boolean;
  /** RFC 3339. */
  exportedAt: string;
  appVersion: string;
  counts: { folders: number; connections: number; credentials: number; trust: number };
  /** A foreign vault: its master password is needed to reseal the secrets under ours. */
  needsSourcePassword: boolean;
}

export type ImportMode = "merge" | "replace";
/** The word `vault_import_age` needs as `confirm` for `replace`. */
export const REPLACE_CONFIRM = "REPLACE";

export type ImportConflictResolution = "kept_both" | "last_writer_wins" | "kept_edit";

export interface ImportConflict {
  kind: "folder" | "connection" | "credential";
  id: string;
  name: string;
  resolution: ImportConflictResolution;
}

export interface ImportResult {
  mode: ImportMode;
  added: number;
  updated: number;
  conflicts: ImportConflict[];
  skipped: number;
}

// ---------- ADR-0028 build channel ----------

export type BuildChannel = "release" | "dev";

export interface A5Ipc {
  /** Passive; works while locked. */
  biometricStatus(): Promise<BiometricStatus>;
  /** Vault unlocked; shows the OS prompt. */
  biometricEnroll(args: { password: string }): Promise<BiometricStatus>;
  /** Vault locked; shows the OS prompt. No secret crosses. */
  biometricUnlock(): Promise<"unlocked">;
  biometricDisable(args: { password: string }): Promise<BiometricStatus>;

  /** Native save dialog run by Rust; null = cancelled. */
  vaultExportPick(): Promise<BackupPick | null>;
  vaultExportAge(args: { pickId: string; password: string; exportPassphrase: string }): Promise<ExportResult>;
  /** Native open dialog run by Rust; null = cancelled. */
  vaultImportPick(): Promise<ImportPickResult | null>;
  vaultImportInspect(args: { pickId: string; exportPassphrase: string }): Promise<ImportInspect>;
  vaultImportAge(args: {
    pickId: string;
    password: string;
    sourcePassword: string | null;
    mode: ImportMode;
    confirm: string | null;
  }): Promise<ImportResult>;
}
