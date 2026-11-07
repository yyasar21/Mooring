// Mock ADR-0022 biometric unlock and ADR-0023 `age` backups as rust-core R2 serves them. No OS
// prompt and no file: the outcome of the "system prompt" and the picked file are knobs. Nothing
// here stores a password; the mock only compares what the test set up.
/* eslint-disable @typescript-eslint/require-await */
import type {
  BiometricPlatform,
  BiometricReason,
  BiometricStatus,
  BiometricSuspendedReason,
  ImportInspect,
  ImportResult,
  A5Ipc,
} from "./ipc.types";
import { REPLACE_CONFIRM } from "./ipc.types.a5";
import { IpcError } from "./ipc.error";
import { MockImportBase } from "./ipc.mock.import";
import { MOCK_VAULT_ID } from "./ipc.mock.sync";

/** The passphrase the demo backup file was "encrypted" with. */
export const MOCK_BACKUP_PASSPHRASE = "a long backup passphrase";
/** The master password of the "other" vault a foreign demo backup came from. */
export const MOCK_SOURCE_PASSWORD = "the other vault password";

/** The backup file the next `vault_import_pick` "chooses". */
export interface MockBackupFile {
  name: string;
  bytes: number;
  /** Made by another vault: the import needs that vault's master password. */
  foreign: boolean;
  passphrase: string;
  /** 1 = an ADR-0023 v1 file (refused with `vault.import_version`). */
  version: 1 | 2;
}

export const MOCK_BACKUP_FILE: MockBackupFile = { name: "mooring-2026-11-08.age", bytes: 48_213, foreign: false, passphrase: MOCK_BACKUP_PASSPHRASE, version: 2 };

/** What the "system prompt" answers next. */
export type BiometricOutcome = "ok" | "cancelled" | "failed";

const LABEL: Record<BiometricPlatform, BiometricStatus["label"]> = { macos: "Touch ID", windows: "Windows Hello", linux: null };
const FAILURE_WINDOW_MS = 10 * 60_000;

export abstract class MockA5Base extends MockImportBase implements A5Ipc {
  bioPlatform: BiometricPlatform = "windows";
  /** Why the platform store cannot be used (null = it can). */
  bioUnavailable: Exclude<BiometricReason, "ok" | "suspended"> | null = null;
  bioEnabled = false;
  bioSuspended: BiometricSuspendedReason | null = null;
  bioOutcome: BiometricOutcome = "ok";
  private bioFailures: number[] = [];
  /** Set by `vault_create`; null = any non-empty master password is accepted. */
  masterPassword: string | null = null;
  /** The next save / open dialog answers: false = the user cancels. */
  exportPickOk = true;
  importPickOk = true;
  backupFile: MockBackupFile = { ...MOCK_BACKUP_FILE };
  /** Written exports, newest last (names and counts only). */
  exports: { name: string; counts: string }[] = [];
  private backupPicks = new Map<string, { kind: "export" | "import"; name: string; tries: number; held: ImportInspect | null }>();
  private backupSeq = 0;

  protected checkMaster(password: string): void {
    if (password.length === 0 || (this.masterPassword !== null && password !== this.masterPassword)) {
      throw new IpcError("vault.unlock", "wrong password");
    }
  }

  /** ADR-0022 auto-disable: the OS item is deleted at once and the reason is kept for Settings. */
  protected suspendBiometric(reason: BiometricSuspendedReason): void {
    if (!this.bioEnabled) return;
    this.bioEnabled = false;
    this.bioSuspended = reason;
    this.bioFailures = [];
    this.record("vault.biometric_suspended", { reason });
  }

  protected override lockBackend(): void {
    super.lockBackend();
    this.backupPicks.clear();
  }

  private bioStatus(): BiometricStatus {
    const reason: BiometricReason = this.bioUnavailable ?? (this.bioSuspended ? "suspended" : "ok");
    return {
      available: this.bioUnavailable === null,
      enabled: this.bioEnabled,
      platform: this.bioPlatform,
      label: LABEL[this.bioPlatform],
      reason,
      suspendedReason: this.bioSuspended,
    };
  }

  private bioAvailable(): void {
    if (this.bioUnavailable !== null) throw new IpcError("biometric.unavailable", `biometric unlock is not available: ${this.bioUnavailable}`);
  }

  /** The OS prompt "ran"; a cancel or failure counts towards the 3-in-10-minutes rule. */
  private prompt(): void {
    const outcome = this.bioOutcome;
    if (outcome === "ok") {
      this.bioFailures = [];
      return;
    }
    const now = Date.now();
    this.bioFailures = [...this.bioFailures.filter((t) => now - t < FAILURE_WINDOW_MS), now];
    this.record("vault.biometric_failed", { reason: outcome });
    if (this.bioFailures.length >= 3) {
      this.suspendBiometric("failed_attempts");
      throw new IpcError("biometric.suspended", "biometric unlock was turned off after repeated failures");
    }
    throw outcome === "cancelled"
      ? new IpcError("biometric.cancelled", "the system prompt was cancelled")
      : new IpcError("biometric.failed", "the system prompt did not verify");
  }

  biometricStatus: A5Ipc["biometricStatus"] = () => Promise.resolve(this.bioStatus());

  biometricEnroll: A5Ipc["biometricEnroll"] = async ({ password }) => {
    await this.unlocked();
    this.checkMaster(password);
    this.bioAvailable();
    if (this.syncState.config !== null) throw new IpcError("biometric.sync_enabled", "biometric unlock is not available while sync is configured");
    if (this.bioOutcome === "cancelled") throw new IpcError("biometric.cancelled", "the system prompt was cancelled");
    if (this.bioOutcome === "failed") throw new IpcError("biometric.failed", "the system prompt did not verify");
    this.bioEnabled = true;
    this.bioSuspended = null;
    this.bioFailures = [];
    this.record("vault.biometric_enabled", { platform: this.bioPlatform });
    return this.bioStatus();
  };

  biometricUnlock: A5Ipc["biometricUnlock"] = async () => {
    this.bioAvailable();
    if (this.bioSuspended) throw new IpcError("biometric.suspended", "biometric unlock is suspended");
    if (!this.bioEnabled) throw new IpcError("biometric.not_enrolled", "biometric unlock is not set up");
    if (this.vault === "unlocked") return "unlocked";
    this.prompt();
    this.vault = "unlocked";
    this.record("vault.unlock_biometric", {});
    return "unlocked";
  };

  biometricDisable: A5Ipc["biometricDisable"] = async ({ password }) => {
    this.checkMaster(password);
    const was = this.bioEnabled || this.bioSuspended !== null;
    this.bioEnabled = false;
    this.bioSuspended = null;
    if (was) this.record("vault.biometric_disabled", {});
    return this.bioStatus();
  };

  // ---------- ADR-0023 export / import ----------

  private backupPickId(): string {
    this.backupSeq += 1;
    return `bk-${this.backupSeq.toString(16).padStart(4, "0")}`;
  }

  private backupPick(pickId: string, kind: "export" | "import") {
    const p = this.backupPicks.get(pickId);
    if (!p || p.kind !== kind) throw new IpcError("input.invalid", "invalid pick");
    return p;
  }

  vaultExportPick: A5Ipc["vaultExportPick"] = async () => {
    await this.unlocked();
    if (!this.exportPickOk) return null;
    const pickId = this.backupPickId();
    const name = "mooring-backup.age";
    this.backupPicks.set(pickId, { kind: "export", name, tries: 0, held: null });
    return { pickId, name };
  };

  vaultExportAge: A5Ipc["vaultExportAge"] = async ({ pickId, password, exportPassphrase }) => {
    await this.unlocked();
    const pick = this.backupPick(pickId, "export");
    this.checkMaster(password);
    if (exportPassphrase.length < 12 || exportPassphrase === password) {
      throw new IpcError("vault.export_passphrase", "the export passphrase must be at least 12 characters and differ from the master password");
    }
    this.backupPicks.delete(pickId);
    const counts = { folders: this.folders.length, connections: this.connections.length, credentials: this.credentialRows().length };
    const bytes = 2_048 + counts.connections * 512 + counts.credentials * 640;
    this.exports.push({ name: pick.name, counts: JSON.stringify(counts) });
    this.record("vault.exported", { counts: JSON.stringify(counts) });
    return { bytes, ...counts };
  };

  vaultImportPick: A5Ipc["vaultImportPick"] = async () => {
    await this.unlocked();
    if (!this.importPickOk) return null;
    if (this.backupFile.bytes > 64 * 1024 * 1024) throw new IpcError("vault.import_too_large", "the file is larger than 64 MiB");
    const pickId = this.backupPickId();
    this.backupPicks.set(pickId, { kind: "import", name: this.backupFile.name, tries: 0, held: null });
    return { pickId, name: this.backupFile.name, bytes: this.backupFile.bytes };
  };

  vaultImportInspect: A5Ipc["vaultImportInspect"] = async ({ pickId, exportPassphrase }) => {
    await this.unlocked();
    const pick = this.backupPick(pickId, "import");
    const f = this.backupFile;
    if (exportPassphrase !== f.passphrase) {
      pick.tries += 1;
      if (pick.tries >= 3) this.backupPicks.delete(pickId);
      this.record("vault.import_refused", { code: "vault.import_passphrase" });
      throw new IpcError("vault.import_passphrase", "the passphrase does not open this file");
    }
    if (f.version === 1) {
      this.backupPicks.delete(pickId);
      throw new IpcError("vault.import_version", "version 1 backups cannot be imported");
    }
    pick.held = {
      vaultId: f.foreign ? "0d9e8f7a-6b5c-4d3e-8f1a-2b3c4d5e6f70" : MOCK_VAULT_ID,
      sameVault: !f.foreign,
      exportedAt: "2026-11-07T18:30:00Z",
      appVersion: "0.1.2",
      counts: { folders: 6, connections: 11, credentials: 9, trust: 3 },
      needsSourcePassword: f.foreign,
    };
    return structuredClone(pick.held);
  };

  vaultImportAge: A5Ipc["vaultImportAge"] = async ({ pickId, password, sourcePassword, mode, confirm }) => {
    await this.unlocked();
    const pick = this.backupPick(pickId, "import");
    const held = pick.held;
    if (!held) throw new IpcError("input.invalid", "invalid pick");
    this.checkMaster(password);
    if ((mode as string) !== "merge" && (mode as string) !== "replace") throw new IpcError("input.invalid", "invalid mode");
    if (mode === "replace" && confirm !== REPLACE_CONFIRM) throw new IpcError("input.invalid", "invalid confirm");
    if (held.needsSourcePassword && sourcePassword !== MOCK_SOURCE_PASSWORD) {
      this.record("vault.import_refused", { code: "vault.import_source_password" });
      throw new IpcError("vault.import_source_password", "the source master password is wrong");
    }
    this.backupPicks.delete(pickId); // single use
    const c = held.counts;
    const result: ImportResult = mode === "replace"
      ? { mode, added: c.folders + c.connections + c.credentials, updated: 0, conflicts: [], skipped: 0 }
      : {
          mode,
          added: 4,
          updated: 2,
          conflicts: [
            { kind: "connection", id: "c-web01-imported", name: "web01 (imported 2026-11-08)", resolution: "kept_both" },
            { kind: "folder", id: "f-prod", name: "Production", resolution: "last_writer_wins" },
          ],
          skipped: 0,
        };
    if (mode === "replace" && held.needsSourcePassword) this.suspendBiometric("vault_rotated");
    this.record("vault.import", { mode, foreign: String(held.needsSourcePassword), counts: JSON.stringify(c) });
    return result;
  };
}
