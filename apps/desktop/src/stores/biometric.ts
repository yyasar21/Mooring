import { create } from "zustand";
import { ipc, type BiometricPlatform, type BiometricStatus, type BiometricSuspendedReason } from "../lib/ipc";
import { describeError } from "./errors";

/**
 * ADR-0022 biometric unlock state. `biometric_status` is passive and works while locked, so the
 * unlock screen and Settings → Security both read it; nothing here starts an OS prompt on its
 * own: enrol, disable and unlock each follow a click. The master password typed for enrol or
 * disable goes straight to Rust and is not kept.
 */
interface BiometricState {
  status: BiometricStatus | null;
  busy: boolean;
  error: string | null;
  notice: string | null;
  load: () => Promise<BiometricStatus | null>;
  enroll: (password: string) => Promise<boolean>;
  disable: (password: string) => Promise<boolean>;
  clearMessages: () => void;
}

/** "Touch ID" / "Windows Hello" / a neutral name where the platform has none. */
export function biometricName(s: Pick<BiometricStatus, "label" | "platform"> | null): string {
  if (s?.label) return s.label;
  const byPlatform: Record<BiometricPlatform, string> = { macos: "Touch ID", windows: "Windows Hello", linux: "biometrics" };
  return s ? byPlatform[s.platform] : "biometrics";
}

/** Helper text when the store cannot be used (`available: false`), keyed by `reason`. */
export function unavailableText(s: BiometricStatus): string | null {
  if (s.available) return null;
  switch (s.reason) {
    case "unsigned_build": return "Touch ID needs a signed build of Mooring. This copy is not signed, so the keychain refuses to protect the key.";
    case "no_acl": return "Not available on Linux: there is no system keychain that asks for a fingerprint before it releases a key.";
    case "keychain_unavailable": return "The system keychain is not available right now. Try again after signing in to your computer again.";
    case "not_enrolled": return `Set up ${biometricName(s)} in the system settings first.`;
    default: return `${biometricName(s)} is not available on this device.`;
  }
}

const SUSPENDED: Record<BiometricSuspendedReason, string> = {
  failed_attempts: "three failed or cancelled attempts within 10 minutes",
  password_changed: "the master password changed",
  biometry_changed: "the fingerprints or faces enrolled on this computer changed",
  vault_rotated: "the vault key changed (a synced vault was joined, or a backup from another vault replaced this one)",
};

/** "Turned off by Mooring because …" for a suspended enrolment. */
export function suspendedText(s: BiometricStatus): string | null {
  if (s.suspendedReason === null) return null;
  return `${biometricName(s)} unlock was turned off because ${SUSPENDED[s.suspendedReason]}. Turn it on again to keep using it.`;
}

export const useBiometric = create<BiometricState>((set, get) => ({
  status: null,
  busy: false,
  error: null,
  notice: null,

  load: async () => {
    try {
      const status = await ipc.biometricStatus();
      set({ status });
      return status;
    } catch {
      set({ status: null });
      return null;
    }
  },

  enroll: async (password) => {
    if (get().busy) return false;
    set({ busy: true, error: null, notice: null });
    try {
      const status = await ipc.biometricEnroll({ password });
      set({ status, notice: `${biometricName(status)} unlock is on.` });
      return true;
    } catch (e: unknown) {
      set({ error: describeError(e) });
      void get().load();
      return false;
    } finally {
      set({ busy: false });
    }
  },

  disable: async (password) => {
    if (get().busy) return false;
    set({ busy: true, error: null, notice: null });
    try {
      const status = await ipc.biometricDisable({ password });
      set({ status, notice: `${biometricName(status)} unlock is off. Mooring removed its key from the system.` });
      return true;
    } catch (e: unknown) {
      set({ error: describeError(e) });
      return false;
    } finally {
      set({ busy: false });
    }
  },

  clearMessages: () => { set({ error: null, notice: null }); },
}));
