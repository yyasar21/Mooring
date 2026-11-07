import { create } from "zustand";
import {
  ipc,
  isIpcError,
  isOtpSettings,
  type CredentialCreate,
  type CredentialFields,
  type CredentialKind,
  type CredentialMeta,
  type KindSchema,
} from "../lib/ipc";
import { errorText } from "./errors";

/** Clipboard deadline key: `${credentialId}:${secretName}` (secretName "otp" for codes). */
export const copyKey = (id: string, name: string) => `${id}:${name}`;

export interface OtpCopy {
  /** Epoch ms when the code Rust copied stops being valid. */
  validUntil: number;
  periodMs: number;
}

interface CredentialState {
  items: CredentialMeta[];
  kinds: KindSchema[];
  error: string | null;
  /** The IpcError code behind `error` (a form offers a fix for some, e.g. `credential.use_sk_kind`). */
  errorCode: string | null;
  /** copyKey -> epoch ms when Rust clears the clipboard. The UI never touches the clipboard. */
  copiedUntil: Record<string, number>;
  /** credential id -> the window of the TOTP code Rust last copied. */
  otp: Record<string, OtpCopy>;

  load: () => Promise<void>;
  reset: () => void;
  create: (input: CredentialCreate) => Promise<CredentialMeta | null>;
  updateFields: (id: string, name: string, fields: CredentialFields) => Promise<boolean>;
  replaceSecrets: (id: string, set: Record<string, string>, clear: string[]) => Promise<boolean>;
  remove: (id: string) => Promise<boolean>;
  copySecret: (id: string, name: string, now?: number) => Promise<boolean>;
  copyOtp: (id: string, now?: number) => Promise<boolean>;
  expireCopies: (now?: number) => void;
}

const EMPTY = { items: [], error: null, errorCode: null, copiedUntil: {}, otp: {} };

export const useCredentials = create<CredentialState>((set, get) => {
  async function attempt<T>(fn: () => Promise<T>): Promise<T | null> {
    try {
      const out = await fn();
      set({ error: null, errorCode: null });
      return out;
    } catch (e: unknown) {
      set({ error: errorText(e), errorCode: isIpcError(e) ? e.code : null });
      return null;
    }
  }

  /** Re-read one credential's metadata after a secret change (secretNames / fingerprint move). */
  async function refresh(): Promise<void> {
    const items = await ipc.credentialList();
    set({ items });
  }

  return {
    ...EMPTY,
    kinds: [],

    load: async () => {
      await attempt(async () => {
        const [items, kinds] = await Promise.all([
          ipc.credentialList(),
          get().kinds.length ? Promise.resolve(get().kinds) : ipc.credentialKinds(),
        ]);
        set({ items, kinds });
      });
    },

    // The kind table is not vault data; keep it across lock so forms do not flash empty.
    reset: () => { set({ ...EMPTY }); },

    create: async (input) => {
      const meta = await attempt(() => ipc.credentialCreate(input));
      if (meta) set({ items: [...get().items, meta] });
      return meta;
    },

    updateFields: async (id, name, fields) => {
      const meta = await attempt(() => ipc.credentialUpdateFields({ id, name, fields }));
      if (meta) set({ items: get().items.map((c) => (c.id === id ? meta : c)) });
      return meta !== null;
    },

    replaceSecrets: async (id, setSecrets, clear) => {
      if (Object.keys(setSecrets).length === 0 && clear.length === 0) return true;
      return (
        (await attempt(async () => {
          await ipc.credentialReplaceSecrets({ id, set: setSecrets, clear });
          await refresh();
          return true;
        })) === true
      );
    },

    remove: async (id) => {
      const ok = (await attempt(async () => { await ipc.credentialDelete({ id }); return true; })) === true;
      if (ok) {
        const copiedUntil = Object.fromEntries(Object.entries(get().copiedUntil).filter(([k]) => !k.startsWith(`${id}:`)));
        const otp = Object.fromEntries(Object.entries(get().otp).filter(([k]) => k !== id));
        set({ items: get().items.filter((c) => c.id !== id), copiedUntil, otp });
      }
      return ok;
    },

    copySecret: async (id, name, now = Date.now()) => {
      const r = await attempt(() => ipc.credentialCopySecret({ id, name }));
      if (r) set({ copiedUntil: { ...get().copiedUntil, [copyKey(id, name)]: now + r.clearsInMs } });
      return r !== null;
    },

    copyOtp: async (id, now = Date.now()) => {
      const r = await attempt(() => ipc.credentialCopyOtp({ id }));
      if (!r) return false;
      const cred = get().items.find((c) => c.id === id);
      const o = cred?.fields.otp;
      const periodMs = (isOtpSettings(o) ? o.period : 30) * 1000;
      set({
        copiedUntil: { ...get().copiedUntil, [copyKey(id, "otp")]: now + r.clearsInMs },
        otp: { ...get().otp, [id]: { validUntil: now + r.validForMs, periodMs } },
      });
      return true;
    },

    expireCopies: (now = Date.now()) => {
      const cur = get().copiedUntil;
      const next = Object.fromEntries(Object.entries(cur).filter(([, until]) => until > now));
      const otpCur = get().otp;
      const otp = Object.fromEntries(Object.entries(otpCur).filter(([, o]) => o.validUntil > now));
      if (Object.keys(next).length !== Object.keys(cur).length || Object.keys(otp).length !== Object.keys(otpCur).length) {
        set({ copiedUntil: next, otp });
      }
    },
  };
});

/** Label for a kind, from the served schema; falls back to the wire name. */
export function kindLabel(kinds: KindSchema[], kind: CredentialKind): string {
  return kinds.find((k) => k.kind === kind)?.label ?? kind;
}
