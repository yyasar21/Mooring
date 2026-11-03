import { create } from "zustand";
import { ipc, type CredentialCreate, type CredentialMeta } from "../lib/ipc";
import { errorText } from "./errors";

interface CredentialState {
  items: CredentialMeta[];
  error: string | null;
  /** credential id -> epoch ms when Rust clears the clipboard. The UI never touches the clipboard. */
  copiedUntil: Record<string, number>;

  load: () => Promise<void>;
  reset: () => void;
  create: (input: CredentialCreate) => Promise<CredentialMeta | null>;
  updateMeta: (id: string, name: string, username: string) => Promise<boolean>;
  replaceSecret: (id: string, secret: string, secret2: string | null) => Promise<boolean>;
  remove: (id: string) => Promise<boolean>;
  copyPassword: (id: string, now?: number) => Promise<boolean>;
  expireCopies: (now?: number) => void;
}

export const useCredentials = create<CredentialState>((set, get) => ({
  items: [],
  error: null,
  copiedUntil: {},

  load: async () => {
    try {
      set({ items: await ipc.credentialList(), error: null });
    } catch (e: unknown) {
      set({ error: errorText(e) });
    }
  },

  reset: () => { set({ items: [], error: null, copiedUntil: {} }); },

  create: async (input) => {
    try {
      const meta = await ipc.credentialCreate(input);
      set({ items: [...get().items, meta], error: null });
      return meta;
    } catch (e: unknown) {
      set({ error: errorText(e) });
      return null;
    }
  },

  updateMeta: async (id, name, username) => {
    try {
      const meta = await ipc.credentialUpdateMeta({ id, name, username });
      set({ items: get().items.map((c) => (c.id === id ? meta : c)), error: null });
      return true;
    } catch (e: unknown) {
      set({ error: errorText(e) });
      return false;
    }
  },

  replaceSecret: async (id, secret, secret2) => {
    try {
      await ipc.credentialReplaceSecret({ id, secret, secret2 });
      set({ error: null });
      return true;
    } catch (e: unknown) {
      set({ error: errorText(e) });
      return false;
    }
  },

  remove: async (id) => {
    try {
      await ipc.credentialDelete({ id });
      const copiedUntil = Object.fromEntries(Object.entries(get().copiedUntil).filter(([k]) => k !== id));
      set({ items: get().items.filter((c) => c.id !== id), copiedUntil, error: null });
      return true;
    } catch (e: unknown) {
      set({ error: errorText(e) });
      return false;
    }
  },

  copyPassword: async (id, now = Date.now()) => {
    try {
      const { clearsInMs } = await ipc.credentialCopyPassword({ id });
      set({ copiedUntil: { ...get().copiedUntil, [id]: now + clearsInMs }, error: null });
      return true;
    } catch (e: unknown) {
      set({ error: errorText(e) });
      return false;
    }
  },

  expireCopies: (now = Date.now()) => {
    const cur = get().copiedUntil;
    const next = Object.fromEntries(Object.entries(cur).filter(([, until]) => until > now));
    if (Object.keys(next).length !== Object.keys(cur).length) set({ copiedUntil: next });
  },
}));

export const KIND_LABEL: Record<CredentialMeta["kind"], string> = {
  password: "Password",
  ssh_key: "SSH key",
  certificate: "Certificate",
};
