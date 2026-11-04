import { create } from "zustand";
import { ipc, type Protocol, type ProtocolOptions } from "../lib/ipc";
import { hasOptions, normalizeOptions } from "../lib/validate.options";
import { useTree } from "./tree";

/**
 * Per-connection protocol options, loaded with `connection_options_get`. `tree_list` rows do not
 * carry them (ADR-0011: the options travel on their own commands), so every reader of an option
 * (initial view-only, clipboard policy) goes through this cache. No secret lives in options.
 */
interface ConnOptionsState {
  byId: Record<string, ProtocolOptions>;
  /** Load (or reload) one connection's options; null when the protocol has none or the call fails. */
  load: (connectionId: string) => Promise<ProtocolOptions | null>;
  /** Save through `connection_options_set`; the stored (defaults filled) value is cached. Throws IpcError. */
  save: (connectionId: string, protocol: Protocol, options: ProtocolOptions) => Promise<ProtocolOptions>;
  reset: () => void;
}

const protocolOf = (id: string): Protocol | null => useTree.getState().connections.find((c) => c.id === id)?.protocol ?? null;

export const useConnOptions = create<ConnOptionsState>((set, get) => ({
  byId: {},
  load: async (connectionId) => {
    const p = protocolOf(connectionId);
    if (!p || !hasOptions(p)) return null;
    try {
      const o = normalizeOptions(p, await ipc.connectionOptionsGet({ connectionId }));
      set({ byId: { ...get().byId, [connectionId]: o } });
      return o;
    } catch {
      return null;
    }
  },
  save: async (connectionId, protocol, options) => {
    const stored = normalizeOptions(protocol, await ipc.connectionOptionsSet({ connectionId, options }));
    set({ byId: { ...get().byId, [connectionId]: stored } });
    return stored;
  },
  reset: () => { set({ byId: {} }); },
}));

/** Cached options, else what a backend with options on the tree row sent (mock seed), else undefined. */
export function optionsOf(connectionId: string): ProtocolOptions | undefined {
  return useConnOptions.getState().byId[connectionId] ?? useTree.getState().connections.find((c) => c.id === connectionId)?.options;
}
