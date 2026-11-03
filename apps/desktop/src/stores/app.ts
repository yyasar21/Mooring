import { create } from "zustand";
import type { ProtocolName } from "@nexus/ui";
import { inTauri, ipc, isIpcError, type AppInfo, type VaultStatus } from "../lib/ipc";

export interface Folder {
  id: string;
  parent: string | null;
  name: string;
}

export interface Connection {
  id: string;
  folder: string;
  name: string;
  protocol: ProtocolName;
  host: string;
  tags: string[];
}

export interface Tab {
  connectionId: string;
  state: "idle" | "connecting" | "connected" | "closed";
}

interface AppState {
  info: AppInfo | null;
  vault: VaultStatus | "unknown";
  lastError: string | null;
  folders: Folder[];
  connections: Connection[];
  selected: string | null;
  tabs: Tab[];
  activeTab: string | null;
  paletteOpen: boolean;

  boot: () => Promise<void>;
  createVault: (password: string) => Promise<void>;
  unlock: (password: string) => Promise<void>;
  lock: () => Promise<void>;
  select: (id: string | null) => void;
  openTab: (id: string) => void;
  closeTab: (id: string) => void;
  setActiveTab: (id: string) => void;
  setPalette: (open: boolean) => void;
}

// Phase A0 sample tree: the home lab as it will look once A1 imports it from the vault.
const SAMPLE_FOLDERS: Folder[] = [
  { id: "root", parent: null, name: "Home lab" },
  { id: "servers", parent: "root", name: "servers · VLAN 20" },
  { id: "okd", parent: "root", name: "okd · VLAN 40" },
  { id: "rke", parent: "root", name: "rke · VLAN 50" },
  { id: "mgmt", parent: "root", name: "esxi-mgmt · VLAN 100" },
];
const SAMPLE_CONNECTIONS: Connection[] = [
  { id: "c1", folder: "servers", name: "xinfra01", protocol: "ssh", host: "10.10.20.5", tags: ["dns", "haproxy"] },
  { id: "c2", folder: "servers", name: "xmon01", protocol: "ssh", host: "10.10.20.30", tags: ["prometheus"] },
  { id: "c3", folder: "servers", name: "xdc01", protocol: "rdp", host: "10.10.20.39", tags: ["ad"] },
  { id: "c4", folder: "servers", name: "xado01", protocol: "rdp", host: "10.10.20.36", tags: ["azure-devops"] },
  { id: "c5", folder: "servers", name: "grafana", protocol: "web", host: "https://grafana.homelab.xyz", tags: [] },
  { id: "c6", folder: "okd", name: "okd-master01", protocol: "ssh", host: "10.10.40.11", tags: ["control-plane"] },
  { id: "c7", folder: "okd", name: "api.okd", protocol: "kubernetes", host: "okd", tags: [] },
  { id: "c8", folder: "rke", name: "rancher", protocol: "web", host: "https://rancher.homelab.xyz", tags: [] },
  { id: "c9", folder: "mgmt", name: "vcenter", protocol: "web", host: "https://vcenter.homelab.xyz", tags: ["vcha"] },
  { id: "c10", folder: "mgmt", name: "esxi01", protocol: "vsphere-console", host: "esxi01.homelab.xyz", tags: [] },
];

function errorText(e: unknown): string {
  return isIpcError(e) ? e.message : "unexpected error";
}

export const useApp = create<AppState>((set, get) => ({
  info: null,
  vault: "unknown",
  lastError: null,
  folders: SAMPLE_FOLDERS,
  connections: SAMPLE_CONNECTIONS,
  selected: null,
  tabs: [],
  activeTab: null,
  paletteOpen: false,

  boot: async () => {
    if (!inTauri()) {
      // Browser preview (vite dev without Tauri): pretend the vault is unlocked.
      set({ info: { name: "Nexus Remote", version: "dev", os: "browser", arch: "-", debug: true }, vault: "unlocked" });
      return;
    }
    try {
      const [info, vault] = await Promise.all([ipc.appInfo(), ipc.vaultStatus()]);
      set({ info, vault, lastError: null });
    } catch (e: unknown) {
      set({ lastError: errorText(e) });
    }
  },

  createVault: async (password) => {
    try {
      set({ vault: await ipc.vaultCreate(password), lastError: null });
    } catch (e: unknown) {
      set({ lastError: errorText(e) });
    }
  },

  unlock: async (password) => {
    try {
      set({ vault: await ipc.vaultUnlock(password), lastError: null });
    } catch (e: unknown) {
      set({ lastError: errorText(e) });
    }
  },

  lock: async () => {
    if (!inTauri()) {
      set({ vault: "locked", tabs: [], activeTab: null });
      return;
    }
    try {
      set({ vault: await ipc.vaultLock("user"), tabs: [], activeTab: null, lastError: null });
    } catch (e: unknown) {
      set({ lastError: errorText(e) });
    }
  },

  select: (id) => { set({ selected: id }); },

  openTab: (id) => {
    const { tabs } = get();
    if (!tabs.some((t) => t.connectionId === id)) {
      set({ tabs: [...tabs, { connectionId: id, state: "idle" }] });
    }
    set({ activeTab: id, selected: id, paletteOpen: false });
  },

  closeTab: (id) => {
    const tabs = get().tabs.filter((t) => t.connectionId !== id);
    const active = get().activeTab === id ? (tabs.at(-1)?.connectionId ?? null) : get().activeTab;
    set({ tabs, activeTab: active });
  },

  setActiveTab: (id) => { set({ activeTab: id, selected: id }); },
  setPalette: (open) => { set({ paletteOpen: open }); },
}));
