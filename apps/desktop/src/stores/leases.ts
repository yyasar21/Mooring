// ADR-0026 §2: dynamic-secret leases per session tab, read from the `leases` field of
// `session_list` rows (passive, R3). Rust sends engine, seconds left, renewable and state, never a
// lease id. The UI keeps only those facts plus the largest TTL it has seen, to say when the next
// renewal (at two thirds of the TTL) is due.
import { create } from "zustand";
import { ipc, type LeaseInfo, type LeaseState, type SessionInfo } from "../lib/ipc";
import type { Tab } from "./sessions.types";

export const LEASE_POLL_MS = 15_000;

export interface LeaseView {
  engine: string;
  state: LeaseState | "unknown";
  renewable: boolean;
  /** `Date.now()` + seconds left when last read; null = no TTL reported. */
  expiresAt: number | null;
  /** Largest seconds-left seen since the last renewal (≈ the lease TTL). */
  ttlSeconds: number | null;
}

const STATES: readonly string[] = ["active", "renew_failed", "expired"];

/** Defensive read of one wire row: unknown shapes are dropped, never shown. */
export function decodeLease(raw: unknown): LeaseInfo | null {
  if (raw === null || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  if (typeof r.engine !== "string" || r.engine.length > 32 || typeof r.renewable !== "boolean" || typeof r.state !== "string") return null;
  const exp = r.expiresInSeconds;
  if (exp !== null && exp !== undefined && (typeof exp !== "number" || !Number.isFinite(exp) || exp < 0)) return null;
  return { engine: r.engine, renewable: r.renewable, state: r.state, expiresInSeconds: typeof exp === "number" ? exp : null };
}

/** Merge a fresh read into the previous view of the same lease (by position). */
export function nextView(prev: LeaseView | undefined, l: LeaseInfo, now: number): LeaseView {
  const left = l.expiresInSeconds;
  let ttl = left;
  if (prev && prev.engine === l.engine && left !== null && prev.ttlSeconds !== null && prev.expiresAt !== null) {
    const expectedLeft = (prev.expiresAt - now) / 1000;
    // Seconds left went up by more than polling jitter: Rust renewed it, so this is the new TTL.
    ttl = left > expectedLeft + 5 ? left : Math.max(prev.ttlSeconds, left);
  }
  return {
    engine: l.engine,
    state: STATES.includes(l.state) ? (l.state as LeaseState) : "unknown",
    renewable: l.renewable,
    expiresAt: left === null ? null : now + left * 1000,
    ttlSeconds: ttl,
  };
}

interface LeaseStore {
  /** By local tab id. Kept after the tab closes, so the tab can say the lease was revoked. */
  byTab: Record<string, LeaseView[]>;
  apply: (rows: SessionInfo[], tabs: Tab[], now?: number) => void;
  poll: (tabs: Tab[]) => Promise<void>;
  reset: () => void;
}

export const useLeases = create<LeaseStore>((set, get) => ({
  byTab: {},
  apply: (rows, tabs, now = Date.now()) => {
    const prev = get().byTab;
    const out: Record<string, LeaseView[]> = {};
    for (const t of tabs) {
      const row = t.sessionId ? rows.find((r) => r.sessionId === t.sessionId) : undefined;
      if (row) {
        const leases = (Array.isArray(row.leases) ? row.leases : []).map(decodeLease).filter((x): x is LeaseInfo => x !== null);
        if (leases.length > 0) out[t.id] = leases.map((l, i) => nextView(prev[t.id]?.[i], l, now));
      } else {
        const kept = prev[t.id];
        if (kept && t.state === "closed") out[t.id] = kept; // keep it to show "revoked"
      }
    }
    set({ byTab: out });
  },
  poll: async (tabs) => {
    try {
      get().apply(await ipc.sessionList(), tabs);
    } catch {
      // passive status read; the next poll tries again
    }
  },
  reset: () => { set({ byTab: {} }); },
}));

/** "23 min", "1 h 5 min", "under a minute". */
export function leaseDuration(seconds: number): string {
  if (seconds < 60) return "under a minute";
  const m = Math.round(seconds / 60);
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  const rest = m % 60;
  return rest === 0 ? `${h} h` : `${h} h ${rest} min`;
}

export type ChipState = LeaseState | "revoked" | "unknown";

/** The one lease the chip speaks for: the worst state, then the soonest expiry. */
export function worstLease(leases: LeaseView[]): LeaseView | null {
  const rank = (l: LeaseView) => (l.state === "expired" ? 0 : l.state === "renew_failed" ? 1 : l.state === "unknown" ? 2 : 3);
  return [...leases].sort((a, b) => rank(a) - rank(b) || (a.expiresAt ?? Infinity) - (b.expiresAt ?? Infinity))[0] ?? null;
}

/** Chip text and state for a tab's leases at `now`. */
export function leaseChip(leases: LeaseView[], tabState: Tab["state"], now: number): { state: ChipState; text: string } | null {
  const l = worstLease(leases);
  if (!l) return null;
  if (tabState === "closed") return { state: "revoked", text: "Lease revoked" };
  const left = l.expiresAt === null ? null : Math.max(0, (l.expiresAt - now) / 1000);
  if (l.state === "expired" || left === 0) return { state: "expired", text: "Lease expired" };
  if (l.state === "renew_failed") return { state: "renew_failed", text: left === null ? "Lease · renewal failed" : `Lease · renewal failed, expires in ${leaseDuration(left)}` };
  if (l.state === "unknown") return { state: "unknown", text: "Lease" };
  if (left === null) return { state: "active", text: "Lease · no expiry reported" };
  if (l.renewable && l.ttlSeconds !== null) {
    const renewsIn = left - l.ttlSeconds / 3;
    return { state: "active", text: renewsIn > 0 ? `Lease · renews in ${leaseDuration(renewsIn)}` : "Lease · renewing" };
  }
  return { state: "active", text: `Lease · expires in ${leaseDuration(left)}` };
}
