// ADR-0025 picker rules for the connection form's "Connect via" list. Rust re-checks everything
// (`connection.via_invalid`); these only keep the form from offering a choice it would refuse.
import type { ConnectionSummary, Protocol } from "./ipc.types";
import { MAX_VIA } from "./ipc.types.a5";

/** Protocols that can open through a chain today (web waits for R6; vCenter is refused). */
export function supportsVia(p: Protocol): boolean {
  return p === "ssh" || p === "rdp" || p === "vnc" || p === "kubernetes";
}

/**
 * SSH connections that may be added as the next hop: not this connection, not already in the
 * list, and not one whose own chain goes through this connection (that would loop).
 */
export function viaCandidates(connections: readonly ConnectionSummary[], selfId: string | null, via: readonly string[]): ConnectionSummary[] {
  if (via.length >= MAX_VIA) return [];
  return connections
    .filter((c) => c.protocol === "ssh" && c.id !== selfId && !via.includes(c.id) && !(selfId !== null && (c.via ?? []).includes(selfId)))
    .sort((a, b) => a.name.localeCompare(b.name));
}

/** `you → bastion01 → bastion02 → target` (unknown hop ids read as "missing jump host"). */
export function chainText(connections: readonly ConnectionSummary[], via: readonly string[], target: string): string {
  const names = via.map((id) => connections.find((c) => c.id === id)?.name ?? "missing jump host");
  return ["you", ...names, target || "this connection"].join(" → ");
}

/** Move `list[i]` by `delta` places, clamped; returns a new array. */
export function moveItem<T>(list: readonly T[], i: number, delta: number): T[] {
  const j = Math.max(0, Math.min(list.length - 1, i + delta));
  const out = [...list];
  const [item] = out.splice(i, 1);
  if (item !== undefined) out.splice(j, 0, item);
  return out;
}
