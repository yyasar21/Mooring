import { useCallback, useEffect, useState } from "react";
import { ipc, type KnownCert, type KnownCertProtocol } from "../../lib/ipc";
import { hostKey, plainHost } from "../../lib/hostHash";
import { describeError } from "../../stores/errors";
import { useTree } from "../../stores/tree";

/** `rdg` (ADR-0027): RD Gateway pins, listed hashed until Rust names them from connection options. */
export type CertProtocol = KnownCertProtocol;
export const DEFAULT_PORT: Record<CertProtocol, number> = { rdp: 3389, vnc: 5900, rdg: 443 };
/** What the card calls each store. */
export const STORE_LABEL: Record<CertProtocol, string> = { rdp: "RDP", vnc: "VNC", rdg: "RD Gateway" };

/** One stored pin, labelled with the connections whose host:port it belongs to (if any). */
export interface PinRow extends KnownCert {
  /** host:port when known (Rust matched a connection, or a hand-written plain line). */
  target: { host: string; port: number } | null;
  connections: string[];
  /**
   * Another pin of the same host:port carries a different fingerprint (review 6b L-35, after a
   * sync merge). Rust refuses to connect until the user removes them; `known_certs_remove`
   * clears every pin of the host:port.
   */
  conflict: boolean;
}

/**
 * Flag conflicts and group the rows: conflicting hosts first, pins of one host:port adjacent, the
 * wire order kept otherwise. Pins without a known host cannot be compared (their hashes carry
 * different salts) and are never flagged.
 */
export function groupPins(rows: Omit<PinRow, "conflict">[]): PinRow[] {
  const fps = new Map<string, Set<string>>();
  for (const r of rows) {
    if (!r.target) continue;
    const k = hostKey(r.target.host, r.target.port);
    fps.set(k, new Set([...(fps.get(k) ?? []), r.fingerprint]));
  }
  const keyOf = (r: Omit<PinRow, "conflict">) => (r.target ? hostKey(r.target.host, r.target.port) : null);
  const flagged = rows.map((r) => ({ ...r, conflict: (fps.get(keyOf(r) ?? "")?.size ?? 0) > 1 }));
  const order = new Map<string, number>();
  for (const r of flagged) {
    const k = keyOf(r);
    if (k !== null && !order.has(k)) order.set(k, order.size);
  }
  const rank = (r: PinRow) => {
    const k = keyOf(r);
    return (r.conflict ? 0 : 1) * 1_000_000 + (k === null ? order.size : (order.get(k) ?? 0));
  };
  return flagged.map((r, i) => ({ r, i })).sort((a, b) => rank(a.r) - rank(b.r) || a.i - b.i).map(({ r }) => r);
}

/**
 * `known_certs_list` for one protocol. Rust fills `host`/`port` for every pin whose salted hash
 * matches one of this protocol's connections (review 5, N-33): the UI only maps that `host:port`
 * back to connection names and never recomputes an HMAC.
 */
export function useKnownCerts(protocol: CertProtocol) {
  const connections = useTree((s) => s.connections);
  const [rows, setRows] = useState<PinRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [gen, setGen] = useState(0);
  const reload = useCallback(() => { setGen((g) => g + 1); }, []);

  useEffect(() => {
    const run = { live: true };
    setRows(null);
    setError(null);
    const names = new Map<string, string[]>();
    for (const c of connections) {
      if (c.protocol !== protocol) continue;
      const k = hostKey(c.host, c.port ?? DEFAULT_PORT[protocol]);
      names.set(k, [...(names.get(k) ?? []), c.name]);
    }
    void (async () => {
      try {
        const pins = await ipc.knownCertsList({ protocol });
        const out = pins.map((p) => {
          const target = p.host !== undefined && p.port !== undefined ? { host: p.host, port: p.port } : plainHost(p.hostHash);
          return { ...p, target, connections: target ? (names.get(hostKey(target.host, target.port)) ?? []) : [] };
        });
        if (run.live) setRows(groupPins(out));
      } catch (e: unknown) {
        if (run.live) {
          setRows([]);
          setError(describeError(e));
        }
      }
    })();
    return () => { run.live = false; };
  }, [protocol, connections, gen]);

  return { rows, error, reload };
}

/** Case-insensitive filter over connection names, host:port, fingerprint and date. */
export function filterPins(rows: PinRow[], query: string): PinRow[] {
  const q = query.trim().toLowerCase();
  if (q === "") return rows;
  return rows.filter((r) => {
    const hay = [...r.connections, r.target ? `${r.target.host}:${String(r.target.port)}` : "", r.fingerprint, r.addedAt].join(" ").toLowerCase();
    return hay.includes(q) || hay.replace(/:/g, "").includes(q.replace(/:/g, ""));
  });
}
