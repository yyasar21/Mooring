import { useCallback, useEffect, useState } from "react";
import { ipc, type KnownCert } from "../../lib/ipc";
import { hostKey, plainHost } from "../../lib/hostHash";
import { describeError } from "../../stores/errors";
import { useTree } from "../../stores/tree";

export type CertProtocol = "rdp" | "vnc";
const DEFAULT_PORT: Record<CertProtocol, number> = { rdp: 3389, vnc: 5900 };

/** One stored pin, labelled with the connections whose host:port it belongs to (if any). */
export interface PinRow extends KnownCert {
  /** host:port when known (Rust matched a connection, or a hand-written plain line). */
  target: { host: string; port: number } | null;
  connections: string[];
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
        const out: PinRow[] = pins.map((p) => {
          const target = p.host !== undefined && p.port !== undefined ? { host: p.host, port: p.port } : plainHost(p.hostHash);
          return { ...p, target, connections: target ? (names.get(hostKey(target.host, target.port)) ?? []) : [] };
        });
        if (run.live) setRows(out);
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
