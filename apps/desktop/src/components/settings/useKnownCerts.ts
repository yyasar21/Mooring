import { useCallback, useEffect, useState } from "react";
import { ipc, type KnownCert } from "../../lib/ipc";
import { hostMatches, plainHost } from "../../lib/hostHash";
import { describeError } from "../../stores/errors";
import { useTree } from "../../stores/tree";

export type CertProtocol = "rdp" | "vnc";
const DEFAULT_PORT: Record<CertProtocol, number> = { rdp: 3389, vnc: 5900 };

/** One stored pin, labelled with the connections whose host:port it belongs to (if any). */
export interface PinRow extends KnownCert {
  /** host:port when known (a matching connection, or a hand-written plain line). */
  target: { host: string; port: number } | null;
  connections: string[];
}

/** `known_certs_list` for one protocol, with each hashed host matched against this protocol's connections. */
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
    const candidates = connections
      .filter((c) => c.protocol === protocol)
      .map((c) => ({ name: c.name, host: c.host, port: c.port ?? DEFAULT_PORT[protocol] }));
    void (async () => {
      try {
        const pins = await ipc.knownCertsList({ protocol });
        const out: PinRow[] = [];
        for (const p of pins) {
          const plain = plainHost(p.hostHash);
          const names: string[] = [];
          let target = plain;
          for (const c of candidates) {
            if (await hostMatches(p.hostHash, c.host, c.port)) {
              names.push(c.name);
              target ??= { host: c.host, port: c.port };
            }
          }
          out.push({ ...p, target, connections: names });
        }
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
