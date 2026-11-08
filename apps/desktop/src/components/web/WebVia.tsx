// ADR-0025 §3 (R6): a web window through jump hosts. The page goes through a SOCKS proxy on the
// last hop, so opening waits for the whole chain (up to 90 s). The chain opens without a human:
// a hop that asks anything (an unknown host key, a password) fails the open.
import type { ConnectionSummary } from "../../lib/ipc";
import { useTree } from "../../stores/tree";
import { hopName } from "../terminal/HopStrip";

/** Readable title and next step for the two R6 `web_open` refusals. */
export const WEB_OPEN_ERROR: Readonly<Record<string, { title: string; hint: string }>> = {
  "web.via_unsupported": {
    title: "Jump hosts are not available for web windows on macOS",
    hint: "This build cannot put a macOS web window behind a proxy. Open the jump host as an SSH session with a dynamic forward (SOCKS) and point a browser at it, or remove the jump hosts from this connection.",
  },
  "session.hop_failed": {
    title: "A jump host could not be used",
    hint: "A web window cannot answer a jump host's questions. Open the jump host once as an SSH session to trust its key, and give it a stored credential instead of asking at connect. Then reopen this window.",
  },
};

/** "bastion01 → bastion02" from the connection's own chain, else "2 jump hosts". */
export function viaNames(connections: readonly ConnectionSummary[], connection: ConnectionSummary | undefined, hops: number): string {
  if ((connection?.via?.length ?? 0) !== hops) return `${String(hops)} jump host${hops === 1 ? "" : "s"}`;
  return Array.from({ length: hops }, (_, i) => hopName(connections, connection, i)).join(" → ");
}

/** Toolbar chip of an open window that goes through jump hosts. */
export function WebViaChip({ connection, hops }: { connection: ConnectionSummary | undefined; hops: number }) {
  const connections = useTree((s) => s.connections);
  return (
    <span className="chip" title="The page goes through a SOCKS proxy on the last jump host; host names are resolved there. Certificates are checked as usual.">
      via {viaNames(connections, connection, hops)} (SOCKS)
    </span>
  );
}

/** The opening state: there is no cancel command, so it only says what is happening and how long it may take. */
export function WebOpening({ hops }: { hops: number }) {
  return (
    <div className="web-opening" role="status" aria-live="polite">
      <span className="web-spinner" aria-hidden />
      <span>
        Opening through {hops} jump host{hops === 1 ? "" : "s"}…
        <span className="web-opening-hint">Each jump host signs in first. This can take up to 90 seconds.</span>
      </span>
    </div>
  );
}

/** Title and next step of a refused open (null for other errors: the reason alone is shown). */
export function WebOpenError({ code }: { code: string | null | undefined }) {
  const e = code ? WEB_OPEN_ERROR[code] : undefined;
  if (!e) return null;
  return (
    <div className="web-open-error" role="alert">
      <span className="dropped-title">{e.title}</span>
      <span className="dropped-hint">{e.hint}</span>
    </div>
  );
}
