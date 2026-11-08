import { useEffect, useState } from "react";
import { ENGINE_LABEL } from "../../lib/ipc";
import { isVaultEngine, roleOf } from "../../lib/validate.refs";
import { useCredentials } from "../../stores/credentials";
import { LEASE_POLL_MS, leaseChip, leaseDuration, useLeases, worstLease, type LeaseView } from "../../stores/leases";
import { useSessions, type Tab } from "../../stores/sessions";
import { useTree } from "../../stores/tree";

/** `Date.now()`, refreshed every `ms`. */
function useNow(ms: number): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = window.setInterval(() => { setNow(Date.now()); }, ms);
    return () => { window.clearInterval(id); };
  }, [ms]);
  return now;
}

/**
 * Polls `session_list` while a session is open, so lease chips follow renewals (ADR-0026 §2).
 * `session_list` is passive in Rust: the poll never keeps the vault from locking.
 */
export function LeasePoller() {
  const live = useSessions((s) => s.tabs.filter((t) => t.sessionId !== null && (t.state === "connected" || t.state === "connecting")).map((t) => t.sessionId).join(","));
  useEffect(() => {
    if (live === "") return;
    const tick = () => { void useLeases.getState().poll(useSessions.getState().tabs); };
    tick();
    const id = window.setInterval(tick, LEASE_POLL_MS);
    return () => { window.clearInterval(id); };
  }, [live]);
  return null;
}

/** "Database lease for Vault role readonly": engine and role only, never a lease or secret id. */
export function useLeaseRole(tab: Tab, lease: LeaseView | null): string | null {
  const conn = useTree((s) => s.connections.find((c) => c.id === tab.connectionId));
  const creds = useCredentials((s) => s.items);
  if (!lease || !conn) return null;
  const id = conn.effectiveCredentialId ?? conn.credentialId;
  const cred = creds.find((c) => c.id === id);
  if (cred?.kind !== "external_ref" || cred.fields.engine !== lease.engine || typeof cred.fields.reference !== "string") return null;
  return roleOf(cred.fields.reference);
}

/** Chip state, text and tooltip of a tab (null = no lease). The tooltip names engine and role only. */
export function useLeaseChip(tab: Tab): { state: string; text: string; title: string } | null {
  const leases = useLeases((s) => s.byTab[tab.id]);
  const now = useNow(LEASE_POLL_MS);
  const lease = leases ? worstLease(leases) : null;
  const role = useLeaseRole(tab, lease);
  // A reconnect that has no session yet must not show the revoked lease of the last one.
  const chip = leases && (tab.sessionId !== null || tab.state === "closed") ? leaseChip(leases, tab.state, now) : null;
  if (!chip || !lease) return null;
  const engine = isVaultEngine(lease.engine) ? ENGINE_LABEL[lease.engine] : lease.engine;
  const what = `${engine} lease${role ? ` for Vault role ${role}` : ""}`;
  const detail =
    chip.state === "revoked" ? "Mooring revoked it when the session closed."
      : chip.state === "expired" ? "Vault may already have removed the account; the session keeps running until the server ends it."
        : chip.state === "renew_failed" ? "Mooring could not renew it. The session goes on until the lease expires; reconnect for a new one."
          : lease.renewable ? "Mooring renews it at two thirds of its TTL and revokes it when the session closes." : "It is not renewable and ends at its TTL.";
  return { state: chip.state, text: chip.text, title: `${what}. ${detail}${remaining(lease, chip.state, now)}` };
}

/** " Expires in 52 min (TTL 1 h)." while the lease is live; the TTL is Rust's `ttlSeconds` since R6. */
export function remaining(lease: LeaseView, state: string, now: number): string {
  if (lease.expiresAt === null || state === "revoked" || state === "expired") return "";
  const left = Math.max(0, (lease.expiresAt - now) / 1000);
  return ` Expires in ${leaseDuration(left)}${lease.ttlSeconds !== null ? ` (TTL ${leaseDuration(lease.ttlSeconds)})` : ""}.`;
}

/** "Lease · renews in 23 min" on a session tab whose credential is dynamic. */
export function LeaseChip({ chip }: { chip: { state: string; text: string; title: string } }) {
  return <span className="lease-chip" data-state={chip.state} title={chip.title} aria-hidden>{chip.text}</span>;
}
