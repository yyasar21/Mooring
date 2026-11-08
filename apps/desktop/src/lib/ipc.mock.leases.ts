// Mock ADR-0026 pieces for MockTransport: dynamic-engine and 1Password / Bitwarden reference tests
// (names only) and a lease book for sessions whose credential is a Vault `database` reference.
// No Vault exists; a lease is a TTL and a clock, never an id the UI could see.
import type { CredentialMeta, ExternalRefTest, LeaseInfo } from "./ipc.types";
import { KIND_SCHEMAS } from "./ipc.kinds";
import { checkBwsReference, checkOpReference, engineOf } from "./validate.refs";

/** Fields of the fake 1Password items, by `op://vault/item` (names only). */
const FAKE_OP: Record<string, string[]> = {
  "op://Infra/prod-db": ["username", "password", "notes"],
  "op://Infra/deploy-key": ["username", "private_key"],
};

type Record_ = (event: string, details: Record<string, string>) => void;
const str = (v: unknown) => (typeof v === "string" ? v : "");

/** The test result of a dynamic Vault engine: issue once, revoke at once (`ssh_sign` is tested by connecting). */
export function dynamicRefTest(c: CredentialMeta): ExternalRefTest | null {
  const engine = engineOf(c.fields.engine);
  if (c.fields.provider !== "vault" || engine === "kv2") return null;
  const base = { version: null, missing: [], extra: [], category: null };
  if (engine === "ssh_sign") return { ...base, ok: false, present: [], error: "credential.external_engine" };
  const present = engine === "pki" ? ["cert_pem", "key_pem"] : ["username", "password"];
  return { ...base, ok: true, present, error: null };
}

/** Names the target kind needs, required first. */
function targetOf(c: CredentialMeta) {
  return KIND_SCHEMAS.find((k) => k.kind === c.fields.target_kind);
}

/** 1Password Connect and Bitwarden `bws` reference tests (ADR-0026 §3–§4), names only. */
export function providerRefTest(c: CredentialMeta, record: Record_): ExternalRefTest {
  const ref = str(c.fields.reference);
  const fail = (error: string, category: string | null): ExternalRefTest => {
    record("secret_failed", { credential: c.id, category: category ?? "shape" });
    return { ok: false, version: null, present: [], missing: [], extra: [], error, category };
  };
  const target = targetOf(c);
  if (!target) return fail("credential.external_shape", "shape");
  const required = target.fields.filter((f) => f.required).map((f) => f.name);
  const one = (): ExternalRefTest => {
    // A single value fills a kind with exactly one required value; anything else is an engine error.
    if (required.length !== 1) return fail("credential.external_engine", null);
    record("secret_resolved", { credential: c.id, provider: str(c.fields.provider), target_kind: target.kind, fields: required.join(",") });
    return { ok: true, version: null, present: required, missing: [], extra: [], error: null, category: null };
  };
  if (c.fields.provider === "bitwarden") {
    if (checkBwsReference(ref)) return fail("credential.external_shape", "shape");
    return one();
  }
  if (checkOpReference(ref)) return fail("credential.external_shape", "shape");
  const segs = ref.slice(5).split("/");
  if (segs.length > 2) return one();
  const keys = FAKE_OP[ref];
  if (!keys) return fail("credential.external_not_found", "not_found");
  const map = typeof c.fields.field_map === "object" && !Array.isArray(c.fields.field_map) ? (c.fields.field_map as Record<string, string>) : {};
  const keyOf = (n: string) => map[n] ?? n;
  const names = target.fields.map((f) => f.name);
  const present = names.filter((n) => keys.includes(keyOf(n)));
  const missing = required.filter((n) => !keys.includes(keyOf(n)));
  // Connect items carry extra fields (notes, URLs); they are ignored, not refused.
  record("secret_resolved", { credential: c.id, provider: "onepassword", target_kind: target.kind, fields: present.join(",") });
  return { ok: missing.length === 0, version: null, present, missing, extra: [], error: null, category: null };
}

const noop: Record_ = () => undefined;

interface MockLease {
  engine: "database";
  ttl: number;
  /** `Date.now()` of the issue or the last renewal. */
  since: number;
  renewable: boolean;
  failRenew: boolean;
  state: "active" | "renew_failed" | "expired";
}

/** Leases per session id. Renewal at 2/3 of the TTL is computed lazily from the clock. */
export class MockLeaseBook {
  private leases = new Map<string, MockLease[]>();

  issue(sessionId: string, o: { ttl: number; renewable: boolean; failRenew: boolean }, now = Date.now()): void {
    this.leases.set(sessionId, [{ engine: "database", ttl: o.ttl, since: now, renewable: o.renewable, failRenew: o.failRenew, state: "active" }]);
  }

  /** Bring a lease up to `now` (renew, fail a renewal, expire), recording the audit events Rust writes. */
  private advance(l: MockLease, now: number, record: Record_): void {
    if (l.state === "expired") return;
    const renewAt = (l.ttl * 2000) / 3;
    while (l.state === "active" && l.renewable && !l.failRenew && now - l.since >= renewAt) {
      l.since += renewAt;
      record("secret_lease_renewed", { engine: l.engine });
    }
    if (l.state === "active" && l.renewable && l.failRenew && now - l.since >= renewAt) {
      l.state = "renew_failed";
      record("secret_lease_renew_failed", { engine: l.engine, category: "forbidden" });
    }
    if (now - l.since >= l.ttl * 1000) l.state = "expired";
  }

  status(sessionId: string, record: Record_ = noop, now = Date.now()): LeaseInfo[] {
    return (this.leases.get(sessionId) ?? []).map((l) => {
      this.advance(l, now, record);
      const left = Math.max(0, Math.round((l.ttl * 1000 - (now - l.since)) / 1000));
      return { engine: l.engine, expiresInSeconds: left, renewable: l.renewable, state: l.state, ttlSeconds: l.ttl };
    });
  }

  /** Session closed: revoke (best effort) and forget. */
  release(sessionId: string, reason: string, record: Record_): void {
    for (const l of this.leases.get(sessionId) ?? []) record("secret_lease_revoked", { engine: l.engine, reason });
    this.leases.delete(sessionId);
  }

  /** Vault lock: every lease is revoked; the sessions themselves survive (R3 `drain_for_lock`). */
  drain(record: Record_): void {
    for (const id of [...this.leases.keys()]) this.release(id, "locked", record);
  }
}
