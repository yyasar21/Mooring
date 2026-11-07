// Mock ADR-0016 secret sources (Vault / OpenBao KV v2) as rust-core E2 serves them. No Vault
// exists: sources live in memory, `credential_external_test` answers from a fake KV that holds key
// NAMES only, tokens and secret values never exist at all. The OIDC window is simulated by a timer
// and the `oidcOutcome` knob. Methods stay `async` to mirror the IPC signature even when they do
// not await.
/* eslint-disable @typescript-eslint/require-await */
import type { CredentialMeta, ExternalRefTest, OidcFailure, OidcStatus, SecretSource, SecretSourceInput, SecretSourceTest, SecretsIpc } from "./ipc.types";
import { SOURCE_LOGIN_KIND } from "./ipc.types.secrets";
import { dynamicRefTest, providerRefTest } from "./ipc.mock.leases";
import { IpcError } from "./ipc.error";
import { KIND_SCHEMAS } from "./ipc.kinds";
import { MockSyncBase } from "./ipc.mock.sync";
import { T0 } from "./ipc.seed";
import { checkReference, validateSecretSource } from "./validate.secrets";

/** KV keys the fake Vault holds per reference (names only, never values). */
const FAKE_KV: Record<string, string[]> = {
  "kv/ops/db": ["username", "password"],
  "kv/ops/ssh": ["username", "private_key", "passphrase"],
  "kv/ops/legacy": ["user", "pass", "note"],
};

interface OidcFlow extends OidcStatus { id: string }

/** The seeded sources: Vault AppRole (`cr-approle`), 1Password Connect (`cr-op-token`), Bitwarden (`cr-bws-token`). */
export function seedSources(): SecretSource[] {
  return [{
    id: "src-ops", name: "ops vault", kind: "vault", address: "https://vault.example.test:8200", namespace: null, authMethod: "approle",
    authMount: "approle", credentialId: "cr-approle", oidcRole: null, options: { caPem: null, allowHttp: false, allowedOrigins: [] },
    createdAt: T0, updatedAt: T0,
  }, {
    id: "src-op", name: "infra connect", kind: "onepassword", address: "https://connect.example.test:8080", namespace: null, authMethod: "token",
    authMount: "token", credentialId: "cr-op-token", oidcRole: null, options: { caPem: null, allowHttp: false, allowedOrigins: [] },
    createdAt: T0, updatedAt: T0,
  }, {
    id: "src-bws", name: "team secrets", kind: "bitwarden", address: "https://bitwarden.example.test", namespace: null, authMethod: "token",
    authMount: "token", credentialId: "cr-bws-token", oidcRole: null, options: { caPem: null, allowHttp: false, allowedOrigins: [], bwsPath: null },
    createdAt: T0, updatedAt: T0,
  }];
}

export abstract class MockSecretsBase extends MockSyncBase implements SecretsIpc {
  sources = new Map<string, SecretSource>(seedSources().map((s) => [s.id, s]));
  /** OIDC flows by session id. */
  oidc = new Map<string, OidcFlow>();
  /** How a simulated OIDC sign-in ends (`done`, or a failure reason). */
  oidcOutcome: "done" | OidcFailure = "done";
  /** ADR-0026 knob: is `bws` present at one of the fixed paths (`secret.tool_missing` when not). */
  bwsFound = true;
  private srcIds = 0;
  private oidcIds = 0;
  protected abstract override credentialRows(): CredentialMeta[];

  private checkSource(a: SecretSourceInput): SecretSourceInput {
    const errors = validateSecretSource(a);
    const field = Object.keys(errors)[0];
    if (field) throw new IpcError("input.invalid", `invalid ${field}`);
    const kind = a.kind ?? "vault";
    if (a.credentialId !== null) {
      const cred = this.credentialRows().find((c) => c.id === a.credentialId);
      if (!cred) throw new IpcError("credential.not_found", "credential not found");
      const want = kind !== "vault" ? SOURCE_LOGIN_KIND[kind] : a.authMethod === "token" ? "api_token" : "vault_approle";
      if (cred.kind !== want) throw new IpcError("credential.incompatible", `this source needs a ${want} credential`);
    }
    const options = structuredClone(a.options);
    if (kind === "bitwarden") options.bwsPath ??= null;
    else delete options.bwsPath;
    return {
      ...structuredClone(a), kind, options, name: a.name.trim(), address: a.address.trim().replace(/\/+$/, "").toLowerCase(),
      namespace: a.namespace?.trim().replace(/^\/+|\/+$/g, "") || null, authMount: a.authMount.trim().replace(/^\/+|\/+$/g, "") || a.authMethod,
      oidcRole: a.oidcRole?.trim() || null,
    };
  }

  private source(id: string): SecretSource {
    const s = this.sources.get(id);
    if (!s) throw new IpcError("source.not_found", "secret source not found");
    return s;
  }

  /** Mock rule: addresses under `.invalid` (RFC 6761) never answer. */
  private down(s: SecretSource): boolean {
    return s.address.includes(".invalid");
  }

  secretSourceList: SecretsIpc["secretSourceList"] = async () => {
    await this.unlocked();
    return [...this.sources.values()].map((s) => structuredClone(s));
  };

  secretSourceGet: SecretsIpc["secretSourceGet"] = async ({ id }) => {
    await this.unlocked();
    return structuredClone(this.source(id));
  };

  secretSourceCreate: SecretsIpc["secretSourceCreate"] = async (a) => {
    await this.unlocked();
    const v = this.checkSource(a);
    this.srcIds += 1;
    const now = new Date().toISOString();
    const s: SecretSource = { ...v, id: `src-${this.srcIds.toString(16).padStart(4, "0")}`, kind: v.kind ?? "vault", createdAt: now, updatedAt: now };
    this.sources.set(s.id, s);
    this.record("secret_source_changed", { source: s.id, changed: "created", warning: String(v.options.allowHttp || v.options.caPem !== null) });
    return structuredClone(s);
  };

  secretSourceUpdate: SecretsIpc["secretSourceUpdate"] = async ({ id, ...a }) => {
    await this.unlocked();
    const cur = this.source(id);
    // R3: an update without `kind` keeps the stored one; a different kind is refused.
    if (a.kind !== undefined && a.kind !== cur.kind) throw new IpcError("input.invalid", "invalid kind: a source keeps its provider");
    const v = this.checkSource({ ...a, kind: cur.kind });
    const changed = (Object.keys(v) as (keyof SecretSourceInput)[]).filter((k) => JSON.stringify(v[k]) !== JSON.stringify(cur[k]));
    Object.assign(cur, v, { updatedAt: new Date().toISOString() });
    this.record("secret_source_changed", { source: id, changed: changed.join(","), warning: String(changed.includes("options")) });
    this.secretToolPin.delete(id);
    return structuredClone(cur);
  };

  secretSourceDelete: SecretsIpc["secretSourceDelete"] = async ({ id }) => {
    await this.unlocked();
    this.source(id);
    if (this.credentialRows().some((c) => c.kind === "external_ref" && c.fields.source === id)) {
      this.record("secret_refused", { source: id, action: "delete", detail: "in use" });
      throw new IpcError("source.in_use", "an external reference uses this source");
    }
    this.sources.delete(id);
    this.record("secret_source_changed", { source: id, changed: "deleted", warning: "false" });
  };

  /** Sources whose `bws` binary was already pinned (first run audits `secret_tool_spawned`). */
  protected secretToolPin = new Set<string>();

  /** Connect: `/heartbeat` + `/v1/vaults`. Bitwarden: `bws --version` + `project list`. Counts only. */
  private testProvider(s: SecretSource): SecretSourceTest {
    const base = { method: "token" as const, ttlSeconds: null, renewable: false };
    if (this.down(s)) {
      this.record("secret_failed", { source: s.id, category: "network" });
      return { ...base, ok: false, policiesCount: 0, error: "credential.external_unavailable", category: "network" };
    }
    if (s.kind === "bitwarden") {
      if (!this.bwsFound) {
        this.record("secret_failed", { source: s.id, category: "tool" });
        return { ...base, ok: false, policiesCount: 0, error: "secret.tool_missing", category: "tool" };
      }
      if (!this.secretToolPin.has(s.id)) this.secretToolPin.add(s.id);
      this.record("secret_tool_spawned", { provider: "bitwarden", exit: "0" });
      return { ...base, ok: true, policiesCount: 3, error: null, category: null };
    }
    this.record("secret_login", { source: s.id, method: "token", ttl: "0" });
    return { ...base, ok: true, policiesCount: 2, error: null, category: null };
  }

  secretSourceTest: SecretsIpc["secretSourceTest"] = async ({ id }) => {
    await this.unlocked();
    const s = this.source(id);
    if (s.kind !== "vault") return this.testProvider(s);
    if (this.down(s)) {
      this.record("secret_failed", { source: id, category: "network" });
      return { ok: false, method: s.authMethod, ttlSeconds: null, renewable: false, policiesCount: 0, error: "credential.external_unavailable", category: "network" };
    }
    if (s.authMethod === "oidc" && ![...this.oidc.values()].some((f) => f.sourceId === id && f.state === "done")) {
      return { ok: false, method: "oidc", ttlSeconds: null, renewable: false, policiesCount: 0, error: "credential.external_unavailable", category: "auth_failed" };
    }
    this.record("secret_login", { source: id, method: s.authMethod, ttl: "3600" });
    return { ok: true, method: s.authMethod, ttlSeconds: 3600, renewable: s.authMethod !== "token", policiesCount: 2, error: null, category: null };
  };

  /** Works while locked: the token is revoked (AppRole/OIDC) or forgotten (token). */
  secretSourceRevoke: SecretsIpc["secretSourceRevoke"] = async ({ id }) => {
    const s = this.source(id);
    for (const [sid, f] of this.oidc) if (f.sourceId === id) this.oidc.delete(sid);
    if (s.authMethod !== "token") this.record("secret_revoked", { source: id });
  };

  credentialExternalTest: SecretsIpc["credentialExternalTest"] = async ({ credentialId }) => {
    await this.unlocked();
    const c = this.credentialRows().find((x) => x.id === credentialId);
    if (!c) throw new IpcError("credential.not_found", "credential not found");
    if (c.kind !== "external_ref") throw new IpcError("input.invalid", "invalid credentialId: not an external reference");
    const src = typeof c.fields.source === "string" ? this.sources.get(c.fields.source) : undefined;
    if (!src) throw new IpcError("source.not_found", "secret source not found");
    if (src.kind !== c.fields.provider) throw new IpcError("source.kind_unsupported", "the reference's provider does not match its source");
    const fail = (error: string, category: string): ExternalRefTest => {
      this.record("secret_failed", { source: src.id, category });
      return { ok: false, version: null, present: [], missing: [], extra: [], error, category };
    };
    if (this.down(src)) return fail("credential.external_unavailable", "network");
    if (src.kind === "bitwarden" && !this.bwsFound) return fail("secret.tool_missing", "tool");
    const dyn = dynamicRefTest(c);
    if (dyn) {
      if (dyn.ok) this.record("secret_lease_revoked", { source: src.id, engine: typeof c.fields.engine === "string" ? c.fields.engine : "kv2", reason: "test" });
      return dyn;
    }
    if (src.kind !== "vault") return providerRefTest(c, (e, d) => { this.record(e, d); });
    const ref = typeof c.fields.reference === "string" ? c.fields.reference : "";
    if (checkReference(ref)) return fail("credential.external_shape", "shape");
    const keys = FAKE_KV[ref];
    if (!keys) return fail("credential.external_not_found", "not_found");
    const target = KIND_SCHEMAS.find((k) => k.kind === c.fields.target_kind);
    if (!target) return fail("credential.external_shape", "shape");
    const map = typeof c.fields.field_map === "object" && !Array.isArray(c.fields.field_map) ? (c.fields.field_map as Record<string, string>) : {};
    const keyOf = (name: string) => map[name] ?? name;
    const names = [...target.fields.map((f) => f.name), ...(target.supportsOtp ? ["otp_seed"] : [])];
    const present = names.filter((n) => keys.includes(keyOf(n)));
    const missing = target.fields.filter((f) => f.required && !keys.includes(keyOf(f.name))).map((f) => f.name);
    const wanted = new Set(names.map(keyOf));
    const extra = keys.filter((k) => !wanted.has(k));
    const version = typeof c.fields.version === "number" ? c.fields.version : 3;
    this.record("secret_resolved", { credential: c.id, source: src.id, reference: ref, version: String(version), target_kind: target.kind, fields: present.join(",") });
    return { ok: missing.length === 0 && extra.length === 0, version, present, missing, extra, error: null, category: null };
  };

  secretSourceOidcBegin: SecretsIpc["secretSourceOidcBegin"] = async ({ id }) => {
    await this.unlocked();
    const s = this.source(id);
    if (s.authMethod !== "oidc") throw new IpcError("input.invalid", "invalid id: not an OIDC source");
    const running = [...this.oidc.values()].find((f) => f.sourceId === id && f.state === "pending");
    if (running) return { sessionId: running.id, windowLabel: `oidc-${id}` };
    if (this.down(s)) throw new IpcError("window.failed", "the identity provider did not answer");
    this.oidcIds += 1;
    const flow: OidcFlow = { id: `oidc-${this.oidcIds.toString(16).padStart(4, "0")}`, state: "pending", sourceId: id, error: null };
    this.oidc.set(flow.id, flow);
    this.later(() => { this.finishOidc(flow.id, this.oidcOutcome); });
    return { sessionId: flow.id, windowLabel: `oidc-${id}` };
  };

  /** Test/dev hook: end a pending flow (the window closed, the vault locked, the IdP answered). */
  finishOidc(sessionId: string, outcome: string): void {
    const f = this.oidc.get(sessionId);
    if (!f || f.state !== "pending") return;
    if (outcome === "done") {
      Object.assign(f, { state: "done", error: null });
      this.record("secret_login", { source: f.sourceId, method: "oidc", ttl: "3600" });
    } else {
      Object.assign(f, { state: "failed", error: outcome });
      this.record("secret_refused", { source: f.sourceId, action: "oidc", detail: outcome });
    }
  }

  secretSourceOidcStatus: SecretsIpc["secretSourceOidcStatus"] = async ({ sessionId }) => {
    const f = this.oidc.get(sessionId);
    if (!f) throw new IpcError("session.not_found", "unknown OIDC session");
    return { state: f.state, sourceId: f.sourceId, error: f.error };
  };

  /** Every lock fails the open OIDC flows and forgets the tokens (E2 `on_lock`). */
  protected override lockBackend(): void {
    super.lockBackend();
    for (const f of this.oidc.values()) if (f.state === "pending") Object.assign(f, { state: "failed", error: "locked" });
  }
}
