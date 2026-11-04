// Mock ADR-0016 secret sources (Vault / OpenBao KV v2) and ADR-0017 vault sync. No Vault or
// bucket exists: sources and the sync config live in memory, `external_ref_test` answers from a
// fake KV, tokens and secret values never exist at all. The OIDC window is simulated by a timer.
// Methods stay `async` to mirror the IPC signature even when they do not await.
/* eslint-disable @typescript-eslint/require-await */
import type {
  CredentialMeta,
  SecretSource,
  SecretSourceInput,
  SecretsIpc,
  SyncConfig,
  SyncIpc,
  SyncStatus,
  OidcStatus,
} from "./ipc.types";
import { SECRET_AUTH_METHODS } from "./ipc.types.secrets";
import { IpcError } from "./ipc.error";
import { MockVsphereBase } from "./ipc.mock.vsphere";
import { checkCaPem, checkUrl } from "./validate.options";

const LOOPBACK_HTTP = /^http:\/\/(127\.0\.0\.1|\[::1\])(:\d{1,5})?(\/|$)/;
const REFERENCE = /^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)+$/;
/** KV keys the fake Vault holds per reference (names only). */
const FAKE_KV: Record<string, string[]> = { "kv/ops/db": ["username", "password"], "kv/ops/ssh": ["username", "private_key"] };

export abstract class MockSecretsBase extends MockVsphereBase implements SecretsIpc, SyncIpc {
  sources = new Map<string, SecretSource>();
  oidc = new Map<string, OidcStatus>();
  syncConfig: SyncConfig | null = null;
  syncState: SyncStatus = { lastPull: null, lastPush: null, counter: 0, state: "disabled", conflicts: [] };
  /** Credentials the mock consults for `external_ref_test` and `source.in_use`. */
  protected abstract credentialRows(): CredentialMeta[];
  private srcIds = 0;

  private checkSource(a: SecretSourceInput): void {
    const name = a.name.trim();
    if (name === "" || name.length > 200) throw new IpcError("input.invalid", "invalid name: 1 to 200 characters");
    const http = a.address.startsWith("http://");
    if (http && !(a.options.allowHttp && LOOPBACK_HTTP.test(a.address))) throw new IpcError("input.invalid", "invalid address: https only (http for loopback with allowHttp)");
    if (!http && checkUrl(a.address, false, false)) throw new IpcError("input.invalid", "invalid address");
    if (!SECRET_AUTH_METHODS.includes(a.authMethod)) throw new IpcError("input.invalid", "invalid authMethod");
    if (!/^[A-Za-z0-9._-]{1,128}$/.test(a.authMount)) throw new IpcError("input.invalid", "invalid authMount");
    if (a.authMethod === "oidc" ? a.oidcRole === null || a.credentialId !== null : a.credentialId === null) {
      throw new IpcError("input.invalid", "invalid credentialId: token/approle need a credential, oidc a role");
    }
    if (a.options.allowedOrigins.length > 16) throw new IpcError("input.invalid", "invalid allowedOrigins: at most 16");
    if (checkCaPem(a.options.caPem)) throw new IpcError("input.invalid", "invalid caPem");
  }

  private source(id: string): SecretSource {
    const s = this.sources.get(id);
    if (!s) throw new IpcError("source.not_found", "secret source not found");
    return s;
  }

  secretSourceList: SecretsIpc["secretSourceList"] = async () => {
    await this.unlocked();
    return [...this.sources.values()].map((s) => structuredClone(s));
  };

  secretSourceCreate: SecretsIpc["secretSourceCreate"] = async (a) => {
    await this.unlocked();
    this.checkSource(a);
    this.srcIds += 1;
    const now = new Date().toISOString();
    const s: SecretSource = { ...structuredClone(a), name: a.name.trim(), id: `src-${this.srcIds.toString(16).padStart(4, "0")}`, kind: "vault", createdAt: now, updatedAt: now };
    this.sources.set(s.id, s);
    return structuredClone(s);
  };

  secretSourceUpdate: SecretsIpc["secretSourceUpdate"] = async ({ id, ...a }) => {
    await this.unlocked();
    const cur = this.source(id);
    this.checkSource(a);
    const changed = (Object.keys(a) as (keyof SecretSourceInput)[]).filter((k) => JSON.stringify(a[k]) !== JSON.stringify(cur[k]));
    Object.assign(cur, structuredClone(a), { name: a.name.trim(), updatedAt: new Date().toISOString() });
    this.record("secret.source_changed", { source: id, changed: changed.join(",") });
    return structuredClone(cur);
  };

  secretSourceDelete: SecretsIpc["secretSourceDelete"] = async ({ id }) => {
    await this.unlocked();
    this.source(id);
    if (this.credentialRows().some((c) => c.kind === "external_ref" && c.fields.source === id)) throw new IpcError("source.in_use", "an external reference uses this source");
    this.sources.delete(id);
  };

  /** Mock rule: addresses under `.invalid` (RFC 6761) never answer. */
  secretSourceTest: SecretsIpc["secretSourceTest"] = async ({ id }) => {
    await this.unlocked();
    const s = this.source(id);
    const down = s.address.includes(".invalid");
    if (!down) this.record("secret.login", { source: id, method: s.authMethod, ttl: "3600" });
    return { ok: !down, method: s.authMethod, ttlSeconds: down ? null : 3600, renewable: !down && s.authMethod !== "token", policiesCount: down ? 0 : 2, error: down ? "network" : null };
  };

  secretSourceLogout: SecretsIpc["secretSourceLogout"] = async ({ id }) => {
    await this.unlocked();
    this.source(id);
    this.record("secret.revoked", { source: id });
  };

  externalRefTest: SecretsIpc["externalRefTest"] = async ({ credentialId }) => {
    await this.unlocked();
    const c = this.credentialRows().find((x) => x.id === credentialId);
    if (!c) throw new IpcError("credential.not_found", "credential not found");
    if (c.kind !== "external_ref") throw new IpcError("input.invalid", "invalid credentialId: not an external reference");
    const ref = typeof c.fields.reference === "string" ? c.fields.reference : "";
    if (!REFERENCE.test(ref) || ref.split("/").includes("..")) return { ok: false, version: null, present: [], missing: [], error: "shape" };
    const keys = FAKE_KV[ref];
    if (!keys) return { ok: false, version: null, present: [], missing: [], error: "not_found" };
    return { ok: true, version: 3, present: [...keys], missing: [], error: null };
  };

  secretSourceOidcStart: SecretsIpc["secretSourceOidcStart"] = async ({ id }) => {
    await this.unlocked();
    const s = this.source(id);
    if (s.authMethod !== "oidc") throw new IpcError("input.invalid", "invalid id: not an OIDC source");
    if (this.oidc.get(id)?.state === "waiting") throw new IpcError("input.invalid", "invalid id: a sign-in is already running");
    this.oidc.set(id, { state: "waiting", error: null });
    this.later(() => {
      if (this.oidc.get(id)?.state !== "waiting") return;
      this.oidc.set(id, { state: "done", error: null });
      this.record("secret.login", { source: id, method: "oidc", ttl: "3600" });
    });
    return { windowLabel: `oidc-${id}` };
  };

  secretSourceOidcStatus: SecretsIpc["secretSourceOidcStatus"] = async ({ id }) => {
    this.source(id);
    return { ...(this.oidc.get(id) ?? { state: "idle", error: null }) };
  };

  // ---------- sync (ADR-0017) ----------

  syncGet: SyncIpc["syncGet"] = async () => {
    await this.unlocked();
    return this.syncConfig ? structuredClone(this.syncConfig) : null;
  };

  syncStatus: SyncIpc["syncStatus"] = async () => structuredClone(this.syncState);

  syncSet: SyncIpc["syncSet"] = async (a) => {
    await this.unlocked();
    if (checkUrl(a.endpoint, false, false)) throw new IpcError("input.invalid", "invalid endpoint");
    if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(a.bucket)) throw new IpcError("input.invalid", "invalid bucket");
    if (a.prefix.length > 512 || a.prefix.includes("..")) throw new IpcError("input.invalid", "invalid prefix");
    const cred = this.credentialRows().find((c) => c.id === a.credentialId);
    if (!cred) throw new IpcError("credential.not_found", "credential not found");
    this.syncConfig = { ...structuredClone(a), deviceId: this.syncConfig?.deviceId ?? "dev-0001" };
    this.syncState = { ...this.syncState, state: "idle" };
    this.record("sync.config_changed", { endpoint: a.endpoint });
    return structuredClone(this.syncConfig);
  };

  /** Mock rule: endpoints under `.invalid` lack conditional writes. */
  syncProbe: SyncIpc["syncProbe"] = async () => {
    await this.unlocked();
    if (!this.syncConfig) throw new IpcError("sync.not_configured", "save the sync settings first");
    const ok = !this.syncConfig.endpoint.includes(".invalid");
    return { conditionalWrites: ok, error: ok ? null : "the backend ignores If-None-Match" };
  };

  syncNow: SyncIpc["syncNow"] = async () => {
    await this.unlocked();
    if (!this.syncConfig) throw new IpcError("sync.not_configured", "save the sync settings first");
    if (this.syncConfig.endpoint.includes(".invalid")) throw new IpcError("sync.unsupported_backend", "the backend has no conditional writes");
    const now = new Date().toISOString();
    this.syncState = { ...this.syncState, counter: this.syncState.counter + 1, lastPull: now, lastPush: now, state: "idle" };
    this.record("sync.push", { counter: String(this.syncState.counter), bytes: "48211" });
    return { pulled: true, pushed: true, merged: this.syncState.conflicts.length > 0, conflicts: structuredClone(this.syncState.conflicts) };
  };

  syncDisable: SyncIpc["syncDisable"] = async ({ deleteRemote }) => {
    await this.unlocked();
    if (!this.syncConfig) throw new IpcError("sync.not_configured", "sync is not configured");
    this.syncConfig = null;
    this.syncState = { lastPull: null, lastPush: null, counter: 0, state: "disabled", conflicts: [] };
    this.record("sync.config_changed", { enabled: "false", delete_remote: String(deleteRemote) });
  };

  /** Only on a fresh device; the mock "finds" a vault unless the prefix is `empty`. */
  vaultJoin: SyncIpc["vaultJoin"] = async (a) => {
    if (this.vault !== "missing") throw new IpcError("vault.exists", "a vault already exists on this device");
    if (a.password.length === 0) throw new IpcError("vault.unlock", "wrong password");
    if (a.prefix === "empty") throw new IpcError("sync.not_found", "no vault under this prefix");
    this.vault = "unlocked";
    this.record("vault_unlocked", {});
    return this.vault;
  };
}
