// DTOs of the ADR-0016 (external secrets: Vault / OpenBao KV v2) and ADR-0017 (vault sync to
// S3-compatible storage) IPC contracts, exactly as rust-core E2 and S2 serve them
// (docs/handoff/a3-rust-core-e2.md, a3-rust-core-s2.md). Secrets cross inward only (the vault
// password on `vault_join`); nothing returned here carries a secret value or a token.
import type { CredentialKind, VaultStatus } from "./ipc.types";

// ---------- secret sources (ADR-0016, E2) ----------

export type SecretAuthMethod = "token" | "approle" | "oidc";
export const SECRET_AUTH_METHODS: readonly SecretAuthMethod[] = ["token", "approle", "oidc"];

/** The login credential kind per method (null = the OIDC window, nothing stored). */
export const SECRET_AUTH_CREDENTIAL: Readonly<Record<SecretAuthMethod, CredentialKind | null>> = {
  token: "api_token",
  approle: "vault_approle",
  oidc: null,
};

export interface SecretSourceOptions {
  caPem: string | null;
  /** http only for 127.0.0.1 / [::1]; audited. */
  allowHttp: boolean;
  /** Extra IdP origins for the OIDC window (`https://host[:port]`), ≤ 16; OIDC only. */
  allowedOrigins: string[];
}

export interface SecretSourceInput {
  name: string;
  address: string;
  namespace: string | null;
  authMethod: SecretAuthMethod;
  /** Empty = the method's default mount (`token`, `approle`, `oidc`). */
  authMount: string;
  /** `api_token` (token) or `vault_approle` (approle); null for oidc. */
  credentialId: string | null;
  oidcRole: string | null;
  options: SecretSourceOptions;
}

export interface SecretSource {
  id: string;
  name: string;
  kind: "vault";
  address: string;
  namespace: string | null;
  authMethod: SecretAuthMethod;
  authMount: string;
  credentialId: string | null;
  oidcRole: string | null;
  options: SecretSourceOptions;
  createdAt: string;
  updatedAt: string;
}

/** `credential.external_unavailable` categories (ADR-0016 §3). */
export type SecretErrorCategory = "network" | "tls" | "auth_failed" | "forbidden" | "not_found" | "shape" | "locked";

export interface SecretSourceTest {
  ok: boolean;
  method: SecretAuthMethod;
  ttlSeconds: number | null;
  renewable: boolean;
  policiesCount: number;
  /** The error code when `ok` is false. */
  error: string | null;
  /** A `SecretErrorCategory` (or a newer one this build does not know). */
  category: string | null;
}

/** ADR-0016 §2: kinds an `external_ref` may resolve into. */
export const EXTERNAL_TARGET_KINDS = [
  "user_password", "domain_user", "ssh_key", "x509", "api_token", "kube_token", "kubeconfig",
  "vsphere_user", "vnc_password", "vnc_user_password", "sudo_become",
] as const satisfies readonly CredentialKind[];
export type ExternalTargetKind = (typeof EXTERNAL_TARGET_KINDS)[number];

/** `external_ref` credential fields as stored (E1: snake_case `field_map`, numeric `version`). */
export interface ExternalRefFields {
  provider: "vault" | "onepassword" | "bitwarden";
  source?: string;
  /** `<mount>/<path>`, segments `[A-Za-z0-9._-]+`, ≤ 1 KiB. */
  reference: string;
  target_kind: ExternalTargetKind;
  version?: number;
  /** target field or secret name → KV key. */
  field_map?: Record<string, string>;
}

/** `credential_external_test`: KV key names only, never values. `ok` = nothing missing, nothing extra. */
export interface ExternalRefTest {
  ok: boolean;
  version: number | null;
  present: string[];
  missing: string[];
  extra: string[];
  error: string | null;
  category: string | null;
}

export type OidcState = "pending" | "done" | "failed";
/** Fixed failure reasons; anything else is an `external_unavailable` category. */
export type OidcFailure = "timeout" | "closed" | "locked" | "exit" | "state_mismatch";
export interface OidcStatus {
  state: OidcState;
  sourceId: string;
  /** An `OidcFailure`, or the `external_unavailable` category of the callback exchange. */
  error: string | null;
}

export interface SecretsIpc {
  secretSourceList(): Promise<SecretSource[]>;
  secretSourceGet(args: { id: string }): Promise<SecretSource>;
  secretSourceCreate(args: SecretSourceInput): Promise<SecretSource>;
  /** The cached token is forgotten. */
  secretSourceUpdate(args: SecretSourceInput & { id: string }): Promise<SecretSource>;
  /** `source.in_use` while an external_ref names it. */
  secretSourceDelete(args: { id: string }): Promise<void>;
  secretSourceTest(args: { id: string }): Promise<SecretSourceTest>;
  /** Revoke (AppRole/OIDC) or forget (token) the cached token; works while locked. */
  secretSourceRevoke(args: { id: string }): Promise<void>;
  credentialExternalTest(args: { credentialId: string }): Promise<ExternalRefTest>;
  /** Opens `oidc-<id>`; one flow per source (a running one is returned and focused). */
  secretSourceOidcBegin(args: { id: string }): Promise<{ sessionId: string; windowLabel: string }>;
  /** Passive: poll every second until the state leaves `pending`. */
  secretSourceOidcStatus(args: { sessionId: string }): Promise<OidcStatus>;
}

// ---------- vault sync (ADR-0017, S2) ----------

export const SYNC_INTERVAL = { min: 5, max: 1440, default: 15 } as const;

export interface SyncBackend {
  kind: "s3";
  /** `https://host[:port]`, no path (`http://` only for a loopback literal). */
  endpoint: string;
  region: string;
  bucket: string;
  /** `[A-Za-z0-9._-]` segments joined by `/`; may be empty. */
  prefix: string;
  pathStyle: boolean;
}

export interface SyncConfig {
  backend: SyncBackend;
  /** An `s3_access_key` credential. */
  credentialId: string;
  /** 5..=1440, or null = manual only. */
  intervalMinutes: number | null;
}

export type SyncRunState = "disabled" | "idle" | "running" | "error" | "fork" | "rollback";

export type SyncConflictKind = "folder" | "connection" | "credential";
export type SyncResolution =
  | { type: "keptBoth"; copyId: string }
  | { type: "keptEdit" }
  | { type: "lastWriterWins" };
export interface SyncConflict {
  kind: SyncConflictKind;
  id: string;
  name: string;
  resolution: SyncResolution;
}

export type SyncOutcome =
  | { type: "pushed"; counter: number }
  | { type: "pulled"; counter: number }
  | { type: "merged"; counter: number; conflicts: SyncConflict[] }
  | { type: "noChange"; counter: number };

export type SyncAlarm = { type: "fork"; remote: number } | { type: "rollback"; remote: number; last: number };

/** `sync_status` and the payload of the `sync:status` event. Times are unix seconds. */
export interface SyncStatus {
  state: SyncRunState;
  config: SyncConfig | null;
  /** What a joining device enters. */
  vaultId: string;
  deviceId: string | null;
  /** Last generation seen or written; 0 = never. */
  counter: number;
  remoteCounter: number | null;
  remoteDevice: string | null;
  remoteCreatedUnix: number | null;
  lastPullUnix: number | null;
  lastPushUnix: number | null;
  lastRunUnix: number | null;
  lastOutcome: SyncOutcome | null;
  /** `http.trust_prompt` = a background run met an unpinned certificate; `sync_now` asks. */
  lastError: { code: string; message: string } | null;
  alarm: SyncAlarm | null;
  /** Of the last merge, kept until the next merge. */
  conflicts: SyncConflict[];
  nextRunUnix: number | null;
}

export type SyncStatusHandler = (status: SyncStatus) => void;

export interface VaultJoin {
  backend: SyncBackend;
  /** The `s3_access_key` in the bootstrap vault. */
  credentialId: string;
  /** `sync_status.vaultId` of a synced device. */
  vaultId: string;
  /** Master password of the synced vault. Inward only. */
  password: string;
  intervalMinutes: number | null;
}

export interface SyncIpc {
  /** Probes the backend (native trust prompt if needed) and stores the config. */
  syncConfigure(args: SyncConfig): Promise<SyncConfig>;
  /** Passive (POLLED_COMMANDS). */
  syncStatus(): Promise<SyncStatus>;
  syncNow(): Promise<SyncOutcome>;
  /** Rust asks for a native confirmation first; cancelling returns `sync.cancelled`. */
  syncResolveFork(args: { keep: "local" | "remote" }): Promise<SyncOutcome>;
  syncDisable(args: { deleteRemote: boolean }): Promise<void>;
  /** Fresh device only: bootstrap vault + `s3_access_key` first; the synced password unlocks afterwards. */
  vaultJoin(args: VaultJoin): Promise<VaultStatus>;
  /** `sync:status` event: the full status whenever it changes. Returns unsubscribe. */
  onSyncStatus(handler: SyncStatusHandler): () => void;
}
