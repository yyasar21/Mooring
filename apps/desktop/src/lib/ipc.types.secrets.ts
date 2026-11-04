// DTOs of the ADR-0016 (external secrets: Vault / OpenBao KV v2) and ADR-0017 (vault sync to
// S3-compatible storage) IPC contracts. Secrets cross inward only (S3 secret key, vault password
// on `vault_join`); nothing returned here carries a secret value or a token.
// Shapes marked ASSUMED are not spelled out in the ADRs; see docs/handoff/a3-ui-u1.md.
import type { CredentialKind, VaultStatus } from "./ipc.types";

// ---------- secret sources (ADR-0016) ----------

export type SecretAuthMethod = "token" | "approle" | "oidc";
export const SECRET_AUTH_METHODS: readonly SecretAuthMethod[] = ["token", "approle", "oidc"];

export interface SecretSourceOptions {
  caPem: string | null;
  /** http only for 127.0.0.1 / [::1]; audited. */
  allowHttp: boolean;
  /** Extra IdP origins for the OIDC window, ≤ 16. */
  allowedOrigins: string[];
}

export interface SecretSourceInput {
  name: string;
  address: string;
  namespace: string | null;
  authMethod: SecretAuthMethod;
  authMount: string;
  /** `api_token` (token) or `vault_approle` (approle); null for oidc. */
  credentialId: string | null;
  oidcRole: string | null;
  options: SecretSourceOptions;
}

/** ASSUMED: the row as `secret_source_list` returns it (the input plus id/kind/timestamps). */
export interface SecretSource extends SecretSourceInput {
  id: string;
  kind: "vault";
  createdAt: string;
  updatedAt: string;
}

export interface SecretSourceTest {
  ok: boolean;
  method: SecretAuthMethod;
  ttlSeconds: number | null;
  renewable: boolean;
  policiesCount: number;
  error: string | null;
}

/** ADR-0016 §2: kinds an `external_ref` may resolve into. */
export const EXTERNAL_TARGET_KINDS = [
  "user_password", "domain_user", "ssh_key", "x509", "api_token", "kube_token", "kubeconfig",
  "vsphere_user", "vnc_password", "vnc_user_password", "sudo_become",
] as const satisfies readonly CredentialKind[];
export type ExternalTargetKind = (typeof EXTERNAL_TARGET_KINDS)[number];

/** `external_ref` credential fields as amended by ADR-0016 §2 (no secrets). */
export interface ExternalRefFields {
  provider: "vault" | "onepassword" | "bitwarden";
  source: string;
  /** `<mount>/<path>`, segments `[A-Za-z0-9._-]+`, ≤ 1 KiB. */
  reference: string;
  target_kind: ExternalTargetKind;
  version: number | null;
  fieldMap: Record<string, string> | null;
}

export interface ExternalRefTest {
  ok: boolean;
  version: number | null;
  /** KV key names only, never values. */
  present: string[];
  missing: string[];
  error: string | null;
}

/** ASSUMED: OIDC window lifecycle (ADR-0016 §4 names no commands for it). */
export type OidcState = "idle" | "waiting" | "done" | "failed" | "timeout";
export interface OidcStatus {
  state: OidcState;
  error: string | null;
}

export interface SecretsIpc {
  secretSourceList(): Promise<SecretSource[]>;
  secretSourceCreate(args: SecretSourceInput): Promise<SecretSource>;
  secretSourceUpdate(args: SecretSourceInput & { id: string }): Promise<SecretSource>;
  /** `source.in_use` while an external_ref uses it. */
  secretSourceDelete(args: { id: string }): Promise<void>;
  secretSourceTest(args: { id: string }): Promise<SecretSourceTest>;
  secretSourceLogout(args: { id: string }): Promise<void>;
  externalRefTest(args: { credentialId: string }): Promise<ExternalRefTest>;
  /** ASSUMED: opens `oidc-<sourceId>`; Rust intercepts the redirect. */
  secretSourceOidcStart(args: { id: string }): Promise<{ windowLabel: string }>;
  /** ASSUMED. */
  secretSourceOidcStatus(args: { id: string }): Promise<OidcStatus>;
}

// ---------- vault sync (ADR-0017) ----------

export interface SyncSettings {
  endpoint: string;
  bucket: string;
  prefix: string;
  region: string;
  pathStyle: boolean;
  /** An `s3_access_key` credential. */
  credentialId: string;
  options: { caPem: string | null };
}

/** ASSUMED: `SyncConfig` = the settings plus the device id. */
export interface SyncConfig extends SyncSettings {
  deviceId: string;
}

export type SyncConflictKind = "folder" | "connection" | "credential" | "secret_source" | "trust";
export interface SyncConflict {
  kind: SyncConflictKind;
  id: string;
  name: string;
}

/** ASSUMED values of `state`. */
export type SyncRunState = "idle" | "pulling" | "pushing" | "merging" | "error" | "rollback" | "fork" | "disabled";

export interface SyncStatus {
  lastPull: string | null;
  lastPush: string | null;
  counter: number;
  state: SyncRunState;
  /** ASSUMED: the conflict list of the last merge (the ADR does not say list or count). */
  conflicts: SyncConflict[];
}

export interface SyncReport {
  pulled: boolean;
  pushed: boolean;
  merged: boolean;
  conflicts: SyncConflict[];
}

export interface VaultJoin {
  endpoint: string;
  bucket: string;
  prefix: string;
  region: string;
  accessKeyId: string;
  /** Inward only. */
  secretAccessKey: string;
  /** Inward only. */
  password: string;
}

export interface SyncIpc {
  syncGet(): Promise<SyncConfig | null>;
  /** Passive (POLLED_COMMANDS). */
  syncStatus(): Promise<SyncStatus>;
  syncSet(args: SyncSettings): Promise<SyncConfig>;
  syncProbe(): Promise<{ conditionalWrites: boolean; error: string | null }>;
  syncNow(): Promise<SyncReport>;
  syncDisable(args: { deleteRemote: boolean }): Promise<void>;
  vaultJoin(args: VaultJoin): Promise<VaultStatus>;
}
