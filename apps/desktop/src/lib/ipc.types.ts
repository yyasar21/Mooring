// DTOs of the ADR-0008 IPC contract, as the UI sees them (after wire decoding in ipc.ts).
// Nothing here ever carries a secret outward: credentials are metadata + ids only.
import type { ProtocolName } from "@mooring/ui";
import type { ExitIpc } from "./ipc.types.exit";
import type { CertificateInfo, CloseCode, FrameHandler, ProtocolOptions, RemoteIpc } from "./ipc.types.remote";
import type { KubeExecTarget, KubeIpc } from "./ipc.types.kube";
import type { SyncedRowFlags, SyncState, VsphereIpc } from "./ipc.types.vsphere";
import type { SecretsIpc, SyncIpc } from "./ipc.types.secrets";
import type { UpdateIpc } from "./ipc.types.update";
import type { NetIpc } from "./ipc.types.net";
import type { ImportIpc } from "./ipc.types.import";
import type { A5Ipc, BuildChannel, HopStatus } from "./ipc.types.a5";

export * from "./ipc.types.exit";
export * from "./ipc.types.remote";
export * from "./ipc.types.kube";
export * from "./ipc.types.vsphere";
export * from "./ipc.types.secrets";
export * from "./ipc.types.update";
export * from "./ipc.types.net";
export * from "./ipc.types.import";
export * from "./ipc.types.a5";

export type Protocol = ProtocolName;
export type VaultStatus = "missing" | "locked" | "unlocked";
/** ADR-0006 audit reasons; also the payload of the `vault:locked` UI event (ADR-0010). */
export type LockReason = "user" | "idle" | "screen_lock" | "sleep" | "window_hidden";
export const LOCK_REASONS: readonly LockReason[] = ["user", "idle", "screen_lock", "sleep", "window_hidden"];

/** `unknown` = the backend sent a reason this build does not know; the lock still applies. */
export type VaultLockedHandler = (event: { reason: LockReason | "unknown" }) => void;

export interface AppInfo {
  name: string;
  version: string;
  os: string;
  arch: string;
  debug: boolean;
  /** ADR-0021 §1: the `Mooring Data` folder of a portable build (next to the marker), null when installed. */
  portableDataDir: string | null;
  /** ADR-0028: `dev` = Mooring Dev (own identifier and data); absent from builds before A5 = release. */
  channel?: BuildChannel;
  identifier?: string;
}

export interface Folder extends SyncedRowFlags {
  id: string;
  parentId: string | null;
  name: string;
  defaultCredentialId: string | null;
  sort: number;
}

export interface ConnectionSummary extends SyncedRowFlags {
  id: string;
  folderId: string;
  name: string;
  protocol: Protocol;
  host: string;
  port: number | null;
  credentialId: string | null;
  effectiveCredentialId: string | null;
  /** ADR-0009 §3: replaces the effective credential's username/user for this connection only. */
  usernameOverride: string | null;
  domainOverride: string | null;
  /** Secondary roles (per connection, no inheritance). Gateway null = same as the session credential. */
  gatewayCredentialId: string | null;
  becomeCredentialId: string | null;
  tags: string[];
  /** ADR-0011 per-protocol options; absent from a backend without migration 0005. */
  options?: ProtocolOptions;
  /** ADR-0015 (V2): only on VM rows inside a synced subtree; `missing` = not reported by vCenter. */
  syncState?: SyncState | null;
  /** ADR-0025: SSH jump hosts, first hop first (≤ 3). Absent from a backend before A5 = none. */
  via?: string[];
  createdAt: string;
  updatedAt: string;
}

/** Fields shared by `connection_create` and `connection_update`. */
export interface ConnectionFields {
  folderId: string;
  name: string;
  protocol: Protocol;
  host: string;
  port: number | null;
  credentialId: string | null;
  usernameOverride: string | null;
  domainOverride: string | null;
  gatewayCredentialId: string | null;
  becomeCredentialId: string | null;
  tags: string[];
  /** Omitted = leave the stored options unchanged (update) or `{}` (create). */
  options?: ProtocolOptions;
  /** ADR-0025: omitted on update keeps the stored chain; `[]` clears it. */
  via?: string[];
}

export interface ConnectionHit {
  id: string;
  name: string;
  host: string;
  folderId: string;
  protocol: Protocol;
}

export interface TreeSnapshot {
  folders: Folder[];
  connections: ConnectionSummary[];
}

/** ADR-0009 §1: the closed set of credential kinds (wire names). Kind is immutable after creation. */
export const CREDENTIAL_KINDS = [
  "user_password",
  "domain_user",
  "ssh_key",
  "ssh_agent",
  "x509",
  "api_token",
  "oauth_client",
  "kubeconfig",
  "kube_token",
  "vsphere_user",
  "vnc_password",
  "vnc_user_password",
  "prompt",
  "external_ref",
  "sudo_become",
  // ADR-0016 §1 / ADR-0017 §4: consumer-only kinds (no protocol).
  "vault_approle",
  "s3_access_key",
] as const;
export type CredentialKind = (typeof CREDENTIAL_KINDS)[number];

export type KindGroup = "Windows" | "SSH" | "VNC" | "Web/API" | "Kubernetes" | "vSphere" | "Other" | "Secret sources" | "Sync";
/** ADR-0016/0017: non-protocol uses of a credential (a Vault login, the sync access key). */
export type KindConsumer = "secret_source" | "sync";
export type CredentialRole = "primary" | "gateway" | "become";
export type FieldFormat = "text" | "pem" | "base32" | "yaml" | "url" | "netbios_or_upn" | "upn" | "enum";

export interface FieldValidation {
  maxBytes: number;
  format: FieldFormat;
  options?: string[];
  pattern?: string;
}

export interface FieldSchema {
  name: string;
  label: string;
  secret: boolean;
  required: boolean;
  multiline: boolean;
  placeholder: string;
  /** Secret fields only: `credential_copy_secret` accepts this name. */
  copyable: boolean;
  validation: FieldValidation;
}

export interface KindProtocol {
  protocol: Protocol;
  roles: CredentialRole[];
}

/** `credential_kinds()`: the schema every credential form is rendered from (ADR-0009 §6). */
/** Derived values (`fingerprint`, `contexts`) are not fields: they arrive on `CredentialMeta`. */
export interface KindSchema {
  kind: CredentialKind;
  label: string;
  group: KindGroup;
  protocols: KindProtocol[];
  /** Omitted on the wire when empty. */
  consumers?: KindConsumer[];
  supportsOtp: boolean;
  fields: FieldSchema[];
}

export type OtpDigits = 6 | 8;
export type OtpPeriod = 30 | 60;
export type OtpAlgorithm = "sha1" | "sha256" | "sha512";
export interface OtpSettings {
  digits: OtpDigits;
  period: OtpPeriod;
  algorithm: OtpAlgorithm;
}

/**
 * Non-secret field values. `otp` holds the TOTP parameters; `contexts` is derived (names only);
 * `external_ref` stores `version` as a number and `field_map` as name → KV key (ADR-0016 §2).
 */
export type FieldValue = string | number | string[] | OtpSettings | Record<string, string>;

/** The `otp` field value (other object values are the `external_ref` field map). */
export function isOtpSettings(v: unknown): v is OtpSettings {
  return typeof v === "object" && v !== null && !Array.isArray(v) && typeof (v as { period?: unknown }).period === "number";
}
export type CredentialFields = Record<string, FieldValue>;

export interface CredentialMeta {
  id: string;
  name: string;
  kind: CredentialKind;
  fields: CredentialFields;
  /** Which secrets are stored. Presence only; a value never crosses outward. */
  secretNames: string[];
  /** `SHA256:…` for ssh_key / x509, else null. */
  fingerprint: string | null;
  createdAt: string;
  updatedAt: string;
}

/** Inward only. The caller must drop its copy of `secrets` once the promise settles. */
export interface CredentialCreate {
  name: string;
  kind: CredentialKind;
  fields: CredentialFields;
  secrets: Record<string, string>;
}

export interface CredentialReplaceSecrets {
  id: string;
  set: Record<string, string>;
  clear: string[];
}

export type AccountForm = "netbios" | "upn";
export interface ParsedAccount {
  form: AccountForm;
  user: string;
  domain: string;
}

export interface Size {
  width: number;
  height: number;
}

/** Why a prompt was raised; set by Rust, never derived from server text (review 2, L-2). */
export type PromptPurpose = "host_key_trust" | "certificate_trust" | "keyboard_interactive" | "credential" | "other";

/**
 * `purpose: "credential"` only (ADR-0009 `prompt` kind): what the connect-time form should ask.
 * `username`/`domain` are pre-fills from the credential fields or connection overrides.
 */
export interface PromptAccount {
  username: string | null;
  domain: string | null;
  needsUsername: boolean;
  needsDomain: boolean;
}

/**
 * ADR-0011: `frame` is gone (pixels use the MFR1 `onFrame` channel), `closed` carries a code,
 * `connected` the negotiated security, and RDP/VNC add `desktop_resized` and `reconnecting`.
 * `detached` (ADR-0013) tells this view another window took the session over; `attached` tells
 * `main` the session came back (window_attach or the detached window closed): call
 * `session_attach` again with fresh channels.
 */
export type SessionEvent =
  | { kind: "connected"; protocol: Protocol; peerIdentity: string | null; security: string | null }
  | { kind: "bytes"; data: Uint8Array }
  | {
      kind: "prompt";
      id: number;
      message: string;
      secret: boolean;
      purpose: PromptPurpose;
      account: PromptAccount | null;
      certificate: CertificateInfo | null;
      /** ADR-0025: the 0-based jump host that asks; absent/null = the target. */
      hop?: number | null;
    }
  | ({ kind: "hop_status" } & HopStatus)
  | { kind: "desktop_resized"; width: number; height: number }
  | { kind: "reconnecting"; attempt: number; delayMs: number }
  | { kind: "detached" }
  | { kind: "attached" }
  | { kind: "closed"; reason: string; code: CloseCode | "unknown" };

export type SessionInput =
  | { kind: "bytes"; data: Uint8Array }
  | { kind: "resize"; size: Size }
  | { kind: "answer"; id: number; text: string }
  /** Answer to a `credential` prompt. Inward only; Rust holds `password` as a SecretString. */
  | { kind: "credential_answer"; id: number; username: string; domain: string | null; password: string }
  /** Framebuffer pixels; `buttons` uses POINTER_BUTTON bits (not the DOM order). */
  | { kind: "pointer"; x: number; y: number; buttons: number }
  /** `code` = KeyboardEvent.code (≤ 32 ASCII, layout independent), `key` = KeyboardEvent.key (≤ 32 B). */
  | { kind: "key"; code: string; key: string; pressed: boolean }
  /** 120 per notch, DOM sign: dy > 0 scrolls down, dx > 0 scrolls right. */
  | { kind: "wheel"; dx: number; dy: number }
  /** Text the IME composed, ≤ 64 chars per message. */
  | { kind: "unicode"; text: string }
  | { kind: "release_all" }
  /** Rust reads the OS clipboard itself and announces it; the text never crosses IPC. */
  | { kind: "clipboard_offer" };

export type SessionEventHandler = (event: SessionEvent) => void;

export interface SessionInfo {
  sessionId: string;
  connectionId: string;
  protocol: Protocol;
  state: string;
  openedAt: string;
  /** ASSUMED (ADR-0014): kubernetes sessions say whether they are a cluster handle or an exec shell. */
  kube?: { parentSessionId: string | null };
}

export interface AuditEntry {
  seq: number;
  at: string;
  prev: string;
  event: string;
  /** Remaining flattened fields of the event (ids, reasons, fingerprints — never secrets). */
  details: Record<string, string>;
}

export interface AuditVerify {
  ok: boolean;
  entries: number;
  brokenAt: number | null;
}

/** Every command of ADR-0008 … ADR-0020 (plus the A0 vault/app commands). */
export interface Ipc extends ExitIpc, RemoteIpc, KubeIpc, VsphereIpc, SecretsIpc, SyncIpc, UpdateIpc, NetIpc, ImportIpc, A5Ipc {
  appInfo(): Promise<AppInfo>;
  vaultStatus(): Promise<VaultStatus>;
  vaultCreate(password: string): Promise<VaultStatus>;
  vaultUnlock(password: string): Promise<VaultStatus>;
  vaultLock(reason: LockReason): Promise<VaultStatus>;
  vaultChangePassword(args: { current: string; next: string }): Promise<VaultStatus>;

  treeList(): Promise<TreeSnapshot>;
  folderCreate(args: { parentId: string; name: string }): Promise<Folder>;
  folderRename(args: { id: string; name: string }): Promise<Folder>;
  folderMove(args: { id: string; parentId: string }): Promise<Folder>;
  folderSetDefaultCredential(args: { id: string; credentialId: string | null }): Promise<Folder>;
  folderDelete(args: { id: string }): Promise<void>;
  connectionCreate(args: ConnectionFields): Promise<ConnectionSummary>;
  connectionUpdate(args: ConnectionFields & { id: string }): Promise<ConnectionSummary>;
  connectionMove(args: { id: string; folderId: string }): Promise<ConnectionSummary>;
  connectionDelete(args: { id: string }): Promise<void>;
  connectionSearch(args: { query: string; limit: number }): Promise<ConnectionHit[]>;

  connectionSetRoleCredential(args: {
    id: string;
    role: Exclude<CredentialRole, "primary">;
    credentialId: string | null;
  }): Promise<ConnectionSummary>;

  credentialKinds(): Promise<KindSchema[]>;
  credentialList(): Promise<CredentialMeta[]>;
  credentialCreate(args: CredentialCreate): Promise<CredentialMeta>;
  credentialUpdateFields(args: { id: string; name: string; fields: CredentialFields }): Promise<CredentialMeta>;
  credentialReplaceSecrets(args: CredentialReplaceSecrets): Promise<void>;
  credentialDelete(args: { id: string }): Promise<void>;
  /** Rust writes the clipboard, schedules the clear and audits `credential.copied {id, name}`. */
  credentialCopySecret(args: { id: string; name: string }): Promise<{ clearsInMs: number }>;
  /** Rust computes the current TOTP code and writes it to the clipboard; the code never comes back. */
  credentialCopyOtp(args: { id: string }): Promise<{ clearsInMs: number; validForMs: number }>;
  credentialParseAccount(args: { input: string }): Promise<ParsedAccount>;

  /** `onFrame` is required for rdp/vnc and refused for ssh (`input.invalid "onFrame"`). `kube` opens an exec shell (ADR-0014). */
  sessionOpen(args: { connectionId: string; size: Size; onEvent: SessionEventHandler; onFrame?: FrameHandler; kube?: KubeExecTarget }): Promise<{ sessionId: string }>;
  sessionSend(args: { sessionId: string; input: SessionInput }): Promise<void>;
  sessionClose(args: { sessionId: string }): Promise<void>;
  sessionList(): Promise<SessionInfo[]>;

  auditTail(args: { limit: number; before: number | null }): Promise<AuditEntry[]>;
  auditVerify(): Promise<AuditVerify>;

  /** ADR-0013: moves a live session into `detached-<sessionId>`; refused for web sessions. */
  windowDetach(args: { sessionId: string }): Promise<{ windowLabel: string }>;

  /** ADR-0010: the backend locked the vault on its own (idle, screen lock, ...). Returns unsubscribe. */
  onVaultLocked(handler: VaultLockedHandler): () => void;
}
