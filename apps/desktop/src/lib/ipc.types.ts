// DTOs of the ADR-0008 IPC contract, as the UI sees them (after wire decoding in ipc.ts).
// Nothing here ever carries a secret outward: credentials are metadata + ids only.
import type { ProtocolName } from "@mooring/ui";

export type Protocol = ProtocolName;
export type VaultStatus = "missing" | "locked" | "unlocked";
export type LockReason = "user" | "idle" | "screen_lock" | "sleep";

export interface AppInfo {
  name: string;
  version: string;
  os: string;
  arch: string;
  debug: boolean;
}

export interface Folder {
  id: string;
  parentId: string | null;
  name: string;
  defaultCredentialId: string | null;
  sort: number;
}

export interface ConnectionSummary {
  id: string;
  folderId: string;
  name: string;
  protocol: Protocol;
  host: string;
  port: number | null;
  credentialId: string | null;
  effectiveCredentialId: string | null;
  tags: string[];
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
  tags: string[];
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

export type CredentialKind = "password" | "ssh_key" | "certificate";

export interface CredentialMeta {
  id: string;
  name: string;
  kind: CredentialKind;
  username: string;
  createdAt: string;
  updatedAt: string;
}

/** Inward only. The caller must drop its copy of `secret`/`secret2` once the promise settles. */
export interface CredentialCreate {
  name: string;
  kind: CredentialKind;
  username: string;
  secret: string;
  secret2: string | null;
}

export interface Size {
  width: number;
  height: number;
}

export type SessionEvent =
  | { kind: "connected"; protocol: Protocol; peerIdentity: string | null }
  | { kind: "bytes"; data: Uint8Array }
  | { kind: "frame"; x: number; y: number; width: number; height: number; rgba: Uint8Array }
  | { kind: "prompt"; id: number; message: string; secret: boolean }
  | { kind: "closed"; reason: string };

export type SessionInput =
  | { kind: "bytes"; data: Uint8Array }
  | { kind: "resize"; size: Size }
  | { kind: "answer"; id: number; text: string }
  | { kind: "pointer"; x: number; y: number; buttons: number }
  | { kind: "key"; scancode: number; pressed: boolean };

export type SessionEventHandler = (event: SessionEvent) => void;

export interface SessionInfo {
  sessionId: string;
  connectionId: string;
  protocol: Protocol;
  state: string;
  openedAt: string;
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

/** Every command of ADR-0008 (plus A0 vault/app commands and `window_detach`). */
export interface Ipc {
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

  credentialList(): Promise<CredentialMeta[]>;
  credentialCreate(args: CredentialCreate): Promise<CredentialMeta>;
  credentialUpdateMeta(args: { id: string; name: string; username: string }): Promise<CredentialMeta>;
  credentialReplaceSecret(args: { id: string; secret: string; secret2: string | null }): Promise<void>;
  credentialDelete(args: { id: string }): Promise<void>;
  credentialCopyPassword(args: { id: string }): Promise<{ clearsInMs: number }>;

  sessionOpen(args: { connectionId: string; size: Size; onEvent: SessionEventHandler }): Promise<{ sessionId: string }>;
  sessionSend(args: { sessionId: string; input: SessionInput }): Promise<void>;
  sessionClose(args: { sessionId: string }): Promise<void>;
  sessionList(): Promise<SessionInfo[]>;

  auditTail(args: { limit: number; before: number | null }): Promise<AuditEntry[]>;
  auditVerify(): Promise<AuditVerify>;

  /** Not in ADR-0008 yet: moves a live session into its own window (rust-core to add). */
  windowDetach(args: { sessionId: string }): Promise<void>;
}
