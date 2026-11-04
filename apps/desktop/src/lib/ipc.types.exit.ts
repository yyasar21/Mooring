// DTOs of the ADR-0010 IPC contract (A1 exit): forwarding, SFTP, auto-lock, syslog mirror.
// Same conventions as ADR-0008: camelCase on the wire, `IpcError` on failure, no secrets outward.

// ---------- port forwarding ----------
import type { PodForwardOpen, PodTarget } from "./ipc.types.kube";

export type ForwardKind = "local" | "remote" | "dynamic";
export type Exposure = "loopback" | "external";

export interface HostPort {
  host: string;
  port: number;
}

export interface ForwardOpen {
  sessionId: string;
  kind: ForwardKind;
  bind: HostPort;
  /** Required for `local` and `remote`; absent (null) for `dynamic` (SOCKS5). */
  target: HostPort | null;
  exposure: Exposure;
}

/** `pod` (ADR-0014) runs on a Kubernetes cluster session, the others on SSH sessions. */
export type AnyForwardKind = ForwardKind | "pod";

export interface ForwardInfo {
  id: string;
  kind: AnyForwardKind;
  /** The address actually bound: port 0 in the request comes back resolved. */
  bind: HostPort;
  target: HostPort | PodTarget | null;
  exposure: Exposure;
  openedAt: string;
  /** Live connections through this forward right now. */
  connections: number;
}

/** Crate bounds (ADR-0010 / mooring-proto-ssh). */
export const FORWARD_LIMITS = { perSession: 64, connectionsPerForward: 128 } as const;

// ---------- SFTP ----------

export type EntryKind = "file" | "dir" | "symlink" | "other";

export interface SftpEntry {
  name: string;
  kind: EntryKind;
  size: number;
  /** Seconds since the Unix epoch; null when the server did not send it. */
  mtime: number | null;
  /** Permission bits (`mode & 0o7777`); null when unknown. */
  mode: number | null;
}

export interface SftpListing {
  entries: SftpEntry[];
  /** The server had more than 10 000 entries; the list is cut. */
  truncated: boolean;
}

export type TransferState = "running" | "done" | "failed" | "cancelled";

export interface TransferProgress {
  transferId: string;
  bytesDone: number;
  bytesTotal: number | null;
  state: TransferState;
  error: string | null;
}

export type ProgressHandler = (p: TransferProgress) => void;

/** What the native dialog opened by Rust should pick (ADR-0010, review 4 B-4). */
export type PickMode = "folder" | "file";

/**
 * A local file or folder the user chose in the native dialog. Rust keeps the path; the UI only
 * ever sees an opaque, single-use, session-bound `pickId` and the display `name`.
 */
export interface LocalPick {
  pickId: string;
  name: string;
}

// ---------- auto-lock ----------

export interface AutoLockPolicy {
  /** Lock after this many idle minutes; null = never. */
  idleMinutes: number | null;
  onScreenLock: boolean;
  onSleep: boolean;
  onWindowHidden: boolean;
}

/** UI bounds for the idle timeout (one minute to one day). */
export const IDLE_MINUTES = { min: 1, max: 1440 } as const;

// ---------- syslog mirror ----------

export type SyslogTransport = "udp" | "tcp" | "tls";

/** RFC 5424 facility keywords, in code order (0..23). */
export const SYSLOG_FACILITIES = [
  "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
  "uucp", "cron", "authpriv", "ftp", "ntp", "security", "console", "solaris-cron",
  "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
] as const;
export type SyslogFacility = (typeof SYSLOG_FACILITIES)[number];

export interface SyslogConfig {
  host: string;
  port: number;
  transport: SyslogTransport;
  facility: SyslogFacility;
  enabled: boolean;
}

export interface SyslogTestResult {
  ok: boolean;
  error: string | null;
}

/** IANA defaults per transport (RFC 5426 / 6587 / 5425). */
export const SYSLOG_DEFAULT_PORT: Record<SyslogTransport, number> = { udp: 514, tcp: 601, tls: 6514 };

// ---------- commands ----------

export interface ExitIpc {
  forwardOpen(args: ForwardOpen | PodForwardOpen): Promise<ForwardInfo>;
  forwardClose(args: { sessionId: string; forwardId: string }): Promise<void>;
  forwardList(args: { sessionId: string }): Promise<ForwardInfo[]>;

  sftpList(args: { sessionId: string; path: string }): Promise<SftpListing>;
  sftpStat(args: { sessionId: string; path: string }): Promise<SftpEntry>;
  sftpMkdir(args: { sessionId: string; path: string }): Promise<void>;
  sftpRename(args: { sessionId: string; from: string; to: string }): Promise<void>;
  sftpRemove(args: { sessionId: string; path: string }): Promise<void>;
  /** Rust opens the native dialog; null = the user cancelled. Local paths never cross IPC. */
  sftpPickLocal(args: { sessionId: string; mode: PickMode }): Promise<LocalPick | null>;
  /** `pick` is a folder `pickId`. An existing target is refused with `sftp.exists` unless `overwrite`. */
  sftpDownload(args: { sessionId: string; remote: string; pick: string; overwrite?: boolean; onProgress: ProgressHandler }): Promise<{ transferId: string }>;
  /** `pick` is a file `pickId`. */
  sftpUpload(args: { sessionId: string; pick: string; remoteDir: string; onProgress: ProgressHandler }): Promise<{ transferId: string }>;
  /** Running transfers of the session, to re-adopt them after an unlock (M-10). */
  sftpTransfers(args: { sessionId: string }): Promise<TransferProgress[]>;
  sftpCancel(args: { sessionId: string; transferId: string }): Promise<void>;

  autolockGet(): Promise<AutoLockPolicy>;
  autolockSet(policy: AutoLockPolicy): Promise<AutoLockPolicy>;

  syslogGet(): Promise<SyslogConfig | null>;
  syslogSet(config: SyslogConfig): Promise<SyslogConfig>;
  syslogTest(): Promise<SyslogTestResult>;
}
