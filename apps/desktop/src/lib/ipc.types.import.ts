// DTOs of the ADR-0019 import commands as rust-core I1 ships them (docs/handoff/a4-rust-core-i1.md,
// "UI contract"). Names only cross the IPC: a credential says `hasSecret`, never a secret; a
// source is a `pickId` from the Rust-side dialog or a known location, never a path; the file's
// bytes never reach the WebView (I1 deviation from ADR §3, kept on purpose).
import type { Protocol } from "./ipc.types";

/** Wire names of the six file importers (`ImportFormat` in `mooring-import`). */
export type ImportFormat = "royal_ts" | "rdm" | "termius" | "mremoteng" | "putty" | "openssh";
export const IMPORT_FORMATS: readonly ImportFormat[] = ["royal_ts", "rdm", "termius", "mremoteng", "putty", "openssh"];

/** Locations Rust reads without a pick: `~/.ssh/config`, `~/.putty/sessions/`. */
export type KnownLocation = "openssh" | "putty";

export interface ImportFormatInfo {
  format: ImportFormat;
  label: string;
  /** Picker filter; empty for a format that only has a known location. */
  extensions: string[];
  knownLocation: KnownLocation | null;
  /** The plaintext-secret opt-in applies (Termius, OpenSSH key files). */
  secretsPossible: boolean;
}

/** `import_pick` result: the dialog's choice, held in Rust under the `"import"` pick session. */
export interface ImportPick {
  pickId: string;
  fileName: string;
  /** Bytes on disk, for the wizard's caption only. */
  size: number;
}

export type ImportSource = { pickId: string } | { known: KnownLocation };

export interface ImportPreviewArgs {
  source: ImportSource;
  /** Owner decision 16: carry a plaintext secret the source documents as such. Off by default. */
  includePlaintextSecrets: boolean;
  /** ADR-0019 §3: read OpenSSH `IdentityFile`s under `~/.ssh/` into `ssh_key` credentials. */
  importKeyFiles: boolean;
}

export type ImportSkipReason = "unsupported" | "invalid" | "encrypted" | "key_unreadable" | "duplicate" | "limit";

export type ImportWarningCode =
  | "host_pattern"
  | "match_block"
  | "include_ignored"
  | "proxy_jump"
  | "ppk_key"
  | "password_dropped"
  | "secret_encrypted"
  | "tags_truncated"
  | "port_ignored"
  | "user_ignored"
  | "notes_truncated";

/** One folder or connection of the dry run; `parent` null = directly under the import root. */
export interface ImportItem {
  key: string;
  parent: string | null;
  kind: "folder" | "connection";
  name: string;
  protocol?: Protocol;
  host?: string;
  port?: number;
  username?: string;
  credentialKey?: string;
  /** Existing connection id with the same protocol, host, port and user. */
  duplicateOf?: string;
}

export interface ImportCredentialItem {
  key: string;
  name: string;
  /** A credential kind of ADR-0009 (`prompt`, `user_password`, `ssh_key`, `ssh_agent`, ...). */
  kind: string;
  /** A plaintext secret rides with it (never the secret itself). */
  hasSecret: boolean;
}

export interface ImportCounts {
  folders: number;
  connections: number;
  credentials: number;
  secrets: number;
  skipped: number;
  warnings: number;
}

export interface ImportSkipped {
  /** A positional reference (line, element ordinal), never file content. */
  sourceRef: string;
  reason: ImportSkipReason;
}

export interface ImportWarning {
  code: ImportWarningCode;
  sourceRef: string;
}

export interface ImportPreview {
  /** Single use, 10 minutes, dropped on lock (`import.plan_expired` afterwards). */
  planId: string;
  format: ImportFormat;
  /** "Imported from <format> (<date>)": the new root folder of the apply. */
  rootName: string;
  counts: ImportCounts;
  items: ImportItem[];
  credentials: ImportCredentialItem[];
  skipped: ImportSkipped[];
  warnings: ImportWarning[];
}

export type DuplicatePolicy = "skip" | "import";

export interface ImportApplyArgs {
  planId: string;
  /** Plan keys left out: an excluded folder lifts its subtree, an excluded credential unlinks. */
  exclude: string[];
  duplicates?: DuplicatePolicy;
}

export interface ImportReport {
  rootFolderId: string;
  folders: number;
  connections: number;
  credentials: number;
  secrets: number;
  /** Skipped by the parser, excluded here, or duplicates left out. */
  skipped: number;
}

/** ADR-0019 §5 (I1): formats, the Rust-side pick dialog, preview → apply, discard. */
export interface ImportIpc {
  /** Static; not vault-gated. */
  importFormats(): Promise<ImportFormatInfo[]>;
  /** Opens the native file dialog with the format's extension filter; null = cancelled. */
  importPick(args: { format: ImportFormat }): Promise<ImportPick | null>;
  importPreview(args: ImportPreviewArgs): Promise<ImportPreview>;
  importApply(args: ImportApplyArgs): Promise<ImportReport>;
  importDiscard(args: { planId: string }): Promise<void>;
}
