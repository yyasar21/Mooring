// Plain-English text of the import wizard: what each source tile is, what a skip reason or a
// warning code means, how a file size reads. Nothing here names a path from the user's machine.
import type { ImportFormat, ImportSkipReason, ImportWarningCode, KnownLocation } from "../../lib/ipc";

/** The source tiles, in display order; the LDAPS tile is the I2 extension point (disabled here). */
export type SourceId = ImportFormat | "ldaps";

export interface SourceTile {
  id: SourceId;
  label: string;
  /** What the user exports, in the tool's own words. */
  hint: string;
}

export const SOURCE_TILES: readonly SourceTile[] = [
  { id: "royal_ts", label: "Royal TS", hint: "A document saved as .rtsx or .rtsz" },
  { id: "rdm", label: "Remote Desktop Manager", hint: "An .rdm or XML export" },
  { id: "termius", label: "Termius", hint: "A CSV or JSON export" },
  { id: "mremoteng", label: "mRemoteNG", hint: "The confCons.xml file" },
  { id: "putty", label: "PuTTY", hint: "A .reg export of the sessions" },
  { id: "openssh", label: "OpenSSH config", hint: "Host entries of an ssh config file" },
  { id: "ldaps", label: "Directory (LDAPS)", hint: "Computers from Active Directory" },
];

/** The shortcut under a tile whose format has a known location. */
export const KNOWN_LOCATION_TEXT: Record<KnownLocation, { button: string; where: string }> = {
  openssh: { button: "Import from ~/.ssh/config", where: "~/.ssh/config" },
  putty: { button: "Import from ~/.putty/sessions", where: "~/.putty/sessions" },
};

export const SKIP_REASON_TEXT: Record<ImportSkipReason, string> = {
  unsupported: "a kind of connection Mooring has no model for",
  invalid: "a name, host or port that failed validation",
  encrypted: "an encrypted value Mooring does not decrypt",
  key_unreadable: "a key file that is missing, outside ~/.ssh, too large or not an OpenSSH key",
  duplicate: "already in the vault",
  limit: "past an import limit",
};

export const WARNING_TEXT: Record<ImportWarningCode, string> = {
  host_pattern: "Host entries with wildcards or negation were left out; only literal aliases import.",
  match_block: "Match blocks were ignored.",
  include_ignored: "Include directives were not followed; import those files separately.",
  proxy_jump: "ProxyJump was kept as a jump: tag; Mooring has no jump-host setting yet.",
  ppk_key: "A PuTTY key file (.ppk) was referenced but not read. Convert it to OpenSSH format and add it to the credential.",
  password_dropped: "A stored password was not imported; you will be asked for it at connect.",
  secret_encrypted: "An encrypted password was left behind; Mooring never decrypts another tool's store.",
  tags_truncated: "More than 50 tags on an item; the rest were dropped.",
  port_ignored: "A port outside 1–65535; the protocol default is used.",
  user_ignored: "A user name or domain that failed validation was dropped.",
  notes_truncated: "The lists of skipped items and warnings hit their cap; the counts are complete, the lists are not.",
};

/** "1.3 KB", "48 KB", "2.1 MB": enough for a caption. */
export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** Group warnings by code, keeping the first order of appearance. */
export function groupWarnings(list: readonly { code: ImportWarningCode; sourceRef: string }[]): { code: ImportWarningCode; refs: string[] }[] {
  const out: { code: ImportWarningCode; refs: string[] }[] = [];
  for (const w of list) {
    const hit = out.find((g) => g.code === w.code);
    if (hit) hit.refs.push(w.sourceRef);
    else out.push({ code: w.code, refs: [w.sourceRef] });
  }
  return out;
}

export const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
