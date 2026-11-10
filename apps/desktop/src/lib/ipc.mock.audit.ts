// The mock side of the filtered `audit_tail` and `audit_export` (rust-core
// `commands/audit_query.rs` and `commands/audit_export.rs`, `a5-rust-core-audit-export.md`).
// Same rules as Rust: the filter is validated the same way, every detail is redacted as a
// rendered `key=value` line, the free text searches only those lines, one call tests at most
// `cap` candidate rows newest first, and the export writes the redacted rows oldest first,
// framed by a header (chain state) and a footer (row count).
import { IpcError } from "./ipc.error";
import type { AuditEntry, AuditVerify } from "./ipc.types";
import { MAX_FILTER_CONNECTION, MAX_FILTER_EVENTS, MAX_FILTER_TEXT, type AuditExportFormat, type AuditFilterInput, type AuditTailPage } from "./ipc.types.audit";

const REDACTED = "[REDACTED]";
/** `mooring_audit::redact` SECRET_KEYS. */
const SECRET_KEYS = ["password", "passwd", "pwd", "passphrase", "secret", "token", "api_key", "apikey", "private_key", "authorization", "cookie", "set-cookie", "x-api-key"];
const FILTER_KEYS = new Set(["events", "connection", "since", "until", "text"]);
const CONTROL = /\p{Cc}/u;

const isValueEnd = (c: string) => /\s/.test(c) || ",;&\"'}])".includes(c);

function redactPem(s: string): string {
  return s.replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*-----|$)/gi, "-----BEGIN PRIVATE KEY [REDACTED]-----");
}

function redactSchemes(s: string): string {
  let out = s;
  for (const scheme of ["Bearer ", "Basic ", "bearer ", "basic "]) {
    let cursor = 0;
    for (let i = out.indexOf(scheme, cursor); i >= 0; i = out.indexOf(scheme, cursor)) {
      const start = i + scheme.length;
      let end = start;
      while (end < out.length && !isValueEnd(out.charAt(end))) end += 1;
      if (end > start) out = out.slice(0, start) + REDACTED + out.slice(end);
      cursor = start + REDACTED.length;
    }
  }
  return out;
}

function redactKey(s: string, key: string): string {
  const lower = s.toLowerCase();
  let out = "";
  let last = 0;
  let cursor = 0;
  for (let k = lower.indexOf(key, cursor); k >= 0 && cursor < s.length; k = lower.indexOf(key, cursor)) {
    const kEnd = k + key.length;
    const beforeOk = k === 0 || !/[a-z0-9]/i.test(lower.charAt(k - 1));
    const after = s.slice(kEnd);
    const afterTrim = after.replace(/^["']+/, "");
    let valueStart: number | null = null;
    if (afterTrim.startsWith("=") || afterTrim.startsWith(":")) {
      const v = afterTrim.slice(1);
      const v2 = v.trimStart();
      const v3 = v2.replace(/^["']+/, "");
      valueStart = kEnd + (after.length - afterTrim.length) + 1 + (v.length - v2.length) + (v2.length - v3.length);
    }
    if (beforeOk && valueStart !== null && valueStart < s.length) {
      let ve = valueStart;
      while (ve < s.length && !isValueEnd(s.charAt(ve))) ve += 1;
      out += s.slice(last, valueStart) + REDACTED;
      last = ve;
      cursor = ve;
    } else {
      cursor = kEnd;
    }
  }
  return out + s.slice(last);
}

/** `mooring_audit::redact`: PEM private keys, `Bearer`/`Basic` values, secret-named `key=value`. */
export function redactText(input: string): string {
  let out = redactSchemes(redactPem(input));
  for (const key of SECRET_KEYS) out = redactKey(out, key);
  return out;
}

/** Each detail rendered as `key=value`, scrubbed, and taken back (`Redacted::parse`). */
export function redactEntry(e: AuditEntry): AuditEntry {
  const details: Record<string, string> = {};
  for (const [k, v] of Object.entries(e.details)) {
    const scrubbed = redactText(`${k}=${v}`);
    details[k] = scrubbed.startsWith(`${k}=`) ? scrubbed.slice(k.length + 1) : REDACTED;
  }
  return { ...e, details };
}

/** `key=value` per detail: what the free text searches and the CSV `details` column holds. */
export const renderedDetails = (e: AuditEntry): string[] => Object.entries(e.details).map(([k, v]) => `${k}=${v}`);

export interface CompiledFilter {
  events: Set<string> | null;
  connection: string | null;
  since: number | null;
  until: number | null;
  text: string | null;
}

const bad = (reason: string) => new IpcError("input.invalid", `invalid filter: ${reason}`);
const isMs = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;

/** `AuditFilter::compile`. `known` answers whether a name is an event wire tag. */
export function compileAuditFilter(input: AuditFilterInput | undefined, known: (name: string) => boolean): CompiledFilter {
  const none: CompiledFilter = { events: null, connection: null, since: null, until: null, text: null };
  if (input === undefined) return none;
  if (typeof input !== "object" || Object.keys(input).some((k) => !FILTER_KEYS.has(k))) throw bad("unknown field");
  const { events, connection, since, until, text } = input;
  let ev: Set<string> | null = null;
  if (events !== undefined && events.length > 0) {
    if (events.length > MAX_FILTER_EVENTS) throw bad("too many event names");
    if (!events.every((n) => typeof n === "string" && known(n))) throw bad("unknown event name");
    ev = new Set(events);
  }
  let conn: string | null = null;
  if (connection !== undefined && connection !== "") {
    if (new TextEncoder().encode(connection).length > MAX_FILTER_CONNECTION || CONTROL.test(connection)) throw bad("connection id");
    conn = connection;
  }
  if ((since !== undefined && !isMs(since)) || (until !== undefined && !isMs(until))) throw bad("time");
  if (since !== undefined && until !== undefined && since > until) throw bad("since is after until");
  let t: string | null = null;
  const trimmed = text?.trim() ?? "";
  if (trimmed !== "") {
    if (Array.from(trimmed).length > MAX_FILTER_TEXT) throw bad("text too long");
    if (CONTROL.test(trimmed)) throw bad("text");
    t = trimmed.toLowerCase();
  }
  return { events: ev, connection: conn, since: since ?? null, until: until ?? null, text: t };
}

export const isEmptyFilter = (f: CompiledFilter): boolean =>
  f.events === null && f.connection === null && f.since === null && f.until === null && f.text === null;

/** `AuditFilter::matches` on a redacted entry. Time compares `floor(at)` in milliseconds. */
export function auditMatches(e: AuditEntry, f: CompiledFilter): boolean {
  if (f.events && !f.events.has(e.event)) return false;
  if (f.connection !== null && e.details.connection !== f.connection) return false;
  const at = Math.floor(Date.parse(e.at));
  if (f.since !== null && !(at >= f.since)) return false;
  if (f.until !== null && !(at < f.until)) return false;
  const t = f.text;
  return t === null || renderedDetails(e).some((l) => l.toLowerCase().includes(t));
}

/** `scan_page`: `log` is oldest first, as stored. */
export function scanAuditPage(log: readonly AuditEntry[], f: CompiledFilter, limit: number, before: number | null, cap: number): AuditTailPage {
  const candidates = log.filter((e) => before === null || e.seq < before);
  const skip = Math.max(0, candidates.length - cap);
  const scanned = candidates.slice(skip);
  const window = scanned.map(redactEntry).filter((e) => auditMatches(e, f)).slice(-limit);
  const full = window.length === limit;
  const entries = window.reverse();
  const oldest = scanned.reduce<number | null>((m, e) => (m === null || e.seq < m ? e.seq : m), null);
  const scannedTo = full ? (entries.at(-1)?.seq ?? null) : oldest;
  return { entries, scannedTo, done: skip === 0 && !full };
}

// ---------- export ----------

const FORMULA = /^[=+\-@\t\r]/;

/** RFC 4180 cell with the OWASP CSV-injection guard (a leading `'` before a formula prefix). */
export function csvCell(raw: string): string {
  const v = FORMULA.test(raw) ? `'${raw}` : raw;
  return /[",\r\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
}

/** The export file Rust would write, as text. `rows` are redacted matches, oldest first. */
export function renderAuditExport(format: AuditExportFormat, rows: readonly AuditEntry[], chain: AuditVerify, filtered: boolean, exportedAt: string): string {
  const state = chain.ok ? "intact" : "broken";
  if (format === "csv") {
    const lines = [
      `#mooring-audit-export,version=1,exported_at=${exportedAt},chain=${state},verified_entries=${String(chain.entries)},broken_at=${chain.brokenAt === null ? "" : String(chain.brokenAt)},filtered=${String(filtered)}`,
      "seq,at,event,details,prev",
      ...rows.map((e) => [String(e.seq), e.at, e.event, renderedDetails(e).join("; "), e.prev].map(csvCell).join(",")),
      `#end,rows=${String(rows.length)},chain=${state}`,
    ];
    return lines.map((l) => `${l}\r\n`).join("");
  }
  const chainObj = { ok: chain.ok, entries: chain.entries, brokenAt: chain.brokenAt };
  const lines = [
    JSON.stringify({ header: { format: "mooring-audit-export", version: 1, exportedAt, chain: chainObj, filtered } }),
    ...rows.map((e) => JSON.stringify({ seq: e.seq, at: e.at, prev: e.prev, event: e.event, ...e.details })),
    JSON.stringify({ footer: { rows: rows.length, chain: chainObj } }),
  ];
  return lines.map((l) => `${l}\n`).join("");
}

/** A file the mock "save dialog" received. Tests read it; the UI never sees it. */
export interface MockAuditFile {
  name: string;
  format: AuditExportFormat;
  text: string;
  count: number;
}

/** The save-dialog answer: the queued name, `null` = cancelled; the extension is added when missing. */
export function auditSaveName(queue: (string | null)[], format: AuditExportFormat): string | null {
  const name = queue.length > 0 ? queue.shift() : `mooring-audit.${format}`;
  if (name === null || name === undefined) return null;
  return name.endsWith(`.${format}`) ? name : `${name}.${format}`;
}
