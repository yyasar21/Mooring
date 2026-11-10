// The mock of the filtered `audit_tail` and `audit_export` follows rust-core's rules
// (`a5-rust-core-audit-export.md`): validation, redaction, text scope, paging and the export layout.
import { MockTransport } from "./ipc.mock";
import { IpcError } from "./ipc.error";
import type { AuditEntry } from "./ipc.types";
import { compileAuditFilter, csvCell, redactText, scanAuditPage } from "./ipc.mock.audit";

const T = Date.parse("2026-11-08T10:00:00Z");
const row = (seq: number, event: string, details: Record<string, string> = {}, at = T + seq * 1000): AuditEntry =>
  ({ seq, at: new Date(at).toISOString(), prev: `h${String(seq)}`, event, details });

function mockWith(rows: AuditEntry[]): MockTransport {
  const m = new MockTransport();
  m.audit = rows.map((r) => ({ ...r, details: { ...r.details } }));
  return m;
}

const LOG = [
  row(1, "vault_unlocked"),
  row(2, "session_opened", { connection: "c-web01", host: "web01.example.test" }),
  row(3, "credential_copied", { credential: "cr-ad", note: "password=hunter2" }),
  row(4, "session_closed", { connection: "c-web01", reason: "Closed by user" }),
  row(5, "session_opened", { connection: "c-db", token: "abc.def" }),
];

async function refused(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e: unknown) {
    if (e instanceof IpcError) return `${e.code}: ${e.message}`;
  }
  return "accepted";
}

describe("mock audit filter validation", () => {
  const known = (n: string) => ["vault_unlocked", "session_opened"].includes(n);
  const bad = (input: unknown) => {
    try {
      compileAuditFilter(input as Parameters<typeof compileAuditFilter>[0], known);
      return "ok";
    } catch (e: unknown) {
      return e instanceof IpcError ? `${e.code} ${e.message}` : "other";
    }
  };

  it("refuses what Rust refuses and treats empty values as no condition", () => {
    expect(bad({ events: Array.from({ length: 33 }, () => "vault_unlocked") })).toBe("input.invalid invalid filter: too many event names");
    expect(bad({ events: ["nope"] })).toBe("input.invalid invalid filter: unknown event name");
    expect(bad({ since: 5, until: 4 })).toBe("input.invalid invalid filter: since is after until");
    expect(bad({ since: 4, until: 4 })).toBe("ok");
    expect(bad({ text: "x".repeat(129) })).toBe("input.invalid invalid filter: text too long");
    expect(bad({ text: `  ${"é".repeat(128)}  ` })).toBe("ok");
    expect(bad({ text: "a\u0007b" })).toBe("input.invalid invalid filter: text");
    expect(bad({ connection: "c".repeat(129) })).toBe("input.invalid invalid filter: connection id");
    expect(bad({ connection: "c\n1" })).toBe("input.invalid invalid filter: connection id");
    expect(bad({ host: "x" })).toBe("input.invalid invalid filter: unknown field");
    expect(compileAuditFilter({ events: [], connection: "", text: "   " }, known)).toEqual({ events: null, connection: null, since: null, until: null, text: null });
  });
});

describe("mock redaction", () => {
  it("scrubs secret-looking values and secret-named keys like mooring_audit::redact", () => {
    expect(redactText("user=alice password=hunter2 token: abc.def Authorization: Bearer eyJ.x.y")).toBe(
      // As in Rust: the scheme pass hides the token, then the `authorization` key pass hides "Bearer".
      "user=alice password=[REDACTED] token: [REDACTED] Authorization: [REDACTED] [REDACTED]",
    );
    expect(redactText("note=-----BEGIN OPENSSH PRIVATE KEY-----\nAAA\n-----END OPENSSH PRIVATE KEY-----")).toBe("note=-----BEGIN PRIVATE KEY [REDACTED]-----");
    expect(redactText("host=web01")).toBe("host=web01");
  });
});

describe("mock filtered audit_tail", () => {
  it("filters any-of events, the exact connection, the window and redacted detail text", async () => {
    const m = mockWith(LOG);
    const seqs = async (filter: object) => (await m.auditSearch({ limit: 50, before: null, filter })).entries.map((e) => e.seq);
    expect(await seqs({ events: ["session_opened", "session_closed"] })).toEqual([5, 4, 2]);
    expect(await seqs({ connection: "c-web01" })).toEqual([4, 2]);
    expect(await seqs({ connection: "c-web" })).toEqual([]);
    expect(await seqs({ since: T + 2000, until: T + 4000 })).toEqual([3, 2]);
    expect(await seqs({ text: "CLOSED BY" })).toEqual([4]);
    // Text searches details only: not the event name, never a hidden secret, but the marker.
    expect(await seqs({ text: "session_opened" })).toEqual([]);
    expect(await seqs({ text: "hunter2" })).toEqual([]);
    expect(await seqs({ text: "abc.def" })).toEqual([]);
    expect(await seqs({ text: "[redacted]" })).toEqual([5, 3]);
    const page = await m.auditSearch({ limit: 50, before: null, filter: { connection: "c-db" } });
    expect(page.entries[0]?.details.token).toBe("[REDACTED]");
    expect(JSON.stringify(await m.auditTail({ limit: 50, before: null }))).not.toMatch(/hunter2|abc\.def/);
  });

  it("pages with scannedTo: full pages, the scan cap and done", () => {
    const log = Array.from({ length: 10 }, (_, i) => row(i + 1, i % 2 ? "session_opened" : "vault_unlocked"));
    const f = compileAuditFilter({ events: ["session_opened"] }, () => true);
    // A full page: scannedTo is the oldest returned seq.
    expect(scanAuditPage(log, f, 2, null, 100)).toMatchObject({ scannedTo: 8, done: false });
    expect(scanAuditPage(log, f, 2, null, 100).entries.map((e) => e.seq)).toEqual([10, 8]);
    // The cap stops the scan: not full, scannedTo is the oldest scanned seq.
    expect(scanAuditPage(log, f, 50, null, 3)).toMatchObject({ scannedTo: 8, done: false });
    expect(scanAuditPage(log, f, 50, 8, 3).entries.map((e) => e.seq)).toEqual([6]);
    expect(scanAuditPage(log, f, 50, 2, 3)).toMatchObject({ entries: [], scannedTo: 1, done: true });
    expect(scanAuditPage([], f, 50, null, 3)).toEqual({ entries: [], scannedTo: null, done: true });
  });

  it("needs an unlocked vault and refuses a bad filter", async () => {
    const m = mockWith(LOG);
    expect(await refused(m.auditSearch({ limit: 5, before: null, filter: { events: ["made_up"] } }))).toBe("input.invalid: invalid filter: unknown event name");
    m.vault = "locked";
    expect(await refused(m.auditSearch({ limit: 5, before: null, filter: {} }))).toMatch(/^vault\.locked/);
  });
});

describe("mock audit_export", () => {
  it("writes CSV with header, redacted filtered rows oldest first, footer, and audits the export", async () => {
    const m = mockWith(LOG);
    m.auditSaves.push("audit");
    const res = await m.auditExport({ format: "csv", filter: { connection: "c-web01" } });
    expect(res).toEqual({ count: 2, cancelled: false });
    const file = m.auditFiles[0];
    expect(file?.name).toBe("audit.csv");
    const lines = file?.text.split("\r\n") ?? [];
    expect(lines[0]).toMatch(/^#mooring-audit-export,version=1,exported_at=\S+,chain=intact,verified_entries=5,broken_at=,filtered=true$/);
    expect(lines[1]).toBe("seq,at,event,details,prev");
    expect(lines[2]).toMatch(/^2,.*,session_opened,connection=c-web01; host=web01\.example\.test,h2$/);
    expect(lines[3]).toMatch(/^4,/);
    expect(lines[4]).toBe("#end,rows=2,chain=intact");
    const last = m.audit.at(-1);
    expect(last?.event).toBe("audit.exported");
    expect(last?.details).toEqual({ format: "csv", count: "2" });
    expect(JSON.stringify(last)).not.toContain("audit.csv");
  });

  it("writes JSONL framed by header and footer, unfiltered, without secrets", async () => {
    const m = mockWith(LOG);
    await m.auditExport({ format: "jsonl" });
    const text = m.auditFiles[0]?.text ?? "";
    const lines = text.trimEnd().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(lines[0]).toMatchObject({ header: { format: "mooring-audit-export", version: 1, filtered: false, chain: { ok: true, entries: 5, brokenAt: null } } });
    expect(lines.slice(1, -1).map((l) => l.seq)).toEqual([1, 2, 3, 4, 5]);
    expect(lines.at(-1)).toEqual({ footer: { rows: 5, chain: { ok: true, entries: 5, brokenAt: null } } });
    expect(text).not.toMatch(/hunter2|abc\.def/);
  });

  it("a cancelled dialog writes and audits nothing; refusals come before the dialog", async () => {
    const m = mockWith(LOG);
    m.auditSaves.push(null);
    expect(await m.auditExport({ format: "csv" })).toEqual({ count: 0, cancelled: true });
    expect(m.auditFiles).toHaveLength(0);
    expect(m.audit).toHaveLength(5);
    m.auditSaves.push("kept");
    expect(await refused(m.auditExport({ format: "csv", filter: { since: 9, until: 1 } }))).toMatch(/^input\.invalid/);
    expect(m.auditSaves).toEqual(["kept"]);
    m.failAuditExport = true;
    expect(await refused(m.auditExport({ format: "jsonl" }))).toBe("audit.export: the audit export could not be written");
    expect(m.auditFiles).toHaveLength(0);
    m.vault = "locked";
    expect(await refused(m.auditExport({ format: "csv" }))).toMatch(/^vault\.locked/);
  });

  it("quotes CSV cells and neutralises formulas", () => {
    expect(csvCell("plain")).toBe("plain");
    expect(csvCell("a,b")).toBe('"a,b"');
    expect(csvCell('say "hi"')).toBe('"say ""hi"""');
    for (const p of ["=", "+", "-", "@", "\t"]) expect(csvCell(`${p}1`)).toBe(`'${p}1`);
    expect(csvCell("=SUM(A1,B1)")).toBe('"\'=SUM(A1,B1)"');
    expect(csvCell("\r1")).toBe('"\'\r1"');
  });
});
