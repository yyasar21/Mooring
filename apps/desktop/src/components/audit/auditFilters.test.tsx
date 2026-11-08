// L4: audit filters (text, event type, connection, time) and the row detail drawer.
import { fireEvent, render, screen, within } from "@testing-library/react";
import type { AuditEntry } from "../../lib/ipc";
import { useTree } from "../../stores/tree";
import { freshBackend, settle } from "../../test/harness";
import { AuditView } from "./AuditView";
import { NO_FILTER, auditFacets, filterAudit, isFiltered } from "./auditFilter";
import { fieldLabel } from "./AuditDrawer";

const NOW = Date.parse("2026-11-08T12:00:00Z");
const row = (seq: number, event: string, at: string, details: Record<string, string> = {}): AuditEntry => ({ seq, at, prev: `h${String(seq)}`, event, details });
const ROWS = [
  row(4, "session_closed", "2026-11-08T11:30:00Z", { connection: "c-web01", reason: "closed by user" }),
  row(3, "session_opened", "2026-11-08T10:50:00Z", { connection: "c-web01" }),
  row(2, "credential_copied", "2026-11-07T09:00:00Z", { credential: "cr-ad", name: "password" }),
  row(1, "vault_unlocked", "2026-10-01T09:00:00Z"),
];
const hay = (e: AuditEntry) => [e.event, ...Object.values(e.details)];

describe("audit filter logic", () => {
  it("combines event, connection, time window and text", () => {
    const seqs = (f: Partial<typeof NO_FILTER>) => filterAudit(ROWS, { ...NO_FILTER, ...f }, hay, NOW).map((e) => e.seq);
    expect(seqs({})).toEqual([4, 3, 2, 1]);
    expect(seqs({ event: "session_opened" })).toEqual([3]);
    expect(seqs({ connection: "c-web01" })).toEqual([4, 3]);
    expect(seqs({ span: "hour" })).toEqual([4]);
    expect(seqs({ span: "day" })).toEqual([4, 3]);
    expect(seqs({ span: "week" })).toEqual([4, 3, 2]);
    expect(seqs({ text: "BY USER" })).toEqual([4]);
    expect(seqs({ connection: "c-web01", text: "password" })).toEqual([]);
    expect(isFiltered(NO_FILTER)).toBe(false);
    expect(isFiltered({ ...NO_FILTER, span: "day" })).toBe(true);
  });

  it("offers the events and connections that occur in the loaded rows", () => {
    expect(auditFacets(ROWS)).toEqual({ events: ["session_closed", "session_opened", "credential_copied", "vault_unlocked"], connections: ["c-web01"] });
    expect(fieldLabel("peer_identity")).toBe("Peer identity");
  });
});

describe("AuditView filters and drawer", () => {
  it("filters by event type and connection, and opens a row's fields in a drawer", async () => {
    freshBackend();
    await useTree.getState().load();
    render(<AuditView />);
    await settle();
    const grid = screen.getByRole("grid", { name: "Entries, newest first" });
    const filters = screen.getByRole("group", { name: "Filters" });
    const all = within(grid).getAllByRole("row").length - 1;
    expect(filters).toHaveTextContent(`${String(all)} of ${String(all)} loaded entries`);

    fireEvent.change(within(filters).getByLabelText("Event type"), { target: { value: "session_closed" } });
    let rows = within(grid).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toHaveTextContent("Session closed");
    const conn = within(filters).getByLabelText("Connection");
    expect(within(conn).getByRole("option", { name: "web01" })).toBeInTheDocument();
    fireEvent.change(conn, { target: { value: "c-web01" } });
    expect(within(grid).getAllByRole("row").slice(1)).toHaveLength(1);
    fireEvent.change(within(filters).getByLabelText("Time"), { target: { value: "hour" } });
    expect(within(filters).getByLabelText("Time")).toHaveValue("hour");

    fireEvent.click(within(filters).getByRole("button", { name: "Clear filters" }));
    rows = within(grid).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(all);

    const closed = rows.find((r) => r.textContent.includes("Session closed"));
    if (!closed) throw new Error("no closed row");
    fireEvent.click(closed);
    const drawer = screen.getByRole("complementary", { name: /^Entry \d+$/ });
    expect(within(drawer).getByRole("heading", { name: "Session closed" })).toBeInTheDocument();
    expect(drawer).toHaveTextContent("Event codesession_closed");
    expect(drawer).toHaveTextContent("Connectionweb01 c-web01");
    expect(drawer).toHaveTextContent("Reasonclosed by user");
    expect(drawer).toHaveTextContent(/Time \(UTC\)\d{4}-\d\d-\d\dT/);
    expect(within(drawer).getByRole("button", { name: "Close entry details" })).toHaveFocus();
    fireEvent.keyDown(drawer, { key: "Escape" });
    expect(screen.queryByRole("complementary", { name: /^Entry / })).toBeNull();
    // The chain status keeps its role.
    expect(screen.getByRole("status")).toHaveTextContent(/Chain intact/);
  });

  it("has no export button until Rust offers an export command", async () => {
    freshBackend();
    render(<AuditView />);
    await settle();
    expect(screen.queryByRole("button", { name: /export/i })).toBeNull();
  });
});
