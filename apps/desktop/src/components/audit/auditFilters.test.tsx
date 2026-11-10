// L4: audit filters (text, event type, connection, time) run in Rust (filtered `audit_tail`),
// the row detail drawer, and "Export…" (`audit_export`).
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { IpcError, type AuditEntry } from "../../lib/ipc";
import type { MockTransport } from "../../lib/ipc.mock";
import { useToasts } from "../../stores/toast";
import { useTree } from "../../stores/tree";
import { freshBackend, settle } from "../../test/harness";
import { AuditView, EVENT_LABEL } from "./AuditView";
import { NO_FACETS, NO_FILTER, isFiltered, mergeFacets, toFilterInput } from "./auditFilter";
import { fieldLabel } from "./AuditDrawer";
import { searchedCount } from "./useAuditLog";

const NOW = Date.parse("2026-11-08T12:00:00Z");
const row = (seq: number, event: string, details: Record<string, string> = {}): AuditEntry => ({ seq, at: "2026-11-08T11:30:00Z", prev: `h${String(seq)}`, event, details });

describe("audit filter input", () => {
  it("maps the filter bar to the Rust filter", () => {
    expect(toFilterInput(NO_FILTER, NOW)).toBeNull();
    expect(toFilterInput({ ...NO_FILTER, event: "session_opened" }, NOW)).toEqual({ events: ["session_opened"] });
    expect(toFilterInput({ ...NO_FILTER, connection: "c-web01", span: "hour" }, NOW)).toEqual({ connection: "c-web01", since: NOW - 3_600_000 });
    expect(toFilterInput({ ...NO_FILTER, span: "month" }, NOW)).toEqual({ since: NOW - 30 * 86_400_000 });
    expect(toFilterInput({ ...NO_FILTER, text: "  web01  " }, NOW)).toEqual({ text: "web01" });
    expect(toFilterInput({ ...NO_FILTER, text: "x".repeat(200) }, NOW)?.text).toHaveLength(128);
    expect(toFilterInput({ ...NO_FILTER, text: "   " }, NOW)).toBeNull();
    expect(isFiltered({ ...NO_FILTER, span: "day" })).toBe(true);
  });

  it("keeps every event and connection seen in any page", () => {
    const a = mergeFacets(NO_FACETS, [row(2, "session_opened", { connection: "c-web01" }), row(1, "vault_unlocked")]);
    expect(a).toEqual({ events: ["session_opened", "vault_unlocked"], connections: ["c-web01"] });
    expect(mergeFacets(a, [row(3, "session_opened")])).toBe(a);
    expect(mergeFacets(a, [row(4, "session_closed", { connection: "c-db" })]).connections).toEqual(["c-web01", "c-db"]);
    expect(searchedCount(150, 51)).toBe(100);
    expect(searchedCount(null, 51)).toBeNull();
    expect(fieldLabel("peer_identity")).toBe("Peer identity");
    expect(EVENT_LABEL["audit.exported"]).toBe("Audit log exported");
  });
});

/** Append synthetic rows to the mock log (consecutive seqs, the mock's own timestamps). */
function grow(mock: MockTransport, n: number, event: (i: number) => string): void {
  const base = mock.audit.at(-1)?.seq ?? 0;
  const at = mock.audit.at(-1)?.at ?? "2026-11-07T00:00:00Z";
  for (let i = 1; i <= n; i++) mock.audit.push({ seq: base + i, at, prev: `mock-${String(base + i - 1)}`, event: event(i), details: { connection: "c-web01", n: String(i) } });
}

const grid = () => screen.getByRole("grid", { name: "Entries, newest first" });
const filters = () => screen.getByRole("group", { name: "Filters" });
const bodyRows = () => within(grid()).getAllByRole("row").slice(1);

describe("AuditView filters (Rust side) and drawer", () => {
  it("asks Rust for the filtered log and opens a row's fields in a drawer", async () => {
    const mock = freshBackend();
    await useTree.getState().load();
    const search = vi.spyOn(mock, "auditSearch");
    render(<AuditView />);
    await settle();
    const all = bodyRows().length;
    expect(filters()).toHaveTextContent(`${String(all)} loaded entries`);
    expect(search).not.toHaveBeenCalled();

    fireEvent.change(within(filters()).getByLabelText("Event type"), { target: { value: "session_closed" } });
    await settle();
    expect(search).toHaveBeenLastCalledWith({ limit: 200, before: null, filter: { events: ["session_closed"] } });
    expect(bodyRows()).toHaveLength(1);
    expect(bodyRows()[0]).toHaveTextContent("Session closed");
    expect(filters()).toHaveTextContent("1 match");
    // The other choices stay offered while the list is narrowed.
    expect(within(within(filters()).getByLabelText("Event type")).getAllByRole("option").length).toBeGreaterThan(2);
    const conn = within(filters()).getByLabelText("Connection");
    expect(within(conn).getByRole("option", { name: "web01" })).toBeInTheDocument();
    fireEvent.change(conn, { target: { value: "c-web01" } });
    await settle();
    expect(search).toHaveBeenLastCalledWith({ limit: 200, before: null, filter: { events: ["session_closed"], connection: "c-web01" } });
    fireEvent.change(within(filters()).getByLabelText("Time"), { target: { value: "hour" } });
    await settle();
    expect(search.mock.lastCall?.[0].filter.since).toEqual(expect.any(Number));

    fireEvent.click(within(filters()).getByRole("button", { name: "Clear filters" }));
    await settle();
    expect(bodyRows()).toHaveLength(all);

    const closed = bodyRows().find((r) => r.textContent.includes("Session closed"));
    if (!closed) throw new Error("no closed row");
    fireEvent.click(closed);
    const drawer = screen.getByRole("complementary", { name: /^Entry \d+$/ });
    expect(within(drawer).getByRole("heading", { name: "Session closed" })).toBeInTheDocument();
    expect(drawer).toHaveTextContent("Event codesession_closed");
    expect(drawer).toHaveTextContent("Connectionweb01 c-web01");
    expect(drawer).toHaveTextContent("Reasonclosed by user");
    expect(within(drawer).getByRole("button", { name: "Close entry details" })).toHaveFocus();
    fireEvent.keyDown(drawer, { key: "Escape" });
    expect(screen.queryByRole("complementary", { name: /^Entry / })).toBeNull();
    expect(screen.getByRole("status")).toHaveTextContent(/Chain intact/);
  });

  it("sends the text once typing pauses and searches the details only", async () => {
    const mock = freshBackend();
    const search = vi.spyOn(mock, "auditSearch");
    render(<AuditView />);
    await settle();
    fireEvent.change(within(filters()).getByLabelText("Filter audit entries"), { target: { value: "closed by" } });
    expect(search).not.toHaveBeenCalled();
    await waitFor(() => { expect(search).toHaveBeenCalledWith({ limit: 200, before: null, filter: { text: "closed by" } }); });
    await settle();
    expect(bodyRows()).toHaveLength(1);
    expect(bodyRows()[0]).toHaveTextContent("Session closed");
  });

  it("pages a filtered search: Load more, then Continue search at the scan cap", async () => {
    const mock = freshBackend();
    const search = vi.spyOn(mock, "auditSearch");
    render(<AuditView />);
    await settle(); // the seed rows (one `vault_unlocked`) are seen, so the select offers them
    grow(mock, 450, () => "session_opened");
    fireEvent.change(within(filters()).getByLabelText("Event type"), { target: { value: "session_opened" } });
    await settle();
    expect(bodyRows()).toHaveLength(200);
    expect(filters()).toHaveTextContent("200 matches so far");
    fireEvent.click(screen.getByRole("button", { name: "Load more" }));
    await settle();
    expect(bodyRows()).toHaveLength(400);
    expect(search.mock.lastCall?.[0].before).toBeGreaterThan(0);

    // A rare event over a log larger than the scan cap: the search stops and says how far it got.
    mock.auditScanCap = 100;
    const newest = mock.audit.at(-1)?.seq ?? 0;
    const rare = mock.audit.find((e) => e.event === "vault_unlocked");
    if (!rare) throw new Error("no unlock row");
    fireEvent.change(within(filters()).getByLabelText("Event type"), { target: { value: "vault_unlocked" } });
    await settle();
    expect(grid()).not.toHaveTextContent("Vault unlocked");
    expect(grid()).toHaveTextContent("No match in the entries searched so far.");
    expect(screen.getByText("Searched the newest 100 entries.")).toBeInTheDocument();
    expect(search.mock.lastCall?.[0].before).toBeNull();
    for (let i = 0; i < 10 && !bodyRows().some((r) => r.textContent.includes("Vault unlocked")); i++) {
      fireEvent.click(screen.getByRole("button", { name: "Continue search" }));
      await settle();
    }
    expect(bodyRows().map((r) => r.textContent)).toEqual(expect.arrayContaining([expect.stringContaining("Vault unlocked")]));
    expect(newest - rare.seq).toBeGreaterThanOrEqual(100);
  });

  it("shows a refused filter as a readable error", async () => {
    const mock = freshBackend();
    mock.auditSearch = () => Promise.reject(new IpcError("input.invalid", "invalid filter: unknown event name"));
    render(<AuditView />);
    await settle();
    fireEvent.change(within(filters()).getByLabelText("Event type"), { target: { value: "session_closed" } });
    await settle();
    expect(screen.getByRole("alert")).toHaveTextContent("invalid filter: unknown event name");
    expect(bodyRows()).toHaveLength(1);
    expect(bodyRows()[0]).toHaveTextContent("No entry matches the filters.");
  });
});

describe("AuditView export", () => {
  async function exportAs(name: "CSV" | "JSON Lines") {
    fireEvent.click(within(filters()).getByRole("button", { name: "Export…" }));
    const menu = screen.getByRole("menu", { name: "Export format" });
    expect(within(menu).getAllByRole("menuitem")[0]).toHaveFocus();
    act(() => { fireEvent.click(within(menu).getByRole("menuitem", { name: new RegExp(`^${name}`) })); });
    await settle();
  }

  it("exports the filtered rows, toasts the count and labels the new audit row", async () => {
    const mock = freshBackend();
    render(<AuditView />);
    await settle();
    fireEvent.change(within(filters()).getByLabelText("Event type"), { target: { value: "session_closed" } });
    await settle();
    await exportAs("CSV");
    expect(mock.auditFiles).toHaveLength(1);
    expect(mock.auditFiles[0]?.format).toBe("csv");
    expect(mock.auditFiles[0]?.count).toBe(1);
    expect(useToasts.getState().toasts.map((t) => t.text)).toEqual(["Exported 1 entry"]);
    expect(mock.audit.at(-1)?.event).toBe("audit.exported");

    fireEvent.click(within(filters()).getByRole("button", { name: "Clear filters" }));
    await settle();
    await exportAs("JSON Lines");
    expect(mock.auditFiles[1]?.format).toBe("jsonl");
    expect(mock.auditFiles[1]?.text).toContain('"filtered":false');
    expect(bodyRows()[0]).toHaveTextContent("Audit log exported");
    expect(bodyRows()[0]).toHaveTextContent("format: jsonl");
  });

  it("says nothing on cancel and shows a readable error on failure", async () => {
    const mock = freshBackend();
    render(<AuditView />);
    await settle();
    mock.auditSaves.push(null);
    await exportAs("CSV");
    expect(useToasts.getState().toasts).toHaveLength(0);
    expect(screen.queryByRole("alert")).toBeNull();

    mock.failAuditExport = true;
    await exportAs("CSV");
    expect(useToasts.getState().toasts).toHaveLength(0);
    expect(screen.getByRole("alert")).toHaveTextContent("The audit export could not be written there. Nothing was saved; choose another location.");
    expect(mock.auditFiles).toHaveLength(0);
  });

  it("closes the format menu on Escape and returns focus", async () => {
    freshBackend();
    render(<AuditView />);
    await settle();
    const trigger = within(filters()).getByRole("button", { name: "Export…" });
    fireEvent.click(trigger);
    fireEvent.keyDown(screen.getByRole("menu", { name: "Export format" }), { key: "Escape" });
    expect(screen.queryByRole("menu")).toBeNull();
    expect(trigger).toHaveFocus();
  });
});
