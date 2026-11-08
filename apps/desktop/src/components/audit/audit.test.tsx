import { act, render, screen, within } from "@testing-library/react";
import { useApp } from "../../stores/app";
import { useSessions } from "../../stores/sessions";
import { useTree } from "../../stores/tree";
import { freshBackend, settle } from "../../test/harness";
import { AuditView } from "./AuditView";

describe("AuditView labels (ADR-0021 rows)", () => {
  it("names app.start with its portable detail and the ACL fallback", async () => {
    const mock = freshBackend();
    const last = mock.audit.at(-1);
    const seq = last?.seq ?? 0;
    const at = last?.at ?? "2026-11-07T00:00:00Z";
    mock.audit.push(
      { seq: seq + 1, at, prev: `mock-${seq}`, event: "app.start", details: { portable: "true" } },
      { seq: seq + 2, at, prev: `mock-${seq + 1}`, event: "portable.acl_unavailable", details: {} },
    );
    render(<AuditView />);
    await settle();
    const rows = within(screen.getByRole("table", { name: "Entries, newest first" })).getAllByRole("row").slice(1);
    expect(rows[0]).toHaveTextContent("Portable data folder: owner-only ACL could not be applied (FAT/exFAT or policy)");
    expect(rows[1]).toHaveTextContent("Application started");
    expect(rows[1]).toHaveTextContent("portable: true");
  });

  it("names forward_refused from the web-via proxy (L-48) with its target", async () => {
    const mock = freshBackend();
    useApp.setState({ vault: "unlocked" });
    mock.trustedHosts.add("bastion.stage.example.test");
    await useTree.getState().load();
    await act(async () => { await useSessions.getState().open("c-wiki"); });
    await settle(6);
    mock.webViaRefuse("c-wiki", "tracker.example.test:443");
    // a window without jump hosts has no proxy, so nothing is refused there
    mock.webViaRefuse("c-lb", "tracker.example.test:443");
    expect(mock.audit.filter((e) => e.event === "forward_refused")).toHaveLength(1);
    render(<AuditView />);
    await settle();
    const rows = within(screen.getByRole("table", { name: "Entries, newest first" })).getAllByRole("row").slice(1);
    expect(rows[0]).toHaveTextContent("Web proxy refused a destination outside the allowed origins");
    expect(rows[0]).toHaveTextContent("tracker.example.test:443");
    for (const t of useSessions.getState().tabs) await act(async () => { await useSessions.getState().close(t.id); });
  });
});
