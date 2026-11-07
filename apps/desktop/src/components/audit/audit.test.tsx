import { render, screen, within } from "@testing-library/react";
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
    const rows = within(screen.getByRole("list", { name: "Entries, newest first" })).getAllByRole("listitem");
    expect(rows[0]).toHaveTextContent("Portable data folder: owner-only ACL could not be applied (FAT/exFAT or policy)");
    expect(rows[1]).toHaveTextContent("Application started");
    expect(rows[1]).toHaveTextContent("portable: true");
  });
});
