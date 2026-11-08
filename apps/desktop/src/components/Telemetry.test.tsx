import { act, render, screen } from "@testing-library/react";
import { App } from "../App";
import { useSessions } from "../stores/sessions";
import { freshBackend, settle } from "../test/harness";

describe("status bar", () => {
  it("says, in plain words, the vault state, open sessions, who waits and the audit chain result", async () => {
    const mock = freshBackend();
    mock.auditVerify = () => Promise.resolve({ ok: false, entries: 4, brokenAt: 3 });
    render(<App />);
    await screen.findByText("Nothing open yet");
    await settle();
    const bar = screen.getByRole("contentinfo", { name: "Status" });
    expect(bar).toHaveTextContent("Vault unlocked");
    expect(bar).toHaveTextContent("0 sessions open");
    expect(bar).toHaveTextContent("Audit chain broken at entry 3");
    // Q8: build internals are in Settings → About, not in the status bar.
    expect(bar).not.toHaveTextContent(/build|debug|browser\/mock/i);
    expect(bar).toHaveTextContent(/Mooring \S+$/);

    await act(async () => {
      await useSessions.getState().open("c-web01");
    });
    await settle();
    expect(bar).toHaveTextContent(/1 waiting for you/);
  });

  it("reports a verified chain without jargon", async () => {
    freshBackend();
    render(<App />);
    await screen.findByText("Nothing open yet");
    await settle();
    expect(screen.getByRole("contentinfo", { name: "Status" })).toHaveTextContent("Audit chain verified");
  });
});
