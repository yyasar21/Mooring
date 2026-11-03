import { act, render, screen, within } from "@testing-library/react";
import { App } from "../App";
import { useSessions } from "../stores/sessions";
import { freshBackend, settle } from "../test/harness";

describe("telemetry strip", () => {
  it("shows vault state, link counts and the audit chain result", async () => {
    const mock = freshBackend();
    mock.auditVerify = () => Promise.resolve({ ok: false, entries: 4, brokenAt: 3 });
    render(<App />);
    await screen.findByText("Nothing open yet");
    await settle();
    const strip = screen.getByRole("contentinfo", { name: "Status" });
    expect(strip).toHaveTextContent(/Vault\s*unlocked/);
    expect(strip).toHaveTextContent("0 connected");
    expect(within(strip).getByText("broken at 3")).toBeInTheDocument();

    await act(async () => {
      await useSessions.getState().open("c-web01");
    });
    await settle();
    expect(strip).toHaveTextContent(/waiting for you/);
  });
});
