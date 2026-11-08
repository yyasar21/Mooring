import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { App } from "../../App";
import { useSessions } from "../../stores/sessions";
import { useUi } from "../../stores/ui";
import { freshBackend, settle } from "../../test/harness";
import type { MockTransport } from "../../lib/ipc.mock";
import { touchSecondsLeft } from "./TouchBanner";

async function boot() {
  render(<App />);
  await screen.findByText("Nothing open yet");
  await settle();
}

const tab = () => useSessions.getState().tabs[0];
const panel = () => screen.getByRole("tabpanel");

describe("security-key touch on an SSH tab (ADR-0024)", () => {
  let mock: MockTransport;
  beforeEach(() => {
    mock = freshBackend();
    mock.trustedHosts.add("runner.example.test");
    // Long enough that a slow CI runner still sees the banner before the mock clears it.
    mock.sk.touchMs = 1500;
  });

  it("shows a non-modal banner with the short fingerprint until touch_cleared, then connects", async () => {
    await boot();
    await act(async () => { await useSessions.getState().open("c-yubi"); });
    await settle();
    expect(within(panel()).getByRole("status")).toHaveTextContent("Touch your security key to continue");
    expect(panel()).toHaveTextContent("Key SHA256:0f/IntG4…rdDv4");
    expect(within(panel()).getByLabelText("30 seconds left")).toBeInTheDocument();
    // Nothing to answer: no dialog, and the terminal is not blocked by a prompt.
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(tab()?.prompt).toBeNull();
    // A touch_cleared for another id does not hide this banner.
    const live = [...mock.sessions.values()][0];
    act(() => { live?.emit({ kind: "touch_cleared", id: 99 }); });
    expect(within(panel()).getByRole("status")).toHaveTextContent("Touch your security key to continue");
    await waitFor(() => { expect(tab()?.state).toBe("connected"); }, { timeout: 5000 });
    expect(within(panel()).queryByText("Touch your security key to continue")).toBeNull();
    expect(mock.audit.some((e) => e.event === "session.auth_sk" && e.details.outcome === "ok")).toBe(true);
  });

  it("after touch_timeout says so and Retry reconnects", async () => {
    mock.sk.touch = "timeout";
    mock.sk.touchMs = 80;
    await boot();
    await act(async () => { await useSessions.getState().open("c-yubi"); });
    await waitFor(() => { expect(tab()?.state).toBe("closed"); });
    const banner = within(panel()).getByRole("alert", { name: "Security key not touched" });
    expect(banner).toHaveTextContent("No touch within 30 seconds");
    expect(banner).toHaveTextContent("did not try a password");
    expect(tab()?.closeCode).toBe("auth_failed");
    // The generic "Link lost" strip is replaced by the touch banner.
    expect(within(panel()).queryByText("Link lost")).toBeNull();
    mock.sk.touch = "touch";
    fireEvent.click(within(banner).getByRole("button", { name: "Retry" }));
    await settle();
    expect(within(panel()).queryByRole("alert", { name: "Security key not touched" })).toBeNull();
    await waitFor(() => { expect(tab()?.state).toBe("connected"); });
  });

  it("names the pre-flight refusal when the agent does not hold the key", async () => {
    mock.sk.agentHolds = false;
    await boot();
    await act(async () => { await useSessions.getState().open("c-yubi"); });
    await settle();
    expect(tab()).toMatchObject({ state: "closed", openError: "ssh.sk_key_not_in_agent" });
    expect(panel()).toHaveTextContent("Security key not in ssh-agent");
    expect(panel()).toHaveTextContent("Add the key to your ssh-agent: ssh-add -K or ssh-add <handle file>.");
    expect(within(panel()).queryByText(/Touch your security key/)).toBeNull();
  });

  it("names the refusal of a credential set to the helper backend", async () => {
    const cred = mock.creds.items.find((c) => c.id === "cr-yubi");
    if (cred) cred.fields.backend = "helper";
    await boot();
    await act(async () => { await useSessions.getState().open("c-yubi"); });
    await settle();
    expect(panel()).toHaveTextContent("Direct security-key signing is off");
    expect(panel()).toHaveTextContent("This credential signs with ssh-sk-helper, which is turned off.");
  });

  it("counts down from timeout_seconds", () => {
    expect(touchSecondsLeft({ since: 1000, timeoutSeconds: 30 }, 1000)).toBe(30);
    expect(touchSecondsLeft({ since: 1000, timeoutSeconds: 30 }, 21_500)).toBe(10);
    expect(touchSecondsLeft({ since: 1000, timeoutSeconds: 30 }, 99_000)).toBe(0);
  });
});

describe("Settings → SSH", () => {
  beforeEach(() => { freshBackend(); });

  it("shows the ssh-sk-helper backend as an informational row without a toggle", async () => {
    await boot();
    act(() => { useUi.getState().setView("settings"); });
    const card = await screen.findByRole("region", { name: "SSH" });
    expect(card).toHaveTextContent("Direct security-key access (without ssh-agent) — coming later");
    expect(card).toHaveTextContent("Not available");
    expect(within(card).queryByRole("switch")).toBeNull();
    expect(within(card).queryByRole("button")).toBeNull();
  });
});
