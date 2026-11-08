// L-49: Rust adds a smart card to ssh-agent for 60 minutes, so the mock agent must not ask the PIN
// again inside that time (and must not extend it on a sign-in that finds the key).
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { App } from "../../App";
import type { MockTransport } from "../../lib/ipc.mock";
import { CARD_LIFETIME_MS, MockAgentCards } from "../../lib/ipc.mock.piv";
import { useSessions } from "../../stores/sessions";
import { freshBackend, settle } from "../../test/harness";

async function closeAll() {
  for (const t of useSessions.getState().tabs) await act(async () => { await useSessions.getState().close(t.id); });
}

describe("mock ssh-agent card lifetime (L-49)", () => {
  let mock: MockTransport;
  let clock = 0;
  beforeEach(() => {
    mock = freshBackend();
    const c = mock.connections.find((x) => x.id === "c-web01");
    if (c) c.credentialId = "cr-piv";
    mock.trustedHosts.add("web01.example.test");
    clock = Date.parse("2026-11-08T10:00:00Z");
    mock.agentCards = new MockAgentCards(() => clock);
  });

  const pinDialog = () => screen.queryByRole("alertdialog", { name: "Smart card PIN" });

  it("holds a card for 60 minutes from the PIN, then forgets it", () => {
    const cards = new MockAgentCards(() => clock);
    expect(cards.holds("SHA256:x")).toBe(false);
    cards.load("SHA256:x");
    clock += CARD_LIFETIME_MS - 1;
    expect(cards.holds("SHA256:x")).toBe(true);
    clock += 1;
    expect(cards.holds("SHA256:x")).toBe(false);
    cards.load("SHA256:x");
    cards.forget();
    expect(cards.holds("SHA256:x")).toBe(false);
  });

  it("a reconnect within the 60 minutes is not asked again; after them, the PIN is asked", async () => {
    render(<App />);
    await screen.findByText("Nothing open yet");
    await settle();
    await act(async () => { await useSessions.getState().open("c-web01"); });
    await settle();
    fireEvent.change(within(pinDialog() ?? document.body).getByLabelText("PIN"), { target: { value: "246810" } });
    fireEvent.click(screen.getByRole("button", { name: "Unlock card" }));
    await waitFor(() => { expect(useSessions.getState().tabs[0]?.state).toBe("connected"); });
    await closeAll();

    clock += CARD_LIFETIME_MS - 60_000;
    await act(async () => { await useSessions.getState().open("c-web01"); });
    await waitFor(() => { expect(useSessions.getState().tabs[0]?.state).toBe("connected"); });
    expect(pinDialog()).toBeNull();
    expect(mock.audit.filter((e) => e.event === "credential.pin_prompted")).toHaveLength(1);
    await closeAll();

    clock += 120_000; // past the lifetime of the first load: the reconnect did not extend it
    await act(async () => { await useSessions.getState().open("c-web01"); });
    await settle();
    expect(pinDialog()).not.toBeNull();
    await closeAll();
  });
});
