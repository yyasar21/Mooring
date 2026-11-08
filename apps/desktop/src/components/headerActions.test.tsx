// W3 leftovers from W2: the open-forward count on "Forwards" and the header's Disconnect.
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { App } from "../App";
import { useForwardCounts } from "../stores/forwardCounts";
import { useSessions } from "../stores/sessions";
import { canDisconnect } from "../stores/sessions.disconnect";
import { freshBackend, settle } from "../test/harness";

async function bootWithWeb01() {
  const mock = freshBackend();
  mock.trustedHosts.add("web01.example.test");
  render(<App />);
  await screen.findByText("Nothing open yet");
  await act(async () => { await useSessions.getState().open("c-web01"); });
  await settle();
  return mock;
}

const tools = () => screen.getByRole("toolbar", { name: "Session tools" });

describe("session header actions (W3)", () => {
  it("counts the open forwards on Forwards, keeping its name", async () => {
    const mock = await bootWithWeb01();
    const sid = useSessions.getState().tabs[0]?.sessionId ?? "";
    const forwards = within(tools()).getByRole("button", { name: "Forwards" });
    expect(forwards).not.toHaveAccessibleDescription();
    await act(async () => {
      await mock.forwardOpen({ sessionId: sid, kind: "local", bind: { host: "127.0.0.1", port: 15432 }, target: { host: "db.example.test", port: 5432 }, exposure: "loopback" });
    });
    // The panel's list writes the count; it stays on the switch after going back to the terminal.
    fireEvent.click(forwards);
    await settle();
    fireEvent.click(within(tools()).getByRole("button", { name: "Terminal" }));
    expect(useForwardCounts.getState().counts[sid]).toBe(1);
    expect(within(tools()).getByRole("button", { name: "Forwards" })).toHaveAccessibleDescription("1 forward open");
    expect(forwards.querySelector(".seg-count")).toHaveTextContent("1");
    for (const t of useSessions.getState().tabs) await act(async () => { await useSessions.getState().close(t.id); });
  });

  it("the header reads the count with forward_list without opening the panel", async () => {
    const mock = freshBackend();
    mock.trustedHosts.add("web01.example.test");
    const spy = vi.spyOn(mock, "forwardList");
    render(<App />);
    await screen.findByText("Nothing open yet");
    await act(async () => { await useSessions.getState().open("c-web01"); });
    await settle();
    const sid = useSessions.getState().tabs[0]?.sessionId ?? "";
    await waitFor(() => { expect(spy).toHaveBeenCalledWith({ sessionId: sid }); });
    expect(screen.queryByRole("region", { name: "Port forwards" })).toBeNull();
    for (const t of useSessions.getState().tabs) await act(async () => { await useSessions.getState().close(t.id); });
  });

  it("Disconnect ends the session but keeps the tab, closed by the user, with Reconnect", async () => {
    const mock = await bootWithWeb01();
    const close = vi.spyOn(mock, "sessionClose");
    const tab = () => useSessions.getState().tabs[0];
    expect(tab()?.state).toBe("connected");
    fireEvent.click(screen.getByRole("button", { name: "Disconnect" }));
    await settle();
    expect(close).toHaveBeenCalledTimes(1);
    expect(tab()).toMatchObject({ state: "closed", closeCode: "user", sessionId: null });
    expect(screen.getByRole("button", { name: "Disconnect" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Reconnect" })).toBeInTheDocument();
    expect(canDisconnect({ state: "closed", sessionId: null })).toBe(false);
    expect(canDisconnect({ state: "connecting", sessionId: "s" })).toBe(true);
    for (const t of useSessions.getState().tabs) await act(async () => { await useSessions.getState().close(t.id); });
  });
});
