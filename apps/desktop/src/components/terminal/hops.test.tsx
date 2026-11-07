import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { App } from "../../App";
import { useSessions } from "../../stores/sessions";
import { freshBackend, settle } from "../../test/harness";
import type { MockTransport } from "../../lib/ipc.mock";

async function boot() {
  render(<App />);
  await screen.findByText("Nothing open yet");
  await settle();
}

const tab = () => useSessions.getState().tabs[0];

describe("jump hosts on a session tab (ADR-0025)", () => {
  let mock: MockTransport;
  beforeEach(() => { mock = freshBackend(); });

  it("names the hop in its host-key prompt and shows per-hop chips until the target connects", async () => {
    await boot();
    await act(async () => { await useSessions.getState().open("c-stg"); });
    await settle();
    const trust = await screen.findByRole("alertdialog", { name: "Jump host bastion01: verify host identity" });
    expect(trust).toHaveTextContent("Hop 1 of 1 — bastion.stage.example.test:22");
    const strip = screen.getByRole("list", { name: "Jump hosts" });
    expect(within(strip).getByLabelText("Jump host 1 of 1, bastion01, bastion.stage.example.test:22: connecting")).toBeInTheDocument();

    fireEvent.click(within(trust).getByRole("button", { name: "Trust and connect" }));
    await settle();
    expect(mock.trustedHosts.has("bastion.stage.example.test")).toBe(true);
    // the chip is up; now the target asks, without a hop name
    expect(within(screen.getByRole("list", { name: "Jump hosts" })).getByLabelText(/bastion01, .*: connected$/)).toBeInTheDocument();
    const target = await screen.findByRole("alertdialog", { name: "Verify host identity" });
    fireEvent.click(within(target).getByRole("button", { name: "Trust and connect" }));
    await settle(6);
    expect(tab()?.state).toBe("connected");
    expect(screen.queryByRole("list", { name: "Jump hosts" })).toBeNull();
  });

  it("shows a failed chip and the hop_failed text when the hop key is rejected", async () => {
    await boot();
    await act(async () => { await useSessions.getState().open("c-stg"); });
    await settle();
    const trust = await screen.findByRole("alertdialog", { name: "Jump host bastion01: verify host identity" });
    fireEvent.click(within(trust).getByRole("button", { name: "Reject and disconnect" }));
    await settle(6);
    expect(tab()).toMatchObject({ state: "closed", closeCode: "hop_failed" });
    expect(within(screen.getByRole("list", { name: "Jump hosts" })).getByLabelText(/bastion01, .*: failed$/)).toBeInTheDocument();
    expect(screen.getByText(/never contacted the target/)).toBeInTheDocument();
    expect(screen.getByText(/Disconnected: jump host bastion01: host key rejected/)).toBeInTheDocument();
  });

  it("names the hop on a credential prompt from a jump host", async () => {
    mock.trustedHosts.add("jump.stage.example.test");
    const stg = mock.connections.find((c) => c.id === "c-stg");
    if (stg) stg.via = ["c-jump"];
    await boot();
    await act(async () => { await useSessions.getState().open("c-stg"); });
    await settle();
    const dlg = await screen.findByRole("alertdialog", { name: "Jump host ask-me: sign in" });
    fireEvent.change(within(dlg).getByLabelText("Username"), { target: { value: "ops" } });
    fireEvent.change(within(dlg).getByLabelText("Password"), { target: { value: "pw" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Sign in" }));
    await settle();
    expect(tab()?.hops?.[0]?.state).toBe("up");
  });
});
