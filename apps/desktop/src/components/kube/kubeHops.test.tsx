// ADR-0025 on a Kubernetes cluster tab: `kube_open` forwards jump-host prompts and `hop_status` on
// its channel; the tab shows the hop strip and the same prompt dialogs as an SSH tab and answers
// them with `session_send` on the cluster handle.
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { App } from "../../App";
import { useKube } from "../../stores/kube";
import { useSessions } from "../../stores/sessions";
import { freshBackend, settle } from "../../test/harness";
import type { MockTransport } from "../../lib/ipc.mock";
import { decodeClusterEvent } from "../../lib/ipc.decode.kube";

async function boot() {
  render(<App />);
  await screen.findByText("Nothing open yet");
  await settle();
}

const tab = () => useSessions.getState().tabs[0];

describe("jump hosts on a Kubernetes cluster tab (ADR-0025)", () => {
  let mock: MockTransport;
  beforeEach(() => {
    mock = freshBackend();
    const k8s = mock.connections.find((c) => c.id === "c-k8s");
    if (k8s) k8s.via = ["c-bastion"];
  });

  it("asks to trust the hop key, shows the hop strip, then connects the cluster", async () => {
    const send = vi.spyOn(mock, "sessionSend");
    await boot();
    await act(async () => { await useSessions.getState().open("c-k8s"); });
    await settle();
    const trust = await screen.findByRole("alertdialog", { name: "Jump host bastion01: verify host identity" });
    expect(trust).toHaveTextContent("Hop 1 of 1 — bastion.stage.example.test:22");
    const strip = screen.getByRole("list", { name: "Jump hosts" });
    expect(within(strip).getByLabelText("Jump host 1 of 1, bastion01, bastion.stage.example.test:22: connecting")).toBeInTheDocument();
    expect(screen.getByText("Connecting to the API server…")).toBeInTheDocument();

    fireEvent.click(within(trust).getByRole("button", { name: "Trust and connect" }));
    await settle(6);
    expect(send).toHaveBeenCalledWith({ sessionId: tab()?.sessionId, input: { kind: "answer", id: 1000, text: "yes" } });
    expect(mock.trustedHosts.has("bastion.stage.example.test")).toBe(true);
    expect(tab()?.state).toBe("connected");
    expect(useKube.getState().clusters[tab()?.id ?? ""]?.identity?.user).toBe("ops@example.test");
    expect(screen.queryByRole("list", { name: "Jump hosts" })).toBeNull(); // hidden once connected
    expect(mock.audit.some((e) => e.event === "session_hop_open" && e.details.connection === "c-k8s")).toBe(true);
  });

  it("a rejected hop key closes the cluster with hop_failed, the failed chip and the hint", async () => {
    await boot();
    await act(async () => { await useSessions.getState().open("c-k8s"); });
    await settle();
    const trust = await screen.findByRole("alertdialog", { name: "Jump host bastion01: verify host identity" });
    fireEvent.click(within(trust).getByRole("button", { name: "Reject and disconnect" }));
    await settle(6);
    expect(tab()).toMatchObject({ state: "closed", closeCode: "hop_failed" });
    expect(within(screen.getByRole("list", { name: "Jump hosts" })).getByLabelText(/bastion01, .*: failed$/)).toBeInTheDocument();
    expect(screen.getByText("jump host bastion01: host key rejected")).toBeInTheDocument();
    expect(screen.getByText(/never contacted the target/)).toBeInTheDocument();
    expect(mock.clusters.size).toBe(0);
  });

  it("names the hop on a credential prompt and signs in through it", async () => {
    mock.trustedHosts.add("jump.stage.example.test");
    const k8s = mock.connections.find((c) => c.id === "c-k8s");
    if (k8s) k8s.via = ["c-jump"];
    await boot();
    await act(async () => { await useSessions.getState().open("c-k8s"); });
    await settle();
    const dlg = await screen.findByRole("alertdialog", { name: "Jump host ask-me: sign in" });
    fireEvent.change(within(dlg).getByLabelText("Username"), { target: { value: "ops" } });
    fireEvent.change(within(dlg).getByLabelText("Password"), { target: { value: "pw" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Sign in" }));
    await settle(6);
    expect(tab()?.hops?.[0]?.state).toBe("up");
    expect(tab()?.state).toBe("connected");
  });
});

describe("decodeClusterEvent", () => {
  it("reads connected, reuses the session decoder for hop events, and ignores unknown kinds", () => {
    expect(decodeClusterEvent({ kind: "connected", server: "https://k.example.test", identity: { user: "u", groups: ["g", 3] }, contextNamespace: "ns", rbac: {} }))
      .toEqual({ kind: "connected", server: "https://k.example.test", identity: { user: "u", groups: ["g"] }, contextNamespace: "ns" });
    expect(decodeClusterEvent({ kind: "connected", server: "s", identity: null, contextNamespace: null })).toMatchObject({ identity: null, contextNamespace: null });
    expect(decodeClusterEvent({ kind: "hop_status", hop: 0, of: 1, state: "up", host: "b.example.test:22" })).toMatchObject({ kind: "hop_status", hop: 0, state: "up" });
    expect(decodeClusterEvent({ kind: "prompt", id: 1000, message: "m", secret: false, purpose: "host_key_trust", account: null, certificate: null, hop: 0 })).toMatchObject({ kind: "prompt", hop: 0 });
    expect(decodeClusterEvent({ kind: "closed", reason: "r", code: "hop_lost" })).toEqual({ kind: "closed", reason: "r", code: "hop_lost" });
    expect(decodeClusterEvent({ kind: "bytes", data: "AA==" })).toBeNull();
  });
});
