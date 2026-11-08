import { act, fireEvent, render, screen, within } from "@testing-library/react";
import type { MockTransport } from "../../lib/ipc.mock";
import { useCredentials } from "../../stores/credentials";
import { useKube } from "../../stores/kube";
import { useSessions } from "../../stores/sessions";
import { useTree } from "../../stores/tree";
import { freshBackend, settle } from "../../test/harness";
import { Workspace } from "../Workspace";
import { KUBE_POLL_MS } from "./useCluster";
import { matchesPod, podStatus } from "./podStatus";

let mock: MockTransport;

async function openCluster(prepare?: (m: MockTransport) => void) {
  mock = freshBackend();
  mock.logFollowMs = 60_000;
  prepare?.(mock);
  await useTree.getState().load();
  await useCredentials.getState().load();
  render(<Workspace />);
  await act(async () => { await useSessions.getState().open("c-k8s"); });
  await settle(5);
  return screen.getByRole("tabpanel");
}

const row = (name: string) => screen.getByRole("row", { name: new RegExp(name) });

describe("ClusterBrowser", () => {
  it("opens with kube_open, not session_open, and shows the read-only banner and identity", async () => {
    const spy = vi.fn();
    const panel = await openCluster((m) => { vi.spyOn(m, "sessionOpen").mockImplementation(spy); });
    expect(spy).not.toHaveBeenCalled();
    expect(within(panel).getByRole("note")).toHaveTextContent("Mooring never mutates this cluster");
    expect(within(panel).getByText("https://k8s.stage.example.test:6443")).toBeInTheDocument();
    expect(within(panel).getByText("ops@example.test")).toBeInTheDocument();
    const tab = useSessions.getState().tabs[0];
    expect(tab?.kube).toEqual({ view: "cluster" });
    expect(tab?.sessionId).toMatch(/^k-/);
    expect(useKube.getState().clusters[tab?.id ?? ""]?.identity?.groups).toContain("platform-ops");
  });

  it("lists contexts and namespaces, starts in the context namespace, and switches", async () => {
    const panel = await openCluster();
    const ctx = within(panel).getByRole("list", { name: "Contexts" });
    expect(within(ctx).getByText("stage-admin")).toHaveAttribute("aria-current", "true");
    expect(within(ctx).getByText("stage-readonly")).toHaveAttribute("aria-disabled", "true");
    const ns = within(panel).getByRole("list", { name: "Namespaces" });
    expect(within(ns).getByRole("button", { name: "payments" })).toHaveAttribute("aria-current", "true");
    expect(screen.getAllByRole("row")).toHaveLength(6); // header + 5 pods
    fireEvent.click(within(ns).getByRole("button", { name: "monitoring" }));
    await settle(5);
    expect(row("prometheus-0")).toBeInTheDocument();
    expect(screen.queryByText("api-7f9c8d6b5-2kqzt")).toBeNull();
  });

  it("shows status badges, restarts and the RBAC pre-flight; denied actions are disabled", async () => {
    await openCluster();
    expect(within(row("worker-5b8f7c9d4")).getByText("Restarting")).toHaveAttribute("data-tone", "hot");
    expect(within(row("api-7f9c8d6b5-2kqzt")).getByText("Running")).toHaveAttribute("data-tone", "ok");
    expect(within(row("migrate-29c41")).getByText("Completed")).toBeInTheDocument();
    const rbac = screen.getByRole("list", { name: "Permissions in payments" });
    expect(within(rbac).getAllByText("Allowed")).toHaveLength(5);
    fireEvent.click(within(screen.getByRole("list", { name: "Namespaces" })).getByRole("button", { name: "kube-system" }));
    await settle(5);
    const denied = screen.getByRole("list", { name: "Permissions in kube-system" });
    expect(within(denied).getAllByText("Denied")).toHaveLength(3);
    fireEvent.click(row("coredns"));
    expect(screen.getByRole("button", { name: "Exec into coredns" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Logs of coredns" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Forward port 53 of coredns" })).toBeDisabled();
    expect(screen.getByText("The token may not exec into pods in this namespace.")).toBeInTheDocument();
  });

  it("searches pods by name, node and image", async () => {
    await openCluster();
    fireEvent.change(screen.getByRole("searchbox", { name: "Search pods" }), { target: { value: "node-b api" } });
    expect(screen.getAllByRole("row")).toHaveLength(2);
    expect(row("api-7f9c8d6b5-9wmrx")).toBeInTheDocument();
    fireEvent.change(screen.getByRole("searchbox", { name: "Search pods" }), { target: { value: "nothing-here" } });
    expect(screen.getByText("No pod matches the search.")).toBeInTheDocument();
  });

  it("exec opens a terminal tab through kube_exec_open with the chosen allow-listed shell", async () => {
    await openCluster();
    const spy = vi.spyOn(mock, "kubeExecOpen");
    const session = vi.spyOn(mock, "sessionOpen");
    fireEvent.click(row("api-7f9c8d6b5-2kqzt"));
    fireEvent.change(screen.getByLabelText("Exec command"), { target: { value: "/bin/bash" } });
    act(() => { fireEvent.click(screen.getByRole("button", { name: "Exec into envoy" })); });
    await settle(5);
    const parent = useSessions.getState().tabs[0]?.sessionId;
    expect(spy).toHaveBeenCalledWith(expect.objectContaining({
      sessionId: parent, namespace: "payments", pod: "api-7f9c8d6b5-2kqzt", container: "envoy", command: "/bin/bash", size: { width: 80, height: 24 },
    }));
    expect(session).not.toHaveBeenCalled();
    const exec = useSessions.getState().tabs[1];
    expect(exec).toMatchObject({ kube: { view: "exec" }, state: "connected", protocol: "kubernetes" });
    expect(useSessions.getState().activeTab).toBe(exec?.id);
    expect(screen.getByRole("tab", { name: /stage-cluster · api-7f9c8d6b5-2kqzt\/envoy, connected/ })).toBeInTheDocument();
    // Opening the connection again goes back to the cluster tab, not the exec tab.
    await act(async () => { await useSessions.getState().open("c-k8s"); });
    expect(useSessions.getState().activeTab).toBe(useSessions.getState().tabs[0]?.id);
  });

  it("logs opens a logs tab; a port opens the Forwards panel pre-filled with kind pod", async () => {
    await openCluster();
    fireEvent.click(row("api-7f9c8d6b5-2kqzt"));
    act(() => { fireEvent.click(screen.getByRole("button", { name: "Logs of api" })); });
    await settle(3);
    expect(useSessions.getState().tabs[1]?.kube).toMatchObject({ view: "logs", logs: { pod: "api-7f9c8d6b5-2kqzt", container: "api" } });
    act(() => { useSessions.getState().activate(useSessions.getState().tabs[0]?.id ?? ""); });

    const spy = vi.spyOn(mock, "forwardOpen");
    fireEvent.click(screen.getByRole("button", { name: "Forward port 9090 of api" }));
    await settle();
    const form = screen.getByRole("form", { name: "New pod forward" });
    expect(within(form).getByLabelText("Pod")).toHaveValue("payments/api-7f9c8d6b5-2kqzt");
    expect(within(form).getByLabelText("Pod port")).toHaveValue("9090");
    fireEvent.click(within(form).getByRole("button", { name: "Open forward" }));
    await settle();
    expect(spy).toHaveBeenCalledWith({
      sessionId: useSessions.getState().tabs[0]?.sessionId,
      kind: "pod",
      bind: { host: "127.0.0.1", port: 9090 },
      target: { namespace: "payments", pod: "api-7f9c8d6b5-2kqzt", port: 9090 },
      exposure: "loopback",
    });
    expect(within(screen.getByRole("table", { name: "Forwards on this session" })).getByText("payments/api-7f9c8d6b5-2kqzt:9090")).toBeInTheDocument();
  });

  it("falls back to the context namespace and the allowed list when namespaces may not be listed", async () => {
    mock = freshBackend();
    mock.denyNamespaceList = true;
    mock.connections = mock.connections.map((c) => (c.id === "c-k8s" ? { ...c, options: { allowedNamespaces: ["monitoring"] } as never } : c));
    await useTree.getState().load();
    render(<Workspace />);
    await act(async () => { await useSessions.getState().open("c-k8s"); });
    await settle(5);
    expect(screen.getByText(/The token may not list namespaces/)).toBeInTheDocument();
    const ns = screen.getByRole("list", { name: "Namespaces" });
    expect(within(ns).getAllByRole("button").map((b) => b.textContent)).toEqual(["payments", "monitoring"]);
  });

  it("follows pod changes with the kube_pods poll (K4 has no watch), and closing the tab closes the cluster session", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    try {
      await openCluster();
      const pod = mock.pods.payments?.find((p) => p.name === "ledger-0");
      if (!pod) throw new Error("seed");
      const poll = async () => {
        await act(async () => { await vi.advanceTimersByTimeAsync(KUBE_POLL_MS); });
        await settle();
      };
      mock.kubeSetPod("payments", { ...pod, phase: "Running", node: "node-a", containers: pod.containers.map((c) => ({ ...c, ready: true })) });
      expect(within(row("ledger-0")).queryByText("Running")).toBeNull(); // not before the next poll
      await poll();
      expect(within(row("ledger-0")).getByText("Running")).toBeInTheDocument();
      mock.kubeSetPod("payments", pod, true);
      await poll();
      expect(screen.queryByText("ledger-0")).toBeNull();
    } finally {
      vi.useRealTimers();
    }
    const sid = useSessions.getState().tabs[0]?.sessionId ?? "";
    await act(async () => { await useSessions.getState().close(useSessions.getState().tabs[0]?.id ?? ""); });
    expect(mock.clusters.has(sid)).toBe(false);
  });

  it("shows the failure and offers Reconnect when kube_open fails", async () => {
    mock = freshBackend({ vault: "locked" });
    useTree.setState({ connections: [{ id: "c-k8s", folderId: "f-root", name: "stage-cluster", protocol: "kubernetes", host: "https://k8s.example.test", port: null, credentialId: null, effectiveCredentialId: null, usernameOverride: null, domainOverride: null, gatewayCredentialId: null, becomeCredentialId: null, tags: [], createdAt: "", updatedAt: "" }] });
    render(<Workspace />);
    await act(async () => { await useSessions.getState().open("c-k8s"); });
    expect(screen.getByRole("status")).toHaveTextContent("The vault is locked.");
    mock.vault = "unlocked";
    act(() => { fireEvent.click(screen.getByRole("button", { name: "Reconnect" })); });
    await settle(5);
    expect(screen.getByRole("table", { name: "Pods" })).toBeInTheDocument();
  });
});

describe("pod helpers", () => {
  const p = { name: "a", phase: "Running" as const, node: "n1", createdAt: "", containers: [{ name: "c", image: "registry.example.test/x:1", ready: true, restarts: 0, ports: [] }] };
  it("badges and search", () => {
    expect(podStatus(p)).toEqual({ label: "Running", tone: "ok" });
    expect(podStatus({ ...p, phase: "Unknown" }).tone).toBe("hot");
    expect(matchesPod(p, "n1 x:1")).toBe(true);
    expect(matchesPod(p, "n2")).toBe(false);
  });
});
