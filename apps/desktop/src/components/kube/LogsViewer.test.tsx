import { act, fireEvent, render, screen, within } from "@testing-library/react";
import type { LogChunk } from "../../lib/ipc";
import type { MockTransport } from "../../lib/ipc.mock";
import { openLogs } from "../../stores/kube";
import { useSessions } from "../../stores/sessions";
import { useTree } from "../../stores/tree";
import { freshBackend, settle } from "../../test/harness";
import { Workspace } from "../Workspace";
import { formatBytes } from "./LogsViewer";
import { sanitizeLogLine } from "./useLogStream";

let mock: MockTransport;

async function logsTab(pod = "api-7f9c8d6b5-2kqzt", container = "api", namespace = "payments", before?: (m: MockTransport) => void) {
  mock = freshBackend();
  mock.logFollowMs = 60_000; // follow streams stay quiet unless a test pushes chunks
  before?.(mock);
  await useTree.getState().load();
  render(<Workspace />);
  const { sessionId } = await mock.kubeOpen({ connectionId: "c-k8s" });
  await act(async () => { await openLogs("c-k8s", { parentSessionId: sessionId, namespace, pod, container }); });
  await settle(4);
  return { sessionId, region: screen.getByRole("region", { name: new RegExp(`Logs of ${pod}`) }) };
}

const lines = () => within(screen.getByLabelText("Log lines")).queryAllByText(/./);

describe("LogsViewer", () => {
  it("streams the tail with follow on by default and shows the byte count", async () => {
    let spy: unknown = null;
    await logsTab(undefined, undefined, undefined, (m) => { spy = vi.spyOn(m, "kubeLogs"); });
    expect(spy).toHaveBeenCalledWith(expect.objectContaining({ namespace: "payments", pod: "api-7f9c8d6b5-2kqzt", container: "api", follow: true, tailLines: 500, timestamps: false, sinceSeconds: null }));
    expect(lines().length).toBeGreaterThan(100);
    expect(screen.getByText("Following")).toBeInTheDocument();
    expect(screen.getByText(/lines · .* of 8 MiB/)).toBeInTheDocument();
    expect(useSessions.getState().tabs[0]).toMatchObject({ kube: { view: "logs" }, state: "connected", sessionId: null });
  });

  it("appends followed chunks, splitting lines across chunk borders", async () => {
    const { sessionId } = await logsTab();
    const stream = [...(mock.clusters.get(sessionId)?.logs.values() ?? [])][0];
    if (!stream) throw new Error("no stream");
    const before = lines().length;
    const send = (text: string) => { act(() => { stream.emit({ kind: "data", data: new TextEncoder().encode(text) } satisfies LogChunk); }); };
    send("partial li");
    send("ne done\nsecond‮ line\n");
    expect(lines().length).toBe(before + 2);
    expect(screen.getByText("partial line done")).toBeInTheDocument();
    expect(screen.getByText("second� line")).toBeInTheDocument();
  });

  it("searches with a match count, highlights, and can show only matching lines", async () => {
    await logsTab();
    fireEvent.change(screen.getByRole("searchbox", { name: "Search logs" }), { target: { value: "upstream timeout" } });
    const count = screen.getByText(/\d+ match(es)?/);
    const n = Number(/(\d+)/.exec(count.textContent)?.[1]);
    expect(n).toBeGreaterThan(10);
    expect(document.querySelectorAll(".kube-log-body mark")).toHaveLength(n);
    fireEvent.click(screen.getByRole("checkbox", { name: "Only matches" }));
    expect(document.querySelectorAll(".kube-log-line")).toHaveLength(n);
  });

  it("restarts the stream when the container, tail or timestamps change, and stops it on close", async () => {
    const { sessionId } = await logsTab();
    const spy = vi.spyOn(mock, "kubeLogs");
    const stop = vi.spyOn(mock, "kubeLogsStop");
    fireEvent.change(screen.getByLabelText("Container"), { target: { value: "envoy" } });
    await settle(3);
    expect(spy).toHaveBeenLastCalledWith(expect.objectContaining({ container: "envoy" }));
    expect(stop).toHaveBeenCalledTimes(1);
    fireEvent.change(screen.getByLabelText("Tail lines"), { target: { value: "20" } });
    fireEvent.keyDown(screen.getByLabelText("Tail lines"), { key: "Enter" });
    await settle(3);
    expect(spy).toHaveBeenLastCalledWith(expect.objectContaining({ tailLines: 20 }));
    expect(lines()).toHaveLength(20);
    fireEvent.change(screen.getByLabelText("Tail lines"), { target: { value: "20000" } });
    expect(screen.getByLabelText("Tail lines")).toHaveAttribute("aria-invalid", "true");
    fireEvent.click(screen.getByRole("checkbox", { name: "Timestamps" }));
    await settle(3);
    expect(spy).toHaveBeenLastCalledWith(expect.objectContaining({ timestamps: true, tailLines: 20 }));
    expect(lines()[0]?.textContent).toMatch(/^2026-11-01T/);
    await act(async () => { await useSessions.getState().close(useSessions.getState().tabs[0]?.id ?? ""); });
    expect(mock.clusters.get(sessionId)?.logs.size).toBe(0);
  });

  it("without follow the stream ends; Stop and Restart work", async () => {
    await logsTab();
    fireEvent.click(screen.getByRole("button", { name: "Stop" }));
    expect(screen.getByText("Stopped")).toBeInTheDocument();
    const n = lines().length;
    fireEvent.click(screen.getByRole("button", { name: "Restart" }));
    await settle(4);
    expect(screen.getByText("Following")).toBeInTheDocument();
    expect(lines().length).toBe(n);
    fireEvent.click(screen.getByRole("checkbox", { name: "Follow" }));
    await settle(4);
    expect(screen.getByText("Ended")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Restart" })).toBeInTheDocument();
  });

  it("says so when Rust stops the stream at the byte cap", async () => {
    await logsTab("log-flood-8c7d6-zz1aa", "flood", "monitoring", (m) => {
      m.connections = m.connections.map((c) => (c.id === "c-k8s" ? { ...c, options: { maxLogBytes: 65_536 } as never } : c));
    });
    expect(screen.getByText(/Stopped at the 64 KiB log limit of this connection/)).toBeInTheDocument();
    expect(screen.getByText("Ended")).toBeInTheDocument();
    expect(screen.getByText(/lines · 64 KiB of 64 KiB/)).toBeInTheDocument();
  });

  it("shows a refusal from the backend", async () => {
    await logsTab("kube-proxy-p7m2c", "kube-proxy", "kube-system");
    expect(screen.getByRole("alert")).toHaveTextContent("The cluster's RBAC does not let this token do that here.");
  });
});

describe("log helpers", () => {
  it("formats bytes and sanitises lines", () => {
    expect(formatBytes(8 * 1024 * 1024)).toBe("8 MiB");
    expect(formatBytes(65_536)).toBe("64 KiB");
    expect(formatBytes(12)).toBe("12 B");
    expect(sanitizeLogLine("a\tb\x1b[31mred\r")).toBe("a\tb�[31mred");
  });
});
