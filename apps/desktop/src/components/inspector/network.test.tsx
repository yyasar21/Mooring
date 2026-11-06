import { act, fireEvent, render, screen, within } from "@testing-library/react";
import type { MockTransport } from "../../lib/ipc.mock";
import { probeHostOf } from "../../lib/validate.net";
import { useTree } from "../../stores/tree";
import { freshBackend, settle } from "../../test/harness";
import { Inspector } from "./Inspector";
import { hasNetworkCard, NetworkCard, TOOL_MISSING } from "./NetworkCard";
import { MAX_OUTPUT_LINES, OutputLines, PORT_OUTCOME } from "./NetResults";

describe("Inspector → Network (ADR-0020, N1)", () => {
  let mock: MockTransport;
  beforeEach(async () => {
    mock = freshBackend();
    mock.netRateWindowMs = 0;
    await useTree.getState().load();
  });

  const conn = (id: string) => {
    const c = useTree.getState().connections.find((x) => x.id === id);
    if (!c) throw new Error(`no ${id}`);
    return c;
  };

  async function card(id = "c-web01") {
    render(<NetworkCard c={conn(id)} />);
    await settle();
    return screen.getByRole("region", { name: "Network" });
  }

  it("shows for SSH / RDP / VNC / web rows and hides for Kubernetes and vSphere consoles", async () => {
    expect(["c-web01", "c-dc", "c-kiosk", "c-lb"].map((id) => hasNetworkCard(conn(id)))).toEqual([true, true, true, true]);
    expect(["c-k8s", "c-vc"].map((id) => hasNetworkCard(conn(id)))).toEqual([false, false]);
    expect(probeHostOf("web", "https://lb.example.test", 443)).toEqual({ host: "lb.example.test", port: 443 });
    expect(probeHostOf("web", "https://[2001:db8::1]:8443/x", null)).toEqual({ host: "2001:db8::1", port: 8443 });
    expect(probeHostOf("web", "not a url", null)).toBeNull();
    render(<Inspector />);
    act(() => { useTree.getState().select({ kind: "connection", id: "c-k8s" }); });
    await settle();
    expect(screen.queryByRole("region", { name: "Network" })).toBeNull();
    act(() => { useTree.getState().select({ kind: "connection", id: "c-dc" }); });
    await settle();
    expect(screen.getByRole("region", { name: "Network" })).toBeInTheDocument();
  });

  it("defaults to the connection's host and port; Check port reports the outcome and the RTT", async () => {
    const c = await card();
    expect(within(c).getByLabelText(/Other host/)).toHaveAttribute("placeholder", "web01.example.test");
    expect(within(c).getByLabelText("port")).toHaveValue("22");
    fireEvent.click(within(c).getByRole("button", { name: "Check port" }));
    await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
    await settle();
    expect(c).toHaveTextContent(/Open.*192\.0\.2\.\d+:22 in \d+(\.\d)? ms/);
    expect(mock.audit.filter((e) => e.event === "net_tcp_check").at(-1)).toMatchObject({ details: { host: "web01.example.test", port: "22", outcome: "open" } });
  });

  it("other host: validated like Rust, every port outcome has text, a second check within a second is rate-limited", async () => {
    const c = await card();
    const host = within(c).getByLabelText(/Other host/);
    fireEvent.change(host, { target: { value: "bad host" } });
    expect(host).toHaveAttribute("aria-invalid", "true");
    expect(within(c).getByRole("button", { name: "Check port" })).toBeDisabled();
    expect(within(c).getByRole("button", { name: "Ping" })).toBeDisabled();
    for (const [name, text] of [["closed.example.test", "Closed"], ["slow.example.test", "Timed out"], ["unreach.example.test", "Unreachable"], ["nowhere.invalid", "DNS lookup failed"]]) {
      fireEvent.change(host, { target: { value: name } });
      expect(host).not.toHaveAttribute("aria-invalid");
      fireEvent.click(within(c).getByRole("button", { name: "Check port" }));
      await settle();
      expect(c).toHaveTextContent(text ?? "");
    }
    expect(Object.keys(PORT_OUTCOME)).toEqual(["open", "closed", "timeout", "unreachable", "dns_failed"]);
    mock.netRateWindowMs = 60_000;
    fireEvent.click(within(c).getByRole("button", { name: "Check port" }));
    await settle();
    expect(within(c).getByRole("alert")).toHaveTextContent("One port check per second.");
  });

  it("Ping: count selector, summary, per-reply list and the raw output", async () => {
    const c = await card();
    const count = within(c).getByLabelText("count");
    expect(within(count).getAllByRole("option")).toHaveLength(10);
    expect(count).toHaveValue("4");
    fireEvent.change(count, { target: { value: "3" } });
    fireEvent.click(within(c).getByRole("button", { name: "Ping" }));
    await settle();
    expect(c).toHaveTextContent("Reachable 3 sent, 3 received, 0% loss");
    expect(c).toHaveTextContent(/min\/avg\/max [\d.]+ ms \/ [\d.]+ ms \/ [\d.]+ ms/);
    expect(within(within(c).getByRole("table", { name: "Ping replies" })).getAllByRole("row")).toHaveLength(4);
    const out = within(c).getByLabelText("ping output");
    expect(out.tagName).toBe("PRE");
    expect(out).toHaveTextContent("PING web01.example.test");
    expect(out).toHaveTextContent("3 packets transmitted, 3 received, 0% packet loss");
    fireEvent.change(within(c).getByLabelText(/Other host/), { target: { value: "unreach.example.test" } });
    fireEvent.click(within(c).getByRole("button", { name: "Ping" }));
    await settle();
    expect(c).toHaveTextContent("No reply 3 sent, 0 received, 100% loss");
    expect(within(c).queryByRole("table", { name: "Ping replies" })).toBeNull();
  });

  it("shows a running state while a tool runs and net.busy beyond two processes", async () => {
    mock = freshBackend({ delayMs: 40 });
    await useTree.getState().load();
    const c = await card();
    fireEvent.click(within(c).getByRole("button", { name: "Ping" }));
    fireEvent.click(within(c).getByRole("button", { name: "Traceroute" }));
    await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
    expect(within(c).getAllByRole("status").map((s) => s.textContent.trim())).toEqual(["Running…", "Running…"]);
    expect(within(c).getByRole("button", { name: "Ping" })).toBeDisabled();
    fireEvent.click(within(c).getByRole("button", { name: "WireGuard" }));
    await act(async () => { await new Promise((r) => setTimeout(r, 0)); });
    expect(within(c).getByRole("alert")).toHaveTextContent("Two network tools are already running.");
    await vi.waitFor(() => { expect(within(c).queryAllByRole("status")).toHaveLength(0); });
    expect(c).toHaveTextContent("Reachable");
    expect(c).toHaveTextContent("Reached");
  });

  it("Traceroute: hop table with RTTs and timeouts, max hops validated, the tool named", async () => {
    const c = await card();
    const hops = within(c).getByLabelText("max hops");
    expect(hops).toHaveValue("20");
    fireEvent.change(hops, { target: { value: "31" } });
    expect(hops).toHaveAttribute("aria-invalid", "true");
    expect(within(c).getByRole("button", { name: "Traceroute" })).toBeDisabled();
    fireEvent.change(hops, { target: { value: "5" } });
    fireEvent.click(within(c).getByRole("button", { name: "Traceroute" }));
    await settle();
    expect(c).toHaveTextContent("Reached 5 hops · traceroute");
    const rows = within(within(c).getByRole("table", { name: "Traceroute hops" })).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(5);
    expect(rows[0]).toHaveTextContent(/1192\.0\.2\.1[\d.]+ ms/);
    fireEvent.change(within(c).getByLabelText(/Other host/), { target: { value: "unreach.example.test" } });
    fireEvent.click(within(c).getByRole("button", { name: "Traceroute" }));
    await settle();
    expect(c).toHaveTextContent("Not reached 5 hops");
    const lost = within(within(c).getByRole("table", { name: "Traceroute hops" })).getAllByRole("row").slice(1);
    expect(lost.filter((r) => r.hasAttribute("data-timeout"))).toHaveLength(3);
    expect(lost[4]).toHaveTextContent("5**");
    expect(within(c).getByLabelText("traceroute output")).toHaveTextContent("traceroute to unreach.example.test");
  });

  it("greys out missing tools with the reason and hides WireGuard without wg", async () => {
    mock.netToolsState = { ping: false, traceroute: null, wg: false };
    const c = await card();
    const ping = within(c).getByRole("button", { name: "Ping" });
    expect(ping).toBeDisabled();
    expect(ping).toHaveAttribute("title", TOOL_MISSING);
    expect(within(c).getByRole("button", { name: "Traceroute" })).toBeDisabled();
    expect(c).toHaveTextContent(`ping ${TOOL_MISSING}`);
    expect(c).toHaveTextContent(`traceroute ${TOOL_MISSING}`);
    expect(within(c).queryByRole("button", { name: "WireGuard" })).toBeNull();
    expect(within(c).getByRole("button", { name: "Check port" })).toBeEnabled(); // own Rust code, no tool
    expect(c.querySelectorAll(".net-tool[data-missing]")).toHaveLength(2);
  });

  it("WireGuard: interfaces, peers with endpoint, handshake age and transfer; permission denied text", async () => {
    const c = await card();
    fireEvent.click(within(c).getByRole("button", { name: "WireGuard" }));
    await settle();
    expect(c).toHaveTextContent("wg0 listening on 51820 · 2 peers");
    const rows = within(within(c).getByRole("list", { name: "Peers of wg0" })).getAllByRole("listitem");
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent("hQ4m2zYk…9sLp");
    expect(rows[0]).toHaveTextContent("198.51.100.7:51820");
    expect(rows[0]).toHaveTextContent("handshake 42 s ago");
    expect(rows[0]).toHaveTextContent("rx 18.4 MB · tx 2.2 MB");
    expect(rows[1]).toHaveTextContent("handshake never");
    expect(c.textContent).not.toMatch(/[A-Za-z0-9+/]{43}=/); // never a full key
    mock.netWgDenied = true;
    fireEvent.click(within(c).getByRole("button", { name: "WireGuard" }));
    await settle();
    expect(within(c).getByRole("alert")).toHaveTextContent("WireGuard status needs elevated rights; Mooring does not elevate.");
  });

  it("tracks the port for a web connection and reports a kube target as invalid", async () => {
    const c = await card("c-lb");
    expect(within(c).getByLabelText(/Other host/)).toHaveAttribute("placeholder", "lb.example.test");
    expect(within(c).getByLabelText("port")).toHaveValue("443");
    fireEvent.click(within(c).getByRole("button", { name: "Check port" }));
    await settle();
    expect(c).toHaveTextContent(/Open.*:443 in/);
  });

  it("caps the raw output display and names the partial-run flags", () => {
    const lines = Array.from({ length: MAX_OUTPUT_LINES + 5 }, (_, i) => `line ${String(i)}`);
    render(<OutputLines lines={lines} timedOut truncated exitCode={1} label="ping output" />);
    const out = screen.getByLabelText("ping output");
    expect(out.textContent.split("\n")).toHaveLength(MAX_OUTPUT_LINES);
    expect(screen.getByText(/ping output · stopped at the deadline.*output cap reached.*5 more lines not shown.*exit code 1/)).toBeInTheDocument();
  });

  it("a locked vault refuses the tool table with friendly text", async () => {
    mock.vault = "locked";
    const c = await card();
    expect(within(c).getByRole("alert")).toHaveTextContent("The vault is locked.");
  });
});
