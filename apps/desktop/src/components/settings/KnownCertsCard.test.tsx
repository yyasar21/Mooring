/// <reference types="vite/client" />
import { fireEvent, render, screen, within } from "@testing-library/react";
import type { MockTransport } from "../../lib/ipc.mock";

/** Everything that ships (no tests, no mocks, not the helper file itself). */
const UI_SOURCES = import.meta.glob<string>(["../../**/*.{ts,tsx}", "!../../**/*.test.{ts,tsx}", "!../../test/**", "!../../lib/ipc.mock*.ts", "!../../lib/hostHash.ts"], {
  eager: true,
  query: "?raw",
  import: "default",
});
import { useTree } from "../../stores/tree";
import { freshBackend, settle } from "../../test/harness";
import { KnownCertsCard } from "./KnownCertsCard";
import { filterPins, groupPins } from "./useKnownCerts";

const target = (protocol: "rdp" | "vnc", host: string, port: number) => ({ connectionId: "x", protocol, name: host, host, port, tags: [], options: undefined });

describe("Settings → Trust: known certificates", () => {
  let mock: MockTransport;
  beforeEach(async () => {
    mock = freshBackend();
    await useTree.getState().load();
  });

  async function card() {
    render(<KnownCertsCard />);
    await vi.waitFor(() => { expect(screen.queryByText("Loading…")).toBeNull(); });
    return screen.getByRole("region", { name: "Known certificates" });
  }

  it("shows an empty state per protocol", async () => {
    const c = await card();
    expect(c).toHaveTextContent("No stored certificates");
    expect(c).toHaveTextContent("RDP certificates appear here");
    fireEvent.click(within(c).getByRole("radio", { name: "VNC" }));
    await vi.waitFor(() => { expect(c).toHaveTextContent("VNC certificates appear here"); });
  });

  it("labels hashed pins with the matching connection, filters, and removes after confirmation", async () => {
    await mock.pin(target("rdp", "dc01.example.test", 3389), "2026-11-01T08:00:00Z");
    await mock.pin(target("rdp", "203.0.113.9", 3389), "2026-10-01T08:00:00Z");
    const c = await card();
    const list = within(c).getByRole("list", { name: "RDP certificates" });
    const rows = within(list).getAllByRole("listitem");
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent("dc01.example.test:3389");
    expect(rows[0]).toHaveTextContent("dc01");
    expect(rows[0]).toHaveTextContent("First seen 2026-11-01");
    expect(rows[1]).toHaveTextContent("Host not in your connections (stored hashed)");

    fireEvent.change(within(c).getByLabelText("Search"), { target: { value: "dc01" } });
    expect(within(list).getAllByRole("listitem")).toHaveLength(1);
    fireEvent.change(within(c).getByLabelText("Search"), { target: { value: "nothing-like-this" } });
    expect(c).toHaveTextContent("Nothing matches");
    fireEvent.change(within(c).getByLabelText("Search"), { target: { value: "" } });

    const first = within(c).getAllByRole("listitem")[0] as HTMLElement;
    fireEvent.click(within(first).getByRole("button", { name: "Remove…" }));
    const dlg = screen.getByRole("dialog", { name: "Remove stored certificate" });
    expect(dlg).toHaveTextContent("dc01.example.test:3389 (dc01)");
    expect(dlg).toHaveTextContent("recorded in the audit log");
    expect(document.activeElement).toBe(within(dlg).getByRole("button", { name: "Cancel" }));
    fireEvent.click(within(dlg).getByRole("button", { name: "Remove certificate" }));
    await settle();
    await vi.waitFor(() => { expect(within(c).getAllByRole("listitem")).toHaveLength(1); });
    expect(within(c).getByRole("status")).toHaveTextContent("Removed the stored certificate for dc01.example.test:3389");
    expect((await mock.auditTail({ limit: 5, before: null })).some((e) => e.event === "trust_cert_removed")).toBe(true);
  });

  it("an unmatched pin asks for host and port, and says when nothing matched", async () => {
    await mock.pin(target("vnc", "198.51.100.4", 5901));
    const c = await card();
    fireEvent.click(within(c).getByRole("radio", { name: "VNC" }));
    await vi.waitFor(() => { expect(within(c).getAllByRole("listitem")).toHaveLength(1); });
    fireEvent.click(within(c).getByRole("button", { name: "Remove…" }));
    const dlg = screen.getByRole("dialog", { name: "Remove stored certificate" });
    const remove = within(dlg).getByRole("button", { name: "Remove certificate" });
    expect(remove).toBeDisabled();
    fireEvent.change(within(dlg).getByLabelText("Host"), { target: { value: "198.51.100.4" } });
    expect(within(dlg).getByLabelText("Port")).toHaveValue("5900");
    fireEvent.click(remove);
    await settle();
    expect(dlg).toHaveTextContent("No stored VNC certificate matches 198.51.100.4:5900.");
    fireEvent.change(within(dlg).getByLabelText("Port"), { target: { value: "5901" } });
    fireEvent.click(remove);
    await settle();
    await vi.waitFor(() => { expect(c).toHaveTextContent("No stored certificates"); });
  });

  it("shows a locked vault as an error, not as an empty list", async () => {
    mock.vault = "locked";
    const c = await card();
    expect(within(c).getByRole("alert")).toHaveTextContent("The vault is locked.");
    expect(c).not.toHaveTextContent("No stored certificates");
  });

  it("labels from the wire's host/port, never by hashing in the UI (N-33)", async () => {
    // A pin the mock would not name (no connection) but the wire says belongs to kiosk: the label follows the wire.
    const list = mock.knownCertsList;
    mock.knownCertsList = async (a) => (await list(a)).map((r) => ({ ...r, host: "kiosk.example.test", port: 5900 }));
    await mock.pin(target("vnc", "198.51.100.4", 5901));
    const c = await card();
    fireEvent.click(within(c).getByRole("radio", { name: "VNC" }));
    await vi.waitFor(() => { expect(within(c).getAllByRole("listitem")).toHaveLength(1); });
    const row = within(c).getAllByRole("listitem")[0];
    expect(row).toHaveTextContent("kiosk.example.test:5900");
    expect(row).toHaveTextContent("kiosk"); // the seed connection with that host:port
  });

  it("no UI module reaches the mock's HMAC helpers (one crypto path, in Rust)", () => {
    const offenders = Object.entries(UI_SOURCES).filter(([, src]) => /\b(hashHost|hostMatches)\b/.test(src)).map(([p]) => p);
    expect(offenders).toEqual([]);
  });

  it("groups conflicting pins of one host:port, flags them, and Remove on either clears all (6b L-35)", async () => {
    await mock.pin(target("rdp", "203.0.113.9", 3389), "2026-10-01T08:00:00Z");
    await mock.pin(target("rdp", "dc01.example.test", 3389), "2026-11-01T08:00:00Z");
    await mock.pin(target("rdp", "dc01.example.test", 3389), "2026-11-03T08:00:00Z", "#laptop");
    const c = await card();
    expect(c).toHaveTextContent("marked as a conflict");
    expect(c).toHaveTextContent("“Trust once (this sync only)”, then “Trust and remember”");
    const rows = within(within(c).getByRole("list", { name: "RDP certificates" })).getAllByRole("listitem");
    expect(rows).toHaveLength(3);
    // the conflicting pair comes first, adjacent, each flagged with its own Remove; the lone pin is not flagged
    expect(rows[0]).toHaveAttribute("data-conflict");
    expect(rows[1]).toHaveAttribute("data-conflict");
    expect(rows[2]).not.toHaveAttribute("data-conflict");
    expect(rows[0]).toHaveTextContent("Conflict");
    expect(rows[0]).toHaveTextContent("dc01.example.test:3389");
    expect(rows[1]).toHaveTextContent("dc01.example.test:3389");
    expect(rows[2]).toHaveTextContent("Host not in your connections");
    expect(within(rows[0] as HTMLElement).getByRole("button", { name: "Remove…" })).toBeInTheDocument();
    fireEvent.click(within(rows[1] as HTMLElement).getByRole("button", { name: "Remove…" }));
    const dlg = screen.getByRole("dialog", { name: "Remove stored certificate" });
    expect(dlg).toHaveTextContent("conflicting stored certificates (synced from another device); removing clears all of them");
    fireEvent.click(within(dlg).getByRole("button", { name: "Remove certificate" }));
    await settle();
    await vi.waitFor(() => { expect(within(c).getAllByRole("listitem")).toHaveLength(1); });
    expect(within(c).getAllByRole("listitem")[0]).not.toHaveAttribute("data-conflict");
  });

  it("groupPins flags only known hosts with two fingerprints and keeps the wire order otherwise", () => {
    const row = (fp: string, host: string | null) => ({ hostHash: `|2|s|${fp}`, fingerprint: fp, addedAt: "2026-01-01", target: host ? { host, port: 3389 } : null, connections: [] });
    const out = groupPins([row("a", "x.example.test"), row("b", null), row("c", "y.example.test"), row("c", "y.example.test"), row("d", "x.example.test")]);
    expect(out.map((r) => [r.fingerprint, r.conflict])).toEqual([["a", true], ["d", true], ["c", false], ["c", false], ["b", false]]);
  });

  it("filterPins matches names, host:port and the fingerprint with or without colons", () => {
    const rows = [{ hostHash: "h", fingerprint: "SHA256:abcd", addedAt: "2026-01-01", target: { host: "a.example.test", port: 3389 }, connections: ["alpha"], conflict: false }];
    expect(filterPins(rows, "ALPHA")).toHaveLength(1);
    expect(filterPins(rows, "a.example.test:3389")).toHaveLength(1);
    expect(filterPins(rows, "ab:cd")).toHaveLength(1);
    expect(filterPins(rows, "zzz")).toHaveLength(0);
  });
});
