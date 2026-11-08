import { act, render, screen } from "@testing-library/react";
import { App } from "../../App";
import { POLLED_COMMANDS } from "../../lib/ipc";
import type { MockTransport } from "../../lib/ipc.mock";
import { decodeLease, leaseChip, leaseDuration, nextView, useLeases, type LeaseView } from "../../stores/leases";
import { remaining } from "./LeaseChip";
import { useSessions } from "../../stores/sessions";
import { freshBackend, settle } from "../../test/harness";

async function boot() {
  render(<App />);
  await screen.findByText("Nothing open yet");
  await settle();
}

const tab = () => useSessions.getState().tabs[0];
const tabEl = () => screen.getByRole("tab", { name: /^pg-reporting/ });

async function openReporting(mock: MockTransport) {
  mock.trustedHosts.add("report.example.test");
  await act(async () => { await useSessions.getState().open("c-report"); });
  await settle(6);
}

describe("lease chips on a session tab (ADR-0026 §2)", () => {
  let mock: MockTransport;
  beforeEach(() => {
    mock = freshBackend();
    useLeases.getState().reset();
  });
  afterEach(() => { vi.useRealTimers(); });

  it("polls the passive session_list and shows when the lease renews, with engine and role in the tooltip", async () => {
    expect(POLLED_COMMANDS).toContain("session_list");
    await boot();
    await openReporting(mock);
    expect(tab()?.state).toBe("connected");
    expect(mock.audit.some((a) => a.event === "secret_lease_issued")).toBe(true);
    const chip = tabEl().querySelector(".lease-chip");
    // TTL 3600 s, renewed at 2/3 → in 40 min.
    expect(chip).toHaveTextContent("Lease · renews in 40 min");
    expect(chip?.getAttribute("data-state")).toBe("active");
    expect(chip?.getAttribute("title")).toMatch(/^Database lease for Vault role reporting\. Mooring renews it at two thirds/);
    // The accessible name carries the same facts, never an id.
    expect(tabEl().getAttribute("aria-label")).toMatch(/Lease · renews in 40 min \(Database lease for Vault role reporting/);
    expect(document.body.innerHTML).not.toMatch(/lease_id|database\/creds/);
  });

  it("a session without a dynamic credential has no chip", async () => {
    await boot();
    mock.trustedHosts.add("web01.example.test");
    await act(async () => { await useSessions.getState().open("c-web01"); });
    await settle(6);
    expect(document.querySelector(".lease-chip")).toBeNull();
  });

  it("shows a failed renewal as a warning and an expired lease as an error", async () => {
    mock.leaseRenewFails = true;
    await boot();
    const t0 = Date.now();
    await openReporting(mock);
    const s = tab();
    if (!s) throw new Error("no tab");
    vi.useFakeTimers({ toFake: ["Date"], now: t0 + 2500 * 1000 });
    await act(async () => { await useLeases.getState().poll(useSessions.getState().tabs); });
    expect(useLeases.getState().byTab[s.id]?.[0]?.state).toBe("renew_failed");
    expect(mock.audit.some((a) => a.event === "secret_lease_renew_failed")).toBe(true);
    expect(leaseChip(useLeases.getState().byTab[s.id] ?? [], "connected", Date.now())).toEqual({ state: "renew_failed", text: "Lease · renewal failed, expires in 18 min" });
    vi.setSystemTime(t0 + 3700 * 1000);
    await act(async () => { await useLeases.getState().poll(useSessions.getState().tabs); });
    expect(leaseChip(useLeases.getState().byTab[s.id] ?? [], "connected", Date.now())).toEqual({ state: "expired", text: "Lease expired" });
  });

  it("says the lease was revoked once the session closes", async () => {
    await boot();
    await openReporting(mock);
    const s = tab();
    if (!s) throw new Error("no tab");
    await act(async () => { await useSessions.getState().close(s.id); });
    await settle();
    expect(mock.audit.some((a) => a.event === "secret_lease_revoked" && a.details.reason === "closed")).toBe(true);
    expect(leaseChip(useLeases.getState().byTab[s.id] ?? [], "closed", Date.now())).toEqual({ state: "revoked", text: "Lease revoked" });
  });

  it("a lease refusal closes the tab with the contract's text", async () => {
    mock.leaseRefused = true;
    await boot();
    await openReporting(mock);
    expect(tab()?.state).toBe("closed");
    expect(tab()?.reason).toMatch(/^Vault did not hand out a lease for the dynamic credential, so Mooring did not use it and did not connect\./);
    expect(document.querySelector(".lease-chip")).toBeNull();
  });

  it("the vault lock drains leases; the session survives without a chip", async () => {
    await boot();
    await openReporting(mock);
    await act(async () => { await mock.vaultLock("user"); });
    expect(mock.audit.some((a) => a.event === "secret_lease_revoked" && a.details.reason === "locked")).toBe(true);
    const rows = await mock.sessionList();
    expect(rows.find((r) => r.connectionId === "c-report")?.leases).toBeUndefined();
  });
});

describe("lease math", () => {
  const view = (p: Partial<LeaseView>): LeaseView => ({ engine: "database", state: "active", renewable: true, expiresAt: 0, ttlSeconds: 3600, ...p });

  it("decodes only well-formed rows", () => {
    expect(decodeLease({ engine: "database", expiresInSeconds: 60, renewable: true, state: "active" })).toEqual({ engine: "database", expiresInSeconds: 60, renewable: true, state: "active", ttlSeconds: null });
    // R6 `ttlSeconds`: kept when positive; a bad value is unknown, never a dropped row.
    expect(decodeLease({ engine: "database", expiresInSeconds: 60, renewable: true, state: "active", ttlSeconds: 3600 })?.ttlSeconds).toBe(3600);
    for (const ttl of [null, -5, 0, "3600", Number.NaN]) {
      expect(decodeLease({ engine: "database", expiresInSeconds: 60, renewable: true, state: "active", ttlSeconds: ttl })?.ttlSeconds).toBeNull();
    }
    expect(decodeLease({ engine: "database", expiresInSeconds: null, renewable: false, state: "expired" })?.expiresInSeconds).toBeNull();
    for (const bad of [null, "x", { engine: 1, renewable: true, state: "active" }, { engine: "database", renewable: "yes", state: "active" }, { engine: "database", renewable: true, state: "active", expiresInSeconds: -1 }]) {
      expect(decodeLease(bad)).toBeNull();
    }
  });

  it("uses Rust's ttlSeconds for the renewal figure instead of the estimate (R6)", () => {
    // Opened late: 1000 s left of a 3600 s lease. The estimate would say TTL 1000; Rust says 3600.
    const v = nextView(undefined, { engine: "database", expiresInSeconds: 1000, renewable: true, state: "active", ttlSeconds: 3600 }, 0);
    expect(v.ttlSeconds).toBe(3600);
    expect(leaseChip([v], "connected", 0)?.text).toBe("Lease · renewing"); // past two thirds of 3600
    const fresh = nextView(undefined, { engine: "database", expiresInSeconds: 3000, renewable: true, state: "active", ttlSeconds: 3600 }, 0);
    expect(leaseChip([fresh], "connected", 0)?.text).toBe("Lease · renews in 30 min");
    expect(remaining(fresh, "active", 0)).toBe(" Expires in 50 min (TTL 1 h).");
    expect(remaining(fresh, "revoked", 0)).toBe("");
    expect(remaining({ ...fresh, ttlSeconds: null }, "active", 600_000)).toBe(" Expires in 40 min.");
  });

  it("learns the TTL and notices a renewal", () => {
    const first = nextView(undefined, { engine: "database", expiresInSeconds: 3600, renewable: true, state: "active" }, 0);
    expect(first).toMatchObject({ ttlSeconds: 3600, expiresAt: 3_600_000 });
    const later = nextView(first, { engine: "database", expiresInSeconds: 1000, renewable: true, state: "active" }, 2_600_000);
    expect(later.ttlSeconds).toBe(3600);
    const renewed = nextView(later, { engine: "database", expiresInSeconds: 1800, renewable: true, state: "active" }, 2_700_000);
    expect(renewed.ttlSeconds).toBe(1800);
  });

  it("chip texts", () => {
    expect(leaseChip([view({ expiresAt: 3_600_000 })], "connected", 0)?.text).toBe("Lease · renews in 40 min");
    expect(leaseChip([view({ expiresAt: 1_000_000 })], "connected", 0)?.text).toBe("Lease · renewing");
    expect(leaseChip([view({ renewable: false, expiresAt: 5_400_000 })], "connected", 0)?.text).toBe("Lease · expires in 1 h 30 min");
    expect(leaseChip([view({ expiresAt: null })], "connected", 0)?.text).toBe("Lease · no expiry reported");
    expect(leaseChip([view({ state: "unknown", expiresAt: 1_000_000 })], "connected", 0)?.text).toBe("Lease");
    expect(leaseChip([], "connected", 0)).toBeNull();
    // The worst lease speaks for the tab.
    expect(leaseChip([view({ expiresAt: 3_600_000 }), view({ state: "renew_failed", expiresAt: 600_000 })], "connected", 0)?.state).toBe("renew_failed");
    expect(leaseDuration(30)).toBe("under a minute");
    expect(leaseDuration(7200)).toBe("2 h");
  });
});
