import { act, fireEvent, render, screen, within } from "@testing-library/react";
import type { MockTransport } from "../../lib/ipc.mock";
import { useCredentials } from "../../stores/credentials";
import { freshBackend, settle } from "../../test/harness";
import { SecretSourcesCard, testText } from "./SecretSourcesCard";
import { OIDC_POLL_MS, oidcFailureText } from "./useOidcLogin";

describe("Settings → Secret sources (ADR-0016)", () => {
  let mock: MockTransport;
  beforeEach(async () => {
    mock = freshBackend();
    await useCredentials.getState().load();
  });

  async function card() {
    render(<SecretSourcesCard />);
    await vi.waitFor(() => { expect(screen.queryByText("Loading…")).toBeNull(); });
    return screen.getByRole("region", { name: "Secret sources" });
  }
  const row = (c: HTMLElement, name: string) => within(c).getByRole("listitem", { name });

  it("lists the seeded source with its method, credential and usage; Test shows TTL, renewable and policies", async () => {
    const c = await card();
    const r = row(c, "ops vault");
    expect(r).toHaveTextContent("AppRole");
    expect(r).toHaveTextContent("https://vault.example.test:8200");
    expect(r).toHaveTextContent("Signs in with vault approle");
    expect(r).toHaveTextContent("used by 1 reference");
    fireEvent.click(within(r).getByRole("button", { name: "Test" }));
    await settle();
    expect(within(r).getByRole("status")).toHaveTextContent("Signed in with AppRole: token TTL 1 h, renewable, 2 policies.");
    expect(c.textContent).not.toMatch(/hvs\.|secret_id/i);
  });

  it("explains a failed test with its category, and Revoke forgets the token", async () => {
    const src = (await mock.secretSourceList())[0];
    if (!src) throw new Error("no seed");
    await mock.secretSourceUpdate({ ...src, address: "https://down.invalid" });
    const c = await card();
    const r = row(c, "ops vault");
    fireEvent.click(within(r).getByRole("button", { name: "Test" }));
    await settle();
    expect(within(r).getByRole("status")).toHaveTextContent("Sign-in with AppRole failed (network): Mooring could not fetch the secret");
    fireEvent.click(within(r).getByRole("button", { name: "Revoke" }));
    await settle();
    expect(within(c).getByRole("status")).toHaveTextContent("Revoked and forgot the token of ops vault.");
    expect(mock.audit.at(-1)?.event).toBe("secret_revoked");
  });

  it("creates an OIDC source through the dialog and refuses an incomplete one", async () => {
    const c = await card();
    fireEvent.click(within(c).getByRole("button", { name: "Add source…" }));
    const dlg = screen.getByRole("dialog", { name: "New secret source" });
    fireEvent.click(within(dlg).getByRole("button", { name: "Create source" }));
    expect(within(dlg).getByRole("alert")).toHaveTextContent("Fix the highlighted fields.");
    fireEvent.change(within(dlg).getByLabelText("Name"), { target: { value: "sso vault" } });
    fireEvent.change(within(dlg).getByLabelText("Address"), { target: { value: "https://sso.example.test" } });
    fireEvent.click(within(dlg).getByRole("radio", { name: "OIDC" }));
    expect(dlg).toHaveTextContent("OIDC needs a role.");
    fireEvent.change(within(dlg).getByLabelText("OIDC role"), { target: { value: "ops" } });
    expect(dlg).toHaveTextContent("http://localhost:8250/oidc/callback");
    fireEvent.change(within(dlg).getByLabelText("Origin to allow"), { target: { value: "https://login.example.test/" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Add" }));
    expect(within(dlg).getByRole("list", { name: "Allowed origins" })).toHaveTextContent("https://login.example.test");
    fireEvent.click(within(dlg).getByRole("button", { name: "Create source" }));
    await settle();
    expect(screen.queryByRole("dialog")).toBeNull();
    const created = (await mock.secretSourceList()).find((s) => s.name === "sso vault");
    expect(created).toMatchObject({ authMethod: "oidc", oidcRole: "ops", authMount: "oidc", credentialId: null, options: { allowedOrigins: ["https://login.example.test"] } });
    expect(row(c, "sso vault")).toHaveTextContent("Role ops on oidc");
  });

  it("OIDC sign-in: begin, poll the passive status every second, then test", async () => {
    const s = await mock.secretSourceCreate({ name: "sso", address: "https://sso.example.test", namespace: null, authMethod: "oidc", authMount: "", credentialId: null, oidcRole: "ops", options: { caPem: null, allowHttp: false, allowedOrigins: [] } });
    const c = await card();
    const r = row(c, "sso");
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    try {
      fireEvent.click(within(r).getByRole("button", { name: "Sign in…" }));
      await settle();
      expect(r).toHaveTextContent("Sign-in window open.");
      expect(within(r).getByRole("button", { name: "Sign in…" })).toBeDisabled();
      // The mock finishes the flow on the next macrotask; the UI only learns it from the poll.
      act(() => { vi.advanceTimersByTime(OIDC_POLL_MS); });
      await settle();
      expect(within(r).getByRole("status")).toHaveTextContent("Signed in with OIDC: token TTL 1 h, renewable, 2 policies.");
      const flow = [...mock.oidc.values()].find((f) => f.sourceId === s.id);
      expect(flow?.state).toBe("done");
    } finally {
      vi.useRealTimers();
    }
  });

  it("OIDC sign-in: timeout, closed and state mismatch are explained", async () => {
    await mock.secretSourceCreate({ name: "sso", address: "https://sso.example.test", namespace: null, authMethod: "oidc", authMount: "", credentialId: null, oidcRole: "ops", options: { caPem: null, allowHttp: false, allowedOrigins: [] } });
    const c = await card();
    const r = row(c, "sso");
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    try {
      for (const outcome of ["timeout", "closed", "state_mismatch"] as const) {
        mock.oidcOutcome = outcome;
        fireEvent.click(within(r).getByRole("button", { name: "Sign in…" }));
        await settle();
        act(() => { vi.advanceTimersByTime(OIDC_POLL_MS); });
        await settle();
        expect(within(r).getByRole("alert")).toHaveTextContent(oidcFailureText(outcome));
      }
    } finally {
      vi.useRealTimers();
    }
    expect(oidcFailureText("locked")).toMatch(/vault was locked/);
  });

  it("delete is refused while a reference uses the source, with the reason", async () => {
    const c = await card();
    const r = row(c, "ops vault");
    fireEvent.click(within(r).getByRole("button", { name: "Delete ops vault" }));
    expect(r).toHaveTextContent("1 credential still reference this source");
    fireEvent.click(within(r).getByRole("button", { name: "Confirm delete" }));
    await settle();
    expect(within(c).getByRole("alert")).toHaveTextContent("A credential still references this source.");
    expect(await mock.secretSourceList()).toHaveLength(1);
    await mock.credentialDelete({ id: "cr-ext" });
    await useCredentials.getState().load();
    fireEvent.click(within(r).getByRole("button", { name: "Confirm delete" }));
    await settle();
    expect(within(c).getByRole("status")).toHaveTextContent("Deleted ops vault.");
    expect(c).toHaveTextContent("No secret sources");
  });

  it("testText covers the token method and no TTL", () => {
    expect(testText({ ok: true, method: "token", ttlSeconds: null, renewable: false, policiesCount: 1, error: null, category: null })).toBe("Signed in with Token: token TTL no TTL, not renewable, 1 policy.");
    expect(testText({ ok: false, method: "token", ttlSeconds: null, renewable: false, policiesCount: 0, error: "credential.external_root_token", category: null })).toMatch(/refuses root tokens/);
  });
});
