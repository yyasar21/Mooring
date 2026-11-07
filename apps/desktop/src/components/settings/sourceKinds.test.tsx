import { fireEvent, render, screen, within } from "@testing-library/react";
import { BWS_PATHS } from "../../lib/ipc";
import type { MockTransport } from "../../lib/ipc.mock";
import { validateSecretSource } from "../../lib/validate.secrets";
import { useCredentials } from "../../stores/credentials";
import { freshBackend, settle } from "../../test/harness";
import { SecretSourcesCard, testText } from "./SecretSourcesCard";

describe("Settings → Secret sources: 1Password Connect and Bitwarden (ADR-0026)", () => {
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

  it("lists the seeded Connect and Bitwarden sources; Test reports counts only", async () => {
    const c = await card();
    const op = row(c, "infra connect");
    expect(op).toHaveTextContent("1Password Connect");
    expect(op).toHaveTextContent("Signs in with connect token");
    fireEvent.click(within(op).getByRole("button", { name: "Test" }));
    await settle();
    expect(within(op).getByRole("status")).toHaveTextContent("Connect answered: the token sees 2 vaults.");

    const bw = row(c, "team secrets");
    expect(bw).toHaveTextContent("Bitwarden Secrets Manager");
    expect(bw).toHaveTextContent("bws: first one found · own TLS, not pinned by Mooring");
    fireEvent.click(within(bw).getByRole("button", { name: "Test" }));
    await settle();
    expect(within(bw).getByRole("status")).toHaveTextContent("bws ran: the access token sees 3 projects.");
    expect(mock.audit.at(-1)).toMatchObject({ event: "secret_tool_spawned", details: { provider: "bitwarden", exit: "0" } });
    expect(c.textContent).not.toMatch(/0\.[a-f0-9-]{8,}|BWS_ACCESS_TOKEN/);
  });

  it("shows where Mooring looks for bws when the backend reports it missing", async () => {
    mock.bwsFound = false;
    const c = await card();
    const bw = row(c, "team secrets");
    fireEvent.click(within(bw).getByRole("button", { name: "Test" }));
    await settle();
    expect(within(bw).getByRole("status")).toHaveTextContent("Bitwarden test failed (tool): bws was not found at the locations Mooring checks.");
    const note = within(bw).getByRole("note");
    expect(note).toHaveTextContent("bws was not found at any of these locations");
    expect(within(note).getByRole("list", { name: "Where Mooring looks for bws" }).textContent).toBe(BWS_PATHS.join(""));
  });

  it("creates a 1Password Connect source: address, Connect token credential and CA; no namespace or method", async () => {
    const c = await card();
    fireEvent.click(within(c).getByRole("button", { name: "Add source…" }));
    const dlg = screen.getByRole("dialog", { name: "New secret source" });
    fireEvent.click(within(dlg).getByRole("radio", { name: "1Password Connect" }));
    expect(within(dlg).queryByLabelText(/^Namespace/)).toBeNull();
    expect(within(dlg).queryByRole("radio", { name: "AppRole" })).toBeNull();
    expect(within(dlg).getByPlaceholderText("https://connect.example.test:8080")).toBeInTheDocument();
    fireEvent.change(within(dlg).getByLabelText("Name"), { target: { value: "lab connect" } });
    fireEvent.change(within(dlg).getByLabelText("Address"), { target: { value: "https://connect2.example.test:8080" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Create source" }));
    expect(dlg).toHaveTextContent("Choose the API token credential that holds the Connect token.");
    fireEvent.change(within(dlg).getByLabelText("Connect token credential"), { target: { value: "cr-op-token" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Create source" }));
    await settle();
    const created = (await mock.secretSourceList()).find((s) => s.name === "lab connect");
    expect(created).toMatchObject({ kind: "onepassword", authMethod: "token", credentialId: "cr-op-token", namespace: null });
    expect(created?.options).not.toHaveProperty("bwsPath");
  });

  it("creates a Bitwarden source with a fixed bws location and an access-token credential; no CA", async () => {
    const c = await card();
    fireEvent.click(within(c).getByRole("button", { name: "Add source…" }));
    const dlg = screen.getByRole("dialog", { name: "New secret source" });
    fireEvent.click(within(dlg).getByRole("radio", { name: "Bitwarden" }));
    expect(within(dlg).queryByText(/Extra CA certificates|CA certificate/i)).toBeNull();
    expect(dlg).toHaveTextContent("bws makes its own TLS connection to the server");
    expect(within(dlg).getByRole("list", { name: "Where Mooring looks for bws" })).toHaveTextContent("/usr/local/bin/bws");
    fireEvent.change(within(dlg).getByLabelText("Name"), { target: { value: "self-hosted bw" } });
    fireEvent.change(within(dlg).getByLabelText("Address"), { target: { value: "https://bw2.example.test" } });
    fireEvent.change(within(dlg).getByLabelText("Access token credential"), { target: { value: "cr-bws-token" } });
    fireEvent.change(within(dlg).getByLabelText("bws location"), { target: { value: "/opt/homebrew/bin/bws" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Create source" }));
    await settle();
    const created = (await mock.secretSourceList()).find((s) => s.name === "self-hosted bw");
    expect(created).toMatchObject({ kind: "bitwarden", credentialId: "cr-bws-token", options: { bwsPath: "/opt/homebrew/bin/bws", caPem: null } });
    expect(row(c, "self-hosted bw")).toHaveTextContent("bws: /opt/homebrew/bin/bws");
  });

  it("edit keeps the provider fixed", async () => {
    const c = await card();
    fireEvent.click(within(row(c, "team secrets")).getByRole("button", { name: "Edit…" }));
    const dlg = screen.getByRole("dialog", { name: "Edit team secrets" });
    expect(dlg).toHaveTextContent("Provider: Bitwarden Secrets Manager. The provider of a source cannot change.");
    expect(within(dlg).queryByRole("radio", { name: "1Password Connect" })).toBeNull();
    fireEvent.change(within(dlg).getByLabelText("bws location"), { target: { value: "/usr/local/bin/bws" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Save source" }));
    await settle();
    expect((await mock.secretSourceGet({ id: "src-bws" })).options.bwsPath).toBe("/usr/local/bin/bws");
  });

  it("form rules per kind mirror Rust", () => {
    const base = { name: "x", address: "https://x.example.test", namespace: null, authMethod: "token" as const, authMount: "", credentialId: "c", oidcRole: null, options: { caPem: null, allowHttp: false, allowedOrigins: [] } };
    expect(validateSecretSource({ ...base, kind: "onepassword" })).toEqual({});
    expect(validateSecretSource({ ...base, kind: "onepassword", namespace: "team" })).toHaveProperty("namespace");
    expect(validateSecretSource({ ...base, kind: "onepassword", authMethod: "approle" })).toHaveProperty("authMethod");
    expect(validateSecretSource({ ...base, kind: "onepassword", options: { ...base.options, bwsPath: BWS_PATHS[0] } })).toHaveProperty("bwsPath");
    expect(validateSecretSource({ ...base, kind: "bitwarden", options: { ...base.options, bwsPath: "/tmp/bws" } })).toHaveProperty("bwsPath");
    expect(validateSecretSource({ ...base, kind: "bitwarden", options: { ...base.options, caPem: "-----BEGIN CERTIFICATE-----" } })).toHaveProperty("caPem");
    expect(validateSecretSource({ ...base, kind: "bitwarden", options: { ...base.options, bwsPath: "%ProgramFiles%\\bws\\bws.exe" } })).toEqual({});
    expect(validateSecretSource({ ...base, kind: "vault", options: { ...base.options, bwsPath: BWS_PATHS[0] } })).toHaveProperty("bwsPath");
  });

  it("testText per provider", () => {
    const t = { ok: false, method: "token" as const, ttlSeconds: null, renewable: false, policiesCount: 0, error: "secret.tool_version", category: "tool" };
    expect(testText(t, "bitwarden")).toBe("Bitwarden test failed (tool): The bws found is older than 1.0. Install a current Bitwarden Secrets Manager CLI.");
    expect(testText({ ...t, ok: true, policiesCount: 1, error: null, category: null }, "onepassword")).toBe("Connect answered: the token sees 1 vault.");
  });
});
