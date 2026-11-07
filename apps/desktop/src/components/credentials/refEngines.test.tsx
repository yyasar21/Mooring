import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { App } from "../../App";
import type { MockTransport } from "../../lib/ipc.mock";
import { checkBwsReference, checkEngine, checkOpReference, roleOf } from "../../lib/validate.refs";
import { useCredentials } from "../../stores/credentials";
import { useTree } from "../../stores/tree";
import { useUi } from "../../stores/ui";
import { freshBackend, settle } from "../../test/harness";
import { KIND_SCHEMAS } from "../../lib/ipc.kinds";
import { buildFields, initialState } from "./formModel";

const view = () => screen.getByRole("region", { name: "Credentials" });

async function boot() {
  render(<App />);
  await screen.findByText("Nothing open yet");
  await settle();
}

async function newReference(name: string) {
  act(() => { useUi.getState().showCredentials({ mode: "new" }); });
  fireEvent.click(within(view()).getByRole("button", { name: "Secret manager reference" }));
  await settle();
  const form = within(view()).getByRole("form", { name: "New Secret manager reference" });
  fireEvent.change(within(form).getByLabelText("Name"), { target: { value: name } });
  fireEvent.click(within(form).getByRole("radio", { name: "Vault" }));
  fireEvent.change(within(form).getByLabelText("Secret source"), { target: { value: "src-ops" } });
  return form;
}

describe("dynamic Vault engines in the reference form (ADR-0026 §1)", () => {
  let mock: MockTransport;
  beforeEach(async () => {
    mock = freshBackend();
    await boot();
  });

  it("Database: the engine fixes the target kind; role only, no version or field map; Test issues and revokes", async () => {
    const form = await newReference("reporting ro");
    fireEvent.change(within(form).getByLabelText(/^Resolves to/), { target: { value: "ssh_key" } });
    expect(within(form).getByRole("button", { name: "Map" })).toBeInTheDocument(); // KV has a field map
    fireEvent.change(within(form).getByLabelText("Vault engine"), { target: { value: "database" } });
    expect(form).toHaveTextContent("Vault creates a database user and password for each connect.");
    expect(within(form).getByLabelText(/^Resolves to/).tagName).toBe("P"); // read-only now
    expect(within(form).getByLabelText(/^Resolves to/)).toHaveTextContent("Username and password");
    expect(form).toHaveTextContent("Fixed by the Database engine.");
    expect(within(form).queryByLabelText(/^KV version/)).toBeNull();
    expect(within(form).queryByRole("button", { name: "Map" })).toBeNull();
    expect(form).toHaveTextContent("renews the lease at two thirds of its TTL");
    fireEvent.change(within(form).getByLabelText("Role"), { target: { value: "database/readonly" } });
    fireEvent.click(within(form).getByRole("button", { name: "Create credential" }));
    await settle();
    const saved = useCredentials.getState().items.find((c) => c.name === "reporting ro");
    expect(saved?.fields).toEqual({ provider: "vault", source: "src-ops", engine: "database", reference: "database/readonly", target_kind: "user_password" });

    const card = within(view()).getByRole("article", { name: "reporting ro details" });
    expect(card).toHaveTextContent("EngineDatabase");
    expect(card).toHaveTextContent("Roledatabase/readonly");
    expect(card).toHaveTextContent("Renewed while the session is open, revoked when it closes");
    fireEvent.click(within(card).getByRole("button", { name: "Test" }));
    await settle();
    expect(within(card).getByRole("status", { name: "Reference test" })).toHaveTextContent("Vault issued Database values with every field the target kind needs. Mooring revoked them at once.");
    expect(mock.audit.at(-1)).toMatchObject({ event: "secret_lease_revoked", details: { reason: "test" } });
  });

  it("SSH sign: principals as chips and a TTL; it fills only the certificate role of an SSH connection", async () => {
    const form = await newReference("ops cert");
    fireEvent.change(within(form).getByLabelText("Vault engine"), { target: { value: "ssh_sign" } });
    fireEvent.change(within(form).getByLabelText("Role"), { target: { value: "ssh/ops" } });
    const principals = within(form).getByRole("textbox", { name: /^Principals/ });
    fireEvent.change(principals, { target: { value: "ops" } });
    fireEvent.keyDown(principals, { key: "Enter" });
    fireEvent.change(principals, { target: { value: "deploy, ops" } });
    fireEvent.keyDown(principals, { key: "Enter" });
    expect(within(within(form).getByRole("list", { name: "Principals added" })).getAllByRole("listitem").map((l) => l.textContent)).toEqual(["ops×", "deploy×"]);
    fireEvent.click(within(form).getByRole("button", { name: "Remove principal deploy" }));
    fireEvent.change(within(form).getByLabelText(/^TTL/), { target: { value: "90000" } });
    fireEvent.click(within(form).getByRole("button", { name: "Create credential" }));
    expect(form).toHaveTextContent("TTL is 1 to 86400 seconds");
    fireEvent.change(within(form).getByLabelText(/^TTL/), { target: { value: "600" } });
    fireEvent.click(within(form).getByRole("button", { name: "Create credential" }));
    await settle();
    const ref = useCredentials.getState().items.find((c) => c.name === "ops cert");
    expect(ref?.fields).toEqual({ provider: "vault", source: "src-ops", engine: "ssh_sign", reference: "ssh/ops", target_kind: "ssh_key", principals: ["ops"], ttl: 600 });
    if (!ref) throw new Error("not saved");

    // web01 inherits the folder's SSH key (ops on-call); the SSH sign reference is not a sign-in.
    act(() => { useUi.getState().openDialog({ kind: "connection", id: "c-web01", folderId: "f-web" }); });
    const dlg = screen.getByRole("dialog", { name: "Edit connection" });
    fireEvent.click(within(dlg).getByRole("button", { name: /^Credential/ }));
    const primary = within(dlg).getByRole("listbox", { name: "Credential" });
    const inPrimary = within(primary).getAllByRole("option").find((o) => o.textContent.includes("ops cert"));
    expect(inPrimary).toHaveAttribute("aria-disabled", "true");
    expect(inPrimary).toHaveTextContent("pick it as the connection's certificate");
    fireEvent.keyDown(primary, { key: "Escape" });
    fireEvent.click(within(dlg).getByRole("button", { name: /^Certificate \(Vault SSH CA\)/ }));
    const certs = within(dlg).getByRole("listbox", { name: "Certificate (Vault SSH CA)" });
    // Only SSH sign references (and "None") are offered.
    const offered = within(certs).getAllByRole("option");
    expect(offered).toHaveLength(2);
    expect(offered[0]).toHaveTextContent("None");
    expect(offered[1]).toHaveTextContent("ops cert");
    const pick = within(certs).getAllByRole("option").find((o) => o.textContent.includes("ops cert"));
    if (!pick) throw new Error("no option");
    fireEvent.click(pick);
    fireEvent.click(within(dlg).getByRole("button", { name: "Save connection" }));
    await settle();
    expect(useTree.getState().connections.find((c) => c.id === "c-web01")?.certificateCredentialId).toBe(ref.id);
    expect(mock.connections.find((c) => c.id === "c-web01")?.certificateCredentialId).toBe(ref.id);

    act(() => { useUi.getState().showCredentials({ mode: "view", id: "cr-ops" }); });
    await settle();
    const key = within(view()).getByRole("article", { name: "ops on-call details" });
    expect(within(key).getByRole("region", { name: "Certificate" })).toHaveTextContent("Certificate: signed by Vault role ops at connect · web01");
  });

  it("SSH OTP needs a login; PKI needs a common name and says it is test-only", async () => {
    const form = await newReference("otp");
    fireEvent.change(within(form).getByLabelText("Vault engine"), { target: { value: "ssh_otp" } });
    fireEvent.change(within(form).getByLabelText("Role"), { target: { value: "ssh/otp" } });
    fireEvent.click(within(form).getByRole("button", { name: "Create credential" }));
    expect(form).toHaveTextContent("SSH OTP needs the login the password is issued for.");
    fireEvent.change(within(form).getByLabelText("Vault engine"), { target: { value: "pki" } });
    expect(form).toHaveTextContent("PKI can only be tested for now.");
    expect(form).toHaveTextContent("PKI needs a common name.");
    fireEvent.change(within(form).getByLabelText("Common name"), { target: { value: "client.example.test" } });
    const alt = within(form).getByRole("textbox", { name: /^Alt names/ });
    fireEvent.change(alt, { target: { value: "alt.example.test" } });
    fireEvent.keyDown(alt, { key: "Enter" });
    fireEvent.click(within(form).getByRole("button", { name: "Create credential" }));
    await settle();
    expect(useCredentials.getState().items.find((c) => c.name === "otp")?.fields).toEqual({
      provider: "vault", source: "src-ops", engine: "pki", reference: "ssh/otp", target_kind: "x509", common_name: "client.example.test", alt_names: ["alt.example.test"],
    });
  });

  it("Bitwarden: secret id or project/key, through a Bitwarden source; JSON keys map like KV", async () => {
    act(() => { useUi.getState().showCredentials({ mode: "new" }); });
    fireEvent.click(within(view()).getByRole("button", { name: "Secret manager reference" }));
    await settle();
    const form = within(view()).getByRole("form", { name: "New Secret manager reference" });
    fireEvent.change(within(form).getByLabelText("Name"), { target: { value: "bw token" } });
    fireEvent.click(within(form).getByRole("radio", { name: "Bitwarden" }));
    fireEvent.change(within(form).getByLabelText("Secret source"), { target: { value: "src-bws" } });
    fireEvent.change(within(form).getByLabelText(/^Resolves to/), { target: { value: "api_token" } });
    fireEvent.change(within(form).getByLabelText(/^Reference/), { target: { value: "not-a-uuid" } });
    fireEvent.click(within(form).getByRole("button", { name: "Create credential" }));
    expect(form).toHaveTextContent("Use a secret id (a UUID) or <project id>/<key>.");
    expect(within(form).getByRole("button", { name: "Map" })).toBeInTheDocument();
    fireEvent.change(within(form).getByLabelText(/^Reference/), { target: { value: "be8e0ad8-d545-4017-a55a-b02f014d4158" } });
    fireEvent.click(within(form).getByRole("button", { name: "Create credential" }));
    await settle();
    const card = within(view()).getByRole("article", { name: "bw token details" });
    fireEvent.click(within(card).getByRole("button", { name: "Test" }));
    await settle();
    expect(within(card).getByRole("status", { name: "Reference test" })).toHaveTextContent("has every field the target kind needs");
  });
});

describe("reference rules (validate.refs)", () => {
  it("1Password and Bitwarden reference shapes", () => {
    expect(checkOpReference("op://Infra/prod-db/password")).toBeNull();
    expect(checkOpReference("op://Infra/prod-db")).toBeNull();
    expect(checkOpReference("op://Infra/prod-db/section/password")).toBeNull();
    expect(checkOpReference("op://Infra")).toMatch(/Use op:\/\/vault\/item/);
    expect(checkOpReference("op://a/b/c/d/e")).toMatch(/Use op:\/\/vault\/item/);
    expect(checkOpReference("op://Infra//x")).toMatch(/empty segment/);
    expect(checkOpReference("op://Infra/db?attribute=otp")).toMatch(/must not contain/);
    expect(checkOpReference("op://Infra/d\u202eb")).toMatch(/must not contain/);
    expect(checkBwsReference("be8e0ad8-d545-4017-a55a-b02f014d4158")).toBeNull();
    expect(checkBwsReference("be8e0ad8-d545-4017-a55a-b02f014d4158/DB_PASSWORD")).toBeNull();
    expect(checkBwsReference("project/key")).not.toBeNull();
    expect(roleOf("database/prod/readonly")).toBe("readonly");
  });

  it("engine parameters belong to their engine and keep Rust's caps", () => {
    const d = { provider: "vault", source: "s", reference: "ssh/ops", target_kind: "ssh_key", version: "", field_map: {}, engine: "ssh_sign" };
    expect(checkEngine(d)).toEqual({});
    expect(checkEngine({ ...d, target_kind: "user_password" })).toHaveProperty("target_kind");
    expect(checkEngine({ ...d, version: "2" })).toHaveProperty("version");
    expect(checkEngine({ ...d, principals: Array.from({ length: 17 }, (_, i) => `p${i}`) })).toHaveProperty("principals");
    expect(checkEngine({ ...d, principals: ["a b"] })).toHaveProperty("principals");
    expect(checkEngine({ ...d, principals: ["x".repeat(65)] })).toHaveProperty("principals");
    expect(checkEngine({ ...d, common_name: "x" })).toHaveProperty("common_name");
    expect(checkEngine({ ...d, engine: "database", target_kind: "user_password", ttl: "60" })).toHaveProperty("ttl");
    expect(checkEngine({ ...d, provider: "onepassword", engine: "database" })).toEqual({ engine: "Only Vault references have an engine." });
  });

  it("buildFields sends kv2 as nothing, ttl as a number and the lists as arrays", () => {
    const schema = KIND_SCHEMAS.find((k) => k.kind === "external_ref");
    if (!schema) throw new Error("no schema");
    const s = initialState(schema);
    s.values = { ...s.values, provider: "vault", source: "src-ops", engine: "ssh_sign", reference: "ssh/ops", target_kind: "ssh_key", ttl: "300" };
    s.lists = { principals: ["ops", " "] };
    expect(buildFields(schema, s)).toEqual({ provider: "vault", source: "src-ops", engine: "ssh_sign", reference: "ssh/ops", target_kind: "ssh_key", ttl: 300, principals: ["ops"] });
    s.values = { ...s.values, engine: "kv2", ttl: "" };
    s.lists = {};
    expect(buildFields(schema, s)).not.toHaveProperty("engine");
    // A stored row comes back into the form with its lists and TTL.
    const back = initialState(schema, { id: "x", name: "x", kind: "external_ref", fields: { provider: "vault", engine: "ssh_sign", reference: "ssh/ops", target_kind: "ssh_key", principals: ["a"], ttl: 60 }, secretNames: [], fingerprint: null, createdAt: "", updatedAt: "" });
    expect(back.lists).toEqual({ principals: ["a"] });
    expect(back.values.ttl).toBe("60");
  });
});
