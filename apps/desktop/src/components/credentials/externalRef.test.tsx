import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { App } from "../../App";
import type { MockTransport } from "../../lib/ipc.mock";
import { useCredentials } from "../../stores/credentials";
import { useUi } from "../../stores/ui";
import { freshBackend, settle } from "../../test/harness";
import { refTestSummary } from "./ExternalRefSection";

describe("external_ref credential form (ADR-0016 §2)", () => {
  let mock: MockTransport;
  beforeEach(async () => {
    mock = freshBackend();
    render(<App />);
    await screen.findByText("Nothing open yet");
    await settle();
  });

  const view = () => screen.getByRole("region", { name: "Credentials" });

  it("edits the seeded reference: source, field map and version are stored in the E1 shapes; Test lists names only", async () => {
    act(() => { useUi.getState().showCredentials({ mode: "edit", id: "cr-ext" }); });
    await settle();
    const form = within(view()).getByRole("form", { name: "Edit db via vault" });
    expect(within(form).getByLabelText("Secret source")).toHaveValue("src-ops");
    expect(within(form).getByLabelText(/^Reference/)).toHaveValue("kv/ops/db");
    fireEvent.change(within(form).getByLabelText(/^KV version/), { target: { value: "7" } });
    fireEvent.change(within(form).getByLabelText("Target field to map"), { target: { value: "password" } });
    fireEvent.click(within(form).getByRole("button", { name: "Map" }));
    fireEvent.change(within(form).getByLabelText("KV key for password"), { target: { value: "pass" } });
    fireEvent.click(within(form).getByRole("button", { name: "Save credential" }));
    await settle();
    const saved = useCredentials.getState().items.find((c) => c.id === "cr-ext");
    expect(saved?.fields).toEqual({ provider: "vault", source: "src-ops", reference: "kv/ops/db", target_kind: "user_password", version: 7, field_map: { password: "pass" } });

    const edited = within(view()).getByRole("form", { name: "Edit db via vault" });
    fireEvent.click(within(edited).getByRole("button", { name: "Test reference" }));
    await settle();
    const result = within(edited).getByRole("status", { name: "Reference test" });
    expect(result).toHaveTextContent("1 required name is missing and 1 extra key would be refused");
    expect(result).toHaveTextContent("presentusername");
    expect(result).toHaveTextContent("missingpassword");
    expect(result).toHaveTextContent("extrapassword");
    expect(document.body.innerHTML).not.toMatch(/hunter2/);
    fireEvent.click(within(edited).getByRole("button", { name: "Remove mapping for password" }));
    fireEvent.click(within(edited).getByRole("button", { name: "Save credential" }));
    await settle();
    expect(useCredentials.getState().items.find((c) => c.id === "cr-ext")?.fields).not.toHaveProperty("field_map");
  });

  it("a new Vault reference needs a source and a valid reference; Test is offered after the first save", async () => {
    act(() => { useUi.getState().showCredentials({ mode: "new" }); });
    fireEvent.click(within(view()).getByRole("button", { name: "Secret manager reference" }));
    await settle(); // the source list loads
    const form = within(view()).getByRole("form", { name: "New Secret manager reference" });
    expect(within(form).getByRole("button", { name: "Test reference" })).toBeDisabled();
    fireEvent.change(within(form).getByLabelText("Name"), { target: { value: "ssh via vault" } });
    fireEvent.click(within(form).getByRole("radio", { name: "Vault" }));
    fireEvent.change(within(form).getByLabelText(/^Reference/), { target: { value: "kv/../ssh" } });
    fireEvent.change(within(form).getByLabelText(/^Resolves to/), { target: { value: "ssh_key" } });
    fireEvent.click(within(form).getByRole("button", { name: "Create credential" }));
    expect(form).toHaveTextContent("Choose a secret source.");
    expect(form).toHaveTextContent("Reference must not contain '.' or '..' segments.");
    fireEvent.change(within(form).getByLabelText("Secret source"), { target: { value: "src-ops" } });
    fireEvent.change(within(form).getByLabelText(/^Reference/), { target: { value: "kv/ops/ssh" } });
    fireEvent.click(within(form).getByRole("button", { name: "Create credential" }));
    await settle();
    const saved = useCredentials.getState().items.find((c) => c.name === "ssh via vault");
    expect(saved?.fields).toEqual({ provider: "vault", source: "src-ops", reference: "kv/ops/ssh", target_kind: "ssh_key" });
    const editor = within(view()).getByRole("form", { name: "Edit ssh via vault" });
    fireEvent.click(within(editor).getByRole("button", { name: "Test reference" }));
    await settle();
    expect(within(editor).getByRole("status", { name: "Reference test" })).toHaveTextContent("has every field the target kind needs");
    expect(mock.audit.at(-1)?.event).toBe("secret_resolved");
  });

  it("1Password references keep validating and storing without a source", async () => {
    act(() => { useUi.getState().showCredentials({ mode: "new" }); });
    fireEvent.click(within(view()).getByRole("button", { name: "Secret manager reference" }));
    const form = within(view()).getByRole("form", { name: "New Secret manager reference" });
    fireEvent.click(within(form).getByRole("radio", { name: "1Password" }));
    expect(within(form).queryByLabelText("Secret source")).toBeNull();
    expect(form).toHaveTextContent("arrives in a later release");
    fireEvent.change(within(form).getByLabelText("Name"), { target: { value: "op db" } });
    fireEvent.change(within(form).getByLabelText(/^Reference/), { target: { value: "op://Infra/prod-db/password" } });
    fireEvent.change(within(form).getByLabelText(/^Resolves to/), { target: { value: "user_password" } });
    fireEvent.click(within(form).getByRole("button", { name: "Create credential" }));
    await settle();
    expect(useCredentials.getState().items.find((c) => c.name === "op db")?.fields).toEqual({ provider: "onepassword", reference: "op://Infra/prod-db/password", target_kind: "user_password" });
  });

  it("summarises test results", () => {
    expect(refTestSummary({ ok: false, version: null, present: [], missing: [], extra: [], error: "credential.external_not_found", category: "not_found" })).toMatch(/does not exist.*\(not found\)/);
    expect(refTestSummary({ ok: true, version: 2, present: ["username"], missing: [], extra: [], error: null, category: null })).toBe("The secret (version 2) has every field the target kind needs.");
  });
});
