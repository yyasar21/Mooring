import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { App } from "../../App";
import { SK_FINGERPRINT, SK_PUBLIC } from "../../lib/ipc.seed";
import { useCredentials } from "../../stores/credentials";
import { useUi } from "../../stores/ui";
import { freshBackend, settle } from "../../test/harness";
import { skHandlePem } from "../../test/sk";

async function boot() {
  render(<App />);
  await screen.findByText("Nothing open yet");
  await settle();
}

function newKind(label: string) {
  act(() => { useUi.getState().showCredentials({ mode: "new" }); });
  const view = screen.getByRole("region", { name: "Credentials" });
  fireEvent.click(within(view).getByRole("button", { name: label }));
  return { view, form: within(view).getByRole("form") };
}

describe("Security key (FIDO2) credentials (ADR-0024)", () => {
  beforeEach(() => { freshBackend(); });

  it("creates one from a pasted public key: preview, agent signing, helper greyed, then the detail card", async () => {
    await boot();
    const { view, form } = newKind("SSH security key (FIDO2)");
    fireEvent.change(within(form).getByLabelText("Name"), { target: { value: "yubikey 5c" } });
    fireEvent.change(within(form).getByLabelText("Username"), { target: { value: "deploy" } });
    fireEvent.change(within(form).getByLabelText(/^Public key/), { target: { value: `${SK_PUBLIC} deploy@key` } });
    const preview = await within(form).findByLabelText("Key preview");
    expect(preview).toHaveTextContent("TypeEd25519 security key");
    expect(preview).toHaveTextContent("Applicationssh:");
    expect(await within(preview).findByText(SK_FINGERPRINT.slice(7))).toBeInTheDocument();

    const agent = within(form).getByRole("radio", { name: /Through your ssh-agent/ });
    const helper = within(form).getByRole("radio", { name: /Directly with ssh-sk-helper/ });
    expect(agent).toBeChecked();
    expect(helper).toBeDisabled();
    expect(form).toHaveTextContent("Direct security-key access (without ssh-agent) is coming later.");
    fireEvent.click(within(form).getByRole("checkbox", { name: /Resident key/ }));
    expect(within(form).getByLabelText(/^Key handle file/)).toBeInTheDocument();

    fireEvent.click(within(form).getByRole("button", { name: "Create credential" }));
    await settle();
    const saved = useCredentials.getState().items.find((c) => c.name === "yubikey 5c");
    expect(saved).toMatchObject({ kind: "ssh_sk_key", secretNames: [], fields: { username: "deploy", resident: true, backend: "agent", application: "ssh:" } });
    const detail = within(view).getByRole("article", { name: "yubikey 5c details" });
    expect(detail).toHaveTextContent("Signs through your ssh-agent");
    expect(detail).toHaveTextContent("Resident");
    expect(detail).toHaveTextContent("Yes, stored on the key (ssh-add -K)");
    expect(detail).toHaveTextContent("Applicationssh:");
    expect(within(detail).getByText(/Ed25519 security key/)).toBeInTheDocument();
  });

  it("checks the shape of the public key and the certificate before saving", async () => {
    await boot();
    const { form } = newKind("SSH security key (FIDO2)");
    fireEvent.change(within(form).getByLabelText("Name"), { target: { value: "k" } });
    fireEvent.change(within(form).getByLabelText("Username"), { target: { value: "u" } });
    fireEvent.change(within(form).getByLabelText(/^Public key/), { target: { value: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixture" } });
    fireEvent.change(within(form).getByLabelText(/^OpenSSH certificate/), { target: { value: "ssh-ed25519-cert-v01@openssh.com AAAA" } });
    fireEvent.click(within(form).getByRole("button", { name: "Create credential" }));
    await settle();
    expect(form).toHaveTextContent("This is a regular SSH key, not a security key.");
    expect(form).toHaveTextContent("Expected an sk-…-cert-v01@openssh.com certificate");
    expect(useCredentials.getState().items.some((c) => c.name === "k")).toBe(false);
  });

  it("an SSH key form refused with credential.use_sk_kind offers the security-key form, pre-filled", async () => {
    await boot();
    const { view, form } = newKind("SSH key");
    fireEvent.change(within(form).getByLabelText("Name"), { target: { value: "old key" } });
    fireEvent.change(within(form).getByLabelText("Username"), { target: { value: "ops" } });
    // Typed, not pasted: a paste would already have switched the kind.
    fireEvent.change(within(form).getByLabelText(/^Private key/), { target: { value: skHandlePem() } });
    fireEvent.click(within(form).getByRole("button", { name: "Create credential" }));
    await settle();
    const note = within(form).getAllByRole("alert").find((el) => el.classList.contains("kind-note"));
    if (!note) throw new Error("no refusal note");
    expect(note).toHaveTextContent("This is a security-key key — create a Security key (FIDO2) credential instead");
    fireEvent.click(within(note).getByRole("button", { name: "Create Security key (FIDO2) credential" }));
    const next = within(view).getByRole("form", { name: "New SSH security key (FIDO2)" });
    expect(within(next).getByLabelText("Name")).toHaveValue("old key");
    expect(within(next).getByLabelText("Username")).toHaveValue("ops");
    // The handle was a secret: it is not carried over.
    expect(within(next).getByLabelText(/^Key handle file/)).toHaveValue("");
  });

  it("an sk public key in an SSH key form shows the note before saving and carries the key over", async () => {
    await boot();
    const { view, form } = newKind("SSH key");
    fireEvent.change(within(form).getByLabelText(/^Public key/), { target: { value: SK_PUBLIC } });
    const note = within(form).getByRole("note");
    fireEvent.click(within(note).getByRole("button", { name: "Create Security key (FIDO2) credential" }));
    const next = within(view).getByRole("form", { name: "New SSH security key (FIDO2)" });
    expect(within(next).getByLabelText(/^Public key/)).toHaveValue(SK_PUBLIC);
  });

  it("the seeded key's card and the conversion row in the audit log", async () => {
    await boot();
    act(() => { useUi.getState().showCredentials({ mode: "view", id: "cr-yubi" }); });
    const detail = screen.getByRole("article", { name: "yubikey ops details" });
    expect(detail).toHaveTextContent("Signs through your ssh-agent. Touch the key when Mooring asks");
    expect(detail).toHaveTextContent(SK_FINGERPRINT.slice(7));
    expect(detail).toHaveTextContent("1 connection");
    act(() => { useUi.getState().setView("audit"); });
    const log = await screen.findByRole("region", { name: "Audit log" });
    expect(await within(log).findByText("SSH key converted to a security-key credential")).toBeInTheDocument();
    expect(log).toHaveTextContent("credential: yubikey ops");
  });
});
