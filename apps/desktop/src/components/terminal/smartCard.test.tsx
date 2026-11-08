import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { App } from "../../App";
import { PIV_FINGERPRINT, PIV_PUBLIC, SK_PUBLIC } from "../../lib/ipc.seed";
import type { MockTransport } from "../../lib/ipc.mock";
import { useSessions } from "../../stores/sessions";
import { useUi } from "../../stores/ui";
import { useCredentials } from "../../stores/credentials";
import { freshBackend, settle } from "../../test/harness";
import { PIN_NOTE, SSH_ADD_HINT } from "../credentials/SmartCard";
import { CARD_LIFETIME_MINUTES } from "./SmartCardPinDialog";

async function boot() {
  render(<App />);
  await screen.findByText("Nothing open yet");
  await settle();
}

const tab = () => useSessions.getState().tabs[0];
const panel = () => screen.getByRole("tabpanel");

/** web01 signs in with the seeded PIV card. */
function useCard(mock: MockTransport) {
  const c = mock.connections.find((x) => x.id === "c-web01");
  if (c) c.credentialId = "cr-piv";
  mock.trustedHosts.add("web01.example.test");
}

describe("smart card PIN at connect (ADR-0027)", () => {
  let mock: MockTransport;
  beforeEach(() => {
    mock = freshBackend();
    useCard(mock);
  });

  it("asks the PIN in a masked dialog, sends it once, clears it, and connects", async () => {
    await boot();
    await act(async () => { await useSessions.getState().open("c-web01"); });
    await settle();
    const dlg = screen.getByRole("alertdialog", { name: "Smart card PIN" });
    expect(dlg).toHaveTextContent("Enter the PIN of the smart card (Yubico YubiKey)");
    const pin = within(dlg).getByLabelText("PIN");
    expect(pin).toHaveAttribute("type", "password");
    expect(pin).toHaveAttribute("autocomplete", "off");
    expect(document.activeElement).toBe(pin);
    // L-49: the agent keeps the card for CARD_LIFETIME_SECS (3600 s) after the PIN
    expect(within(dlg).getByTestId("pin-lifetime")).toHaveTextContent(`stays loaded in ssh-agent for ${String(CARD_LIFETIME_MINUTES)} minutes`);
    expect(CARD_LIFETIME_MINUTES * 60).toBe(3600);
    const unlock = within(dlg).getByRole("button", { name: "Unlock card" });
    expect(unlock).toBeDisabled();
    const send = vi.spyOn(mock, "sessionSend");
    fireEvent.change(pin, { target: { value: "123456" } });
    fireEvent.click(unlock);
    expect(pin).toHaveValue("");
    fireEvent.click(unlock);
    expect(send).toHaveBeenCalledTimes(1);
    expect(send.mock.calls[0]?.[0].input).toEqual({ kind: "answer", id: 4, text: "123456" });
    await waitFor(() => { expect(tab()?.state).toBe("connected"); });
    expect(screen.queryByRole("alertdialog")).toBeNull();
    // The PIN is in no store and no audit row.
    expect(JSON.stringify(useSessions.getState().tabs)).not.toContain("123456");
    expect(JSON.stringify(mock.audit)).not.toContain("123456");
    expect(mock.audit.find((e) => e.event === "credential.pin_prompted")?.details.outcome).toBe("entered");
    expect(mock.audit.some((e) => e.event === "session.auth_sk" && e.details.backend === "piv" && e.details.outcome === "ok")).toBe(true);
  });

  it("Escape cancels with the empty answer: closed by the user, no password fallback", async () => {
    await boot();
    await act(async () => { await useSessions.getState().open("c-web01"); });
    await settle();
    const dlg = screen.getByRole("alertdialog", { name: "Smart card PIN" });
    fireEvent.change(within(dlg).getByLabelText("PIN"), { target: { value: "99" } });
    fireEvent.keyDown(dlg, { key: "Escape" });
    await waitFor(() => { expect(tab()?.state).toBe("closed"); });
    expect(tab()?.closeCode).toBe("user");
    expect(tab()?.reason).toBe("smart card PIN cancelled");
    expect(mock.audit.find((e) => e.event === "credential.pin_prompted")?.details.outcome).toBe("cancelled");
  });

  it("no PIN when the agent already holds the key; a key it lacks without a module is a pre-flight refusal", async () => {
    mock.piv.agentHolds = true;
    await boot();
    await act(async () => { await useSessions.getState().open("c-web01"); });
    await waitFor(() => { expect(tab()?.state).toBe("connected"); });
    expect(screen.queryByRole("alertdialog")).toBeNull();

    mock.piv.agentHolds = false;
    const card = mock.creds.items.find((c) => c.id === "cr-piv");
    if (card) delete card.fields.pkcs11_module;
    await act(async () => { await useSessions.getState().open("c-web01", { newTab: true }); });
    await settle();
    const t = useSessions.getState().tabs[1];
    expect(t?.openError).toBe("ssh.piv_key_not_in_agent");
    act(() => { if (t) useSessions.getState().activate(t.id); });
    const strip = within(panel()).getByText("Smart card key not in ssh-agent").closest(".dropped");
    expect(strip).toHaveTextContent("ssh-add -s <module>");
    expect(strip).toHaveTextContent("choose the module so Mooring asks the PIN");
  });
});

describe("Smart card / PIV credentials", () => {
  beforeEach(() => { freshBackend(); });

  function newKind(label: string) {
    act(() => { useUi.getState().showCredentials({ mode: "new" }); });
    const view = screen.getByRole("region", { name: "Credentials" });
    fireEvent.click(within(view).getByRole("button", { name: label }));
    return { view, form: within(view).getByRole("form") };
  }

  it("creates one with no secret section, the PIN note and the module choice, then shows the card", async () => {
    await boot();
    const { view, form } = newKind("Smart card / PIV");
    expect(within(form).queryByText("Secrets")).toBeNull();
    expect(form).toHaveTextContent(PIN_NOTE);
    expect(form).toHaveTextContent(SSH_ADD_HINT);
    fireEvent.change(within(form).getByLabelText("Name"), { target: { value: "badge" } });
    fireEvent.change(within(form).getByLabelText(/^Username/), { target: { value: "alice" } });
    fireEvent.change(within(form).getByLabelText(/^Public key/), { target: { value: `${PIV_PUBLIC} badge` } });
    expect(await within(form).findByText(PIV_FINGERPRINT)).toBeInTheDocument();
    fireEvent.click(within(form).getByRole("radio", { name: "OpenSC" }));
    expect(within(form).getByRole("radio", { name: "YubiKey (ykcs11)" })).not.toBeChecked();
    fireEvent.click(within(form).getByRole("button", { name: /^Create/ }));
    await settle();
    const detail = within(view).getByRole("article");
    expect(detail).toHaveTextContent("Smart card");
    expect(detail).toHaveTextContent("PKCS#11 moduleOpenSC");
    expect(detail).toHaveTextContent(PIN_NOTE);
    expect(detail).toHaveTextContent("Smart-card logon over RDP needs Kerberos PKINIT (planned).");
    expect(detail).toHaveTextContent(/none stored/);
  });

  it("shows the stored fingerprint read-only when editing, and refuses a FIDO2 line", async () => {
    await boot();
    act(() => { useUi.getState().showCredentials({ mode: "edit", id: "cr-piv" }); });
    const view = screen.getByRole("region", { name: "Credentials" });
    const form = within(view).getByRole("form");
    // The derived fingerprint is shown, never an input.
    const derived = within(form).getByTitle(PIV_FINGERPRINT);
    expect(derived.closest("dl")).toHaveTextContent(`Fingerprint${PIV_FINGERPRINT}`);
    expect(within(form).queryByDisplayValue(PIV_FINGERPRINT)).toBeNull();
    fireEvent.change(within(form).getByLabelText(/^Public key/), { target: { value: SK_PUBLIC } });
    fireEvent.click(within(form).getByRole("button", { name: /^Save/ }));
    await settle();
    expect(useCredentials.getState().errorCode).toBe("credential.use_sk_kind");
    expect(within(form).getByRole("alert")).toHaveTextContent("FIDO2 security key");
  });
});
