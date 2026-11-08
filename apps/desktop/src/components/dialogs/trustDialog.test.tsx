import { fireEvent, render, screen, within } from "@testing-library/react";
import type { CertificateInfo } from "../../lib/ipc";
import type { MockTransport } from "../../lib/ipc.mock";
import { blankTab, useSessions, type PendingPrompt } from "../../stores/sessions";
import { useTree } from "../../stores/tree";
import { freshBackend } from "../../test/harness";
import { reactStateHolds } from "../../test/reactState";
import { PromptModal } from "../terminal/PromptModal";
import { ConfirmDialog } from "./TrustDialog";

// M8: one pattern for trust and confirmation dialogs. Security UX: the trust button never holds
// the initial focus, Escape always answers "reject", and what each button answers is unchanged.

const SHA = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
const CERT: CertificateInfo = {
  subject: "CN=gw01.example.test", issuer: "CN=Example CA", notBefore: "2026-01-01T00:00:00Z", notAfter: "2099-01-01T00:00:00Z",
  sha256: SHA, san: ["gw01.example.test"], problems: [],
};

describe("trust dialogs (M8)", () => {
  let mock: MockTransport;
  let sent: string[];
  beforeEach(async () => {
    mock = freshBackend();
    await useTree.getState().load();
    sent = [];
    vi.spyOn(mock, "sessionSend").mockImplementation(({ input }) => {
      if (input.kind === "answer") sent.push(input.text);
      return Promise.resolve();
    });
  });

  function show(connectionId: string, prompt: PendingPrompt, host = "web01.example.test") {
    const tab = blankTab("t1", connectionId, null, { sessionId: "s-x", prompt, gateway: { state: "connecting", host: "gw01.example.test:443", peerIdentity: null } });
    useSessions.setState({ tabs: [tab] });
    return render(<PromptModal tabId="t1" prompt={prompt} host={host} />);
  }

  it("host key: focus starts on Reject, the key sits in a mono well, Escape rejects, Tab stays inside", () => {
    show("c-web01", { id: 1, message: "web01.example.test:22 ED25519 SHA256:abc", secret: false, purpose: "host_key_trust" });
    const dlg = screen.getByRole("alertdialog", { name: "Verify host identity" });
    const reject = within(dlg).getByRole("button", { name: "Reject and disconnect" });
    const trust = within(dlg).getByRole("button", { name: "Trust and connect" });
    expect(reject).toHaveFocus();
    expect(trust).not.toHaveFocus();
    const well = dlg.querySelector(".fp-well");
    expect(well).toHaveTextContent("Host key");
    expect(well?.querySelector(".mono")).toHaveTextContent("SHA256:abc");
    fireEvent.keyDown(dlg, { key: "Tab", shiftKey: true });
    expect(trust).toHaveFocus();
    fireEvent.keyDown(dlg, { key: "Tab" });
    expect(reject).toHaveFocus();
    fireEvent.keyDown(dlg, { key: "Escape" });
    expect(sent).toEqual(["no"]);
  });

  it("host key: the buttons still answer yes and no", () => {
    show("c-web01", { id: 2, message: "k", secret: false, purpose: "host_key_trust" });
    fireEvent.click(screen.getByRole("button", { name: "Trust and connect" }));
    expect(sent).toEqual(["yes"]);
  });

  it("RD Gateway certificate: focus on Reject, fingerprint well, Trust once kept, Escape rejects", () => {
    show("c-dc", { id: 3, message: "m", secret: false, purpose: "gateway_certificate_trust", account: null, certificate: CERT });
    const dlg = screen.getByRole("alertdialog", { name: "RD Gateway certificate" });
    expect(within(dlg).getByRole("button", { name: "Reject" })).toHaveFocus();
    expect(within(dlg).getByRole("button", { name: "Trust once" })).toBeEnabled();
    const well = dlg.querySelector(".fp-well");
    expect(well).toHaveTextContent("SHA-256 fingerprint");
    expect(within(dlg).getByLabelText(/^SHA-256 fingerprint A1:B2:C3/)).toBeInTheDocument();
    expect(dlg).toHaveTextContent("gw01.example.test:443");
    fireEvent.keyDown(dlg, { key: "Escape" });
    expect(sent).toEqual(["no"]);
  });

  it("server prompt: focus on the answer and the typed code stays out of React state", () => {
    const { container } = show("c-web01", { id: 4, message: "Verification code:", secret: true, purpose: "keyboard_interactive" });
    const dlg = screen.getByRole("alertdialog", { name: "web01.example.test asks" });
    const field = within(dlg).getByLabelText("Answer");
    expect(field).toHaveFocus();
    fireEvent.change(field, { target: { value: "731904" } });
    expect(reactStateHolds(container, "731904")).toBe(false);
    fireEvent.click(within(dlg).getByRole("button", { name: "Send" }));
    expect(sent).toEqual(["731904"]);
    expect(field).toHaveValue("");
  });

  it("server prompt: Escape sends the empty answer", () => {
    show("c-web01", { id: 5, message: "Verification code:", secret: true, purpose: "keyboard_interactive" });
    fireEvent.keyDown(screen.getByRole("alertdialog"), { key: "Escape" });
    expect(sent).toEqual([""]);
  });
});

describe("ConfirmDialog (M8)", () => {
  beforeEach(() => { freshBackend(); });

  it("focuses Cancel first, shows the well, and Escape cancels", () => {
    const onConfirm = vi.fn();
    const onCancel = vi.fn();
    render(
      <ConfirmDialog title="Expose this forward?" tone="danger" well={{ label: "Listening on", value: "0.0.0.0:1080" }} confirmLabel="Expose to network" danger onConfirm={onConfirm} onCancel={onCancel}>
        <p>Any machine can reach it.</p>
      </ConfirmDialog>,
    );
    const dlg = screen.getByRole("dialog", { name: "Expose this forward?" });
    expect(within(dlg).getByRole("button", { name: "Cancel" })).toHaveFocus();
    expect(dlg.querySelector(".fp-well")).toHaveTextContent("Listening on0.0.0.0:1080");
    expect(dlg.querySelector(".decision-icon")).toHaveAttribute("data-tone", "danger");
    expect(within(dlg).getByRole("button", { name: "Expose to network" })).toHaveClass("btn-danger-solid");
    fireEvent.keyDown(dlg, { key: "Escape" });
    expect(onCancel).toHaveBeenCalledTimes(1);
    fireEvent.click(within(dlg).getByRole("button", { name: "Expose to network" }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });
});
