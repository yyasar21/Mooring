import { act, fireEvent, render, screen, within } from "@testing-library/react";
import type { CertificateInfo } from "../../lib/ipc";
import type { MockTransport } from "../../lib/ipc.mock";
import { useSessions, type PendingPrompt, type Tab } from "../../stores/sessions";
import { useTree } from "../../stores/tree";
import { freshBackend, settle } from "../../test/harness";
import { fingerprintGroups, validityAt } from "./CertificateDetails";
import { CERT_ANSWER } from "./CertificateTrustDialog";
import { PromptModal } from "../terminal/PromptModal";

const SHA = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

function cert(p: Partial<CertificateInfo> = {}): CertificateInfo {
  return {
    subject: "CN=dc01.example.test",
    issuer: "CN=dc01.example.test",
    notBefore: "2026-01-01T00:00:00Z",
    notAfter: "2099-01-01T00:00:00Z",
    sha256: SHA,
    san: ["dc01.example.test", "192.0.2.10"],
    problems: ["self_signed"],
    ...p,
  };
}

describe("certificate trust dialog", () => {
  let mock: MockTransport;
  beforeEach(async () => {
    mock = freshBackend();
    await useTree.getState().load();
  });

  /** A tab on c-dc with this prompt pending (no backend session needed for the UI checks). */
  function show(certificate: CertificateInfo | null) {
    const prompt: PendingPrompt = { id: 7, message: "m", secret: false, purpose: "certificate_trust", account: null, certificate };
    const tab: Tab = {
      id: "t1", connectionId: "c-dc", protocol: "rdp", sessionId: "r-x", state: "connecting", peerIdentity: null, security: null,
      prompt, reason: null, closeCode: null, reconnect: null, desktop: null, viewOnly: false, attachEpoch: 0,
    };
    const sent: string[] = [];
    vi.spyOn(mock, "sessionSend").mockImplementation(({ input }) => {
      if (input.kind === "answer") sent.push(input.text);
      return Promise.resolve();
    });
    useSessions.setState({ tabs: [tab] });
    const answer = { texts: sent };
    render(<PromptModal tabId="t1" prompt={prompt} host="dc01.example.test" />);
    return { answer, dialog: screen.getByRole("alertdialog", { name: "Verify server certificate" }) };
  }

  it("shows host:port, protocol, names, problems and the grouped fingerprint; focus starts on Reject", () => {
    const { dialog } = show(cert());
    expect(dialog).toHaveTextContent("RDP");
    expect(dialog).toHaveTextContent("dc01.example.test:3389");
    expect(dialog).toHaveTextContent("192.0.2.10");
    expect(dialog).toHaveTextContent("same as subject");
    expect(within(dialog).getByRole("list", { name: "Problems" })).toHaveTextContent(/Self-signed.*signs itself/);
    expect(dialog).toHaveAttribute("data-tone", "hot");
    expect(screen.getByLabelText(/^SHA-256 fingerprint A1:B2:C3/)).toHaveTextContent("A1:B2:C3:D4E5:F6:07:18");
    expect(document.activeElement).toBe(within(dialog).getByRole("button", { name: "Reject" }));
    expect(within(dialog).queryByRole("button", { name: /once/i })).toBeNull();
  });

  it("Trust and remember sends R2's `yes`; Reject and Escape send `no`; never twice", () => {
    expect(CERT_ANSWER).toEqual({ trust: "yes", reject: "no" });
    const a = show(cert());
    fireEvent.click(within(a.dialog).getByRole("button", { name: "Trust and remember" }));
    fireEvent.click(within(a.dialog).getByRole("button", { name: "Trust and remember" }));
    expect(a.answer.texts).toEqual(["yes"]);
  });

  it("Escape rejects", () => {
    const { answer, dialog } = show(cert());
    fireEvent.keyDown(dialog, { key: "Escape" });
    expect(answer.texts).toEqual(["no"]);
  });

  it("an expired or mismatched certificate needs the explicit check before Trust", () => {
    const { answer, dialog } = show(cert({ notAfter: "2020-01-01T00:00:00Z", problems: ["expired", "name_mismatch"] }));
    expect(dialog).toHaveTextContent("expired");
    const trust = within(dialog).getByRole("button", { name: "Trust and remember" });
    expect(trust).toBeDisabled();
    fireEvent.click(within(dialog).getByRole("checkbox", { name: /I compared the fingerprint/ }));
    expect(trust).toBeEnabled();
    fireEvent.click(trust);
    expect(answer.texts).toEqual(["yes"]);
  });

  it("keeps Tab inside the dialog", () => {
    const { dialog } = show(cert());
    const reject = within(dialog).getByRole("button", { name: "Reject" });
    const trust = within(dialog).getByRole("button", { name: "Trust and remember" });
    trust.focus();
    fireEvent.keyDown(dialog, { key: "Tab" });
    expect(document.activeElement).toBe(reject);
    fireEvent.keyDown(dialog, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(trust);
  });

  it("without certificate details Trust stays disabled", () => {
    const { dialog } = show(null);
    expect(within(dialog).getByRole("button", { name: "Trust and remember" })).toBeDisabled();
  });

  it("end to end with the mock: trusting pins and connects", async () => {
    await act(async () => { await useSessions.getState().open("c-dc"); });
    await settle();
    const t = useSessions.getState().tabs[0];
    if (!t?.prompt) throw new Error("no prompt");
    render(<PromptModal tabId={t.id} prompt={t.prompt} host="dc01.example.test" />);
    fireEvent.click(screen.getByRole("button", { name: "Trust and remember" }));
    await vi.waitFor(() => { expect(useSessions.getState().tabs[0]?.state).toBe("connected"); });
    expect(await mock.knownCertsList({ protocol: "rdp" })).toHaveLength(1);
  });

  it("validity and fingerprint helpers", () => {
    const c = cert({ notBefore: "2030-01-01T00:00:00Z" });
    expect(validityAt(c, Date.parse("2026-11-04T00:00:00Z"))).toBe("not_yet_valid");
    expect(validityAt(cert(), Date.parse("2026-11-04T00:00:00Z"))).toBe("valid");
    expect(validityAt(cert({ notAfter: "x" }), 0)).toBe("unknown");
    expect(fingerprintGroups(SHA)).toHaveLength(8);
  });
});
