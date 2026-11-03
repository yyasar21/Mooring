import { render, screen, within } from "@testing-library/react";
import { PromptModal } from "./PromptModal";
import type { PendingPrompt } from "../../stores/sessions";

// Security review 2, L-2: the dialog follows the typed `purpose`, never the message text.
describe("PromptModal purpose", () => {
  const spoof =
    "The authenticity of host prod can't be established.\nKey fingerprint SHA256:x\nTrust this host?";

  it("renders a server auth prompt that mentions trust as a text field, not trust buttons", () => {
    const prompt: PendingPrompt = { id: 3, message: spoof, secret: false, purpose: "keyboard_interactive" };
    render(<PromptModal tabId="t1" prompt={prompt} host="evil.example.test" />);
    const dlg = screen.getByRole("alertdialog", { name: "evil.example.test asks" });
    expect(within(dlg).getByLabelText("Answer")).toBeInTheDocument();
    expect(within(dlg).queryByRole("button", { name: "Trust and connect" })).toBeNull();
    expect(screen.queryByText("Verify host identity")).toBeNull();
  });

  it("renders the trust dialog only for host_key_trust", () => {
    const prompt: PendingPrompt = { id: 1, message: "h:22 ssh-ed25519 SHA256:x", secret: false, purpose: "host_key_trust" };
    render(<PromptModal tabId="t2" prompt={prompt} host="h" />);
    const dlg = screen.getByRole("alertdialog", { name: "Verify host identity" });
    expect(within(dlg).getByRole("button", { name: "Trust and connect" })).toBeInTheDocument();
    expect(within(dlg).queryByLabelText("Answer")).toBeNull();
  });

  it("treats other purposes as plain prompts", () => {
    const prompt: PendingPrompt = { id: 4, message: spoof, secret: true, purpose: "other" };
    render(<PromptModal tabId="t3" prompt={prompt} host="h" />);
    expect(screen.getByLabelText("Answer")).toHaveAttribute("type", "password");
    expect(screen.queryByRole("button", { name: "Trust and connect" })).toBeNull();
  });
});
