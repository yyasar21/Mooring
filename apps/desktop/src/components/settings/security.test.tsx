import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { App } from "../../App";
import { useApp } from "../../stores/app";
import { useBiometric } from "../../stores/biometric";
import { freshBackend, settle } from "../../test/harness";
import type { MockTransport } from "../../lib/ipc.mock";
import { SecurityCard } from "./SecurityCard";

const card = () => screen.getByRole("region", { name: "Security" });
const toggle = () => within(card()).getByRole("switch");

async function renderCard() {
  render(<SecurityCard />);
  await settle();
}

async function typePassword(text: string, submit: RegExp) {
  const form = within(card()).getByRole("form");
  fireEvent.change(within(form).getByLabelText("Master password"), { target: { value: text } });
  fireEvent.click(within(form).getByRole("button", { name: submit }));
  await settle();
}

describe("Settings → Security (ADR-0022)", () => {
  let mock: MockTransport;
  beforeEach(() => { mock = freshBackend(); });

  it("turns Windows Hello on after the master password, and off again", async () => {
    await renderCard();
    expect(toggle()).not.toBeChecked();
    expect(within(card()).getByText("Unlock with Windows Hello")).toBeInTheDocument();
    fireEvent.click(toggle());
    // nothing was enrolled yet: the password step comes first
    expect(mock.bioEnabled).toBe(false);
    await typePassword("any password", /Turn on Windows Hello/);
    expect(mock.bioEnabled).toBe(true);
    expect(toggle()).toBeChecked();
    expect(within(card()).getByRole("status")).toHaveTextContent("Windows Hello unlock is on.");
    expect(mock.audit.map((a) => a.event)).toContain("vault.biometric_enabled");

    fireEvent.click(toggle());
    await typePassword("any password", /Turn off Windows Hello/);
    expect(mock.bioEnabled).toBe(false);
    expect(toggle()).not.toBeChecked();
  });

  it("shows the system-prompt cancel and keeps the switch off", async () => {
    mock.bioOutcome = "cancelled";
    await renderCard();
    fireEvent.click(toggle());
    await typePassword("any password", /Turn on/);
    expect(within(card()).getByRole("alert")).toHaveTextContent("The system prompt was cancelled. Nothing changed.");
    expect(toggle()).not.toBeChecked();
  });

  it("refuses an empty master password without calling Rust", async () => {
    await renderCard();
    fireEvent.click(toggle());
    fireEvent.click(within(card()).getByRole("button", { name: /Turn on/ }));
    await settle();
    expect(within(card()).getByRole("alert")).toHaveTextContent("Enter the master password.");
    expect(mock.bioEnabled).toBe(false);
  });

  it.each([
    ["unsigned_build", "macos", "Unlock with Touch ID", /Touch ID needs a signed build of Mooring/],
    ["no_acl", "linux", "Unlock with biometrics", /Not available on Linux/],
    ["keychain_unavailable", "macos", "Unlock with Touch ID", /keychain is not available/],
  ] as const)("explains %s and disables the switch", async (reason, platform, label, text) => {
    mock.bioPlatform = platform;
    mock.bioUnavailable = reason;
    await renderCard();
    expect(within(card()).getByText(label)).toBeInTheDocument();
    expect(within(card()).getByText(text)).toBeInTheDocument();
    expect(toggle()).toBeDisabled();
  });

  it("explains a suspended enrolment with its reason", async () => {
    mock.bioSuspended = "failed_attempts";
    await renderCard();
    expect(screen.getByTestId("biometric-suspended")).toHaveTextContent(
      "Windows Hello unlock was turned off because three failed or cancelled attempts within 10 minutes.",
    );
    expect(toggle()).not.toBeChecked();
    expect(toggle()).toBeEnabled();
  });
});

describe("unlock screen (ADR-0022)", () => {
  let mock: MockTransport;
  beforeEach(() => { mock = freshBackend({ vault: "locked" }); });

  it("offers Unlock with Windows Hello only when enabled, and unlocks on click", async () => {
    mock.bioEnabled = true;
    render(<App />);
    const btn = await screen.findByRole("button", { name: "Unlock with Windows Hello" });
    expect(mock.vault).toBe("locked"); // never prompted on its own
    fireEvent.click(btn);
    await screen.findByText("Nothing open yet");
    expect(mock.audit.map((a) => a.event)).toContain("vault.unlock_biometric");
  });

  it("shows no biometric button when it is off or unavailable", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Unlock Mooring" });
    await settle();
    expect(screen.queryByRole("button", { name: /Unlock with/ })).toBeNull();
  });

  it("the third failed prompt suspends it; the next password unlock says so once", async () => {
    mock.bioEnabled = true;
    mock.bioOutcome = "failed";
    render(<App />);
    for (let i = 0; i < 3; i++) {
      fireEvent.click(await screen.findByRole("button", { name: "Unlock with Windows Hello" }));
      await settle();
    }
    expect(mock.bioSuspended).toBe("failed_attempts");
    expect(screen.getByRole("alert")).toHaveTextContent(/turned off for safety/);
    expect(screen.queryByRole("button", { name: "Unlock with Windows Hello" })).toBeNull();
    await act(async () => { await useApp.getState().unlock("pw"); });
    await settle();
    expect(screen.getByText(/Windows Hello unlock was turned off because three failed/)).toBeInTheDocument();
    expect(useBiometric.getState().status?.reason).toBe("suspended");
  });
});
