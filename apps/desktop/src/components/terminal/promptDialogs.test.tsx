// W3 leftovers: the sign-in and smart-card PIN prompts on the M8 decision shell, their secret
// handling (uncontrolled, emptied, never in React state).
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { App } from "../../App";
import type { MockTransport } from "../../lib/ipc.mock";
import { useSessions } from "../../stores/sessions";
import { freshBackend, settle } from "../../test/harness";
import { reactStateHolds } from "../../test/reactState";

const PIN = "246810";
const PASSWORD = "fixture-prompt-pw";

async function boot() {
  const view = render(<App />);
  await screen.findByText("Nothing open yet");
  await settle();
  return view;
}

async function closeAll() {
  for (const t of useSessions.getState().tabs) await act(async () => { await useSessions.getState().close(t.id); });
}

describe("sign-in prompt on the decision shell", () => {
  let mock: MockTransport;
  beforeEach(() => {
    mock = freshBackend();
    mock.trustedHosts.add("jump.stage.example.test");
  });

  it("starts on the password, keeps it out of React state, and Escape cancels", async () => {
    const { container } = await boot();
    await act(async () => { await useSessions.getState().open("c-jump"); });
    await settle();
    const dlg = screen.getByRole("alertdialog", { name: "Sign in to jump.stage.example.test" });
    expect(dlg).toHaveClass("decision-dialog");
    expect(dlg).toHaveAccessibleDescription(/stores no password/);
    const pw = within(dlg).getByLabelText("Password");
    expect(pw).toHaveFocus(); // the username is known
    expect(pw).toHaveAttribute("data-secret");
    fireEvent.change(pw, { target: { value: PASSWORD } });
    expect(reactStateHolds(container, PASSWORD)).toBe(false);
    // An empty username is refused in place, without sending.
    fireEvent.change(within(dlg).getByLabelText("Username"), { target: { value: "" } });
    const send = vi.spyOn(mock, "sessionSend");
    fireEvent.click(within(dlg).getByRole("button", { name: "Sign in" }));
    expect(within(dlg).getByRole("alert")).toHaveTextContent("Enter a username and a password.");
    expect(send).not.toHaveBeenCalled();
    fireEvent.keyDown(dlg, { key: "Escape" });
    expect(pw).toHaveValue("");
    await settle();
    expect(send.mock.calls[0]?.[0].input).toMatchObject({ kind: "credential_answer", username: "", password: "" });
    await closeAll();
  });
});

describe("smart card PIN on the decision shell", () => {
  let mock: MockTransport;
  beforeEach(() => {
    mock = freshBackend();
    const c = mock.connections.find((x) => x.id === "c-web01");
    if (c) c.credentialId = "cr-piv";
    mock.trustedHosts.add("web01.example.test");
  });

  const pinDialog = () => screen.queryByRole("alertdialog", { name: "Smart card PIN" });

  it("keeps the PIN out of React state, shows the card's question in the well and traps Tab", async () => {
    const { container } = await boot();
    await act(async () => { await useSessions.getState().open("c-web01"); });
    await settle();
    const dlg = pinDialog();
    if (!dlg) throw new Error("no PIN dialog");
    expect(dlg).toHaveClass("decision-dialog");
    expect(dlg).toHaveAccessibleDescription(/Enter the PIN of the smart card \(Yubico YubiKey\)/);
    const pin = within(dlg).getByLabelText("PIN");
    expect(pin).toHaveFocus();
    fireEvent.change(pin, { target: { value: PIN } });
    expect(reactStateHolds(container, PIN)).toBe(false);
    const unlock = within(dlg).getByRole("button", { name: "Unlock card" });
    unlock.focus();
    fireEvent.keyDown(dlg, { key: "Tab" });
    expect(pin).toHaveFocus(); // Tab from the last control wraps to the first
    await closeAll();
  });
});
