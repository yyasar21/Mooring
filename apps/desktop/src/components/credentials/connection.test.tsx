import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { App } from "../../App";
import { useCredentials } from "../../stores/credentials";
import { useSessions } from "../../stores/sessions";
import { useTree } from "../../stores/tree";
import { useUi } from "../../stores/ui";
import { freshBackend, settle } from "../../test/harness";
import type { MockTransport } from "../../lib/ipc.mock";

async function boot() {
  render(<App />);
  await screen.findByText("Nothing open yet");
  await settle();
}

describe("connection credential picker", () => {
  beforeEach(() => { freshBackend(); });

  it("disables incompatible credentials with the reason and offers RD Gateway on RDP only", async () => {
    await boot();
    act(() => { useUi.getState().openDialog({ kind: "connection", id: "c-dc", folderId: "f-desk" }); });
    const dlg = screen.getByRole("dialog", { name: "Edit connection" });
    fireEvent.click(within(dlg).getByRole("button", { name: /^Credential/ }));
    const list = within(dlg).getByRole("listbox", { name: "Credential" });
    const opt = (name: string) => within(list).getAllByRole("option").find((o) => o.textContent.includes(name));
    expect(opt("ops on-call")).toHaveAttribute("aria-disabled", "true");
    expect(opt("ops on-call")).toHaveTextContent("SSH key is for SSH, not RDP sign-in.");
    expect(opt("domain admin")).not.toHaveAttribute("aria-disabled");
    expect(opt("ask at connect")).not.toHaveAttribute("aria-disabled");
    // keyboard skips disabled options
    fireEvent.keyDown(list, { key: "Escape" });
    expect(within(dlg).getByRole("button", { name: /^RD Gateway credential/ })).toBeInTheDocument();
    expect(within(dlg).queryByRole("button", { name: /^Become/ })).toBeNull();
    expect(within(dlg).getByLabelText(/^Username override/)).toHaveValue("dc-admin");
    fireEvent.click(within(dlg).getByRole("radio", { name: "SSH" }));
    expect(within(dlg).queryByRole("button", { name: /^RD Gateway/ })).toBeNull();
    expect(within(dlg).getByRole("button", { name: /^Become/ })).toBeInTheDocument();
  });

  it("saves overrides and the become role through connection_update", async () => {
    await boot();
    act(() => { useUi.getState().openDialog({ kind: "connection", id: "c-web01", folderId: "f-web" }); });
    const dlg = screen.getByRole("dialog", { name: "Edit connection" });
    fireEvent.change(within(dlg).getByLabelText(/^Username override/), { target: { value: "deploy" } });
    expect(within(dlg).getByLabelText(/^Domain override/)).toBeDisabled(); // ssh_key has no domain
    fireEvent.click(within(dlg).getByRole("button", { name: /^Become/ }));
    const list = within(dlg).getByRole("listbox", { name: "Become (sudo)" });
    fireEvent.keyDown(list, { key: "ArrowDown" });
    fireEvent.keyDown(list, { key: "Enter" });
    fireEvent.click(within(dlg).getByRole("button", { name: "Save connection" }));
    await settle();
    expect(useTree.getState().connections.find((c) => c.id === "c-web01")).toMatchObject({
      usernameOverride: "deploy",
      domainOverride: null,
      becomeCredentialId: "cr-sudo",
    });
  });
});

describe("copy OTP countdown", () => {
  beforeEach(() => { freshBackend(); });
  afterEach(() => { vi.useRealTimers(); });

  it("rings down over the code's remaining validity, then disappears", async () => {
    await boot();
    vi.useFakeTimers({ toFake: ["setInterval", "Date"] });
    vi.setSystemTime(new Date("2026-11-03T10:00:12Z")); // 12 s into a 30 s window
    act(() => { useTree.getState().select({ kind: "connection", id: "c-stg" }); });
    const details = screen.getByRole("complementary", { name: "Details" });
    await act(async () => {
      const [direct] = within(details).getAllByRole("button", { name: "Copy OTP code" });
      if (direct) fireEvent.click(direct);
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(useCredentials.getState().otp["cr-deploy"]?.periodMs).toBe(30_000);
    expect(within(details).getByRole("status", { name: "OTP code valid for 18 more seconds" })).toBeInTheDocument();
    act(() => { vi.advanceTimersByTime(10_000); });
    expect(within(details).getByRole("status", { name: "OTP code valid for 8 more seconds" })).toBeInTheDocument();
    act(() => { vi.advanceTimersByTime(8_250); });
    expect(within(details).queryByRole("status", { name: /OTP code valid/ })).toBeNull();
    expect(useCredentials.getState().otp["cr-deploy"]).toBeUndefined();
  });
});

describe("prompt credential at connect", () => {
  let mock: MockTransport;
  beforeEach(() => { mock = freshBackend(); });

  it("collects username and password, sends a credential answer and clears the field", async () => {
    await boot();
    mock.trustedHosts.add("jump.stage.example.test");
    await act(async () => { await useSessions.getState().open("c-jump"); });
    await settle();
    const dlg = await screen.findByRole("alertdialog", { name: "Sign in to jump.stage.example.test" });
    expect(within(dlg).getByLabelText("Username")).toHaveValue("ops");
    const pw = within(dlg).getByLabelText("Password");
    fireEvent.change(pw, { target: { value: "fixture-not-a-secret" } });
    const send = vi.spyOn(mock, "sessionSend");
    fireEvent.click(within(dlg).getByRole("button", { name: "Sign in" }));
    expect(pw).toHaveValue("");
    await settle();
    expect(send.mock.calls[0]?.[0].input).toMatchObject({ kind: "credential_answer", id: 3, username: "ops", domain: null });
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(useSessions.getState().tabs[0]?.state).toBe("connected");
    expect(document.body.innerHTML).not.toContain("fixture-not-a-secret");
  });

  it("splits DOMAIN\\user typed at connect", async () => {
    await boot();
    mock.trustedHosts.add("jump.stage.example.test");
    await act(async () => { await useSessions.getState().open("c-jump"); });
    await settle();
    const dlg = await screen.findByRole("alertdialog");
    fireEvent.change(within(dlg).getByLabelText("Username"), { target: { value: "CORP\\bob" } });
    expect(dlg).toHaveTextContent("User bob in domain CORP");
    fireEvent.change(within(dlg).getByLabelText("Password"), { target: { value: "x" } });
    const send = vi.spyOn(mock, "sessionSend");
    fireEvent.click(within(dlg).getByRole("button", { name: "Sign in" }));
    await settle();
    expect(send.mock.calls[0]?.[0].input).toMatchObject({ kind: "credential_answer", username: "bob", domain: "CORP" });
  });
});
