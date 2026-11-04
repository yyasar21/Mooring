import { act, fireEvent, render, screen } from "@testing-library/react";
import { App } from "../App";
import { useApp } from "../stores/app";
import { useSessions } from "../stores/sessions";
import { freshBackend, settle } from "../test/harness";
import { lockReasonText } from "./VaultGate";

describe("vault:locked (ADR-0010)", () => {
  it("returns to the unlock screen with the reason and drops every tab", async () => {
    const mock = freshBackend();
    render(<App />);
    await screen.findByText("Nothing open yet");
    await act(async () => {
      await useSessions.getState().open("c-dc");
    });
    expect(useSessions.getState().tabs).toHaveLength(1);

    act(() => { mock.fireAutoLock("idle"); });
    expect(await screen.findByText("Unlock Mooring")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Locked after a period of inactivity.");
    expect(useSessions.getState().tabs).toHaveLength(0);

    fireEvent.change(screen.getByLabelText("Master password"), { target: { value: "correct horse" } });
    fireEvent.click(screen.getByRole("button", { name: "Unlock" }));
    await settle();
    expect(await screen.findByText("Nothing open yet")).toBeInTheDocument();
    expect(useApp.getState().lockReason).toBeNull();
  });

  it("shows no reason after a user lock", async () => {
    freshBackend();
    render(<App />);
    await screen.findByText("Nothing open yet");
    fireEvent.click(screen.getByRole("button", { name: "Lock" }));
    expect(await screen.findByText("Unlock Mooring")).toBeInTheDocument();
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("treats a user-reason event like a user lock", () => {
    freshBackend();
    act(() => { useApp.getState().lockedByBackend("user"); });
    expect(useApp.getState()).toMatchObject({ vault: "locked", lockReason: null });
  });

  it("has an English sentence for every reason", () => {
    for (const r of ["idle", "screen_lock", "sleep", "window_hidden", "unknown"] as const) {
      expect(lockReasonText(r)).toMatch(/^Locked /);
    }
    expect(lockReasonText("user")).toBeNull();
    expect(lockReasonText(null)).toBeNull();
  });
});
