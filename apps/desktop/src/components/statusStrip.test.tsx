import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { App } from "../App";
import { useSessions } from "../stores/sessions";
import { TOAST_DETAIL_MS, TOAST_MS, useToasts } from "../stores/toast";
import { freshBackend, settle } from "../test/harness";
import { Toasts } from "./Toasts";

// M7: toasts carry an icon, a title and an optional detail; a closed terminal shows an inline
// strip under the session header instead of the floating "Link lost" box.

describe("toasts (M7)", () => {
  beforeEach(() => { freshBackend(); });

  it("shows a status icon, the title and the detail, and dismisses by name", () => {
    render(<Toasts />);
    act(() => { useToasts.getState().push("Connection created", { detail: "web01" }); });
    act(() => { useToasts.getState().push("Biometric unlock turned off", { tone: "warning" }); });
    const [saved, warn] = Array.from(screen.getByTestId("toasts").querySelectorAll(".toast"));
    expect(saved).toHaveAttribute("data-tone", "success");
    expect(saved?.querySelector(".toast-icon svg")).not.toBeNull();
    expect(saved?.querySelector(".toast-title")).toHaveTextContent("Connection created");
    expect(saved?.querySelector(".toast-detail")).toHaveTextContent("web01");
    expect(warn).toHaveAttribute("data-tone", "warning");
    expect(warn?.querySelector(".toast-detail")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Dismiss: Connection created" }));
    expect(useToasts.getState().toasts.map((t) => t.text)).toEqual(["Biometric unlock turned off"]);
  });

  it("a toast with a detail stays longer", () => {
    vi.useFakeTimers();
    try {
      useToasts.getState().push("Saved");
      useToasts.getState().push("Credential saved", { detail: "ops on-call" });
      vi.advanceTimersByTime(TOAST_MS + 1);
      expect(useToasts.getState().toasts.map((t) => t.text)).toEqual(["Credential saved"]);
      vi.advanceTimersByTime(TOAST_DETAIL_MS - TOAST_MS);
      expect(useToasts.getState().toasts).toEqual([]);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("closed terminal strip (M7)", () => {
  beforeEach(() => { freshBackend(); });

  it("sits in the layout under the header with an icon, a title, the reason and Reconnect", async () => {
    render(<App />);
    await screen.findByText("Nothing open yet");
    await settle();
    await act(async () => { await useSessions.getState().open("c-web01"); });
    await settle();
    const trust = await screen.findByRole("alertdialog", { name: "Verify host identity" });
    fireEvent.click(within(trust).getByRole("button", { name: "Reject and disconnect" }));
    await settle(6);
    const panel = screen.getByRole("tabpanel");
    const strip = within(panel).getByRole("status");
    expect(strip).toHaveClass("status-strip");
    // in the frame, between the header and the terminal body: not floating over the output
    expect(strip.parentElement).toHaveClass("session-frame");
    expect(strip.previousElementSibling).toHaveClass("session-header");
    expect(strip.nextElementSibling).toHaveClass("session-body");
    expect(strip.querySelector(".status-strip-icon svg")).not.toBeNull();
    expect(strip.querySelector(".status-strip-title")?.textContent).not.toBe("");
    expect(strip).toHaveTextContent(/Disconnected: /);
    expect(within(panel).queryByText("Link lost")).toBeNull();
    expect(within(strip).getByRole("button", { name: "Reconnect" })).toBeInTheDocument();
    expect(document.querySelector(".session-pill")).toHaveTextContent(/^(Closed|Disconnected)$/);
  });
});
