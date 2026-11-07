import { render, screen, fireEvent } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { TabErrorBoundary } from "./TabErrorBoundary";

function Boom(): never {
  throw new TypeError("Attempted to assign to readonly property.");
}

describe("TabErrorBoundary", () => {
  it("keeps a failing view inside its tab instead of blanking the window", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const onClose = vi.fn();
    render(
      <div>
        <p>sidebar stays</p>
        <TabErrorBoundary what="the terminal" onClose={onClose}>
          <Boom />
        </TabErrorBoundary>
      </div>,
    );
    expect(screen.getByText("sidebar stays")).toBeInTheDocument();
    const alert = screen.getByTestId("tab-error");
    expect(alert).toHaveTextContent("Mooring could not display the terminal");
    expect(alert).toHaveTextContent("Attempted to assign to readonly property.");
    fireEvent.click(screen.getByRole("button", { name: "Close tab" }));
    expect(onClose).toHaveBeenCalledOnce();
    spy.mockRestore();
  });

  it("renders its children when nothing fails", () => {
    render(
      <TabErrorBoundary what="the terminal">
        <p>terminal</p>
      </TabErrorBoundary>,
    );
    expect(screen.getByText("terminal")).toBeInTheDocument();
    expect(screen.queryByTestId("tab-error")).toBeNull();
  });
});
