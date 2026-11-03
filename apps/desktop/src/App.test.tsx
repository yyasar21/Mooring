import { act, render, screen, fireEvent } from "@testing-library/react";
import { App } from "./App";
import { useApp } from "./stores/app";

describe("shell (browser mode, no Tauri)", () => {
  beforeEach(() => {
    useApp.setState({ vault: "unknown", tabs: [], activeTab: null, selected: null, paletteOpen: false });
  });

  it("boots into the unlocked shell and opens a connection from the palette", async () => {
    render(<App />);
    expect(await screen.findByText("Nothing open yet")).toBeInTheDocument();

    fireEvent.keyDown(window, { key: "k", metaKey: true });
    const input = await screen.findByLabelText("Search connections");
    fireEvent.change(input, { target: { value: "xinfra" } });
    fireEvent.keyDown(input, { key: "Enter" });

    expect(screen.getByRole("tab", { name: /xinfra01/ })).toHaveAttribute("aria-selected", "true");
    // host shows in the session view and in the inspector
    expect(screen.getAllByText("10.10.20.5")).toHaveLength(2);
  });

  it("lock clears the tabs", async () => {
    render(<App />);
    await screen.findByText("Nothing open yet");
    act(() => {
      useApp.getState().openTab("c3");
    });
    expect(screen.getByRole("tab", { name: /xdc01/ })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Lock" }));
    expect(await screen.findByText("Unlock Nexus")).toBeInTheDocument();
  });
});
