import { act, fireEvent, render, screen } from "@testing-library/react";
import { App } from "./App";
import { useSessions } from "./stores/sessions";
import { freshBackend, settle } from "./test/harness";

describe("shell (browser mode, mock transport)", () => {
  beforeEach(() => {
    freshBackend();
  });

  it("boots into the unlocked shell and opens a connection from the palette", async () => {
    render(<App />);
    expect(await screen.findByText("Nothing open yet")).toBeInTheDocument();

    fireEvent.keyDown(window, { key: "k", metaKey: true });
    const input = await screen.findByLabelText("Search connections");
    fireEvent.change(input, { target: { value: "web01" } });
    await settle();
    fireEvent.keyDown(input, { key: "Enter" });
    await settle();

    expect(screen.getByRole("tab", { name: /web01/ })).toHaveAttribute("aria-selected", "true");
    // the inspector shows the host of the opened connection
    expect(screen.getByRole("complementary", { name: "Details" })).toHaveTextContent("web01.example.test");
  });

  it("lock clears the tabs", async () => {
    render(<App />);
    await screen.findByText("Nothing open yet");
    await act(async () => {
      await useSessions.getState().open("c-dc");
    });
    expect(screen.getByRole("tab", { name: /dc01/ })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Lock" }));
    expect(await screen.findByText("Unlock Mooring")).toBeInTheDocument();
    expect(useSessions.getState().tabs).toHaveLength(0);
  });
});
