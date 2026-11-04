import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { App } from "../../App";
import { IpcError } from "../../lib/ipc";
import { describeError } from "../../stores/errors";
import { useSessions } from "../../stores/sessions";
import { freshBackend, settle } from "../../test/harness";
import { connectedSsh } from "../../test/ssh";
import { ForwardsPanel } from "./ForwardsPanel";

async function panel() {
  const mock = freshBackend();
  const { sessionId } = await connectedSsh(mock);
  render(<ForwardsPanel sessionId={sessionId} />);
  await settle();
  return { mock, sessionId };
}

function fill(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

describe("ForwardsPanel", () => {
  it("opens a loopback local forward and lists it", async () => {
    const { mock, sessionId } = await panel();
    expect(screen.getByText(/No forwards yet/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "New forward" }));
    fill("Bind port", "15432");
    fill("Target host", "db.example.test");
    fill("Target port", "5432");
    fireEvent.click(screen.getByRole("button", { name: "Open forward" }));
    await settle();

    const table = screen.getByRole("table", { name: "Forwards on this session" });
    expect(within(table).getByText("127.0.0.1:15432")).toBeInTheDocument();
    expect(within(table).getByText("db.example.test:5432")).toBeInTheDocument();
    expect(within(table).getByText("Loopback")).toBeInTheDocument();
    expect(screen.queryByRole("form", { name: "New forward" })).toBeNull();
    expect(mock.forwards.get(sessionId)?.[0]).toMatchObject({ exposure: "loopback", kind: "local" });
  });

  it("shows field errors before calling the backend", async () => {
    const { mock, sessionId } = await panel();
    fireEvent.click(screen.getByRole("button", { name: "New forward" }));
    fill("Bind port", "99999");
    fireEvent.click(screen.getByRole("button", { name: "Open forward" }));
    await settle();
    expect(screen.getByText("Use 0 to 65535 (0 picks a free port).")).toBeInTheDocument();
    expect(screen.getByText("Enter a host name or IP address.")).toBeInTheDocument();
    expect(mock.forwards.get(sessionId) ?? []).toHaveLength(0);
  });

  it("asks before exposing a forward to the network", async () => {
    const { mock, sessionId } = await panel();
    fireEvent.click(screen.getByRole("button", { name: "New forward" }));
    fireEvent.click(screen.getByRole("radio", { name: "Dynamic" }));
    expect(screen.queryByLabelText("Target host")).toBeNull();
    fill("Bind port", "1080");
    fireEvent.click(screen.getByRole("switch"));
    expect(screen.getByLabelText("Bind host")).toHaveValue("0.0.0.0");

    fireEvent.click(screen.getByRole("button", { name: "Open external forward" }));
    let dialog = screen.getByRole("dialog", { name: "Expose this forward?" });
    expect(dialog).toHaveTextContent("0.0.0.0:1080");
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await settle();
    expect(mock.forwards.get(sessionId) ?? []).toHaveLength(0);

    fireEvent.click(screen.getByRole("button", { name: "Open external forward" }));
    dialog = screen.getByRole("dialog", { name: "Expose this forward?" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Expose to network" }));
    await settle();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByText("External")).toBeInTheDocument();
    expect(screen.getByText("SOCKS5")).toBeInTheDocument();
    expect(mock.audit.at(-1)).toMatchObject({ event: "session.forward.open", details: { exposure: "external" } });
  });

  it("refuses a non-loopback bind without external exposure", async () => {
    await panel();
    fireEvent.click(screen.getByRole("button", { name: "New forward" }));
    fill("Bind host", "192.0.2.10");
    fill("Target host", "db.example.test");
    fill("Target port", "5432");
    fireEvent.click(screen.getByRole("button", { name: "Open forward" }));
    expect(screen.getByText("A non-loopback bind address needs external exposure.")).toBeInTheDocument();
  });

  it("closes a forward and maps backend errors to plain text", async () => {
    const mock = freshBackend();
    const { sessionId } = await connectedSsh(mock);
    await mock.forwardOpen({ sessionId, kind: "local", bind: { host: "127.0.0.1", port: 8080 }, target: { host: "web.example.test", port: 80 }, exposure: "loopback" });
    render(<ForwardsPanel sessionId={sessionId} />);
    await settle();

    fireEvent.click(screen.getByRole("button", { name: "New forward" }));
    fill("Bind port", "8080");
    fill("Target host", "web.example.test");
    fill("Target port", "80");
    fireEvent.click(screen.getByRole("button", { name: "Open forward" }));
    await settle();
    expect(screen.getByRole("alert")).toHaveTextContent("The bind address is in use or not permitted.");
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));

    fireEvent.click(screen.getByRole("button", { name: "Close forward 127.0.0.1:8080" }));
    await settle();
    expect(mock.forwards.get(sessionId)).toEqual([]);
    expect(screen.getByText(/No forwards yet/)).toBeInTheDocument();
  });

  it("explains that forwards need a connected session", () => {
    freshBackend();
    render(<ForwardsPanel sessionId={null} />);
    expect(screen.getByText("Forwards are available once the session is connected.")).toBeInTheDocument();
  });
});

describe("SSH tab tools", () => {
  it("switches between the terminal and the forwards panel", async () => {
    const mock = freshBackend();
    mock.trustedHosts.add("web01.example.test");
    render(<App />);
    await screen.findByText("Nothing open yet");
    await act(async () => {
      await useSessions.getState().open("c-web01");
    });
    await settle();
    const bar = screen.getByRole("toolbar", { name: "Session tools" });
    expect(within(bar).getByRole("button", { name: "Terminal" })).toHaveAttribute("aria-pressed", "true");
    fireEvent.click(within(bar).getByRole("button", { name: "Forwards" }));
    expect(await screen.findByRole("region", { name: "Port forwards" })).toBeInTheDocument();
    fireEvent.click(within(bar).getByRole("button", { name: "Terminal" }));
    expect(screen.queryByRole("region", { name: "Port forwards" })).toBeNull();
  });
});

describe("describeError", () => {
  it("maps known codes and falls back to the scrubbed message", () => {
    expect(describeError(new IpcError("forward.limit", "x"))).toMatch(/64 forwards/);
    expect(describeError(new IpcError("input.invalid", "port out of range"))).toBe("port out of range");
    expect(describeError(new Error("boom"))).toBe("unexpected error");
  });
});
