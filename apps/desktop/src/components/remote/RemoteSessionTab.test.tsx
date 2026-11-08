import { act, fireEvent, render, screen } from "@testing-library/react";
import { freshBackend, settle } from "../../test/harness";
import type { MockTransport } from "../../lib/ipc.mock";
import { useSessions, type Tab } from "../../stores/sessions";
import { useTree } from "../../stores/tree";
import { CLOSE_TEXT } from "./ConnectionBanner";
import { formatFingerprint } from "./CertificateDetails";
import { RemoteSessionTab, securityBadge } from "./RemoteSessionTab";
import { Workspace } from "../Workspace";

function TabUnderTest({ connectionId }: { connectionId: string }) {
  const tab = useSessions((s) => s.tabs[0]);
  const c = useTree((s) => s.connections.find((x) => x.id === connectionId));
  return tab ? <RemoteSessionTab tab={tab} active connection={c} /> : null;
}

const tab = (): Tab | undefined => useSessions.getState().tabs[0];

describe("RemoteSessionTab", () => {
  let mock: MockTransport;
  beforeEach(async () => {
    mock = freshBackend();
    mock.frameIntervalMs = 60_000;
    await useTree.getState().load();
  });
  afterEach(async () => {
    for (const t of useSessions.getState().tabs) await useSessions.getState().close(t.id);
  });

  it("shows the certificate prompt with its details in the workspace, then the NLA badge", async () => {
    await act(async () => { await useSessions.getState().open("c-dc"); });
    render(<Workspace />);
    await settle();
    const dialog = screen.getByRole("alertdialog", { name: "Verify server certificate" });
    expect(dialog).toHaveTextContent("CN=dc01.example.test");
    expect(dialog).toHaveTextContent("Self-signed");
    fireEvent.click(screen.getByRole("button", { name: "Trust and remember" }));
    await vi.waitFor(() => { expect(tab()?.state).toBe("connected"); });
    await settle();
    expect(screen.queryByRole("alertdialog")).toBeNull();
    const tools = screen.getByRole("toolbar", { name: "Remote desktop tools" });
    expect(tools).toHaveTextContent("RDP");
    expect(tools).toHaveTextContent("NLA");
    expect(screen.getByRole("img", { name: "dc01 desktop" })).toBeInTheDocument();
  });

  it("VNC: unencrypted badge, view-only indicator and toggle, clipboard offer", async () => {
    await act(async () => { await useSessions.getState().open("c-kiosk"); });
    render(<TabUnderTest connectionId="c-kiosk" />);
    await settle();
    expect(screen.getByText("Unencrypted")).toBeInTheDocument();
    expect(screen.getByText("View only", { selector: ".chip" })).toBeInTheDocument();
    const send = screen.getByRole("button", { name: "Send clipboard" });
    expect(send).toBeDisabled(); // view-only: nothing goes to the remote
    fireEvent.click(screen.getByRole("button", { name: "View only", pressed: true }));
    await settle();
    expect(screen.getByText("Input on")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Send clipboard" }));
    await settle();
    expect(mock.remote.get(tab()?.sessionId ?? "")?.inputs).toContainEqual({ kind: "clipboard_offer" });
    expect(screen.getByRole("status", { name: "" })).toHaveTextContent("Clipboard text offered to the remote");
  });

  it("shows the reconnect countdown, then the connected view again", async () => {
    await act(async () => { await useSessions.getState().open("c-kiosk"); });
    render(<TabUnderTest connectionId="c-kiosk" />);
    await settle();
    mock.reconnectDelaysMs = [4000, 8000];
    act(() => { mock.dropLink(tab()?.sessionId ?? "", 1); });
    await settle(1);
    expect(screen.getByText(/^Link lost · reconnecting to /)).toBeInTheDocument();
    expect(screen.getByText(/Attempt 1 of 6/)).toBeInTheDocument();
    expect(screen.getByLabelText("Next attempt in 4 seconds")).toHaveTextContent("4 s");
    expect(screen.getByRole("list", { name: "Attempt 1 of 6" }).children).toHaveLength(6);
  });

  it("Cancel reconnect ends the retries and leaves a closed tab with Reconnect", async () => {
    await act(async () => { await useSessions.getState().open("c-kiosk"); });
    render(<TabUnderTest connectionId="c-kiosk" />);
    await settle();
    mock.reconnectDelaysMs = [60_000];
    act(() => { mock.dropLink(tab()?.sessionId ?? "", 1); });
    await settle(1);
    fireEvent.click(screen.getByRole("button", { name: "Cancel reconnect" }));
    await settle();
    expect(tab()).toMatchObject({ state: "closed", closeCode: "user" });
    expect(screen.getByText("Session closed")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reconnect" })).toBeEnabled();
  });

  it("names the close code and offers Reconnect", async () => {
    await act(async () => { await useSessions.getState().open("c-dc"); });
    render(<TabUnderTest connectionId="c-dc" />);
    await settle();
    act(() => {
      useSessions.setState({ tabs: [{ ...(tab() as Tab), prompt: null, state: "closed", closeCode: "trust_mismatch", reason: "CERTIFICATE CHANGED for dc01.example.test:3389" }] });
    });
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("Certificate changed");
    expect(alert).toHaveTextContent("CERTIFICATE CHANGED for dc01.example.test:3389");
    expect(screen.getByRole("button", { name: "Reconnect" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Screenshot" })).toBeDisabled();
  });

  it("copies a screenshot through Rust and shows its size", async () => {
    await act(async () => { await useSessions.getState().open("c-kiosk"); });
    render(<TabUnderTest connectionId="c-kiosk" />);
    await settle();
    fireEvent.click(screen.getByRole("button", { name: "Screenshot" }));
    await settle();
    expect(screen.getByText("Screenshot 1280×800 copied")).toBeInTheDocument();
  });

  it("maps security and close codes to English text", () => {
    expect(securityBadge("nla")).toEqual({ text: "NLA", hot: false });
    expect(securityBadge("tls")?.hot).toBe(true);
    expect(securityBadge("none")).toEqual({ text: "Unencrypted", hot: true });
    expect(securityBadge(null)).toBeNull();
    expect(Object.keys(CLOSE_TEXT).sort()).toEqual(["auth_failed", "gateway_auth", "gateway_refused", "gateway_unsupported", "hop_failed", "hop_lost", "network", "protocol_error", "server_ended", "trust_conflict", "trust_mismatch", "trust_rejected", "unknown", "user", "vault_locked"]);
    expect(CLOSE_TEXT.trust_conflict).toMatchObject({ title: "Conflicting certificates", hot: true });
    expect(CLOSE_TEXT.trust_conflict.hint).toMatch(/Settings → Trust/);
    expect(CLOSE_TEXT.hop_failed.hint).toMatch(/never contacted the target/);
    expect(formatFingerprint("ab01ff")).toBe("AB:01:FF");
  });
});
