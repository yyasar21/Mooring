// ADR-0025 §3 (R6): web windows through jump hosts. The chain opens before the window (up to
// 90 s), unattended: a hop that asks anything fails the open; macOS refuses web via in this build.
import { act, render, screen, waitFor, within } from "@testing-library/react";
import { freshBackend, settle } from "../../test/harness";
import type { MockTransport } from "../../lib/ipc.mock";
import { decodeWebEvent } from "../../lib/ipc.decode.session";
import { useApp } from "../../stores/app";
import { useSessions } from "../../stores/sessions";
import { useTree } from "../../stores/tree";
import { useWebTabs } from "../../stores/web";
import { Workspace } from "../Workspace";

const BASTION = "bastion.stage.example.test";
const tab = () => useSessions.getState().tabs[0];
const bar = () => screen.getByRole("toolbar", { name: "Web window controls" });
const events = (m: MockTransport, name: string) => m.audit.filter((e) => e.event === name);

describe("web window through jump hosts (R6)", () => {
  let mock: MockTransport;
  beforeEach(async () => {
    mock = freshBackend();
    useApp.setState({ vault: "unlocked" });
    await useTree.getState().load();
  });
  afterEach(async () => {
    for (const t of useSessions.getState().tabs) await useSessions.getState().close(t.id);
  });

  async function openWiki() {
    render(<Workspace />);
    await act(async () => { await useSessions.getState().open("c-wiki"); });
    await settle();
  }

  it("shows the opening state while the chain comes up, then the SOCKS chip and the audit rows", async () => {
    mock.trustedHosts.add(BASTION);
    mock.webViaDelayMs = 40;
    render(<Workspace />);
    let opening: Promise<string> | null = null;
    act(() => { opening = useSessions.getState().open("c-wiki"); });
    const status = await screen.findByText(/Opening through 1 jump host…/);
    expect(status.closest("[role=status]")).toHaveTextContent("This can take up to 90 seconds.");
    expect(tab()?.state).toBe("connecting");
    expect(screen.getByRole("button", { name: "Close tab" })).toBeInTheDocument();
    await act(async () => { await opening; });
    await settle();
    expect(tab()?.state).toBe("connected");
    expect(screen.queryByText(/Opening through/)).toBeNull();
    expect(within(bar()).getByText("via bastion01 (SOCKS)")).toBeInTheDocument();
    expect(useWebTabs.getState().byTab[tab()?.id ?? ""]?.viaHops).toBe(1);
    expect(events(mock, "session_hop_open")[0]?.details).toMatchObject({ connection: "c-wiki", hop: "0", protocol: "web" });
    expect(events(mock, "forward_opened").at(-1)?.details).toMatchObject({ id: "web-via", target: "socks5", reason: "web_via" });
    await act(async () => { await useSessions.getState().close(tab()?.id ?? ""); });
    expect(events(mock, "forward_closed").at(-1)?.details).toMatchObject({ id: "web-via", reason: "web_via" });
  });

  it("a hop that would ask (unknown key) fails the open with Rust's reason and the SSH-session hint", async () => {
    await openWiki();
    expect(tab()).toMatchObject({ state: "closed", openError: "session.hop_failed" });
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("A jump host could not be used");
    expect(alert).toHaveTextContent(/Open the jump host once as an SSH session to trust its key/);
    expect(screen.getByText(/jump host 1 asked a question a web window cannot answer/)).toBeInTheDocument();
    expect(mock.trustedHosts.has(BASTION)).toBe(false); // nothing is trusted for the user
    expect(mock.web.size).toBe(0);
    // after trusting the bastion in an SSH session, Reopen works
    mock.trustedHosts.add(BASTION);
    act(() => { screen.getByRole("button", { name: "Reopen window" }).click(); });
    await settle();
    expect(tab()).toMatchObject({ state: "connected", openError: null });
  });

  it("macOS refuses with a readable title and the dynamic-forward next step", async () => {
    mock.trustedHosts.add(BASTION);
    mock.webViaSupported = false;
    await openWiki();
    expect(tab()?.openError).toBe("web.via_unsupported");
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("Jump hosts are not available for web windows on macOS");
    expect(alert).toHaveTextContent("dynamic forward (SOCKS)");
    expect(screen.getByText(/cannot open through jump hosts on macOS in this build/)).toBeInTheDocument();
  });

  it("a tab closed while the chain opens closes the window as soon as it exists", async () => {
    mock.trustedHosts.add(BASTION);
    mock.webViaDelayMs = 30;
    render(<Workspace />);
    let opening: Promise<string> | null = null;
    act(() => { opening = useSessions.getState().open("c-wiki"); });
    await screen.findByText(/Opening through 1 jump host…/);
    await act(async () => { await useSessions.getState().close(tab()?.id ?? ""); });
    await act(async () => { await opening; });
    await waitFor(() => { expect(mock.web.size).toBe(0); });
    expect(events(mock, "web_closed")).toHaveLength(1);
  });

  it("a direct web window shows no chip and no opening state", async () => {
    render(<Workspace />);
    await act(async () => { await useSessions.getState().open("c-lb"); });
    await settle();
    expect(within(bar()).queryByText(/SOCKS/)).toBeNull();
    expect(useWebTabs.getState().byTab[tab()?.id ?? ""]?.viaHops).toBeNull();
  });
});

describe("decodeWebEvent", () => {
  it("ignores an unknown kind instead of reading it as closed", () => {
    expect(decodeWebEvent({ kind: "prompt", id: 1 })).toBeNull();
    expect(decodeWebEvent("garbage")).toBeNull();
    expect(decodeWebEvent({ kind: "closed" })).toEqual({ kind: "closed" });
    expect(decodeWebEvent({ kind: "title", title: "T" })).toEqual({ kind: "title", title: "T" });
  });

});
