import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { freshBackend, settle } from "../../test/harness";
import type { MockTransport } from "../../lib/ipc.mock";
import { setIpc } from "../../lib/ipc";
import { useSessions, type Tab } from "../../stores/sessions";
import { useTree } from "../../stores/tree";
import { useUi } from "../../stores/ui";
import { Workspace } from "../Workspace";
import { DialogHost } from "../dialogs/DialogHost";
import { KnownCertsCard } from "../settings/KnownCertsCard";
import { BASIC_WARNING } from "../dialogs/options/RdpGatewaySection";

const tab = (): Tab | undefined => useSessions.getState().tabs[0];
const tools = () => screen.getByRole("toolbar", { name: "Remote desktop tools" });

describe("RD Gateway (ADR-0027)", () => {
  let mock: MockTransport;
  beforeEach(async () => {
    mock = freshBackend();
    mock.frameIntervalMs = 60_000;
    await useTree.getState().load();
  });
  afterEach(async () => {
    for (const t of useSessions.getState().tabs) await useSessions.getState().close(t.id);
  });

  it("asks for the gateway certificate first (with Trust once), then the server's, then shows the chip and NLA", async () => {
    await act(async () => { await useSessions.getState().open("c-rdg"); });
    render(<Workspace />);
    await settle();
    expect(tab()?.gateway).toMatchObject({ host: "gw01.example.test:443", state: "connecting" });
    const gwDialog = screen.getByRole("alertdialog", { name: "RD Gateway certificate" });
    expect(gwDialog).toHaveTextContent("gw01.example.test:443");
    expect(gwDialog).toHaveTextContent("CN=gw01.example.test");
    expect(gwDialog).toHaveTextContent("Trust once uses it for this connection only");
    fireEvent.click(within(gwDialog).getByRole("button", { name: "Trust once" }));
    await settle();
    expect(mock.audit.some((e) => e.event === "trust_decision" && e.details.protocol === "rdg" && e.details.decision === "trusted_once")).toBe(true);
    // Trusted once: nothing pinned for the gateway.
    expect(mock.knownCerts.has("rdg|gw01.example.test:443")).toBe(false);
    const server = await screen.findByRole("alertdialog", { name: "Verify server certificate" });
    expect(tab()?.gateway?.state).toBe("up");
    expect(within(server).queryByRole("button", { name: "Trust once" })).toBeNull();
    fireEvent.click(within(server).getByRole("button", { name: "Trust and remember" }));
    await vi.waitFor(() => { expect(tab()?.state).toBe("connected"); });
    await settle();
    expect(tab()?.security).toBe("nla+rdg");
    expect(tools()).toHaveTextContent("NLA");
    expect(within(tools()).getByText("via RD Gateway gw01.example.test")).toBeInTheDocument();
    expect(mock.audit.some((e) => e.event === "session.rdp.gateway" && e.details.outcome === "ok")).toBe(true);
  });

  it("Trust and remember pins the gateway; Settings → Trust lists it hashed under RD Gateway", async () => {
    await act(async () => { await useSessions.getState().open("c-rdg"); });
    render(<Workspace />);
    await settle();
    fireEvent.click(within(screen.getByRole("alertdialog", { name: "RD Gateway certificate" })).getByRole("button", { name: "Trust and remember" }));
    await settle();
    expect(mock.knownCerts.has("rdg|gw01.example.test:443")).toBe(true);
    render(<KnownCertsCard />);
    const card = screen.getByRole("region", { name: "Known certificates" });
    fireEvent.click(within(card).getByRole("radio", { name: "RD Gateway" }));
    const list = await within(card).findByRole("list", { name: "RD Gateway certificates" });
    expect(list).toHaveTextContent("RD Gateway (host stored hashed)");
    fireEvent.click(within(list).getByRole("button", { name: "Remove…" }));
    const dlg = screen.getByRole("dialog", { name: "Remove stored certificate" });
    expect(within(dlg).getByLabelText("Port")).toHaveValue("443");
    fireEvent.change(within(dlg).getByLabelText("Host"), { target: { value: "gw01.example.test" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Remove certificate" }));
    await settle();
    expect(mock.knownCerts.has("rdg|gw01.example.test:443")).toBe(false);
  });

  it.each([
    ["auth", "gateway_auth", "The RD Gateway refused the credentials"],
    ["refused", "gateway_refused", "The RD Gateway refused the connection"],
    ["unsupported", "gateway_unsupported", "RD Gateway not supported"],
  ] as const)("a gateway that answers %s closes with %s and a readable title", async (outcome, code, title) => {
    mock.rdg.outcome = outcome;
    await mock.pinAt("rdg|gw01.example.test:443", "gw01.example.test", 443);
    await act(async () => { await useSessions.getState().open("c-rdg"); });
    render(<Workspace />);
    await vi.waitFor(() => { expect(tab()?.state).toBe("closed"); });
    expect(tab()?.closeCode).toBe(code);
    expect(tab()?.gateway?.state).toBe("failed");
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent(title);
    if (outcome === "refused") expect(alert).toHaveTextContent("0x800759DD");
    // The target was never asked about.
    expect(screen.queryByRole("alertdialog")).toBeNull();
  });

  it("a changed gateway pin is a hard stop titled for the gateway", async () => {
    mock.rdg.outcome = "mismatch";
    await act(async () => { await useSessions.getState().open("c-rdg"); });
    render(<Workspace />);
    await vi.waitFor(() => { expect(tab()?.state).toBe("closed"); });
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("RD Gateway certificate changed");
    expect(alert).toHaveTextContent("Settings → Trust → RD Gateway");
  });

  it("Basic only works with allowBasicGateway, and is audited", async () => {
    mock.rdg.outcome = "basic";
    await mock.pinAt("rdg|gw01.example.test:443", "gw01.example.test", 443);
    await act(async () => { await useSessions.getState().open("c-rdg"); });
    render(<Workspace />);
    await vi.waitFor(() => { expect(tab()?.closeCode).toBe("gateway_auth"); });
    expect(tab()?.reason).toMatch(/allowBasicGateway/);
    expect(mock.audit.some((e) => e.event === "session.rdp.gateway_basic")).toBe(false);
  });
});

describe("RD Gateway section of the RDP form", () => {
  it("turns the gateway on, shows the Basic warning, and saves options.gateway", async () => {
    const mock = freshBackend();
    setIpc(mock);
    await useTree.getState().load();
    const setSpy = vi.spyOn(mock, "connectionOptionsSet");
    render(<DialogHost />);
    act(() => { useUi.getState().openDialog({ kind: "connection", id: "c-dc", folderId: "f-desk" }); });
    const dlg = screen.getByRole("dialog", { name: "Edit connection" });
    // The existing gateway role picker stays, with Same as sign-in as its empty choice.
    expect(within(dlg).getByRole("button", { name: /^RD Gateway credential/ })).toBeInTheDocument();
    const section = await within(dlg).findByRole("group", { name: "RD Gateway" });
    expect(within(section).queryByLabelText("Gateway host")).toBeNull();
    fireEvent.click(within(section).getByRole("switch", { name: /^Connect through an RD Gateway/ }));
    const host = within(section).getByLabelText("Gateway host");
    fireEvent.click(within(dlg).getByRole("button", { name: "Save connection" })); // L1: blocked, with the footer summary
    expect(within(dlg).getByText(/^Fix \d+ fields? to continue$/)).toBeInTheDocument();
    expect(section).toHaveTextContent("Enter the RD Gateway's host name or IP address.");
    fireEvent.change(host, { target: { value: "https://gw" } });
    expect(section).toHaveTextContent("without https://");
    fireEvent.change(host, { target: { value: "gw02.example.test" } });
    expect(within(section).getByLabelText("Port")).toHaveValue("443");
    expect(section).not.toHaveTextContent(BASIC_WARNING);
    fireEvent.click(within(section).getByRole("switch", { name: /^Allow Basic authentication/ }));
    expect(within(section).getByRole("note")).toHaveTextContent(BASIC_WARNING);
    fireEvent.click(within(section).getByRole("radio", { name: "Only when the computer is unreachable" }));
    fireEvent.click(within(dlg).getByRole("button", { name: "Save connection" }));
    await settle();
    expect(setSpy).toHaveBeenCalledWith({
      connectionId: "c-dc",
      options: expect.objectContaining({
        gateway: { host: "gw02.example.test", port: 443, usage: "if_unreachable", allowBasicGateway: true, caPem: null },
      }) as unknown,
    });
  });
});
