import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { DEFAULT_RDP_OPTIONS, IpcError } from "../../../lib/ipc";
import type { MockTransport } from "../../../lib/ipc.mock";
import { useConnOptions } from "../../../stores/connOptions";
import { useCredentials } from "../../../stores/credentials";
import { useTree } from "../../../stores/tree";
import { freshBackend, settle } from "../../../test/harness";
import { ConnectionDialog } from "../ConnectionDialog";

const PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
const sw = (name: RegExp) => screen.getByRole("switch", { name });

describe("connection form · protocol options", () => {
  let mock: MockTransport;
  const onClose = vi.fn();
  beforeEach(async () => {
    mock = freshBackend();
    onClose.mockReset();
    await useTree.getState().load();
    await useCredentials.getState().load();
  });

  async function edit(id: string, folderId: string) {
    render(<ConnectionDialog id={id} folderId={folderId} onClose={onClose} />);
    await settle();
    return screen.getByRole("dialog");
  }

  it("RDP: loads with connection_options_get, edits and saves with connection_options_set", async () => {
    const getSpy = vi.spyOn(mock, "connectionOptionsGet");
    const setSpy = vi.spyOn(mock, "connectionOptionsSet");
    await edit("c-dc", "f-desk");
    expect(getSpy).toHaveBeenCalledWith({ connectionId: "c-dc" });
    const section = screen.getByRole("region", { name: "RDP options" });
    expect(within(section).getByText("Off in this release.")).toBeInTheDocument(); // audio, read-only
    fireEvent.change(within(section).getByLabelText("Keyboard layout"), { target: { value: String(0x041f) } });
    fireEvent.change(within(section).getByLabelText("Clipboard"), { target: { value: "to_remote" } });
    fireEvent.click(within(section).getByRole("radio", { name: "60 fps" }));
    expect(within(section).queryByRole("note")).toBeNull();
    fireEvent.click(sw(/^Allow TLS without NLA/));
    expect(within(section).getByRole("note")).toHaveTextContent(/before you are authenticated/);
    fireEvent.click(screen.getByRole("button", { name: "Save connection" }));
    await settle();
    expect(setSpy).toHaveBeenCalledWith({
      connectionId: "c-dc",
      options: { keyboardLayout: 0x041f, clipboard: "to_remote", allowTlsWithoutNla: true, caPem: null, maxFps: 60, gateway: null },
    });
    expect(useConnOptions.getState().byId["c-dc"]).toMatchObject({ allowTlsWithoutNla: true });
    expect(onClose).toHaveBeenCalled();
  });

  it("RDP: a bad CA PEM blocks saving with the Rust rule", async () => {
    await edit("c-dc", "f-desk");
    fireEvent.click(screen.getByRole("checkbox", { name: "Trust an extra certificate authority" }));
    const pem = screen.getByLabelText("CA certificates (PEM)");
    fireEvent.change(pem, { target: { value: "-----BEGIN RSA PRIVATE KEY-----" } });
    expect(screen.getByText("Paste certificates only, never a private key.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save connection" })).toBeDisabled();
    fireEvent.change(pem, { target: { value: PEM } });
    expect(screen.getByRole("button", { name: "Save connection" })).toBeEnabled();
  });

  it("VNC: plaintext warning, view-only default, encodings read-only", async () => {
    await edit("c-kiosk", "f-desk");
    const section = screen.getByRole("region", { name: "VNC options" });
    expect(sw(/^Start in view-only mode/)).toBeChecked();
    expect(within(section).getByRole("note")).toHaveTextContent(/falls back to an unencrypted session/);
    fireEvent.click(within(section).getByRole("radio", { name: "Allow plaintext" }));
    expect(within(section).getByRole("note")).toHaveTextContent(/Plaintext allowed/);
    fireEvent.click(within(section).getByRole("radio", { name: "Require TLS" }));
    expect(within(section).queryByRole("note")).toBeNull();
    expect(within(section).getByText(/CopyRect, ZRLE, Tight \(no JPEG\), Raw/)).toBeInTheDocument();
    fireEvent.click(sw(/^Start in view-only mode/));
    fireEvent.click(screen.getByRole("button", { name: "Save connection" }));
    await settle();
    expect(await mock.connectionOptionsGet({ connectionId: "c-kiosk" })).toMatchObject({ security: "require_tls", viewOnly: false, shared: true });
  });

  it("VNC: allowNoAuth is off, warns when on, survives a save and a reload (N-34)", async () => {
    await edit("c-kiosk", "f-desk");
    const section = screen.getByRole("region", { name: "VNC options" });
    const toggle = sw(/^Allow servers without authentication/);
    expect(toggle).not.toBeChecked();
    expect(within(section).queryByText(/no authentication is accepted/)).toBeNull();
    fireEvent.click(toggle);
    expect(within(section).getByText(/A server that offers no authentication is accepted although a password is set/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Save connection" }));
    await settle();
    expect(await mock.connectionOptionsGet({ connectionId: "c-kiosk" })).toMatchObject({ allowNoAuth: true, viewOnly: true });
    // a second edit/save keeps it (normalizeOptions no longer drops the field)
    cleanup();
    await edit("c-kiosk", "f-desk");
    expect(sw(/^Allow servers without authentication/)).toBeChecked();
    fireEvent.click(sw(/^Shared session/));
    fireEvent.click(screen.getByRole("button", { name: "Save connection" }));
    await settle();
    expect(await mock.connectionOptionsGet({ connectionId: "c-kiosk" })).toMatchObject({ allowNoAuth: true, shared: false });
  });

  it("Web: URL rules, origin allow-list editor and the persistent-storage note", async () => {
    await edit("c-lb", "f-web");
    const section = screen.getByRole("region", { name: "Web options" });
    const url = within(section).getByLabelText("Start URL");
    fireEvent.change(url, { target: { value: "http://lb.example.test" } });
    expect(within(section).getByText(/uses http:\/\//)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save connection" })).toBeDisabled();
    fireEvent.click(sw(/^Allow http:\/\//));
    expect(within(section).getByText(/can be read and changed by anyone/)).toBeInTheDocument();
    fireEvent.click(sw(/^Allow http:\/\//));
    fireEvent.change(url, { target: { value: "https://lb.example.test/login" } });

    const add = within(section).getByRole("button", { name: "Add origin" });
    const origin = within(section).getByLabelText("New origin");
    fireEvent.change(origin, { target: { value: "https://sso.example.test/path" } });
    fireEvent.click(add);
    expect(within(section).getByText(/Origins have no path/)).toBeInTheDocument();
    fireEvent.change(origin, { target: { value: "https://lb.example.test" } });
    fireEvent.click(add);
    expect(within(section).getByText("That origin is already allowed.")).toBeInTheDocument();
    fireEvent.change(origin, { target: { value: "https://sso.example.test" } });
    fireEvent.keyDown(origin, { key: "Enter" });
    fireEvent.change(origin, { target: { value: "https://idp.example.test:8443/" } });
    fireEvent.click(add);
    const list = within(section).getByRole("list", { name: "Allowed origins" });
    expect(within(list).getAllByRole("listitem")).toHaveLength(2);
    fireEvent.click(within(list).getByRole("button", { name: "Remove https://idp.example.test:8443" }));

    expect(within(section).queryByText(/unencrypted, outside the vault/)).toBeNull();
    fireEvent.click(sw(/^Keep me signed in/));
    expect(within(section).getByText(/unencrypted, outside the vault/)).toHaveTextContent(/recorded in the audit log/);
    fireEvent.click(screen.getByRole("button", { name: "Save connection" }));
    await settle();
    expect(await mock.connectionOptionsGet({ connectionId: "c-lb" })).toEqual({
      url: "https://lb.example.test/login", allowedOrigins: ["https://sso.example.test"], persistent: true, allowHttp: false,
    });
  });

  it("a new RDP connection gets its options after connection_create", async () => {
    render(<ConnectionDialog folderId="f-desk" onClose={onClose} />);
    await settle();
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "ts02" } });
    fireEvent.change(screen.getByLabelText("Host"), { target: { value: "ts02.example.test" } });
    fireEvent.change(screen.getByLabelText("Protocol"), { target: { value: "rdp" } });
    fireEvent.click(screen.getByRole("radio", { name: "60 fps" }));
    fireEvent.click(screen.getByRole("button", { name: "Create connection" }));
    await settle();
    const created = mock.connections.find((c) => c.name === "ts02");
    expect(created?.options).toEqual({ ...DEFAULT_RDP_OPTIONS, maxFps: 60 });
  });

  it("switching protocol starts from that protocol's defaults; SSH has no section", async () => {
    await edit("c-kiosk", "f-desk");
    fireEvent.change(screen.getByLabelText("Protocol"), { target: { value: "rdp" } });
    expect(screen.getByRole("region", { name: "RDP options" })).toBeInTheDocument();
    expect(screen.getByLabelText("Keyboard layout")).toHaveValue(String(0x0409));
    fireEvent.change(screen.getByLabelText("Protocol"), { target: { value: "ssh" } });
    expect(screen.queryByRole("region", { name: /options$/ })).toBeNull();
  });

  it("a failed options save keeps the dialog open and does not create a duplicate", async () => {
    vi.spyOn(mock, "connectionOptionsSet").mockRejectedValueOnce(new IpcError("vault.locked", "vault is locked"));
    render(<ConnectionDialog folderId="f-desk" onClose={onClose} />);
    await settle();
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "ts03" } });
    fireEvent.change(screen.getByLabelText("Host"), { target: { value: "ts03.example.test" } });
    fireEvent.change(screen.getByLabelText("Protocol"), { target: { value: "vnc" } });
    fireEvent.click(screen.getByRole("button", { name: "Create connection" }));
    await settle();
    expect(screen.getByText(/its VNC options were not: The vault is locked/)).toBeInTheDocument();
    expect(onClose).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Save connection" }));
    await settle();
    expect(mock.connections.filter((c) => c.name === "ts03")).toHaveLength(1);
    expect(onClose).toHaveBeenCalled();
  });

  it("stored options that fail to load are not overwritten blind", async () => {
    vi.spyOn(mock, "connectionOptionsGet").mockRejectedValueOnce(new IpcError("vault.locked", "vault is locked"));
    const setSpy = vi.spyOn(mock, "connectionOptionsSet");
    await edit("c-dc", "f-desk");
    expect(screen.getByText(/could not be loaded \(The vault is locked\.\)/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Save connection" }));
    await settle();
    expect(setSpy).not.toHaveBeenCalled();
  });
});
