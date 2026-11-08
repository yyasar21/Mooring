import { fireEvent, render, screen, within } from "@testing-library/react";
import { DEFAULT_KUBE_OPTIONS, DEFAULT_VSPHERE_OPTIONS } from "../../../lib/ipc";
import type { MockTransport } from "../../../lib/ipc.mock";
import { T0 } from "../../../lib/ipc.seed";
import { useCredentials } from "../../../stores/credentials";
import { useTree } from "../../../stores/tree";
import { freshBackend, settle } from "../../../test/harness";
import { ConnectionDialog } from "../ConnectionDialog";

const PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

describe("connection form · Kubernetes and vCenter options", () => {
  let mock: MockTransport;
  const onClose = vi.fn();
  beforeEach(async () => {
    mock = freshBackend();
    mock.creds.items.push({ id: "cr-tok", name: "ci token", kind: "kube_token", fields: {}, secretNames: ["token"], fingerprint: null, createdAt: T0, updatedAt: T0 });
    onClose.mockReset();
    await useTree.getState().load();
    await useCredentials.getState().load();
  });

  it("kubeconfig: context from the credential, no server/CA, allow-listed shell; saves every field", async () => {
    const setSpy = vi.spyOn(mock, "connectionOptionsSet");
    render(<ConnectionDialog id="c-k8s" folderId="f-staging" onClose={onClose} />);
    await settle();
    const section = screen.getByRole("region", { name: "Kubernetes options" });
    expect(within(section).queryByLabelText("API server")).toBeNull();
    expect(within(section).getByText(/never creates, changes or deletes/)).toBeInTheDocument();
    const ctx = within(section).getByLabelText("Context");
    expect(within(ctx).getAllByRole("option").map((o) => o.textContent)).toEqual(["The kubeconfig's current context", "stage-admin", "stage-readonly"]);
    fireEvent.change(ctx, { target: { value: "stage-readonly" } });
    expect(within(within(section).getByLabelText("Exec shell")).getAllByRole("option").map((o) => o.textContent)).toEqual(["/bin/sh", "/bin/bash", "/bin/ash", "sh", "bash"]);
    fireEvent.change(within(section).getByLabelText("Exec shell"), { target: { value: "bash" } });
    fireEvent.change(within(section).getByLabelText(/Namespaces to offer/), { target: { value: "payments, monitoring" } });
    fireEvent.change(within(section).getByLabelText("Max log bytes"), { target: { value: String(16 * 1024 * 1024) } });
    fireEvent.click(within(section).getByRole("switch", { name: /Allow pod port-forward/ }));
    fireEvent.click(screen.getByRole("button", { name: "Save connection" }));
    await settle();
    expect(setSpy).toHaveBeenCalledWith({
      connectionId: "c-k8s",
      options: { ...DEFAULT_KUBE_OPTIONS, context: "stage-readonly", execCommand: "bash", allowedNamespaces: ["payments", "monitoring"], maxLogBytes: 16 * 1024 * 1024, portForward: false },
    });
    expect(onClose).toHaveBeenCalled();
  });

  it("kube_token: server and CA are required before saving; ranges are checked", async () => {
    render(<ConnectionDialog id="c-k8s" folderId="f-staging" onClose={onClose} />);
    await settle();
    fireEvent.click(screen.getByRole("button", { name: /^Credential/ }));
    const list = screen.getByRole("listbox", { name: "Credential" });
    const tok = within(list).getAllByRole("option").find((o) => o.textContent.includes("ci token"));
    if (!tok) throw new Error("no token option");
    fireEvent.click(tok);
    const section = screen.getByRole("region", { name: "Kubernetes options" });
    expect(within(section).queryByLabelText("Context")).toBeNull();
    expect(within(section).getByText("A token credential needs the API server URL.")).toBeInTheDocument();
    const save = screen.getByRole("button", { name: "Save connection" });
    fireEvent.click(save); // L1: blocked, with the footer summary
    expect(document.querySelector(".conn-footer-msg")).toHaveTextContent(/^Fix \d+ fields? to continue$/);
    fireEvent.change(within(section).getByLabelText("API server"), { target: { value: "http://k8s.example.test" } });
    expect(within(section).getByText("The API server must use https://.")).toBeInTheDocument();
    fireEvent.change(within(section).getByLabelText("API server"), { target: { value: "https://k8s.example.test:6443" } });
    fireEvent.change(within(section).getByLabelText("Cluster CA (PEM)"), { target: { value: PEM } });
    fireEvent.change(within(section).getByLabelText("Log tail lines"), { target: { value: "20000" } });
    expect(within(section).getByText("Use 1 to 10 000 lines.")).toBeInTheDocument();
    fireEvent.click(save); // L1: blocked, with the footer summary
    expect(document.querySelector(".conn-footer-msg")).toHaveTextContent(/^Fix \d+ fields? to continue$/);
    fireEvent.change(within(section).getByLabelText("Log tail lines"), { target: { value: "2000" } });
    expect(document.querySelector(".conn-footer-msg")).toHaveTextContent(/^$/);
  });

  it("vCenter: refresh range, power actions opt-in with the warning, VMRC opt-in", async () => {
    const setSpy = vi.spyOn(mock, "connectionOptionsSet");
    render(<ConnectionDialog id="c-vc" folderId="f-staging" onClose={onClose} />);
    await settle();
    const section = screen.getByRole("region", { name: "vCenter options" });
    expect(within(section).getByText(/Not imported yet/)).toBeInTheDocument();
    fireEvent.change(within(section).getByLabelText("Refresh every (minutes)"), { target: { value: "5" } });
    expect(within(section).getByText("Use 15 to 1440 minutes, or manual.")).toBeInTheDocument();
    fireEvent.change(within(section).getByLabelText("Refresh every (minutes)"), { target: { value: "30" } });
    expect(within(section).queryByRole("note")).toBeNull();
    fireEvent.click(within(section).getByRole("switch", { name: /Allow power actions/ }));
    expect(within(section).getByRole("note")).toHaveTextContent(/may lose data/);
    expect(within(section).getByRole("note")).toHaveTextContent("three buttons (Cancel, the action, Not now)"); // 6b B-6
    fireEvent.click(within(section).getByRole("switch", { name: /VMware Remote Console/ }));
    fireEvent.click(screen.getByRole("button", { name: "Save connection" }));
    await settle();
    expect(setSpy).toHaveBeenCalledWith({ connectionId: "c-vc", options: { ...DEFAULT_VSPHERE_OPTIONS, refreshMinutes: 30, allowPowerActions: true, allowVmrc: true } });
  });
});
