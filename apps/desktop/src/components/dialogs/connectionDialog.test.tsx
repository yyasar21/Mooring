// L1: section nav, protocol radio cards, inline validation with a footer summary, Create and connect.
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { useSessions } from "../../stores/sessions";
import { useTree } from "../../stores/tree";
import { freshBackend, settle } from "../../test/harness";
import { ConnectionDialog } from "./ConnectionDialog";
import { connErrors, sectionsFor, summaryText } from "./connectionForm";

async function open(props: { id?: string; folderId?: string } = {}) {
  freshBackend();
  await act(async () => { await useTree.getState().load(); });
  const onClose = vi.fn();
  render(<ConnectionDialog folderId={props.folderId ?? "f-staging"} {...(props.id ? { id: props.id } : {})} onClose={onClose} />);
  await settle();
  return { dlg: screen.getByRole("dialog"), onClose };
}

const navItems = (dlg: HTMLElement) =>
  within(within(dlg).getByRole("navigation", { name: "Connection sections" })).getAllByRole("button").map((b) => b.textContent);

describe("connection form rules", () => {
  it("lists sections per protocol and the field errors in plain words", () => {
    expect(sectionsFor("ssh", false)).toEqual(["general", "signin", "gateway"]);
    expect(sectionsFor("rdp", false)).toEqual(["general", "signin", "gateway", "display"]);
    expect(sectionsFor("kubernetes", false)).toEqual(["general", "signin", "gateway", "advanced"]);
    expect(sectionsFor("vsphere-console", true)).not.toContain("advanced");
    expect(connErrors({ name: " ", host: "", port: "0", optionsValid: true, fitOk: true })).toEqual({
      name: "Enter a name for the connection.", host: "Enter a host name or IP address.", port: "Port must be 1 to 65535.",
    });
    expect(connErrors({ name: "a", host: "b", port: "", optionsValid: false, fitOk: true })).toEqual({ options: "Fix the highlighted options." });
    expect(summaryText(1)).toBe("Fix 1 field to continue");
    expect(summaryText(2)).toBe("Fix 2 fields to continue");
  });
});

describe("ConnectionDialog (L1)", () => {
  it("starts on Name, shows the section nav and protocol cards, and switches sections with the protocol", async () => {
    const { dlg } = await open();
    expect(within(dlg).getByLabelText("Name")).toHaveFocus();
    expect(navItems(dlg)).toEqual(["General", "Sign-in", "Gateway"]);
    const ssh = within(dlg).getByRole("radio", { name: "SSH" });
    expect(ssh).toBeChecked();
    fireEvent.click(within(dlg).getByRole("radio", { name: "RDP" }));
    expect(within(dlg).getByRole("radio", { name: "RDP" })).toBeChecked();
    expect(navItems(dlg)).toEqual(["General", "Sign-in", "Gateway", "Display"]);
    expect(within(dlg).getByLabelText("Port")).toHaveAttribute("placeholder", "3389");
    expect(within(dlg).getByRole("region", { name: "RDP options" })).toBeInTheDocument();
  });

  it("a nav click focuses the section heading and marks the item current", async () => {
    const { dlg } = await open();
    const nav = within(dlg).getByRole("navigation", { name: "Connection sections" });
    fireEvent.click(within(nav).getByRole("button", { name: "Sign-in" }));
    expect(within(dlg).getByRole("heading", { name: "Sign-in" })).toHaveFocus();
    expect(within(nav).getByRole("button", { name: "Sign-in" })).toHaveAttribute("aria-current", "true");
    expect(within(nav).getByRole("button", { name: "General" })).not.toHaveAttribute("aria-current");
  });

  it("shows a field error on blur, linked by aria-describedby, and a footer summary that goes to the first problem", async () => {
    const { dlg, onClose } = await open();
    const name = within(dlg).getByLabelText("Name");
    fireEvent.blur(name);
    expect(name).not.toHaveAttribute("aria-invalid"); // never typed in: waits for Create
    fireEvent.change(name, { target: { value: "x" } });
    fireEvent.change(name, { target: { value: "" } });
    fireEvent.blur(name);
    expect(name).toHaveAttribute("aria-invalid", "true");
    expect(name).toHaveAccessibleDescription("Enter a name for the connection.");
    expect(within(dlg).getByLabelText("Host")).not.toHaveAttribute("aria-invalid");

    fireEvent.click(within(dlg).getByRole("button", { name: "Create connection" }));
    await settle();
    expect(onClose).not.toHaveBeenCalled();
    const alert = within(dlg).getByRole("alert");
    expect(alert).toHaveTextContent("Fix 2 fields to continue");
    expect(name).toHaveFocus();
    expect(within(dlg).getByRole("button", { name: "General has errors" })).toBeInTheDocument();
    fireEvent.change(name, { target: { value: "lab" } });
    within(dlg).getByLabelText("Host").focus();
    fireEvent.click(within(alert).getByRole("button", { name: "Fix 1 field to continue" }));
    expect(within(dlg).getByLabelText("Host")).toHaveFocus();
    expect(within(dlg).getByLabelText("Host")).toHaveAccessibleDescription("Enter a host name or IP address.");
  });

  it("Create and connect saves the connection and opens its session", async () => {
    const { dlg, onClose } = await open();
    fireEvent.change(within(dlg).getByLabelText("Name"), { target: { value: "lab box" } });
    fireEvent.change(within(dlg).getByLabelText("Host"), { target: { value: "lab.example.test" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Create and connect" }));
    await settle();
    const created = useTree.getState().connections.find((c) => c.name === "lab box");
    expect(created?.folderId).toBe("f-staging");
    expect(onClose).toHaveBeenCalled();
    expect(useSessions.getState().tabs.map((t) => t.connectionId)).toContain(created?.id);
    for (const t of useSessions.getState().tabs) await act(async () => { await useSessions.getState().close(t.id); });
  });

  it("an edit has no Create and connect; a vCenter never offers it", async () => {
    let { dlg } = await open({ id: "c-web01", folderId: "f-web" });
    expect(within(dlg).queryByRole("button", { name: "Create and connect" })).toBeNull();
    expect(within(dlg).getByRole("button", { name: "Save connection" })).toBeEnabled();
    cleanup();
    ({ dlg } = await open());
    fireEvent.click(within(dlg).getByRole("radio", { name: "vSphere console" }));
    expect(within(dlg).queryByRole("button", { name: "Create and connect" })).toBeNull();
    expect(navItems(dlg)).toEqual(["General", "Sign-in", "Advanced"]);
  });
});
