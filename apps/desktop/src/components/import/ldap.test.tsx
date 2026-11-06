// The directory step of the import wizard (ADR-0019 §4, I2) against the mock: the form and its
// client-side checks, the credential picker limited to the kinds that can bind, "Test bind" and
// its result line, the preview path into the shared step 2/3, the error texts of ldap.* and the
// trust codes, Back keeping the form, and the pure form helpers.
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { freshBackend, settle } from "../../test/harness";
import { useCredentials } from "../../stores/credentials";
import { useTree } from "../../stores/tree";
import { ImportWizard } from "./ImportWizard";
import { checkBaseDn, checkFilter, checkSizeLimit, checkUrl, LDAP_FORM_DEFAULT, toPreviewArgs, toTestArgs, validateLdapForm } from "./ldapForm";

const dialog = () => screen.getByRole("dialog");
const click = (name: string | RegExp) => { fireEvent.click(within(dialog()).getByRole("button", { name })); };
const type = (label: string | RegExp, value: string) => { fireEvent.change(within(dialog()).getByLabelText(label), { target: { value } }); };

async function openDirectory() {
  const mock = freshBackend();
  await act(async () => { await Promise.all([useTree.getState().load(), useCredentials.getState().load()]); });
  const onClose = vi.fn();
  render(<ImportWizard format="ldaps" onClose={onClose} />);
  await settle();
  return { mock, onClose };
}

function fill() {
  type("Server", "ldaps://dc01.example.test");
  type("Base DN", "DC=example,DC=test");
  type("Bind credential", "cr-ad");
}

describe("ImportWizard · directory (LDAPS)", () => {
  it("opens on the Directory step with the defaults and only bindable credentials", async () => {
    await openDirectory();
    expect(dialog()).toHaveAccessibleName("Import from Directory (LDAPS)");
    expect(within(dialog()).getByRole("list", { name: "Import steps" }).textContent).toBe("1Directory2Preview3Apply");
    expect(within(dialog()).getByRole("listitem", { current: "step" })).toHaveTextContent("Directory");
    expect(within(dialog()).getByLabelText("Server")).toHaveValue("ldaps://");
    expect(within(dialog()).getByLabelText("Server")).toHaveFocus();
    expect(within(dialog()).getByRole("radio", { name: "Subtree" })).toBeChecked();
    expect(within(dialog()).getByRole("radio", { name: "Active Directory" })).toBeChecked();
    expect(within(dialog()).getByLabelText("Size limit")).toHaveValue("5000");
    const cred = within(dialog()).getByLabelText("Bind credential");
    const names = within(cred).getAllByRole("option").map((o) => o.textContent);
    expect(names).toEqual(["Choose…", "deploy bot · deploy (Username and password)", "domain admin · EXAMPLE\\admin (Domain account)", "legacy admin · EXAMPLE\\legacy (Username and password)"]);
    expect(names.join()).not.toMatch(/ops on-call|kiosk|vcenter|approle/); // ssh_key, vnc, vsphere, approle cannot bind
    expect(within(dialog()).getByText(/escaped, never interpreted/)).toBeInTheDocument();
    expect(within(dialog()).getByText(/Not tested yet/)).toBeInTheDocument();
    expect(within(dialog()).getByRole("button", { name: "Preview" })).toBeEnabled();
    expect(dialog().textContent).not.toMatch(/[çğışöüÇĞİŞÖÜ]/);
  });

  it("checks the form before contacting the directory, naming ldap:// as insecure", async () => {
    const { mock } = await openDirectory();
    click("Test bind");
    expect(within(dialog()).getByLabelText("Server")).toHaveAccessibleDescription(/Enter the server as ldaps:\/\/host/);
    expect(within(dialog()).getByLabelText("Base DN")).toHaveAccessibleDescription(/Enter where the search starts/);
    expect(within(dialog()).getByLabelText("Bind credential")).toHaveAccessibleDescription("Choose the credential Mooring binds with.");
    expect(within(dialog()).getByLabelText("Server")).toHaveAttribute("aria-invalid", "true");
    type("Server", "ldap://dc01.example.test");
    click("Test bind");
    expect(within(dialog()).getByLabelText("Server")).toHaveAccessibleDescription(/Only ldaps:\/\/ is supported/);
    type("Server", "ldaps://dc01.example.test");
    expect(within(dialog()).getByLabelText("Server")).not.toHaveAttribute("aria-invalid"); // the problem clears as you type
    type("Base DN", "example.test");
    type("Size limit", "9000");
    type("Bind credential", "cr-ad");
    click("Preview");
    await settle();
    expect(within(dialog()).getByLabelText("Base DN")).toHaveAccessibleDescription(/not a distinguished name/);
    expect(within(dialog()).getByLabelText("Size limit")).toHaveAccessibleDescription("The size limit must be between 1 and 5000.");
    expect(within(dialog()).getByRole("listitem", { current: "step" })).toHaveTextContent("Directory");
    expect(mock.audit.some((a) => a.event === "ldap_bind")).toBe(false);
  });

  it("Test bind shows host, port and bind name, and a changed credential clears it", async () => {
    const { mock } = await openDirectory();
    fill();
    click("Test bind");
    await settle();
    const status = within(dialog()).getByRole("status");
    expect(status).toHaveTextContent("dc01.example.test:636");
    expect(status).toHaveTextContent("Bound as EXAMPLE\\admin, then disconnected. Nothing was searched.");
    expect(mock.audit.at(-1)?.event).toBe("ldap_bind");
    expect(mock.importPlans.size).toBe(0);
    type("Bind credential", "cr-deploy");
    expect(within(dialog()).queryByRole("status")).toBeNull();
    expect(within(dialog()).getByText(/Not tested yet/)).toBeInTheDocument();
  });

  it("shows the friendly text for a refused bind, a rejected certificate and an unreachable server", async () => {
    const { mock } = await openDirectory();
    fill();
    type("Bind credential", "cr-legacy");
    click("Test bind");
    await settle();
    expect(within(dialog()).getByRole("alert")).toHaveTextContent("The directory refused the sign-in. Check the credential's user, domain and password");
    type("Bind credential", "cr-ad");
    expect(within(dialog()).queryByRole("alert")).toBeNull();
    mock.ldapPinned.clear();
    mock.ldapTrust.push("reject");
    click("Preview");
    await settle();
    expect(within(dialog()).getByRole("alert")).toHaveTextContent("You rejected the server's certificate, so Mooring did not connect. Nothing was stored.");
    expect(within(dialog()).getByRole("listitem", { current: "step" })).toHaveTextContent("Directory");
    mock.ldapFaults.push("ldap.unavailable");
    click("Test bind");
    await settle();
    expect(within(dialog()).getByRole("alert")).toHaveTextContent("The directory server did not answer. Check the host, the port (usually 636) and the network");
    expect(dialog().textContent).not.toMatch(/rc 49|rc 32/); // Rust's reasons never show; the friendly text does
  });

  it("F2 (L-43): explains the native sign-in confirmation and maps a declined or impossible one to text", async () => {
    const { mock } = await openDirectory();
    expect(within(dialog()).getByTestId("ldap-signin-note")).toHaveTextContent("The first sign-in to a server with this credential asks you to confirm in a Mooring dialog (“Sign in to host:port”) before the password is sent.");
    expect(within(dialog()).getByText(/the first bind asks for your confirmation/)).toBeInTheDocument();
    fill();
    mock.ldapSignIn.push("decline", "no_dialog");
    click("Test bind");
    await settle();
    expect(within(dialog()).getByRole("alert")).toHaveTextContent("You did not confirm the sign-in to the directory, so Mooring did not send the credential. Nothing was searched; try again and choose \"Sign in\" to continue.");
    expect(within(dialog()).getByText(/Not tested yet/)).toBeInTheDocument();
    expect(mock.audit.filter((a) => a.event === "ldap_bind")).toHaveLength(0);
    expect(mock.audit.at(-2)).toMatchObject({ event: "confirm_refused", details: { kind: "ldap_bind", reason: "declined" } });
    click("Preview");
    await settle();
    expect(within(dialog()).getByRole("alert")).toHaveTextContent("The sign-in to the directory needs a confirmation dialog, and none could be shown here. Run the import again from the main window.");
    expect(within(dialog()).getByRole("listitem", { current: "step" })).toHaveTextContent("Directory");
    // Confirmed once: test and preview both proceed without asking again.
    click("Test bind");
    await settle();
    expect(within(dialog()).getByRole("status")).toHaveTextContent(/Bound as/);
    mock.ldapSignIn.push("decline"); // would refuse, but the pair is remembered
    click("Preview");
    await settle();
    expect(within(dialog()).getByRole("listitem", { current: "step" })).toHaveTextContent("Preview");
    expect(mock.ldapSignIn).toEqual(["decline"]);
    expect(dialog().textContent).not.toMatch(/[çğışöüÇĞİŞÖÜ]/);
  });

  it("previews the directory into the shared preview step, applies, and Back keeps the form", async () => {
    const { mock } = await openDirectory();
    fill();
    type("Base DN", "OU=Servers,DC=example,DC=test");
    type(/^Name filter/, "web");
    click("Preview");
    await settle();
    expect(within(dialog()).getByRole("listitem", { current: "step" })).toHaveTextContent("Preview");
    expect(within(dialog()).getByRole("group", { name: "Preview counts" }).textContent).toBe("1folders2connections1credentials0secrets0skipped0warnings");
    const tree = within(dialog()).getByRole("region", { name: "Items to import" });
    expect(within(tree).getAllByRole("checkbox").map((c) => c.getAttribute("aria-label") ?? c.closest("label")?.textContent)).toHaveLength(3);
    expect(within(tree).getByText("Duplicate, skipped")).toBeInTheDocument(); // web01 is already in the vault
    expect(within(dialog()).getByText("Directory account (example.test)")).toBeInTheDocument();
    expect(within(dialog()).getByText("Ask at connect", { selector: ".imp-cred-kind" })).toBeInTheDocument();
    expect(within(dialog()).queryByRole("switch", { name: /plaintext|private keys/ })).toBeNull(); // no opt-ins for a directory
    expect(mock.importPlans.size).toBe(1);
    click("Back");
    await settle();
    expect(within(dialog()).getByRole("listitem", { current: "step" })).toHaveTextContent("Directory");
    expect(within(dialog()).getByLabelText("Base DN")).toHaveValue("OU=Servers,DC=example,DC=test");
    expect(within(dialog()).getByLabelText(/^Name filter/)).toHaveValue("web");
    expect(mock.importPlans.size).toBe(0); // Back discards the held plan
    type(/^Name filter/, "");
    click("Preview");
    await settle();
    expect(within(dialog()).getByRole("group", { name: "Preview counts" }).textContent).toBe("2folders5connections1credentials0secrets0skipped0warnings");
    click(/^Import 6 items/); // 2 folders + 5 connections, the duplicate skipped
    await settle();
    expect(within(dialog()).getByRole("group", { name: "Import report" }).textContent).toBe("2folders4connections1credentials0secrets1skipped");
    expect(useTree.getState().folders.some((f) => f.name.startsWith("Imported from LDAP directory"))).toBe(true);
    expect(mock.audit.at(-1)?.details.format).toBe("ldap");
  });

  it("explains a size-limit stop, a deep OU path and a stale account in plain words", async () => {
    await openDirectory();
    fill();
    type("Size limit", "5");
    click("Preview");
    await settle();
    expect(within(dialog()).getByRole("alert")).toHaveTextContent("The search matched more entries than the size limit allows, so nothing was imported.");
    type("Size limit", "5000");
    click("Preview");
    await settle();
    expect(within(dialog()).getByRole("region", { name: "Warnings" })).toHaveTextContent("An OU path deeper than eight levels was cut at eight");
    expect(within(dialog()).getByRole("region", { name: "Skipped" })).toHaveTextContent("a name, host or port that failed validation");
    expect(within(dialog()).getByRole("region", { name: "Skipped" })).toHaveTextContent("entry 8");
    expect(dialog().textContent).not.toMatch(/OU=|DC=/); // no DN of an entry is shown; folders carry the OU names only
  });

  it("switches to OpenLDAP and one level, and the source grid offers the directory", async () => {
    const { mock } = await openDirectory();
    fill();
    fireEvent.click(within(dialog()).getByRole("radio", { name: "OpenLDAP" }));
    expect(within(dialog()).getByText(/Reads ipHost and device objects/)).toBeInTheDocument();
    click("Preview");
    await settle();
    expect(within(dialog()).getByRole("group", { name: "Preview counts" }).textContent).toBe("1folders2connections1credentials0secrets0skipped0warnings");
    expect(within(dialog()).getByText("203.0.113.20")).toBeInTheDocument();
    click("Back");
    click("Back");
    expect(within(dialog()).getByRole("list", { name: "Import sources" })).toBeInTheDocument();
    click(/^Directory \(LDAPS\)/);
    expect(within(dialog()).getByLabelText("Server")).toHaveValue("ldaps://"); // a fresh form
    fill();
    type("Base DN", "OU=Servers,DC=example,DC=test");
    fireEvent.click(within(dialog()).getByRole("radio", { name: "One level" }));
    click("Preview");
    await settle();
    expect(within(dialog()).getByRole("group", { name: "Preview counts" }).textContent).toBe("0folders2connections1credentials0secrets0skipped0warnings");
    expect(mock.importPlans.size).toBe(1);
  });
});

describe("ldapForm", () => {
  it("checks the URL, the DN, the filter and the size limit like Rust", () => {
    expect(checkUrl("ldaps://dc01.example.test")).toBeUndefined();
    expect(checkUrl("ldaps://[2001:db8::1]:636/")).toBeUndefined();
    expect(checkUrl("ldaps://")).toMatch(/Enter the server/);
    expect(checkUrl("ldap://dc01.example.test")).toMatch(/Only ldaps/);
    expect(checkUrl("ldaps://a@dc01.example.test")).toMatch(/No user name, path or query/);
    expect(checkUrl("ldaps://dc01.example.test:70000")).toMatch(/between 1 and 65535/);
    expect(checkBaseDn("DC=example,DC=test")).toBeUndefined();
    expect(checkBaseDn("OU=Servers, DC=example, DC=test")).toBeUndefined();
    expect(checkBaseDn("")).toMatch(/Enter where/);
    expect(checkBaseDn("example.test")).toMatch(/not a distinguished name/);
    expect(checkBaseDn("x".repeat(1025))).toMatch(/longer than/);
    expect(checkFilter("web*")).toBeUndefined(); // escaped by Rust, allowed here
    expect(checkFilter("x".repeat(257))).toMatch(/longer than 256/);
    expect(checkFilter("a\u0007b")).toMatch(/control character/);
    expect(checkSizeLimit("1")).toBeUndefined();
    expect(checkSizeLimit("5000")).toBeUndefined();
    expect(checkSizeLimit("0")).toMatch(/between 1 and 5000/);
    expect(checkSizeLimit("5001")).toMatch(/between 1 and 5000/);
    expect(checkSizeLimit("12a")).toBe("Enter a whole number.");
    const errs = validateLdapForm({ ...LDAP_FORM_DEFAULT, caPem: "not pem" }, true);
    expect(Object.keys(errs).sort()).toEqual(["baseDn", "caPem", "credentialId", "url"]);
    expect(validateLdapForm({ ...LDAP_FORM_DEFAULT, url: "ldaps://h.example.test", baseDn: "DC=x", credentialId: "c", sizeLimit: "0" }, false)).toEqual({});
  });

  it("builds the command arguments without empty optionals", () => {
    const f = { ...LDAP_FORM_DEFAULT, url: " ldaps://h.example.test ", baseDn: " DC=x ", credentialId: "cr-ad", filter: "  ", sizeLimit: " 250 " };
    expect(toTestArgs(f)).toEqual({ url: "ldaps://h.example.test", baseDn: "DC=x", kind: "ad", credentialId: "cr-ad" });
    expect(toPreviewArgs(f)).toEqual({ url: "ldaps://h.example.test", baseDn: "DC=x", kind: "ad", credentialId: "cr-ad", scope: "sub", sizeLimit: 250 });
    expect(toPreviewArgs({ ...f, filter: " web ", caPem: "-----BEGIN CERTIFICATE-----", scope: "one", kind: "openldap" })).toMatchObject({ filter: "web", caPem: "-----BEGIN CERTIFICATE-----", scope: "one", kind: "openldap" });
    expect(toTestArgs({ ...f, caPem: "" })).not.toHaveProperty("caPem"); // the box is on but empty
  });
});
