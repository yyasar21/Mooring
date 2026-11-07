import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { App } from "../../App";
import { KIND_SCHEMAS } from "../../lib/ipc.kinds";
import { useCredentials } from "../../stores/credentials";
import { useTree } from "../../stores/tree";
import { useUi } from "../../stores/ui";
import { freshBackend, settle } from "../../test/harness";
import { CredentialEditor } from "./CredentialEditor";

// Fixture values only; none of these is a real secret.
const FIXTURE = "fixture-pw-7f3a";
const KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nZml4dHVyZS1rZXktbm90LXJlYWw=\n-----END OPENSSH PRIVATE KEY-----\n";
const BUNDLE =
  "-----BEGIN CERTIFICATE-----\nMIIBfixture\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nZml4dHVyZS1rZXk=\n-----END PRIVATE KEY-----\n";
const KUBE =
  "apiVersion: v1\nkind: Config\nclusters:\n- name: c\n  cluster: {server: 'https://k.example.test'}\ncontexts:\n- name: blue\n  context: {cluster: c, user: u}\n- name: green\n  context: {cluster: c, user: u}\nusers:\n- name: u\n  user: {token: fixture-token-1}\n";

/** Does any hook state of a component above or inside `root` hold `needle`? (React fiber walk.) */
function hookStateContains(root: Element, needle: string): boolean {
  const seen = new Set<unknown>();
  const has = (v: unknown, depth: number): boolean => {
    if (typeof v === "string") return v.includes(needle);
    if (!v || typeof v !== "object" || depth > 6 || seen.has(v) || v instanceof Node) return false;
    seen.add(v);
    return Object.values(v as Record<string, unknown>).some((x) => has(x, depth + 1));
  };
  const key = Object.keys(root).find((k) => k.startsWith("__reactFiber$"));
  type Fiber = { memoizedState: unknown; return: Fiber | null; tag: number };
  let fiber = key ? ((root as unknown as Record<string, Fiber>)[key] ?? null) : null;
  for (; fiber; fiber = fiber.return) {
    // function components keep hooks as a linked list of { memoizedState, next }
    let hook = fiber.tag === 0 ? (fiber.memoizedState as { memoizedState: unknown; next: unknown } | null) : null;
    while (hook) {
      if (has(hook.memoizedState, 0)) return true;
      hook = hook.next as typeof hook;
    }
  }
  return false;
}

async function boot() {
  render(<App />);
  await screen.findByText("Nothing open yet");
  await settle();
}

function openNew() {
  act(() => { useUi.getState().showCredentials({ mode: "new" }); });
  return screen.getByRole("region", { name: "Credentials" });
}

describe("schema-driven credential form", () => {
  beforeEach(() => { freshBackend(); });

  it.each(KIND_SCHEMAS.map((k) => [k.kind, k] as const))("renders %s from its schema", (_kind, schema) => {
    const { unmount } = render(
      <CredentialEditor schema={schema} kinds={KIND_SCHEMAS} onDone={vi.fn()} onCancel={vi.fn()} onSwitchKind={vi.fn()} />,
    );
    const form = screen.getByRole("form", { name: `New ${schema.label}` });
    for (const f of schema.fields) {
      // account siblings (domain/form) fold into the account field
      if (schema.fields.some((x) => x.validation.format === "netbios_or_upn") && (f.name === "domain" || f.name === "form")) continue;
      // ADR-0026: engine parameters show once their Vault engine is chosen (refEngines.test.tsx).
      if (schema.kind === "external_ref" && ["ttl", "common_name", "username"].includes(f.name)) continue;
      const found = within(form).queryAllByText(new RegExp(`^${f.label}`)).length + within(form).queryAllByRole("radiogroup", { name: f.label }).length;
      expect([schema.kind, f.name, found > 0]).toEqual([schema.kind, f.name, true]);
    }
    for (const el of form.querySelectorAll("[data-secret]")) {
      const input = el as HTMLInputElement;
      expect(input.tagName === "TEXTAREA" || input.type === "password").toBe(true);
      expect(input.autocomplete).toBe("new-password");
    }
    expect(within(form).queryByText("Second factor (TOTP)") !== null).toBe(schema.supportsOtp);
    unmount();
  });

  it("shows the domain_user split live and stores user/domain/form", async () => {
    await boot();
    const view = openNew();
    fireEvent.click(within(view).getByRole("button", { name: "Domain account" }));
    const form = within(view).getByRole("form");
    const account = within(form).getByLabelText("Account");
    fireEvent.change(account, { target: { value: "CORP\\alice" } });
    const split = within(form).getByRole("status");
    expect(split).toHaveTextContent("Useralice");
    expect(split).toHaveTextContent("DomainCORP");
    expect(split).toHaveTextContent("FormNetBIOS");
    fireEvent.change(account, { target: { value: "alice@corp.example" } });
    expect(split).toHaveTextContent("Domaincorp.example");
    expect(split).toHaveTextContent("FormUPN");
    fireEvent.change(within(form).getByLabelText("Name"), { target: { value: "corp alice" } });
    fireEvent.change(within(form).getByLabelText(/^Password/), { target: { value: FIXTURE } });
    fireEvent.click(within(form).getByRole("button", { name: "Create credential" }));
    await settle();
    const saved = useCredentials.getState().items.find((c) => c.name === "corp alice");
    expect(saved?.fields).toEqual({ user: "alice", domain: "corp.example", form: "upn" });
  });

  it("never echoes secret values into the DOM or the stores after submit", async () => {
    await boot();
    const view = openNew();
    fireEvent.click(within(view).getByRole("button", { name: "Username and password" }));
    const form = within(view).getByRole("form");
    fireEvent.change(within(form).getByLabelText("Name"), { target: { value: "otp user" } });
    fireEvent.change(within(form).getByLabelText("Username"), { target: { value: "u1" } });
    fireEvent.change(within(form).getByLabelText(/^Password/), { target: { value: FIXTURE } });
    fireEvent.click(within(form).getByRole("checkbox"));
    expect(within(form).getByRole("note")).toHaveTextContent(/two factors into one/);
    fireEvent.change(within(form).getByLabelText(/^TOTP seed/), { target: { value: "JBSWY3DPEHPK3PXPJBSWY3DP" } });
    fireEvent.click(within(form).getByRole("button", { name: "Create credential" }));
    await settle();
    const saved = useCredentials.getState().items.find((c) => c.name === "otp user");
    expect(saved?.secretNames).toEqual(["otp_seed", "password"]);
    const html = document.body.innerHTML;
    expect(html).not.toContain(FIXTURE);
    expect(html).not.toContain("JBSWY3DPEHPK3PXPJBSWY3DP");
    for (const el of document.querySelectorAll<HTMLInputElement>("input, textarea")) {
      expect(el.value).not.toContain(FIXTURE);
    }
    const state = JSON.stringify([useCredentials.getState(), useUi.getState(), useTree.getState()]);
    expect(state).not.toContain(FIXTURE);
    // U0: the save lands on the detail card; Edit opens the form, where stored secrets show presence only
    const detail = within(view).getByRole("article", { name: "otp user details" });
    expect(detail).toHaveTextContent(/TOTP seed, Password.* \(sealed\)/);
    fireEvent.click(within(detail).getByRole("button", { name: "Edit" }));
    const editor = within(view).getByRole("form", { name: "Edit otp user" });
    expect(within(editor).getAllByText("Stored").length).toBeGreaterThan(0);
    fireEvent.click(within(editor).getByRole("button", { name: "Replace password" }));
    expect(within(editor).getByPlaceholderText("New password")).toHaveValue("");
    expect(within(editor).queryByRole("button", { name: "Clear password" })).toBeNull(); // required
  });

  it("detects a pasted OpenSSH key and switches the form to SSH key", async () => {
    await boot();
    const view = openNew();
    const zone = within(view).getByLabelText("Paste a key, certificate or kubeconfig");
    fireEvent.paste(zone, { clipboardData: { getData: () => KEY } });
    const form = within(view).getByRole("form", { name: "New SSH key" });
    expect(form).toBeInTheDocument();
    await settle();
    expect(form.querySelector<HTMLTextAreaElement>("textarea[data-secret]")?.value).toBe(KEY);
    expect(zone).not.toBeInTheDocument();
    expect(JSON.stringify(useUi.getState())).not.toContain("OPENSSH");
  });

  it("splits a pasted certificate + key bundle: key into the secret input, never a plain field (B-3)", async () => {
    await boot();
    const view = openNew();
    const zone = within(view).getByLabelText("Paste a key, certificate or kubeconfig");
    fireEvent.paste(zone, { clipboardData: { getData: () => BUNDLE } });
    const form = within(view).getByRole("form", { name: "New X.509 client certificate" });
    await settle();
    const cert = within(form).getByLabelText(/^Certificate/);
    expect((cert as HTMLTextAreaElement).value).toContain("BEGIN CERTIFICATE");
    const secret = form.querySelector<HTMLTextAreaElement>("textarea[data-secret]");
    expect(secret?.value).toContain("PRIVATE KEY-----");
    for (const el of form.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>("input:not([data-secret]), textarea:not([data-secret])")) {
      expect(el.value).not.toContain("PRIVATE KEY");
      expect(el.value).not.toContain("Zml4dHVyZS1rZXk");
    }
    // pasting the bundle straight into the certificate field is split the same way
    fireEvent.change(cert, { target: { value: "" } });
    if (secret) secret.value = "";
    fireEvent.paste(cert, { clipboardData: { getData: () => BUNDLE } });
    await settle();
    expect((cert as HTMLTextAreaElement).value).not.toContain("PRIVATE KEY");
    expect(secret?.value).toContain("PRIVATE KEY-----");
    expect(JSON.stringify(useUi.getState())).not.toContain("PRIVATE KEY");
  });

  it("keeps the OTP seed out of React state: the input is uncontrolled (N-6)", async () => {
    await boot();
    const view = openNew();
    fireEvent.click(within(view).getByRole("button", { name: "Username and password" }));
    const form = within(view).getByRole("form");
    fireEvent.click(within(form).getByRole("checkbox"));
    const seedInput = within(form).getByPlaceholderText("JBSWY3DPEHPK3PXPJBSWY3DP");
    expect(seedInput).not.toHaveAttribute("value");
    fireEvent.change(seedInput, { target: { value: "GEZDGNBVGY3TQOJQGEZDGNBV" } });
    expect(seedInput.getAttribute("value")).toBeNull();
    expect(document.body.innerHTML).not.toContain("GEZDGNBVGY3TQOJQGEZDGNBV");
  });

  it("drops the pasted blob from the view's React state once the editor has it (N-6)", async () => {
    await boot();
    const view = openNew();
    const zone = within(view).getByLabelText("Paste a key, certificate or kubeconfig");
    fireEvent.paste(zone, { clipboardData: { getData: () => KEY } });
    await settle();
    const form = within(view).getByRole("form", { name: "New SSH key" });
    expect(form.querySelector<HTMLTextAreaElement>("textarea[data-secret]")?.value).toBe(KEY);
    expect(hookStateContains(view, "Zml4dHVyZS1rZXktbm90LXJlYWw")).toBe(false);
  });

  it("lists kubeconfig contexts from the pasted file", async () => {
    await boot();
    const view = openNew();
    fireEvent.click(within(view).getByRole("button", { name: "kubeconfig" }));
    const form = within(view).getByRole("form");
    const yaml = form.querySelector<HTMLTextAreaElement>("textarea[data-secret]");
    if (!yaml) throw new Error("no kubeconfig input");
    fireEvent.change(yaml, { target: { value: KUBE } });
    const ctx = within(form).getByLabelText(/^Context/);
    expect(within(ctx).getAllByRole("option").map((o) => o.textContent)).toEqual(["Default", "blue", "green"]);
    fireEvent.change(ctx, { target: { value: "green" } });
    fireEvent.change(within(form).getByLabelText("Name"), { target: { value: "kube" } });
    fireEvent.click(within(form).getByRole("button", { name: "Create credential" }));
    await settle();
    expect(useCredentials.getState().items.find((c) => c.name === "kube")?.fields).toEqual({ context: "green", contexts: ["blue", "green"] });
    expect(document.body.innerHTML).not.toContain("fixture-token-1");
  });

  it("counts VNC password bytes and refuses more than 8", async () => {
    await boot();
    const view = openNew();
    fireEvent.click(within(view).getByRole("button", { name: "VNC password" }));
    const form = within(view).getByRole("form");
    fireEvent.change(within(form).getByLabelText(/^Password/), { target: { value: "123456789" } });
    expect(within(form).getByText("9 / 8 bytes")).toBeInTheDocument();
    expect(within(form).getByText(/rejected, not truncated/)).toBeInTheDocument();
  });

  it("offers convert to domain user on a user_password with a domain-looking username", async () => {
    await boot();
    act(() => { useUi.getState().showCredentials({ mode: "edit", id: "cr-legacy" }); });
    const view = screen.getByRole("region", { name: "Credentials" });
    fireEvent.click(within(view).getByRole("button", { name: "Convert to domain user" }));
    const form = within(view).getByRole("form", { name: "New Domain account" });
    expect(within(form).getByLabelText("Account")).toHaveValue("EXAMPLE\\legacy");
    expect(within(form).getByRole("status")).toHaveTextContent("Userlegacy");
  });

  it("shows used-by counts and greys kinds that cannot sign in to the protocol", async () => {
    await boot();
    act(() => { useUi.getState().showCredentials({ mode: "new", protocol: "vnc" }); });
    const view = screen.getByRole("region", { name: "Credentials" });
    expect(within(view).getByRole("button", { name: "VNC password" })).toBeEnabled();
    const key = within(view).getByRole("button", { name: "SSH key" });
    expect(key).toBeDisabled();
    expect(key).toHaveAccessibleDescription("SSH key is for SSH, not VNC sign-in.");
    const list = within(view).getByRole("list", { name: "Stored credentials" });
    const ops = within(list).getByText("ops on-call").closest("li");
    expect(ops).toHaveTextContent(/1used/); // default of folder Production
    const ad = within(list).getByText("domain admin").closest("li");
    expect(ad).toHaveTextContent(/2used/); // default of Desktops + RD Gateway of dc01
  });
});
