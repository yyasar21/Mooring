import { KIND_SCHEMAS } from "./ipc.kinds";
import {
  credentialValidFor,
  detectKind,
  isAccountError,
  kindValidFor,
  parseAccount,
  previewKubeContexts,
  renderAccount,
  validateField,
} from "./credentials";
import { pickerOptions } from "../components/credentials/CredentialPicker";
import { seedCredentials } from "./ipc.seed";
import type { CredentialKind, CredentialRole, Protocol } from "./ipc.types";

const schema = (k: CredentialKind) => {
  const s = KIND_SCHEMAS.find((x) => x.kind === k);
  if (!s) throw new Error(`no schema ${k}`);
  return s;
};

// Mirror of the mooring-core `parse_account` vectors (ADR-0009 test plan).
describe("parseAccount", () => {
  it.each([
    ["CORP\\alice", { form: "netbios", user: "alice", domain: "CORP" }],
    ["alice@corp.example", { form: "upn", user: "alice", domain: "corp.example" }],
    ["  EXAMPLE\\admin  ", { form: "netbios", user: "admin", domain: "EXAMPLE" }],
    ["first.last@sub.corp.example", { form: "upn", user: "first.last", domain: "sub.corp.example" }],
    ["administrator@vsphere.local", { form: "upn", user: "administrator", domain: "vsphere.local" }],
    ["ABCDEFGHIJKLMNO\\u", { form: "netbios", user: "u", domain: "ABCDEFGHIJKLMNO" }],
  ])("splits %s", (input, out) => {
    expect(parseAccount(input)).toEqual(out);
  });

  it.each([
    ["alice", /Add a domain/],
    ["", /Enter/],
    ["\\alice", /domain before/],
    ["CORP\\", /user after/],
    ["ABCDEFGHIJKLMNOP\\u", /at most 15/],
    ["CO:RP\\alice", /cannot contain/],
    ["CORP\\a\\b", /one backslash/],
    ["@corp.example", /user before/],
    ["alice@", /DNS name/],
    ["alice@-bad-.example", /DNS name/],
    ["ali​ce@corp.example", /invisible/],
  ])("rejects %j", (input, msg) => {
    const r = parseAccount(input);
    expect(isAccountError(r) && r.error).toMatch(msg);
  });

  it("renders the inverse of the split", () => {
    for (const s of ["CORP\\alice", "alice@corp.example"]) {
      const r = parseAccount(s);
      if (isAccountError(r)) throw new Error(r.error);
      expect(renderAccount(r)).toBe(s);
    }
  });
});

describe("compatibility matrix", () => {
  // ✓ cells of the ADR table (primary role). Everything else must be refused.
  const PRIMARY: Partial<Record<CredentialKind, Protocol[]>> = {
    user_password: ["ssh", "rdp", "web", "vsphere-console"],
    domain_user: ["ssh", "rdp", "web", "vsphere-console"],
    ssh_key: ["ssh"],
    ssh_agent: ["ssh"],
    x509: ["web", "kubernetes"],
    api_token: ["web"],
    oauth_client: ["web"],
    kubeconfig: ["kubernetes"],
    kube_token: ["kubernetes"],
    vsphere_user: ["web", "vsphere-console"],
    vnc_password: ["vnc"],
    vnc_user_password: ["vnc"],
    prompt: ["ssh", "rdp", "vnc", "web", "vsphere-console"],
    external_ref: [],
    sudo_become: [],
  };
  const ROLES: [CredentialKind, Protocol, CredentialRole][] = [
    ["user_password", "rdp", "gateway"],
    ["domain_user", "rdp", "gateway"],
    ["prompt", "rdp", "gateway"],
    ["sudo_become", "ssh", "become"],
  ];
  const protocols: Protocol[] = ["ssh", "rdp", "vnc", "web", "kubernetes", "vsphere-console"];

  it("matches the ADR table exhaustively", () => {
    for (const k of KIND_SCHEMAS) {
      for (const p of protocols) {
        for (const role of ["primary", "gateway", "become"] as CredentialRole[]) {
          const expected = role === "primary" ? (PRIMARY[k.kind] ?? []).includes(p) : ROLES.some(([a, b, c]) => a === k.kind && b === p && c === role);
          expect([k.kind, p, role, kindValidFor(k, p, role).ok]).toEqual([k.kind, p, role, expected]);
        }
      }
    }
  });

  it("gives the footnote reason where the ADR has one", () => {
    const r = kindValidFor(schema("user_password"), "kubernetes", "primary");
    expect(!r.ok && r.reason).toMatch(/removed static basic auth/);
    const x = kindValidFor(schema("x509"), "rdp", "primary");
    expect(!x.ok && x.reason).toMatch(/Smart-card/);
    const k = kindValidFor(schema("ssh_key"), "rdp", "primary");
    expect(!k.ok && k.reason).toBe("SSH key is for SSH, not RDP sign-in.");
  });

  it("follows target_kind for external references", () => {
    const [first] = seedCredentials();
    if (!first) throw new Error("no seed");
    const ref = { ...first, kind: "external_ref" as const, fields: { provider: "vault", reference: "x", target_kind: "ssh_key" } };
    expect(credentialValidFor(KIND_SCHEMAS, ref, "ssh", "primary").ok).toBe(true);
    expect(credentialValidFor(KIND_SCHEMAS, ref, "rdp", "primary").ok).toBe(false);
  });

  it("filters the connection picker: incompatible credentials disabled with a reason, prompt grouped first", () => {
    const opts = pickerOptions(seedCredentials(), KIND_SCHEMAS, "rdp", "primary", "Inherit", "");
    const byId = (id: string) => opts.find((o) => o.value === id);
    expect(opts[0]?.value).toBe("");
    expect(byId("cr-ad")?.disabledReason).toBeNull();
    expect(byId("cr-prompt")?.group).toBe("Ask at connect");
    expect(byId("cr-ops")?.disabledReason).toMatch(/SSH key is for SSH/);
    expect(byId("cr-vnc")?.disabledReason).toMatch(/VNC password is for VNC/);
    expect(byId("cr-sudo")?.disabledReason).toMatch(/SSH become/);
    const groups = opts.slice(1).map((o) => o.group);
    expect(groups.indexOf("Not usable here")).toBeGreaterThan(groups.lastIndexOf("Stored"));
    const become = pickerOptions(seedCredentials(), KIND_SCHEMAS, "ssh", "become", "None", "");
    expect(become.filter((o) => o.value && !o.disabledReason).map((o) => o.value)).toEqual(["cr-sudo"]);
  });
});

describe("paste detection and validation", () => {
  it("picks the kind from unambiguous headers only", () => {
    expect(detectKind("-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn...")).toMatchObject({ kind: "ssh_key", field: "private_key" });
    expect(detectKind("\n-----BEGIN RSA PRIVATE KEY-----")).toMatchObject({ kind: "ssh_key" });
    expect(detectKind("-----BEGIN CERTIFICATE-----\nMIIB")).toMatchObject({ kind: "x509", field: "cert_pem" });
    expect(detectKind("apiVersion: v1\nkind: Config\nclusters:\n- name: a")).toMatchObject({ kind: "kubeconfig" });
    expect(detectKind("hunter2")).toBeNull();
    expect(detectKind("ssh-ed25519 AAAAC3Nza")).toBeNull();
  });

  it("lists kubeconfig context names", () => {
    const yaml = "apiVersion: v1\nclusters: []\ncontexts:\n- context:\n    cluster: a\n  name: prod-admin\n- name: \"stage\"\n  context: {}\nusers: []\n";
    expect(previewKubeContexts(yaml)).toEqual(["prod-admin", "stage"]);
  });

  it("enforces the 8-byte VNC limit and the base32 seed rule", () => {
    const [vnc] = schema("vnc_password").fields;
    if (!vnc) throw new Error("no field");
    expect(validateField(vnc, "12345678")).toBeNull();
    expect(validateField(vnc, "123456789")).toMatch(/rejected, not truncated/);
    expect(validateField(vnc, "ééééé")).toMatch(/8 bytes/); // 10 UTF-8 bytes
    const seed = { ...vnc, name: "otp_seed", label: "TOTP seed", validation: { maxBytes: 128, format: "base32" as const } };
    expect(validateField(seed, "JBSWY3DPEHPK3PXP")).toBeNull();
    expect(validateField(seed, "JBSWY3DP")).toMatch(/10 bytes/);
    expect(validateField(seed, "not-base32!")).toMatch(/base32/);
  });
});
