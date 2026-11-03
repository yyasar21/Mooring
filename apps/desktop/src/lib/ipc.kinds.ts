// The ADR-0009 kind table as `credential_kinds()` serves it. Rust owns the real table
// (`CredentialKind::valid_for` in mooring-core); this copy feeds MockTransport and the tests.
//
// Conventions the UI relies on (rust-core: please serve the same):
// - `fields` lists plain fields and secrets in display order; `secret: true` marks a sealed one.
// - The TOTP slot is not listed: `supportsOtp: true` means the secret `otp_seed` and the plain
//   field `otp: {digits, period, algorithm}` are accepted.
// - Derived values are not fields: `fingerprint` is on CredentialMeta, kubeconfig `contexts`
//   is `fields.contexts` (string[]) on CredentialMeta.
// - An `enum` field with no `options` takes its options from that derived list (`context` ← `contexts`).
import type { CredentialKind, FieldFormat, FieldSchema, KindProtocol, KindSchema } from "./ipc.types";

const KIB = 1024;

interface FieldOpts {
  required?: boolean;
  multiline?: boolean;
  placeholder?: string;
  copyable?: boolean;
  options?: string[];
  pattern?: string;
}

function field(name: string, label: string, maxBytes: number, format: FieldFormat, o: FieldOpts = {}): FieldSchema {
  const validation: FieldSchema["validation"] = { maxBytes, format };
  if (o.options) validation.options = o.options;
  if (o.pattern) validation.pattern = o.pattern;
  return {
    name,
    label,
    secret: false,
    required: o.required ?? false,
    multiline: o.multiline ?? false,
    placeholder: o.placeholder ?? "",
    copyable: false,
    validation,
  };
}

function secret(name: string, label: string, maxBytes: number, format: FieldFormat, o: FieldOpts = {}): FieldSchema {
  return { ...field(name, label, maxBytes, format, o), secret: true, copyable: o.copyable ?? false };
}

const P = (protocol: KindProtocol["protocol"], ...roles: KindProtocol["roles"]): KindProtocol => ({
  protocol,
  roles: roles.length ? roles : ["primary"],
});

const username = (required = true) => field("username", "Username", 256, "text", { required, placeholder: "alice" });
const password = (o: FieldOpts = {}) => secret("password", "Password", 4 * KIB, "text", { required: true, copyable: true, ...o });

export const TARGET_KINDS: CredentialKind[] = [
  "user_password",
  "domain_user",
  "ssh_key",
  "x509",
  "api_token",
  "oauth_client",
  "kubeconfig",
  "kube_token",
  "vsphere_user",
  "vnc_password",
  "vnc_user_password",
  "sudo_become",
];

export const KIND_SCHEMAS: KindSchema[] = [
  {
    kind: "user_password",
    label: "Username and password",
    group: "Windows",
    protocols: [P("ssh"), P("rdp", "primary", "gateway"), P("web"), P("vsphere-console")],
    supportsOtp: true,
    fields: [username(), field("domain", "Domain", 253, "text", { placeholder: "optional" }), password()],
  },
  {
    kind: "domain_user",
    label: "Domain account",
    group: "Windows",
    protocols: [P("ssh"), P("rdp", "primary", "gateway"), P("web"), P("vsphere-console")],
    supportsOtp: true,
    fields: [
      field("user", "Account", 256, "netbios_or_upn", { required: true, placeholder: "CORP\\alice or alice@corp.example" }),
      field("domain", "Domain", 253, "text", { required: true }),
      field("form", "Form", 8, "enum", { required: true, options: ["netbios", "upn"] }),
      password(),
    ],
  },
  {
    kind: "ssh_key",
    label: "SSH key",
    group: "SSH",
    protocols: [P("ssh")],
    supportsOtp: true,
    fields: [
      username(),
      secret("private_key", "Private key", 64 * KIB, "pem", {
        required: true,
        multiline: true,
        placeholder: "-----BEGIN OPENSSH PRIVATE KEY-----",
      }),
      secret("passphrase", "Key passphrase", 4 * KIB, "text", { copyable: true, placeholder: "optional" }),
      field("public_key", "Public key", 16 * KIB, "text", { multiline: true, placeholder: "ssh-ed25519 AAAA… (optional)" }),
      field("certificate", "OpenSSH certificate", 64 * KIB, "text", {
        multiline: true,
        placeholder: "ssh-ed25519-cert-v01@openssh.com AAAA… (optional, from *-cert.pub)",
      }),
    ],
  },
  {
    kind: "ssh_agent",
    label: "SSH agent",
    group: "SSH",
    protocols: [P("ssh")],
    supportsOtp: false,
    fields: [
      username(),
      field("key_fingerprint", "Pin agent key", 128, "text", { placeholder: "SHA256:… (optional)", pattern: "^SHA256:[A-Za-z0-9+/]{43}=?$" }),
    ],
  },
  {
    kind: "sudo_become",
    label: "Become (sudo, su, doas)",
    group: "SSH",
    protocols: [P("ssh", "become")],
    supportsOtp: false,
    fields: [
      field("method", "Method", 8, "enum", { required: true, options: ["sudo", "su", "doas"] }),
      field("become_user", "Become user", 256, "text", { placeholder: "root" }),
      secret("password", "Become password", 4 * KIB, "text", { copyable: true, placeholder: "optional" }),
    ],
  },
  {
    kind: "x509",
    label: "X.509 client certificate",
    group: "Web/API",
    protocols: [P("web"), P("kubernetes")],
    supportsOtp: false,
    fields: [
      username(false),
      field("cert_pem", "Certificate", 64 * KIB, "pem", { required: true, multiline: true, placeholder: "-----BEGIN CERTIFICATE-----" }),
      secret("key_pem", "Private key", 64 * KIB, "pem", { required: true, multiline: true, placeholder: "-----BEGIN PRIVATE KEY-----" }),
      secret("key_passphrase", "Key passphrase", 4 * KIB, "text", { placeholder: "optional" }),
    ],
  },
  {
    kind: "api_token",
    label: "API token",
    group: "Web/API",
    protocols: [P("web")],
    supportsOtp: false,
    fields: [
      field("header_name", "Header", 64, "text", { placeholder: "Authorization" }),
      field("scheme", "Scheme", 64, "text", { placeholder: "Bearer" }),
      secret("token", "Token", 16 * KIB, "text", { required: true, copyable: true }),
    ],
  },
  {
    kind: "oauth_client",
    label: "OAuth client credentials",
    group: "Web/API",
    protocols: [P("web")],
    supportsOtp: false,
    fields: [
      field("token_url", "Token URL", 2048, "url", { required: true, placeholder: "https://login.example.test/oauth2/token" }),
      field("client_id", "Client ID", 256, "text", { required: true }),
      field("scope", "Scope", 1024, "text", { placeholder: "optional" }),
      secret("client_secret", "Client secret", 16 * KIB, "text", { required: true, copyable: true }),
      secret("refresh_token", "Refresh token", 16 * KIB, "text", { placeholder: "optional" }),
    ],
  },
  {
    kind: "kubeconfig",
    label: "kubeconfig",
    group: "Kubernetes",
    protocols: [P("kubernetes")],
    supportsOtp: false,
    fields: [
      secret("kubeconfig_yaml", "kubeconfig", 1024 * KIB, "yaml", { required: true, multiline: true, placeholder: "apiVersion: v1\nkind: Config\n…" }),
      field("context", "Context", 253, "enum", { placeholder: "current-context" }),
    ],
  },
  {
    kind: "kube_token",
    label: "Kubernetes token",
    group: "Kubernetes",
    protocols: [P("kubernetes")],
    supportsOtp: false,
    fields: [
      field("subject", "Subject", 256, "text", { placeholder: "system:serviceaccount:ns:name (display only)" }),
      secret("token", "Bearer token", 16 * KIB, "text", { required: true, copyable: true }),
    ],
  },
  {
    kind: "vsphere_user",
    label: "vSphere SSO account",
    group: "vSphere",
    protocols: [P("web"), P("vsphere-console")],
    supportsOtp: true,
    fields: [field("upn", "Account", 510, "upn", { required: true, placeholder: "administrator@vsphere.local" }), password()],
  },
  {
    kind: "vnc_password",
    label: "VNC password",
    group: "VNC",
    protocols: [P("vnc")],
    supportsOtp: false,
    // RFB DES uses 8 bytes; longer input is rejected, never truncated (ADR-0009 §5).
    fields: [secret("password", "Password", 8, "text", { required: true, copyable: true, placeholder: "at most 8 bytes" })],
  },
  {
    kind: "vnc_user_password",
    label: "VNC username and password",
    group: "VNC",
    protocols: [P("vnc")],
    supportsOtp: false,
    fields: [username(), password()],
  },
  {
    kind: "prompt",
    label: "Ask at connect",
    group: "Other",
    protocols: [P("ssh"), P("rdp", "primary", "gateway"), P("vnc"), P("web"), P("vsphere-console")],
    supportsOtp: false,
    fields: [username(false), field("domain", "Domain", 253, "text", { placeholder: "optional" })],
  },
  {
    kind: "external_ref",
    label: "Secret manager reference",
    group: "Other",
    protocols: [],
    supportsOtp: false,
    fields: [
      field("provider", "Provider", 16, "enum", { required: true, options: ["vault", "onepassword", "bitwarden"] }),
      field("reference", "Reference", 1024, "text", { required: true }),
      field("target_kind", "Resolves to", 32, "enum", { required: true, options: TARGET_KINDS }),
    ],
  },
];
