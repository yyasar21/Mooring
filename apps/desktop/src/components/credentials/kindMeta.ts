// Display-only metadata for credential kinds: badge codes, picker sections and short notes.
// Forms never branch on these; they render from the served KindSchema.
import type { CredentialKind, KindGroup, KindSchema, Protocol } from "../../lib/ipc";

/** Four-letter code on the bevelled kind badge. */
export const KIND_CODE: Record<CredentialKind, string> = {
  user_password: "PASS",
  domain_user: "DOM",
  ssh_key: "KEY",
  ssh_agent: "AGNT",
  x509: "X509",
  api_token: "TOKN",
  oauth_client: "OAUT",
  kubeconfig: "KCFG",
  kube_token: "KTOK",
  vsphere_user: "SSO",
  vnc_password: "VNC",
  vnc_user_password: "VNCU",
  prompt: "ASK",
  external_ref: "REF",
  sudo_become: "SUDO",
  vault_approle: "ROLE",
  s3_access_key: "S3",
  bitwarden_access_token: "BWS",
};

/** Picker sections, in order. The served `group` maps onto these (Windows + vSphere are accounts). */
export const SECTIONS = ["Accounts", "SSH", "Certificates & tokens", "Kubernetes", "VNC", "Other", "Secret sources & sync"] as const;
export type Section = (typeof SECTIONS)[number];

const SECTION_OF: Record<KindGroup, Section> = {
  Windows: "Accounts",
  vSphere: "Accounts",
  SSH: "SSH",
  "Web/API": "Certificates & tokens",
  Kubernetes: "Kubernetes",
  VNC: "VNC",
  Other: "Other",
  "Secret sources": "Secret sources & sync",
  Sync: "Secret sources & sync",
};

export function sectionOf(k: KindSchema): Section {
  return SECTION_OF[k.group];
}

export function bySection(kinds: KindSchema[]): { section: Section; kinds: KindSchema[] }[] {
  return SECTIONS.map((section) => ({ section, kinds: kinds.filter((k) => sectionOf(k) === section) })).filter(
    (g) => g.kinds.length > 0,
  );
}

/** Column order of the matrix strip. */
export const MATRIX: { protocol: Protocol; code: string }[] = [
  { protocol: "ssh", code: "SSH" },
  { protocol: "rdp", code: "RDP" },
  { protocol: "vnc", code: "VNC" },
  { protocol: "web", code: "WEB" },
  { protocol: "kubernetes", code: "K8S" },
  { protocol: "vsphere-console", code: "VMK" },
];

/** One line under the kind name in the picker. */
export const KIND_BLURB: Record<CredentialKind, string> = {
  user_password: "A username and password, optionally with a domain.",
  domain_user: "A Windows account typed as CORP\\alice or alice@corp.example.",
  ssh_key: "A private key, with an optional passphrase and OpenSSH certificate.",
  ssh_agent: "Sign in with a key held by your running SSH agent.",
  sudo_become: "Escalate after login with sudo, su or doas.",
  x509: "A client certificate and key for mutual TLS.",
  api_token: "A bearer token sent in an HTTP header.",
  oauth_client: "OAuth 2.0 client credentials exchanged for a token.",
  kubeconfig: "A self-contained kubeconfig. Exec plugins and file paths are refused.",
  kube_token: "A service account or user bearer token.",
  vsphere_user: "A vCenter single sign-on account, user@domain.",
  vnc_password: "The classic VNC password, at most 8 bytes.",
  vnc_user_password: "Apple Remote Desktop or VeNCrypt Plain login.",
  prompt: "Nothing is stored. Mooring asks for the account when you connect.",
  external_ref: "Points at a secret in Vault, 1Password or Bitwarden.",
  vault_approle: "The AppRole a secret source signs in to Vault with. Both halves are sealed.",
  s3_access_key: "The access key vault sync uses for the S3 bucket. Never usable for a connection.",
  bitwarden_access_token: "The machine access token a Bitwarden Secrets Manager source runs bws with. Sealed.",
};

export const PROVIDERS: { value: string; label: string; placeholder: string; hint: string }[] = [
  {
    value: "vault",
    label: "HashiCorp Vault",
    placeholder: "kv/prod/db",
    hint: "<mount>/<path> of a KV v2 secret, or <mount>/<role> of a dynamic engine. Mooring signs in through the chosen secret source.",
  },
  {
    value: "onepassword",
    label: "1Password",
    placeholder: "op://Infra/prod-db/password",
    hint: "A secret reference: op://vault/item/[section/]field, read through 1Password Connect.",
  },
  {
    value: "bitwarden",
    label: "Bitwarden",
    placeholder: "be8e0ad8-d545-4017-a55a-b02f014d4158",
    hint: "The secret id, or <project id>/<key>, from Bitwarden Secrets Manager.",
  },
];

/** One line of relationship guidance for the kinds that never sign in to a connection (ADR-0016/0017). */
export const BWS_TOKEN_HINT = "Use it in Settings → Secret sources for a Bitwarden source, then create a Secret manager reference credential.";
export const APPROLE_HINT = "Use it in Settings → Secret sources, then create a Secret manager reference credential.";
