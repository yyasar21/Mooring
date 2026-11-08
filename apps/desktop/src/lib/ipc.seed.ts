// Seed data for MockTransport. Fake hosts only (*.example.test, RFC 6761); credentials are metadata.
import type { ConnectionSummary, CredentialMeta, Folder } from "./ipc.types";
import { DEFAULT_RDP_OPTIONS, DEFAULT_VNC_OPTIONS } from "./ipc.types.remote";

export const T0 = "2026-11-01T08:00:00Z";

/** A well-formed `sk-ssh-ed25519` public key (made-up key bytes) and its real SHA-256 fingerprint. */
export const SK_PUBLIC =
  "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIAcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmAAAABHNzaDo=";
export const SK_FINGERPRINT = "SHA256:0f/IntG4BPp3d8fT9X/gGHh5if5mE+U8QZtkqXrdDv4";

/** ADR-0027: a PIV card's ECDSA P-256 key line (made-up point; the fingerprint is its real SHA-256). */
export const PIV_PUBLIC =
  "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=";
export const PIV_FINGERPRINT = "SHA256:GIU4ybieeLjdOEuH/yYndvEe5hnX23ys7LuuE//Wdr0";

export function seedFolders(): Folder[] {
  const f = (id: string, parentId: string | null, name: string, sort: number, cred: string | null = null): Folder => ({
    id,
    parentId,
    name,
    defaultCredentialId: cred,
    sort,
  });
  return [
    f("f-root", null, "All connections", 0),
    f("f-prod", "f-root", "Production", 0, "cr-ops"),
    f("f-web", "f-prod", "Web tier", 0),
    f("f-db", "f-prod", "Databases", 1),
    f("f-staging", "f-root", "Staging", 1),
    f("f-desk", "f-root", "Desktops", 2, "cr-ad"),
  ];
}

export function seedConnections(): ConnectionSummary[] {
  const c = (
    id: string,
    folderId: string,
    name: string,
    protocol: ConnectionSummary["protocol"],
    host: string,
    port: number | null,
    credentialId: string | null,
    tags: string[],
  ): ConnectionSummary => ({
    id,
    folderId,
    name,
    protocol,
    host,
    port,
    credentialId,
    effectiveCredentialId: null,
    usernameOverride: null,
    domainOverride: null,
    gatewayCredentialId: null,
    becomeCredentialId: null,
    tags,
    createdAt: T0,
    updatedAt: T0,
  });
  return [
    c("c-web01", "f-web", "web01", "ssh", "web01.example.test", 22, null, ["nginx"]),
    c("c-web02", "f-web", "web02", "ssh", "web02.example.test", 22, null, ["nginx"]),
    c("c-lb", "f-web", "edge-lb", "web", "https://lb.example.test", 443, null, ["haproxy"]),
    c("c-pg", "f-db", "pg-primary", "ssh", "pg01.example.test", 2222, "cr-deploy", ["postgres", "otp"]),
    c("c-stg", "f-staging", "stage-app", "ssh", "app.stage.example.test", null, "cr-deploy", []),
    c("c-dc", "f-desk", "dc01", "rdp", "dc01.example.test", 3389, null, ["ad"]),
    // `flaky`: the mock drops the link once, 4 s after connecting, to show the reconnect banner.
    c("c-kiosk", "f-desk", "lobby-kiosk", "vnc", "kiosk.example.test", 5900, "cr-vnc", ["flaky"]),
    c("c-k8s", "f-staging", "stage-cluster", "kubernetes", "https://k8s.stage.example.test:6443", null, "cr-kube", []),
    c("c-jump", "f-staging", "ask-me", "ssh", "jump.stage.example.test", 22, "cr-prompt", ["prompt"]),
    c("c-vc", "f-staging", "stage-vcenter", "vsphere-console", "vcenter.example.test", null, "cr-vc", []),
    // ADR-0025: stage-app is reached through this bastion (its own key, its own host key).
    c("c-bastion", "f-staging", "bastion01", "ssh", "bastion.stage.example.test", 22, "cr-deploy", ["bastion"]),
    // ADR-0026: signs in with a Vault database lease; the session tab shows the lease chip.
    c("c-report", "f-db", "pg-reporting", "ssh", "report.example.test", 22, "cr-db-dyn", ["postgres"]),
    // ADR-0024: signs in with a FIDO2 key through the agent; connecting shows the touch banner.
    c("c-yubi", "f-staging", "build-runner", "ssh", "runner.example.test", 22, "cr-yubi", ["fido2"]),
    // ADR-0027: reached through an RD Gateway; the gateway gets the sign-in ("Same as sign-in").
    c("c-rdg", "f-desk", "finance-desk", "rdp", "fin01.example.test", 3389, "cr-ad", ["rdg"]),
  ].map((x) => {
    if (x.id === "c-stg") return { ...x, via: ["c-bastion"] };
    if (x.id === "c-pg") return { ...x, becomeCredentialId: "cr-sudo" };
    if (x.id === "c-dc") return { ...x, usernameOverride: "dc-admin", gatewayCredentialId: "cr-ad", options: { ...DEFAULT_RDP_OPTIONS } };
    if (x.id === "c-rdg") {
      return { ...x, options: { ...DEFAULT_RDP_OPTIONS, gateway: { host: "gw01.example.test", port: 443, usage: "always" as const, allowBasicGateway: false, caPem: null } } };
    }
    if (x.id === "c-kiosk") return { ...x, options: { ...DEFAULT_VNC_OPTIONS, viewOnly: true } };
    if (x.id === "c-lb") return { ...x, options: { url: "https://lb.example.test", allowedOrigins: [], persistent: false, allowHttp: false } };
    return x;
  });
}

export function seedCredentials(): CredentialMeta[] {
  const m = (
    id: string,
    name: string,
    kind: CredentialMeta["kind"],
    fields: CredentialMeta["fields"],
    secretNames: string[],
    fingerprint: string | null = null,
  ): CredentialMeta => ({ id, name, kind, fields, secretNames, fingerprint, createdAt: T0, updatedAt: T0 });
  return [
    m("cr-ops", "ops on-call", "ssh_key", { username: "ops" }, ["passphrase", "private_key"], "SHA256:q3Wn8bVt0mX1yC7rA5kE2pL9sD4fG6hJ8uZ0iO1tR2w"),
    m("cr-deploy", "deploy bot", "user_password", { username: "deploy", otp: { digits: 6, period: 30, algorithm: "sha1" } }, ["otp_seed", "password"]),
    m("cr-ad", "domain admin", "domain_user", { user: "admin", domain: "EXAMPLE", form: "netbios" }, ["password"]),
    m("cr-vnc", "kiosk vnc", "vnc_password", {}, ["password"]),
    m("cr-kube", "stage kubeconfig", "kubeconfig", { context: "stage-admin", contexts: ["stage-admin", "stage-readonly"] }, ["kubeconfig_yaml"]),
    m("cr-sudo", "sudo as root", "sudo_become", { method: "sudo", become_user: "root" }, ["password"]),
    m("cr-prompt", "ask at connect", "prompt", { username: "ops" }, []),
    m("cr-legacy", "legacy admin", "user_password", { username: "EXAMPLE\\legacy" }, ["password"]),
    m("cr-vc", "vcenter sso", "vsphere_user", { upn: "administrator@vsphere.local" }, ["password"]),
    // ADR-0016 / ADR-0017: the AppRole login of the seeded source `src-ops`, a reference it resolves, and a sync key.
    m("cr-approle", "vault approle", "vault_approle", {}, ["role_id", "secret_id"]),
    m("cr-ext", "db via vault", "external_ref", { provider: "vault", source: "src-ops", reference: "kv/ops/db", target_kind: "user_password" }, []),
    m("cr-s3", "team bucket key", "s3_access_key", { access_key_id: "AKIAEXAMPLE0000001", region: "eu-west-1" }, ["secret_access_key"]),
    // ADR-0026: the logins of the seeded Connect and Bitwarden sources, and a dynamic database user.
    m("cr-op-token", "connect token", "api_token", { header_name: "Authorization", scheme: "Bearer" }, ["token"]),
    m("cr-bws-token", "bws machine token", "bitwarden_access_token", {}, ["access_token"]),
    m("cr-yubi", "yubikey ops", "ssh_sk_key", {
      username: "ops", public_key: `${SK_PUBLIC} ops@yubikey`, backend: "agent", resident: true, application: "ssh:", fingerprint: SK_FINGERPRINT,
    }, [], SK_FINGERPRINT),
    // ADR-0027: a PIV card; nothing is sealed (the PIN is asked at connect when the agent lacks the key).
    m("cr-piv", "piv badge", "smart_card", {
      username: "ops", reader_hint: "Yubico YubiKey", public_key: `${PIV_PUBLIC} piv@yubikey`, pkcs11_module: "ykcs11", fingerprint: PIV_FINGERPRINT,
    }, [], PIV_FINGERPRINT),
    m("cr-db-dyn", "reporting db (dynamic)", "external_ref", { provider: "vault", source: "src-ops", engine: "database", reference: "database/reporting", target_kind: "user_password" }, []),
  ];
}
