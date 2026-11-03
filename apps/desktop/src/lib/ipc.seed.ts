// Seed data for MockTransport. Fake hosts only (*.example.test, RFC 6761); credentials are metadata.
import type { ConnectionSummary, CredentialMeta, Folder } from "./ipc.types";

export const T0 = "2026-11-01T08:00:00Z";

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
    c("c-kiosk", "f-desk", "lobby-kiosk", "vnc", "kiosk.example.test", 5900, "cr-vnc", []),
    c("c-k8s", "f-staging", "stage-cluster", "kubernetes", "https://k8s.stage.example.test:6443", null, "cr-kube", []),
    c("c-jump", "f-staging", "ask-me", "ssh", "jump.stage.example.test", 22, "cr-prompt", ["prompt"]),
  ].map((x) => {
    if (x.id === "c-pg") return { ...x, becomeCredentialId: "cr-sudo" };
    if (x.id === "c-dc") return { ...x, usernameOverride: "dc-admin", gatewayCredentialId: "cr-ad" };
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
  ];
}
