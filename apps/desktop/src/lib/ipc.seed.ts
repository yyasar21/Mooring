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
    c("c-kiosk", "f-desk", "lobby-kiosk", "vnc", "kiosk.example.test", 5900, null, []),
  ];
}

export function seedCredentials(): CredentialMeta[] {
  const m = (id: string, name: string, kind: CredentialMeta["kind"], username: string): CredentialMeta => ({
    id,
    name,
    kind,
    username,
    createdAt: T0,
    updatedAt: T0,
  });
  return [
    m("cr-ops", "ops on-call", "ssh_key", "ops"),
    m("cr-deploy", "deploy bot", "password", "deploy"),
    m("cr-ad", "domain admin", "password", "EXAMPLE\\admin"),
  ];
}
