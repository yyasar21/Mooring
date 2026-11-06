// Demo plans of the mock importers, one per format, shaped like the plans I1's parsers build from
// the fixtures under crates/mooring-import/tests/fixtures/. Fake hosts only (*.example.test);
// no secret exists anywhere here: `hasSecret` is a flag the mock sets from the opt-in.
import type { ImportCredentialItem, ImportFormat, ImportItem, ImportSkipped, ImportWarning } from "./ipc.types.import";

/** What the mock parser yields before the src-tauri steps (duplicates, key files) run. */
export interface MockPlan {
  items: ImportItem[];
  credentials: MockPlanCredential[];
  skipped: ImportSkipped[];
  warnings: ImportWarning[];
}

export interface MockPlanCredential extends ImportCredentialItem {
  /**
   * The source holds this credential's secret in plaintext: with the opt-in it keeps `kind`
   * and `hasSecret: true`; without it the credential becomes a `prompt` and a
   * `password_dropped` warning is added (Termius) — as `creds.rs` maps it.
   */
  plaintext?: boolean;
  /** OpenSSH `IdentityFile`: with `importKeyFiles` it becomes `ssh_key` (or `key_unreadable`). */
  keyFile?: "readable" | "unreadable";
}

const folder = (key: string, parent: string | null, name: string): ImportItem => ({ key, parent, kind: "folder", name });
const conn = (key: string, parent: string | null, name: string, rest: Omit<ImportItem, "key" | "parent" | "kind" | "name">): ImportItem => ({
  key, parent, kind: "connection", name, ...rest,
});

/** The demo picks of the browser "dialog", per format. */
export const DEMO_IMPORT_FILES: Record<ImportFormat, { fileName: string; size: number }> = {
  royal_ts: { fileName: "ops-team.rtsz", size: 48_213 },
  rdm: { fileName: "rdm-export.rdm", size: 131_904 },
  termius: { fileName: "termius-hosts.csv", size: 7_410 },
  mremoteng: { fileName: "confCons.xml", size: 22_870 },
  putty: { fileName: "putty-sessions.reg", size: 9_156 },
  openssh: { fileName: "config", size: 1_288 },
};

export function demoPlan(format: ImportFormat): MockPlan {
  switch (format) {
    case "royal_ts":
      return {
        items: [
          folder("f1", null, "Datacenter A"),
          folder("f2", "f1", "Linux"),
          folder("f3", "f1", "Windows"),
          conn("c1", "f2", "web01", { protocol: "ssh", host: "web01.example.test", port: 22 }),
          conn("c2", "f2", "cache01", { protocol: "ssh", host: "cache01.example.test", port: 22, username: "ops", credentialKey: "k1" }),
          conn("c3", "f3", "fs01", { protocol: "rdp", host: "fs01.example.test", port: 3389, username: "fsadmin", credentialKey: "k2" }),
          conn("c4", "f3", "lobby display", { protocol: "vnc", host: "203.0.113.40", port: 5900 }),
          conn("c5", null, "intranet", { protocol: "web", host: "https://intranet.example.test" }),
        ],
        credentials: [
          { key: "k1", name: "ops (Royal TS)", kind: "prompt", hasSecret: false },
          { key: "k2", name: "fsadmin (Royal TS)", kind: "prompt", hasSecret: false },
        ],
        skipped: [{ sourceRef: "RoyalICAConnection #7", reason: "unsupported" }],
        warnings: [{ code: "port_ignored", sourceRef: "RoyalVNCConnection #4" }],
      };
    case "rdm":
      return {
        items: [
          folder("f1", null, "Customers"),
          folder("f2", "f1", "Acme"),
          conn("c1", "f2", "acme-dc", { protocol: "rdp", host: "dc.acme.example.test", port: 3389, username: "administrator", credentialKey: "k1" }),
          conn("c2", "f2", "acme-bastion", { protocol: "ssh", host: "bastion.acme.example.test", port: 2200, username: "root", credentialKey: "k2" }),
          conn("c3", "f1", "support portal", { protocol: "web", host: "https://support.example.test" }),
          conn("c4", null, "dc01", { protocol: "rdp", host: "dc01.example.test", port: 3389 }),
        ],
        credentials: [
          { key: "k1", name: "administrator (RDM)", kind: "prompt", hasSecret: false },
          { key: "k2", name: "root (RDM)", kind: "prompt", hasSecret: false },
        ],
        skipped: [{ sourceRef: "Connection #9", reason: "encrypted" }],
        warnings: [{ code: "secret_encrypted", sourceRef: "Connection #3" }, { code: "secret_encrypted", sourceRef: "Connection #5" }],
      };
    case "termius":
      return {
        items: [
          folder("f1", null, "homelab"),
          conn("c1", "f1", "nas", { protocol: "ssh", host: "nas.example.test", port: 22, username: "admin", credentialKey: "k1" }),
          conn("c2", "f1", "pi-hole", { protocol: "ssh", host: "192.0.2.53", port: 22, username: "pi", credentialKey: "k2" }),
          conn("c3", null, "web01", { protocol: "ssh", host: "web01.example.test", port: 22 }),
          conn("c4", null, "pg-primary", { protocol: "ssh", host: "pg01.example.test", port: 2222, username: "deploy", credentialKey: "k3" }),
        ],
        credentials: [
          { key: "k1", name: "admin (Termius)", kind: "user_password", hasSecret: true, plaintext: true },
          { key: "k2", name: "pi (Termius)", kind: "ssh_key", hasSecret: true, plaintext: true },
          { key: "k3", name: "deploy (Termius)", kind: "prompt", hasSecret: false },
        ],
        skipped: [{ sourceRef: "record 6", reason: "invalid" }],
        warnings: [{ code: "tags_truncated", sourceRef: "record 2" }],
      };
    case "mremoteng":
      return {
        items: [
          folder("f1", null, "Branch offices"),
          folder("f2", "f1", "North"),
          conn("c1", "f2", "north-fs", { protocol: "rdp", host: "fs.north.example.test", port: 3389, username: "svc-backup", credentialKey: "k1" }),
          conn("c2", "f2", "north-sw", { protocol: "ssh", host: "sw.north.example.test", port: 22, username: "netops", credentialKey: "k2" }),
          conn("c3", "f1", "kiosk-cam", { protocol: "vnc", host: "198.51.100.9", port: 5900 }),
          conn("c4", null, "wiki", { protocol: "web", host: "https://wiki.example.test" }),
        ],
        credentials: [
          { key: "k1", name: "EXAMPLE\\svc-backup (mRemoteNG)", kind: "prompt", hasSecret: false },
          { key: "k2", name: "netops (mRemoteNG)", kind: "prompt", hasSecret: false },
        ],
        skipped: [{ sourceRef: "Node #5", reason: "unsupported" }],
        warnings: [{ code: "password_dropped", sourceRef: "Node #2" }, { code: "password_dropped", sourceRef: "Node #3" }],
      };
    case "putty":
      return {
        items: [
          conn("c1", null, "router-core", { protocol: "ssh", host: "198.51.100.1", port: 22, username: "admin", credentialKey: "k1" }),
          conn("c2", null, "build box", { protocol: "ssh", host: "build.example.test", port: 22 }),
          conn("c3", null, "web01", { protocol: "ssh", host: "web01.example.test", port: 22 }),
        ],
        credentials: [{ key: "k1", name: "admin (PuTTY)", kind: "prompt", hasSecret: false }],
        skipped: [
          { sourceRef: "Sessions\\Default%20Settings", reason: "unsupported" },
          { sourceRef: "Sessions\\old-telnet", reason: "unsupported" },
        ],
        warnings: [{ code: "ppk_key", sourceRef: "Sessions\\router-core" }],
      };
    case "openssh":
      return {
        items: [
          conn("c1", null, "bastion", { protocol: "ssh", host: "bastion.example.test", port: 22, username: "yy", credentialKey: "k1" }),
          conn("c2", null, "app-stage", { protocol: "ssh", host: "app.stage.example.test", port: 22, username: "deploy", credentialKey: "k2" }),
          conn("c3", null, "legacy", { protocol: "ssh", host: "legacy.example.test", port: 2022, username: "root", credentialKey: "k3" }),
          conn("c4", null, "web01", { protocol: "ssh", host: "web01.example.test", port: 22 }),
        ],
        credentials: [
          { key: "k1", name: "yy · id_ed25519", kind: "ssh_agent", hasSecret: false, keyFile: "readable" },
          { key: "k2", name: "deploy · id_rsa_old", kind: "ssh_agent", hasSecret: false, keyFile: "unreadable" },
          { key: "k3", name: "root", kind: "prompt", hasSecret: false },
        ],
        skipped: [],
        warnings: [
          { code: "host_pattern", sourceRef: "line 1" },
          { code: "match_block", sourceRef: "line 18" },
          { code: "include_ignored", sourceRef: "line 2" },
          { code: "proxy_jump", sourceRef: "line 11" },
        ],
      };
  }
}
