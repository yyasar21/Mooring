// Client-side mirror of `mooring-net::Target::parse` (ADR-0020) so the inspector can refuse a bad
// "other host" before the IPC hop. Rust validates again; this only shapes the form feedback.
import { NET_LIMITS } from "./ipc.types.net";

const LABEL = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
export const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6 = /^[0-9A-Fa-f:.]+$/;

/** ASCII, ≤ 253 bytes, RFC 1123 labels or an IPv4 / IPv6 literal (brackets allowed, `%zone` refused). */
export function validHost(raw: string): boolean {
  let host = raw;
  if (host.length === 0 || host.length > 253 || host.startsWith("-") || host.startsWith("/")) return false;
  if (!/^[\x21-\x7e]+$/.test(host)) return false; // printable ASCII only: no whitespace, controls or non-ASCII
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  if (host.includes("%")) return false;
  if (IPV4.test(host) || (host.includes(":") && IPV6.test(host))) return true;
  return host.split(".").every((l) => LABEL.test(l));
}

export function validPort(n: number): boolean {
  return Number.isInteger(n) && n >= 1 && n <= 65535;
}

export function validCount(n: number): boolean {
  const { min, max } = NET_LIMITS.ping.count;
  return Number.isInteger(n) && n >= min && n <= max;
}

export function validMaxHops(n: number): boolean {
  const { min, max } = NET_LIMITS.traceroute.maxHops;
  return Number.isInteger(n) && n >= min && n <= max;
}

/** The host the tools probe for a connection: a web URL's hostname; null for kube / vSphere consoles. */
export function probeHostOf(protocol: string, host: string, port: number | null): { host: string; port: number | null } | null {
  if (protocol === "kubernetes" || protocol === "vsphere-console") return null;
  if (protocol === "web") {
    try {
      const url = new URL(host);
      const p = url.port ? Number(url.port) : url.protocol === "http:" ? 80 : 443;
      return { host: url.hostname.replace(/^\[|\]$/g, ""), port: p };
    } catch {
      return null;
    }
  }
  return { host, port };
}
