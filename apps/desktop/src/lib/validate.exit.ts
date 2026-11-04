// Input rules for ADR-0010 forms. The mock transport enforces the same rules so the UI and the
// mock never disagree; Rust validates again and stays the authority (`input.invalid`).
import {
  IDLE_MINUTES,
  SYSLOG_FACILITIES,
  type AutoLockPolicy,
  type ForwardOpen,
  type SyslogConfig,
} from "./ipc.types";

const LABEL = "[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?";
const HOSTNAME = new RegExp(`^(?=.{1,253}$)${LABEL}(?:\\.${LABEL})*\\.?$`);
const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const IPV6 = /^[0-9A-Fa-f:.]{2,45}$/;

export function isIpv4(host: string): boolean {
  const m = IPV4.exec(host);
  return m !== null && m.slice(1).every((o) => Number(o) <= 255);
}

function isIpv6(host: string): boolean {
  return host.includes(":") && IPV6.test(host) && (host.match(/::/g) ?? []).length <= 1;
}

/** A DNS name or an IP literal (no brackets, no scheme, no port). */
export function isValidHost(host: string): boolean {
  if (host !== host.trim() || host.length === 0) return false;
  if (/^[\d.]+$/.test(host)) return isIpv4(host);
  return isIpv6(host) || HOSTNAME.test(host);
}

export function isLoopbackHost(host: string): boolean {
  const h = host.trim().toLowerCase();
  return h === "localhost" || h === "::1" || (isIpv4(h) && h.startsWith("127."));
}

function isPort(p: number, min: number): boolean {
  return Number.isInteger(p) && p >= min && p <= 65535;
}

export type FieldErrors<K extends string> = Partial<Record<K, string>>;
export type ForwardField = "bindHost" | "bindPort" | "targetHost" | "targetPort" | "exposure";

/** The local side of a forward is bound/connected by Mooring itself: an IP literal or
 *  `localhost` only — no implicit DNS resolution (mirrors the Rust validator). */
export function isLocalAddrHost(host: string): boolean {
  const h = host.trim();
  return h.toLowerCase() === "localhost" || (isValidHost(h) && (isIpv4(h) || isIpv6(h)));
}

/** Field errors for a new forward; empty object = valid. */
export function validateForward(f: Omit<ForwardOpen, "sessionId">): FieldErrors<ForwardField> {
  const e: FieldErrors<ForwardField> = {};
  if (!isValidHost(f.bind.host)) e.bindHost = "Enter a host name or IP address.";
  else if (f.kind !== "remote" && !isLocalAddrHost(f.bind.host)) {
    e.bindHost = "Bind to an IP address or localhost.";
  }
  if (!isPort(f.bind.port, 0)) e.bindPort = "Use 0 to 65535 (0 picks a free port).";
  if (f.exposure === "loopback" && isValidHost(f.bind.host) && !isLoopbackHost(f.bind.host)) {
    e.exposure = "A non-loopback bind address needs external exposure.";
  }
  if (f.kind === "dynamic") {
    if (f.target !== null) e.targetHost = "A dynamic (SOCKS5) forward has no fixed target.";
  } else if (f.target === null) {
    e.targetHost = "Enter the target host.";
  } else {
    if (!isValidHost(f.target.host)) e.targetHost = "Enter a host name or IP address.";
    else if (f.kind === "remote" && !isLocalAddrHost(f.target.host)) {
      e.targetHost = "A remote forward targets a local IP address or localhost.";
    }
    if (!isPort(f.target.port, 1)) e.targetPort = "Use 1 to 65535.";
  }
  return e;
}

/** Null when valid, else the message shown under the idle field. */
export function validateIdleMinutes(v: number | null): string | null {
  if (v === null) return null;
  return Number.isInteger(v) && v >= IDLE_MINUTES.min && v <= IDLE_MINUTES.max
    ? null
    : `Use a whole number of minutes from ${IDLE_MINUTES.min} to ${IDLE_MINUTES.max}.`;
}

export function validatePolicy(p: AutoLockPolicy): string | null {
  return validateIdleMinutes(p.idleMinutes);
}

export type SyslogField = "host" | "port" | "transport" | "facility";

export function validateSyslog(c: SyslogConfig): FieldErrors<SyslogField> {
  const e: FieldErrors<SyslogField> = {};
  if (!isValidHost(c.host)) e.host = "Enter a host name or IP address, without scheme or port.";
  if (!isPort(c.port, 1)) e.port = "Use 1 to 65535.";
  if (!["udp", "tcp", "tls"].includes(c.transport)) e.transport = "Choose UDP, TCP or TLS.";
  if (!(SYSLOG_FACILITIES as readonly string[]).includes(c.facility)) e.facility = "Choose a facility.";
  return e;
}

export function hasErrors(e: Record<string, string | undefined>): boolean {
  return Object.values(e).some((v) => v !== undefined);
}
