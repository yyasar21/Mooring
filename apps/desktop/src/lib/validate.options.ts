// Input rules for the per-protocol connection options (ADR-0011/0012/0013). They mirror
// `crates/mooring-core/src/options/{mod,conn}.rs` so the form and the mock never disagree with
// Rust; Rust validates again (and re-validates on read) and stays the authority.
import type { Protocol } from "./ipc.types";
import {
  CLIPBOARD_POLICIES,
  DEFAULT_RDP_OPTIONS,
  DEFAULT_VNC_OPTIONS,
  DEFAULT_WEB_OPTIONS,
  KEYBOARD_LAYOUTS,
  MAX_FPS_VALUES,
  OPTION_LIMITS,
  VNC_SECURITIES,
  type ClipboardPolicy,
  type KeyboardLayout,
  type MaxFps,
  type ProtocolOptions,
  type RdpConnOptions,
  type VncConnOptions,
  type VncSecurity,
  type WebConnOptions,
} from "./ipc.types.remote";
import { DEFAULT_KUBE_OPTIONS, type KubeConnOptions } from "./ipc.types.kube";
import { DEFAULT_VSPHERE_OPTIONS, type VsphereConnOptions } from "./ipc.types.vsphere";
import { normalizeKube, normalizeVsphere, validateKube, validateVsphere } from "./validate.kube";
import { normalizeGateway, validateGateway } from "./validate.rdg";

/** Field → message. Empty = valid. */
export type OptionErrors = Partial<Record<string, string>>;

/** Protocols with an options struct; the rest store `{}`. */
export const hasOptions = (p: Protocol): p is "rdp" | "vnc" | "web" | "kubernetes" | "vsphere-console" =>
  p === "rdp" || p === "vnc" || p === "web" || p === "kubernetes" || p === "vsphere-console";

export function defaultOptions(p: Protocol): ProtocolOptions {
  switch (p) {
    case "rdp":
      return { ...DEFAULT_RDP_OPTIONS };
    case "vnc":
      return { ...DEFAULT_VNC_OPTIONS };
    case "web":
      return { ...DEFAULT_WEB_OPTIONS, allowedOrigins: [] };
    case "kubernetes":
      return { ...DEFAULT_KUBE_OPTIONS, allowedNamespaces: [] };
    case "vsphere-console":
      return { ...DEFAULT_VSPHERE_OPTIONS };
    default:
      return {};
  }
}

/** Display names of the ADR-0011 KLID list. */
export const KEYBOARD_LAYOUT_NAMES: Record<KeyboardLayout, string> = {
  0x0409: "English (US)",
  0x041f: "Turkish Q",
  0x1041f: "Turkish F",
  0x0407: "German",
  0x040c: "French",
  0x0809: "English (UK)",
  0x0410: "Italian",
  0x040a: "Spanish",
  0x0419: "Russian",
};

const utf8Len = (s: string): number => new TextEncoder().encode(s).length;

/**
 * `caPem` (B-3): certificate PEM blocks only, ≤ 64 KiB. Rust also decodes the first block as DER;
 * the form checks the shape so the common mistakes (a key, a bare base64 blob) show at once.
 */
export function checkCaPem(pem: string | null): string | null {
  if (pem === null) return null;
  if (utf8Len(pem) > OPTION_LIMITS.maxCaPem) return "The CA certificates are larger than 64 KiB.";
  if (/PRIVATE KEY/.test(pem)) return "Paste certificates only, never a private key.";
  const blocks = pem.match(/-----BEGIN ([A-Z0-9 ]+)-----/g) ?? [];
  if (blocks.length === 0) return "Paste one or more PEM blocks starting with -----BEGIN CERTIFICATE-----.";
  if (blocks.some((b) => b !== "-----BEGIN CERTIFICATE-----")) return "Only CERTIFICATE blocks are accepted.";
  return null;
}

function splitUrl(url: string): { scheme: string; authority: string; rest: string } | null {
  const i = url.indexOf("://");
  if (i < 0) return null;
  const after = url.slice(i + 3);
  const m = /[/?#]/.exec(after);
  const end = m ? m.index : after.length;
  return { scheme: url.slice(0, i), authority: after.slice(0, end), rest: after.slice(end) };
}

function splitAuthority(a: string): { host: string; port: string | null } | null {
  if (a.startsWith("[")) {
    const close = a.indexOf("]");
    if (close < 0) return null;
    const tail = a.slice(close + 1);
    if (tail === "") return { host: a.slice(1, close), port: null };
    return tail.startsWith(":") ? { host: a.slice(1, close), port: tail.slice(1) } : null;
  }
  const c = a.lastIndexOf(":");
  return c < 0 ? { host: a, port: null } : { host: a.slice(0, c), port: a.slice(c + 1) };
}

/** Rust `check_url`: same order of checks, same outcomes. */
export function checkUrl(url: string, allowHttp: boolean, originOnly: boolean): string | null {
  const what = originOnly ? "Origin" : "URL";
  if (utf8Len(url) > OPTION_LIMITS.maxUrl) return `${what} is longer than 2048 bytes.`;
  // eslint-disable-next-line no-control-regex
  if (/[\s\u0000-\u001f\u007f-\u009f]/u.test(url)) return `${what} contains spaces or control characters.`;
  const parts = splitUrl(url);
  if (!parts) return `${what} must be an absolute https:// address.`;
  const scheme = parts.scheme.toLowerCase();
  if (scheme === "http" && !allowHttp) return `${what} uses http://. Turn on "Allow http://" or use https://.`;
  if (scheme !== "https" && scheme !== "http") return `${what} must use https://.`;
  if (parts.authority.includes("@")) return `${what} must not carry a user name or password.`;
  if (parts.authority.includes("*")) return `${what} must not contain wildcards.`;
  const hp = splitAuthority(parts.authority);
  const portOk = (p: string) => /^\d{1,5}$/.test(p) && Number(p) >= 1 && Number(p) <= 65535;
  if (!hp || hp.host === "" || (hp.port !== null && !portOk(hp.port))) return `${what} has an invalid host or port.`;
  if (originOnly && parts.rest !== "" && parts.rest !== "/") return "Origins have no path: use scheme://host[:port].";
  return null;
}

/** `scheme://host[:port]`, lowercased, as Rust builds it for the allow-list. */
export function originOf(url: string): string | null {
  const p = splitUrl(url);
  return p ? `${p.scheme.toLowerCase()}://${p.authority.toLowerCase()}` : null;
}

export function validateRdp(o: RdpConnOptions): OptionErrors {
  const e: OptionErrors = {};
  if (!KEYBOARD_LAYOUTS.includes(o.keyboardLayout)) e.keyboardLayout = "Choose a supported keyboard layout.";
  if (!CLIPBOARD_POLICIES.includes(o.clipboard)) e.clipboard = "Choose a clipboard policy.";
  if (!MAX_FPS_VALUES.includes(o.maxFps)) e.maxFps = "Frame rate is 30 or 60.";
  const ca = checkCaPem(o.caPem);
  if (ca) e.caPem = ca;
  return { ...e, ...validateGateway(o.gateway ?? null, checkCaPem) };
}

export function validateVnc(o: VncConnOptions): OptionErrors {
  const e: OptionErrors = {};
  if (!VNC_SECURITIES.includes(o.security)) e.security = "Choose a security policy.";
  if (!CLIPBOARD_POLICIES.includes(o.clipboard)) e.clipboard = "Choose a clipboard policy.";
  if (!MAX_FPS_VALUES.includes(o.maxFps)) e.maxFps = "Frame rate is 30 or 60.";
  const ca = checkCaPem(o.caPem);
  if (ca) e.caPem = ca;
  return e;
}

export function validateWeb(o: WebConnOptions): OptionErrors {
  const e: OptionErrors = {};
  if (o.url === "") e.url = "A start URL is required.";
  else {
    const u = checkUrl(o.url, o.allowHttp, false);
    if (u) e.url = u;
  }
  if (o.allowedOrigins.length > OPTION_LIMITS.maxAllowedOrigins) e.allowedOrigins = "At most 16 extra origins.";
  else {
    for (const origin of o.allowedOrigins) {
      const bad = checkUrl(origin, o.allowHttp, true);
      if (bad) {
        e.allowedOrigins = `${origin.slice(0, 80)}: ${bad}`;
        break;
      }
    }
  }
  return e;
}

export function validateOptions(p: Protocol, o: ProtocolOptions): OptionErrors {
  switch (p) {
    case "rdp":
      return validateRdp(o as RdpConnOptions);
    case "vnc":
      return validateVnc(o as VncConnOptions);
    case "web":
      return validateWeb(o as WebConnOptions);
    case "kubernetes":
      return validateKube(o as KubeConnOptions, checkCaPem);
    case "vsphere-console":
      return validateVsphere(o as VsphereConnOptions, checkCaPem);
    default:
      return Object.keys(o).length === 0 ? {} : { options: "This protocol has no options." };
  }
}

const RDP_KEYS = new Set(Object.keys(DEFAULT_RDP_OPTIONS));
const VNC_KEYS = new Set(Object.keys(DEFAULT_VNC_OPTIONS));
const WEB_KEYS = new Set(Object.keys(DEFAULT_WEB_OPTIONS));
const KEYS: Partial<Record<Protocol, Set<string>>> = {
  rdp: RDP_KEYS, vnc: VNC_KEYS, web: WEB_KEYS,
  kubernetes: new Set(Object.keys(DEFAULT_KUBE_OPTIONS)), "vsphere-console": new Set(Object.keys(DEFAULT_VSPHERE_OPTIONS)),
};
const keysOf = (p: Protocol): Set<string> => KEYS[p] ?? new Set();

/** Rust `deny_unknown_fields`: the name of the first unknown field, or null. */
export function unknownField(p: Protocol, raw: Record<string, unknown>): string | null {
  const known = keysOf(p);
  return Object.keys(raw).find((k) => !known.has(k)) ?? null;
}

/**
 * Wire → typed options, defaults filled in for absent fields (serde `#[serde(default)]`). Values
 * of the wrong type fall back to the default: the form never shows something Rust would refuse.
 */
export function normalizeOptions(p: Protocol, raw: unknown): ProtocolOptions {
  const w = (typeof raw === "object" && raw !== null ? raw : {}) as Record<string, unknown>;
  const pick = <T>(v: unknown, ok: (x: unknown) => boolean, d: T): T => (ok(v) ? (v as T) : d);
  const isBool = (v: unknown) => typeof v === "boolean";
  const isPem = (v: unknown) => v === null || typeof v === "string";
  const fps = (v: unknown) => pick<MaxFps>(v, (x) => MAX_FPS_VALUES.includes(x as MaxFps), 30);
  const clip = (v: unknown) => pick<ClipboardPolicy>(v, (x) => CLIPBOARD_POLICIES.includes(x as ClipboardPolicy), "both");
  switch (p) {
    case "rdp":
      return {
        keyboardLayout: pick<KeyboardLayout>(w.keyboardLayout, (x) => KEYBOARD_LAYOUTS.includes(x as KeyboardLayout), 0x0409),
        clipboard: clip(w.clipboard),
        allowTlsWithoutNla: pick(w.allowTlsWithoutNla, isBool, false),
        caPem: pick<string | null>(w.caPem, isPem, null),
        maxFps: fps(w.maxFps),
        gateway: normalizeGateway(w.gateway),
      };
    case "vnc":
      return {
        security: pick<VncSecurity>(w.security, (x) => VNC_SECURITIES.includes(x as VncSecurity), "prefer_tls"),
        viewOnly: pick(w.viewOnly, isBool, false),
        shared: pick(w.shared, isBool, true),
        clipboard: clip(w.clipboard),
        caPem: pick<string | null>(w.caPem, isPem, null),
        maxFps: fps(w.maxFps),
        allowNoAuth: pick(w.allowNoAuth, isBool, false),
      };
    case "web":
      return {
        url: pick(w.url, (x) => typeof x === "string", ""),
        allowedOrigins: Array.isArray(w.allowedOrigins) ? w.allowedOrigins.filter((x): x is string => typeof x === "string") : [],
        persistent: pick(w.persistent, isBool, false),
        allowHttp: pick(w.allowHttp, isBool, false),
      };
    case "kubernetes":
      return normalizeKube(w);
    case "vsphere-console":
      return normalizeVsphere(w);
    default:
      return {};
  }
}
