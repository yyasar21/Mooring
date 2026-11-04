// Input rules for ADR-0014 (KubeConnOptions, exec, logs, pod port-forward) and ADR-0015
// (VsphereConnOptions). They mirror the ranges in the ADRs so the form and the mock agree;
// Rust validates again and stays the authority (`input.invalid`).
import type { CredentialKind } from "./ipc.types";
import {
  DEFAULT_KUBE_OPTIONS,
  KUBE_EXEC_COMMANDS,
  KUBE_LIMITS,
  type KubeConnOptions,
  type KubeExecCommand,
  type PodForwardOpen,
} from "./ipc.types.kube";
import { DEFAULT_VSPHERE_OPTIONS, VSPHERE_LIMITS, type VsphereConnOptions } from "./ipc.types.vsphere";
import { hasErrors, isLocalAddrHost, isLoopbackHost, isValidHost, type FieldErrors } from "./validate.exit";

type Errors = Partial<Record<string, string>>;

/** RFC 1123 label (namespaces, container names): lowercase alphanumerics and `-`, ≤ 63. */
export function isDnsLabel(s: string): boolean {
  return s.length <= KUBE_LIMITS.maxLabel && /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(s);
}

/** RFC 1123 subdomain (pod names): labels joined by `.`, ≤ 253. */
export function isDnsSubdomain(s: string): boolean {
  return s.length > 0 && s.length <= KUBE_LIMITS.maxName && s.split(".").every(isDnsLabel);
}

export const isExecCommand = (v: unknown): v is KubeExecCommand => KUBE_EXEC_COMMANDS.includes(v as KubeExecCommand);

/** `https://host[:port][/path]` without credentials or whitespace (the API server URL). */
export function checkServer(url: string): string | null {
  if (url.length > 2048) return "Server URL is longer than 2048 bytes.";
  if (!/^https:\/\//i.test(url)) return "The API server must use https://.";
  // eslint-disable-next-line no-control-regex
  if (/[\s\u0000-\u001f\u007f]/.test(url)) return "Server URL contains spaces or control characters.";
  const authority = url.slice(8).split(/[/?#]/)[0] ?? "";
  if (authority.includes("@")) return "Server URL must not carry a user name or password.";
  const m = /^(\[[0-9a-fA-F:.]+\]|[^:]+)(?::(\d{1,5}))?$/.exec(authority);
  const host = m?.[1]?.replace(/^\[|\]$/g, "") ?? "";
  if (!m || !isValidHost(host) || (m[2] !== undefined && (Number(m[2]) < 1 || Number(m[2]) > 65535))) return "Server URL has an invalid host or port.";
  return null;
}

/** Shape rules of KubeConnOptions (credential-independent). `checkCaPem` is passed in to avoid a cycle. */
export function validateKube(o: KubeConnOptions, checkCaPem: (pem: string | null) => string | null): Errors {
  const e: Errors = {};
  if (o.context !== null && (o.context.trim() === "" || o.context.length > KUBE_LIMITS.maxContext)) e.context = "Context names are 1 to 253 characters.";
  if (o.server !== null) {
    const bad = checkServer(o.server);
    if (bad) e.server = bad;
  }
  const ca = checkCaPem(o.caPem);
  if (ca) e.caPem = ca;
  if (o.tlsServerName !== null && !isValidHost(o.tlsServerName)) e.tlsServerName = "Enter a DNS name.";
  if (o.namespace !== null && !isDnsLabel(o.namespace)) e.namespace = "Namespaces are lowercase letters, digits and -, at most 63.";
  if (!Number.isInteger(o.maxLogBytes) || o.maxLogBytes < KUBE_LIMITS.minLogBytes || o.maxLogBytes > KUBE_LIMITS.maxLogBytes) {
    e.maxLogBytes = "Use 64 KiB to 64 MiB.";
  }
  if (o.allowedNamespaces.length > KUBE_LIMITS.maxAllowedNamespaces) e.allowedNamespaces = "At most 64 namespaces.";
  else {
    const bad = o.allowedNamespaces.find((n) => !isDnsLabel(n));
    if (bad !== undefined) e.allowedNamespaces = `${bad.slice(0, 64)} is not a valid namespace.`;
    else if (new Set(o.allowedNamespaces).size !== o.allowedNamespaces.length) e.allowedNamespaces = "Each namespace once.";
  }
  if (!isExecCommand(o.execCommand)) e.execCommand = "Choose a shell from the list.";
  if (!Number.isInteger(o.logTailLines) || o.logTailLines < 1 || o.logTailLines > KUBE_LIMITS.maxTailLines) e.logTailLines = "Use 1 to 10 000 lines.";
  return e;
}

/**
 * ADR-0014 §3: `server` and `caPem` are required for `kube_token` and refused for `kubeconfig`
 * (the kubeconfig carries both). Null = fits, or no credential chosen yet.
 */
export function kubeCredentialFit(o: KubeConnOptions, kind: CredentialKind | null | undefined): Errors {
  const e: Errors = {};
  if (kind === "kube_token") {
    if (o.server === null) e.server = "A token credential needs the API server URL.";
    if (o.caPem === null) e.caPem = "A token credential needs the cluster CA certificate.";
  } else if (kind === "kubeconfig") {
    if (o.server !== null) e.server = "The kubeconfig names the server; leave this empty.";
    if (o.caPem !== null) e.caPem = "The kubeconfig carries the CA; leave this empty.";
  }
  return e;
}

export function validateVsphere(o: VsphereConnOptions, checkCaPem: (pem: string | null) => string | null): Errors {
  const e: Errors = {};
  const r = o.refreshMinutes;
  if (r !== null && (!Number.isInteger(r) || r < VSPHERE_LIMITS.minRefresh || r > VSPHERE_LIMITS.maxRefresh)) {
    e.refreshMinutes = "Use 15 to 1440 minutes, or manual.";
  }
  const ca = checkCaPem(o.caPem);
  if (ca) e.caPem = ca;
  return e;
}

const isBool = (v: unknown): v is boolean => typeof v === "boolean";
const strOrNull = (v: unknown): v is string | null => v === null || typeof v === "string";
const intIn = (v: unknown, min: number, max: number): v is number => Number.isInteger(v) && (v as number) >= min && (v as number) <= max;

/** Wire → typed, defaults for absent or mistyped fields (serde `#[serde(default)]`). */
export function normalizeKube(w: Record<string, unknown>): KubeConnOptions {
  const d = DEFAULT_KUBE_OPTIONS;
  const s = (k: keyof KubeConnOptions): string | null => {
    const v = w[k];
    return typeof v === "string" ? v : null;
  };
  return {
    context: s("context"),
    server: s("server"),
    caPem: s("caPem"),
    tlsServerName: s("tlsServerName"),
    namespace: s("namespace"),
    maxLogBytes: Number.isInteger(w.maxLogBytes) ? (w.maxLogBytes as number) : d.maxLogBytes,
    allowedNamespaces: Array.isArray(w.allowedNamespaces) ? w.allowedNamespaces.filter((x): x is string => typeof x === "string") : [],
    execCommand: isExecCommand(w.execCommand) ? w.execCommand : d.execCommand,
    logTailLines: Number.isInteger(w.logTailLines) ? (w.logTailLines as number) : d.logTailLines,
    portForward: isBool(w.portForward) ? w.portForward : d.portForward,
  };
}

export function normalizeVsphere(w: Record<string, unknown>): VsphereConnOptions {
  const d = DEFAULT_VSPHERE_OPTIONS;
  return {
    syncFolderId: typeof w.syncFolderId === "string" ? w.syncFolderId : null,
    refreshMinutes: w.refreshMinutes === null ? null : Number.isInteger(w.refreshMinutes) ? (w.refreshMinutes as number) : d.refreshMinutes,
    allowPowerActions: isBool(w.allowPowerActions) ? w.allowPowerActions : false,
    allowVmrc: isBool(w.allowVmrc) ? w.allowVmrc : false,
    caPem: strOrNull(w.caPem) ? w.caPem : null,
  };
}

export type PodForwardField = "bindHost" | "bindPort" | "namespace" | "pod" | "port" | "exposure";

/** A pod forward binds locally (IP literal or localhost) and targets one container port. */
export function validatePodForward(f: Omit<PodForwardOpen, "sessionId">): FieldErrors<PodForwardField> {
  const e: FieldErrors<PodForwardField> = {};
  if (!isLocalAddrHost(f.bind.host)) e.bindHost = "Bind to an IP address or localhost.";
  if (!intIn(f.bind.port, 0, 65535)) e.bindPort = "Use 0 to 65535 (0 picks a free port).";
  if (f.exposure === "loopback" && isLocalAddrHost(f.bind.host) && !isLoopbackHost(f.bind.host)) {
    e.exposure = "A non-loopback bind address needs external exposure.";
  }
  if (!isDnsLabel(f.target.namespace)) e.namespace = "Choose a namespace.";
  if (!isDnsSubdomain(f.target.pod)) e.pod = "Choose a pod.";
  if (!intIn(f.target.port, 1, 65535)) e.port = "Use 1 to 65535.";
  return e;
}

/** `kube_logs` argument rules (ADR-0014 §5); null = valid. */
export function checkLogsArgs(a: { namespace: string; pod: string; container: string; tailLines: number | null; sinceSeconds: number | null }): string | null {
  if (!isDnsLabel(a.namespace)) return "invalid namespace";
  if (!isDnsSubdomain(a.pod)) return "invalid pod";
  if (!isDnsLabel(a.container)) return "invalid container";
  if (a.tailLines !== null && !intIn(a.tailLines, 1, KUBE_LIMITS.maxTailLines)) return "invalid tailLines: 1 to 10000";
  if (a.sinceSeconds !== null && !intIn(a.sinceSeconds, 1, 365 * 86_400)) return "invalid sinceSeconds";
  return null;
}

export { hasErrors };
