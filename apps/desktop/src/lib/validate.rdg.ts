// ADR-0027: input rules for `RdpConnOptions.gateway`, mirroring `RdGatewayOptions::validate` in
// `crates/mooring-core/src/options/gateway.rs`. Rust validates again and stays the authority.
import { DEFAULT_GATEWAY, GATEWAY_USAGES, MAX_GATEWAY_HOST, type GatewayUsage, type RdGatewayOptions } from "./ipc.types.rdg";

type Errors = Partial<Record<string, string>>;

const utf8Len = (s: string): number => new TextEncoder().encode(s).length;
// Control, format (bidi, zero-width) and other invisible characters: Rust `is_forbidden`.
const FORBIDDEN = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;

/** Rust: non-empty, ≤ 253 bytes, no whitespace, no invisible character, none of `/?#@\`. */
export function gatewayHostProblem(host: string): string | null {
  if (host === "") return "Enter the RD Gateway's host name or IP address.";
  if (utf8Len(host) > MAX_GATEWAY_HOST) return "The RD Gateway host is longer than 253 bytes.";
  if (/\s/u.test(host) || FORBIDDEN.test(host)) return "The RD Gateway host contains spaces or invisible characters.";
  if (/[/?#@\\]/.test(host)) return "Enter a host name or IP address only, without https://, a path or a user name.";
  return null;
}

/** Errors under `gateway.*` keys (empty = valid, or no gateway). */
export function validateGateway(g: RdGatewayOptions | null, checkCaPem: (pem: string | null) => string | null): Errors {
  if (g === null) return {};
  const e: Errors = {};
  const host = gatewayHostProblem(g.host);
  if (host) e["gateway.host"] = host;
  if (!Number.isInteger(g.port) || g.port < 1 || g.port > 65535) e["gateway.port"] = "Port must be 1 to 65535.";
  if (!GATEWAY_USAGES.includes(g.usage)) e["gateway.usage"] = "Choose when the gateway is used.";
  const ca = checkCaPem(g.caPem);
  if (ca) e["gateway.caPem"] = ca;
  return e;
}

/** Wire → typed, serde defaults filled in. Absent, `null` or not an object = no gateway. */
export function normalizeGateway(raw: unknown): RdGatewayOptions | null {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return null;
  const w = raw as Record<string, unknown>;
  const port = w.port;
  return {
    host: typeof w.host === "string" ? w.host : "",
    port: typeof port === "number" && Number.isInteger(port) && port >= 1 && port <= 65535 ? port : DEFAULT_GATEWAY.port,
    usage: GATEWAY_USAGES.includes(w.usage as GatewayUsage) ? (w.usage as GatewayUsage) : "always",
    allowBasicGateway: w.allowBasicGateway === true,
    caPem: typeof w.caPem === "string" ? w.caPem : null,
  };
}
