// DTOs of ADR-0027 as rust-core R5 serves them (`docs/handoff/a5-rust-core-r5.md`, "UI contract"):
// the RD Gateway options of an RDP connection, the `gateway_status` session event, and the
// smart-card kind's fixed module list. Nothing here carries a secret: the gateway credential is a
// credential id on the connection row, and the smart-card PIN only ever travels inward as an answer.
import type { HopState } from "./ipc.types.a5";

/** `always`: every connect goes through the gateway. `if_unreachable`: a 3 s direct probe first (audited). */
export type GatewayUsage = "always" | "if_unreachable";
export const GATEWAY_USAGES: readonly GatewayUsage[] = ["always", "if_unreachable"];

/** `RdpConnOptions.gateway` (`RdGatewayOptions`, camelCase, `deny_unknown_fields`). */
export interface RdGatewayOptions {
  /** DNS name or IP: the TLS name and the `known_rdg_certs` key. */
  host: string;
  /** HTTPS port, 443 by default. */
  port: number;
  usage: GatewayUsage;
  /** HTTP Basic when the gateway refuses NTLM (inside TLS only; audited as a warning). */
  allowBasicGateway: boolean;
  /** Extra CA certificates for the gateway (PEM, certificates only, ≤ 64 KiB). */
  caPem: string | null;
}

export const DEFAULT_GATEWAY: RdGatewayOptions = { host: "", port: 443, usage: "always", allowBasicGateway: false, caPem: null };

/** Rust `MAX_GATEWAY_HOST`. */
export const MAX_GATEWAY_HOST = 253;

/** `{ kind: "gateway_status" }`: progress of the RD Gateway, before the target's `connected`. */
export interface GatewayStatus {
  /** `host:port` as configured. */
  host: string;
  state: HopState;
  /** Gateway certificate fingerprint once TLS passed. */
  peerIdentity: string | null;
}

/** ADR-0027 §2: the fixed PKCS#11 providers of a `smart_card` (the path is resolved per OS in Rust). */
export const PKCS11_MODULE_LABEL: Record<string, string> = {
  opensc: "OpenSC",
  ykcs11: "YubiKey (ykcs11)",
  cryptoapi: "Windows smart card (no module)",
};
