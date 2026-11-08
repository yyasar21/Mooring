// Tab and prompt shapes of the session store, split out of `sessions.ts` (re-exported there).
import type { LineState } from "@mooring/ui";
import type { CertificateInfo, CloseCode, GatewayStatus, HopStatus, PromptAccount, PromptPurpose, Protocol, Size } from "../lib/ipc";
import type { KubeTab } from "./kube";

export type TabState = "connecting" | "connected" | "reconnecting" | "detached" | "closed";

export interface PendingPrompt {
  id: number;
  message: string;
  secret: boolean;
  purpose: PromptPurpose;
  /** Only for `purpose: "credential"`: what to ask and the pre-fills. */
  account?: PromptAccount | null;
  /** Only for `purpose: "certificate_trust"` / `"gateway_certificate_trust"`: the leaf to decide on. */
  certificate?: CertificateInfo | null;
  /** ADR-0025: the 0-based jump host that asks; null/absent = the target. */
  hop?: number | null;
}

export interface CredentialAnswer {
  username: string;
  domain: string | null;
  password: string;
}

export interface Reconnect {
  attempt: number;
  delayMs: number;
  /** `Date.now()` when the event arrived; the countdown runs from here. */
  since: number;
}

/** ADR-0024: a security key waiting for a touch (from `touch_required`), or one that timed out. */
export interface TouchState {
  id: number;
  fingerprint: string;
  timeoutSeconds: number;
  hop: number | null;
  /** `Date.now()` when `touch_required` arrived; the countdown runs from here. */
  since: number;
  timedOut: boolean;
}

export interface Tab {
  /** Local tab id (exists before the backend hands out a session id). */
  id: string;
  connectionId: string;
  protocol: Protocol | null;
  sessionId: string | null;
  state: TabState;
  peerIdentity: string | null;
  /** `Connected.security`: "nla", "tls", "vnc-auth", "none", ... */
  security: string | null;
  prompt: PendingPrompt | null;
  reason: string | null;
  closeCode: CloseCode | "unknown" | null;
  reconnect: Reconnect | null;
  /** Remote desktop size after `desktop_resized` (rdp/vnc). */
  desktop: Size | null;
  /** VNC view-only (advisory in the UI; Rust drops the input). */
  viewOnly: boolean;
  /** Bumped each time this view re-attaches after a detach: the terminal resends its size. */
  attachEpoch: number;
  /** Kubernetes tabs only (ADR-0014): cluster browser, exec shell or log viewer. */
  kube?: KubeTab;
  /** ADR-0025: the latest `hop_status` per jump host, in chain order (empty = direct). */
  hops?: HopStatus[];
  /** ADR-0024: the touch banner (null = none). Kept after a timeout so the banner can offer Retry. */
  touch?: TouchState | null;
  /** ADR-0027: the latest `gateway_status` (null = no RD Gateway, or not reported yet). */
  gateway?: GatewayStatus | null;
  /** The IpcError code when `session_open` refused (pre-flight), for a readable close reason. */
  openError?: string | null;
}

/** The three-state rail and dot of the design system: a reconnect reads as connecting. */
export function lineState(s: TabState): LineState {
  if (s === "reconnecting") return "connecting";
  if (s === "detached") return "connected";
  return s;
}

/** Protocols whose live session can move to a `detached-<sessionId>` window (ADR-0013). */
export const canDetach = (p: Protocol | null | undefined): boolean => p === "ssh" || p === "rdp" || p === "vnc";
/** rdp/vnc sessions draw MFR1 frames on a canvas instead of a terminal. */
export const isGraphical = (p: Protocol | null | undefined): boolean => p === "rdp" || p === "vnc";
/** Initial desktop request before the canvas has measured itself. */
export const DEFAULT_DESKTOP: Size = { width: 1280, height: 800 };
