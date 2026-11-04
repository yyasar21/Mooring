// DTOs of the A2 IPC contract: RDP (ADR-0011), VNC (ADR-0012), web sessions and detach (ADR-0013).
// Same conventions as ADR-0008: command args camelCase, session events snake_case on the wire
// (decoded in ipc.decode.session.ts), `IpcError` on failure, no secret or pixel ever outward
// except MFR1 frames on the dedicated `onFrame` channel.
import type { Protocol, SessionEventHandler, Size } from "./ipc.types";

// ---------- per-protocol connection options (connection.options, migration 0005) ----------

export type ClipboardPolicy = "off" | "to_remote" | "from_remote" | "both";
export const CLIPBOARD_POLICIES: readonly ClipboardPolicy[] = ["off", "to_remote", "from_remote", "both"];
export type MaxFps = 30 | 60;

/** ADR-0011 closed KLID list; 0x0409 en-US is the default. */
export const KEYBOARD_LAYOUTS = [0x0409, 0x041f, 0x1041f, 0x0407, 0x040c, 0x0809, 0x0410, 0x040a, 0x0419] as const;
export type KeyboardLayout = (typeof KEYBOARD_LAYOUTS)[number];

export interface RdpConnOptions {
  keyboardLayout: KeyboardLayout;
  clipboard: ClipboardPolicy;
  allowTlsWithoutNla: boolean;
  /** Certificate PEM blocks only, ≤ 64 KiB (B-3). */
  caPem: string | null;
  maxFps: MaxFps;
}

export type VncSecurity = "require_tls" | "prefer_tls" | "allow_plaintext";

export interface VncConnOptions {
  security: VncSecurity;
  viewOnly: boolean;
  shared: boolean;
  clipboard: ClipboardPolicy;
  caPem: string | null;
  maxFps: MaxFps;
}

export interface WebConnOptions {
  /** `https://` (or `http://` with `allowHttp`), no `user:pass@`. */
  url: string;
  /** Exact origins (`scheme://host[:port]`), ≤ 16, no wildcards. */
  allowedOrigins: string[];
  persistent: boolean;
  allowHttp: boolean;
}

/** The serde type for the connection's protocol; `{}` for protocols without options. */
export type ProtocolOptions = RdpConnOptions | VncConnOptions | WebConnOptions | Record<string, never>;

export const DEFAULT_RDP_OPTIONS: RdpConnOptions = {
  keyboardLayout: 0x0409,
  clipboard: "both",
  allowTlsWithoutNla: false,
  caPem: null,
  maxFps: 30,
};

export const DEFAULT_WEB_OPTIONS: WebConnOptions = { url: "", allowedOrigins: [], persistent: false, allowHttp: false };

/** Rust caps (mooring_core::options): ≤ 16 extra origins, URLs ≤ 2048 bytes, CA PEM ≤ 64 KiB, options ≤ 128 KiB. */
export const OPTION_LIMITS = { maxAllowedOrigins: 16, maxUrl: 2048, maxCaPem: 64 * 1024, maxOptionsJson: 128 * 1024 } as const;
export const MAX_FPS_VALUES: readonly MaxFps[] = [30, 60];
export const VNC_SECURITIES: readonly VncSecurity[] = ["require_tls", "prefer_tls", "allow_plaintext"];

export const DEFAULT_VNC_OPTIONS: VncConnOptions = {
  security: "prefer_tls",
  viewOnly: false,
  shared: true,
  clipboard: "both",
  caPem: null,
  maxFps: 30,
};

// ---------- session events (ADR-0011 SessionEvent changes) ----------

export type CloseCode =
  | "user"
  | "network"
  | "auth_failed"
  | "trust_rejected"
  | "trust_mismatch"
  | "server_ended"
  | "protocol_error"
  | "vault_locked";
export const CLOSE_CODES: readonly CloseCode[] = [
  "user", "network", "auth_failed", "trust_rejected", "trust_mismatch", "server_ended", "protocol_error", "vault_locked",
];

export type CertificateProblem = "self_signed" | "unknown_issuer" | "name_mismatch" | "expired" | "not_yet_valid";
export const CERTIFICATE_PROBLEMS: readonly CertificateProblem[] = ["self_signed", "unknown_issuer", "name_mismatch", "expired", "not_yet_valid"];

/** The leaf a `certificate_trust` prompt asks about. Strings are server-controlled: display only. */
export interface CertificateInfo {
  subject: string;
  issuer: string;
  /** RFC 3339. */
  notBefore: string;
  notAfter: string;
  /** Hex SHA-256 of the leaf DER. */
  sha256: string;
  /** Subject alternative names (DNS names and IP addresses as text). */
  san: string[];
  problems: CertificateProblem[];
}

/** One MFR1 message from the `onFrame` channel. The UI must ack its `seq` once drawn. */
export type FrameHandler = (message: ArrayBuffer) => void;

/** ADR-0011 reconnect schedule: 1, 2, 4, 8, 16, 30 s (±20 %), at most 6 attempts. */
export const RECONNECT_MAX_ATTEMPTS = 6;

// ---------- inputs ----------

/** ADR-0011 pointer buttons (not the DOM order): 1 left, 2 middle, 4 right, 8 back, 16 forward. */
export const POINTER_BUTTON = { left: 1, middle: 2, right: 4, back: 8, forward: 16 } as const;
/** One wheel notch. */
export const WHEEL_NOTCH = 120;
export const INPUT_LIMITS = { codeChars: 32, keyBytes: 32, unicodeChars: 64, minDesktop: 200, maxDesktop: 8192 } as const;

// ---------- trust store ----------

export interface KnownCert {
  /** `|2|salt|hmac` form: the host is never stored in the clear. */
  hostHash: string;
  fingerprint: string;
  addedAt: string;
}

// ---------- web sessions (ADR-0013) ----------

export type WebEvent =
  | { kind: "title"; title: string }
  | { kind: "navigated"; origin: string }
  | { kind: "blocked"; origin: string }
  | { kind: "download_blocked"; origin: string }
  | { kind: "closed" };
export type WebEventHandler = (event: WebEvent) => void;

export interface WebWindowInfo {
  connectionId: string;
  windowLabel: string;
  origin: string;
  title: string;
  persistent: boolean;
  openedAt: string;
}

export const WEB_ZOOM = { min: 0.25, max: 5 } as const;

/** `session_attach` result: what the attaching view needs to draw the session. */
export interface AttachedSession {
  protocol: Protocol;
  state: string;
  size: Size;
}

// ---------- commands ----------

export interface RemoteIpc {
  /** Return one frame credit (passive: in POLLED_COMMANDS). */
  sessionFrameAck(args: { sessionId: string; seq: number }): Promise<void>;
  /** Rust copies its framebuffer to the OS clipboard as an image; no pixels come back. */
  sessionScreenshot(args: { sessionId: string }): Promise<Size>;
  /** VNC only; Rust enforces it (drops input), the UI flag is advisory. */
  sessionSetViewOnly(args: { sessionId: string; viewOnly: boolean }): Promise<void>;

  /** The plain per-protocol object with defaults filled in; `{}` for protocols without options. */
  connectionOptionsGet(args: { connectionId: string }): Promise<ProtocolOptions>;
  /** Replaces every option (`input.invalid` for unknown fields, wrong protocol, maxFps ∉ {30,60}). */
  connectionOptionsSet(args: { connectionId: string; options: ProtocolOptions }): Promise<ProtocolOptions>;

  knownCertsList(args: { protocol: "rdp" | "vnc" }): Promise<KnownCert[]>;
  knownCertsRemove(args: { protocol: "rdp" | "vnc"; host: string; port: number }): Promise<{ removed: number }>;

  webOpen(args: { connectionId: string; onEvent: WebEventHandler }): Promise<{ windowLabel: string }>;
  webClose(args: { connectionId: string }): Promise<void>;
  webFocus(args: { connectionId: string }): Promise<void>;
  webReload(args: { connectionId: string }): Promise<void>;
  webPrint(args: { connectionId: string }): Promise<void>;
  webClearData(args: { connectionId: string }): Promise<void>;
  webZoom(args: { connectionId: string; factor: number }): Promise<void>;
  webList(): Promise<WebWindowInfo[]>;

  windowAttach(args: { sessionId: string }): Promise<void>;
  sessionAttach(args: { sessionId: string; onEvent: SessionEventHandler; onFrame?: FrameHandler }): Promise<AttachedSession>;
}
