// Wire decoding for session channels (snake_case `mooring_core` serde shapes) and the A2 commands.
// Decoders never throw: an unknown event kind closes the tab, unknown enum values fall back to
// the safest choice (never the trust dialog, never a known close code).
import type {
  CertificateInfo,
  CertificateProblem,
  CloseCode,
  KnownCert,
  PromptAccount,
  PromptPurpose,
  Protocol,
  SessionEvent,
  SessionInput,
  WebEvent,
  WebWindowInfo,
} from "./ipc.types";
import { CERTIFICATE_PROBLEMS, CLOSE_CODES } from "./ipc.types.remote";

type WireRecord = Record<string, unknown>;

const rec = (raw: unknown): WireRecord => (typeof raw === "object" && raw !== null ? raw : {}) as WireRecord;
const str = (v: unknown): string => (typeof v === "string" ? v : "");
const num = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) ? v : 0);
const optStr = (v: unknown): string | null => (typeof v === "string" ? v : null);
/** snake_case first (session events), camelCase tolerated. */
const field = (w: WireRecord, snake: string, camel: string): unknown => (snake in w ? w[snake] : w[camel]);

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToBase64(data: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < data.length; i += 0x8000) {
    bin += String.fromCharCode(...data.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

/**
 * Decode one channel message. Strict: only the kinds of `mooring_core::SessionEvent` (plus R5's
 * `detached`/`attached`) are recognised; anything else becomes a `closed` event so the tab never
 * hangs on a message it cannot interpret.
 */
export function decodeSessionEvent(raw: unknown): SessionEvent {
  const w = rec(raw);
  switch (w.kind) {
    case "connected":
      return {
        kind: "connected",
        protocol: str(w.protocol) as Protocol,
        peerIdentity: optStr(field(w, "peer_identity", "peerIdentity")),
        security: optStr(w.security),
      };
    case "bytes":
      return { kind: "bytes", data: base64ToBytes(str(w.data)) };
    case "prompt": {
      const purpose = promptPurpose(w.purpose);
      return {
        kind: "prompt",
        id: num(w.id),
        message: str(w.message),
        secret: w.secret === true,
        purpose,
        account: purpose === "credential" ? promptAccount(w.account) : null,
        certificate: purpose === "certificate_trust" ? decodeCertificate(w.certificate) : null,
      };
    }
    case "desktop_resized":
      return { kind: "desktop_resized", width: num(w.width), height: num(w.height) };
    case "reconnecting":
      return { kind: "reconnecting", attempt: num(w.attempt), delayMs: num(field(w, "delay_ms", "delayMs")) };
    case "detached":
      return { kind: "detached" };
    case "attached":
      return { kind: "attached" };
    case "closed":
      return { kind: "closed", reason: str(w.reason), code: closeCode(w.code) };
    default:
      return { kind: "closed", reason: "unrecognised session event", code: "unknown" };
  }
}

function closeCode(v: unknown): CloseCode | "unknown" {
  return CLOSE_CODES.includes(v as CloseCode) ? (v as CloseCode) : "unknown";
}

/** Unknown or missing purposes fall back to "other": never a trust dialog. */
function promptPurpose(v: unknown): PromptPurpose {
  return v === "host_key_trust" || v === "certificate_trust" || v === "keyboard_interactive" || v === "credential" ? v : "other";
}

/** `account` of a credential prompt (snake_case on the wire). Missing = ask for everything. */
function promptAccount(raw: unknown): PromptAccount {
  const w = rec(raw);
  return {
    username: optStr(w.username),
    domain: optStr(w.domain),
    needsUsername: w.needs_username !== false,
    needsDomain: w.needs_domain === true,
  };
}

/** More names than any sane certificate carries; the rest is not shown. */
const MAX_SAN = 64;

/** A `certificate_trust` prompt without a certificate is still a trust prompt, shown with blanks. */
export function decodeCertificate(raw: unknown): CertificateInfo {
  const w = rec(raw);
  const problems = Array.isArray(w.problems) ? w.problems : [];
  return {
    subject: str(w.subject),
    issuer: str(w.issuer),
    notBefore: str(field(w, "not_before", "notBefore")),
    notAfter: str(field(w, "not_after", "notAfter")),
    sha256: str(w.sha256),
    san: (Array.isArray(w.san) ? w.san : []).filter((n): n is string => typeof n === "string").slice(0, MAX_SAN),
    problems: problems.filter((p): p is CertificateProblem => CERTIFICATE_PROBLEMS.includes(p as CertificateProblem)),
  };
}

export function encodeSessionInput(input: SessionInput): WireRecord {
  switch (input.kind) {
    case "bytes":
      return { kind: "bytes", data: bytesToBase64(input.data) };
    default:
      return { ...input };
  }
}

/**
 * A raw `Channel` message as the WebView hands it over: an ArrayBuffer for binary bodies; a typed
 * array or a JSON number array are accepted too, anything else is dropped (null).
 */
export function frameBuffer(msg: unknown): ArrayBuffer | null {
  if (msg instanceof ArrayBuffer) return msg;
  if (ArrayBuffer.isView(msg)) {
    return new Uint8Array(msg.buffer, msg.byteOffset, msg.byteLength).slice().buffer;
  }
  if (Array.isArray(msg) && msg.every((b) => typeof b === "number")) return Uint8Array.from(msg).buffer;
  return null;
}

export function decodeKnownCert(raw: unknown): KnownCert {
  const w = rec(raw);
  const out: KnownCert = { hostHash: str(field(w, "host_hash", "hostHash")), fingerprint: str(w.fingerprint), addedAt: str(field(w, "added_at", "addedAt")) };
  const port = w.port;
  if (typeof w.host === "string" && w.host !== "" && typeof port === "number" && Number.isInteger(port) && port >= 1 && port <= 65535) {
    out.host = w.host;
    out.port = port;
  }
  return out;
}

export function decodeWebEvent(raw: unknown): WebEvent {
  const w = rec(raw);
  switch (w.kind) {
    case "title":
      return { kind: "title", title: str(w.title) };
    case "navigated":
    case "blocked":
    case "download_blocked":
      return { kind: w.kind, origin: str(w.origin) };
    default:
      return { kind: "closed" };
  }
}

export function decodeWebWindow(raw: unknown): WebWindowInfo {
  const w = rec(raw);
  return {
    connectionId: str(field(w, "connection_id", "connectionId")),
    windowLabel: str(field(w, "window_label", "windowLabel")),
    origin: str(w.origin),
    title: str(w.title),
    persistent: w.persistent === true,
    openedAt: str(field(w, "opened_at", "openedAt")),
  };
}
