// Pure mapping from DOM input to ADR-0011 `SessionInput`, and the letterbox layout. Kept free of
// React and the DOM tree so it can be tested exhaustively.
import { INPUT_LIMITS, POINTER_BUTTON, WHEEL_NOTCH, type SessionInput, type Size } from "../../lib/ipc";

/** DOM `MouseEvent.buttons` bits: 1 left, 2 right, 4 middle, 8 back, 16 forward. */
export function remoteButtons(domButtons: number): number {
  let out = 0;
  if (domButtons & 1) out |= POINTER_BUTTON.left;
  if (domButtons & 2) out |= POINTER_BUTTON.right;
  if (domButtons & 4) out |= POINTER_BUTTON.middle;
  if (domButtons & 8) out |= POINTER_BUTTON.back;
  if (domButtons & 16) out |= POINTER_BUTTON.forward;
  return out;
}

export interface Box {
  left: number;
  top: number;
  width: number;
  height: number;
}

/** A client point on the displayed canvas → framebuffer pixel, clamped to the framebuffer. */
export function toFramebuffer(clientX: number, clientY: number, box: Box, fb: Size): { x: number; y: number } {
  const fx = box.width > 0 ? ((clientX - box.left) / box.width) * fb.width : 0;
  const fy = box.height > 0 ? ((clientY - box.top) / box.height) * fb.height : 0;
  const clamp = (v: number, max: number) => Math.max(0, Math.min(max - 1, Math.floor(v)));
  return { x: clamp(fx, fb.width), y: clamp(fy, fb.height) };
}

/** Where the framebuffer sits inside the container: aspect kept, shrunk to fit, never enlarged, centred. */
export function letterbox(container: Size, fb: Size): Box & { scale: number } {
  if (container.width <= 0 || container.height <= 0 || fb.width <= 0 || fb.height <= 0) return { left: 0, top: 0, width: 0, height: 0, scale: 0 };
  const scale = Math.min(container.width / fb.width, container.height / fb.height, 1);
  const width = Math.round(fb.width * scale);
  const height = Math.round(fb.height * scale);
  return { left: Math.floor((container.width - width) / 2), top: Math.floor((container.height - height) / 2), width, height, scale };
}

/** Backing-store size of the WebGL canvas: the displayed CSS size times the device pixel ratio. */
export function backingSize(display: Size, dpr: number): Size {
  const r = Number.isFinite(dpr) && dpr > 0 ? Math.min(dpr, 4) : 1;
  return { width: Math.max(1, Math.round(display.width * r)), height: Math.max(1, Math.round(display.height * r)) };
}

/** The desktop size to ask the server for: the container in CSS pixels, clamped, even width. */
export function desktopRequest(container: Size): Size {
  const c = (v: number) => Math.max(INPUT_LIMITS.minDesktop, Math.min(INPUT_LIMITS.maxDesktop, Math.floor(v)));
  return { width: c(container.width) & ~1, height: c(container.height) };
}

const DELTA_LINE = 40;
const DELTA_PAGE = 360;

/**
 * Wheel deltas → 120-per-notch units (DOM sign: positive = down/right). Fractions carry over in
 * `acc` so a touchpad's small pixel steps still add up; each axis is clamped to i16.
 */
export function wheelInput(
  e: { deltaX: number; deltaY: number; deltaMode: number },
  acc: { x: number; y: number },
): SessionInput | null {
  const k = e.deltaMode === 1 ? DELTA_LINE : e.deltaMode === 2 ? DELTA_PAGE : WHEEL_NOTCH / 100;
  acc.x += e.deltaX * k;
  acc.y += e.deltaY * k;
  const dx = Math.trunc(acc.x);
  const dy = Math.trunc(acc.y);
  acc.x -= dx;
  acc.y -= dy;
  if (dx === 0 && dy === 0) return null;
  const i16 = (v: number) => Math.max(-32768, Math.min(32767, v));
  return { kind: "wheel", dx: i16(dx), dy: i16(dy) };
}

const enc = new TextEncoder();

/** A key event → `key` input, or null when it must not be sent (IME composing, bad `code`). */
export function keyInput(e: { code: string; key: string; isComposing?: boolean; keyCode?: number }, pressed: boolean): SessionInput | null {
  if (e.isComposing === true || e.keyCode === 229) return null;
  if (e.code === "" || e.code.length > INPUT_LIMITS.codeChars || !/^[\x21-\x7e]+$/.test(e.code)) return null;
  const key = enc.encode(e.key).length <= INPUT_LIMITS.keyBytes ? e.key : "";
  return { kind: "key", code: e.code, key, pressed };
}

/** IME-composed text → `unicode` inputs of ≤ 64 code points each. */
export function unicodeInputs(text: string): SessionInput[] {
  const cps = Array.from(text);
  const out: SessionInput[] = [];
  for (let i = 0; i < cps.length; i += INPUT_LIMITS.unicodeChars) {
    out.push({ kind: "unicode", text: cps.slice(i, i + INPUT_LIMITS.unicodeChars).join("") });
  }
  return out;
}

const MODIFIERS: { flag: "shiftKey" | "ctrlKey" | "altKey" | "metaKey"; codes: [string, string] }[] = [
  { flag: "shiftKey", codes: ["ShiftLeft", "ShiftRight"] },
  { flag: "ctrlKey", codes: ["ControlLeft", "ControlRight"] },
  { flag: "altKey", codes: ["AltLeft", "AltRight"] },
  { flag: "metaKey", codes: ["MetaLeft", "MetaRight"] },
];

const MOD_KEY: Record<string, string> = { shiftKey: "Shift", ctrlKey: "Control", altKey: "Alt", metaKey: "Meta" };

/**
 * Bring the remote modifier state in line with the event's: a modifier we think is down but the
 * event says is up (released while focus was elsewhere) is released; one that is down but never
 * seen (pressed before focus) is pressed as its left key. Mutates `down`.
 */
export function syncModifiers(
  e: { shiftKey: boolean; ctrlKey: boolean; altKey: boolean; metaKey: boolean },
  down: Set<string>,
  skipCode?: string,
): SessionInput[] {
  const out: SessionInput[] = [];
  for (const m of MODIFIERS) {
    if (skipCode !== undefined && m.codes.includes(skipCode)) continue;
    const held = m.codes.filter((c) => down.has(c));
    const key = MOD_KEY[m.flag] ?? "";
    if (!e[m.flag]) {
      for (const c of held) {
        down.delete(c);
        out.push({ kind: "key", code: c, key, pressed: false });
      }
    } else if (held.length === 0) {
      down.add(m.codes[0]);
      out.push({ kind: "key", code: m.codes[0], key, pressed: true });
    }
  }
  return out;
}
