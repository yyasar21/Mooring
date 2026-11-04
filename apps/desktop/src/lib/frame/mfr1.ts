// MFR1 frame messages (ADR-0011 §Frame path), little-endian:
//   header  magic "MFR1" | seq u32 | fbW u16 | fbH u16 | n u16 | flags u16 (1 = full, 2 = resized)
//   record  kind u8 | 0 u8 | x y w h u16, then the kind's own fields:
//           1 RGBA (w·h·4 B) · 2 copy (srcX srcY u16) · 3 fill (rgba[4]) ·
//           4 cursor sprite (hotX hotY u16 + w·h·4 B RGBA, ≤ 384²) · 5 cursor hidden · 6 cursor default
//   limits  n ≤ 256 · fb ≤ 8192² · message ≤ 4·fbW·fbH + 64 KiB
// The bytes come from our own Rust pump, but are still treated as hostile: every length is checked
// before it is read, the record loop is bounded by n, and a bad message throws `Mfr1Error`.
// Pixel payloads are zero-copy `Uint8Array` views into the message buffer.

export const MFR1_MAGIC = 0x3152464d; // "MFR1" read as u32 LE
export const MFR1_HEADER = 16;
export const MFR1_RECORD = 10;
export const MFR1_LIMITS = { maxRects: 256, maxSide: 8192, maxCursor: 384, slack: 64 * 1024 } as const;
export const MFR1_FLAG = { full: 1, resized: 2 } as const;
export const MFR1_KIND = { rgba: 1, copy: 2, fill: 3, cursor: 4, cursorHidden: 5, cursorDefault: 6 } as const;

export type Mfr1ErrorCode = "truncated" | "bad_magic" | "bad_flags" | "bad_kind" | "reserved" | "limit" | "out_of_bounds" | "trailing";

export class Mfr1Error extends Error {
  constructor(
    readonly code: Mfr1ErrorCode,
    message: string,
  ) {
    super(`MFR1 ${code}: ${message}`);
    this.name = "Mfr1Error";
  }
}

export interface RectBase {
  x: number;
  y: number;
  w: number;
  h: number;
}

export type Mfr1Rect =
  | (RectBase & { kind: "rgba"; data: Uint8Array })
  | (RectBase & { kind: "copy"; srcX: number; srcY: number })
  | (RectBase & { kind: "fill"; rgba: [number, number, number, number] })
  | (RectBase & { kind: "cursor"; hotX: number; hotY: number; data: Uint8Array })
  | (RectBase & { kind: "cursor_hidden" })
  | (RectBase & { kind: "cursor_default" });

export interface Mfr1Frame {
  seq: number;
  width: number;
  height: number;
  /** The rects cover the whole framebuffer. */
  full: boolean;
  /** The framebuffer size changed with this message (rects are in the new size). */
  resized: boolean;
  rects: Mfr1Rect[];
}

/** Upper bound of a message for a framebuffer (the ADR limit). */
export function maxMessageBytes(width: number, height: number): number {
  return 4 * width * height + MFR1_LIMITS.slack;
}

export function decodeMfr1(input: ArrayBuffer | Uint8Array): Mfr1Frame {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const len = bytes.byteLength;
  if (len < MFR1_HEADER) throw new Mfr1Error("truncated", `header needs ${MFR1_HEADER} bytes, got ${len}`);
  if (view.getUint32(0, true) !== MFR1_MAGIC) throw new Mfr1Error("bad_magic", "not an MFR1 message");
  const seq = view.getUint32(4, true);
  const width = view.getUint16(8, true);
  const height = view.getUint16(10, true);
  const n = view.getUint16(12, true);
  const flags = view.getUint16(14, true);
  if (flags & ~(MFR1_FLAG.full | MFR1_FLAG.resized)) throw new Mfr1Error("bad_flags", `unknown flag bits 0x${flags.toString(16)}`);
  if (width === 0 || height === 0 || width > MFR1_LIMITS.maxSide || height > MFR1_LIMITS.maxSide) {
    throw new Mfr1Error("limit", `framebuffer ${width}x${height} outside 1..${MFR1_LIMITS.maxSide}`);
  }
  if (n > MFR1_LIMITS.maxRects) throw new Mfr1Error("limit", `${n} rects > ${MFR1_LIMITS.maxRects}`);
  if (len > maxMessageBytes(width, height)) throw new Mfr1Error("limit", `message of ${len} bytes is too large for ${width}x${height}`);

  let off = MFR1_HEADER;
  const need = (bytesNeeded: number, what: string) => {
    if (off + bytesNeeded > len) throw new Mfr1Error("truncated", `${what} needs ${bytesNeeded} bytes at offset ${off}, ${len - off} left`);
  };
  const inside = (x: number, y: number, w: number, h: number, what: string) => {
    if (x + w > width || y + h > height) throw new Mfr1Error("out_of_bounds", `${what} ${w}x${h}@${x},${y} outside ${width}x${height}`);
  };

  const rects: Mfr1Rect[] = [];
  for (let i = 0; i < n; i++) {
    need(MFR1_RECORD, `record ${i}`);
    const kind = view.getUint8(off);
    if (view.getUint8(off + 1) !== 0) throw new Mfr1Error("reserved", `record ${i} reserved byte is not 0`);
    const x = view.getUint16(off + 2, true);
    const y = view.getUint16(off + 4, true);
    const w = view.getUint16(off + 6, true);
    const h = view.getUint16(off + 8, true);
    off += MFR1_RECORD;
    switch (kind) {
      case MFR1_KIND.rgba: {
        inside(x, y, w, h, "rgba rect");
        const size = w * h * 4;
        need(size, `rgba rect ${i}`);
        rects.push({ kind: "rgba", x, y, w, h, data: bytes.subarray(off, off + size) });
        off += size;
        break;
      }
      case MFR1_KIND.copy: {
        need(4, `copy rect ${i}`);
        const srcX = view.getUint16(off, true);
        const srcY = view.getUint16(off + 2, true);
        off += 4;
        inside(x, y, w, h, "copy destination");
        inside(srcX, srcY, w, h, "copy source");
        rects.push({ kind: "copy", x, y, w, h, srcX, srcY });
        break;
      }
      case MFR1_KIND.fill: {
        need(4, `fill rect ${i}`);
        inside(x, y, w, h, "fill rect");
        rects.push({ kind: "fill", x, y, w, h, rgba: [bytes[off] ?? 0, bytes[off + 1] ?? 0, bytes[off + 2] ?? 0, bytes[off + 3] ?? 0] });
        off += 4;
        break;
      }
      case MFR1_KIND.cursor: {
        if (w > MFR1_LIMITS.maxCursor || h > MFR1_LIMITS.maxCursor) throw new Mfr1Error("limit", `cursor ${w}x${h} > ${MFR1_LIMITS.maxCursor}²`);
        need(4, `cursor ${i}`);
        const hotX = view.getUint16(off, true);
        const hotY = view.getUint16(off + 2, true);
        off += 4;
        if (hotX > w || hotY > h) throw new Mfr1Error("out_of_bounds", `cursor hotspot ${hotX},${hotY} outside ${w}x${h}`);
        const size = w * h * 4;
        need(size, `cursor ${i} pixels`);
        rects.push({ kind: "cursor", x, y, w, h, hotX, hotY, data: bytes.subarray(off, off + size) });
        off += size;
        break;
      }
      case MFR1_KIND.cursorHidden:
        rects.push({ kind: "cursor_hidden", x, y, w, h });
        break;
      case MFR1_KIND.cursorDefault:
        rects.push({ kind: "cursor_default", x, y, w, h });
        break;
      default:
        throw new Mfr1Error("bad_kind", `record ${i} has unknown kind ${kind}`);
    }
  }
  if (off !== len) throw new Mfr1Error("trailing", `${len - off} bytes after the last record`);
  return { seq, width, height, full: (flags & MFR1_FLAG.full) !== 0, resized: (flags & MFR1_FLAG.resized) !== 0, rects };
}

/** The `seq` of a message without decoding it (to return the credit of a message that failed to decode). */
export function peekSeq(input: ArrayBuffer | Uint8Array): number | null {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (bytes.byteLength < 8) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getUint32(0, true) === MFR1_MAGIC ? view.getUint32(4, true) : null;
}
