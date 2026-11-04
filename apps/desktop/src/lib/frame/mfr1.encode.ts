// MFR1 encoder for the mock transport and tests. Production frames are encoded in Rust
// (`mooring_core::frame`); this mirrors the ADR-0011 layout byte for byte (see mfr1.ts).
import { MFR1_FLAG, MFR1_HEADER, MFR1_KIND, MFR1_MAGIC, MFR1_RECORD, type Mfr1Rect } from "./mfr1";

/** A rect to encode: the decoded shape, with pixel data for `rgba` and `cursor`. */
export type EncodeRect = Mfr1Rect;

export interface EncodeFrame {
  seq: number;
  width: number;
  height: number;
  full?: boolean;
  resized?: boolean;
  rects: EncodeRect[];
}

function extra(r: EncodeRect): number {
  switch (r.kind) {
    case "rgba":
      return r.data.byteLength;
    case "copy":
    case "fill":
      return 4;
    case "cursor":
      return 4 + r.data.byteLength;
    default:
      return 0;
  }
}

const KIND: Record<EncodeRect["kind"], number> = {
  rgba: MFR1_KIND.rgba,
  copy: MFR1_KIND.copy,
  fill: MFR1_KIND.fill,
  cursor: MFR1_KIND.cursor,
  cursor_hidden: MFR1_KIND.cursorHidden,
  cursor_default: MFR1_KIND.cursorDefault,
};

export function encodeMfr1(f: EncodeFrame): ArrayBuffer {
  const total = MFR1_HEADER + f.rects.reduce((a, r) => a + MFR1_RECORD + extra(r), 0);
  const buf = new ArrayBuffer(total);
  const view = new DataView(buf);
  const bytes = new Uint8Array(buf);
  view.setUint32(0, MFR1_MAGIC, true);
  view.setUint32(4, f.seq >>> 0, true);
  view.setUint16(8, f.width, true);
  view.setUint16(10, f.height, true);
  view.setUint16(12, f.rects.length, true);
  view.setUint16(14, (f.full ? MFR1_FLAG.full : 0) | (f.resized ? MFR1_FLAG.resized : 0), true);
  let off = MFR1_HEADER;
  for (const r of f.rects) {
    view.setUint8(off, KIND[r.kind]);
    view.setUint8(off + 1, 0);
    view.setUint16(off + 2, r.x, true);
    view.setUint16(off + 4, r.y, true);
    view.setUint16(off + 6, r.w, true);
    view.setUint16(off + 8, r.h, true);
    off += MFR1_RECORD;
    switch (r.kind) {
      case "rgba":
        bytes.set(r.data, off);
        off += r.data.byteLength;
        break;
      case "copy":
        view.setUint16(off, r.srcX, true);
        view.setUint16(off + 2, r.srcY, true);
        off += 4;
        break;
      case "fill":
        bytes.set(r.rgba, off);
        off += 4;
        break;
      case "cursor":
        view.setUint16(off, r.hotX, true);
        view.setUint16(off + 2, r.hotY, true);
        bytes.set(r.data, off + 4);
        off += 4 + r.data.byteLength;
        break;
      default:
        break;
    }
  }
  return buf;
}

/** w·h RGBA pixels of one colour (tests and the mock). */
export function solid(w: number, h: number, rgba: readonly [number, number, number, number]): Uint8Array {
  const out = new Uint8Array(w * h * 4);
  for (let i = 0; i < out.length; i += 4) out.set(rgba, i);
  return out;
}
