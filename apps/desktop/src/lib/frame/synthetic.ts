// A synthetic remote desktop for the mock transport: a dark grid background (one full frame),
// then a moving gradient band swept down the screen as one RGBA dirty rect per tick, a blinking
// fill rect, and a cursor sprite. Lets the RDP/VNC panel be demoed without Rust.
import { encodeMfr1, solid, type EncodeRect } from "./mfr1.encode";

const BAND = 48;
const STEP = 8;

function hsv(h: number, s: number, v: number): [number, number, number] {
  const f = (n: number) => {
    const k = (n + h / 60) % 6;
    return Math.round(255 * (v - v * s * Math.max(0, Math.min(k, 4 - k, 1))));
  };
  return [f(5), f(3), f(1)];
}

function background(w: number, h: number): Uint8Array {
  const px = solid(w, h, [6, 12, 17, 255]);
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      if (x % 32 === 0 || y % 32 === 0) px.set([14, 38, 46, 255], (y * w + x) * 4);
    }
  }
  return px;
}

/** A 12×19 arrow cursor in the accent colour. */
function arrow(): { w: number; h: number; data: Uint8Array } {
  const w = 12;
  const h = 19;
  const data = new Uint8Array(w * h * 4);
  for (let y = 0; y < h; y++) {
    const span = Math.min(y, w - 1);
    for (let x = 0; x <= span; x++) {
      const edge = x === 0 || x === span || y === h - 1;
      data.set(edge ? [1, 20, 23, 255] : [41, 230, 242, 255], (y * w + x) * 4);
    }
  }
  return { w, h, data };
}

export class SyntheticDesktop {
  private band = 0;
  private sent = false;
  private resized = false;

  constructor(
    public width: number,
    public height: number,
  ) {}

  resize(width: number, height: number): void {
    this.width = width;
    this.height = height;
    this.band = 0;
    this.sent = false;
    this.resized = true;
  }

  /** The next message: a full frame first (and after a resize), then one band per tick. */
  next(seq: number, nowMs: number): ArrayBuffer {
    const { width: w, height: h } = this;
    if (!this.sent) {
      this.sent = true;
      const resized = this.resized;
      this.resized = false;
      const cur = arrow();
      const rects: EncodeRect[] = [
        { kind: "rgba", x: 0, y: 0, w, h, data: background(w, h) },
        { kind: "cursor", x: 0, y: 0, w: cur.w, h: cur.h, hotX: 0, hotY: 0, data: cur.data },
      ];
      return encodeMfr1({ seq, width: w, height: h, full: true, resized, rects });
    }
    const y = this.band;
    const bh = Math.min(BAND, h - y);
    const row = new Uint8Array(w * 4);
    const phase = (nowMs / 20) % 360;
    for (let x = 0; x < w; x++) {
      const [r, g, b] = hsv((phase + (x / w) * 240) % 360, 0.85, 0.9);
      row.set([r, g, b, 255], x * 4);
    }
    const band = new Uint8Array(w * bh * 4);
    for (let i = 0; i < bh; i++) band.set(row, i * w * 4);
    this.band = y + STEP >= h ? 0 : y + STEP;
    const on = Math.floor(nowMs / 500) % 2 === 0;
    const rects: EncodeRect[] = [{ kind: "rgba", x: 0, y, w, h: bh, data: band }];
    if (w >= 40 && h >= 40) rects.push({ kind: "fill", x: w - 28, y: 12, w: 16, h: 16, rgba: on ? [255, 59, 141, 255] : [6, 12, 17, 255] });
    return encodeMfr1({ seq, width: w, height: h, rects });
  }
}
