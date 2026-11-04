// MFR1 decoder against hand-built buffers (ADR-0011 wire layout), plus hostile input.
import { decodeMfr1, maxMessageBytes, Mfr1Error, peekSeq, type Mfr1ErrorCode } from "./mfr1";
import { encodeMfr1, solid } from "./mfr1.encode";
import { SyntheticDesktop } from "./synthetic";

/** Little-endian byte builder, so the vectors below are written out field by field. */
class Bytes {
  private out: number[] = [];
  u8(...v: number[]) { this.out.push(...v.map((x) => x & 0xff)); return this; }
  u16(...v: number[]) { for (const x of v) this.out.push(x & 0xff, (x >> 8) & 0xff); return this; }
  u32(x: number) { return this.u16(x & 0xffff, (x >>> 16) & 0xffff); }
  ascii(s: string) { return this.u8(...Array.from(s, (c) => c.charCodeAt(0))); }
  header(seq: number, w: number, h: number, n: number, flags: number) { return this.ascii("MFR1").u32(seq).u16(w, h, n, flags); }
  record(kind: number, x: number, y: number, w: number, h: number) { return this.u8(kind, 0).u16(x, y, w, h); }
  get buffer(): ArrayBuffer { return new Uint8Array(this.out).buffer; }
}

function code(fn: () => unknown): Mfr1ErrorCode | "no error" {
  try {
    fn();
    return "no error";
  } catch (e: unknown) {
    if (e instanceof Mfr1Error) return e.code;
    throw e;
  }
}

describe("MFR1 decoder", () => {
  it("reads the header fields little-endian", () => {
    const b = new Bytes().header(0x01020304, 1920, 1080, 0, 3).buffer;
    expect(new Uint8Array(b).slice(0, 16)).toEqual(new Uint8Array([0x4d, 0x46, 0x52, 0x31, 4, 3, 2, 1, 0x80, 7, 0x38, 4, 0, 0, 3, 0]));
    expect(decodeMfr1(b)).toEqual({ seq: 0x01020304, width: 1920, height: 1080, full: true, resized: true, rects: [] });
    expect(peekSeq(b)).toBe(0x01020304);
  });

  it("decodes every record kind in order, with zero-copy pixel views", () => {
    const b = new Bytes()
      .header(9, 64, 48, 6, 0)
      .record(1, 2, 3, 2, 1).u8(1, 2, 3, 4, 5, 6, 7, 8)
      .record(2, 10, 10, 4, 4).u16(0, 0)
      .record(3, 0, 40, 64, 8).u8(255, 59, 141, 255)
      .record(4, 5, 6, 1, 2).u16(0, 1).u8(9, 9, 9, 9, 8, 8, 8, 8)
      .record(5, 0, 0, 0, 0)
      .record(6, 0, 0, 0, 0)
      .buffer;
    const f = decodeMfr1(b);
    expect(f).toMatchObject({ seq: 9, width: 64, height: 48, full: false, resized: false });
    expect(f.rects.map((r) => r.kind)).toEqual(["rgba", "copy", "fill", "cursor", "cursor_hidden", "cursor_default"]);
    const [rgba, copy, fill, cursor] = f.rects;
    expect(rgba).toMatchObject({ x: 2, y: 3, w: 2, h: 1 });
    expect(rgba?.kind === "rgba" && [...rgba.data]).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(rgba?.kind === "rgba" && rgba.data.buffer).toBe(b);
    expect(copy).toEqual({ kind: "copy", x: 10, y: 10, w: 4, h: 4, srcX: 0, srcY: 0 });
    expect(fill).toEqual({ kind: "fill", x: 0, y: 40, w: 64, h: 8, rgba: [255, 59, 141, 255] });
    expect(cursor).toMatchObject({ kind: "cursor", w: 1, h: 2, hotX: 0, hotY: 1 });
    expect(cursor?.kind === "cursor" && [...cursor.data]).toEqual([9, 9, 9, 9, 8, 8, 8, 8]);
  });

  it("accepts a Uint8Array view at an offset", () => {
    const inner = new Uint8Array(new Bytes().header(1, 2, 2, 1, 1).record(3, 0, 0, 2, 2).u8(1, 1, 1, 1).buffer);
    const outer = new Uint8Array(inner.length + 5);
    outer.set(inner, 5);
    expect(decodeMfr1(outer.subarray(5)).rects).toHaveLength(1);
  });

  it("round-trips the mock encoder and the synthetic desktop", () => {
    const px = solid(3, 2, [1, 2, 3, 255]);
    const f = decodeMfr1(encodeMfr1({ seq: 4, width: 8, height: 8, full: true, rects: [{ kind: "rgba", x: 5, y: 6, w: 3, h: 2, data: px }] }));
    expect(f.rects[0]?.kind === "rgba" && f.rects[0].data).toEqual(px);
    const d = new SyntheticDesktop(320, 200);
    const first = decodeMfr1(d.next(1, 0));
    expect(first).toMatchObject({ full: true, width: 320, height: 200 });
    expect(first.rects.map((r) => r.kind)).toEqual(["rgba", "cursor"]);
    const band = decodeMfr1(d.next(2, 40));
    expect(band.full).toBe(false);
    expect(band.rects.map((r) => r.kind)).toEqual(["rgba", "fill"]);
    d.resize(400, 300);
    expect(decodeMfr1(d.next(3, 80))).toMatchObject({ full: true, resized: true, width: 400, height: 300 });
  });

  it("rejects malformed headers with a typed error", () => {
    expect(code(() => decodeMfr1(new ArrayBuffer(0)))).toBe("truncated");
    expect(code(() => decodeMfr1(new Bytes().header(1, 2, 2, 0, 0).buffer.slice(0, 15)))).toBe("truncated");
    expect(code(() => decodeMfr1(new Bytes().ascii("MFR2").u32(1).u16(2, 2, 0, 0).buffer))).toBe("bad_magic");
    expect(code(() => decodeMfr1(new Bytes().header(1, 2, 2, 0, 4).buffer))).toBe("bad_flags");
    expect(code(() => decodeMfr1(new Bytes().header(1, 0, 2, 0, 0).buffer))).toBe("limit");
    expect(code(() => decodeMfr1(new Bytes().header(1, 8193, 2, 0, 0).buffer))).toBe("limit");
    expect(code(() => decodeMfr1(new Bytes().header(1, 2, 2, 257, 0).buffer))).toBe("limit");
    expect(peekSeq(new ArrayBuffer(4))).toBeNull();
  });

  it("rejects truncated, out-of-bounds, unknown and trailing records", () => {
    const base = () => new Bytes().header(1, 16, 16, 1, 0);
    expect(code(() => decodeMfr1(base().buffer))).toBe("truncated"); // n = 1, no record
    expect(code(() => decodeMfr1(base().record(1, 0, 0, 2, 2).u8(1, 2, 3).buffer))).toBe("truncated");
    expect(code(() => decodeMfr1(base().record(2, 0, 0, 2, 2).u16(1).buffer))).toBe("truncated");
    expect(code(() => decodeMfr1(base().record(3, 0, 0, 2, 2).u8(1, 2).buffer))).toBe("truncated");
    expect(code(() => decodeMfr1(base().record(1, 15, 0, 2, 1).u8(...new Array<number>(8).fill(0)).buffer))).toBe("out_of_bounds");
    expect(code(() => decodeMfr1(base().record(3, 0, 0, 16, 17).u8(0, 0, 0, 0).buffer))).toBe("out_of_bounds");
    expect(code(() => decodeMfr1(base().record(2, 0, 0, 4, 4).u16(13, 0).buffer))).toBe("out_of_bounds");
    expect(code(() => decodeMfr1(base().record(4, 0, 0, 385, 1).u16(0, 0).buffer))).toBe("limit");
    expect(code(() => decodeMfr1(base().record(4, 0, 0, 1, 1).u16(2, 0).u8(0, 0, 0, 0).buffer))).toBe("out_of_bounds");
    expect(code(() => decodeMfr1(base().record(7, 0, 0, 0, 0).buffer))).toBe("bad_kind");
    expect(code(() => decodeMfr1(new Bytes().header(1, 16, 16, 1, 0).u8(5, 1).u16(0, 0, 0, 0).buffer))).toBe("reserved");
    expect(code(() => decodeMfr1(base().record(5, 0, 0, 0, 0).u8(0).buffer))).toBe("trailing");
  });

  it("rejects a message larger than the framebuffer allows before reading records", () => {
    const big = new Uint8Array(maxMessageBytes(1, 1) + 1);
    big.set(new Uint8Array(new Bytes().header(1, 1, 1, 0, 0).buffer));
    expect(code(() => decodeMfr1(big))).toBe("limit");
  });

  it("never hangs or throws anything but Mfr1Error on random and mutated input", () => {
    let seed = 0x2f6b1d;
    const rnd = () => {
      seed = (Math.imul(seed, 1103515245) + 12345) >>> 0;
      return seed;
    };
    const valid = new Uint8Array(new SyntheticDesktop(64, 48).next(1, 0));
    const started = performance.now();
    for (let i = 0; i < 2000; i++) {
      const mutated = valid.slice(0, 16 + (rnd() % (valid.length - 15)));
      for (let k = 0; k < 4; k++) mutated[rnd() % mutated.length] = rnd() & 0xff;
      const noise = new Uint8Array(rnd() % 96);
      for (let k = 0; k < noise.length; k++) noise[k] = rnd() & 0xff;
      if (i % 3 === 0) noise.set([0x4d, 0x46, 0x52, 0x31].slice(0, noise.length));
      for (const input of [mutated, noise]) {
        try {
          decodeMfr1(input);
        } catch (e: unknown) {
          expect(e).toBeInstanceOf(Mfr1Error);
        }
      }
    }
    expect(performance.now() - started).toBeLessThan(5000);
  });
});
