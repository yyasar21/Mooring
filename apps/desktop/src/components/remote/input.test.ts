import { backingSize, desktopRequest, keyInput, letterbox, remoteButtons, syncModifiers, toFramebuffer, unicodeInputs, wheelInput } from "./input";
import { FrameStats } from "./stats";

describe("remote input mapping", () => {
  it("reorders DOM buttons to left 1, middle 2, right 4, back 8, forward 16", () => {
    expect([1, 2, 4, 8, 16, 0, 31].map(remoteButtons)).toEqual([1, 4, 2, 8, 16, 0, 31]);
  });

  it("maps and clamps client points to framebuffer pixels", () => {
    const box = { left: 100, top: 50, width: 640, height: 400 };
    const fb = { width: 1280, height: 800 };
    expect(toFramebuffer(100, 50, box, fb)).toEqual({ x: 0, y: 0 });
    expect(toFramebuffer(420, 250, box, fb)).toEqual({ x: 640, y: 400 });
    expect(toFramebuffer(10_000, -10, box, fb)).toEqual({ x: 1279, y: 0 });
    expect(toFramebuffer(5, 5, { left: 0, top: 0, width: 0, height: 0 }, fb)).toEqual({ x: 0, y: 0 });
  });

  it("letterboxes: keeps the aspect, shrinks to fit, never enlarges, centres", () => {
    expect(letterbox({ width: 1000, height: 1000 }, { width: 2000, height: 1000 })).toEqual({ left: 0, top: 250, width: 1000, height: 500, scale: 0.5 });
    expect(letterbox({ width: 1000, height: 800 }, { width: 800, height: 600 })).toEqual({ left: 100, top: 100, width: 800, height: 600, scale: 1 });
    expect(letterbox({ width: 0, height: 800 }, { width: 800, height: 600 }).width).toBe(0);
  });

  it("sizes the WebGL backing store by the device pixel ratio", () => {
    expect(backingSize({ width: 800, height: 600 }, 2)).toEqual({ width: 1600, height: 1200 });
    expect(backingSize({ width: 801, height: 601 }, 1.25)).toEqual({ width: 1001, height: 751 });
    expect(backingSize({ width: 10, height: 10 }, Number.NaN)).toEqual({ width: 10, height: 10 });
    expect(backingSize({ width: 10, height: 10 }, 9)).toEqual({ width: 40, height: 40 });
  });

  it("asks for a clamped desktop with an even width", () => {
    expect(desktopRequest({ width: 1281.7, height: 799 })).toEqual({ width: 1280, height: 799 });
    expect(desktopRequest({ width: 50, height: 9000 })).toEqual({ width: 200, height: 8192 });
  });

  it("turns wheel deltas into 120-per-notch steps and carries fractions", () => {
    const acc = { x: 0, y: 0 };
    expect(wheelInput({ deltaX: 0, deltaY: 100, deltaMode: 0 }, acc)).toEqual({ kind: "wheel", dx: 0, dy: 120 });
    expect(wheelInput({ deltaX: 0.4, deltaY: 0, deltaMode: 0 }, acc)).toBeNull();
    expect(wheelInput({ deltaX: 0.5, deltaY: 0, deltaMode: 0 }, acc)).toEqual({ kind: "wheel", dx: 1, dy: 0 });
    expect(wheelInput({ deltaX: 0, deltaY: 1, deltaMode: 2 }, acc)).toEqual({ kind: "wheel", dx: 0, dy: 360 });
    expect(wheelInput({ deltaX: 0, deltaY: 1e6, deltaMode: 1 }, { x: 0, y: 0 })).toEqual({ kind: "wheel", dx: 0, dy: 32767 });
  });

  it("validates key codes and skips IME keydowns", () => {
    expect(keyInput({ code: "Digit1", key: "!" }, true)).toEqual({ kind: "key", code: "Digit1", key: "!", pressed: true });
    expect(keyInput({ code: "KeyA", key: "a", isComposing: true }, true)).toBeNull();
    expect(keyInput({ code: "KeyA", key: "Process", keyCode: 229 }, true)).toBeNull();
    expect(keyInput({ code: "", key: "a" }, true)).toBeNull();
    expect(keyInput({ code: "K".repeat(33), key: "a" }, true)).toBeNull();
    expect(keyInput({ code: "Ünï", key: "a" }, true)).toBeNull();
    expect(keyInput({ code: "KeyA", key: "ğ".repeat(17) }, false)).toEqual({ kind: "key", code: "KeyA", key: "", pressed: false });
  });

  it("chunks composed text at 64 code points", () => {
    const text = "😀".repeat(65);
    const parts = unicodeInputs(text);
    expect(parts).toHaveLength(2);
    expect(parts.map((p) => (p.kind === "unicode" ? Array.from(p.text).length : 0))).toEqual([64, 1]);
    expect(unicodeInputs("")).toEqual([]);
  });

  it("syncs modifiers both ways", () => {
    const down = new Set(["ShiftRight"]);
    const out = syncModifiers({ shiftKey: false, ctrlKey: false, altKey: true, metaKey: false }, down);
    expect(out).toEqual([
      { kind: "key", code: "ShiftRight", key: "Shift", pressed: false },
      { kind: "key", code: "AltLeft", key: "Alt", pressed: true },
    ]);
    expect([...down]).toEqual(["AltLeft"]);
    expect(syncModifiers({ shiftKey: false, ctrlKey: false, altKey: true, metaKey: false }, down)).toEqual([]);
  });

  it("measures fps and bandwidth over a window", () => {
    const s = new FrameStats(0);
    for (let i = 0; i < 30; i++) s.frame(1024 * 100);
    expect(s.sample(1000)).toEqual({ fps: 30, kBps: 3000, errors: 0 });
    expect(s.sample(2000).fps).toBe(0);
  });
});
