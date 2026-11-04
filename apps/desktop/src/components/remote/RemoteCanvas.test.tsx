import { act, fireEvent, render, screen } from "@testing-library/react";
import { encodeMfr1, solid } from "../../lib/frame/mfr1.encode";
import type { SessionInput } from "../../lib/ipc";
import type { FrameListener } from "../../stores/frames";
import { installCanvas, installPointerEvent, manualFrames } from "../../test/fakeGl";
import { RemoteCanvas, type RemoteCanvasProps } from "./RemoteCanvas";

installPointerEvent();

function setup(over: Partial<RemoteCanvasProps> = {}, webgl = true) {
  const canvasLogs = installCanvas({ webgl });
  const frames = manualFrames();
  let push: FrameListener = () => undefined;
  const inputs: SessionInput[] = [];
  const acks: number[] = [];
  const order: string[] = [];
  const props: RemoteCanvasProps = {
    tabId: "tab-x",
    label: "dc01 desktop",
    active: false,
    inputEnabled: true,
    showStats: false,
    onInput: (i) => inputs.push(i),
    onAck: (s) => { acks.push(s); order.push(`ack ${String(s)}`); },
    subscribe: (_tab, l) => { push = l; return () => undefined; },
    ...over,
  };
  const view = render(<RemoteCanvas {...props} />);
  const canvas = screen.getByRole<HTMLCanvasElement>("img", { name: "dc01 desktop" });
  canvas.getBoundingClientRect = () => ({ left: 10, top: 20, width: 200, height: 100, right: 210, bottom: 120, x: 10, y: 20, toJSON: () => ({}) });
  const sink = screen.getByLabelText("Keyboard input for dc01 desktop");
  const send = (m: ArrayBuffer) => { act(() => { push(m); }); };
  const draw = () => { act(() => { frames.flush(); }); };
  return { ...canvasLogs, frames, inputs, acks, order, canvas, sink, send, draw, view, cleanup: () => { frames.restore(); canvasLogs.restore(); } };
}

const full = (seq: number, w = 400, h = 200) => encodeMfr1({ seq, width: w, height: h, full: true, rects: [{ kind: "rgba", x: 0, y: 0, w, h, data: solid(w, h, [1, 2, 3, 255]) }] });

describe("RemoteCanvas · frames", () => {
  let t: ReturnType<typeof setup>;
  afterEach(() => { t.cleanup(); });

  it("uploads one texSubImage2D per dirty rect, presents once, then acks each frame", () => {
    t = setup();
    expect(t.view.container.querySelector(".remote-host")).toHaveAttribute("data-renderer", "webgl2");
    t.send(full(1));
    t.send(encodeMfr1({ seq: 2, width: 400, height: 200, rects: [
      { kind: "rgba", x: 5, y: 6, w: 2, h: 3, data: solid(2, 3, [9, 9, 9, 255]) },
      { kind: "rgba", x: 100, y: 50, w: 1, h: 1, data: solid(1, 1, [8, 8, 8, 255]) },
      { kind: "fill", x: 0, y: 0, w: 10, h: 10, rgba: [255, 0, 0, 255] },
    ] }));
    expect(t.acks).toEqual([]); // nothing is acked before it is drawn
    expect(t.frames.pending()).toBe(1); // both messages share one animation frame
    t.gl.length = 0;
    t.draw();
    const subs = t.gl.filter((c) => c.fn === "texSubImage2D").map((c) => c.args.slice(2, 6));
    expect(subs).toEqual([[0, 0, 400, 200], [5, 6, 2, 3], [100, 50, 1, 1]]);
    expect(t.gl.filter((c) => c.fn === "texStorage2D").map((c) => c.args.slice(3))).toEqual([[400, 200]]);
    expect(t.gl.some((c) => c.fn === "scissor" && c.args.join() === "0,0,10,10")).toBe(true);
    const drawAt = t.gl.findIndex((c) => c.fn === "drawArrays");
    const lastSub = t.gl.map((c) => c.fn).lastIndexOf("texSubImage2D");
    expect(drawAt).toBeGreaterThan(lastSub);
    expect(t.gl.filter((c) => c.fn === "drawArrays")).toHaveLength(1);
    expect(t.acks).toEqual([1, 2]);
  });

  it("acks a message that fails to decode, so its credit is not lost", () => {
    t = setup();
    const bad = new Uint8Array(full(7)).slice(0, 40).buffer; // truncated rgba payload
    t.send(bad);
    t.draw();
    expect(t.acks).toEqual([7]);
    expect(t.gl.some((c) => c.fn === "texSubImage2D")).toBe(false);
  });

  it("re-allocates the texture when the framebuffer is resized", () => {
    t = setup();
    t.send(full(1, 400, 200));
    t.draw();
    t.send(full(2, 640, 480));
    t.draw();
    expect(t.gl.filter((c) => c.fn === "texStorage2D").map((c) => c.args.slice(3))).toEqual([[400, 200], [640, 480]]);
    expect(t.gl.some((c) => c.fn === "deleteTexture")).toBe(true);
  });

  it("uses a scratch texture for copy rects so overlaps stay correct", () => {
    t = setup();
    t.send(full(1));
    t.send(encodeMfr1({ seq: 2, width: 400, height: 200, rects: [{ kind: "copy", x: 10, y: 0, w: 20, h: 20, srcX: 0, srcY: 0 }] }));
    t.draw();
    expect(t.gl.filter((c) => c.fn === "copyTexSubImage2D").map((c) => c.args.slice(2))).toEqual([[0, 0, 0, 0, 20, 20], [10, 0, 0, 0, 20, 20]]);
  });

  it("falls back to Canvas 2D putImageData without WebGL2", () => {
    t = setup({}, false);
    expect(t.view.container.querySelector(".remote-host")).toHaveAttribute("data-renderer", "canvas2d");
    t.send(full(1, 8, 4));
    t.draw();
    expect(t.ctx.filter((c) => c.fn === "putImageData").map((c) => c.args.slice(1))).toEqual([[0, 0]]);
    expect(t.canvas.width).toBe(8);
    expect(t.acks).toEqual([1]);
  });

  it("applies cursor records to the canvas cursor style", () => {
    t = setup();
    t.send(encodeMfr1({ seq: 1, width: 4, height: 4, rects: [{ kind: "cursor_hidden", x: 0, y: 0, w: 0, h: 0 }] }));
    t.draw();
    expect(t.canvas.style.cursor).toBe("none");
    t.send(encodeMfr1({ seq: 2, width: 4, height: 4, rects: [{ kind: "cursor_default", x: 0, y: 0, w: 0, h: 0 }] }));
    t.draw();
    expect(t.canvas.style.cursor).toBe("default");
  });

  it("shows the statistics overlay on demand", () => {
    t = setup({ showStats: true });
    expect(screen.getByRole("status", { name: "Frame statistics" })).toHaveTextContent(/fps.*WebGL2/i);
  });
});

describe("RemoteCanvas · input", () => {
  let t: ReturnType<typeof setup>;
  afterEach(() => { t.cleanup(); });

  const ready = (over: Partial<RemoteCanvasProps> = {}) => {
    t = setup(over);
    t.send(full(1, 400, 200));
    t.draw();
    return t;
  };

  it("maps pointer position to framebuffer pixels and DOM buttons to the ADR order", () => {
    ready();
    fireEvent.pointerDown(t.canvas, { clientX: 110, clientY: 70, buttons: 2 }); // half way → 200,100; right button
    fireEvent.pointerMove(t.canvas, { clientX: 110, clientY: 70, buttons: 2 }); // unchanged → coalesced
    fireEvent.pointerMove(t.canvas, { clientX: 500, clientY: -5, buttons: 4 }); // clamped; middle
    fireEvent.pointerUp(t.canvas, { clientX: 10, clientY: 20, buttons: 0 });
    expect(t.inputs).toEqual([
      { kind: "pointer", x: 200, y: 100, buttons: 4 },
      { kind: "pointer", x: 399, y: 0, buttons: 2 },
      { kind: "pointer", x: 0, y: 0, buttons: 0 },
    ]);
  });

  it("sends wheel notches and keeps the page from scrolling", () => {
    ready();
    const ev = new WheelEvent("wheel", { deltaY: 100, deltaMode: 0, cancelable: true });
    t.canvas.dispatchEvent(ev);
    expect(ev.defaultPrevented).toBe(true);
    t.canvas.dispatchEvent(new WheelEvent("wheel", { deltaY: -3, deltaMode: 1, cancelable: true }));
    expect(t.inputs).toEqual([{ kind: "wheel", dx: 0, dy: 120 }, { kind: "wheel", dx: 0, dy: -120 }]);
  });

  it("sends keys by code, syncs modifiers, ignores IME keydowns and sends composed text as Unicode", () => {
    ready();
    fireEvent.keyDown(t.sink, { code: "KeyC", key: "c", ctrlKey: true }); // Control was pressed before focus
    fireEvent.keyUp(t.sink, { code: "KeyC", key: "c", ctrlKey: true });
    fireEvent.keyUp(t.sink, { code: "KeyK", key: "k" }); // never pressed here (app shortcut): not sent
    fireEvent.keyDown(t.sink, { code: "KeyA", key: "Process", keyCode: 229 });
    fireEvent.compositionEnd(t.sink, { data: "日本語" });
    fireEvent.pointerDown(t.canvas, { clientX: 10, clientY: 20, buttons: 1, ctrlKey: false }); // Control released elsewhere
    expect(t.inputs).toEqual([
      { kind: "key", code: "ControlLeft", key: "Control", pressed: true },
      { kind: "key", code: "KeyC", key: "c", pressed: true },
      { kind: "key", code: "KeyC", key: "c", pressed: false },
      { kind: "unicode", text: "日本語" },
      { kind: "key", code: "ControlLeft", key: "Control", pressed: false },
      { kind: "pointer", x: 0, y: 0, buttons: 1 },
    ]);
  });

  it("offers the clipboard on focus and releases every key on blur", () => {
    ready({ offerClipboardOnFocus: true });
    fireEvent.focus(t.sink);
    fireEvent.keyDown(t.sink, { code: "ShiftLeft", key: "Shift", shiftKey: true });
    fireEvent.blur(t.sink);
    expect(t.inputs).toEqual([
      { kind: "clipboard_offer" },
      { kind: "key", code: "ShiftLeft", key: "Shift", pressed: true },
      { kind: "release_all" },
    ]);
  });

  it("sends nothing while input is disabled (view-only) and releases held keys when it gets disabled", () => {
    ready();
    fireEvent.keyDown(t.sink, { code: "KeyQ", key: "q" });
    t.view.rerender(<RemoteCanvas tabId="tab-x" label="dc01 desktop" active={false} inputEnabled={false} showStats={false} onInput={(i) => t.inputs.push(i)} onAck={() => undefined} subscribe={() => () => undefined} />);
    fireEvent.keyDown(t.sink, { code: "KeyW", key: "w" });
    fireEvent.pointerDown(t.canvas, { clientX: 50, clientY: 50, buttons: 1 });
    expect(t.inputs).toEqual([{ kind: "key", code: "KeyQ", key: "q", pressed: true }, { kind: "release_all" }]);
  });
});
