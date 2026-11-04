// jsdom has no canvas: a recording WebGL2 / Canvas 2D context and a controllable animation frame.

export interface GlCall {
  fn: string;
  args: unknown[];
}

/** A WebGL2RenderingContext stand-in: constants are numbers, create* return tokens, calls are logged. */
export function fakeGl(log: GlCall[]): WebGL2RenderingContext {
  const constants = new Map<string, number>();
  return new Proxy({} as WebGL2RenderingContext, {
    get(_t, prop) {
      if (typeof prop !== "string") return undefined;
      if (/^[A-Z0-9_]+$/.test(prop)) {
        if (!constants.has(prop)) constants.set(prop, 0x1000 + constants.size);
        return constants.get(prop);
      }
      if (prop === "getShaderParameter" || prop === "getProgramParameter") return () => true;
      if (prop.startsWith("create")) return () => ({ token: prop });
      return (...args: unknown[]) => { log.push({ fn: prop, args }); };
    },
  });
}

export function fake2d(log: GlCall[]): CanvasRenderingContext2D {
  return new Proxy({} as CanvasRenderingContext2D, {
    get(_t, prop) {
      if (typeof prop !== "string") return undefined;
      return (...args: unknown[]) => { log.push({ fn: prop, args }); };
    },
    set() {
      return true;
    },
  });
}

/** Install getContext: "webgl2" → fake GL unless `webgl` is false; "2d" → fake 2D. Returns the logs. */
export function installCanvas(opts: { webgl: boolean }): { gl: GlCall[]; ctx: GlCall[]; restore: () => void } {
  const gl: GlCall[] = [];
  const ctx: GlCall[] = [];
  const proto = HTMLCanvasElement.prototype;
  const original = Object.getOwnPropertyDescriptor(proto, "getContext");
  Object.defineProperty(proto, "getContext", {
    configurable: true,
    value(type: string) {
      if (type === "webgl2") return opts.webgl ? fakeGl(gl) : null;
      if (type === "2d") return fake2d(ctx);
      return null;
    },
  });
  // ImageData is missing from jsdom as well.
  const g = globalThis as { ImageData?: unknown };
  const hadImageData = "ImageData" in g;
  if (!hadImageData) {
    g.ImageData = class {
      constructor(
        readonly data: Uint8ClampedArray,
        readonly width: number,
        readonly height: number,
      ) {}
    };
  }
  return {
    gl,
    ctx,
    restore: () => {
      if (original) Object.defineProperty(proto, "getContext", original);
      if (!hadImageData) delete g.ImageData;
    },
  };
}

/** requestAnimationFrame that runs only when the test says so. */
export function manualFrames(): { flush: () => void; pending: () => number; restore: () => void } {
  let queue: FrameRequestCallback[] = [];
  vi.stubGlobal("requestAnimationFrame", (cb: FrameRequestCallback) => {
    queue.push(cb);
    return queue.length;
  });
  vi.stubGlobal("cancelAnimationFrame", () => undefined);
  return {
    flush: () => {
      const run = queue;
      queue = [];
      for (const cb of run) cb(performance.now());
    },
    pending: () => queue.length,
    restore: () => { vi.unstubAllGlobals(); },
  };
}

/** jsdom lacks PointerEvent; testing-library falls back to it by name. */
export function installPointerEvent(): void {
  const w = window as unknown as { PointerEvent?: unknown };
  if (w.PointerEvent) return;
  w.PointerEvent = class PointerEvent extends MouseEvent {
    readonly pointerId: number;
    constructor(type: string, init: PointerEventInit = {}) {
      super(type, init);
      this.pointerId = init.pointerId ?? 1;
    }
  };
}
