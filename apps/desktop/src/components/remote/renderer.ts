// Draws decoded MFR1 rects. WebGL2 keeps one RGBA texture the size of the remote framebuffer and
// updates it with one `texSubImage2D` per dirty rect (fills and copies stay on the GPU through a
// framebuffer object), then draws one textured quad. Canvas 2D (`putImageData`) is the fallback.
import type { Mfr1Rect } from "../../lib/frame/mfr1";

/** The RGBA payload as ImageData pixels, without copying (MFR1 messages are plain ArrayBuffers). */
function pixels(data: Uint8Array): Uint8ClampedArray<ArrayBuffer> {
  return new Uint8ClampedArray(data.buffer as ArrayBuffer, data.byteOffset, data.byteLength);
}

export interface Renderer {
  readonly kind: "webgl2" | "canvas2d";
  /** Re-allocate for a new framebuffer size; the content is cleared to black. */
  resize(width: number, height: number): void;
  apply(rects: readonly Mfr1Rect[]): void;
  /** Draw the framebuffer onto the canvas (WebGL: into its current backing size). */
  present(): void;
  dispose(): void;
}

const VS = `#version 300 es
out vec2 uv;
void main() {
  vec2 p = vec2(float(gl_VertexID & 1), float((gl_VertexID >> 1) & 1));
  uv = vec2(p.x, 1.0 - p.y);
  gl_Position = vec4(p * 2.0 - 1.0, 0.0, 1.0);
}`;

const FS = `#version 300 es
precision mediump float;
uniform sampler2D fb;
in vec2 uv;
out vec4 color;
void main() { color = vec4(texture(fb, uv).rgb, 1.0); }`;

function compile(gl: WebGL2RenderingContext, type: number, src: string): WebGLShader {
  const s = gl.createShader(type);
  if (!s) throw new Error("WebGL2: createShader failed");
  gl.shaderSource(s, src);
  gl.compileShader(s);
  if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) throw new Error("WebGL2: shader did not compile");
  return s;
}

export class GlRenderer implements Renderer {
  readonly kind = "webgl2";
  private tex: WebGLTexture | null = null;
  private fbo: WebGLFramebuffer | null = null;
  private scratch: WebGLTexture | null = null;
  private scratchFbo: WebGLFramebuffer | null = null;
  private readonly prog: WebGLProgram;
  private readonly vao: WebGLVertexArrayObject | null;
  private w = 0;
  private h = 0;

  constructor(
    private readonly canvas: HTMLCanvasElement,
    private readonly gl: WebGL2RenderingContext,
  ) {
    const prog = gl.createProgram();
    gl.attachShader(prog, compile(gl, gl.VERTEX_SHADER, VS));
    gl.attachShader(prog, compile(gl, gl.FRAGMENT_SHADER, FS));
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) throw new Error("WebGL2: program did not link");
    this.prog = prog;
    this.vao = gl.createVertexArray();
  }

  private texture(w: number, h: number): { tex: WebGLTexture | null; fbo: WebGLFramebuffer | null } {
    const gl = this.gl;
    const tex = gl.createTexture();
    gl.bindTexture(gl.TEXTURE_2D, tex);
    gl.texStorage2D(gl.TEXTURE_2D, 1, gl.RGBA8, w, h);
    for (const p of [gl.TEXTURE_WRAP_S, gl.TEXTURE_WRAP_T]) gl.texParameteri(gl.TEXTURE_2D, p, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    const fbo = gl.createFramebuffer();
    gl.bindFramebuffer(gl.FRAMEBUFFER, fbo);
    gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, tex, 0);
    gl.bindFramebuffer(gl.FRAMEBUFFER, null);
    return { tex, fbo };
  }

  private release(): void {
    const gl = this.gl;
    for (const t of [this.tex, this.scratch]) if (t) gl.deleteTexture(t);
    for (const f of [this.fbo, this.scratchFbo]) if (f) gl.deleteFramebuffer(f);
    this.tex = this.scratch = null;
    this.fbo = this.scratchFbo = null;
  }

  resize(width: number, height: number): void {
    this.release();
    this.w = width;
    this.h = height;
    const { tex, fbo } = this.texture(width, height);
    this.tex = tex;
    this.fbo = fbo;
    this.fill(0, 0, width, height, [0, 0, 0, 255]);
  }

  private fill(x: number, y: number, w: number, h: number, rgba: readonly number[]): void {
    const gl = this.gl;
    gl.bindFramebuffer(gl.FRAMEBUFFER, this.fbo);
    gl.viewport(0, 0, this.w, this.h);
    gl.enable(gl.SCISSOR_TEST);
    gl.scissor(x, y, w, h);
    gl.clearColor((rgba[0] ?? 0) / 255, (rgba[1] ?? 0) / 255, (rgba[2] ?? 0) / 255, 1);
    gl.clear(gl.COLOR_BUFFER_BIT);
    gl.disable(gl.SCISSOR_TEST);
    gl.bindFramebuffer(gl.FRAMEBUFFER, null);
  }

  /** Copy through a scratch texture, so overlapping source and destination stay correct. */
  private copy(x: number, y: number, w: number, h: number, srcX: number, srcY: number): void {
    const gl = this.gl;
    if (!this.scratch) {
      const s = this.texture(this.w, this.h);
      this.scratch = s.tex;
      this.scratchFbo = s.fbo;
    }
    gl.bindFramebuffer(gl.READ_FRAMEBUFFER, this.fbo);
    gl.bindTexture(gl.TEXTURE_2D, this.scratch);
    gl.copyTexSubImage2D(gl.TEXTURE_2D, 0, 0, 0, srcX, srcY, w, h);
    gl.bindFramebuffer(gl.READ_FRAMEBUFFER, this.scratchFbo);
    gl.bindTexture(gl.TEXTURE_2D, this.tex);
    gl.copyTexSubImage2D(gl.TEXTURE_2D, 0, x, y, 0, 0, w, h);
    gl.bindFramebuffer(gl.READ_FRAMEBUFFER, null);
  }

  apply(rects: readonly Mfr1Rect[]): void {
    const gl = this.gl;
    for (const r of rects) {
      if (r.w === 0 || r.h === 0) continue;
      switch (r.kind) {
        case "rgba":
          gl.bindTexture(gl.TEXTURE_2D, this.tex);
          gl.texSubImage2D(gl.TEXTURE_2D, 0, r.x, r.y, r.w, r.h, gl.RGBA, gl.UNSIGNED_BYTE, r.data);
          break;
        case "fill":
          this.fill(r.x, r.y, r.w, r.h, r.rgba);
          break;
        case "copy":
          this.copy(r.x, r.y, r.w, r.h, r.srcX, r.srcY);
          break;
        default:
          break; // cursor records are handled by the component (CSS cursor)
      }
    }
  }

  present(): void {
    const gl = this.gl;
    if (!this.tex || this.w === 0) return;
    gl.bindFramebuffer(gl.FRAMEBUFFER, null);
    gl.viewport(0, 0, this.canvas.width, this.canvas.height);
    gl.useProgram(this.prog);
    gl.bindVertexArray(this.vao);
    gl.activeTexture(gl.TEXTURE0);
    gl.bindTexture(gl.TEXTURE_2D, this.tex);
    // Integer scale (1:1 or exactly ×DPR) stays crisp; anything else is filtered.
    const crisp = this.canvas.width % this.w === 0 && this.canvas.width / this.w === this.canvas.height / this.h;
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, crisp ? gl.NEAREST : gl.LINEAR);
    gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
  }

  dispose(): void {
    this.release();
    this.gl.deleteProgram(this.prog);
    if (this.vao) this.gl.deleteVertexArray(this.vao);
  }
}

export class Canvas2dRenderer implements Renderer {
  readonly kind = "canvas2d";

  constructor(
    private readonly canvas: HTMLCanvasElement,
    private readonly ctx: CanvasRenderingContext2D,
  ) {}

  resize(width: number, height: number): void {
    this.canvas.width = width;
    this.canvas.height = height;
    this.ctx.fillStyle = "#000";
    this.ctx.fillRect(0, 0, width, height);
  }

  apply(rects: readonly Mfr1Rect[]): void {
    const ctx = this.ctx;
    for (const r of rects) {
      if (r.w === 0 || r.h === 0) continue;
      switch (r.kind) {
        case "rgba":
          ctx.putImageData(new ImageData(pixels(r.data), r.w, r.h), r.x, r.y);
          break;
        case "fill":
          ctx.fillStyle = `rgb(${String(r.rgba[0])} ${String(r.rgba[1])} ${String(r.rgba[2])})`;
          ctx.fillRect(r.x, r.y, r.w, r.h);
          break;
        case "copy":
          ctx.drawImage(this.canvas, r.srcX, r.srcY, r.w, r.h, r.x, r.y, r.w, r.h);
          break;
        default:
          break;
      }
    }
  }

  present(): void {
    // putImageData draws immediately; the browser scales the canvas element.
  }

  dispose(): void {
    // nothing held beyond the canvas itself
  }
}

/** WebGL2 when the WebView has it (and `preferWebgl`), else Canvas 2D; null when neither exists. */
export function createRenderer(canvas: HTMLCanvasElement, preferWebgl = true): Renderer | null {
  if (preferWebgl) {
    try {
      const gl = canvas.getContext("webgl2", { alpha: false, antialias: false, depth: false, preserveDrawingBuffer: false });
      if (gl) return new GlRenderer(canvas, gl);
    } catch {
      // fall through to Canvas 2D
    }
  }
  const ctx = canvas.getContext("2d", { alpha: false });
  return ctx ? new Canvas2dRenderer(canvas, ctx) : null;
}

/** A CSS `cursor` value for a sprite (built on a scratch canvas), or null when that is not possible. */
export function spriteCursor(r: Extract<Mfr1Rect, { kind: "cursor" }>): string | null {
  if (r.w === 0 || r.h === 0) return "none";
  try {
    const c = document.createElement("canvas");
    c.width = r.w;
    c.height = r.h;
    const ctx = c.getContext("2d");
    if (!ctx) return null;
    ctx.putImageData(new ImageData(pixels(r.data), r.w, r.h), 0, 0);
    return `url(${c.toDataURL("image/png")}) ${String(r.hotX)} ${String(r.hotY)}, default`;
  } catch {
    return null;
  }
}
