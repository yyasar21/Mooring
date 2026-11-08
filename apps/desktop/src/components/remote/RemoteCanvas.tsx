import { useEffect, useRef, useState, type PointerEvent as ReactPointerEvent } from "react";
import { decodeMfr1, peekSeq } from "../../lib/frame/mfr1";
import type { SessionInput, Size } from "../../lib/ipc";
import { subscribeFrames, type FrameListener } from "../../stores/frames";
import { backingSize, desktopRequest, keyInput, letterbox, remoteButtons, syncModifiers, toFramebuffer, unicodeInputs, wheelInput, type Box } from "./input";
import { createRenderer, spriteCursor, type Renderer } from "./renderer";
import { FrameStats, type StatsSample } from "./stats";

export interface RemoteCanvasProps {
  tabId: string;
  /** Accessible name of the desktop image. */
  label: string;
  active: boolean;
  /** False while view-only or not connected: nothing is sent (Rust enforces view-only anyway). */
  inputEnabled: boolean;
  showStats: boolean;
  onInput: (input: SessionInput) => void;
  /** Return the credit of a drawn message (`session_frame_ack`). */
  onAck: (seq: number) => void;
  /** The container changed size (debounced 300 ms): the desktop size to ask for. */
  onDesktopRequest?: (size: Size) => void;
  /** ADR-0011 `ClipboardOffer` on focus gain, when the clipboard policy sends to the remote. */
  offerClipboardOnFocus?: boolean;
  preferWebgl?: boolean;
  /** Frame source (tests); defaults to the per-tab queue of the sessions store. */
  subscribe?: (tabId: string, listener: FrameListener) => () => void;
}

const RESIZE_DEBOUNCE_MS = 300;
const raf = (cb: FrameRequestCallback): number =>
  typeof requestAnimationFrame === "function" ? requestAnimationFrame(cb) : window.setTimeout(() => { cb(performance.now()); }, 16);
const cancelRaf = (id: number) => {
  if (typeof cancelAnimationFrame === "function") cancelAnimationFrame(id);
  else window.clearTimeout(id);
};

/**
 * One remote desktop surface (RDP or VNC). MFR1 messages are decoded and drawn in one animation
 * frame, then each one's credit is returned, so a slow WebView receives fewer, newer frames
 * instead of a queue. Input goes through a hidden textarea (keys by `code`, IME text as Unicode)
 * and pointer events on the canvas, mapped to framebuffer pixels.
 */
export function RemoteCanvas(props: RemoteCanvasProps) {
  const { tabId, label, active, inputEnabled, showStats, preferWebgl = true, subscribe = subscribeFrames } = props;
  const hostRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const sinkRef = useRef<HTMLTextAreaElement>(null);
  const cb = useRef(props);
  const renderer = useRef<Renderer | null>(null);
  const fbRef = useRef<Size | null>(null);
  const statsRef = useRef(new FrameStats(0));
  const down = useRef(new Set<string>());
  const lastPointer = useRef("");
  const wheelAcc = useRef({ x: 0, y: 0 });
  const [fb, setFb] = useState<Size | null>(null);
  const [container, setContainer] = useState<Size>({ width: 0, height: 0 });
  const [kind, setKind] = useState<Renderer["kind"] | "none">("none");
  const [stats, setStats] = useState<StatsSample | null>(null);

  useEffect(() => {
    cb.current = props;
  });

  const send = (input: SessionInput) => {
    if (cb.current.inputEnabled) cb.current.onInput(input);
  };

  // Renderer + frame subscription: decode, draw once per animation frame, then ack.
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    renderer.current = createRenderer(canvas, preferWebgl);
    setKind(renderer.current?.kind ?? "none");
    statsRef.current = new FrameStats(performance.now());
    const pending: ArrayBuffer[] = [];
    let frameId = 0;
    const draw = () => {
      frameId = 0;
      const acks: number[] = [];
      for (const msg of pending.splice(0)) {
        let seq = peekSeq(msg);
        try {
          const f = decodeMfr1(msg);
          seq = f.seq;
          const cur = fbRef.current;
          if (!cur || cur.width !== f.width || cur.height !== f.height) {
            fbRef.current = { width: f.width, height: f.height };
            renderer.current?.resize(f.width, f.height);
            setFb(fbRef.current);
          }
          renderer.current?.apply(f.rects);
          for (const r of f.rects) {
            if (r.kind === "cursor") canvas.style.cursor = spriteCursor(r) ?? "default";
            else if (r.kind === "cursor_hidden") canvas.style.cursor = "none";
            else if (r.kind === "cursor_default") canvas.style.cursor = "default";
          }
          statsRef.current.frame(msg.byteLength);
        } catch {
          statsRef.current.errors += 1;
        }
        if (seq !== null) acks.push(seq);
      }
      renderer.current?.present();
      for (const s of acks) cb.current.onAck(s);
    };
    const off = subscribe(tabId, (msg) => {
      pending.push(msg);
      if (!frameId) frameId = raf(draw);
    });
    const lost = (e: Event) => { e.preventDefault(); };
    const restored = () => {
      // The texture is gone; it is rebuilt here and refilled by the next full frame.
      renderer.current?.dispose();
      renderer.current = createRenderer(canvas, preferWebgl);
      const cur = fbRef.current;
      if (cur) renderer.current?.resize(cur.width, cur.height);
    };
    canvas.addEventListener("webglcontextlost", lost);
    canvas.addEventListener("webglcontextrestored", restored);
    return () => {
      off();
      if (frameId) cancelRaf(frameId);
      // Received but never drawn (unmount, lock): return their credits so the pump keeps going.
      for (const m of pending.splice(0)) {
        const seq = peekSeq(m);
        if (seq !== null) cb.current.onAck(seq);
      }
      canvas.removeEventListener("webglcontextlost", lost);
      canvas.removeEventListener("webglcontextrestored", restored);
      renderer.current?.dispose();
      renderer.current = null;
      fbRef.current = null;
    };
  }, [tabId, preferWebgl, subscribe]);

  // Container size (CSS px), from a ResizeObserver.
  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    const measure = () => {
      setContainer((c) => (c.width === host.clientWidth && c.height === host.clientHeight ? c : { width: host.clientWidth, height: host.clientHeight }));
    };
    measure();
    const ro = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(measure);
    ro?.observe(host);
    window.addEventListener("resize", measure);
    return () => {
      ro?.disconnect();
      window.removeEventListener("resize", measure);
    };
  }, []);

  // Ask the server for a desktop that fits the container (debounced).
  useEffect(() => {
    if (container.width <= 0 || container.height <= 0) return;
    const t = window.setTimeout(() => { cb.current.onDesktopRequest?.(desktopRequest(container)); }, RESIZE_DEBOUNCE_MS);
    return () => { window.clearTimeout(t); };
  }, [container]);

  const box: Box = letterbox(container, fb ?? container);

  // WebGL draws at the displayed size × DPR; Canvas 2D keeps the framebuffer size and lets CSS scale.
  useEffect(() => {
    const canvas = canvasRef.current;
    const r = renderer.current;
    if (!canvas || r?.kind !== "webgl2" || box.width === 0) return;
    const b = backingSize({ width: box.width, height: box.height }, window.devicePixelRatio);
    if (canvas.width !== b.width || canvas.height !== b.height) {
      canvas.width = b.width;
      canvas.height = b.height;
      r.present();
    }
  }, [box.width, box.height, kind]);

  // Wheel needs a non-passive listener to keep the page from scrolling.
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const w = wheelInput(e, wheelAcc.current);
      if (w) send(w);
    };
    canvas.addEventListener("wheel", onWheel, { passive: false });
    return () => { canvas.removeEventListener("wheel", onWheel); };
  }, []);

  // Losing input (view-only, disconnect) must not leave a key held on the remote.
  useEffect(() => {
    if (!inputEnabled && down.current.size > 0) {
      down.current.clear();
      cb.current.onInput({ kind: "release_all" });
    }
  }, [inputEnabled]);

  useEffect(() => {
    if (!active) return;
    const id = raf(() => { sinkRef.current?.focus({ preventScroll: true }); });
    return () => { cancelRaf(id); };
  }, [active]);

  useEffect(() => {
    if (!showStats) return;
    statsRef.current.sample(performance.now());
    const id = window.setInterval(() => { setStats(statsRef.current.sample(performance.now())); }, 1000);
    return () => {
      window.clearInterval(id);
      setStats(null);
    };
  }, [showStats]);

  const pointer = (e: ReactPointerEvent<HTMLCanvasElement>, force: boolean) => {
    const cur = fbRef.current;
    if (!cur || !cb.current.inputEnabled) return;
    const { x, y } = toFramebuffer(e.clientX, e.clientY, e.currentTarget.getBoundingClientRect(), cur);
    const buttons = remoteButtons(e.buttons);
    const key = `${String(x)},${String(y)},${String(buttons)}`;
    if (!force && key === lastPointer.current) return;
    lastPointer.current = key;
    send({ kind: "pointer", x, y, buttons });
  };

  return (
    // L5: the desktop sits centred (letterboxed) on a neutral surface, never on the terminal black.
    <div ref={hostRef} className="remote-host" data-renderer={kind} data-framed={fb ? true : undefined} data-testid={`remote-${tabId}`}>
      {!fb && <p className="remote-wait" aria-hidden>Waiting for the first frame…</p>}
      <canvas
        ref={canvasRef}
        role="img"
        aria-label={label}
        className="remote-canvas"
        style={{ left: box.left, top: box.top, width: box.width, height: box.height }}
        onPointerDown={(e) => {
          e.preventDefault();
          sinkRef.current?.focus({ preventScroll: true });
          if ("setPointerCapture" in e.currentTarget) e.currentTarget.setPointerCapture(e.pointerId);
          for (const m of syncModifiers(e, down.current)) send(m);
          pointer(e, true);
        }}
        onPointerMove={(e) => { pointer(e, false); }}
        onPointerUp={(e) => { pointer(e, true); }}
        onContextMenu={(e) => { e.preventDefault(); }}
      />
      <textarea
        ref={sinkRef}
        className="remote-sink"
        aria-label={`Keyboard input for ${label}`}
        autoCapitalize="off"
        autoComplete="off"
        autoCorrect="off"
        spellCheck={false}
        style={{ left: box.left, top: box.top }}
        onKeyDown={(e) => {
          const k = keyInput(e.nativeEvent, true);
          if (!k) return; // IME composing: the composition events carry the text
          e.preventDefault();
          for (const m of syncModifiers(e, down.current, e.code)) send(m);
          down.current.add(e.code);
          send(k);
        }}
        onKeyUp={(e) => {
          const k = keyInput(e.nativeEvent, false);
          // Only keys we pressed go up: an app shortcut's keydown never reached the remote.
          if (!k || !down.current.has(e.code)) return;
          e.preventDefault();
          down.current.delete(e.code);
          send(k);
        }}
        onCompositionEnd={(e) => {
          for (const u of unicodeInputs(e.data)) send(u);
          e.currentTarget.value = "";
        }}
        onInput={(e) => {
          if (!e.nativeEvent.isComposing) e.currentTarget.value = "";
        }}
        onFocus={() => { if (cb.current.offerClipboardOnFocus) send({ kind: "clipboard_offer" }); }}
        onBlur={() => {
          down.current.clear();
          lastPointer.current = "";
          send({ kind: "release_all" });
        }}
      />
      {showStats && (
        <div className="remote-stats" role="status" aria-label="Frame statistics">
          <span>{stats ? `${String(stats.fps)} fps` : "-- fps"}</span>
          <span>{stats ? `${(stats.kBps / 1024).toFixed(1)} MB/s` : "-- MB/s"}</span>
          <span>{fb ? `${String(fb.width)}×${String(fb.height)}` : "no frame"}</span>
          <span>{kind === "webgl2" ? "WebGL2" : kind === "canvas2d" ? "Canvas 2D" : "No renderer"}</span>
          {stats && stats.errors > 0 && <span data-tone="hot">{stats.errors} bad frames</span>}
        </div>
      )}
    </div>
  );
}
