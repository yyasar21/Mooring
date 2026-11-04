// The detached window's whole session logic (ADR-0013 route contract). It may call only
// session_attach / session_send / session_close / session_frame_ack / session_screenshot /
// window_attach, all for this session id: no store that reads the vault, no `listen()` (Rust hides
// this window on lock instead). Output and frames use the same IPC-free buffers as main.
import { useCallback, useEffect, useRef, useState } from "react";
import { ipc, isIpcError, type Protocol, type SessionEvent, type SessionInput, type Size } from "../../lib/ipc";
import { peekSeq } from "../../lib/frame/mfr1";
import { drainFrames, dropFrames, pushFrame } from "../../stores/frames";
import { dropOutput, pushOutput } from "../../stores/output";
import { describeError } from "../../stores/errors";

export type DetachedPhase = "attaching" | "live" | "away" | "closed" | "failed";

export interface DetachedState {
  phase: DetachedPhase;
  protocol: Protocol | null;
  /** The session's own state: connecting / connected / reconnecting. */
  state: string;
  desktop: Size | null;
  reason: string | null;
  /** A prompt arrived; it is answered in main (Bring back), not here. */
  prompt: boolean;
}

/** Output / frame buffer key of this view (never a main tab id). */
export const detachedKey = (sessionId: string) => `detached:${sessionId}`;

const INITIAL: DetachedState = { phase: "attaching", protocol: null, state: "connecting", desktop: null, reason: null, prompt: false };

export function useDetachedSession(sessionId: string) {
  const [st, setSt] = useState<DetachedState>(INITIAL);
  const stRef = useRef(st);
  useEffect(() => { stRef.current = st; });
  const key = detachedKey(sessionId);

  const ack = useCallback((seq: number) => { ipc.sessionFrameAck({ sessionId, seq }).catch(() => undefined); }, [sessionId]);

  useEffect(() => {
    let live = true; // false after unmount (and in StrictMode's first, discarded mount)
    const patch = (p: Partial<DetachedState>) => { if (live) setSt((s) => ({ ...s, ...p })); };
    const onEvent = (ev: SessionEvent) => {
      if (!live) return;
      switch (ev.kind) {
        case "connected":
          patch({ state: "connected", prompt: false });
          break;
        case "bytes":
          pushOutput(key, ev.data);
          break;
        case "prompt":
          patch({ prompt: true });
          break;
        case "desktop_resized":
          patch({ desktop: { width: ev.width, height: ev.height } });
          break;
        case "reconnecting":
          patch({ state: "reconnecting" });
          break;
        case "detached":
          patch({ phase: "away" }); // main took the session back; Rust closes this window
          break;
        case "attached":
          break; // sent to main only
        case "closed":
          patch({ phase: "closed", reason: ev.reason });
          break;
      }
    };
    const onFrame = (m: ArrayBuffer) => {
      if (live) {
        pushFrame(key, m, ack);
        return;
      }
      const seq = peekSeq(m);
      if (seq !== null) ack(seq);
    };

    // The route carries no protocol: rdp/vnc need onFrame, ssh refuses it (input.invalid).
    void (async () => {
      try {
        let a;
        try {
          a = await ipc.sessionAttach({ sessionId, onEvent, onFrame });
        } catch (e: unknown) {
          if (!isIpcError(e) || e.code !== "input.invalid") throw e;
          a = await ipc.sessionAttach({ sessionId, onEvent });
        }
        const graphical = a.protocol === "rdp" || a.protocol === "vnc";
        patch({ phase: "live", protocol: a.protocol, state: a.state, desktop: graphical ? a.size : null });
      } catch (e: unknown) {
        patch({ phase: "failed", reason: describeError(e) });
      }
    })();

    return () => {
      live = false;
      for (const m of drainFrames(key)) {
        const seq = peekSeq(m);
        if (seq !== null) ack(seq);
      }
      dropFrames(key);
      dropOutput(key);
    };
  }, [sessionId, key, ack]);

  const input = useCallback((i: SessionInput) => { ipc.sessionSend({ sessionId, input: i }).catch(() => undefined); }, [sessionId]);
  const [error, setError] = useState<string | null>(null);
  const bringBack = useCallback(() => {
    ipc.windowAttach({ sessionId }).then(() => { setError(null); }, (e: unknown) => { setError(describeError(e)); });
  }, [sessionId]);
  /** rdp/vnc: the size the canvas wants, sent once connected (and only when it differs). */
  const wanted = useRef<Size | null>(null);
  const sendDesktop = useCallback(() => {
    const s = stRef.current;
    const size = wanted.current;
    if (!size || s.phase !== "live" || s.state !== "connected" || (s.desktop?.width === size.width && s.desktop.height === size.height)) return;
    input({ kind: "resize", size });
  }, [input]);
  const requestDesktop = useCallback((size: Size) => {
    wanted.current = size;
    sendDesktop();
  }, [sendDesktop]);
  const ready = st.phase === "live" && st.state === "connected";
  useEffect(() => { if (ready) sendDesktop(); }, [ready, sendDesktop]);

  return { st, key, input, ack, bringBack, requestDesktop, error };
}
