// MFR1 messages stay out of React state, like terminal output: they are queued per tab until a
// RemoteCanvas subscribes, then handed straight to it. Rust keeps at most 2 messages in flight
// (credits), so the queue only ever holds a couple; the cap guards a misbehaving backend, and a
// message dropped by the cap is acked so its credit is not lost.
import { peekSeq } from "../lib/frame/mfr1";

export type FrameListener = (message: ArrayBuffer) => void;
type Ack = (seq: number) => void;

export const MAX_QUEUED_FRAMES = 4;

const frames = new Map<string, { queue: ArrayBuffer[]; listener: FrameListener | null }>();

export function pushFrame(tabId: string, message: ArrayBuffer, ack: Ack): void {
  let f = frames.get(tabId);
  if (!f) {
    f = { queue: [], listener: null };
    frames.set(tabId, f);
  }
  if (f.listener) {
    f.listener(message);
    return;
  }
  f.queue.push(message);
  while (f.queue.length > MAX_QUEUED_FRAMES) {
    const dropped = f.queue.shift();
    const seq = dropped ? peekSeq(dropped) : null;
    if (seq !== null) ack(seq);
  }
}

/** Attach a canvas; queued messages replay first, in order. Returns the detach function. */
export function subscribeFrames(tabId: string, listener: FrameListener): () => void {
  const f = frames.get(tabId) ?? { queue: [], listener: null };
  frames.set(tabId, f);
  const queued = f.queue;
  f.queue = [];
  f.listener = listener;
  for (const m of queued) listener(m);
  return () => {
    if (f.listener === listener) f.listener = null;
  };
}

export function dropFrames(tabId?: string): void {
  if (tabId === undefined) frames.clear();
  else frames.delete(tabId);
}

export function queuedFrames(tabId: string): number {
  return frames.get(tabId)?.queue.length ?? 0;
}
