// Terminal output stays out of React state: it is buffered per tab (or per detached view) until a
// terminal mounts, then streamed straight to xterm. The buffer is capped so a hidden tab cannot
// grow unbounded. No IPC here, so the detached window can use it too.

type OutputListener = (data: Uint8Array) => void;

const MAX_BUFFER = 1 << 20;
const outputs = new Map<string, { chunks: Uint8Array[]; size: number; listener: OutputListener | null }>();

export function pushOutput(tabId: string, data: Uint8Array): void {
  let o = outputs.get(tabId);
  if (!o) {
    o = { chunks: [], size: 0, listener: null };
    outputs.set(tabId, o);
  }
  if (o.listener) {
    o.listener(data);
    return;
  }
  o.chunks.push(data);
  o.size += data.length;
  while (o.size > MAX_BUFFER && o.chunks.length > 1) o.size -= o.chunks.shift()?.length ?? 0;
}

/** Attach a terminal; buffered output is replayed first. Returns the detach function. */
export function subscribeOutput(tabId: string, listener: OutputListener): () => void {
  const o = outputs.get(tabId) ?? { chunks: [], size: 0, listener: null };
  outputs.set(tabId, o);
  for (const c of o.chunks) listener(c);
  o.chunks = [];
  o.size = 0;
  o.listener = listener;
  return () => {
    if (o.listener === listener) o.listener = null;
  };
}

export function dropOutput(tabId: string): void {
  outputs.delete(tabId);
}

export function clearOutput(): void {
  outputs.clear();
}
