// L-53 test helper: does a string appear anywhere in the React state or props of a rendered tree?
// It walks the fiber tree from the RTL container and searches every hook's memoized state and
// every component's props (DOM nodes and functions are skipped; cycles are guarded).

type Fiber = {
  child: Fiber | null;
  sibling: Fiber | null;
  memoizedState: unknown;
  memoizedProps: unknown;
  stateNode: unknown;
};

function rootFiber(container: Element): Fiber | null {
  const key = Object.keys(container).find((k) => k.startsWith("__reactContainer$"));
  if (!key) return null;
  const marked = (container as unknown as Record<string, Fiber | undefined>)[key];
  // The marked fiber is the first host root; after a commit the live tree is FiberRoot.current.
  const fiberRoot = marked?.stateNode as { current?: Fiber } | undefined;
  return fiberRoot?.current ?? marked ?? null;
}

function holds(value: unknown, needle: string, seen: Set<unknown>, depth: number): boolean {
  if (typeof value === "string") return value.includes(needle);
  if (value === null || typeof value !== "object" || depth > 12) return false;
  if (seen.has(value)) return false;
  seen.add(value);
  if (typeof Node !== "undefined" && value instanceof Node) return false;
  // Fibers inside hook queues point back into the tree; the walk covers those separately.
  if ("stateNode" in value && "return" in value) return false;
  for (const v of Object.values(value)) {
    if (holds(v, needle, seen, depth + 1)) return true;
  }
  return false;
}

/** True when `needle` is in any component's state or props under `container`. */
export function reactStateHolds(container: Element, needle: string): boolean {
  const root = rootFiber(container);
  if (!root) throw new Error("no React root on this container");
  const seen = new Set<unknown>();
  const stack: Fiber[] = [root];
  while (stack.length) {
    const f = stack.pop();
    if (!f) continue;
    if (holds(f.memoizedState, needle, seen, 0)) return true;
    // Host elements carry their DOM props (for example a controlled input's `value`).
    if (holds(f.memoizedProps, needle, seen, 0)) return true;
    if (f.child) stack.push(f.child);
    if (f.sibling) stack.push(f.sibling);
  }
  return false;
}
