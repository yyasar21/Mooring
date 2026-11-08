export type LineState = "connecting" | "connected" | "closed";

/**
 * Status vocabulary (design review 2026-11 §4.3): ok = connected, wait = needs you (amber),
 * busy = connecting (a small spinner), err = failed, neutral = closed or idle.
 */
export type DotTone = "ok" | "wait" | "busy" | "err" | "neutral";

const TONE: Record<LineState, DotTone> = { connected: "ok", connecting: "busy", closed: "neutral" };

/** Map a session line state to its dot tone. */
export function dotTone(state: LineState): DotTone {
  return TONE[state];
}

/**
 * A quiet 2 px rule under a session tab; only "connecting" paints. Styling lives in the
 * primitives stylesheet under `.mooring-line`; this component only sets the state attribute.
 */
export function MooringLine({ state }: { state: LineState }) {
  return <span aria-hidden className="mooring-line" data-state={state} />;
}

/**
 * The 8 px round status dot for the tree, tabs, inspector and the status bar. Pass `tone`
 * directly or a session `state`. Colour is never the only carrier: give it a `label` (it becomes
 * an image with that name) or put a text label next to it.
 */
export function StateDot({ state, tone, label }: { state?: LineState; tone?: DotTone; label?: string }) {
  const t = tone ?? (state ? TONE[state] : "neutral");
  return (
    <span
      role={label ? "img" : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
      title={label}
      className="state-dot"
      data-tone={t}
    />
  );
}
