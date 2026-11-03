export type LineState = "connecting" | "connected" | "closed";

/**
 * The state rail under a session tab. Taut (solid accent) when connected, slack (dashed, drifting)
 * while connecting, frayed (short faint dashes) once closed. Styling lives in the app stylesheet
 * under `.mooring-line`; this component only sets the state attribute.
 */
export function MooringLine({ state }: { state: LineState }) {
  return <span aria-hidden className="mooring-line" data-state={state} />;
}

/** Same state as a dot, for the tree and the status bar. */
export function StateDot({ state, label }: { state: LineState; label?: string }) {
  return <span role={label ? "img" : undefined} aria-label={label} aria-hidden={label ? undefined : true} className="state-dot" data-state={state} />;
}
