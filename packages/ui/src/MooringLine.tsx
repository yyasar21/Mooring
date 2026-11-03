export type LineState = "connecting" | "connected" | "closed";

/**
 * The state rail under a session tab. Taut and lit when connected, a travelling pulse while
 * connecting, frayed (short faint dashes) once closed. Styling lives in the primitives stylesheet
 * under `.mooring-line`; this component only sets the state attribute.
 */
export function MooringLine({ state }: { state: LineState }) {
  return <span aria-hidden className="mooring-line" data-state={state} />;
}

/** Same state as a small diamond, for the tree, inspector and the telemetry strip. */
export function StateDot({ state, label }: { state: LineState; label?: string }) {
  return <span role={label ? "img" : undefined} aria-label={label} aria-hidden={label ? undefined : true} className="state-dot" data-state={state} />;
}
