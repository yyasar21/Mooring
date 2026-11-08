import type { ReactNode } from "react";

/**
 * Section heading used by the inspector, cards and dialogs: 13 px semibold, sentence case. The
 * name survives from the bridge-console system; `m-hud` is now a plain hairline frame.
 */
export function HudLabel({ children, id }: { children: ReactNode; id?: string }) {
  return (
    <h3 id={id} className="m-hud-label">
      <span>{children}</span>
    </h3>
  );
}
