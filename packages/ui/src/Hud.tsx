import type { ReactNode } from "react";

/**
 * Bracketed section heading used by the inspector and dialogs: a tracked micro-label between
 * corner ticks, followed by a hairline that runs to the edge of the pane. HUD frames themselves
 * are a class (`m-hud`, light it with `data-active`), not a component, so any element can be one.
 */
export function HudLabel({ children, id }: { children: ReactNode; id?: string }) {
  return (
    <h3 id={id} className="m-hud-label">
      <span>{children}</span>
    </h3>
  );
}
