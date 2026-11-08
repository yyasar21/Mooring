import type { ReactNode } from "react";
import { Icon, type IconName } from "@mooring/ui";

export type StripTone = "danger" | "warning" | "info" | "neutral";

const ICON: Record<StripTone, IconName> = { danger: "x-circle", warning: "alert", info: "info", neutral: "info" };

/**
 * A full-width status line under a session header (design review §4.3 callouts): an icon, a
 * title, the detail and an optional hint, then the actions. It sits in the layout instead of
 * floating over the terminal, so it never hides output.
 */
export function StatusStrip({ tone, title, detail, hint, role, className, children }: {
  tone: StripTone;
  title: string;
  detail?: ReactNode;
  hint?: ReactNode;
  role?: "alert" | "status";
  className?: string;
  children?: ReactNode;
}) {
  return (
    <div className={`status-strip${className ? ` ${className}` : ""}`} data-tone={tone} role={role}>
      <span className="status-strip-icon" aria-hidden>
        <Icon name={ICON[tone]} />
      </span>
      <span className="status-strip-text">
        <span className="status-strip-title">{title}</span>
        {detail && <span className="status-strip-detail">{detail}</span>}
        {hint && <span className="status-strip-hint">{hint}</span>}
      </span>
      {children && <span className="status-strip-actions">{children}</span>}
    </div>
  );
}
