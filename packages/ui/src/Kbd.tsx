import type { ReactNode } from "react";

/** Keyboard hint: a small keycap. Renders the platform's modifier glyph for "mod". */
export function Kbd({ children }: { children: ReactNode }) {
  const isMac = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform);
  const text = typeof children === "string" ? children.replace("mod", isMac ? "⌘" : "Ctrl") : children;
  return <kbd className="m-kbd">{text}</kbd>;
}
