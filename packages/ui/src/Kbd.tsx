import type { ReactNode } from "react";

/** Keyboard hint. Renders the platform's modifier glyph for "mod". */
export function Kbd({ children }: { children: ReactNode }) {
  const isMac = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform);
  const text = typeof children === "string" ? children.replace("mod", isMac ? "⌘" : "Ctrl") : children;
  return (
    <kbd
      style={{
        font: `500 ${"var(--fs-xs)"} var(--font-sans)`,
        color: "var(--text-muted)",
        border: "1px solid var(--line-strong)",
        borderBottomWidth: 2,
        borderRadius: "var(--radius-s)",
        padding: "1px 5px",
        lineHeight: 1.4,
        background: "var(--surface)",
      }}
    >
      {text}
    </kbd>
  );
}
