export function isMac(): boolean {
  return typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.userAgent);
}

/** Platform "mod" key: Cmd on macOS, Ctrl elsewhere (Super/Win is accepted too; it never reaches a shell). */
export function isMod(e: { metaKey: boolean; ctrlKey: boolean }): boolean {
  return isMac() ? e.metaKey : e.ctrlKey || e.metaKey;
}

/** App-level chords, shown in the palette. Mirrors `appCommandFor`. */
export const SHORTCUTS: { keys: string; label: string }[] = [
  { keys: "mod K", label: "Open a connection or run a command (in a terminal on Linux/Windows: mod ⇧ K)" },
  { keys: "mod W", label: "Close tab (in a terminal on Linux/Windows: mod ⇧ W)" },
  { keys: "mod ⇧ D", label: "Detach tab to a window" },
  { keys: "ctrl Tab", label: "Next tab" },
  { keys: "mod I", label: "Show or hide details" },
  { keys: "mod ⇧ L", label: "Lock vault" },
  { keys: "mod ⇧ Y", label: "Audit log" },
];

export type AppCommand = "palette" | "closeTab" | "detachTab" | "nextTab" | "prevTab" | "inspector" | "lock" | "audit";

/**
 * Map a key event to an app command. Inside a terminal on Linux/Windows, Ctrl+K/W/I belong to
 * the shell (kill line, delete word, tab), so there the app only answers to Ctrl+Shift+<key>;
 * Cmd on macOS never reaches the shell anyway. Ctrl+Shift+<key> also works outside the terminal.
 */
export function appCommandFor(e: KeyboardEvent, inTerminal: boolean): AppCommand | null {
  if (e.ctrlKey && e.key === "Tab") return e.shiftKey ? "prevTab" : "nextTab";
  if (!isMod(e) || e.altKey) return null;
  const k = e.key.toLowerCase();
  const plainAllowed = isMac() || !inTerminal || e.shiftKey || (e.metaKey && !e.ctrlKey);
  if (k === "k" && plainAllowed) return "palette";
  if (k === "w" && plainAllowed) return "closeTab";
  if (k === "i" && plainAllowed) return "inspector";
  if (e.shiftKey && k === "d") return "detachTab";
  if (e.shiftKey && k === "l") return "lock";
  if (e.shiftKey && k === "y") return "audit";
  return null;
}

/** True for chords the app handles itself, which must not reach the remote shell. */
export function isAppShortcut(e: KeyboardEvent): boolean {
  return appCommandFor(e, true) !== null;
}
