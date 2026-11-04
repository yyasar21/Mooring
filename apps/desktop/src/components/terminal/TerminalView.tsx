import { useEffect, useRef } from "react";
import { subscribeOutput } from "../../stores/output";
import type { Size } from "../../lib/ipc";
import { useUi } from "../../stores/ui";
import { isAppShortcut } from "../../lib/shortcuts";
import { createTerminal, themeFromCss, type TermHandle } from "./xterm";

const enc = new TextEncoder();

export interface TerminalViewProps {
  /** Output buffer key (`stores/output.ts`): the tab id, or the detached view's key. */
  tabId: string;
  active: boolean;
  /** A prompt is open over the terminal: it must not take focus. */
  blocked: boolean;
  onData: (data: Uint8Array) => void;
  onResize: (size: Size) => void;
  /** A change makes the terminal send its size again (after the session comes back from a window). */
  resyncKey?: number;
}

/**
 * One xterm per tab. Kept mounted while the tab exists so scrollback survives tab switches. It
 * holds no store: the main window and the detached window wire input and resizes themselves.
 */
export function TerminalView({ tabId, active, blocked, onData, onResize, resyncKey = 0 }: TerminalViewProps) {
  const hostRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<TermHandle | null>(null);
  const lastSize = useRef("");
  const syncRef = useRef<() => void>(() => undefined);
  const cb = useRef({ onData, onResize });
  useEffect(() => {
    cb.current = { onData, onResize };
  });
  const theme = useUi((s) => s.theme);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    const font = getComputedStyle(document.documentElement).getPropertyValue("--font-mono").trim() || "monospace";
    const term = createTerminal(host, {
      fontFamily: font,
      theme: themeFromCss(),
      onData: (d) => { cb.current.onData(enc.encode(d)); },
      shouldPassKey: (e) => !isAppShortcut(e),
    });
    termRef.current = term;
    const off = subscribeOutput(tabId, (d) => { term.write(d); });

    const sync = () => {
      const { cols, rows } = term.fit();
      const key = `${cols}x${rows}`;
      if (cols > 0 && rows > 0 && key !== lastSize.current) {
        lastSize.current = key;
        cb.current.onResize({ width: cols, height: rows });
      }
    };
    const ro = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(sync);
    ro?.observe(host);
    syncRef.current = sync;
    sync();

    return () => {
      ro?.disconnect();
      off();
      term.dispose();
      termRef.current = null;
    };
  }, [tabId]);

  useEffect(() => {
    termRef.current?.setTheme(themeFromCss());
  }, [theme]);

  useEffect(() => {
    if (resyncKey === 0) return;
    lastSize.current = "";
    syncRef.current();
  }, [resyncKey]);

  useEffect(() => {
    if (active && !blocked) {
      const id = requestAnimationFrame(() => {
        termRef.current?.fit();
        termRef.current?.focus();
      });
      return () => { cancelAnimationFrame(id); };
    }
    return undefined;
  }, [active, blocked]);

  return <div ref={hostRef} className="term-host" data-testid={`terminal-${tabId}`} />;
}
