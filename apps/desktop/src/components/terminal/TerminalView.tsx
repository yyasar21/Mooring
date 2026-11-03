import { useEffect, useRef } from "react";
import { subscribeOutput, useSessions } from "../../stores/sessions";
import { useUi } from "../../stores/ui";
import { isAppShortcut } from "../../lib/shortcuts";
import { createTerminal, themeFromCss, type TermHandle } from "./xterm";

const enc = new TextEncoder();

/** One xterm per tab. Kept mounted while the tab exists so scrollback survives tab switches. */
export function TerminalView({ tabId, active }: { tabId: string; active: boolean }) {
  const hostRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<TermHandle | null>(null);
  const lastSize = useRef("");
  const theme = useUi((s) => s.theme);
  const blocked = useSessions((s) => s.tabs.find((t) => t.id === tabId)?.prompt !== null);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    const font = getComputedStyle(document.documentElement).getPropertyValue("--font-mono").trim() || "monospace";
    const term = createTerminal(host, {
      fontFamily: font,
      theme: themeFromCss(),
      onData: (d) => void useSessions.getState().send(tabId, enc.encode(d)),
      shouldPassKey: (e) => !isAppShortcut(e),
    });
    termRef.current = term;
    const off = subscribeOutput(tabId, (d) => { term.write(d); });

    const sync = () => {
      const { cols, rows } = term.fit();
      const key = `${cols}x${rows}`;
      if (cols > 0 && rows > 0 && key !== lastSize.current) {
        lastSize.current = key;
        void useSessions.getState().resize(tabId, { width: cols, height: rows });
      }
    };
    const ro = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(sync);
    ro?.observe(host);
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
