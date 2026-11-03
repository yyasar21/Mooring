import { useEffect } from "react";
import { appCommandFor } from "../lib/shortcuts";
import { useApp } from "../stores/app";
import { useSessions } from "../stores/sessions";
import { useUi } from "../stores/ui";

/** Window-level shortcuts. Capture phase so they win over focused widgets; see lib/shortcuts.ts. */
export function useShortcuts(): void {
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const target = e.target instanceof HTMLElement ? e.target : null;
      const inTerminal = target?.closest(".term-host") !== null && target !== null;
      const cmd = appCommandFor(e, inTerminal);
      if (!cmd) return;
      const ui = useUi.getState();
      const s = useSessions.getState();
      const idx = s.tabs.findIndex((t) => t.id === s.activeTab);
      e.preventDefault();
      e.stopPropagation();
      switch (cmd) {
        case "palette":
          ui.setPalette(!ui.paletteOpen);
          break;
        case "closeTab":
          if (s.activeTab) void s.close(s.activeTab);
          break;
        case "detachTab":
          if (s.activeTab) void s.detach(s.activeTab);
          break;
        case "nextTab":
        case "prevTab": {
          if (s.tabs.length === 0) break;
          const step = cmd === "nextTab" ? 1 : -1;
          const next = s.tabs[(idx + step + s.tabs.length) % s.tabs.length];
          if (next) {
            ui.setView("workspace");
            s.activate(next.id);
          }
          break;
        }
        case "inspector":
          ui.toggleInspector();
          break;
        case "lock":
          void useApp.getState().lock();
          break;
        case "audit":
          ui.setView(ui.view === "audit" ? "workspace" : "audit");
          break;
      }
    }
    window.addEventListener("keydown", onKey, true);
    return () => { window.removeEventListener("keydown", onKey, true); };
  }, []);
}
