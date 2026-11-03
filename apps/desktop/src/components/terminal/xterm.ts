// The only module that touches xterm.js. Tests replace it (jsdom has no canvas or WebGL).
import { Terminal, type ITheme } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { WebglAddon } from "@xterm/addon-webgl";

export interface TermHandle {
  write: (data: Uint8Array) => void;
  focus: () => void;
  fit: () => { cols: number; rows: number };
  setTheme: (theme: ITheme) => void;
  dispose: () => void;
}

export interface TermOptions {
  onData: (data: string) => void;
  /** Return false to keep a key away from the remote side (app shortcuts). */
  shouldPassKey: (e: KeyboardEvent) => boolean;
  theme: ITheme;
  fontFamily: string;
}

/**
 * OSC 8 hyperlinks come from remote terminal output (untrusted). xterm's default activation
 * would `window.open` them inside the app WebView, so activation is a no-op until A2 adds an
 * audited Rust `open_url` (security review 2, M-4). Rust also blocks navigation off-origin.
 */
export const inertLinkHandler = {
  activate: () => {},
  allowNonHttpProtocols: false,
} as const;

export function createTerminal(host: HTMLElement, opts: TermOptions): TermHandle {
  const term = new Terminal({
    fontFamily: opts.fontFamily,
    fontSize: 13,
    lineHeight: 1.15,
    cursorBlink: true,
    scrollback: 5000,
    allowProposedApi: false,
    theme: opts.theme,
    linkHandler: inertLinkHandler,
  });
  const fit = new FitAddon();
  term.loadAddon(fit);
  term.open(host);

  // WebGL first; on failure or context loss xterm's built-in DOM renderer stays in charge.
  try {
    const gl = new WebglAddon();
    gl.onContextLoss(() => { gl.dispose(); });
    term.loadAddon(gl);
  } catch {
    // no WebGL2 in this WebView: the default renderer is already active
  }

  term.attachCustomKeyEventHandler(opts.shouldPassKey);
  const sub = term.onData(opts.onData);

  return {
    write: (data) => { term.write(data); },
    focus: () => { term.focus(); },
    fit: () => {
      try {
        fit.fit();
      } catch {
        // host not laid out yet (hidden tab); keep the previous size
      }
      return { cols: term.cols, rows: term.rows };
    },
    setTheme: (theme) => { term.options.theme = theme; },
    dispose: () => {
      sub.dispose();
      term.dispose();
    },
  };
}

/** Terminal colours from the active CSS tokens, so the theme toggle reaches the terminal too. */
export function themeFromCss(): ITheme {
  const css = getComputedStyle(document.documentElement);
  const v = (name: string, fallback: string) => css.getPropertyValue(name).trim() || fallback;
  return {
    background: v("--term-bg", "#0e1218"),
    foreground: v("--term-fg", "#d6dde7"),
    cursor: v("--term-cursor", "#5cc8b8"),
    cursorAccent: v("--term-bg", "#0e1218"),
    selectionBackground: v("--term-selection", "rgba(92,200,184,0.28)"),
  };
}
