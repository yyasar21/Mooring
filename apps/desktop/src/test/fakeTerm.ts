import type { TermHandle, TermOptions } from "../components/terminal/xterm";

/** Stand-in for xterm.js in jsdom: records output and lets a test type into the terminal. */
export interface FakeTerm {
  output: string;
  type: (text: string) => void;
  disposed: boolean;
}

export const fakeTerms: FakeTerm[] = [];
const dec = new TextDecoder();

export function createFakeTerminal(_host: HTMLElement, opts: TermOptions): TermHandle {
  const t: FakeTerm = { output: "", type: (s) => { opts.onData(s); }, disposed: false };
  fakeTerms.push(t);
  return {
    write: (d) => { t.output += dec.decode(d); },
    focus: () => undefined,
    fit: () => ({ cols: 100, rows: 30 }),
    setTheme: () => undefined,
    dispose: () => { t.disposed = true; },
  };
}
