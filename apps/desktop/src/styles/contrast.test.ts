import { pairRatio, parseColor, ratio, resolve, themes } from "./contrast";

// Vitest blanks CSS modules (even `?raw`), so read the file itself. Vitest runs from apps/desktop.
const proc = (globalThis as unknown as { process: { cwd: () => string } }).process;
const FS_MODULE = "node:fs";
const fs = (await import(/* @vite-ignore */ FS_MODULE)) as { readFileSync: (p: string, enc: "utf8") => string };
const TOKENS = fs.readFileSync(`${proc.cwd()}/../../packages/ui/src/tokens.css`, "utf8");

// Design review 2026-11 §8: AA must not regress. Text ≥ 4.5:1, non-text (input borders, focus
// ring, switch track, selected-tab indicator, status dots) ≥ 3:1, in both themes. A pair is
// [foreground token, background token, surface the background is drawn on].
type Pair = [fg: string, bg: string, base?: string];

const TEXT: Pair[] = [
  ...["--text", "--text-2", "--text-3"].flatMap((fg): Pair[] => [
    [fg, "--canvas", "--canvas"],
    [fg, "--surface"],
    [fg, "--surface-2"],
  ]),
  ["--text-2", "--surface-3"], // segmented control, unpressed
  ["--text", "--selection"], // selected tree row / table row on a pane
  ["--text", "--selection", "--canvas"], // selected tree row on the sidebar
  ["--text-2", "--selection", "--canvas"],
  ["--accent", "--surface"], // links, info text
  ["--accent", "--canvas", "--canvas"],
  ["--accent", "--accent-subtle"], // info pill, pressed ghost button
  ["--accent", "--accent-subtle", "--canvas"], // current rail item
  ["--accent-text", "--accent"], // primary button label
  ...["--success", "--warning", "--danger"].flatMap((fg): Pair[] => [
    [fg, "--surface"],
    [fg, "--canvas", "--canvas"],
    [fg, `${fg}-bg`], // status pill
    [fg, `${fg}-bg`, "--canvas"], // banners on the canvas
  ]),
  ["--text", "--danger-bg"],
  ["--text", "--warning-bg"],
  ["--term-fg", "--term-bg"],
];

const NON_TEXT: Pair[] = [
  ["--border-input", "--surface"], // field border, switch track (off)
  ["--border-input", "--canvas", "--canvas"],
  ["--border-input", "--surface-2"],
  ["--accent", "--surface"], // focus ring, switch track (on), selected tab indicator
  ["--accent", "--canvas", "--canvas"],
  ["--accent", "--surface-2"],
  ["--success", "--surface-2"], // status dots on a hovered row
  ["--warning", "--surface-2"],
  ["--danger", "--surface-2"],
];

const withBase = (ps: Pair[]) => ps.map(([fg, bg, base]): [string, string, string] => [fg, bg, base ?? "--surface"]);
const { light, dark } = themes(TOKENS);

describe.each([
  ["light", light],
  ["dark", dark],
])("contrast, %s theme", (_name, t) => {
  it.each(withBase(TEXT))("text %s on %s (over %s) is at least 4.5:1", (fg, bg, base) => {
    expect(pairRatio(t, fg, bg, base).toFixed(2)).toSatisfy((r: string) => Number(r) >= 4.5);
  });
  it.each(withBase(NON_TEXT))("non-text %s on %s (over %s) is at least 3:1", (fg, bg, base) => {
    expect(pairRatio(t, fg, bg, base).toFixed(2)).toSatisfy((r: string) => Number(r) >= 3);
  });
  it("defines every Harbor token with a literal colour", () => {
    for (const name of ["--canvas", "--surface", "--surface-2", "--surface-3", "--border", "--border-strong", "--border-input",
      "--text", "--text-2", "--text-3", "--accent", "--accent-text", "--success", "--warning", "--danger"]) {
      expect(() => parseColor(resolve(t, name))).not.toThrow();
    }
  });
});

describe("contrast helpers", () => {
  it("matches the WCAG reference values", () => {
    expect(ratio([0, 0, 0, 1], [255, 255, 255, 1])).toBeCloseTo(21, 5);
    expect(ratio([118, 118, 118, 1], [255, 255, 255, 1])).toBeCloseTo(4.54, 2);
  });
  it("keeps the deprecated aliases resolvable for one release", () => {
    for (const alias of ["--bg", "--bg-sunken", "--line", "--line-strong", "--text-muted", "--text-faint", "--accent-soft", "--hot", "--ok", "--warn"]) {
      expect(() => parseColor(resolve(light, alias))).not.toThrow();
      expect(() => parseColor(resolve(dark, alias))).not.toThrow();
    }
  });
  it("composites a translucent background over its surface", () => {
    // 50 % black over white is mid grey; white text on it is ~3.95:1.
    const t = new Map([["--fg", "#ffffff"], ["--bg", "rgba(0, 0, 0, 0.5)"], ["--surface", "#ffffff"]]);
    expect(pairRatio(t, "--fg", "--bg")).toBeCloseTo(3.95, 1);
  });
});
