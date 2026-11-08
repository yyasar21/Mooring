// Harbor W2: the app's own stylesheets use Harbor token names only. The bridge-console aliases
// stay defined in tokens.css for one release (third-party CSS, detached windows), but nothing in
// this app may reference them again.

const proc = (globalThis as unknown as { process: { cwd: () => string } }).process;
const FS_MODULE = "node:fs";
const fs = (await import(/* @vite-ignore */ FS_MODULE)) as {
  readFileSync: (p: string, enc: "utf8") => string;
  readdirSync: (p: string) => string[];
};

const ALIASES = [
  "bg", "bg-sunken", "surface-raised", "glass", "void", "line", "line-strong", "text-muted", "text-faint", "accent-ink",
  "accent-soft", "accent-line", "accent-dim", "hot", "hot-soft", "hot-line", "ok", "warn", "warn-soft", "danger-soft",
  "glow-accent", "glow-accent-s", "glow-hot", "text-glow", "focus-ring", "grid-line", "grid-size", "scanline", "bracket",
  "bracket-len", "line-taut", "line-slack", "line-frayed", "term-bezel", "radius-s", "radius-m", "bevel", "shadow-pop",
  "blur", "fs-2xs", "fs-xs", "fs-s", "fs-m", "fs-l", "fs-xl", "fs-2xl", "track-micro", "track-display", "ease-out",
  "ease-snap", "dur-fast", "dur-mid", "dur-slow", "font-display", "bar-h", "indent",
];
const USE = new RegExp(`var\\(--(${ALIASES.join("|")})\\)`, "g");

const dir = `${proc.cwd()}/src/styles`;
const sheets = [
  ...fs.readdirSync(dir).filter((f) => f.endsWith(".css")).map((f) => `${dir}/${f}`),
  `${proc.cwd()}/../../packages/ui/src/primitives.css`,
];

describe("Harbor token names (W2)", () => {
  it.each(sheets.map((p) => [p.split("/").slice(-2).join("/"), p]))("%s references no deprecated alias", (_name, path) => {
    const found = [...fs.readFileSync(path, "utf8").matchAll(USE)].map((m) => m[0]);
    expect(found).toEqual([]);
  });
});

export {};
