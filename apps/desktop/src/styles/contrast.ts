// WCAG 2.x contrast over the design tokens (design review 2026-11 §8). Pure: it reads the text of
// packages/ui/src/tokens.css, resolves var() references per theme and composites translucent
// colours over the surface they sit on, so CI can hold every documented pair at AA.

export type Rgba = [number, number, number, number];
export type Tokens = Map<string, string>;

/** Declarations of the first rule whose selector is exactly `selector` (comments stripped). */
export function block(css: string, selector: string): Tokens {
  const src = css.replace(/\/\*[\s\S]*?\*\//g, "");
  const at = src.indexOf(`${selector} {`);
  if (at < 0) throw new Error(`no rule for ${selector}`);
  const open = src.indexOf("{", at);
  const close = src.indexOf("}", open);
  const out: Tokens = new Map();
  for (const decl of src.slice(open + 1, close).split(";")) {
    const m = /^\s*(--[\w-]+)\s*:\s*([\s\S]+?)\s*$/.exec(decl);
    if (m?.[1] && m[2]) out.set(m[1], m[2]);
  }
  return out;
}

/** Light = `:root`; dark = `:root` overlaid with `:root[data-theme="dark"]`. */
export function themes(css: string): { light: Tokens; dark: Tokens } {
  const light = block(css, ":root");
  const dark = new Map([...light, ...block(css, ':root[data-theme="dark"]')]);
  return { light, dark };
}

/** Follow `var(--x)` chains to a literal value. */
export function resolve(t: Tokens, name: string, depth = 0): string {
  const v = t.get(name);
  if (v === undefined) throw new Error(`token ${name} is not defined`);
  const m = /^var\((--[\w-]+)\)$/.exec(v);
  if (!m?.[1]) return v;
  if (depth > 16) throw new Error(`var() cycle at ${name}`);
  return resolve(t, m[1], depth + 1);
}

export function parseColor(v: string): Rgba {
  const hex = /^#([0-9a-f]{6})$/i.exec(v.trim());
  if (hex?.[1]) {
    const n = parseInt(hex[1], 16);
    return [(n >> 16) & 255, (n >> 8) & 255, n & 255, 1];
  }
  const rgba = /^rgba?\(\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)\s*(?:,\s*([\d.]+)\s*)?\)$/i.exec(v.trim());
  if (rgba) return [Number(rgba[1]), Number(rgba[2]), Number(rgba[3]), rgba[4] === undefined ? 1 : Number(rgba[4])];
  throw new Error(`not a colour: ${v}`);
}

/** `top` painted over an opaque `base`. */
export function over(top: Rgba, base: Rgba): Rgba {
  const a = top[3];
  return [top[0] * a + base[0] * (1 - a), top[1] * a + base[1] * (1 - a), top[2] * a + base[2] * (1 - a), 1];
}

function luminance([r, g, b]: Rgba): number {
  const f = (c: number) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
}

export function ratio(a: Rgba, b: Rgba): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

/**
 * Contrast of token `fg` on token `bg`. A translucent `bg` is first composited over `base`
 * (the surface it is drawn on); a translucent `fg` over the resulting background.
 */
export function pairRatio(t: Tokens, fg: string, bg: string, base = "--surface"): number {
  const ground = parseColor(resolve(t, base));
  const back = over(parseColor(resolve(t, bg)), ground);
  const front = over(parseColor(resolve(t, fg)), back);
  return ratio(front, back);
}
