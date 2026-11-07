// Regression for the blank window on SSH connect (2026-11-07): Tauri runs the app with
// `freezePrototype: true`, and xterm.js 6 assigned `toString` on a plain object at module load.
// Each check runs in a child Node process because freezing Object.prototype in the test runner
// would break vitest itself.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { rewriteToStringAssignments } from "./frozenPrototype";

const require = createRequire(import.meta.url);
const MODULES = {
  xterm: require.resolve("@xterm/xterm").replace(/xterm\.js$/, "xterm.mjs"),
  webgl: require.resolve("@xterm/addon-webgl").replace(/addon-webgl\.js$/, "addon-webgl.mjs"),
};
const dir = mkdtempSync(join(tmpdir(), "mooring-frozen-"));
afterAll(() => { rmSync(dir, { recursive: true, force: true }); });

/** Imports `file` in a fresh Node process with Object.prototype frozen; returns "ok" or the error. */
function loadFrozen(file: string): string {
  const script = `Object.freeze(Object.prototype);
try { await import(${JSON.stringify(`file://${file}`)}); console.log("ok"); }
catch (e) { console.log(e.constructor.name + ": " + e.message); }`;
  return execFileSync(process.execPath, ["--input-type=module", "-e", script], { encoding: "utf8" }).trim();
}

describe("xterm under Tauri's frozen Object.prototype", () => {
  for (const [name, path] of Object.entries(MODULES)) {
    it(`${name}: the unpatched module fails (keeps this test honest)`, () => {
      const raw = join(dir, `${name}.raw.mjs`);
      writeFileSync(raw, readFileSync(path, "utf8"));
      // When upstream fixes it this flips to "ok": then drop the plugin and this test.
      expect(loadFrozen(raw)).toMatch(/TypeError: .*toString/);
    });

    it(`${name}: the build rewrite loads`, () => {
      const res = rewriteToStringAssignments(readFileSync(path, "utf8"));
      expect(res.count).toBe(1);
      const fixed = join(dir, `${name}.fixed.mjs`);
      writeFileSync(fixed, res.code);
      expect(loadFrozen(fixed)).toBe("ok");
    });
  }

  it("rewrites only the exact assignment shape", () => {
    const src = 'var a;(t=>{function e(){return""}t.toString=e;t.fromString=e})(a||={});x.toString==y;';
    const res = rewriteToStringAssignments(src);
    expect(res.count).toBe(1);
    expect(res.code).toContain('Object.defineProperty(t,"toString",{value:e,');
    expect(res.code).toContain("x.toString==y;");
  });
});
