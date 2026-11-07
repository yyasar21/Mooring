// Build-time fix for third-party code that breaks under Tauri's `freezePrototype: true`.
//
// With `Object.prototype` frozen, `toString` is a non-writable inherited property, so a plain
// assignment `obj.toString = fn` throws in strict code (every ES module). xterm.js 6 and its
// WebGL addon bundle VS Code's `KeyCodeUtils` namespace, which does exactly that at module
// evaluation; the terminal chunk then fails to load and React unmounts the whole window (blank
// page on "Connect" for SSH, macOS and Windows alike — 2026-11-07). `Object.defineProperty`
// creates an own property instead and is unaffected by the frozen prototype.
//
// The rewrite is exact and counted: an xterm upgrade that changes the code fails the build here
// instead of shipping a blank terminal. Remove the plugin once upstream stops assigning.
import type { Plugin } from "vite";

const TARGETS: { test: RegExp; expected: number }[] = [
  { test: /[\\/]@xterm[\\/]xterm[\\/]lib[\\/]xterm\.mjs$/, expected: 1 },
  { test: /[\\/]@xterm[\\/]addon-webgl[\\/]lib[\\/]addon-webgl\.mjs$/, expected: 1 },
];

// `ns.toString=fn;` (minified identifiers), as emitted in the KeyCodeUtils IIFE.
const ASSIGN = /([A-Za-z_$][\w$]*)\.toString=([A-Za-z_$][\w$]*);/g;

export function rewriteToStringAssignments(code: string): { code: string; count: number } {
  let count = 0;
  const out = code.replace(ASSIGN, (_m, obj: string, fn: string) => {
    count += 1;
    return `Object.defineProperty(${obj},"toString",{value:${fn},writable:!0,enumerable:!0,configurable:!0});`;
  });
  return { code: out, count };
}

export function frozenPrototypeCompat(): Plugin {
  return {
    name: "mooring:frozen-prototype-compat",
    enforce: "pre",
    transform(code, id) {
      const path = id.split("?")[0] ?? id;
      const target = TARGETS.find((t) => t.test.test(path));
      if (!target) return null;
      const res = rewriteToStringAssignments(code);
      if (res.count !== target.expected) {
        this.error(
          `frozen-prototype-compat: expected ${String(target.expected)} toString assignment(s) in ${path}, found ${String(res.count)}; re-check the xterm upgrade`,
        );
      }
      return { code: res.code, map: null };
    },
  };
}
