/// <reference types="vite/client" />
// Drift guard: every command the Tauri transport invokes must be registered in Rust's
// `generate_handler![...]` (src-tauri/src/lib.rs). The mock cannot catch a renamed or missing
// command (A5 U7: `kube_logs`, `kube_watch` and `session_open({ kube })` had drifted from K4
// unnoticed). Rust commands the UI never invokes are listed for information only.

const LIB_RS = import.meta.glob<string>("../../../../src-tauri/src/lib.rs", { eager: true, query: "?raw", import: "default" });
const IPC_TS = import.meta.glob<string>("./ipc.ts", { eager: true, query: "?raw", import: "default" });

/** Command names of the `generate_handler![ ... ]` list (the last path segment of each entry). */
export function handlerCommands(libRs: string): string[] {
  const start = libRs.indexOf("generate_handler![");
  if (start < 0) return [];
  const end = libRs.indexOf("]", start);
  const body = libRs.slice(start + "generate_handler![".length, end).replace(/\/\/[^\n]*/g, "");
  return body
    .split(",")
    .map((e) => e.trim())
    .filter(Boolean)
    .map((e) => e.split("::").at(-1) ?? e)
    .filter((n) => /^[a-z][a-z0-9_]*$/.test(n));
}

/** Command names the transport passes to `call(...)` / `invoke(...)` as string literals. */
export function invokedCommands(ipcTs: string): string[] {
  const out = new Set<string>();
  for (const m of ipcTs.matchAll(/\b(?:call|invoke)(?:<[^;(]*>)?\(\s*"([a-z][a-z0-9_]*)"/g)) if (m[1]) out.add(m[1]);
  return [...out].sort();
}

const libRs = Object.values(LIB_RS)[0] ?? "";
const ipcTs = Object.values(IPC_TS)[0] ?? "";

describe("IPC command names (ipc.ts vs src-tauri generate_handler!)", () => {
  it("parses both sides", () => {
    expect(handlerCommands("tauri::generate_handler![\n  a::one,\n  // note\n  b::c::two_x,\n]")).toEqual(["one", "two_x"]);
    expect(invokedCommands('call("a_b", {}); call<X<Y>>("c"); invoke<T>("d", x); foo("e")')).toEqual(["a_b", "c", "d"]);
    expect(handlerCommands(libRs).length).toBeGreaterThan(100);
    expect(invokedCommands(ipcTs).length).toBeGreaterThan(100);
  });

  it("every command invoked from ipc.ts is registered in Rust", () => {
    const rust = new Set(handlerCommands(libRs));
    expect(invokedCommands(ipcTs).filter((c) => !rust.has(c))).toEqual([]);
  });

  it("lists Rust commands the UI never invokes (information, not a failure)", () => {
    const ui = new Set(invokedCommands(ipcTs));
    const unused = handlerCommands(libRs).filter((c) => !ui.has(c));
    // eslint-disable-next-line no-console -- informational test output
    if (unused.length > 0) console.info(`Rust commands not invoked from ipc.ts (${String(unused.length)}): ${unused.join(", ")}`);
    expect(Array.isArray(unused)).toBe(true);
  });
});
