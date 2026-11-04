/// <reference types="vite/client" />
import ts from "typescript";
import { missing, RUST_PASSIVE } from "../test/rustContract";
import { POLLED_COMMANDS } from "./ipc";

// Review 4, M-8: a command polled from a timer must be passive on the backend, or the idle lock
// never fires while its panel is open. Every `setInterval` callback in the app is traced (through
// the functions it calls in the same file) to the `ipc.*` methods it reaches.

const SOURCES = import.meta.glob<string>(["../**/*.{ts,tsx}", "!../**/*.test.{ts,tsx}", "!../test/**", "!../lib/ipc.mock*.ts"], {
  eager: true,
  query: "?raw",
  import: "default",
});

const parse = (path: string, text: string) => ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, path.endsWith("x") ? ts.ScriptKind.TSX : ts.ScriptKind.TS);

/** `TauriTransport` method name -> the command string it passes to `call(...)`. */
function commandOfMethod(): Map<string, string> {
  const src = SOURCES["./ipc.ts"];
  if (!src) throw new Error("lib/ipc.ts not found");
  const map = new Map<string, string>();
  const visit = (n: ts.Node): void => {
    if (ts.isClassDeclaration(n) && n.name?.text === "TauriTransport") {
      for (const m of n.members) {
        if (!ts.isPropertyDeclaration(m) || !m.initializer || !ts.isIdentifier(m.name)) continue;
        const name = m.name.text;
        const find = (x: ts.Node): void => {
          if (ts.isCallExpression(x) && ts.isIdentifier(x.expression) && x.expression.text === "call") {
            const arg = x.arguments[0];
            if (arg && ts.isStringLiteral(arg)) map.set(name, arg.text);
          }
          ts.forEachChild(x, find);
        };
        find(m.initializer);
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(parse("ipc.ts", src));
  return map;
}

/** Declarations by name in one file (functions, consts, useCallback results). */
function declarations(file: ts.SourceFile): Map<string, ts.Node> {
  const out = new Map<string, ts.Node>();
  const visit = (n: ts.Node): void => {
    if (ts.isFunctionDeclaration(n) && n.name) out.set(n.name.text, n);
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer) out.set(n.name.text, n.initializer);
    ts.forEachChild(n, visit);
  };
  visit(file);
  return out;
}

/** `ipc.<method>` names reached from `root`, following calls to same-file declarations. */
function ipcMethodsReached(root: ts.Node, decls: Map<string, ts.Node>): Set<string> {
  const found = new Set<string>();
  const seen = new Set<ts.Node>();
  const walk = (n: ts.Node): void => {
    if (seen.has(n)) return;
    seen.add(n);
    if (ts.isPropertyAccessExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === "ipc") found.add(n.name.text);
    if (ts.isIdentifier(n)) {
      const d = decls.get(n.text);
      if (d && d !== root) walk(d);
    }
    ts.forEachChild(n, walk);
  };
  walk(root);
  return found;
}

interface Poller { file: string; commands: string[] }

function pollers(): Poller[] {
  const cmd = commandOfMethod();
  const out: Poller[] = [];
  for (const [path, text] of Object.entries(SOURCES)) {
    if (!text.includes("setInterval")) continue;
    const file = parse(path, text);
    const decls = declarations(file);
    const visit = (n: ts.Node): void => {
      if (ts.isCallExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === "setInterval" && n.arguments[0]) {
        const methods = ipcMethodsReached(n.arguments[0], decls);
        out.push({ file: path, commands: [...methods].map((m) => cmd.get(m) ?? `<unknown ipc.${m}>`) });
      }
      ts.forEachChild(n, visit);
    };
    visit(file);
  }
  return out;
}

describe("polled commands (M-8)", () => {
  it("every setInterval poller calls only POLLED_COMMANDS", () => {
    const all = pollers();
    expect(all.length).toBeGreaterThanOrEqual(3); // Telemetry (audit + clock), CopySecret ticker, Forwards
    for (const p of all) {
      for (const c of p.commands) expect({ file: p.file, command: c, polled: POLLED_COMMANDS.includes(c) }).toEqual({ file: p.file, command: c, polled: true });
    }
    // The tracer works: the two real pollers are found through their local helpers.
    const reached = new Set(all.flatMap((p) => p.commands));
    expect([...reached].sort()).toEqual(["audit_verify", "forward_list"]);
  });

  it("maps every transport method to a command", () => {
    const cmd = commandOfMethod();
    expect(cmd.get("forwardList")).toBe("forward_list");
    expect(cmd.get("auditVerify")).toBe("audit_verify");
    expect(cmd.size).toBeGreaterThan(40);
  });

  it.skipIf(RUST_PASSIVE === null)(
    RUST_PASSIVE === null ? `POLLED_COMMANDS are passive in Rust (${missing("ipc-passive.json")})` : "POLLED_COMMANDS are passive in Rust (src-tauri/ipc-passive.json)",
    () => {
      for (const c of POLLED_COMMANDS) expect({ command: c, passive: RUST_PASSIVE?.has(c) }).toEqual({ command: c, passive: true });
    },
  );
});
