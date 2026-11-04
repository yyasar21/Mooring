import { ESLint } from "eslint";

// Review 4, N-11: the dialog plugin turns window.confirm into a call that resolves to a (truthy)
// Promise without asking. The lint config must refuse every native dialog.

// Vitest runs from apps/desktop (the jsdom environment hides import.meta's file URL).
const root = `${(globalThis as unknown as { process: { cwd: () => string } }).process.cwd()}/`;

async function ruleIds(code: string): Promise<string[]> {
  const eslint = new ESLint({ cwd: root, overrideConfigFile: `${root}eslint.config.js` });
  // An existing file name, so the type-aware parser accepts the text.
  const [res] = await eslint.lintText(code, { filePath: `${root}src/lib/fuzzy.ts` });
  return (res?.messages ?? []).map((m) => m.ruleId ?? m.message);
}

describe("lint: native dialogs are refused (N-11)", () => {
  it.each([
    ["window.confirm", "export const ok = (): boolean => window.confirm(\"Delete?\");\n", "no-alert"],
    ["bare confirm", "export const ok = (): boolean => confirm(\"Delete?\");\n", "no-restricted-globals"],
    ["bare alert", "export function warn(): void { alert(\"x\"); }\n", "no-restricted-globals"],
    ["bare prompt", "export const ask = (): string | null => prompt(\"name\");\n", "no-restricted-globals"],
  ])("%s", async (_name, code, rule) => {
    expect(await ruleIds(code)).toContain(rule);
  }, 60_000);

  it("leaves ordinary code alone", async () => {
    expect(await ruleIds("export const x = (a: number): number => a + 1;\n")).toEqual([]);
  }, 60_000);
});
