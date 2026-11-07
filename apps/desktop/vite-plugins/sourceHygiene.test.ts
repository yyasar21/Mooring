/**
 * No raw bidirectional control characters in the UI source ("Trojan Source", CVE-2021-42574).
 * Tests and validators that need them write `\u202e`-style escapes instead. semgrep's
 * `contains-bidirectional-characters` rule enforces the same in CI; this check fails locally
 * first (CI 2026-11-08: two files from A5 U4 carried raw U+202E).
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = join(__dirname, ".."); // apps/desktop
const DIRS = ["src", "e2e", "vite-plugins"];
const EXT = /\.(ts|tsx|mjs|js|css|html)$/;
// U+200E/F (LRM/RLM), U+202A–U+202E (embeddings/overrides), U+2066–U+2069 (isolates).
const BIDI = /[\u200e\u200f\u202a-\u202e\u2066-\u2069]/u;

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    if (name === "node_modules" || name === "results") return [];
    return statSync(p).isDirectory() ? files(p) : EXT.test(name) ? [p] : [];
  });
}

describe("source hygiene", () => {
  it("contains no raw bidi control characters", () => {
    const hits: string[] = [];
    for (const dir of DIRS) {
      for (const f of files(join(ROOT, dir))) {
        readFileSync(f, "utf8")
          .split("\n")
          .forEach((line, i) => {
            if (BIDI.test(line))
              hits.push(`${relative(ROOT, f)}:${String(i + 1)}`);
          });
      }
    }
    expect(hits).toEqual([]);
  });
});
