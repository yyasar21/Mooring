/// <reference types="vite/client" />
import { missing, RUST_CODES } from "../test/rustContract";
import { FRIENDLY } from "./errors";

// Review 4, N-14: the UI's error codes drifted from Rust's, and the mock threw the UI's own codes,
// so tests passed while the friendly text was never shown. Both are now checked against the code
// list Rust generates (`src-tauri/ipc-codes.json`).

const MOCK_SOURCES = import.meta.glob<string>(["../lib/ipc.mock*.ts", "../lib/validate*.ts"], { eager: true, query: "?raw", import: "default" });

/** Every code the mock backend can throw: it only ever builds `new IpcError("<literal>", ...)`. */
function mockCodes(): Set<string> {
  const out = new Set<string>();
  for (const text of Object.values(MOCK_SOURCES)) {
    for (const m of text.matchAll(/IpcError\("([^"]+)"/g)) if (m[1]) out.add(m[1]);
    // A non-literal code would escape this guard.
    expect(text).not.toMatch(/IpcError\((?!")/);
  }
  return out;
}

const missingCodes = missing("ipc-codes.json");

describe("error codes match Rust (N-14)", () => {
  it("the mock throws a known set of codes", () => {
    const codes = mockCodes();
    expect(codes.size).toBeGreaterThan(10);
    expect(codes).toContain("sftp.exists");
    expect(codes).toContain("input.invalid");
  });

  it("keeps none of the drifted UI-only codes", () => {
    const drifted = ["forward.bind_failed", "forward.refused", "sftp.permission", "sftp.local_path"];
    for (const c of drifted) {
      expect(Object.keys(FRIENDLY)).not.toContain(c);
      expect(mockCodes()).not.toContain(c);
    }
  });

  it.skipIf(RUST_CODES === null)(
    RUST_CODES === null ? `FRIENDLY keys are Rust codes (${missingCodes})` : "FRIENDLY keys are Rust codes (src-tauri/ipc-codes.json)",
    () => {
      for (const c of Object.keys(FRIENDLY)) expect({ code: c, inRust: RUST_CODES?.has(c) }).toEqual({ code: c, inRust: true });
    },
  );

  it.skipIf(RUST_CODES === null)(
    RUST_CODES === null ? `the mock throws only Rust codes (${missingCodes})` : "the mock throws only Rust codes (src-tauri/ipc-codes.json)",
    () => {
      for (const c of mockCodes()) expect({ code: c, inRust: RUST_CODES?.has(c) }).toEqual({ code: c, inRust: true });
    },
  );
});
