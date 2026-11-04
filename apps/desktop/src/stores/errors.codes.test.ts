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

/**
 * A3 codes the UI and mock already use while Rust adds them with K4/V2/E2/S1 (ADR-0014..0017).
 * While `ipc-codes.json` lacks one, its check is skipped with a message instead of failing; once
 * Rust ships it the normal check applies. `ASSUMED` ones are not named in the ADRs.
 */
export const PENDING_A3_CODES: Record<string, string> = {
  "kube.forbidden_request": "ADR-0014 §6, K4", "kube.rbac_denied": "ADR-0014 §6, K4", "kube.not_found": "ADR-0014 §6, K4",
  "kube.unsupported_auth": "ADR-0014 §6, K4", "kube.stream_limit": "ASSUMED for the 8-streams cap (ADR-0014 §5), K4",
  // ADR-0015 (V2), ADR-0016 source.* and ADR-0017 sync.* codes shipped with `a3` and are no longer pending.
  // E2 ships these at connect (mooring-secrets `SecretsError::code()`), but the generated
  // `ipc-codes.json` does not list them yet (it is built from src-tauri's own constructors).
  "credential.external_unavailable": "ADR-0016 §7, E2 (missing from ipc-codes.json)", "credential.external_shape": "ADR-0016 §7, E2 (missing from ipc-codes.json)",
  "credential.external_not_found": "ADR-0016 §7, E2 (missing from ipc-codes.json)", "credential.external_root_token": "ADR-0016 §7, E2 (missing from ipc-codes.json)",
};
const pending = (c: string) => RUST_CODES !== null && !RUST_CODES.has(c) && c in PENDING_A3_CODES;

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
      for (const c of Object.keys(FRIENDLY).filter((x) => !pending(x))) expect({ code: c, inRust: RUST_CODES?.has(c) }).toEqual({ code: c, inRust: true });
    },
  );

  it.skipIf(RUST_CODES === null)(
    RUST_CODES === null ? `the mock throws only Rust codes (${missingCodes})` : "the mock throws only Rust codes (src-tauri/ipc-codes.json)",
    () => {
      for (const c of [...mockCodes()].filter((x) => !pending(x))) expect({ code: c, inRust: RUST_CODES?.has(c) }).toEqual({ code: c, inRust: true });
    },
  );

  const waiting = Object.keys(PENDING_A3_CODES).filter(pending);
  it.skipIf(waiting.length > 0)(
    waiting.length > 0 ? `A3 codes are Rust codes (skipped: src-tauri/ipc-codes.json lacks ${waiting.length} yet: ${waiting.join(", ")})` : "A3 codes are Rust codes",
    () => {
      for (const c of Object.keys(PENDING_A3_CODES)) expect({ code: c, inRust: RUST_CODES?.has(c) }).toEqual({ code: c, inRust: true });
    },
  );

  it("every A3 code the mock throws is either in Rust or listed as pending", () => {
    for (const c of mockCodes()) if (RUST_CODES && !RUST_CODES.has(c)) expect({ code: c, pending: c in PENDING_A3_CODES }).toEqual({ code: c, pending: true });
  });
});
