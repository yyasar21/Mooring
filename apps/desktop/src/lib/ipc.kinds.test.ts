/// <reference types="vite/client" />
import { KIND_SCHEMAS } from "./ipc.kinds";

// The kind table Rust serves (`credential_kinds()`) is dumped to `kinds.snapshot.json` by a Rust
// test that fails when it drifts from this file. Check the same equality from this side.
const SNAPSHOT = import.meta.glob<unknown>("../../../../src-tauri/src/commands/kinds.snapshot.json", { eager: true, import: "default" });

describe("credential kinds match src-tauri/src/commands/kinds.snapshot.json", () => {
  const raw = Object.values(SNAPSHOT)[0];
  it.skipIf(raw === undefined)("every kind, field and consumer is identical", () => {
    const rust = raw as { kind: string }[];
    expect(rust.map((k) => k.kind)).toEqual(KIND_SCHEMAS.map((k) => k.kind));
    for (const [i, k] of KIND_SCHEMAS.entries()) {
      expect(JSON.parse(JSON.stringify(k))).toEqual(rust[i]);
    }
  });

  it("the two A3 kinds serve a consumer and no protocol", () => {
    const approle = KIND_SCHEMAS.find((k) => k.kind === "vault_approle");
    const s3 = KIND_SCHEMAS.find((k) => k.kind === "s3_access_key");
    expect(approle).toMatchObject({ protocols: [], consumers: ["secret_source"] });
    expect(s3).toMatchObject({ protocols: [], consumers: ["sync"] });
    // Every secret of both kinds is write-only: nothing is copyable.
    for (const f of [...(approle?.fields ?? []), ...(s3?.fields ?? [])]) expect(f.copyable).toBe(false);
    expect(approle?.fields.map((f) => [f.name, f.secret])).toEqual([["role_id", true], ["secret_id", true]]);
    expect(s3?.fields.filter((f) => f.secret).map((f) => f.name)).toEqual(["secret_access_key", "session_token"]);
  });
});
