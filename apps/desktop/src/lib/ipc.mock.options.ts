// Mock `connection_options_get/set` (ADR-0011 migration 0005): same rules as
// `src-tauri/src/commands/conn_options.rs` + `mooring_core::options` (unknown fields, wrong
// protocol, maxFps, the 128 KiB cap, per-protocol validation), refusals without echoing values.
import type { ProtocolOptions, RemoteIpc } from "./ipc.types";
import { MAX_FPS_VALUES, OPTION_LIMITS, type MaxFps } from "./ipc.types.remote";
import { IpcError } from "./ipc.error";
import { MockDetachBase } from "./ipc.mock.detach";
import { hasOptions, normalizeOptions, unknownField, validateOptions } from "./validate.options";

export abstract class MockOptionsBase extends MockDetachBase {
  /** Replace the stored options of a connection (MockTransport owns the rows). */
  protected abstract storeOptions(connectionId: string, options: ProtocolOptions): void;

  connectionOptionsGet: RemoteIpc["connectionOptionsGet"] = async ({ connectionId }) => {
    await this.unlocked();
    const t = this.target(connectionId);
    return normalizeOptions(t.protocol, t.options ?? {});
  };

  connectionOptionsSet: RemoteIpc["connectionOptionsSet"] = async ({ connectionId, options }) => {
    await this.unlocked();
    const t = this.target(connectionId);
    if (typeof options !== "object" || Array.isArray(options)) throw new IpcError("input.invalid", "invalid options: must be a JSON object");
    if (JSON.stringify(options).length > OPTION_LIMITS.maxOptionsJson) throw new IpcError("input.invalid", "invalid options: larger than 128 KiB");
    const raw = options as Record<string, unknown>;
    const unknown = unknownField(t.protocol, raw);
    if (unknown !== null) {
      const name = /^[A-Za-z0-9_]{1,32}$/.test(unknown) ? ` ${unknown}` : "";
      throw new IpcError("input.invalid", `invalid options: unknown field${name}`);
    }
    if (hasOptions(t.protocol) && "maxFps" in raw && !MAX_FPS_VALUES.includes(raw.maxFps as MaxFps)) {
      throw new IpcError("input.invalid", "invalid options: maxFps must be 30 or 60");
    }
    const typed = normalizeOptions(t.protocol, raw);
    const parsed = typed as Record<string, unknown>;
    // serde refuses a wrong type where normalizeOptions would fall back to the default.
    if (Object.keys(raw).some((k) => JSON.stringify(raw[k]) !== JSON.stringify(parsed[k]))) {
      throw new IpcError("input.invalid", "invalid options: invalid value or type");
    }
    const errors = Object.values(validateOptions(t.protocol, typed));
    if (errors.length > 0) throw new IpcError("input.invalid", "invalid options: value refused");
    this.storeOptions(connectionId, typed);
    return normalizeOptions(t.protocol, typed);
  };
}
