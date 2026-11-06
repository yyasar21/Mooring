// The Tauri transport against a fake `invoke`: command names and argument shapes of ADR-0018 §3
// (U0) and ADR-0020 (N1), the `update:available` subscription, and that none of them is polled.
import { POLLED_COMMANDS } from "./ipc";

const calls: { cmd: string; args: Record<string, unknown> | undefined }[] = [];
let reply: unknown = undefined;
const listeners = new Map<string, (e: { payload: unknown }) => void>();

vi.mock("@tauri-apps/api/core", () => {
  class Channel {
    onmessage: (msg: unknown) => void = () => undefined;
  }
  return {
    Channel,
    invoke: (cmd: string, args?: Record<string, unknown>) => {
      calls.push({ cmd, args });
      return Promise.resolve(reply);
    },
  };
});
vi.mock("@tauri-apps/api/event", () => ({
  listen: (event: string, handler: (e: { payload: unknown }) => void) => {
    listeners.set(event, handler);
    return Promise.resolve(() => { listeners.delete(event); });
  },
}));

const { TauriTransport } = await import("./ipc");

beforeEach(() => {
  calls.length = 0;
  reply = undefined;
  listeners.clear();
});

describe("TauriTransport · ADR-0018 §3 + ADR-0020", () => {
  it("names every U0 and N1 command with camelCase arguments", async () => {
    const t = new TauriTransport();
    reply = { current: "0.1.0", available: null, installMode: "manual", manualReason: "homebrew", checkedAt: "t" };
    expect(await t.updateCheck()).toEqual({ current: "0.1.0", available: null, installMode: "manual", manualReason: "homebrew", checkedAt: "t" });
    reply = undefined;
    await t.updateInstall({ version: "0.2.0", closeSessions: true });
    reply = { backgroundCheck: false, channel: "stable", lastCheck: null, lastVerified: "0.2.0" };
    expect(await t.updateSettingsGet()).toEqual({ backgroundCheck: false, channel: "stable", lastCheck: null, lastVerified: "0.2.0" });
    reply = { backgroundCheck: true, channel: "stable", lastCheck: "t" }; // an older Rust without the F2 field decodes to null
    expect(await t.updateSettingsSet({ backgroundCheck: true })).toEqual({ backgroundCheck: true, channel: "stable", lastCheck: "t", lastVerified: null });
    reply = undefined;
    await t.netTools();
    await t.netPortCheck({ target: { connectionId: "c-1" }, timeoutMs: 2000 });
    await t.netPing({ target: { host: "web01.example.test" }, count: 3 });
    await t.netTraceroute({ target: { host: "web01.example.test" }, maxHops: 10 });
    await t.netWgShow();
    expect(calls.map((c) => c.cmd)).toEqual([
      "update_check", "update_install", "update_settings_get", "update_settings_set",
      "net_tools", "net_port_check", "net_ping", "net_traceroute", "net_wg_show",
    ]);
    expect(calls[1]?.args).toEqual({ version: "0.2.0", closeSessions: true });
    expect(calls[3]?.args).toEqual({ backgroundCheck: true });
    expect(calls[5]?.args).toEqual({ target: { connectionId: "c-1" }, timeoutMs: 2000 });
    expect(calls[6]?.args).toEqual({ target: { host: "web01.example.test" }, count: 3 });
    expect(calls[7]?.args).toEqual({ target: { host: "web01.example.test" }, maxHops: 10 });
  });

  it("subscribes to update:available and decodes the payload; unsubscribing stops delivery", async () => {
    const t = new TauriTransport();
    const seen: string[] = [];
    const off = t.onUpdateAvailable((i) => seen.push(i.available?.version ?? "none"));
    await Promise.resolve();
    listeners.get("update:available")?.({ payload: { current: "0.1.0", available: { version: "0.2.0", notes: "n" }, installMode: "in_app", checkedAt: "t" } });
    expect(seen).toEqual(["0.2.0"]);
    off();
    expect(listeners.has("update:available")).toBe(false);
  });

  it("none of the U0 / N1 commands is polled (all vault-gated, none passive)", () => {
    for (const c of ["update_check", "update_install", "update_settings_get", "update_settings_set", "net_tools", "net_port_check", "net_ping", "net_traceroute", "net_wg_show"]) {
      expect(POLLED_COMMANDS).not.toContain(c);
    }
  });
});
