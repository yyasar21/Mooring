import { act } from "@testing-library/react";
import { IpcError } from "../lib/ipc";
import type { MockTransport } from "../lib/ipc.mock";
import { freshBackend, settle } from "../test/harness";
import { backoffProgress } from "../components/remote/ConnectionBanner";
import { describeError, FRIENDLY } from "./errors";
import { useSessions } from "./sessions";
import { cancelReconnect } from "./sessions.reconnect";
import { useTree } from "./tree";

const tab = () => useSessions.getState().tabs[0];

describe("A2 error texts", () => {
  it("has friendly text for the trust, security, protocol, window and clipboard codes", () => {
    for (const c of ["session.trust_rejected", "session.trust_mismatch", "session.unsupported_security", "protocol.unavailable", "ipc.forbidden", "clipboard.unavailable"]) {
      expect(FRIENDLY[c]).toMatch(/\.$/);
    }
    expect(describeError(new IpcError("session.trust_mismatch", "CERTIFICATE CHANGED"))).toMatch(/remove the stored certificate in Settings → Trust/);
  });

  it("a session_open refused for trust keeps the close code and shows the friendly text", async () => {
    const mock = freshBackend();
    await useTree.getState().load();
    vi.spyOn(mock, "sessionOpen").mockRejectedValueOnce(new IpcError("session.trust_mismatch", "CERTIFICATE CHANGED for dc01.example.test:3389"));
    await act(async () => { await useSessions.getState().open("c-dc"); });
    expect(tab()).toMatchObject({ state: "closed", closeCode: "trust_mismatch" });
    expect(tab()?.reason).toMatch(/Settings → Trust/);
  });

  it("http.trust_conflict (6b L-35) fails closed: friendly text, trust_conflict close code, no host or fingerprint", () => {
    expect(FRIENDLY["http.trust_conflict"]).toBe(
      "This host has two different trusted certificates (synced from another device). Remove one in Settings → Trust before connecting.",
    );
    expect(describeError(new IpcError("http.trust_conflict", "conflicting pins"))).not.toMatch(/SHA256|example\.test/);
  });

  it("a session_open refused with http.trust_conflict keeps the close code", async () => {
    const mock = freshBackend();
    await useTree.getState().load();
    vi.spyOn(mock, "sessionOpen").mockRejectedValueOnce(new IpcError("http.trust_conflict", "conflicting pins"));
    await act(async () => { await useSessions.getState().open("c-kiosk"); });
    expect(tab()).toMatchObject({ state: "closed", closeCode: "trust_conflict", reconnect: null });
    expect(tab()?.reason).toMatch(/Remove one in Settings → Trust/);
  });

  it("conflicting pins close the session with trust_conflict and never schedule a reconnect", async () => {
    const mock = freshBackend();
    await useTree.getState().load();
    const t = { connectionId: "c-kiosk", protocol: "vnc" as const, name: "lobby-kiosk", host: "kiosk.example.test", port: 5900, tags: [], options: undefined };
    await mock.pin(t);
    await mock.pin(t, undefined, "#laptop");
    await act(async () => { await useSessions.getState().open("c-kiosk"); });
    await settle();
    expect(tab()).toMatchObject({ state: "closed", closeCode: "trust_conflict", reconnect: null, sessionId: null });
    expect(tab()?.reason).toMatch(/conflicting certificates for kiosk\.example\.test:5900/);
    expect(tab()?.reason).not.toMatch(/SHA256/);
    // no prompt was raised and the mock session is gone (no backoff timers)
    expect(tab()?.prompt).toBeNull();
    expect(mock.remote.size).toBe(0);
  });
});

describe("options-driven session state", () => {
  it("initial VNC view-only comes from connection_options_get, not the tree row", async () => {
    const mock = freshBackend();
    mock.frameIntervalMs = 60_000;
    await useTree.getState().load();
    // Rust's tree rows carry no options.
    useTree.setState({ connections: useTree.getState().connections.map((row) => {
      const c = { ...row };
      delete c.options;
      return c;
    }) });
    const spy = vi.spyOn(mock, "connectionOptionsGet");
    await act(async () => { await useSessions.getState().open("c-kiosk"); });
    expect(spy).toHaveBeenCalledWith({ connectionId: "c-kiosk" });
    expect(tab()?.viewOnly).toBe(true);
    await useSessions.getState().close(tab()?.id ?? "");
  });
});

describe("reconnect", () => {
  let mock: MockTransport;
  beforeEach(async () => {
    mock = freshBackend();
    mock.frameIntervalMs = 60_000;
    await useTree.getState().load();
  });

  it("Cancel reconnect closes the backend session and keeps the tab for a manual Reconnect", async () => {
    await act(async () => { await useSessions.getState().open("c-kiosk"); });
    await settle();
    const sid = tab()?.sessionId ?? "";
    mock.reconnectDelaysMs = [60_000];
    act(() => { mock.dropLink(sid, 1); });
    await settle(1);
    expect(tab()?.state).toBe("reconnecting");
    const close = vi.spyOn(mock, "sessionClose");
    await act(async () => { await cancelReconnect(tab()?.id ?? ""); });
    expect(close).toHaveBeenCalledWith({ sessionId: sid });
    expect(tab()).toMatchObject({ state: "closed", closeCode: "user", reconnect: null, sessionId: null });
    expect(mock.remote.has(sid)).toBe(false);
    await act(async () => { await useSessions.getState().reconnect(tab()?.id ?? ""); });
    await settle();
    expect(tab()?.state).toBe("connected");
    await useSessions.getState().close(tab()?.id ?? "");
  });

  it("does nothing unless the tab is reconnecting", async () => {
    await act(async () => { await useSessions.getState().open("c-kiosk"); });
    await settle();
    const close = vi.spyOn(mock, "sessionClose");
    await cancelReconnect(tab()?.id ?? "");
    expect(close).not.toHaveBeenCalled();
    expect(tab()?.state).toBe("connected");
    await useSessions.getState().close(tab()?.id ?? "");
  });

  it("backoff progress: seconds left and elapsed fraction", () => {
    expect(backoffProgress({ delayMs: 4000, since: 1000 }, 1000)).toEqual({ secs: 4, fraction: 0 });
    expect(backoffProgress({ delayMs: 4000, since: 1000 }, 3000)).toEqual({ secs: 2, fraction: 0.5 });
    expect(backoffProgress({ delayMs: 4000, since: 1000 }, 9000)).toEqual({ secs: 0, fraction: 1 });
    expect(backoffProgress({ delayMs: 0, since: 0 }, 0)).toEqual({ secs: 0, fraction: 1 });
  });
});
