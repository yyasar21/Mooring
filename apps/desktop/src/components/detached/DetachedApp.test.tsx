// The detached window (`#/detached/<sessionId>`) calls only what `capabilities/detached.json`
// grants: the commands listed for `detached-<sessionId>` in src-tauri/ipc-manifest.json. The
// router mounts it instead of App, so the main boot (vault_status, app_info, listen) never runs.
import { act, render, screen, fireEvent, waitFor } from "@testing-library/react";
import { setIpc, type Ipc } from "../../lib/ipc";
import { commandName, DETACHED_COMMANDS } from "../../lib/ipc.mock.detach";
import { MockTransport } from "../../lib/ipc.mock";
import { resetBootRoute, detachedSessionId } from "../../lib/route";
import { RUST_DETACHED_COMMANDS } from "../../test/rustContract";
import { fakeTerms } from "../../test/fakeTerm";
import { settle } from "../../test/harness";
import { Root } from "../../Root";

/** Wrap a transport and record the command name of every call. */
function recording(inner: Ipc): { ipc: Ipc; calls: string[] } {
  const calls: string[] = [];
  const ipc = new Proxy(inner, {
    get(target, prop, receiver) {
      const v: unknown = Reflect.get(target, prop, receiver);
      if (typeof prop !== "string" || typeof v !== "function") return v;
      return (...args: unknown[]) => {
        calls.push(prop === "onVaultLocked" ? "listen" : commandName(prop));
        return (v as (...a: unknown[]) => unknown).apply(target, args);
      };
    },
  });
  return { ipc, calls };
}

async function sshSession(m: MockTransport): Promise<{ sessionId: string; main: string[] }> {
  m.trustedHosts.add("web01.example.test");
  const main: string[] = [];
  const { sessionId } = await m.sessionOpen({ connectionId: "c-web01", size: { width: 80, height: 24 }, onEvent: (e) => main.push(e.kind) });
  await vi.waitFor(() => { expect(main).toContain("connected"); });
  return { sessionId, main };
}

async function mountDetached(m: MockTransport, sessionId: string) {
  const { ipc, calls } = recording(m.viewOf(sessionId));
  setIpc(ipc);
  window.location.hash = `#/detached/${sessionId}`;
  resetBootRoute();
  render(<Root />);
  await settle(4);
  return calls;
}

describe("detached window route", () => {
  afterEach(() => {
    window.location.hash = "";
    resetBootRoute();
  });

  it("parses only #/detached/<id>", () => {
    expect(detachedSessionId("#/detached/3f2a9c1e-0b7d-4e5f-9a8b-1c2d3e4f5a6b")).toBe("3f2a9c1e-0b7d-4e5f-9a8b-1c2d3e4f5a6b");
    for (const h of ["", "#/", "#/detached/", "#/detached/a/b", "#/detached/a?x=1", "#/detached/<x>", "#detached/a", `#/detached/${"a".repeat(65)}`]) {
      expect(detachedSessionId(h)).toBeNull();
    }
  });

  it("the mock's detached list is Rust's (src-tauri/ipc-manifest.json)", () => {
    // N-36: the manifest is committed; a missing file is a broken checkout, not a reason to skip.
    expect(RUST_DETACHED_COMMANDS, "src-tauri/ipc-manifest.json is committed; it must resolve from this test").not.toBeNull();
    expect(new Set(DETACHED_COMMANDS)).toEqual(RUST_DETACHED_COMMANDS);
  });

  it("SSH: attaches, streams output, sends input and its size, brings back — only granted commands", async () => {
    const m = new MockTransport();
    m.phantomDetach = false;
    const { sessionId, main } = await sshSession(m);
    await m.windowDetach({ sessionId });
    const calls = await mountDetached(m, sessionId);

    expect(screen.getByRole("toolbar", { name: "Detached session" })).toHaveTextContent("SSH · separate window");
    expect(main.at(-1)).toBe("detached"); // main shows its placeholder now
    // The terminal mounts after a lazy import; slow runners need to wait for it.
    await waitFor(() => { expect(fakeTerms.length).toBeGreaterThan(0); }, { timeout: 5000 });
    const term = fakeTerms.at(-1);
    act(() => { term?.type("hi\r"); });
    await waitFor(() => { expect(term?.output ?? "").toContain("hi"); }, { timeout: 5000 });
    fireEvent.click(screen.getByRole("button", { name: "Bring back" }));
    await settle();
    expect(main.at(-1)).toBe("attached");

    const granted = RUST_DETACHED_COMMANDS ?? new Set<string>(DETACHED_COMMANDS);
    expect(calls.length).toBeGreaterThan(0);
    for (const c of calls) expect({ command: c, granted: granted.has(c) }).toEqual({ command: c, granted: true });
    expect(calls).toEqual(expect.arrayContaining(["session_attach", "session_send", "window_attach"]));
    expect(m.forbidden).toEqual([]);
  });

  it("VNC: attaches with a frame channel, acks what it draws, shows the session end", async () => {
    const m = new MockTransport();
    m.phantomDetach = false;
    m.frameIntervalMs = 60_000;
    const main: string[] = [];
    const { sessionId } = await m.sessionOpen({
      connectionId: "c-kiosk", size: { width: 800, height: 600 }, onEvent: (e) => main.push(e.kind), onFrame: () => undefined,
    });
    await vi.waitFor(() => { expect(main).toContain("desktop_resized"); });
    const calls = await mountDetached(m, sessionId);
    expect(screen.getByRole("toolbar", { name: "Detached session" })).toHaveTextContent("VNC · separate window");
    expect(screen.getByRole("img", { name: "VNC desktop" })).toBeInTheDocument();
    m.pumpOnce(sessionId);
    await settle();
    await act(async () => { await m.sessionClose({ sessionId }); });
    await settle();
    expect(screen.getByRole("alert")).toHaveTextContent("Session ended");
    expect(main.at(-1)).toBe("closed"); // closed reaches main too

    const granted = RUST_DETACHED_COMMANDS ?? new Set<string>(DETACHED_COMMANDS);
    for (const c of calls) expect({ command: c, granted: granted.has(c) }).toEqual({ command: c, granted: true });
    expect(calls).not.toContain("vault_status");
    expect(calls).not.toContain("listen");
    expect(m.forbidden).toEqual([]);
  });

  it("an attach failure is shown, not retried with forbidden commands", async () => {
    const m = new MockTransport();
    const calls = await mountDetached(m, "s-gone");
    expect(screen.getByRole("alert")).toHaveTextContent("Could not attach");
    expect(new Set(calls)).toEqual(new Set(["session_attach"]));
    expect(m.forbidden).toEqual([]);
  });

  it("the main route still boots the main app", async () => {
    const m = new MockTransport({ vault: "missing" });
    const { ipc, calls } = recording(m);
    setIpc(ipc);
    resetBootRoute();
    render(<Root />);
    await settle();
    expect(calls).toEqual(expect.arrayContaining(["app_info", "vault_status", "listen"]));
  });
});
