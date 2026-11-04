// Detach / attach seen from main: "Detach to window" → window_detach; the placeholder appears on
// `detached` (not before); "Bring back" → window_attach → `attached` → session_attach with fresh
// channels (credits reset, full frame). Survives a lock without pulling the session back.
import { act, fireEvent, render, screen } from "@testing-library/react";
import { freshBackend, settle } from "../../test/harness";
import type { MockTransport } from "../../lib/ipc.mock";
import { decodeMfr1 } from "../../lib/frame/mfr1";
import { subscribeFrames } from "../../stores/frames";
import { useSessions } from "../../stores/sessions";
import { useTree } from "../../stores/tree";
import { fakeTerms } from "../../test/fakeTerm";
import { Workspace } from "../Workspace";

const tab = () => useSessions.getState().tabs[0];

describe("detach and attach in main", () => {
  let mock: MockTransport;
  beforeEach(async () => {
    mock = freshBackend();
    mock.frameIntervalMs = 60_000;
    mock.phantomDetach = false; // the test plays the detached window itself
    await useTree.getState().load();
  });
  afterEach(async () => {
    for (const t of useSessions.getState().tabs) await useSessions.getState().close(t.id);
  });

  it("VNC: placeholder only after `detached`; Bring back re-attaches with fresh channels and a full frame", async () => {
    await act(async () => { await useSessions.getState().open("c-kiosk"); });
    render(<Workspace />);
    await settle();
    const sid = tab()?.sessionId ?? "";
    const detach = vi.spyOn(mock, "windowDetach");
    fireEvent.click(screen.getByRole("button", { name: "Detach to window" }));
    await settle();
    expect(detach).toHaveBeenCalledWith({ sessionId: sid });
    expect(screen.queryByRole("status", { name: "Open in a separate window" })).toBeNull(); // not before `detached`

    const view = mock.viewOf(sid);
    await act(async () => { await view.sessionAttach({ sessionId: sid, onEvent: () => undefined, onFrame: () => undefined }); });
    await settle();
    expect(tab()?.state).toBe("detached");
    const card = screen.getByRole("status", { name: "Open in a separate window" });
    expect(card).toHaveTextContent("lobby-kiosk is shown in its own window");

    const attach = vi.spyOn(mock, "sessionAttach");
    const back = vi.spyOn(mock, "windowAttach");
    fireEvent.click(screen.getByRole("button", { name: "Bring back" }));
    await settle(4);
    expect(back).toHaveBeenCalledWith({ sessionId: sid });
    expect(attach).toHaveBeenCalledTimes(1);
    const args = attach.mock.calls[0]?.[0];
    expect(args?.sessionId).toBe(sid);
    expect(typeof args?.onFrame).toBe("function");
    expect(tab()).toMatchObject({ state: "connected", attachEpoch: 1, desktop: { width: 1280, height: 800 } });
    expect(screen.queryByRole("status", { name: "Open in a separate window" })).toBeNull();
    expect(mock.remote.get(sid)?.inFlight).toBe(0); // credits reset

    const seen: boolean[] = [];
    const off = subscribeFrames(tab()?.id ?? "", (m) => seen.push(decodeMfr1(m).full));
    mock.pumpOnce(sid);
    expect(seen).toEqual([true]);
    off();
  });

  it("SSH: re-attach passes no frame channel, notes the gap and resends the terminal size", async () => {
    mock.trustedHosts.add("web01.example.test");
    await act(async () => { await useSessions.getState().open("c-web01"); });
    render(<Workspace />);
    await settle();
    const sid = tab()?.sessionId ?? "";
    expect(await useSessions.getState().detach(tab()?.id ?? "")).toBe(true);
    await act(async () => { await mock.viewOf(sid).sessionAttach({ sessionId: sid, onEvent: () => undefined }); });
    await settle();
    expect(screen.getByRole("status", { name: "Open in a separate window" })).toBeInTheDocument();
    const attach = vi.spyOn(mock, "sessionAttach");
    const send = vi.spyOn(mock, "sessionSend");
    await act(async () => { await mock.windowAttach({ sessionId: sid }); });
    await settle(4);
    expect(attach.mock.calls[0]?.[0]).not.toHaveProperty("onFrame");
    expect(tab()).toMatchObject({ state: "connected", attachEpoch: 1 });
    expect(fakeTerms.at(-1)?.output).toContain("back from its own window");
    expect(send).toHaveBeenCalledWith({ sessionId: sid, input: { kind: "resize", size: { width: 100, height: 30 } } });
  });

  it("no detach for web tabs or before the session is connected; window_detach errors are shown", async () => {
    await act(async () => { await useSessions.getState().open("c-lb"); });
    expect(await useSessions.getState().detach(tab()?.id ?? "")).toBe(false);
    render(<Workspace />);
    await settle();
    expect(screen.queryByRole("button", { name: /Detach edge-lb/ })).toBeNull();
    await act(async () => { await useSessions.getState().open("c-kiosk"); });
    mock.vault = "locked";
    expect(await useSessions.getState().detach(useSessions.getState().tabs[1]?.id ?? "")).toBe(false);
    expect(useSessions.getState().error).toBe("The vault is locked.");
    mock.vault = "unlocked";
  });

  it("a lock keeps a detached session in its window: the adopted tab stays a placeholder", async () => {
    await act(async () => { await useSessions.getState().open("c-kiosk"); });
    await settle();
    const sid = tab()?.sessionId ?? "";
    mock.phantomDetach = true;
    await useSessions.getState().detach(tab()?.id ?? "");
    await vi.waitFor(() => { expect(tab()?.state).toBe("detached"); });
    useSessions.getState().reset(); // lock
    const attach = vi.spyOn(mock, "sessionAttach");
    useSessions.getState().adopt(await mock.sessionList());
    await settle();
    expect(tab()).toMatchObject({ sessionId: sid, state: "detached" });
    expect(attach).not.toHaveBeenCalled();
    // Bringing it back after the unlock still works through the kept channel.
    await act(async () => { await mock.windowAttach({ sessionId: sid }); });
    await settle(4);
    expect(attach).toHaveBeenCalledTimes(1);
    expect(tab()?.state).toBe("connected");
  });
});
