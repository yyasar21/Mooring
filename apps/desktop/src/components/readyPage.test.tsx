// L5: the ready-to-connect page of a selected connection, and the remote canvas surface.
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { App } from "../App";
import { useSessions } from "../stores/sessions";
import { useTree } from "../stores/tree";
import { useUi } from "../stores/ui";
import { freshBackend, settle } from "../test/harness";
import { installCanvas } from "../test/fakeGl";
import { RemoteCanvas } from "./remote/RemoteCanvas";

async function boot() {
  render(<App />);
  await screen.findByText("Nothing open yet");
  await settle();
}

describe("ready to connect page (L5)", () => {
  beforeEach(() => { freshBackend(); });

  it("shows the selected connection's facts and connects from its own Connect", async () => {
    await boot();
    act(() => { useTree.getState().select({ kind: "connection", id: "c-pg" }); });
    const page = screen.getByRole("region", { name: "pg-primary, ready to connect" });
    expect(screen.queryByText("Nothing open yet")).toBeNull();
    expect(within(page).getByRole("heading", { name: "pg-primary" })).toBeInTheDocument();
    expect(page).toHaveTextContent("pg01.example.test:2222");
    expect(page).toHaveTextContent("ProtocolSSH");
    expect(page).toHaveTextContent("Sign-indeploy bot");
    expect(page).toHaveTextContent("Tagspostgres, otp");
    // Two "Connect" buttons on screen; each is found inside its own landmark.
    const details = screen.getByRole("complementary", { name: "Details" });
    expect(within(details).getByRole("button", { name: "Connect" })).toBeInTheDocument();
    fireEvent.click(within(page).getByRole("button", { name: "Connect" }));
    await settle();
    expect(useSessions.getState().tabs.map((t) => t.connectionId)).toEqual(["c-pg"]);
    expect(screen.queryByRole("region", { name: /ready to connect$/ })).toBeNull();
    for (const t of useSessions.getState().tabs) await act(async () => { await useSessions.getState().close(t.id); });
  });

  it("says when the folder default signs in, opens the editor, and has no page for a vCenter", async () => {
    await boot();
    act(() => { useTree.getState().select({ kind: "connection", id: "c-dc" }); });
    const page = screen.getByRole("region", { name: "dc01, ready to connect" });
    expect(page).toHaveTextContent("Sign-indomain admin (folder default)");
    fireEvent.click(within(page).getByRole("button", { name: "Edit connection" }));
    expect(useUi.getState().dialog).toEqual({ kind: "connection", id: "c-dc", folderId: "f-desk" });
    act(() => { useUi.getState().closeDialog(); useTree.getState().select({ kind: "connection", id: "c-vc" }); });
    expect(screen.queryByRole("region", { name: /ready to connect$/ })).toBeNull();
    expect(screen.getByText("Nothing open yet")).toBeInTheDocument();
  });
});

describe("remote canvas surface (L5)", () => {
  it("waits on a neutral surface until the first frame", () => {
    const gl = installCanvas({ webgl: false });
    const { container } = render(
      <RemoteCanvas tabId="t" label="desk" active={false} inputEnabled showStats={false} onInput={() => undefined} onAck={() => undefined} subscribe={() => () => undefined} />,
    );
    const host = container.querySelector(".remote-host");
    expect(host).not.toHaveAttribute("data-framed");
    expect(host).toHaveTextContent("Waiting for the first frame…");
    gl.restore();
  });
});
