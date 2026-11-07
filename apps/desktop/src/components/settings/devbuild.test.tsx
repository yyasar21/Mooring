import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { App } from "../../App";
import { useApp } from "../../stores/app";
import { useUi } from "../../stores/ui";
import { freshBackend, settle } from "../../test/harness";
import { describeError } from "../../stores/errors";
import { DEV_MANUAL_TEXT } from "../../lib/ipc.mock.update";
import { AboutCard } from "./AboutCard";
import { DEV_UPDATE_TEXT, UpdatesCard } from "./UpdatesCard";

async function boot() {
  render(<App />);
  await screen.findByText("Nothing open yet");
  await settle();
}

describe("Mooring Dev (ADR-0028)", () => {
  it("shows a Dev badge in the title bar and About only in a dev build", async () => {
    const mock = freshBackend();
    mock.buildChannel = "dev";
    await boot();
    expect(within(screen.getByRole("banner")).getByText("Dev")).toHaveClass("dev-badge");
    act(() => { useUi.getState().setView("settings"); });
    expect(screen.getByTestId("about-dev")).toHaveTextContent("Mooring Dev — development build, separate data from Mooring (io.github.yyasar21.mooring.dev).");
    expect(screen.getByTestId("update-dev")).toHaveTextContent(DEV_UPDATE_TEXT);
  });

  it("changes nothing for a release build", async () => {
    freshBackend();
    await boot();
    expect(within(screen.getByRole("banner")).queryByText("Dev")).toBeNull();
    render(<AboutCard />);
    expect(screen.queryByTestId("about-dev")).toBeNull();
    expect(screen.queryByTestId("update-dev")).toBeNull();
  });

  it("disables check and background updates in dev; Rust refuses them with dev_build", async () => {
    const mock = freshBackend();
    mock.buildChannel = "dev";
    await act(async () => { await useApp.getState().boot(); });
    render(<UpdatesCard />);
    await settle();
    expect(screen.getByRole("button", { name: "Check for updates" })).toBeDisabled();
    expect(screen.getByRole("switch")).toBeDisabled();
    expect(screen.getByRole("switch")).not.toBeChecked();
    fireEvent.click(screen.getByRole("button", { name: "Check for updates" }));
    // the backend refuses on its own as well
    const err = await mock.updateCheck().catch((e: unknown) => e);
    expect(describeError(err)).toBe(DEV_MANUAL_TEXT);
    expect(await mock.updateSettingsSet({ backgroundCheck: true }).catch((e: unknown) => (e as { code: string }).code)).toBe("update.manual_only");
    expect(await mock.updateSettingsSet({ backgroundCheck: false })).toMatchObject({ backgroundCheck: false });
  });
});
