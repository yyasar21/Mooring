import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { App } from "../../App";
import type { MockTransport } from "../../lib/ipc.mock";
import { describeCode, TOOL_CHANGED } from "../../stores/errors";
import { useCredentials } from "../../stores/credentials";
import { useUi } from "../../stores/ui";
import { freshBackend, settle } from "../../test/harness";

// L-50 (review 9 follow-up): a bws binary that no longer matches its pin is refused with
// `secret.tool_changed`; testing the source in Settings re-trusts it.

const view = () => screen.getByRole("region", { name: "Credentials" });

describe("bws changed (L-50)", () => {
  let mock: MockTransport;
  beforeEach(() => { mock = freshBackend(); });

  it("has friendly text that names the next step", () => {
    expect(describeCode("secret.tool_changed")).toMatch(/bws binary changed .*Test the source in Settings → Secret sources to trust it again\./);
  });

  it("a reference test says the binary changed and points to the source; testing the source trusts it again", async () => {
    render(<App />);
    await screen.findByText("Nothing open yet");
    await settle();
    act(() => { useUi.getState().showCredentials({ mode: "new" }); });
    fireEvent.click(within(view()).getByRole("button", { name: "Secret manager reference" }));
    await settle();
    const form = within(view()).getByRole("form", { name: "New Secret manager reference" });
    fireEvent.change(within(form).getByLabelText("Name"), { target: { value: "bw token" } });
    fireEvent.click(within(form).getByRole("radio", { name: "Bitwarden" }));
    fireEvent.change(within(form).getByLabelText("Secret source"), { target: { value: "src-bws" } });
    fireEvent.change(within(form).getByLabelText(/^Resolves to/), { target: { value: "api_token" } });
    fireEvent.change(within(form).getByLabelText(/^Reference/), { target: { value: "be8e0ad8-d545-4017-a55a-b02f014d4158" } });
    fireEvent.click(within(form).getByRole("button", { name: "Create credential" }));
    await settle();

    mock.bwsChanged = true;
    const card = () => within(view()).getByRole("article", { name: "bw token details" });
    fireEvent.click(within(card()).getByRole("button", { name: "Test" }));
    await settle();
    expect(within(card()).getByRole("status", { name: "Reference test" })).toHaveTextContent("The bws binary changed since Mooring last trusted it.");
    const note = within(card()).getByRole("note", { name: "bws changed" });
    expect(note).toHaveTextContent(`${TOOL_CHANGED.title}. ${TOOL_CHANGED.next}`);
    expect(mock.audit.find((e) => e.event === "secret.tool_changed")?.details).toEqual({ source: "src-bws" });

    fireEvent.click(within(note).getByRole("button", { name: "Open Secret sources" }));
    await settle();
    expect(useUi.getState().view).toBe("settings");
    const bw = within(screen.getByRole("region", { name: "Secret sources" })).getByRole("listitem", { name: "team secrets" });
    fireEvent.click(within(bw).getByRole("button", { name: "Test" }));
    await settle();
    expect(mock.bwsChanged).toBe(false);

    const id = useCredentials.getState().items.find((c) => c.name === "bw token")?.id ?? "";
    act(() => { useUi.getState().showCredentials({ mode: "view", id }); });
    await settle();
    fireEvent.click(within(card()).getByRole("button", { name: "Test" }));
    await settle();
    expect(within(card()).getByRole("status", { name: "Reference test" })).toHaveTextContent("has every field the target kind needs");
    expect(within(card()).queryByRole("note", { name: "bws changed" })).toBeNull();
  });
});
