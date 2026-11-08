// L2: the credentials list as a table, the detail page with Overview / Used by / Audit tabs, and
// the editor in a side sheet.
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { App } from "../../App";
import { useCredentials } from "../../stores/credentials";
import { useTree } from "../../stores/tree";
import { useUi } from "../../stores/ui";
import { freshBackend, settle } from "../../test/harness";

async function boot() {
  render(<App />);
  await screen.findByText("Nothing open yet");
  await settle();
  act(() => { useUi.getState().showCredentials(); });
  await settle();
}

const view = () => screen.getByRole("region", { name: "Credentials" });
const grid = () => within(view()).getByRole("grid", { name: "Stored credentials" });
const rowNames = () => within(grid()).getAllByRole("row").slice(1).map((r) => r.getAttribute("aria-label") ?? "");

describe("Credentials view (L2)", () => {
  beforeEach(() => { freshBackend(); });

  it("sorts by name, filters by text and kind chips, and says what it is sorted by", async () => {
    await boot();
    const names = rowNames();
    expect(names.length).toBe(useCredentials.getState().items.length);
    expect(within(grid()).getByRole("columnheader", { name: "Name" })).toHaveAttribute("aria-sort", "ascending");
    expect(view()).toHaveTextContent("Sorted by name");
    fireEvent.click(within(grid()).getByRole("button", { name: "Used by" }));
    expect(within(grid()).getByRole("columnheader", { name: "Used by" })).toHaveAttribute("aria-sort", "ascending");
    expect(view()).toHaveTextContent("Sorted by use");

    const chips = within(view()).getByRole("radiogroup", { name: "Kind" });
    fireEvent.click(within(chips).getByRole("radio", { name: "Domain" }));
    expect(rowNames()).toEqual([expect.stringMatching(/^Domain account domain admin /)]);
    fireEvent.click(within(chips).getByRole("radio", { name: "All" }));
    fireEvent.change(within(view()).getByLabelText("Filter credentials"), { target: { value: "nothing-like-this" } });
    expect(within(grid()).getByText("No credential matches the filter.")).toBeInTheDocument();
  });

  it("opens the detail page on a row, with Overview first, Used by with roles and a jump to Hosts", async () => {
    await boot();
    fireEvent.click(within(grid()).getByRole("row", { name: / domain admin / }));
    const detail = within(view()).getByRole("article", { name: "domain admin details" });
    const tabs = within(detail).getByRole("tablist", { name: "Credential sections" });
    expect(within(tabs).getAllByRole("tab").map((t) => t.textContent)).toEqual(["Overview", "Used by (3)", "Audit"]);
    expect(within(tabs).getByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
    expect(within(detail).getByRole("tabpanel")).toHaveTextContent("Signs in to");

    fireEvent.click(within(tabs).getByRole("tab", { name: "Used by (3)" }));
    const used = within(detail).getByRole("list", { name: "Used by" });
    expect(used).toHaveTextContent("dc01Sign-in (folder default), RD Gateway");
    expect(used).toHaveTextContent("finance-deskSign-in");
    expect(used).toHaveTextContent("DesktopsFolder default");
    fireEvent.click(within(used).getByRole("button", { name: "dc01" }));
    expect(useUi.getState().view).toBe("workspace");
    expect(useTree.getState().selected).toEqual({ kind: "connection", id: "c-dc" });
  });

  it("the Audit tab lists the rows that name this credential", async () => {
    await boot();
    await act(async () => { await useCredentials.getState().copySecret("cr-ad", "password"); });
    fireEvent.click(within(grid()).getByRole("row", { name: / domain admin / }));
    const detail = within(view()).getByRole("article", { name: "domain admin details" });
    fireEvent.click(within(detail).getByRole("tab", { name: "Audit" }));
    await settle();
    const table = within(detail).getByRole("table", { name: "Audit entries for this credential" });
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toHaveTextContent("Secret copied");
  });

  it("edits in a side sheet that hides the page behind it and closes on Escape", async () => {
    await boot();
    fireEvent.click(within(grid()).getByRole("row", { name: / deploy bot / }));
    fireEvent.click(within(view()).getByRole("button", { name: "Edit" }));
    const sheet = within(view()).getByRole("dialog", { name: "Edit deploy bot" });
    expect(within(sheet).getByRole("form", { name: "Edit deploy bot" })).toBeInTheDocument();
    expect(within(view()).queryByRole("article")).toBeNull(); // aria-hidden behind the sheet
    expect(sheet.contains(document.activeElement)).toBe(true);
    fireEvent.keyDown(sheet, { key: "Escape" });
    expect(within(view()).queryByRole("dialog")).toBeNull();
    expect(within(view()).getByRole("article", { name: "deploy bot details" })).toBeInTheDocument();
  });

  it("deletes from the row with a confirm step, and Enter on the row's button does not select the row", async () => {
    await boot();
    const del = within(grid()).getByRole("button", { name: "Delete legacy admin" });
    fireEvent.keyDown(del, { key: "Enter" });
    expect(useUi.getState().credentialPane).toEqual({ mode: "none" });
    fireEvent.click(del);
    fireEvent.click(within(grid()).getByRole("button", { name: "Confirm delete" }));
    await settle();
    expect(useCredentials.getState().items.some((c) => c.name === "legacy admin")).toBe(false);
  });
});
