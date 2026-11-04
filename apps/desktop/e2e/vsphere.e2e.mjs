// A3 E2E flows for the vSphere UI (ADR-0015, U2) against the real UI with the mock transport:
// the import wizard (sign-in test → folder → import → report → show the folder), the synced
// subtree's read-only affordances and the missing-VM styling, the VM power menu (disabled until
// the vCenter opt-in; done / cancelled outcomes with no UI confirm) and the console buttons.
// The Rust-native dialogs are the mock's `confirmPower` knob; the vCenter itself is `vsphereDown`.
// Run: `node --test --test-concurrency=1 apps/desktop/e2e/vsphere.e2e.mjs` (after `pnpm install`).
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { createVault, freshPage, probe, screenshotOnFailure, startHarness, waitForProbe } from "./harness.mjs";

let h;
before(async () => {
  h = await startHarness();
});
after(async () => {
  await h?.stop();
});

async function flow(t, body) {
  const { page, errors, close } = await freshPage(h);
  try {
    await body(page);
    assert.deepEqual(errors, [], "uncaught errors in the page");
  } catch (e) {
    await screenshotOnFailure(page, t.name);
    throw e;
  } finally {
    await close();
  }
}

const VCENTER_ROW = /^stage-vcenter, vcenter\.example\.test/;
const SYNCED_ROOT = /^stage-vcenter, synced from stage-vcenter$/;
const APP_VM = /^app-vm-01, 192\.0\.2\.21, synced from stage-vcenter$/;

const tree = (page) => page.getByRole("tree", { name: "Connections" });
const details = (page) => page.getByRole("complementary", { name: "Details" });
const row = (page, name) => tree(page).getByRole("treeitem", { name });

/** Mock knobs: the vCenter down / a VM hidden / the native power dialog's answer. */
function setVsphere(page, patch) {
  return page.evaluate((p) => {
    const t = window.__mooringE2E?.transport;
    if (!t) throw new Error("e2e probe missing");
    for (const id of p.down ?? []) t.vsphereDown.add(id);
    if (p.clearDown) t.vsphereDown.clear();
    for (const id of p.hidden ?? []) t.vsphereHidden.add(id);
    if (typeof p.confirmPower === "boolean") t.confirmPower = p.confirmPower;
  }, patch);
}

/** Create the vault and run the import wizard on stage-vcenter under its own folder. */
async function importInventory(page) {
  await createVault(page);
  await row(page, VCENTER_ROW).click();
  await details(page).getByRole("button", { name: "Import inventory…" }).click();
  const dialog = page.getByRole("dialog", { name: "Import vCenter inventory" });
  await dialog.getByRole("status").filter({ hasText: "Signed in as administrator@vsphere.local" }).waitFor();
  await dialog.getByRole("button", { name: "Next" }).click();
  await dialog.getByRole("button", { name: "Next" }).click();
  await dialog.getByRole("button", { name: "Start import" }).click();
  await dialog.getByRole("status").filter({ hasText: "Inventory imported into “stage-vcenter”." }).waitFor();
  await dialog.getByRole("button", { name: "Show the folder" }).click();
  await dialog.waitFor({ state: "detached" });
  await row(page, APP_VM).waitFor();
  return dialog;
}

/** Turn the vCenter's power / VMRC opt-ins on through its connection dialog. */
async function optIn(page, { power = false, vmrc = false }) {
  await row(page, VCENTER_ROW).click();
  await details(page).getByRole("button", { name: "Edit", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Edit connection" });
  // The native checkbox sits under the styled track: click the label text, as a user does.
  for (const [on, label] of [[power, "Allow power actions on VMs"], [vmrc, "Offer VMware Remote Console"]]) {
    if (!on) continue;
    await dialog.getByText(label, { exact: true }).click();
    assert.equal(await dialog.getByRole("switch", { name: label }).isChecked(), true);
  }
  await dialog.getByRole("button", { name: "Save connection" }).click();
  await dialog.waitFor({ state: "detached" });
}

const vmPanel = (page) => details(page).getByRole("region", { name: "Virtual machine" });

test("import wizard: sign-in test, parent folder, import, report and the synced subtree", (t) =>
  flow(t, async (page) => {
    await createVault(page);
    await row(page, VCENTER_ROW).click();
    assert.equal(await details(page).getByRole("button", { name: "Connect" }).count(), 0, "a vCenter has no session");

    // A vCenter that does not answer: the wizard explains it and cannot go on.
    await setVsphere(page, { down: ["c-vc"] });
    await details(page).getByRole("button", { name: "Import inventory…" }).click();
    const dialog = page.getByRole("dialog", { name: "Import vCenter inventory" });
    await dialog.getByRole("alert").filter({ hasText: "vCenter did not answer" }).waitFor();
    assert.equal(await dialog.getByRole("button", { name: "Next" }).isDisabled(), true);
    await setVsphere(page, { clearDown: true });
    await dialog.getByRole("button", { name: "Test again" }).click();
    await dialog.getByRole("status").filter({ hasText: "Signed in as administrator@vsphere.local · vCenter 8.0.3.00400" }).waitFor();

    await dialog.getByRole("button", { name: "Next" }).click();
    const parent = dialog.getByLabel("Put the inventory under");
    assert.equal(await parent.inputValue(), "f-staging", "defaults to the vCenter's own folder");
    await dialog.getByRole("button", { name: "Next" }).click();
    await dialog.getByText("Staging / stage-vcenter").waitFor();
    await dialog.getByRole("button", { name: "Start import" }).click();
    await dialog.getByRole("status").filter({ hasText: "Inventory imported into “stage-vcenter”." }).waitFor();
    assert.equal(await dialog.getByRole("group", { name: "Last refresh" }).textContent(), "5added0changed0missing0deleted");

    await dialog.getByRole("button", { name: "Show the folder" }).click();
    await dialog.waitFor({ state: "detached" });
    await row(page, APP_VM).waitFor();
    await row(page, SYNCED_ROOT).waitFor();
    await details(page).getByRole("region", { name: "Inventory sync" }).waitFor();
    const snap = await probe(page);
    const events = snap.audit.map((e) => e.event);
    assert.ok(events.includes("vsphere_sync_started") && events.includes("vsphere_sync_finished"), events.join(","));
    assert.equal(snap.sessions, 0, "an import opens no UI session");
  }));

test("synced tree: badges, aria-readonly, F2 and toolbar refused, missing VM styled after a refresh", (t) =>
  flow(t, async (page) => {
    await importInventory(page);
    const root = row(page, SYNCED_ROOT);
    assert.equal(await root.getAttribute("aria-readonly"), "true");
    assert.equal(await root.getAttribute("draggable"), "false");
    assert.equal(await root.getByRole("img", { name: /Synced from stage-vcenter/ }).textContent(), "stage-vcenter");
    assert.equal(await row(page, /^DC-East, synced/).getByRole("img", { name: /Synced from stage-vcenter/ }).textContent(), "", "compact: glyph only");
    assert.equal(await row(page, /^web01,/).getAttribute("draggable"), "true", "ordinary rows still drag");

    // F2 on a synced row: no rename field, the reason instead.
    await root.click();
    await page.keyboard.press("F2");
    const nav = page.getByRole("navigation", { name: "Connection tree" });
    await nav.getByRole("alert").filter({ hasText: "Synced from vCenter: this item is read-only." }).waitFor();
    assert.equal(await page.getByLabel("New name").count(), 0);
    assert.equal(await nav.getByRole("button", { name: "New connection" }).isDisabled(), true);
    assert.match(await nav.getByRole("button", { name: "New folder" }).getAttribute("title"), /read-only/);
    assert.equal(await details(page).getByRole("button", { name: "New connection" }).isDisabled(), true);
    await details(page).getByRole("button", { name: "Default credential…" }).waitFor();

    // A VM the vCenter stops reporting: dimmed, struck through and labelled after Refresh now.
    await setVsphere(page, { hidden: ["vm-build-vm"] });
    const panel = details(page).getByRole("region", { name: "Inventory sync" });
    await panel.getByRole("button", { name: "Refresh now" }).click();
    await panel.getByRole("status").filter({ hasText: "Refreshed: 0 added, 0 changed, 1 missing, 0 deleted." }).waitFor();
    const missing = row(page, /^build-vm, .*, missing in vCenter$/);
    await missing.waitFor();
    assert.equal(await missing.getAttribute("data-sync"), "missing");
    assert.equal(await row(page, APP_VM).getAttribute("data-sync"), "synced");

    // The missing VM's panel explains why nothing works.
    await missing.click();
    await vmPanel(page).filter({ hasText: "stage-vcenter no longer reports this VM." }).waitFor();
    assert.equal(await vmPanel(page).getByRole("button", { name: "Power" }).count(), 0);
  }));

test("VM power: disabled without the opt-in, then the menu, a requested action and a cancelled dialog", (t) =>
  flow(t, async (page) => {
    await importInventory(page);
    await row(page, APP_VM).click();
    const panel = vmPanel(page);
    await panel.getByRole("status").filter({ hasText: "Powered on" }).waitFor();
    const power = panel.getByRole("button", { name: "Power" });
    assert.equal(await power.isDisabled(), true);
    assert.equal(await power.getAttribute("title"), "Power actions are off for stage-vcenter. Turn them on in its connection options.");
    assert.equal(await panel.getByRole("button", { name: "VMRC" }).isDisabled(), true);
    await details(page).getByRole("region", { name: "Guest identity" }).filter({ hasText: "app-vm-01.example.test" }).waitFor();

    await optIn(page, { power: true });
    await row(page, APP_VM).click();
    await power.waitFor();
    assert.equal(await power.isEnabled(), true);
    await power.click();
    const menu = page.getByRole("menu", { name: "Power actions" });
    const items = menu.getByRole("menuitem");
    assert.deepEqual(await items.allTextContents(), [
      "Power onAlready powered on.",
      "Shut down guestneeds VMware Tools",
      "Reboot guestneeds VMware Tools",
      "Power offmay lose data",
      "Resetmay lose data",
    ]);
    assert.equal(await items.nth(0).getAttribute("aria-disabled"), "true");
    assert.equal(await items.nth(3).getAttribute("data-destructive"), "true");
    assert.equal(await items.nth(4).getAttribute("data-destructive"), "true");

    // Power off: the confirmation is Rust's native dialog (the mock answers yes), no UI confirm.
    await items.nth(3).click();
    await panel.getByRole("status").filter({ hasText: "Power off: requested from stage-vcenter." }).waitFor();
    assert.equal(await page.getByRole("dialog").count(), 0, "no second confirm in the UI");
    await panel.getByRole("status").filter({ hasText: "Powered off" }).waitFor();

    // Cancelled in the dialog: nothing done, said so.
    await setVsphere(page, { confirmPower: false });
    await power.click();
    await page.getByRole("menu").getByRole("menuitem", { name: /^Power on/ }).click();
    await panel.getByRole("status").filter({ hasText: "Cancelled in the dialog. Nothing was done." }).waitFor();

    // Escape closes the menu and returns focus to the button.
    await power.click();
    await page.keyboard.press("Escape");
    assert.equal(await page.getByRole("menu").count(), 0);
    assert.equal(await power.evaluate((el) => el === document.activeElement), true);

    const snap = await probe(page);
    const audited = snap.audit.filter((e) => e.event === "vsphere_power").map((e) => `${e.details.action}:${e.details.outcome}`);
    assert.deepEqual(audited, ["stop:requested", "stop:done", "start:cancelled"], "every outcome is audited");
    assert.doesNotMatch(JSON.stringify(snap.audit), /vmrc:\/\//);
  }));

test("consoles: the vSphere Client window label, VMRC only when opted in, Enter on the row", (t) =>
  flow(t, async (page) => {
    await importInventory(page);
    await row(page, APP_VM).click();
    const status = () => details(page).getByRole("status").last();
    await details(page).getByRole("button", { name: "Open in vSphere Client" }).click();
    await status().filter({ hasText: "Opened the vSphere Client window (web-c-vc)." }).waitFor();
    let snap = await probe(page);
    assert.deepEqual(snap.audit.at(-1)?.event, "vsphere_console");

    const vmrc = details(page).getByRole("button", { name: "VMRC" });
    assert.equal(await vmrc.isDisabled(), true);
    assert.equal(await vmrc.getAttribute("title"), "VMware Remote Console is off for stage-vcenter. Turn it on in its connection options.");
    await optIn(page, { vmrc: true });
    await row(page, APP_VM).click();
    await vmrc.waitFor();
    await vmrc.click();
    await status().filter({ hasText: "Ticket handed to VMware Remote Console." }).waitFor();
    snap = await probe(page);
    assert.doesNotMatch(JSON.stringify(snap.audit), /vmrc:\/\//, "no ticket in the audit log");

    // Enter on the VM row opens the Client window as well (no session).
    await tree(page).focus();
    await page.keyboard.press("Enter");
    snap = await waitForProbe(page, (s) => s.audit.filter((e) => e.event === "vsphere_console").length === 3, "a third vsphere_console row");
    assert.equal(snap.sessions, 0);
  }));
