// A5 E2E flows (ADR-0025 / 0022 / 0023 / 0028, U1–U3) against the real UI with the mock
// transport: an SSH session through a jump host (hop prompt naming the hop, per-hop chips, the
// target's own prompt after it), the "Connect via" picker saving a chain, Windows Hello unlock
// turned on in Settings → Security and used on the unlock screen, a backup exported and merged
// back, and the Dev badge of a Mooring Dev build.
// Run: `node --test --test-concurrency=1 apps/desktop/e2e/a5.e2e.mjs` (after `pnpm install`).
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { MASTER, createVault, freshPage, lockFromTitleBar, probe, screenshotOnFailure, startHarness, waitForProbe } from "./harness.mjs";

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

const events = (snap) => snap.audit.map((e) => e.event);
const views = (page) => page.getByRole("navigation", { name: "Views" });
const region = (page, name) => page.getByRole("region", { name });
const tree = (page) => page.getByRole("tree", { name: "Connections" });

test("jump host: the hop asks first by name, chips track it, then the target asks", (t) =>
  flow(t, async (page) => {
    await createVault(page);
    const row = tree(page).getByRole("treeitem", { name: /^stage-app, .*via bastion01/ });
    await row.dblclick();
    const hop = page.getByRole("alertdialog", { name: "Jump host bastion01: verify host identity" });
    await hop.waitFor();
    assert.match(await hop.innerText(), /Hop 1 of 1 — bastion\.stage\.example\.test:22/);
    await page.getByRole("list", { name: "Jump hosts" }).getByLabel(/bastion01, .*: connecting$/).waitFor();
    await hop.getByRole("button", { name: "Trust and connect" }).click();
    const target = page.getByRole("alertdialog", { name: "Verify host identity" });
    await target.waitFor();
    await target.getByRole("button", { name: "Trust and connect" }).click();
    const snap = await waitForProbe(page, (s) => s.events.includes("connected"), "the target to connect");
    assert.ok(events(snap).includes("session_hop_open"));
    const kinds = snap.events.filter((k) => k === "hop_status" || k === "prompt" || k === "connected");
    assert.deepEqual(kinds.slice(0, 2), ["hop_status", "prompt"], "the hop is reported before anything else");
    await page.getByRole("list", { name: "Jump hosts" }).waitFor({ state: "detached" });
  }));

test("Connect via: pick a jump host, see the route, save", (t) =>
  flow(t, async (page) => {
    await createVault(page);
    await tree(page).getByRole("treeitem", { name: /^web02,/ }).click();
    await page.getByRole("complementary", { name: "Details" }).getByRole("button", { name: "Edit" }).click();
    const dlg = page.getByRole("dialog", { name: "Edit connection" });
    const via = dlg.getByRole("group", { name: "Connect via" });
    await via.getByLabel("Add jump host").selectOption({ label: "bastion01 (bastion.stage.example.test)" });
    await via.getByRole("button", { name: "Add", exact: true }).click();
    assert.equal(await via.getByLabel("Route").innerText(), "you → bastion01 → web02");
    await dlg.getByRole("button", { name: "Save connection" }).click();
    await dlg.waitFor({ state: "detached" });
    await tree(page).getByRole("treeitem", { name: /^web02, web02\.example\.test, via bastion01/ }).waitFor();
  }));

test("Windows Hello: turn it on with the master password, lock, unlock with it", (t) =>
  flow(t, async (page) => {
    await createVault(page);
    await views(page).getByRole("button", { name: "Settings" }).click();
    const card = region(page, "Security");
    // The native checkbox sits under the styled track: click the label text, as a user does.
    await card.getByText("Unlock with Windows Hello", { exact: true }).click();
    await card.getByLabel("Master password", { exact: true }).fill(MASTER);
    await card.getByRole("button", { name: "Turn on Windows Hello" }).click();
    await card.getByText("Windows Hello unlock is on.").waitFor();
    await lockFromTitleBar(page);
    await page.getByRole("button", { name: "Unlock with Windows Hello" }).click();
    await tree(page).waitFor();
    const snap = await probe(page);
    assert.ok(events(snap).includes("vault.biometric_enabled"));
    assert.ok(events(snap).includes("vault.unlock_biometric"));
  }));

test("backup: export with a passphrase, then merge the file back and see the conflicts", (t) =>
  flow(t, async (page) => {
    await createVault(page);
    await views(page).getByRole("button", { name: "Settings" }).click();
    const card = region(page, "Backup");
    await card.getByRole("button", { name: "Export backup…" }).click();
    const exp = page.getByRole("dialog", { name: "Export a backup" });
    await exp.getByLabel("Master password").fill(MASTER);
    await exp.getByLabel("Backup passphrase", { exact: true }).fill("a long backup passphrase");
    await exp.getByLabel("Repeat backup passphrase").fill("a long backup passphrase");
    await exp.getByRole("button", { name: "Choose file and export…" }).click();
    await page.getByRole("dialog", { name: "Backup saved" }).getByRole("button", { name: "Done" }).click();

    await card.getByRole("button", { name: "Import backup…" }).click();
    const imp = page.getByRole("dialog", { name: "Import a backup" });
    await imp.getByLabel("Backup passphrase").fill("a long backup passphrase");
    await imp.getByRole("button", { name: "Open backup" }).click();
    await imp.getByLabel("Master password of this vault").fill(MASTER);
    await imp.getByRole("button", { name: "Merge into this vault" }).click();
    const done = page.getByRole("dialog", { name: "Backup imported" });
    await done.getByRole("list", { name: "Conflicts" }).waitFor();
    const snap = await probe(page);
    assert.ok(events(snap).includes("vault.exported"));
    assert.ok(events(snap).includes("vault.import"));
  }));

test("Mooring Dev: the title bar and About carry the Dev badge", (t) =>
  flow(t, async (page) => {
    await page.goto(new URL("e2e/boot.html?channel=dev", h.base).href);
    await createVault(page);
    await page.getByRole("banner").getByText("Dev", { exact: true }).waitFor();
    await views(page).getByRole("button", { name: "Settings" }).click();
    await page.getByTestId("about-dev").waitFor();
    await page.getByTestId("update-dev").waitFor();
  }));
