// A5 E2E flows (ADR-0025 / 0022 / 0023 / 0028, U1–U3) against the real UI with the mock
// transport: an SSH session through a jump host (hop prompt naming the hop, per-hop chips, the
// target's own prompt after it), the "Connect via" picker saving a chain, Windows Hello unlock
// turned on in Settings → Security and used on the unlock screen, a backup exported and merged
// back, the Dev badge of a Mooring Dev build, and (U4, ADR-0026) a Vault database reference whose
// session tab shows its lease chip, (U5, ADR-0024) the touch banner of a security-key sign-in, and
// (U6, ADR-0027) an RDP session through an RD Gateway trusted once plus a smart card PIN dialog.
// Run: `node --test --test-concurrency=1 apps/desktop/e2e/a5.e2e.mjs` (after `pnpm install`).
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { MASTER, createVault, freshPage, lockFromTitleBar, openSession, probe, screenshotOnFailure, startHarness, waitForProbe } from "./harness.mjs";

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

// A5 U4 (ADR-0026): a Vault database reference created in the form, a new SSH connection that
// signs in with it, and the lease chip on the session tab (renewal time, engine and role, no id).
test("dynamic secret: a database reference, a connection that uses it, the lease chip", (t) =>
  flow(t, async (page) => {
    await createVault(page);
    await views(page).getByRole("button", { name: "Credentials" }).click();
    const view = page.getByRole("region", { name: "Credentials" });
    await view.getByRole("button", { name: "New credential" }).click();
    await view.getByRole("button", { name: "Secret manager reference", exact: true }).click();
    const form = view.getByRole("form", { name: "New Secret manager reference" });
    await form.getByLabel("Name", { exact: true }).fill("analytics db");
    await form.getByText("Vault", { exact: true }).click();
    await form.getByLabel("Secret source").selectOption("src-ops");
    await form.getByLabel("Vault engine").selectOption("database");
    await form.getByText("Fixed by the Database engine.").waitFor();
    await form.getByLabel("Role", { exact: true }).fill("database/analytics");
    await form.getByRole("button", { name: "Create credential" }).click();
    const card = view.getByRole("article", { name: "analytics db details" });
    await card.waitFor();
    await card.getByRole("button", { name: "Test" }).click();
    await card.getByRole("status", { name: "Reference test" }).filter({ hasText: "Mooring revoked them at once" }).waitFor();

    // Harbor M1: the tree (and its "New connection") lives in Hosts; Credentials is full width.
    await views(page).getByRole("button", { name: "Hosts" }).click();
    await page.getByRole("button", { name: "New connection" }).click();
    const dlg = page.getByRole("dialog", { name: "New connection" });
    await dlg.getByLabel("Name", { exact: true }).fill("analytics");
    await dlg.getByLabel("Host", { exact: true }).fill("analytics.example.test");
    await dlg.getByLabel("Folder", { exact: true }).selectOption("f-db");
    await dlg.getByRole("button", { name: /^Credential/ }).click();
    await dlg.getByRole("listbox", { name: "Credential" }).getByRole("option").filter({ hasText: "analytics db" }).click();
    await dlg.getByRole("button", { name: "Create connection" }).click();
    await dlg.waitFor({ state: "detached" });

    const prompt = await openSession(page, tree(page).getByRole("treeitem", { name: /^analytics, analytics\.example\.test/ }));
    await prompt.getByRole("button", { name: "Trust and connect" }).click();
    await waitForProbe(page, (s) => s.events.includes("connected"), "the session to connect");
    const tab = page.getByRole("tab", { name: /^analytics, connected, Lease · renews in 40 min \(Database lease for Vault role analytics\./ });
    await tab.waitFor();
    assert.equal(await tab.locator(".lease-chip").innerText(), "Lease · renews in 40 min");
    assert.ok(events(await probe(page)).includes("secret_lease_issued"));
    assert.doesNotMatch(await page.content(), /lease_id|hvs\./, "no lease id or token in the DOM");

    await tab.getByRole("button", { name: "Close analytics" }).click();
    await waitForProbe(page, (s) => s.audit.some((e) => e.event === "secret_lease_revoked" && e.details.reason === "closed"), "the lease to be revoked");
  }));

// A5 U5 (ADR-0024): a connection that signs in with a FIDO2 key through the agent. After the host
// key, the non-modal touch banner names the key; the mock "touches" it after ~1.5 s, the banner
// goes and the session connects. Nothing is asked: no dialog opens for the touch.
test("security key: the touch banner shows while the key signs, then the session connects", (t) =>
  flow(t, async (page) => {
    await createVault(page);
    const prompt = await openSession(page, tree(page).getByRole("treeitem", { name: /^build-runner, runner\.example\.test/ }));
    await prompt.getByRole("button", { name: "Trust and connect" }).click();
    await page.getByRole("status").filter({ hasText: "Touch your security key to continue" }).waitFor();
    const banner = page.locator(".touch-banner");
    assert.match(await banner.innerText(), /Key SHA256:0f\/IntG4…rdDv4/);
    assert.equal(await page.getByRole("alertdialog").count(), 0, "the touch takes no answer");
    const snap = await waitForProbe(page, (s) => s.events.includes("connected"), "the key to be touched");
    const kinds = snap.events.filter((k) => k.startsWith("touch_") || k === "connected");
    assert.deepEqual(kinds, ["touch_required", "touch_cleared", "connected"]);
    await banner.waitFor({ state: "detached" });
    assert.ok(events(snap).includes("session.auth_sk"));
  }));

// A5 U6 (ADR-0027): the seeded "finance-desk" signs in through RD Gateway gw01.example.test. The
// gateway certificate is asked first (with Trust once, which pins nothing), then the server's
// (no Trust once there), then the session is up with NLA over the gateway and the chip names it.
test("RD Gateway: Trust once for the gateway, Trust and remember for the server, the via chip", (t) =>
  flow(t, async (page) => {
    await createVault(page);
    await tree(page).getByRole("treeitem", { name: /^finance-desk,/ }).dblclick();
    const gw = page.getByRole("alertdialog", { name: "RD Gateway certificate" });
    await gw.waitFor();
    assert.match(await gw.innerText(), /gw01\.example\.test:443/);
    assert.match(await gw.innerText(), /Trust once uses it for this connection only/);
    await gw.getByRole("button", { name: "Trust once" }).click();
    const server = page.getByRole("alertdialog", { name: "Verify server certificate" });
    await server.waitFor();
    assert.equal(await server.getByRole("button", { name: "Trust once" }).count(), 0, "no Trust once for the server");
    await server.getByRole("button", { name: "Trust and remember" }).click();
    const snap = await waitForProbe(page, (s) => s.events.includes("connected"), "the RDP session to connect");
    const kinds = snap.events.filter((k) => k === "gateway_status" || k === "prompt" || k === "connected");
    assert.equal(kinds[0], "gateway_status", "the gateway is reported before anything else");
    assert.ok(kinds.indexOf("connected") > kinds.lastIndexOf("prompt"), "connected after both prompts");
    const tools = page.getByRole("toolbar", { name: "Remote desktop tools" });
    await tools.getByText("via RD Gateway gw01.example.test").waitFor();
    assert.match(await tools.innerText(), /NLA/);
    assert.ok(snap.audit.some((e) => e.event === "trust_decision" && e.details.protocol === "rdg" && e.details.decision === "trusted_once"));
    assert.ok(snap.audit.some((e) => e.event === "session.rdp.gateway" && e.details.outcome === "ok"));
    const pinned = await page.evaluate(() => window.__mooringE2E.transport.knownCerts.has("rdg|gw01.example.test:443"));
    assert.equal(pinned, false, "Trust once stores nothing for the gateway");
  }));

// A5 U6 (ADR-0027): web01 is pointed at the seeded "piv badge" smart card in the editor. Opening
// it asks the host key, then the card PIN in a masked dialog; the answer connects. L-49: the card
// stays in ssh-agent for 60 minutes, so a reopen within that time connects without the PIN. Once
// the agent forgets it, the PIN is asked again (it is never stored) and Escape closes the session
// as the user's.
test("smart card: the PIN dialog connects; a reopen within the agent lifetime does not ask; after it, Escape cancels", (t) =>
  flow(t, async (page) => {
    await createVault(page);
    await tree(page).getByRole("treeitem", { name: /^web01,/ }).click();
    await page.getByRole("complementary", { name: "Details" }).getByRole("button", { name: "Edit" }).click();
    const dlg = page.getByRole("dialog", { name: "Edit connection" });
    await dlg.getByRole("button", { name: /^Credential/ }).click();
    await dlg.getByRole("listbox", { name: "Credential" }).getByRole("option").filter({ hasText: "piv badge" }).click();
    await dlg.getByRole("button", { name: "Save connection" }).click();
    await dlg.waitFor({ state: "detached" });

    const row = tree(page).getByRole("treeitem", { name: /^web01,/ });
    const hostKey = await openSession(page, row);
    await hostKey.getByRole("button", { name: "Trust and connect" }).click();
    const pinDlg = page.getByRole("alertdialog", { name: "Smart card PIN" });
    await pinDlg.waitFor();
    assert.match(await pinDlg.innerText(), /Enter the PIN of the smart card \(Yubico YubiKey\)/);
    const pin = pinDlg.getByLabel("PIN");
    assert.equal(await pin.getAttribute("type"), "password");
    const unlock = pinDlg.getByRole("button", { name: "Unlock card" });
    assert.equal(await unlock.isDisabled(), true, "Unlock is disabled while the PIN is empty");
    await pin.fill("123456");
    await unlock.click();
    let snap = await waitForProbe(page, (s) => s.events.includes("connected"), "the card to unlock");
    await pinDlg.waitFor({ state: "detached" });
    assert.ok(snap.audit.some((e) => e.event === "credential.pin_prompted" && e.details.outcome === "entered"));
    assert.ok(snap.audit.some((e) => e.event === "session.auth_sk" && e.details.backend === "piv" && e.details.outcome === "ok"));
    assert.doesNotMatch(JSON.stringify(snap.audit), /123456/, "the PIN is in no audit row");
    assert.doesNotMatch(await page.content(), /123456/, "the PIN is not left in the DOM");

    await page.getByRole("tab", { name: /^web01, connected/ }).getByRole("button", { name: "Close web01" }).click();
    await waitForProbe(page, (s) => s.sessions === 0, "the first session to close");
    await row.dblclick(); // the host is trusted and the agent holds the card: no question at all
    snap = await waitForProbe(page, (s) => s.events.filter((k) => k === "connected").length === 2, "the reopen to connect without a PIN");
    assert.equal(snap.audit.filter((e) => e.event === "credential.pin_prompted").length, 1, "the PIN was asked once");
    assert.equal(await pinDlg.count(), 0, "no PIN dialog within the agent lifetime");
    await page.getByRole("tab", { name: /^web01, connected/ }).getByRole("button", { name: "Close web01" }).click();
    await waitForProbe(page, (s) => s.sessions === 0, "the second session to close");

    // The 60 minutes are over: the agent no longer holds the card.
    await page.evaluate(() => { window.__mooringE2E.transport.agentCards.forget(); });
    await row.dblclick(); // the PIN is the first question again
    await pinDlg.waitFor();
    await pinDlg.getByLabel("PIN").fill("99");
    await page.keyboard.press("Escape");
    await pinDlg.waitFor({ state: "detached" });
    snap = await waitForProbe(
      page,
      (s) =>
        s.audit.some((e) => e.event === "credential.pin_prompted" && e.details.outcome === "cancelled") &&
        s.events.lastIndexOf("closed") > s.events.lastIndexOf("prompt"),
      "the PIN prompt to be cancelled and the session to close",
    );
    assert.equal(snap.events.filter((k) => k === "connected").length, 2, "Escape never connects");
    await page.getByText("smart card PIN cancelled").first().waitFor();
    assert.doesNotMatch(JSON.stringify(snap.audit), /"99"/);
  }));
