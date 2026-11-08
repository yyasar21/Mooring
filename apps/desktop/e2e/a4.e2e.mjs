// A4 E2E flows (ADR-0018 / 0019 / 0020, Q1) against the real UI with the mock transport: the
// import wizard for three formats (plaintext opt-in, duplicates, the mRemoteNG banner), the
// first-run onboarding card's paths, Settings → Updates (unconfigured / in_app offer with the
// install confirmation / manual reason) and the title-bar indicator after a background check,
// the inspector's Network card (port check, ping, traceroute, WireGuard hidden when `wg` is
// missing), Settings → About, and (U5) the Directory (LDAPS) source: form → the declined and
// then confirmed native sign-in → test bind → preview → apply. The Rust side of the same flows
// is `cargo test -p mooring-app --test e2e_flow a4_`.
// Run: `node --test --test-concurrency=1 apps/desktop/e2e/a4.e2e.mjs` (after `pnpm install`).
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

const events = (snap) => snap.audit.map((e) => e.event);
const views = (page) => page.getByRole("navigation", { name: "Views" });
const region = (page, name) => page.getByRole("region", { name });
const dialog = (page) => page.getByRole("dialog");
const tree = (page) => page.getByRole("tree", { name: "Connections" });
const details = (page) => page.getByRole("complementary", { name: "Details" });

/** Mock knobs on the transport (nothing here is a secret). */
function setMock(page, patch) {
  return page.evaluate((p) => {
    const t = window.__mooringE2E?.transport;
    if (!t) throw new Error("e2e probe missing");
    if (p.emptyTree) {
      t.connections = [];
      t.folders = t.folders.filter((f) => f.parentId === null);
      localStorage.removeItem("mooring.onboarding");
    }
    if (p.importPicks) t.importPicks = p.importPicks;
    if (typeof p.updateConfigured === "boolean") t.updateConfigured = p.updateConfigured;
    if (p.updateMode) t.updateMode = p.updateMode;
    if (p.updateRateWindowMs !== undefined) t.updateRateWindowMs = p.updateRateWindowMs;
    if (p.netToolsState) t.netToolsState = p.netToolsState;
    if (p.netRateWindowMs !== undefined) t.netRateWindowMs = p.netRateWindowMs;
    if (p.updateInstallFails) t.updateInstallFails = p.updateInstallFails;
    if (p.ldapSignIn) t.ldapSignIn = p.ldapSignIn;
    if (p.ldapTrust) t.ldapTrust = p.ldapTrust;
    if (p.backgroundCheck) return t.simulateBackgroundCheck();
    return undefined;
  }, patch);
}

async function openSettings(page) {
  await views(page).getByRole("button", { name: "Settings" }).click();
  await region(page, "About").waitFor();
}

/** Settings → Import → tile → Choose file → Preview; returns the wizard dialog. */
async function previewFromTile(page, tile, name) {
  await openSettings(page);
  const tiles = region(page, "Import").getByRole("list", { name: "Import sources" });
  await tiles.getByRole("button", { name: tile }).click();
  const dlg = dialog(page);
  assert.equal(await dlg.getAttribute("aria-label"), name);
  assert.equal(await dlg.getByRole("button", { name: "Preview" }).isDisabled(), true, "no file yet");
  await dlg.getByRole("button", { name: "Choose file" }).click();
  await dlg.getByRole("button", { name: "Preview" }).waitFor();
  await dlg.getByRole("button", { name: "Preview" }).click();
  await dlg.getByRole("group", { name: "Preview counts" }).waitFor();
  return dlg;
}

/** DOM text (CSS upper-cases the labels), whitespace stripped. */
const textOf = (loc) => loc.evaluate((el) => (el.textContent ?? "").replace(/\s+/g, ""));
const counts = (dlg) => textOf(dlg.getByRole("group", { name: "Preview counts" }));
/** Settings toggles once more to the workspace (the nav button is a toggle). */
const closeSettings = (page) => views(page).getByRole("button", { name: "Settings" }).click();

// ---------------------------------------------------------------- import wizard

test("import wizard: Royal TS file → preview with a duplicate and a skipped item → apply → new folder in the tree", (t) =>
  flow(t, async (page) => {
    await createVault(page);
    const dlg = await previewFromTile(page, /^Royal TS/, "Import from Royal TS");
    assert.equal(await counts(dlg), "3folders5connections2credentials0secrets1skipped1warnings");
    const items = dlg.getByRole("region", { name: "Items to import" });
    assert.equal(await items.getByRole("checkbox").count(), 8);
    assert.ok(await items.getByText("Duplicate, skipped").isVisible(), "the seeded web01 is flagged as a duplicate");
    assert.equal(await dlg.getByRole("switch", { name: /plaintext/ }).count(), 0, "Royal TS never carries secrets");
    assert.match(await dlg.getByRole("region", { name: "Skipped" }).innerText(), /no model for/);
    // Untick a folder: its children lift to the parent, the count follows.
    await items.getByRole("checkbox", { name: "Windows" }).click();
    assert.match(await items.getByRole("status").innerText(), /7 of 8 items selected/);
    await dlg.getByRole("button", { name: /^Import 6 items/ }).click();
    const report = dlg.getByRole("group", { name: "Import report" });
    await report.waitFor();
    assert.equal(await textOf(report), "2folders4connections2credentials0secrets3skipped");
    await dlg.getByRole("button", { name: "Open folder" }).click();
    await dlg.waitFor({ state: "detached" });
    await tree(page).getByRole("treeitem", { name: /^Imported from Royal TS/ }).waitFor();
    const snap = await probe(page);
    assert.ok(events(snap).includes("import_previewed") && events(snap).includes("import_applied"));
    const applied = snap.audit.find((e) => e.event === "import_applied");
    assert.equal(applied.details.format, "royal_ts");
    assert.ok(!JSON.stringify(snap.audit).includes("ops-team.rtsz"), "no file name in the audit");
  }));

test("import wizard: Termius plaintext opt-in re-runs the preview and only then carries secrets", (t) =>
  flow(t, async (page) => {
    await createVault(page);
    const dlg = await previewFromTile(page, /^Termius/, "Import from Termius");
    assert.match(await counts(dlg), /0secrets/);
    assert.match(await dlg.getByRole("region", { name: "Warnings" }).innerText(), /A stored password was not imported/);
    const optIn = dlg.getByRole("switch", { name: /^Import plaintext passwords and keys/ });
    assert.equal(await optIn.isChecked(), false, "off by default");
    // The pick is single use: the opt-in asks the Rust dialog again (the mock answers at once).
    // The native checkbox sits under the styled track: click the label text, as a user does.
    await dlg.getByText("Import plaintext passwords and keys", { exact: true }).click();
    await dlg.getByRole("group", { name: "Preview counts" }).filter({ hasText: "2secrets" }).waitFor();
    assert.equal(await optIn.isChecked(), true);
    assert.equal(await dlg.getByText("has secret", { exact: true }).count(), 2);
    assert.doesNotMatch(await dlg.innerText(), /password=|BEGIN OPENSSH/i, "nothing secret-shaped reaches the DOM");
    await dlg.getByRole("button", { name: /^Import \d+ items/ }).click();
    const report = dlg.getByRole("group", { name: "Import report" });
    await report.waitFor();
    assert.match(await textOf(report), /2secrets/);
    await dlg.getByRole("button", { name: "Close" }).click();
    await dlg.waitFor({ state: "detached" });
    const snap = await probe(page);
    const text = JSON.stringify(snap.audit);
    assert.ok(!/test-only|hunter|password":/.test(text), "no secret in the audit");
    assert.equal(snap.audit.filter((e) => e.event === "import_previewed").length, 2, "one preview per opt-in state");
  }));

test("import wizard: mRemoteNG shows the passwords-never-imported banner; a refused file keeps the step", (t) =>
  flow(t, async (page) => {
    await createVault(page);
    const dlg = await previewFromTile(page, /^mRemoteNG/, "Import from mRemoteNG");
    assert.match(await dlg.getByRole("note").innerText(), /mRemoteNG passwords are never imported/);
    assert.match(await counts(dlg), /0secrets/);
    assert.equal(await dlg.getByRole("switch", { name: /plaintext/ }).count(), 0);
    await dlg.getByRole("button", { name: "Cancel" }).click();
    await dlg.waitFor({ state: "detached" });
    // An encrypted export: the error text under the File step, Preview disabled until a new pick.
    await setMock(page, { importPicks: [{ fileName: "locked.xml", size: 10, error: "import.encrypted" }] });
    const tiles = region(page, "Import").getByRole("list", { name: "Import sources" });
    await tiles.getByRole("button", { name: /^mRemoteNG/ }).click();
    const again = dialog(page);
    await again.getByRole("button", { name: "Choose file" }).click();
    await again.getByText("locked.xml").waitFor();
    await again.getByRole("button", { name: "Preview" }).click();
    await again.getByRole("alert").waitFor();
    assert.match(await again.getByRole("alert").innerText(), /This file is encrypted/);
    assert.equal(await again.getByRole("button", { name: "Preview" }).isDisabled(), true, "the pick was consumed");
    await again.getByRole("button", { name: "Cancel" }).click();
    await again.waitFor({ state: "detached" });
    const snap = await probe(page);
    assert.ok(events(snap).includes("import_refused"));
    assert.ok(!JSON.stringify(snap.audit).includes("locked.xml"), "a refusal is audited by code only");
    assert.equal(await tiles.getByRole("button", { name: /Directory \(LDAPS\)/ }).isEnabled(), true, "the LDAPS tile is live since U4");
  }));

test("import wizard: LDAPS form → declined sign-in refuses → confirmed test bind → preview → apply → new folder", (t) =>
  flow(t, async (page) => {
    await createVault(page);
    await openSettings(page);
    const tiles = region(page, "Import").getByRole("list", { name: "Import sources" });
    await tiles.getByRole("button", { name: /Directory \(LDAPS\)/ }).click();
    const dlg = dialog(page);
    assert.equal(await dlg.getAttribute("aria-label"), "Import from Directory (LDAPS)");
    assert.equal(await textOf(dlg.getByRole("list", { name: "Import steps" })), "1Directory2Preview3Apply");
    assert.match(await dlg.innerText(), /asks you to confirm in a Mooring dialog/, "the form explains the native sign-in");
    // Client-side checks first: ldap:// is named as insecure before anything is contacted.
    await dlg.getByLabel("Server").fill("ldap://dc01.example.test");
    await dlg.getByRole("button", { name: "Test bind" }).click();
    assert.equal(await dlg.getByLabel("Server").getAttribute("aria-invalid"), "true");
    await dlg.getByLabel("Server").fill("ldaps://dc01.example.test");
    await dlg.getByLabel("Base DN").fill("OU=Servers,DC=example,DC=test");
    await dlg.getByLabel("Bind credential").selectOption("cr-ad");
    // The certificate is trusted (first contact), then the sign-in dialog is declined: nothing is sent.
    await setMock(page, { ldapTrust: ["trust"], ldapSignIn: ["decline"] });
    await dlg.getByRole("button", { name: "Test bind" }).click();
    await dlg.getByRole("alert").filter({ hasText: "You did not confirm the sign-in" }).waitFor();
    assert.match(await dlg.innerText(), /Not tested yet/);
    let snap = await probe(page);
    assert.ok(!events(snap).includes("ldap_bind"), "a declined sign-in never binds");
    const refused = snap.audit.find((e) => e.event === "confirm_refused");
    assert.deepEqual(refused?.details, { kind: "ldap_bind", target: "dc01.example.test:636", reason: "declined" });
    // Confirmed: bound as the domain account, then disconnected, nothing searched.
    await dlg.getByRole("button", { name: "Test bind" }).click();
    const bound = dlg.getByRole("status").filter({ hasText: "Bound as" });
    await bound.waitFor();
    assert.match(await bound.innerText(), /dc01\.example\.test:636[\s\S]*EXAMPLE\\admin[\s\S]*Nothing was searched/);
    // Preview: the pair is remembered, so no second dialog; the Servers OU with its sub-OUs.
    await setMock(page, { ldapSignIn: ["decline"] }); // would refuse if the dialog were raised again
    await dlg.getByRole("button", { name: "Preview" }).click();
    await dlg.getByRole("group", { name: "Preview counts" }).waitFor();
    assert.equal(await counts(dlg), "2folders5connections1credentials0secrets0skipped0warnings");
    const items = dlg.getByRole("region", { name: "Items to import" });
    assert.ok(await items.getByText("Duplicate, skipped").isVisible(), "the seeded web01 is flagged as a duplicate");
    assert.equal(await dlg.getByRole("switch", { name: /plaintext|private keys/ }).count(), 0, "no opt-ins for a directory");
    assert.match(await dlg.innerText(), /Directory account \(example\.test\)/);
    assert.doesNotMatch(await dlg.innerText(), /DC=example|OU=Servers/, "no DN on the preview step");
    await dlg.getByRole("button", { name: /^Import 6 items/ }).click(); // 7 selected minus the duplicate
    const report = dlg.getByRole("group", { name: "Import report" });
    await report.waitFor();
    assert.equal(await textOf(report), "2folders4connections1credentials0secrets1skipped");
    await dlg.getByRole("button", { name: "Open folder" }).click();
    await dlg.waitFor({ state: "detached" });
    await tree(page).getByRole("treeitem", { name: /^Imported from LDAP directory/ }).waitFor();
    snap = await probe(page);
    assert.equal(events(snap).filter((e) => e === "ldap_bind").length, 2, "one bind for the test, one for the preview");
    assert.equal(snap.audit.find((e) => e.event === "import_previewed")?.details.format, "ldap");
    assert.equal(snap.audit.find((e) => e.event === "import_applied")?.details.format, "ldap");
    assert.equal(snap.audit.filter((e) => e.event === "cert_decision").length, 1, "the certificate dialog ran once");
    assert.ok(!/admin|DC=example|OU=|password/.test(JSON.stringify(snap.audit)), "no bind name, DN or secret in the audit");
    assert.equal(await page.evaluate(() => window.__mooringE2E?.transport.ldapSignIn.length ?? -1), 1, "the dialog was not raised for the remembered pair");
  }));

// ---------------------------------------------------------------- onboarding card

test("onboarding: an empty vault shows the card; Import from another tool runs the wizard; Not now persists", (t) =>
  flow(t, async (page) => {
    await setMock(page, { emptyTree: true });
    await createVault(page);
    const card = region(page, "Nothing is moored here yet");
    await card.waitFor();
    await card.getByRole("button", { name: /^Import from another tool/ }).click();
    const dlg = dialog(page);
    const tiles = dlg.getByRole("list", { name: "Import sources" });
    await tiles.getByRole("button", { name: "Import from ~/.ssh/config" }).click();
    await dlg.getByRole("group", { name: "Preview counts" }).waitFor();
    assert.equal(await dlg.getAttribute("aria-label"), "Import from OpenSSH config");
    await dlg.getByRole("button", { name: /^Import \d+ items/ }).click();
    await dlg.getByRole("button", { name: "Open folder" }).click();
    await dlg.waitFor({ state: "detached" });
    await tree(page).getByRole("treeitem", { name: /^Imported from OpenSSH config/ }).waitFor();
    assert.equal(await card.count(), 0, "a filled tree hides the card");
  }));

test("onboarding: Start from scratch opens the connection dialog; Copy User guide link; Not now survives a lock", (t) =>
  flow(t, async (page) => {
    await page.context().grantPermissions(["clipboard-read", "clipboard-write"]);
    await setMock(page, { emptyTree: true });
    await createVault(page);
    const card = region(page, "Nothing is moored here yet");
    await card.waitFor();
    await card.getByRole("button", { name: "Copy User guide link" }).click();
    await card.getByRole("status").filter({ hasText: "Link copied." }).waitFor();
    const copied = await page.evaluate(() => navigator.clipboard.readText());
    assert.match(copied, /^https:\/\/github\.com\/yyasar21\/Mooring\//);
    await card.getByRole("button", { name: /^Start from scratch/ }).click();
    const dlg = page.getByRole("dialog", { name: "New connection" });
    await dlg.waitFor();
    await page.keyboard.press("Escape");
    await dlg.waitFor({ state: "detached" });
    // Dismissed by the path above; lock and unlock → still dismissed for this vault.
    await page.getByRole("button", { name: "Lock", exact: true }).click();
    await page.getByRole("heading", { name: "Unlock Mooring" }).waitFor();
    await page.getByLabel("Master password").fill("correct horse battery");
    await page.getByRole("button", { name: "Unlock" }).click();
    await tree(page).waitFor();
    assert.equal(await region(page, "Nothing is moored here yet").count(), 0, "dismissal is stored per vault");
    assert.ok(await page.getByText("Nothing open yet").isVisible());
  }));

// ---------------------------------------------------------------- updates card

test("updates: unconfigured build disables the check; in_app offer → confirm dialog → signature refusal text", (t) =>
  flow(t, async (page) => {
    await setMock(page, { updateConfigured: false });
    await createVault(page);
    await openSettings(page);
    const card = region(page, "Updates");
    await card.getByRole("status").filter({ hasText: "Updates are not configured in this build." }).waitFor();
    assert.equal(await card.getByRole("button", { name: "Check for updates" }).isDisabled(), true);
    assert.equal(await card.getByRole("switch").count(), 0);
    // Configured, in-app: the offer, its notes as plain text, the confirmation dialog.
    await setMock(page, { updateConfigured: true, updateMode: { installMode: "in_app" } });
    await closeSettings(page);
    await openSettings(page);
    await card.getByRole("button", { name: "Check for updates" }).click();
    const offer = card.getByLabel("Available update");
    await offer.waitFor();
    assert.match(await offer.innerText(), /0\.2\.0/);
    assert.equal(await offer.getByRole("link").count(), 0, "release notes are never links");
    await offer.getByRole("button", { name: "Install and restart" }).click();
    const confirm = page.getByRole("dialog", { name: "Install 0.2.0 and restart?" });
    await confirm.waitFor();
    await confirm.getByRole("button", { name: "Cancel" }).click();
    await confirm.waitFor({ state: "detached" });
    let snap = await probe(page);
    assert.ok(!events(snap).includes("update.install"), "cancel installs nothing");
    // Confirmed, but the bundle's signature does not verify: refused, nothing installed.
    await setMock(page, { updateInstallFails: "update.signature" });
    await offer.getByRole("button", { name: "Install and restart" }).click();
    await confirm.getByRole("button", { name: "Install and restart" }).click();
    await card.getByRole("alert").filter({ hasText: "signature did not verify" }).waitFor();
    snap = await probe(page);
    assert.ok(!events(snap).includes("update.install"), "no install row for a refused bundle");
    assert.equal(snap.audit.filter((e) => e.event === "update.refused").length, 1);
    assert.equal(await page.evaluate(() => window.__mooringE2E?.transport.restarted ?? null), null, "the app did not restart");
    // A second manual check inside the window is rate limited.
    await card.getByRole("button", { name: "Check for updates" }).click();
    await card.getByRole("alert").filter({ hasText: "You checked a moment ago" }).waitFor();
    snap = await probe(page);
    assert.equal(snap.audit.filter((e) => e.event === "update.check").length, 1);
    assert.ok(!JSON.stringify(snap.audit).includes("http"), "no URL in the audit");
  }));

test("updates: manual mode names the reason and the release page as text; background check shows the title-bar badge", (t) =>
  flow(t, async (page) => {
    await setMock(page, { updateMode: { installMode: "manual", manualReason: "homebrew" } });
    await createVault(page);
    await openSettings(page);
    const card = region(page, "Updates");
    await card.getByRole("button", { name: "Check for updates" }).click();
    const offer = card.getByLabel("Available update");
    await offer.waitFor();
    assert.match(await offer.innerText(), /installed with Homebrew/i);
    assert.equal(await card.getByRole("button", { name: "Install and restart" }).count(), 0, "no in-app install in manual mode");
    assert.equal(await card.getByRole("link").count(), 0);
    assert.match(await card.innerText(), /github\.com\/yyasar21\/Mooring\/releases\/latest/);
    // Opt in to the background check, go back to the workspace, let the mock's daily check fire.
    // The native checkbox sits under the styled track: click the label text, as a user does.
    await card.getByText("Check for updates in the background (daily)", { exact: true }).click();
    assert.equal(await card.getByRole("switch", { name: /^Check for updates in the background \(daily\)/ }).isChecked(), true);
    await closeSettings(page);
    assert.equal(await page.getByRole("button", { name: /Update .* available/ }).count(), 0);
    await setMock(page, { backgroundCheck: true });
    const badge = page.getByRole("button", { name: "Update 0.2.0 available. Open update settings" });
    await badge.waitFor();
    await badge.click();
    await region(page, "Updates").getByLabel("Available update").waitFor();
    assert.equal(await page.getByRole("button", { name: /Update .* available/ }).count(), 0, "the badge clears once the card is open");
    const snap = await waitForProbe(page, (s) => events(s).filter((e) => e === "update.check").length >= 2, "two checks");
    assert.ok(!events(snap).includes("update.install"), "a background check never installs");
    assert.ok(events(snap).includes("update.settings_changed"));
  }));

// ---------------------------------------------------------------- network card

test("network card: port check, ping and traceroute on an SSH row; WireGuard hidden without wg; absent for Kubernetes", (t) =>
  flow(t, async (page) => {
    await setMock(page, { netToolsState: { ping: true, traceroute: "tracepath", wg: false }, netRateWindowMs: 0 });
    await createVault(page);
    await tree(page).getByRole("treeitem", { name: "web01, web01.example.test" }).click();
    await details(page).getByRole("tab", { name: "Network" }).click();
    const card = details(page).getByRole("region", { name: "Network" });
    await card.waitFor();
    assert.equal(await card.getByLabel(/Other host/).getAttribute("placeholder"), "web01.example.test");
    assert.equal(await card.getByLabel("port").inputValue(), "22");
    assert.equal(await card.getByRole("button", { name: "WireGuard" }).count(), 0, "wg missing → section hidden");
    await card.getByRole("button", { name: "Check port" }).click();
    await card.getByText(/^Open .*:22 in /).waitFor();
    await card.getByLabel(/Other host/).fill("closed.example.test");
    await card.getByRole("button", { name: "Check port" }).click();
    await card.getByText(/^Closed/).waitFor();
    await card.getByLabel(/Other host/).fill("");
    await card.getByRole("button", { name: "Ping" }).click();
    await card.getByRole("table", { name: "Ping replies" }).waitFor();
    assert.match(await card.innerText(), /4 sent, 4 received, 0% loss/i);
    await card.getByRole("button", { name: "Traceroute" }).click();
    await card.getByRole("table", { name: "Traceroute hops" }).waitFor();
    assert.match(await card.innerText(), /reached[\s\S]*tracepath/i);
    // A shell-shaped host never reaches a tool: validated in the UI like Target::parse.
    await card.getByLabel(/Other host/).fill("h;id");
    assert.equal(await card.getByLabel(/Other host/).getAttribute("aria-invalid"), "true");
    assert.equal(await card.getByRole("button", { name: "Ping" }).isDisabled(), true);
    const snap = await probe(page);
    const net = snap.audit.filter((e) => e.event.startsWith("net_"));
    assert.deepEqual(net.map((e) => e.event), ["net_tcp_check", "net_tcp_check", "net_ping", "net_traceroute"]);
    assert.ok(net.every((e) => !("lines" in e.details) && !("result" in e.details)), "names and counts only");
    assert.ok(!JSON.stringify(snap.audit).includes("h;id"));
    // No card on a Kubernetes row.
    await tree(page).getByRole("treeitem", { name: /^stage-cluster/ }).click();
    await details(page).getByText("stage-cluster").first().waitFor();
    assert.equal(await details(page).getByRole("region", { name: "Network" }).count(), 0);
    assert.equal(await details(page).getByRole("tab", { name: "Network" }).count(), 0, "no Network tab either");
  }));

test("network card: missing tools are greyed with the reason; WireGuard peers show shortened keys only", (t) =>
  flow(t, async (page) => {
    await setMock(page, { netToolsState: { ping: false, traceroute: null, wg: true } });
    await createVault(page);
    await tree(page).getByRole("treeitem", { name: "dc01, dc01.example.test" }).click();
    await details(page).getByRole("tab", { name: "Network" }).click();
    const card = details(page).getByRole("region", { name: "Network" });
    await card.waitFor();
    assert.equal(await card.getByRole("button", { name: "Ping" }).isDisabled(), true);
    assert.equal(await card.getByRole("button", { name: "Traceroute" }).isDisabled(), true);
    assert.match(await card.innerText(), /ping not found on this system/i);
    assert.equal(await card.getByRole("button", { name: "Check port" }).isEnabled(), true, "own code, no tool");
    await card.getByRole("button", { name: "WireGuard" }).click();
    await card.getByRole("list", { name: "Peers of wg0" }).waitFor();
    const peers = await card.getByRole("list", { name: "Peers of wg0" }).innerText();
    assert.ok(!/[A-Za-z0-9+/]{40,}=/.test(peers), "keys are shortened, never a full key");
  }));

// ---------------------------------------------------------------- about card

test("about: name, version line, MIT, no telemetry, three links as text with Copy", (t) =>
  flow(t, async (page) => {
    await page.context().grantPermissions(["clipboard-read", "clipboard-write"]);
    await createVault(page);
    await openSettings(page);
    const card = region(page, "About");
    const about = await card.innerText();
    assert.match(about, /Mooring/i);
    assert.match(about, /Version .* for browser \(mock\)/i);
    assert.match(about, /MIT\./i);
    assert.match(about, /sends nothing about you/i);
    assert.equal(await card.getByRole("link").count(), 0, "no <a>: the main window has no opener");
    const links = card.getByRole("list", { name: "Links" });
    assert.equal(await links.getByRole("listitem").count(), 3);
    await card.getByRole("button", { name: "Copy Security policy link" }).click();
    await card.getByRole("status").filter({ hasText: "Link copied." }).waitFor();
    const copied = await page.evaluate(() => navigator.clipboard.readText());
    assert.match(copied, /^https:\/\/github\.com\/yyasar21\/Mooring\//);
    const regions = await page.getByRole("region").evaluateAll((els) => els.map((e) => e.getAttribute("aria-labelledby")));
    assert.deepEqual(regions.slice(-2), ["updates-title", "about-title"], "Updates sits directly above About");
    const text = await page.locator("body").innerText();
    assert.ok(!/[çğıöşüÇĞİÖŞÜ]/.test(text), "no Turkish text anywhere in the UI");
  }));
