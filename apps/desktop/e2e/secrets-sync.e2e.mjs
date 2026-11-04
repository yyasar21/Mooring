// A3 E2E flows for secret sources and vault sync (ADR-0016 / ADR-0017, U3 + U4) against the real
// UI with the mock transport: Settings → Secret sources (a token source from a new API token
// credential, Test, Forget; OIDC begin → poll → done through the mock; delete refused with
// `source.in_use`), the `external_ref` credential form with its names-only Test, Settings →
// Vault sync (set up, Sync now, fork banner → settings → keep remote, the conflict list, disable),
// the first-run join flow and the global sync banner. The IdP window, the S3 bucket and Rust's
// native confirmations are the mock's knobs (`oidcOutcome`, `remoteEdits`, `confirmResolve`).
// Run: `node --test --test-concurrency=1 apps/desktop/e2e/secrets-sync.e2e.mjs`.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { createVault, freshPage, MASTER, probe, screenshotOnFailure, startHarness } from "./harness.mjs";

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

/** The vault id the mock's seeded bucket holds (what a joining device types). */
const MOCK_VAULT_ID = "7b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d";
/** A fixture secret for the join form; never a real key. */
const JOIN_SECRET = "wJalrXUtnFEMI-FIXTURE-KEY";

const views = (page) => page.getByRole("navigation", { name: "Views" });
const settingsCard = (page, name) => page.getByRole("region", { name });
const sourceRow = (page, name) => settingsCard(page, "Secret sources").getByRole("listitem", { name });

/** Mock knobs on the transport (nothing here is a secret). */
function setMock(page, patch) {
  return page.evaluate((p) => {
    const t = window.__mooringE2E?.transport;
    if (!t) throw new Error("e2e probe missing");
    if (p.oidcOutcome) t.oidcOutcome = p.oidcOutcome;
    if (typeof p.confirmResolve === "boolean") t.confirmResolve = p.confirmResolve;
    if (p.remoteEdits) t.remoteEdits = p.remoteEdits;
    if (p.alarm) t.simulateAlarm(p.alarm);
    if (p.trustPrompt) t.simulateTrustPrompt();
  }, patch);
}

async function openSettings(page) {
  await views(page).getByRole("button", { name: "Settings" }).click();
  await settingsCard(page, "Secret sources").waitFor();
}

/** Credentials → New credential → API token, so a token source has something to pick. */
async function createApiToken(page, name) {
  await views(page).getByRole("button", { name: "Credentials" }).click();
  const view = page.getByRole("region", { name: "Credentials" });
  await view.getByRole("button", { name: "New credential" }).click();
  await view.getByRole("button", { name: "API token" }).click();
  const form = view.getByRole("form", { name: "New API token" });
  await form.getByLabel("Name", { exact: true }).fill(name);
  await form.getByLabel(/^Token/).fill("test-only token value");
  await form.getByRole("button", { name: "Create credential" }).click();
  await view.getByRole("form", { name: `Edit ${name}` }).waitFor();
}

/** Settings → Vault sync → Set up… with the seeded `team bucket key`. */
async function configureSync(page, { manual = false } = {}) {
  const card = settingsCard(page, "Vault sync");
  await card.getByRole("button", { name: "Set up…" }).click();
  const dlg = page.getByRole("dialog", { name: "Set up vault sync" });
  await dlg.getByRole("textbox", { name: "Endpoint" }).fill("https://s3.example.test");
  await dlg.getByLabel("Bucket").fill("team-vault");
  await dlg.getByLabel("Region").fill("eu-west-1");
  await dlg.getByLabel("Access key").selectOption("cr-s3");
  if (manual) await dlg.getByText("Manual only", { exact: true }).click();
  else await dlg.getByLabel("Minutes between syncs").fill("30");
  await dlg.getByRole("button", { name: "Save and check" }).click();
  await dlg.waitFor({ state: "detached" });
  await card.getByRole("status").filter({ hasText: "Saved. The storage answered and conditional writes work." }).waitFor();
  return card;
}

test("secret sources: a token source from a new API token credential, Test, Forget", (t) =>
  flow(t, async (page) => {
    await createVault(page);
    await createApiToken(page, "vault token");
    await openSettings(page);
    const card = settingsCard(page, "Secret sources");
    await sourceRow(page, "ops vault").waitFor();
    await card.getByRole("button", { name: "Add source…" }).click();
    const dlg = page.getByRole("dialog", { name: "New secret source" });
    await dlg.getByRole("button", { name: "Create source" }).click();
    await dlg.getByRole("alert").filter({ hasText: "Fix the highlighted fields." }).waitFor();
    await dlg.getByLabel("Name", { exact: true }).fill("kv vault");
    await dlg.getByLabel("Address", { exact: true }).fill("https://kv.example.test:8200");
    await dlg.getByText("Token", { exact: true }).click();
    const tokenCred = dlg.getByLabel("Token credential");
    await tokenCred.selectOption(await tokenCred.locator("option", { hasText: "vault token" }).getAttribute("value"));
    await dlg.getByRole("button", { name: "Create source" }).click();
    await dlg.waitFor({ state: "detached" });

    const row = sourceRow(page, "kv vault");
    await row.filter({ hasText: "https://kv.example.test:8200" }).waitFor();
    await row.getByRole("button", { name: "Test" }).click();
    await row.getByRole("status").filter({ hasText: "Signed in with Token: token TTL 1 h, not renewable, 2 policies." }).waitFor();
    await row.getByRole("button", { name: "Forget" }).click();
    await card.getByRole("status").filter({ hasText: "Forgot the cached token of kv vault." }).waitFor();

    const snap = await probe(page);
    assert.equal(snap.audit.at(-1)?.event, "secret_login", "the test login is audited; forgetting a token writes no revoke row");
    assert.equal(snap.audit.at(-1)?.details?.method, "token");
    const html = await page.content();
    assert.doesNotMatch(html, /test-only token value/, "the token never reaches the DOM again");
    assert.doesNotMatch(JSON.stringify(snap.audit), /test-only token value/);
  }));

test("secret sources: OIDC sign-in through the mock (begin → poll → done → test) and a closed window", (t) =>
  flow(t, async (page) => {
    await createVault(page);
    await openSettings(page);
    const card = settingsCard(page, "Secret sources");
    await card.getByRole("button", { name: "Add source…" }).click();
    const dlg = page.getByRole("dialog", { name: "New secret source" });
    await dlg.getByLabel("Name", { exact: true }).fill("sso vault");
    await dlg.getByLabel("Address", { exact: true }).fill("https://sso.example.test");
    await dlg.getByText("OIDC", { exact: true }).click();
    await dlg.getByRole("button", { name: "Create source" }).click();
    await dlg.getByText("OIDC needs a role.").waitFor();
    await dlg.getByLabel("OIDC role").fill("ops");
    await dlg.getByText("http://localhost:8250/oidc/callback").waitFor();
    await dlg.getByRole("button", { name: "Create source" }).click();
    await dlg.waitFor({ state: "detached" });

    const row = sourceRow(page, "sso vault");
    await row.filter({ hasText: "Role ops on oidc" }).waitFor();
    await row.getByRole("button", { name: "Sign in…" }).click();
    await row.getByText("Sign-in window open.").waitFor();
    // The UI learns the outcome from the 1 s `secret_source_oidc_status` poll, then tests.
    await row.getByRole("status").filter({ hasText: "Signed in with OIDC: token TTL 1 h, renewable, 2 policies." }).waitFor();

    await setMock(page, { oidcOutcome: "closed" });
    await row.getByRole("button", { name: "Sign in…" }).click();
    await row.getByRole("alert").filter({ hasText: "The sign-in window was closed before the identity provider answered." }).waitFor();
    const snap = await probe(page);
    assert.ok(snap.audit.some((e) => e.event === "secret_login"), "the OIDC login is audited");
  }));

test("secret sources: delete is refused with source.in_use while a reference uses it, then succeeds", (t) =>
  flow(t, async (page) => {
    await createVault(page);
    await openSettings(page);
    const card = settingsCard(page, "Secret sources");
    const row = sourceRow(page, "ops vault");
    await row.filter({ hasText: "used by 1 reference" }).waitFor();
    await row.getByRole("button", { name: "Delete ops vault" }).click();
    await row.getByText(/1 credential still reference this source/).waitFor();
    await row.getByRole("button", { name: "Confirm delete" }).click();
    await card.getByRole("alert").filter({ hasText: "A credential still references this source." }).waitFor();
    await row.waitFor();

    // Delete the reference, then the source goes.
    await views(page).getByRole("button", { name: "Credentials" }).click();
    const view = page.getByRole("region", { name: "Credentials" });
    await view.getByRole("button", { name: "Delete db via vault" }).click();
    await view.getByRole("button", { name: "Confirm delete" }).click();
    await view.getByRole("button", { name: "Delete db via vault" }).waitFor({ state: "detached" });
    await openSettings(page);
    const again = sourceRow(page, "ops vault");
    await again.getByRole("button", { name: "Delete ops vault" }).click();
    await again.getByRole("button", { name: "Confirm delete" }).click();
    await card.getByRole("status").filter({ hasText: "Deleted ops vault." }).waitFor();
    await card.getByText("No secret sources").waitFor();
  }));

test("external_ref credential: edit the reference, Test lists names only, no value in the DOM", (t) =>
  flow(t, async (page) => {
    await createVault(page);
    await views(page).getByRole("button", { name: "Credentials" }).click();
    const view = page.getByRole("region", { name: "Credentials" });
    await view.getByRole("list", { name: "Stored credentials" }).getByRole("button", { name: /^Secret manager reference db via vault/ }).click();
    const form = view.getByRole("form", { name: "Edit db via vault" });
    assert.equal(await form.getByLabel("Secret source").inputValue(), "src-ops");
    assert.equal(await form.getByLabel(/^Reference/).inputValue(), "kv/ops/db");
    await form.getByLabel(/^KV version/).fill("7");
    await form.getByLabel("Target field to map").selectOption("password");
    await form.getByRole("button", { name: "Map" }).click();
    await form.getByLabel("KV key for password").fill("pass");
    await form.getByRole("button", { name: "Save credential" }).click();

    const edited = view.getByRole("form", { name: "Edit db via vault" });
    await edited.getByRole("button", { name: "Test reference" }).click();
    const result = edited.getByRole("status", { name: "Reference test" });
    await result.filter({ hasText: "1 required name is missing and 1 extra key would be refused" }).waitFor();
    const text = await result.textContent();
    assert.match(text, /present\s*username/);
    assert.match(text, /missing\s*password/);
    assert.match(text, /extra\s*password/);
    assert.doesNotMatch(await page.content(), /hunter2/, "the mock's secret value never reaches the DOM");
    const snap = await probe(page);
    assert.equal(snap.audit.at(-1)?.event, "secret_resolved");
  }));

test("vault sync: set up, Sync now, fork banner → settings → keep remote, conflicts, disable", (t) =>
  flow(t, async (page) => {
    await createVault(page);
    await openSettings(page);
    const card = settingsCard(page, "Vault sync");
    await card.getByLabel("Sync status").filter({ hasText: "Off" }).waitFor();
    await card.getByText(MOCK_VAULT_ID).waitFor();
    await configureSync(page);
    const status = card.getByLabel("Sync status");
    await status.filter({ hasText: "Idle" }).waitFor();
    await status.filter({ hasText: "https://s3.example.test / team-vault / mooring" }).waitFor();
    await status.filter({ hasText: "every 30 min" }).waitFor();

    await card.getByRole("button", { name: "Sync now" }).click();
    await card.getByRole("status").filter({ hasText: "Pushed generation 1." }).waitFor();
    await status.filter({ hasText: "gen 1" }).waitFor();

    // A fork found by a background pull: the global banner shows outside Settings.
    await views(page).getByRole("button", { name: "Settings" }).click(); // back to the workspace
    await page.getByText("Nothing open yet").waitFor();
    await setMock(page, { alarm: "fork" });
    const banner = page.getByRole("alert").filter({ hasText: "Sync fork detected" });
    await banner.waitFor();
    await banner.getByText(/Two devices published generation 2 by laptop/).waitFor();
    assert.equal(await banner.getByRole("button", { name: /Resolve/ }).count(), 0, "resolve stays on the card");
    await banner.getByRole("button", { name: "Open Vault sync settings" }).click();
    await card.getByRole("alert").filter({ hasText: "Fork detected" }).waitFor();
    assert.equal(await page.locator(".sync-banner").count(), 0, "one alert at a time");
    assert.equal(await card.getByRole("heading", { name: "Vault sync" }).evaluate((el) => el === document.activeElement), true);
    assert.equal(await card.getByRole("button", { name: "Sync now" }).isDisabled(), true);

    // Rust's native confirmation: cancelled first, then confirmed.
    await setMock(page, { confirmResolve: false });
    await card.getByRole("button", { name: "Resolve: keep remote" }).click();
    await card.getByRole("alert").filter({ hasText: "You cancelled the confirmation, so nothing was changed." }).waitFor();
    await setMock(page, { confirmResolve: true });
    await card.getByRole("button", { name: "Resolve: keep remote" }).click();
    await card.getByRole("status").filter({ hasText: /Resolved, keeping the remote copy\./ }).waitFor();
    await status.filter({ hasText: "Idle" }).waitFor();

    // A merge with a conflict lists it.
    await setMock(page, { remoteEdits: [{ kind: "credential", id: "cr-ops", name: "ops on-call", resolution: { type: "keptBoth", copyId: "cr-ops-2" } }] });
    await card.getByRole("button", { name: "Sync now" }).click();
    await card.getByRole("status").filter({ hasText: /Merged into generation \d+ with 1 conflict \(listed below\)\./ }).waitFor();
    const conflicts = card.getByRole("list", { name: "Merge conflicts" });
    await conflicts.filter({ hasText: "ops on-call" }).waitFor();
    assert.match(await conflicts.textContent(), /both copies kept/);

    // Disable, keeping the bucket.
    await card.getByRole("button", { name: "Disable…" }).click();
    await card.getByRole("button", { name: "Disable, keep bucket" }).click();
    await status.filter({ hasText: "Off" }).waitFor();
    const snap = await probe(page);
    const events = snap.audit.map((e) => e.event);
    for (const want of ["sync.fork_detected", "sync.disabled"]) assert.ok(events.includes(want), `${want} in ${events.join(",")}`);
    assert.doesNotMatch(JSON.stringify(snap.audit), /AKIAEXAMPLE|secret_access_key/i, "no key material in the audit log");
  }));

test("global sync banner: a failed background run shows the trust hint and clears after a run; dismiss is per alarm", (t) =>
  flow(t, async (page) => {
    await createVault(page);
    await openSettings(page);
    const card = await configureSync(page, { manual: true });
    await card.getByRole("button", { name: "Sync now" }).click();
    await card.getByRole("status").filter({ hasText: "Pushed generation 1." }).waitFor();
    await views(page).getByRole("button", { name: "Settings" }).click();
    await page.getByText("Nothing open yet").waitFor();

    await setMock(page, { trustPrompt: true });
    const error = page.getByRole("alert").filter({ hasText: "Vault sync failed" });
    await error.waitFor();
    await error.getByText(/the certificate is not trusted\. Run Sync now from the settings to answer the certificate prompt/).waitFor();
    assert.equal(await error.getAttribute("data-kind"), "error");
    await error.getByRole("button", { name: "Open Vault sync settings" }).click();
    await card.getByRole("button", { name: "Sync now" }).click();
    await card.getByRole("status").filter({ hasText: /Nothing to sync|Pushed generation|Pulled/ }).waitFor();
    await views(page).getByRole("button", { name: "Settings" }).click();
    await page.getByText("Nothing open yet").waitFor();
    assert.equal(await page.locator(".sync-banner").count(), 0, "a successful run clears the error banner");

    await setMock(page, { alarm: "rollback" });
    await page.getByRole("alert").filter({ hasText: "Sync rollback detected" }).waitFor();
    await page.getByRole("button", { name: "Dismiss sync notice" }).click();
    await page.locator(".sync-banner").waitFor({ state: "detached" });
    // The dismissal is per unlocked session: a lock and unlock brings the alarm back.
    await page.getByRole("button", { name: "Lock", exact: true }).click();
    await page.getByRole("heading", { name: "Unlock Mooring" }).waitFor();
    await page.getByLabel("Master password").fill(MASTER);
    await page.getByRole("button", { name: "Unlock" }).click();
    await page.getByRole("tree", { name: "Connections" }).waitFor();
    await page.getByRole("alert").filter({ hasText: "Sync rollback detected" }).waitFor();
  }));

test("first run: join a synced vault (bootstrap → key → join) opens the shell with sync on", (t) =>
  flow(t, async (page) => {
    await page.getByRole("heading", { name: "Create your vault" }).waitFor();
    await page.getByRole("button", { name: "Join a synced vault instead" }).click();
    const form = page.getByRole("form", { name: "Join a synced vault" });
    await form.getByRole("button", { name: "Join vault" }).click();
    await form.getByRole("alert").filter({ hasText: "Fix the highlighted fields." }).waitFor();
    assert.equal(await form.getByLabel("Vault id").getAttribute("aria-invalid"), "true");
    assert.equal((await probe(page)).vault, "missing", "nothing is created before the form is valid");

    await form.getByRole("textbox", { name: "Endpoint" }).fill("https://s3.example.test");
    await form.getByLabel("Bucket").fill("team-vault");
    await form.getByLabel("Region").fill("eu-west-1");
    await form.getByLabel("Access key ID").fill("AKIAEXAMPLE");
    await form.getByLabel("Secret access key").fill(JOIN_SECRET);
    await form.getByLabel("Vault id").fill("00000000-0000-4000-8000-000000000000");
    await form.getByLabel("Synced vault password").fill(MASTER);
    await form.getByText("Manual only", { exact: true }).click();
    await form.getByRole("button", { name: "Join vault" }).click();
    // A wrong vault id: the bootstrap vault and the key stay, the form says so, a retry re-joins only.
    await form.getByRole("alert").filter({ hasText: "The bucket does not hold a vault with that id under that prefix." }).waitFor();
    await form.getByRole("note").filter({ hasText: "The bootstrap vault and the access key are already on this device" }).waitFor();
    assert.equal(await form.getByLabel("Secret access key").isDisabled(), true);
    assert.equal((await probe(page)).vault, "unlocked");

    await form.getByLabel("Vault id").fill(MOCK_VAULT_ID);
    await form.getByLabel("Synced vault password").fill(MASTER);
    await form.getByRole("button", { name: "Join vault" }).click();
    await page.getByRole("tree", { name: "Connections" }).waitFor();
    await page.getByText("Nothing open yet").waitFor();
    const snap = await probe(page);
    const events = snap.audit.map((e) => e.event);
    assert.equal(events.filter((e) => e === "vault_created").length, 1, "one bootstrap vault");
    assert.ok(events.includes("sync.joined"), events.join(","));
    assert.doesNotMatch(await page.content(), new RegExp(JOIN_SECRET), "the key never lingers in the DOM");
    assert.doesNotMatch(JSON.stringify(snap.audit), new RegExp(JOIN_SECRET));

    await views(page).getByRole("button", { name: "Settings" }).click();
    const card = settingsCard(page, "Vault sync");
    await card.getByLabel("Sync status").filter({ hasText: "Idle" }).waitFor();
    await card.getByLabel("Sync status").filter({ hasText: "dev-0002" }).waitFor();
  }));
