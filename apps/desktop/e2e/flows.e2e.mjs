// A1 E2E flows against the real UI with the mock transport.
// Run: `node --test --test-concurrency=1 apps/desktop/e2e/flows.e2e.mjs` (after `pnpm install`).
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import {
  MASTER,
  addConnection,
  createVault,
  freshPage,
  lockFromTitleBar,
  openSession,
  probe,
  screenshotOnFailure,
  startHarness,
  typeInTerminal,
  waitForProbe,
} from "./harness.mjs";

let h;
before(async () => {
  h = await startHarness();
});
after(async () => {
  await h?.stop();
});

/**
 * Run one flow on a fresh page; any uncaught page error fails it. On failure a full-page
 * screenshot lands in apps/desktop/e2e/results/ (uploaded by .github/workflows/e2e.yml).
 */
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

test("create vault: weak and mismatched passwords are refused, a valid one opens the shell", (t) =>
  flow(t, async (page) => {
    await page.getByRole("heading", { name: "Create your vault" }).waitFor();
    const submit = page.getByRole("button", { name: "Create vault" });

    await page.getByLabel("Master password").fill("short");
    assert.equal(await submit.isDisabled(), true, "short password must not submit");
    assert.match(await page.getByRole("alert").first().innerText(), /at least 12 characters/);

    await page.getByLabel("Master password").fill(MASTER);
    await page.getByLabel("Repeat password").fill(`${MASTER}x`);
    assert.equal(await submit.isDisabled(), true, "mismatch must not submit");

    await createVault(page);
    const snap = await probe(page);
    assert.equal(snap.vault, "unlocked");
    assert.ok(events(snap).includes("vault_created"));
  }));

test("happy path: create vault, add connection, trust host, echo shell, lock", (t) =>
  flow(t, async (page) => {
    await createVault(page);
    const row = await addConnection(page, { name: "e2e-box", host: "e2e-box.example.test" });
    await row.waitFor();

    const prompt = await openSession(page, row);
    assert.match(await prompt.innerText(), /SHA256:mock-e2e-box/);
    await page.getByRole("tab", { name: "e2e-box, waiting for you" }).waitFor();
    await prompt.getByRole("button", { name: "Trust and connect" }).click();
    await page.getByRole("tab", { name: "e2e-box, connected" }).waitFor();

    await typeInTerminal(page, "uname -a\r");
    const snap = await waitForProbe(page, (s) => s.output.includes("uname -a\r\n$ "), "shell echo");
    assert.equal(snap.sessions, 1);
    const trust = snap.audit.find((e) => e.event === "trust_decision");
    assert.equal(trust?.details.decision, "accepted");
    assert.equal(trust?.details.host, "e2e-box.example.test");

    await lockFromTitleBar(page);
    const locked = await probe(page);
    assert.equal(locked.vault, "locked");
    assert.equal(locked.sessions, 0, "lock must drop every session");
    assert.equal(await page.getByRole("tab").count(), 0, "no session tab survives the lock");
    assert.equal(await page.locator(".xterm").count(), 0, "no terminal survives the lock");
  }));

test("TOFU reject: the session ends and the decision is audited", (t) =>
  flow(t, async (page) => {
    await createVault(page);
    const row = await addConnection(page, { name: "mitm", host: "mitm.example.test" });
    const prompt = await openSession(page, row);
    await prompt.getByRole("button", { name: "Reject and disconnect" }).click();
    await prompt.waitFor({ state: "detached" });

    const snap = await waitForProbe(page, (s) => s.events.includes("closed"), "session closed");
    assert.equal(snap.sessions, 0);
    assert.ok(!snap.events.includes("connected"), "a rejected host must never connect");
    const trust = snap.audit.find((e) => e.event === "trust_decision");
    assert.equal(trust?.details.decision, "rejected");
    const closed = snap.audit.filter((e) => e.event === "session_closed").at(-1);
    assert.equal(closed?.details.reason, "host key rejected");
  }));

test("lock then unlock: the shell reloads with the saved connection and the host stays trusted", (t) =>
  flow(t, async (page) => {
    await createVault(page);
    const row = await addConnection(page, { name: "keep-me", host: "keep-me.example.test" });
    const prompt = await openSession(page, row);
    await prompt.getByRole("button", { name: "Trust and connect" }).click();
    await page.getByRole("tab", { name: "keep-me, connected" }).waitFor();
    await lockFromTitleBar(page);

    const unlock = page.getByRole("button", { name: "Unlock" });
    assert.equal(await unlock.isDisabled(), true, "empty password must not submit");
    await page.getByLabel("Master password").fill(MASTER);
    await unlock.click();
    await page.getByRole("tree", { name: "Connections" }).waitFor();

    const again = page.getByRole("treeitem", { name: "keep-me, keep-me.example.test" });
    await again.dblclick();
    // Known host now: no TOFU prompt, straight to connected.
    await page.getByRole("tab", { name: "keep-me, connected" }).waitFor();
    assert.equal(await page.getByRole("alertdialog").count(), 0);
    const snap = await probe(page);
    assert.deepEqual(
      events(snap).filter((e) => e.startsWith("vault_")),
      ["vault_unlocked", "vault_created", "vault_locked", "vault_unlocked"],
    );
  }));

test("lock shortcut (mod+Shift+L) locks from the workspace", (t) =>
  flow(t, async (page) => {
    await createVault(page);
    const row = await addConnection(page, { name: "kb", host: "kb.example.test" });
    const prompt = await openSession(page, row);
    await prompt.getByRole("button", { name: "Trust and connect" }).click();
    await page.getByRole("tab", { name: "kb, connected" }).waitFor();
    // Focus the tree, not the terminal: in a terminal the shortcut belongs to the remote shell
    // on Linux/Windows unless Shift is added (see lib/shortcuts.ts).
    await page.getByRole("tree", { name: "Connections" }).focus();
    await page.keyboard.press("ControlOrMeta+Shift+L");
    await page.getByRole("heading", { name: "Unlock Mooring" }).waitFor();
    assert.equal((await probe(page)).sessions, 0);
  }));
