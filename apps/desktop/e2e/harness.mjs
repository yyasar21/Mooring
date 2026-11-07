// E2E harness: the Vite dev server (real UI, MockTransport via e2e/boot.html) driven by a
// headless Chromium through the `playwright` library and `node:test`. No Tauri, no display
// server, no network beyond loopback.
//
// Resolution: `vite` comes from apps/desktop/node_modules; `playwright` from NODE_PATH (CI
// installs a pinned global copy, see .github/workflows/e2e.yml) or any local install.
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { mkdir } from "node:fs/promises";
import path from "node:path";

const require = createRequire(import.meta.url);
const appRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/** Every action and wait fails after this long; the mock answers within one macrotask. */
export const STEP_TIMEOUT_MS = 10_000;

/** A valid master password for the mock (the UI enforces >= 12 characters). */
export const MASTER = "correct horse battery";

/** Start Vite on a free loopback port and launch Chromium. Call `stop()` when done. */
export async function startHarness() {
  const { chromium } = require("playwright");
  const { createServer } = await import(require.resolve("vite"));
  const server = await createServer({
    root: appRoot,
    configFile: path.join(appRoot, "vite.config.ts"),
    server: { host: "127.0.0.1", port: 0, strictPort: false, hmr: false },
    logLevel: "warn",
  });
  await server.listen();
  const base = server.resolvedUrls?.local[0];
  if (!base) throw new Error("vite did not report a local URL");
  // `MOORING_E2E_BROWSER` names a Chromium / Chrome binary for machines where Playwright's
  // own download is blocked (a sandbox); CI uses the pinned Playwright Chromium.
  const executablePath = process.env.MOORING_E2E_BROWSER || undefined;
  const browser = await chromium.launch({ executablePath });
  return {
    base,
    browser,
    async stop() {
      await browser.close();
      await server.close();
    },
  };
}

/**
 * A fresh page on the e2e entry: a new MockTransport with no vault. Page errors fail the test
 * through `errors` (checked by the caller after each flow).
 */
export async function freshPage(h) {
  const context = await h.browser.newContext({ viewport: { width: 1280, height: 800 } });
  context.setDefaultTimeout(STEP_TIMEOUT_MS);
  // Tauri runs the app with `freezePrototype: true`; mirror it so a dependency that writes to an
  // inherited Object.prototype member fails here, not only in a release build (2026-11-07 blank
  // SSH window). The Vite dev client is loaded before boot and tolerates it.
  await context.addInitScript(() => { Object.freeze(Object.prototype); });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(new URL("e2e/boot.html", h.base).href);
  return { page, errors, close: () => context.close() };
}

/** Directory for failure screenshots (gitignored by apps/desktop/e2e/.gitignore). */
export const RESULTS_DIR = path.join(appRoot, "e2e", "results");

/** Best effort: a failing flow keeps its original error even if the screenshot fails. */
export async function screenshotOnFailure(page, name) {
  const file = `${name.replace(/[^a-z0-9]+/gi, "-").slice(0, 80)}.png`;
  try {
    await mkdir(RESULTS_DIR, { recursive: true });
    await page.screenshot({ path: path.join(RESULTS_DIR, file), fullPage: true });
  } catch {
    // ignored: the assertion error is what matters
  }
}

/** What the mock transport holds right now (session count, audit events, echoed output). */
export function probe(page) {
  return page.evaluate(() => {
    const p = window.__mooringE2E;
    if (!p) throw new Error("e2e probe missing: was the page loaded through e2e/boot.html?");
    return {
      vault: p.transport.vault,
      sessions: p.transport.sessions.size,
      audit: p.transport.audit.map((e) => ({ event: e.event, details: e.details })),
      output: p.output,
      events: [...p.events],
    };
  });
}

/** Poll `probe` until `pred` holds (mock events arrive asynchronously). */
export async function waitForProbe(page, pred, what) {
  const deadline = Date.now() + STEP_TIMEOUT_MS;
  for (;;) {
    const snap = await probe(page);
    if (pred(snap)) return snap;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}: ${JSON.stringify(snap)}`);
    await page.waitForTimeout(50);
  }
}

// ---------- UI steps (accessible names only, so styling changes do not break them) ----------

export async function createVault(page, password = MASTER) {
  await page.getByLabel("Master password").fill(password);
  await page.getByLabel("Repeat password").fill(password);
  await page.getByRole("button", { name: "Create vault" }).click();
  await page.getByRole("tree", { name: "Connections" }).waitFor();
}

export async function addConnection(page, { name, host, folder = "Staging" }) {
  await page.getByRole("button", { name: "New connection" }).click();
  const dialog = page.getByRole("dialog", { name: "New connection" });
  await dialog.getByLabel("Name", { exact: true }).fill(name);
  await dialog.getByLabel("Host", { exact: true }).fill(host);
  await dialog.getByLabel("Folder", { exact: true }).selectOption({ label: folder });
  await dialog.getByRole("button", { name: "Create connection" }).click();
  await dialog.waitFor({ state: "detached" });
  return page.getByRole("treeitem", { name: `${name}, ${host}` });
}

/** Double-click a connection row and wait for the host-key (TOFU) prompt. */
export async function openSession(page, row) {
  await row.dblclick();
  const prompt = page.getByRole("alertdialog");
  await prompt.getByRole("heading", { name: "Verify host identity" }).waitFor();
  return prompt;
}

/** Type into the focused terminal (xterm's hidden textarea). */
export async function typeInTerminal(page, text) {
  await page.locator(".xterm-helper-textarea").first().focus();
  await page.keyboard.type(text);
}

export async function lockFromTitleBar(page) {
  await page.getByRole("button", { name: "Lock", exact: true }).click();
  await page.getByRole("heading", { name: "Unlock Mooring" }).waitFor();
}
