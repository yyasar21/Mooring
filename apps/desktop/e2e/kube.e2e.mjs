// A3 E2E flows for the Kubernetes cluster UI (ADR-0014, U1) against the real UI with the mock
// transport: open stage-cluster, the RBAC card, pod list and search, exec opens a terminal, the
// logs viewer (follow / search / stop), the pod port-forward form with its loopback default and
// the exposure confirmation, and the read-only banner.
// Run: `node --test --test-concurrency=1 apps/desktop/e2e/kube.e2e.mjs` (after `pnpm install`).
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import {
  createVault,
  freshPage,
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

const CLUSTER_ROW = "stage-cluster, https://k8s.stage.example.test:6443";
const POD = "api-7f9c8d6b5-2kqzt";

/** Create the vault and open the seeded stage-cluster connection; returns the cluster panel. */
async function openCluster(page) {
  await createVault(page);
  await page.getByRole("treeitem", { name: CLUSTER_ROW }).dblclick();
  await page.getByRole("tab", { name: /stage-cluster, connected/ }).waitFor();
  const panel = page.getByRole("tabpanel");
  await panel.getByRole("note").waitFor();
  return panel;
}

const podRow = (page, name) => page.getByRole("row", { name: new RegExp(name) });

/** What the mock cluster holds: open cluster sessions and their exec / log / forward children. */
function clusterProbe(page) {
  return page.evaluate(() => {
    const t = window.__mooringE2E?.transport;
    if (!t) throw new Error("e2e probe missing");
    const clusters = [...t.clusters.values()].map((c) => ({
      logs: c.logs.size,
      forwards: (t.forwards.get(c.info.sessionId) ?? []).map((f) => ({ kind: f.kind, exposure: f.exposure, bind: f.bind, target: f.target })),
    }));
    return {
      clusters,
      execs: t.execs.size,
      sessions: t.sessions.size,
      audit: t.audit.map((e) => ({ event: e.event, details: e.details })),
    };
  });
}

test("open stage-cluster: read-only banner, identity, RBAC card and the pod list", (t) =>
  flow(t, async (page) => {
    const panel = await openCluster(page);
    assert.match(await panel.getByRole("note").innerText(), /Mooring never mutates this cluster/);
    await panel.getByText("https://k8s.stage.example.test:6443").waitFor();
    await panel.getByText("ops@example.test").waitFor();

    const contexts = panel.getByRole("list", { name: "Contexts" });
    assert.equal(await contexts.getByText("stage-admin").getAttribute("aria-current"), "true");
    assert.equal(await contexts.getByText("stage-readonly").getAttribute("aria-disabled"), "true");

    const ns = panel.getByRole("list", { name: "Namespaces" });
    assert.equal(await ns.getByRole("button", { name: "payments" }).getAttribute("aria-current"), "true");
    const rbac = panel.getByRole("list", { name: "Permissions in payments" });
    assert.equal(await rbac.getByText("Allowed").count(), 5, "five allowed checks in payments");
    await podRow(page, POD).waitFor();
    assert.equal(await page.getByRole("row").count(), 6, "header + 5 pods");

    // A namespace where the token is denied: the card flips and the pod actions are disabled.
    await ns.getByRole("button", { name: "kube-system" }).click();
    const denied = panel.getByRole("list", { name: "Permissions in kube-system" });
    await denied.waitFor();
    assert.equal(await denied.getByText("Denied").count(), 3);
    await podRow(page, "coredns").click();
    assert.equal(await page.getByRole("button", { name: "Exec into coredns" }).isDisabled(), true);
    assert.equal(await page.getByRole("button", { name: "Logs of coredns" }).isDisabled(), true);
    assert.equal(await page.getByRole("button", { name: "Forward port 53 of coredns" }).isDisabled(), true);
    await page.getByText("The token may not exec into pods in this namespace.").waitFor();

    const snap = await clusterProbe(page);
    assert.equal(snap.clusters.length, 1, "one cluster handle");
    assert.equal(snap.sessions, 0, "never a session_open for a cluster handle");
    assert.ok(!(await probe(page)).events.includes("connected"), "no SSH-style session event");
  }));

test("pod search matches name, node and image, and an empty result says so", (t) =>
  flow(t, async (page) => {
    await openCluster(page);
    const search = page.getByRole("searchbox", { name: "Search pods" });
    await search.fill("node-b api");
    await podRow(page, "api-7f9c8d6b5-9wmrx").waitFor();
    assert.equal(await page.getByRole("row").count(), 2, "header + one pod");
    await search.fill("nothing-here");
    await page.getByText("No pod matches the search.").waitFor();
    await search.fill("");
    assert.equal(await page.getByRole("row").count(), 6);
  }));

test("exec opens a terminal tab for the chosen container and the shell echoes", (t) =>
  flow(t, async (page) => {
    await openCluster(page);
    await podRow(page, POD).click();
    await page.getByLabel("Exec command").selectOption("/bin/bash");
    await page.getByRole("button", { name: "Exec into envoy" }).click();
    await page.getByRole("tab", { name: new RegExp(`stage-cluster · ${POD}/envoy, connected`) }).waitFor();
    await page.locator(".xterm").first().waitFor();
    assert.equal(await page.locator(".xterm").count(), 1, "one terminal for the exec tab");
    assert.equal(await page.getByRole("tab").count(), 2, "cluster tab + exec tab");

    const before = await clusterProbe(page);
    assert.equal(before.clusters.length, 1);
    assert.equal(before.execs, 1, "the exec shell is its own session under the cluster handle");
    await typeInTerminal(page, "id\r");
    await waitForProbe(page, (s) => s.output.includes("id"), "exec shell echo");
    // Back to the cluster tab: the terminal stays mounted and the cluster view is unchanged.
    await page.getByRole("tab", { name: /stage-cluster, connected/ }).click();
    await page.getByRole("list", { name: "Namespaces" }).waitFor();
  }));

test("logs viewer: follow by default, search with a match count, only-matches, stop and restart", (t) =>
  flow(t, async (page) => {
    await openCluster(page);
    await podRow(page, POD).click();
    await page.getByRole("button", { name: "Logs of api" }).click();
    const region = page.getByRole("region", { name: new RegExp(`Logs of ${POD}/api`) });
    await region.waitFor();
    await region.getByText("Following").waitFor();
    assert.equal(await region.getByRole("checkbox", { name: "Follow" }).isChecked(), true, "follow is on by default");
    assert.ok((await region.getByLabel("Log lines").locator(".kube-log-line").count()) > 100, "the tail is shown");

    await region.getByRole("searchbox", { name: "Search logs" }).fill("upstream timeout");
    const count = await region.getByText(/\d+ match(es)?/).innerText();
    const n = Number(/(\d+)/.exec(count)?.[1]);
    assert.ok(n > 10, `matches: ${count}`);
    assert.equal(await region.locator(".kube-log-body mark").count(), n, "every match is highlighted");
    await region.getByRole("checkbox", { name: "Only matches" }).check();
    assert.equal(await region.locator(".kube-log-line").count(), n, "only matching lines are drawn");
    await region.getByRole("checkbox", { name: "Only matches" }).uncheck();

    await region.getByRole("button", { name: "Stop" }).click();
    await region.getByText("Stopped").waitFor();
    let snap = await clusterProbe(page);
    assert.equal(snap.clusters[0]?.logs, 0, "Stop ends the stream on the backend");
    await region.getByRole("button", { name: "Restart" }).click();
    await region.getByText("Following").waitFor();
    snap = await clusterProbe(page);
    assert.equal(snap.clusters[0]?.logs, 1, "Restart opens a new stream");

    // Closing the logs tab stops the stream.
    const logsTab = page.getByRole("tab", { name: `stage-cluster · logs ${POD}/api, connected` });
    await logsTab.getByRole("button", { name: `Close stage-cluster · logs ${POD}/api` }).click();
    snap = await clusterProbe(page);
    assert.equal(snap.clusters[0]?.logs, 0, "closing the tab stops the stream");
  }));

test("pod port-forward: loopback by default from a port button; exposure needs the confirmation", (t) =>
  flow(t, async (page) => {
    await openCluster(page);
    await podRow(page, POD).click();
    await page.getByRole("button", { name: "Forward port 9090 of api" }).click();
    const form = page.getByRole("form", { name: "New pod forward" });
    await form.waitFor();
    assert.equal(await form.getByLabel("Pod", { exact: true }).inputValue(), `payments/${POD}`);
    assert.equal(await form.getByLabel("Pod port").inputValue(), "9090");
    assert.equal(await form.getByLabel("Bind host").inputValue(), "127.0.0.1", "loopback by default");
    assert.equal(await form.getByRole("switch").isChecked(), false);
    await form.getByRole("button", { name: "Open forward" }).click();
    const table = page.getByRole("table", { name: "Forwards on this session" });
    await table.getByText(`payments/${POD}:9090`).waitFor();
    let snap = await clusterProbe(page);
    assert.deepEqual(snap.clusters[0]?.forwards, [
      { kind: "pod", exposure: "loopback", bind: { host: "127.0.0.1", port: 9090 }, target: { namespace: "payments", pod: POD, port: 9090 } },
    ]);

    // Second forward, exposed: the switch flips the bind host, the confirm dialog gates it.
    await page.getByRole("button", { name: "New forward" }).click();
    const again = page.getByRole("form", { name: "New pod forward" });
    await again.getByLabel("Pod port").fill("8080");
    await again.getByLabel("Bind port").fill("18080");
    await again.getByText("Allow other machines to connect").click();
    assert.equal(await again.getByRole("switch").isChecked(), true);
    assert.equal(await again.getByLabel("Bind host").inputValue(), "0.0.0.0");
    await again.getByRole("button", { name: "Open external forward" }).click();
    const dialog = page.getByRole("dialog", { name: "Expose this forward?" });
    assert.match(await dialog.innerText(), /0\.0\.0\.0:18080/);
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await dialog.waitFor({ state: "detached" });
    snap = await clusterProbe(page);
    assert.equal(snap.clusters[0]?.forwards.length, 1, "cancel opens nothing");

    await again.getByRole("button", { name: "Open external forward" }).click();
    await page.getByRole("dialog", { name: "Expose this forward?" }).getByRole("button", { name: "Expose to network" }).click();
    await table.getByText(`payments/${POD}:8080`).waitFor();
    snap = await clusterProbe(page);
    assert.equal(snap.clusters[0]?.forwards.length, 2);
    assert.equal(snap.clusters[0]?.forwards[1]?.exposure, "external");
    const opened = snap.audit.filter((e) => e.event === "session.forward.open");
    assert.deepEqual(opened.map((e) => e.details.exposure), ["loopback", "external"]);
  }));

test("the read-only banner is on the cluster tab and nothing mutating is offered", (t) =>
  flow(t, async (page) => {
    const panel = await openCluster(page);
    await panel.getByRole("note").waitFor();
    assert.match(await panel.getByRole("note").innerText(), /never mutates/);
    const names = await panel.getByRole("button").evaluateAll((els) => els.map((e) => e.textContent ?? ""));
    for (const forbidden of [/delete/i, /scale/i, /apply/i, /edit/i, /restart pod/i]) {
      assert.ok(!names.some((n) => forbidden.test(n)), `a mutating action is offered: ${names.join(", ")}`);
    }
    await podRow(page, POD).click();
    const detail = panel.getByRole("region", { name: `Pod ${POD}` });
    await detail.waitFor();
    const actions = await detail.getByRole("button").evaluateAll((els) => els.map((e) => e.textContent ?? ""));
    assert.ok(actions.every((a) => /^(Exec|Logs|:\d+)$/.test(a.trim())), actions.join(", "));
  }));
