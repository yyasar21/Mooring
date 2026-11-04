// ADR-0017 mock contract as rust-core S2 serves it: configure (with the backend probe), status
// and the `sync:status` event, runs, fork/rollback alarms and their native-confirmed resolution,
// disable, and `vault_join` on a fresh device. No status ever carries a secret.
import { IpcError, type SyncConfig, type SyncStatus } from "./ipc";
import { MockTransport } from "./ipc.mock";
import { MOCK_VAULT_ID } from "./ipc.mock.sync";

const code = async (p: Promise<unknown>) => {
  try {
    await p;
    return "ok";
  } catch (e: unknown) {
    return e instanceof IpcError ? e.code : "not an IpcError";
  }
};

const config = (p: Partial<SyncConfig> = {}, backend: Partial<SyncConfig["backend"]> = {}): SyncConfig => ({
  backend: { kind: "s3", endpoint: "https://s3.example.test", region: "eu-west-1", bucket: "team-vault", prefix: "mooring", pathStyle: true, ...backend },
  credentialId: "cr-s3", intervalMinutes: 15, ...p,
});

describe("mock · vault sync (ADR-0017, S2)", () => {
  it("configures, reports status and the event, runs, then disables", async () => {
    const m = new MockTransport();
    const seen: SyncStatus[] = [];
    const off = m.onSyncStatus((s) => seen.push(s));
    expect(await m.syncStatus()).toMatchObject({ state: "disabled", config: null, vaultId: MOCK_VAULT_ID, deviceId: null, counter: 0 });
    expect(await code(m.syncNow())).toBe("sync.not_configured");
    expect(await m.syncConfigure(config({}, { endpoint: "https://S3.example.test/" }))).toEqual(config({}, { endpoint: "https://s3.example.test" }));
    expect(await m.syncStatus()).toMatchObject({ state: "idle", deviceId: "dev-0001", config: config() });
    expect(seen.at(-1)?.state).toBe("idle");
    expect(await m.syncNow()).toEqual({ type: "pushed", counter: 1 });
    expect(await m.syncNow()).toEqual({ type: "noChange", counter: 1 });
    const st = await m.syncStatus();
    expect(st).toMatchObject({ state: "idle", counter: 1, lastOutcome: { type: "noChange", counter: 1 }, lastError: null });
    expect(st.lastPushUnix).not.toBeNull();
    expect(st.nextRunUnix).toBe((st.lastRunUnix ?? 0) + 15 * 60);
    expect(seen.map((s) => s.state)).toContain("running");
    expect(JSON.stringify(st)).not.toMatch(/secret|password/i);
    await m.syncDisable({ deleteRemote: true });
    expect(await m.syncStatus()).toMatchObject({ state: "disabled", config: null, counter: 0 });
    expect(m.audit.at(-1)).toMatchObject({ event: "sync.disabled", details: { delete_remote: "true" } });
    off();
    const n = seen.length;
    await m.syncConfigure(config());
    expect(seen).toHaveLength(n);
  });

  it("refuses bad settings, the wrong credential kind, backends without conditional writes and an untrusted certificate", async () => {
    const m = new MockTransport();
    expect(await code(m.syncConfigure(config({}, { bucket: "Bad_Bucket" })))).toBe("input.invalid");
    expect(await code(m.syncConfigure(config({}, { endpoint: "http://s3.example.test" })))).toBe("input.invalid");
    expect(await code(m.syncConfigure(config({ intervalMinutes: 4 })))).toBe("input.invalid");
    expect(await code(m.syncConfigure(config({ intervalMinutes: null })))).toBe("ok");
    expect((await m.syncStatus()).nextRunUnix).toBeNull();
    expect(await code(m.syncConfigure(config({ credentialId: "cr-ops" })))).toBe("credential.incompatible");
    expect(await code(m.syncConfigure({ ...config(), backend: { ...config().backend, kind: "gcs" as "s3" } }))).toBe("sync.backend_unsupported");
    expect(await code(m.syncConfigure(config({}, { endpoint: "https://s3.invalid" })))).toBe("sync.unsupported_backend");
    m.trustCert = false;
    expect(await code(m.syncConfigure(config({}, { endpoint: "https://untrusted.example.test" })))).toBe("http.trust_prompt");
    m.trustCert = true;
    expect(await code(m.syncConfigure(config({}, { endpoint: "https://untrusted.example.test" })))).toBe("ok");
    expect(m.audit.some((a) => a.event === "cert_decision" && a.details.protocol === "sync")).toBe(true);
  });

  it("a background trust prompt shows as lastError; a manual run answers it", async () => {
    const m = new MockTransport();
    await m.syncConfigure(config({}, { endpoint: "https://untrusted.example.test" }));
    m.simulateTrustPrompt();
    expect(await m.syncStatus()).toMatchObject({ state: "error", lastError: { code: "http.trust_prompt" } });
    m.trustCert = false;
    expect(await code(m.syncNow())).toBe("http.trust_prompt");
    m.trustCert = true;
    expect(await m.syncNow()).toEqual({ type: "pushed", counter: 1 });
    expect((await m.syncStatus()).lastError).toBeNull();
  });

  it("merges remote edits and keeps the conflict list until the next merge", async () => {
    const m = new MockTransport();
    await m.syncConfigure(config());
    await m.syncNow();
    m.remoteEdits = [{ kind: "connection", id: "c-web01", name: "web01", resolution: { type: "keptBoth", copyId: "c-web01-laptop" } }];
    expect(await m.syncNow()).toMatchObject({ type: "merged", counter: 2, conflicts: [{ name: "web01" }] });
    expect((await m.syncStatus()).conflicts).toHaveLength(1);
    expect(await m.syncNow()).toEqual({ type: "noChange", counter: 2 });
    expect((await m.syncStatus()).conflicts).toHaveLength(1);
    expect(m.audit.some((a) => a.event === "sync.merged" && a.details.conflicts === "1")).toBe(true);
  });

  it("a two-device apply with different pins lists a trust conflict until the pins are removed (6b L-35)", async () => {
    const m = new MockTransport();
    const kiosk = { connectionId: "c-kiosk", protocol: "vnc" as const, name: "lobby-kiosk", host: "kiosk.example.test", port: 5900, tags: [], options: undefined };
    await m.pin(kiosk);
    await m.syncConfigure(config());
    await m.syncNow();
    const seen: SyncStatus[] = [];
    m.onSyncStatus((s) => seen.push(s));
    m.remoteTrust = [kiosk];
    expect(await m.syncNow()).toMatchObject({ type: "merged", counter: 2, conflicts: [] });
    const trust = { kind: "trust", id: "known_vnc_certs", name: "kiosk.example.test:5900" };
    expect((await m.syncStatus()).conflicts).toEqual([trust]);
    expect(m.audit.some((a) => a.event === "trust_conflict" && a.details.file === "known_vnc_certs" && a.details.host === "kiosk.example.test:5900")).toBe(true);
    expect(JSON.stringify(m.audit.filter((a) => a.event === "trust_conflict"))).not.toMatch(/SHA256/);
    // both pins are listed, with different fingerprints; the conflict stands across runs
    const pins = await m.knownCertsList({ protocol: "vnc" });
    expect(new Set(pins.map((p) => p.fingerprint)).size).toBe(2);
    expect(await m.syncNow()).toEqual({ type: "noChange", counter: 2 });
    expect((await m.syncStatus()).conflicts).toEqual([trust]);
    // removing clears every pin of the host, the conflict and the event follows at once
    expect(await m.knownCertsRemove({ protocol: "vnc", host: "kiosk.example.test", port: 5900 })).toEqual({ removed: 2 });
    expect((await m.syncStatus()).conflicts).toEqual([]);
    expect(seen.at(-1)?.conflicts).toEqual([]);
    expect(await m.knownCertsList({ protocol: "vnc" })).toEqual([]);
  });

  it("fork and rollback alarms stop runs until resolved through the native confirmation", async () => {
    const m = new MockTransport();
    await m.syncConfigure(config());
    await m.syncNow();
    m.simulateAlarm("fork");
    expect(await m.syncStatus()).toMatchObject({ state: "fork", alarm: { type: "fork", remote: 2 }, remoteCounter: 2, nextRunUnix: null });
    expect(await code(m.syncNow())).toBe("sync.fork");
    m.confirmResolve = false;
    expect(await code(m.syncResolveFork({ keep: "remote" }))).toBe("sync.cancelled");
    expect((await m.syncStatus()).alarm).not.toBeNull();
    m.confirmResolve = true;
    expect(await m.syncResolveFork({ keep: "remote" })).toEqual({ type: "pulled", counter: 3 });
    expect(await m.syncStatus()).toMatchObject({ state: "idle", alarm: null, counter: 3 });
    expect(m.audit.at(-1)).toMatchObject({ event: "sync.fork_resolved", details: { keep: "remote" } });
    expect(await code(m.syncResolveFork({ keep: "local" }))).toBe("input.invalid");
    m.simulateAlarm("rollback");
    expect(await m.syncStatus()).toMatchObject({ state: "rollback", alarm: { type: "rollback", last: 3 } });
    expect(await code(m.syncNow())).toBe("sync.rollback");
    expect(await m.syncResolveFork({ keep: "local" })).toMatchObject({ type: "pushed" });
  });

  it("every command needs the vault unlocked", async () => {
    const m = new MockTransport();
    await m.syncConfigure(config());
    await m.vaultLock("user");
    expect(await code(m.syncConfigure(config()))).toBe("vault.locked");
    expect(await code(m.syncNow())).toBe("vault.locked");
    expect(await code(m.syncDisable({ deleteRemote: false }))).toBe("vault.locked");
    expect(await code(m.syncResolveFork({ keep: "local" }))).toBe("vault.locked");
    expect((await m.syncStatus()).state).toBe("idle"); // passive: still answers
  });

  it("vault_join: bootstrap vault + key first, then the synced password unlocks the device", async () => {
    const fresh = new MockTransport({ vault: "missing" });
    const join = { backend: config().backend, credentialId: "cr-s3", vaultId: MOCK_VAULT_ID, password: "correct horse battery", intervalMinutes: null };
    expect(await code(fresh.vaultJoin(join))).toBe("vault.missing");
    await fresh.vaultCreate(join.password);
    const key = await fresh.credentialCreate({ name: "bucket key", kind: "s3_access_key", fields: { access_key_id: "AKIAEXAMPLE" }, secrets: { secret_access_key: "x" } });
    expect(key.secretNames).toEqual(["secret_access_key"]);
    expect(await code(fresh.vaultJoin({ ...join, vaultId: "not-a-uuid" }))).toBe("input.invalid");
    expect(await code(fresh.vaultJoin({ ...join, vaultId: "00000000-0000-4000-8000-000000000000" }))).toBe("sync.wrong_vault");
    expect(await code(fresh.vaultJoin({ ...join, credentialId: "cr-ops" }))).toBe("credential.incompatible");
    expect(await code(fresh.vaultJoin({ ...join, password: "" }))).toBe("vault.unlock");
    expect(await fresh.vaultJoin({ ...join, credentialId: key.id })).toBe("unlocked");
    expect(await fresh.syncStatus()).toMatchObject({ state: "idle", deviceId: "dev-0002", counter: 4, config: { credentialId: key.id, intervalMinutes: null } });
    // A device that already synced, or holds other data, cannot join.
    expect(await code(fresh.vaultJoin({ ...join, credentialId: key.id }))).toBe("sync.store_not_empty");
    const used = new MockTransport();
    await used.credentialCreate({ name: "pw", kind: "user_password", fields: { username: "a" }, secrets: { password: "b" } });
    expect(await code(used.vaultJoin(join))).toBe("sync.store_not_empty");
    expect(fresh.audit.some((a) => a.event === "sync.joined")).toBe(true);
  });
});
