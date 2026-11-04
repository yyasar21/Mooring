// `sync_status.conflicts` is untagged on the wire (rust-core fix 8, review 6b L-35): merge entries
// with a resolution and trust entries without one. Each is decoded by shape; drift is dropped.
import { decodeSyncConflict, decodeSyncConflicts, decodeSyncStatus, isMergeConflict, isTrustConflict } from "./ipc.decode.sync";

const merge = { kind: "connection", id: "c-web01", name: "web01", resolution: { type: "keptBoth", copyId: "c-web01-laptop" } };
const trust = { kind: "trust", id: "known_rdp_certs", name: "dc01.example.test:3389" };

describe("sync conflict decoder (6b L-35)", () => {
  it("decodes merge entries with every resolution and trust entries without one", () => {
    expect(decodeSyncConflict(merge)).toEqual(merge);
    expect(decodeSyncConflict({ ...merge, kind: "folder", resolution: { type: "keptEdit" } })).toMatchObject({ kind: "folder", resolution: { type: "keptEdit" } });
    expect(decodeSyncConflict({ ...merge, kind: "credential", resolution: { type: "lastWriterWins" } })).toMatchObject({ resolution: { type: "lastWriterWins" } });
    expect(decodeSyncConflict(trust)).toEqual(trust);
    // the exact JSON rust-core's sync_tests_6b pins, with known_hosts as the file
    expect(decodeSyncConflict({ kind: "trust", id: "known_hosts", name: "ssh.example.test:22" })).toEqual({ kind: "trust", id: "known_hosts", name: "ssh.example.test:22" });
  });

  it("drops entries that are neither shape instead of crashing", () => {
    expect(decodeSyncConflict({ kind: "trust", id: "known_rdp_certs" })).toBeNull(); // no name
    expect(decodeSyncConflict({ kind: "connection", id: "c", name: "n" })).toBeNull(); // merge without resolution
    expect(decodeSyncConflict({ kind: "connection", id: "c", name: "n", resolution: { type: "keptBoth" } })).toBeNull(); // no copyId
    expect(decodeSyncConflict({ kind: "pin", id: "x", name: "y" })).toBeNull(); // unknown kind
    expect(decodeSyncConflict("trust")).toBeNull();
    expect(decodeSyncConflicts([merge, null, trust, 7, { kind: "trust" }])).toEqual([merge, trust]);
    expect(decodeSyncConflicts("not a list")).toEqual([]);
  });

  it("keeps the wire order (merge first, then trust) and the rest of the status untouched", () => {
    const s = decodeSyncStatus({ state: "idle", counter: 3, conflicts: [trust, merge], lastError: null });
    expect(s).toMatchObject({ state: "idle", counter: 3, lastError: null });
    expect(s.conflicts).toEqual([trust, merge]);
    expect(s.conflicts.filter(isTrustConflict)).toEqual([trust]);
    expect(s.conflicts.filter(isMergeConflict)).toEqual([merge]);
    expect(decodeSyncStatus(null).conflicts).toEqual([]);
  });
});
