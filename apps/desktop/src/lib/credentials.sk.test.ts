import { isSkMaterial, parseSkPublicLine, shortFingerprint, skCertificateProblem } from "./credentials.sk";
import { detectKind } from "./credentials";
import { decodeSessionEvent } from "./ipc.decode.session";
import { deriveSk, refuseSkInSshKey, skPreflight, DEFAULT_SK_KNOBS } from "./ipc.mock.sk";
import { SK_FINGERPRINT, SK_PUBLIC } from "./ipc.seed";
import { publicKeyFingerprint } from "../components/credentials/usePublicKeyFingerprint";
import { skHandlePem } from "../test/sk";
import { FRIENDLY } from "../stores/errors";

// Public test material only: made-up key bytes, no private key anywhere.
const ECDSA =
  "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8AAAALc3NoOm1vb3Jpbmc=";

describe("sk-* public key shape (ADR-0024)", () => {
  it("reads the type and FIDO application of both key types", () => {
    expect(parseSkPublicLine(`${SK_PUBLIC} ops@yubikey`)).toEqual({
      key: { type: "sk-ssh-ed25519@openssh.com", application: "ssh:", comment: "ops@yubikey" },
      problem: null,
    });
    expect(parseSkPublicLine(ECDSA).key).toMatchObject({ type: "sk-ecdsa-sha2-nistp256@openssh.com", application: "ssh:mooring" });
    expect(parseSkPublicLine("").problem).toBeNull();
  });

  it("explains what is wrong with a line that is not an sk key", () => {
    expect(parseSkPublicLine("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixture").problem).toMatch(/regular SSH key/);
    expect(parseSkPublicLine("sk-ssh-ed25519-cert-v01@openssh.com AAAA").problem).toMatch(/certificate/);
    expect(parseSkPublicLine("sk-ssh-ed25519@openssh.com !!!!").problem).toMatch(/Expected an sk-/);
    expect(parseSkPublicLine("sk-ssh-ed25519@openssh.com AAAA").problem).toMatch(/does not match its type/);
    // an ecdsa blob under the ed25519 name
    expect(parseSkPublicLine(`sk-ssh-ed25519@openssh.com ${ECDSA.split(" ")[1] ?? ""}`).problem).toMatch(/does not match/);
    expect(parseSkPublicLine(`${SK_PUBLIC}\n${SK_PUBLIC}`).problem).toMatch(/one public key line/);
    expect(skCertificateProblem("ssh-ed25519-cert-v01@openssh.com AAAA")).toMatch(/sk-…-cert-v01/);
    expect(skCertificateProblem("sk-ssh-ed25519-cert-v01@openssh.com AAAA")).toBeNull();
  });

  it("the live fingerprint is the real SHA-256 of the blob", async () => {
    expect(await publicKeyFingerprint(SK_PUBLIC)).toBe(SK_FINGERPRINT);
  });

  it("tells sk material from other keys, including a key handle file", () => {
    expect(isSkMaterial(SK_PUBLIC)).toBe(true);
    expect(isSkMaterial("sk-ssh-ed25519-cert-v01@openssh.com AAAA x")).toBe(true);
    expect(isSkMaterial(skHandlePem())).toBe(true);
    expect(isSkMaterial("-----BEGIN OPENSSH PRIVATE KEY-----\nZml4dHVyZS1rZXktbm90LXJlYWw=\n-----END OPENSSH PRIVATE KEY-----")).toBe(false);
    expect(isSkMaterial("ssh-ed25519 AAAA")).toBe(false);
  });

  it("a pasted sk line or handle file picks the security-key kind", () => {
    expect(detectKind(SK_PUBLIC)).toMatchObject({ kind: "ssh_sk_key", field: "public_key" });
    expect(detectKind(skHandlePem())).toMatchObject({ kind: "ssh_sk_key", field: "private_key" });
    expect(detectKind("-----BEGIN OPENSSH PRIVATE KEY-----\nZml4\n-----END OPENSSH PRIVATE KEY-----")?.kind).toBe("ssh_key");
  });

  it("shortens a fingerprint for the banner", () => {
    expect(shortFingerprint(SK_FINGERPRINT)).toBe("SHA256:0f/IntG4…rdDv4");
    expect(shortFingerprint("SHA256:short")).toBe("SHA256:short");
  });
});

describe("touch events on the wire", () => {
  it("decodes touch_required / touch_cleared / touch_timeout without turning them into a close", () => {
    expect(decodeSessionEvent({ kind: "touch_required", id: 4, fingerprint: SK_FINGERPRINT, timeout_seconds: 30 })).toEqual({
      kind: "touch_required", id: 4, fingerprint: SK_FINGERPRINT, timeoutSeconds: 30,
    });
    expect(decodeSessionEvent({ kind: "touch_required", id: 4, fingerprint: "x", timeout_seconds: -1, hop: 1 })).toMatchObject({ timeoutSeconds: 30, hop: 1 });
    expect(decodeSessionEvent({ kind: "touch_cleared", id: 4 })).toEqual({ kind: "touch_cleared", id: 4 });
    expect(decodeSessionEvent({ kind: "touch_timeout", id: 4, hop: 9 })).toEqual({ kind: "touch_timeout", id: 4 });
  });
});

describe("mock security-key rules (R4)", () => {
  it("refuses sk material in an ssh_key with credential.use_sk_kind", () => {
    expect(() => { refuseSkInSshKey("ssh_key", { public_key: SK_PUBLIC }, {}); }).toThrow(expect.objectContaining({ code: "credential.use_sk_kind" }));
    expect(() => { refuseSkInSshKey("ssh_key", {}, { private_key: skHandlePem() }); }).toThrow(expect.objectContaining({ code: "credential.use_sk_kind" }));
    expect(() => { refuseSkInSshKey("ssh_key", { public_key: "ssh-ed25519 AAAA" }, {}); }).not.toThrow();
  });

  it("derives application and fingerprint, serves resident as a boolean and defaults the backend", () => {
    expect(deriveSk({ username: "u", public_key: SK_PUBLIC, resident: "true" })).toMatchObject({ backend: "agent", resident: true, application: "ssh:" });
    expect(deriveSk({ username: "u", public_key: SK_PUBLIC, resident: "false" })).not.toHaveProperty("resident");
  });

  it("refuses before connecting: helper off, key not in the agent", () => {
    expect(() => { skPreflight({ backend: "helper" }, DEFAULT_SK_KNOBS); }).toThrow(expect.objectContaining({ code: "ssh.sk_helper_disabled" }));
    expect(() => { skPreflight({ backend: "agent" }, { ...DEFAULT_SK_KNOBS, agentHolds: false }); }).toThrow(expect.objectContaining({ code: "ssh.sk_key_not_in_agent" }));
  });
});

describe("R4 error codes have English copy", () => {
  it("names each security-key code", () => {
    for (const c of ["credential.use_sk_kind", "ssh.sk_key_not_in_agent", "ssh.sk_helper_disabled", "ssh.sk_helper_missing"]) {
      expect([c, (FRIENDLY[c] ?? "").length > 20]).toEqual([c, true]);
    }
  });
});
