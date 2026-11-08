import { decodeSessionEvent } from "./ipc.decode.session";
import { IpcError } from "./ipc.error";
import { DEFAULT_RDP_OPTIONS } from "./ipc.types.remote";
import { normalizeOptions, validateOptions } from "./validate.options";
import { gatewayHostProblem, normalizeGateway } from "./validate.rdg";
import { derivePiv, pinOutcome, pivPreflight } from "./ipc.mock.piv";
import { PIV_FINGERPRINT, PIV_PUBLIC, SK_PUBLIC } from "./ipc.seed";
import { SMART_CARD_RDP } from "./credentials";
import { describeError, FRIENDLY } from "../stores/errors";
import { gatewayPickerOptions, GATEWAY_PROMPT_REASON } from "../components/credentials/CredentialPicker";
import { closeTextFor } from "../components/remote/ConnectionBanner";
import { gatewayChip, securityBadge } from "../components/remote/RemoteSessionTab";
import type { CredentialMeta } from "./ipc.types";
import { EVENT_LABEL } from "../components/audit/AuditView";

describe("audit labels", () => {
  it("names the R5 rows in English", () => {
    expect(EVENT_LABEL["session.rdp.gateway"]).toBe("RD Gateway sign-in");
    expect(EVENT_LABEL["session.rdp.gateway_basic"]).toBe("RD Gateway used Basic authentication");
    expect(EVENT_LABEL["credential.pin_prompted"]).toBe("Smart card PIN asked");
  });
});

const gw = { host: "gw01.example.test", port: 443, usage: "always" as const, allowBasicGateway: false, caPem: null };

describe("ADR-0027 wire: gateway_status, prompts, close codes", () => {
  it("decodes gateway_status and closes on an unknown state", () => {
    expect(decodeSessionEvent({ kind: "gateway_status", host: "gw01:443", state: "authenticating", peer_identity: "SHA256:x" }))
      .toEqual({ kind: "gateway_status", host: "gw01:443", state: "authenticating", peerIdentity: "SHA256:x" });
    expect(decodeSessionEvent({ kind: "gateway_status", host: "gw01:443", state: "up" })).toMatchObject({ state: "up", peerIdentity: null });
    expect(decodeSessionEvent({ kind: "gateway_status", host: "gw01:443", state: "sideways" })).toMatchObject({ kind: "closed", code: "unknown" });
  });

  it("a gateway trust prompt carries its certificate; a PIN prompt is always secret", () => {
    const cert = { subject: "CN=gw01", issuer: "CN=gw01", not_before: "", not_after: "", sha256: "ab", san: [], problems: ["self_signed"] };
    const p = decodeSessionEvent({ kind: "prompt", id: 2, message: "m", secret: false, purpose: "gateway_certificate_trust", certificate: cert });
    expect(p).toMatchObject({ kind: "prompt", purpose: "gateway_certificate_trust", certificate: { subject: "CN=gw01", problems: ["self_signed"] } });
    const pin = decodeSessionEvent({ kind: "prompt", id: 4, message: "Enter the PIN", secret: false, purpose: "smart_card_pin" });
    expect(pin).toMatchObject({ purpose: "smart_card_pin", secret: true, certificate: null, account: null });
    expect(decodeSessionEvent({ kind: "prompt", id: 5, message: "", secret: true, purpose: "smart_card_pin_v2" })).toMatchObject({ purpose: "other" });
  });

  it("knows the three gateway close codes", () => {
    for (const code of ["gateway_auth", "gateway_refused", "gateway_unsupported"]) {
      expect(decodeSessionEvent({ kind: "closed", reason: "r", code })).toEqual({ kind: "closed", reason: "r", code });
    }
  });
});

describe("RdpConnOptions.gateway", () => {
  it("defaults to null and normalises the wire with serde defaults", () => {
    expect(DEFAULT_RDP_OPTIONS.gateway).toBeNull();
    expect(normalizeOptions("rdp", {})).toMatchObject({ gateway: null });
    expect(normalizeGateway({ host: "gw01.example.test" })).toEqual(gw);
    expect(normalizeGateway({ host: "gw", port: 8443, usage: "if_unreachable", allowBasicGateway: true, caPem: "x" }))
      .toEqual({ host: "gw", port: 8443, usage: "if_unreachable", allowBasicGateway: true, caPem: "x" });
    expect(normalizeGateway({ host: "gw", port: 0, usage: "sometimes" })).toMatchObject({ port: 443, usage: "always" });
    expect(normalizeGateway(null)).toBeNull();
    expect(normalizeGateway("gw01")).toBeNull();
  });

  it("validates like RdGatewayOptions::validate", () => {
    for (const bad of ["", "gw01 .example.test", "https://gw", "user@gw", "gw/x", "gw\\x", `gw${String.fromCharCode(0x200b)}`]) {
      expect({ bad, problem: gatewayHostProblem(bad) !== null }).toEqual({ bad, problem: true });
    }
    expect(gatewayHostProblem("gw01.example.test")).toBeNull();
    expect(gatewayHostProblem("192.0.2.10")).toBeNull();
    const rdp = (g: unknown) => validateOptions("rdp", { ...DEFAULT_RDP_OPTIONS, gateway: g as typeof gw });
    expect(rdp(gw)).toEqual({});
    expect(rdp(null)).toEqual({});
    expect(Object.keys(rdp({ ...gw, host: "", port: 0, caPem: "-----BEGIN PRIVATE KEY-----" })).sort()).toEqual(["gateway.caPem", "gateway.host", "gateway.port"]);
  });
});

describe("gateway credential picker", () => {
  it("keeps Same as sign-in first and greys a prompt credential with the reason", () => {
    const meta = (id: string, kind: CredentialMeta["kind"]) => ({ id, kind }) as CredentialMeta;
    const out = gatewayPickerOptions([
      { value: "", label: "Same as sign-in", detail: "", meta: null, disabledReason: null, group: "" },
      { value: "p", label: "ask", detail: "", meta: meta("p", "prompt"), disabledReason: null, group: "Ask at connect" },
      { value: "a", label: "admin", detail: "", meta: meta("a", "domain_user"), disabledReason: null, group: "Stored" },
    ]);
    expect(out.map((o) => o.value)).toEqual(["", "a", "p"]);
    expect(out[2]).toMatchObject({ disabledReason: GATEWAY_PROMPT_REASON, group: "Not usable here" });
  });
});

describe("gateway and smart-card copy", () => {
  it("has English text for every R5 code and the PKINIT refusal", () => {
    for (const c of ["rdp.gateway_auth", "rdp.gateway_refused", "rdp.gateway_unsupported", "rdp.smart_card_unsupported", "ssh.piv_key_not_in_agent"]) {
      expect(FRIENDLY[c]).toMatch(/^[A-Z]/);
    }
    expect(FRIENDLY["rdp.gateway_unsupported"]).toContain("No RD Gateway WebSocket endpoint (RPC over HTTP gateways are not supported)");
    expect(FRIENDLY["ssh.piv_key_not_in_agent"]).toContain("ssh-add -s");
    expect(describeError(new IpcError("credential.incompatible", `Smart card / PIV is for SSH, not RDP. ${SMART_CARD_RDP}`))).toBe(SMART_CARD_RDP);
  });

  it("titles a changed gateway pin apart from a changed server certificate", () => {
    expect(closeTextFor({ closeCode: "trust_mismatch", reason: "RD GATEWAY CERTIFICATE CHANGED for gw01:443", openError: null }).title).toBe("RD Gateway certificate changed");
    expect(closeTextFor({ closeCode: "trust_mismatch", reason: "certificate changed", openError: null }).title).toBe("Certificate changed");
    expect(closeTextFor({ closeCode: "gateway_auth", reason: "", openError: null }).title).toBe("The RD Gateway refused the credentials");
    expect(closeTextFor({ closeCode: null, reason: "", openError: "rdp.smart_card_unsupported" }).title).toBe("Smart-card logon over RDP is not available");
  });

  it("labels nla+rdg and shows the gateway chip only while it is up", () => {
    expect(securityBadge("nla+rdg")).toEqual({ text: "NLA", hot: false });
    expect(securityBadge("tls+rdg")).toEqual({ text: "TLS without NLA", hot: true });
    expect(gatewayChip({ gateway: { host: "gw01:443", state: "up", peerIdentity: null } })).toBe("via RD Gateway gw01");
    expect(gatewayChip({ gateway: { host: "gw01:8443", state: "up", peerIdentity: null } })).toBe("via RD Gateway gw01:8443");
    expect(gatewayChip({ gateway: { host: "gw01:443", state: "authenticating", peerIdentity: null } })).toBeNull();
    expect(gatewayChip({ gateway: null })).toBeNull();
  });
});

describe("mock smart card (R5 rules)", () => {
  const card = (fields: CredentialMeta["fields"]) => ({ id: "c", name: "c", kind: "smart_card", fields, secretNames: [], fingerprint: null, createdAt: "", updatedAt: "" }) as CredentialMeta;

  it("derives the fingerprint and refuses an sk-* line", () => {
    expect(derivePiv({ public_key: `${PIV_PUBLIC} x`, fingerprint: "SHA256:forged" }).fingerprint).toMatch(/^SHA256:/);
    expect(derivePiv({ public_key: `${PIV_PUBLIC} x`, fingerprint: "SHA256:forged" }).fingerprint).not.toBe("SHA256:forged");
    expect(derivePiv({ username: "ops" })).toEqual({ username: "ops" });
    expect(() => derivePiv({ public_key: SK_PUBLIC })).toThrow(expect.objectContaining({ code: "credential.use_sk_kind" }));
  });

  it("pre-flight: no module and no agent key is refused before any I/O; the PIN is never kept", () => {
    const knobs = { agentHolds: false, pin: "accept" as const };
    expect(() => { pivPreflight(card({ public_key: PIV_PUBLIC, fingerprint: PIV_FINGERPRINT }), knobs); }).toThrow(expect.objectContaining({ code: "ssh.piv_key_not_in_agent" }));
    expect(() => { pivPreflight(card({ public_key: PIV_PUBLIC, pkcs11_module: "cryptoapi" }), knobs); }).toThrow(expect.objectContaining({ code: "ssh.piv_key_not_in_agent" }));
    expect(() => { pivPreflight(card({ pkcs11_module: "opensc" }), { ...knobs, agentHolds: true }); }).toThrow(expect.objectContaining({ code: "ssh.piv_key_not_in_agent" }));
    expect(() => { pivPreflight(card({ public_key: PIV_PUBLIC, pkcs11_module: "opensc" }), knobs); }).not.toThrow();
    expect(pinOutcome("", knobs)).toBe("cancelled");
    expect(pinOutcome("123456", knobs)).toBe("ok");
    expect(pinOutcome("123456", { ...knobs, pin: "refuse" })).toBe("refused");
  });
});
