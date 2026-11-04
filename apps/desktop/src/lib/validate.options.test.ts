// The option rules mirror crates/mooring-core/src/options/{conn,tests}.rs; cases are copied from there.
import { DEFAULT_RDP_OPTIONS, DEFAULT_VNC_OPTIONS } from "./ipc.types";
import { MockTransport } from "./ipc.mock";
import { hashHost, hostKey, hostMatches, plainHost } from "./hostHash";
import { checkCaPem, checkUrl, defaultOptions, normalizeOptions, originOf, unknownField, validateOptions, validateWeb } from "./validate.options";

const PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
const web = (p: Partial<{ url: string; allowedOrigins: string[]; allowHttp: boolean }>) =>
  validateWeb({ url: "", allowedOrigins: [], persistent: false, allowHttp: false, ...p });

describe("web URL rules (Rust check_url)", () => {
  it("accepts what Rust accepts", () => {
    for (const url of ["https://app.example.test/login?x=1", "https://192.0.2.7:8443/", "https://[2001:db8::1]:8443/"]) expect(web({ url })).toEqual({});
    expect(web({ url: "http://app.example.test", allowHttp: true })).toEqual({});
  });

  it("refuses what Rust refuses", () => {
    expect(web({ url: "http://app.example.test" }).url).toMatch(/http:\/\//);
    for (const bad of [
      "ftp://app.example.test", "https://user:pw@app.example.test", "https://", "https://app.example.test:0/",
      "https://app.example.test:99999/", "https://[2001:db8::1/", "https://*.example.test", "https://app.example.test/ space",
      "javascript:alert(1)", "app.example.test", `https://${"a".repeat(2050)}.example.test`, "https://app.example.test/\u0007",
    ]) expect({ bad, err: web({ url: bad }).url !== undefined }).toEqual({ bad, err: true });
    expect(web({ url: "" }).url).toBe("A start URL is required.");
  });

  it("limits origins to 16 exact origins without paths", () => {
    const origins = Array.from({ length: 17 }, (_, i) => `https://sso${String(i)}.example.test`);
    expect(web({ url: "https://a.example.test", allowedOrigins: origins.slice(0, 16) })).toEqual({});
    expect(web({ url: "https://a.example.test", allowedOrigins: origins }).allowedOrigins).toBe("At most 16 extra origins.");
    expect(web({ url: "https://a.example.test", allowedOrigins: ["https://sso.example.test/path"] }).allowedOrigins).toMatch(/no path/);
    expect(checkUrl("https://sso.example.test/", false, true)).toBeNull();
    expect(originOf("HTTPS://App.Example.test:8443/x")).toBe("https://app.example.test:8443");
  });
});

describe("RDP / VNC option rules", () => {
  it("keyboard layouts are the closed KLID list; maxFps is 30 or 60", () => {
    expect(validateOptions("rdp", { ...DEFAULT_RDP_OPTIONS, keyboardLayout: 0x1041f })).toEqual({});
    expect(validateOptions("rdp", { ...DEFAULT_RDP_OPTIONS, keyboardLayout: 1234 as 0x0409 }).keyboardLayout).toBeDefined();
    expect(validateOptions("vnc", { ...DEFAULT_VNC_OPTIONS, maxFps: 45 as 30 }).maxFps).toBe("Frame rate is 30 or 60.");
    expect(validateOptions("ssh", {})).toEqual({});
  });

  it("caPem: certificates only, ≤ 64 KiB", () => {
    expect(checkCaPem(null)).toBeNull();
    expect(checkCaPem(PEM + PEM)).toBeNull();
    expect(checkCaPem("hello")).toMatch(/BEGIN CERTIFICATE/);
    expect(checkCaPem(`${PEM}-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----`)).toMatch(/private key/);
    expect(checkCaPem(`${PEM}-----BEGIN PUBLIC KEY-----`)).toMatch(/Only CERTIFICATE/);
    expect(checkCaPem(PEM + "A".repeat(64 * 1024))).toMatch(/64 KiB/);
  });

  it("normalizes wire objects with serde defaults and spots unknown fields", () => {
    expect(normalizeOptions("rdp", {})).toEqual(DEFAULT_RDP_OPTIONS);
    expect(normalizeOptions("vnc", { viewOnly: true, maxFps: 60 })).toEqual({ ...DEFAULT_VNC_OPTIONS, viewOnly: true, maxFps: 60 });
    expect(normalizeOptions("web", null)).toEqual(defaultOptions("web"));
    expect(normalizeOptions("ssh", { x: 1 })).toEqual({});
    expect(unknownField("rdp", { keyboardLayout: 1033, colorDepth: 16 })).toBe("colorDepth");
    expect(unknownField("vnc", { viewOnly: true })).toBeNull();
    // N-34: `allowNoAuth` is part of the mirror, so a load does not flag it and a save does not reset it.
    expect(unknownField("vnc", { allowNoAuth: true })).toBeNull();
    expect(normalizeOptions("vnc", { allowNoAuth: true })).toMatchObject({ allowNoAuth: true });
    expect(normalizeOptions("vnc", { allowNoAuth: "yes" })).toMatchObject({ allowNoAuth: false });
    expect(DEFAULT_VNC_OPTIONS.allowNoAuth).toBe(false);
  });
});

describe("known-certs host fields", () => {
  it("matches a salted HMAC host field like mooring_core::known_certs", async () => {
    const salt = new Uint8Array(32).fill(7);
    const field = await hashHost("DC01.example.test", 3389, salt);
    expect(field).toMatch(/^\|2\|[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]{44}$/);
    expect(await hostMatches(field, "dc01.example.test", 3389)).toBe(true);
    expect(await hostMatches(field, "dc01.example.test", 3390)).toBe(false);
    expect(await hostMatches("|2|!!|??", "dc01.example.test", 3389)).toBe(false);
    expect(await hostMatches("192.0.2.10:5900", "192.0.2.10", 5900)).toBe(true);
    expect(hostKey("[2001:DB8::1]", 3389)).toBe("[2001:db8::1]:3389");
    expect(plainHost("[2001:db8::1]:3389")).toEqual({ host: "2001:db8::1", port: 3389 });
    expect(plainHost(field)).toBeNull();
  });
});

describe("mock connection_options_get/set", () => {
  it("round-trips, fills defaults and refuses like Rust", async () => {
    const m = new MockTransport();
    expect(await m.connectionOptionsGet({ connectionId: "c-kiosk" })).toEqual({ ...DEFAULT_VNC_OPTIONS, viewOnly: true });
    expect(await m.connectionOptionsGet({ connectionId: "c-web01" })).toEqual({});
    const stored = await m.connectionOptionsSet({ connectionId: "c-dc", options: { ...DEFAULT_RDP_OPTIONS, maxFps: 60 } });
    expect(stored).toMatchObject({ maxFps: 60, keyboardLayout: 0x0409 });
    const bad = (options: Record<string, unknown>) => m.connectionOptionsSet({ connectionId: "c-dc", options: options as never });
    await expect(bad({ colorDepth: 16 })).rejects.toMatchObject({ code: "input.invalid", message: "invalid options: unknown field colorDepth" });
    await expect(bad({ maxFps: 45 })).rejects.toMatchObject({ message: "invalid options: maxFps must be 30 or 60" });
    await expect(bad({ keyboardLayout: 1234 })).rejects.toMatchObject({ code: "input.invalid" });
    await expect(bad({ caPem: "hello" })).rejects.toMatchObject({ code: "input.invalid" });
    await expect(m.connectionOptionsSet({ connectionId: "c-web01", options: { maxFps: 30 } as never })).rejects.toMatchObject({ code: "input.invalid" });
    await expect(m.connectionOptionsSet({ connectionId: "c-lb", options: { url: "http://lb.example.test" } as never })).rejects.toMatchObject({ code: "input.invalid" });
  });

  it("drops stored options when the protocol changes, as the store does", async () => {
    const m = new MockTransport();
    const c = m.connections.find((x) => x.id === "c-kiosk");
    if (!c) throw new Error("seed");
    await m.connectionUpdate({ ...c, id: c.id, protocol: "rdp", credentialId: null });
    expect(await m.connectionOptionsGet({ connectionId: "c-kiosk" })).toEqual(DEFAULT_RDP_OPTIONS);
  });
});
