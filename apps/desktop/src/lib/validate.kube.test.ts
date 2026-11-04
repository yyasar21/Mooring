// KubeConnOptions / VsphereConnOptions rules mirror the ranges of ADR-0014 §3, §5 and ADR-0015 §2.
import { DEFAULT_KUBE_OPTIONS, DEFAULT_VSPHERE_OPTIONS, KUBE_LIMITS, type KubeConnOptions } from "./ipc";
import { checkLogsArgs, checkServer, isDnsLabel, isDnsSubdomain, kubeCredentialFit, validatePodForward } from "./validate.kube";
import { normalizeOptions, unknownField, validateOptions } from "./validate.options";

const PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
const kube = (p: Partial<KubeConnOptions>) => validateOptions("kubernetes", { ...DEFAULT_KUBE_OPTIONS, ...p });

describe("KubeConnOptions validation", () => {
  it("accepts the defaults (8 MiB logs, 500 lines, /bin/sh, port-forward on)", () => {
    expect(DEFAULT_KUBE_OPTIONS).toMatchObject({ maxLogBytes: 8 * 1024 * 1024, logTailLines: 500, execCommand: "/bin/sh", portForward: true });
    expect(kube({})).toEqual({});
  });

  it("mirrors the log ranges: 64 KiB..64 MiB bytes, 1..10 000 tail lines", () => {
    expect(kube({ maxLogBytes: KUBE_LIMITS.maxLogBytes })).toEqual({});
    expect(kube({ maxLogBytes: KUBE_LIMITS.maxLogBytes + 1 }).maxLogBytes).toBeDefined();
    expect(kube({ maxLogBytes: 64 * 1024 - 1 }).maxLogBytes).toBeDefined();
    expect(kube({ maxLogBytes: 1.5 }).maxLogBytes).toBeDefined();
    expect(kube({ logTailLines: 10_000 })).toEqual({});
    expect(kube({ logTailLines: 10_001 }).logTailLines).toBeDefined();
    expect(kube({ logTailLines: 0 }).logTailLines).toBeDefined();
    expect(kube({ logTailLines: NaN }).logTailLines).toBeDefined();
  });

  it("allows only the owner's exec allow-list", () => {
    for (const c of ["/bin/sh", "/bin/bash", "/bin/ash", "sh", "bash"] as const) expect(kube({ execCommand: c })).toEqual({});
    expect(kube({ execCommand: "/usr/bin/python3" as never }).execCommand).toBeDefined();
  });

  it("checks server, namespaces, TLS name and CA", () => {
    expect(kube({ server: "https://k8s.example.test:6443" })).toEqual({});
    expect(kube({ server: "https://[2001:db8::1]:6443/base" })).toEqual({});
    expect(checkServer("http://k8s.example.test")).toMatch(/https/);
    expect(checkServer("https://u:p@k8s.example.test")).toMatch(/user name/);
    expect(checkServer("https://k8s.example.test:99999")).toMatch(/invalid/);
    expect(kube({ namespace: "Payments" }).namespace).toBeDefined();
    expect(kube({ allowedNamespaces: ["a", "b"] })).toEqual({});
    expect(kube({ allowedNamespaces: ["a", "a"] }).allowedNamespaces).toBe("Each namespace once.");
    expect(kube({ allowedNamespaces: ["ok", "bad_ns"] }).allowedNamespaces).toMatch(/bad_ns/);
    expect(kube({ allowedNamespaces: Array.from({ length: 65 }, (_, i) => `ns${i}`) }).allowedNamespaces).toMatch(/64/);
    expect(kube({ tlsServerName: "not a name" }).tlsServerName).toBeDefined();
    expect(kube({ caPem: PEM })).toEqual({});
    expect(kube({ caPem: "-----BEGIN PRIVATE KEY-----" }).caPem).toBeDefined();
    expect(kube({ context: "" }).context).toBeDefined();
  });

  it("server and CA: required with kube_token, refused with kubeconfig", () => {
    const base = DEFAULT_KUBE_OPTIONS;
    expect(Object.keys(kubeCredentialFit(base, "kube_token")).sort()).toEqual(["caPem", "server"]);
    expect(kubeCredentialFit({ ...base, server: "https://k.example.test", caPem: PEM }, "kube_token")).toEqual({});
    expect(kubeCredentialFit(base, "kubeconfig")).toEqual({});
    expect(Object.keys(kubeCredentialFit({ ...base, server: "https://k.example.test" }, "kubeconfig"))).toEqual(["server"]);
    expect(kubeCredentialFit(base, null)).toEqual({});
  });

  it("normalises the wire with serde defaults and knows every field", () => {
    expect(normalizeOptions("kubernetes", {})).toEqual(DEFAULT_KUBE_OPTIONS);
    expect(normalizeOptions("kubernetes", { execCommand: "zsh", maxLogBytes: "big", portForward: 1 })).toEqual(DEFAULT_KUBE_OPTIONS);
    expect(unknownField("kubernetes", { ...DEFAULT_KUBE_OPTIONS })).toBeNull();
    expect(unknownField("kubernetes", { secrets: true })).toBe("secrets");
  });
});

describe("VsphereConnOptions validation", () => {
  const vs = (p: object) => validateOptions("vsphere-console", { ...DEFAULT_VSPHERE_OPTIONS, ...p });
  it("refresh 15..1440 or manual, power actions off by default", () => {
    expect(DEFAULT_VSPHERE_OPTIONS).toMatchObject({ refreshMinutes: 60, allowPowerActions: false, allowVmrc: false });
    expect(vs({ refreshMinutes: 15 })).toEqual({});
    expect(vs({ refreshMinutes: 1440 })).toEqual({});
    expect(vs({ refreshMinutes: null })).toEqual({});
    expect(vs({ refreshMinutes: 14 }).refreshMinutes).toBeDefined();
    expect(vs({ refreshMinutes: 1441 }).refreshMinutes).toBeDefined();
    expect(normalizeOptions("vsphere-console", { refreshMinutes: null, allowPowerActions: "yes" })).toEqual({ ...DEFAULT_VSPHERE_OPTIONS, refreshMinutes: null });
  });
});

describe("kube names, logs and pod forwards", () => {
  it("RFC 1123 labels and subdomains", () => {
    expect(isDnsLabel("kube-system")).toBe(true);
    expect(isDnsLabel("-x")).toBe(false);
    expect(isDnsLabel("a".repeat(64))).toBe(false);
    expect(isDnsSubdomain("api-7f9c8d6b5-2kqzt")).toBe(true);
    expect(isDnsSubdomain("a.b.c")).toBe(true);
    expect(isDnsSubdomain("../etc")).toBe(false);
    expect(isDnsSubdomain("a%2Fb")).toBe(false);
  });

  it("log arguments", () => {
    const ok = { namespace: "ns", pod: "p", container: "c", tailLines: 10, sinceSeconds: null };
    expect(checkLogsArgs(ok)).toBeNull();
    expect(checkLogsArgs({ ...ok, tailLines: 0 })).toMatch(/tailLines/);
    expect(checkLogsArgs({ ...ok, sinceSeconds: -1 })).toMatch(/sinceSeconds/);
  });

  it("pod forwards bind locally and need external exposure off loopback", () => {
    const f = { kind: "pod" as const, bind: { host: "127.0.0.1", port: 0 }, target: { namespace: "ns", pod: "p", port: 80 }, exposure: "loopback" as const };
    expect(validatePodForward(f)).toEqual({});
    expect(validatePodForward({ ...f, bind: { host: "0.0.0.0", port: 0 } }).exposure).toBeDefined();
    expect(validatePodForward({ ...f, bind: { host: "0.0.0.0", port: 0 }, exposure: "external" })).toEqual({});
    expect(validatePodForward({ ...f, bind: { host: "db.example.test", port: 0 } }).bindHost).toBeDefined();
    expect(validatePodForward({ ...f, target: { ...f.target, port: 0 } }).port).toBeDefined();
    expect(validatePodForward({ ...f, target: { ...f.target, namespace: "" } }).namespace).toBeDefined();
  });
});
