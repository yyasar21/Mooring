// ADR-0024 test material: public bytes only, never a private key.
const u32 = (n: number) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
const wire = (s: string | number[]) => {
  const b = typeof s === "string" ? [...new TextEncoder().encode(s)] : s;
  return [...u32(b.length), ...b];
};

/** The clear-text header of an `openssh-key-v1` file for an sk-ed25519 key (no private section). */
export function skHandlePem(): string {
  const blob = wire("sk-ssh-ed25519@openssh.com").concat(wire(Array.from({ length: 32 }, (_, i) => i)), wire("ssh:"));
  const bytes = [...new TextEncoder().encode("openssh-key-v1"), 0, ...wire("none"), ...wire("none"), ...wire(""), ...u32(1), ...wire(blob), ...wire([1, 2, 3, 4])];
  const b64 = btoa(String.fromCharCode(...bytes));
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${b64.replace(/(.{70})/g, "$1\n")}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

