// The mock's side of the `known_*_certs` host field. Rust stores
// `|2|<salt b64>|<HMAC-SHA256(salt, "host:port") b64>` (mooring_core::known_certs) so the file
// never names a host, and `known_certs_list` fills `host`/`port` for the pins that match one of
// the user's connections (`KnownCerts::list_named`). The UI reads those fields and never
// recomputes an HMAC (review 5, N-33): `hashHost`/`hostMatches` exist only so `MockTransport`
// can store and name pins the way Rust does. `hostKey`/`plainHost` are plain string helpers.

/** Rust `host_key`: lowercase, IPv6 in brackets. */
export function hostKey(host: string, port: number): string {
  const h = host.replace(/^\[/, "").replace(/\]$/, "").toLowerCase();
  return h.includes(":") ? `[${h}]:${String(port)}` : `${h}:${String(port)}`;
}

function b64ToBytes(b64: string): Uint8Array | null {
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function bytesToB64(b: Uint8Array): string {
  return btoa(String.fromCharCode(...b));
}

const subtle = (): SubtleCrypto | null => (typeof crypto !== "undefined" && "subtle" in crypto ? crypto.subtle : null);

async function hmac(salt: Uint8Array, text: string): Promise<Uint8Array | null> {
  const s = subtle();
  if (!s) return null;
  const key = await s.importKey("raw", new Uint8Array(salt), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await s.sign("HMAC", key, new TextEncoder().encode(text)));
}

/** A hashed host field for `host:port` with `salt` (the mock writes these; tests use them). */
export async function hashHost(host: string, port: number, salt: Uint8Array): Promise<string> {
  const mac = await hmac(salt, hostKey(host, port));
  return mac ? `|2|${bytesToB64(salt)}|${bytesToB64(mac)}` : hostKey(host, port);
}

/** Whether a stored host field (hashed or the plain `host:port` of a hand-written line) is `host:port`. */
export async function hostMatches(field: string, host: string, port: number): Promise<boolean> {
  const key = hostKey(host, port);
  if (!field.startsWith("|2|")) return field.toLowerCase() === key;
  const [, , saltB64, hashB64] = field.split("|");
  const salt = b64ToBytes(saltB64 ?? "");
  if (!salt || !hashB64) return false;
  const mac = await hmac(salt, key);
  return mac !== null && bytesToB64(mac) === hashB64;
}

/** The plain `host:port` of a hand-written line, or null for a hashed one. */
export function plainHost(field: string): { host: string; port: number } | null {
  if (field.startsWith("|2|")) return null;
  const m = /^\[?([^\]]+?)\]?:(\d{1,5})$/.exec(field);
  if (!m?.[1] || !m[2]) return null;
  const port = Number(m[2]);
  return port >= 1 && port <= 65535 ? { host: m[1], port } : null;
}
