import { useEffect, useState } from "react";
import { base64ToBytes } from "../../lib/ipc";

/**
 * OpenSSH-style `SHA256:` fingerprint of a public key line (`ssh-ed25519 AAAA… comment`), for
 * the live readout while typing. Public data only; the stored fingerprint comes from Rust.
 * Returns null for anything that is not one well-formed key line or when WebCrypto is missing.
 */
export async function publicKeyFingerprint(line: string): Promise<string | null> {
  const m = /^\s*((?:ssh|ecdsa|sk)-[a-z0-9@.-]+)\s+([A-Za-z0-9+/]+={0,2})(\s.*)?$/.exec(line.trim());
  const subtle = (globalThis.crypto as Crypto | undefined)?.subtle;
  if (!m?.[2] || !subtle) return null;
  let blob: Uint8Array<ArrayBuffer>;
  try {
    blob = new Uint8Array(base64ToBytes(m[2]));
  } catch {
    return null;
  }
  if (blob.length < 16) return null;
  const digest = new Uint8Array(await subtle.digest("SHA-256", blob));
  let bin = "";
  for (const b of digest) bin += String.fromCharCode(b);
  return `SHA256:${btoa(bin).replace(/=+$/, "")}`;
}

export function usePublicKeyFingerprint(line: string): string | null {
  const [fp, setFp] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    if (!line.trim()) {
      setFp(null);
      return;
    }
    publicKeyFingerprint(line).then(
      (v) => { if (alive) setFp(v); },
      () => { if (alive) setFp(null); },
    );
    return () => { alive = false; };
  }, [line]);
  return fp;
}
