// Mock ADR-0027 smart cards as rust-core R5 serves them: the `smart_card` field rules (derived
// `fingerprint`, `sk-*` lines refused with `credential.use_sk_kind`), the connect pre-flight
// (`ssh.piv_key_not_in_agent`) and the `smart_card_pin` prompt. The mock never keeps a PIN: it only
// checks that one was entered and drops it.
import type { CredentialFields, CredentialMeta, SessionEventHandler } from "./ipc.types";
import { IpcError } from "./ipc.error";
import { isSkMaterial } from "./credentials.sk";
import { fakeFingerprint } from "./ipc.mock.creds";

const str = (v: unknown) => (typeof v === "string" ? v : "");

/** Prompt id of the PIN question (distinct from TOFU 1, OTP 2 and credential 3). */
export const PIN_PROMPT_ID = 4;

/** Derived fields of a `smart_card` (`card_fields::normalise`). */
export function derivePiv(fields: CredentialFields): CredentialFields {
  const out: CredentialFields = { ...fields };
  delete out.fingerprint;
  const line = str(fields.public_key).trim();
  if (line === "") return out;
  if (isSkMaterial(line)) throw new IpcError("credential.use_sk_kind", "this is a FIDO2 security key; create an SSH security key (FIDO2) credential");
  const blob = line.split(/\s+/)[1] ?? "";
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(blob)) throw new IpcError("input.invalid", "public_key: not an OpenSSH public key line");
  out.fingerprint = fakeFingerprint(blob);
  return out;
}

/** How the mock card behaves at connect. */
export interface MockPivKnobs {
  /** ssh-agent already holds the card's key (no PIN asked). */
  agentHolds: boolean;
  /** What the card says to a PIN. */
  pin: "accept" | "refuse";
}

export const DEFAULT_PIV_KNOBS: MockPivKnobs = { agentHolds: false, pin: "accept" };

/** L-49: Rust adds the card with an ssh-agent lifetime of `CARD_LIFETIME_SECS` (3600 s). */
export const CARD_LIFETIME_MS = 3_600_000;

/**
 * The keys the mock ssh-agent holds after a PIN, by fingerprint, until their lifetime ends. A
 * reconnect inside the hour finds the key and is not asked again, as with the real agent.
 */
export class MockAgentCards {
  private until = new Map<string, number>();
  constructor(private readonly now: () => number = Date.now) {}
  holds(fingerprint: string): boolean {
    const t = this.until.get(fingerprint);
    return t !== undefined && t > this.now();
  }
  load(fingerprint: string): void {
    this.until.set(fingerprint, this.now() + CARD_LIFETIME_MS);
  }
  /** The lifetime ran out (or the agent restarted): the next sign-in asks the PIN again. */
  forget(): void {
    this.until.clear();
  }
}

/** The app pre-flight: no public key, or a key the agent lacks with no module to load it → refuse before any I/O. */
export function pivPreflight(cred: CredentialMeta, knobs: MockPivKnobs): void {
  const module = str(cred.fields.pkcs11_module);
  if (str(cred.fields.public_key) === "") {
    throw new IpcError("ssh.piv_key_not_in_agent", "the smart card credential has no public key; paste the line from ssh-keygen -D <module>");
  }
  if (!knobs.agentHolds && (module === "" || module === "cryptoapi")) {
    throw new IpcError("ssh.piv_key_not_in_agent", `smart card key ${str(cred.fields.fingerprint)} is not in ssh-agent; load the card with \`ssh-add -s <module>\``);
  }
}

/** The PIN question (`piv_auth::load_card`). */
export function askPin(emit: SessionEventHandler, cred: CredentialMeta): void {
  const reader = str(cred.fields.reader_hint);
  emit({
    kind: "prompt",
    id: PIN_PROMPT_ID,
    message: `Enter the PIN of the smart card${reader ? ` (${reader})` : ""} for key ${str(cred.fields.fingerprint)}`,
    secret: true,
    purpose: "smart_card_pin",
    account: null,
    certificate: null,
  });
}

/** What the answer leads to. The PIN itself is never recorded: only whether one was entered. */
export function pinOutcome(pin: string, knobs: MockPivKnobs): "ok" | "cancelled" | "refused" {
  if (pin === "") return "cancelled";
  return knobs.pin === "accept" ? "ok" : "refused";
}
