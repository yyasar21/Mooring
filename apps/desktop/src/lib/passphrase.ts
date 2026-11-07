// ADR-0023: the backup passphrase hint. Rust enforces ≥ 12 characters and "not the master
// password"; the UI adds a length/word-count hint. No dictionary, no entropy estimate: length
// and separate words are what make a passphrase strong.

export type StrengthLevel = "weak" | "fair" | "good" | "strong";

export const MIN_EXPORT_PASSPHRASE = 12;

export function passphraseStrength(p: string): { level: StrengthLevel; text: string } {
  const words = p.trim().split(/\s+/).filter((w) => w.length >= 3).length;
  if (p.length < MIN_EXPORT_PASSPHRASE) {
    return { level: "weak", text: `Too short: use at least ${String(MIN_EXPORT_PASSPHRASE)} characters.` };
  }
  if (p.length >= 24 || words >= 5) return { level: "strong", text: "Strong." };
  if (p.length >= 16 || words >= 4) return { level: "good", text: "Good. A few more words make it strong." };
  return { level: "fair", text: "Fair. Four or more unrelated words make a stronger passphrase." };
}

/** Why the export form cannot be sent yet (null = it can). */
export function exportFormProblem(a: { master: string; passphrase: string; repeat: string }): string | null {
  if (a.master === "") return "Enter the master password.";
  if (a.passphrase.length < MIN_EXPORT_PASSPHRASE) return `The backup passphrase needs at least ${String(MIN_EXPORT_PASSPHRASE)} characters.`;
  if (a.passphrase === a.master) return "Use a passphrase that differs from the master password.";
  if (a.repeat !== a.passphrase) return "The two passphrases differ.";
  return null;
}
