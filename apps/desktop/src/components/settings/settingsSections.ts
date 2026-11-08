// M6: the settings sections in page order, grouped for the left-hand navigation. `id` is the
// card heading id (the contract `openSettingsCard` and the tests rely on); `terms` are extra
// words the search matches besides the title.

export interface SettingsSection {
  id: string;
  title: string;
  group: "Vault" | "Trust and audit" | "Application";
  terms: string;
}

export const SETTINGS_SECTIONS: readonly SettingsSection[] = [
  { id: "autolock-title", title: "Auto-lock", group: "Vault", terms: "lock idle timeout screen sleep minutes" },
  { id: "security-title", title: "Security", group: "Vault", terms: "biometric touch id windows hello unlock master password" },
  { id: "backup-title", title: "Backup", group: "Vault", terms: "export import age passphrase restore file" },
  { id: "sync-title", title: "Vault sync", group: "Vault", terms: "devices synchronise synchronize folder conflict" },
  { id: "sources-title", title: "Secret sources", group: "Vault", terms: "external secrets hashicorp vault approle oidc 1password bitwarden token" },
  { id: "trust-title", title: "Known certificates", group: "Trust and audit", terms: "trust tls pin fingerprint rdp vnc rd gateway remove" },
  { id: "ssh-title", title: "SSH", group: "Trust and audit", terms: "security key fido2 agent smart card piv" },
  { id: "syslog-title", title: "Syslog mirror", group: "Trust and audit", terms: "audit log server udp tcp tls forward" },
  { id: "appearance-title", title: "Appearance", group: "Application", terms: "theme dark light system colour color" },
  { id: "settings-import", title: "Import", group: "Application", terms: "connections mremoteng royal ts rdm csv ldap" },
  { id: "updates-title", title: "Updates", group: "Application", terms: "version upgrade release check install" },
  { id: "about-title", title: "About", group: "Application", terms: "version build licence license platform" },
];

/** Sections whose title or terms contain every word of the query (case-insensitive). */
export function matchSections(query: string, sections: readonly SettingsSection[] = SETTINGS_SECTIONS): SettingsSection[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) return [...sections];
  return sections.filter((s) => {
    const hay = `${s.title} ${s.group} ${s.terms}`.toLowerCase();
    return words.every((w) => hay.includes(w));
  });
}
