import { useEffect, useState } from "react";
import { useApp } from "../../stores/app";
import { PortableLine } from "./PortableLine";
import { SettingsCard } from "./Toggle";
import { DevBadge } from "../DevBadge";

/** Public places a user may want to reach from the app. No command opens a browser from the main window (no opener capability), so each one is shown as text with a Copy button. */
export const ABOUT_LINKS: readonly { label: string; url: string }[] = [
  { label: "Source code", url: "https://github.com/yyasar21/Mooring" },
  { label: "Security policy", url: "https://github.com/yyasar21/Mooring/blob/main/SECURITY.md" },
  { label: "User guide", url: "https://github.com/yyasar21/Mooring/tree/main/docs/user-guide" },
];

const OS_NAMES: Record<string, string> = { macos: "macOS", windows: "Windows", linux: "Linux" };

/** "Version 0.1.0 for macOS (aarch64)", plus "debug build" when it is one. */
export function versionLine(info: { version: string; os: string; arch: string; debug: boolean } | null): string {
  if (!info) return "Version unknown";
  const os = OS_NAMES[info.os] ?? info.os;
  return `Version ${info.version} for ${os} (${info.arch})${info.debug ? ", debug build" : ""}`;
}

/** Settings → About: name, version from `app_info`, the icon, links, licence, the no-telemetry promise. */
export function AboutCard() {
  const info = useApp((s) => s.info);
  const dev = info?.channel === "dev";
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    if (copied === null) return;
    const t = setTimeout(() => { setCopied(null); }, 1800);
    return () => { clearTimeout(t); };
  }, [copied]);

  const copy = async (url: string) => {
    try {
      await navigator.clipboard.writeText(url);
      setCopied(url);
    } catch {
      setCopied(null);
    }
  };

  return (
    <SettingsCard title="About" labelledBy="about-title">
      <div className="settings-body about">
        <div className="about-head">
          <img src="/favicon.svg" alt="" width={72} height={72} className="about-icon" />
          <div className="min-w-0">
            <p className="about-name">{info?.name ?? "Mooring"}{dev && <> <DevBadge /></>}</p>
            <p className="about-version" data-testid="about-version">{versionLine(info)}</p>
            {dev && (
              <p className="about-dev" data-testid="about-dev">
                Mooring Dev — development build, separate data from Mooring{info.identifier ? <> (<span className="mono">{info.identifier}</span>)</> : null}.
              </p>
            )}
            <p className="about-tagline">Remote access, kept local: your connections and credentials never leave this machine unless you sync them yourself.</p>
          </div>
        </div>
        {info?.portableDataDir && <PortableLine path={info.portableDataDir} />}

        <ul className="about-links" aria-label="Links">
          {ABOUT_LINKS.map((l) => (
            <li key={l.url} className="about-link">
              <span className="about-link-label">{l.label}</span>
              <code className="about-link-url">{l.url.replace(/^https:\/\//, "")}</code>
              <button type="button" className="btn btn-ghost" onClick={() => void copy(l.url)} aria-label={`Copy ${l.label} link`}>
                {copied === l.url ? "Copied" : "Copy"}
              </button>
            </li>
          ))}
        </ul>
        <p role="status" className="sr-only">{copied ? "Link copied." : ""}</p>

        <dl className="about-facts">
          <div>
            <dt>Licence</dt>
            <dd>MIT. Free to use, study, change and share; the source is public.</dd>
          </div>
          <div>
            <dt>Telemetry</dt>
            <dd>None. Mooring sends nothing about you or your sessions anywhere. The only request it makes on its own is the update check, and only if you turn it on.</dd>
          </div>
          <div>
            <dt>Vault</dt>
            <dd>Argon2id key derivation, XChaCha20-Poly1305 encryption, hash-chained audit log.</dd>
          </div>
        </dl>
      </div>
    </SettingsCard>
  );
}
