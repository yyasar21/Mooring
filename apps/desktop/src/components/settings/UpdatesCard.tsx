import { useEffect, useState } from "react";
import type { UpdateInfo, UpdateManualReason } from "../../lib/ipc";
import { fmtBytes, fmtDate, fmtStamp } from "../../lib/format";
import { useApp } from "../../stores/app";
import { useSessions } from "../../stores/sessions";
import { useUpdate } from "../../stores/update";
import { Modal } from "../dialogs/Modal";
import { PORTABLE_UPDATE_TEXT, PortableLine } from "./PortableLine";
import { SettingsCard, Toggle } from "./Toggle";

/** Where a manual install starts. Always the latest release, never a URL from the manifest. */
export const RELEASE_PAGE = "https://github.com/yyasar21/Mooring/releases/latest";

export const MANUAL_REASON_TEXT: Record<UpdateManualReason, string> = {
  package_manager: "This copy was installed by a package manager (deb, rpm or MSI). Update it with the package manager, or download the new package from the release page.",
  homebrew: "This copy was installed with Homebrew. Update it with brew upgrade, or download the new version from the release page.",
  not_writable: "The installed application is not writable by your user (for example a root-owned /Applications bundle or a per-machine install), and Mooring never asks for elevated rights. Download the new version from the release page and install it the way this one was installed.",
  not_bundled: "This build is not a packaged release, so there is nothing for Mooring to replace. Download a packaged release from the release page.",
  portable: PORTABLE_UPDATE_TEXT,
};

/** Release notes as plain text: Rust stripped controls, ANSI and bidi; the UI only keeps the line breaks. */
function Notes({ text }: { text: string }) {
  const lines = text.split("\n");
  return (
    <div className="update-notes select-text" aria-label="Release notes">
      {lines.map((l, i) => (
        <span key={i} className="update-notes-line">{l}</span>
      ))}
    </div>
  );
}

function Available({ info, onInstall, busy }: { info: UpdateInfo; onInstall: () => void; busy: boolean }) {
  const a = info.available;
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => { setCopied(false); }, 1800);
    return () => { clearTimeout(t); };
  }, [copied]);
  if (!a) return null;
  const date = fmtDate(a.date);
  const size = fmtBytes(a.size);
  const manual = info.installMode === "manual";
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(RELEASE_PAGE);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };
  return (
    <div className="update-offer" data-mode={info.installMode} aria-label="Available update">
      <div className="update-offer-head">
        <span className="update-offer-label">Update available</span>
        <span className="update-offer-version tnum">{a.version}</span>
        <span className="m-micro ml-auto tnum">{[date, size].filter(Boolean).join(" · ")}</span>
      </div>
      {a.notes.trim() !== "" && <Notes text={a.notes} />}
      {manual ? (
        <>
          <p className="field-hint">{MANUAL_REASON_TEXT[info.manualReason ?? "not_bundled"]}</p>
          <div className="about-link">
            <span className="about-link-label">Release page</span>
            <code className="about-link-url">{RELEASE_PAGE.replace(/^https:\/\//, "")}</code>
            <button type="button" className="btn btn-ghost" onClick={() => void copy()} aria-label="Copy release page link">{copied ? "Copied" : "Copy"}</button>
          </div>
          <p role="status" className="sr-only">{copied ? "Link copied." : ""}</p>
        </>
      ) : (
        <div className="flex flex-wrap items-center gap-2">
          <button type="button" className="btn btn-primary" disabled={busy} onClick={onInstall}>Install and restart</button>
          <span className="field-hint">The download is verified against the key built into Mooring before anything is written.</span>
        </div>
      )}
    </div>
  );
}

/** The in-UI confirmation (not a native dialog): what restarts and which sessions close. */
function ConfirmInstall({ version, sessions, onClose, onConfirm }: { version: string; sessions: number; onClose: () => void; onConfirm: () => void }) {
  return (
    <Modal title={`Install ${version} and restart?`} onClose={onClose}>
      <div className="flex flex-col gap-3">
        <p className="m-0">
          Mooring downloads the update, verifies its signature, replaces itself and restarts.
          {sessions > 0
            ? ` ${String(sessions)} open session${sessions === 1 ? "" : "s"} will be closed first; unsaved work in them is lost. Port forwards and web windows end with the restart.`
            : " No sessions are open."}
        </p>
        <div className="flex justify-end gap-2">
          <button type="button" className="btn btn-ghost" onClick={onClose}>Cancel</button>
          <button type="button" className="btn btn-primary" onClick={onConfirm}>{sessions > 0 ? "Close sessions, install and restart" : "Install and restart"}</button>
        </div>
      </div>
    </Modal>
  );
}

/** Settings → Updates (ADR-0018 §3): the running version, a manual check, the offer, the background toggle. */
export function UpdatesCard() {
  const appInfo = useApp((s) => s.info);
  const info = useUpdate((s) => s.info);
  const settings = useUpdate((s) => s.settings);
  const unconfigured = useUpdate((s) => s.unconfigured);
  const checking = useUpdate((s) => s.checking);
  const installing = useUpdate((s) => s.installing);
  const error = useUpdate((s) => s.error);
  const notice = useUpdate((s) => s.notice);
  const sessions = useSessions((s) => s.tabs.filter((t) => t.state !== "closed").length);
  const [confirming, setConfirming] = useState(false);

  useEffect(() => {
    const u = useUpdate.getState();
    u.seen();
    void u.load();
  }, []);

  const current = info?.current ?? appInfo?.version ?? "unknown";
  const portableDir = appInfo?.portableDataDir ?? null;
  const busy = checking || installing;
  const offer = info?.available ?? null;

  return (
    <SettingsCard title="Updates" kicker="Application" labelledBy="updates-title">
      <div className="settings-body" aria-busy={busy || undefined}>
        <div className="update-head">
          <div className="min-w-0">
            <span className="field-label">Installed version</span>
            <p className="update-current tnum" data-testid="update-current">{current}</p>
            <p className="field-hint">Last checked: {fmtStamp(settings?.lastCheck ?? null)}</p>
            {settings?.lastVerified && (
              <p className="field-hint" data-testid="update-last-verified">
                Last verified update: <span className="tnum">{settings.lastVerified}</span>. Older versions are refused from now on.
              </p>
            )}
          </div>
          <button type="button" className="btn" disabled={busy || unconfigured} onClick={() => void useUpdate.getState().check()}>
            {checking ? "Checking…" : "Check for updates"}
          </button>
        </div>
        {portableDir !== null && <PortableLine path={portableDir} />}
        {unconfigured && (
          <p role="status" className="settings-warn">Updates are not configured in this build. There is no update key, so Mooring never checks for or installs anything; install new versions the way this one was installed.</p>
        )}
        {error && <p role="alert" className="settings-err">{error}</p>}
        {notice && <p role="status" className="settings-ok">{notice}</p>}
        {info && offer && <Available info={info} busy={busy} onInstall={() => { setConfirming(true); }} />}
        {!unconfigured && (
          <div className="settings-toggles">
            <Toggle
              checked={portableDir === null && (settings?.backgroundCheck ?? false)}
              disabled={settings === null || portableDir !== null}
              onChange={(on) => void useUpdate.getState().setBackground(on)}
              label="Check for updates in the background (daily)"
              hint={portableDir !== null
                ? PORTABLE_UPDATE_TEXT
                : "One request a day to the release server carrying only the version and platform. It only shows a notice in the title bar; nothing is downloaded or installed until you ask."}
            />
          </div>
        )}
      </div>
      {confirming && offer && (
        <ConfirmInstall
          version={offer.version}
          sessions={sessions}
          onClose={() => { setConfirming(false); }}
          onConfirm={() => {
            setConfirming(false);
            void useUpdate.getState().install(offer.version, sessions > 0);
          }}
        />
      )}
    </SettingsCard>
  );
}
