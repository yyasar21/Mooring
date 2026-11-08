import { useEffect, useState } from "react";
import type { ConnectionSummary } from "../../lib/ipc";
import { useApp } from "../../stores/app";
import { useSessions, type Tab } from "../../stores/sessions";
import { useUi } from "../../stores/ui";
import { dismissNotice, useWebTabs, webAction, webZoomStep, type WebAction, type WebNotice } from "../../stores/web";
import { Modal } from "../dialogs/Modal";
import { SessionHeader } from "../SessionHeader";
import { WebOpenError, WebOpening, WebViaChip } from "./WebVia";

const NOTICE_TEXT: Record<WebNotice["kind"], { title: string; hint: string }> = {
  blocked: {
    title: "Blocked navigation",
    hint: "Only the start origin and the connection's allowed origins may load. Add this origin to the connection to permit it (an SSO page, for example).",
  },
  download_blocked: { title: "Download blocked", hint: "Mooring web windows never save files to this computer." },
};

/**
 * A web connection's tab (ADR-0013). The page runs in its own `web-<connectionId>` window with no
 * IPC bridge; this card only controls that window and shows what Rust reports about it. Page
 * title and origins are untrusted text (sanitised in the store, rendered as text).
 */
export function WebSessionTab({ tab, connection }: { tab: Tab; connection: ConnectionSummary | undefined }) {
  const web = useWebTabs((s) => s.byTab[tab.id]);
  const locked = useApp((s) => s.vault !== "unlocked");
  const reconnect = useSessions((s) => s.reconnect);
  const closeTab = useSessions((s) => s.close);
  const openDialog = useUi((s) => s.openDialog);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [confirm, setConfirm] = useState(false);

  useEffect(() => {
    if (note === null) return;
    const t = window.setTimeout(() => { setNote(null); }, 3000);
    return () => { window.clearTimeout(t); };
  }, [note]);

  const open = tab.state === "connected";
  const name = connection?.name ?? "web console";
  const zoom = web?.zoom ?? 1;
  const run = (a: WebAction, done?: string) => {
    void webAction(tab.id, a).then((e) => {
      setError(e);
      if (!e && done) setNote(done);
    });
  };
  const zoomBy = (dir: -1 | 0 | 1) => {
    void webZoomStep(tab.id, dir).then(setError);
  };

  return (
    <div className="session-frame">
      <SessionHeader tab={tab} connection={connection}>
      <div role="toolbar" aria-label="Web window controls" className="remote-toolbar">
        {web?.persistent ? (
          <span className="chip" data-tone="warning" title="Cookies and site storage of this connection are kept on disk, in plaintext, until you clear them">
            Persistent storage
          </span>
        ) : (
          <span className="chip" title="Nothing reaches disk; closing the window forgets the sign-in">
            Ephemeral
          </span>
        )}
        {open && web?.viaHops ? <WebViaChip connection={connection} hops={web.viaHops} /> : null}
        <span className="spacer" />
        {note && (
          <span role="status" className="remote-note">
            {note}
          </span>
        )}
        <button type="button" className="btn btn-ghost" disabled={!open || locked} onClick={() => { run("focus"); }}>
          Focus
        </button>
        <button type="button" className="btn btn-ghost" disabled={!open} onClick={() => { run("reload", "Reloading"); }}>
          Reload
        </button>
        <button type="button" className="btn btn-ghost" disabled={!open || locked} onClick={() => { run("print"); }}>
          Print
        </button>
        <span className="web-zoom" role="group" aria-label="Zoom">
          <button type="button" className="btn btn-ghost" aria-label="Zoom out" disabled={!open || zoom <= 0.25} onClick={() => { zoomBy(-1); }}>
            −
          </button>
          <button type="button" className="btn btn-ghost" aria-label="Reset zoom" title="Reset zoom" disabled={!open} onClick={() => { zoomBy(0); }}>
            {Math.round(zoom * 100)}%
          </button>
          <button type="button" className="btn btn-ghost" aria-label="Zoom in" disabled={!open || zoom >= 5} onClick={() => { zoomBy(1); }}>
            +
          </button>
        </span>
        <button type="button" className="btn btn-ghost" onClick={() => { setConfirm(true); }}>
          Clear site data…
        </button>
        <button type="button" className="btn btn-ghost" disabled={!open} onClick={() => { run("close"); }}>
          Close window
        </button>
      </div>
      </SessionHeader>
      <div className="session-body">
        <div className="web-card m-hud" data-active={open ? true : undefined}>
          <p className="m-micro">{open ? "Open in its own window" : tab.state === "connecting" ? "Opening window" : "Window closed"}</p>
          <p className="m-display web-title" data-testid="web-title">{web?.title || name}</p>
          <p className="readout-host select-text" data-testid="web-origin">{web?.origin || connection?.host || ""}</p>
          {tab.state === "connecting" && web?.viaHops ? <WebOpening hops={web.viaHops} /> : null}
          <p className="web-note">
            The page runs in a separate window with no access to Mooring. Nothing is filled in for you: copy the
            credential from the inspector when the page asks for it.
          </p>
          {error && (
            <p role="alert" className="web-error">
              {error}
            </p>
          )}
          {tab.state === "closed" && <WebOpenError code={tab.openError} />}
          {tab.state === "connecting" && web?.viaHops ? (
            <div className="actions">
              <button type="button" className="btn btn-ghost" onClick={() => void closeTab(tab.id)}>
                Close tab
              </button>
            </div>
          ) : null}
          {tab.state === "closed" && (
            <div className="actions">
              {tab.reason && <span className="text-text-muted">{tab.reason}</span>}
              <button type="button" className="btn btn-ghost" onClick={() => void closeTab(tab.id)}>
                Close tab
              </button>
              <button type="button" className="btn" onClick={() => void reconnect(tab.id)}>
                Reopen window
              </button>
            </div>
          )}
          {web && web.notices.length > 0 && (
            <ul className="web-notices" aria-label="Refused by the window">
              {web.notices.map((n) => (
                <li key={n.id} data-kind={n.kind}>
                  <span className="m-micro" style={{ color: "var(--danger)" }}>{NOTICE_TEXT[n.kind].title}</span>
                  <span className="web-notice-origin select-text">{n.origin}</span>
                  <span className="text-[length:var(--fs-12)] text-text-muted">{NOTICE_TEXT[n.kind].hint}</span>
                  <span className="actions">
                    {n.kind === "blocked" && connection && (
                      <button type="button" className="btn btn-ghost" onClick={() => { openDialog({ kind: "connection", id: connection.id, folderId: connection.folderId }); }}>
                        Edit connection
                      </button>
                    )}
                    <button type="button" className="btn btn-ghost" aria-label={`Dismiss ${NOTICE_TEXT[n.kind].title.toLowerCase()}`} onClick={() => { dismissNotice(tab.id, n.id); }}>
                      Dismiss
                    </button>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
      {confirm && (
        <Modal title="Clear site data" onClose={() => { setConfirm(false); }}>
          <div className="flex flex-col gap-3 px-4 py-4 text-[length:var(--fs-13)]">
            <p>
              Remove every cookie and all site storage of <strong>{name}</strong>? You will be signed out of the page.
            </p>
            <p className="text-text-muted">The window stays open. The clear is written to the audit log.</p>
          </div>
          <div className="flex justify-end gap-2 border-t border-line px-4 py-3">
            <button type="button" className="btn btn-ghost" onClick={() => { setConfirm(false); }}>
              Cancel
            </button>
            <button
              type="button"
              className="btn btn-danger"
              onClick={() => {
                setConfirm(false);
                run("clear_data", "Site data cleared");
              }}
            >
              Clear site data
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
}
