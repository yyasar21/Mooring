import { Kbd, ProtocolPip } from "@nexus/ui";
import { useApp } from "../stores/app";

/** Centre pane: session tabs. Sessions themselves arrive in A1 (SSH) and A2 (RDP/VNC/web). */
export function Workspace() {
  const tabs = useApp((s) => s.tabs);
  const activeTab = useApp((s) => s.activeTab);
  const connections = useApp((s) => s.connections);
  const setActiveTab = useApp((s) => s.setActiveTab);
  const closeTab = useApp((s) => s.closeTab);
  const setPalette = useApp((s) => s.setPalette);

  const active = connections.find((c) => c.id === activeTab);

  return (
    <section className="flex h-full min-w-0 flex-col bg-bg">
      <div role="tablist" className="flex h-9 items-stretch border-b border-line bg-bg-sunken">
        {tabs.map((t) => {
          const c = connections.find((x) => x.id === t.connectionId);
          if (!c) return null;
          const isActive = t.connectionId === activeTab;
          return (
            <div
              key={t.connectionId}
              role="tab"
              aria-selected={isActive}
              tabIndex={0}
              onClick={() => { setActiveTab(t.connectionId); }}
              onKeyDown={(e) => {
                if (e.key === "Enter") setActiveTab(t.connectionId);
              }}
              className={`group flex max-w-56 items-center gap-2 border-r border-line px-3 ${
                isActive ? "bg-bg text-text" : "text-text-muted hover:text-text"
              }`}
              style={{ boxShadow: isActive ? "inset 0 2px 0 var(--accent)" : "none" }}
            >
              <ProtocolPip protocol={c.protocol} />
              <span className="truncate">{c.name}</span>
              <button
                type="button"
                aria-label={`Close ${c.name}`}
                onClick={(e) => {
                  e.stopPropagation();
                  closeTab(t.connectionId);
                }}
                className="ml-1 rounded px-1 text-text-faint opacity-0 hover:bg-surface-raised hover:text-text group-hover:opacity-100 focus-visible:opacity-100"
              >
                ×
              </button>
            </div>
          );
        })}
        <button
          type="button"
          onClick={() => { setPalette(true); }}
          aria-label="Open a connection"
          className="px-3 text-text-faint hover:text-text"
        >
          +
        </button>
      </div>

      <div className="flex min-h-0 flex-1 items-center justify-center">
        {active ? (
          <div className="text-center">
            <p className="text-text-muted">Session view for</p>
            <p className="mt-1 text-[length:var(--fs-l)] font-medium">{active.name}</p>
            <p className="mono mt-1 text-text-muted">{active.host}</p>
            <p className="mt-6 max-w-xs text-[length:var(--fs-s)] text-text-faint">
              {active.protocol.toUpperCase()} sessions land in the next phase. The tab, the audit entry and the
              credential lookup are already wired to this view.
            </p>
          </div>
        ) : (
          <div className="text-center">
            <p className="text-[length:var(--fs-l)] font-medium">Nothing open yet</p>
            <p className="mt-2 text-text-muted">
              Press <Kbd>mod K</Kbd> and type a host, a name or a tag.
            </p>
          </div>
        )}
      </div>
    </section>
  );
}
