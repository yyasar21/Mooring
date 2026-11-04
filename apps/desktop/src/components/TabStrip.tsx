import { useRef, useState } from "react";
import { MooringLine, ProtocolPip } from "@mooring/ui";
import { lineState, useSessions, type Tab } from "../stores/sessions";
import { useTree } from "../stores/tree";
import { useUi } from "../stores/ui";

/**
 * Session tabs. Arrow keys move focus, Enter/Space activates, Alt+Shift+Arrow reorders,
 * Delete closes. Mouse: click, middle-click closes, drag to reorder.
 */
export function TabStrip() {
  const tabs = useSessions((s) => s.tabs);
  const activeTab = useSessions((s) => s.activeTab);
  const setPalette = useUi((s) => s.setPalette);
  const listRef = useRef<HTMLDivElement>(null);
  const [dragId, setDragId] = useState<string | null>(null);

  const focusTab = (i: number) => {
    const el = listRef.current?.querySelectorAll<HTMLElement>('[role="tab"]')[i];
    el?.focus();
  };

  return (
    <div className="tabstrip">
      <div ref={listRef} role="tablist" aria-label="Open sessions" className="flex min-w-0 items-stretch overflow-x-auto">
        {tabs.map((t, i) => (
          <TabItem
            key={t.id}
            tab={t}
            index={i}
            active={t.id === activeTab}
            focusable={t.id === activeTab || (activeTab === null && i === 0)}
            onFocusIndex={focusTab}
            count={tabs.length}
            dragging={dragId === t.id}
            onDragStart={() => { setDragId(t.id); }}
            onDragEnd={() => { setDragId(null); }}
            onDropAt={(toIndex) => {
              if (dragId) useSessions.getState().move(dragId, toIndex);
              setDragId(null);
            }}
          />
        ))}
      </div>
      <button
        type="button"
        onClick={() => { setPalette(true); }}
        aria-label="Open a connection"
        title="Open a connection"
        className="icon-btn my-auto ml-1 flex-none"
      >
        <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden>
          <path d="M6 1v10M1 6h10" stroke="currentColor" strokeWidth="1.4" />
        </svg>
      </button>
    </div>
  );
}

interface TabItemProps {
  tab: Tab;
  index: number;
  count: number;
  active: boolean;
  focusable: boolean;
  dragging: boolean;
  onFocusIndex: (i: number) => void;
  onDragStart: () => void;
  onDragEnd: () => void;
  onDropAt: (i: number) => void;
}

function TabItem({ tab, index, count, active, focusable, dragging, onFocusIndex, onDragStart, onDragEnd, onDropAt }: TabItemProps) {
  const c = useTree((s) => s.connections.find((x) => x.id === tab.connectionId));
  const { activate, close, move, detach } = useSessions.getState();
  const name = c?.name ?? "unknown";
  const stateLabel = tab.prompt ? "waiting for you" : tab.state;

  return (
    <div
      role="tab"
      id={`tab-${tab.id}`}
      aria-selected={active}
      aria-controls={`panel-${tab.id}`}
      aria-label={`${name}, ${stateLabel}`}
      tabIndex={focusable ? 0 : -1}
      draggable
      className="tab"
      style={{ opacity: dragging ? 0.5 : 1 }}
      onClick={() => { activate(tab.id); }}
      onAuxClick={(e) => {
        if (e.button === 1) void close(tab.id);
      }}
      onDragStart={(e) => {
        e.dataTransfer.effectAllowed = "move";
        onDragStart();
      }}
      onDragEnd={onDragEnd}
      onDragOver={(e) => { e.preventDefault(); }}
      onDrop={(e) => {
        e.preventDefault();
        onDropAt(index);
      }}
      onKeyDown={(e) => {
        if (e.target !== e.currentTarget) return;
        const dir = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
        if (dir !== 0 && e.altKey && e.shiftKey) {
          e.preventDefault();
          const to = Math.max(0, Math.min(count - 1, index + dir));
          move(tab.id, to);
          requestAnimationFrame(() => { onFocusIndex(to); });
        } else if (dir !== 0) {
          e.preventDefault();
          onFocusIndex((index + dir + count) % count);
        } else if (e.key === "Home" || e.key === "End") {
          e.preventDefault();
          onFocusIndex(e.key === "Home" ? 0 : count - 1);
        } else if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          activate(tab.id);
        } else if (e.key === "Delete") {
          e.preventDefault();
          void close(tab.id);
        }
      }}
    >
      {c && <ProtocolPip protocol={c.protocol} live={tab.state === "connected"} />}
      <span className="tab-name min-w-0 flex-1 truncate">{name}</span>
      {tab.prompt && <span aria-hidden className="tab-attn" />}
      <button
        type="button"
        className="tab-action icon-btn flex-none"
        aria-label={`Detach ${name} to a window`}
        title="Detach to a window"
        tabIndex={active ? 0 : -1}
        disabled={!tab.sessionId}
        onClick={(e) => {
          e.stopPropagation();
          void detach(tab.id);
        }}
      >
        <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden fill="none" stroke="currentColor" strokeWidth="1.2">
          <path d="M5 2H2v8h8V7M7 1.5h3.5V5M10.5 1.5 5.5 6.5" />
        </svg>
      </button>
      <button
        type="button"
        className="tab-action icon-btn flex-none"
        aria-label={`Close ${name}`}
        title="Close tab"
        tabIndex={active ? 0 : -1}
        onClick={(e) => {
          e.stopPropagation();
          void close(tab.id);
        }}
      >
        <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden>
          <path d="M2 2l6 6M8 2 2 8" stroke="currentColor" strokeWidth="1.3" />
        </svg>
      </button>
      <MooringLine state={lineState(tab.state)} />
    </div>
  );
}
