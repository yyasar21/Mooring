// Shared chrome for the Harbor mockups: title bar, navigation rail, connection tree, status bar.
// A page sets <body data-view data-selected data-live data-inspector data-tree> and provides
// <template id="center"> (and optionally id="inspector" / id="overlay"). ?theme=dark and
// ?variant=teal switch the token set. Static design artefact: no app code, no network.
const q = new URLSearchParams(location.search);
document.documentElement.dataset.theme = q.get("theme") === "dark" ? "dark" : "light";
if (q.get("variant")) document.documentElement.dataset.variant = q.get("variant");

const P = {
  ssh: '<rect x="1.75" y="2.75" width="12.5" height="10.5" rx="1.5"/><path d="M4.5 6.5l2 1.75-2 1.75M8 10.25h3.5"/>',
  rdp: '<rect x="1.75" y="2.25" width="12.5" height="8.5" rx="1.25"/><path d="M5.5 13.75h5M8 10.75v3"/>',
  vnc: '<rect x="1.75" y="2.25" width="12.5" height="8.5" rx="1.25"/><path d="M5.5 13.75h5M8 10.75v3"/><circle cx="8" cy="6.5" r="1.5"/>',
  web: '<circle cx="8" cy="8" r="6.25"/><path d="M1.75 8h12.5M8 1.75c1.9 2 1.9 10.5 0 12.5M8 1.75c-1.9 2-1.9 10.5 0 12.5"/>',
  kubernetes: '<path d="M8 1.75l5.5 3.1v6.3L8 14.25l-5.5-3.1v-6.3z"/><circle cx="8" cy="8" r="2"/>',
  vsphere: '<rect x="2" y="2.25" width="12" height="4.5" rx="1"/><rect x="2" y="9.25" width="12" height="4.5" rx="1"/><path d="M4.5 4.5h1M4.5 11.5h1"/>',
  folder: '<path d="M1.75 4.25a1 1 0 0 1 1-1h3.4l1.4 1.5h5.7a1 1 0 0 1 1 1v6.5a1 1 0 0 1-1 1H2.75a1 1 0 0 1-1-1z"/>',
  down: '<path d="M4.5 6.25L8 9.75l3.5-3.5"/>', right: '<path d="M6.25 4.5L9.75 8l-3.5 3.5"/>',
  plus: '<path d="M8 3v10M3 8h10"/>', search: '<circle cx="7" cy="7" r="4.25"/><path d="M10.25 10.25L13.5 13.5"/>',
  lock: '<rect x="3" y="7" width="10" height="7" rx="1.25"/><path d="M5.25 7V5a2.75 2.75 0 0 1 5.5 0v2"/>',
  key: '<circle cx="5.25" cy="10.75" r="3"/><path d="M7.4 8.6L13.5 2.5M11 5l1.75 1.75"/>',
  list: '<path d="M5.5 4h8M5.5 8h8M5.5 12h8"/><circle cx="2.75" cy="4" r=".6"/><circle cx="2.75" cy="8" r=".6"/><circle cx="2.75" cy="12" r=".6"/>',
  gear: '<circle cx="8" cy="8" r="2.25"/><path d="M8 1.75v1.7M8 12.55v1.7M14.25 8h-1.7M3.45 8h-1.7M12.4 3.6l-1.2 1.2M4.8 11.2l-1.2 1.2M12.4 12.4l-1.2-1.2M4.8 4.8L3.6 3.6"/>',
  hosts: '<rect x="1.75" y="2" width="5.5" height="5" rx="1"/><rect x="8.75" y="2" width="5.5" height="5" rx="1"/><rect x="1.75" y="9" width="5.5" height="5" rx="1"/><rect x="8.75" y="9" width="5.5" height="5" rx="1"/>',
  check: '<path d="M3.25 8.5l3 3 6.5-7"/>', x: '<path d="M4 4l8 8M12 4l-8 8"/>',
  more: '<circle cx="3.5" cy="8" r=".9"/><circle cx="8" cy="8" r=".9"/><circle cx="12.5" cy="8" r=".9"/>',
  copy: '<rect x="5.25" y="5.25" width="8.5" height="8.5" rx="1.25"/><path d="M10.75 5.25V3.5a1.25 1.25 0 0 0-1.25-1.25h-6a1.25 1.25 0 0 0-1.25 1.25v6A1.25 1.25 0 0 0 3.5 10.75h1.75"/>',
  ext: '<path d="M9.5 2.25h4.25V6.5M13.5 2.5L7.5 8.5M11.75 9.5v3a1.25 1.25 0 0 1-1.25 1.25h-7A1.25 1.25 0 0 1 2.25 12.5v-7A1.25 1.25 0 0 1 3.5 4.25h3"/>',
  info: '<circle cx="8" cy="8" r="6.25"/><path d="M8 7.25v4M8 4.75v.5"/>',
  alert: '<path d="M8 2l6.25 11H1.75z"/><path d="M8 6.5v3M8 11.25v.5"/>',
  shield: '<path d="M8 1.75l5.25 2v4c0 3.2-2.3 5.4-5.25 6.5C5.05 13.15 2.75 10.95 2.75 7.75v-4z"/><path d="M5.75 8l1.6 1.6 3-3.1"/>',
  user: '<circle cx="8" cy="5.5" r="2.75"/><path d="M2.75 14c.6-2.8 2.7-4.25 5.25-4.25S12.65 11.2 13.25 14"/>',
  filter: '<path d="M2 3.25h12l-4.75 5.5v4.5l-2.5 1v-5.5z"/>', refresh: '<path d="M13.25 4.5v3h-3M2.75 11.5v-3h3"/><path d="M12.9 7.5A5 5 0 0 0 3.6 5.25M3.1 8.5a5 5 0 0 0 9.3 2.25"/>',
  sync: '<path d="M2.75 8a5.25 5.25 0 0 1 9.4-3.2M13.25 8a5.25 5.25 0 0 1-9.4 3.2"/><path d="M12.5 2.25v2.75H9.75M3.5 13.75V11h2.75"/>',
  help: '<circle cx="8" cy="8" r="6.25"/><path d="M6.25 6.25a1.75 1.75 0 1 1 2.5 1.6c-.5.25-.75.6-.75 1.15v.25M8 11.25v.5"/>',
  sun: '<circle cx="8" cy="8" r="3"/><path d="M8 1.5v1.5M8 13v1.5M1.5 8H3M13 8h1.5M3.4 3.4l1.05 1.05M11.55 11.55l1.05 1.05M3.4 12.6l1.05-1.05M11.55 4.45l1.05-1.05"/>',
  play: '<path d="M5 3.25l7.5 4.75L5 12.75z"/>', split: '<rect x="1.75" y="2.75" width="12.5" height="10.5" rx="1.25"/><path d="M8 2.75v10.5"/>',
  upload: '<path d="M8 10.5V2.75M4.75 6L8 2.75 11.25 6M2.75 10.75v1.5a1 1 0 0 0 1 1h8.5a1 1 0 0 0 1-1v-1.5"/>',
};
function icon(name, size = 16, extra = "") {
  return `<svg width="${size}" height="${size}" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" ${extra}>${P[name] ?? ""}</svg>`;
}
window.icon = icon;

const TREE = [
  { f: "Production", d: 0, n: 4, open: true },
  { f: "Web tier", d: 1, n: 3, open: true },
  { c: "edge-lb", p: "web", d: 2 }, { c: "web01", p: "ssh", d: 2 }, { c: "web02", p: "ssh", d: 2 },
  { f: "Databases", d: 1, n: 1, open: true },
  { c: "pg-primary", p: "ssh", d: 2 },
  { f: "Staging", d: 0, n: 4, open: true },
  { c: "ask-me", p: "ssh", d: 1 }, { c: "stage-app", p: "ssh", d: 1 }, { c: "stage-cluster", p: "kubernetes", d: 1 }, { c: "stage-vcenter", p: "vsphere", d: 1 },
  { f: "Desktops", d: 0, n: 2, open: true },
  { c: "dc01", p: "rdp", d: 1 }, { c: "lobby-kiosk", p: "vnc", d: 1 },
];

function tree(selected, live) {
  return TREE.map((r) => {
    const pad = `style="padding-left:${4 + r.d * 16}px"`;
    if (r.f) return `<div class="trow folder" role="treeitem" ${pad}><span class="chev">${icon(r.open ? "down" : "right", 14)}</span><span class="ico">${icon("folder")}</span><span class="name">${r.f}</span><span class="meta">${r.n}</span></div>`;
    const state = live[r.c];
    const dot = state ? `<span class="dot ${state}"></span>` : "";
    return `<div class="trow" role="treeitem" aria-selected="${r.c === selected}" ${pad}><span class="chev"></span><span class="ico">${icon(r.p)}${dot}</span><span class="name">${r.c}</span></div>`;
  }).join("");
}

const NAV = [["connections", "hosts", "Hosts"], ["credentials", "key", "Credentials"], ["audit", "list", "Audit"]];

function build() {
  const b = document.body.dataset;
  const view = b.view ?? "connections";
  const live = Object.fromEntries((b.live ?? "").split(",").filter(Boolean).map((x) => x.split(":")));
  const t = (id) => document.getElementById(id)?.innerHTML ?? "";
  const withTree = view === "connections";
  const insp = withTree && b.inspector !== "0";
  const sessions = Object.keys(live).filter((k) => live[k] === "ok").length;
  const teal = document.documentElement.dataset.variant === "teal";
  const mark = teal
    ? `<svg width="20" height="20" viewBox="0 0 20 20" aria-hidden="true"><rect width="20" height="20" rx="5" fill="var(--accent)"/><path d="M6 6.5h8M7.5 6.5v7h5v-7M10 13.5v2" stroke="#fff" stroke-width="1.6" fill="none" stroke-linecap="round"/></svg>`
    : `<svg width="20" height="20" viewBox="0 0 20 20" aria-hidden="true"><rect width="20" height="20" rx="5" fill="var(--text)"/><path d="M6 6.5h8M7.5 6.5v7h5v-7M10 13.5v2" stroke="var(--surface)" stroke-width="1.6" fill="none" stroke-linecap="round"/></svg>`;
  document.body.innerHTML = `
  <div class="app">
    <header class="titlebar">
      <div class="brand">${mark}<span>Mooring</span><span class="vault">Personal vault ${icon("down", 12)}</span></div>
      <div class="search">${icon("search", 14)}<span class="grow">Search hosts, credentials and commands</span><span class="kbd">Ctrl K</span></div>
      <div class="title-actions">
        <span class="pill success nodot">${icon("sync", 12)} Synced</span>
        <button class="icon-btn" aria-label="Help">${icon("help")}</button>
        <button class="btn sm">${icon("lock", 14)} Lock</button>
      </div>
    </header>
    <div class="body ${withTree ? (insp ? "" : "") : "no-inspector"}" style="${withTree && !insp ? "grid-template-columns:var(--rail-w) 264px minmax(0,1fr)" : ""}">
      <nav class="rail" aria-label="Views">
        ${NAV.map(([id, ic, label]) => `<a href="#" ${view === id ? 'aria-current="page"' : ""}>${icon(ic, 20)}<span>${label}</span></a>`).join("")}
        <span class="spacer"></span>
        <a href="#" ${view === "settings" ? 'aria-current="page"' : ""}>${icon("gear", 20)}<span>Settings</span></a>
      </nav>
      ${withTree ? `<aside class="pane sidebar" aria-label="Connections">
        <div class="pane-head"><h2>Connections</h2>
          <button class="icon-btn sm" aria-label="New folder">${icon("folder", 15)}</button>
          <button class="btn sm primary" aria-label="New connection">${icon("plus", 14)} New</button></div>
        <div class="filter"><div class="input ph">${icon("filter", 14)} Filter by name, host or tag</div></div>
        <div class="tree" role="tree">${tree(b.selected, live)}</div>
      </aside>` : ""}
      <main class="pane" style="min-width:0">${t("center")}</main>
      ${insp ? `<aside class="pane inspector" aria-label="Details">${t("inspector")}</aside>` : ""}
    </div>
    <footer class="statusbar">
      <span class="item"><span class="dot ok"></span>Vault unlocked</span>
      <span class="item">${sessions} ${sessions === 1 ? "session" : "sessions"} open</span>
      <span class="item">${icon("shield", 13)} Audit chain verified</span>
      <span class="grow"></span>
      <span class="item">Auto-lock in 14 min</span>
      <span class="item">Mooring 0.2.0</span>
    </footer>
  </div>${t("overlay")}`;
  // <i data-i="name" data-s="14"></i> in page templates becomes an inline icon.
  for (const el of document.querySelectorAll("i[data-i]")) el.outerHTML = icon(el.dataset.i, Number(el.dataset.s ?? 16));
}
const standalone = document.currentScript?.hasAttribute("data-standalone");
if (standalone) { for (const el of document.querySelectorAll("i[data-i]")) el.outerHTML = icon(el.dataset.i, Number(el.dataset.s ?? 16)); } else build();
