import type { ReactNode } from "react";

// Hand-drawn 16 px line icons (design review 2026-11 mockups, shell.js). Inline SVG, stroke in
// currentColor, no icon font and no dependency.
const PATHS = {
  ssh: <><rect x="1.75" y="2.75" width="12.5" height="10.5" rx="1.5" /><path d="M4.5 6.5l2 1.75-2 1.75M8 10.25h3.5" /></>,
  rdp: <><rect x="1.75" y="2.25" width="12.5" height="8.5" rx="1.25" /><path d="M5.5 13.75h5M8 10.75v3" /></>,
  vnc: <><rect x="1.75" y="2.25" width="12.5" height="8.5" rx="1.25" /><path d="M5.5 13.75h5M8 10.75v3" /><circle cx="8" cy="6.5" r="1.5" /></>,
  web: <><circle cx="8" cy="8" r="6.25" /><path d="M1.75 8h12.5M8 1.75c1.9 2 1.9 10.5 0 12.5M8 1.75c-1.9 2-1.9 10.5 0 12.5" /></>,
  kubernetes: <><path d="M8 1.75l5.5 3.1v6.3L8 14.25l-5.5-3.1v-6.3z" /><circle cx="8" cy="8" r="2" /></>,
  vsphere: <><rect x="2" y="2.25" width="12" height="4.5" rx="1" /><rect x="2" y="9.25" width="12" height="4.5" rx="1" /><path d="M4.5 4.5h1M4.5 11.5h1" /></>,
  folder: <path d="M1.75 4.25a1 1 0 0 1 1-1h3.4l1.4 1.5h5.7a1 1 0 0 1 1 1v6.5a1 1 0 0 1-1 1H2.75a1 1 0 0 1-1-1z" />,
  "folder-plus": <><path d="M1.75 4.25a1 1 0 0 1 1-1h3.4l1.4 1.5h5.7a1 1 0 0 1 1 1v6.5a1 1 0 0 1-1 1H2.75a1 1 0 0 1-1-1z" /><path d="M8 7.25v3.5M6.25 9h3.5" /></>,
  down: <path d="M4.5 6.25L8 9.75l3.5-3.5" />,
  right: <path d="M6.25 4.5L9.75 8l-3.5 3.5" />,
  plus: <path d="M8 3v10M3 8h10" />,
  search: <><circle cx="7" cy="7" r="4.25" /><path d="M10.25 10.25L13.5 13.5" /></>,
  lock: <><rect x="3" y="7" width="10" height="7" rx="1.25" /><path d="M5.25 7V5a2.75 2.75 0 0 1 5.5 0v2" /></>,
  key: <><circle cx="5.25" cy="10.75" r="3" /><path d="M7.4 8.6L13.5 2.5M11 5l1.75 1.75" /></>,
  list: <><path d="M5.5 4h8M5.5 8h8M5.5 12h8" /><circle cx="2.75" cy="4" r=".6" /><circle cx="2.75" cy="8" r=".6" /><circle cx="2.75" cy="12" r=".6" /></>,
  gear: <><circle cx="8" cy="8" r="2.25" /><path d="M8 1.75v1.7M8 12.55v1.7M14.25 8h-1.7M3.45 8h-1.7M12.4 3.6l-1.2 1.2M4.8 11.2l-1.2 1.2M12.4 12.4l-1.2-1.2M4.8 4.8L3.6 3.6" /></>,
  hosts: <><rect x="1.75" y="2" width="5.5" height="5" rx="1" /><rect x="8.75" y="2" width="5.5" height="5" rx="1" /><rect x="1.75" y="9" width="5.5" height="5" rx="1" /><rect x="8.75" y="9" width="5.5" height="5" rx="1" /></>,
  check: <path d="M3.25 8.5l3 3 6.5-7" />,
  x: <path d="M4 4l8 8M12 4l-8 8" />,
  info: <><circle cx="8" cy="8" r="6.25" /><path d="M8 7.25v4M8 4.75v.5" /></>,
  alert: <><path d="M8 2l6.25 11H1.75z" /><path d="M8 6.5v3M8 11.25v.5" /></>,
  shield: <><path d="M8 1.75l5.25 2v4c0 3.2-2.3 5.4-5.25 6.5C5.05 13.15 2.75 10.95 2.75 7.75v-4z" /><path d="M5.75 8l1.6 1.6 3-3.1" /></>,
  filter: <path d="M2 3.25h12l-4.75 5.5v4.5l-2.5 1v-5.5z" />,
  sync: <><path d="M2.75 8a5.25 5.25 0 0 1 9.4-3.2M13.25 8a5.25 5.25 0 0 1-9.4 3.2" /><path d="M12.5 2.25v2.75H9.75M3.5 13.75V11h2.75" /></>,
  help: <><circle cx="8" cy="8" r="6.25" /><path d="M6.25 6.25a1.75 1.75 0 1 1 2.5 1.6c-.5.25-.75.6-.75 1.15v.25M8 11.25v.5" /></>,
  upload: <path d="M8 10.5V2.75M4.75 6L8 2.75 11.25 6M2.75 10.75v1.5a1 1 0 0 0 1 1h8.5a1 1 0 0 0 1-1v-1.5" />,
  "check-circle": <><circle cx="8" cy="8" r="6.25" /><path d="M5.25 8.25l1.9 1.9 3.6-3.9" /></>,
  "x-circle": <><circle cx="8" cy="8" r="6.25" /><path d="M5.75 5.75l4.5 4.5M10.25 5.75l-4.5 4.5" /></>,
  external: <><path d="M9.25 2.75h4v4M13.25 2.75L7.5 8.5" /><path d="M11.75 9.5v3a1 1 0 0 1-1 1h-7a1 1 0 0 1-1-1v-7a1 1 0 0 1 1-1h3" /></>,
  forward: <><path d="M2.75 5h8.5M8.75 2.5L11.25 5l-2.5 2.5" /><path d="M13.25 11H4.75M7.25 8.5L4.75 11l2.5 2.5" /></>,
  file: <><path d="M4 1.75h5l3 3v9.5H4z" /><path d="M9 1.75v3h3" /></>,
  certificate: <><rect x="1.75" y="2.25" width="12.5" height="8.5" rx="1" /><path d="M4.25 5h7.5M4.25 7.25h4" /><circle cx="11" cy="11.5" r="1.75" /><path d="M10 13v1.75l1-.6 1 .6V13" /></>,
  download: <path d="M8 2.75v7.75M4.75 7.25L8 10.5l3.25-3.25M2.75 10.75v1.5a1 1 0 0 0 1 1h8.5a1 1 0 0 0 1-1v-1.5" />,
} satisfies Record<string, ReactNode>;

export type IconName = keyof typeof PATHS;

/** A decorative line icon (`aria-hidden`); the control that holds it carries the name. */
export function Icon({ name, size = 16 }: { name: IconName; size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.3"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
      focusable="false"
    >
      {PATHS[name]}
    </svg>
  );
}
