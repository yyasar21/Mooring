import { useId } from "react";

/**
 * The Mooring mark as an inline glyph: a bollard with the line made fast around its neck.
 * Same geometry as `packaging/icon.svg`, reduced to two inks — the post in `currentColor`,
 * the loop and the line in the accent — so it sits in the title bar, the airlock and the
 * About card without loading an image and on any surface (the gap where the loop crosses
 * the post is a mask, not a painted stroke). Decorative by default (`aria-hidden`); pass
 * `title` when the mark stands alone.
 */
export function BrandMark({ size = 18, title }: { size?: number; title?: string }) {
  const gap = useId();
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 1024 1024"
      fill="none"
      aria-hidden={title ? undefined : true}
      role={title ? "img" : undefined}
      className="brand-mark"
    >
      {title && <title>{title}</title>}
      <defs>
        <mask id={gap}>
          <rect width="1024" height="1024" fill="#fff" />
          <path d="M322 560 A190 66 0 0 0 702 560" stroke="#000" strokeWidth="170" strokeLinecap="round" />
        </mask>
      </defs>
      <g stroke="var(--accent)" strokeWidth="84" strokeLinecap="round">
        <path d="M330 566 C 262 600, 200 700, 130 830" />
        <path d="M322 560 A190 66 0 0 1 702 560" />
      </g>
      <g fill="currentColor" mask={`url(#${gap})`}>
        <path d="M296 356 v-52 a216 112 0 0 1 432 0 v52 a24 24 0 0 1 -24 24 h-384 a24 24 0 0 1 -24 -24 z" />
        <path d="M432 370 h160 l8 300 c2 30 18 40 44 44 h8 a22 22 0 0 1 22 22 v22 a22 22 0 0 1 -22 22 h-280 a22 22 0 0 1 -22 -22 v-22 a22 22 0 0 1 22 -22 h8 c26 -4 42 -14 44 -44 z" />
      </g>
      <path d="M322 560 A190 66 0 0 0 702 560" stroke="var(--accent)" strokeWidth="84" strokeLinecap="round" />
    </svg>
  );
}
