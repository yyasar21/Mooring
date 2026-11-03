import { useRef } from "react";

/**
 * Vertical splitter. Drag with the mouse or focus it and use ←/→ (shift = 40 px steps).
 * `sign` is +1 when dragging right grows the pane (sidebar), −1 when it shrinks it (inspector).
 */
export function PaneHandle({
  label,
  value,
  min,
  max,
  sign,
  onChange,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  sign: 1 | -1;
  onChange: (v: number) => void;
}) {
  const start = useRef<{ x: number; v: number } | null>(null);
  return (
    <div
      role="separator"
      aria-orientation="vertical"
      aria-label={label}
      aria-valuenow={value}
      aria-valuemin={min}
      aria-valuemax={max}
      tabIndex={0}
      className="pane-handle"
      onPointerDown={(e) => {
        e.currentTarget.setPointerCapture(e.pointerId);
        start.current = { x: e.clientX, v: value };
      }}
      onPointerMove={(e) => {
        if (start.current) onChange(start.current.v + sign * (e.clientX - start.current.x));
      }}
      onPointerUp={() => { start.current = null; }}
      onKeyDown={(e) => {
        const step = e.shiftKey ? 40 : 10;
        if (e.key === "ArrowLeft") onChange(value - sign * step);
        else if (e.key === "ArrowRight") onChange(value + sign * step);
        else return;
        e.preventDefault();
      }}
    />
  );
}
