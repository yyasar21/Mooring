import { useEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { Icon } from "./Icon";

export type SortDir = "ascending" | "descending";
export interface SortState {
  column: string;
  dir: SortDir;
}

export interface DataColumn<T> {
  id: string;
  /** Visible header text; it is also the column header's accessible name. */
  header: string;
  cell: (row: T) => ReactNode;
  /** When set, the header is a sort button and `aria-sort` tells the current order. */
  sortValue?: (row: T) => string | number;
  /** Right-aligned, tabular numbers. */
  numeric?: boolean;
  /** CSS width of the column (`<col>`); columns without one share the rest. */
  width?: string;
  /** The header text is for screen readers only (an actions column). */
  hideHeader?: boolean;
  className?: string;
}

export interface DataTableProps<T> {
  /** Accessible name of the grid or table. */
  label: string;
  columns: DataColumn<T>[];
  rows: readonly T[];
  rowKey: (row: T) => string;
  /** Accessible name of a row. Without it the name comes from the cells, as before. */
  rowLabel?: (row: T) => string;
  /** Extra attributes for a row (`data-*`, a title). */
  rowAttrs?: (row: T) => Record<string, string | boolean | undefined>;
  /** The selected row. With `onSelect` the table is a `grid` with keyboard row selection. */
  selected?: string | null;
  onSelect?: (key: string, row: T) => void;
  /** Enter or a double click on a row. */
  onActivate?: (row: T) => void;
  /** Focusing a row (Tab into the grid) selects it, as a listbox does. */
  selectOnFocus?: boolean;
  /** Keys the caller handles (F2, Delete, Backspace…). Return true when handled. */
  onKeyDown?: (e: KeyboardEvent, row: T | undefined) => boolean;
  defaultSort?: SortState | null;
  onSortChange?: (s: SortState) => void;
  /** Shown as one full-width row when there are no rows. */
  empty?: ReactNode;
  /** After the last row, inside the scroll area (a "Load more" button). */
  footer?: ReactNode;
  busy?: boolean;
  className?: string;
}

/** Sort rows by a column's `sortValue`: numbers numerically, strings with the locale's collation. */
export function sortRows<T>(rows: readonly T[], columns: DataColumn<T>[], sort: SortState | null): T[] {
  const col = sort ? columns.find((c) => c.id === sort.column) : undefined;
  if (!sort || !col?.sortValue) return [...rows];
  const val = col.sortValue;
  const sign = sort.dir === "ascending" ? 1 : -1;
  return [...rows].sort((a, b) => {
    const x = val(a);
    const y = val(b);
    const c = typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y), undefined, { numeric: true, sensitivity: "base" });
    return c * sign;
  });
}

const PAGE = 10;

/**
 * The data table of the design review (§4.3, M5): a sticky header, sortable columns with
 * `aria-sort`, 36 px rows, tabular numbers and keyboard row selection. Selectable tables are a
 * `grid` with a roving tab stop on the rows (↑ ↓ Home End PageUp PageDown move and select, Enter
 * activates); read-only ones are a plain `table`. Rows keep the names the old lists gave them.
 */
export function DataTable<T>(props: DataTableProps<T>) {
  const { label, columns, rows, rowKey, rowLabel, rowAttrs, selected = null, onSelect, onActivate, selectOnFocus, onKeyDown, empty, footer, busy, className } = props;
  const [sort, setSort] = useState<SortState | null>(props.defaultSort ?? null);
  const [focusKey, setFocusKey] = useState<string | null>(null);
  const bodyRef = useRef<HTMLTableSectionElement>(null);
  const grid = onSelect !== undefined;
  const shown = useMemo(() => sortRows(rows, columns, sort), [rows, columns, sort]);
  const keys = shown.map(rowKey);
  const stop = selected !== null && keys.includes(selected) ? selected : focusKey !== null && keys.includes(focusKey) ? focusKey : (keys[0] ?? null);

  useEffect(() => {
    if (selected === null) return;
    rowEl(bodyRef.current, selected)?.scrollIntoView({ block: "nearest" });
  }, [selected]);

  const toggleSort = (id: string) => {
    const next: SortState = sort?.column === id && sort.dir === "ascending" ? { column: id, dir: "descending" } : { column: id, dir: "ascending" };
    setSort(next);
    props.onSortChange?.(next);
  };

  const go = (to: number) => {
    const i = Math.max(0, Math.min(shown.length - 1, to));
    const row = shown[i];
    if (row === undefined) return;
    const key = rowKey(row);
    setFocusKey(key);
    onSelect?.(key, row);
    rowEl(bodyRef.current, key)?.focus();
  };

  const keyDown = (e: KeyboardEvent<HTMLTableElement>) => {
    const at = stop === null ? -1 : keys.indexOf(stop);
    const row = at >= 0 ? shown[at] : undefined;
    if (onKeyDown?.(e, row)) {
      e.preventDefault();
      return;
    }
    if (!grid) return;
    switch (e.key) {
      case "ArrowDown": go(at + 1); break;
      case "ArrowUp": go(at < 0 ? 0 : at - 1); break;
      case "Home": go(0); break;
      case "End": go(shown.length - 1); break;
      case "PageDown": go(at + PAGE); break;
      case "PageUp": go(at - PAGE); break;
      case "Enter":
        if (!row) return;
        if (onActivate) onActivate(row);
        else onSelect(rowKey(row), row);
        break;
      case " ":
        if (!row) return;
        onSelect(rowKey(row), row);
        break;
      default:
        return;
    }
    e.preventDefault();
  };

  return (
    <div className={`dt-wrap${className ? ` ${className}` : ""}`}>
      <table
        role={grid ? "grid" : "table"}
        aria-label={label}
        aria-busy={busy || undefined}
        className="dt"
        tabIndex={grid && shown.length === 0 ? 0 : undefined}
        onKeyDown={keyDown}
      >
        <colgroup>
          {columns.map((c) => <col key={c.id} style={c.width ? { width: c.width } : undefined} />)}
        </colgroup>
        <thead>
          <tr>
            {columns.map((c) => {
              const dir = sort?.column === c.id ? sort.dir : null;
              return (
                <th
                  key={c.id}
                  scope="col"
                  aria-sort={c.sortValue ? (dir ?? "none") : undefined}
                  data-numeric={c.numeric || undefined}
                >
                  {c.sortValue ? (
                    <button type="button" className="dt-sort" onClick={() => { toggleSort(c.id); }}>
                      {c.header}
                      <span className="dt-sort-icon" data-dir={dir ?? undefined} aria-hidden>
                        <Icon name={dir === "descending" ? "down" : "up"} size={12} />
                      </span>
                    </button>
                  ) : c.hideHeader ? <span className="sr-only">{c.header}</span> : c.header}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody ref={bodyRef}>
          {shown.map((r) => {
            const key = rowKey(r);
            const sel = grid ? key === selected : undefined;
            return (
              <tr
                key={key}
                data-key={key}
                aria-label={rowLabel?.(r)}
                aria-selected={sel}
                data-selected={sel || undefined}
                tabIndex={grid ? (key === stop ? 0 : -1) : undefined}
                onClick={grid ? () => { setFocusKey(key); onSelect(key, r); } : undefined}
                onDoubleClick={onActivate ? () => { onActivate(r); } : undefined}
                onFocus={grid && selectOnFocus ? (e) => { if (e.target === e.currentTarget && key !== selected) { setFocusKey(key); onSelect(key, r); } } : undefined}
                {...rowAttrs?.(r)}
              >
                {columns.map((c) => (
                  <td key={c.id} className={c.className} data-numeric={c.numeric || undefined}>{c.cell(r)}</td>
                ))}
              </tr>
            );
          })}
          {shown.length === 0 && empty !== undefined && (
            <tr className="dt-empty">
              <td colSpan={columns.length}>{empty}</td>
            </tr>
          )}
        </tbody>
      </table>
      {footer}
    </div>
  );
}

function rowEl(body: HTMLElement | null, key: string): HTMLElement | null {
  if (!body) return null;
  for (const tr of body.querySelectorAll<HTMLElement>("tr[data-key]")) if (tr.dataset.key === key) return tr;
  return null;
}
