import { useState } from "react";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { DataTable, sortRows, type DataColumn } from "@mooring/ui";

interface Host { id: string; name: string; port: number }
const HOSTS: Host[] = [
  { id: "b", name: "web10", port: 22 },
  { id: "a", name: "web2", port: 8443 },
  { id: "c", name: "api", port: 443 },
];
const COLUMNS: DataColumn<Host>[] = [
  { id: "name", header: "Name", cell: (h) => h.name, sortValue: (h) => h.name },
  { id: "port", header: "Port", cell: (h) => h.port, sortValue: (h) => h.port, numeric: true },
  { id: "note", header: "Note", cell: () => "—" },
];

function Grid({ onActivate, onKey }: { onActivate?: (h: Host) => void; onKey?: (k: string, h: Host | undefined) => boolean }) {
  const [sel, setSel] = useState<string | null>(null);
  return (
    <DataTable
      label="Hosts"
      columns={COLUMNS}
      rows={HOSTS}
      rowKey={(h) => h.id}
      rowLabel={(h) => `${h.name}, port ${String(h.port)}`}
      selected={sel}
      onSelect={(k) => { setSel(k); }}
      {...(onActivate ? { onActivate } : {})}
      {...(onKey ? { onKeyDown: (e: React.KeyboardEvent, h: Host | undefined) => onKey(e.key, h) } : {})}
      defaultSort={{ column: "name", dir: "ascending" }}
    />
  );
}

const names = () => within(screen.getByRole("grid", { name: "Hosts" })).getAllByRole("row").slice(1).map((r) => r.getAttribute("aria-label"));

describe("DataTable (M5)", () => {
  it("sorts with a natural order and says so with aria-sort", () => {
    render(<Grid />);
    expect(names()).toEqual(["api, port 443", "web2, port 8443", "web10, port 22"]);
    const name = screen.getByRole("columnheader", { name: "Name" });
    const port = screen.getByRole("columnheader", { name: "Port" });
    expect(name).toHaveAttribute("aria-sort", "ascending");
    expect(port).toHaveAttribute("aria-sort", "none");
    expect(screen.getByRole("columnheader", { name: "Note" })).not.toHaveAttribute("aria-sort");
    fireEvent.click(within(port).getByRole("button", { name: "Port" }));
    expect(port).toHaveAttribute("aria-sort", "ascending");
    expect(name).toHaveAttribute("aria-sort", "none");
    expect(names()).toEqual(["web10, port 22", "api, port 443", "web2, port 8443"]);
    fireEvent.click(within(port).getByRole("button", { name: "Port" }));
    expect(port).toHaveAttribute("aria-sort", "descending");
    expect(names()[0]).toBe("web2, port 8443");
  });

  it("keeps one tab stop on the rows and moves the selection with the keyboard", () => {
    const activate = vi.fn();
    render(<Grid onActivate={activate} />);
    const grid = screen.getByRole("grid", { name: "Hosts" });
    const rows = within(grid).getAllByRole("row").slice(1);
    expect(rows.map((r) => r.tabIndex)).toEqual([0, -1, -1]);
    rows[0]?.focus();
    fireEvent.keyDown(rows[0] as HTMLElement, { key: "ArrowDown" });
    expect(screen.getByRole("row", { name: "web2, port 8443" })).toHaveAttribute("aria-selected", "true");
    expect(document.activeElement).toBe(screen.getByRole("row", { name: "web2, port 8443" }));
    fireEvent.keyDown(grid, { key: "End" });
    expect(screen.getByRole("row", { name: "web10, port 22" })).toHaveAttribute("aria-selected", "true");
    fireEvent.keyDown(grid, { key: "Home" });
    expect(screen.getByRole("row", { name: "api, port 443" })).toHaveAttribute("aria-selected", "true");
    expect(within(grid).getAllByRole("row").slice(1).map((r) => r.tabIndex)).toEqual([0, -1, -1]);
    fireEvent.keyDown(grid, { key: "Enter" });
    expect(activate).toHaveBeenCalledWith(HOSTS[2]);
    fireEvent.doubleClick(screen.getByRole("row", { name: "web2, port 8443" }));
    expect(activate).toHaveBeenLastCalledWith(HOSTS[1]);
  });

  it("selects on click and hands other keys to the caller first", () => {
    const seen: string[] = [];
    render(<Grid onKey={(k, h) => { seen.push(`${k}:${h?.name ?? "-"}`); return k === "F2"; }} />);
    fireEvent.click(screen.getByRole("row", { name: "web10, port 22" }));
    expect(screen.getByRole("row", { name: "web10, port 22" })).toHaveAttribute("aria-selected", "true");
    fireEvent.keyDown(screen.getByRole("grid"), { key: "F2" });
    fireEvent.keyDown(screen.getByRole("grid"), { key: "ArrowUp" });
    expect(seen).toEqual(["F2:web10", "ArrowUp:web10"]);
    expect(screen.getByRole("row", { name: "web2, port 8443" })).toHaveAttribute("aria-selected", "true");
  });

  it("is a plain table without selection, with an empty row and names from the cells", () => {
    render(<DataTable label="Replies" columns={COLUMNS} rows={[]} rowKey={(h) => h.id} empty="Nothing yet." />);
    const table = screen.getByRole("table", { name: "Replies" });
    expect(within(table).getByText("Nothing yet.")).toBeInTheDocument();
    render(<DataTable label="Some" columns={COLUMNS} rows={HOSTS.slice(0, 1)} rowKey={(h) => h.id} />);
    const row = within(screen.getByRole("table", { name: "Some" })).getAllByRole("row")[1];
    expect(row).toHaveAccessibleName("web10 22 —");
    expect(row).not.toHaveAttribute("aria-selected");
    expect(row).not.toHaveAttribute("tabindex");
  });

  it("sortRows leaves the input alone and sorts strings without case", () => {
    const rows = [{ id: "1", name: "b", port: 1 }, { id: "2", name: "A", port: 2 }];
    expect(sortRows(rows, COLUMNS, { column: "name", dir: "ascending" }).map((r) => r.name)).toEqual(["A", "b"]);
    expect(rows[0]?.name).toBe("b");
    expect(sortRows(rows, COLUMNS, null)).toEqual(rows);
  });
});
