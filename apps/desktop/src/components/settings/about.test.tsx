import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { freshBackend, settle } from "../../test/harness";
import { useApp } from "../../stores/app";
import { ABOUT_LINKS, AboutCard, versionLine } from "./AboutCard";
import { SettingsView } from "./SettingsView";

const card = () => screen.getByRole("region", { name: "About" });

describe("AboutCard", () => {
  it("shows the name, the version from app_info, the icon, licence and no-telemetry lines", async () => {
    freshBackend();
    render(<AboutCard />);
    await act(async () => { await useApp.getState().boot(); });
    await settle();
    expect(within(card()).getByText("Mooring", { selector: ".about-name" })).toBeInTheDocument();
    expect(screen.getByTestId("about-version")).toHaveTextContent("Version dev for browser (mock), debug build");
    expect(within(card()).getByRole("presentation")).toHaveAttribute("src", "/favicon.svg");
    expect(within(card()).getByText(/^MIT\./)).toBeInTheDocument();
    expect(within(card()).getByText(/sends nothing about you/)).toBeInTheDocument();
  });

  it("lists the repository, security policy and user guide and copies a link", async () => {
    freshBackend();
    const written: string[] = [];
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: (t: string) => { written.push(t); return Promise.resolve(); } },
    });
    render(<AboutCard />);
    const links = within(card()).getByRole("list", { name: "Links" });
    const items = within(links).getAllByRole("listitem");
    expect(items.map((li) => li.textContent)).toEqual(
      ABOUT_LINKS.map((l) => `${l.label}${l.url.replace(/^https:\/\//, "")}Copy`),
    );
    expect(ABOUT_LINKS.map((l) => l.label)).toEqual(["Source code", "Security policy", "User guide"]);
    for (const l of ABOUT_LINKS) expect(l.url.startsWith("https://github.com/yyasar21/Mooring")).toBe(true);
    // never a real <a>: the main window has no opener capability
    expect(within(card()).queryAllByRole("link")).toHaveLength(0);

    fireEvent.click(within(card()).getByRole("button", { name: "Copy Security policy link" }));
    await settle();
    expect(written).toEqual(["https://github.com/yyasar21/Mooring/blob/main/SECURITY.md"]);
    expect(within(card()).getByRole("button", { name: "Copy Security policy link" })).toHaveTextContent("Copied");
    expect(within(card()).getByRole("status")).toHaveTextContent("Link copied.");
  });

  it("stays quiet when the clipboard is unavailable", async () => {
    freshBackend();
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: () => Promise.reject(new Error("denied")) },
    });
    render(<AboutCard />);
    fireEvent.click(within(card()).getByRole("button", { name: "Copy User guide link" }));
    await settle();
    expect(within(card()).getByRole("button", { name: "Copy User guide link" })).toHaveTextContent("Copy");
    expect(within(card()).getByRole("status")).toHaveTextContent("");
  });

  it("shows the portable line with a copyable path only in a portable build (ADR-0021 §1)", async () => {
    const mock = freshBackend();
    render(<AboutCard />);
    await act(async () => { await useApp.getState().boot(); });
    await settle();
    expect(screen.queryByTestId("portable-line")).toBeNull();
    expect(card()).not.toHaveTextContent("Portable build");

    const written: string[] = [];
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: (t: string) => { written.push(t); return Promise.resolve(); } } });
    mock.portableDataDir = "D:\\Mooring\\Mooring Data";
    await act(async () => { await useApp.getState().boot(); });
    await settle();
    const line = within(card()).getByTestId("portable-line");
    expect(line).toHaveTextContent("Portable build — data in D:\\Mooring\\Mooring Data");
    expect(line.querySelector("code.about-link-url")).toHaveTextContent("D:\\Mooring\\Mooring Data");
    fireEvent.click(within(line).getByRole("button", { name: "Copy portable data folder path" }));
    await settle();
    expect(written).toEqual(["D:\\Mooring\\Mooring Data"]);
    expect(within(line).getByRole("button", { name: "Copy portable data folder path" })).toHaveTextContent("Copied");
    expect(within(line).getByRole("status")).toHaveTextContent("Path copied.");
    expect(within(card()).queryAllByRole("link")).toHaveLength(0);
  });

  it("is the last card of Settings", async () => {
    freshBackend();
    render(<SettingsView />);
    await settle();
    const regions = screen.getAllByRole("region").map((r) => r.getAttribute("aria-labelledby"));
    expect(regions.at(-1)).toBe("about-title");
  });

  it("versionLine names the OS and the debug build", () => {
    expect(versionLine(null)).toBe("Version unknown");
    expect(versionLine({ version: "0.1.0", os: "macos", arch: "aarch64", debug: false })).toBe("Version 0.1.0 for macOS (aarch64)");
    expect(versionLine({ version: "0.1.0", os: "windows", arch: "x86_64", debug: true })).toBe("Version 0.1.0 for Windows (x86_64), debug build");
    expect(versionLine({ version: "0.1.0", os: "freebsd", arch: "x86_64", debug: false })).toBe("Version 0.1.0 for freebsd (x86_64)");
  });
});
