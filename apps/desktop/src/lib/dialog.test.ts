import { vi, type Mock } from "vitest";

const open: Mock<(opts: unknown) => Promise<string | null>> = vi.fn();
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: (opts: unknown) => open(opts) }));

const { localName, pickDownloadDir, pickUploadFile } = await import("./dialog");

describe("file pickers", () => {
  afterEach(() => {
    delete (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__;
    open.mockReset();
  });

  it("uses the native dialog inside Tauri and returns null on cancel", async () => {
    (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ = {};
    open.mockResolvedValueOnce("/picked/dir").mockResolvedValueOnce(null);
    expect(await pickDownloadDir()).toBe("/picked/dir");
    expect(open).toHaveBeenLastCalledWith(expect.objectContaining({ directory: true, multiple: false }));
    expect(await pickUploadFile()).toBeNull();
    expect(open).toHaveBeenLastCalledWith(expect.objectContaining({ directory: false, multiple: false }));
  });

  it("falls back to demo picks in a plain browser", async () => {
    expect(await pickDownloadDir()).toMatch(/Downloads$/);
    expect(await pickUploadFile()).toMatch(/notes\.txt$/);
    expect(open).not.toHaveBeenCalled();
  });

  it("shows only the last path component", () => {
    expect(localName("/a/b/c.txt")).toBe("c.txt");
    expect(localName("C:\\Users\\x\\d.bin")).toBe("d.bin");
    expect(localName("/a/dir/")).toBe("dir");
  });
});
