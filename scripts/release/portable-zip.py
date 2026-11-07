#!/usr/bin/env python3
"""Deterministic zip for the portable builds (ADR-0021 §4).

    python3 -I scripts/release/portable-zip.py --out <zip> --epoch <SOURCE_DATE_EPOCH> \
        [--root <dir>] [<name>=<path> ...]

`--root <dir>` zips the directory's contents at the top level of the archive; each
`<name>=<path>` adds one entry (a file, a symlink or a directory, which is added recursively)
under the archive name `<name>`. Both may be combined. The output is byte-identical for the
same inputs:

  * entries sorted by archive path, `LC_ALL=C` order (UTF-8 bytes), parents before children;
  * every mtime = `--epoch` (UTC), floored to 1980-01-01 00:00:00, the zip format's minimum;
  * Unix mode in `external_attr` (create_system = 3) so the executable bit and the mode of a
    macOS `.app` bundle survive; symlinks are stored as symlinks (`S_IFLNK`, link target as the
    entry data, never dereferenced: `Contents/Frameworks` of a `.app` is full of them);
  * one fixed deflate level, symlinks and directories stored; no extra fields (no timestamps,
    no zip64 unless an entry needs it, which the portable builds never do).

Only `zipfile` and the standard library; run with `-I` so nothing is imported from the cwd.
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
import time
import zipfile

DEFLATE_LEVEL = 9
ZIP_MIN_EPOCH = 315532800  # 1980-01-01T00:00:00Z: the earliest DOS date a zip can hold


def fail(msg: str) -> None:
    print(f"portable-zip: error: {msg}", file=sys.stderr)
    sys.exit(1)


def check_arcname(name: str) -> str:
    if not name or name.startswith("/") or "\\" in name or name != os.path.normpath(name).replace(os.sep, "/"):
        fail(f"invalid archive name {name!r}")
    parts = name.split("/")
    if any(p in ("", ".", "..") for p in parts):
        fail(f"invalid archive name {name!r}")
    return name


def collect(arcname: str, path: str, out: dict[str, tuple[str, os.stat_result]]) -> None:
    """Add `path` as `arcname`; a directory is walked without following symlinks."""
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or stat.S_ISREG(st.st_mode):
        put(out, arcname, path, st)
    elif stat.S_ISDIR(st.st_mode):
        put(out, arcname, path, st)
        for entry in sorted(os.listdir(path), key=lambda s: s.encode("utf-8")):
            collect(f"{arcname}/{entry}", os.path.join(path, entry), out)
    else:
        fail(f"{path}: not a regular file, directory or symlink")


def put(out: dict[str, tuple[str, os.stat_result]], arcname: str, path: str, st: os.stat_result) -> None:
    check_arcname(arcname)
    if arcname in out:
        fail(f"duplicate archive name {arcname!r}")
    out[arcname] = (path, st)


def dos_time(epoch: int) -> tuple[int, int, int, int, int, int]:
    t = time.gmtime(max(epoch, ZIP_MIN_EPOCH))
    return (t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec)


def add(zf: zipfile.ZipFile, arcname: str, path: str, st: os.stat_result, when: tuple) -> None:
    mode = stat.S_IMODE(st.st_mode)
    if stat.S_ISDIR(st.st_mode):
        zi = zipfile.ZipInfo(arcname + "/", date_time=when)
        zi.create_system = 3
        zi.compress_type = zipfile.ZIP_STORED
        zi.external_attr = ((stat.S_IFDIR | mode) << 16) | 0x10  # 0x10: MS-DOS directory bit
        zf.writestr(zi, b"")
        return
    zi = zipfile.ZipInfo(arcname, date_time=when)
    zi.create_system = 3
    if stat.S_ISLNK(st.st_mode):
        zi.compress_type = zipfile.ZIP_STORED
        zi.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(zi, os.fsencode(os.readlink(path)))
        return
    zi.compress_type = zipfile.ZIP_DEFLATED
    zi.external_attr = (stat.S_IFREG | mode) << 16
    with open(path, "rb") as fh:
        data = fh.read()
    zf.writestr(zi, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=DEFLATE_LEVEL)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0], add_help=True)
    ap.add_argument("--out", required=True, help="zip file to write (replaced if it exists)")
    ap.add_argument("--epoch", required=True, type=int, help="SOURCE_DATE_EPOCH for every entry")
    ap.add_argument("--root", help="directory whose contents form the top level of the archive")
    ap.add_argument("entries", nargs="*", metavar="NAME=PATH", help="explicit entries")
    args = ap.parse_args(argv)
    if args.epoch < 0:
        fail("--epoch must be a non-negative integer")

    items: dict[str, tuple[str, os.stat_result]] = {}
    if args.root:
        if not os.path.isdir(args.root):
            fail(f"--root {args.root!r} is not a directory")
        for entry in os.listdir(args.root):
            collect(entry, os.path.join(args.root, entry), items)
    for spec in args.entries:
        name, sep, path = spec.partition("=")
        if not sep or not name or not path:
            fail(f"entry {spec!r} is not NAME=PATH")
        if not os.path.lexists(path):
            fail(f"{path}: no such file or directory")
        collect(name, path, items)
    if not items:
        fail("nothing to archive")

    when = dos_time(args.epoch)
    tmp = args.out + ".tmp"
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=False) as zf:
        for arcname in sorted(items, key=lambda s: s.encode("utf-8")):
            path, st = items[arcname]
            add(zf, arcname, path, st, when)
    os.replace(tmp, args.out)
    print(f"portable-zip: wrote {args.out} ({len(items)} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
