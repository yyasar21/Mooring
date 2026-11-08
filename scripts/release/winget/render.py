#!/usr/bin/env python3
"""Render the winget manifest set for one Mooring release (ADR-0018 A2).

    python3 -I scripts/release/winget/render.py --templates packaging/winget \
        --sums SHA256SUMS --version 0.2.0 --release-date 2026-11-08 \
        [--msi-product-code '{GUID}'] --out <dir>

Writes the three-file multi-file manifest (schema 1.10.0) under
`<out>/manifests/y/yyasar21/Mooring/<version>/`, the layout microsoft/winget-pkgs expects:

    yyasar21.Mooring.yaml                 version manifest
    yyasar21.Mooring.installer.yaml       NSIS (per-user) + MSI (per-machine), x64
    yyasar21.Mooring.locale.en-US.yaml    defaultLocale manifest

Hashes come from the release's SHA256SUMS (cosign-verified by the caller), never from
re-downloading an installer. Stable versions only: winget-pkgs takes no pre-releases here.
Without `--msi-product-code` the ProductCode line is dropped (winget then matches the MSI by
its ARP entry). Prints the output directory. Standard library only; run with `-I`.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

PACKAGE = "yyasar21.Mooring"
TEMPLATES = (f"{PACKAGE}.yaml", f"{PACKAGE}.installer.yaml", f"{PACKAGE}.locale.en-US.yaml")
STABLE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
SHA = re.compile(r"^[0-9a-fA-F]{64}$")
GUID = re.compile(r"^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$")
DATE = re.compile(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$")
PLACEHOLDER = re.compile(r"@[A-Z0-9_]+@")


def die(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def read_sums(path: pathlib.Path) -> dict[str, str]:
    sums: dict[str, str] = {}
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2 or not SHA.match(parts[0]):
            die(f"{path}:{n}: not a sha256sum line")
        name = parts[1].lstrip("*")
        if name.startswith("./"):
            name = name[2:]
        if name in sums:
            die(f"{path}:{n}: {name} listed twice")
        sums[name] = parts[0].upper()
    return sums


def render(text: str, values: dict[str, str], product_code: str | None) -> str:
    out = []
    for line in text.splitlines():
        # Template notes are for maintainers; the schema hint line stays.
        if line.startswith("#") and "yaml-language-server" not in line:
            continue
        if "@MSI_PRODUCT_CODE@" in line and product_code is None:
            continue
        for key, value in values.items():
            line = line.replace(f"@{key}@", value)
        out.append(line)
    body = "\n".join(out) + "\n"
    left = PLACEHOLDER.findall(body)
    if left:
        die(f"unrendered placeholder(s): {', '.join(sorted(set(left)))}")
    return "# Created by scripts/release/winget/render.py (Mooring release pipeline)\n" + body


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--templates", required=True, type=pathlib.Path)
    ap.add_argument("--sums", required=True, type=pathlib.Path)
    ap.add_argument("--version", required=True)
    ap.add_argument("--release-date", required=True)
    ap.add_argument("--msi-product-code")
    ap.add_argument("--out", required=True, type=pathlib.Path)
    a = ap.parse_args()

    if not STABLE.match(a.version):
        die(f"'{a.version}' is not a stable MAJOR.MINOR.PATCH version")
    if not DATE.match(a.release_date):
        die(f"'{a.release_date}' is not YYYY-MM-DD")
    code = a.msi_product_code
    if code is not None:
        code = code.strip().upper()
        if not GUID.match(code):
            die(f"'{a.msi_product_code}' is not a {{GUID}} product code")

    sums = read_sums(a.sums)
    nsis = f"Mooring_{a.version}_x64-setup.exe"
    msi = f"Mooring_{a.version}_x64_en-US.msi"
    for name in (nsis, msi):
        if name not in sums:
            die(f"{name} is not in {a.sums}")
    values = {
        "VERSION": a.version,
        "RELEASE_DATE": a.release_date,
        "SHA256_NSIS": sums[nsis],
        "SHA256_MSI": sums[msi],
        "MSI_PRODUCT_CODE": code or "",
    }

    dest = a.out / "manifests" / "y" / "yyasar21" / "Mooring" / a.version
    dest.mkdir(parents=True, exist_ok=True)
    for name in TEMPLATES:
        src = a.templates / name
        if not src.is_file():
            die(f"template {src} not found")
        (dest / name).write_text(render(src.read_text(encoding="utf-8"), values, code), encoding="utf-8")
    print(dest)


if __name__ == "__main__":
    main()
