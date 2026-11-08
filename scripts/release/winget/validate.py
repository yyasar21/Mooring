#!/usr/bin/env python3
"""Offline check of a rendered winget manifest set (ADR-0018 A2).

    python3 -I scripts/release/winget/validate.py <manifest-dir>

Checks what `winget validate` would reject first, without Windows or network: the three
files of a multi-file manifest (version, installer, defaultLocale), schema 1.10.0, one
PackageIdentifier and PackageVersion across them, the key set of every manifest (unknown keys
are typos), and the field patterns and length limits of the 1.10.0 JSON schemas for the
fields Mooring uses. The authoritative check stays `winget validate` / the winget-pkgs
pipeline on the PR. Needs PyYAML (`python3-yaml` on Ubuntu).
"""
from __future__ import annotations

import pathlib
import re
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - environment
    print("error: PyYAML is required (apt-get install python3-yaml)", file=sys.stderr)
    sys.exit(2)

MANIFEST_VERSION = "1.10.0"
ID = re.compile(r'^[^\.\s\\/:\*\?"<>\|\x01-\x1f]{1,32}(\.[^\.\s\\/:\*\?"<>\|\x01-\x1f]{1,32}){1,7}$')
VERSION = re.compile(r'^[^\\/:\*\?"<>\|\x01-\x1f]+$')
LOCALE = re.compile(r"^([a-zA-Z]{2,3}|[iI]-[a-zA-Z]+|[xX]-[a-zA-Z]{1,8})(-[a-zA-Z]{1,8})*$")
SHA = re.compile(r"^[A-Fa-f0-9]{64}$")
GUID = re.compile(r"^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
URL = re.compile(r"^https://[^\s]{1,2040}$")
OSVER = re.compile(r"^(0|[1-9]\d{0,4})(\.(0|[1-9]\d{0,4})){0,3}$")
TAG = re.compile(r"^\S{1,40}$")

COMMON = {"PackageIdentifier", "PackageVersion", "ManifestType", "ManifestVersion"}
KEYS = {
    "version": COMMON | {"DefaultLocale"},
    "installer": COMMON | {"MinimumOSVersion", "ReleaseDate", "Installers", "InstallerLocale",
                           "Platform", "UpgradeBehavior", "InstallerSwitches", "Scope"},
    "defaultLocale": COMMON | {"PackageLocale", "Publisher", "PublisherUrl", "PublisherSupportUrl",
                               "PrivacyUrl", "Author", "PackageName", "PackageUrl", "License",
                               "LicenseUrl", "Copyright", "CopyrightUrl", "ShortDescription",
                               "Description", "Moniker", "Tags", "ReleaseNotes", "ReleaseNotesUrl"},
}
INSTALLER_KEYS = {"Architecture", "InstallerType", "Scope", "InstallerUrl", "InstallerSha256",
                  "ProductCode", "UpgradeBehavior", "InstallerSwitches", "InstallerLocale",
                  "ElevationRequirement", "AppsAndFeaturesEntries"}
SWITCH_KEYS = {"Silent", "SilentWithProgress", "Interactive", "InstallLocation", "Log", "Upgrade", "Custom"}
ARCH = {"x86", "x64", "arm", "arm64", "neutral"}
TYPES = {"msix", "msi", "appx", "exe", "zip", "inno", "nullsoft", "wix", "burn", "pwa", "portable", "font"}
UPGRADE = {"install", "uninstallPrevious", "deny"}

errors: list[str] = []


def err(where: str, msg: str) -> None:
    errors.append(f"{where}: {msg}")


def text(where: str, doc: dict, key: str, *, required: bool = True, pattern=None, maxlen: int | None = None):
    v = doc.get(key)
    if v is None:
        if required:
            err(where, f"{key} is required")
        return None
    if not isinstance(v, str):
        err(where, f"{key} must be a string, got {type(v).__name__}")
        return None
    if maxlen is not None and not (1 <= len(v) <= maxlen):
        err(where, f"{key} length {len(v)} outside 1..{maxlen}")
    if pattern is not None and not pattern.match(v):
        err(where, f"{key} '{v}' does not match {pattern.pattern}")
    return v


def load(path: pathlib.Path) -> dict:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        err(path.name, f"not YAML: {e}")
        return {}
    if not isinstance(doc, dict):
        err(path.name, "not a mapping")
        return {}
    return doc


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__.splitlines()[2].strip(), file=sys.stderr)
        sys.exit(2)
    d = pathlib.Path(sys.argv[1])
    files = sorted(p for p in d.glob("*.yaml"))
    by_type: dict[str, tuple[pathlib.Path, dict]] = {}
    for p in files:
        doc = load(p)
        t = doc.get("ManifestType")
        if t not in KEYS:
            err(p.name, f"ManifestType '{t}' is not version/installer/defaultLocale")
            continue
        if t in by_type:
            err(p.name, f"second {t} manifest")
        by_type[t] = (p, doc)
        extra = set(doc) - KEYS[t]
        if extra:
            err(p.name, f"unknown keys {sorted(extra)}")
        if doc.get("ManifestVersion") != MANIFEST_VERSION:
            err(p.name, f"ManifestVersion must be '{MANIFEST_VERSION}', got {doc.get('ManifestVersion')!r}")
        text(p.name, doc, "PackageIdentifier", pattern=ID, maxlen=128)
        text(p.name, doc, "PackageVersion", pattern=VERSION, maxlen=128)
    for t in KEYS:
        if t not in by_type:
            err(str(d), f"no {t} manifest")
    if errors:
        finish()

    ids = {doc["PackageIdentifier"] for _, doc in by_type.values()}
    versions = {doc["PackageVersion"] for _, doc in by_type.values()}
    if len(ids) != 1 or len(versions) != 1:
        err(str(d), f"PackageIdentifier/PackageVersion differ across files: {sorted(ids)} {sorted(versions)}")
        finish()
    pid, ver = ids.pop(), versions.pop()

    vp, vdoc = by_type["version"]
    loc = text(vp.name, vdoc, "DefaultLocale", pattern=LOCALE, maxlen=20)
    expected = {"version": f"{pid}.yaml", "installer": f"{pid}.installer.yaml",
                "defaultLocale": f"{pid}.locale.{loc}.yaml"}
    for t, (p, _) in by_type.items():
        if p.name != expected[t]:
            err(p.name, f"a {t} manifest must be named {expected[t]}")
    parts = d.resolve().parts
    if len(parts) >= 2 and (parts[-1] != ver or parts[-2] != pid.split(".")[-1]):
        err(str(d), f"directory should end in .../{pid.split('.')[-1]}/{ver}")

    ip, idoc = by_type["installer"]
    text(ip.name, idoc, "MinimumOSVersion", required=False, pattern=OSVER)
    text(ip.name, idoc, "ReleaseDate", required=False, pattern=DATE)
    installers = idoc.get("Installers")
    if not isinstance(installers, list) or not 1 <= len(installers) <= 1024:
        err(ip.name, "Installers must be a non-empty list")
        installers = []
    seen = set()
    for i, inst in enumerate(installers):
        w = f"{ip.name}: Installers[{i}]"
        if not isinstance(inst, dict):
            err(w, "not a mapping")
            continue
        extra = set(inst) - INSTALLER_KEYS
        if extra:
            err(w, f"unknown keys {sorted(extra)}")
        arch = inst.get("Architecture")
        if arch not in ARCH:
            err(w, f"Architecture {arch!r} not in {sorted(ARCH)}")
        itype = inst.get("InstallerType")
        if itype not in TYPES:
            err(w, f"InstallerType {itype!r} not in {sorted(TYPES)}")
        scope = inst.get("Scope")
        if scope not in (None, "user", "machine"):
            err(w, f"Scope {scope!r}")
        if inst.get("UpgradeBehavior") not in (None, *UPGRADE):
            err(w, f"UpgradeBehavior {inst.get('UpgradeBehavior')!r}")
        url = text(w, inst, "InstallerUrl", pattern=URL)
        if url and f"v{ver}/" not in url:
            err(w, f"InstallerUrl does not point at tag v{ver}")
        text(w, inst, "InstallerSha256", pattern=SHA)
        text(w, inst, "ProductCode", required=False, maxlen=255, pattern=GUID if itype in ("wix", "msi") else None)
        sw = inst.get("InstallerSwitches")
        if sw is not None:
            if not isinstance(sw, dict) or set(sw) - SWITCH_KEYS:
                err(w, f"InstallerSwitches keys must be within {sorted(SWITCH_KEYS)}")
            else:
                for k in sw:
                    text(w, sw, k, maxlen=2048)
        key = (arch, itype, scope)
        if key in seen:
            err(w, f"duplicate installer {key}")
        seen.add(key)

    lp, ldoc = by_type["defaultLocale"]
    if ldoc.get("PackageLocale") != loc:
        err(lp.name, f"PackageLocale {ldoc.get('PackageLocale')!r} != DefaultLocale {loc!r}")
    for k, n in (("Publisher", 256), ("PackageName", 256), ("License", 512), ("ShortDescription", 256)):
        text(lp.name, ldoc, k, maxlen=n)
    for k in ("PublisherUrl", "PublisherSupportUrl", "PackageUrl", "LicenseUrl", "ReleaseNotesUrl", "PrivacyUrl", "CopyrightUrl"):
        text(lp.name, ldoc, k, required=False, pattern=URL)
    text(lp.name, ldoc, "Description", required=False, maxlen=10000)
    text(lp.name, ldoc, "Copyright", required=False, maxlen=512)
    text(lp.name, ldoc, "Moniker", required=False, pattern=TAG)
    tags = ldoc.get("Tags", [])
    if not isinstance(tags, list) or len(tags) > 16 or any(not isinstance(t, str) or not TAG.match(t) for t in tags):
        err(lp.name, "Tags: at most 16 strings of 1..40 non-space characters")
    finish(pid, ver)


def finish(pid: str | None = None, ver: str | None = None) -> None:
    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"winget manifests ok: {pid} {ver}")
    sys.exit(0)


if __name__ == "__main__":
    main()
