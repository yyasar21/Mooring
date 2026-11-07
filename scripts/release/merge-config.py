#!/usr/bin/env python3
"""RFC 7396 JSON Merge Patch of Tauri configs, and the ADR-0028 identity checks.

    python3 -I scripts/release/merge-config.py merge BASE PATCH... [--get /json/pointer]
    python3 -I scripts/release/merge-config.py check-identity [SRC_TAURI_DIR]
    python3 -I scripts/release/merge-config.py self-test

`merge` applies each PATCH in order, the way the Tauri CLI folds repeated `--config` values
and tauri-build applies `TAURI_CONFIG` (json_patch::merge, tauri-build 2.7.4 lib.rs:681):
objects merge key by key, `null` deletes, anything else (arrays included) replaces.

`check-identity` asserts that the checked-in `tauri.conf.json` is the dev identity and that
it merged with `tauri.release.conf.json` is the release identity (ADR-0028 §1). Used by
ci.yml and scripts/release/tests/identity.test.sh. Tests and CI only; no build reads this.
Standard library only.
"""
import json
import os
import struct
import sys
import uuid

RELEASE_ID = "io.github.yyasar21.mooring"
DEV_ID = RELEASE_ID + ".dev"
RELEASE_UPGRADE_CODE = "1f940c60-f3be-5e3f-81de-92ee690e0b6d"  # Tauri's uuid5(DNS, "Mooring.exe.app.x64")
DEV_UPGRADE_CODE = str(uuid.uuid5(uuid.NAMESPACE_DNS, DEV_ID))  # 9eff6699-6217-579b-8071-28cf4e556939
ENDPOINT = "https://github.com/yyasar21/Mooring/releases/latest/download/latest.json"
OVERLAY_KEYS = {"productName", "identifier", "app", "bundle", "plugins"}


def merge_patch(target, patch):
    """RFC 7396 §2 MergePatch, returning a new value."""
    if not isinstance(patch, dict):
        return patch
    result = dict(target) if isinstance(target, dict) else {}
    for key, value in patch.items():
        if value is None:
            result.pop(key, None)
        else:
            result[key] = merge_patch(result.get(key), value)
    return result


def pointer(doc, ptr):
    """RFC 6901 lookup; KeyError when absent."""
    if ptr in ("", "/"):
        return doc
    for raw in ptr.lstrip("/").split("/"):
        part = raw.replace("~1", "/").replace("~0", "~")
        doc = doc[int(part)] if isinstance(doc, list) else doc[part]
    return doc


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def png_size(path):
    with open(path, "rb") as fh:
        head = fh.read(24)
    if head[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError(f"{path} is not a PNG")
    return struct.unpack(">II", head[16:24])


def get(doc, ptr, default=None):
    try:
        return pointer(doc, ptr)
    except (KeyError, IndexError, TypeError, ValueError):
        return default


def check_identity(src):
    errors = []

    def need(cond, msg):
        if not cond:
            errors.append(msg)

    base = load(os.path.join(src, "tauri.conf.json"))
    overlay = load(os.path.join(src, "tauri.release.conf.json"))
    merged = merge_patch(base, overlay)

    # The overlay carries release keys only (ADR-0028 §1); the version stays in the base file,
    # which bump-version.sh edits.
    extra = set(overlay) - OVERLAY_KEYS
    need(not extra, f"overlay: unexpected top-level keys {sorted(extra)}")

    # Dev identity: what `make dev`, `make bundle`, plain `cargo tauri build` and CI produce.
    need(base.get("identifier") == DEV_ID, f"base: identifier {base.get('identifier')!r} != {DEV_ID!r}")
    need(base.get("productName") == "Mooring Dev", f"base: productName {base.get('productName')!r}")
    need(get(base, "/app/windows/0/title") == "Mooring Dev", "base: main window title is not 'Mooring Dev'")
    need(get(base, "/plugins/updater") is None, "base: plugins.updater must be absent (no updater in dev builds)")
    need(not get(base, "/bundle/createUpdaterArtifacts", False), "base: createUpdaterArtifacts must be false")
    need(get(base, "/bundle/windows/wix/upgradeCode") == DEV_UPGRADE_CODE,
         f"base: WiX upgradeCode must be uuid5(DNS, {DEV_ID}) = {DEV_UPGRADE_CODE}")
    need(get(base, "/bundle/windows/nsis/installerIcon") == "icons-dev/icon.ico", "base: NSIS installerIcon not icons-dev")

    # Release identity: base + overlay, as release.yml builds it.
    need(merged.get("identifier") == RELEASE_ID, f"merged: identifier {merged.get('identifier')!r} != {RELEASE_ID!r}")
    need(merged.get("productName") == "Mooring", f"merged: productName {merged.get('productName')!r}")
    need(get(merged, "/app/windows/0/title") == "Mooring", "merged: main window title is not 'Mooring'")
    key = get(merged, "/plugins/updater/pubkey", "")
    need(isinstance(key, str) and key.strip(), "merged: plugins.updater.pubkey missing")
    need(get(merged, "/plugins/updater/endpoints") == [ENDPOINT], "merged: updater endpoints")
    need(get(merged, "/plugins/updater/requireSignedVersion") is True, "merged: requireSignedVersion must be true (L-39)")
    need(get(merged, "/bundle/createUpdaterArtifacts") is True, "merged: createUpdaterArtifacts must be true")
    need(get(merged, "/bundle/windows/wix/upgradeCode") == RELEASE_UPGRADE_CODE,
         "merged: WiX upgradeCode must stay byte-identical to the shipped one")
    need(get(merged, "/bundle/windows/wix/language") == "en-US", "merged: WiX language lost in the merge")
    need(get(merged, "/bundle/windows/nsis/installerIcon") == "icons/icon.ico", "merged: NSIS installerIcon")
    need(get(merged, "/bundle/windows/nsis/installMode") == "currentUser", "merged: NSIS installMode lost in the merge")

    # Arrays replace under RFC 7396: the overlay repeats the main window, so it must equal the
    # base window apart from the title, or a base edit silently misses release builds.
    bw, mw = get(base, "/app/windows", []), get(merged, "/app/windows", [])
    need(len(bw) == len(mw) == 1, "app.windows: expected exactly one window in base and merged")
    if len(bw) == len(mw) == 1:
        diff = {k for k in set(bw[0]) | set(mw[0]) if k != "title" and bw[0].get(k) != mw[0].get(k)}
        need(not diff, f"overlay main window drifted from tauri.conf.json: {sorted(diff)}")
    need(merged.get("version") == base.get("version"), "merged: version must come from the base file")
    need(get(merged, "/app/security") == get(base, "/app/security"), "merged: app.security must come from the base file")

    # Icon sets: same file names, each in its own directory, every file present.
    bi, mi = get(base, "/bundle/icon", []), get(merged, "/bundle/icon", [])
    need(bi and all(p.startswith("icons-dev/") for p in bi), "base: bundle.icon must use icons-dev/")
    need(mi and all(p.startswith("icons/") for p in mi), "merged: bundle.icon must use icons/")
    need([p.split("/", 1)[1] for p in bi] == [p.split("/", 1)[1] for p in mi], "icon lists differ beyond the directory")
    for p in bi + mi:
        need(os.path.isfile(os.path.join(src, p)), f"icon file missing: {p}")

    # DMG layout (ADR-0028 §3): shared by both identities.
    dmg = get(merged, "/bundle/macOS/dmg", {})
    need(dmg == get(base, "/bundle/macOS/dmg", {}), "bundle.macOS.dmg must live in the base file only")
    need(dmg.get("windowSize") == {"width": 660, "height": 400}, "dmg: windowSize 660x400")
    need(dmg.get("appPosition") == {"x": 180, "y": 170}, "dmg: appPosition")
    need(dmg.get("applicationFolderPosition") == {"x": 480, "y": 170}, "dmg: applicationFolderPosition")
    bg = os.path.join(src, dmg.get("background", "missing"))
    if os.path.isfile(bg):
        need(png_size(bg) == (660, 400), f"dmg: background is {png_size(bg)}, want 660x400")
    else:
        errors.append(f"dmg: background {dmg.get('background')!r} not found")
    return errors


def self_test():
    # RFC 7396 Appendix A, every example.
    cases = [
        ({"a": "b"}, {"a": "c"}, {"a": "c"}),
        ({"a": "b"}, {"b": "c"}, {"a": "b", "b": "c"}),
        ({"a": "b"}, {"a": None}, {}),
        ({"a": "b", "b": "c"}, {"a": None}, {"b": "c"}),
        ({"a": ["b"]}, {"a": "c"}, {"a": "c"}),
        ({"a": "c"}, {"a": ["b"]}, {"a": ["b"]}),
        ({"a": {"b": "c"}}, {"a": {"b": "d", "c": None}}, {"a": {"b": "d"}}),
        ({"a": [{"b": "c"}]}, {"a": [1]}, {"a": [1]}),
        (["a", "b"], ["c", "d"], ["c", "d"]),
        ({"a": "b"}, ["c"], ["c"]),
        ({"a": "foo"}, None, None),
        ({"a": "foo"}, "bar", "bar"),
        ({"e": None}, {"a": 1}, {"e": None, "a": 1}),
        ([1, 2], {"a": "b", "c": None}, {"a": "b"}),
        ({}, {"a": {"bb": {"ccc": None}}}, {"a": {"bb": {}}}),
    ]
    bad = 0
    for i, (t, p, want) in enumerate(cases, 1):
        got = merge_patch(t, p)
        if got != want:
            bad += 1
            print(f"FAIL rfc7396 A.{i}: {t!r} + {p!r} = {got!r}, want {want!r}")
    # The target is not mutated, and nested siblings survive (the case the overlay relies on).
    t = {"bundle": {"windows": {"wix": {"language": "en-US", "upgradeCode": "x"}}}}
    got = merge_patch(t, {"bundle": {"windows": {"wix": {"upgradeCode": "y"}}}})
    if got["bundle"]["windows"]["wix"] != {"language": "en-US", "upgradeCode": "y"} or t["bundle"]["windows"]["wix"]["upgradeCode"] != "x":
        bad += 1
        print("FAIL nested merge keeps siblings and leaves the target alone")
    if pointer({"a": [{"b/c": 1}]}, "/a/0/b~1c") != 1:
        bad += 1
        print("FAIL json pointer")
    print(f"merge-config self-test: {len(cases) + 2 - bad} passed, {bad} failed")
    return 0 if bad == 0 else 1


def main(argv):
    if not argv:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    cmd, args = argv[0], argv[1:]
    if cmd == "self-test":
        return self_test()
    if cmd == "check-identity":
        here = os.path.dirname(os.path.abspath(__file__))
        src = args[0] if args else os.path.join(here, "..", "..", "src-tauri")
        errors = check_identity(src)
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        if not errors:
            print(f"identity: ok (base {DEV_ID}, base+overlay {RELEASE_ID})")
        return 1 if errors else 0
    if cmd == "merge":
        ptr = None
        if "--get" in args:
            i = args.index("--get")
            ptr, args = args[i + 1], args[:i] + args[i + 2:]
        if not args:
            print("usage: merge BASE PATCH... [--get /pointer]", file=sys.stderr)
            return 2
        doc = load(args[0])
        for p in args[1:]:
            doc = merge_patch(doc, load(p))
        out = pointer(doc, ptr) if ptr else doc
        print(out if isinstance(out, str) else json.dumps(out, indent=2))
        return 0
    print(f"unknown command {cmd!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
