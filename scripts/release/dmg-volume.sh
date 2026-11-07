#!/usr/bin/env bash
# Rename the volume of a Tauri-built .dmg to a per-version name (ADR-0028 §3, owner decision 46):
#
#   scripts/release/dmg-volume.sh <Mooring_X.Y.Z_arch.dmg> "Mooring X.Y.Z"
#
# Why a post-step: tauri-utils 2.10.2 `DmgConfig` has no volume-name field; the bundler names
# the volume after productName ("Mooring"), so two mounted releases show up as "Mooring" and
# "Mooring 1" (the owner's report). The plan, all with Apple's own tools:
#   1. hdiutil convert UDZO -> UDRW (a writable copy; the input stays untouched until step 6)
#   2. hdiutil attach -nobrowse -noautoopen at a private mount point (Finder never shows it)
#   3. require the Finder layout the bundler wrote: `.DS_Store` + `.background/` (the
#      bundle.macOS.dmg background). Without it there is nothing the rename could break and
#      nothing worth keeping: refuse, so a layout regression is loud
#   4. diskutil rename <mount point> "<name>"; re-read the name; the entry list of the volume
#      root must be identical before and after (nothing added, nothing dropped)
#   5. hdiutil detach, convert UDRW -> UDZO (zlib-level 9), hdiutil verify
#   6. replace the input atomically (mv within the same directory)
# What this script cannot prove: the background alias inside `.DS_Store` records the volume
# name it was created under. Finder usually re-resolves it on the same volume, but whether the
# background still *shows* after the rename on macOS 26 is a visual check in the rc dry run
# (decision 46: keep the per-version name only if it does; otherwise turn the step off by
# leaving the repository variable DMG_VERSIONED_VOLUME unset, and the volume stays "Mooring").
# HDIUTIL / DISKUTIL: test hooks only (scripts/release/tests/dmg-volume.test.sh).
set -euo pipefail

DMG="${1:?usage: dmg-volume.sh <file.dmg> <volume name>}"
NAME="${2:?volume name required}"
HDIUTIL="${HDIUTIL:-/usr/bin/hdiutil}"
DISKUTIL="${DISKUTIL:-/usr/sbin/diskutil}"
[[ -f "$DMG" && "$DMG" == *.dmg ]] || { echo "error: $DMG is not a .dmg file" >&2; exit 1; }
# A fixed shape: "Mooring" or "Mooring Dev", a space, a semver. HFS+/APFS allow more, but a
# volume name ends up in /Volumes paths and Finder windows; keep it boring.
[[ "$NAME" =~ ^Mooring(\ Dev)?\ [0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ && ${#NAME} -le 27 ]] \
  || { echo "error: volume name '$NAME' is not 'Mooring X.Y.Z' (max 27 characters)" >&2; exit 1; }

WORK="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/dmgvol.XXXXXX")"
MNT="$WORK/mnt"
attached=0
cleanup() {
  if ((attached)); then "$HDIUTIL" detach "$MNT" -quiet || "$HDIUTIL" detach "$MNT" -force -quiet || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

"$HDIUTIL" convert "$DMG" -format UDRW -o "$WORK/rw.dmg" -quiet
mkdir "$MNT"
"$HDIUTIL" attach "$WORK/rw.dmg" -mountpoint "$MNT" -nobrowse -noautoopen -noverify -quiet
attached=1

[[ -f "$MNT/.DS_Store" && -d "$MNT/.background" ]] \
  || { echo "error: $DMG has no Finder layout (.DS_Store + .background/); bundle.macOS.dmg not applied?" >&2; exit 1; }
before=$(cd "$MNT" && LC_ALL=C ls -A)

"$DISKUTIL" rename "$MNT" "$NAME" >/dev/null
got=$("$DISKUTIL" info "$MNT" | sed -n 's/^ *Volume Name: *//p')
[[ "$got" == "$NAME" ]] || { echo "error: volume is named '$got' after the rename, wanted '$NAME'" >&2; exit 1; }
after=$(cd "$MNT" && LC_ALL=C ls -A)
[[ "$before" == "$after" ]] || { echo "error: volume root changed during the rename" >&2; diff <(echo "$before") <(echo "$after") >&2 || true; exit 1; }

"$HDIUTIL" detach "$MNT" -quiet
attached=0
"$HDIUTIL" convert "$WORK/rw.dmg" -format UDZO -imagekey zlib-level=9 -o "$WORK/out.dmg" -quiet
"$HDIUTIL" verify "$WORK/out.dmg" -quiet
mv -f "$WORK/out.dmg" "$DMG.tmp" && mv -f "$DMG.tmp" "$DMG"
echo "renamed volume of $(basename "$DMG") to '$NAME'"
