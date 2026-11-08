#!/usr/bin/env bash
# Developer ID signing + notarization of one macOS build (ADR-0018 A1). Runs in release.yml's
# `sign-macos` job only: no npm, no cargo, no package build scripts, environment `release`.
#
#   scripts/release/macos-sign.sh <in-dir> <out-dir> <version> <entitlements.plist>
#
# <in-dir> is the build job's `bundles-<name>` artifact: exactly one `.dmg` holding the
# ad-hoc-signed `Mooring.app`, optionally the `.pkg`, the updater `.app.tar.gz` and the portable
# zip. <out-dir> receives the same file names, rebuilt from the Developer-ID-signed, notarized,
# stapled `.app`:
#   .dmg          the original image (layout, background, volume name kept), app replaced,
#                 the image itself signed, notarized and stapled
#   .pkg          scripts/release/macos-pkg.sh on the signed .app (installer signing and
#                 notarization there, if the APPLE_INSTALLER_* secrets exist)
#   .app.tar.gz   the updater archive (sign-updater signs it later)
#   _portable.zip portable-zip.py with the signed .app and the original `portable` + README.txt
#
# Environment (never printed):
#   APPLE_CERTIFICATE (base64 .p12), APPLE_CERTIFICATE_PASSWORD, APPLE_SIGNING_IDENTITY
#   notarization, one set: APPLE_API_KEY + APPLE_API_ISSUER + APPLE_API_KEY_PATH (preferred)
#                          or APPLE_ID + APPLE_PASSWORD + APPLE_TEAM_ID
#   SOURCE_DATE_EPOCH      epoch for the portable zip (the tagged commit's time)
#   MACOS_SIGN_DRY_RUN=1   test hook: check arguments and inputs, print the plan, touch nothing
set -euo pipefail

IN="${1:?usage: macos-sign.sh <in-dir> <out-dir> <version> <entitlements.plist>}"
OUT="${2:?out-dir required}"
VERSION="${3:?version required}"
ENTITLEMENTS="${4:?entitlements.plist required}"
HERE="$(cd "$(dirname "$0")" && pwd)"

die() { echo "error: $*" >&2; exit 1; }
[[ -d "$IN" ]] || die "$IN is not a directory"
[[ -f "$ENTITLEMENTS" ]] || die "$ENTITLEMENTS not found"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || die "bad version '$VERSION'"

shopt -s nullglob
dmgs=("$IN"/*.dmg)
((${#dmgs[@]} == 1)) || die "expected one .dmg in $IN, found ${#dmgs[@]}"
plan=()
for f in "$IN"/*; do
  [[ -f "$f" ]] || continue
  case "${f##*/}" in
    *.dmg) plan+=("dmg ${f##*/}") ;;
    *.pkg) plan+=("pkg ${f##*/}") ;;
    *.app.tar.gz) plan+=("updater ${f##*/}") ;;
    *_portable.zip) plan+=("portable ${f##*/}") ;;
    *) die "unexpected file ${f##*/} in $IN (nothing unsigned may pass through)" ;;
  esac
done

notary=()
if [[ -n "${APPLE_API_KEY:-}" && -n "${APPLE_API_ISSUER:-}" && -n "${APPLE_API_KEY_PATH:-}" ]]; then
  notary=(--key "$APPLE_API_KEY_PATH" --key-id "$APPLE_API_KEY" --issuer "$APPLE_API_ISSUER")
  how="App Store Connect API key"
elif [[ -n "${APPLE_ID:-}" && -n "${APPLE_PASSWORD:-}" && -n "${APPLE_TEAM_ID:-}" ]]; then
  notary=(--apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" --team-id "$APPLE_TEAM_ID")
  how="Apple ID + app-specific password"
fi
for v in APPLE_CERTIFICATE APPLE_CERTIFICATE_PASSWORD APPLE_SIGNING_IDENTITY; do
  [[ -n "${!v:-}" ]] || die "$v is not set"
done
((${#notary[@]} > 0)) || die "no complete notarization credential set (API key trio or Apple ID trio)"

# Review 9 N-75: the signature is verified against a designated requirement that names our
# Developer ID team (from "Developer ID Application: <name> (<TEAMID>)"), not just "valid".
team="${APPLE_SIGNING_IDENTITY##*(}"; team="${team%)}"
[[ "$APPLE_SIGNING_IDENTITY" == *"($team)" && "$team" =~ ^[A-Z0-9]{10}$ ]] \
  || die "APPLE_SIGNING_IDENTITY must end in '(<10-character team id>)'"
[[ -z "${APPLE_TEAM_ID:-}" || "$APPLE_TEAM_ID" == "$team" ]] || die "APPLE_TEAM_ID differs from the signing identity's team"
REQ="anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"$team\""

if [[ "${MACOS_SIGN_DRY_RUN:-}" == 1 ]]; then
  echo "notarization: $how"
  echo "team: $team"
  printf 'plan: %s\n' "${plan[@]}"
  exit 0
fi

mkdir -p "$OUT"
WORK="$(mktemp -d)"
KC="$WORK/signing.keychain-db"
MNT="$WORK/mnt"
OLD_KEYCHAINS=()
cleanup() {
  hdiutil detach "$MNT" -force >/dev/null 2>&1 || true
  if ((${#OLD_KEYCHAINS[@]} > 0)); then security list-keychains -d user -s "${OLD_KEYCHAINS[@]}" >/dev/null 2>&1 || true; fi
  security delete-keychain "$KC" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# A throw-away keychain holds the certificate for this script only.
kpw="$(openssl rand -hex 24)"
security create-keychain -p "$kpw" "$KC"
security set-keychain-settings -lut 3600 "$KC"
security unlock-keychain -p "$kpw" "$KC"
(umask 077; printf '%s' "$APPLE_CERTIFICATE" | base64 --decode > "$WORK/cert.p12")
security import "$WORK/cert.p12" -k "$KC" -P "$APPLE_CERTIFICATE_PASSWORD" -T /usr/bin/codesign >/dev/null
rm -f "$WORK/cert.p12"
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$kpw" "$KC" >/dev/null
while IFS= read -r k; do k="${k//\"/}"; k="${k#"${k%%[![:space:]]*}"}"; [[ -n "$k" ]] && OLD_KEYCHAINS+=("$k"); done < <(security list-keychains -d user)
security list-keychains -d user -s "$KC" "${OLD_KEYCHAINS[@]}"
security find-identity -v -p codesigning "$KC" | grep -qF "\"$APPLE_SIGNING_IDENTITY\"" \
  || die "APPLE_SIGNING_IDENTITY is not a valid code-signing identity in APPLE_CERTIFICATE"

sign() { codesign --force --timestamp --options runtime --keychain "$KC" --sign "$APPLE_SIGNING_IDENTITY" "$@"; }
notarize() { # notarize <file>: submit, wait, require "Accepted" (the log on failure has no secrets)
  local f="$1" res status id
  res="$WORK/notary.json"
  xcrun notarytool submit "$f" "${notary[@]}" --wait --output-format json > "$res" || true
  status=$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1])).get("status",""))' "$res" 2>/dev/null || true)
  id=$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1])).get("id",""))' "$res" 2>/dev/null || true)
  if [[ "$status" != Accepted ]]; then
    [[ -n "$id" ]] && xcrun notarytool log "$id" "${notary[@]}" >&2 || true
    die "notarization of ${f##*/} ended with '${status:-no status}'"
  fi
  echo "notarized ${f##*/} ($id)"
}

# 1. The .app out of the build's dmg.
dmg="${dmgs[0]}"; dmg_name="${dmg##*/}"
mkdir -p "$MNT"
hdiutil attach -readonly -nobrowse -noautoopen -mountpoint "$MNT" "$dmg" >/dev/null
[[ -d "$MNT/Mooring.app" ]] || die "$dmg_name holds no Mooring.app"
ditto "$MNT/Mooring.app" "$WORK/Mooring.app"
hdiutil detach "$MNT" >/dev/null
APP="$WORK/Mooring.app"
ident=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$APP/Contents/Info.plist")
[[ "$ident" != *.dev ]] || die "$dmg_name carries the dev identity $ident (ADR-0028)"
main=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$APP/Contents/Info.plist")

# 2. Inside out: nested Mach-O code first, then the bundle (main executable + entitlements).
while IFS= read -r -d '' f; do
  [[ "$f" == "$APP/Contents/MacOS/$main" ]] && continue
  if file -b "$f" | grep -q 'Mach-O'; then sign "$f"; fi
done < <(find "$APP/Contents" -type f \( -perm -u+x -o -name '*.dylib' \) -print0)
sign --entitlements "$ENTITLEMENTS" "$APP"
codesign --verify --strict --deep -R="$REQ" "$APP" || die "the .app does not satisfy the team requirement"
codesign -dv "$APP" 2>&1 | grep -q '^Authority=Developer ID Application:' || die "the .app is not Developer ID signed"
(cd "$WORK" && ditto -c -k --keepParent Mooring.app app.zip)
notarize "$WORK/app.zip"
xcrun stapler staple "$APP" >/dev/null
xcrun stapler validate "$APP" >/dev/null
spctl --assess --type execute "$APP" || die "Gatekeeper rejects the signed .app"

# 3. The same dmg (layout, background, volume name) with the signed app inside.
hdiutil convert "$dmg" -format UDSP -o "$WORK/rw.sparseimage" >/dev/null
hdiutil attach -nobrowse -noautoopen -mountpoint "$MNT" "$WORK/rw.sparseimage" >/dev/null
rm -rf "$MNT/Mooring.app"
ditto "$APP" "$MNT/Mooring.app"
hdiutil detach "$MNT" >/dev/null
hdiutil convert "$WORK/rw.sparseimage" -format UDZO -imagekey zlib-level=9 -o "$OUT/$dmg_name" >/dev/null
sign "$OUT/$dmg_name"
codesign --verify -R="$REQ" "$OUT/$dmg_name" || die "the .dmg does not satisfy the team requirement"
notarize "$OUT/$dmg_name"
xcrun stapler staple "$OUT/$dmg_name" >/dev/null

# 4. The other artifacts, rebuilt from the signed .app under their original names.
for f in "$IN"/*; do
  name="${f##*/}"
  case "$name" in
    *.pkg)
      bash "$HERE/macos-pkg.sh" "$APP" "$VERSION" "$OUT/$name" ;;
    *.app.tar.gz)
      COPYFILE_DISABLE=1 tar -czf "$OUT/$name" -C "$WORK" Mooring.app
      tar -tzf "$OUT/$name" | awk -F/ '{print $1}' | sort -u | grep -qx 'Mooring.app' || die "unexpected archive layout" ;;
    *_portable.zip)
      : "${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH required for the portable zip}"
      mkdir -p "$WORK/portable"
      python3 -I - "$f" "$WORK/portable" <<'PY'
import sys, zipfile, pathlib
z, dest = zipfile.ZipFile(sys.argv[1]), pathlib.Path(sys.argv[2])
for n in ("portable", "README.txt"):
    (dest / n).write_bytes(z.read(n))
PY
      python3 -I "$HERE/portable-zip.py" --out "$OUT/$name" --epoch "$SOURCE_DATE_EPOCH" \
        "Mooring.app=$APP" "portable=$WORK/portable/portable" "README.txt=$WORK/portable/README.txt" ;;
  esac
done

# Same file names in and out: publish and finalize see one complete set.
diff <(cd "$IN" && ls -1 | LC_ALL=C sort) <(cd "$OUT" && ls -1 | LC_ALL=C sort) >&2 || die "signed set differs from the build set"
echo "signed: $(cd "$OUT" && ls -1 | tr '\n' ' ')"
