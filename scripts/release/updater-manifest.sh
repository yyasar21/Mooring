#!/usr/bin/env bash
# Write the Tauri updater manifest (latest.json) from the updater artifacts of one release.
#
#   scripts/release/updater-manifest.sh <dist-dir> <tag> [owner/repo]
#   NOTES_FILE=notes.txt scripts/release/updater-manifest.sh dist v0.1.0
#
# <dist-dir> holds the release files as uploaded (installers, `*.sig` next to each updater
# artifact). The manifest goes to <dist-dir>/latest.json so that SHA256SUMS and the provenance
# attestation cover it. It never downloads anything and reads only `*.sig` files (base64 text
# written by the Tauri bundler) — the installers themselves are not opened.
#
# Schema (tauri-plugin-updater 2.x "dynamic" format):
#   { "version", "notes", "pub_date", "platforms": { "<os>-<arch>": { "url", "signature" } } }
# Platform keys and their artifacts (ADR-0018 §3: in-app install only where no elevation is
# needed):
#   darwin-aarch64, darwin-x86_64   Mooring_<arch>.app.tar.gz; `universal` fills both slots
#                                   unless an arch-specific archive exists
#   windows-x86_64, windows-aarch64 Mooring_<v>_<arch>-setup.exe (NSIS, per-user); the MSI is
#                                   never offered (per-machine, needs elevation)
#   linux-x86_64, linux-aarch64     Mooring_<v>_<arch>.AppImage (rpm/deb are manual installs)
# A platform without a signed artifact is simply absent (pre-releases ship no AppImage).
# No `*.sig` at all (unsigned/fork build): prints a notice, writes nothing, exits 0.
# pub_date: SOURCE_DATE_EPOCH when set (UTC), else now.
set -euo pipefail

usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

DIST="${1:-}"
TAG="${2:-}"
REPO="${3:-yyasar21/Mooring}"
[[ "$DIST" == "-h" || "$DIST" == "--help" ]] && usage 0
[[ -n "$DIST" && -n "$TAG" ]] || usage 1
[[ -d "$DIST" ]] || { echo "error: '$DIST' is not a directory" >&2; exit 1; }
[[ "$TAG" =~ ^v([0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?)$ ]] || { echo "error: tag must look like v1.2.3" >&2; exit 1; }
VERSION="${BASH_REMATCH[1]}"
[[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "error: repo must be owner/name" >&2; exit 1; }

mapfile -t SIGS < <(cd "$DIST" && find . -maxdepth 1 -type f -name '*.sig' -printf '%P\n' | LC_ALL=C sort)
if ((${#SIGS[@]} == 0)); then
  echo "notice: no *.sig files in $DIST; no updater artifacts, latest.json not written" >&2
  exit 0
fi

# platform key -> "asset-name" (arch-specific entries win over the universal macOS archive)
declare -A ASSET
declare -A FROM_UNIVERSAL
claim() { # claim <platform> <asset> <universal:0|1>
  local p="$1" a="$2" u="$3"
  if [[ -z "${ASSET[$p]:-}" ]]; then
    ASSET[$p]="$a"; FROM_UNIVERSAL[$p]="$u"
  elif [[ "${FROM_UNIVERSAL[$p]}" == 1 && "$u" == 0 ]]; then
    ASSET[$p]="$a"; FROM_UNIVERSAL[$p]=0
  elif [[ "$u" == 0 ]]; then
    echo "error: two updater artifacts for $p: ${ASSET[$p]} and $a" >&2; exit 1
  fi
}
arch_key() { # arch_key <x64|amd64|x86_64|aarch64|arm64> -> x86_64|aarch64|""
  case "$1" in
    x64|amd64|x86_64) echo x86_64 ;;
    aarch64|arm64) echo aarch64 ;;
    *) echo "" ;;
  esac
}

for sig in "${SIGS[@]}"; do
  asset="${sig%.sig}"
  [[ -f "$DIST/$asset" ]] || { echo "error: $sig has no matching artifact $asset" >&2; exit 1; }
  [[ "$asset" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "error: unexpected characters in asset name '$asset'" >&2; exit 1; }
  case "$asset" in
    *_universal.app.tar.gz)
      claim darwin-aarch64 "$asset" 1; claim darwin-x86_64 "$asset" 1 ;;
    *.app.tar.gz)
      a="${asset%.app.tar.gz}"; a="${a##*_}"; k=$(arch_key "$a")
      [[ -n "$k" ]] || { echo "error: cannot derive the macOS arch from $asset" >&2; exit 1; }
      claim "darwin-$k" "$asset" 0 ;;
    *-setup.exe)
      a="${asset%-setup.exe}"; a="${a##*_}"; k=$(arch_key "$a")
      [[ -n "$k" ]] || { echo "error: cannot derive the Windows arch from $asset" >&2; exit 1; }
      claim "windows-$k" "$asset" 0 ;;
    *.msi)
      echo "notice: $asset is per-machine; not offered to the in-app updater" >&2 ;;
    *.AppImage)
      a="${asset%.AppImage}"; a="${a##*_}"; k=$(arch_key "$a")
      [[ -n "$k" ]] || { echo "error: cannot derive the Linux arch from $asset" >&2; exit 1; }
      claim "linux-$k" "$asset" 0 ;;
    *)
      echo "error: signed artifact of unknown kind: $asset" >&2; exit 1 ;;
  esac
done
((${#ASSET[@]} > 0)) || { echo "error: signatures found but no updater platform could be filled" >&2; exit 1; }

# A Tauri `.sig` is one base64 line (the minisign signature of the artifact); refuse anything else.
sig_of() {
  local s; s=$(tr -d '\r\n' < "$DIST/$1.sig")
  [[ "$s" =~ ^[A-Za-z0-9+/=]+$ && ${#s} -ge 64 ]] || { echo "error: $1.sig is not a base64 signature" >&2; exit 1; }
  printf '%s' "$s"
}

PUB_DATE=$(date -u -d "@${SOURCE_DATE_EPOCH:-$(date +%s)}" +%Y-%m-%dT%H:%M:%SZ)
NOTES="See https://github.com/$REPO/releases/tag/$TAG"
if [[ -n "${NOTES_FILE:-}" ]]; then NOTES=$(cat "$NOTES_FILE"); fi

# Build the JSON with python (-I: no site, no env hooks) so nothing is hand-escaped.
ROWS=()
for p in $(printf '%s\n' "${!ASSET[@]}" | LC_ALL=C sort); do
  ROWS+=("$p" "${ASSET[$p]}" "$(sig_of "${ASSET[$p]}")")
done
python3 -I - "$DIST/latest.json" "$VERSION" "$PUB_DATE" "$REPO" "$TAG" "$NOTES" "${ROWS[@]}" <<'PY'
import json, sys
out, version, pub_date, repo, tag, notes, *rows = sys.argv[1:]
platforms = {}
for i in range(0, len(rows), 3):
    key, asset, sig = rows[i:i + 3]
    platforms[key] = {"signature": sig,
                      "url": f"https://github.com/{repo}/releases/download/{tag}/{asset}"}
doc = {"version": version, "notes": notes[:16384], "pub_date": pub_date, "platforms": platforms}
with open(out, "w", encoding="utf-8", newline="\n") as fh:
    json.dump(doc, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY

echo "wrote $DIST/latest.json for $VERSION:"
for p in $(printf '%s\n' "${!ASSET[@]}" | LC_ALL=C sort); do echo "  $p -> ${ASSET[$p]}"; done
