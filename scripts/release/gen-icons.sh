#!/usr/bin/env bash
# Regenerate the platform icon sets from their SVG masters (ADR-0028 §1):
#
#   scripts/release/gen-icons.sh            # both sets
#   scripts/release/gen-icons.sh release    # packaging/icon.svg     -> src-tauri/icons/     (release overlay)
#   scripts/release/gen-icons.sh dev        # packaging/icon-dev.svg -> src-tauri/icons-dev/ (checked-in config)
#
# Uses the Tauri CLI from the pnpm workspace (`pnpm tauri icon`), which writes the PNG sizes,
# icon.icns (macOS), icon.ico (Windows) and the Store/Appx logos. Commit the result.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
command -v pnpm >/dev/null || { echo "error: pnpm is required" >&2; exit 1; }
[[ -d node_modules/@tauri-apps/cli ]] || pnpm install --frozen-lockfile

gen() { # gen <svg> <out dir>
  [[ -f "$1" ]] || { echo "error: icon source '$1' not found" >&2; exit 1; }
  # `tauri icon` accepts a square PNG or SVG; 1024x1024 is the recommended source size.
  pnpm tauri icon "$1" --output "$2"
  # Mobile targets are not shipped; drop what the CLI generates for them.
  rm -rf "$2/android" "$2/ios"
  echo "icons written to $2/ — review with: git status $2"
}

case "${1:-all}" in
  release) gen packaging/icon.svg src-tauri/icons ;;
  dev) gen packaging/icon-dev.svg src-tauri/icons-dev ;;
  all) gen packaging/icon.svg src-tauri/icons; gen packaging/icon-dev.svg src-tauri/icons-dev ;;
  *) echo "usage: gen-icons.sh [release|dev|all]" >&2; exit 1 ;;
esac
