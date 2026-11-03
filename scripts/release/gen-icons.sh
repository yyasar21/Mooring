#!/usr/bin/env bash
# Regenerate every platform icon in src-tauri/icons/ from packaging/icon.svg.
#
#   scripts/release/gen-icons.sh                 # default source
#   scripts/release/gen-icons.sh path/to/icon.svg
#
# Uses the Tauri CLI from the pnpm workspace (`pnpm tauri icon`), which writes the PNG sizes,
# icon.icns (macOS), icon.ico (Windows) and the Store/Appx logos. Commit the result.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
SRC="${1:-$ROOT/packaging/icon.svg}"
[[ -f "$SRC" ]] || { echo "error: icon source '$SRC' not found" >&2; exit 1; }
command -v pnpm >/dev/null || { echo "error: pnpm is required" >&2; exit 1; }

cd "$ROOT"
[[ -d node_modules/@tauri-apps/cli ]] || pnpm install --frozen-lockfile

# `tauri icon` accepts a square PNG or SVG; 1024x1024 is the recommended source size.
pnpm tauri icon "$SRC" --output src-tauri/icons

# Mobile targets are not shipped; drop what the CLI generates for them.
rm -rf src-tauri/icons/android src-tauri/icons/ios
echo "icons written to src-tauri/icons/ — review with: git status src-tauri/icons"
