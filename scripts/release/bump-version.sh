#!/usr/bin/env bash
# Bump the Mooring version everywhere it is declared and roll the CHANGELOG.
#
#   scripts/release/bump-version.sh 0.2.0            # edit files only
#   scripts/release/bump-version.sh 0.2.0 --dry-run  # show what would change
#
# Touches: Cargo.toml [workspace.package] version, the `version = "x"` pins on internal path
# dependencies (crates/*/Cargo.toml, src-tauri/Cargo.toml), Cargo.lock (offline refresh),
# src-tauri/tauri.conf.json, every package.json in the pnpm workspace, and CHANGELOG.md
# (`## [Unreleased]` -> `## [x.y.z] - YYYY-MM-DD`, a fresh Unreleased section on top).
# It never commits or tags; `make release` does that after this script succeeds.
set -euo pipefail

usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

VERSION="${1:-}"
DRY_RUN=0
[[ "${2:-}" == "--dry-run" ]] && DRY_RUN=1
[[ -z "$VERSION" || "$VERSION" == "-h" || "$VERSION" == "--help" ]] && usage 1

# SemVer 2.0.0 (no leading v). Pre-releases such as 0.2.0-rc.1 are allowed.
SEMVER='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'
if ! [[ "$VERSION" =~ $SEMVER ]]; then
  echo "error: '$VERSION' is not SemVer (expected MAJOR.MINOR.PATCH[-PRERELEASE], no 'v')" >&2
  exit 1
fi
if [[ "$VERSION" == *-* ]]; then
  # MSI ProductVersion is numeric only; Tauri derives it from the version unless
  # bundle.windows.wix.version is set. Warn instead of producing a broken MSI silently.
  echo "warning: pre-release '$VERSION' — the MSI build needs bundle.windows.wix.version" >&2
fi

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

CURRENT="$(python3 -I - <<'PY'
import re
text = open("Cargo.toml", encoding="utf-8").read()
block = re.search(r"^\[workspace\.package\]\n(.*?)(?=^\[)", text, re.S | re.M)
m = re.search(r'^version\s*=\s*"([^"]+)"', block.group(1), re.M) if block else None
print(m.group(1) if m else "")
PY
)"
[[ -n "$CURRENT" ]] || { echo "error: no [workspace.package] version in Cargo.toml" >&2; exit 1; }
if [[ "$CURRENT" == "$VERSION" ]]; then
  echo "error: version is already $VERSION" >&2
  exit 1
fi
echo "bump: $CURRENT -> $VERSION"

mapfile -t PKG_JSON < <(git ls-files '*package.json' | grep -v node_modules)
mapfile -t CRATE_TOML < <(git ls-files 'crates/*/Cargo.toml' 'src-tauri/Cargo.toml')

python3 -I - "$CURRENT" "$VERSION" "$DRY_RUN" "${PKG_JSON[@]}" -- "${CRATE_TOML[@]}" <<'PY'
import datetime, json, re, sys

old, new, dry = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
rest = sys.argv[4:]
sep = rest.index("--")
pkg_json, crate_toml = rest[:sep], rest[sep + 1:]
changed = []

def write(path, before, after):
    if before == after:
        return
    changed.append(path)
    if not dry:
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(after)

# Cargo.toml: only the [workspace.package] version line.
src = open("Cargo.toml", encoding="utf-8").read()
def bump_ws(m):
    return re.sub(r'^(version\s*=\s*")[^"]+(")', rf"\g<1>{new}\g<2>", m.group(0), count=1, flags=re.M)
write("Cargo.toml", src, re.sub(r"^\[workspace\.package\]\n.*?(?=^\[)", bump_ws, src, count=1, flags=re.S | re.M))

# Internal path dependencies carry `version = "x"` so they stay publishable.
for path in crate_toml:
    src = open(path, encoding="utf-8").read()
    out = re.sub(r'(\{\s*path\s*=\s*"[^"]+"\s*,\s*version\s*=\s*")' + re.escape(old) + '"',
                 rf'\g<1>{new}"', src)
    write(path, src, out)

# tauri.conf.json and package.json: rewrite the top-level "version" only, keep formatting.
for path in ["src-tauri/tauri.conf.json", *pkg_json]:
    src = open(path, encoding="utf-8").read()
    if json.loads(src).get("version") is None:
        continue
    out = re.sub(r'^(  "version":\s*")[^"]+(")', rf"\g<1>{new}\g<2>", src, count=1, flags=re.M)
    if json.loads(out).get("version") != new:
        sys.exit(f"error: could not rewrite version in {path}")
    write(path, src, out)

# CHANGELOG.md (Keep a Changelog layout). Missing file -> warn, do not invent one.
try:
    src = open("CHANGELOG.md", encoding="utf-8").read()
except FileNotFoundError:
    print("warning: CHANGELOG.md not found; skipped", file=sys.stderr)
else:
    if not re.search(r"^## \[Unreleased\]", src, re.M):
        sys.exit("error: CHANGELOG.md has no '## [Unreleased]' heading")
    if re.search(rf"^## \[{re.escape(new)}\]", src, re.M):
        sys.exit(f"error: CHANGELOG.md already has a [{new}] section")
    today = datetime.date.today().isoformat()
    out = re.sub(r"^## \[Unreleased\]", f"## [Unreleased]\n\n## [{new}] - {today}", src, count=1, flags=re.M)
    repo = "https://github.com/yyasar21/Mooring"
    link = re.search(r"^\[Unreleased\]:.*$", out, re.M)
    if link:
        out = out.replace(link.group(0),
                          f"[Unreleased]: {repo}/compare/v{new}...HEAD\n"
                          f"[{new}]: {repo}/compare/v{old}...v{new}", 1)
    write("CHANGELOG.md", src, out)

for path in changed:
    print(("would change " if dry else "changed ") + path)
PY

if [[ "$DRY_RUN" == 0 ]]; then
  # Refresh the lockfile entries of workspace members without touching anything else.
  if command -v cargo >/dev/null; then
    cargo update --workspace --offline >/dev/null 2>&1 || cargo update --workspace >/dev/null
    echo "changed Cargo.lock"
  else
    echo "warning: cargo not found; run 'cargo update --workspace' before committing" >&2
  fi
fi
