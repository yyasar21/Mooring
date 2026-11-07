#!/usr/bin/env bash
# Tests for updater-manifest.sh against fake dist directories (no network, no Tauri).
# Run: scripts/release/tests/updater-manifest.test.sh (or tests/run.sh for all)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/../updater-manifest.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0
SIG64="$(printf 'untrusted comment: signature\n%s\n' "$(head -c 60 /dev/zero | base64 -w0)" | base64 -w0)"

dist() { # dist <name> <plain files...> -- <signed files...>
  local d="$WORK/$1"; shift
  mkdir -p "$d"
  local signed=0
  for f in "$@"; do
    [[ "$f" == -- ]] && { signed=1; continue; }
    echo "content of $f" >"$d/$f"
    ((signed)) && printf '%s\n' "$SIG64" >"$d/$f.sig"
  done
  echo "$d"
}
check() { # check <label> <test command...>
  local label="$1"; shift
  if "$@"; then pass=$((pass + 1)); echo "ok   $label"
  else fail=$((fail + 1)); echo "FAIL $label"; sed 's/^/     /' "$WORK/out" 2>/dev/null || true; fi
}
run() { bash "$SCRIPT" "$@" >"$WORK/out" 2>&1; }
runfails() { ! run "$@"; }
field() { # field <json> <python expr over doc>
  python3 -I -c 'import json,sys; doc=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$1" "$2"
}

# full stable release: universal macOS archive, NSIS + MSI, two AppImages
full=$(dist full Mooring_1.2.3_x64_en-US.msi a.deb -- Mooring_universal.app.tar.gz \
  Mooring_1.2.3_x64-setup.exe Mooring_1.2.3_amd64.AppImage Mooring_1.2.3_aarch64.AppImage)
printf '%s\n' "$SIG64" >"$full/Mooring_1.2.3_x64_en-US.msi.sig"
check "full release: manifest written" run "$full" v1.2.3
check "  version is the tag without v" [ "$(field "$full/latest.json" 'doc["version"]')" = 1.2.3 ]
check "  five platforms" [ "$(field "$full/latest.json" 'len(doc["platforms"])')" = 5 ]
check "  universal archive fills both macOS slots" \
  [ "$(field "$full/latest.json" 'doc["platforms"]["darwin-x86_64"]["url"].rsplit("/",1)[1] + " " + doc["platforms"]["darwin-aarch64"]["url"].rsplit("/",1)[1]')" = "Mooring_universal.app.tar.gz Mooring_universal.app.tar.gz" ]
check "  windows takes the NSIS installer, not the MSI" \
  [ "$(field "$full/latest.json" 'doc["platforms"]["windows-x86_64"]["url"]')" = "https://github.com/yyasar21/Mooring/releases/download/v1.2.3/Mooring_1.2.3_x64-setup.exe" ]
check "  linux arm64 key is linux-aarch64" \
  [ "$(field "$full/latest.json" 'doc["platforms"]["linux-aarch64"]["url"].rsplit("/",1)[1]')" = Mooring_1.2.3_aarch64.AppImage ]
check "  signature is the .sig content" [ "$(field "$full/latest.json" 'doc["platforms"]["linux-x86_64"]["signature"]')" = "$SIG64" ]
check "  pub_date honours SOURCE_DATE_EPOCH" bash -c 'SOURCE_DATE_EPOCH=0 bash "$1" "$2" v1.2.3 >/dev/null 2>&1 && [[ "$(python3 -I -c "import json,sys;print(json.load(open(sys.argv[1]))[\"pub_date\"])" "$2/latest.json")" == 1970-01-01T00:00:00Z ]]' _ "$SCRIPT" "$full"
check "  notes default to the release page" [ "$(field "$full/latest.json" 'doc["notes"]')" = "See https://github.com/yyasar21/Mooring/releases/tag/v1.2.3" ]
check "  custom repo in urls" bash -c 'bash "$1" "$2" v1.2.3 owner/fork >/dev/null 2>&1 && grep -q "github.com/owner/fork/releases/download/v1.2.3/" "$2/latest.json"' _ "$SCRIPT" "$full"

# pre-release: no AppImage on Linux, universal macOS + NSIS only
pre=$(dist pre Mooring_1.2.3_amd64.deb -- Mooring_universal.app.tar.gz Mooring_1.2.3_x64-setup.exe)
check "pre-release without AppImage: three platforms" bash -c 'bash "$1" "$2" v1.2.3-rc.2 >/dev/null 2>&1 && [[ "$(python3 -I -c "import json,sys;d=json.load(open(sys.argv[1]));print(d[\"version\"], len(d[\"platforms\"]))" "$2/latest.json")" == "1.2.3-rc.2 3" ]]' _ "$SCRIPT" "$pre"

# arch-specific macOS archives win over the universal one
arch=$(dist arch -- Mooring_universal.app.tar.gz Mooring_aarch64.app.tar.gz)
check "arch-specific macOS archive wins over universal" bash -c 'bash "$1" "$2" v1.2.3 >/dev/null 2>&1 && [[ "$(python3 -I -c "import json,sys;d=json.load(open(sys.argv[1]))[\"platforms\"];print(d[\"darwin-aarch64\"][\"url\"].rsplit(\"/\",1)[1], d[\"darwin-x86_64\"][\"url\"].rsplit(\"/\",1)[1])" "$2/latest.json")" == "Mooring_aarch64.app.tar.gz Mooring_universal.app.tar.gz" ]]' _ "$SCRIPT" "$arch"

# ADR-0021: portable zips are not updater artifacts. Without a .sig they are ignored like
# every other plain asset; with a .sig the manifest is refused outright.
port=$(dist port Mooring_1.2.3_x64_portable.zip Mooring_1.2.3_universal_portable.zip -- \
  Mooring_universal.app.tar.gz Mooring_1.2.3_x64-setup.exe)
check "portable zips without .sig are ignored" bash -c 'bash "$1" "$2" v1.2.3 >/dev/null 2>&1 && [[ "$(python3 -I -c "import json,sys;print(len(json.load(open(sys.argv[1]))[\"platforms\"]))" "$2/latest.json")" == 3 ]] && ! grep -q portable "$2/latest.json"' _ "$SCRIPT" "$port"
portsig=$(dist portsig -- Mooring_universal.app.tar.gz Mooring_1.2.3_x64_portable.zip)
check "a .sig for a portable zip fails" runfails "$portsig" v1.2.3
check "  and writes no manifest" [ ! -e "$portsig/latest.json" ]
anyzip=$(dist anyzip -- Mooring_universal.app.tar.gz Mooring_1.2.3_x64.zip)
check "a .sig for any other zip fails" runfails "$anyzip" v1.2.3

# unsigned build (fork, no key): no manifest, exit 0
none=$(dist none a.dmg b.msi)
check "no .sig files: exit 0 and no latest.json" bash -c 'bash "$1" "$2" v1.2.3 >/dev/null 2>&1 && [[ ! -e "$2/latest.json" ]]' _ "$SCRIPT" "$none"

# failures
orphan=$(dist orphan -- Mooring_1.2.3_amd64.AppImage); rm "$orphan/Mooring_1.2.3_amd64.AppImage"
check "a .sig without its artifact fails" runfails "$orphan" v1.2.3
dup=$(dist dup -- Mooring_1.2.3_amd64.AppImage Mooring_1.2.3_x86_64.AppImage)
check "two artifacts for one platform fail" runfails "$dup" v1.2.3
odd=$(dist odd -- Mooring_1.2.3.deb)
check "a signed artifact of unknown kind fails" runfails "$odd" v1.2.3
badsig=$(dist badsig -- Mooring_1.2.3_amd64.AppImage); echo 'not base64 !!' >"$badsig/Mooring_1.2.3_amd64.AppImage.sig"
check "a .sig that is not base64 fails" runfails "$badsig" v1.2.3
check "a bad tag fails" runfails "$full" 1.2.3
check "a bad repo fails" runfails "$full" v1.2.3 "evil;rm"
check "a missing dist dir fails" runfails "$WORK/nope" v1.2.3

echo "$pass passed, $fail failed"
((fail == 0))
