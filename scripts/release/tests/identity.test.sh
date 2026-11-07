#!/usr/bin/env bash
# Tests for the ADR-0028 build identity: merge-config.py's RFC 7396 merge (self-test), the
# repository's tauri.conf.json (dev) + tauri.release.conf.json (release) pair, and fixtures
# where one identity rule is broken, each of which must fail check-identity.
# Run: scripts/release/tests/identity.test.sh (or tests/run.sh for all)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
SCRIPT="$HERE/../merge-config.py"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0

expect() { # expect <0|nonzero> <label> <command...>
  local want="$1" label="$2" rc=0; shift 2
  "$@" >"$WORK/out" 2>&1 || rc=$?
  if { [[ "$want" == 0 ]] && ((rc == 0)); } || { [[ "$want" != 0 ]] && ((rc != 0)); }; then
    pass=$((pass + 1)); echo "ok   $label (exit $rc)"
  else
    fail=$((fail + 1)); echo "FAIL $label (exit $rc, wanted $want)"; sed 's/^/     /' "$WORK/out"
  fi
}

# A copy of the two configs next to links to the real icon sets and DMG background.
fixture() { # fixture <name> <python edit of (base, overlay)> -> src-tauri dir
  local d="$WORK/$1"; mkdir -p "$d/src-tauri" "$d/packaging/macos"
  cp "$ROOT/src-tauri/tauri.conf.json" "$ROOT/src-tauri/tauri.release.conf.json" "$d/src-tauri/"
  ln -s "$ROOT/src-tauri/icons" "$d/src-tauri/icons"
  ln -s "$ROOT/src-tauri/icons-dev" "$d/src-tauri/icons-dev"
  ln -s "$ROOT/packaging/macos/dmg-background.png" "$d/packaging/macos/dmg-background.png"
  python3 -I - "$d/src-tauri" "$2" <<'PY'
import json, sys
d, edit = sys.argv[1], sys.argv[2]
paths = {"base": f"{d}/tauri.conf.json", "overlay": f"{d}/tauri.release.conf.json"}
docs = {k: json.load(open(p)) for k, p in paths.items()}
base, overlay = docs["base"], docs["overlay"]
exec(edit)
for k, p in paths.items():
    json.dump(docs[k], open(p, "w"), indent=2)
PY
  echo "$d/src-tauri"
}

check() { python3 -I "$SCRIPT" check-identity "$1"; }

expect 0 "RFC 7396 self-test" python3 -I "$SCRIPT" self-test
expect 0 "the repository's own configs" python3 -I "$SCRIPT" check-identity
expect 0 "unchanged fixture" check "$(fixture good 'pass')"

got=$(python3 -I "$SCRIPT" merge "$ROOT/src-tauri/tauri.conf.json" --get /identifier)
[[ "$got" == io.github.yyasar21.mooring.dev ]] && { pass=$((pass + 1)); echo "ok   base identifier is .dev"; } \
  || { fail=$((fail + 1)); echo "FAIL base identifier is $got"; }
got=$(python3 -I "$SCRIPT" merge "$ROOT/src-tauri/tauri.conf.json" "$ROOT/src-tauri/tauri.release.conf.json" --get /identifier)
[[ "$got" == io.github.yyasar21.mooring ]] && { pass=$((pass + 1)); echo "ok   base+overlay identifier is the release id"; } \
  || { fail=$((fail + 1)); echo "FAIL base+overlay identifier is $got"; }

# The CI keys release.yml adds on top keep the release identity and turn updater artifacts off.
printf '{"bundle":{"createUpdaterArtifacts":false,"windows":{"wix":{"version":"0.2.0"}}}}' >"$WORK/ci.json"
got=$(python3 -I "$SCRIPT" merge "$ROOT/src-tauri/tauri.conf.json" "$ROOT/src-tauri/tauri.release.conf.json" "$WORK/ci.json" --get /bundle/windows/wix)
python3 -I -c 'import json,sys; w=json.loads(sys.argv[1]); sys.exit(0 if w=={"language":"en-US","upgradeCode":"1f940c60-f3be-5e3f-81de-92ee690e0b6d","version":"0.2.0"} else 1)' "$got" \
  && { pass=$((pass + 1)); echo "ok   overlay then CI keys: wix merged key by key"; } \
  || { fail=$((fail + 1)); echo "FAIL overlay then CI keys: $got"; }

expect nonzero "base carries the release identifier" check "$(fixture relbase 'base["identifier"] = "io.github.yyasar21.mooring"')"
expect nonzero "base productName is Mooring" check "$(fixture relname 'base["productName"] = "Mooring"')"
expect nonzero "base has an updater pubkey" check "$(fixture pubkey 'base["plugins"] = {"updater": {"pubkey": "abc"}}')"
expect nonzero "base creates updater artifacts" check "$(fixture artifacts 'base["bundle"]["createUpdaterArtifacts"] = True')"
expect nonzero "base reuses the release upgradeCode" check "$(fixture upg 'base["bundle"]["windows"]["wix"]["upgradeCode"] = "1f940c60-f3be-5e3f-81de-92ee690e0b6d"')"
expect nonzero "base uses release icons" check "$(fixture icons 'base["bundle"]["icon"] = overlay["bundle"]["icon"]')"
expect nonzero "overlay without identifier" check "$(fixture noid 'del overlay["identifier"]')"
expect nonzero "overlay changes the release upgradeCode" check "$(fixture relupg 'overlay["bundle"]["windows"]["wix"]["upgradeCode"] = "00000000-0000-5000-8000-000000000000"')"
expect nonzero "overlay without pubkey" check "$(fixture nokey 'del overlay["plugins"]')"
expect nonzero "overlay sets requireSignedVersion false" check "$(fixture rsv 'overlay["plugins"]["updater"]["requireSignedVersion"] = False')"
expect nonzero "overlay sets a version" check "$(fixture ver 'overlay["version"] = "9.9.9"')"
expect nonzero "overlay window drifted from base" check "$(fixture drift 'base["app"]["windows"][0]["minWidth"] = 800')"
expect nonzero "overlay replaces app.security" check "$(fixture sec 'overlay["app"]["security"] = {"csp": None}')"
expect nonzero "overlay icon missing on disk" check "$(fixture iconfile 'overlay["bundle"]["icon"][0] = "icons/nope.png"')"
expect nonzero "dmg layout only in the overlay" check "$(fixture dmg 'overlay["bundle"]["macOS"] = {"dmg": {"windowSize": {"width": 1, "height": 1}}}')"
expect nonzero "dmg layout missing" check "$(fixture nodmg 'del base["bundle"]["macOS"]["dmg"]')"

echo "$pass passed, $fail failed"
((fail == 0))
