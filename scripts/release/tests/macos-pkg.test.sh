#!/usr/bin/env bash
# Tests for the ADR-0028 guard in macos-pkg.sh: a release run (tag ref or MOORING_RELEASE_BUILD=1)
# refuses an .app with the `.dev` identifier. PlistBuddy is stubbed; the packaging tools are
# not, so a run that passes the guard stops later (pkgbuild/lipo are macOS-only) and only the
# guard's verdict is checked here.
# Run: scripts/release/tests/macos-pkg.test.sh (or tests/run.sh for all)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/../macos-pkg.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0
mkdir -p "$WORK/Mooring.app/Contents" "$WORK/bin"
cat >"$WORK/bin/PlistBuddy" <<'EOF'
#!/usr/bin/env bash
case "$2" in
  "Print :CFBundleIdentifier") echo "$FAKE_ID" ;;
  "Print :CFBundleExecutable") echo Mooring ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$WORK/bin/PlistBuddy"

expect() { # expect <refused|passes> <label> <env...>
  local want="$1" label="$2" rc=0 refused=no; shift 2
  env PLISTBUDDY="$WORK/bin/PlistBuddy" GITHUB_REF= MOORING_RELEASE_BUILD= "$@" \
    bash "$SCRIPT" "$WORK/Mooring.app" 1.2.3 "$WORK/out.pkg" >"$WORK/out" 2>&1 || rc=$?
  grep -q "development identifier" "$WORK/out" && ((rc != 0)) && refused=yes
  if { [[ "$want" == refused && "$refused" == yes ]] || [[ "$want" == passes && "$refused" == no ]]; }; then
    pass=$((pass + 1)); echo "ok   $label"
  else
    fail=$((fail + 1)); echo "FAIL $label (wanted $want)"; sed 's/^/     /' "$WORK/out"
  fi
}

expect refused ".dev id on a tag build" FAKE_ID=io.github.yyasar21.mooring.dev GITHUB_REF=refs/tags/v1.2.3
expect refused ".dev id with MOORING_RELEASE_BUILD=1" FAKE_ID=io.github.yyasar21.mooring.dev MOORING_RELEASE_BUILD=1
expect passes ".dev id on a branch (local .pkg of a dev build)" FAKE_ID=io.github.yyasar21.mooring.dev GITHUB_REF=refs/heads/main
expect passes "release id on a tag build" FAKE_ID=io.github.yyasar21.mooring GITHUB_REF=refs/tags/v1.2.3

echo "$pass passed, $fail failed"
((fail == 0))
