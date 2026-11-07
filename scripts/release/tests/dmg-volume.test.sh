#!/usr/bin/env bash
# Tests for dmg-volume.sh with stub `hdiutil` and `diskutil` (no macOS needed): the command
# plan (UDRW -> attach -> rename -> detach -> UDZO -> verify -> replace), the volume-name
# shape, and refusals when the Finder layout is missing or the rename disturbs the volume.
# The real run (and the visual "does the background survive" check) is the macOS rc dry run.
# Run: scripts/release/tests/dmg-volume.test.sh (or tests/run.sh for all)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/../dmg-volume.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0
mkdir -p "$WORK/bin"

# hdiutil: convert copies (and tags the format), attach fills the mount point from $LAYOUT,
# everything is logged to $LOG.
cat >"$WORK/bin/hdiutil" <<'EOF'
#!/usr/bin/env bash
echo "hdiutil $*" >>"$LOG"
case "$1" in
  convert) in="$2"; out=""; fmt=""
           while (($#)); do case "$1" in -o) out="$2" ;; -format) fmt="$2" ;; esac; shift; done
           { cat "$in"; echo "fmt=$fmt"; } >"$out" ;;
  attach) mnt=""; while (($#)); do [[ "$1" == -mountpoint ]] && mnt="$2"; shift; done
          cp -a "$LAYOUT/." "$mnt/" ;;
  detach|verify) ;;
  *) exit 2 ;;
esac
EOF
# diskutil: rename records the name (and drops a file when $DROP is set); info reports it.
cat >"$WORK/bin/diskutil" <<'EOF'
#!/usr/bin/env bash
echo "diskutil $*" >>"$LOG"
case "$1" in
  rename) printf '%s' "${FORCE_NAME:-$3}" >"$STATE/name"; [[ -n "${DROP:-}" ]] && rm -rf "$2/$DROP"; exit 0 ;;
  info) printf '   Volume Name:              %s\n' "$(cat "$STATE/name")" ;;
  *) exit 2 ;;
esac
EOF
chmod +x "$WORK/bin/hdiutil" "$WORK/bin/diskutil"

layout() { # layout <name> [no-ds|no-bg] -> dir with the bundler's Finder layout
  local d="$WORK/layout-$1"; mkdir -p "$d/.background"
  echo bg >"$d/.background/dmg-background.png"; echo ds >"$d/.DS_Store"; ln -s /Applications "$d/Applications"
  mkdir -p "$d/Mooring.app"
  case "${2:-}" in no-ds) rm "$d/.DS_Store" ;; no-bg) rm -r "$d/.background" ;; esac
  echo "$d"
}

run() { # run <want 0|nonzero> <label> <layout> <volume name> [env...]
  local want="$1" label="$2" lay="$3" name="$4" rc=0; shift 4
  local case="$WORK/case-$pass-$fail"; mkdir -p "$case/state"
  echo "original" >"$case/Mooring_1.2.3_aarch64.dmg"
  : >"$case/log"
  env PATH="$WORK/bin:$PATH" HDIUTIL="$WORK/bin/hdiutil" DISKUTIL="$WORK/bin/diskutil" \
    LOG="$case/log" STATE="$case/state" LAYOUT="$lay" RUNNER_TEMP="$case" "$@" \
    bash "$SCRIPT" "$case/Mooring_1.2.3_aarch64.dmg" "$name" >"$case/out" 2>&1 || rc=$?
  LAST="$case"
  if { [[ "$want" == 0 ]] && ((rc == 0)); } || { [[ "$want" != 0 ]] && ((rc != 0)); }; then
    pass=$((pass + 1)); echo "ok   $label (exit $rc)"
  else
    fail=$((fail + 1)); echo "FAIL $label (exit $rc, wanted $want)"; sed 's/^/     /' "$case/out"
  fi
}

good=$(layout good)
run 0 "renames a Tauri dmg" "$good" "Mooring 1.2.3"
plan=$(awk '{print $1, $2}' "$LAST/log" | tr '\n' ';')
if [[ "$plan" == "hdiutil convert;hdiutil attach;diskutil rename;diskutil info;hdiutil detach;hdiutil convert;hdiutil verify;" ]]; then
  pass=$((pass + 1)); echo "ok   command plan in order"
else
  fail=$((fail + 1)); echo "FAIL command plan: $plan"
fi
if grep -q -- '-format UDRW' "$LAST/log" && grep -q -- '-format UDZO -imagekey zlib-level=9' "$LAST/log" \
   && grep -q -- '-nobrowse -noautoopen' "$LAST/log" && ! grep -q -- '-force' "$LAST/log"; then
  pass=$((pass + 1)); echo "ok   UDRW in, UDZO out, private mount, no forced detach"
else
  fail=$((fail + 1)); echo "FAIL hdiutil flags"; sed 's/^/     /' "$LAST/log"
fi
if [[ "$(tail -1 "$LAST/Mooring_1.2.3_aarch64.dmg")" == "fmt=UDZO" ]] && ! ls "$LAST"/dmgvol.* >/dev/null 2>&1; then
  pass=$((pass + 1)); echo "ok   input replaced by the UDZO image, work dir removed"
else
  fail=$((fail + 1)); echo "FAIL output not replaced or work dir left behind"
fi

run 0 "a pre-release name" "$good" "Mooring 1.2.3-rc.1"
run 0 "a dev-identity name" "$good" "Mooring Dev 1.2.3"
run nonzero "a name that is not 'Mooring X.Y.Z'" "$good" "Evil 1.2.3"
run nonzero "a name with a path separator" "$good" "Mooring 1.2.3/x"
run nonzero "a name over 27 characters" "$good" "Mooring 1.2.3-rc.1234567890ab"
run nonzero "no .DS_Store (no Finder layout)" "$(layout nods no-ds)" "Mooring 1.2.3"
run nonzero "no .background (no dmg background)" "$(layout nobg no-bg)" "Mooring 1.2.3"
if [[ "$(cat "$LAST/Mooring_1.2.3_aarch64.dmg")" == original ]] && grep -q 'hdiutil detach' "$LAST/log"; then
  pass=$((pass + 1)); echo "ok   refusal leaves the input untouched and detaches"
else
  fail=$((fail + 1)); echo "FAIL refusal changed the input or left the image attached"
fi
run nonzero "the rename did not take" "$good" "Mooring 1.2.3" FORCE_NAME="Mooring"
run nonzero "the rename dropped the background" "$good" "Mooring 1.2.3" DROP=.background

echo "$pass passed, $fail failed"
((fail == 0))
