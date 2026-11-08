#!/usr/bin/env bash
# Tests for the gates of macos-sign.sh (ADR-0018 A1) in its dry-run mode, which stops before any
# macOS tool: an incomplete secret set or a stray input file is refused, either notarization
# set is accepted, the plan covers every input. The signing itself needs macOS + a Developer ID
# and is exercised by the rc dry run with MACOS_SIGNING=true.
# Run: scripts/release/tests/macos-sign.test.sh (or tests/run.sh for all)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/../macos-sign.sh"
ENT="$HERE/../../../packaging/macos/entitlements.plist"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0

expect() { # expect <ok|refused> <label> <in-dir> <env...>
  local want="$1" label="$2" in="$3" rc=0; shift 3
  env -i PATH="$PATH" MACOS_SIGN_DRY_RUN=1 "$@" bash "$SCRIPT" "$in" "$WORK/out" 1.2.3 "$ENT" >"$WORK/log" 2>&1 || rc=$?
  if { [[ "$want" == ok ]] && ((rc == 0)); } || { [[ "$want" == refused ]] && ((rc != 0)); }; then
    pass=$((pass + 1)); echo "ok   $label"
  else
    fail=$((fail + 1)); echo "FAIL $label (exit $rc)"; sed 's/^/     /' "$WORK/log"
  fi
}

in="$WORK/in"; mkdir -p "$in"
touch "$in/Mooring_1.2.3_universal.dmg" "$in/Mooring_1.2.3_universal.pkg" \
  "$in/Mooring_universal.app.tar.gz" "$in/Mooring_1.2.3_universal_portable.zip"
CERT=(APPLE_CERTIFICATE=x APPLE_CERTIFICATE_PASSWORD=x "APPLE_SIGNING_IDENTITY=Developer ID Application: Example (TEAMID1234)")
API=(APPLE_API_KEY=ABC123DEF4 APPLE_API_ISSUER=00000000-0000-0000-0000-000000000000 APPLE_API_KEY_PATH=/nonexistent/AuthKey.p8)
AID=(APPLE_ID=dev@example.test APPLE_PASSWORD=x APPLE_TEAM_ID=TEAMID1234)

expect ok "certificate + API key" "$in" "${CERT[@]}" "${API[@]}"
grep -q 'App Store Connect API key' "$WORK/log" && grep -c '^plan: ' "$WORK/log" | grep -qx 4 \
  && { pass=$((pass + 1)); echo "ok     plan covers dmg, pkg, updater archive, portable zip"; } \
  || { fail=$((fail + 1)); echo "FAIL   plan"; sed 's/^/     /' "$WORK/log"; }
expect ok "certificate + Apple ID" "$in" "${CERT[@]}" "${AID[@]}"
expect refused "no certificate" "$in" "${API[@]}"
expect refused "certificate without its password" "$in" APPLE_CERTIFICATE=x "APPLE_SIGNING_IDENTITY=x" "${API[@]}"
expect refused "no notarization set" "$in" "${CERT[@]}"
expect refused "half an API key set" "$in" "${CERT[@]}" APPLE_API_KEY=ABC123DEF4 APPLE_API_ISSUER=x
expect refused "half an Apple ID set" "$in" "${CERT[@]}" APPLE_ID=dev@example.test APPLE_PASSWORD=x

stray="$WORK/stray"; cp -r "$in" "$stray"; touch "$stray/notes.txt"
expect refused "a file that would pass through unsigned" "$stray" "${CERT[@]}" "${API[@]}"
two="$WORK/two"; cp -r "$in" "$two"; touch "$two/Mooring_1.2.3_aarch64.dmg"
expect refused "two dmgs" "$two" "${CERT[@]}" "${API[@]}"
none="$WORK/none"; mkdir -p "$none"
expect refused "no dmg" "$none" "${CERT[@]}" "${API[@]}"

rc=0; env -i PATH="$PATH" MACOS_SIGN_DRY_RUN=1 "${CERT[@]}" "${API[@]}" bash "$SCRIPT" "$in" "$WORK/out" 1.2 "$ENT" >/dev/null 2>&1 || rc=$?
((rc != 0)) && { pass=$((pass + 1)); echo "ok   refuses a malformed version"; } || { fail=$((fail + 1)); echo "FAIL malformed version accepted"; }

echo "$pass passed, $fail failed"
((fail == 0))
