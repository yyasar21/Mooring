#!/usr/bin/env bash
# Wrap a built Mooring.app into a macOS installer package (.pkg) for /Applications.
#
#   scripts/release/macos-pkg.sh <path/to/Mooring.app> <version> <out.pkg>
#
# pkgbuild makes the component package, productbuild the distribution package (title, min OS,
# host architectures). Signing is optional and needs a "Developer ID Installer" certificate,
# which is different from the "Developer ID Application" certificate that signs the .app:
#   APPLE_INSTALLER_CERTIFICATE           base64 .p12
#   APPLE_INSTALLER_CERTIFICATE_PASSWORD  its export password
#   APPLE_INSTALLER_SIGNING_IDENTITY      e.g. "Developer ID Installer: Name (TEAMID)"
# When the installer is signed and APPLE_ID/APPLE_PASSWORD/APPLE_TEAM_ID (or APPLE_API_KEY,
# APPLE_API_ISSUER, APPLE_API_KEY_PATH) are present, the .pkg is notarized and stapled.
set -euo pipefail

APP="${1:?usage: macos-pkg.sh <Mooring.app> <version> <out.pkg>}"
VERSION="${2:?version required}"
OUT="${3:?output path required}"
[[ -d "$APP" ]] || { echo "error: $APP not found" >&2; exit 1; }
plist() { /usr/libexec/PlistBuddy -c "Print :$1" "$APP/Contents/Info.plist"; }
IDENTIFIER="$(plist CFBundleIdentifier)"
MIN_OS="$(plist LSMinimumSystemVersion 2>/dev/null || echo 11.0)"

WORK="$(mktemp -d)"
KEYCHAIN=""
cleanup() {
  if [[ -n "$KEYCHAIN" ]]; then security delete-keychain "$KEYCHAIN" 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# Host architectures from the main executable (arm64, x86_64 or both for universal).
EXE="$APP/Contents/MacOS/$(plist CFBundleExecutable)"
ARCHS="$(lipo -archs "$EXE" | tr ' ' ',')"

mkdir -p "$WORK/root"
ditto "$APP" "$WORK/root/$(basename "$APP")"

cat > "$WORK/component.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><array><dict>
  <key>RootRelativeBundlePath</key><string>$(basename "$APP")</string>
  <key>BundleIsRelocatable</key><false/>
  <key>BundleIsVersionChecked</key><true/>
  <key>BundleHasStrictIdentifier</key><true/>
  <key>BundleOverwriteAction</key><string>upgrade</string>
</dict></array></plist>
PLIST

pkgbuild \
  --root "$WORK/root" \
  --install-location /Applications \
  --identifier "$IDENTIFIER" \
  --version "$VERSION" \
  --component-plist "$WORK/component.plist" \
  "$WORK/component.pkg"

cat > "$WORK/distribution.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
  <title>Mooring ${VERSION}</title>
  <options customize="never" require-scripts="false" hostArchitectures="${ARCHS}"/>
  <domains enable_localSystem="true"/>
  <volume-check><allowed-os-versions><os-version min="${MIN_OS}"/></allowed-os-versions></volume-check>
  <choices-outline><line choice="default"><line choice="${IDENTIFIER}"/></line></choices-outline>
  <choice id="default"/>
  <choice id="${IDENTIFIER}" visible="false"><pkg-ref id="${IDENTIFIER}"/></choice>
  <pkg-ref id="${IDENTIFIER}" version="${VERSION}" onConclusion="none">#component.pkg</pkg-ref>
</installer-gui-script>
XML

SIGN_ARGS=()
if [[ -n "${APPLE_INSTALLER_CERTIFICATE:-}" && -n "${APPLE_INSTALLER_SIGNING_IDENTITY:-}" ]]; then
  KEYCHAIN="$WORK/installer.keychain-db"
  KC_PASS="$(openssl rand -hex 24)"
  security create-keychain -p "$KC_PASS" "$KEYCHAIN"
  security set-keychain-settings -lut 900 "$KEYCHAIN"
  security unlock-keychain -p "$KC_PASS" "$KEYCHAIN"
  printf '%s' "$APPLE_INSTALLER_CERTIFICATE" | base64 --decode > "$WORK/installer.p12"
  security import "$WORK/installer.p12" -k "$KEYCHAIN" -P "${APPLE_INSTALLER_CERTIFICATE_PASSWORD:-}" -T /usr/bin/productbuild
  rm -f "$WORK/installer.p12"
  mapfile -t EXISTING < <(security list-keychains -d user | sed -e 's/^[[:space:]]*"//' -e 's/"$//')
  security list-keychains -d user -s "$KEYCHAIN" "${EXISTING[@]}"
  SIGN_ARGS=(--sign "$APPLE_INSTALLER_SIGNING_IDENTITY" --keychain "$KEYCHAIN" --timestamp)
else
  echo "note: no Developer ID Installer certificate; building an unsigned .pkg" >&2
fi

productbuild --distribution "$WORK/distribution.xml" --package-path "$WORK" ${SIGN_ARGS[@]+"${SIGN_ARGS[@]}"} "$OUT"

if ((${#SIGN_ARGS[@]})); then
  if [[ -n "${APPLE_ID:-}" && -n "${APPLE_PASSWORD:-}" && -n "${APPLE_TEAM_ID:-}" ]]; then
    xcrun notarytool submit "$OUT" --apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" \
      --team-id "$APPLE_TEAM_ID" --wait
    xcrun stapler staple "$OUT"
  elif [[ -n "${APPLE_API_KEY:-}" && -n "${APPLE_API_ISSUER:-}" && -n "${APPLE_API_KEY_PATH:-}" ]]; then
    xcrun notarytool submit "$OUT" --key "$APPLE_API_KEY_PATH" --key-id "$APPLE_API_KEY" \
      --issuer "$APPLE_API_ISSUER" --wait
    xcrun stapler staple "$OUT"
  else
    echo "note: no notarization credentials; .pkg is signed but not notarized" >&2
  fi
fi
echo "built $OUT ($ARCHS)"
