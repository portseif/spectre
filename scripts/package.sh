#!/usr/bin/env bash
# Build a signed, distributable Spectre.app (zip + dmg).
#
# Environment:
#   SPECTRE_SIGNING_IDENTITY  "Developer ID Application: Name (TEAMID)". Omit for ad-hoc.
#   SPECTRE_TEAM_ID           Team ID for the signing identity.
#   SPECTRE_NOTARY_PROFILE    notarytool keychain profile (xcrun notarytool store-credentials).
#   SPECTRE_UNIVERSAL=1       Build arm64 + x86_64 (needs: rustup target add x86_64-apple-darwin).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/build/package"
DERIVED="$ROOT/build/DerivedData"
IDENTITY="${SPECTRE_SIGNING_IDENTITY:--}"
ARCHS="arm64"
[[ "${SPECTRE_UNIVERSAL:-0}" == "1" ]] && ARCHS="arm64 x86_64"

rm -rf "$OUT" && mkdir -p "$OUT"
SIGNING=(CODE_SIGN_IDENTITY="$IDENTITY" CODE_SIGN_STYLE=Manual ENABLE_HARDENED_RUNTIME=YES OTHER_CODE_SIGN_FLAGS=--timestamp)
[[ -n "${SPECTRE_TEAM_ID:-}" ]] && SIGNING+=(DEVELOPMENT_TEAM="$SPECTRE_TEAM_ID")
[[ "$IDENTITY" == "-" ]] && SIGNING=(CODE_SIGN_IDENTITY=- ENABLE_HARDENED_RUNTIME=YES)

echo "==> Release build ($ARCHS, identity: $IDENTITY)"
xcodebuild -project "$ROOT/macos/Spectre.xcodeproj" -scheme Spectre -configuration Release \
  -derivedDataPath "$DERIVED" ARCHS="$ARCHS" ONLY_ACTIVE_ARCH=NO "${SIGNING[@]}" build -quiet

APP="$DERIVED/Build/Products/Release/Spectre.app"
cp -R "$APP" "$OUT/"
codesign --verify --deep --strict --verbose=2 "$OUT/Spectre.app"
VERSION="$(defaults read "$OUT/Spectre.app/Contents/Info" CFBundleShortVersionString)"

echo "==> Archives"
ditto -c -k --keepParent "$OUT/Spectre.app" "$OUT/Spectre-$VERSION.zip"
hdiutil create -volname "Spectre $VERSION" -srcfolder "$OUT/Spectre.app" -ov -format UDZO "$OUT/Spectre-$VERSION.dmg" >/dev/null

if [[ -n "${SPECTRE_NOTARY_PROFILE:-}" && "$IDENTITY" != "-" ]]; then
  echo "==> Notarizing"
  xcrun notarytool submit "$OUT/Spectre-$VERSION.dmg" --keychain-profile "$SPECTRE_NOTARY_PROFILE" --wait
  xcrun stapler staple "$OUT/Spectre-$VERSION.dmg"
else
  echo "Skipping notarization (set SPECTRE_SIGNING_IDENTITY and SPECTRE_NOTARY_PROFILE)."
fi
echo "Artifacts in $OUT"
