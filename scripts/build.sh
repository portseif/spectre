#!/usr/bin/env bash
# Build the Rust workspace and the macOS app.
#   scripts/build.sh            Debug build
#   scripts/build.sh release    Release build
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIGURATION="Debug"
[[ "${1:-}" == "release" ]] && CONFIGURATION="Release"

echo "==> Rust workspace ($CONFIGURATION)"
if [[ "$CONFIGURATION" == "Release" ]]; then
  (cd "$ROOT/rust" && cargo build --workspace --release)
else
  (cd "$ROOT/rust" && cargo build --workspace)
fi

echo "==> macOS app ($CONFIGURATION)"
if command -v xcodegen >/dev/null 2>&1; then
  (cd "$ROOT/macos" && xcodegen generate --quiet)
fi
xcodebuild -project "$ROOT/macos/Spectre.xcodeproj" -scheme Spectre -configuration "$CONFIGURATION" \
  -derivedDataPath "$ROOT/build/DerivedData" build -quiet
echo "App: $ROOT/build/DerivedData/Build/Products/$CONFIGURATION/Spectre.app"
