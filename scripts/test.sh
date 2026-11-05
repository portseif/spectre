#!/usr/bin/env bash
# Run every quality gate: Rust fmt/clippy/tests, CLI integration, Swift tests.
# No test depends on live external APIs.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> cargo fmt --check"
(cd "$ROOT/rust" && cargo fmt --all --check)
echo "==> cargo clippy -D warnings"
(cd "$ROOT/rust" && cargo clippy --all-targets --all-features -- -D warnings)
echo "==> cargo test"
(cd "$ROOT/rust" && cargo test --workspace)
echo "==> CLI offline integration"
"$ROOT/tests/integration/cli_offline.sh"

if [[ "${SKIP_SWIFT:-0}" != "1" ]]; then
  echo "==> Swift tests"
  xcodebuild -project "$ROOT/macos/Spectre.xcodeproj" -scheme Spectre -configuration Debug \
    -derivedDataPath "$ROOT/build/DerivedData" test -quiet
fi
echo "All checks passed."
