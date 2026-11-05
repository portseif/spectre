#!/usr/bin/env bash
# Xcode build phase: compile the Rust engine as a static library for the
# architectures Xcode is building, and place it where the linker looks.
set -euo pipefail

export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUST_DIR="$ROOT/rust"
CONFIGURATION="${CONFIGURATION:-Debug}"
OUTPUT_DIR="$RUST_DIR/target/xcode/$CONFIGURATION"
ARCHS="${ARCHS:-$(uname -m)}"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-15.0}"

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo not found. Install Rust from https://rustup.rs" >&2
  exit 1
fi

PROFILE_FLAG=""
PROFILE_DIR="debug"
if [[ "$CONFIGURATION" == "Release" ]]; then
  PROFILE_FLAG="--release"
  PROFILE_DIR="release"
fi

LIBS=()
for ARCH in $ARCHS; do
  case "$ARCH" in
    arm64) TRIPLE="aarch64-apple-darwin" ;;
    x86_64) TRIPLE="x86_64-apple-darwin" ;;
    *) echo "error: unsupported architecture $ARCH" >&2; exit 1 ;;
  esac
  if ! rustup target list --installed 2>/dev/null | grep -q "^$TRIPLE$"; then
    echo "error: Rust target $TRIPLE is not installed. Run: rustup target add $TRIPLE" >&2
    exit 1
  fi
  (cd "$RUST_DIR" && cargo build -p spectre-ffi --lib $PROFILE_FLAG --target "$TRIPLE")
  LIBS+=("$RUST_DIR/target/$TRIPLE/$PROFILE_DIR/libspectre_ffi.a")
done

mkdir -p "$OUTPUT_DIR"
if [[ ${#LIBS[@]} -gt 1 ]]; then
  lipo -create "${LIBS[@]}" -output "$OUTPUT_DIR/libspectre_ffi.a"
else
  cp "${LIBS[0]}" "$OUTPUT_DIR/libspectre_ffi.a"
fi
echo "Rust engine ready: $OUTPUT_DIR/libspectre_ffi.a ($ARCHS)"
