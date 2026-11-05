# Development

## Toolchain

Verified with:

- Xcode 27.0 (Swift 6.4, macOS 26 SDK) and macOS 26.7.
- Rust 1.91.1 stable (`rust-version = "1.91"`).
- XcodeGen.

Deployment target: macOS 15.0.

Dependency pins worth knowing:

- `sqlx` is held at 0.8.x because 0.9 requires Rust 1.94.
- `reqwest` 0.13 uses rustls with `aws-lc-rs` and the platform certificate verifier (macOS trust store).

```bash
brew install xcodegen
rustup target add aarch64-apple-darwin            # default on Apple silicon
rustup target add x86_64-apple-darwin             # only for universal packages
```

## Layout

```
rust/                 Cargo workspace (engine, FFI, CLI)
  crates/spectre-ffi/include/   C header + module map consumed by Swift
macos/project.yml     XcodeGen spec that generates macos/Spectre.xcodeproj (committed)
macos/Spectre/        App sources (App, Features/*, Components, Models, Services, DesignSystem, Resources)
macos/SpectreTests/   Swift Testing suites
tests/fixtures/       Shared fixtures (HIBP responses captured from the documented test account)
tests/integration/    CLI end-to-end test (offline)
scripts/              build, test, package, Xcode Rust build phase
```

## Build and run

```bash
scripts/build.sh                 # Debug: Rust workspace + app
scripts/build.sh release
open build/DerivedData/Build/Products/Debug/Spectre.app
```

In Xcode, open `macos/Spectre.xcodeproj` and run the Spectre scheme. The *Build Rust engine* phase (`scripts/build-rust-xcode.sh`) compiles `spectre-ffi` as a static library for the active architectures into `rust/target/xcode/<Configuration>/`. Swift imports it as the `SpectreFFI` module.

After changing `project.yml`, regenerate the project with `cd macos && xcodegen generate`.

The app stores its database at `~/Library/Containers/io.portseif.Spectre/Data/Library/Application Support/Spectre/spectre.sqlite`.

## CLI

```bash
cd rust && cargo run -p spectre-cli -- --db :memory: investigate username octocat --purpose "Self-assessment of my accounts"
cargo run -p spectre-cli -- providers
echo 'candidate' | cargo run -p spectre-cli -- password-check
cargo run -p spectre-cli -- hash-inventory /path/to/authorized-export.txt
cargo run -p spectre-cli -- breach-catalog --refresh adobe
cargo run --release -p spectre-cli -- bench username octocat --runs 3
cargo run -p spectre-cli -- call engine.diagnostics
```

Credentials come from `SPECTRE_HIBP_API_KEY` and `SPECTRE_GITHUB_TOKEN`. The default database is `~/Library/Application Support/Spectre/cli.sqlite` (override with `--db` or `SPECTRE_DB`). Set `SPECTRE_LOG=debug` for engine tracing on stderr.

## Tests

```bash
scripts/test.sh                  # everything below
SKIP_SWIFT=1 scripts/test.sh     # Rust + CLI only
```

| Suite | Command | Coverage |
|---|---|---|
| Rust unit/integration | `cargo test --workspace` | Validation, HTTP policy/retry/cache/cancel, providers (mock servers), correlation, breach and risk, audit, storage and migrations, engine streaming/concurrency/cancellation/authorization, FFI |
| Lint | `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings` | |
| CLI | `tests/integration/cli_offline.sh` | Offline investigation, exports, authorization gates, hash inventory, deletion |
| Swift | `xcodebuild ... test` | Real Rust engine via FFI (offline), view-model state transitions with scripted engines, decoding, PDF report, graph layout and filters |

No test calls live external APIs. For manual live checks, use HIBP's test key with `multiple-breaches@hibp-integration-tests.com` (attest ownership first).

## Packaging and signing

```bash
scripts/package.sh                                   # ad-hoc signed zip + dmg
SPECTRE_SIGNING_IDENTITY="Developer ID Application: Name (TEAMID)" \
SPECTRE_TEAM_ID=TEAMID SPECTRE_NOTARY_PROFILE=spectre \
SPECTRE_UNIVERSAL=1 scripts/package.sh               # Developer ID, notarized, universal
```

- The app is sandboxed with `network.client` and `files.user-selected.read-write` entitlements and the hardened runtime enabled.
- Create a notary profile once with `xcrun notarytool store-credentials spectre --apple-id <id> --team-id <team>`.
- Debug builds are ad-hoc signed (Sign to Run Locally). Keychain items written by an ad-hoc build can prompt again after a rebuild because the code signature changes.

## Conventions

- Rust edition 2024, `rustfmt.toml` (max width 140), and clippy clean with `-D warnings`.
- Structured errors (`SpectreError` with a stable `ErrorCode`). Providers never swallow failures.
- Swift 6 strict concurrency. `@Observable` models are `@MainActor`, and every FFI call runs off the main actor.
- Every SwiftUI view file has `#Preview`s backed by `PreviewData` and `PreviewEngine`.
