# Spectre

A native macOS OSINT investigation platform for **authorized** investigations. It combines a SwiftUI app with a reusable Rust engine:

- public profile discovery
- email, phone, and domain intelligence
- evidence-based identity correlation
- ownership-gated breach exposure checks
- k-anonymity password checks
- password-hash storage audits
- PDF, JSON, and CSV reports

> Spectre is for self-assessment, consented assessments, and scoped engagements. Every investigation requires a recorded authorization basis. Breach data is only requested for ownership-verified addresses. Spectre never enumerates private accounts, bypasses protections, or recovers credentials. See [docs/security.md](docs/security.md).

## What it does

| Input | Discovery |
|---|---|
| **Username** | GitHub, GitLab, Codeberg, Keybase (signed proofs), Mastodon (rel="me" verified links), Bluesky, Hacker News, DEV, Hugging Face, Docker Hub, Chess.com, Lichess, Wikipedia — all through documented public APIs |
| **Email** | Syntax validation, MX / implicit MX / null MX, SPF, DMARC, and public Gravatar profiles. Breach exposure via Have I Been Pwned after ownership verification |
| **Phone** | E.164 normalization, country code, region, and line type from offline numbering-plan metadata. No reverse lookups or location inference |
| **Domain** | DNS records and mail-security posture, RDAP registration, the site's `rel="me"` links and `security.txt`, and public breach history of the service |

Other features:

- **Streaming results.** Findings appear as each provider responds. Investigations can be cancelled at any time.
- **Identity correlation.** Explainable evidence weights, categorized as Confirmed, Strong Evidence, Possible, Weak Evidence, or Unrelated. A matching username alone is always Weak Evidence. Investigators confirm or reject associations, and those decisions persist.
- **Identity graph.** A native, zoomable graph with filters, collapsing, and an evidence inspector.
- **Security audits.** A Pwned Passwords k-anonymity check (only a 5-character hash prefix leaves the Mac), plus an OWASP-based hash storage inventory for administrators.
- **Reports.** PDF (Core Text and PDFKit) that separates confirmed findings from inferred associations, plus JSON bundles (importable) and CSV.
- **Local and private.** SQLite in the app sandbox (secure delete, 0600 permissions, retention, backup and restore). API keys live in the Keychain only.

## Quick start

```bash
brew install xcodegen          # only needed if you change macos/project.yml
scripts/build.sh
open build/DerivedData/Build/Products/Debug/Spectre.app
```

Or open `macos/Spectre.xcodeproj` in Xcode and run the **Spectre** scheme; the Rust engine builds automatically.

The CLI shares the same engine:

```bash
cd rust
cargo run -p spectre-cli -- --db :memory: investigate username octocat --purpose "Self-assessment of my own accounts"
```

Optional credentials, set in Settings → Providers (stored in the Keychain):

- a **Have I Been Pwned API key**, required for account breach lookups
- a **GitHub token**, which raises the rate limit

Everything else works without paid APIs.

## Tests

```bash
scripts/test.sh
```

This runs `cargo fmt --check`, `clippy -D warnings`, 88 Rust tests, an offline CLI end-to-end test, and 17 Swift tests (including tests against the real engine over FFI). None call live external APIs.

## Repository

```
rust/        Cargo workspace: core · providers · correlation · breach · audit · storage · discovery (engine) · ffi · cli
macos/       SwiftUI app (XcodeGen project.yml + generated Spectre.xcodeproj) and Swift tests
docs/        architecture · providers · security · development
tests/       shared fixtures and CLI integration test
scripts/     build · test · package · Xcode Rust build phase
```

See [docs/architecture.md](docs/architecture.md) for the design, including the FFI decision, concurrency model, correlation weights, storage schema, and measured performance.

## License

MIT. Breach data © Have I Been Pwned, used under CC BY 4.0.
