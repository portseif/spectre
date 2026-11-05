# Spectre

Spectre is a macOS app for OSINT investigations you are authorized to run. The interface is SwiftUI. Underneath is a Rust engine that also works on its own, from the command line or embedded in another app.

You give it a username, email address, phone number or domain. It queries public sources, links what it finds into an identity graph with the evidence behind each link, and can check breach exposure for addresses whose ownership you have verified. Reports export as PDF, JSON or CSV.

Spectre won't enumerate private accounts, get around CAPTCHAs or rate limits, or recover anyone's passwords. Every investigation needs a written authorization basis before it starts. The details are in [docs/security.md](docs/security.md).

## What it looks up

| Input | Sources |
|---|---|
| Username | 13 platforms through their documented APIs (GitHub, GitLab, Codeberg, Keybase, Mastodon, Bluesky, Hacker News, DEV, Hugging Face, Docker Hub, Chess.com, Lichess, Wikipedia), plus profile-page checks on 34 more sites from a catalog Spectre maintains and self-tests |
| Email | Mail-domain checks (MX, implicit MX, null MX, SPF, DMARC), public Gravatar profiles and OpenPGP keys on keys.openpgp.org. Have I Been Pwned breach data once ownership is verified |
| Phone | E.164 normalization, country code, region and line type from offline numbering-plan data. There are no reverse lookups and no location guessing |
| Domain | DNS records and mail security, RDAP registration, Certificate Transparency hostnames, Wayback Machine history, the homepage's security headers, rel="me" links and security.txt, and public breach history for the service |

Results appear as each provider answers, and you can cancel a run at any point. When a run finishes, the Follow-ups tab lists the identifiers it turned up (linked handles, published addresses, websites, other addresses on a PGP key). Spectre never investigates those on its own, but one click opens a new investigation with the target filled in.

Correlation puts every relationship in a category (Confirmed, Strong Evidence, Possible, Weak Evidence or Unrelated) and lists the evidence for it. A username match on its own always lands at Weak Evidence. You can confirm or reject any relationship, and the decision survives when correlation reruns. The identity graph is a native view you can zoom, filter and collapse.

The audit tools check a password against Pwned Passwords (only the first 5 characters of its SHA-1 hash leave the Mac) and inventory how a system stores password hashes against OWASP guidance. PDF reports keep confirmed findings separate from inferred ones.

Everything stays on the Mac. Investigations live in SQLite inside the app sandbox, with secure delete, 0600 permissions, retention and backups. API keys go in the Keychain and nowhere else.

## Getting started

```bash
scripts/build.sh
open build/DerivedData/Build/Products/Debug/Spectre.app
```

You can also open `macos/Spectre.xcodeproj` in Xcode and run the Spectre scheme. The Rust engine builds as part of it. Install XcodeGen (`brew install xcodegen`) only if you plan to edit `macos/project.yml`.

The CLI runs the same engine:

```bash
cd rust
cargo run -p spectre-cli -- --db :memory: investigate username octocat --purpose "Self-assessment of my own accounts"
```

Three credentials are optional and live in Settings > Providers. A Have I Been Pwned API key is needed for account breach lookups. A GitHub token raises GitHub's rate limit, and a Cert Spotter key lifts its free tier of 10 lookups an hour. Nothing else needs a paid API.

## Tests

```bash
scripts/test.sh
```

The script runs `cargo fmt --check`, clippy with warnings as errors, 101 Rust tests, an offline CLI end-to-end test and 20 Swift tests. Some of the Swift tests call the real engine over the FFI. No test touches a live external API.

## Layout

```
rust/      Cargo workspace: core, providers, correlation, breach, audit, storage, discovery (engine), ffi, cli
macos/     SwiftUI app (XcodeGen project.yml plus the generated Spectre.xcodeproj) and Swift tests
docs/      architecture, providers, security, development
tests/     shared fixtures and the CLI integration test
scripts/   build, test, package, and the Xcode build phase for Rust
```

[docs/architecture.md](docs/architecture.md) covers the design: why the FFI is plain C, how concurrency works, the correlation weights, the storage schema and measured performance.

## License

MIT. Breach data comes from Have I Been Pwned under CC BY 4.0.
