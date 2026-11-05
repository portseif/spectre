# Architecture

Spectre is a native macOS app (SwiftUI, Swift 6) on top of a reusable Rust engine (Tokio, Reqwest, SQLx/SQLite). The engine has no dependency on the app. It is embedded through a small C ABI and also drives the `spectre` CLI.

```
┌──────────────────────── macOS app (SwiftUI) ────────────────────────┐
│ Features/*  ── AppModel / InvestigationViewModel (@MainActor @Observable)
│                    │ EngineClient protocol (mockable)
│                    ▼
│ Services/RustEngine ── background DispatchQueue ── C ABI (JSON in/out)
│ Services/KeychainStore (API keys)   Services/ReportGenerator (PDF)
└──────────────────────────────────┬──────────────────────────────────┘
                                   │ spectre_ffi.h
┌──────────────────────────────────▼──────────────── Rust workspace ──┐
│ spectre-ffi        C ABI, Tokio runtime, panic guard                 │
│ spectre-discovery  Engine: orchestration, events, JSON API (call)    │
│   ├─ spectre-providers   username / email / phone / domain adapters  │
│   ├─ spectre-breach      HIBP client, catalog provider, risk         │
│   ├─ spectre-audit       Pwned Passwords k-anon, hash inventory      │
│   ├─ spectre-correlation evidence-based identity graph               │
│   └─ spectre-storage     SQLite, migrations, export/import, backup   │
│ spectre-core       model, validation, provider trait, HTTP policy    │
│ spectre-cli        command-line front end over the same engine       │
└──────────────────────────────────────────────────────────────────────┘
```

## Swift ↔ Rust boundary

**Decision: a hand-written C ABI that exchanges JSON. UniFFI is not used.**

UniFFI was evaluated. The API is coarse-grained (roughly 40 methods, each called a few times per user action, with payloads dominated by network latency). For an API like that, UniFFI adds a code-generation step and generated Swift sources to keep in sync, and its async/callback support complicates the build. It buys little type safety over a single JSON dispatcher that is unit-tested in Rust and decoded into Swift `Codable` mirrors. JSON overhead is negligible next to network I/O.

The ABI has seven functions (`rust/crates/spectre-ffi/include/spectre_ffi.h`):

| Function | Purpose |
|---|---|
| `spectre_engine_open(options_json, &error)` | Create the engine (owns a 4-worker Tokio runtime) |
| `spectre_engine_call(engine, method, params_json)` | JSON API dispatch (`Engine::call`) |
| `spectre_engine_poll_events(engine, id, max, timeout_ms)` | Blocking wait for streamed events |
| `spectre_check_password(engine, bytes, len)` | Password check; bytes, never JSON |
| `spectre_string_free`, `spectre_engine_close`, `spectre_version` | Lifecycle |

Responses are envelopes: `{"ok": …}` or `{"error": {"code", "message"}}`. Error codes are stable (`invalid_input`, `authorization_required`, `credentials_missing`, `rate_limited`, `policy_violation`, …). Every entry point is wrapped in `catch_unwind`.

On the Swift side, `RustEngine` runs every blocking call on a private concurrent `DispatchQueue` and bridges it with continuations, so nothing touches the main actor. Event streaming is an `AsyncThrowingStream` fed by a background loop that calls `spectre_engine_poll_events` with a 250 ms timeout.

### JSON API

`Engine::call(method, params)` in `spectre-discovery/src/api.rs` is the single dispatcher. Methods are grouped by namespace: `investigation.*` (start, cancel, get, list, delete, events, correlate, export_json, export_csv, import), `relationship.decide`, `verification.*`, `breach.*`, `audit.*`, `settings.*`, `providers.*`, `credentials.*`, `privacy.purge`, `storage.*`, `dashboard.stats`, `engine.diagnostics`, and `target.validate`.

## Investigation lifecycle

1. `investigation.start` validates and normalizes the target, requires an authorization record of at least 10 characters, selects enabled providers that support the target type, persists the investigation, and writes an audit event.
2. A Tokio task fans out to the providers through `FuturesUnordered`. A **global semaphore** (`max_concurrency`, default 4) bounds concurrent provider work across all investigations. Each provider also has a deadline (`provider_timeout_secs`) and a cancellation token.
3. Each provider result is persisted **immediately** and emitted as events (`provider_started`, `finding_discovered`, `provider_completed` / `provider_failed`, `progress`), so the UI updates before slower providers finish.
4. When every provider is done, correlation runs. It writes the identity graph and updates profile-finding confidence, then emits `correlation_updated` and finally `finished` with metrics.
5. Final status: `completed` (no failures), `partially_completed` (some failures), `failed` (every provider failed or was cancelled), or `cancelled`. Investigations left running by a crashed process are marked `failed` on the next launch.

Events live in an in-memory per-investigation queue (`events.rs`). Producers never block. Consumers wait on a `Condvar` (FFI) or through `spawn_blocking` (CLI). A queue is removed once its terminal event has been drained.

### Metrics

Every run records startup latency (request to first provider dispatch), time to first finding, total duration, per-provider latency and outcome, HTTP request count, and cache hits and misses. They appear under *Run Details* in the app and in `spectre bench`.

Measured on this machine (2026-11-05, release build, live APIs, username with 13 providers):

| Run | Startup | First finding | Total | Requests | Cache hit rate |
|---|---|---|---|---|---|
| Cold | 1 ms | 745 ms | 2,371 ms | 14 | 0% |
| Warm (cache) | 0 ms | 0 ms | 5–7 ms | 0 | 100% |

Peak RSS of the CLI process across all three runs was 31 MB. GitHub was the slowest provider (2.3 s).

## HTTP layer (`spectre-core/src/http.rs`)

- One shared `reqwest::Client` (connection pooling, rustls with the platform verifier).
- An **endpoint allowlist**: HTTPS only, port 443, no IP literals, no URL credentials. Only hosts that providers declare are allowed. Redirects are re-checked against the same policy.
- Per-provider **rate limiting** (even spacing, configurable per provider).
- **Retries** on timeouts, connection errors, 429, and 5xx. Backoff is exponential with "equal jitter", capped at 8 s. `Retry-After` is honored up to 30 s; beyond that the 429 goes back to the provider instead of stalling the run.
- A bounded in-memory **response cache** (TTL configurable, 2xx and 404 only, 1,024 entries). Ownership challenges and breach lookups bypass it.
- `fetch_public_web` for the investigated domain's own website: DNS is resolved first, every address must be public, the connection is pinned to those addresses to prevent DNS rebinding, and redirects are followed manually and re-validated.
- Body size caps of 8 MiB for APIs and 1 MiB for web pages.

## Identity correlation (`spectre-correlation`)

Findings become an identity graph. Nodes are usernames, profiles, emails, phones, domains, websites, and breaches. Each edge carries explainable evidence items, and weights combine with a noisy-OR, `1 − Π(1 − wᵢ)`.

| Signal | Weight |
|---|---|
| Exact username match | 0.35 |
| Explicit link (profile links to the URL or handle) | 0.60 |
| Platform-verified link (Keybase proof, Mastodon `rel="me"`, Gravatar verified account) | 0.75 |
| Mutual link | 0.40 |
| Corroborating link with another target-matching profile | 0.45 (0.60 if verified) |
| Shared public email | 0.60 |
| Shared website | 0.25 |
| Matching display name (two or more words or eight or more characters) | 0.15 |
| Gravatar profile registered to the investigated address | 0.80 |

Categories, applied in order:

1. An investigator rejection gives **Unrelated**. An investigator confirmation or verified ownership gives **Confirmed**.
2. A score of at least 0.75 *plus* at least one explicit-link signal gives **Strong Evidence**.
3. A score of at least 0.40 gives **Possible**. Anything lower is **Weak Evidence**.

A username match alone (0.35) is therefore always Weak Evidence. Coincidental signals such as names and websites can never reach Strong Evidence without an explicit link. Identity and relationship IDs are UUIDv5 values derived from canonical values, so investigator decisions survive re-correlation.

## Storage (`spectre-storage`)

SQLite in WAL mode with `foreign_keys=ON`, `secure_delete=ON`, file mode `0600`, and embedded versioned migrations (`migrations/0001_initial.sql`).

Tables: `investigations`, `investigation_targets`, `investigation_errors`, `findings`, `finding_sources`, `profiles`, `identities`, `identity_relationships`, `email_addresses`, `phone_numbers`, `domains`, `breach_incidents`, `breach_exposures`, `provider_configs`, `audit_events`, `engine_settings`.

Investigation-scoped tables cascade on delete. `audit_events` deliberately has no foreign key, so the accountability trail outlives deletion; it never contains passwords, hashes, or keys.

Other storage features:

- Deletes are followed by `PRAGMA wal_checkpoint(TRUNCATE)`.
- Backups use `VACUUM INTO`.
- Restores validate integrity and schema version before replacing the file.
- Exports are versioned bundles (`spectre.investigation` v1). Imports re-validate targets.

## macOS app

- `AppModel` (root) and `InvestigationViewModel` (per investigation, persisted per ID) are `@MainActor @Observable`. Derived collections such as grouped finding sections are cached as stored properties.
- Layout: `NavigationSplitView` (sidebar plus detail) with `.inspector` attached to the detail column.
- The identity graph is a native `Canvas` with a deterministic Fruchterman–Reingold layout computed off the main actor. It supports pinch and button zoom, drag to pan, click to select nodes or edges, kind and confidence filters, and collapsing leaf neighbors. The relationship list beside it is the accessible alternative.
- PDF reports use Core Text pagination into a `CGContext` PDF and are previewed with PDFKit. JSON and CSV come from the engine. CSV cells are neutralized against formula injection.
