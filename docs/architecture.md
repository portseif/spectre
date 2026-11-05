# Architecture

Spectre has two halves. The macOS app is SwiftUI on Swift 6. The engine is a Rust workspace (Tokio, Reqwest, SQLx on SQLite) that knows nothing about the app. The app embeds it through a small C ABI, and the `spectre` CLI uses it directly.

```
+------------------------- macOS app (SwiftUI) --------------------------+
| Features/*  -->  AppModel, InvestigationViewModel (@MainActor @Observable)
|                     |  EngineClient protocol (mockable in tests)
|                     v
| Services/RustEngine  -->  background DispatchQueue  -->  C ABI (JSON)
| Services/KeychainStore (API keys)   Services/ReportGenerator (PDF)
+-----------------------------------+-------------------------------------+
                                    |  spectre_ffi.h
+-----------------------------------v---------------- Rust workspace -----+
| spectre-ffi          C ABI, Tokio runtime, panic guard                  |
| spectre-discovery    the engine: orchestration, events, JSON API        |
|   spectre-providers    username, email, phone and domain adapters       |
|   spectre-breach       HIBP client, catalog provider, risk assessment   |
|   spectre-audit        Pwned Passwords check, hash inventory            |
|   spectre-correlation  evidence-based identity graph                    |
|   spectre-storage      SQLite, migrations, export/import, backup        |
| spectre-core         model, validation, provider trait, HTTP policy     |
| spectre-cli          command-line front end over the same engine        |
+-------------------------------------------------------------------------+
```

## Swift and Rust

The boundary is a hand-written C ABI that passes JSON. I looked at UniFFI first and decided against it. The API is coarse: about 40 methods, each called a handful of times per user action, and the payload sizes don't matter next to network latency. UniFFI would add a code generation step plus generated Swift files to keep in sync, and its async and callback support makes the build more involved. A single JSON dispatcher, tested in Rust and decoded into Swift `Codable` types, is simpler and nearly as safe.

The header (`rust/crates/spectre-ffi/include/spectre_ffi.h`) exposes seven functions:

| Function | Purpose |
|---|---|
| `spectre_engine_open(options_json, &error)` | Create the engine, which owns a 4-worker Tokio runtime |
| `spectre_engine_call(engine, method, params_json)` | Dispatch a JSON API call (`Engine::call`) |
| `spectre_engine_poll_events(engine, id, max, timeout_ms)` | Wait for streamed events, blocking up to the timeout |
| `spectre_check_password(engine, bytes, len)` | Password check. Takes raw bytes, never JSON |
| `spectre_string_free`, `spectre_engine_close`, `spectre_version` | Lifecycle |

Every response is an envelope, either `{"ok": ...}` or `{"error": {"code", "message"}}`. The error codes are stable strings such as `invalid_input`, `authorization_required`, `credentials_missing`, `rate_limited` and `policy_violation`. Each entry point runs inside `catch_unwind`, so a Rust panic comes back as an `internal` error instead of crashing the app.

`RustEngine` on the Swift side runs every blocking call on a private concurrent `DispatchQueue` and bridges it with a continuation, so the main actor never waits on Rust. Event streaming is an `AsyncThrowingStream` fed by a background loop that calls `spectre_engine_poll_events` with a 250 ms timeout.

### JSON API

All methods go through `Engine::call(method, params)` in `spectre-discovery/src/api.rs`. They are grouped by prefix:

- `investigation.*`: start, cancel, get, list, delete, events, correlate, suggestions, export_json, export_csv, import
- `sites.catalog`, `sites.verify` (the profile-page catalog and its live self-test)
- `relationship.decide`
- `verification.*`, `breach.*`, `audit.*`
- `settings.*`, `providers.*`, `credentials.*`
- `privacy.purge`, `storage.*`, `dashboard.stats`, `engine.diagnostics`, `target.validate`

## How an investigation runs

1. `investigation.start` normalizes the target and refuses to go further without an authorization record of at least 10 characters. It picks the enabled providers that support the target type, saves the investigation and writes an audit event.
2. A Tokio task starts every provider at once through `FuturesUnordered`. A global semaphore (`max_concurrency`, 4 by default) caps how many actually do work at the same time, across all investigations. Each provider also gets a deadline (`provider_timeout_secs`) and a cancellation token.
3. As each provider returns, its findings are saved right away and emitted as events (`provider_started`, `finding_discovered`, `provider_completed` or `provider_failed`, `progress`). The UI shows them before the slower providers finish.
4. After the last provider, correlation runs. It writes the identity graph and updates the confidence of profile findings, then the engine emits `correlation_updated` and finally `finished` with the run's metrics.
5. The final status is `completed` when nothing failed, `partially_completed` when some providers failed, `failed` when all of them failed or were cancelled, and `cancelled` when the user stopped the run. If the process dies mid-run, the next launch marks that investigation `failed`.

A provider doesn't have to wait until it returns to hand over findings. `ProviderContext::publish` sends a finding down a channel the engine reads alongside provider completions, so a provider that checks 34 sites can stream each hit as it lands. Before the engine handles a provider's completion it drains anything that provider already published, so the finding count in `provider_completed` is always right. Providers that fan out like that can also ask for a longer deadline through `OsintProvider::deadline`; `site-check` asks for 90 seconds.

When a run is done, `investigation.suggestions` lists the identifiers the findings point to (linked handles, published emails, websites, other user IDs on a PGP key), marking the ones already investigated. The engine never starts them itself. Maigret follows discovered usernames recursively; Spectre leaves that step to the investigator so every target gets its own authorization record.

Events sit in an in-memory queue per investigation (`events.rs`). Producers never block. The FFI waits on a `Condvar` and the CLI waits through `spawn_blocking`. A queue is dropped once its last event has been read.

### Metrics

Each run records:

- startup latency (from the request to the first provider dispatch)
- time to first finding and total duration
- latency and outcome for each provider
- HTTP request count, cache hits and cache misses

You can see them under Run Details in the app or with `spectre bench`.

These numbers come from this machine on 2026-11-05, using a release build against the live APIs with a username and 13 providers:

| Run | Startup | First finding | Total | Requests | Cache hit rate |
|---|---|---|---|---|---|
| Cold | 1 ms | 745 ms | 2,371 ms | 14 | 0% |
| Warm (cached) | 0 ms | 0 ms | 5 to 7 ms | 0 | 100% |

The CLI process peaked at 31 MB of resident memory over the three runs. GitHub was the slowest provider at 2.3 s.

## HTTP layer

`spectre-core/src/http.rs` holds the one HTTP client everything shares.

- A single `reqwest::Client` gives connection pooling. TLS is rustls with the platform verifier, so certificates are checked against the macOS trust store.
- An endpoint allowlist only permits HTTPS on port 443 to hosts that a provider declared. IP literals and credentials in URLs are refused, and every redirect hop is checked against the same rules.
- Rate limiting is per provider and spaces requests evenly. Each provider's limit can be changed in Settings.
- Timeouts, connection errors, 429 and 5xx responses are retried with exponential backoff and jitter, capped at 8 s. A `Retry-After` of up to 30 s is honored. Anything longer goes back to the provider as a rate-limit error so the run doesn't stall.
- Responses are cached in memory (2xx and 404 only, 1,024 entries, TTL from settings). Ownership challenges and breach lookups skip the cache.
- `fetch_public_web` is a separate path for the investigated domain's own website. It resolves DNS first and requires every address to be public. It then pins the connection to those addresses so DNS rebinding can't redirect it, and follows redirects by hand, checking each one.
- Response bodies are capped at 8 MiB for APIs and 1 MiB for web pages.

## Identity correlation

`spectre-correlation` turns findings into a graph. Nodes are usernames, profiles, emails, phones, domains, websites and breaches. Every edge carries a list of evidence items with weights, and the weights combine as `1 - product(1 - w_i)`, so independent signals reinforce each other without ever reaching 1.0.

| Signal | Weight |
|---|---|
| Exact username match | 0.35 |
| Explicit link (the profile links to the URL or handle) | 0.60 |
| Link verified by the platform (Keybase proof, Mastodon rel="me", Gravatar verified account) | 0.75 |
| Both profiles link to each other | 0.40 |
| Linked to another profile that also matches the target | 0.45, or 0.60 if platform-verified |
| Same public email | 0.60 |
| Same website | 0.25 |
| Same display name (two or more words, or at least 8 characters) | 0.15 |
| Gravatar profile registered to the investigated address | 0.80 |

The category is decided in this order:

1. If the investigator rejected the relationship, it is Unrelated. If they confirmed it, or ownership is verified, it is Confirmed.
2. A score of 0.75 or more counts as Strong Evidence, but only when at least one signal is an explicit link.
3. A score of 0.40 or more is Possible. Anything lower is Weak Evidence.

A username match alone scores 0.35, so it always stays at Weak Evidence. Coincidences like a shared name or website can't push a relationship to Strong Evidence without an explicit link. Identity and relationship IDs are UUIDv5 values built from canonical values, which is why investigator decisions survive when correlation reruns.

## Storage

`spectre-storage` uses SQLite in WAL mode with `foreign_keys=ON` and `secure_delete=ON`. The database file is created with mode 0600. Migrations are embedded and versioned (`migrations/0001_initial.sql`).

Tables: `investigations`, `investigation_targets`, `investigation_errors`, `findings`, `finding_sources`, `profiles`, `identities`, `identity_relationships`, `email_addresses`, `phone_numbers`, `domains`, `breach_incidents`, `breach_exposures`, `provider_configs`, `audit_events` and `engine_settings`.

Deleting an investigation cascades to every table scoped to it. `audit_events` has no foreign key on purpose, so the record that an investigation existed outlives it. Audit events never hold passwords, hashes or keys.

After a delete the engine runs `PRAGMA wal_checkpoint(TRUNCATE)` so the overwritten pages don't linger in the WAL. Backups use `VACUUM INTO`. A restore checks the backup's integrity and schema version before replacing the database file. Exports are versioned bundles (`spectre.investigation` v1), and imports re-validate every target.

## The macOS app

- `AppModel` holds app-wide state and `InvestigationViewModel` holds one investigation. Both are `@MainActor @Observable`, and there is one persisted view model per investigation ID. Derived data such as the grouped finding sections is cached as stored properties rather than computed on every read.
- The window is a `NavigationSplitView` with a sidebar and a detail column, and the `.inspector` is attached to the detail column.
- The identity graph is a native `Canvas`. Its Fruchterman-Reingold layout is deterministic and computed off the main actor. You can pinch or use buttons to zoom, drag to pan, click nodes or edges, filter by kind and confidence, and collapse leaf neighbors. The relationship list beside the graph is the accessible version of the same data.
- PDF reports are paginated with Core Text into a `CGContext` PDF and previewed with PDFKit. JSON and CSV come from the engine, and CSV cells are escaped so spreadsheets don't run them as formulas.
