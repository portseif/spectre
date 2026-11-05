# Providers

Every provider implements `OsintProvider` (`spectre-core/src/provider.rs`). Each one declares its id, name, supported target types, capabilities, credential requirement, default rate limit, and the **exact hosts** it may contact. The engine registers those hosts with the endpoint allowlist; any other destination is refused.

Response shapes for every adapter were checked against the live APIs on 2026-11-05. Adapter tests use local mock servers that mirror those shapes with synthetic values.

## Built-in providers

| ID | Target | Source | Auth | Notes |
|---|---|---|---|---|
| `github` | username | `api.github.com` `/users/{u}`, `/users/{u}/social_accounts` | optional token | 60 req/h unauthenticated; blog, X handle, social accounts, and public email |
| `gitlab` | username | `gitlab.com` `/api/v4/users?username=` | — | Public email when set |
| `codeberg` | username | `codeberg.org` `/api/v1/users/{u}` | — | `noreply` addresses ignored |
| `keybase` | username | `keybase.io` `/_/api/1.0/user/lookup.json` | — | Signed identity proofs become platform-verified links (state 1) |
| `mastodon` | username | `mastodon.social` `/api/v1/accounts/lookup` | — | Fields with `verified_at` (rel="me") become platform-verified links; mastodon.social only |
| `bluesky` | username | `public.api.bsky.app` `app.bsky.actor.getProfile` | — | Looks up `<username>.bsky.social` (dotted names are treated as full handles) |
| `hackernews` | username | `hacker-news.firebaseio.com` `/v0/user/{id}.json` | — | Usernames are case-sensitive; `null` means not found |
| `devto` | username | `dev.to` `/api/users/by_username` | — | Owner-declared GitHub, X, and website |
| `huggingface` | username | `huggingface.co` `/api/users/{u}/overview` | — | |
| `dockerhub` | username | `hub.docker.com` `/v2/users/{u}/` | — | Organizations redirect and are skipped |
| `chesscom` | username | `api.chess.com` `/pub/player/{u}` | — | Published-Data API |
| `lichess` | username | `lichess.org` `/api/user/{u}` | — | Profile links |
| `wikipedia` | username | `en.wikipedia.org` MediaWiki `list=users` | — | `missing`/`invalid` means not found |
| `email-dns` | email | `cloudflare-dns.com` (DoH JSON) | — | MX, implicit MX (RFC 5321), null MX (RFC 7505), SPF, DMARC |
| `gravatar` | email | `api.gravatar.com` `/v3/profiles/{sha256}` | — | Public profile created by the address owner; verified accounts |
| `phone-numbering` | phone | offline libphonenumber metadata | — | E.164, country code, region, line type. No network, no subscriber lookups |
| `domain-dns` | domain | `cloudflare-dns.com` | — | A, AAAA, MX, NS, TXT, CAA, `_dmarc`; posture observations |
| `rdap` | domain | `data.iana.org` bootstrap, then the registry's RDAP server | — | Registry host comes from the IANA bootstrap and is allowlisted at runtime |
| `website` | domain | the investigated domain over HTTPS | — | Homepage title, description, `rel="me"` and profile links, `/.well-known/security.txt`. Public IPs only, DNS-pinned. Contacts the target's own server |
| `hibp-catalog` | domain | `haveibeenpwned.com` `/api/v3/breaches?Domain=` | — | Public breach metadata for the service; no personal data |

Services outside the provider list:

| Service | Host | Auth | Used for |
|---|---|---|---|
| HIBP account breaches | `haveibeenpwned.com` `/api/v3/breachedaccount/{email}` | `hibp-api-key` (paid) | Ownership-verified addresses only (`AuthorizedAccount`) |
| HIBP catalog | `haveibeenpwned.com` `/api/v3/breaches` | — | Local breach catalog |
| Pwned Passwords | `api.pwnedpasswords.com` `/range/{prefix5}` | — | k-anonymity checks with `Add-Padding: true` |

HIBP data is licensed under CC BY 4.0, and the app attributes it wherever it is shown. HIBP's documented test key (`000…0`) and test addresses (`*@hibp-integration-tests.com`) work for manual end-to-end checks.

### Deliberately not implemented

- **Registration, login, or password-reset probing** to learn whether an address has an account (Holehe-style enumeration). It discloses private account existence and touches the target's accounts.
- **Scraping** of X, Instagram, TikTok, LinkedIn, and other sites without public APIs, and anything that would require bypassing CAPTCHAs or bot protection.
- **Reverse phone lookups**, carrier queries, and location inference.
- **Automatic pivoting** from one target to another (for example, investigating a discovered email). Pivots are always an explicit new investigation with its own authorization record.

## Adding a provider

1. Create a struct with an injectable `base: Url` (`with_base` for tests) and implement `OsintProvider`. Use the `provider_metadata!` macro for the static fields.
2. Declare every host in `allowed_hosts()`. Use `ProviderContext::get` for API calls (policy checks, rate limits, retries, cache, cancellation, and stats come with it). Return `Ok(vec![])` for "not found"; return errors for everything else, never silently.
3. Build findings with `common::profile_draft` / `public_email_draft` / `observed_fact` so confidence and provenance stay consistent.
4. Register it in `spectre_providers::default_providers()`.
5. Add mock-server tests next to the adapter (see `username/tests.rs`). Do not invent response fields: verify them against the live API or its documentation first.

## Open-source tools evaluated

All of these were reviewed from their repositories only, on 2026-11-05. None were installed or executed.

| Tool | License | Technique | Last commit | Decision |
|---|---|---|---|---|
| [Sherlock](https://github.com/sherlock-project/sherlock) | MIT | `data.json` (≈481 sites): status code, error message, or redirect URL checks | 2026-11-01 | Technique reviewed; not bundled. Status-code checks have high false-positive rates, and it fetches its manifest remotely by default |
| [Maigret](https://github.com/soxoj/maigret) | MIT | ≈8.5k site entries, presence/absence strings, recursive search | 2026-11-04 | Not bundled. Auto-updating DB (hash from the same repo), optional Cloudflare-bypass and AI features conflict with Spectre's policy |
| [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) | CC BY-SA 4.0 (data) | `wmn-data.json` (≈692 sites): `e_code`/`e_string` vs `m_code`/`m_string` | 2026-11-02 | Candidate for a future optional, runtime-fetched dataset with attribution. Share-alike implications of bundling need legal review |
| [Social Analyzer](https://github.com/qeeqbox/social-analyzer) | AGPL-3.0 | Detections plus scoring; Selenium and OCR slow mode | 2026-01-12 | Not used (network copyleft, browser automation) |
| [SpiderFoot](https://github.com/smicallef/spiderfoot) | MIT | 200+ modules; `sfp_accounts` fetches WhatsMyName at runtime | 2023-11-05 | Not used (unmaintained since 2023, shells out to local tools) |
| [Holehe](https://github.com/megadose/holehe) | GPL-3.0 | Registration, login, and recovery endpoint probing | 2024-09-10 | Rejected on principle (private account enumeration) |
| [PhoneInfoga](https://github.com/sundowndev/phoneinfoga) | GPL-3.0 | libphonenumber parsing, OVH/numverify, Google dorks | 2026-08-25 | Only the offline numbering-metadata idea is adopted (via the Apache-2.0 `phonenumber` crate) |

The engine favors documented per-platform APIs over generic HTTP status checks. This keeps findings accurate and provenance precise, at the cost of breadth: 13 username platforms versus hundreds in the tools above.
