# Providers

A provider implements `OsintProvider` (`spectre-core/src/provider.rs`). It declares an id, a name, the target types it handles, its capabilities, whether it needs a credential, a default rate limit, and the exact hosts it is allowed to contact. The engine adds those hosts to the endpoint allowlist, and requests to anything else are refused.

I checked the response shape of every adapter against the live API on 2026-11-05. The adapter tests run against local mock servers that return the same fields with made-up values.

## Built-in providers

| ID | Target | Source | Auth | Notes |
|---|---|---|---|---|
| `github` | username | `api.github.com` `/users/{u}`, `/users/{u}/social_accounts` | optional token | 60 requests an hour without a token. Reads the blog, X handle, social accounts and public email |
| `gitlab` | username | `gitlab.com` `/api/v4/users?username=` | none | Public email when the user set one |
| `codeberg` | username | `codeberg.org` `/api/v1/users/{u}` | none | Ignores `noreply` addresses |
| `keybase` | username | `keybase.io` `/_/api/1.0/user/lookup.json` | none | Signed identity proofs (state 1) become platform-verified links |
| `mastodon` | username | `mastodon.social` `/api/v1/accounts/lookup` | none | Fields with `verified_at` (rel="me") become platform-verified links. Only checks mastodon.social |
| `bluesky` | username | `public.api.bsky.app` `app.bsky.actor.getProfile` | none | Looks up `<username>.bsky.social`. A name with dots is treated as a full handle |
| `hackernews` | username | `hacker-news.firebaseio.com` `/v0/user/{id}.json` | none | Usernames are case-sensitive, and `null` means no such user |
| `devto` | username | `dev.to` `/api/users/by_username` | none | GitHub, X and website links the owner entered |
| `huggingface` | username | `huggingface.co` `/api/users/{u}/overview` | none | |
| `dockerhub` | username | `hub.docker.com` `/v2/users/{u}/` | none | Organizations redirect and are skipped |
| `chesscom` | username | `api.chess.com` `/pub/player/{u}` | none | Published-Data API |
| `lichess` | username | `lichess.org` `/api/user/{u}` | none | Profile links |
| `wikipedia` | username | `en.wikipedia.org` MediaWiki `list=users` | none | `missing` or `invalid` means no such user |
| `email-dns` | email | `cloudflare-dns.com` (DoH JSON) | none | MX, implicit MX (RFC 5321), null MX (RFC 7505), SPF and DMARC |
| `gravatar` | email | `api.gravatar.com` `/v3/profiles/{sha256}` | none | Public profile the address owner created, with its verified accounts |
| `phone-numbering` | phone | offline libphonenumber metadata | none | E.164, country code, region and line type. Makes no network requests and no subscriber lookups |
| `domain-dns` | domain | `cloudflare-dns.com` | none | A, AAAA, MX, NS, TXT, CAA and `_dmarc`, plus notes on weak mail or certificate settings |
| `rdap` | domain | `data.iana.org` bootstrap, then the registry's RDAP server | none | The registry host comes from the IANA bootstrap file and is allowed at runtime |
| `website` | domain | the investigated domain, over HTTPS | none | Homepage title and description, rel="me" and profile links, `/.well-known/security.txt`. Public IPs only, DNS-pinned. This one contacts the target's own server |
| `hibp-catalog` | domain | `haveibeenpwned.com` `/api/v3/breaches?Domain=` | none | Public breach metadata for the service, with no personal data |

Three services sit outside the provider list:

| Service | Host | Auth | Used for |
|---|---|---|---|
| HIBP account breaches | `haveibeenpwned.com` `/api/v3/breachedaccount/{email}` | `hibp-api-key` (paid) | Ownership-verified addresses only, enforced by `AuthorizedAccount` |
| HIBP catalog | `haveibeenpwned.com` `/api/v3/breaches` | none | The local breach catalog |
| Pwned Passwords | `api.pwnedpasswords.com` `/range/{prefix5}` | none | k-anonymity password checks with `Add-Padding: true` |

HIBP data is licensed CC BY 4.0, and the app credits it wherever it shows up. For manual end-to-end checks, HIBP's documented test key (all zeros) works with its test addresses under `hibp-integration-tests.com`.

### What I left out on purpose

- Probing registration, login or password-reset pages to find out whether an address has an account (the Holehe approach). It reveals private account existence and touches the target's accounts.
- Scraping X, Instagram, TikTok, LinkedIn or any other site without a public API, and anything that would mean getting past CAPTCHAs or bot protection.
- Reverse phone lookups, carrier queries and location guesses.
- Pivoting automatically from one target to another, for example investigating an email address that turned up on a profile. A pivot is always a new investigation with its own authorization record.

## Adding a provider

1. Write a struct with an injectable `base: Url` (with a `with_base` constructor for tests) and implement `OsintProvider`. The `provider_metadata!` macro fills in the static fields.
2. List every host in `allowed_hosts()`. Make API calls with `ProviderContext::get`, which handles the policy check, rate limiting, retries, caching, cancellation and stats. Return `Ok(vec![])` when nothing is found and an error for anything else. Never drop an error silently.
3. Build findings with `common::profile_draft`, `public_email_draft` or `observed_fact` so confidence and provenance stay consistent with the other providers.
4. Register the provider in `spectre_providers::default_providers()`.
5. Add mock-server tests next to the adapter, following `username/tests.rs`. Check every response field against the live API or its documentation first.

## Open-source tools I looked at

I reviewed these from their repositories only, on 2026-11-05. I didn't install or run any of them.

| Tool | License | How it works | Last commit | Outcome |
|---|---|---|---|---|
| [Sherlock](https://github.com/sherlock-project/sherlock) | MIT | `data.json` with about 481 sites, checked by status code, error message or redirect URL | 2026-11-01 | Read for ideas, not bundled. Status-code checks give a lot of false positives, and by default it downloads its site list at runtime |
| [Maigret](https://github.com/soxoj/maigret) | MIT | About 8,500 site entries with presence and absence strings, plus recursive search | 2026-11-04 | Not bundled. It auto-updates its database (checked against a hash from the same repo) and has optional Cloudflare-bypass and AI features that don't fit Spectre's rules |
| [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) | CC BY-SA 4.0 (data) | `wmn-data.json` with about 692 sites, comparing `e_code`/`e_string` against `m_code`/`m_string` | 2026-11-02 | A possible future add-on, fetched at runtime with attribution. Bundling it needs a legal look at the share-alike terms first |
| [Social Analyzer](https://github.com/qeeqbox/social-analyzer) | AGPL-3.0 | Detections with scoring, and a slow mode that drives Selenium with OCR | 2026-01-12 | Not used, because of the network copyleft and the browser automation |
| [SpiderFoot](https://github.com/smicallef/spiderfoot) | MIT | 200+ modules. Its `sfp_accounts` module downloads WhatsMyName at runtime | 2023-11-05 | Not used. It hasn't been maintained since 2023 and it shells out to local tools |
| [Holehe](https://github.com/megadose/holehe) | GPL-3.0 | Probes registration, login and recovery endpoints | 2024-09-10 | Rejected. It enumerates private accounts |
| [PhoneInfoga](https://github.com/sundowndev/phoneinfoga) | GPL-3.0 | libphonenumber parsing, OVH and numverify lookups, Google dorks | 2026-08-25 | Only the offline numbering-metadata idea made it in, through the Apache-2.0 `phonenumber` crate |

Spectre prefers each platform's documented API over generic status-code checks. Findings are more accurate and the provenance is exact, but coverage is narrower: 13 username platforms, where those tools reach hundreds.
