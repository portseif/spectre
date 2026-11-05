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
| `site-check` | username | 34 sites from `data/sites.json` | none | Public profile pages on sites without a usable API. See below |
| `openpgp` | email | `keys.openpgp.org` `/pks/lookup?op=index&options=mr` | none | Published keys and their confirmed user IDs. Other addresses on the key become linked identities |
| `certspotter` | domain | `api.certspotter.com` `/v1/issuances` | optional key | Hostnames and issuers from Certificate Transparency. 10 lookups an hour without a key |
| `wayback` | domain | `web.archive.org` `/cdx/search/cdx` | none | First and latest Internet Archive captures of the homepage |

Three services sit outside the provider list:

| Service | Host | Auth | Used for |
|---|---|---|---|
| HIBP account breaches | `haveibeenpwned.com` `/api/v3/breachedaccount/{email}` | `hibp-api-key` (paid) | Ownership-verified addresses only, enforced by `AuthorizedAccount` |
| HIBP catalog | `haveibeenpwned.com` `/api/v3/breaches` | none | The local breach catalog |
| Pwned Passwords | `api.pwnedpasswords.com` `/range/{prefix5}` | none | k-anonymity password checks with `Add-Padding: true` |

HIBP data is licensed CC BY 4.0, and the app credits it wherever it shows up. For manual end-to-end checks, HIBP's documented test key (all zeros) works with its test addresses under `hibp-integration-tests.com`.

### Profile-page checks

Some sites have no public API but do answer a profile URL differently depending on whether the account exists. `data/sites.json` lists 34 of them. Every entry was written for Spectre and tested by hand before it went in. Each one declares:

- the public profile URL, plus an API URL when the site has one worth asking instead
- how to read the answer: HTTP status codes, or text that appears only on real profiles (or only on the "not found" page)
- a username pattern, so names the site can't have are skipped without a request
- one account known to exist, for the self-test

`spectre sites verify` checks every entry against its known account and a random name, and fails loudly when a site changes. Run it before relying on the results.

Entries are only accepted when they need nothing but a plain GET. Sites that answered with bot challenges or 403s in testing (PyPI, Medium, npm, Reddit, Behance and others) were left out. So was Replit, whose profiles sit behind a login. The checks run up to 8 at a time, each to a different host, and findings stream into the investigation as they're found. A found profile is still only Weak Evidence: the page says an account exists, not who owns it. When most checks come back blocked, the provider reports an error instead of a clean run.

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

I reviewed these from their repositories only, in two passes on 2026-11-05. I didn't install or run any of them, and no code or data from them is in Spectre. What came across is ideas, reimplemented in Rust.

| Tool | License | How it works | Last commit | Outcome |
|---|---|---|---|---|
| [Sherlock](https://github.com/sherlock-project/sherlock) | MIT | `data.json` with about 481 sites, checked by status code, error message or redirect URL | 2026-11-01 | Read for ideas, not bundled. Status-code checks give a lot of false positives, and by default it downloads its site list at runtime |
| [Maigret](https://github.com/soxoj/maigret) | MIT | About 8,500 site entries with presence and absence strings, plus recursive search | 2026-11-04 | Not bundled. It auto-updates its database (checked against a hash from the same repo) and has optional Cloudflare-bypass and AI features that don't fit Spectre's rules |
| [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) | CC BY-SA 4.0 (data) | `wmn-data.json` with about 692 sites, comparing `e_code`/`e_string` against `m_code`/`m_string` | 2026-11-02 | A possible future add-on, fetched at runtime with attribution. Bundling it needs a legal look at the share-alike terms first |
| [Social Analyzer](https://github.com/qeeqbox/social-analyzer) | AGPL-3.0 | Detections with scoring, and a slow mode that drives Selenium with OCR | 2026-01-12 | Not used, because of the network copyleft and the browser automation |
| [SpiderFoot](https://github.com/smicallef/spiderfoot) | MIT | 200+ modules. Its `sfp_accounts` module downloads WhatsMyName at runtime | 2023-11-05 | No code used. It hasn't been maintained since 2023 and it shells out to local tools, but several of its module ideas are reimplemented here (see below) |
| [Holehe](https://github.com/megadose/holehe) | GPL-3.0 | Probes registration, login and recovery endpoints | 2024-09-10 | Rejected. It enumerates private accounts |
| [PhoneInfoga](https://github.com/sundowndev/phoneinfoga) | GPL-3.0 | libphonenumber parsing, OVH and numverify lookups, Google dorks | 2026-08-25 | Only the offline numbering-metadata idea made it in, through the Apache-2.0 `phonenumber` crate |
| [OSINT-Framework](https://github.com/lockfale/OSINT-Framework) | MIT | A browsable tree of OSINT resources (`arf.json`) | 2026-10-31 | Not imported. The idea of handing off to manual tools became the "Search manually" links in the Follow-ups tab |
| [Sn1per](https://github.com/1N3/Sn1per) | Custom EULA | Active recon and vulnerability scanning that shells out to many tools | 2026-10-27 | Nothing used. Its EULA forbids building anything from the code, and active scanning is outside Spectre's passive scope. The homepage header review is a generic passive check, not taken from it |
| [Mr.Holmes](https://github.com/Lucksi/Mr.Holmes) | GPL-3.0 | Username site lists, phone and website lookups, Google dorks | 2026-02-21 | GPL, so no code or site lists. The dork idea became plain search links you open yourself |
| [gosearch](https://github.com/ibnaleem/gosearch) | GPL-3.0 | Fast concurrent username checks in Go from a `data.json`, plus breach lookups | 2026-11-04 | GPL, so no code or data. Spectre's site checks do the same job with typed definitions, per-host rate limits and a self-test. Its breach integrations were rejected: ProxyNova's COMB search returns plaintext leaked passwords, and the other lookups expose credential data for people whose ownership nobody verified |

Ideas that did make it in, and where they came from:

| Idea | From | Spectre's version |
|---|---|---|
| Declarative site checks with known and unknown sample accounts | Maigret, Sherlock, gosearch | `site-check` with Spectre's own catalog, a username pattern per site, and `spectre sites verify` |
| Recursive search on discovered usernames | Maigret | Suggested follow-ups that you start yourself, each with its own authorization record |
| Certificate Transparency hostnames | SpiderFoot (`sfp_crt`) | `certspotter`, using SSLMate's documented API because crt.sh kept returning 502 during testing |
| PGP keyserver lookups | SpiderFoot (`sfp_pgp`) | `openpgp`, limited to keys.openpgp.org, which only lists confirmed addresses |
| Wayback Machine history | SpiderFoot (`sfp_archiveorg`) | `wayback`, first and latest capture only |
| Web server banners and unusual headers | SpiderFoot (`sfp_webserver`, `sfp_strangeheaders`) | Passive review of the homepage response the `website` provider already fetches |
| Search-engine dorks | Mr.Holmes, OSINT-Framework | "Search manually" links that open in your browser; nothing scrapes a search engine |

Spectre prefers each platform's documented API over generic status-code checks. Findings are more accurate and the provenance is exact, but coverage is narrower: 13 API platforms and 34 checked profile pages, where those tools reach hundreds or thousands.
