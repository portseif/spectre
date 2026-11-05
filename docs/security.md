# Security model

Spectre is meant for investigations someone has authorized: checking your own exposure, an assessment the subject agreed to, or an engagement with written scope. The controls below keep it on that side of the line by default, and leave a record of how it was used.

## Authorization

Every investigation needs a purpose of at least 10 characters describing the authorization basis and scope. The engine stores it with the investigation and in the audit log, and the app also asks you to confirm that you're authorized. Discovery only uses public, documented sources. Spectre never pivots to a new target by itself, never probes registration or password-reset pages, and never touches private account data.

Breach data has a harder gate. `AuthorizedAccount` in `spectre-breach` can only be created from an `EmailRecord` whose status is `ownership_verified`, and the account-specific HIBP lookup only accepts an `AuthorizedAccount`. An unverified address can't reach that API at all, and the engine refuses before it sends anything.

Ownership can be shown two ways:

- A DNS TXT challenge on a domain. The record goes at `_spectre-challenge.<domain>` with the value `spectre-verify=<128 random bits>`, and the check always queries fresh instead of using the cache. Once a domain is verified, every address on it counts as verified too.
- An attestation for a single mailbox. You write a statement, which is stored and audited. You can revoke it later, and the app labels it as an attestation everywhere it appears.

When an investigator confirms or rejects an association, that decision is audited too, and it survives correlation reruns.

The audit log records:

- investigations starting and finishing, deletions, exports and imports
- attestations, domain verification and breach lookups
- password checks (only that one happened, never the result or any hash material)
- settings changes, purges, backups and restores

It never contains a password, a hash or an API key.

## Network and SSRF

API traffic goes through `HttpClient` and its allowlist: HTTPS only, port 443, no IP literals and no credentials in the URL. Only hosts that some provider declared are allowed, and each redirect hop is checked against the same rules. The one host added at runtime is the registry's RDAP server, and it can only come from IANA's bootstrap file at `data.iana.org`.

The `website` provider is the exception, because it has to contact the investigated domain itself, so it uses a separate path with tighter rules.

- The hostname first goes through domain normalization, which rejects IP addresses and internal or reserved suffixes (`localhost`, `.local`, `.internal`, `.test`, `.example`, `.onion`, `home.arpa`, `.lan`).
- Every address the name resolves to must be publicly routable. Private, loopback, link-local, CGNAT, multicast, documentation, benchmarking, NAT64 and IPv4-mapped ranges are all blocked.
- The connection is pinned to the addresses that passed, so a DNS rebind can't send it somewhere else.
- Redirects are followed one hop at a time (at most three), and each hop gets the same checks.

Targets are normalized before any provider sees them. Usernames have a strict character set, email local parts must be RFC 5322 dot-atoms, domains go through IDNA, and phone numbers become E.164. Path segments are percent-encoded on top of that. Response bodies have size caps, and transport errors never include the URL, since it can contain the identifier being investigated.

One privacy tradeoff: DNS lookups go over Cloudflare's DNS-over-HTTPS service, so Cloudflare sees the names being queried.

## Credentials

The HIBP and GitHub keys live only in your Keychain, with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. At launch the app hands them to the engine in memory, where they sit in `Zeroizing<String>` and go out as sensitive headers that `Debug` output redacts. They never reach the database, the logs, exports or the diagnostics screen. The CLI reads them from environment variables instead.

## Passwords

The Pwned Passwords check takes the password across the FFI as raw bytes rather than JSON. The engine copies them into memory that is zeroed afterwards, hashes them with SHA-1 locally, and sends only the first 5 characters of the hash with `Add-Padding: true`. The returned suffixes are compared on the Mac, padding entries with a count of 0 are skipped, and range responses are never cached. Neither the password nor the full hash is logged or stored. Swift wipes its byte copy with `memset_s`. What it can't reliably wipe is the `String` behind the `SecureField`, so the app clears that field as soon as the check starts.

The hash inventory classifies storage schemes and their parameters against the OWASP Password Storage Cheat Sheet, and flags unsalted, legacy and duplicate hashes. It accepts bare hashes, `user:hash`, tab-separated pairs, `/etc/shadow` and pwdump files. The output is counts only. No hash values are kept, and nothing tries to crack them.

`spectre-audit/src/offline.rs` defines an `OfflineAuditBackend` interface for any future offline auditing. It requires an `AuditAuthorization` and may only return aggregate results. The only backend that ships is `NotConfigured`, which refuses.

### Why not `defuse/preimage`

I reviewed [`defuse/preimage`](https://github.com/defuse/preimage) (MIT OR Apache-2.0, last commit 2026-09-01) as a possible backend and decided not to use it.

- It only handles unsalted fast hashes (MD5, SHA-1, SHA-2, SHA-3, NTLM, LM, MySQL 4.1 and similar). Without bcrypt, scrypt, Argon2 or PBKDF2 it can't audit how modern systems store passwords.
- Its index is a sorted file of 14-byte entries (an 8-byte digest prefix plus a 6-byte wordlist position) with no header. Prefix hits are re-checked against the wordlist. An interrupted sort leaves the file corrupt.
- It memory-maps the index through `memmap2`, which is `unsafe`. If something truncates the file while it's mapped, the process gets a SIGBUS it can't catch, so index files must be static and owned by the app.
- You bring your own wordlist. A CrackStation-sized list produces an index of about 17 GB.
- It has 373 tests, but its own README says it was written with heavy AI assistance and hasn't been reviewed by a person. It has one maintainer, an open bug with 4-byte digests, and RustCrypto dependencies a minor version behind.

If Spectre ever needs an offline backend, reimplementing that simple format, or vendoring a pinned and fuzzed copy behind `OfflineAuditBackend`, would be safer. Breach datasets from third parties should never be accepted as input either way.

## Data at rest

The database lives in the App Sandbox container with file mode 0600 and SQLite `secure_delete=ON`, and the WAL is checkpointed after every delete. Retention settings purge old investigations at launch, and you can also purge or delete everything by hand. Spectre never stores plaintext passwords, password hashes, recovered credentials or API keys.

Spectre doesn't encrypt the database itself, so turn on FileVault. The planned next step is SQLCipher, or field-level encryption with a key held in the Keychain. Exports are plain files written only where you choose to save them.

## Things Spectre will not do

Credential stuffing, password spraying, account takeover, getting past CAPTCHAs or bot protection, bulk plaintext-password recovery, pulling leaked hashes for arbitrary people, showing recovered credentials, Holehe-style account enumeration, or guessing someone's location from a phone number.

## Supply chain

CI runs `cargo audit`, `cargo deny` (advisories, licenses, sources and duplicate crates), Gitleaks for secrets, and CodeQL for Rust and GitHub Actions. Nothing from a third-party OSINT repository is downloaded or executed at build time or at runtime.
