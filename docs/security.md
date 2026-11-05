# Security model

Spectre is built for **authorized** investigations: self-assessment, consented assessments, and engagements with written scope. Its controls aim to keep the tool on that side of the line by default and to leave an accountable record when it is used.

## Authorization controls

- **Authorization record.** Every investigation requires a purpose of at least 10 characters (the authorization basis and scope). It is stored with the investigation and in the audit log. The app also requires an explicit "I am authorized" confirmation.
- **No silent escalation.** Discovery uses only public, documented sources. Spectre never pivots automatically, never probes registration or password-reset flows, and never touches private account data.
- **Ownership gate for breach data.** `AuthorizedAccount` (`spectre-breach`) can only be built from an `EmailRecord` whose status is `ownership_verified`. Account-specific HIBP lookups take an `AuthorizedAccount`, so unverified addresses cannot reach the API; the engine refuses before any network request is made. Ownership is established in one of three ways:
  - **DNS TXT challenge** for a domain (`_spectre-challenge.<domain>` = `spectre-verify=<128-bit random>`, checked fresh without the cache). Addresses on the domain inherit verification.
  - **Investigator attestation** for a single mailbox. The investigator's statement is stored and audited, can be revoked, and is labeled as an attestation everywhere it appears.
- **Investigator decisions.** Confirming or rejecting an association is audited and survives re-correlation.
- **Audit log.** Records investigation start and finish, deletions, exports and imports, attestations, domain verification, breach lookups, password checks (that a check happened, with no result or hash material), settings changes, purges, and backup and restore. It never stores passwords, hashes, or API keys.

## Network security (SSRF prevention)

- All API traffic goes through `HttpClient` with an **allowlist**: HTTPS only, port 443, no IP literals, and no embedded credentials. Only hosts declared by providers are allowed. Redirect hops are validated against the same policy.
- The RDAP registry host is added at runtime only from IANA's bootstrap registry (`data.iana.org`).
- The `website` provider contacts the investigated domain itself through a separate path. The hostname goes through domain normalization, which rejects IPs and internal or reserved suffixes (`localhost`, `.local`, `.internal`, `.test`, `.example`, `.onion`, `home.arpa`, `.lan`). Every resolved address must be publicly routable (private, loopback, link-local, CGNAT, multicast, documentation, benchmarking, NAT64, and IPv4-mapped ranges are blocked). The connection is pinned to the validated addresses, preventing DNS rebinding, and redirects are re-validated one hop at a time (three at most).
- Targets are normalized before use (strict username charset, RFC 5322 dot-atom local parts, IDNA domains, E.164 phones), and path segments are percent-encoded.
- Response bodies are size-capped, and transport errors never echo URLs (which can contain the identifier under investigation).
- **Privacy note:** DNS lookups use Cloudflare DNS-over-HTTPS, so queried names are visible to that resolver.

## Credentials

- API keys (`hibp`, `github`) are stored only in the user's **Keychain** (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`). They are passed to the engine in memory at launch, held in `Zeroizing<String>`, and sent as sensitive headers that are redacted from `Debug` output. They never reach the database, logs, exports, or diagnostics. The CLI reads them from environment variables.

## Password handling

**Pwned Passwords (Workflow A)**

- The password crosses the FFI as raw bytes, never JSON. It is copied into zeroizing memory and hashed with SHA-1 locally.
- Only the 5-character prefix is sent, with `Add-Padding: true`. Suffixes are compared locally, padding entries (count 0) are ignored, and range responses are never cached.
- The plaintext and the full hash are never logged or persisted. Swift wipes its byte copy with `memset_s`. Limitation: Swift `String` storage (the `SecureField` value) cannot be reliably zeroed, so the app clears the field immediately.

**Hash inventory (Workflow B)**

- Classifies storage schemes and parameters against OWASP Password Storage Cheat Sheet thresholds and flags unsalted, legacy, and duplicate hashes.
- Output is aggregate only. No hash values are kept, and no cracking or plaintext recovery is ever attempted.
- Accepted input formats: bare hashes, `user:hash`, tab-separated, `/etc/shadow`, and pwdump.

**Offline auditing.** `spectre-audit/src/offline.rs` defines an isolated `OfflineAuditBackend` interface (requiring an `AuditAuthorization` and returning aggregate results only). Only a refusing `NotConfigured` backend ships.

### `defuse/preimage` evaluation

[`defuse/preimage`](https://github.com/defuse/preimage) (MIT OR Apache-2.0, last commit 2026-09-01) was reviewed as a candidate backend and **not adopted**:

- **Scope.** It does unsalted fast-hash lookups only: MD5, SHA-1/2/3, NTLM, LM, MySQL 4.1, and similar. There is no bcrypt, scrypt, Argon2, or PBKDF2 support, so it cannot audit modern storage.
- **Format.** Indexes hold 14-byte entries (8-byte digest prefix plus 6-byte wordlist position), sorted, with no file header. Prefix hits are re-verified against the wordlist. An interrupted sort corrupts the file.
- **Memory mapping.** It maps the index with `memmap2` (`unsafe`). Concurrent truncation causes an uncatchable SIGBUS, so index files must be static and app-owned.
- **Dataset.** The operator supplies the wordlist. CrackStation-scale wordlists produce indexes of about 17 GB.
- **Quality.** It has 373 tests, but its README states the code was written with heavy AI assistance and has not been reviewed by a human. It has a single maintainer, open bugs (4-byte digests), and RustCrypto dependencies one minor version behind.
- **Conclusion.** If an offline backend is ever needed, reimplementing the simple format or vendoring a pinned, fuzzed copy behind `OfflineAuditBackend` is preferable. Third-party breach datasets must never be accepted as input.

## Data protection at rest

- The database sits in the App Sandbox container with file mode `0600`, under SQLite `secure_delete=ON`, and is WAL-checkpointed after deletes.
- Data retention purges old investigations at launch. Manual purge and delete-all are also available.
- No plaintext passwords, password hashes, recovered credentials, or API keys are ever stored.
- **Limitation:** the database is not encrypted by Spectre itself. Rely on FileVault. SQLCipher, or field-level encryption with a Keychain-held key, is the documented next step.
- Exports are unencrypted files written only where the user chooses.

## Not implemented, by design

Credential stuffing, password spraying, account takeover, CAPTCHA or bot-protection bypass, bulk plaintext-password recovery, leaked-hash retrieval for arbitrary people, display of recovered credentials, Holehe-style account enumeration, and location inference from phone numbers.

## Supply chain

CI runs `cargo audit`, `cargo deny` (advisories, licenses, sources, bans), Gitleaks secret scanning, and CodeQL (Rust and GitHub Actions). Third-party OSINT repositories are never fetched or executed at build or run time.
