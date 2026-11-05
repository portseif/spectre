//! Policy-enforcing HTTP client.
//!
//! All outbound traffic goes through [`HttpClient`], which provides:
//!
//! * an endpoint allowlist ([`EndpointPolicy`]): HTTPS only, no IP literals,
//!   no credentials in URLs, only hosts registered by providers (SSRF guard);
//! * redirect validation against the same policy;
//! * per-provider rate limiting;
//! * request timeouts, retry with exponential backoff and jitter
//!   (honouring `Retry-After`), and cooperative cancellation;
//! * a bounded in-memory response cache;
//! * connection pooling via a single shared `reqwest::Client`;
//! * a separate, DNS-pinned fetcher for public web pages of user-supplied
//!   domains that refuses private, loopback, and link-local addresses.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use reqwest::header::{ACCEPT, HeaderMap, HeaderName, HeaderValue, RETRY_AFTER};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::error::{ErrorCode, SpectreError, SpectreResult};

pub const USER_AGENT: &str = concat!("Spectre-OSINT/", env!("CARGO_PKG_VERSION"), " (authorized investigations; macOS)");

/// Maximum response body accepted from an API.
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
/// Maximum response body accepted from a public web page.
const MAX_WEB_BODY_BYTES: usize = 1024 * 1024;
const MAX_CACHE_ENTRIES: usize = 1024;
const MAX_RETRY_AFTER: Duration = Duration::from_secs(30);
const MAX_BACKOFF: Duration = Duration::from_secs(8);
const MAX_WEB_REDIRECTS: usize = 3;

// ---------------------------------------------------------------------------
// Endpoint policy
// ---------------------------------------------------------------------------

/// Allowlist of hosts the engine may contact.
#[derive(Debug, Default)]
pub struct EndpointPolicy {
    allowed_hosts: RwLock<HashSet<String>>,
    allow_insecure_loopback: bool,
}

impl EndpointPolicy {
    pub fn new(hosts: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let policy = Self::default();
        for host in hosts {
            policy.allow_host(host);
        }
        policy
    }

    /// Test-only policy that additionally permits `http://127.0.0.1:<port>` so
    /// providers can be exercised against a local mock server.
    #[doc(hidden)]
    pub fn for_testing() -> Self {
        Self { allowed_hosts: RwLock::default(), allow_insecure_loopback: true }
    }

    pub fn allow_host(&self, host: impl Into<String>) {
        let host = host.into().trim().trim_end_matches('.').to_ascii_lowercase();
        if !host.is_empty() {
            self.allowed_hosts.write().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(host);
        }
    }

    pub fn allowed_hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = self.allowed_hosts.read().unwrap_or_else(|poisoned| poisoned.into_inner()).iter().cloned().collect();
        hosts.sort();
        hosts
    }

    pub fn check(&self, url: &Url) -> SpectreResult<()> {
        if !url.username().is_empty() || url.password().is_some() {
            return Err(policy_violation("URLs with embedded credentials are not allowed"));
        }
        if self.allow_insecure_loopback && is_loopback_test_url(url) {
            return Ok(());
        }
        if url.scheme() != "https" {
            return Err(policy_violation(format!("only HTTPS is allowed (got '{}')", url.scheme())));
        }
        if !matches!(url.port(), None | Some(443)) {
            return Err(policy_violation("non-standard ports are not allowed"));
        }
        let host = match url.host() {
            Some(url::Host::Domain(domain)) => domain.trim_end_matches('.').to_ascii_lowercase(),
            Some(_) => return Err(policy_violation("IP address destinations are not allowed")),
            None => return Err(policy_violation("URL has no host")),
        };
        if self.allowed_hosts.read().unwrap_or_else(|poisoned| poisoned.into_inner()).contains(&host) {
            Ok(())
        } else {
            Err(policy_violation(format!("host '{host}' is not an approved provider endpoint")))
        }
    }
}

fn is_loopback_test_url(url: &Url) -> bool {
    url.scheme() == "http" && matches!(url.host(), Some(url::Host::Ipv4(address)) if address.is_loopback())
}

fn policy_violation(message: impl Into<String>) -> SpectreError {
    SpectreError::new(ErrorCode::PolicyViolation, message)
}

/// True for addresses that are publicly routable. Private, loopback,
/// link-local, CGNAT, multicast, documentation, benchmarking, and reserved
/// ranges all return false.
pub fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => is_public_ipv4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_public_ipv4(mapped);
            }
            is_public_ipv6(v6)
        }
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let [first, second, third, _] = address.octets();
    !(address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_broadcast()
        || address.is_documentation()
        || address.is_unspecified()
        || address.is_multicast()
        || first == 0
        || first >= 240
        || (first == 100 && (64..=127).contains(&second))
        || (first == 198 && (18..=19).contains(&second))
        || (first == 192 && second == 0 && third == 0))
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    !(address.is_loopback()
        || address.is_unspecified()
        || address.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
        || (segments[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        || (segments[0] == 0x2001 && segments[1] == 0x0db8) // documentation
        || segments[0] == 0x0064 && segments[1] == 0xff9b) // NAT64 could reach internal v4
}

// ---------------------------------------------------------------------------
// Requests, responses, statistics
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub provider_id: String,
    pub url: Url,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub cacheable: bool,
    pub accept: &'static str,
}

impl HttpRequest {
    pub fn new(provider_id: &str, url: Url) -> Self {
        Self { provider_id: provider_id.to_string(), url, headers: Vec::new(), cacheable: true, accept: "application/json" }
    }

    pub fn header(mut self, name: &'static str, value: &str) -> SpectreResult<Self> {
        let value = HeaderValue::from_str(value).map_err(|_| SpectreError::invalid_input("invalid header value"))?;
        self.headers.push((HeaderName::from_static(name), value));
        Ok(self)
    }

    /// Mark a header value as sensitive so it is never printed by `Debug`.
    pub fn sensitive_header(mut self, name: &'static str, value: &str) -> SpectreResult<Self> {
        let mut value = HeaderValue::from_str(value).map_err(|_| SpectreError::invalid_input("invalid header value"))?;
        value.set_sensitive(true);
        self.headers.push((HeaderName::from_static(name), value));
        Ok(self)
    }

    pub fn accept(mut self, accept: &'static str) -> Self {
        self.accept = accept;
        self
    }

    pub fn no_cache(mut self) -> Self {
        self.cacheable = false;
        self
    }

    fn cache_key(&self) -> String {
        format!("{}|{}|{}", self.provider_id, self.accept, self.url)
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Arc<Vec<u8>>,
    pub from_cache: bool,
    pub retry_after: Option<Duration>,
    pub final_url: Url,
    /// Response headers, lowercased names. Empty for cached responses.
    pub headers: Vec<(String, String)>,
}

impl HttpResponse {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn json<T: DeserializeOwned>(&self) -> SpectreResult<T> {
        serde_json::from_slice(&self.body).map_err(|error| {
            SpectreError::new(ErrorCode::UpstreamError, format!("unexpected response format from {}: {error}", host_of(&self.final_url)))
        })
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// First value of a header (case-insensitive name).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
    }

    /// Map non-success statuses to structured errors.
    pub fn ensure_success(self) -> SpectreResult<Self> {
        if self.is_success() {
            return Ok(self);
        }
        Err(status_error(self.status, &self.final_url, self.retry_after))
    }
}

pub fn status_error(status: u16, url: &Url, retry_after: Option<Duration>) -> SpectreError {
    let host = host_of(url);
    match status {
        401 => SpectreError::new(ErrorCode::Unauthorized, format!("{host} rejected the credentials (401)")),
        403 => SpectreError::new(ErrorCode::Unauthorized, format!("{host} refused the request (403)")),
        404 => SpectreError::not_found(format!("{host} returned 404")),
        429 => SpectreError::new(
            ErrorCode::RateLimited,
            match retry_after {
                Some(delay) => format!("{host} rate limit exceeded; retry after {}s", delay.as_secs()),
                None => format!("{host} rate limit exceeded"),
            },
        ),
        500..=599 => SpectreError::new(ErrorCode::UpstreamError, format!("{host} returned server error {status}")),
        other => SpectreError::new(ErrorCode::UpstreamError, format!("{host} returned unexpected status {other}")),
    }
}

fn host_of(url: &Url) -> String {
    url.host_str().unwrap_or("upstream").to_string()
}

/// Per-operation counters (one per investigation run).
#[derive(Debug, Default)]
pub struct RequestStats {
    pub requests: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub retries: AtomicU64,
}

impl RequestStats {
    pub fn snapshot(&self) -> RequestStatsSnapshot {
        RequestStatsSnapshot {
            requests: self.requests.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            retries: self.retries.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct RequestStatsSnapshot {
    pub requests: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub retries: u64,
}

// ---------------------------------------------------------------------------
// Rate limiting & retry
// ---------------------------------------------------------------------------

/// Spaces requests evenly: at most `per_minute` requests per minute, no burst.
#[derive(Debug)]
pub struct RateLimiter {
    interval: Duration,
    next_slot: Mutex<Instant>,
}

impl RateLimiter {
    pub fn per_minute(per_minute: u32) -> Self {
        let per_minute = per_minute.max(1);
        Self { interval: Duration::from_secs(60) / per_minute, next_slot: Mutex::new(Instant::now()) }
    }

    /// Reserve the next slot and return how long the caller must wait.
    pub fn reserve(&self) -> Duration {
        let mut next_slot = self.next_slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        let slot = (*next_slot).max(now);
        *next_slot = slot + self.interval;
        slot.saturating_duration_since(now)
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }
}

/// Retry configuration derived from [`crate::config::EngineSettings`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpSettings {
    pub request_timeout: Duration,
    pub max_retries: u32,
    pub retry_base_delay: Duration,
    pub cache_ttl: Duration,
    pub default_rate_limit_per_minute: u32,
}

impl Default for HttpSettings {
    fn default() -> Self {
        let defaults = crate::config::EngineSettings::default();
        Self::from(&defaults)
    }
}

impl From<&crate::config::EngineSettings> for HttpSettings {
    fn from(settings: &crate::config::EngineSettings) -> Self {
        Self {
            request_timeout: Duration::from_secs(settings.request_timeout_secs.into()),
            max_retries: settings.max_retries,
            retry_base_delay: Duration::from_millis(settings.retry_base_delay_ms.into()),
            cache_ttl: Duration::from_secs(settings.cache_ttl_secs.into()),
            default_rate_limit_per_minute: settings.default_rate_limit_per_minute,
        }
    }
}

/// Exponential backoff with "equal jitter": half the capped delay is fixed,
/// the other half is random, which avoids synchronized retry storms.
pub fn backoff_delay(base: Duration, attempt: u32) -> Duration {
    let exponential = base.saturating_mul(2u32.saturating_pow(attempt)).min(MAX_BACKOFF);
    let half = exponential / 2;
    let jitter_ms = rand::random_range(0..=half.as_millis().max(1) as u64);
    half + Duration::from_millis(jitter_ms)
}

/// Sleep unless cancelled first.
pub async fn sleep_cancellable(delay: Duration, cancellation: &CancellationToken) -> SpectreResult<()> {
    if delay.is_zero() {
        return if cancellation.is_cancelled() { Err(SpectreError::cancelled()) } else { Ok(()) };
    }
    tokio::select! {
        _ = cancellation.cancelled() => Err(SpectreError::cancelled()),
        _ = tokio::time::sleep(delay) => Ok(()),
    }
}

fn parse_retry_after(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

fn is_retryable_status(status: u16) -> bool {
    matches!(status, 429 | 500 | 502 | 503 | 504)
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

struct CacheEntry {
    stored_at: Instant,
    status: u16,
    body: Arc<Vec<u8>>,
    final_url: Url,
}

struct HttpInner {
    client: reqwest::Client,
    policy: Arc<EndpointPolicy>,
    settings: RwLock<HttpSettings>,
    cache: Mutex<HashMap<String, CacheEntry>>,
    limiters: Mutex<HashMap<String, Arc<RateLimiter>>>,
    rate_overrides: RwLock<HashMap<String, u32>>,
    totals: RequestStats,
}

/// Cheaply cloneable handle to the shared HTTP client.
#[derive(Clone)]
pub struct HttpClient {
    inner: Arc<HttpInner>,
}

impl std::fmt::Debug for HttpClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("HttpClient").field("allowed_hosts", &self.inner.policy.allowed_hosts()).finish()
    }
}

impl HttpClient {
    pub fn new(policy: Arc<EndpointPolicy>, settings: HttpSettings) -> SpectreResult<Self> {
        let redirect_policy = {
            let policy = Arc::clone(&policy);
            reqwest::redirect::Policy::custom(move |attempt| {
                if attempt.previous().len() >= 5 {
                    attempt.error("too many redirects")
                } else if policy.check(attempt.url()).is_err() {
                    attempt.error("redirect target is not an approved endpoint")
                } else {
                    attempt.follow()
                }
            })
        };
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .redirect(redirect_policy)
            .connect_timeout(Duration::from_secs(10))
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(4)
            .build()
            .map_err(|error| SpectreError::internal(format!("failed to build HTTP client: {error}")))?;
        Ok(Self {
            inner: Arc::new(HttpInner {
                client,
                policy,
                settings: RwLock::new(settings),
                cache: Mutex::new(HashMap::new()),
                limiters: Mutex::new(HashMap::new()),
                rate_overrides: RwLock::new(HashMap::new()),
                totals: RequestStats::default(),
            }),
        })
    }

    pub fn policy(&self) -> &EndpointPolicy {
        &self.inner.policy
    }

    pub fn settings(&self) -> HttpSettings {
        *self.inner.settings.read().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn update_settings(&self, settings: HttpSettings) {
        *self.inner.settings.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = settings;
        self.inner.limiters.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clear();
        if settings.cache_ttl.is_zero() {
            self.clear_cache();
        }
    }

    /// Override the rate limit for one provider (`None` restores the default).
    pub fn set_rate_limit(&self, provider_id: &str, per_minute: Option<u32>) {
        {
            let mut overrides = self.inner.rate_overrides.write().unwrap_or_else(|poisoned| poisoned.into_inner());
            match per_minute {
                Some(limit) => overrides.insert(provider_id.to_string(), limit),
                None => overrides.remove(provider_id),
            };
        }
        self.inner.limiters.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(provider_id);
    }

    pub fn clear_cache(&self) {
        self.inner.cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clear();
    }

    pub fn totals(&self) -> RequestStatsSnapshot {
        self.inner.totals.snapshot()
    }

    pub fn cache_len(&self) -> usize {
        self.inner.cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).len()
    }

    fn limiter_for(&self, provider_id: &str) -> Arc<RateLimiter> {
        let mut limiters = self.inner.limiters.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        Arc::clone(limiters.entry(provider_id.to_string()).or_insert_with(|| {
            let per_minute = self
                .inner
                .rate_overrides
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(provider_id)
                .copied()
                .unwrap_or_else(|| self.settings().default_rate_limit_per_minute);
            Arc::new(RateLimiter::per_minute(per_minute))
        }))
    }

    fn cache_lookup(&self, key: &str, ttl: Duration) -> Option<HttpResponse> {
        if ttl.is_zero() {
            return None;
        }
        let cache = self.inner.cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = cache.get(key)?;
        (entry.stored_at.elapsed() < ttl).then(|| HttpResponse {
            status: entry.status,
            body: Arc::clone(&entry.body),
            from_cache: true,
            retry_after: None,
            final_url: entry.final_url.clone(),
            headers: Vec::new(),
        })
    }

    fn cache_store(&self, key: String, response: &HttpResponse, ttl: Duration) {
        if ttl.is_zero() || !(response.is_success() || response.status == 404) {
            return;
        }
        let mut cache = self.inner.cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if cache.len() >= MAX_CACHE_ENTRIES {
            cache.retain(|_, entry| entry.stored_at.elapsed() < ttl);
            if cache.len() >= MAX_CACHE_ENTRIES
                && let Some(oldest_key) = cache.iter().min_by_key(|(_, entry)| entry.stored_at).map(|(key, _)| key.clone())
            {
                cache.remove(&oldest_key);
            }
        }
        cache.insert(
            key,
            CacheEntry {
                stored_at: Instant::now(),
                status: response.status,
                body: Arc::clone(&response.body),
                final_url: response.final_url.clone(),
            },
        );
    }

    /// Policy-checked GET with rate limiting, retries, caching, cancellation.
    ///
    /// Returns the final response for any HTTP status; callers decide how to
    /// interpret 404 and other statuses (see [`HttpResponse::ensure_success`]).
    pub async fn get(&self, request: HttpRequest, cancellation: &CancellationToken, stats: &RequestStats) -> SpectreResult<HttpResponse> {
        self.inner.policy.check(&request.url)?;
        let settings = self.settings();
        let cache_key = request.cache_key();
        if request.cacheable {
            if let Some(cached) = self.cache_lookup(&cache_key, settings.cache_ttl) {
                stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                self.inner.totals.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Ok(cached);
            }
            stats.cache_misses.fetch_add(1, Ordering::Relaxed);
            self.inner.totals.cache_misses.fetch_add(1, Ordering::Relaxed);
        }

        let limiter = self.limiter_for(&request.provider_id);
        let mut attempt: u32 = 0;
        loop {
            sleep_cancellable(limiter.reserve(), cancellation).await?;
            stats.requests.fetch_add(1, Ordering::Relaxed);
            self.inner.totals.requests.fetch_add(1, Ordering::Relaxed);

            let mut builder = self.inner.client.get(request.url.clone()).timeout(settings.request_timeout).header(ACCEPT, request.accept);
            for (name, value) in &request.headers {
                builder = builder.header(name, value.clone());
            }

            let outcome = tokio::select! {
                _ = cancellation.cancelled() => return Err(SpectreError::cancelled()),
                result = builder.send() => result,
            };

            let can_retry = attempt < settings.max_retries;
            match outcome {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let retry_after = parse_retry_after(response.headers());
                    if is_retryable_status(status) && can_retry {
                        let delay = match retry_after {
                            Some(delay) if delay <= MAX_RETRY_AFTER => delay,
                            Some(_) => {
                                // The server asked us to back off longer than we are
                                // willing to wait inside an investigation.
                                return Ok(HttpResponse {
                                    status,
                                    body: Arc::new(Vec::new()),
                                    from_cache: false,
                                    retry_after,
                                    final_url: response.url().clone(),
                                    headers: collect_headers(response.headers()),
                                });
                            }
                            None => backoff_delay(settings.retry_base_delay, attempt),
                        };
                        tracing::debug!(provider = %request.provider_id, status, attempt, "retrying after transient status");
                        attempt += 1;
                        stats.retries.fetch_add(1, Ordering::Relaxed);
                        self.inner.totals.retries.fetch_add(1, Ordering::Relaxed);
                        sleep_cancellable(delay, cancellation).await?;
                        continue;
                    }
                    let final_url = response.url().clone();
                    let headers = collect_headers(response.headers());
                    let body = tokio::select! {
                        _ = cancellation.cancelled() => return Err(SpectreError::cancelled()),
                        body = read_limited(response, MAX_BODY_BYTES) => body?,
                    };
                    let response = HttpResponse { status, body: Arc::new(body), from_cache: false, retry_after, final_url, headers };
                    if request.cacheable {
                        self.cache_store(cache_key, &response, settings.cache_ttl);
                    }
                    return Ok(response);
                }
                Err(error) => {
                    let transient = error.is_timeout() || error.is_connect() || error.is_request();
                    if transient && can_retry && !error.is_redirect() {
                        tracing::debug!(provider = %request.provider_id, attempt, "retrying after transport error");
                        let delay = backoff_delay(settings.retry_base_delay, attempt);
                        attempt += 1;
                        stats.retries.fetch_add(1, Ordering::Relaxed);
                        self.inner.totals.retries.fetch_add(1, Ordering::Relaxed);
                        sleep_cancellable(delay, cancellation).await?;
                        continue;
                    }
                    return Err(map_transport_error(&error));
                }
            }
        }
    }

    /// Fetch a public web page on a user-supplied domain.
    ///
    /// The destination host is resolved first; every resolved address must be
    /// publicly routable, and the connection is pinned to those addresses to
    /// prevent DNS-rebinding. Redirects are followed manually (max 3), each
    /// hop re-validated the same way.
    pub async fn fetch_public_web(
        &self,
        provider_id: &str,
        url: Url,
        cancellation: &CancellationToken,
        stats: &RequestStats,
    ) -> SpectreResult<HttpResponse> {
        let settings = self.settings();
        let limiter = self.limiter_for(provider_id);
        let mut current = url;
        for _ in 0..=MAX_WEB_REDIRECTS {
            let (host, addresses) = validate_public_web_url(&current).await?;
            sleep_cancellable(limiter.reserve(), cancellation).await?;
            stats.requests.fetch_add(1, Ordering::Relaxed);
            self.inner.totals.requests.fetch_add(1, Ordering::Relaxed);

            let client = reqwest::Client::builder()
                .user_agent(USER_AGENT)
                .redirect(reqwest::redirect::Policy::none())
                .resolve_to_addrs(&host, &addresses)
                .connect_timeout(Duration::from_secs(10))
                .timeout(settings.request_timeout)
                .https_only(true)
                .build()
                .map_err(|error| SpectreError::internal(format!("failed to build HTTP client: {error}")))?;
            let request = client.get(current.clone()).header(ACCEPT, "text/html,text/plain;q=0.9,*/*;q=0.1");
            let response = tokio::select! {
                _ = cancellation.cancelled() => return Err(SpectreError::cancelled()),
                result = request.send() => result.map_err(|error| map_transport_error(&error))?,
            };
            let status = response.status().as_u16();
            if response.status().is_redirection() {
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| SpectreError::new(ErrorCode::UpstreamError, "redirect without location"))?;
                current = current.join(location).map_err(|_| SpectreError::new(ErrorCode::UpstreamError, "invalid redirect location"))?;
                continue;
            }
            let final_url = response.url().clone();
            let headers = collect_headers(response.headers());
            let body = tokio::select! {
                _ = cancellation.cancelled() => return Err(SpectreError::cancelled()),
                body = read_limited(response, MAX_WEB_BODY_BYTES) => body?,
            };
            return Ok(HttpResponse { status, body: Arc::new(body), from_cache: false, retry_after: None, final_url, headers });
        }
        Err(policy_violation("too many redirects"))
    }
}

/// Validate a public-web URL and resolve it to public addresses only.
pub async fn validate_public_web_url(url: &Url) -> SpectreResult<(String, Vec<SocketAddr>)> {
    if url.scheme() != "https" {
        return Err(policy_violation("only HTTPS web pages are fetched"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(policy_violation("URLs with embedded credentials are not allowed"));
    }
    if !matches!(url.port(), None | Some(443)) {
        return Err(policy_violation("non-standard ports are not allowed"));
    }
    let host = match url.host() {
        Some(url::Host::Domain(domain)) => crate::target::normalize_domain(domain)?,
        _ => return Err(policy_violation("web pages must be addressed by domain name")),
    };
    let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 443))
        .await
        .map_err(|error| SpectreError::new(ErrorCode::Network, format!("could not resolve {host}: {error}")))?
        .collect();
    if resolved.is_empty() {
        return Err(SpectreError::new(ErrorCode::Network, format!("{host} did not resolve")));
    }
    if let Some(blocked) = resolved.iter().find(|address| !is_public_ip(address.ip())) {
        return Err(policy_violation(format!("{host} resolves to non-public address {}", blocked.ip())));
    }
    Ok((host, resolved))
}

/// Headers worth keeping: security policy, banners, rate limits. Never cookies.
const KEPT_HEADERS: [&str; 12] = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "server",
    "x-powered-by",
    "content-type",
    "x-ratelimit-remaining",
    "location",
];

fn collect_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    KEPT_HEADERS
        .iter()
        .filter_map(|name| headers.get(*name).and_then(|value| value.to_str().ok()).map(|value| (name.to_string(), value.to_string())))
        .collect()
}

async fn read_limited(mut response: reqwest::Response, limit: usize) -> SpectreResult<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| map_transport_error(&error))? {
        if body.len() + chunk.len() > limit {
            return Err(SpectreError::new(ErrorCode::UpstreamError, "response body exceeds size limit"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn map_transport_error(error: &reqwest::Error) -> SpectreError {
    // Never include the URL: it can contain the investigated identifier.
    if error.is_timeout() {
        SpectreError::new(ErrorCode::Timeout, "request timed out")
    } else if error.is_redirect() {
        policy_violation("redirect to an unapproved destination was blocked")
    } else if error.is_connect() {
        SpectreError::new(ErrorCode::Network, "could not connect to provider")
    } else if error.is_body() || error.is_decode() {
        SpectreError::new(ErrorCode::UpstreamError, "failed to read provider response")
    } else {
        SpectreError::new(ErrorCode::Network, "network request failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_client(settings: HttpSettings) -> HttpClient {
        HttpClient::new(Arc::new(EndpointPolicy::for_testing()), settings).unwrap()
    }

    fn fast_settings() -> HttpSettings {
        HttpSettings {
            request_timeout: Duration::from_secs(5),
            max_retries: 2,
            retry_base_delay: Duration::from_millis(10),
            cache_ttl: Duration::from_secs(60),
            default_rate_limit_per_minute: 6000,
        }
    }

    #[test]
    fn policy_rejects_unapproved_destinations() {
        let policy = EndpointPolicy::new(["api.github.com"]);
        assert!(policy.check(&Url::parse("https://api.github.com/users/x").unwrap()).is_ok());
        assert!(policy.check(&Url::parse("https://API.GitHub.com./users/x").unwrap()).is_ok());
        assert!(policy.check(&Url::parse("http://api.github.com/users/x").unwrap()).is_err());
        assert!(policy.check(&Url::parse("https://evil.example/users/x").unwrap()).is_err());
        assert!(policy.check(&Url::parse("https://api.github.com:8443/").unwrap()).is_err());
        assert!(policy.check(&Url::parse("https://user:pw@api.github.com/").unwrap()).is_err());
        assert!(policy.check(&Url::parse("https://127.0.0.1/").unwrap()).is_err());
        assert!(policy.check(&Url::parse("https://169.254.169.254/latest/meta-data").unwrap()).is_err());
        assert!(policy.check(&Url::parse("http://127.0.0.1:8080/").unwrap()).is_err());
    }

    #[test]
    fn public_ip_classification() {
        for blocked in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:10.0.0.1",
            "198.18.0.1",
            "224.0.0.1",
        ] {
            assert!(!is_public_ip(blocked.parse().unwrap()), "{blocked} should be blocked");
        }
        for allowed in ["8.8.8.8", "140.82.112.3", "2606:4700:4700::1111"] {
            assert!(is_public_ip(allowed.parse().unwrap()), "{allowed} should be allowed");
        }
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        let base = Duration::from_millis(100);
        for attempt in 0..10 {
            let delay = backoff_delay(base, attempt);
            assert!(delay <= MAX_BACKOFF);
        }
        let first = backoff_delay(base, 0);
        assert!(first >= Duration::from_millis(50) && first <= Duration::from_millis(100));
    }

    #[test]
    fn rate_limiter_spaces_requests() {
        let limiter = RateLimiter::per_minute(60);
        assert_eq!(limiter.reserve(), Duration::ZERO);
        let second = limiter.reserve();
        assert!(second > Duration::from_millis(900) && second <= Duration::from_secs(1));
    }

    #[tokio::test]
    async fn retries_transient_failures_then_succeeds() {
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/flaky")).respond_with(ResponseTemplate::new(503)).up_to_n_times(2).mount(&server).await;
        Mock::given(method("GET"))
            .and(path("/flaky"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{\"ok\":true}"))
            .mount(&server)
            .await;

        let client = test_client(fast_settings());
        let stats = RequestStats::default();
        let url = Url::parse(&format!("{}/flaky", server.uri())).unwrap();
        let response = client.get(HttpRequest::new("test", url), &CancellationToken::new(), &stats).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(stats.snapshot().requests, 3);
        assert_eq!(stats.snapshot().retries, 2);
    }

    #[tokio::test]
    async fn honours_retry_after_and_gives_up_after_max_retries() {
        let server = MockServer::start().await;
        Mock::given(method("GET")).respond_with(ResponseTemplate::new(429).insert_header("retry-after", "0")).mount(&server).await;
        let client = test_client(fast_settings());
        let stats = RequestStats::default();
        let url = Url::parse(&format!("{}/limited", server.uri())).unwrap();
        let response = client.get(HttpRequest::new("test", url), &CancellationToken::new(), &stats).await.unwrap();
        assert_eq!(response.status, 429);
        assert_eq!(stats.snapshot().requests, 3);
        let error = response.ensure_success().unwrap_err();
        assert_eq!(error.code, ErrorCode::RateLimited);
    }

    #[tokio::test]
    async fn caches_successful_and_not_found_responses() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/hit"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET")).and(path("/missing")).respond_with(ResponseTemplate::new(404)).expect(1).mount(&server).await;
        let client = test_client(fast_settings());
        let stats = RequestStats::default();
        for path_segment in ["hit", "hit", "missing", "missing"] {
            let url = Url::parse(&format!("{}/{path_segment}", server.uri())).unwrap();
            client.get(HttpRequest::new("test", url), &CancellationToken::new(), &stats).await.unwrap();
        }
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.cache_hits, 2);
        assert_eq!(snapshot.cache_misses, 2);
    }

    #[tokio::test]
    async fn cancellation_interrupts_in_flight_requests() {
        let server = MockServer::start().await;
        Mock::given(method("GET")).respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(10))).mount(&server).await;
        let client = test_client(fast_settings());
        let cancellation = CancellationToken::new();
        let trigger = cancellation.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            trigger.cancel();
        });
        let started = Instant::now();
        let url = Url::parse(&format!("{}/slow", server.uri())).unwrap();
        let error = client.get(HttpRequest::new("test", url), &cancellation, &RequestStats::default()).await.unwrap_err();
        assert_eq!(error.code, ErrorCode::Cancelled);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn public_web_fetch_refuses_internal_destinations() {
        for url in ["http://example.com/", "https://localhost/", "https://127.0.0.1/", "https://example.com:8080/"] {
            let parsed = Url::parse(url).unwrap();
            assert!(validate_public_web_url(&parsed).await.is_err(), "{url} must be refused");
        }
    }
}
