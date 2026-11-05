//! Pwned Passwords k-anonymity range API —
//! https://haveibeenpwned.com/API/v3#PwnedPasswords

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use spectre_core::error::{SpectreError, SpectreResult};
use spectre_core::http::{HttpClient, HttpRequest, RequestStats};
use tokio_util::sync::CancellationToken;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

pub const PWNED_PASSWORDS_HOST: &str = "api.pwnedpasswords.com";
const PROVIDER_ID: &str = "pwned-passwords";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordCheckResult {
    pub compromised: bool,
    pub occurrences: u64,
    pub recommendation: String,
    pub checked_at: DateTime<Utc>,
    /// Number of non-padding suffixes in the range response (k-anonymity set).
    pub range_size: u32,
}

pub struct PwnedPasswordsClient {
    base: Url,
}

impl Default for PwnedPasswordsClient {
    fn default() -> Self {
        Self { base: Url::parse("https://api.pwnedpasswords.com/").expect("valid URL") }
    }
}

/// Uppercase hex SHA-1 of the password, held in zeroizing memory.
fn sha1_hex(password: &[u8]) -> Zeroizing<String> {
    let mut digest = Sha1::digest(password);
    let encoded = Zeroizing::new(hex::encode_upper(digest.as_slice()));
    digest.as_mut_slice().zeroize();
    encoded
}

/// Find `suffix` in a range response, ignoring padding entries (count 0).
pub fn count_in_range(body: &str, suffix: &str) -> (u64, u32) {
    let mut occurrences = 0;
    let mut range_size = 0;
    for line in body.lines() {
        let Some((candidate, count)) = line.trim().split_once(':') else { continue };
        let count: u64 = count.trim().parse().unwrap_or(0);
        if count == 0 {
            continue;
        }
        range_size += 1;
        if candidate.eq_ignore_ascii_case(suffix) {
            occurrences = count;
        }
    }
    (occurrences, range_size)
}

impl PwnedPasswordsClient {
    pub fn with_base(base: Url) -> Self {
        Self { base }
    }

    pub fn host(&self) -> String {
        self.base.host_str().unwrap_or(PWNED_PASSWORDS_HOST).to_string()
    }

    /// Check a password. The plaintext and full hash never leave this
    /// function; neither is logged or persisted.
    pub async fn check(
        &self,
        http: &HttpClient,
        cancellation: &CancellationToken,
        stats: &RequestStats,
        password: &Zeroizing<Vec<u8>>,
    ) -> SpectreResult<PasswordCheckResult> {
        if password.is_empty() {
            return Err(SpectreError::invalid_input("password is empty"));
        }
        if password.len() > 4096 {
            return Err(SpectreError::invalid_input("password exceeds 4096 bytes"));
        }
        let hash = sha1_hex(password);
        let (prefix, suffix) = hash.split_at(5);
        let mut url = self.base.clone();
        if let Ok(mut path) = url.path_segments_mut() {
            path.pop_if_empty().push("range").push(prefix);
        }
        let request = HttpRequest::new(PROVIDER_ID, url).accept("text/plain").header("add-padding", "true")?.no_cache();
        let response = http.get(request, cancellation, stats).await?.ensure_success()?;
        let (occurrences, range_size) = count_in_range(&response.text(), suffix);
        let compromised = occurrences > 0;
        let recommendation = if compromised {
            format!(
                "This password appears {occurrences} time(s) in known breach data. Stop using it everywhere, replace it with a unique password from a password manager, and enable MFA."
            )
        } else {
            "Not found in the Pwned Passwords dataset. That does not make it strong: use a long, unique password and enable MFA."
                .to_string()
        };
        Ok(PasswordCheckResult { compromised, occurrences, recommendation, checked_at: Utc::now(), range_size })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use spectre_core::http::{EndpointPolicy, HttpSettings};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    use super::*;

    #[test]
    fn hashing_matches_known_vector() {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        assert_eq!(sha1_hex(b"password").as_str(), "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    #[test]
    fn range_parsing_ignores_padding() {
        let body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\r\n0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\r\n";
        assert_eq!(count_in_range(body, "1e4c9b93f3f0682250b6cf8331b7ee68fd8"), (9659365, 2));
        assert_eq!(count_in_range(body, "0018A45C4D1DEF81644B54AB7F969B88D65"), (0, 2));
    }

    #[tokio::test]
    async fn only_the_prefix_is_transmitted() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/range/5BAA6"))
            .and(header("add-padding", "true"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\r\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0\r\n"),
            )
            .mount(&server)
            .await;
        let settings = HttpSettings {
            request_timeout: Duration::from_secs(5),
            max_retries: 0,
            retry_base_delay: Duration::from_millis(10),
            cache_ttl: Duration::from_secs(60),
            default_rate_limit_per_minute: 6000,
        };
        let http = HttpClient::new(Arc::new(EndpointPolicy::for_testing()), settings).unwrap();
        let client = PwnedPasswordsClient::with_base(Url::parse(&format!("{}/", server.uri())).unwrap());
        let password = Zeroizing::new(b"password".to_vec());
        let result = client.check(&http, &CancellationToken::new(), &RequestStats::default(), &password).await.unwrap();
        assert!(result.compromised);
        assert_eq!(result.occurrences, 42);
        assert_eq!(result.range_size, 1);
        assert_eq!(http.cache_len(), 0, "range responses are never cached");

        let requests: Vec<Request> = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let sent = format!("{} {:?} {}", requests[0].url, requests[0].headers, String::from_utf8_lossy(&requests[0].body));
        assert!(!sent.contains("password"), "plaintext must never be sent");
        assert!(!sent.to_uppercase().contains("1E4C9B93F3F0682250B6CF8331B7EE68FD8"), "hash suffix must never be sent");
    }

    #[tokio::test]
    async fn rejects_empty_passwords() {
        let http = HttpClient::new(Arc::new(EndpointPolicy::for_testing()), HttpSettings::default()).unwrap();
        let error = PwnedPasswordsClient::default()
            .check(&http, &CancellationToken::new(), &RequestStats::default(), &Zeroizing::new(Vec::new()))
            .await
            .unwrap_err();
        assert_eq!(error.code, spectre_core::error::ErrorCode::InvalidInput);
    }
}
