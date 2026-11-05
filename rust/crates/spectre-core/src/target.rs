//! Investigation targets: validation and normalization of user input.
//!
//! All user-supplied identifiers pass through [`InvestigationTarget::parse`]
//! before they reach a provider. Normalization is deliberately strict: the
//! normalized value is interpolated into provider URLs (always URL-encoded as
//! well), so rejecting unexpected characters early is a first SSRF/injection
//! barrier.

use std::fmt;
use std::str::FromStr;
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::error::{SpectreError, SpectreResult};

/// The kind of identifier being investigated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TargetType {
    Username,
    Email,
    Phone,
    Domain,
}

impl TargetType {
    pub const ALL: [TargetType; 4] = [Self::Username, Self::Email, Self::Phone, Self::Domain];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Username => "username",
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Domain => "domain",
        }
    }
}

impl fmt::Display for TargetType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for TargetType {
    type Err = SpectreError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "username" => Ok(Self::Username),
            "email" => Ok(Self::Email),
            "phone" => Ok(Self::Phone),
            "domain" => Ok(Self::Domain),
            other => Err(SpectreError::invalid_input(format!("unknown target type '{other}'"))),
        }
    }
}

/// A validated, normalized investigation target.
///
/// Instances can only be created through [`InvestigationTarget::parse`] (or
/// deserialization, which re-validates), so downstream code can rely on the
/// value being normalized.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum InvestigationTarget {
    Username(String),
    Email(String),
    Phone(String),
    Domain(String),
}

impl<'de> Deserialize<'de> for InvestigationTarget {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(rename = "type")]
            target_type: TargetType,
            value: String,
        }
        let raw = Raw::deserialize(deserializer)?;
        InvestigationTarget::parse(raw.target_type, &raw.value).map_err(serde::de::Error::custom)
    }
}

impl InvestigationTarget {
    /// Validate and normalize raw input for the given target type.
    pub fn parse(target_type: TargetType, raw: &str) -> SpectreResult<Self> {
        Self::parse_with_region(target_type, raw, None)
    }

    /// Like [`parse`](Self::parse) but allows a default ISO 3166 region for
    /// phone numbers written without an international prefix.
    pub fn parse_with_region(target_type: TargetType, raw: &str, default_region: Option<&str>) -> SpectreResult<Self> {
        match target_type {
            TargetType::Username => normalize_username(raw).map(Self::Username),
            TargetType::Email => normalize_email(raw).map(Self::Email),
            TargetType::Phone => normalize_phone(raw, default_region).map(|parsed| Self::Phone(parsed.e164)),
            TargetType::Domain => normalize_domain(raw).map(Self::Domain),
        }
    }

    pub fn target_type(&self) -> TargetType {
        match self {
            Self::Username(_) => TargetType::Username,
            Self::Email(_) => TargetType::Email,
            Self::Phone(_) => TargetType::Phone,
            Self::Domain(_) => TargetType::Domain,
        }
    }

    pub fn value(&self) -> &str {
        match self {
            Self::Username(value) | Self::Email(value) | Self::Phone(value) | Self::Domain(value) => value,
        }
    }
}

impl fmt::Display for InvestigationTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.target_type(), self.value())
    }
}

static USERNAME_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9_])?$").expect("valid regex"));

static EMAIL_LOCAL_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    // RFC 5322 dot-atom (unquoted) local part. Quoted local parts are rejected:
    // they are vanishingly rare and complicate safe handling.
    Regex::new(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$").expect("valid regex")
});

static DOMAIN_LABEL_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$").expect("valid regex"));

/// Special-use and internal names that are never valid OSINT targets and
/// could otherwise be used to point the engine at local infrastructure.
const RESERVED_SUFFIXES: [&str; 9] = ["localhost", "local", "internal", "invalid", "test", "example", "onion", "home.arpa", "lan"];

/// Normalize a username: trims whitespace and a leading `@`, enforces a
/// conservative character set shared by the supported platforms.
pub fn normalize_username(raw: &str) -> SpectreResult<String> {
    let trimmed = raw.trim().trim_start_matches('@');
    if trimmed.is_empty() {
        return Err(SpectreError::invalid_input("username is empty"));
    }
    if !USERNAME_PATTERN.is_match(trimmed) {
        return Err(SpectreError::invalid_input(
            "username may contain letters, digits, '.', '_' and '-' (max 64 characters) and must start with a letter or digit",
        ));
    }
    Ok(trimmed.to_string())
}

/// Normalize an email address: lowercases it, validates the local part as an
/// RFC 5322 dot-atom and the domain with [`normalize_domain`].
pub fn normalize_email(raw: &str) -> SpectreResult<String> {
    let trimmed = raw.trim();
    if trimmed.len() > 254 {
        return Err(SpectreError::invalid_input("email address exceeds 254 characters"));
    }
    let (local, domain) = trimmed.rsplit_once('@').ok_or_else(|| SpectreError::invalid_input("email address must contain '@'"))?;
    if local.is_empty() || local.len() > 64 || !EMAIL_LOCAL_PATTERN.is_match(local) {
        return Err(SpectreError::invalid_input("email local part is invalid"));
    }
    let domain = normalize_domain(domain)?;
    Ok(format!("{}@{}", local.to_ascii_lowercase(), domain))
}

/// Normalize a domain name to lowercase ASCII (IDNA/punycode), rejecting IP
/// literals, single-label names, and reserved/internal suffixes.
pub fn normalize_domain(raw: &str) -> SpectreResult<String> {
    let mut candidate = raw.trim().to_string();
    if candidate.contains("://") {
        let parsed = url::Url::parse(&candidate).map_err(|_| SpectreError::invalid_input("domain is not a valid URL or hostname"))?;
        candidate = parsed.host_str().ok_or_else(|| SpectreError::invalid_input("URL has no host"))?.to_string();
    }
    let candidate = candidate.trim_end_matches('.');
    if candidate.is_empty() {
        return Err(SpectreError::invalid_input("domain is empty"));
    }
    let ascii = match url::Host::parse(candidate) {
        Ok(url::Host::Domain(domain)) => domain.to_ascii_lowercase(),
        Ok(url::Host::Ipv4(_) | url::Host::Ipv6(_)) => {
            return Err(SpectreError::invalid_input("IP addresses are not supported as domain targets"));
        }
        Err(_) => return Err(SpectreError::invalid_input("domain contains invalid characters")),
    };
    if ascii.len() > 253 {
        return Err(SpectreError::invalid_input("domain exceeds 253 characters"));
    }
    let labels: Vec<&str> = ascii.split('.').collect();
    if labels.len() < 2 {
        return Err(SpectreError::invalid_input("domain must include a top-level domain"));
    }
    if labels.iter().any(|label| !DOMAIN_LABEL_PATTERN.is_match(label)) {
        return Err(SpectreError::invalid_input("domain label is invalid"));
    }
    let top_level = labels.last().copied().unwrap_or_default();
    if top_level.chars().all(|character| character.is_ascii_digit()) {
        return Err(SpectreError::invalid_input("top-level domain cannot be numeric"));
    }
    if RESERVED_SUFFIXES.iter().any(|suffix| ascii == *suffix || ascii.ends_with(&format!(".{suffix}"))) {
        return Err(SpectreError::invalid_input("reserved or internal domains are not valid targets"));
    }
    Ok(ascii)
}

/// Public numbering-plan metadata derived offline from libphonenumber data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhoneNumberInfo {
    pub e164: String,
    pub international_format: String,
    pub national_format: String,
    pub country_calling_code: u16,
    /// ISO 3166-1 alpha-2 region, when the number maps to a single region.
    pub region_code: Option<String>,
    pub number_type: String,
    pub is_valid: bool,
}

/// Parse and normalize a phone number to E.164.
///
/// Numbers without a `+` prefix require `default_region`. Only numbers that
/// libphonenumber considers valid for their region are accepted.
pub fn normalize_phone(raw: &str, default_region: Option<&str>) -> SpectreResult<PhoneNumberInfo> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(SpectreError::invalid_input("phone number is empty"));
    }
    if trimmed.len() > 32 {
        return Err(SpectreError::invalid_input("phone number is too long"));
    }
    let region = match default_region {
        Some(code) if !code.trim().is_empty() => Some(
            phonenumber::country::Id::from_str(&code.trim().to_ascii_uppercase())
                .map_err(|_| SpectreError::invalid_input(format!("unknown region code '{code}'")))?,
        ),
        _ => None,
    };
    if region.is_none() && !trimmed.starts_with('+') {
        return Err(SpectreError::invalid_input(
            "phone number must start with '+' and a country code, or a default region must be provided",
        ));
    }
    let parsed = phonenumber::parse(region, trimmed)
        .map_err(|error| SpectreError::invalid_input(format!("phone number could not be parsed: {error}")))?;
    let is_valid = phonenumber::is_valid(&parsed);
    if !is_valid {
        return Err(SpectreError::invalid_input("phone number is not valid for its numbering plan"));
    }
    let number_type = parsed.number_type(&phonenumber::metadata::DATABASE);
    Ok(PhoneNumberInfo {
        e164: parsed.format().mode(phonenumber::Mode::E164).to_string(),
        international_format: parsed.format().mode(phonenumber::Mode::International).to_string(),
        national_format: parsed.format().mode(phonenumber::Mode::National).to_string(),
        country_calling_code: parsed.code().value(),
        region_code: parsed.country().id().map(|id| format!("{id:?}")),
        number_type: format!("{number_type:?}"),
        is_valid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_normalization() {
        assert_eq!(normalize_username("  @octocat ").unwrap(), "octocat");
        assert_eq!(normalize_username("first.last-99").unwrap(), "first.last-99");
        assert!(normalize_username("").is_err());
        assert!(normalize_username("bad name").is_err());
        assert!(normalize_username("../etc/passwd").is_err());
        assert!(normalize_username("name?x=1").is_err());
        assert!(normalize_username(&"a".repeat(65)).is_err());
    }

    #[test]
    fn email_normalization() {
        assert_eq!(normalize_email(" Alice.Smith@Example.COM ").unwrap(), "alice.smith@example.com");
        assert_eq!(normalize_email("a+tag@sub.example.org").unwrap(), "a+tag@sub.example.org");
        assert!(normalize_email("no-at-sign").is_err());
        assert!(normalize_email("a..b@example.com").is_err());
        assert!(normalize_email("a@localhost").is_err());
        assert!(normalize_email("a@127.0.0.1").is_err());
        assert!(normalize_email("@example.com").is_err());
    }

    #[test]
    fn domain_normalization() {
        assert_eq!(normalize_domain("Example.COM.").unwrap(), "example.com");
        assert_eq!(normalize_domain("https://www.example.com/path?q=1").unwrap(), "www.example.com");
        assert_eq!(normalize_domain("bücher.de").unwrap(), "xn--bcher-kva.de");
        assert!(normalize_domain("localhost").is_err());
        assert!(normalize_domain("printer.local").is_err());
        assert!(normalize_domain("10.0.0.1").is_err());
        assert!(normalize_domain("[::1]").is_err());
        assert!(normalize_domain("singlelabel").is_err());
        assert!(normalize_domain("-bad-.com").is_err());
        assert!(normalize_domain("exa mple.com").is_err());
    }

    #[test]
    fn phone_normalization() {
        let info = normalize_phone("+1 650-253-0000", None).unwrap();
        assert_eq!(info.e164, "+16502530000");
        assert_eq!(info.country_calling_code, 1);
        assert_eq!(info.region_code.as_deref(), Some("US"));

        let info = normalize_phone("020 7946 0958", Some("gb")).unwrap();
        assert_eq!(info.e164, "+442079460958");
        assert_eq!(info.region_code.as_deref(), Some("GB"));

        assert!(normalize_phone("6502530000", None).is_err());
        assert!(normalize_phone("+1 000", None).is_err());
        assert!(normalize_phone("not a number", Some("US")).is_err());
    }

    #[test]
    fn target_round_trips_through_serde_with_revalidation() {
        let target = InvestigationTarget::parse(TargetType::Email, "Bob@Example.com").unwrap();
        let json = serde_json::to_string(&target).unwrap();
        assert_eq!(json, r#"{"type":"email","value":"bob@example.com"}"#);
        let decoded: InvestigationTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, target);
        let invalid = serde_json::from_str::<InvestigationTarget>(r#"{"type":"domain","value":"localhost"}"#);
        assert!(invalid.is_err());
    }
}
