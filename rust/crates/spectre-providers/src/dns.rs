//! DNS-over-HTTPS resolver (Cloudflare JSON API).
//!
//! DoH keeps every lookup on an allowlisted HTTPS endpoint and avoids
//! depending on the host's resolver configuration. Queried names are visible
//! to the DoH operator; this is documented in `docs/security.md`.

use serde::Deserialize;
use spectre_core::error::{ErrorCode, SpectreError, SpectreResult};
use spectre_core::model::{DnsRecord, MxRecord};
use spectre_core::provider::ProviderContext;
use url::Url;

use crate::common::base_url;

pub const DOH_HOST: &str = "cloudflare-dns.com";
const DOH_ENDPOINT: &str = "https://cloudflare-dns.com/dns-query";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Ns,
    Soa,
    Txt,
    Caa,
}

impl RecordType {
    pub fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Ns => 2,
            Self::Cname => 5,
            Self::Soa => 6,
            Self::Mx => 15,
            Self::Txt => 16,
            Self::Aaaa => 28,
            Self::Caa => 257,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Cname => "CNAME",
            Self::Mx => "MX",
            Self::Ns => "NS",
            Self::Soa => "SOA",
            Self::Txt => "TXT",
            Self::Caa => "CAA",
        }
    }
}

/// Response codes from RFC 1035 / 6895 that matter to us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCode {
    NoError,
    NxDomain,
    Other(u32),
}

#[derive(Debug, Clone)]
pub struct DnsAnswer {
    pub response_code: ResponseCode,
    pub records: Vec<DnsRecord>,
}

impl DnsAnswer {
    pub fn values(&self) -> impl Iterator<Item = &str> {
        self.records.iter().map(|record| record.value.as_str())
    }
}

#[derive(Debug, Deserialize)]
struct DohResponse {
    #[serde(rename = "Status")]
    status: u32,
    #[serde(rename = "Answer", default)]
    answer: Vec<DohRecord>,
}

#[derive(Debug, Deserialize)]
struct DohRecord {
    #[serde(rename = "type")]
    record_type: u16,
    #[serde(rename = "TTL", default)]
    ttl: u32,
    data: String,
}

#[derive(Debug, Clone)]
pub struct DohResolver {
    endpoint: Url,
}

impl Default for DohResolver {
    fn default() -> Self {
        Self { endpoint: base_url(DOH_ENDPOINT) }
    }
}

impl DohResolver {
    pub fn with_endpoint(endpoint: Url) -> Self {
        Self { endpoint }
    }

    pub fn host(&self) -> String {
        crate::common::host_of(&self.endpoint)
    }

    pub async fn query(&self, context: &ProviderContext, name: &str, record_type: RecordType) -> SpectreResult<DnsAnswer> {
        let mut url = self.endpoint.clone();
        url.query_pairs_mut().append_pair("name", name).append_pair("type", record_type.name());
        let request = context.request(url).accept("application/dns-json");
        let response = context.get(request).await?.ensure_success()?;
        let parsed: DohResponse = response.json()?;
        let response_code = match parsed.status {
            0 => ResponseCode::NoError,
            3 => ResponseCode::NxDomain,
            other => ResponseCode::Other(other),
        };
        if let ResponseCode::Other(code) = response_code {
            return Err(SpectreError::new(ErrorCode::UpstreamError, format!("DNS query for {name} failed with rcode {code}")));
        }
        let records = parsed
            .answer
            .into_iter()
            .filter(|record| record.record_type == record_type.code())
            .map(|record| DnsRecord {
                record_type: record_type.name().to_string(),
                value: if record_type == RecordType::Txt {
                    unquote_txt(&record.data)
                } else {
                    record.data.trim_end_matches('.').to_string()
                },
                ttl: record.ttl,
            })
            .collect();
        Ok(DnsAnswer { response_code, records })
    }

    /// TXT values, each with its character-strings joined.
    pub async fn txt(&self, context: &ProviderContext, name: &str) -> SpectreResult<Vec<String>> {
        Ok(self.query(context, name, RecordType::Txt).await?.records.into_iter().map(|record| record.value).collect())
    }
}

/// Join the quoted character-strings of a TXT record (`"a" "b"` becomes `ab`).
pub fn unquote_txt(data: &str) -> String {
    if !data.contains('"') {
        return data.to_string();
    }
    let mut output = String::new();
    let mut inside = false;
    let mut characters = data.chars();
    while let Some(character) = characters.next() {
        match (character, inside) {
            ('"', _) => inside = !inside,
            ('\\', true) => {
                if let Some(escaped) = characters.next() {
                    output.push(escaped);
                }
            }
            (other, true) => output.push(other),
            _ => {}
        }
    }
    output
}

pub fn parse_mx(record: &DnsRecord) -> Option<MxRecord> {
    let (preference, exchange) = record.value.split_once(' ')?;
    Some(MxRecord { preference: preference.trim().parse().ok()?, exchange: exchange.trim().trim_end_matches('.').to_string() })
}

pub fn find_spf(values: &[String]) -> Option<String> {
    values.iter().find(|value| value.to_ascii_lowercase().starts_with("v=spf1")).cloned()
}

pub fn find_dmarc(values: &[String]) -> Option<String> {
    values.iter().find(|value| value.to_ascii_uppercase().starts_with("V=DMARC1")).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txt_unquoting() {
        assert_eq!(unquote_txt(r#""v=spf1 include:_spf.google.com " "~all""#), "v=spf1 include:_spf.google.com ~all");
        assert_eq!(unquote_txt(r#""say \"hi\"""#), r#"say "hi""#);
        assert_eq!(unquote_txt("plain"), "plain");
    }

    #[test]
    fn mx_parsing() {
        let record = DnsRecord { record_type: "MX".into(), value: "10 mx.example.com".into(), ttl: 300 };
        assert_eq!(parse_mx(&record), Some(MxRecord { preference: 10, exchange: "mx.example.com".into() }));
        let null = DnsRecord { record_type: "MX".into(), value: "0 .".into(), ttl: 300 };
        assert_eq!(parse_mx(&null).unwrap().exchange, "");
    }
}
