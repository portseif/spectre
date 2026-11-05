use std::sync::Arc;
use std::time::Duration;

use chrono::{NaiveDate, Utc};
use spectre_core::credentials::{CredentialStore, ids};
use spectre_core::error::ErrorCode;
use spectre_core::http::{EndpointPolicy, HttpClient, HttpSettings, RequestStats};
use spectre_core::model::{EmailRecord, FindingData, RiskLevel, VerificationMethod, VerificationStatus};
use spectre_core::provider::{OsintProvider, ProviderContext};
use spectre_core::target::{InvestigationTarget, TargetType};
use tokio_util::sync::CancellationToken;
use url::Url;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};
use zeroize::Zeroizing;

use super::*;
use crate::risk::assess_risk_on;

const MULTIPLE: &str = include_str!("../../../../tests/fixtures/hibp/breachedaccount_multiple.json");
const ADOBE: &str = include_str!("../../../../tests/fixtures/hibp/breach_adobe.json");

fn context() -> ProviderContext {
    let settings = HttpSettings {
        request_timeout: Duration::from_secs(5),
        max_retries: 0,
        retry_base_delay: Duration::from_millis(10),
        cache_ttl: Duration::ZERO,
        default_rate_limit_per_minute: 6000,
    };
    ProviderContext {
        provider_id: "hibp".into(),
        provider_name: "Have I Been Pwned".into(),
        http: HttpClient::new(Arc::new(EndpointPolicy::for_testing()), settings).unwrap(),
        credentials: Arc::new(CredentialStore::new()),
        cancellation: CancellationToken::new(),
        stats: Arc::new(RequestStats::default()),
        sink: None,
    }
}

fn record(status: VerificationStatus, method: Option<VerificationMethod>) -> EmailRecord {
    EmailRecord {
        email: "owner@example.org".into(),
        verification_status: status,
        verification_method: method,
        attestation: None,
        verified_at: None,
        last_breach_check_at: None,
        created_at: Utc::now(),
    }
}

fn client(server: &MockServer) -> HibpClient {
    HibpClient::with_base(Url::parse(&format!("{}/api/v3/", server.uri())).unwrap())
}

#[test]
fn unverified_addresses_cannot_be_authorized() {
    for status in [VerificationStatus::Unverified, VerificationStatus::PubliclyObserved] {
        let error = AuthorizedAccount::from_record(&record(status, None)).unwrap_err();
        assert_eq!(error.code, ErrorCode::AuthorizationRequired);
    }
    let authorized =
        AuthorizedAccount::from_record(&record(VerificationStatus::OwnershipVerified, Some(VerificationMethod::InvestigatorAttestation)))
            .unwrap();
    assert_eq!(authorized.email(), "owner@example.org");
}

#[test]
fn breach_model_normalization() {
    let breach: HibpBreach = serde_json::from_str(ADOBE).unwrap();
    let incident: spectre_core::model::BreachIncident = breach.into();
    assert_eq!(incident.name, "Adobe");
    assert!(incident.password_data_exposed);
    assert!(!incident.description.contains('<'), "HTML must be stripped");
    assert_eq!(incident.breach_date.as_deref(), Some("2013-10-04"));
}

#[tokio::test]
async fn account_lookup_requires_key_and_sends_it() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/breachedaccount/owner@example.org"))
        .and(query_param("truncateResponse", "false"))
        .and(header("hibp-api-key", "test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_string(MULTIPLE))
        .mount(&server)
        .await;
    let account =
        AuthorizedAccount::from_record(&record(VerificationStatus::OwnershipVerified, Some(VerificationMethod::InvestigatorAttestation)))
            .unwrap();
    let context = context();
    let missing = client(&server).account_breaches(&context, &account).await.unwrap_err();
    assert_eq!(missing.code, ErrorCode::CredentialsMissing);

    context.credentials.set(ids::HIBP_API_KEY, Zeroizing::new("test-key".into()));
    let breaches = client(&server).account_breaches(&context, &account).await.unwrap();
    assert_eq!(breaches.iter().map(|breach| breach.name.as_str()).collect::<Vec<_>>(), vec!["Adobe", "Stratfor", "Gawker"]);
}

#[tokio::test]
async fn account_lookup_status_mapping() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/breachedaccount/owner@example.org"))
        .respond_with(ResponseTemplate::new(404))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v3/breachedaccount/owner@example.org"))
        .respond_with(ResponseTemplate::new(401))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v3/breachedaccount/owner@example.org"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "2"))
        .mount(&server)
        .await;
    let account =
        AuthorizedAccount::from_record(&record(VerificationStatus::OwnershipVerified, Some(VerificationMethod::InvestigatorAttestation)))
            .unwrap();
    let context = context();
    context.credentials.set(ids::HIBP_API_KEY, Zeroizing::new("k".into()));
    assert!(client(&server).account_breaches(&context, &account).await.unwrap().is_empty(), "404 means not pwned");
    assert_eq!(client(&server).account_breaches(&context, &account).await.unwrap_err().code, ErrorCode::Unauthorized);
    assert_eq!(client(&server).account_breaches(&context, &account).await.unwrap_err().code, ErrorCode::RateLimited);
}

#[tokio::test]
async fn catalog_provider_reports_service_breaches_for_domains() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/breaches"))
        .and(query_param("Domain", "adobe.com"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!("[{ADOBE}]")))
        .mount(&server)
        .await;
    let provider = HibpCatalogProvider::with_client(client(&server));
    let target = InvestigationTarget::parse(TargetType::Domain, "adobe.com").unwrap();
    let drafts = provider.discover(&context(), &target).await.unwrap();
    assert_eq!(drafts.len(), 1);
    assert!(matches!(&drafts[0].data, FindingData::BreachIncident(finding) if finding.exposed_account.is_none()));
}

#[test]
fn risk_assessment_levels_and_wording() {
    let breaches: Vec<spectre_core::model::BreachIncident> =
        serde_json::from_str::<Vec<HibpBreach>>(MULTIPLE).unwrap().into_iter().map(Into::into).collect();
    let assessment = assess_risk_on(&breaches, NaiveDate::from_ymd_opt(2026, 11, 5).unwrap());
    // The test breaches are older than three years (password exposure is Medium),
    // but Stratfor exposed credit cards, which is High.
    assert_eq!(assessment.level, RiskLevel::High);
    assert!(assessment.indicators.iter().any(|indicator| indicator.title.contains("Stratfor: financial")));
    assert!(
        assessment
            .indicators
            .iter()
            .any(|indicator| indicator.title.contains("Gawker: password") && indicator.severity == RiskLevel::Medium)
    );
    assert!(assessment.indicators.iter().all(|indicator| !indicator.detail.to_lowercase().contains("your password is")));
    assert!(assessment.recommendations.iter().any(|text| text.contains("multi-factor")));

    let recent = {
        let mut breach = breaches[0].clone();
        breach.breach_date = Some("2025-06-01".into());
        breach
    };
    assert_eq!(assess_risk_on(&[recent], NaiveDate::from_ymd_opt(2026, 11, 5).unwrap()).level, RiskLevel::High);
    assert_eq!(assess_risk_on(&[], NaiveDate::from_ymd_opt(2026, 11, 5).unwrap()).level, RiskLevel::None);
}
