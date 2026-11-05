//! Adapter tests against a local mock server. Response bodies mirror the
//! field structure of the live APIs (verified 2026-11) with synthetic values.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use spectre_core::credentials::{CredentialStore, ids};
use spectre_core::error::ErrorCode;
use spectre_core::http::{EndpointPolicy, HttpClient, HttpSettings, RequestStats};
use spectre_core::model::FindingData;
use spectre_core::provider::{FindingDraft, OsintProvider, ProviderContext};
use spectre_core::target::{InvestigationTarget, TargetType};
use tokio_util::sync::CancellationToken;
use url::Url;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::community::*;
use super::forges::*;
use super::social::*;

pub(crate) fn test_context(provider: &dyn OsintProvider) -> ProviderContext {
    let settings = HttpSettings {
        request_timeout: Duration::from_secs(5),
        max_retries: 0,
        retry_base_delay: Duration::from_millis(10),
        cache_ttl: Duration::ZERO,
        default_rate_limit_per_minute: 6000,
    };
    ProviderContext {
        provider_id: provider.id().to_string(),
        provider_name: provider.name().to_string(),
        http: HttpClient::new(Arc::new(EndpointPolicy::for_testing()), settings).unwrap(),
        credentials: Arc::new(CredentialStore::new()),
        cancellation: CancellationToken::new(),
        stats: Arc::new(RequestStats::default()),
        sink: None,
    }
}

fn base(server: &MockServer) -> Url {
    Url::parse(&format!("{}/", server.uri())).unwrap()
}

fn username(value: &str) -> InvestigationTarget {
    InvestigationTarget::parse(TargetType::Username, value).unwrap()
}

fn profile(draft: &FindingDraft) -> &spectre_core::model::ProfileFinding {
    match &draft.data {
        FindingData::Profile(profile) => profile,
        other => panic!("expected profile, got {other:?}"),
    }
}

async fn run(provider: &dyn OsintProvider, target: &str) -> Vec<FindingDraft> {
    provider.discover(&test_context(provider), &username(target)).await.unwrap()
}

#[tokio::test]
async fn github_profile_with_links_and_public_email() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/users/exampleuser"))
        .and(header("x-github-api-version", "2022-11-28"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "login": "exampleuser", "id": 1, "html_url": "https://github.com/exampleuser", "type": "User",
            "name": "Example User", "company": "Acme", "blog": "example.dev", "location": "Earth",
            "email": "example@example.dev", "bio": "Builds things", "twitter_username": "example_x",
            "public_repos": 12, "followers": 3, "created_at": "2015-01-01T00:00:00Z", "avatar_url": "https://avatars.example/1"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/users/exampleuser/social_accounts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"provider": "mastodon", "url": "https://mastodon.social/@example"},
            {"provider": "twitter", "url": "https://x.com/example_x"}
        ])))
        .mount(&server)
        .await;

    let drafts = run(&GitHubProvider::with_base(base(&server)), "exampleuser").await;
    assert_eq!(drafts.len(), 2, "profile + public email association");
    let found = profile(&drafts[0]);
    assert_eq!(found.username, "exampleuser");
    assert_eq!(found.website.as_deref(), Some("https://example.dev/"));
    let urls: Vec<_> = found.linked_accounts.iter().filter_map(|account| account.url.as_deref()).collect();
    assert_eq!(urls, vec!["https://example.dev/", "https://x.com/example_x", "https://mastodon.social/@example"]);
    assert!(matches!(&drafts[1].data, FindingData::EmailAssociation(association) if association.email == "example@example.dev"));
    assert_eq!(drafts[0].confidence.category, spectre_core::model::ConfidenceCategory::WeakEvidence);
}

#[tokio::test]
async fn github_sends_token_and_maps_rate_limits() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/users/limited"))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({"message": "API rate limit exceeded for 1.2.3.4."})))
        .mount(&server)
        .await;
    let provider = GitHubProvider::with_base(base(&server));
    let context = test_context(&provider);
    context.credentials.set(ids::GITHUB_TOKEN, zeroize::Zeroizing::new("test-token".to_string()));
    let error = provider.discover(&context, &username("limited")).await.unwrap_err();
    assert_eq!(error.code, ErrorCode::RateLimited);
}

#[tokio::test]
async fn gitlab_found_and_missing() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/users"))
        .and(query_param("username", "exampleuser"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "id": 7, "username": "exampleuser", "public_email": "", "name": "Example", "state": "active",
            "locked": false, "avatar_url": "https://gitlab.example/a.png", "web_url": "https://gitlab.com/exampleuser"
        }])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/users"))
        .and(query_param("username", "ghost"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    let provider = GitLabProvider::with_base(base(&server));
    let drafts = run(&provider, "exampleuser").await;
    assert_eq!(drafts.len(), 1, "empty public_email must not create an association");
    assert_eq!(profile(&drafts[0]).profile_url, "https://gitlab.com/exampleuser");
    assert!(run(&provider, "ghost").await.is_empty());
}

#[tokio::test]
async fn keybase_proofs_are_platform_verified_links() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/_/api/1.0/user/lookup.json"))
        .and(query_param("usernames", "exampleuser"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": {"code": 0, "name": "OK"},
            "them": [{
                "basics": {"username": "exampleuser", "ctime": 1391657400},
                "profile": {"full_name": "Example User", "location": "Earth", "bio": "hi"},
                "proofs_summary": {"all": [
                    {"proof_type": "github", "nametag": "exampleuser", "state": 1, "service_url": "https://github.com/exampleuser", "proof_url": "https://gist.github.com/x"},
                    {"proof_type": "twitter", "nametag": "ex_x", "state": 2, "service_url": "https://twitter.com/ex_x"}
                ]}
            }]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/_/api/1.0/user/lookup.json"))
        .and(query_param("usernames", "ghost"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": {"code": 0, "name": "OK"}, "them": [null]})))
        .mount(&server)
        .await;
    let provider = KeybaseProvider::with_base(base(&server));
    let drafts = run(&provider, "exampleuser").await;
    let found = profile(&drafts[0]);
    assert_eq!(found.linked_accounts.len(), 2);
    assert!(found.linked_accounts[0].verified_by_platform);
    assert!(!found.linked_accounts[1].verified_by_platform, "non-OK proof state is not verified");
    assert!(run(&provider, "ghost").await.is_empty());
    // Names that cannot exist on Keybase are skipped without a request.
    assert!(run(&provider, "has.dot-and-dash").await.is_empty());
}

#[tokio::test]
async fn mastodon_verified_fields() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/accounts/lookup"))
        .and(query_param("acct", "exampleuser"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "1", "username": "exampleuser", "acct": "exampleuser", "display_name": "Example",
            "note": "<p>Hello <a href=\"https://blog.example.dev\">blog</a></p>", "url": "https://mastodon.social/@exampleuser",
            "avatar": "https://files.example/a.png", "created_at": "2020-01-01T00:00:00.000Z", "followers_count": 5,
            "statuses_count": 9, "bot": false,
            "fields": [
                {"name": "GitHub", "value": "<a href=\"https://github.com/exampleuser\" rel=\"me\">github.com/exampleuser</a>", "verified_at": "2023-02-07T23:24:40.347+00:00"},
                {"name": "Site", "value": "<a href=\"https://example.dev\">example.dev</a>", "verified_at": null}
            ]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/accounts/lookup"))
        .and(query_param("acct", "ghost"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"error": "Record not found"})))
        .mount(&server)
        .await;
    let provider = MastodonProvider::with_base(base(&server));
    let drafts = run(&provider, "exampleuser").await;
    let found = profile(&drafts[0]);
    assert_eq!(found.bio.as_deref(), Some("Hello blog"));
    let verified: Vec<_> = found.linked_accounts.iter().filter(|account| account.verified_by_platform).collect();
    assert_eq!(verified.len(), 1);
    assert_eq!(verified[0].url.as_deref(), Some("https://github.com/exampleuser"));
    assert_eq!(found.linked_accounts.len(), 3);
    assert!(run(&provider, "ghost").await.is_empty());
}

#[tokio::test]
async fn bluesky_handles_and_not_found() {
    assert_eq!(BlueskyProvider::handle_for("Alice").as_deref(), Some("alice.bsky.social"));
    assert_eq!(BlueskyProvider::handle_for("alice.example.com").as_deref(), Some("alice.example.com"));
    assert_eq!(BlueskyProvider::handle_for("under_score"), None);

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.actor.getProfile"))
        .and(query_param("actor", "exampleuser.bsky.social"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "did": "did:plc:abc", "handle": "exampleuser.bsky.social", "displayName": "Example",
            "description": "hi", "createdAt": "2023-01-01T00:00:00Z", "followersCount": 1, "postsCount": 2,
            "verification": {"verifications": [], "verifiedStatus": "valid", "trustedVerifierStatus": "none"}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/xrpc/app.bsky.actor.getProfile"))
        .and(query_param("actor", "ghost.bsky.social"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": "InvalidRequest", "message": "Profile not found"})))
        .mount(&server)
        .await;
    let provider = BlueskyProvider::with_base(base(&server));
    let drafts = run(&provider, "exampleuser").await;
    assert!(profile(&drafts[0]).platform_verified);
    assert_eq!(profile(&drafts[0]).profile_url, "https://bsky.app/profile/exampleuser.bsky.social");
    assert!(run(&provider, "ghost").await.is_empty());
}

#[tokio::test]
async fn hacker_news_null_means_missing() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v0/user/exampleuser.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"id": "exampleuser", "created": 1160418092, "karma": 42, "about": "See <a href=\"https://example.dev\">site</a>"}),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v0/user/ghost.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string("null"))
        .mount(&server)
        .await;
    let provider = HackerNewsProvider::with_base(base(&server));
    let drafts = run(&provider, "exampleuser").await;
    assert_eq!(profile(&drafts[0]).linked_accounts[0].url.as_deref(), Some("https://example.dev/"));
    assert_eq!(profile(&drafts[0]).attributes.get("karma").map(String::as_str), Some("42"));
    assert!(run(&provider, "ghost").await.is_empty());
}

#[tokio::test]
async fn devto_declared_links() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/users/by_username"))
        .and(query_param("url", "exampleuser"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "type_of": "user", "id": 1, "username": "exampleuser", "name": "Example", "twitter_username": "ex_x",
            "github_username": "exampleuser", "summary": "hi", "location": "Earth", "website_url": "http://example.dev",
            "joined_at": "Dec 27, 2015", "profile_image": "https://media.example/p.png"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/users/by_username"))
        .and(query_param("url", "ghost"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let provider = DevToProvider::with_base(base(&server));
    let drafts = run(&provider, "exampleuser").await;
    let platforms: Vec<_> = profile(&drafts[0]).linked_accounts.iter().map(|account| account.platform.clone()).collect();
    assert_eq!(platforms, vec![Some("GitHub".into()), Some("X".into()), None]);
    assert!(run(&provider, "ghost").await.is_empty());
}

#[tokio::test]
async fn simple_profile_providers_found_and_missing() {
    let server = MockServer::start().await;
    let respond = |route: &str, body: serde_json::Value| {
        Mock::given(method("GET")).and(path(route.to_string())).respond_with(ResponseTemplate::new(200).set_body_json(body))
    };
    respond("/api/v1/users/exampleuser", json!({"id": 1, "login": "exampleuser", "full_name": "Example", "email": "x@noreply.codeberg.org", "avatar_url": "a", "html_url": "https://codeberg.org/exampleuser", "created": "2022-11-06T07:18:11+01:00", "location": "", "website": "https://example.dev", "description": "hi"})).mount(&server).await;
    respond("/api/users/exampleuser/overview", json!({"user": "exampleuser", "fullname": "Example", "avatarUrl": "a", "createdAt": "2019-11-23T17:38:57.000Z", "details": "ml", "isPro": false, "numModels": 3, "type": "user"})).mount(&server).await;
    respond("/v2/users/exampleuser/", json!({"id": "x", "username": "exampleuser", "full_name": "Example", "location": "", "company": "", "profile_url": "http://example.dev/", "date_joined": "2013-05-01T07:14:57Z", "type": "User"})).mount(&server).await;
    respond("/pub/player/exampleuser", json!({"username": "exampleuser", "url": "https://www.chess.com/member/ExampleUser", "name": "Example", "country": "https://api.chess.com/pub/country/US", "joined": 1389043258, "status": "basic", "followers": 1, "verified": false, "twitch_url": "https://twitch.tv/example"})).mount(&server).await;
    respond("/api/user/exampleuser", json!({"id": "exampleuser", "username": "ExampleUser", "url": "https://lichess.org/@/ExampleUser", "createdAt": 1290415680000i64, "profile": {"bio": "hi", "realName": "Example User", "links": "github.com/exampleuser\nmas.to/@example"}})).mount(&server).await;
    Mock::given(method("GET")).respond_with(ResponseTemplate::new(404)).mount(&server).await;

    let codeberg = run(&CodebergProvider::with_base(base(&server)), "exampleuser").await;
    assert_eq!(codeberg.len(), 1, "noreply addresses are not public email associations");
    assert_eq!(profile(&codeberg[0]).public_email, None);

    let huggingface = run(&HuggingFaceProvider::with_base(base(&server)), "exampleuser").await;
    assert_eq!(profile(&huggingface[0]).profile_url, "https://huggingface.co/exampleuser");

    let docker = run(&DockerHubProvider::with_base(base(&server)), "exampleuser").await;
    assert_eq!(profile(&docker[0]).website.as_deref(), Some("http://example.dev/"));

    let chess = run(&ChessComProvider::with_base(base(&server)), "ExampleUser").await;
    assert_eq!(profile(&chess[0]).attributes.get("country").map(String::as_str), Some("US"));

    let lichess = run(&LichessProvider::with_base(base(&server)), "exampleuser").await;
    assert_eq!(profile(&lichess[0]).linked_accounts.len(), 2);
    assert_eq!(profile(&lichess[0]).display_name.as_deref(), Some("Example User"));

    for provider in [
        Box::new(CodebergProvider::with_base(base(&server))) as Box<dyn OsintProvider>,
        Box::new(HuggingFaceProvider::with_base(base(&server))),
        Box::new(DockerHubProvider::with_base(base(&server))),
        Box::new(ChessComProvider::with_base(base(&server))),
        Box::new(LichessProvider::with_base(base(&server))),
    ] {
        assert!(run(provider.as_ref(), "ghost").await.is_empty(), "{} should report nothing for 404", provider.id());
    }
}

#[tokio::test]
async fn wikipedia_missing_flag() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/w/api.php"))
        .and(query_param("ususers", "Example User"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"batchcomplete": "", "query": {"users": [{"userid": 24, "name": "Example User", "editcount": 15, "registration": "2001-03-27T20:47:31Z"}]}})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/w/api.php"))
        .and(query_param("ususers", "ghost"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"batchcomplete": "", "query": {"users": [{"name": "Ghost", "missing": ""}]}})),
        )
        .mount(&server)
        .await;
    let provider = WikipediaProvider::with_base(base(&server));
    let context = test_context(&provider);
    // Usernames with spaces are not valid targets; exercise the adapter directly.
    let target = InvestigationTarget::Username("Example User".to_string());
    let drafts = provider.discover(&context, &target).await.unwrap();
    assert_eq!(profile(&drafts[0]).profile_url, "https://en.wikipedia.org/wiki/User:Example_User");
    assert!(run(&provider, "ghost").await.is_empty());
}

#[tokio::test]
async fn upstream_errors_are_reported_not_swallowed() {
    let server = MockServer::start().await;
    Mock::given(method("GET")).respond_with(ResponseTemplate::new(500)).mount(&server).await;
    let provider = DevToProvider::with_base(base(&server));
    let error = provider.discover(&test_context(&provider), &username("x")).await.unwrap_err();
    assert_eq!(error.code, ErrorCode::UpstreamError);
}

#[tokio::test]
async fn endpoint_policy_blocks_unregistered_hosts() {
    // The test policy only allows loopback; production hosts are not registered.
    let provider = GitLabProvider::default();
    let error = provider.discover(&test_context(&provider), &username("x")).await.unwrap_err();
    assert_eq!(error.code, ErrorCode::PolicyViolation);
}
