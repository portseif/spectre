use chrono::Utc;
use spectre_core::model::*;
use spectre_core::target::{InvestigationTarget, TargetType};

use super::*;

fn profile_finding(
    investigation_id: Uuid,
    platform: &str,
    username: &str,
    url: &str,
    configure: impl FnOnce(&mut ProfileFinding),
) -> Finding {
    let mut profile = ProfileFinding {
        platform: platform.to_string(),
        username: username.to_string(),
        profile_url: url.to_string(),
        ..Default::default()
    };
    configure(&mut profile);
    Finding {
        id: Uuid::new_v4(),
        investigation_id,
        provider_id: platform.to_ascii_lowercase(),
        title: String::new(),
        summary: None,
        confidence: Confidence::new(0.35, ConfidenceCategory::WeakEvidence, Vec::<String>::new()),
        verification_status: VerificationStatus::PubliclyObserved,
        discovered_at: Utc::now(),
        sources: Vec::new(),
        data: FindingData::Profile(profile),
    }
}

fn username_target(value: &str) -> InvestigationTarget {
    InvestigationTarget::parse(TargetType::Username, value).unwrap()
}

fn edge_to<'a>(graph: &'a IdentityGraph, source: Uuid, label_contains: &str) -> &'a IdentityRelationship {
    let node = graph.nodes.iter().find(|node| node.label.contains(label_contains)).expect("node exists");
    graph.edges.iter().find(|edge| edge.source_identity == source && edge.target_identity == node.id).expect("edge exists")
}

fn root(graph: &IdentityGraph) -> Uuid {
    graph.nodes.iter().find(|node| node.is_target).unwrap().id
}

#[test]
fn noisy_or_combination() {
    assert_eq!(combine([]), 0.0);
    assert!((combine([0.5, 0.5]) - 0.75).abs() < 1e-9);
    assert!(combine([0.9, 0.9, 0.9]) < 1.0);
}

#[test]
fn username_match_alone_is_weak_evidence() {
    let investigation = Uuid::new_v4();
    let findings = vec![profile_finding(investigation, "GitHub", "octo", "https://github.com/octo", |_| {})];
    let result = correlate(investigation, &username_target("octo"), &findings, &CorrelationContext::default());
    let edge = edge_to(&result.graph, root(&result.graph), "GitHub");
    assert_eq!(edge.category, ConfidenceCategory::WeakEvidence);
    assert_eq!(edge.evidence.len(), 1);
    assert_eq!(edge.evidence[0].signal, EvidenceSignal::ExactUsernameMatch);
    assert!(!edge.verified);
    assert_eq!(result.finding_confidence[0].1.category, ConfidenceCategory::WeakEvidence);
}

#[test]
fn cross_links_between_matching_profiles_strengthen_both() {
    let investigation = Uuid::new_v4();
    let findings = vec![
        profile_finding(investigation, "GitHub", "octo", "https://github.com/octo", |profile| {
            profile.display_name = Some("Octo Cat".into());
            profile.linked_accounts.push(LinkedAccount { url: Some("https://dev.to/octo".into()), ..Default::default() });
        }),
        profile_finding(investigation, "DEV Community", "octo", "https://dev.to/octo", |profile| {
            profile.display_name = Some("Octo  Cat".into());
            profile.linked_accounts.push(LinkedAccount {
                platform: Some("GitHub".into()),
                handle: Some("octo".into()),
                url: Some("https://github.com/Octo".into()),
                ..Default::default()
            });
        }),
        profile_finding(investigation, "Lichess", "octo", "https://lichess.org/@/octo", |_| {}),
    ];
    let result = correlate(investigation, &username_target("octo"), &findings, &CorrelationContext::default());
    let root = root(&result.graph);
    let github = edge_to(&result.graph, root, "GitHub");
    assert_eq!(github.category, ConfidenceCategory::StrongEvidence, "evidence: {:?}", github.evidence);
    assert!(github.evidence.iter().any(|item| item.signal == EvidenceSignal::MatchingDisplayName));
    let lichess = edge_to(&result.graph, root, "Lichess");
    assert_eq!(lichess.category, ConfidenceCategory::WeakEvidence, "uncorroborated profile stays weak");

    // The profile-to-profile link is mutual.
    let github_node = result.graph.nodes.iter().find(|node| node.label.starts_with("GitHub")).unwrap().id;
    let link = edge_to(&result.graph, github_node, "DEV");
    assert!(link.evidence.iter().any(|item| item.signal == EvidenceSignal::MutualLink));
    assert_eq!(link.relationship, RelationshipKind::PubliclyLinked);
}

#[test]
fn linked_accounts_become_possible_associated_identities() {
    let investigation = Uuid::new_v4();
    let findings = vec![profile_finding(investigation, "Keybase", "octo", "https://keybase.io/octo", |profile| {
        profile.linked_accounts.push(LinkedAccount {
            platform: Some("X".into()),
            handle: Some("octo_x".into()),
            url: Some("https://twitter.com/octo_x".into()),
            verified_by_platform: true,
            note: None,
        });
        profile.public_email = Some("Octo@Example.org".into());
    })];
    let result = correlate(investigation, &username_target("octo"), &findings, &CorrelationContext::default());
    let keybase = result.graph.nodes.iter().find(|node| node.label.starts_with("Keybase")).unwrap().id;
    let x = edge_to(&result.graph, keybase, "x.com/octo_x");
    assert_eq!(x.category, ConfidenceCategory::StrongEvidence);
    assert_eq!(x.evidence[0].signal, EvidenceSignal::PlatformVerifiedLink);
    let email = edge_to(&result.graph, keybase, "octo@example.org");
    assert_eq!(email.relationship, RelationshipKind::PubliclyLinked);
    assert_eq!(email.category, ConfidenceCategory::Possible);
}

#[test]
fn investigator_decisions_override_and_survive_recorrelation() {
    let investigation = Uuid::new_v4();
    let findings = vec![
        profile_finding(investigation, "GitHub", "octo", "https://github.com/octo", |_| {}),
        profile_finding(investigation, "GitLab", "octo", "https://gitlab.com/octo", |_| {}),
    ];
    let target = username_target("octo");
    let first = correlate(investigation, &target, &findings, &CorrelationContext::default());
    let root = root(&first.graph);
    let github = edge_to(&first.graph, root, "GitHub").clone();
    let gitlab = edge_to(&first.graph, root, "GitLab").clone();

    let mut context = CorrelationContext::default();
    context.decisions.insert((github.source_identity, github.target_identity), InvestigatorDecision::Confirmed);
    context.decisions.insert((gitlab.source_identity, gitlab.target_identity), InvestigatorDecision::Rejected);
    let second = correlate(investigation, &target, &findings, &context);
    let github = edge_to(&second.graph, root, "GitHub");
    assert_eq!(github.category, ConfidenceCategory::Confirmed);
    assert_eq!(github.relationship, RelationshipKind::InvestigatorConfirmed);
    assert!(github.verified);
    assert_eq!(github.id, relationship_id(investigation, github.source_identity, github.target_identity));
    let gitlab = edge_to(&second.graph, root, "GitLab");
    assert_eq!(gitlab.category, ConfidenceCategory::Unrelated);
    assert_eq!(gitlab.confidence, 0.0);
}

#[test]
fn email_hash_profile_and_ownership_verification() {
    let investigation = Uuid::new_v4();
    let target = InvestigationTarget::parse(TargetType::Email, "owner@example.org").unwrap();
    let findings = vec![profile_finding(investigation, "Gravatar", "owner", "https://gravatar.com/owner", |profile| {
        profile.attributes.insert("matched_by".into(), "email_hash".into());
    })];
    let unverified = correlate(investigation, &target, &findings, &CorrelationContext::default());
    let edge = edge_to(&unverified.graph, root(&unverified.graph), "Gravatar");
    assert_eq!(edge.category, ConfidenceCategory::StrongEvidence);

    let mut context = CorrelationContext::default();
    context.verified_emails.insert("owner@example.org".into());
    let verified = correlate(investigation, &target, &findings, &context);
    let edge = edge_to(&verified.graph, root(&verified.graph), "Gravatar");
    assert_eq!(edge.category, ConfidenceCategory::Confirmed);
    assert_eq!(edge.relationship, RelationshipKind::OwnershipVerified);
    assert!(verified.graph.nodes.iter().find(|node| node.is_target).unwrap().verified);
}

#[test]
fn breach_findings_attach_to_the_exposed_account() {
    let investigation = Uuid::new_v4();
    let target = InvestigationTarget::parse(TargetType::Email, "owner@example.org").unwrap();
    let incident = BreachIncident {
        name: "Example".into(),
        title: "Example Breach".into(),
        domain: Some("example.com".into()),
        breach_date: Some("2022-04-15".into()),
        added_date: None,
        modified_date: None,
        pwn_count: 10,
        description: String::new(),
        data_classes: vec!["Passwords".into()],
        password_data_exposed: true,
        is_verified: true,
        is_fabricated: false,
        is_sensitive: false,
        is_retired: false,
        is_spam_list: false,
        is_malware: false,
        is_stealer_log: false,
        logo_url: None,
        source: "Have I Been Pwned".into(),
    };
    let finding = Finding {
        id: Uuid::new_v4(),
        investigation_id: investigation,
        provider_id: "hibp-account".into(),
        title: "Example".into(),
        summary: None,
        confidence: Confidence::new(1.0, ConfidenceCategory::Confirmed, ["x"]),
        verification_status: VerificationStatus::OwnershipVerified,
        discovered_at: Utc::now(),
        sources: Vec::new(),
        data: FindingData::BreachIncident(BreachFinding { exposed_account: Some("owner@example.org".into()), incident }),
    };
    let result = correlate(investigation, &target, &[finding], &CorrelationContext::default());
    let edge = edge_to(&result.graph, root(&result.graph), "Example Breach");
    assert_eq!(edge.relationship, RelationshipKind::ExposedInBreach);
    assert_eq!(edge.category, ConfidenceCategory::Confirmed);
}

#[test]
fn canonical_keys() {
    assert_eq!(canonical_profile_key("https://www.GitHub.com/Octo/").as_deref(), Some("github.com/octo"));
    assert_eq!(canonical_profile_key("http://twitter.com/octo").as_deref(), Some("x.com/octo"));
    assert_eq!(canonical_profile_key("https://news.ycombinator.com/user?id=PG").as_deref(), Some("news.ycombinator.com/user/pg"));
    assert!(username_matches("alice", "alice.bsky.social"));
    assert!(username_matches("alice", "Alice"));
    assert!(!username_matches("alice", "alice2"));
}

#[test]
fn identity_ids_are_deterministic() {
    let investigation = Uuid::new_v4();
    assert_eq!(
        identity_id(investigation, IdentityKind::Profile, "github.com/x"),
        identity_id(investigation, IdentityKind::Profile, "github.com/x")
    );
    assert_ne!(
        identity_id(investigation, IdentityKind::Profile, "github.com/x"),
        identity_id(Uuid::new_v4(), IdentityKind::Profile, "github.com/x")
    );
}
