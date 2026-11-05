//! Evidence-based identity correlation.
//!
//! Correlation turns an investigation's findings into an identity graph whose
//! edges carry explicit, explainable evidence. Each evidence item has a weight;
//! weights combine with a noisy-OR (`1 - product(1 - w_i)`), so independent signals
//! reinforce each other without exceeding 1.0. Scores are evidence weights,
//! not calibrated probabilities: the UI leads with the category.
//!
//! Category rules (applied in order):
//! 1. Investigator rejection gives `Unrelated`; investigator confirmation or
//!    verified ownership gives `Confirmed`.
//! 2. Score >= [`STRONG_THRESHOLD`] *and* at least one explicit-link signal gives
//!    `StrongEvidence`. Coincidental signals alone never reach it.
//! 3. Score >= [`POSSIBLE_THRESHOLD`] gives `Possible`; otherwise `WeakEvidence`.
//!
//! The algorithm is deterministic: identity and relationship IDs are UUIDv5
//! values derived from the investigation ID and canonical values, so
//! re-running correlation preserves investigator decisions.

use std::collections::{BTreeMap, HashMap, HashSet};

use spectre_core::model::{
    Confidence, ConfidenceCategory, EvidenceItem, EvidenceSignal, Finding, FindingData, Identity, IdentityGraph, IdentityKind,
    IdentityRelationship, InvestigatorDecision, LinkedAccount, ProfileFinding, RelationshipKind,
};
use spectre_core::target::InvestigationTarget;
use url::Url;
use uuid::Uuid;

pub const POSSIBLE_THRESHOLD: f64 = 0.40;
pub const STRONG_THRESHOLD: f64 = 0.75;

/// Evidence weights. Documented in `docs/architecture.md`.
pub mod weights {
    pub const EXACT_USERNAME_MATCH: f64 = 0.35;
    pub const EXPLICIT_LINK: f64 = 0.60;
    pub const PLATFORM_VERIFIED_LINK: f64 = 0.75;
    pub const MUTUAL_LINK: f64 = 0.40;
    /// Corroboration: linked with another profile that also matches the target.
    pub const CORROBORATING_LINK: f64 = 0.45;
    pub const CORROBORATING_VERIFIED_LINK: f64 = 0.60;
    pub const SHARED_WEBSITE: f64 = 0.25;
    pub const SHARED_PUBLIC_EMAIL: f64 = 0.60;
    pub const MATCHING_DISPLAY_NAME: f64 = 0.15;
    pub const EMAIL_HASH_PROFILE: f64 = 0.80;
}

/// Inputs from storage that shape correlation besides the findings.
#[derive(Debug, Default)]
pub struct CorrelationContext {
    /// Investigator decisions keyed by (source identity, target identity).
    pub decisions: HashMap<(Uuid, Uuid), InvestigatorDecision>,
    /// Ownership-verified email addresses (normalized).
    pub verified_emails: HashSet<String>,
    /// Ownership-verified domains (normalized).
    pub verified_domains: HashSet<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CorrelationResult {
    pub graph: IdentityGraph,
    /// Updated confidence for profile findings, derived from their
    /// relationship with the investigation target.
    pub finding_confidence: Vec<(Uuid, Confidence)>,
}

pub fn identity_id(investigation_id: Uuid, kind: IdentityKind, value: &str) -> Uuid {
    Uuid::new_v5(&investigation_id, format!("identity:{}:{}", kind.as_str(), value).as_bytes())
}

pub fn relationship_id(investigation_id: Uuid, source: Uuid, target: Uuid) -> Uuid {
    Uuid::new_v5(&investigation_id, format!("relationship:{source}:{target}").as_bytes())
}

pub fn combine(weights: impl IntoIterator<Item = f64>) -> f64 {
    1.0 - weights.into_iter().fold(1.0, |remaining, weight| remaining * (1.0 - weight.clamp(0.0, 1.0)))
}

fn is_link_signal(signal: EvidenceSignal) -> bool {
    matches!(
        signal,
        EvidenceSignal::ExplicitLink
            | EvidenceSignal::PlatformVerifiedLink
            | EvidenceSignal::MutualLink
            | EvidenceSignal::SharedPublicEmail
    )
}

pub fn categorize(score: f64, evidence: &[EvidenceItem]) -> ConfidenceCategory {
    if evidence.iter().any(|item| item.signal == EvidenceSignal::OwnershipVerified) {
        return ConfidenceCategory::Confirmed;
    }
    let has_link = evidence.iter().any(|item| is_link_signal(item.signal));
    if score >= STRONG_THRESHOLD && has_link {
        ConfidenceCategory::StrongEvidence
    } else if score >= POSSIBLE_THRESHOLD {
        ConfidenceCategory::Possible
    } else {
        ConfidenceCategory::WeakEvidence
    }
}

/// Canonical comparison key for a profile URL: lowercase host (without
/// `www.`/`mobile.`, with twitter.com folded into x.com) plus lowercase path.
pub fn canonical_profile_key(raw: &str) -> Option<String> {
    let url = Url::parse(raw).ok()?;
    let mut host = url.host_str()?.to_ascii_lowercase();
    for prefix in ["www.", "mobile.", "m."] {
        if let Some(stripped) = host.strip_prefix(prefix) {
            host = stripped.to_string();
        }
    }
    if host == "twitter.com" {
        host = "x.com".to_string();
    }
    if host == "news.ycombinator.com" {
        let id = url.query_pairs().find(|(key, _)| key == "id").map(|(_, value)| value.to_ascii_lowercase())?;
        return Some(format!("news.ycombinator.com/user/{id}"));
    }
    let path = url.path().trim_end_matches('/').to_ascii_lowercase();
    Some(format!("{host}{path}"))
}

fn platform_for_host(key: &str) -> Option<&'static str> {
    let host = key.split('/').next().unwrap_or_default();
    Some(match host {
        "github.com" => "GitHub",
        "gitlab.com" => "GitLab",
        "codeberg.org" => "Codeberg",
        "x.com" => "X",
        "linkedin.com" => "LinkedIn",
        "mastodon.social" => "Mastodon",
        "bsky.app" => "Bluesky",
        "keybase.io" => "Keybase",
        "facebook.com" => "Facebook",
        "instagram.com" => "Instagram",
        "youtube.com" => "YouTube",
        "reddit.com" => "Reddit",
        "twitch.tv" => "Twitch",
        "news.ycombinator.com" => "Hacker News",
        "dev.to" => "DEV Community",
        "huggingface.co" => "Hugging Face",
        "threads.net" => "Threads",
        _ => return None,
    })
}

fn normalized_name(name: &str) -> Option<String> {
    let normalized: String = name.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
    let meaningful = normalized.split(' ').count() >= 2 || normalized.chars().count() >= 8;
    meaningful.then_some(normalized)
}

/// Does a platform username refer to the same handle as the target username?
pub fn username_matches(target: &str, platform_username: &str) -> bool {
    let target = target.to_ascii_lowercase();
    let candidate = platform_username.to_ascii_lowercase();
    candidate == target
        || candidate.strip_suffix(".bsky.social").is_some_and(|handle| handle == target)
        || candidate.split_once('@').is_some_and(|(local, _)| local == target)
}

fn website_key(profile: &ProfileFinding) -> Option<String> {
    profile.website.as_deref().and_then(canonical_profile_key)
}

fn link_key(account: &LinkedAccount) -> Option<String> {
    account.url.as_deref().and_then(canonical_profile_key)
}

struct GraphBuilder<'a> {
    investigation_id: Uuid,
    context: &'a CorrelationContext,
    nodes: BTreeMap<Uuid, Identity>,
    edges: BTreeMap<(Uuid, Uuid), (RelationshipKind, Vec<EvidenceItem>)>,
}

impl<'a> GraphBuilder<'a> {
    fn node(&mut self, kind: IdentityKind, value: &str, label: String, platform: Option<String>, finding_id: Option<Uuid>) -> Uuid {
        let id = identity_id(self.investigation_id, kind, value);
        let verified = match kind {
            IdentityKind::Email => self.context.verified_emails.contains(value),
            IdentityKind::Domain => self.context.verified_domains.contains(value),
            _ => false,
        };
        self.nodes.entry(id).or_insert(Identity {
            id,
            kind,
            label,
            value: value.to_string(),
            platform,
            finding_id,
            is_target: false,
            verified,
        });
        id
    }

    fn evidence(&mut self, source: Uuid, target: Uuid, kind: RelationshipKind, item: EvidenceItem) {
        if source == target {
            return;
        }
        let entry = self.edges.entry((source, target)).or_insert_with(|| (kind, Vec::new()));
        if !entry.1.iter().any(|existing| existing.signal == item.signal && existing.description == item.description) {
            entry.1.push(item);
        }
    }

    fn finish(self) -> IdentityGraph {
        let mut edges = Vec::with_capacity(self.edges.len());
        for ((source, target), (kind, evidence)) in self.edges {
            let decision = self.context.decisions.get(&(source, target)).copied();
            let mut score = combine(evidence.iter().map(|item| item.weight));
            let mut category = categorize(score, &evidence);
            let mut relationship = kind;
            match decision {
                Some(InvestigatorDecision::Confirmed) => {
                    score = 1.0;
                    category = ConfidenceCategory::Confirmed;
                    relationship = RelationshipKind::InvestigatorConfirmed;
                }
                Some(InvestigatorDecision::Rejected) => {
                    score = 0.0;
                    category = ConfidenceCategory::Unrelated;
                }
                None => {}
            }
            let verified = category == ConfidenceCategory::Confirmed;
            if category == ConfidenceCategory::Confirmed && decision.is_none() && relationship != RelationshipKind::ExposedInBreach {
                relationship = RelationshipKind::OwnershipVerified;
            }
            edges.push(IdentityRelationship {
                id: relationship_id(self.investigation_id, source, target),
                source_identity: source,
                target_identity: target,
                relationship,
                confidence: (score * 1000.0).round() / 1000.0,
                category,
                evidence,
                verified,
                investigator_decision: decision,
            });
        }
        IdentityGraph { nodes: self.nodes.into_values().collect(), edges }
    }
}

fn item(signal: EvidenceSignal, weight: f64, description: String, finding: &Finding, url: Option<&str>) -> EvidenceItem {
    EvidenceItem { signal, description, weight, source_finding_id: Some(finding.id), source_url: url.map(str::to_string) }
}

/// Build the identity graph for one investigation.
pub fn correlate(
    investigation_id: Uuid,
    target: &InvestigationTarget,
    findings: &[Finding],
    context: &CorrelationContext,
) -> CorrelationResult {
    let mut builder = GraphBuilder { investigation_id, context, nodes: BTreeMap::new(), edges: BTreeMap::new() };

    // Root node.
    let (root_kind, root_value) = match target {
        InvestigationTarget::Username(value) => (IdentityKind::Username, value.to_ascii_lowercase()),
        InvestigationTarget::Email(value) => (IdentityKind::Email, value.clone()),
        InvestigationTarget::Phone(value) => (IdentityKind::Phone, value.clone()),
        InvestigationTarget::Domain(value) => (IdentityKind::Domain, value.clone()),
    };
    let root = builder.node(root_kind, &root_value, target.value().to_string(), None, None);
    if let Some(node) = builder.nodes.get_mut(&root) {
        node.is_target = true;
    }

    // Profile nodes, keyed by canonical URL.
    let profiles: Vec<(&Finding, &ProfileFinding, String)> = findings
        .iter()
        .filter_map(|finding| match &finding.data {
            FindingData::Profile(profile) => canonical_profile_key(&profile.profile_url).map(|key| (finding, profile, key)),
            _ => None,
        })
        .collect();
    let mut profile_nodes: HashMap<String, Uuid> = HashMap::new();
    for (finding, profile, key) in &profiles {
        let id = builder.node(
            IdentityKind::Profile,
            key,
            format!("{} · {}", profile.platform, profile.username),
            Some(profile.platform.clone()),
            Some(finding.id),
        );
        profile_nodes.insert(key.clone(), id);
    }
    let matches_target: HashSet<String> = profiles
        .iter()
        .filter(|(_, profile, _)| match target {
            InvestigationTarget::Username(username) => username_matches(username, &profile.username),
            InvestigationTarget::Email(_) => profile.attributes.get("matched_by").map(String::as_str) == Some("email_hash"),
            _ => false,
        })
        .map(|(_, _, key)| key.clone())
        .collect();

    // Direct evidence between the target and each profile.
    for (finding, profile, key) in &profiles {
        let profile_node = profile_nodes[key];
        if let InvestigationTarget::Username(username) = target
            && username_matches(username, &profile.username)
        {
            builder.evidence(
                root,
                profile_node,
                RelationshipKind::PossibleSameOwner,
                item(
                    EvidenceSignal::ExactUsernameMatch,
                    weights::EXACT_USERNAME_MATCH,
                    format!("{} username \"{}\" matches \"{username}\"", profile.platform, profile.username),
                    finding,
                    Some(&profile.profile_url),
                ),
            );
        }
        if let InvestigationTarget::Email(email) = target {
            if matches_target.contains(key) {
                builder.evidence(
                    root,
                    profile_node,
                    RelationshipKind::PubliclyLinked,
                    item(
                        EvidenceSignal::PlatformVerifiedLink,
                        weights::EMAIL_HASH_PROFILE,
                        format!("{} profile is registered to this exact address", profile.platform),
                        finding,
                        Some(&profile.profile_url),
                    ),
                );
                if context.verified_emails.contains(email) {
                    builder.evidence(
                        root,
                        profile_node,
                        RelationshipKind::OwnershipVerified,
                        item(
                            EvidenceSignal::OwnershipVerified,
                            1.0,
                            "Investigator verified ownership of the address this profile is registered to".to_string(),
                            finding,
                            None,
                        ),
                    );
                }
            }
            if profile.public_email.as_deref() == Some(email.as_str()) {
                builder.evidence(
                    root,
                    profile_node,
                    RelationshipKind::PubliclyLinked,
                    item(
                        EvidenceSignal::SharedPublicEmail,
                        weights::SHARED_PUBLIC_EMAIL,
                        format!("{} profile publishes the investigated address", profile.platform),
                        finding,
                        Some(&profile.profile_url),
                    ),
                );
            }
        }
    }

    // Explicit links between profiles and to external accounts.
    let mut outgoing: HashMap<String, Vec<(String, bool)>> = HashMap::new();
    for (finding, profile, key) in &profiles {
        let source_node = profile_nodes[key];
        for account in &profile.linked_accounts {
            let Some(linked_key) = link_key(account) else { continue };
            if &linked_key == key {
                continue;
            }
            outgoing.entry(key.clone()).or_default().push((linked_key.clone(), account.verified_by_platform));
            let target_node = match profile_nodes.get(&linked_key) {
                Some(existing) => *existing,
                None => {
                    let platform = account.platform.clone().or_else(|| platform_for_host(&linked_key).map(str::to_string));
                    let kind = if platform_for_host(&linked_key).is_some() { IdentityKind::Profile } else { IdentityKind::Website };
                    builder.node(kind, &linked_key, linked_key.clone(), platform, None)
                }
            };
            let (signal, weight, verb) = if account.verified_by_platform {
                (EvidenceSignal::PlatformVerifiedLink, weights::PLATFORM_VERIFIED_LINK, "links to (verified by the platform)")
            } else {
                (EvidenceSignal::ExplicitLink, weights::EXPLICIT_LINK, "links to")
            };
            builder.evidence(
                source_node,
                target_node,
                RelationshipKind::PubliclyLinked,
                item(signal, weight, format!("{} profile {verb} {linked_key}", profile.platform), finding, account.url.as_deref()),
            );
        }
        if let Some(email) = profile.public_email.as_deref().and_then(|email| spectre_core::target::normalize_email(email).ok()) {
            let email_node = builder.node(IdentityKind::Email, &email, email.clone(), None, None);
            builder.evidence(
                source_node,
                email_node,
                RelationshipKind::PubliclyLinked,
                item(
                    EvidenceSignal::ExplicitLink,
                    weights::EXPLICIT_LINK,
                    format!("Address published on the {} profile", profile.platform),
                    finding,
                    Some(&profile.profile_url),
                ),
            );
        }
    }

    // Mutual links strengthen both directions.
    for (source_key, links) in &outgoing {
        for (target_key, _) in links {
            let reciprocal = outgoing.get(target_key).is_some_and(|back| back.iter().any(|(key, _)| key == source_key));
            if reciprocal
                && source_key < target_key
                && let (Some(&source), Some(&target_node)) = (profile_nodes.get(source_key), profile_nodes.get(target_key))
            {
                let finding = profiles.iter().find(|(_, _, key)| key == source_key).map(|(finding, _, _)| *finding);
                if let Some(finding) = finding {
                    let description = format!("{source_key} and {target_key} link to each other");
                    for (from, to) in [(source, target_node), (target_node, source)] {
                        if builder.edges.contains_key(&(from, to)) {
                            builder.evidence(
                                from,
                                to,
                                RelationshipKind::PubliclyLinked,
                                item(EvidenceSignal::MutualLink, weights::MUTUAL_LINK, description.clone(), finding, None),
                            );
                        }
                    }
                }
            }
        }
    }

    // Corroborate target-to-profile edges with other target-matching profiles.
    for (_, profile, key) in &profiles {
        if !matches_target.contains(key) {
            continue;
        }
        let profile_node = profile_nodes[key];
        let mut corroboration = Vec::new();
        for (other_finding, other, other_key) in &profiles {
            if other_key == key || !matches_target.contains(other_key) {
                continue;
            }
            let forward = outgoing.get(key).and_then(|links| links.iter().find(|(linked, _)| linked == other_key));
            let backward = outgoing.get(other_key).and_then(|links| links.iter().find(|(linked, _)| linked == key));
            if let Some((_, verified)) = forward.or(backward) {
                let (signal, weight) = if *verified {
                    (EvidenceSignal::PlatformVerifiedLink, weights::CORROBORATING_VERIFIED_LINK)
                } else {
                    (EvidenceSignal::ExplicitLink, weights::CORROBORATING_LINK)
                };
                corroboration.push(item(
                    signal,
                    weight,
                    format!("Explicitly linked with the {} profile, which also matches the target", other.platform),
                    other_finding,
                    Some(&other.profile_url),
                ));
                if forward.is_some() && backward.is_some() {
                    corroboration.push(item(
                        EvidenceSignal::MutualLink,
                        weights::MUTUAL_LINK,
                        format!("This profile and the {} profile link to each other", other.platform),
                        other_finding,
                        Some(&other.profile_url),
                    ));
                }
            }
            if let (Some(mine), Some(theirs)) = (website_key(profile), website_key(other))
                && mine == theirs
            {
                corroboration.push(item(
                    EvidenceSignal::SharedWebsite,
                    weights::SHARED_WEBSITE,
                    format!("Same website as the {} profile ({mine})", other.platform),
                    other_finding,
                    profile.website.as_deref(),
                ));
            }
            if let (Some(mine), Some(theirs)) =
                (profile.display_name.as_deref().and_then(normalized_name), other.display_name.as_deref().and_then(normalized_name))
                && mine == theirs
                && !corroboration.iter().any(|existing: &EvidenceItem| existing.signal == EvidenceSignal::MatchingDisplayName)
            {
                corroboration.push(item(
                    EvidenceSignal::MatchingDisplayName,
                    weights::MATCHING_DISPLAY_NAME,
                    format!("Display name \"{mine}\" also appears on the {} profile", other.platform),
                    other_finding,
                    None,
                ));
            }
        }
        for evidence in corroboration {
            builder.evidence(root, profile_node, RelationshipKind::PossibleSameOwner, evidence);
        }
    }

    // Email associations, web presence, breaches.
    for finding in findings {
        match &finding.data {
            FindingData::EmailAssociation(association) => {
                let email_node = builder.node(IdentityKind::Email, &association.email, association.email.clone(), None, Some(finding.id));
                if let Some(node) = builder.nodes.get_mut(&email_node) {
                    node.finding_id.get_or_insert(finding.id);
                }
            }
            FindingData::WebPresence(web) => {
                for (links, signal_note) in [(&web.rel_me_links, "declares rel=\"me\""), (&web.profile_links, "links to")] {
                    for href in links {
                        let Some(linked_key) = canonical_profile_key(href) else { continue };
                        let platform = platform_for_host(&linked_key).map(str::to_string);
                        let kind = if platform.is_some() { IdentityKind::Profile } else { IdentityKind::Website };
                        let node = builder.node(kind, &linked_key, linked_key.clone(), platform, None);
                        let weight =
                            if signal_note.starts_with("declares") { weights::EXPLICIT_LINK } else { weights::EXPLICIT_LINK * 0.75 };
                        builder.evidence(
                            root,
                            node,
                            RelationshipKind::PubliclyLinked,
                            item(EvidenceSignal::ExplicitLink, weight, format!("Homepage {signal_note} {linked_key}"), finding, Some(href)),
                        );
                    }
                }
            }
            FindingData::PgpKey(key) => {
                let anchor_email = key.email.to_ascii_lowercase();
                let anchor = builder.node(IdentityKind::Email, &anchor_email, anchor_email.clone(), None, Some(finding.id));
                let short: String = key.fingerprint.chars().skip(key.fingerprint.len().saturating_sub(16)).collect();
                for email in key.user_ids.iter().filter_map(|uid| email_in_user_id(uid)) {
                    if email == anchor_email {
                        continue;
                    }
                    let other = builder.node(IdentityKind::Email, &email, email.clone(), None, Some(finding.id));
                    builder.evidence(
                        anchor,
                        other,
                        RelationshipKind::PubliclyLinked,
                        item(
                            EvidenceSignal::PlatformVerifiedLink,
                            weights::PLATFORM_VERIFIED_LINK,
                            format!("Both addresses are confirmed user IDs on OpenPGP key {short}"),
                            finding,
                            None,
                        ),
                    );
                }
            }
            FindingData::BreachIncident(breach) => {
                let breach_node = builder.node(
                    IdentityKind::Breach,
                    &breach.incident.name.to_ascii_lowercase(),
                    breach.incident.title.clone(),
                    Some(breach.incident.source.clone()),
                    Some(finding.id),
                );
                let (anchor, description) = match &breach.exposed_account {
                    Some(email) => (
                        builder.node(IdentityKind::Email, email, email.clone(), None, None),
                        format!("{email} appears in the {} breach", breach.incident.title),
                    ),
                    None => (
                        root,
                        format!(
                            "The {} service suffered the {} breach",
                            breach.incident.domain.clone().unwrap_or_default(),
                            breach.incident.title
                        ),
                    ),
                };
                builder.evidence(
                    anchor,
                    breach_node,
                    RelationshipKind::ExposedInBreach,
                    item(EvidenceSignal::BreachExposure, 1.0, description, finding, None),
                );
            }
            _ => {}
        }
    }

    let mut graph = builder.finish();
    // Breach exposure edges are factual; mark them confirmed explicitly.
    for edge in &mut graph.edges {
        if edge.relationship == RelationshipKind::ExposedInBreach && edge.investigator_decision.is_none() {
            edge.category = ConfidenceCategory::Confirmed;
            edge.verified = true;
        }
    }

    // Profile finding confidence mirrors the target-to-profile relationship.
    let mut finding_confidence = Vec::new();
    for (finding, _, key) in &profiles {
        let node = profile_nodes[key];
        if let Some(edge) = graph.edges.iter().find(|edge| edge.source_identity == root && edge.target_identity == node) {
            finding_confidence.push((
                finding.id,
                Confidence::new(edge.confidence, edge.category, edge.evidence.iter().map(|evidence| evidence.description.clone())),
            ));
        }
    }
    CorrelationResult { graph, finding_confidence }
}

/// The address in an OpenPGP user ID (`Name <a@b>` or a bare address).
pub fn email_in_user_id(user_id: &str) -> Option<String> {
    let candidate = match (user_id.rfind('<'), user_id.rfind('>')) {
        (Some(start), Some(end)) if start < end => &user_id[start + 1..end],
        _ => user_id,
    };
    spectre_core::target::normalize_email(candidate).ok()
}

mod follow_ups;
pub use follow_ups::{FollowUp, suggest_follow_ups};

#[cfg(test)]
mod tests;
