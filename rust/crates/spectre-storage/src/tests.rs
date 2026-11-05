use chrono::Duration as ChronoDuration;
use spectre_core::model::*;
use spectre_core::target::{InvestigationTarget, TargetType};

use super::*;

fn investigation(target_type: TargetType, value: &str) -> Investigation {
    let target = InvestigationTarget::parse(target_type, value).unwrap();
    Investigation {
        id: Uuid::new_v4(),
        target_type: target.target_type(),
        target,
        purpose: "Authorized self-assessment".into(),
        status: InvestigationStatus::Pending,
        progress: 0.0,
        providers: vec!["github".into()],
        created_at: Utc::now(),
        started_at: None,
        completed_at: None,
        findings_count: 0,
        errors: Vec::new(),
        metrics: None,
    }
}

fn profile_finding(investigation_id: Uuid, username: &str) -> Finding {
    Finding {
        id: Uuid::new_v4(),
        investigation_id,
        provider_id: "github".into(),
        title: format!("GitHub profile: {username}"),
        summary: None,
        confidence: Confidence::new(0.35, ConfidenceCategory::WeakEvidence, ["username match"]),
        verification_status: VerificationStatus::PubliclyObserved,
        discovered_at: Utc::now(),
        sources: vec![SourceReference {
            provider_id: "github".into(),
            provider_name: "GitHub".into(),
            url: Some(format!("https://github.com/{username}")),
            method: DiscoveryMethod::PublicApi,
            retrieved_at: Utc::now(),
        }],
        data: FindingData::Profile(ProfileFinding {
            platform: "GitHub".into(),
            username: username.into(),
            profile_url: format!("https://github.com/{username}"),
            ..Default::default()
        }),
    }
}

#[tokio::test]
async fn migrations_create_the_full_schema() {
    let storage = Storage::open_in_memory().await.unwrap();
    assert_eq!(storage.schema_version().await.unwrap(), SCHEMA_VERSION);
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name != '_sqlx_migrations' ORDER BY name",
    )
    .fetch_all(&storage.pool)
    .await
    .unwrap();
    for expected in [
        "audit_events",
        "breach_exposures",
        "breach_incidents",
        "email_addresses",
        "engine_settings",
        "finding_sources",
        "findings",
        "identities",
        "identity_relationships",
        "investigation_errors",
        "investigation_targets",
        "investigations",
        "phone_numbers",
        "profiles",
        "provider_configs",
    ] {
        assert!(tables.contains(&expected.to_string()), "missing table {expected}");
    }
    let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys").fetch_one(&storage.pool).await.unwrap();
    assert_eq!(foreign_keys, 1);
    // Re-running migrations is a no-op.
    storage.migrate().await.unwrap();
}

#[tokio::test]
async fn file_database_is_private_and_secure_delete_is_on() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("nested").join("spectre.sqlite");
    let storage = Storage::open(&path).await.unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let secure_delete: i64 = sqlx::query_scalar("PRAGMA secure_delete").fetch_one(&storage.pool).await.unwrap();
    assert_eq!(secure_delete, 1);
    let journal: String = sqlx::query_scalar("PRAGMA journal_mode").fetch_one(&storage.pool).await.unwrap();
    assert_eq!(journal, "wal");
}

#[tokio::test]
async fn investigation_lifecycle_and_findings_round_trip() {
    let storage = Storage::open_in_memory().await.unwrap();
    let created = investigation(TargetType::Username, "octocat");
    storage.create_investigation(&created).await.unwrap();
    storage.mark_started(created.id, Utc::now()).await.unwrap();
    let finding = profile_finding(created.id, "octocat");
    storage.insert_finding(&finding).await.unwrap();
    storage
        .record_error(
            created.id,
            &ProviderFailure {
                provider_id: "gitlab".into(),
                code: spectre_core::error::ErrorCode::RateLimited,
                message: "slow down".into(),
                occurred_at: Utc::now(),
            },
        )
        .await
        .unwrap();
    let metrics = InvestigationMetrics { total_duration_ms: 1200, cache_hits: 1, cache_misses: 3, ..Default::default() };
    storage.finish_investigation(created.id, InvestigationStatus::PartiallyCompleted, &metrics, Utc::now()).await.unwrap();

    let loaded = storage.get_investigation(created.id).await.unwrap();
    assert_eq!(loaded.status, InvestigationStatus::PartiallyCompleted);
    assert_eq!(loaded.findings_count, 1);
    assert_eq!(loaded.errors.len(), 1);
    assert_eq!(loaded.errors[0].code, spectre_core::error::ErrorCode::RateLimited);
    assert_eq!(loaded.metrics.unwrap().cache_hit_rate(), Some(0.25));

    let findings = storage.findings_for(created.id).await.unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].data, finding.data);
    assert_eq!(findings[0].sources, finding.sources);

    let listed = storage.list_investigations(10, 0, Some("OCTO")).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert!(storage.list_investigations(10, 0, Some("nobody")).await.unwrap().is_empty());
}

#[tokio::test]
async fn deleting_cascades_but_keeps_audit_trail() {
    let storage = Storage::open_in_memory().await.unwrap();
    let created = investigation(TargetType::Username, "octocat");
    storage.create_investigation(&created).await.unwrap();
    storage.insert_finding(&profile_finding(created.id, "octocat")).await.unwrap();
    storage.record_audit(Some(created.id), "investigation_started", serde_json::json!({"target_type": "username"})).await.unwrap();
    storage.delete_investigation(created.id).await.unwrap();
    for table in ["findings", "finding_sources", "profiles", "investigation_targets"] {
        let remaining: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}")).fetch_one(&storage.pool).await.unwrap();
        assert_eq!(remaining, 0, "{table} should be empty");
    }
    assert_eq!(storage.audit_events(10).await.unwrap().len(), 1);
    assert_eq!(storage.delete_investigation(created.id).await.unwrap_err().code, spectre_core::error::ErrorCode::NotFound);
}

#[tokio::test]
async fn graph_replacement_preserves_decisions() {
    let storage = Storage::open_in_memory().await.unwrap();
    let created = investigation(TargetType::Username, "octocat");
    storage.create_investigation(&created).await.unwrap();
    let node = |label: &str, is_target: bool| Identity {
        id: Uuid::new_v5(&created.id, label.as_bytes()),
        kind: if is_target { IdentityKind::Username } else { IdentityKind::Profile },
        label: label.into(),
        value: label.into(),
        platform: None,
        finding_id: None,
        is_target,
        verified: false,
    };
    let (root, profile) = (node("octocat", true), node("github.com/octocat", false));
    let edge = IdentityRelationship {
        id: Uuid::new_v4(),
        source_identity: root.id,
        target_identity: profile.id,
        relationship: RelationshipKind::PossibleSameOwner,
        confidence: 0.35,
        category: ConfidenceCategory::WeakEvidence,
        evidence: vec![],
        verified: false,
        investigator_decision: None,
    };
    let graph = IdentityGraph { nodes: vec![root.clone(), profile.clone()], edges: vec![edge.clone()] };
    storage.replace_graph(created.id, &graph).await.unwrap();
    assert_eq!(storage.set_relationship_decision(edge.id, Some(InvestigatorDecision::Confirmed)).await.unwrap(), created.id);
    let decisions = storage.decisions_for(created.id).await.unwrap();
    assert_eq!(decisions.get(&(root.id, profile.id)), Some(&InvestigatorDecision::Confirmed));

    let loaded = storage.graph_for(created.id).await.unwrap();
    assert_eq!(loaded.nodes.len(), 2);
    assert_eq!(loaded.edges[0].investigator_decision, Some(InvestigatorDecision::Confirmed));
}

#[tokio::test]
async fn email_verification_never_downgrades_and_domains_propagate() {
    let storage = Storage::open_in_memory().await.unwrap();
    let created = investigation(TargetType::Email, "owner@example.org");
    storage.create_investigation(&created).await.unwrap();
    assert_eq!(storage.email_record("owner@example.org").await.unwrap().verification_status, VerificationStatus::Unverified);

    storage
        .set_email_verification(
            "owner@example.org",
            VerificationStatus::OwnershipVerified,
            Some(VerificationMethod::InvestigatorAttestation),
            Some("I own it"),
        )
        .await
        .unwrap();
    // A later public observation must not downgrade the verified state.
    let mut association = profile_finding(created.id, "x");
    association.data = FindingData::EmailAssociation(EmailAssociationFinding {
        email: "owner@example.org".into(),
        source_description: "test".into(),
        discovery_method: DiscoveryMethod::PublicApi,
        verification_status: VerificationStatus::PubliclyObserved,
    });
    storage.insert_finding(&association).await.unwrap();
    assert_eq!(storage.email_record("owner@example.org").await.unwrap().verification_status, VerificationStatus::OwnershipVerified);
}

#[tokio::test]
async fn breach_exposures_and_dashboard() {
    let storage = Storage::open_in_memory().await.unwrap();
    storage.ensure_email("owner@example.org").await.unwrap();
    let incident = BreachIncident {
        name: "Adobe".into(),
        title: "Adobe".into(),
        domain: Some("adobe.com".into()),
        breach_date: Some("2013-10-04".into()),
        added_date: None,
        modified_date: None,
        pwn_count: 152_445_165,
        description: "x".into(),
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
    storage.upsert_incidents(std::slice::from_ref(&incident)).await.unwrap();
    storage.record_exposures("owner@example.org", &["Adobe".to_string()]).await.unwrap();
    assert_eq!(storage.exposures_for("owner@example.org").await.unwrap(), vec![incident.clone()]);
    assert!(storage.email_record("owner@example.org").await.unwrap().last_breach_check_at.is_some());
    assert_eq!(storage.search_incidents(Some("ADOBE"), 10).await.unwrap().len(), 1);
    let stats = storage.dashboard().await.unwrap();
    assert_eq!(stats.breach_exposures, 1);
    assert_eq!(stats.exposures_by_year, vec![CountByLabel { label: "2013".into(), count: 1 }]);
}

#[tokio::test]
async fn settings_and_provider_configs_persist() {
    let storage = Storage::open_in_memory().await.unwrap();
    assert_eq!(storage.settings().await.unwrap(), EngineSettings::default());
    let updated = EngineSettings { max_concurrency: 8, retention_days: 30, ..Default::default() };
    storage.save_settings(&updated).await.unwrap();
    assert_eq!(storage.settings().await.unwrap(), updated);
    assert!(storage.save_settings(&EngineSettings { max_concurrency: 0, ..Default::default() }).await.is_err());

    let config = ProviderConfig { provider_id: "github".into(), enabled: false, rate_limit_per_minute: Some(10) };
    storage.save_provider_config(&config).await.unwrap();
    assert_eq!(storage.provider_configs().await.unwrap(), vec![config]);
}

#[tokio::test]
async fn retention_purge_and_interrupted_runs() {
    let storage = Storage::open_in_memory().await.unwrap();
    let mut old = investigation(TargetType::Username, "old");
    old.created_at = Utc::now() - ChronoDuration::days(40);
    old.status = InvestigationStatus::Completed;
    storage.create_investigation(&old).await.unwrap();
    let running = investigation(TargetType::Username, "running");
    storage.create_investigation(&running).await.unwrap();
    storage.mark_started(running.id, Utc::now()).await.unwrap();

    assert_eq!(storage.purge_before(Utc::now() - ChronoDuration::days(30)).await.unwrap(), 1);
    assert_eq!(storage.fail_interrupted().await.unwrap(), 1);
    assert_eq!(storage.get_investigation(running.id).await.unwrap().status, InvestigationStatus::Failed);
}

#[tokio::test]
async fn backup_validate_export_import() {
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::open(directory.path().join("main.sqlite")).await.unwrap();
    let created = investigation(TargetType::Username, "octocat");
    storage.create_investigation(&created).await.unwrap();
    storage.insert_finding(&profile_finding(created.id, "octocat")).await.unwrap();

    let backup = directory.path().join("backup.sqlite");
    storage.backup_to(&backup).await.unwrap();
    assert_eq!(Storage::validate_backup(&backup).await.unwrap(), SCHEMA_VERSION);
    assert!(storage.backup_to(&backup).await.is_err(), "never overwrite");
    let bogus = directory.path().join("bogus.sqlite");
    std::fs::write(&bogus, b"not a database").unwrap();
    assert!(Storage::validate_backup(&bogus).await.is_err());

    let bundle = storage.export_bundle(created.id).await.unwrap();
    let json = serde_json::to_string(&bundle).unwrap();
    let other = Storage::open_in_memory().await.unwrap();
    let imported = other.import_bundle(&serde_json::from_str(&json).unwrap()).await.unwrap();
    assert_eq!(imported, created.id);
    assert_eq!(other.findings_for(imported).await.unwrap().len(), 1);
    assert!(other.import_bundle(&bundle).await.is_err(), "duplicate import is refused");
    assert_eq!(storage.integrity_check().await.unwrap(), vec!["ok".to_string()]);
}
