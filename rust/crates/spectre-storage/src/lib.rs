//! SQLite persistence for investigations, findings, identities, verification
//! records, breach data, provider configuration, and audit events.
//!
//! * Versioned migrations are embedded (`migrations/`) and applied on open.
//! * `foreign_keys`, WAL journaling, and `secure_delete` are enabled; deletes
//!   are followed by a WAL checkpoint so removed content is overwritten.
//! * The database file is created with `0600` permissions.
//! * No plaintext passwords, password hashes, recovered credentials, or API
//!   keys are ever stored.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use spectre_core::config::{EngineSettings, ProviderConfig};
use spectre_core::error::{ErrorCode, SpectreError, SpectreResult};
use spectre_core::model::*;
use spectre_core::target::{InvestigationTarget, TargetType};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow, SqliteSynchronous};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

pub const SCHEMA_VERSION: i64 = 1;
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

fn db(error: sqlx::Error) -> SpectreError {
    match error {
        sqlx::Error::RowNotFound => SpectreError::not_found("record not found"),
        other => SpectreError::storage(format!("database error: {other}")),
    }
}

fn json_error(error: serde_json::Error) -> SpectreError {
    SpectreError::storage(format!("stored data could not be decoded: {error}"))
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

fn parse_time(raw: &str) -> SpectreResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| SpectreError::storage("invalid timestamp in database"))
}

fn parse_optional_time(raw: Option<String>) -> SpectreResult<Option<DateTime<Utc>>> {
    raw.as_deref().map(parse_time).transpose()
}

fn parse_uuid(raw: &str) -> SpectreResult<Uuid> {
    Uuid::parse_str(raw).map_err(|_| SpectreError::storage("invalid identifier in database"))
}

/// Aggregate figures for the dashboard.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DashboardStats {
    pub investigations: u64,
    pub running: u64,
    pub findings: u64,
    pub profiles: u64,
    pub confirmed_relationships: u64,
    pub strong_relationships: u64,
    pub verified_emails: u64,
    pub breach_exposures: u64,
    pub findings_by_provider: Vec<CountByLabel>,
    pub findings_by_category: Vec<CountByLabel>,
    pub investigations_by_day: Vec<CountByLabel>,
    pub exposures_by_year: Vec<CountByLabel>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CountByLabel {
    pub label: String,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub investigation_id: Option<Uuid>,
    pub event_type: String,
    pub detail: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageInfo {
    pub path: Option<String>,
    pub schema_version: i64,
    pub size_bytes: u64,
    pub page_count: i64,
    pub freelist_pages: i64,
}

/// Portable export of one investigation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvestigationBundle {
    pub format: String,
    pub format_version: u32,
    pub exported_at: DateTime<Utc>,
    pub detail: InvestigationDetail,
}

pub const BUNDLE_FORMAT: &str = "spectre.investigation";

#[derive(Debug, Clone)]
pub struct Storage {
    pool: SqlitePool,
    path: Option<PathBuf>,
}

impl Storage {
    /// Open (creating if needed) the database at `path` and apply migrations.
    pub async fn open(path: impl AsRef<Path>) -> SpectreResult<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| SpectreError::storage(format!("cannot create storage directory: {error}")))?;
        }
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_secs(5))
            .pragma("secure_delete", "ON");
        let pool = SqlitePoolOptions::new().max_connections(4).connect_with(options).await.map_err(db)?;
        restrict_permissions(&path);
        let storage = Self { pool, path: Some(path) };
        storage.migrate().await?;
        Ok(storage)
    }

    /// Ephemeral database for tests and diagnostics.
    pub async fn open_in_memory() -> SpectreResult<Self> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:").map_err(db)?.foreign_keys(true);
        let pool = SqlitePoolOptions::new().max_connections(1).connect_with(options).await.map_err(db)?;
        let storage = Self { pool, path: None };
        storage.migrate().await?;
        Ok(storage)
    }

    async fn migrate(&self) -> SpectreResult<()> {
        MIGRATOR.run(&self.pool).await.map_err(|error| SpectreError::storage(format!("migration failed: {error}")))
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }

    pub async fn schema_version(&self) -> SpectreResult<i64> {
        let version: Option<i64> =
            sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations WHERE success = 1").fetch_one(&self.pool).await.map_err(db)?;
        Ok(version.unwrap_or(0))
    }

    // -----------------------------------------------------------------------
    // Investigations
    // -----------------------------------------------------------------------

    pub async fn create_investigation(&self, investigation: &Investigation) -> SpectreResult<()> {
        let mut transaction = self.pool.begin().await.map_err(db)?;
        sqlx::query(
            "INSERT INTO investigations (id, target_type, target_value, purpose, status, progress, providers_json, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(investigation.id.to_string())
        .bind(investigation.target_type.as_str())
        .bind(investigation.target.value())
        .bind(&investigation.purpose)
        .bind(investigation.status.as_str())
        .bind(investigation.progress)
        .bind(serde_json::to_string(&investigation.providers).map_err(json_error)?)
        .bind(timestamp(investigation.created_at))
        .execute(&mut *transaction)
        .await
        .map_err(db)?;
        sqlx::query(
            "INSERT INTO investigation_targets (id, investigation_id, target_type, normalized_value, role, created_at) VALUES (?, ?, ?, ?, 'primary', ?)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(investigation.id.to_string())
        .bind(investigation.target_type.as_str())
        .bind(investigation.target.value())
        .bind(timestamp(investigation.created_at))
        .execute(&mut *transaction)
        .await
        .map_err(db)?;
        let now = timestamp(Utc::now());
        match &investigation.target {
            InvestigationTarget::Email(email) => {
                sqlx::query(
                    "INSERT INTO email_addresses (id, email, verification_status, created_at, updated_at) VALUES (?, ?, 'unverified', ?, ?)
                     ON CONFLICT (email) DO NOTHING",
                )
                .bind(Uuid::new_v4().to_string())
                .bind(email)
                .bind(&now)
                .bind(&now)
                .execute(&mut *transaction)
                .await
                .map_err(db)?;
            }
            InvestigationTarget::Domain(domain) => {
                sqlx::query(
                    "INSERT INTO domains (id, domain, verification_status, created_at, updated_at) VALUES (?, ?, 'unverified', ?, ?)
                     ON CONFLICT (domain) DO NOTHING",
                )
                .bind(Uuid::new_v4().to_string())
                .bind(domain)
                .bind(&now)
                .bind(&now)
                .execute(&mut *transaction)
                .await
                .map_err(db)?;
            }
            _ => {}
        }
        transaction.commit().await.map_err(db)
    }

    pub async fn mark_started(&self, investigation_id: Uuid, started_at: DateTime<Utc>) -> SpectreResult<()> {
        sqlx::query("UPDATE investigations SET status = 'running', started_at = ? WHERE id = ?")
            .bind(timestamp(started_at))
            .bind(investigation_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(())
    }

    pub async fn update_progress(&self, investigation_id: Uuid, progress: f64) -> SpectreResult<()> {
        sqlx::query("UPDATE investigations SET progress = ? WHERE id = ?")
            .bind(progress.clamp(0.0, 1.0))
            .bind(investigation_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(())
    }

    pub async fn finish_investigation(
        &self,
        investigation_id: Uuid,
        status: InvestigationStatus,
        metrics: &InvestigationMetrics,
        completed_at: DateTime<Utc>,
    ) -> SpectreResult<()> {
        sqlx::query("UPDATE investigations SET status = ?, progress = 1.0, metrics_json = ?, completed_at = ? WHERE id = ?")
            .bind(status.as_str())
            .bind(serde_json::to_string(metrics).map_err(json_error)?)
            .bind(timestamp(completed_at))
            .bind(investigation_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(())
    }

    /// Investigations left `running`/`pending` by a previous process are
    /// marked failed at startup so the UI never shows phantom activity.
    pub async fn fail_interrupted(&self) -> SpectreResult<u64> {
        let result = sqlx::query("UPDATE investigations SET status = 'failed', completed_at = ? WHERE status IN ('running', 'pending')")
            .bind(timestamp(Utc::now()))
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(result.rows_affected())
    }

    pub async fn record_error(&self, investigation_id: Uuid, failure: &ProviderFailure) -> SpectreResult<()> {
        sqlx::query(
            "INSERT INTO investigation_errors (id, investigation_id, provider_id, code, message, occurred_at) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(investigation_id.to_string())
        .bind(&failure.provider_id)
        .bind(serde_json::to_value(failure.code).map_err(json_error)?.as_str().unwrap_or("internal"))
        .bind(&failure.message)
        .bind(timestamp(failure.occurred_at))
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    fn investigation_from_row(row: &SqliteRow, findings_count: u32, errors: Vec<ProviderFailure>) -> SpectreResult<Investigation> {
        let target_type: TargetType = row.try_get::<String, _>("target_type").map_err(db)?.parse()?;
        let target_value: String = row.try_get("target_value").map_err(db)?;
        let target = match target_type {
            TargetType::Username => InvestigationTarget::Username(target_value),
            TargetType::Email => InvestigationTarget::Email(target_value),
            TargetType::Phone => InvestigationTarget::Phone(target_value),
            TargetType::Domain => InvestigationTarget::Domain(target_value),
        };
        let status_raw: String = row.try_get("status").map_err(db)?;
        let metrics: Option<String> = row.try_get("metrics_json").map_err(db)?;
        Ok(Investigation {
            id: parse_uuid(&row.try_get::<String, _>("id").map_err(db)?)?,
            target,
            target_type,
            purpose: row.try_get("purpose").map_err(db)?,
            status: InvestigationStatus::parse(&status_raw).ok_or_else(|| SpectreError::storage("invalid status"))?,
            progress: row.try_get("progress").map_err(db)?,
            providers: serde_json::from_str(&row.try_get::<String, _>("providers_json").map_err(db)?).map_err(json_error)?,
            created_at: parse_time(&row.try_get::<String, _>("created_at").map_err(db)?)?,
            started_at: parse_optional_time(row.try_get("started_at").map_err(db)?)?,
            completed_at: parse_optional_time(row.try_get("completed_at").map_err(db)?)?,
            findings_count,
            errors,
            metrics: metrics.map(|raw| serde_json::from_str(&raw)).transpose().map_err(json_error)?,
        })
    }

    async fn errors_for(&self, investigation_ids: &[String]) -> SpectreResult<HashMap<String, Vec<ProviderFailure>>> {
        let mut grouped: HashMap<String, Vec<ProviderFailure>> = HashMap::new();
        if investigation_ids.is_empty() {
            return Ok(grouped);
        }
        let placeholders = vec!["?"; investigation_ids.len()].join(",");
        let sql = format!(
            "SELECT investigation_id, provider_id, code, message, occurred_at FROM investigation_errors WHERE investigation_id IN ({placeholders}) ORDER BY occurred_at"
        );
        let mut query = sqlx::query(&sql);
        for identifier in investigation_ids {
            query = query.bind(identifier);
        }
        for row in query.fetch_all(&self.pool).await.map_err(db)? {
            let code: String = row.try_get("code").map_err(db)?;
            grouped.entry(row.try_get("investigation_id").map_err(db)?).or_default().push(ProviderFailure {
                provider_id: row.try_get("provider_id").map_err(db)?,
                code: serde_json::from_value(serde_json::Value::String(code)).unwrap_or(ErrorCode::Internal),
                message: row.try_get("message").map_err(db)?,
                occurred_at: parse_time(&row.try_get::<String, _>("occurred_at").map_err(db)?)?,
            });
        }
        Ok(grouped)
    }

    pub async fn get_investigation(&self, investigation_id: Uuid) -> SpectreResult<Investigation> {
        let identifier = investigation_id.to_string();
        let row = sqlx::query(
            "SELECT i.*, (SELECT COUNT(*) FROM findings f WHERE f.investigation_id = i.id) AS findings_count FROM investigations i WHERE i.id = ?",
        )
        .bind(&identifier)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?
        .ok_or_else(|| SpectreError::not_found(format!("investigation {investigation_id} not found")))?;
        let mut errors = self.errors_for(std::slice::from_ref(&identifier)).await?;
        let count: i64 = row.try_get("findings_count").map_err(db)?;
        Self::investigation_from_row(&row, count as u32, errors.remove(&identifier).unwrap_or_default())
    }

    pub async fn list_investigations(&self, limit: u32, offset: u32, search: Option<&str>) -> SpectreResult<Vec<Investigation>> {
        let pattern = search.map(|text| format!("%{}%", text.trim().to_lowercase()));
        let rows = sqlx::query(
            "SELECT i.*, (SELECT COUNT(*) FROM findings f WHERE f.investigation_id = i.id) AS findings_count
             FROM investigations i
             WHERE (?1 IS NULL OR lower(i.target_value) LIKE ?1 OR lower(i.purpose) LIKE ?1)
             ORDER BY i.created_at DESC LIMIT ?2 OFFSET ?3",
        )
        .bind(pattern)
        .bind(i64::from(limit.clamp(1, 500)))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        let identifiers: Vec<String> = rows.iter().filter_map(|row| row.try_get::<String, _>("id").ok()).collect();
        let mut errors = self.errors_for(&identifiers).await?;
        rows.iter()
            .map(|row| {
                let identifier: String = row.try_get("id").map_err(db)?;
                let count: i64 = row.try_get("findings_count").map_err(db)?;
                Self::investigation_from_row(row, count as u32, errors.remove(&identifier).unwrap_or_default())
            })
            .collect()
    }

    /// Delete an investigation and everything derived from it, then
    /// checkpoint the WAL so `secure_delete` overwrites the freed pages.
    pub async fn delete_investigation(&self, investigation_id: Uuid) -> SpectreResult<()> {
        let result = sqlx::query("DELETE FROM investigations WHERE id = ?")
            .bind(investigation_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(db)?;
        if result.rows_affected() == 0 {
            return Err(SpectreError::not_found(format!("investigation {investigation_id} not found")));
        }
        self.checkpoint().await
    }

    /// Purge investigations created before `cutoff`. Returns the count.
    pub async fn purge_before(&self, cutoff: DateTime<Utc>) -> SpectreResult<u64> {
        let result = sqlx::query("DELETE FROM investigations WHERE created_at < ? AND status NOT IN ('running', 'pending')")
            .bind(timestamp(cutoff))
            .execute(&self.pool)
            .await
            .map_err(db)?;
        if result.rows_affected() > 0 {
            self.checkpoint().await?;
        }
        Ok(result.rows_affected())
    }

    async fn checkpoint(&self) -> SpectreResult<()> {
        if self.path.is_some() {
            sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)").execute(&self.pool).await.map_err(db)?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Findings
    // -----------------------------------------------------------------------

    pub async fn insert_finding(&self, finding: &Finding) -> SpectreResult<()> {
        let mut transaction = self.pool.begin().await.map_err(db)?;
        let identifier = finding.id.to_string();
        sqlx::query(
            "INSERT INTO findings (id, investigation_id, provider_id, kind, title, summary, confidence, category, rationale_json, verification_status, data_json, discovered_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&identifier)
        .bind(finding.investigation_id.to_string())
        .bind(&finding.provider_id)
        .bind(finding.kind().as_str())
        .bind(&finding.title)
        .bind(&finding.summary)
        .bind(finding.confidence.score)
        .bind(finding.confidence.category.as_str())
        .bind(serde_json::to_string(&finding.confidence.rationale).map_err(json_error)?)
        .bind(finding.verification_status.as_str())
        .bind(serde_json::to_string(&finding.data).map_err(json_error)?)
        .bind(timestamp(finding.discovered_at))
        .execute(&mut *transaction)
        .await
        .map_err(db)?;
        for source in &finding.sources {
            sqlx::query(
                "INSERT INTO finding_sources (finding_id, provider_id, provider_name, url, method, retrieved_at) VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(&identifier)
            .bind(&source.provider_id)
            .bind(&source.provider_name)
            .bind(&source.url)
            .bind(serde_json::to_value(source.method).map_err(json_error)?.as_str().unwrap_or_default().to_string())
            .bind(timestamp(source.retrieved_at))
            .execute(&mut *transaction)
            .await
            .map_err(db)?;
        }
        let now = timestamp(Utc::now());
        match &finding.data {
            FindingData::Profile(profile) => {
                sqlx::query(
                    "INSERT INTO profiles (id, investigation_id, platform, username, profile_url, display_name, platform_verified, confidence, discovered_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(&identifier)
                .bind(finding.investigation_id.to_string())
                .bind(&profile.platform)
                .bind(&profile.username)
                .bind(&profile.profile_url)
                .bind(&profile.display_name)
                .bind(profile.platform_verified)
                .bind(finding.confidence.score)
                .bind(timestamp(finding.discovered_at))
                .execute(&mut *transaction)
                .await
                .map_err(db)?;
            }
            FindingData::EmailAssociation(association) => {
                // Never downgrade an existing verification state.
                sqlx::query(
                    "INSERT INTO email_addresses (id, email, verification_status, created_at, updated_at) VALUES (?, ?, 'publicly_observed', ?, ?)
                     ON CONFLICT (email) DO UPDATE SET verification_status = 'publicly_observed', updated_at = excluded.updated_at
                     WHERE email_addresses.verification_status = 'unverified'",
                )
                .bind(Uuid::new_v4().to_string())
                .bind(&association.email)
                .bind(&now)
                .bind(&now)
                .execute(&mut *transaction)
                .await
                .map_err(db)?;
            }
            FindingData::PhoneMetadata(info) => {
                sqlx::query(
                    "INSERT INTO phone_numbers (id, e164, country_calling_code, region_code, number_type, verification_status, created_at)
                     VALUES (?, ?, ?, ?, ?, 'unverified', ?) ON CONFLICT (e164) DO NOTHING",
                )
                .bind(Uuid::new_v4().to_string())
                .bind(&info.e164)
                .bind(i64::from(info.country_calling_code))
                .bind(&info.region_code)
                .bind(&info.number_type)
                .bind(&now)
                .execute(&mut *transaction)
                .await
                .map_err(db)?;
            }
            _ => {}
        }
        transaction.commit().await.map_err(db)
    }

    pub async fn findings_for(&self, investigation_id: Uuid) -> SpectreResult<Vec<Finding>> {
        let identifier = investigation_id.to_string();
        let mut sources: HashMap<String, Vec<SourceReference>> = HashMap::new();
        let source_rows = sqlx::query(
            "SELECT s.finding_id, s.provider_id, s.provider_name, s.url, s.method, s.retrieved_at
             FROM finding_sources s JOIN findings f ON f.id = s.finding_id WHERE f.investigation_id = ? ORDER BY s.id",
        )
        .bind(&identifier)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        for row in source_rows {
            let method: String = row.try_get("method").map_err(db)?;
            sources.entry(row.try_get("finding_id").map_err(db)?).or_default().push(SourceReference {
                provider_id: row.try_get("provider_id").map_err(db)?,
                provider_name: row.try_get("provider_name").map_err(db)?,
                url: row.try_get("url").map_err(db)?,
                method: serde_json::from_value(serde_json::Value::String(method)).map_err(json_error)?,
                retrieved_at: parse_time(&row.try_get::<String, _>("retrieved_at").map_err(db)?)?,
            });
        }
        let rows = sqlx::query("SELECT * FROM findings WHERE investigation_id = ? ORDER BY discovered_at, rowid")
            .bind(&identifier)
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        rows.iter()
            .map(|row| {
                let finding_id: String = row.try_get("id").map_err(db)?;
                let category: String = row.try_get("category").map_err(db)?;
                let verification: String = row.try_get("verification_status").map_err(db)?;
                Ok(Finding {
                    id: parse_uuid(&finding_id)?,
                    investigation_id,
                    provider_id: row.try_get("provider_id").map_err(db)?,
                    title: row.try_get("title").map_err(db)?,
                    summary: row.try_get("summary").map_err(db)?,
                    confidence: Confidence {
                        score: row.try_get("confidence").map_err(db)?,
                        category: ConfidenceCategory::parse(&category).ok_or_else(|| SpectreError::storage("invalid category"))?,
                        rationale: serde_json::from_str(&row.try_get::<String, _>("rationale_json").map_err(db)?).map_err(json_error)?,
                    },
                    verification_status: VerificationStatus::parse(&verification)
                        .ok_or_else(|| SpectreError::storage("invalid verification status"))?,
                    discovered_at: parse_time(&row.try_get::<String, _>("discovered_at").map_err(db)?)?,
                    sources: sources.remove(&finding_id).unwrap_or_default(),
                    data: serde_json::from_str(&row.try_get::<String, _>("data_json").map_err(db)?).map_err(json_error)?,
                })
            })
            .collect()
    }

    pub async fn update_finding_confidence(&self, updates: &[(Uuid, Confidence)]) -> SpectreResult<()> {
        let mut transaction = self.pool.begin().await.map_err(db)?;
        for (finding_id, confidence) in updates {
            sqlx::query("UPDATE findings SET confidence = ?, category = ?, rationale_json = ? WHERE id = ?")
                .bind(confidence.score)
                .bind(confidence.category.as_str())
                .bind(serde_json::to_string(&confidence.rationale).map_err(json_error)?)
                .bind(finding_id.to_string())
                .execute(&mut *transaction)
                .await
                .map_err(db)?;
            sqlx::query("UPDATE profiles SET confidence = ? WHERE id = ?")
                .bind(confidence.score)
                .bind(finding_id.to_string())
                .execute(&mut *transaction)
                .await
                .map_err(db)?;
        }
        transaction.commit().await.map_err(db)
    }

    // -----------------------------------------------------------------------
    // Identity graph
    // -----------------------------------------------------------------------

    /// Investigator decisions keyed by (source identity, target identity).
    pub async fn decisions_for(&self, investigation_id: Uuid) -> SpectreResult<HashMap<(Uuid, Uuid), InvestigatorDecision>> {
        let rows = sqlx::query(
            "SELECT source_identity, target_identity, investigator_decision FROM identity_relationships
             WHERE investigation_id = ? AND investigator_decision IS NOT NULL",
        )
        .bind(investigation_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        let mut decisions = HashMap::new();
        for row in rows {
            let decision: String = row.try_get("investigator_decision").map_err(db)?;
            if let Some(decision) = InvestigatorDecision::parse(&decision) {
                decisions.insert(
                    (
                        parse_uuid(&row.try_get::<String, _>("source_identity").map_err(db)?)?,
                        parse_uuid(&row.try_get::<String, _>("target_identity").map_err(db)?)?,
                    ),
                    decision,
                );
            }
        }
        Ok(decisions)
    }

    pub async fn replace_graph(&self, investigation_id: Uuid, graph: &IdentityGraph) -> SpectreResult<()> {
        let identifier = investigation_id.to_string();
        let mut transaction = self.pool.begin().await.map_err(db)?;
        let previous: HashMap<String, String> =
            sqlx::query("SELECT id, decided_at FROM identity_relationships WHERE investigation_id = ? AND decided_at IS NOT NULL")
                .bind(&identifier)
                .fetch_all(&mut *transaction)
                .await
                .map_err(db)?
                .into_iter()
                .filter_map(|row| Some((row.try_get("id").ok()?, row.try_get("decided_at").ok()?)))
                .collect();
        sqlx::query("DELETE FROM identities WHERE investigation_id = ?").bind(&identifier).execute(&mut *transaction).await.map_err(db)?;
        for node in &graph.nodes {
            sqlx::query(
                "INSERT INTO identities (id, investigation_id, kind, label, value, platform, finding_id, is_target, verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(node.id.to_string())
            .bind(&identifier)
            .bind(node.kind.as_str())
            .bind(&node.label)
            .bind(&node.value)
            .bind(&node.platform)
            .bind(node.finding_id.map(|id| id.to_string()))
            .bind(node.is_target)
            .bind(node.verified)
            .execute(&mut *transaction)
            .await
            .map_err(db)?;
        }
        let now = timestamp(Utc::now());
        for edge in &graph.edges {
            let edge_id = edge.id.to_string();
            let decided_at = edge.investigator_decision.map(|_| previous.get(&edge_id).cloned().unwrap_or_else(|| now.clone()));
            sqlx::query(
                "INSERT INTO identity_relationships (id, investigation_id, source_identity, target_identity, relationship, confidence, category, evidence_json, verified, investigator_decision, decided_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&edge_id)
            .bind(&identifier)
            .bind(edge.source_identity.to_string())
            .bind(edge.target_identity.to_string())
            .bind(edge.relationship.as_str())
            .bind(edge.confidence)
            .bind(edge.category.as_str())
            .bind(serde_json::to_string(&edge.evidence).map_err(json_error)?)
            .bind(edge.verified)
            .bind(edge.investigator_decision.map(InvestigatorDecision::as_str))
            .bind(decided_at)
            .execute(&mut *transaction)
            .await
            .map_err(db)?;
        }
        transaction.commit().await.map_err(db)
    }

    pub async fn graph_for(&self, investigation_id: Uuid) -> SpectreResult<IdentityGraph> {
        let identifier = investigation_id.to_string();
        let node_rows = sqlx::query("SELECT * FROM identities WHERE investigation_id = ? ORDER BY is_target DESC, kind, label")
            .bind(&identifier)
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        let mut nodes = Vec::with_capacity(node_rows.len());
        for row in node_rows {
            let kind: String = row.try_get("kind").map_err(db)?;
            let finding: Option<String> = row.try_get("finding_id").map_err(db)?;
            nodes.push(Identity {
                id: parse_uuid(&row.try_get::<String, _>("id").map_err(db)?)?,
                kind: IdentityKind::parse(&kind).ok_or_else(|| SpectreError::storage("invalid identity kind"))?,
                label: row.try_get("label").map_err(db)?,
                value: row.try_get("value").map_err(db)?,
                platform: row.try_get("platform").map_err(db)?,
                finding_id: finding.as_deref().map(parse_uuid).transpose()?,
                is_target: row.try_get("is_target").map_err(db)?,
                verified: row.try_get("verified").map_err(db)?,
            });
        }
        let edge_rows = sqlx::query("SELECT * FROM identity_relationships WHERE investigation_id = ? ORDER BY confidence DESC")
            .bind(&identifier)
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        let mut edges = Vec::with_capacity(edge_rows.len());
        for row in edge_rows {
            let relationship: String = row.try_get("relationship").map_err(db)?;
            let category: String = row.try_get("category").map_err(db)?;
            let decision: Option<String> = row.try_get("investigator_decision").map_err(db)?;
            edges.push(IdentityRelationship {
                id: parse_uuid(&row.try_get::<String, _>("id").map_err(db)?)?,
                source_identity: parse_uuid(&row.try_get::<String, _>("source_identity").map_err(db)?)?,
                target_identity: parse_uuid(&row.try_get::<String, _>("target_identity").map_err(db)?)?,
                relationship: RelationshipKind::parse(&relationship).ok_or_else(|| SpectreError::storage("invalid relationship"))?,
                confidence: row.try_get("confidence").map_err(db)?,
                category: ConfidenceCategory::parse(&category).ok_or_else(|| SpectreError::storage("invalid category"))?,
                evidence: serde_json::from_str(&row.try_get::<String, _>("evidence_json").map_err(db)?).map_err(json_error)?,
                verified: row.try_get("verified").map_err(db)?,
                investigator_decision: decision.as_deref().and_then(InvestigatorDecision::parse),
            });
        }
        Ok(IdentityGraph { nodes, edges })
    }

    /// Record an investigator decision; returns the relationship's investigation.
    pub async fn set_relationship_decision(&self, relationship_id: Uuid, decision: Option<InvestigatorDecision>) -> SpectreResult<Uuid> {
        let row = sqlx::query(
            "UPDATE identity_relationships SET investigator_decision = ?, decided_at = ? WHERE id = ? RETURNING investigation_id",
        )
        .bind(decision.map(InvestigatorDecision::as_str))
        .bind(decision.map(|_| timestamp(Utc::now())))
        .bind(relationship_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?
        .ok_or_else(|| SpectreError::not_found(format!("relationship {relationship_id} not found")))?;
        parse_uuid(&row.try_get::<String, _>("investigation_id").map_err(db)?)
    }

    pub async fn detail(&self, investigation_id: Uuid) -> SpectreResult<InvestigationDetail> {
        Ok(InvestigationDetail {
            investigation: self.get_investigation(investigation_id).await?,
            findings: self.findings_for(investigation_id).await?,
            graph: self.graph_for(investigation_id).await?,
        })
    }

    // -----------------------------------------------------------------------
    // Ownership verification
    // -----------------------------------------------------------------------

    fn email_from_row(row: &SqliteRow) -> SpectreResult<EmailRecord> {
        let status: String = row.try_get("verification_status").map_err(db)?;
        let method: Option<String> = row.try_get("verification_method").map_err(db)?;
        Ok(EmailRecord {
            email: row.try_get("email").map_err(db)?,
            verification_status: VerificationStatus::parse(&status).ok_or_else(|| SpectreError::storage("invalid verification status"))?,
            verification_method: method.as_deref().and_then(VerificationMethod::parse),
            attestation: row.try_get("attestation").map_err(db)?,
            verified_at: parse_optional_time(row.try_get("verified_at").map_err(db)?)?,
            last_breach_check_at: parse_optional_time(row.try_get("last_breach_check_at").map_err(db)?)?,
            created_at: parse_time(&row.try_get::<String, _>("created_at").map_err(db)?)?,
        })
    }

    pub async fn ensure_email(&self, email: &str) -> SpectreResult<EmailRecord> {
        let now = timestamp(Utc::now());
        sqlx::query("INSERT INTO email_addresses (id, email, verification_status, created_at, updated_at) VALUES (?, ?, 'unverified', ?, ?) ON CONFLICT (email) DO NOTHING")
            .bind(Uuid::new_v4().to_string())
            .bind(email)
            .bind(&now)
            .bind(&now)
            .execute(&self.pool)
            .await
            .map_err(db)?;
        self.email_record(email).await
    }

    pub async fn email_record(&self, email: &str) -> SpectreResult<EmailRecord> {
        let row = sqlx::query("SELECT * FROM email_addresses WHERE email = ?")
            .bind(email)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .ok_or_else(|| SpectreError::not_found(format!("{email} is not known")))?;
        Self::email_from_row(&row)
    }

    pub async fn list_emails(&self) -> SpectreResult<Vec<EmailRecord>> {
        sqlx::query("SELECT * FROM email_addresses ORDER BY (verification_status = 'ownership_verified') DESC, email")
            .fetch_all(&self.pool)
            .await
            .map_err(db)?
            .iter()
            .map(Self::email_from_row)
            .collect()
    }

    pub async fn set_email_verification(
        &self,
        email: &str,
        status: VerificationStatus,
        method: Option<VerificationMethod>,
        attestation: Option<&str>,
    ) -> SpectreResult<EmailRecord> {
        self.ensure_email(email).await?;
        let now = Utc::now();
        let verified_at = (status == VerificationStatus::OwnershipVerified).then(|| timestamp(now));
        sqlx::query("UPDATE email_addresses SET verification_status = ?, verification_method = ?, attestation = ?, verified_at = ?, updated_at = ? WHERE email = ?")
            .bind(status.as_str())
            .bind(method.map(VerificationMethod::as_str))
            .bind(attestation)
            .bind(verified_at)
            .bind(timestamp(now))
            .bind(email)
            .execute(&self.pool)
            .await
            .map_err(db)?;
        self.email_record(email).await
    }

    fn domain_from_row(row: &SqliteRow) -> SpectreResult<DomainRecord> {
        let status: String = row.try_get("verification_status").map_err(db)?;
        let method: Option<String> = row.try_get("verification_method").map_err(db)?;
        Ok(DomainRecord {
            domain: row.try_get("domain").map_err(db)?,
            verification_status: VerificationStatus::parse(&status).ok_or_else(|| SpectreError::storage("invalid verification status"))?,
            verification_method: method.as_deref().and_then(VerificationMethod::parse),
            challenge_value: row.try_get("challenge_value").map_err(db)?,
            challenge_record_name: row.try_get("challenge_record_name").map_err(db)?,
            verified_at: parse_optional_time(row.try_get("verified_at").map_err(db)?)?,
            created_at: parse_time(&row.try_get::<String, _>("created_at").map_err(db)?)?,
        })
    }

    pub async fn domain_record(&self, domain: &str) -> SpectreResult<DomainRecord> {
        let row = sqlx::query("SELECT * FROM domains WHERE domain = ?")
            .bind(domain)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .ok_or_else(|| SpectreError::not_found(format!("{domain} is not known")))?;
        Self::domain_from_row(&row)
    }

    pub async fn list_domains(&self) -> SpectreResult<Vec<DomainRecord>> {
        sqlx::query("SELECT * FROM domains ORDER BY domain")
            .fetch_all(&self.pool)
            .await
            .map_err(db)?
            .iter()
            .map(Self::domain_from_row)
            .collect()
    }

    pub async fn set_domain_challenge(&self, domain: &str, record_name: &str, value: &str) -> SpectreResult<DomainRecord> {
        let now = timestamp(Utc::now());
        sqlx::query(
            "INSERT INTO domains (id, domain, verification_status, challenge_value, challenge_record_name, created_at, updated_at)
             VALUES (?, ?, 'ownership_pending', ?, ?, ?, ?)
             ON CONFLICT (domain) DO UPDATE SET verification_status = 'ownership_pending', verification_method = NULL, verified_at = NULL,
                 challenge_value = excluded.challenge_value, challenge_record_name = excluded.challenge_record_name, updated_at = excluded.updated_at",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(domain)
        .bind(value)
        .bind(record_name)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        self.domain_record(domain).await
    }

    pub async fn mark_domain_verified(&self, domain: &str) -> SpectreResult<DomainRecord> {
        let now = timestamp(Utc::now());
        let mut transaction = self.pool.begin().await.map_err(db)?;
        sqlx::query("UPDATE domains SET verification_status = 'ownership_verified', verification_method = 'dns_txt_challenge', verified_at = ?, updated_at = ? WHERE domain = ?")
            .bind(&now)
            .bind(&now)
            .bind(domain)
            .execute(&mut *transaction)
            .await
            .map_err(db)?;
        // Addresses on a verified domain inherit verification.
        sqlx::query(
            "UPDATE email_addresses SET verification_status = 'ownership_verified', verification_method = 'verified_domain', verified_at = ?, updated_at = ?
             WHERE substr(email, instr(email, '@') + 1) = ? AND verification_status != 'ownership_verified'",
        )
        .bind(&now)
        .bind(&now)
        .bind(domain)
        .execute(&mut *transaction)
        .await
        .map_err(db)?;
        transaction.commit().await.map_err(db)?;
        self.domain_record(domain).await
    }

    pub async fn verified_emails(&self) -> SpectreResult<Vec<String>> {
        sqlx::query_scalar("SELECT email FROM email_addresses WHERE verification_status = 'ownership_verified'")
            .fetch_all(&self.pool)
            .await
            .map_err(db)
    }

    pub async fn verified_domains(&self) -> SpectreResult<Vec<String>> {
        sqlx::query_scalar("SELECT domain FROM domains WHERE verification_status = 'ownership_verified'")
            .fetch_all(&self.pool)
            .await
            .map_err(db)
    }

    // -----------------------------------------------------------------------
    // Breach data
    // -----------------------------------------------------------------------

    pub async fn upsert_incidents(&self, incidents: &[BreachIncident]) -> SpectreResult<()> {
        let now = timestamp(Utc::now());
        let mut transaction = self.pool.begin().await.map_err(db)?;
        for incident in incidents {
            sqlx::query(
                "INSERT INTO breach_incidents (name, title, domain, breach_date, pwn_count, incident_json, fetched_at) VALUES (?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT (name) DO UPDATE SET title = excluded.title, domain = excluded.domain, breach_date = excluded.breach_date,
                     pwn_count = excluded.pwn_count, incident_json = excluded.incident_json, fetched_at = excluded.fetched_at",
            )
            .bind(&incident.name)
            .bind(&incident.title)
            .bind(&incident.domain)
            .bind(&incident.breach_date)
            .bind(incident.pwn_count as i64)
            .bind(serde_json::to_string(incident).map_err(json_error)?)
            .bind(&now)
            .execute(&mut *transaction)
            .await
            .map_err(db)?;
        }
        transaction.commit().await.map_err(db)
    }

    pub async fn catalog_size(&self) -> SpectreResult<u64> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM breach_incidents").fetch_one(&self.pool).await.map_err(db)?;
        Ok(count as u64)
    }

    pub async fn search_incidents(&self, search: Option<&str>, limit: u32) -> SpectreResult<Vec<BreachIncident>> {
        let pattern = search.map(|text| format!("%{}%", text.trim().to_lowercase()));
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT incident_json FROM breach_incidents WHERE (?1 IS NULL OR lower(title) LIKE ?1 OR lower(domain) LIKE ?1)
             ORDER BY breach_date DESC LIMIT ?2",
        )
        .bind(pattern)
        .bind(i64::from(limit.clamp(1, 2000)))
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter().map(|raw| serde_json::from_str(raw).map_err(json_error)).collect()
    }

    /// Replace the recorded exposures of a verified address.
    pub async fn record_exposures(&self, email: &str, breach_names: &[String]) -> SpectreResult<()> {
        let record_id: String =
            sqlx::query_scalar("SELECT id FROM email_addresses WHERE email = ?").bind(email).fetch_one(&self.pool).await.map_err(db)?;
        let now = timestamp(Utc::now());
        let mut transaction = self.pool.begin().await.map_err(db)?;
        sqlx::query("DELETE FROM breach_exposures WHERE email_id = ?").bind(&record_id).execute(&mut *transaction).await.map_err(db)?;
        for name in breach_names {
            sqlx::query("INSERT INTO breach_exposures (id, email_id, breach_name, checked_at) VALUES (?, ?, ?, ?)")
                .bind(Uuid::new_v4().to_string())
                .bind(&record_id)
                .bind(name)
                .bind(&now)
                .execute(&mut *transaction)
                .await
                .map_err(db)?;
        }
        sqlx::query("UPDATE email_addresses SET last_breach_check_at = ?, updated_at = ? WHERE id = ?")
            .bind(&now)
            .bind(&now)
            .bind(&record_id)
            .execute(&mut *transaction)
            .await
            .map_err(db)?;
        transaction.commit().await.map_err(db)
    }

    pub async fn exposures_for(&self, email: &str) -> SpectreResult<Vec<BreachIncident>> {
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT b.incident_json FROM breach_exposures x JOIN email_addresses e ON e.id = x.email_id JOIN breach_incidents b ON b.name = x.breach_name
             WHERE e.email = ? ORDER BY b.breach_date DESC",
        )
        .bind(email)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter().map(|raw| serde_json::from_str(raw).map_err(json_error)).collect()
    }

    // -----------------------------------------------------------------------
    // Settings & provider configuration
    // -----------------------------------------------------------------------

    pub async fn settings(&self) -> SpectreResult<EngineSettings> {
        let raw: Option<String> =
            sqlx::query_scalar("SELECT settings_json FROM engine_settings WHERE id = 1").fetch_optional(&self.pool).await.map_err(db)?;
        match raw {
            Some(raw) => serde_json::from_str(&raw).map_err(json_error),
            None => Ok(EngineSettings::default()),
        }
    }

    pub async fn save_settings(&self, settings: &EngineSettings) -> SpectreResult<()> {
        settings.validate()?;
        sqlx::query(
            "INSERT INTO engine_settings (id, settings_json, updated_at) VALUES (1, ?, ?)
             ON CONFLICT (id) DO UPDATE SET settings_json = excluded.settings_json, updated_at = excluded.updated_at",
        )
        .bind(serde_json::to_string(settings).map_err(json_error)?)
        .bind(timestamp(Utc::now()))
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    pub async fn provider_configs(&self) -> SpectreResult<Vec<ProviderConfig>> {
        let rows = sqlx::query("SELECT provider_id, enabled, rate_limit_per_minute FROM provider_configs")
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        rows.iter()
            .map(|row| {
                let limit: Option<i64> = row.try_get("rate_limit_per_minute").map_err(db)?;
                Ok(ProviderConfig {
                    provider_id: row.try_get("provider_id").map_err(db)?,
                    enabled: row.try_get("enabled").map_err(db)?,
                    rate_limit_per_minute: limit.map(|value| value as u32),
                })
            })
            .collect()
    }

    pub async fn save_provider_config(&self, config: &ProviderConfig) -> SpectreResult<()> {
        config.validate()?;
        sqlx::query(
            "INSERT INTO provider_configs (provider_id, enabled, rate_limit_per_minute, updated_at) VALUES (?, ?, ?, ?)
             ON CONFLICT (provider_id) DO UPDATE SET enabled = excluded.enabled, rate_limit_per_minute = excluded.rate_limit_per_minute, updated_at = excluded.updated_at",
        )
        .bind(&config.provider_id)
        .bind(config.enabled)
        .bind(config.rate_limit_per_minute.map(i64::from))
        .bind(timestamp(Utc::now()))
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Audit log
    // -----------------------------------------------------------------------

    pub async fn record_audit(&self, investigation_id: Option<Uuid>, event_type: &str, detail: serde_json::Value) -> SpectreResult<()> {
        sqlx::query("INSERT INTO audit_events (id, investigation_id, event_type, detail_json, created_at) VALUES (?, ?, ?, ?, ?)")
            .bind(Uuid::new_v4().to_string())
            .bind(investigation_id.map(|id| id.to_string()))
            .bind(event_type)
            .bind(detail.to_string())
            .bind(timestamp(Utc::now()))
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(())
    }

    pub async fn audit_events(&self, limit: u32) -> SpectreResult<Vec<AuditEvent>> {
        let rows = sqlx::query("SELECT * FROM audit_events ORDER BY created_at DESC, rowid DESC LIMIT ?")
            .bind(i64::from(limit.clamp(1, 5000)))
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        rows.iter()
            .map(|row| {
                let investigation: Option<String> = row.try_get("investigation_id").map_err(db)?;
                Ok(AuditEvent {
                    id: parse_uuid(&row.try_get::<String, _>("id").map_err(db)?)?,
                    investigation_id: investigation.as_deref().map(parse_uuid).transpose()?,
                    event_type: row.try_get("event_type").map_err(db)?,
                    detail: serde_json::from_str(&row.try_get::<String, _>("detail_json").map_err(db)?).map_err(json_error)?,
                    created_at: parse_time(&row.try_get::<String, _>("created_at").map_err(db)?)?,
                })
            })
            .collect()
    }

    // -----------------------------------------------------------------------
    // Dashboard
    // -----------------------------------------------------------------------

    async fn count(&self, sql: &str) -> SpectreResult<u64> {
        let value: i64 = sqlx::query_scalar(sql).fetch_one(&self.pool).await.map_err(db)?;
        Ok(value as u64)
    }

    async fn counts(&self, sql: &str) -> SpectreResult<Vec<CountByLabel>> {
        let rows = sqlx::query(sql).fetch_all(&self.pool).await.map_err(db)?;
        rows.iter()
            .map(|row| {
                let label: Option<String> = row.try_get(0).map_err(db)?;
                let count: i64 = row.try_get(1).map_err(db)?;
                Ok(CountByLabel { label: label.unwrap_or_else(|| "unknown".into()), count: count as u64 })
            })
            .collect()
    }

    pub async fn dashboard(&self) -> SpectreResult<DashboardStats> {
        Ok(DashboardStats {
            investigations: self.count("SELECT COUNT(*) FROM investigations").await?,
            running: self.count("SELECT COUNT(*) FROM investigations WHERE status IN ('running', 'pending')").await?,
            findings: self.count("SELECT COUNT(*) FROM findings").await?,
            profiles: self.count("SELECT COUNT(*) FROM profiles").await?,
            confirmed_relationships: self.count("SELECT COUNT(*) FROM identity_relationships WHERE category = 'confirmed'").await?,
            strong_relationships: self.count("SELECT COUNT(*) FROM identity_relationships WHERE category = 'strong_evidence'").await?,
            verified_emails: self.count("SELECT COUNT(*) FROM email_addresses WHERE verification_status = 'ownership_verified'").await?,
            breach_exposures: self.count("SELECT COUNT(*) FROM breach_exposures").await?,
            findings_by_provider: self.counts("SELECT provider_id, COUNT(*) FROM findings GROUP BY provider_id ORDER BY 2 DESC LIMIT 12").await?,
            findings_by_category: self.counts("SELECT category, COUNT(*) FROM findings GROUP BY category ORDER BY 2 DESC").await?,
            investigations_by_day: self
                .counts("SELECT substr(created_at, 1, 10), COUNT(*) FROM investigations WHERE created_at >= date('now', '-30 days') GROUP BY 1 ORDER BY 1")
                .await?,
            exposures_by_year: self
                .counts(
                    "SELECT substr(b.breach_date, 1, 4), COUNT(*) FROM breach_exposures x JOIN breach_incidents b ON b.name = x.breach_name
                     WHERE b.breach_date IS NOT NULL GROUP BY 1 ORDER BY 1",
                )
                .await?,
        })
    }

    // -----------------------------------------------------------------------
    // Maintenance, export, import
    // -----------------------------------------------------------------------

    pub async fn info(&self) -> SpectreResult<StorageInfo> {
        let page_count: i64 = sqlx::query_scalar("PRAGMA page_count").fetch_one(&self.pool).await.map_err(db)?;
        let page_size: i64 = sqlx::query_scalar("PRAGMA page_size").fetch_one(&self.pool).await.map_err(db)?;
        let freelist: i64 = sqlx::query_scalar("PRAGMA freelist_count").fetch_one(&self.pool).await.map_err(db)?;
        Ok(StorageInfo {
            path: self.path.as_ref().map(|path| path.display().to_string()),
            schema_version: self.schema_version().await?,
            size_bytes: (page_count * page_size) as u64,
            page_count,
            freelist_pages: freelist,
        })
    }

    pub async fn integrity_check(&self) -> SpectreResult<Vec<String>> {
        sqlx::query_scalar("PRAGMA integrity_check").fetch_all(&self.pool).await.map_err(db)
    }

    /// Rebuild the database file, reclaiming space freed by deletions.
    pub async fn vacuum(&self) -> SpectreResult<()> {
        sqlx::query("VACUUM").execute(&self.pool).await.map_err(db)?;
        Ok(())
    }

    /// Write a consistent snapshot to `destination` (must not exist).
    pub async fn backup_to(&self, destination: &Path) -> SpectreResult<()> {
        if destination.exists() {
            return Err(SpectreError::invalid_input("backup destination already exists"));
        }
        sqlx::query("VACUUM INTO ?").bind(destination.display().to_string()).execute(&self.pool).await.map_err(db)?;
        restrict_permissions(destination);
        Ok(())
    }

    /// Validate a backup file: it must open, pass integrity checks, and carry
    /// a known schema version.
    pub async fn validate_backup(source: &Path) -> SpectreResult<i64> {
        let options = SqliteConnectOptions::new().filename(source).read_only(true);
        let pool = SqlitePoolOptions::new().max_connections(1).connect_with(options).await.map_err(db)?;
        let integrity: String = sqlx::query_scalar("PRAGMA integrity_check").fetch_one(&pool).await.map_err(db)?;
        let version: Option<i64> = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations WHERE success = 1")
            .fetch_one(&pool)
            .await
            .map_err(|_| SpectreError::invalid_input("file is not a Spectre database"))?;
        pool.close().await;
        if integrity != "ok" {
            return Err(SpectreError::invalid_input(format!("backup failed integrity check: {integrity}")));
        }
        match version {
            Some(version) if version <= SCHEMA_VERSION => Ok(version),
            Some(version) => Err(SpectreError::invalid_input(format!("backup schema {version} is newer than this version of Spectre"))),
            None => Err(SpectreError::invalid_input("file is not a Spectre database")),
        }
    }

    pub async fn export_bundle(&self, investigation_id: Uuid) -> SpectreResult<InvestigationBundle> {
        Ok(InvestigationBundle {
            format: BUNDLE_FORMAT.into(),
            format_version: 1,
            exported_at: Utc::now(),
            detail: self.detail(investigation_id).await?,
        })
    }

    pub async fn import_bundle(&self, bundle: &InvestigationBundle) -> SpectreResult<Uuid> {
        if bundle.format != BUNDLE_FORMAT || bundle.format_version != 1 {
            return Err(SpectreError::invalid_input("unsupported bundle format"));
        }
        let investigation = &bundle.detail.investigation;
        // Re-validate the target: bundles are untrusted input.
        let target = InvestigationTarget::parse(investigation.target_type, investigation.target.value())?;
        if self.get_investigation(investigation.id).await.is_ok() {
            return Err(SpectreError::invalid_input("an investigation with this identifier already exists"));
        }
        let mut imported = investigation.clone();
        imported.target = target;
        if !imported.status.is_terminal() {
            imported.status = InvestigationStatus::Failed;
        }
        self.create_investigation(&imported).await?;
        sqlx::query("UPDATE investigations SET status = ?, progress = ?, metrics_json = ?, started_at = ?, completed_at = ? WHERE id = ?")
            .bind(imported.status.as_str())
            .bind(imported.progress)
            .bind(imported.metrics.as_ref().map(serde_json::to_string).transpose().map_err(json_error)?)
            .bind(imported.started_at.map(timestamp))
            .bind(imported.completed_at.map(timestamp))
            .bind(imported.id.to_string())
            .execute(&self.pool)
            .await
            .map_err(db)?;
        for failure in &imported.errors {
            self.record_error(imported.id, failure).await?;
        }
        for finding in &bundle.detail.findings {
            if finding.investigation_id != imported.id {
                return Err(SpectreError::invalid_input("finding belongs to a different investigation"));
            }
            self.insert_finding(finding).await?;
        }
        self.replace_graph(imported.id, &bundle.detail.graph).await?;
        Ok(imported.id)
    }
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(error) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        tracing::warn!(%error, "could not restrict database file permissions");
    }
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) {}

#[cfg(test)]
mod tests;
