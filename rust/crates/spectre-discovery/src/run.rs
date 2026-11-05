//! Investigation execution: bounded-concurrency provider fan-out with
//! incremental persistence and streaming.

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use futures::StreamExt;
use spectre_core::error::{ErrorCode, SpectreError, SpectreResult};
use spectre_core::http::RequestStats;
use spectre_core::model::*;
use spectre_core::provider::{FindingDraft, OsintProvider};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{Engine, not_cancelled};

struct ProviderRun {
    provider_id: String,
    result: SpectreResult<Vec<FindingDraft>>,
    latency: Duration,
}

impl Engine {
    pub(crate) async fn run_investigation(
        self: Arc<Self>,
        investigation: Investigation,
        providers: Vec<Arc<dyn OsintProvider>>,
        cancellation: CancellationToken,
        requested_at: Instant,
    ) {
        let investigation_id = investigation.id;
        let outcome = self.execute(&investigation, providers, &cancellation, requested_at).await;
        let (status, metrics) = match outcome {
            Ok(result) => result,
            Err(error) => {
                tracing::error!(%investigation_id, code = ?error.code, "investigation failed: {}", error.message);
                let failure =
                    ProviderFailure { provider_id: "engine".into(), code: error.code, message: error.message, occurred_at: Utc::now() };
                let storage = self.storage();
                let _ = storage.record_error(investigation_id, &failure).await;
                self.events.push(investigation_id, InvestigationEventKind::ProviderFailed { failure });
                let metrics = InvestigationMetrics { total_duration_ms: requested_at.elapsed().as_millis() as u64, ..Default::default() };
                (InvestigationStatus::Failed, metrics)
            }
        };
        let storage = self.storage();
        if let Err(error) = storage.finish_investigation(investigation_id, status, &metrics, Utc::now()).await {
            tracing::error!(%investigation_id, "could not record investigation completion: {}", error.message);
        }
        let _ = storage
            .record_audit(
                Some(investigation_id),
                "investigation_finished",
                serde_json::json!({ "status": status, "duration_ms": metrics.total_duration_ms }),
            )
            .await;
        self.active.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(&investigation_id);
        self.events.push(investigation_id, InvestigationEventKind::Finished { status, metrics });
    }

    async fn execute(
        &self,
        investigation: &Investigation,
        providers: Vec<Arc<dyn OsintProvider>>,
        cancellation: &CancellationToken,
        requested_at: Instant,
    ) -> SpectreResult<(InvestigationStatus, InvestigationMetrics)> {
        let investigation_id = investigation.id;
        let storage = self.storage();
        storage.mark_started(investigation_id, Utc::now()).await?;
        self.events.push(investigation_id, InvestigationEventKind::Started { providers: investigation.providers.clone() });

        let stats = Arc::new(RequestStats::default());
        let semaphore = self.semaphore();
        let provider_timeout = Duration::from_secs(u64::from(self.settings().provider_timeout_secs));
        let total = providers.len();
        let first_dispatch = Arc::new(std::sync::OnceLock::<Duration>::new());

        let mut runs = futures::stream::FuturesUnordered::new();
        for provider in providers {
            let semaphore = Arc::clone(&semaphore);
            let cancellation = cancellation.clone();
            let stats = Arc::clone(&stats);
            let first_dispatch = Arc::clone(&first_dispatch);
            let target = investigation.target.clone();
            runs.push(async move {
                let provider_id = provider.id().to_string();
                let permit = tokio::select! {
                    _ = cancellation.cancelled() => None,
                    permit = semaphore.acquire_owned() => permit.ok(),
                };
                let Some(_permit) = permit else {
                    return ProviderRun { provider_id, result: Err(SpectreError::cancelled()), latency: Duration::ZERO };
                };
                let _ = first_dispatch.set(requested_at.elapsed());
                self.events.push(investigation_id, InvestigationEventKind::ProviderStarted { provider_id: provider_id.clone() });
                let context = self.context(provider.id(), provider.name(), cancellation.clone(), stats);
                let started = Instant::now();
                let result = tokio::select! {
                    _ = cancellation.cancelled() => Err(SpectreError::cancelled()),
                    result = tokio::time::timeout(provider_timeout, provider.discover(&context, &target)) => result.unwrap_or_else(|_| {
                        Err(SpectreError::new(ErrorCode::Timeout, format!("{} did not finish within {}s", provider.name(), provider_timeout.as_secs())))
                    }),
                };
                ProviderRun { provider_id, result, latency: started.elapsed() }
            });
        }

        let mut completed = 0usize;
        let mut failures = 0usize;
        let mut cancelled_runs = 0usize;
        let mut time_to_first_finding = None;
        let mut latencies = Vec::with_capacity(total);

        while let Some(run) = runs.next().await {
            completed += 1;
            let latency_ms = run.latency.as_millis() as u64;
            match run.result {
                Ok(drafts) => {
                    let count = drafts.len() as u32;
                    for draft in drafts {
                        let finding = Finding {
                            id: Uuid::new_v4(),
                            investigation_id,
                            provider_id: run.provider_id.clone(),
                            title: draft.title,
                            summary: draft.summary,
                            confidence: draft.confidence,
                            verification_status: draft.verification_status,
                            discovered_at: Utc::now(),
                            sources: draft.sources,
                            data: draft.data,
                        };
                        storage.insert_finding(&finding).await?;
                        time_to_first_finding.get_or_insert_with(|| requested_at.elapsed().as_millis() as u64);
                        self.events.push(investigation_id, InvestigationEventKind::FindingDiscovered { finding: Box::new(finding) });
                    }
                    latencies.push(ProviderLatency {
                        provider_id: run.provider_id.clone(),
                        latency_ms,
                        outcome: if count == 0 { ProviderOutcome::NoResults } else { ProviderOutcome::Succeeded },
                        findings: count,
                    });
                    self.events.push(
                        investigation_id,
                        InvestigationEventKind::ProviderCompleted { provider_id: run.provider_id, findings: count, latency_ms },
                    );
                }
                Err(error) => {
                    let outcome = if not_cancelled(&error) {
                        failures += 1;
                        let failure = ProviderFailure {
                            provider_id: run.provider_id.clone(),
                            code: error.code,
                            message: error.message,
                            occurred_at: Utc::now(),
                        };
                        storage.record_error(investigation_id, &failure).await?;
                        self.events.push(investigation_id, InvestigationEventKind::ProviderFailed { failure });
                        ProviderOutcome::Failed
                    } else {
                        cancelled_runs += 1;
                        ProviderOutcome::Cancelled
                    };
                    latencies.push(ProviderLatency { provider_id: run.provider_id, latency_ms, outcome, findings: 0 });
                }
            }
            let progress = completed as f64 / total.max(1) as f64;
            storage.update_progress(investigation_id, progress).await?;
            self.events.push(investigation_id, InvestigationEventKind::Progress { progress });
        }

        let status = if cancellation.is_cancelled() {
            InvestigationStatus::Cancelled
        } else if failures == 0 {
            InvestigationStatus::Completed
        } else if failures + cancelled_runs >= total {
            InvestigationStatus::Failed
        } else {
            InvestigationStatus::PartiallyCompleted
        };

        // Correlate whatever was found, including partial and cancelled runs.
        let graph = self.correlate(investigation_id).await?;
        self.events.push(
            investigation_id,
            InvestigationEventKind::CorrelationUpdated { identities: graph.nodes.len() as u32, relationships: graph.edges.len() as u32 },
        );

        let snapshot = stats.snapshot();
        let metrics = InvestigationMetrics {
            startup_latency_ms: first_dispatch.get().map(|duration| duration.as_millis() as u64).unwrap_or_default(),
            time_to_first_finding_ms: time_to_first_finding,
            total_duration_ms: requested_at.elapsed().as_millis() as u64,
            provider_latencies: latencies,
            http_requests: snapshot.requests,
            cache_hits: snapshot.cache_hits,
            cache_misses: snapshot.cache_misses,
        };
        Ok((status, metrics))
    }
}
