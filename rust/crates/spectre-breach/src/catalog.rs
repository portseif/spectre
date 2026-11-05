//! Domain-target provider: public breaches of the investigated service.

use async_trait::async_trait;
use spectre_core::error::SpectreResult;
use spectre_core::model::{BreachFinding, Confidence, ConfidenceCategory, DiscoveryMethod, FindingData, VerificationStatus};
use spectre_core::provider::{FindingDraft, OsintProvider, ProviderCapability, ProviderContext};
use spectre_core::target::{InvestigationTarget, TargetType};

use crate::{BreachProvider, HibpClient};

#[derive(Default)]
pub struct HibpCatalogProvider {
    client: HibpClient,
}

impl HibpCatalogProvider {
    pub fn with_client(client: HibpClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl OsintProvider for HibpCatalogProvider {
    fn id(&self) -> &str {
        "hibp-catalog"
    }

    fn name(&self) -> &str {
        "Breach Catalog (HIBP)"
    }

    fn description(&self) -> &str {
        "Public breach metadata for the investigated domain's service from Have I Been Pwned. Contains no personal data."
    }

    fn homepage(&self) -> &str {
        "https://haveibeenpwned.com/PwnedWebsites"
    }

    fn supported_targets(&self) -> Vec<TargetType> {
        vec![TargetType::Domain]
    }

    fn capabilities(&self) -> Vec<ProviderCapability> {
        vec![ProviderCapability::BreachMetadata]
    }

    fn allowed_hosts(&self) -> Vec<String> {
        self.client.allowed_hosts()
    }

    fn default_rate_limit_per_minute(&self) -> u32 {
        10
    }

    async fn discover(&self, context: &ProviderContext, target: &InvestigationTarget) -> SpectreResult<Vec<FindingDraft>> {
        let InvestigationTarget::Domain(domain) = target else { return Ok(Vec::new()) };
        let breaches = self.client.catalog(context, Some(domain)).await?;
        Ok(breaches
            .into_iter()
            .map(|incident| FindingDraft {
                title: format!("{} breach", incident.title),
                summary: Some(format!(
                    "{} · {} accounts · {}",
                    incident.breach_date.clone().unwrap_or_else(|| "date unknown".into()),
                    incident.pwn_count,
                    incident.data_classes.join(", ")
                )),
                confidence: Confidence::new(
                    1.0,
                    ConfidenceCategory::Confirmed,
                    [if incident.is_verified {
                        "Breach verified by Have I Been Pwned"
                    } else {
                        "Breach listed by Have I Been Pwned (unverified)"
                    }],
                ),
                verification_status: VerificationStatus::PubliclyObserved,
                sources: vec![
                    context.source(Some(format!("https://haveibeenpwned.com/Breach/{}", incident.name)), DiscoveryMethod::BreachApi),
                ],
                data: FindingData::BreachIncident(BreachFinding { exposed_account: None, incident }),
            })
            .collect())
    }
}
