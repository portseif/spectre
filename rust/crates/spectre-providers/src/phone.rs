//! Phone number intelligence from offline numbering-plan metadata.
//!
//! Uses libphonenumber's public metadata (via the `phonenumber` crate) only:
//! E.164 normalization, country calling code, region, and number type. It
//! never performs reverse lookups, carrier queries, or location inference.

use async_trait::async_trait;
use spectre_core::error::SpectreResult;
use spectre_core::model::{DiscoveryMethod, FindingData, VerificationStatus};
use spectre_core::provider::{FindingDraft, OsintProvider, ProviderCapability, ProviderContext};
use spectre_core::target::{InvestigationTarget, TargetType, normalize_phone};

use crate::common::observed_fact;
use crate::provider_metadata;

pub struct PhoneNumberingProvider;

#[async_trait]
impl OsintProvider for PhoneNumberingProvider {
    provider_metadata! {
        id: "phone-numbering",
        name: "Numbering Plan Metadata",
        description: "Offline E.164 normalization, country code, region, and line type from libphonenumber metadata.",
        homepage: "https://github.com/google/libphonenumber",
        targets: [TargetType::Phone],
        capabilities: [ProviderCapability::PhoneMetadata],
    }

    fn allowed_hosts(&self) -> Vec<String> {
        Vec::new()
    }

    fn uses_network(&self) -> bool {
        false
    }

    async fn discover(&self, context: &ProviderContext, target: &InvestigationTarget) -> SpectreResult<Vec<FindingDraft>> {
        let InvestigationTarget::Phone(e164) = target else { return Ok(Vec::new()) };
        let info = normalize_phone(e164, None)?;
        let region = info.region_code.clone().unwrap_or_else(|| "non-geographic".to_string());
        Ok(vec![FindingDraft {
            title: format!("Numbering plan: +{} ({region})", info.country_calling_code),
            summary: Some(format!("{} · {}", info.international_format, info.number_type)),
            confidence: observed_fact(
                "Derived offline from public numbering-plan metadata; says nothing about the subscriber's identity or location",
            ),
            verification_status: VerificationStatus::Unverified,
            sources: vec![context.source(None, DiscoveryMethod::OfflineMetadata)],
            data: FindingData::PhoneMetadata(info),
        }])
    }
}
