//! Engine configuration with conservative defaults and validation.

use serde::{Deserialize, Serialize};

use crate::error::{SpectreError, SpectreResult};

/// Tunable engine settings, persisted by the storage layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EngineSettings {
    /// Global cap on concurrently running provider lookups (all investigations).
    pub max_concurrency: u32,
    /// Timeout for a single HTTP request.
    pub request_timeout_secs: u32,
    /// Overall deadline for one provider within an investigation.
    pub provider_timeout_secs: u32,
    /// In-memory response cache lifetime. 0 disables caching.
    pub cache_ttl_secs: u32,
    /// Retries for transient failures (timeouts, 429, 5xx).
    pub max_retries: u32,
    /// Base delay for exponential backoff with jitter.
    pub retry_base_delay_ms: u32,
    /// Default per-provider request budget.
    pub default_rate_limit_per_minute: u32,
    /// Investigations older than this are purged at startup. 0 keeps forever.
    pub retention_days: u32,
}

impl Default for EngineSettings {
    fn default() -> Self {
        Self {
            max_concurrency: 4,
            request_timeout_secs: 15,
            provider_timeout_secs: 45,
            cache_ttl_secs: 900,
            max_retries: 2,
            retry_base_delay_ms: 400,
            default_rate_limit_per_minute: 30,
            retention_days: 0,
        }
    }
}

impl EngineSettings {
    pub fn validate(&self) -> SpectreResult<()> {
        fn check(name: &str, value: u32, min: u32, max: u32) -> SpectreResult<()> {
            if (min..=max).contains(&value) {
                Ok(())
            } else {
                Err(SpectreError::invalid_input(format!("{name} must be between {min} and {max} (got {value})")))
            }
        }
        check("max_concurrency", self.max_concurrency, 1, 32)?;
        check("request_timeout_secs", self.request_timeout_secs, 2, 120)?;
        check("provider_timeout_secs", self.provider_timeout_secs, 5, 600)?;
        check("cache_ttl_secs", self.cache_ttl_secs, 0, 86_400)?;
        check("max_retries", self.max_retries, 0, 5)?;
        check("retry_base_delay_ms", self.retry_base_delay_ms, 50, 10_000)?;
        check("default_rate_limit_per_minute", self.default_rate_limit_per_minute, 1, 600)?;
        check("retention_days", self.retention_days, 0, 3_650)?;
        if self.provider_timeout_secs < self.request_timeout_secs {
            return Err(SpectreError::invalid_input("provider_timeout_secs must be at least request_timeout_secs"));
        }
        Ok(())
    }
}

/// Per-provider overrides stored in `provider_configs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub provider_id: String,
    pub enabled: bool,
    /// Overrides [`EngineSettings::default_rate_limit_per_minute`].
    pub rate_limit_per_minute: Option<u32>,
}

impl ProviderConfig {
    pub fn validate(&self) -> SpectreResult<()> {
        if let Some(limit) = self.rate_limit_per_minute
            && !(1..=600).contains(&limit)
        {
            return Err(SpectreError::invalid_input("rate_limit_per_minute must be between 1 and 600"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid_and_conservative() {
        let settings = EngineSettings::default();
        settings.validate().unwrap();
        assert!(settings.max_concurrency <= 8);
    }

    #[test]
    fn rejects_out_of_range_values() {
        let settings = EngineSettings { max_concurrency: 0, ..Default::default() };
        assert!(settings.validate().is_err());
        let settings = EngineSettings { request_timeout_secs: 60, provider_timeout_secs: 10, ..Default::default() };
        assert!(settings.validate().is_err());
    }

    #[test]
    fn partial_json_uses_defaults() {
        let settings: EngineSettings = serde_json::from_str(r#"{"max_concurrency": 8}"#).unwrap();
        assert_eq!(settings.max_concurrency, 8);
        assert_eq!(settings.request_timeout_secs, EngineSettings::default().request_timeout_secs);
    }
}
