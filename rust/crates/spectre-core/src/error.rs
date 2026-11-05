//! Structured error types shared across the engine.
//!
//! Every error carries a stable machine-readable [`ErrorCode`] so the FFI layer
//! and the macOS app can react to categories (rate limits, missing credentials,
//! authorization) without string matching.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable, serializable error categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidInput,
    NotFound,
    Unauthorized,
    CredentialsMissing,
    AuthorizationRequired,
    RateLimited,
    Timeout,
    Network,
    PolicyViolation,
    UpstreamError,
    Cancelled,
    Storage,
    Internal,
}

impl ErrorCode {
    /// Whether an operation that failed with this code is worth retrying.
    pub fn is_transient(self) -> bool {
        matches!(self, Self::RateLimited | Self::Timeout | Self::Network | Self::UpstreamError)
    }
}

/// Engine-wide error type.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("{message}")]
pub struct SpectreError {
    pub code: ErrorCode,
    pub message: String,
}

impl SpectreError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }

    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidInput, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, message)
    }

    pub fn storage(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Storage, message)
    }

    pub fn authorization_required(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::AuthorizationRequired, message)
    }

    pub fn credentials_missing(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::CredentialsMissing, message)
    }

    pub fn cancelled() -> Self {
        Self::new(ErrorCode::Cancelled, "operation cancelled")
    }
}

pub type SpectreResult<T> = Result<T, SpectreError>;
