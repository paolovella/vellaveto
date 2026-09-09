// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Streaming SIEM exporters for real-time audit log delivery.
//!
//! This module provides async exporters that push audit entries to external
//! SIEM systems in near-real-time, with batching, retry logic, and backpressure.
//!
//! ## Supported Exporters
//!
//! - **Splunk HEC** (HTTP Event Collector): Batch JSON events to Splunk
//! - **Datadog**: Batch logs to Datadog intake API
//! - **Elasticsearch**: Bulk index to Elasticsearch
//! - **Webhook**: Generic HTTP POST to any endpoint
//! - **Syslog**: RFC 5424 formatted syslog messages
//!
//! ## Configuration
//!
//! ```toml
//! [audit.export]
//! enabled = true
//! exporters = ["splunk"]
//!
//! [audit.export.splunk]
//! endpoint = "https://splunk.example.com:8088/services/collector"
//! token_env = "SPLUNK_HEC_TOKEN"
//! index = "vellaveto"
//! source = "vellaveto-prod"
//! batch_size = 100
//! flush_interval_secs = 5
//! max_retries = 3
//! ```

use crate::AuditEntry;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Error type for SIEM export operations.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("HTTP request failed: {0}")]
    HttpError(String),

    #[error("serialization failed: {0}")]
    Serialization(String),

    #[error("configuration error: {0}")]
    Configuration(String),

    #[error("authentication failed: {0}")]
    AuthError(String),

    #[error("rate limited, retry after {retry_after_secs} seconds")]
    RateLimited { retry_after_secs: u64 },

    #[error("timeout after {0:?}")]
    Timeout(Duration),

    #[error("server error: {status} - {message}")]
    ServerError { status: u16, message: String },
}

/// Configuration for exporter batching and retry behavior.
///
/// NOTE: `#[serde(deny_unknown_fields)]` is intentionally omitted here.
/// `ExporterConfig` is embedded via `#[serde(flatten)]` in `SplunkConfig`,
/// `WebhookConfig`, `DatadogConfig`, `ElasticsearchConfig`, and `SyslogConfig`.
/// serde does not support combining `deny_unknown_fields` with `flatten` --
/// the flattened fields from the outer struct would be treated as unknown and
/// deserialization would fail. This is a known serde limitation tracked at
/// <https://github.com/serde-rs/serde/issues/1358>.
///
/// Mitigation: `ExporterConfig::validate()` is called by each outer config's
/// `validate()` method, which enforces structural invariants on the deserialized
/// values. Unknown top-level fields are silently ignored but cannot influence
/// export behavior.
///
/// SECURITY (FIND-R112-006): Documented limitation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExporterConfig {
    /// Maximum entries per batch.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// Flush interval for partial batches.
    #[serde(default = "default_flush_interval_secs")]
    pub flush_interval_secs: u64,

    /// Maximum retry attempts for failed exports.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Initial retry backoff duration.
    #[serde(default = "default_retry_backoff_secs")]
    pub retry_backoff_secs: u64,

    /// Request timeout.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_batch_size() -> usize {
    100
}
fn default_flush_interval_secs() -> u64 {
    5
}
fn default_max_retries() -> u32 {
    3
}
fn default_retry_backoff_secs() -> u64 {
    1
}
fn default_timeout_secs() -> u64 {
    30
}

impl ExporterConfig {
    /// Validate exporter configuration bounds.
    ///
    /// SECURITY (FIND-R67-5-001): Enforces safe ranges to prevent DoS via
    /// unbounded batching (batch_size=0 => infinite wait, usize::MAX => OOM),
    /// zero-interval flush loops, or excessive retry/timeout values.
    pub fn validate(&self) -> Result<(), ExportError> {
        if self.batch_size < 1 || self.batch_size > 10_000 {
            return Err(ExportError::Configuration(format!(
                "batch_size must be in [1, 10000], got {}",
                self.batch_size
            )));
        }
        if self.flush_interval_secs < 1 || self.flush_interval_secs > 3600 {
            return Err(ExportError::Configuration(format!(
                "flush_interval_secs must be in [1, 3600], got {}",
                self.flush_interval_secs
            )));
        }
        if self.max_retries > 20 {
            return Err(ExportError::Configuration(format!(
                "max_retries must be in [0, 20], got {}",
                self.max_retries
            )));
        }
        if self.retry_backoff_secs < 1 || self.retry_backoff_secs > 300 {
            return Err(ExportError::Configuration(format!(
                "retry_backoff_secs must be in [1, 300], got {}",
                self.retry_backoff_secs
            )));
        }
        if self.timeout_secs < 1 || self.timeout_secs > 300 {
            return Err(ExportError::Configuration(format!(
                "timeout_secs must be in [1, 300], got {}",
                self.timeout_secs
            )));
        }
        Ok(())
    }
}

impl Default for ExporterConfig {
    fn default() -> Self {
        Self {
            batch_size: default_batch_size(),
            flush_interval_secs: default_flush_interval_secs(),
            max_retries: default_max_retries(),
            retry_backoff_secs: default_retry_backoff_secs(),
            timeout_secs: default_timeout_secs(),
        }
    }
}

/// Trait for SIEM exporters that can send audit entries to external systems.
#[async_trait]
pub trait SiemExporter: Send + Sync {
    /// Unique name of this exporter (e.g., "splunk", "datadog").
    fn name(&self) -> &str;

    /// Export a batch of audit entries.
    ///
    /// Implementations should handle serialization, batching, and error
    /// handling internally. Returns Ok(()) if all entries were accepted
    /// by the remote system.
    async fn export_batch(&self, entries: &[AuditEntry]) -> Result<(), ExportError>;

    /// Check if the exporter is healthy and can accept entries.
    ///
    /// Used for startup validation and health checks.
    async fn health_check(&self) -> Result<(), ExportError>;

    /// Get the exporter configuration.
    fn config(&self) -> &ExporterConfig;
}

/// Splunk HTTP Event Collector (HEC) configuration.
///
/// SECURITY (FIND-R112-006): `deny_unknown_fields` cannot be applied due to
/// `#[serde(flatten)]` on the `common` field (serde#1358). Validated via
/// `ExporterConfig::validate()`.
/// SECURITY (FIND-R157-004): Custom Debug redacts `token` field to prevent
/// HEC token leaking into logs.
#[derive(Clone, Serialize, Deserialize)]
pub struct SplunkConfig {
    /// HEC endpoint URL (e.g., "https://splunk:8088/services/collector").
    pub endpoint: String,

    /// HEC token (loaded from environment variable).
    #[serde(default)]
    pub token: Option<String>,

    /// Environment variable containing the HEC token.
    #[serde(default)]
    pub token_env: Option<String>,

    /// Splunk index to write to.
    #[serde(default)]
    pub index: Option<String>,

    /// Source identifier for events.
    #[serde(default = "default_splunk_source")]
    pub source: String,

    /// Source type for events.
    #[serde(default = "default_splunk_sourcetype")]
    pub sourcetype: String,

    /// Common exporter configuration (batching, retries).
    #[serde(flatten)]
    pub common: ExporterConfig,
}

impl std::fmt::Debug for SplunkConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SplunkConfig")
            .field("endpoint", &self.endpoint)
            .field("token", &"[REDACTED]")
            .field("token_env", &self.token_env)
            .field("index", &self.index)
            .field("source", &self.source)
            .field("sourcetype", &self.sourcetype)
            .field("common", &self.common)
            .finish()
    }
}

fn default_splunk_source() -> String {
    "vellaveto".to_string()
}

fn default_splunk_sourcetype() -> String {
    "vellaveto:audit".to_string()
}

impl SplunkConfig {
    /// Validate Splunk configuration bounds.
    ///
    /// SECURITY (FIND-R215-001): Delegates to `ExporterConfig::validate()` to ensure
    /// common exporter bounds (batch_size, flush_interval, retries, timeouts) are enforced.
    /// SECURITY (FIND-R216-005): Validates string fields reject control/format characters.
    pub fn validate(&self) -> Result<(), ExportError> {
        self.common.validate()?;
        if vellaveto_types::has_dangerous_chars(&self.endpoint) {
            return Err(ExportError::Configuration(
                "Splunk endpoint contains control or Unicode format characters".to_string(),
            ));
        }
        if vellaveto_types::has_dangerous_chars(&self.source) {
            return Err(ExportError::Configuration(
                "Splunk source contains control or Unicode format characters".to_string(),
            ));
        }
        if vellaveto_types::has_dangerous_chars(&self.sourcetype) {
            return Err(ExportError::Configuration(
                "Splunk sourcetype contains control or Unicode format characters".to_string(),
            ));
        }
        Ok(())
    }
}

impl Default for SplunkConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            token: None,
            token_env: Some("SPLUNK_HEC_TOKEN".to_string()),
            index: None,
            source: default_splunk_source(),
            sourcetype: default_splunk_sourcetype(),
            common: ExporterConfig::default(),
        }
    }
}

/// Splunk HEC event wrapper.
#[cfg(feature = "siem-exporters")]
#[derive(Serialize)]
struct SplunkEvent<'a> {
    /// Event timestamp (epoch seconds with milliseconds).
    time: f64,
    /// Source identifier.
    source: &'a str,
    /// Source type.
    sourcetype: &'a str,
    /// Target index (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    index: Option<&'a str>,
    /// Event payload.
    event: &'a AuditEntry,
}

/// Splunk HTTP Event Collector exporter.
#[cfg(feature = "siem-exporters")]
pub struct SplunkExporter {
    config: SplunkConfig,
    client: reqwest::Client,
    token: String,
}

#[cfg(feature = "siem-exporters")]
impl SplunkExporter {
    /// Create a new Splunk HEC exporter.
    ///
    /// The token is loaded from the configured environment variable or
    /// the direct `token` field in the configuration.
    pub fn new(config: SplunkConfig) -> Result<Self, ExportError> {
        // SECURITY (FIND-R215-001): Validate common exporter config bounds.
        config.validate()?;

        // Load token
        let token = if let Some(ref t) = config.token {
            t.clone()
        } else if let Some(ref env_var) = config.token_env {
            std::env::var(env_var).map_err(|_| {
                ExportError::Configuration(format!(
                    "HEC token environment variable '{}' not set",
                    env_var
                ))
            })?
        } else {
            return Err(ExportError::Configuration(
                "No HEC token configured (set 'token' or 'token_env')".to_string(),
            ));
        };

        if config.endpoint.is_empty() {
            return Err(ExportError::Configuration(
                "Splunk HEC endpoint not configured".to_string(),
            ));
        }

        // SECURITY (GAP-F05): Validate URL scheme to prevent SSRF via exotic schemes.
        if !config.endpoint.starts_with("http://") && !config.endpoint.starts_with("https://") {
            return Err(ExportError::Configuration(format!(
                "Splunk endpoint URL must use http:// or https:// scheme, got: {}",
                config.endpoint.split(':').next().unwrap_or("(empty)")
            )));
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.common.timeout_secs))
            .build()
            .map_err(|e| {
                ExportError::Configuration(format!("Failed to create HTTP client: {}", e))
            })?;

        Ok(Self {
            config,
            client,
            token,
        })
    }

    /// Format entries as Splunk HEC events.
    fn format_events(&self, entries: &[AuditEntry]) -> Result<String, ExportError> {
        let mut output = String::new();

        for entry in entries {
            // Parse timestamp to epoch seconds
            let time = chrono::DateTime::parse_from_rfc3339(&entry.timestamp)
                .map(|dt| dt.timestamp() as f64 + dt.timestamp_subsec_millis() as f64 / 1000.0)
                .unwrap_or_else(|_| chrono::Utc::now().timestamp() as f64);

            let event = SplunkEvent {
                time,
                source: &self.config.source,
                sourcetype: &self.config.sourcetype,
                index: self.config.index.as_deref(),
                event: entry,
            };

            let json = serde_json::to_string(&event)
                .map_err(|e| ExportError::Serialization(e.to_string()))?;
            output.push_str(&json);
        }

        Ok(output)
    }
}

#[cfg(feature = "siem-exporters")]
#[async_trait]
impl SiemExporter for SplunkExporter {
    fn name(&self) -> &str {
        "splunk"
    }

    async fn export_batch(&self, entries: &[AuditEntry]) -> Result<(), ExportError> {
        if entries.is_empty() {
            return Ok(());
        }

        let body = self.format_events(entries)?;

        let mut retries = 0;
        let mut backoff = Duration::from_secs(self.config.common.retry_backoff_secs);
        // SECURITY (FIND-R46-004): Cap exponential backoff to prevent
        // adversarial or misconfigured upstreams from stalling exports indefinitely.
        const MAX_BACKOFF_SECS: u64 = 300;

        loop {
            let result = self
                .client
                .post(&self.config.endpoint)
                .header("Authorization", format!("Splunk {}", self.token))
                .header("Content-Type", "application/json")
                .body(body.clone())
                .send()
                .await;

            match result {
                Ok(response) => {
                    let status = response.status();

                    if status.is_success() {
                        tracing::debug!(
                            exporter = "splunk",
                            entries = entries.len(),
                            "Successfully exported batch"
                        );
                        return Ok(());
                    }

                    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                        // SECURITY (FIND-R46-004): Cap Retry-After at 300 seconds
                        // to prevent an adversarial server from stalling the exporter
                        // indefinitely with a huge Retry-After value.
                        const MAX_RETRY_AFTER_SECS: u64 = 300;
                        let retry_after = response
                            .headers()
                            .get("Retry-After")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(60)
                            .min(MAX_RETRY_AFTER_SECS);

                        if retries >= self.config.common.max_retries {
                            return Err(ExportError::RateLimited {
                                retry_after_secs: retry_after,
                            });
                        }

                        tokio::time::sleep(Duration::from_secs(retry_after)).await;
                        retries += 1;
                        continue;
                    }

                    if status.is_server_error() && retries < self.config.common.max_retries {
                        let capped_backoff = backoff.min(Duration::from_secs(MAX_BACKOFF_SECS));
                        tracing::warn!(
                            exporter = "splunk",
                            status = %status,
                            retry = retries + 1,
                            backoff_secs = capped_backoff.as_secs(),
                            "Server error, retrying"
                        );
                        tokio::time::sleep(capped_backoff).await;
                        backoff = (backoff * 2).min(Duration::from_secs(MAX_BACKOFF_SECS));
                        retries += 1;
                        continue;
                    }

                    let body = response.text().await.unwrap_or_default();
                    return Err(ExportError::ServerError {
                        status: status.as_u16(),
                        message: body,
                    });
                }
                Err(e) => {
                    if e.is_timeout() {
                        if retries < self.config.common.max_retries {
                            let capped_backoff = backoff.min(Duration::from_secs(MAX_BACKOFF_SECS));
                            tracing::warn!(
                                exporter = "splunk",
                                retry = retries + 1,
                                backoff_secs = capped_backoff.as_secs(),
                                "Request timeout, retrying"
                            );
                            tokio::time::sleep(capped_backoff).await;
                            backoff = (backoff * 2).min(Duration::from_secs(MAX_BACKOFF_SECS));
                            retries += 1;
                            continue;
                        }
                        return Err(ExportError::Timeout(Duration::from_secs(
                            self.config.common.timeout_secs,
                        )));
                    }

                    if retries < self.config.common.max_retries {
                        let capped_backoff = backoff.min(Duration::from_secs(MAX_BACKOFF_SECS));
                        tracing::warn!(
                            exporter = "splunk",
                            error = %e,
                            retry = retries + 1,
                            backoff_secs = capped_backoff.as_secs(),
                            "HTTP error, retrying"
                        );
                        tokio::time::sleep(capped_backoff).await;
                        backoff = (backoff * 2).min(Duration::from_secs(MAX_BACKOFF_SECS));
                        retries += 1;
                        continue;
                    }

                    return Err(ExportError::HttpError(e.to_string()));
                }
            }
        }
    }

    async fn health_check(&self) -> Result<(), ExportError> {
        // Send a simple GET to the HEC endpoint to verify connectivity
        // Splunk HEC returns 400 for GET but that confirms the endpoint is reachable
        let result = self
            .client
            .get(&self.config.endpoint)
            .header("Authorization", format!("Splunk {}", self.token))
            .send()
            .await;

        match result {
            Ok(response) => {
                // 400 is expected for GET on HEC, 401 means bad token
                if response.status() == reqwest::StatusCode::UNAUTHORIZED {
                    return Err(ExportError::AuthError("Invalid HEC token".to_string()));
                }
                Ok(())
            }
            Err(e) => Err(ExportError::HttpError(e.to_string())),
        }
    }

    fn config(&self) -> &ExporterConfig {
        &self.config.common
    }
}

/// Maximum number of custom headers allowed in a webhook exporter.
///
/// SECURITY (FIND-R67-5-002): Bounds the HashMap to prevent OOM from
/// attacker-controlled configuration with millions of headers.
const MAX_WEBHOOK_HEADERS: usize = 50;

/// Maximum length of a webhook header key.
const MAX_HEADER_KEY_LEN: usize = 256;

/// Maximum length of a webhook header value.
const MAX_HEADER_VALUE_LEN: usize = 8192;

/// Generic webhook exporter configuration.
///
/// SECURITY (FIND-R112-006): `deny_unknown_fields` cannot be applied due to
/// `#[serde(flatten)]` on the `common` field (serde#1358). Validated via
/// `WebhookConfig::validate()` + `ExporterConfig::validate()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook endpoint URL.
    pub endpoint: String,

    /// Optional authorization header value.
    #[serde(default)]
    pub auth_header: Option<String>,

    /// Environment variable containing the auth header value.
    #[serde(default)]
    pub auth_header_env: Option<String>,

    /// Additional headers to include.
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,

    /// Common exporter configuration.
    #[serde(flatten)]
    pub common: ExporterConfig,
}

impl WebhookConfig {
    /// Validate webhook configuration bounds.
    ///
    /// SECURITY (FIND-R67-5-002): Enforces bounds on headers map to prevent
    /// OOM via attacker-controlled configuration.
    /// SECURITY (FIND-R216-005): Validates string fields reject control/format characters.
    /// SECURITY (FIND-R216-009): Validates header keys/values reject dangerous chars.
    pub fn validate(&self) -> Result<(), ExportError> {
        self.common.validate()?;
        if vellaveto_types::has_dangerous_chars(&self.endpoint) {
            return Err(ExportError::Configuration(
                "Webhook endpoint contains control or Unicode format characters".to_string(),
            ));
        }
        if self.headers.len() > MAX_WEBHOOK_HEADERS {
            return Err(ExportError::Configuration(format!(
                "headers count {} exceeds maximum of {}",
                self.headers.len(),
                MAX_WEBHOOK_HEADERS,
            )));
        }
        for (key, value) in &self.headers {
            if key.len() > MAX_HEADER_KEY_LEN {
                return Err(ExportError::Configuration(format!(
                    "header key length {} exceeds maximum of {}",
                    key.len(),
                    MAX_HEADER_KEY_LEN,
                )));
            }
            if value.len() > MAX_HEADER_VALUE_LEN {
                return Err(ExportError::Configuration(format!(
                    "header value length {} exceeds maximum of {}",
                    value.len(),
                    MAX_HEADER_VALUE_LEN,
                )));
            }
            if vellaveto_types::has_dangerous_chars(key) {
                return Err(ExportError::Configuration(
                    "Webhook header key contains control or Unicode format characters".to_string(),
                ));
            }
            if vellaveto_types::has_dangerous_chars(value) {
                return Err(ExportError::Configuration(
                    "Webhook header value contains control or Unicode format characters"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }
}

/// Generic webhook exporter.
#[cfg(feature = "siem-exporters")]
pub struct WebhookExporter {
    config: WebhookConfig,
    client: reqwest::Client,
    auth_header: Option<String>,
}

#[cfg(feature = "siem-exporters")]
impl WebhookExporter {
    /// Create a new webhook exporter.
    ///
    /// SECURITY (FIND-R216-002): Validates config at construction time, matching
    /// SplunkExporter pattern.
    pub fn new(config: WebhookConfig) -> Result<Self, ExportError> {
        config.validate()?;

        let auth_header = if let Some(ref h) = config.auth_header {
            Some(h.clone())
        } else if let Some(ref env_var) = config.auth_header_env {
            std::env::var(env_var).ok()
        } else {
            None
        };

        if config.endpoint.is_empty() {
            return Err(ExportError::Configuration(
                "Webhook endpoint not configured".to_string(),
            ));
        }

        // SECURITY (GAP-F05): Validate URL scheme to prevent SSRF via exotic schemes.
        if !config.endpoint.starts_with("http://") && !config.endpoint.starts_with("https://") {
            return Err(ExportError::Configuration(format!(
                "Webhook endpoint URL must use http:// or https:// scheme, got: {}",
                config.endpoint.split(':').next().unwrap_or("(empty)")
            )));
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.common.timeout_secs))
            .build()
            .map_err(|e| {
                ExportError::Configuration(format!("Failed to create HTTP client: {}", e))
            })?;

        Ok(Self {
            config,
            client,
            auth_header,
        })
    }
}

#[cfg(feature = "siem-exporters")]
#[async_trait]
impl SiemExporter for WebhookExporter {
    fn name(&self) -> &str {
        "webhook"
    }

    /// SECURITY (FIND-R46-003): Bounded retry with exponential backoff for webhook
    /// delivery failures. 3 attempts, backoff capped at 30s. Each retry is logged.
    async fn export_batch(&self, entries: &[AuditEntry]) -> Result<(), ExportError> {
        if entries.is_empty() {
            return Ok(());
        }

        let body = serde_json::to_string(&entries)
            .map_err(|e| ExportError::Serialization(e.to_string()))?;

        let max_retries = self.config.common.max_retries;
        let mut retries = 0u32;
        let mut backoff = Duration::from_secs(self.config.common.retry_backoff_secs);
        /// SECURITY (FIND-R46-003): Cap backoff at 30 seconds to prevent indefinite waits.
        const MAX_BACKOFF: Duration = Duration::from_secs(30);

        loop {
            let mut request = self
                .client
                .post(&self.config.endpoint)
                .header("Content-Type", "application/json");

            if let Some(ref auth) = self.auth_header {
                request = request.header("Authorization", auth);
            }

            for (key, value) in &self.config.headers {
                request = request.header(key, value);
            }

            let result = request.body(body.clone()).send().await;

            match result {
                Ok(response) => {
                    if response.status().is_success() {
                        return Ok(());
                    }

                    let status = response.status().as_u16();

                    // Retry on server errors (5xx)
                    if status >= 500 && retries < max_retries {
                        let body_text = response.text().await.unwrap_or_default();
                        tracing::warn!(
                            exporter = "webhook",
                            status = status,
                            retry = retries + 1,
                            max_retries = max_retries,
                            backoff_secs = backoff.as_secs(),
                            "Webhook server error, retrying: {}",
                            body_text,
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                        retries += 1;
                        continue;
                    }

                    let message = response.text().await.unwrap_or_default();
                    return Err(ExportError::ServerError { status, message });
                }
                Err(e) => {
                    // Retry on transient network errors
                    if retries < max_retries {
                        tracing::warn!(
                            exporter = "webhook",
                            error = %e,
                            retry = retries + 1,
                            max_retries = max_retries,
                            backoff_secs = backoff.as_secs(),
                            "Webhook request failed, retrying"
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                        retries += 1;
                        continue;
                    }
                    return Err(ExportError::HttpError(e.to_string()));
                }
            }
        }
    }

    async fn health_check(&self) -> Result<(), ExportError> {
        // Simple connectivity check
        let response = self
            .client
            .head(&self.config.endpoint)
            .send()
            .await
            .map_err(|e| ExportError::HttpError(e.to_string()))?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(ExportError::AuthError("Unauthorized".to_string()));
        }

        Ok(())
    }

    fn config(&self) -> &ExporterConfig {
        &self.config.common
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Datadog Exporter
// ────────────────────────────────────────────────────────────────────────────

/// Maximum number of tags allowed in Datadog exporter configuration.
///
/// SECURITY (FIND-R67-5-002): Bounds the Vec to prevent OOM from
/// attacker-controlled configuration with millions of tags.
const MAX_TAG_COUNT: usize = 100;

/// Maximum length of a single Datadog tag.
const MAX_TAG_LEN: usize = 256;

/// Datadog logs intake configuration.
///
/// SECURITY (FIND-R112-006): `deny_unknown_fields` cannot be applied due to
/// `#[serde(flatten)]` on the `common` field (serde#1358). Validated via
/// `DatadogConfig::validate()` + `ExporterConfig::validate()`.
/// SECURITY (FIND-R157-004): Custom Debug redacts `api_key` field to prevent
/// Datadog API key leaking into logs.
#[derive(Clone, Serialize, Deserialize)]
pub struct DatadogConfig {
    /// Datadog logs intake endpoint.
    /// US: `https://http-intake.logs.datadoghq.com/api/v2/logs`
    /// EU: `https://http-intake.logs.datadoghq.eu/api/v2/logs`
    #[serde(default = "default_datadog_endpoint")]
    pub endpoint: String,

    /// Datadog API key (loaded from environment variable).
    #[serde(default)]
    pub api_key: Option<String>,

    /// Environment variable containing the API key.
    #[serde(default = "default_datadog_api_key_env")]
    pub api_key_env: String,

    /// Service name for log entries.
    #[serde(default = "default_datadog_service")]
    pub service: String,

    /// Source identifier.
    #[serde(default = "default_datadog_source")]
    pub source: String,

    /// Tags to attach to all logs (key:value format).
    #[serde(default)]
    pub tags: Vec<String>,

    /// Common exporter configuration.
    #[serde(flatten)]
    pub common: ExporterConfig,
}

impl std::fmt::Debug for DatadogConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatadogConfig")
            .field("endpoint", &self.endpoint)
            .field("api_key", &"[REDACTED]")
            .field("api_key_env", &self.api_key_env)
            .field("service", &self.service)
            .field("source", &self.source)
            .field("tags", &self.tags)
            .field("common", &self.common)
            .finish()
    }
}

fn default_datadog_endpoint() -> String {
    "https://http-intake.logs.datadoghq.com/api/v2/logs".to_string()
}

fn default_datadog_api_key_env() -> String {
    "DD_API_KEY".to_string()
}

fn default_datadog_service() -> String {
    "vellaveto".to_string()
}

fn default_datadog_source() -> String {
    "vellaveto".to_string()
}

impl Default for DatadogConfig {
    fn default() -> Self {
        Self {
            endpoint: default_datadog_endpoint(),
            api_key: None,
            api_key_env: default_datadog_api_key_env(),
            service: default_datadog_service(),
            source: default_datadog_source(),
            tags: vec![],
            common: ExporterConfig::default(),
        }
    }
}

impl DatadogConfig {
    /// Validate Datadog configuration bounds.
    ///
    /// SECURITY (FIND-R67-5-002): Enforces bounds on tags Vec to prevent
    /// OOM via attacker-controlled configuration.
    /// SECURITY (FIND-R216-005): Validates string fields reject control/format characters.
    pub fn validate(&self) -> Result<(), ExportError> {
        self.common.validate()?;
        // SECURITY (FIND-R224-004): Validate URL scheme to prevent SSRF via exotic
        // schemes. Parity with Splunk (line 349), Webhook (line 678), Elasticsearch (line 1278).
        if !self.endpoint.starts_with("http://") && !self.endpoint.starts_with("https://") {
            return Err(ExportError::Configuration(format!(
                "Datadog endpoint URL must use http:// or https:// scheme, got: {}",
                self.endpoint.split(':').next().unwrap_or("(empty)")
            )));
        }
        if vellaveto_types::has_dangerous_chars(&self.endpoint) {
            return Err(ExportError::Configuration(
                "Datadog endpoint contains control or Unicode format characters".to_string(),
            ));
        }
        if vellaveto_types::has_dangerous_chars(&self.service) {
            return Err(ExportError::Configuration(
                "Datadog service contains control or Unicode format characters".to_string(),
            ));
        }
        if vellaveto_types::has_dangerous_chars(&self.source) {
            return Err(ExportError::Configuration(
                "Datadog source contains control or Unicode format characters".to_string(),
            ));
        }
        if self.tags.len() > MAX_TAG_COUNT {
            return Err(ExportError::Configuration(format!(
                "tags count {} exceeds maximum of {}",
                self.tags.len(),
                MAX_TAG_COUNT,
            )));
        }
        for tag in &self.tags {
            if tag.len() > MAX_TAG_LEN {
                return Err(ExportError::Configuration(format!(
                    "tag length {} exceeds maximum of {}",
                    tag.len(),
                    MAX_TAG_LEN,
                )));
            }
            if vellaveto_types::has_dangerous_chars(tag) {
                return Err(ExportError::Configuration(
                    "Datadog tag contains control or Unicode format characters".to_string(),
                ));
            }
        }
        Ok(())
    }
}

/// Datadog log entry format.
#[cfg(feature = "siem-exporters")]
#[derive(Serialize)]
struct DatadogLogEntry<'a> {
    /// Log message (JSON-serialized audit entry).
    message: String,
    /// Service name.
    service: &'a str,
    /// Source identifier.
    ddsource: &'a str,
    /// Tags in key:value format.
    ddtags: String,
    /// Hostname (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,
    /// Timestamp in ISO 8601 format.
    #[serde(rename = "@timestamp")]
    timestamp: &'a str,
}

/// Datadog logs exporter.
#[cfg(feature = "siem-exporters")]
pub struct DatadogExporter {
    config: DatadogConfig,
    client: reqwest::Client,
    api_key: String,
}

#[cfg(feature = "siem-exporters")]
impl DatadogExporter {
    /// Create a new Datadog exporter.
    ///
    /// SECURITY (FIND-R216-003): Validates config at construction time, matching
    /// SplunkExporter pattern.
    pub fn new(config: DatadogConfig) -> Result<Self, ExportError> {
        config.validate()?;

        let api_key = if let Some(ref k) = config.api_key {
            k.clone()
        } else {
            std::env::var(&config.api_key_env).map_err(|_| {
                ExportError::Configuration(format!(
                    "Datadog API key environment variable '{}' not set",
                    config.api_key_env
                ))
            })?
        };

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.common.timeout_secs))
            .build()
            .map_err(|e| {
                ExportError::Configuration(format!("Failed to create HTTP client: {}", e))
            })?;

        Ok(Self {
            config,
            client,
            api_key,
        })
    }
}

#[cfg(feature = "siem-exporters")]
#[async_trait]
impl SiemExporter for DatadogExporter {
    fn name(&self) -> &str {
        "datadog"
    }

    /// SECURITY (FIND-R46-011): Implements bounded retry with exponential backoff
    /// for transient failures (5xx, timeouts, network errors). Max 3 retries with
    /// backoff capped at 30 seconds. Non-retryable errors (4xx) fail immediately.
    async fn export_batch(&self, entries: &[AuditEntry]) -> Result<(), ExportError> {
        if entries.is_empty() {
            return Ok(());
        }

        let hostname = hostname::get()
            .ok()
            .and_then(|h: std::ffi::OsString| h.into_string().ok());

        let ddtags = self.config.tags.join(",");

        let logs: Vec<DatadogLogEntry> = entries
            .iter()
            .map(|entry| {
                // GAP-Q04: Log serialization failures instead of silently returning empty.
                let message = serde_json::to_string(entry).unwrap_or_else(|e| {
                    tracing::warn!(
                        entry_id = %entry.id,
                        error = %e,
                        "Failed to serialize audit entry for Datadog export"
                    );
                    String::new()
                });
                DatadogLogEntry {
                    message,
                    service: &self.config.service,
                    ddsource: &self.config.source,
                    ddtags: ddtags.clone(),
                    hostname: hostname.clone(),
                    timestamp: &entry.timestamp,
                }
            })
            .collect();

        let body =
            serde_json::to_string(&logs).map_err(|e| ExportError::Serialization(e.to_string()))?;

        let max_retries = self.config.common.max_retries;
        let mut retries = 0u32;
        let mut backoff = Duration::from_secs(self.config.common.retry_backoff_secs);
        const MAX_BACKOFF: Duration = Duration::from_secs(30);

        loop {
            let result = self
                .client
                .post(&self.config.endpoint)
                .header("DD-API-KEY", &self.api_key)
                .header("Content-Type", "application/json")
                .body(body.clone())
                .send()
                .await;

            match result {
                Ok(response) => {
                    if response.status().is_success() {
                        tracing::debug!(
                            exporter = "datadog",
                            entries = entries.len(),
                            "Successfully exported batch"
                        );
                        return Ok(());
                    }

                    let status = response.status().as_u16();

                    // Retry on server errors (5xx)
                    if status >= 500 && retries < max_retries {
                        tracing::warn!(
                            exporter = "datadog",
                            status = status,
                            retry = retries + 1,
                            max_retries = max_retries,
                            backoff_secs = backoff.as_secs(),
                            "Datadog server error, retrying"
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                        retries += 1;
                        continue;
                    }

                    let message = response.text().await.unwrap_or_default();
                    return Err(ExportError::ServerError { status, message });
                }
                Err(e) => {
                    if retries < max_retries {
                        tracing::warn!(
                            exporter = "datadog",
                            error = %e,
                            retry = retries + 1,
                            max_retries = max_retries,
                            backoff_secs = backoff.as_secs(),
                            "Datadog request failed, retrying"
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                        retries += 1;
                        continue;
                    }
                    return Err(ExportError::HttpError(e.to_string()));
                }
            }
        }
    }

    async fn health_check(&self) -> Result<(), ExportError> {
        // Datadog validates API key on each request
        // Send an empty batch to check connectivity
        let response = self
            .client
            .post(&self.config.endpoint)
            .header("DD-API-KEY", &self.api_key)
            .header("Content-Type", "application/json")
            .body("[]")
            .send()
            .await
            .map_err(|e| ExportError::HttpError(e.to_string()))?;

        if response.status() == reqwest::StatusCode::FORBIDDEN {
            return Err(ExportError::AuthError(
                "Invalid Datadog API key".to_string(),
            ));
        }

        Ok(())
    }

    fn config(&self) -> &ExporterConfig {
        &self.config.common
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Elasticsearch Exporter
// ────────────────────────────────────────────────────────────────────────────

/// Elasticsearch bulk index configuration.
///
/// SECURITY (FIND-R112-006): `deny_unknown_fields` cannot be applied due to
/// `#[serde(flatten)]` on the `common` field (serde#1358). Validated via
/// `ExporterConfig::validate()`.
/// SECURITY (FIND-R157-004): Custom Debug redacts `api_key` field to prevent
/// Elasticsearch API key leaking into logs.
#[derive(Clone, Serialize, Deserialize)]
pub struct ElasticsearchConfig {
    /// Elasticsearch endpoint (e.g., "https://elasticsearch:9200").
    pub endpoint: String,

    /// Index name or pattern (supports date variables like vellaveto-%Y.%m.%d).
    #[serde(default = "default_es_index")]
    pub index: String,

    /// Username for basic auth (optional).
    #[serde(default)]
    pub username: Option<String>,

    /// Password for basic auth (loaded from environment).
    #[serde(default)]
    pub password_env: Option<String>,

    /// API key for authentication (alternative to basic auth).
    #[serde(default)]
    pub api_key: Option<String>,

    /// Environment variable for API key.
    #[serde(default)]
    pub api_key_env: Option<String>,

    /// Common exporter configuration.
    #[serde(flatten)]
    pub common: ExporterConfig,
}

impl std::fmt::Debug for ElasticsearchConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ElasticsearchConfig")
            .field("endpoint", &self.endpoint)
            .field("index", &self.index)
            .field("username", &self.username)
            .field("password_env", &self.password_env)
            .field("api_key", &"[REDACTED]")
            .field("api_key_env", &self.api_key_env)
            .field("common", &self.common)
            .finish()
    }
}

fn default_es_index() -> String {
    "vellaveto-audit".to_string()
}

impl ElasticsearchConfig {
    /// Validate Elasticsearch configuration bounds.
    ///
    /// SECURITY (FIND-R215-001): Delegates to `ExporterConfig::validate()` to ensure
    /// common exporter bounds (batch_size, flush_interval, retries, timeouts) are enforced.
    /// SECURITY (FIND-R216-005): Validates string fields reject control/format characters.
    pub fn validate(&self) -> Result<(), ExportError> {
        self.common.validate()?;
        if vellaveto_types::has_dangerous_chars(&self.endpoint) {
            return Err(ExportError::Configuration(
                "Elasticsearch endpoint contains control or Unicode format characters".to_string(),
            ));
        }
        if vellaveto_types::has_dangerous_chars(&self.index) {
            return Err(ExportError::Configuration(
                "Elasticsearch index contains control or Unicode format characters".to_string(),
            ));
        }
        Ok(())
    }
}

impl Default for ElasticsearchConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            index: default_es_index(),
            username: None,
            password_env: None,
            api_key: None,
            api_key_env: None,
            common: ExporterConfig::default(),
        }
    }
}

/// Elasticsearch exporter using bulk API.
#[cfg(feature = "siem-exporters")]
pub struct ElasticsearchExporter {
    config: ElasticsearchConfig,
    client: reqwest::Client,
    auth_header: Option<String>,
}

#[cfg(feature = "siem-exporters")]
impl ElasticsearchExporter {
    /// Create a new Elasticsearch exporter.
    pub fn new(config: ElasticsearchConfig) -> Result<Self, ExportError> {
        // SECURITY (FIND-R215-001): Validate common exporter config bounds.
        config.validate()?;

        if config.endpoint.is_empty() {
            return Err(ExportError::Configuration(
                "Elasticsearch endpoint not configured".to_string(),
            ));
        }

        // SECURITY (GAP-F05): Validate URL scheme to prevent SSRF via exotic schemes.
        if !config.endpoint.starts_with("http://") && !config.endpoint.starts_with("https://") {
            return Err(ExportError::Configuration(format!(
                "Elasticsearch endpoint URL must use http:// or https:// scheme, got: {}",
                config.endpoint.split(':').next().unwrap_or("(empty)")
            )));
        }

        // Build auth header from config
        let auth_header = if let Some(ref api_key) = config.api_key {
            Some(format!("ApiKey {}", api_key))
        } else if let Some(ref api_key_env) = config.api_key_env {
            std::env::var(api_key_env)
                .ok()
                .map(|k| format!("ApiKey {}", k))
        } else if let Some(ref username) = config.username {
            let password = config
                .password_env
                .as_ref()
                .and_then(|env| std::env::var(env).ok())
                .unwrap_or_default();
            let credentials = {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .encode(format!("{}:{}", username, password))
            };
            Some(format!("Basic {}", credentials))
        } else {
            None
        };

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.common.timeout_secs))
            .build()
            .map_err(|e| {
                ExportError::Configuration(format!("Failed to create HTTP client: {}", e))
            })?;

        Ok(Self {
            config,
            client,
            auth_header,
        })
    }

    /// Get the index name, expanding date variables if present.
    fn get_index_name(&self) -> String {
        let now = chrono::Utc::now();
        now.format(&self.config.index).to_string()
    }
}

#[cfg(feature = "siem-exporters")]
#[async_trait]
impl SiemExporter for ElasticsearchExporter {
    fn name(&self) -> &str {
        "elasticsearch"
    }

    /// SECURITY (FIND-P1-2): Bounded retry with exponential backoff for
    /// Elasticsearch bulk indexing. 5xx and connection errors are retried up
    /// to `max_retries` times with backoff capped at 30s. Non-retryable errors
    /// (4xx) fail immediately.
    ///
    /// SECURITY (FIND-P1-4): Partial bulk failures (ES `errors: true`) are now
    /// reported as errors instead of being swallowed. The error count is parsed
    /// from the response and included in the error message.
    async fn export_batch(&self, entries: &[AuditEntry]) -> Result<(), ExportError> {
        if entries.is_empty() {
            return Ok(());
        }

        let index_name = self.get_index_name();
        let bulk_url = format!("{}/_bulk", self.config.endpoint);

        // Build NDJSON bulk request body
        let mut body = String::new();
        for entry in entries {
            // Index action line
            let action = serde_json::json!({
                "index": {
                    "_index": index_name,
                    "_id": entry.id
                }
            });
            body.push_str(
                &serde_json::to_string(&action)
                    .map_err(|e| ExportError::Serialization(e.to_string()))?,
            );
            body.push('\n');

            // Document line
            body.push_str(
                &serde_json::to_string(entry)
                    .map_err(|e| ExportError::Serialization(e.to_string()))?,
            );
            body.push('\n');
        }

        let max_retries = self.config.common.max_retries;
        let mut retries = 0u32;
        let mut backoff = Duration::from_secs(self.config.common.retry_backoff_secs);
        const MAX_BACKOFF: Duration = Duration::from_secs(30);

        loop {
            let mut request = self
                .client
                .post(&bulk_url)
                .header("Content-Type", "application/x-ndjson");

            if let Some(ref auth) = self.auth_header {
                request = request.header("Authorization", auth);
            }

            let result = request.body(body.clone()).send().await;

            match result {
                Ok(response) => {
                    let status = response.status();

                    if status.is_success() {
                        // Check for partial failures in bulk response
                        let resp_body: serde_json::Value = response
                            .json()
                            .await
                            .map_err(|e| ExportError::Serialization(e.to_string()))?;

                        if resp_body
                            .get("errors")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false)
                        {
                            // SECURITY (FIND-P1-4): Count and report partial failures
                            // instead of swallowing them.
                            let error_count = resp_body
                                .get("items")
                                .and_then(|v| v.as_array())
                                .map(|items| {
                                    items
                                        .iter()
                                        .filter(|item| {
                                            item.get("index")
                                                .and_then(|idx| idx.get("error"))
                                                .is_some()
                                        })
                                        .count()
                                })
                                .unwrap_or(0);

                            tracing::error!(
                                exporter = "elasticsearch",
                                total = entries.len(),
                                failed = error_count,
                                "Elasticsearch bulk indexing partial failure"
                            );

                            return Err(ExportError::ServerError {
                                status: status.as_u16(),
                                message: format!(
                                    "Bulk indexing partial failure: {} of {} items failed",
                                    error_count,
                                    entries.len()
                                ),
                            });
                        }

                        tracing::debug!(
                            exporter = "elasticsearch",
                            entries = entries.len(),
                            index = %index_name,
                            "Successfully exported batch"
                        );
                        return Ok(());
                    }

                    // Retry on server errors (5xx)
                    if status.is_server_error() && retries < max_retries {
                        let body_text = response.text().await.unwrap_or_default();
                        tracing::warn!(
                            exporter = "elasticsearch",
                            status = %status,
                            retry = retries + 1,
                            max_retries = max_retries,
                            backoff_secs = backoff.as_secs(),
                            "Elasticsearch server error, retrying: {}",
                            body_text,
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                        retries += 1;
                        continue;
                    }

                    let message = response.text().await.unwrap_or_default();
                    return Err(ExportError::ServerError {
                        status: status.as_u16(),
                        message,
                    });
                }
                Err(e) => {
                    // Retry on transient network / timeout errors
                    if retries < max_retries {
                        tracing::warn!(
                            exporter = "elasticsearch",
                            error = %e,
                            retry = retries + 1,
                            max_retries = max_retries,
                            backoff_secs = backoff.as_secs(),
                            "Elasticsearch request failed, retrying"
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                        retries += 1;
                        continue;
                    }
                    return Err(ExportError::HttpError(e.to_string()));
                }
            }
        }
    }

    async fn health_check(&self) -> Result<(), ExportError> {
        let mut request = self.client.get(&self.config.endpoint);

        if let Some(ref auth) = self.auth_header {
            request = request.header("Authorization", auth);
        }

        let response = request
            .send()
            .await
            .map_err(|e| ExportError::HttpError(e.to_string()))?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(ExportError::AuthError(
                "Elasticsearch authentication failed".to_string(),
            ));
        }

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let message = response.text().await.unwrap_or_default();
            return Err(ExportError::ServerError { status, message });
        }

        Ok(())
    }

    fn config(&self) -> &ExporterConfig {
        &self.config.common
    }
}

// ============================================================================
// Syslog Exporter (RFC 5424)
// ============================================================================

/// Syslog protocol variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SyslogProtocol {
    /// UDP (default, fire-and-forget)
    #[default]
    Udp,
    /// TCP (reliable)
    Tcp,
}

/// Syslog facility (RFC 5424 Section 6.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SyslogFacility {
    Kern = 0,
    User = 1,
    Mail = 2,
    Daemon = 3,
    Auth = 4,
    Syslog = 5,
    Lpr = 6,
    News = 7,
    Uucp = 8,
    Cron = 9,
    Authpriv = 10,
    Ftp = 11,
    Ntp = 12,
    Audit = 13,
    Alert = 14,
    Clock = 15,
    #[default]
    Local0 = 16,
    Local1 = 17,
    Local2 = 18,
    Local3 = 19,
    Local4 = 20,
    Local5 = 21,
    Local6 = 22,
    Local7 = 23,
}

/// Syslog severity (RFC 5424 Section 6.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyslogSeverity {
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
    Debug = 7,
}

impl SyslogFacility {
    #[allow(dead_code)] // Used by SyslogExporter when siem-exporters feature is enabled
    fn as_u8(self) -> u8 {
        self as u8
    }
}

impl SyslogSeverity {
    #[allow(dead_code)] // Used by SyslogExporter when siem-exporters feature is enabled
    fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Configuration for syslog exporter.
///
/// SECURITY (FIND-R112-006): `deny_unknown_fields` cannot be applied due to
/// `#[serde(flatten)]` on the `common` field (serde#1358). Validated via
/// `ExporterConfig::validate()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyslogConfig {
    /// Syslog server host.
    pub host: String,

    /// Syslog server port (default: 514 for UDP, 6514 for TLS).
    #[serde(default = "default_syslog_port")]
    pub port: u16,

    /// Protocol: "udp" or "tcp".
    #[serde(default)]
    pub protocol: SyslogProtocol,

    /// Syslog facility.
    #[serde(default)]
    pub facility: SyslogFacility,

    /// Application name for syslog messages.
    #[serde(default = "default_app_name")]
    pub app_name: String,

    /// Enterprise ID for structured data (IANA-assigned or private).
    #[serde(default = "default_enterprise_id")]
    pub enterprise_id: String,

    /// Include JSON payload in message body.
    #[serde(default = "default_include_json")]
    pub include_json: bool,

    /// Common exporter configuration.
    #[serde(flatten, default)]
    pub common: ExporterConfig,
}

fn default_syslog_port() -> u16 {
    514
}

fn default_app_name() -> String {
    "vellaveto".to_string()
}

fn default_enterprise_id() -> String {
    "vellaveto".to_string()
}

fn default_include_json() -> bool {
    true
}

/// Maximum length of syslog host field.
const MAX_SYSLOG_HOST_LEN: usize = 255;

/// Maximum length of syslog app_name field (RFC 5424 Section 6.2.5: max 48 chars).
const MAX_SYSLOG_APP_NAME_LEN: usize = 48;

/// Maximum length of syslog enterprise_id field.
const MAX_SYSLOG_ENTERPRISE_ID_LEN: usize = 128;

impl SyslogConfig {
    /// Validate syslog configuration bounds.
    ///
    /// SECURITY (FIND-R216-001): Validates host, app_name, enterprise_id length and
    /// dangerous characters. Enterprise ID is validated against RFC 5424 SD-ID grammar
    /// (printable ASCII in the range [!-~], i.e., 0x21–0x7E, excluding '=', ']', '"', SP).
    /// SECURITY (FIND-R216-008): RFC 5424 SD-ID grammar enforcement on enterprise_id.
    pub fn validate(&self) -> Result<(), ExportError> {
        self.common.validate()?;

        if self.host.len() > MAX_SYSLOG_HOST_LEN {
            return Err(ExportError::Configuration(format!(
                "syslog host length {} exceeds maximum of {}",
                self.host.len(),
                MAX_SYSLOG_HOST_LEN,
            )));
        }
        if vellaveto_types::has_dangerous_chars(&self.host) {
            return Err(ExportError::Configuration(
                "syslog host contains control or Unicode format characters".to_string(),
            ));
        }

        if self.app_name.len() > MAX_SYSLOG_APP_NAME_LEN {
            return Err(ExportError::Configuration(format!(
                "syslog app_name length {} exceeds maximum of {}",
                self.app_name.len(),
                MAX_SYSLOG_APP_NAME_LEN,
            )));
        }
        if vellaveto_types::has_dangerous_chars(&self.app_name) {
            return Err(ExportError::Configuration(
                "syslog app_name contains control or Unicode format characters".to_string(),
            ));
        }

        if self.enterprise_id.is_empty() {
            return Err(ExportError::Configuration(
                "syslog enterprise_id must not be empty".to_string(),
            ));
        }
        if self.enterprise_id.len() > MAX_SYSLOG_ENTERPRISE_ID_LEN {
            return Err(ExportError::Configuration(format!(
                "syslog enterprise_id length {} exceeds maximum of {}",
                self.enterprise_id.len(),
                MAX_SYSLOG_ENTERPRISE_ID_LEN,
            )));
        }
        // RFC 5424 Section 6.3.2: SD-ID = SD-NAME
        // SD-NAME = 1*32PRINTUSASCII (but we only check character validity here,
        // length is checked above with a generous bound).
        // PRINTUSASCII = %d33-126 (i.e., '!' through '~'), excluding '=', SP, ']', '"'
        for ch in self.enterprise_id.chars() {
            if !(('\x21'..='\x7e').contains(&ch) && ch != '=' && ch != ']' && ch != '"') {
                return Err(ExportError::Configuration(format!(
                    "syslog enterprise_id contains invalid character '{ch}'; \
                     only printable ASCII [!-~] excluding '=', ']', '\"' are allowed per RFC 5424",
                )));
            }
        }

        Ok(())
    }
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: default_syslog_port(),
            protocol: SyslogProtocol::default(),
            facility: SyslogFacility::default(),
            app_name: default_app_name(),
            enterprise_id: default_enterprise_id(),
            include_json: default_include_json(),
            common: ExporterConfig::default(),
        }
    }
}

/// Syslog exporter implementing RFC 5424.
#[cfg(feature = "siem-exporters")]
pub struct SyslogExporter {
    config: SyslogConfig,
    hostname: String,
}

#[cfg(feature = "siem-exporters")]
impl SyslogExporter {
    /// Create a new syslog exporter.
    ///
    /// SECURITY (FIND-R216-001): Validates config at construction time.
    pub fn new(config: SyslogConfig) -> Result<Self, ExportError> {
        config.validate()?;

        if config.host.is_empty() {
            return Err(ExportError::Configuration(
                "Syslog host is required".to_string(),
            ));
        }

        let hostname = hostname::get()
            .ok()
            .and_then(|h: std::ffi::OsString| h.into_string().ok())
            .unwrap_or_else(|| "localhost".to_string());

        Ok(Self { config, hostname })
    }

    /// Extract verdict string and optional reason from Verdict enum.
    fn verdict_info(verdict: &vellaveto_types::Verdict) -> (&'static str, Option<&str>) {
        match verdict {
            vellaveto_types::Verdict::Allow => ("allow", None),
            vellaveto_types::Verdict::Deny { reason } => ("deny", Some(reason.as_str())),
            vellaveto_types::Verdict::RequireApproval { reason } => {
                ("require_approval", Some(reason.as_str()))
            }
            _ => ("unknown", None),
        }
    }

    /// Format an audit entry as RFC 5424 syslog message.
    fn format_rfc5424(&self, entry: &AuditEntry) -> String {
        let (verdict_str, reason) = Self::verdict_info(&entry.verdict);

        // Determine severity based on verdict
        let severity = match verdict_str {
            "deny" => SyslogSeverity::Warning,
            "allow" => SyslogSeverity::Info,
            "require_approval" => SyslogSeverity::Notice,
            _ => SyslogSeverity::Info,
        };

        // Calculate PRI = facility * 8 + severity
        let pri = (self.config.facility.as_u8() as u16) * 8 + (severity.as_u8() as u16);

        // Timestamp is already a String in ISO 8601 format
        let timestamp = &entry.timestamp;

        // Process ID
        let procid = std::process::id();

        // Message ID - use entry ID
        let msgid = &entry.id;

        // Build structured data (RFC 5424 Section 6.3)
        let sd = self.build_structured_data(entry, verdict_str, reason);

        // Build message body
        // GAP-Q04: Log serialization failures instead of silently returning empty.
        let msg = if self.config.include_json {
            serde_json::to_string(entry).unwrap_or_else(|e| {
                tracing::warn!(
                    entry_id = %entry.id,
                    error = %e,
                    "Failed to serialize audit entry for syslog export"
                );
                String::new()
            })
        } else {
            format!(
                "{} {} {} -> {}",
                verdict_str,
                entry.action.tool,
                entry.action.function,
                entry.action.target_paths.join(",")
            )
        };

        // RFC 5424 format:
        // <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
        format!(
            "<{}>1 {} {} {} {} {} {} {}",
            pri, timestamp, self.hostname, self.config.app_name, procid, msgid, sd, msg
        )
    }

    /// Build RFC 5424 structured data section.
    fn build_structured_data(
        &self,
        entry: &AuditEntry,
        verdict_str: &str,
        reason: Option<&str>,
    ) -> String {
        let eid = &self.config.enterprise_id;

        // Escape special characters in SD-PARAM values (RFC 5424 Section 6.3.3)
        let escape_sd_value = |s: &str| -> String {
            s.replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace(']', "\\]")
        };

        let verdict = escape_sd_value(verdict_str);
        let tool = escape_sd_value(&entry.action.tool);
        let function = escape_sd_value(&entry.action.function);

        // Primary structured data element
        let mut sd = format!(
            "[vellaveto@{} verdict=\"{}\" tool=\"{}\" function=\"{}\"]",
            eid, verdict, tool, function
        );

        // Add reason if present
        if let Some(r) = reason {
            let reason_escaped = escape_sd_value(r);
            sd.push_str(&format!("[reason@{} msg=\"{}\"]", eid, reason_escaped));
        }

        // Add target paths if present
        if !entry.action.target_paths.is_empty() {
            let paths = entry
                .action
                .target_paths
                .iter()
                .map(|p| escape_sd_value(p))
                .collect::<Vec<_>>()
                .join(",");
            sd.push_str(&format!("[paths@{} list=\"{}\"]", eid, paths));
        }

        // Add target domains if present
        if !entry.action.target_domains.is_empty() {
            let domains = entry
                .action
                .target_domains
                .iter()
                .map(|d| escape_sd_value(d))
                .collect::<Vec<_>>()
                .join(",");
            sd.push_str(&format!("[domains@{} list=\"{}\"]", eid, domains));
        }

        sd
    }

    /// Maximum syslog UDP message size in bytes.
    ///
    /// SECURITY (FIND-R46-009): RFC 5424 Section 6.1 recommends a minimum transport
    /// receiver buffer of 2048 bytes for UDP. Messages exceeding this limit are
    /// silently truncated by most syslog receivers, leading to data loss. We truncate
    /// on the sender side to 2048 bytes (respecting UTF-8 char boundaries) so that
    /// the message is always complete within the receiver's buffer.
    const MAX_SYSLOG_UDP_MESSAGE_SIZE: usize = 2048;

    /// Send a message via UDP.
    ///
    /// SECURITY (FIND-R46-009): Truncates messages to `MAX_SYSLOG_UDP_MESSAGE_SIZE`
    /// bytes to comply with RFC 5424 UDP transport recommendations.
    async fn send_udp(&self, message: &str) -> Result<(), ExportError> {
        use tokio::net::UdpSocket;

        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| ExportError::HttpError(format!("Failed to bind UDP socket: {}", e)))?;

        let addr = format!("{}:{}", self.config.host, self.config.port);

        // SECURITY (FIND-R46-009): Truncate to max UDP syslog message size.
        let send_bytes = if message.len() > Self::MAX_SYSLOG_UDP_MESSAGE_SIZE {
            let mut end = Self::MAX_SYSLOG_UDP_MESSAGE_SIZE;
            // Back up to a valid UTF-8 char boundary
            while end > 0 && !message.is_char_boundary(end) {
                end -= 1;
            }
            tracing::debug!(
                original_len = message.len(),
                truncated_len = end,
                "Syslog UDP message truncated to RFC 5424 recommended limit"
            );
            &message.as_bytes()[..end]
        } else {
            message.as_bytes()
        };

        socket
            .send_to(send_bytes, &addr)
            .await
            .map_err(|e| ExportError::HttpError(format!("Failed to send UDP: {}", e)))?;

        Ok(())
    }

    /// Send a message via TCP.
    ///
    /// SECURITY (FIND-R46-010): Known limitation — a new TCP connection is established
    /// for each message. This is inefficient for high-throughput deployments because:
    /// 1. TCP handshake overhead (~1.5 RTT per message)
    /// 2. Connection churn may trigger syslog server connection limits
    /// 3. TLS handshake cost (if TLS is used) is paid per message
    ///
    /// For production deployments with high audit event rates, consider:
    /// - Using UDP (fire-and-forget, suitable for local syslog collectors)
    /// - Using a syslog relay (rsyslog/syslog-ng) on localhost with TCP keepalive
    /// - Connection pooling (future enhancement: maintain a persistent TcpStream)
    async fn send_tcp(&self, message: &str) -> Result<(), ExportError> {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpStream;

        let addr = format!("{}:{}", self.config.host, self.config.port);
        let mut stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| ExportError::HttpError(format!("Failed to connect TCP: {}", e)))?;

        // RFC 5425: Octet-counting framing for TCP
        // Format: MSG-LEN SP SYSLOG-MSG
        let framed = format!("{} {}", message.len(), message);
        stream
            .write_all(framed.as_bytes())
            .await
            .map_err(|e| ExportError::HttpError(format!("Failed to write TCP: {}", e)))?;

        stream
            .flush()
            .await
            .map_err(|e| ExportError::HttpError(format!("Failed to flush TCP: {}", e)))?;

        Ok(())
    }
}

#[cfg(feature = "siem-exporters")]
#[async_trait]
impl SiemExporter for SyslogExporter {
    fn name(&self) -> &str {
        "syslog"
    }

    async fn export_batch(&self, entries: &[AuditEntry]) -> Result<(), ExportError> {
        for entry in entries {
            let message = self.format_rfc5424(entry);

            match self.config.protocol {
                SyslogProtocol::Udp => self.send_udp(&message).await?,
                SyslogProtocol::Tcp => self.send_tcp(&message).await?,
            }
        }

        tracing::debug!(
            exporter = "syslog",
            host = %self.config.host,
            count = entries.len(),
            "Exported batch to syslog"
        );

        Ok(())
    }

    async fn health_check(&self) -> Result<(), ExportError> {
        // For UDP, we can't really check health - just verify socket binding works
        // For TCP, attempt a connection
        match self.config.protocol {
            SyslogProtocol::Udp => {
                use tokio::net::UdpSocket;
                UdpSocket::bind("0.0.0.0:0")
                    .await
                    .map_err(|e| ExportError::Configuration(format!("UDP socket error: {}", e)))?;
                Ok(())
            }
            SyslogProtocol::Tcp => {
                use tokio::net::TcpStream;
                let addr = format!("{}:{}", self.config.host, self.config.port);
                TcpStream::connect(&addr)
                    .await
                    .map_err(|e| ExportError::Configuration(format!("TCP connect error: {}", e)))?;
                Ok(())
            }
        }
    }

    fn config(&self) -> &ExporterConfig {
        &self.config.common
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exporter_config_defaults() {
        let config = ExporterConfig::default();
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.flush_interval_secs, 5);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_backoff_secs, 1);
        assert_eq!(config.timeout_secs, 30);
    }

    #[test]
    fn test_splunk_config_defaults() {
        let config = SplunkConfig::default();
        assert_eq!(config.source, "vellaveto");
        assert_eq!(config.sourcetype, "vellaveto:audit");
        assert_eq!(config.token_env, Some("SPLUNK_HEC_TOKEN".to_string()));
    }

    #[cfg(feature = "siem-exporters")]
    #[test]
    fn test_splunk_exporter_requires_endpoint() {
        let config = SplunkConfig {
            endpoint: String::new(),
            token: Some("test-token".to_string()),
            ..Default::default()
        };
        let result = SplunkExporter::new(config);
        assert!(result.is_err());
    }

    #[cfg(feature = "siem-exporters")]
    #[test]
    fn test_splunk_exporter_requires_token() {
        let config = SplunkConfig {
            endpoint: "https://splunk:8088/services/collector".to_string(),
            token: None,
            token_env: None,
            ..Default::default()
        };
        let result = SplunkExporter::new(config);
        assert!(result.is_err());
    }

    #[cfg(feature = "siem-exporters")]
    #[test]
    fn test_webhook_exporter_requires_endpoint() {
        let config = WebhookConfig {
            endpoint: String::new(),
            auth_header: None,
            auth_header_env: None,
            headers: Default::default(),
            common: ExporterConfig::default(),
        };
        let result = WebhookExporter::new(config);
        assert!(result.is_err());
    }

    /// GAP-F05: Splunk exporter rejects non-HTTP URL schemes.
    #[cfg(feature = "siem-exporters")]
    #[test]
    fn test_gap_f05_splunk_rejects_non_http_scheme() {
        let config = SplunkConfig {
            endpoint: "ftp://splunk:8088/services/collector".to_string(),
            token: Some("test-token".to_string()),
            ..Default::default()
        };
        let result = SplunkExporter::new(config);
        assert!(result.is_err());
        let err = match result {
            Ok(_) => panic!("expected SplunkExporter::new to fail for non-http scheme"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("http://") || err.contains("https://"));
    }

    /// GAP-F05: Webhook (streaming) exporter rejects non-HTTP URL schemes.
    #[cfg(feature = "siem-exporters")]
    #[test]
    fn test_gap_f05_webhook_rejects_non_http_scheme() {
        let config = WebhookConfig {
            endpoint: "file:///etc/passwd".to_string(),
            auth_header: None,
            auth_header_env: None,
            headers: Default::default(),
            common: ExporterConfig::default(),
        };
        let result = WebhookExporter::new(config);
        assert!(result.is_err());
    }

    /// GAP-F05: Elasticsearch exporter rejects non-HTTP URL schemes.
    #[cfg(feature = "siem-exporters")]
    #[test]
    fn test_gap_f05_elasticsearch_rejects_non_http_scheme() {
        let config = ElasticsearchConfig {
            endpoint: "ftp://elasticsearch:9200".to_string(),
            ..Default::default()
        };
        let result = ElasticsearchExporter::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_syslog_config_defaults() {
        let config = SyslogConfig::default();
        assert_eq!(config.port, 514);
        assert_eq!(config.protocol, SyslogProtocol::Udp);
        assert_eq!(config.app_name, "vellaveto");
        assert!(config.include_json);
    }

    #[cfg(feature = "siem-exporters")]
    #[test]
    fn test_syslog_exporter_requires_host() {
        let config = SyslogConfig {
            host: String::new(),
            ..Default::default()
        };
        let result = SyslogExporter::new(config);
        assert!(result.is_err());
    }

    #[cfg(feature = "siem-exporters")]
    #[test]
    fn test_syslog_rfc5424_format() {
        use vellaveto_types::{Action, Verdict};

        let config = SyslogConfig {
            host: "localhost".to_string(),
            facility: SyslogFacility::Local0,
            app_name: "vellaveto-test".to_string(),
            enterprise_id: "12345".to_string(),
            include_json: false,
            ..Default::default()
        };
        let exporter = SyslogExporter::new(config).unwrap();

        let entry = AuditEntry {
            id: "test-id-123".to_string(),
            timestamp: "2024-01-15T10:30:00Z".to_string(),
            action: Action {
                tool: "file".to_string(),
                function: "read".to_string(),
                parameters: Default::default(),
                target_paths: vec!["/etc/passwd".to_string()],
                target_domains: vec![],
                resolved_ips: vec![],
            },
            verdict: Verdict::Deny {
                reason: "blocked path".to_string(),
            },
            metadata: Default::default(),
            sequence: 0,
            entry_hash: None,
            prev_hash: None,
            commitment: None,
            tenant_id: None,
            acis_envelope: None,
        };

        let message = exporter.format_rfc5424(&entry);

        // Verify RFC 5424 structure
        assert!(message.starts_with("<132>")); // PRI = 16*8 + 4 (Local0 + Warning)
        assert!(message.contains("vellaveto-test")); // APP-NAME
        assert!(message.contains("test-id-123")); // MSGID
        assert!(message.contains("[vellaveto@12345")); // Structured data
        assert!(message.contains("verdict=\"deny\"")); // SD param
        assert!(message.contains("tool=\"file\"")); // SD param
        assert!(message.contains("[reason@12345")); // Reason structured data
    }

    #[cfg(feature = "siem-exporters")]
    #[test]
    fn test_syslog_structured_data_escaping() {
        use vellaveto_types::{Action, Verdict};

        let config = SyslogConfig {
            host: "localhost".to_string(),
            enterprise_id: "test".to_string(),
            include_json: false,
            ..Default::default()
        };
        let exporter = SyslogExporter::new(config).unwrap();

        let entry = AuditEntry {
            id: "test".to_string(),
            timestamp: "2024-01-15T10:30:00Z".to_string(),
            action: Action {
                tool: "test\"tool".to_string(),    // Contains quote
                function: "func]tion".to_string(), // Contains bracket
                parameters: Default::default(),
                target_paths: vec!["/path\\with\\backslash".to_string()],
                target_domains: vec![],
                resolved_ips: vec![],
            },
            verdict: Verdict::Allow,
            metadata: Default::default(),
            sequence: 0,
            entry_hash: None,
            prev_hash: None,
            commitment: None,
            tenant_id: None,
            acis_envelope: None,
        };

        let message = exporter.format_rfc5424(&entry);

        // Verify escaping
        assert!(message.contains("tool=\"test\\\"tool\"")); // Quote escaped
        assert!(message.contains("function=\"func\\]tion\"")); // Bracket escaped
        assert!(message.contains("\\\\backslash")); // Backslash escaped
    }

    #[test]
    fn test_syslog_severity_mapping() {
        assert_eq!(SyslogSeverity::Emergency.as_u8(), 0);
        assert_eq!(SyslogSeverity::Warning.as_u8(), 4);
        assert_eq!(SyslogSeverity::Info.as_u8(), 6);
    }

    #[test]
    fn test_syslog_facility_values() {
        assert_eq!(SyslogFacility::Kern.as_u8(), 0);
        assert_eq!(SyslogFacility::Local0.as_u8(), 16);
        assert_eq!(SyslogFacility::Local7.as_u8(), 23);
        assert_eq!(SyslogFacility::Auth.as_u8(), 4);
    }

    // ── FIND-R216-001: SyslogConfig::validate() ──────────────────────────

    #[test]
    fn test_r216_001_syslog_config_validate_valid() {
        let config = SyslogConfig {
            host: "syslog.example.com".to_string(),
            app_name: "vellaveto".to_string(),
            enterprise_id: "12345".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_r216_001_syslog_config_validate_host_dangerous_chars() {
        let config = SyslogConfig {
            host: "syslog\x00.example.com".to_string(),
            enterprise_id: "12345".to_string(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("host"));
        assert!(err.contains("control"));
    }

    #[test]
    fn test_r216_001_syslog_config_validate_host_too_long() {
        let config = SyslogConfig {
            host: "a".repeat(256),
            enterprise_id: "12345".to_string(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("host length"));
    }

    #[test]
    fn test_r216_001_syslog_config_validate_app_name_dangerous_chars() {
        let config = SyslogConfig {
            host: "localhost".to_string(),
            app_name: "app\nname".to_string(),
            enterprise_id: "12345".to_string(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("app_name"));
    }

    #[test]
    fn test_r216_001_syslog_config_validate_app_name_too_long() {
        let config = SyslogConfig {
            host: "localhost".to_string(),
            app_name: "a".repeat(49),
            enterprise_id: "12345".to_string(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("app_name length"));
    }

    #[test]
    fn test_r216_001_syslog_config_validate_enterprise_id_empty() {
        let config = SyslogConfig {
            host: "localhost".to_string(),
            enterprise_id: String::new(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("enterprise_id must not be empty"));
    }

    #[test]
    fn test_r216_001_syslog_config_validate_enterprise_id_too_long() {
        let config = SyslogConfig {
            host: "localhost".to_string(),
            enterprise_id: "a".repeat(129),
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("enterprise_id length"));
    }

    /// FIND-R216-008: RFC 5424 SD-ID grammar rejects spaces in enterprise_id.
    #[test]
    fn test_r216_008_syslog_enterprise_id_rejects_space() {
        let config = SyslogConfig {
            host: "localhost".to_string(),
            enterprise_id: "bad id".to_string(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("invalid character"));
    }

    /// FIND-R216-008: RFC 5424 SD-ID grammar rejects '=' in enterprise_id.
    #[test]
    fn test_r216_008_syslog_enterprise_id_rejects_equals() {
        let config = SyslogConfig {
            host: "localhost".to_string(),
            enterprise_id: "bad=id".to_string(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("invalid character"));
    }

    /// FIND-R216-008: RFC 5424 SD-ID grammar rejects ']' in enterprise_id.
    #[test]
    fn test_r216_008_syslog_enterprise_id_rejects_bracket() {
        let config = SyslogConfig {
            host: "localhost".to_string(),
            enterprise_id: "bad]id".to_string(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("invalid character"));
    }

    /// FIND-R216-008: RFC 5424 SD-ID grammar rejects '"' in enterprise_id.
    #[test]
    fn test_r216_008_syslog_enterprise_id_rejects_quote() {
        let config = SyslogConfig {
            host: "localhost".to_string(),
            enterprise_id: "bad\"id".to_string(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("invalid character"));
    }

    /// FIND-R216-008: RFC 5424 SD-ID grammar rejects non-ASCII in enterprise_id.
    #[test]
    fn test_r216_008_syslog_enterprise_id_rejects_non_ascii() {
        let config = SyslogConfig {
            host: "localhost".to_string(),
            enterprise_id: "bad\u{00e9}id".to_string(), // e with acute accent
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("invalid character"));
    }

    /// FIND-R216-008: Valid enterprise_id with digits and dots passes.
    #[test]
    fn test_r216_008_syslog_enterprise_id_accepts_valid() {
        let config = SyslogConfig {
            host: "localhost".to_string(),
            enterprise_id: "12345.6789".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    // ── FIND-R216-005: has_dangerous_chars on string config fields ────────

    #[test]
    fn test_r216_005_splunk_endpoint_dangerous_chars() {
        let config = SplunkConfig {
            endpoint: "https://splunk\x00:8088".to_string(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("Splunk endpoint"));
    }

    #[test]
    fn test_r216_005_splunk_source_dangerous_chars() {
        let config = SplunkConfig {
            endpoint: "https://splunk:8088".to_string(),
            source: "bad\nsource".to_string(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("Splunk source"));
    }

    #[test]
    fn test_r216_005_splunk_sourcetype_dangerous_chars() {
        let config = SplunkConfig {
            endpoint: "https://splunk:8088".to_string(),
            sourcetype: "bad\rsource".to_string(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("Splunk sourcetype"));
    }

    #[test]
    fn test_r216_005_webhook_endpoint_dangerous_chars() {
        let config = WebhookConfig {
            endpoint: "https://hook\x00.example.com".to_string(),
            auth_header: None,
            auth_header_env: None,
            headers: Default::default(),
            common: ExporterConfig::default(),
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("Webhook endpoint"));
    }

    /// FIND-R216-009: Webhook header keys reject dangerous chars.
    #[test]
    fn test_r216_009_webhook_header_key_dangerous_chars() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Bad\x00Key".to_string(), "value".to_string());
        let config = WebhookConfig {
            endpoint: "https://hook.example.com".to_string(),
            auth_header: None,
            auth_header_env: None,
            headers,
            common: ExporterConfig::default(),
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("header key"));
    }

    /// FIND-R216-009: Webhook header values reject dangerous chars.
    #[test]
    fn test_r216_009_webhook_header_value_dangerous_chars() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Custom".to_string(), "bad\nvalue".to_string());
        let config = WebhookConfig {
            endpoint: "https://hook.example.com".to_string(),
            auth_header: None,
            auth_header_env: None,
            headers,
            common: ExporterConfig::default(),
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("header value"));
    }

    #[test]
    fn test_r216_005_datadog_endpoint_dangerous_chars() {
        let config = DatadogConfig {
            endpoint: "https://intake\x00.datadoghq.com".to_string(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("Datadog endpoint"));
    }

    #[test]
    fn test_r216_005_datadog_service_dangerous_chars() {
        let config = DatadogConfig {
            service: "bad\nservice".to_string(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("Datadog service"));
    }

    #[test]
    fn test_r216_005_datadog_source_dangerous_chars() {
        let config = DatadogConfig {
            source: "bad\rsource".to_string(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("Datadog source"));
    }

    #[test]
    fn test_r216_005_datadog_tag_dangerous_chars() {
        let config = DatadogConfig {
            tags: vec!["bad\x00tag".to_string()],
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("tag contains"));
    }

    #[test]
    fn test_r224_004_datadog_endpoint_rejects_non_http_scheme() {
        // SECURITY (FIND-R224-004): SSRF prevention via URL scheme validation.
        let config = DatadogConfig {
            endpoint: "file:///etc/shadow".to_string(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains("http://") || err.contains("https://"),
            "Expected scheme validation error, got: {err}"
        );
    }

    #[test]
    fn test_r224_004_datadog_endpoint_accepts_https() {
        let config = DatadogConfig {
            endpoint: "https://logs.datadoghq.com/api/v2/logs".to_string(),
            ..Default::default()
        };
        // Should not fail on scheme validation
        let result = config.validate();
        assert!(result.is_ok(), "HTTPS endpoint should be valid: {result:?}");
    }

    #[test]
    fn test_r216_005_elasticsearch_endpoint_dangerous_chars() {
        let config = ElasticsearchConfig {
            endpoint: "https://es\x00:9200".to_string(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("Elasticsearch endpoint"));
    }

    #[test]
    fn test_r216_005_elasticsearch_index_dangerous_chars() {
        let config = ElasticsearchConfig {
            index: "bad\nindex".to_string(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("Elasticsearch index"));
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 8: ExporterConfig validation boundary tests
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_exporter_config_validate_batch_size_zero_rejected() {
        let config = ExporterConfig {
            batch_size: 0,
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("batch_size"), "got: {err}");
    }

    #[test]
    fn test_exporter_config_validate_batch_size_over_max_rejected() {
        let config = ExporterConfig {
            batch_size: 10_001,
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("batch_size"), "got: {err}");
    }

    #[test]
    fn test_exporter_config_validate_flush_interval_zero_rejected() {
        let config = ExporterConfig {
            flush_interval_secs: 0,
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("flush_interval_secs"), "got: {err}");
    }

    #[test]
    fn test_exporter_config_validate_flush_interval_over_max_rejected() {
        let config = ExporterConfig {
            flush_interval_secs: 3601,
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("flush_interval_secs"), "got: {err}");
    }

    #[test]
    fn test_exporter_config_validate_max_retries_over_rejected() {
        let config = ExporterConfig {
            max_retries: 21,
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("max_retries"), "got: {err}");
    }

    #[test]
    fn test_exporter_config_validate_max_retries_zero_accepted() {
        let config = ExporterConfig {
            max_retries: 0,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_exporter_config_validate_retry_backoff_zero_rejected() {
        let config = ExporterConfig {
            retry_backoff_secs: 0,
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("retry_backoff_secs"), "got: {err}");
    }

    #[test]
    fn test_exporter_config_validate_retry_backoff_over_max_rejected() {
        let config = ExporterConfig {
            retry_backoff_secs: 301,
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("retry_backoff_secs"), "got: {err}");
    }

    #[test]
    fn test_exporter_config_validate_timeout_zero_rejected() {
        let config = ExporterConfig {
            timeout_secs: 0,
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("timeout_secs"), "got: {err}");
    }

    #[test]
    fn test_exporter_config_validate_timeout_over_max_rejected() {
        let config = ExporterConfig {
            timeout_secs: 301,
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("timeout_secs"), "got: {err}");
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 8: Debug redaction tests (secrets must not leak)
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_splunk_config_debug_redacts_token() {
        let config = SplunkConfig {
            token: Some("super-secret-hec-token".to_string()),
            ..Default::default()
        };
        let debug_output = format!("{config:?}");
        assert!(
            !debug_output.contains("super-secret-hec-token"),
            "Token leaked in Debug output: {debug_output}"
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug should contain [REDACTED]: {debug_output}"
        );
    }

    #[test]
    fn test_datadog_config_debug_redacts_api_key() {
        let config = DatadogConfig {
            api_key: Some("dd-secret-api-key-123".to_string()),
            ..Default::default()
        };
        let debug_output = format!("{config:?}");
        assert!(
            !debug_output.contains("dd-secret-api-key-123"),
            "API key leaked in Debug output: {debug_output}"
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug should contain [REDACTED]: {debug_output}"
        );
    }

    #[test]
    fn test_elasticsearch_config_debug_redacts_api_key() {
        let config = ElasticsearchConfig {
            api_key: Some("es-secret-api-key-456".to_string()),
            ..Default::default()
        };
        let debug_output = format!("{config:?}");
        assert!(
            !debug_output.contains("es-secret-api-key-456"),
            "API key leaked in Debug output: {debug_output}"
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug should contain [REDACTED]: {debug_output}"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 8: Webhook config bounds (headers count / length)
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_webhook_config_validate_headers_count_at_max() {
        let mut headers = std::collections::HashMap::new();
        for i in 0..50 {
            headers.insert(format!("X-Header-{i}"), format!("value-{i}"));
        }
        let config = WebhookConfig {
            endpoint: "https://hook.example.com".to_string(),
            auth_header: None,
            auth_header_env: None,
            headers,
            common: ExporterConfig::default(),
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_webhook_config_validate_headers_count_exceeds_max() {
        let mut headers = std::collections::HashMap::new();
        for i in 0..51 {
            headers.insert(format!("X-Header-{i}"), format!("value-{i}"));
        }
        let config = WebhookConfig {
            endpoint: "https://hook.example.com".to_string(),
            auth_header: None,
            auth_header_env: None,
            headers,
            common: ExporterConfig::default(),
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("headers count"), "got: {err}");
    }

    #[test]
    fn test_webhook_config_validate_header_key_too_long() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-".to_string() + &"k".repeat(255), "value".to_string());
        let config = WebhookConfig {
            endpoint: "https://hook.example.com".to_string(),
            auth_header: None,
            auth_header_env: None,
            headers,
            common: ExporterConfig::default(),
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("header key length"), "got: {err}");
    }

    #[test]
    fn test_webhook_config_validate_header_value_too_long() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("X-Custom".to_string(), "v".repeat(8193));
        let config = WebhookConfig {
            endpoint: "https://hook.example.com".to_string(),
            auth_header: None,
            auth_header_env: None,
            headers,
            common: ExporterConfig::default(),
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("header value length"), "got: {err}");
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 8: Datadog config validation (tags, defaults)
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_datadog_config_defaults() {
        let config = DatadogConfig::default();
        assert_eq!(config.service, "vellaveto");
        assert_eq!(config.source, "vellaveto");
        assert_eq!(config.api_key_env, "DD_API_KEY");
        assert!(config.tags.is_empty());
        assert!(config.endpoint.starts_with("https://"));
    }

    #[test]
    fn test_datadog_config_validate_tag_count_exceeds_max() {
        let config = DatadogConfig {
            tags: (0..101).map(|i| format!("tag:{i}")).collect(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("tags count"), "got: {err}");
    }

    #[test]
    fn test_datadog_config_validate_tag_too_long() {
        let config = DatadogConfig {
            tags: vec!["t".repeat(257)],
            ..Default::default()
        };
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("tag length"), "got: {err}");
    }

    #[test]
    fn test_datadog_config_validate_tag_at_max_length() {
        let config = DatadogConfig {
            tags: vec!["t".repeat(256)],
            ..Default::default()
        };
        // tag at exactly max length should pass (only tags > MAX_TAG_LEN fail)
        assert!(config.validate().is_ok());
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 8: Elasticsearch config (defaults, validation)
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_elasticsearch_config_defaults() {
        let config = ElasticsearchConfig::default();
        assert_eq!(config.index, "vellaveto-audit");
        assert!(config.endpoint.is_empty());
        assert!(config.username.is_none());
        assert!(config.password_env.is_none());
        assert!(config.api_key.is_none());
        assert!(config.api_key_env.is_none());
    }

    #[cfg(feature = "siem-exporters")]
    #[test]
    fn test_elasticsearch_exporter_requires_endpoint() {
        let config = ElasticsearchConfig {
            endpoint: String::new(),
            ..Default::default()
        };
        let result = ElasticsearchExporter::new(config);
        match result {
            Err(e) => {
                let err = e.to_string();
                assert!(err.contains("endpoint not configured"), "got: {err}");
            }
            Ok(_) => panic!("Expected error for empty endpoint"),
        }
    }

    #[cfg(feature = "siem-exporters")]
    #[test]
    fn test_elasticsearch_exporter_accepts_valid_https() {
        let config = ElasticsearchConfig {
            endpoint: "https://localhost:9200".to_string(),
            ..Default::default()
        };
        assert!(ElasticsearchExporter::new(config).is_ok());
    }

    #[cfg(feature = "siem-exporters")]
    #[test]
    fn test_splunk_exporter_accepts_http_endpoint() {
        // http:// scheme is valid for local/dev environments
        let config = SplunkConfig {
            endpoint: "http://localhost:8088/services/collector".to_string(),
            token: Some("test-token".to_string()),
            ..Default::default()
        };
        let result = SplunkExporter::new(config);
        assert!(result.is_ok());
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 8: Splunk format_events tests
    // ═══════════════════════════════════════════════════════════════

    #[cfg(feature = "siem-exporters")]
    #[test]
    fn test_splunk_format_events_produces_valid_json() {
        let config = SplunkConfig {
            endpoint: "https://splunk:8088/services/collector".to_string(),
            token: Some("test-token".to_string()),
            index: Some("test-index".to_string()),
            source: "test-source".to_string(),
            ..Default::default()
        };
        let exporter = SplunkExporter::new(config).unwrap();

        let entry = AuditEntry {
            id: "entry-1".to_string(),
            timestamp: "2026-03-01T12:00:00Z".to_string(),
            action: vellaveto_types::Action {
                tool: "fs".to_string(),
                function: "read".to_string(),
                parameters: Default::default(),
                target_paths: vec!["/tmp/test".to_string()],
                target_domains: vec![],
                resolved_ips: vec![],
            },
            verdict: vellaveto_types::Verdict::Allow,
            metadata: serde_json::json!({}),
            sequence: 1,
            entry_hash: None,
            prev_hash: None,
            commitment: None,
            tenant_id: None,
            acis_envelope: None,
        };

        let output = exporter.format_events(&[entry]).unwrap();
        // Each entry becomes one JSON object in the output
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed.get("time").is_some());
        assert_eq!(parsed["source"], "test-source");
        assert_eq!(parsed["index"], "test-index");
        assert!(parsed.get("event").is_some());
    }

    #[cfg(feature = "siem-exporters")]
    #[test]
    fn test_splunk_format_events_empty_batch() {
        let config = SplunkConfig {
            endpoint: "https://splunk:8088/services/collector".to_string(),
            token: Some("test-token".to_string()),
            ..Default::default()
        };
        let exporter = SplunkExporter::new(config).unwrap();
        let output = exporter.format_events(&[]).unwrap();
        assert!(output.is_empty());
    }

    #[cfg(feature = "siem-exporters")]
    #[test]
    fn test_splunk_format_events_bad_timestamp_uses_fallback() {
        let config = SplunkConfig {
            endpoint: "https://splunk:8088/services/collector".to_string(),
            token: Some("test-token".to_string()),
            ..Default::default()
        };
        let exporter = SplunkExporter::new(config).unwrap();

        let entry = AuditEntry {
            id: "entry-bad-ts".to_string(),
            timestamp: "not-a-timestamp".to_string(),
            action: vellaveto_types::Action {
                tool: "test".to_string(),
                function: "run".to_string(),
                parameters: Default::default(),
                target_paths: vec![],
                target_domains: vec![],
                resolved_ips: vec![],
            },
            verdict: vellaveto_types::Verdict::Allow,
            metadata: serde_json::json!({}),
            sequence: 0,
            entry_hash: None,
            prev_hash: None,
            commitment: None,
            tenant_id: None,
            acis_envelope: None,
        };

        // Should not fail even with bad timestamp, uses fallback to now()
        let output = exporter.format_events(&[entry]).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let time_val = parsed["time"].as_f64().unwrap();
        assert!(time_val > 0.0, "fallback timestamp should be positive");
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 8: Syslog verdict_info coverage
    // ═══════════════════════════════════════════════════════════════

    #[cfg(feature = "siem-exporters")]
    #[test]
    fn test_syslog_verdict_info_allow() {
        let (verdict_str, reason) = SyslogExporter::verdict_info(&vellaveto_types::Verdict::Allow);
        assert_eq!(verdict_str, "allow");
        assert!(reason.is_none());
    }

    #[cfg(feature = "siem-exporters")]
    #[test]
    fn test_syslog_verdict_info_deny() {
        let verdict = vellaveto_types::Verdict::Deny {
            reason: "policy violation".to_string(),
        };
        let (verdict_str, reason) = SyslogExporter::verdict_info(&verdict);
        assert_eq!(verdict_str, "deny");
        assert_eq!(reason, Some("policy violation"));
    }

    #[cfg(feature = "siem-exporters")]
    #[test]
    fn test_syslog_verdict_info_require_approval() {
        let verdict = vellaveto_types::Verdict::RequireApproval {
            reason: "needs review".to_string(),
        };
        let (verdict_str, reason) = SyslogExporter::verdict_info(&verdict);
        assert_eq!(verdict_str, "require_approval");
        assert_eq!(reason, Some("needs review"));
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 8: Syslog RFC 5424 PRI calculation
    // ═══════════════════════════════════════════════════════════════

    #[cfg(feature = "siem-exporters")]
    #[test]
    fn test_syslog_rfc5424_pri_allow_is_info() {
        let config = SyslogConfig {
            host: "localhost".to_string(),
            facility: SyslogFacility::Auth,
            enterprise_id: "test".to_string(),
            include_json: false,
            ..Default::default()
        };
        let exporter = SyslogExporter::new(config).unwrap();

        let entry = AuditEntry {
            id: "test".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            action: vellaveto_types::Action {
                tool: "fs".to_string(),
                function: "read".to_string(),
                parameters: Default::default(),
                target_paths: vec![],
                target_domains: vec![],
                resolved_ips: vec![],
            },
            verdict: vellaveto_types::Verdict::Allow,
            metadata: Default::default(),
            sequence: 0,
            entry_hash: None,
            prev_hash: None,
            commitment: None,
            tenant_id: None,
            acis_envelope: None,
        };

        let msg = exporter.format_rfc5424(&entry);
        // Auth=4, Info=6, PRI = 4*8 + 6 = 38
        assert!(msg.starts_with("<38>"), "Expected PRI 38, got: {msg}");
    }

    // ═══════════════════════════════════════════════════════════════
    // Phase 8: Syslog domain structured data with domains/paths
    // ═══════════════════════════════════════════════════════════════

    #[cfg(feature = "siem-exporters")]
    #[test]
    fn test_syslog_rfc5424_includes_domains_structured_data() {
        let config = SyslogConfig {
            host: "localhost".to_string(),
            enterprise_id: "test".to_string(),
            include_json: false,
            ..Default::default()
        };
        let exporter = SyslogExporter::new(config).unwrap();

        let entry = AuditEntry {
            id: "test".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            action: vellaveto_types::Action {
                tool: "http".to_string(),
                function: "get".to_string(),
                parameters: Default::default(),
                target_paths: vec!["/api/data".to_string()],
                target_domains: vec!["example.com".to_string(), "api.example.com".to_string()],
                resolved_ips: vec![],
            },
            verdict: vellaveto_types::Verdict::Allow,
            metadata: Default::default(),
            sequence: 0,
            entry_hash: None,
            prev_hash: None,
            commitment: None,
            tenant_id: None,
            acis_envelope: None,
        };

        let msg = exporter.format_rfc5424(&entry);
        assert!(msg.contains("[paths@test"), "Should have paths SD: {msg}");
        assert!(
            msg.contains("[domains@test"),
            "Should have domains SD: {msg}"
        );
        assert!(msg.contains("example.com"), "Domain missing: {msg}");
    }
}
