// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Centralized audit store configuration (Phase 43).
//!
//! Controls optional dual-write to PostgreSQL and query backend selection.

use serde::{Deserialize, Serialize};
use vellaveto_types::AuditStoreBackend;

/// Maximum connection pool size.
pub const MAX_POOL_SIZE: u32 = 100;

/// Maximum sink buffer (mpsc channel capacity).
pub const MAX_SINK_BUFFER_SIZE: usize = 10_000;

/// Maximum flush interval (1 minute).
pub const MAX_FLUSH_INTERVAL_MS: u64 = 60_000;

/// Maximum batch insert size.
pub const MAX_BATCH_INSERT_SIZE: usize = 1_000;

/// Maximum connect timeout (seconds).
pub const MAX_CONNECT_TIMEOUT_SECS: u64 = 60;

/// Maximum table name length (SQL identifier).
const MAX_TABLE_NAME_LEN: usize = 128;

/// Maximum database URL length (prevents OOM from excessively long URLs).
const MAX_DATABASE_URL_LEN: usize = 2048;

/// Configuration for the centralized audit store.
///
/// When `enabled` is false (default), no centralized store is used and
/// all audit data is read from the local JSONL file. When enabled with
/// `backend: postgres`, entries are dual-written to PostgreSQL via an
/// async mpsc channel for structured querying.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditStoreConfig {
    /// Whether the centralized audit store is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Backend type for the centralized store.
    #[serde(default)]
    pub backend: AuditStoreBackend,

    /// PostgreSQL connection URL (required when backend is `postgres`).
    /// Must start with `postgres://` or `postgresql://`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database_url: Option<String>,

    /// Connection pool size (1–100, default 5).
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,

    /// PostgreSQL table name (alphanumeric + underscore only, default `vellaveto_audit_entries`).
    #[serde(default = "default_table_name")]
    pub table_name: String,

    /// Whether to auto-create the table on startup (default true).
    #[serde(default = "crate::default_true")]
    pub auto_migrate: bool,

    /// mpsc channel buffer size for the background writer (1–10000, default 1000).
    #[serde(default = "default_sink_buffer_size")]
    pub sink_buffer_size: usize,

    /// Flush interval in milliseconds for the background writer (1–60000, default 1000).
    #[serde(default = "default_flush_interval_ms")]
    pub flush_interval_ms: u64,

    /// Batch insert size for the background writer (1–1000, default 100).
    #[serde(default = "default_batch_insert_size")]
    pub batch_insert_size: usize,

    /// Connection timeout in seconds (1–60, default 5).
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,

    /// Whether a sink write failure is fatal to the audit write.
    ///
    /// When true, a failed sink write makes `log_entry` return an error instead
    /// of succeeding on the strength of the file log alone. It does **not** by
    /// itself deny the request — whether an audit failure denies is
    /// [`AuditConfig::strict_mode`](crate::AuditConfig::strict_mode). The two
    /// compose: this decides what counts as an audit failure, strict mode
    /// decides what a failure costs. Setting this alone surfaces the error to
    /// callers, who log it and continue.
    ///
    /// Default false — the file log is the source of truth, so sink failures
    /// are logged as warnings and the entry is still persisted to disk.
    #[serde(default)]
    pub sink_failure_fatal: bool,
}

fn default_pool_size() -> u32 {
    5
}

fn default_table_name() -> String {
    "vellaveto_audit_entries".to_string()
}

fn default_sink_buffer_size() -> usize {
    1_000
}

fn default_flush_interval_ms() -> u64 {
    1_000
}

fn default_batch_insert_size() -> usize {
    100
}

fn default_connect_timeout_secs() -> u64 {
    5
}

impl Default for AuditStoreConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: AuditStoreBackend::default(),
            database_url: None,
            pool_size: default_pool_size(),
            table_name: default_table_name(),
            auto_migrate: true,
            sink_buffer_size: default_sink_buffer_size(),
            flush_interval_ms: default_flush_interval_ms(),
            batch_insert_size: default_batch_insert_size(),
            connect_timeout_secs: default_connect_timeout_secs(),
            sink_failure_fatal: false,
        }
    }
}

/// SECURITY (FIND-R157-001): Custom Debug impl redacts `database_url` which may
/// contain PostgreSQL credentials (username/password in connection string).
impl std::fmt::Debug for AuditStoreConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditStoreConfig")
            .field("enabled", &self.enabled)
            .field("backend", &self.backend)
            .field(
                "database_url",
                &self.database_url.as_ref().map(|_| "[REDACTED]"),
            )
            .field("pool_size", &self.pool_size)
            .field("table_name", &self.table_name)
            .field("auto_migrate", &self.auto_migrate)
            .field("sink_buffer_size", &self.sink_buffer_size)
            .field("flush_interval_ms", &self.flush_interval_ms)
            .field("batch_insert_size", &self.batch_insert_size)
            .field("connect_timeout_secs", &self.connect_timeout_secs)
            .field("sink_failure_fatal", &self.sink_failure_fatal)
            .finish()
    }
}

impl AuditStoreConfig {
    /// Validate configuration.
    ///
    /// SECURITY (FIND-R203-003 + FIND-R203-005): All field-level checks
    /// (SSRF on database_url, table_name charset, and numeric bounds) run
    /// unconditionally regardless of the `enabled` flag. A config that is
    /// disabled today may be enabled later without re-validation, so invalid
    /// values must be caught at load time.
    pub fn validate(&self) -> Result<(), String> {
        // ── Unconditional database_url checks ──────────────────────────────────
        // Runs whenever a database_url is present, regardless of `enabled`.
        if let Some(ref url) = self.database_url {
            // SECURITY (FIND-R198-003): Length bound prevents OOM on oversized URLs.
            if url.len() > MAX_DATABASE_URL_LEN {
                return Err(format!(
                    "audit_store.database_url length {} exceeds maximum {}",
                    url.len(),
                    MAX_DATABASE_URL_LEN
                ));
            }
            if vellaveto_types::has_dangerous_chars(url.trim()) {
                return Err(
                    "audit_store.database_url contains control or format characters".to_string(),
                );
            }

            // SECURITY (FIND-R203-003): SSRF host validation runs unconditionally
            // when a database_url is present. Disabled configs may be enabled later
            // without re-validation, so private-IP URLs must be caught now.
            let trimmed = url.trim();
            if !trimmed.is_empty()
                && (trimmed.starts_with("postgres://") || trimmed.starts_with("postgresql://"))
            {
                let after_scheme = trimmed
                    .strip_prefix("postgres://")
                    .or_else(|| trimmed.strip_prefix("postgresql://"))
                    .unwrap_or_default();
                // Host is after the last `@` (to skip userinfo) and before `/` or end.
                let host_and_rest = after_scheme
                    .rsplit_once('@')
                    .map(|(_, h)| h)
                    .unwrap_or(after_scheme);
                let host_port = host_and_rest.split('/').next().unwrap_or("");
                // Strip port suffix; handle IPv6 [::1]:5432 bracket notation.
                let host = if host_port.starts_with('[') {
                    host_port
                        .find(']')
                        .map(|i| &host_port[1..i])
                        .unwrap_or(host_port)
                } else {
                    host_port
                        .rsplit_once(':')
                        .map(|(h, _)| h)
                        .unwrap_or(host_port)
                };
                let host_lower = host.to_ascii_lowercase();
                if host_lower == "localhost"
                    || host_lower == "::1"
                    || host_lower == "0.0.0.0"
                    || host_lower == "metadata.google.internal"
                {
                    return Err(format!(
                        "audit_store.database_url host '{host}' is a private/loopback address"
                    ));
                }
                // SECURITY (FIND-R200-007): Reject percent-encoded hostnames that
                // could bypass text-based hostname checks after URL decoding.
                if host.contains('%') {
                    return Err(format!(
                        "audit_store.database_url host '{host}' contains percent-encoding"
                    ));
                }
                // Check IPv4 private/loopback ranges.
                if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
                    if ip.is_loopback()
                        || ip.is_private()
                        || ip.is_link_local()
                        || ip.is_unspecified()
                    {
                        return Err(format!(
                            "audit_store.database_url host '{host}' is a private/loopback address"
                        ));
                    }
                    // Cloud metadata endpoint 169.254.169.254.
                    if ip.octets()[0] == 169 && ip.octets()[1] == 254 {
                        return Err(format!(
                            "audit_store.database_url host '{host}' is a link-local/metadata address"
                        ));
                    }
                }
                if let Ok(ip6) = host.parse::<std::net::Ipv6Addr>() {
                    if ip6.is_loopback() || ip6.is_unspecified() {
                        return Err(format!(
                            "audit_store.database_url host '{host}' is a private/loopback address"
                        ));
                    }
                    // SECURITY (FIND-R200-001): Check IPv6-mapped IPv4 addresses
                    // (e.g. ::ffff:127.0.0.1) which embed IPv4 addresses inside IPv6.
                    if let Some(ipv4) = ip6.to_ipv4_mapped() {
                        if ipv4.is_loopback()
                            || ipv4.is_private()
                            || ipv4.is_link_local()
                            || ipv4.is_unspecified()
                        {
                            return Err(format!(
                                "audit_store.database_url host '{host}' is a private/loopback address (IPv6-mapped IPv4)"
                            ));
                        }
                    }
                    // SECURITY (FIND-R200-001): Reject IPv6 unique-local (fc00::/7)
                    // and link-local (fe80::/10) addresses.
                    let segments = ip6.segments();
                    if (segments[0] & 0xfe00) == 0xfc00 {
                        return Err(format!(
                            "audit_store.database_url host '{host}' is an IPv6 unique-local address"
                        ));
                    }
                    if (segments[0] & 0xffc0) == 0xfe80 {
                        return Err(format!(
                            "audit_store.database_url host '{host}' is an IPv6 link-local address"
                        ));
                    }
                }
            }
        }

        // ── Unconditional table_name charset check ─────────────────────────────
        // SECURITY (FIND-R198-005): Validate charset even when disabled.
        if !self
            .table_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(
                "audit_store.table_name must contain only alphanumeric characters and underscores"
                    .to_string(),
            );
        }

        // ── Unconditional numeric bounds checks ────────────────────────────────
        // SECURITY (FIND-R203-005): Reject out-of-range values regardless of the
        // enabled flag so that misconfigured-but-disabled configs fail fast at
        // config load time rather than silently at enable time.

        // Pool size bounds.
        if self.pool_size == 0 || self.pool_size > MAX_POOL_SIZE {
            return Err(format!(
                "audit_store.pool_size must be in [1, {}], got {}",
                MAX_POOL_SIZE, self.pool_size
            ));
        }

        // Sink buffer size bounds.
        if self.sink_buffer_size == 0 || self.sink_buffer_size > MAX_SINK_BUFFER_SIZE {
            return Err(format!(
                "audit_store.sink_buffer_size must be in [1, {}], got {}",
                MAX_SINK_BUFFER_SIZE, self.sink_buffer_size
            ));
        }

        // Flush interval bounds.
        if self.flush_interval_ms == 0 || self.flush_interval_ms > MAX_FLUSH_INTERVAL_MS {
            return Err(format!(
                "audit_store.flush_interval_ms must be in [1, {}], got {}",
                MAX_FLUSH_INTERVAL_MS, self.flush_interval_ms
            ));
        }

        // Batch insert size bounds.
        if self.batch_insert_size == 0 || self.batch_insert_size > MAX_BATCH_INSERT_SIZE {
            return Err(format!(
                "audit_store.batch_insert_size must be in [1, {}], got {}",
                MAX_BATCH_INSERT_SIZE, self.batch_insert_size
            ));
        }

        // Connect timeout bounds.
        if self.connect_timeout_secs == 0 || self.connect_timeout_secs > MAX_CONNECT_TIMEOUT_SECS {
            return Err(format!(
                "audit_store.connect_timeout_secs must be in [1, {}], got {}",
                MAX_CONNECT_TIMEOUT_SECS, self.connect_timeout_secs
            ));
        }

        // ── enabled=false early return ─────────────────────────────────────────
        // All field-level validation above has already run unconditionally.
        // The remaining checks (database_url presence/scheme/empty and
        // table_name emptiness/length/digit-start/pure-underscore) only apply
        // when the store is actually active.
        if !self.enabled {
            return Ok(());
        }

        // ── enabled-only checks ────────────────────────────────────────────────

        // Backend-specific validation: database URL is required and must use a
        // valid scheme. Note: SSRF host validation was already done unconditionally
        // in the URL block above.
        if self.backend == AuditStoreBackend::Postgres {
            match &self.database_url {
                None => {
                    return Err(
                        "audit_store.database_url is required when backend is postgres".to_string(),
                    );
                }
                Some(url) => {
                    let trimmed = url.trim();
                    if trimmed.is_empty() {
                        return Err("audit_store.database_url must not be empty".to_string());
                    }
                    if !trimmed.starts_with("postgres://") && !trimmed.starts_with("postgresql://")
                    {
                        return Err(
                            "audit_store.database_url must start with postgres:// or postgresql://"
                                .to_string(),
                        );
                    }
                }
            }
        }

        // Table name: full validation (empty / length / digit-start / pure-underscore)
        // only when enabled. Charset was already checked unconditionally above.
        if self.table_name.is_empty() {
            return Err("audit_store.table_name must not be empty".to_string());
        }
        if self.table_name.len() > MAX_TABLE_NAME_LEN {
            return Err(format!(
                "audit_store.table_name length {} exceeds maximum {}",
                self.table_name.len(),
                MAX_TABLE_NAME_LEN
            ));
        }
        // SECURITY: Reject table names starting with digits (invalid SQL identifier).
        if self.table_name.starts_with(|c: char| c.is_ascii_digit()) {
            return Err("audit_store.table_name must not start with a digit".to_string());
        }
        // SECURITY (FIND-R202-010): Reject pure-underscore identifiers.
        if self.table_name.chars().all(|c| c == '_') {
            return Err(
                "audit_store.table_name must contain at least one alphanumeric character"
                    .to_string(),
            );
        }

        Ok(())
    }
}
