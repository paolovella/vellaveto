// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

pub mod dashboard;
pub mod dpop;
pub mod iam;
pub mod idempotency;
pub mod jit;
pub mod metrics;
pub mod observability;
pub mod opa;
pub mod policy_lifecycle;
pub mod rbac;
pub mod routes;
pub mod setup_wizard;
#[cfg(feature = "opentelemetry")]
pub mod telemetry;
pub mod tenant;
pub mod threat_intel;
pub mod tls;
pub mod usage_tracker;
mod verified_approval_id;

/// Re-export for fuzz testing — not part of the public API.
#[doc(hidden)]
pub use routes::scan_params_for_targets;

use arc_swap::ArcSwap;
use governor::clock::Clock;
use governor::{Quota, RateLimiter};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use vellaveto_approval::{ApprovalContainmentContext, ApprovalStore};
use vellaveto_audit::AuditLogger;
use vellaveto_config::PolicyConfig;
use vellaveto_engine::PolicyEngine;
use vellaveto_mcp::mediation::build_secondary_acis_envelope;
use vellaveto_types::acis::DecisionOrigin;
use vellaveto_types::{Policy, Verdict};

// Phase 1 & 2 security managers
use vellaveto_engine::circuit_breaker::CircuitBreakerManager;
use vellaveto_engine::deputy::DeputyValidator;
use vellaveto_mcp::auth_level::AuthLevelTracker;
use vellaveto_mcp::sampling_detector::SamplingDetector;
use vellaveto_mcp::schema_poisoning::SchemaLineageTracker;
use vellaveto_mcp::shadow_agent::ShadowAgentDetector;
use vellaveto_mcp::task_state::TaskStateManager;

/// Per-category rate limiters using governor.
///
/// Each category can independently be enabled (Some) or disabled (None).
/// When enabled, the limiter enforces a global requests-per-second cap.
///
/// ## Priority Order
/// Rate limits are checked in this order (first match wins):
/// 1. Endpoint-specific limits (path prefix match)
/// 2. Category limits (evaluate, admin, readonly based on method/path)
/// 3. Per-IP limits (if configured)
/// 4. Per-principal limits (if configured)
pub struct RateLimits {
    pub evaluate: Option<governor::DefaultDirectRateLimiter>,
    pub admin: Option<governor::DefaultDirectRateLimiter>,
    pub readonly: Option<governor::DefaultDirectRateLimiter>,
    pub per_ip: Option<PerIpRateLimiter>,
    pub per_principal: Option<PerKeyRateLimiter>,
    /// Per-endpoint rate limits. Keys are path prefixes (e.g., "/api/evaluate").
    /// Takes priority over category-based limits.
    pub endpoint_limits: std::collections::HashMap<String, governor::DefaultDirectRateLimiter>,
}

/// Retry-After value (seconds) returned when the rate limiter is at capacity
/// and cannot track new IPs/keys. Asks the client to back off.
const CAPACITY_EXCEEDED_RETRY_SECS: u64 = 60;

/// Convert a governor rate limiter check result to an optional retry-after duration.
///
/// Returns `None` if the request is allowed, or `Some(retry_after_secs)` with
/// a minimum of 1 second if rate-limited.
fn governor_check_to_retry_after(
    result: Result<(), governor::NotUntil<governor::clock::QuantaInstant>>,
) -> Option<u64> {
    match result {
        Ok(()) => None,
        Err(not_until) => {
            let wait = not_until.wait_time_from(governor::clock::DefaultClock::default().now());
            Some(wait.as_secs().max(1))
        }
    }
}

/// Per-IP rate limiter using DashMap for lock-free concurrent access.
///
/// Each unique client IP gets its own governor bucket. Stale entries
/// (no requests for 1 hour) are periodically cleaned up.
///
/// A configurable max capacity prevents memory exhaustion from
/// attackers spoofing large numbers of unique source IPs.
pub struct PerIpRateLimiter {
    buckets: dashmap::DashMap<std::net::IpAddr, (governor::DefaultDirectRateLimiter, Instant)>,
    quota: Quota,
    max_capacity: usize,
}

/// Default maximum number of unique IPs tracked simultaneously (~15MB).
/// Beyond this limit, new IPs are rate-limited immediately (fail-closed)
/// until the periodic cleanup frees slots.
pub const DEFAULT_MAX_IP_CAPACITY: usize = 100_000;

impl PerIpRateLimiter {
    pub fn new(rps: NonZeroU32) -> Self {
        Self {
            buckets: dashmap::DashMap::new(),
            quota: Quota::per_second(rps),
            max_capacity: DEFAULT_MAX_IP_CAPACITY,
        }
    }

    /// Create with burst allowance.
    pub fn new_with_burst(rps: NonZeroU32, burst: Option<NonZeroU32>) -> Self {
        Self {
            buckets: dashmap::DashMap::new(),
            quota: build_quota(rps, burst),
            max_capacity: DEFAULT_MAX_IP_CAPACITY,
        }
    }

    /// Create with a custom max capacity (useful for testing).
    pub fn with_max_capacity(rps: NonZeroU32, max_capacity: usize) -> Self {
        Self {
            buckets: dashmap::DashMap::new(),
            quota: Quota::per_second(rps),
            max_capacity,
        }
    }

    /// Create with burst allowance and custom max capacity.
    pub fn with_max_capacity_and_burst(
        rps: NonZeroU32,
        burst: Option<NonZeroU32>,
        max_capacity: usize,
    ) -> Self {
        Self {
            buckets: dashmap::DashMap::new(),
            quota: build_quota(rps, burst),
            max_capacity,
        }
    }

    /// Check the rate limit for a given IP. Returns `None` if allowed,
    /// `Some(retry_after_secs)` if rate-limited.
    ///
    /// SECURITY (R27-SRV-1): Uses DashMap `entry()` API for atomic get-or-insert,
    /// preventing the TOCTOU race where two concurrent requests from the same new IP
    /// would both create separate limiters (losing the first thread's token consumption).
    /// If the number of tracked IPs exceeds max capacity, unknown IPs are
    /// immediately rate-limited (fail-closed) to prevent memory DoS.
    pub fn check(&self, ip: std::net::IpAddr) -> Option<u64> {
        let now = Instant::now();

        // Capacity check before entry() to avoid holding a shard lock during len().
        // This is approximate (two threads may both pass) but that's acceptable —
        // at worst we exceed capacity by the number of concurrent new-IP requests.
        let at_capacity = self.buckets.len() >= self.max_capacity;

        match self.buckets.entry(ip) {
            dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                entry.get_mut().1 = now;
                governor_check_to_retry_after(entry.get().0.check())
            }
            dashmap::mapref::entry::Entry::Vacant(vacancy) => {
                if at_capacity {
                    return Some(CAPACITY_EXCEEDED_RETRY_SECS);
                }
                let limiter = RateLimiter::direct(self.quota);
                let result = governor_check_to_retry_after(limiter.check());
                vacancy.insert((limiter, now));
                result
            }
        }
    }

    /// Remove entries that haven't been seen for the given duration.
    pub fn cleanup(&self, max_age: std::time::Duration) {
        let cutoff = Instant::now() - max_age;
        self.buckets.retain(|_, (_, last_seen)| *last_seen > cutoff);
    }

    /// Number of tracked IPs.
    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    /// Whether any IPs are tracked.
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    /// Maximum capacity for tracked IPs.
    pub fn max_capacity(&self) -> usize {
        self.max_capacity
    }
}

/// Per-principal (string-keyed) rate limiter using DashMap for lock-free concurrent access.
///
/// Each unique principal key gets its own governor bucket. Stale entries
/// (no requests for 1 hour) are periodically cleaned up.
///
/// The principal key is derived from (in order of precedence):
/// 1. `X-Principal` header
/// 2. Bearer token from the `Authorization` header
/// 3. Client IP address as a string fallback
///
/// A configurable max capacity prevents memory exhaustion from
/// attackers using large numbers of unique principal keys.
pub struct PerKeyRateLimiter {
    buckets: dashmap::DashMap<String, (governor::DefaultDirectRateLimiter, Instant)>,
    quota: Quota,
    max_capacity: usize,
}

/// Default maximum number of unique keys tracked simultaneously.
/// Beyond this limit, new keys are rate-limited immediately (fail-closed)
/// until the periodic cleanup frees slots.
pub const DEFAULT_MAX_KEY_CAPACITY: usize = 100_000;

impl PerKeyRateLimiter {
    pub fn new(rps: NonZeroU32) -> Self {
        Self {
            buckets: dashmap::DashMap::new(),
            quota: Quota::per_second(rps),
            max_capacity: DEFAULT_MAX_KEY_CAPACITY,
        }
    }

    /// Create with burst allowance.
    pub fn new_with_burst(rps: NonZeroU32, burst: Option<NonZeroU32>) -> Self {
        Self {
            buckets: dashmap::DashMap::new(),
            quota: build_quota(rps, burst),
            max_capacity: DEFAULT_MAX_KEY_CAPACITY,
        }
    }

    /// Create with a custom max capacity (useful for testing).
    pub fn with_max_capacity(rps: NonZeroU32, max_capacity: usize) -> Self {
        Self {
            buckets: dashmap::DashMap::new(),
            quota: Quota::per_second(rps),
            max_capacity,
        }
    }

    /// Create with burst allowance and custom max capacity.
    pub fn with_max_capacity_and_burst(
        rps: NonZeroU32,
        burst: Option<NonZeroU32>,
        max_capacity: usize,
    ) -> Self {
        Self {
            buckets: dashmap::DashMap::new(),
            quota: build_quota(rps, burst),
            max_capacity,
        }
    }

    /// Check the rate limit for a given key. Returns `None` if allowed,
    /// `Some(retry_after_secs)` if rate-limited.
    ///
    /// SECURITY (R27-SRV-2): Uses DashMap `entry()` API for atomic get-or-insert,
    /// preventing the TOCTOU race where two concurrent requests with the same new key
    /// would both create separate limiters (losing the first thread's token consumption).
    /// If the number of tracked keys exceeds max capacity, unknown keys are
    /// immediately rate-limited (fail-closed) to prevent memory DoS.
    pub fn check(&self, key: String) -> Option<u64> {
        let now = Instant::now();

        // Capacity check before entry() — approximate but acceptable.
        let at_capacity = self.buckets.len() >= self.max_capacity;

        match self.buckets.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                entry.get_mut().1 = now;
                governor_check_to_retry_after(entry.get().0.check())
            }
            dashmap::mapref::entry::Entry::Vacant(vacancy) => {
                if at_capacity {
                    return Some(CAPACITY_EXCEEDED_RETRY_SECS);
                }
                let limiter = RateLimiter::direct(self.quota);
                let result = governor_check_to_retry_after(limiter.check());
                vacancy.insert((limiter, now));
                result
            }
        }
    }

    /// Remove entries that haven't been seen for the given duration.
    pub fn cleanup(&self, max_age: std::time::Duration) {
        let cutoff = Instant::now() - max_age;
        self.buckets.retain(|_, (_, last_seen)| *last_seen > cutoff);
    }

    /// Number of tracked keys.
    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    /// Whether any keys are tracked.
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    /// Maximum capacity for tracked keys.
    pub fn max_capacity(&self) -> usize {
        self.max_capacity
    }
}

/// Maximum number of unique tenants tracked simultaneously by the per-tenant rate limiter.
/// Beyond this limit, new tenants are rate-limited immediately (fail-closed).
pub const DEFAULT_MAX_TENANT_CAPACITY: usize = 10_000;

/// Per-tenant evaluation rate limiter (Phase 44).
///
/// Each tenant gets its own governor bucket sized by `TenantQuotas.max_evaluations_per_minute`.
/// If a tenant's quota changes, the bucket is recreated on next check.
/// DashMap provides lock-free concurrent access across handler threads.
pub struct PerTenantRateLimiter {
    /// Maps tenant_id → (rate limiter, last_seen, configured rate-per-minute).
    buckets: dashmap::DashMap<String, (governor::DefaultDirectRateLimiter, Instant, u64)>,
    max_capacity: usize,
}

impl Default for PerTenantRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl PerTenantRateLimiter {
    /// Create a new per-tenant rate limiter with default capacity.
    pub fn new() -> Self {
        Self {
            buckets: dashmap::DashMap::new(),
            max_capacity: DEFAULT_MAX_TENANT_CAPACITY,
        }
    }

    /// Create with a custom max capacity (useful for testing).
    pub fn with_max_capacity(max_capacity: usize) -> Self {
        Self {
            buckets: dashmap::DashMap::new(),
            max_capacity,
        }
    }

    /// Check the rate limit for a given tenant. Returns `None` if allowed,
    /// `Some(retry_after_secs)` if rate-limited.
    ///
    /// `max_per_minute` is the tenant's configured quota. If 0 or u64::MAX,
    /// rate limiting is skipped (unlimited). If the stored quota differs from
    /// the current one (tenant quota was updated), the bucket is recreated.
    pub fn check(&self, tenant_id: &str, max_per_minute: u64) -> Option<u64> {
        // Unlimited quota — skip rate limiting
        if max_per_minute == 0 || max_per_minute == u64::MAX {
            return None;
        }

        let now = Instant::now();

        // Convert per-minute to per-second (minimum 1 rps).
        let rps = max_per_minute.div_ceil(60).max(1);
        // SECURITY (FIND-R202-003): Use saturating cast to prevent u64→u32 truncation.
        // Without this, values > u32::MAX wrap to 0, causing NonZeroU32::new to return
        // None and silently bypassing rate limiting.
        let rps_u32 = u32::try_from(rps).unwrap_or(u32::MAX);
        let rps_nz = NonZeroU32::new(rps_u32)?;

        // Capacity check before entry()
        let at_capacity = self.buckets.len() >= self.max_capacity;

        match self.buckets.entry(tenant_id.to_string()) {
            dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                let (ref limiter, ref mut last_seen, ref mut stored_rate) = entry.get_mut();
                *last_seen = now;

                // If quota changed, recreate the bucket
                if *stored_rate != max_per_minute {
                    let new_limiter = RateLimiter::direct(Quota::per_second(rps_nz));
                    let result = governor_check_to_retry_after(new_limiter.check());
                    *entry.get_mut() = (new_limiter, now, max_per_minute);
                    return result;
                }

                governor_check_to_retry_after(limiter.check())
            }
            dashmap::mapref::entry::Entry::Vacant(vacancy) => {
                if at_capacity {
                    return Some(CAPACITY_EXCEEDED_RETRY_SECS);
                }
                let limiter = RateLimiter::direct(Quota::per_second(rps_nz));
                let result = governor_check_to_retry_after(limiter.check());
                vacancy.insert((limiter, now, max_per_minute));
                result
            }
        }
    }

    /// Remove entries that haven't been seen for the given duration.
    pub fn cleanup(&self, max_age: std::time::Duration) {
        let cutoff = Instant::now() - max_age;
        self.buckets
            .retain(|_, (_, last_seen, _)| *last_seen > cutoff);
    }

    /// Number of tracked tenants.
    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    /// Whether any tenants are tracked.
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }
}

/// Build a governor `Quota` from a sustained rate and optional burst size.
///
/// When `burst` is `Some`, `allow_burst(b)` sets the token bucket capacity
/// to `b`, meaning up to `b` requests can be served instantly before the
/// sustained `rps` rate kicks in.  When `None`, the default bucket size of 1
/// is used (no burst above the sustained rate).
fn build_quota(rps: NonZeroU32, burst: Option<NonZeroU32>) -> Quota {
    let q = Quota::per_second(rps);
    match burst {
        Some(b) => q.allow_burst(b),
        None => q,
    }
}

impl RateLimits {
    /// Create rate limiters from optional requests-per-second values.
    /// A value of None or 0 disables rate limiting for that category.
    pub fn new(
        evaluate_rps: Option<u32>,
        admin_rps: Option<u32>,
        readonly_rps: Option<u32>,
    ) -> Self {
        Self {
            evaluate: evaluate_rps
                .and_then(NonZeroU32::new)
                .map(|r| RateLimiter::direct(Quota::per_second(r))),
            admin: admin_rps
                .and_then(NonZeroU32::new)
                .map(|r| RateLimiter::direct(Quota::per_second(r))),
            readonly: readonly_rps
                .and_then(NonZeroU32::new)
                .map(|r| RateLimiter::direct(Quota::per_second(r))),
            per_ip: None,
            per_principal: None,
            endpoint_limits: std::collections::HashMap::new(),
        }
    }

    /// Create rate limiters with burst configuration.
    ///
    /// Each category takes an optional RPS and optional burst. A `None` or 0
    /// RPS disables rate limiting for that category. A `None` burst means
    /// no burst above the sustained rate (bucket size = 1).
    pub fn new_with_burst(
        evaluate_rps: Option<u32>,
        evaluate_burst: Option<u32>,
        admin_rps: Option<u32>,
        admin_burst: Option<u32>,
        readonly_rps: Option<u32>,
        readonly_burst: Option<u32>,
    ) -> Self {
        Self {
            evaluate: evaluate_rps.and_then(NonZeroU32::new).map(|r| {
                RateLimiter::direct(build_quota(r, evaluate_burst.and_then(NonZeroU32::new)))
            }),
            admin: admin_rps.and_then(NonZeroU32::new).map(|r| {
                RateLimiter::direct(build_quota(r, admin_burst.and_then(NonZeroU32::new)))
            }),
            readonly: readonly_rps.and_then(NonZeroU32::new).map(|r| {
                RateLimiter::direct(build_quota(r, readonly_burst.and_then(NonZeroU32::new)))
            }),
            per_ip: None,
            per_principal: None,
            endpoint_limits: std::collections::HashMap::new(),
        }
    }

    /// Add a rate limit for a specific endpoint path.
    ///
    /// The path is matched as a prefix, so "/api/evaluate" matches both
    /// "/api/evaluate" and "/api/evaluate/foo". More specific paths take
    /// priority (longest match wins).
    pub fn with_endpoint_limit(
        mut self,
        path: impl Into<String>,
        rps: NonZeroU32,
        burst: Option<NonZeroU32>,
    ) -> Self {
        let limiter = RateLimiter::direct(build_quota(rps, burst));
        self.endpoint_limits.insert(path.into(), limiter);
        self
    }

    /// Get the endpoint-specific rate limiter for a path, if any.
    ///
    /// Returns the limiter for the longest matching path prefix.
    pub fn get_endpoint_limiter(&self, path: &str) -> Option<&governor::DefaultDirectRateLimiter> {
        // Find the longest matching prefix
        let mut best_match: Option<(&str, &governor::DefaultDirectRateLimiter)> = None;
        for (prefix, limiter) in &self.endpoint_limits {
            if path.starts_with(prefix) {
                match best_match {
                    None => best_match = Some((prefix, limiter)),
                    Some((current, _)) if prefix.len() > current.len() => {
                        best_match = Some((prefix, limiter));
                    }
                    _ => {}
                }
            }
        }
        best_match.map(|(_, limiter)| limiter)
    }

    /// Set the per-IP rate limiter.
    pub fn with_per_ip(mut self, rps: NonZeroU32) -> Self {
        self.per_ip = Some(PerIpRateLimiter::new(rps));
        self
    }

    /// Set the per-IP rate limiter with optional burst and max capacity.
    pub fn with_per_ip_config(
        mut self,
        rps: NonZeroU32,
        burst: Option<NonZeroU32>,
        max_capacity: Option<usize>,
    ) -> Self {
        let capacity = max_capacity.unwrap_or(DEFAULT_MAX_IP_CAPACITY);
        self.per_ip = Some(PerIpRateLimiter::with_max_capacity_and_burst(
            rps, burst, capacity,
        ));
        self
    }

    /// Set the per-principal rate limiter.
    pub fn with_per_principal(mut self, rps: NonZeroU32) -> Self {
        self.per_principal = Some(PerKeyRateLimiter::new(rps));
        self
    }

    /// Set the per-principal rate limiter with optional burst and max capacity.
    pub fn with_per_principal_config(
        mut self,
        rps: NonZeroU32,
        burst: Option<NonZeroU32>,
        max_capacity: Option<usize>,
    ) -> Self {
        let capacity = max_capacity.unwrap_or(DEFAULT_MAX_KEY_CAPACITY);
        self.per_principal = Some(PerKeyRateLimiter::with_max_capacity_and_burst(
            rps, burst, capacity,
        ));
        self
    }

    /// Create rate limits with all categories disabled (no rate limiting).
    pub fn disabled() -> Self {
        Self {
            evaluate: None,
            admin: None,
            readonly: None,
            per_ip: None,
            per_principal: None,
            endpoint_limits: std::collections::HashMap::new(),
        }
    }
}

/// Operational metrics with atomic counters for lock-free updates.
pub struct Metrics {
    pub start_time: Instant,
    pub evaluations_total: AtomicU64,
    pub evaluations_allow: AtomicU64,
    pub evaluations_deny: AtomicU64,
    pub evaluations_require_approval: AtomicU64,
    pub evaluations_error: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            start_time: Instant::now(),
            evaluations_total: AtomicU64::new(0),
            evaluations_allow: AtomicU64::new(0),
            evaluations_deny: AtomicU64::new(0),
            evaluations_require_approval: AtomicU64::new(0),
            evaluations_error: AtomicU64::new(0),
        }
    }
}

impl Metrics {
    pub fn record_evaluation(&self, verdict: &vellaveto_types::Verdict) {
        // SECURITY (CA-005): SeqCst ordering on security-adjacent metrics to ensure
        // visibility across threads. Saturating arithmetic prevents overflow wrap-to-zero.
        let _ = self
            .evaluations_total
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                Some(v.saturating_add(1))
            });
        match verdict {
            vellaveto_types::Verdict::Allow => {
                let _ =
                    self.evaluations_allow
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                            Some(v.saturating_add(1))
                        });
            }
            vellaveto_types::Verdict::Deny { .. } => {
                let _ =
                    self.evaluations_deny
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                            Some(v.saturating_add(1))
                        });
            }
            vellaveto_types::Verdict::RequireApproval { .. } => {
                let _ = self.evaluations_require_approval.fetch_update(
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                    |v| Some(v.saturating_add(1)),
                );
            }
            // Handle future variants - count as deny (fail-closed)
            _ => {
                let _ =
                    self.evaluations_deny
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                            Some(v.saturating_add(1))
                        });
            }
        }
    }

    pub fn record_error(&self) {
        // SECURITY (CA-005): SeqCst + saturating arithmetic.
        let _ = self
            .evaluations_total
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                Some(v.saturating_add(1))
            });
        let _ = self
            .evaluations_error
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                Some(v.saturating_add(1))
            });
    }
}

/// Atomic snapshot of engine + policies for lock-free reads.
///
/// SECURITY (R15-CFG-2): Previously `engine` and `policies` were stored in
/// separate `ArcSwap` fields. Between the two stores a concurrent read could
/// see the new engine with the old policies (or vice versa). Bundling them
/// into a single `ArcSwap<PolicySnapshot>` eliminates this microsecond-wide
/// race: every reader sees a consistent (engine, policies) pair.
pub struct PolicySnapshot {
    pub engine: PolicyEngine,
    pub policies: Vec<Policy>,
    /// Compliance configuration for evidence generation (Phase 19/21).
    pub compliance_config: vellaveto_config::compliance::ComplianceConfig,
}

// ═══════════════════════════════════════════════════════════════════
// Phase 39: Agent Identity Federation — resolver type
// ═══════════════════════════════════════════════════════════════════

/// Federation identity resolver for cross-organization JWKS validation
/// and identity mapping via `FederationTrustAnchor` (Phase 39).
///
/// Stores federation configuration (trust anchors, issuer patterns, identity
/// mappings) and provides status/anchor info for the dashboard and API.
/// Runtime JWKS resolution (fetching and caching remote key sets) requires
/// an async HTTP client and is gated behind the `federation-jwks` feature.
///
/// FIND-R56-SRV-012: Custom `Debug` impl shows only `enabled` and anchor count
/// to avoid leaking JWKS URIs, issuer patterns, and identity mappings.
#[derive(Clone)]
pub struct FederationResolver {
    config: vellaveto_config::abac::FederationConfig,
}

impl std::fmt::Debug for FederationResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FederationResolver")
            .field("enabled", &self.config.enabled)
            .field("trust_anchor_count", &self.config.trust_anchors.len())
            .finish()
    }
}

impl FederationResolver {
    /// Create a new federation resolver from config.
    pub fn new(config: vellaveto_config::abac::FederationConfig) -> Self {
        Self { config }
    }

    /// Return the federation config.
    pub fn config(&self) -> &vellaveto_config::abac::FederationConfig {
        &self.config
    }

    /// Status summary for dashboard/API.
    pub fn status(&self) -> FederationStatus {
        FederationStatus {
            enabled: self.config.enabled,
            trust_anchor_count: self.config.trust_anchors.len(),
            anchors: self
                .config
                .trust_anchors
                .iter()
                .map(|a| FederationAnchorStatus {
                    org_id: a.org_id.clone(),
                    display_name: a.display_name.clone(),
                    issuer_pattern: a.issuer_pattern.clone(),
                    trust_level: a.trust_level.clone(),
                    has_jwks_uri: a.jwks_uri.is_some(),
                    identity_mapping_count: a.identity_mappings.len(),
                    successful_validations: 0,
                    failed_validations: 0,
                })
                .collect(),
        }
    }

    /// Return the list of anchor status entries.
    pub fn anchor_info(&self) -> Vec<FederationAnchorStatus> {
        self.status().anchors
    }
}

/// Summary of federation runtime status.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FederationStatus {
    /// Whether federation is enabled.
    pub enabled: bool,
    /// Number of configured trust anchors.
    pub trust_anchor_count: usize,
    /// Per-anchor status.
    pub anchors: Vec<FederationAnchorStatus>,
}

/// Per-anchor runtime status.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FederationAnchorStatus {
    /// Organization identifier.
    pub org_id: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Glob pattern for trusted JWT issuers.
    pub issuer_pattern: String,
    /// Trust level (full, limited, read_only).
    pub trust_level: String,
    /// Whether a JWKS URI is configured.
    pub has_jwks_uri: bool,
    /// Number of identity mappings configured.
    pub identity_mapping_count: usize,
    /// Successful JWKS validations (lifetime counter).
    pub successful_validations: u64,
    /// Failed JWKS validations (lifetime counter).
    pub failed_validations: u64,
}

/// Billing and licensing state resolved at server startup.
///
/// FIND-R56-SRV-013: Custom `Debug` impl shows only `enabled` to avoid leaking
/// webhook secrets, Stripe/Paddle signing keys, and license validation details.
#[derive(Clone)]
pub struct BillingState {
    /// Paddle webhook configuration.
    pub paddle: vellaveto_config::billing::PaddleConfig,
    /// Stripe webhook configuration.
    pub stripe: vellaveto_config::billing::StripeConfig,
    /// Whether billing webhooks are enabled.
    pub enabled: bool,
    /// Resolved license validation result.
    pub licensing_validation: vellaveto_config::LicenseValidation,
}

impl std::fmt::Debug for BillingState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BillingState")
            .field("enabled", &self.enabled)
            .finish()
    }
}

/// Shared application state for axum handlers.
#[derive(Clone)]
pub struct AppState {
    /// Atomic snapshot of engine + policies. Readers get a consistent pair
    /// via a single `policy_state.load()` call.
    pub policy_state: Arc<ArcSwap<PolicySnapshot>>,
    pub audit: Arc<AuditLogger>,
    pub config_path: Arc<String>,
    pub approvals: Arc<ApprovalStore>,
    /// API key for authenticating mutating requests. None disables auth.
    pub api_key: Option<Arc<String>>,
    /// Per-category rate limiters. Arc-wrapped for Clone.
    pub rate_limits: Arc<RateLimits>,
    /// Allowed CORS origins. Empty vec means localhost only (strict default).
    /// Use `vec!["*".to_string()]` to allow any origin.
    pub cors_origins: Vec<String>,
    /// Operational metrics counters.
    pub metrics: Arc<Metrics>,
    /// Trusted reverse proxy IPs. When non-empty, `X-Forwarded-For` is only
    /// trusted if the connection originates from one of these IPs. The
    /// **rightmost untrusted** entry in the XFF chain is used as the client IP.
    /// When empty (default), proxy headers are ignored entirely and the
    /// connection IP is used directly.
    pub trusted_proxies: Arc<Vec<std::net::IpAddr>>,
    /// SECURITY (R15-RACE-*): Mutex serializing all policy mutation operations
    /// (add_policy, remove_policy, reload_policies). This prevents TOCTOU races
    /// where concurrent mutations can silently drop policies or resurrect deleted
    /// ones. The read path (evaluate) remains lock-free via ArcSwap::load().
    pub policy_write_lock: Arc<tokio::sync::Mutex<()>>,
    /// Prometheus metrics handle for rendering `/metrics` endpoint.
    /// None when Prometheus is not initialized (e.g., recorder already installed).
    pub prometheus_handle: Option<metrics_exporter_prometheus::PrometheusHandle>,
    /// Tool registry for tracking tool trust scores (P2.1).
    /// None when tool registry is disabled.
    pub tool_registry: Option<Arc<vellaveto_mcp::tool_registry::ToolRegistry>>,
    /// Cluster backend for distributed state sharing (P3.4).
    /// When clustering is enabled, approvals and rate limits are shared across
    /// instances. When disabled, delegates to the local `ApprovalStore`.
    pub cluster: Option<Arc<dyn vellaveto_cluster::ClusterBackend>>,
    /// RBAC configuration for role-based access control (Phase 2).
    /// When enabled, endpoints are protected by role-based permissions.
    pub rbac_config: rbac::RbacConfig,
    /// Tenant configuration for multi-tenancy support (Phase 3).
    /// When enabled, requests are scoped to a tenant.
    pub tenant_config: tenant::TenantConfig,
    /// Tenant store for looking up tenant details and quotas.
    /// None means no tenant validation (config + default tenant only).
    pub tenant_store: Option<Arc<dyn tenant::TenantStore>>,
    /// Per-tenant evaluation rate limiter (Phase 44).
    /// Enforces `TenantQuotas.max_evaluations_per_minute` per tenant.
    pub tenant_rate_limiter: Arc<PerTenantRateLimiter>,
    /// Idempotency key store for at-most-once request semantics (Phase 5).
    pub idempotency: idempotency::IdempotencyStore,
    /// SECURITY: Mutex serializing signup requests to prevent TOCTOU race
    /// where concurrent signups all pass the capacity check and exceed
    /// MAX_TOTAL_TENANTS.
    pub signup_lock: Arc<tokio::sync::Mutex<()>>,
    /// Webhook event deduplication tracker (idempotency).
    /// Prevents replayed Paddle/Stripe webhook events from being processed twice.
    pub webhook_dedup: Arc<crate::routes::billing::WebhookDedup>,

    // ═══════════════════════════════════════════════════════════════════
    // Phase 1 & 2 Security Managers (Phase 3.1 Integration)
    // ═══════════════════════════════════════════════════════════════════
    /// Task state manager for async task lifecycle tracking (Phase 1).
    /// None when async task tracking is disabled.
    pub task_state: Option<Arc<TaskStateManager>>,

    /// Auth level tracker for step-up authentication (Phase 1).
    /// None when step-up auth is disabled.
    pub auth_level: Option<Arc<AuthLevelTracker>>,

    /// Enterprise IAM state (Phase 46).
    /// None when IAM is disabled or misconfigured.
    pub iam_state: Option<Arc<iam::IamState>>,

    /// Circuit breaker manager for cascading failure protection (Phase 2, ASI08).
    /// None when circuit breaker is disabled.
    pub circuit_breaker: Option<Arc<CircuitBreakerManager>>,

    /// Deputy validator for confused deputy prevention (Phase 2, ASI02).
    /// None when deputy validation is disabled.
    pub deputy: Option<Arc<DeputyValidator>>,

    /// Shadow agent detector for agent impersonation detection (Phase 2).
    /// None when shadow agent detection is disabled.
    pub shadow_agent: Option<Arc<ShadowAgentDetector>>,

    /// Schema lineage tracker for schema poisoning detection (Phase 2, ASI05).
    /// None when schema poisoning detection is disabled.
    pub schema_lineage: Option<Arc<SchemaLineageTracker>>,

    /// Sampling detector for sampling attack prevention (Phase 2).
    /// None when sampling detection is disabled.
    pub sampling_detector: Option<Arc<SamplingDetector>>,

    // ═══════════════════════════════════════════════════════════════════
    // Phase 6: Observability & Tooling
    // ═══════════════════════════════════════════════════════════════════
    /// Execution graph store for visualizing agent call chains (Phase 6).
    /// None when execution graph tracking is disabled.
    pub exec_graph_store: Option<Arc<vellaveto_audit::exec_graph::ExecutionGraphStore>>,

    // ═══════════════════════════════════════════════════════════════════
    // Phase 8: ETDI Cryptographic Tool Security
    // ═══════════════════════════════════════════════════════════════════
    /// ETDI store for persistent signature, attestation, and pin state.
    /// None when ETDI is disabled.
    pub etdi_store: Option<Arc<vellaveto_mcp::etdi::EtdiStore>>,

    /// ETDI signature verifier.
    /// None when ETDI signature verification is disabled.
    pub etdi_verifier: Option<Arc<vellaveto_mcp::etdi::ToolSignatureVerifier>>,

    /// ETDI attestation chain manager.
    /// None when attestation tracking is disabled.
    pub etdi_attestations: Option<Arc<vellaveto_mcp::etdi::AttestationChain>>,

    /// ETDI version pin manager.
    /// None when version pinning is disabled.
    pub etdi_version_pins: Option<Arc<vellaveto_mcp::etdi::VersionPinManager>>,

    // ═══════════════════════════════════════════════════════════════════
    // Phase 9: Memory Injection Defense (MINJA)
    // ═══════════════════════════════════════════════════════════════════
    /// Memory security manager for MINJA defense.
    /// None when memory security is disabled.
    pub memory_security: Option<Arc<vellaveto_mcp::memory_security::MemorySecurityManager>>,

    // ═══════════════════════════════════════════════════════════════════
    // Phase 10: Non-Human Identity (NHI) Lifecycle
    // ═══════════════════════════════════════════════════════════════════
    /// NHI manager for agent identity lifecycle management.
    /// None when NHI is disabled.
    pub nhi: Option<Arc<vellaveto_mcp::nhi::NhiManager>>,

    // ═══════════════════════════════════════════════════════════════════
    // Phase 15: AI Observability Platform Integration
    // ═══════════════════════════════════════════════════════════════════
    /// Observability manager for exporting security spans to AI observability
    /// platforms (Langfuse, Arize, Helicone). None when observability is disabled.
    pub observability: Option<Arc<observability::ObservabilityManager>>,

    // ═══════════════════════════════════════════════════════════════════
    // Phase 26: Shadow AI Detection & Governance Visibility
    // ═══════════════════════════════════════════════════════════════════
    /// Shadow AI discovery engine for detecting unregistered agents/tools/servers.
    /// None when shadow AI discovery is disabled.
    pub shadow_ai_discovery: Option<Arc<vellaveto_mcp::shadow_ai_discovery::ShadowAiDiscovery>>,

    /// Least agency tracker for permission usage monitoring and enforcement.
    /// None when least agency tracking is disabled.
    pub least_agency_tracker: Option<Arc<vellaveto_engine::least_agency::LeastAgencyTracker>>,

    // ═══════════════════════════════════════════════════════════════════
    // Server Configuration (FIND-004, FIND-005)
    // ═══════════════════════════════════════════════════════════════════
    /// When true, `/metrics` and `/api/metrics` require authentication (FIND-004).
    /// Default: true (secure by default).
    ///
    /// **WARNING (FIND-R56-SRV-007):** Setting this to `false` exposes policy count
    /// and evaluation statistics (allow/deny/error counters) to unauthenticated
    /// clients. Only disable in trusted networks or behind a reverse proxy that
    /// handles authentication for the metrics path.
    pub metrics_require_auth: bool,

    /// Strict audit mode (FIND-005): When true, audit logging failures cause
    /// requests to be denied instead of proceeding without an audit trail.
    /// Default: false (backward compatible).
    pub audit_strict_mode: bool,

    // ═══════════════════════════════════════════════════════════════════
    // Phase 27: Kubernetes-Native Deployment
    // ═══════════════════════════════════════════════════════════════════
    /// Leader election backend for cluster coordination.
    /// None in standalone mode.
    pub leader_election: Option<Arc<dyn vellaveto_cluster::leader::LeaderElection>>,

    /// Service discovery backend for dynamic endpoint resolution.
    /// None in standalone mode.
    pub service_discovery: Option<Arc<dyn vellaveto_cluster::discovery::ServiceDiscovery>>,

    /// Deployment configuration (mode, leader election, service discovery).
    pub deployment_config: vellaveto_config::DeploymentConfig,

    /// Server start time for uptime calculation.
    pub start_time: Instant,

    /// SECURITY (FIND-P27-001): Cached discovered endpoint count.
    /// Updated by a background task instead of live DNS lookup on every
    /// /health and /api/deployment/info request. Prevents DNS amplification DoS.
    pub cached_discovered_endpoints: Arc<AtomicU64>,

    /// SECURITY (FIND-P27-004): Cached instance ID resolved once at startup.
    /// Avoids repeated std::env::var("HOSTNAME") calls with global lock contention.
    pub cached_instance_id: Arc<String>,

    // ═══════════════════════════════════════════════════════════════════
    // Topology Crawling (ActionEngine-inspired live discovery)
    // ═══════════════════════════════════════════════════════════════════
    /// Topology guard for pre-policy tool call filtering.
    /// When set, tool calls are checked against the live topology graph
    /// before policy evaluation. None when topology crawling is disabled.
    pub topology_guard: Option<Arc<vellaveto_discovery::guard::TopologyGuard>>,

    /// Static probe backing the topology crawler. Shared with relay for live updates.
    pub topology_probe: Option<Arc<vellaveto_discovery::crawler::StaticProbe>>,

    /// Trigger handle for requesting immediate re-crawls (e.g., from REST API).
    pub recrawl_trigger: Option<Arc<tokio::sync::Notify>>,

    // ═══════════════════════════════════════════════════════════════════
    // Phase 34: Tool Discovery Service
    // ═══════════════════════════════════════════════════════════════════
    /// Tool discovery engine for intent-based tool search.
    /// None when discovery is disabled in config.
    pub discovery_engine: Option<Arc<vellaveto_mcp::discovery::DiscoveryEngine>>,

    /// Audit logger reference for discovery events.
    /// Shared with the main audit logger.
    pub discovery_audit: Option<Arc<vellaveto_audit::AuditLogger>>,

    // ═══════════════════════════════════════════════════════════════════
    // Phase 35.3: Model Projector
    // ═══════════════════════════════════════════════════════════════════
    /// Model projector registry for cross-model tool schema translation.
    /// None when projector is disabled in config.
    pub projector_registry: Option<Arc<vellaveto_mcp::projector::ProjectorRegistry>>,

    // ═══════════════════════════════════════════════════════════════════
    // Phase 37: Zero-Knowledge Audit Trails
    // ═══════════════════════════════════════════════════════════════════
    /// Stored ZK batch proofs (lightweight — does not require ark-* in server).
    /// None when ZK audit is disabled.
    pub zk_proofs: Option<Arc<std::sync::Mutex<Vec<vellaveto_types::ZkBatchProof>>>>,

    /// Whether ZK audit features are enabled.
    pub zk_audit_enabled: bool,

    /// ZK audit configuration for status reporting.
    pub zk_audit_config: vellaveto_config::ZkAuditConfig,

    // ═══════════════════════════════════════════════════════════════════
    // Phase 39: Agent Identity Federation
    // ═══════════════════════════════════════════════════════════════════
    /// Federation identity resolver for cross-org JWKS validation and
    /// identity mapping. None when federation is disabled.
    pub federation_resolver: Option<Arc<FederationResolver>>,

    // ═══════════════════════════════════════════════════════════════════
    // Licensing & Billing
    // ═══════════════════════════════════════════════════════════════════
    /// Billing configuration (Paddle/Stripe webhook settings).
    pub billing_config: Arc<BillingState>,

    // ═══════════════════════════════════════════════════════════════════
    // Setup Wizard
    // ═══════════════════════════════════════════════════════════════════
    /// Whether initial setup has been completed. Once true, the wizard is locked.
    pub setup_completed: Arc<std::sync::atomic::AtomicBool>,

    /// Active wizard sessions (bounded by MAX_WIZARD_SESSIONS).
    pub wizard_sessions: Arc<dashmap::DashMap<String, setup_wizard::WizardSession>>,

    // ═══════════════════════════════════════════════════════════════════
    // Phase 43: Centralized Audit Store
    // ═══════════════════════════════════════════════════════════════════
    /// Audit query service for structured search over audit entries.
    /// Default: FileAuditQuery wrapping the JSONL audit log.
    pub audit_query: Arc<dyn vellaveto_audit::query::AuditQueryService>,

    /// Cached audit store status for the status endpoint.
    pub audit_store_status: vellaveto_types::audit_store::AuditStoreStatus,

    // Phase 47: Policy Lifecycle Management
    pub policy_lifecycle_store: Option<Arc<dyn policy_lifecycle::PolicyVersionStore>>,
    pub policy_lifecycle_config: vellaveto_config::PolicyLifecycleConfig,
    pub staging_snapshot: Arc<ArcSwap<Option<StagingSnapshot>>>,

    // ═══════════════════════════════════════════════════════════════════
    // Phase 50: Usage Metering & Billing Foundation
    // ═══════════════════════════════════════════════════════════════════
    /// Per-tenant usage tracker for metering evaluations/policies/approvals.
    /// None when metering is disabled.
    pub usage_tracker: Option<Arc<usage_tracker::TenantUsageTracker>>,
}

/// Staging policy engine snapshot for shadow evaluation.
pub struct StagingSnapshot {
    pub engine: PolicyEngine,
    pub policies: Vec<Policy>,
}

/// Error type for cluster-dispatched approval operations.
/// Unifies `ApprovalError` and `ClusterError` for routes.
#[derive(Debug)]
pub enum ApprovalOpError {
    NotFound(String),
    AlreadyResolved(String),
    Expired(String),
    CapacityExceeded(usize),
    Validation(String),
    Internal(String),
}

impl From<vellaveto_approval::ApprovalError> for ApprovalOpError {
    fn from(e: vellaveto_approval::ApprovalError) -> Self {
        match e {
            vellaveto_approval::ApprovalError::NotFound(id) => ApprovalOpError::NotFound(id),
            vellaveto_approval::ApprovalError::AlreadyResolved(id) => {
                ApprovalOpError::AlreadyResolved(id)
            }
            vellaveto_approval::ApprovalError::Expired(id) => ApprovalOpError::Expired(id),
            vellaveto_approval::ApprovalError::CapacityExceeded(max) => {
                ApprovalOpError::CapacityExceeded(max)
            }
            vellaveto_approval::ApprovalError::Validation(msg) => ApprovalOpError::Validation(msg),
            other => ApprovalOpError::Internal(other.to_string()),
        }
    }
}

impl From<vellaveto_cluster::ClusterError> for ApprovalOpError {
    fn from(e: vellaveto_cluster::ClusterError) -> Self {
        match e {
            vellaveto_cluster::ClusterError::NotFound(id) => ApprovalOpError::NotFound(id),
            vellaveto_cluster::ClusterError::AlreadyResolved(id) => {
                ApprovalOpError::AlreadyResolved(id)
            }
            vellaveto_cluster::ClusterError::Expired(id) => ApprovalOpError::Expired(id),
            vellaveto_cluster::ClusterError::CapacityExceeded(max) => {
                ApprovalOpError::CapacityExceeded(max)
            }
            vellaveto_cluster::ClusterError::Validation(msg) => ApprovalOpError::Validation(msg),
            other => ApprovalOpError::Internal(other.to_string()),
        }
    }
}

impl AppState {
    /// Create an approval, dispatching to cluster backend if available.
    pub async fn create_approval(
        &self,
        action: vellaveto_types::Action,
        reason: String,
        requested_by: Option<String>,
        session_id: Option<String>,
        action_fingerprint: Option<String>,
    ) -> Result<String, ApprovalOpError> {
        self.create_approval_with_context(
            action,
            reason,
            requested_by,
            session_id,
            action_fingerprint,
            None,
        )
        .await
    }

    /// Create an approval with optional semantic-containment context, dispatching
    /// to the cluster backend if available.
    pub async fn create_approval_with_context(
        &self,
        action: vellaveto_types::Action,
        reason: String,
        requested_by: Option<String>,
        session_id: Option<String>,
        action_fingerprint: Option<String>,
        containment_context: Option<ApprovalContainmentContext>,
    ) -> Result<String, ApprovalOpError> {
        if let Some(ref cluster) = self.cluster {
            Ok(cluster
                .approval_create_with_context(
                    action,
                    reason,
                    requested_by,
                    session_id,
                    action_fingerprint,
                    containment_context,
                )
                .await?)
        } else {
            Ok(self
                .approvals
                .create_with_context(
                    action,
                    reason,
                    requested_by,
                    session_id,
                    action_fingerprint,
                    containment_context,
                )
                .await?)
        }
    }

    /// Get an approval by ID, dispatching to cluster backend if available.
    pub async fn get_approval(
        &self,
        id: &str,
    ) -> Result<vellaveto_approval::PendingApproval, ApprovalOpError> {
        if let Some(ref cluster) = self.cluster {
            Ok(cluster.approval_get(id).await?)
        } else {
            Ok(self.approvals.get(id).await?)
        }
    }

    /// Approve an approval, dispatching to cluster backend if available.
    pub async fn approve_approval(
        &self,
        id: &str,
        by: &str,
    ) -> Result<vellaveto_approval::PendingApproval, ApprovalOpError> {
        if let Some(ref cluster) = self.cluster {
            Ok(cluster.approval_approve(id, by).await?)
        } else {
            Ok(self.approvals.approve(id, by).await?)
        }
    }

    /// Consume an approved approval exactly once for a matching request scope.
    pub async fn consume_approved_approval(
        &self,
        id: &str,
        session_id: Option<&str>,
        action_fingerprint: Option<&str>,
    ) -> Result<bool, ApprovalOpError> {
        if let Some(ref cluster) = self.cluster {
            Ok(cluster
                .approval_consume_approved(id, session_id, action_fingerprint)
                .await?)
        } else {
            Ok(self
                .approvals
                .consume_approved(id, session_id, action_fingerprint)
                .await?)
        }
    }

    /// Deny an approval, dispatching to cluster backend if available.
    pub async fn deny_approval(
        &self,
        id: &str,
        by: &str,
    ) -> Result<vellaveto_approval::PendingApproval, ApprovalOpError> {
        if let Some(ref cluster) = self.cluster {
            Ok(cluster.approval_deny(id, by).await?)
        } else {
            Ok(self.approvals.deny(id, by).await?)
        }
    }

    /// List pending approvals, dispatching to cluster backend if available.
    pub async fn list_pending_approvals(
        &self,
    ) -> Result<Vec<vellaveto_approval::PendingApproval>, ApprovalOpError> {
        if let Some(ref cluster) = self.cluster {
            Ok(cluster.approval_list_pending().await?)
        } else {
            Ok(self.approvals.list_pending().await)
        }
    }

    /// Count pending approvals, dispatching to cluster backend if available.
    pub async fn pending_approval_count(&self) -> Result<usize, ApprovalOpError> {
        if let Some(ref cluster) = self.cluster {
            Ok(cluster.approval_pending_count().await?)
        } else {
            Ok(self.approvals.pending_count().await)
        }
    }

    /// Expire stale approvals, dispatching to cluster backend if available.
    pub async fn expire_stale_approvals(&self) -> Result<usize, ApprovalOpError> {
        if let Some(ref cluster) = self.cluster {
            Ok(cluster.approval_expire_stale().await?)
        } else {
            Ok(self.approvals.expire_stale().await)
        }
    }

    /// Check cluster backend health. Returns Ok if healthy or not configured.
    pub async fn cluster_health(&self) -> Result<(), String> {
        if let Some(ref cluster) = self.cluster {
            cluster
                .health_check()
                .await
                .map_err(|e| format!("Cluster backend unhealthy: {e}"))
        } else {
            Ok(())
        }
    }
}

/// Reload policies from the config file and recompile the engine.
///
/// This is the shared reload logic used by both the HTTP `/reload` endpoint
/// and the file watcher. Returns the number of policies loaded on success.
pub async fn reload_policies_from_file(state: &AppState, source: &str) -> Result<usize, String> {
    // SECURITY (R15-RACE-*): Serialize with add_policy / remove_policy to
    // prevent reload from overwriting a concurrent mutation (or vice versa).
    let _guard = state.policy_write_lock.lock().await;

    let config_path = state.config_path.as_str();

    // SECURITY (R29-SRV-4): Do not include config_path in error messages
    // to prevent filesystem layout leakage if the error is surfaced.
    let policy_config =
        PolicyConfig::load_file(config_path).map_err(|e| format!("Failed to load config: {e}"))?;

    // SECURITY (R12-RELOAD-1): Warn if non-policy config sections have
    // non-default values, since only policy + OPA runtime settings are
    // hot-reloaded. Operators must restart the server to apply changes to
    // rate_limit, injection, audit, supply_chain, or manifest configuration.
    {
        let default_cfg = vellaveto_config::PolicyConfig {
            policies: vec![],
            injection: Default::default(),
            dlp: Default::default(),
            multimodal: Default::default(),
            rate_limit: Default::default(),
            audit: Default::default(),
            supply_chain: Default::default(),
            manifest: Default::default(),
            memory_tracking: Default::default(),
            elicitation: Default::default(),
            sampling: Default::default(),
            audit_export: Default::default(),
            max_path_decode_iterations: None,
            known_tool_names: Default::default(),
            tool_registry: Default::default(),
            allowed_origins: Default::default(),
            behavioral: Default::default(),
            data_flow: Default::default(),
            semantic_detection: Default::default(),
            cluster: Default::default(),
            async_tasks: Default::default(),
            resource_indicator: Default::default(),
            cimd: Default::default(),
            step_up_auth: Default::default(),
            circuit_breaker: Default::default(),
            deputy: Default::default(),
            shadow_agent: Default::default(),
            schema_poisoning: Default::default(),
            sampling_detection: Default::default(),
            cross_agent: Default::default(),
            advanced_threat: Default::default(),
            tls: Default::default(),
            spiffe: Default::default(),
            opa: Default::default(),
            threat_intel: Default::default(),
            jit_access: Default::default(),
            etdi: Default::default(),
            memory_security: Default::default(),
            nhi: Default::default(),
            semantic_guardrails: Default::default(),
            rag_defense: Default::default(),
            a2a: Default::default(),
            observability: Default::default(),
            metrics_require_auth: true,
            limits: Default::default(),
            compliance: Default::default(),
            extension: Default::default(),
            transport: Default::default(),
            gateway: Default::default(),
            abac: Default::default(),
            fips: Default::default(),
            governance: Default::default(),
            deployment: Default::default(),
            streamable_http: Default::default(),
            discovery: Default::default(),
            projector: Default::default(),
            zk_audit: Default::default(),
            iam: Default::default(),
            licensing: Default::default(),
            billing: Default::default(),
            audit_store: Default::default(),
            policy_lifecycle: Default::default(),
            metering: Default::default(),
            topology: Default::default(),
            shield: Default::default(),
            acis: Default::default(),
            tool_quotas: Default::default(),
            secret_substitutions: Default::default(),
            policy_templates: Default::default(),
            source_trust: Default::default(),
            sink_classification: Default::default(),
            intent_scope: Default::default(),
        };
        let mut changed_sections = Vec::new();
        if policy_config.injection != default_cfg.injection {
            changed_sections.push("injection");
        }
        if policy_config.rate_limit != default_cfg.rate_limit {
            changed_sections.push("rate_limit");
        }
        if policy_config.audit != default_cfg.audit {
            changed_sections.push("audit");
        }
        if policy_config.supply_chain != default_cfg.supply_chain {
            changed_sections.push("supply_chain");
        }
        if policy_config.manifest != default_cfg.manifest {
            changed_sections.push("manifest");
        }
        // SECURITY (FIND-R208-002): Extend changed-section detection to security-critical
        // configs that require restart. Previously only 5 sections were checked; operators
        // modifying other sections had no warning that changes were silently ignored.
        if policy_config.abac != default_cfg.abac {
            changed_sections.push("abac");
        }
        if policy_config.fips != default_cfg.fips {
            changed_sections.push("fips");
        }
        if policy_config.governance != default_cfg.governance {
            changed_sections.push("governance");
        }
        if policy_config.compliance != default_cfg.compliance {
            changed_sections.push("compliance");
        }
        if policy_config.deployment != default_cfg.deployment {
            changed_sections.push("deployment");
        }
        if policy_config.a2a != default_cfg.a2a {
            changed_sections.push("a2a");
        }
        if policy_config.cluster != default_cfg.cluster {
            changed_sections.push("cluster");
        }
        if !changed_sections.is_empty() {
            tracing::warn!(
                "Config reload only applies policies and OPA runtime settings. The following sections \
                 have non-default values but require a server restart to take \
                 effect: [{}]",
                changed_sections.join(", ")
            );
        }
    }

    let mut new_policies = policy_config.to_policies();
    PolicyEngine::sort_policies(&mut new_policies);
    let count = new_policies.len();

    // Compile engine BEFORE storing policies to avoid TOCTOU:
    // if we stored policies first, concurrent requests would see new policies
    // but the old engine until recompilation finishes. If recompilation fails,
    // policies and engine would be permanently inconsistent.
    let new_engine = PolicyEngine::with_policies(false, &new_policies).map_err(|errors| {
        for e in &errors {
            tracing::warn!("Policy recompilation error: {}", e);
        }
        format!(
            "Reload rejected: {} policy compilation error(s) — keeping previous policies and engine",
            errors.len()
        )
    })?;

    // Apply config-level path decode iteration limit if set.
    let mut new_engine = new_engine;
    if let Some(max_iter) = policy_config.max_path_decode_iterations {
        new_engine.set_max_path_decode_iterations(max_iter);
    }

    crate::opa::configure_runtime_client(&policy_config.opa)
        .map_err(|e| format!("Reload rejected: failed to reconfigure OPA runtime: {e}"))?;

    // SECURITY (R15-CFG-2): Single atomic swap of engine + policies.
    // Previously two separate ArcSwap stores had a microsecond-wide race
    // where a reader could see mismatched engine/policies. Now both are
    // bundled in a single PolicySnapshot and swapped atomically.
    state.policy_state.store(Arc::new(PolicySnapshot {
        engine: new_engine,
        policies: new_policies,
        compliance_config: policy_config.compliance.clone(),
    }));
    // SECURITY (FIND-R206-003): Invalidate staging snapshot when the active
    // policy set changes via config reload. Stale staging snapshots would
    // compare against an outdated baseline.
    state.staging_snapshot.store(Arc::new(None));

    tracing::info!(
        "Reloaded {} policies from {} (source: {})",
        count,
        config_path,
        source
    );

    // Audit trail
    // SECURITY (R22-SRV-2): Do not log the filesystem config_path in audit
    // entries — it leaks deployment layout. The source field is sufficient.
    let action = vellaveto_types::Action::new(
        "vellaveto",
        "reload_policies",
        serde_json::json!({
            "policy_count": count,
            "source": source,
        }),
    );
    let acis_envelope = build_secondary_acis_envelope(
        &action,
        &Verdict::Allow,
        DecisionOrigin::PolicyEngine,
        "http",
        None,
    );
    if let Err(e) = state
        .audit
        .log_entry_with_acis(
            &action,
            &Verdict::Allow,
            serde_json::json!({"event": "policies_reloaded", "source": source}),
            acis_envelope,
        )
        .await
    {
        tracing::warn!("Failed to audit policy reload: {}", e);
    }

    Ok(count)
}

/// Attach an audit sink to the logger, honouring `audit_store.sink_failure_fatal`.
///
/// SECURITY (R270-SRV-1): `sink_failure_fatal` is documented as an operator
/// control — "whether sink write failures are fatal" — and every other field of
/// `AuditStoreConfig` is read when the sink is built. This one was not: the call
/// site passed a hardcoded `false`, so setting it in config did nothing at all.
///
/// This exists as a function rather than an inline argument so the wiring is
/// testable. The call site in `main.rs` sits inside a `postgres-store` block
/// that first opens a real `PgPool`, which no unit test can reach; here a test
/// can pass a failing sink and a config and assert on `log_entry`'s behaviour.
/// That is what makes a regression in this line detectable.
pub fn attach_audit_sink(
    logger: AuditLogger,
    sink: std::sync::Arc<dyn vellaveto_audit::sink::AuditSink>,
    config: &vellaveto_config::AuditStoreConfig,
) -> AuditLogger {
    logger.with_sink(sink, config.sink_failure_fatal)
}

/// Spawn a file watcher that reloads policies when the config file changes.
///
/// Uses the `notify` crate with debouncing (1 second) to avoid rapid reloads
/// from editors that write files in multiple steps (e.g., write temp + rename).
pub fn spawn_config_watcher(state: AppState) -> Result<(), String> {
    use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

    let config_path = std::path::PathBuf::from(state.config_path.as_str());
    let watch_dir = config_path
        .parent()
        .ok_or_else(|| "Cannot determine parent directory of config file".to_string())?
        .to_path_buf();
    let config_filename = config_path
        .file_name()
        .ok_or_else(|| "Cannot determine config filename".to_string())?
        .to_os_string();

    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(16);

    // Create the watcher on a std thread since notify's watcher
    // needs to live on a thread with an event loop
    let tx_clone = tx.clone();
    let config_filename_clone = config_filename.clone();
    std::thread::spawn(move || {
        let _rt = tokio::runtime::Handle::current();
        let tx = tx_clone;
        let config_filename = config_filename_clone;
        let config_filename_for_closure = config_filename.clone();

        let mut watcher = match RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    match event.kind {
                        EventKind::Modify(_) | EventKind::Create(_) => {
                            // Check if the event is for our config file
                            let is_config = event.paths.iter().any(|p| {
                                p.file_name() == Some(config_filename_for_closure.as_os_str())
                            });
                            if is_config {
                                if let Err(e) = tx.blocking_send(()) {
                                    tracing::warn!(
                                        "Config reload channel closed, stopping watcher: {}",
                                        e
                                    );
                                }
                            }
                        }
                        _ => {}
                    }
                }
            },
            Config::default(),
        ) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!("Failed to create file watcher: {}", e);
                return;
            }
        };

        if let Err(e) = watcher.watch(&watch_dir, RecursiveMode::NonRecursive) {
            tracing::error!("Failed to watch directory {:?}: {}", watch_dir, e);
            return;
        }

        tracing::info!(
            "Watching {:?} for changes to {:?}",
            watch_dir,
            config_filename
        );

        // Park this thread forever to keep the watcher alive
        loop {
            std::thread::park();
        }
    });

    // Spawn async task to receive change events and debounce reloads
    tokio::spawn(async move {
        let debounce = tokio::time::Duration::from_secs(1);
        let mut last_reload = tokio::time::Instant::now() - debounce;

        while rx.recv().await.is_some() {
            // Debounce: skip if we reloaded within the last second
            let now = tokio::time::Instant::now();
            if now.duration_since(last_reload) < debounce {
                continue;
            }

            // Small delay to let editors finish writing
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

            // Drain any queued events
            while rx.try_recv().is_ok() {}

            match reload_policies_from_file(&state, "file_watcher").await {
                Ok(count) => {
                    tracing::info!("File watcher: reloaded {} policies", count);
                }
                Err(e) => {
                    tracing::warn!("File watcher: reload failed: {}", e);
                }
            }
            last_reload = tokio::time::Instant::now();
        }
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_default_starts_at_zero() {
        let m = Metrics::default();
        assert_eq!(m.evaluations_total.load(Ordering::SeqCst), 0);
        assert_eq!(m.evaluations_allow.load(Ordering::SeqCst), 0);
        assert_eq!(m.evaluations_deny.load(Ordering::SeqCst), 0);
        assert_eq!(m.evaluations_require_approval.load(Ordering::SeqCst), 0);
        assert_eq!(m.evaluations_error.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn metrics_record_allow() {
        let m = Metrics::default();
        m.record_evaluation(&Verdict::Allow);
        assert_eq!(m.evaluations_total.load(Ordering::SeqCst), 1);
        assert_eq!(m.evaluations_allow.load(Ordering::SeqCst), 1);
        assert_eq!(m.evaluations_deny.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn metrics_record_deny() {
        let m = Metrics::default();
        m.record_evaluation(&Verdict::Deny {
            reason: "test".to_string(),
        });
        assert_eq!(m.evaluations_total.load(Ordering::SeqCst), 1);
        assert_eq!(m.evaluations_deny.load(Ordering::SeqCst), 1);
        assert_eq!(m.evaluations_allow.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn metrics_record_require_approval() {
        let m = Metrics::default();
        m.record_evaluation(&Verdict::RequireApproval {
            reason: "review".to_string(),
        });
        assert_eq!(m.evaluations_total.load(Ordering::SeqCst), 1);
        assert_eq!(m.evaluations_require_approval.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn metrics_record_error() {
        let m = Metrics::default();
        m.record_error();
        assert_eq!(m.evaluations_total.load(Ordering::SeqCst), 1);
        assert_eq!(m.evaluations_error.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn metrics_multiple_evaluations_accumulate() {
        let m = Metrics::default();
        for _ in 0..5 {
            m.record_evaluation(&Verdict::Allow);
        }
        for _ in 0..3 {
            m.record_evaluation(&Verdict::Deny {
                reason: "x".to_string(),
            });
        }
        m.record_error();
        m.record_error();
        assert_eq!(m.evaluations_total.load(Ordering::SeqCst), 10);
        assert_eq!(m.evaluations_allow.load(Ordering::SeqCst), 5);
        assert_eq!(m.evaluations_deny.load(Ordering::SeqCst), 3);
        assert_eq!(m.evaluations_error.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn rate_limits_disabled_has_all_none() {
        let rl = RateLimits::disabled();
        assert!(rl.evaluate.is_none());
        assert!(rl.admin.is_none());
        assert!(rl.readonly.is_none());
        assert!(rl.per_ip.is_none());
        assert!(rl.per_principal.is_none());
    }

    #[test]
    fn rate_limits_new_with_values() {
        let rl = RateLimits::new(Some(100), Some(50), Some(200));
        assert!(rl.evaluate.is_some());
        assert!(rl.admin.is_some());
        assert!(rl.readonly.is_some());
        assert!(rl.per_ip.is_none());
    }

    #[test]
    fn rate_limits_new_with_zero_disables() {
        let rl = RateLimits::new(Some(0), None, Some(10));
        assert!(rl.evaluate.is_none(), "0 should disable rate limiting");
        assert!(rl.admin.is_none(), "None should disable rate limiting");
        assert!(rl.readonly.is_some());
    }

    #[test]
    fn rate_limits_with_per_ip() {
        let rl = RateLimits::disabled().with_per_ip(NonZeroU32::new(10).unwrap());
        assert!(rl.per_ip.is_some());
    }

    #[test]
    fn per_ip_rate_limiter_allows_first_request() {
        let limiter = PerIpRateLimiter::new(NonZeroU32::new(10).unwrap());
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        assert!(limiter.is_empty());
        let result = limiter.check(ip);
        assert!(result.is_none(), "First request should be allowed");
        assert_eq!(limiter.len(), 1);
    }

    #[test]
    fn per_ip_rate_limiter_cleanup_removes_stale() {
        let limiter = PerIpRateLimiter::new(NonZeroU32::new(10).unwrap());
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        limiter.check(ip);
        assert_eq!(limiter.len(), 1);
        // Cleanup with zero duration removes everything
        limiter.cleanup(std::time::Duration::ZERO);
        assert_eq!(limiter.len(), 0);
    }

    #[test]
    fn per_ip_rate_limiter_with_max_capacity_sets_limit() {
        let limiter = PerIpRateLimiter::with_max_capacity(NonZeroU32::new(10).unwrap(), 50);
        assert_eq!(limiter.max_capacity(), 50);
        assert!(limiter.is_empty());

        // Fill to capacity
        for i in 0..50u32 {
            let ip: std::net::IpAddr = std::net::Ipv4Addr::from(i.wrapping_add(167_772_160)).into(); // 10.0.0.x
            let result = limiter.check(ip);
            assert!(result.is_none(), "IP {ip} should be allowed");
        }
        assert_eq!(limiter.len(), 50);

        // New IP beyond capacity should be denied (fail-closed)
        let overflow_ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
        let result = limiter.check(overflow_ip);
        assert!(
            result.is_some(),
            "New IP beyond max_capacity should be denied"
        );
        assert_eq!(limiter.len(), 50, "Should not grow beyond max_capacity");
    }

    #[test]
    fn per_ip_rate_limiter_default_capacity() {
        let limiter = PerIpRateLimiter::new(NonZeroU32::new(10).unwrap());
        assert_eq!(limiter.max_capacity(), DEFAULT_MAX_IP_CAPACITY);
    }

    #[test]
    fn rate_limits_new_with_burst_creates_limiters() {
        let rl =
            RateLimits::new_with_burst(Some(100), Some(50), Some(20), Some(5), Some(200), None);
        assert!(rl.evaluate.is_some());
        assert!(rl.admin.is_some());
        assert!(rl.readonly.is_some());
        assert!(rl.per_ip.is_none());

        // Zero RPS should still disable
        let rl2 = RateLimits::new_with_burst(Some(0), Some(10), None, None, None, None);
        assert!(rl2.evaluate.is_none());
        assert!(rl2.admin.is_none());
        assert!(rl2.readonly.is_none());
    }

    #[test]
    fn per_ip_rate_limiter_burst_allows_initial_burst() {
        // With burst=5 and rps=1, we should be able to make several requests quickly
        let limiter = PerIpRateLimiter::new_with_burst(
            NonZeroU32::new(1).unwrap(),
            Some(NonZeroU32::new(5).unwrap()),
        );
        let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();

        // First several requests should all be allowed (burst window)
        for i in 0..5 {
            let result = limiter.check(ip);
            assert!(
                result.is_none(),
                "Request {i} within burst should be allowed"
            );
        }
        // After exhausting the burst, the next request should be rate-limited
        let result = limiter.check(ip);
        assert!(
            result.is_some(),
            "Request after burst exhaustion should be limited"
        );
    }

    #[test]
    fn rate_limits_with_per_ip_config_sets_capacity_and_burst() {
        let rl = RateLimits::disabled().with_per_ip_config(
            NonZeroU32::new(10).unwrap(),
            Some(NonZeroU32::new(20).unwrap()),
            Some(500),
        );
        assert!(rl.per_ip.is_some());
        let per_ip = rl.per_ip.as_ref().unwrap();
        assert_eq!(per_ip.max_capacity(), 500);

        // Default capacity when None
        let rl2 =
            RateLimits::disabled().with_per_ip_config(NonZeroU32::new(10).unwrap(), None, None);
        let per_ip2 = rl2.per_ip.as_ref().unwrap();
        assert_eq!(per_ip2.max_capacity(), DEFAULT_MAX_IP_CAPACITY);
    }

    // ────────────────────────────────
    // PerKeyRateLimiter tests
    // ────────────────────────────────

    #[test]
    fn per_key_rate_limiter_allows_first_request() {
        let limiter = PerKeyRateLimiter::new(NonZeroU32::new(10).unwrap());
        assert!(limiter.is_empty());
        let result = limiter.check("user-a".to_string());
        assert!(result.is_none(), "First request should be allowed");
        assert_eq!(limiter.len(), 1);
    }

    #[test]
    fn per_key_rate_limiter_same_key_limited_different_keys_independent() {
        // 1 req/s with no burst — second request from the same key should be limited
        let limiter = PerKeyRateLimiter::new(NonZeroU32::new(1).unwrap());

        // First request for key "alpha" — allowed
        let r1 = limiter.check("alpha".to_string());
        assert!(r1.is_none(), "First request for alpha should be allowed");

        // Second request for key "alpha" — should be rate-limited
        let r2 = limiter.check("alpha".to_string());
        assert!(
            r2.is_some(),
            "Second immediate request for alpha should be rate-limited"
        );

        // First request for key "beta" — should be allowed (independent bucket)
        let r3 = limiter.check("beta".to_string());
        assert!(
            r3.is_none(),
            "First request for beta should be allowed (independent key)"
        );
        assert_eq!(limiter.len(), 2);
    }

    #[test]
    fn per_key_rate_limiter_cleanup_removes_stale() {
        let limiter = PerKeyRateLimiter::new(NonZeroU32::new(10).unwrap());
        limiter.check("key-1".to_string());
        limiter.check("key-2".to_string());
        assert_eq!(limiter.len(), 2);
        // Cleanup with zero duration removes everything
        limiter.cleanup(std::time::Duration::ZERO);
        assert_eq!(limiter.len(), 0);
    }

    #[test]
    fn per_key_rate_limiter_default_capacity() {
        let limiter = PerKeyRateLimiter::new(NonZeroU32::new(10).unwrap());
        assert_eq!(limiter.max_capacity(), DEFAULT_MAX_KEY_CAPACITY);
    }

    #[test]
    fn per_key_rate_limiter_with_max_capacity_sets_limit() {
        let limiter = PerKeyRateLimiter::with_max_capacity(NonZeroU32::new(10).unwrap(), 3);
        assert_eq!(limiter.max_capacity(), 3);
        assert!(limiter.is_empty());

        // Fill to capacity
        limiter.check("a".to_string());
        limiter.check("b".to_string());
        limiter.check("c".to_string());
        assert_eq!(limiter.len(), 3);

        // New key beyond capacity should be denied (fail-closed)
        let result = limiter.check("d".to_string());
        assert!(
            result.is_some(),
            "New key beyond max_capacity should be denied"
        );
        assert_eq!(limiter.len(), 3, "Should not grow beyond max_capacity");
    }

    #[test]
    fn rate_limits_with_per_principal() {
        let rl = RateLimits::disabled().with_per_principal(NonZeroU32::new(10).unwrap());
        assert!(rl.per_principal.is_some());
        assert_eq!(
            rl.per_principal.as_ref().unwrap().max_capacity(),
            DEFAULT_MAX_KEY_CAPACITY
        );
    }

    #[test]
    fn rate_limits_with_per_principal_config_sets_capacity_and_burst() {
        let rl = RateLimits::disabled().with_per_principal_config(
            NonZeroU32::new(10).unwrap(),
            Some(NonZeroU32::new(20).unwrap()),
            Some(500),
        );
        assert!(rl.per_principal.is_some());
        let per_principal = rl.per_principal.as_ref().unwrap();
        assert_eq!(per_principal.max_capacity(), 500);

        // Default capacity when None
        let rl2 = RateLimits::disabled().with_per_principal_config(
            NonZeroU32::new(10).unwrap(),
            None,
            None,
        );
        let per_principal2 = rl2.per_principal.as_ref().unwrap();
        assert_eq!(per_principal2.max_capacity(), DEFAULT_MAX_KEY_CAPACITY);
    }

    // ── attach_audit_sink: audit_store.sink_failure_fatal wiring (R270-SRV-1) ──
    //
    // The flag was documented, validated and serialized, but the sink call site
    // passed a hardcoded `false`, so setting it did nothing. These assert the
    // config value reaches the logger, through behaviour rather than the flag:
    // `sink_failure_fatal` is pub(crate) to vellaveto-audit, so it cannot be
    // read from here — which is just as well, since what an operator cares
    // about is whether log_entry fails, not what a boolean holds.

    /// A sink whose writes always fail. `NoOpSink` in vellaveto-audit's own
    /// tests returns Ok unconditionally, so there was nothing to reuse.
    #[derive(Debug)]
    struct FailingSink;

    #[async_trait::async_trait]
    impl vellaveto_audit::sink::AuditSink for FailingSink {
        async fn sink(
            &self,
            _entry: &vellaveto_audit::AuditEntry,
        ) -> Result<(), vellaveto_audit::sink::SinkError> {
            Err(vellaveto_audit::sink::SinkError::Write(
                "injected failure".to_string(),
            ))
        }
        async fn flush(&self) -> Result<(), vellaveto_audit::sink::SinkError> {
            Ok(())
        }
        async fn shutdown(&self) -> Result<(), vellaveto_audit::sink::SinkError> {
            Ok(())
        }
        fn is_healthy(&self) -> bool {
            false
        }
        fn pending_count(&self) -> usize {
            0
        }
    }

    #[derive(Debug)]
    struct HealthySink;

    #[async_trait::async_trait]
    impl vellaveto_audit::sink::AuditSink for HealthySink {
        async fn sink(
            &self,
            _entry: &vellaveto_audit::AuditEntry,
        ) -> Result<(), vellaveto_audit::sink::SinkError> {
            Ok(())
        }
        async fn flush(&self) -> Result<(), vellaveto_audit::sink::SinkError> {
            Ok(())
        }
        async fn shutdown(&self) -> Result<(), vellaveto_audit::sink::SinkError> {
            Ok(())
        }
        fn is_healthy(&self) -> bool {
            true
        }
        fn pending_count(&self) -> usize {
            0
        }
    }

    fn audit_store_config(sink_failure_fatal: bool) -> vellaveto_config::AuditStoreConfig {
        vellaveto_config::AuditStoreConfig {
            sink_failure_fatal,
            ..Default::default()
        }
    }

    async fn log_one(logger: &AuditLogger) -> Result<(), vellaveto_audit::AuditError> {
        let action = vellaveto_types::Action::new("file", "read", serde_json::json!({}));
        logger
            .log_entry(&action, &Verdict::Allow, serde_json::json!({}))
            .await
    }

    #[tokio::test]
    async fn attach_audit_sink_honours_fatal_flag() {
        let tmp = tempfile::TempDir::new().unwrap();
        let logger = attach_audit_sink(
            AuditLogger::new(tmp.path().join("audit.jsonl")),
            std::sync::Arc::new(FailingSink),
            &audit_store_config(true),
        );

        assert!(
            log_one(&logger).await.is_err(),
            "sink_failure_fatal = true must surface the sink failure to the caller"
        );
    }

    #[tokio::test]
    async fn attach_audit_sink_defaults_non_fatal() {
        let tmp = tempfile::TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.jsonl");
        let logger = attach_audit_sink(
            AuditLogger::new(log_path),
            std::sync::Arc::new(FailingSink),
            &audit_store_config(false),
        );

        assert!(
            log_one(&logger).await.is_ok(),
            "the documented default is non-fatal: the file log is source of truth"
        );
        assert_eq!(
            logger.load_entries().await.unwrap().len(),
            1,
            "the entry must still reach the file even though the sink failed"
        );
    }

    /// Guards against the fatal flag denying for the wrong reason: with a
    /// working sink it must not fail, so the error above is the sink, not the
    /// flag.
    #[tokio::test]
    async fn attach_audit_sink_ok_when_sink_healthy() {
        let tmp = tempfile::TempDir::new().unwrap();
        let logger = attach_audit_sink(
            AuditLogger::new(tmp.path().join("audit.jsonl")),
            std::sync::Arc::new(HealthySink),
            &audit_store_config(true),
        );

        assert!(
            log_one(&logger).await.is_ok(),
            "fatal mode must not fail a write whose sink succeeded"
        );
    }
}
