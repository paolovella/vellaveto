// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Vellaveto MCP HTTP Proxy library.
//!
//! Re-exports proxy, session, and OAuth modules for use by both the binary
//! and integration tests.

#[cfg(feature = "a2a")]
pub mod a2a_listener;
pub mod federation;
pub mod oauth;
pub mod proxy;
pub mod session;

/// Metrics instrumentation for the HTTP proxy.
pub mod proxy_metrics {
    /// Record a DLP finding with pattern type.
    /// IMPROVEMENT_PLAN 1.1: DLP findings should be metered for observability.
    pub fn record_dlp_finding(pattern_type: &str) {
        metrics::counter!(
            "vellaveto_dlp_findings_total",
            "pattern_type" => pattern_type.to_string()
        )
        .increment(1);
    }

    /// Record DLP scan latency in seconds.
    pub fn record_dlp_scan_latency(seconds: f64) {
        metrics::histogram!("vellaveto_dlp_scan_duration_seconds").record(seconds);
    }

    /// Record a DPoP validation failure with a stable reason code.
    pub fn record_dpop_failure(reason: &str) {
        metrics::counter!(
            "vellaveto_oauth_dpop_failures_total",
            "reason" => reason.to_string()
        )
        .increment(1);
    }

    /// Record that a DPoP replay (`jti` reuse) was detected.
    pub fn record_dpop_replay_detected() {
        metrics::counter!("vellaveto_oauth_dpop_replay_total").increment(1);
    }
}
