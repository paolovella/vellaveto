// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//! MCPSEC: MCP Security Benchmark Framework
//!
//! Vendor-neutral security evaluation for MCP gateways.
//! Tests 10 security properties across 17 attack classes (116 tests).

pub mod attacks;
pub mod compare;
pub mod remediation;
pub mod report;
pub mod runner;
pub mod scoring;

use serde::{Deserialize, Serialize};

/// Configuration for a benchmark run.
#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    /// Gateway configuration (URL, auth, paths).
    pub gateway: GatewayConfig,
    /// Output format.
    pub format: OutputFormat,
    /// Per-request timeout in seconds.
    pub timeout_secs: u64,
    /// Number of concurrent test requests.
    pub concurrency: usize,
    /// Optional class filter (e.g., ["A1", "A4"]). Empty = run all.
    pub class_filter: Vec<String>,
}

/// Gateway connection configuration.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// Base URL of the gateway (e.g., `http://localhost:3000`).
    pub base_url: String,
    /// Path to the evaluate endpoint (e.g., `/api/evaluate`).
    pub evaluate_path: String,
    /// Optional Bearer token for authentication.
    pub auth_header: Option<String>,
}

/// Output format for benchmark results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Markdown,
    Ocsf,
    Junit,
}

/// Result of a single attack test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackResult {
    /// Attack identifier (e.g., "A1.1").
    pub attack_id: String,
    /// Human-readable name.
    pub name: String,
    /// Attack class (e.g., "Prompt Injection Evasion").
    pub class: String,
    /// Whether the gateway correctly blocked/detected the attack.
    pub passed: bool,
    /// Request latency in nanoseconds.
    pub latency_ns: u64,
    /// Details about the test outcome.
    pub details: String,
}

/// Score for a single security property.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyScore {
    /// Property identifier (e.g., "P1").
    pub property_id: String,
    /// Property name.
    pub name: String,
    /// Score as percentage (0-100).
    pub score: f64,
    /// Number of tests that passed.
    pub tests_passed: usize,
    /// Total number of tests.
    pub tests_total: usize,
}

/// Complete benchmark result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    /// Framework identifier.
    pub framework: String,
    /// Framework version.
    pub version: String,
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Gateway name.
    pub gateway: String,
    /// Gateway version (if reported).
    pub gateway_version: String,
    /// Overall SECURITY score (0-100), weighted across properties P1-P10.
    pub overall_score: f64,
    /// Availability score (0-100): the percentage of A17 legitimate-traffic
    /// checks that were allowed through.
    ///
    /// Separate from `overall_score` on purpose. A gateway that refuses every
    /// request scores highly on the security axis by construction — 57 of the
    /// security tests pass on a denial alone — so the security number cannot
    /// distinguish "secure" from "closed". This one can.
    pub availability_score: f64,
    /// Tier (0-5).
    pub tier: u8,
    /// Tier name.
    pub tier_name: String,
    /// Per-property scores.
    pub properties: Vec<PropertyScore>,
    /// Individual attack results.
    pub attacks: Vec<AttackResult>,
    /// Summary statistics.
    pub summary: BenchmarkSummary,
}

/// Summary statistics for a benchmark run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkSummary {
    pub total_tests: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
}

/// Run the full benchmark suite against a gateway.
pub async fn run_benchmark(config: &BenchmarkConfig) -> BenchmarkResult {
    let tests = runner::filter_tests_by_class(attacks::all_tests(), &config.class_filter);
    let attack_results = runner::run_tests(
        &tests,
        &config.gateway,
        config.timeout_secs,
        config.concurrency,
    )
    .await;
    let properties = scoring::calculate_property_scores(&attack_results);
    let overall_score = scoring::calculate_overall_score(&properties);
    let availability_score = scoring::calculate_availability_score(&attack_results);
    let tier = scoring::score_to_tier(overall_score);
    let tier_name = scoring::tier_name(tier);

    let passed = attack_results.iter().filter(|r| r.passed).count();
    let total = attack_results.len();

    BenchmarkResult {
        framework: "MCPSEC".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        gateway: config.gateway.base_url.clone(),
        gateway_version: String::new(),
        overall_score,
        availability_score,
        tier,
        tier_name: tier_name.to_string(),
        properties,
        attacks: attack_results,
        summary: BenchmarkSummary {
            total_tests: total,
            passed,
            failed: total - passed,
            skipped: 0,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gateway_config_construction() {
        let cfg = GatewayConfig {
            base_url: "http://localhost:3000".to_string(),
            evaluate_path: "/api/evaluate".to_string(),
            auth_header: Some("test-token".to_string()),
        };
        assert_eq!(cfg.base_url, "http://localhost:3000");
        assert_eq!(cfg.evaluate_path, "/api/evaluate");
        assert_eq!(cfg.auth_header.as_deref(), Some("test-token"));
    }

    #[test]
    fn test_gateway_config_no_auth() {
        let cfg = GatewayConfig {
            base_url: "https://gw.example.com".to_string(),
            evaluate_path: "/evaluate".to_string(),
            auth_header: None,
        };
        assert!(cfg.auth_header.is_none());
    }

    #[test]
    fn test_output_format_equality() {
        assert_eq!(OutputFormat::Json, OutputFormat::Json);
        assert_eq!(OutputFormat::Markdown, OutputFormat::Markdown);
        assert_ne!(OutputFormat::Json, OutputFormat::Markdown);
    }

    #[test]
    fn test_benchmark_config_construction() {
        let cfg = BenchmarkConfig {
            gateway: GatewayConfig {
                base_url: "http://localhost:3000".to_string(),
                evaluate_path: "/api/evaluate".to_string(),
                auth_header: None,
            },
            format: OutputFormat::Json,
            timeout_secs: 30,
            concurrency: 4,
            class_filter: vec![],
        };
        assert_eq!(cfg.timeout_secs, 30);
        assert_eq!(cfg.concurrency, 4);
        assert_eq!(cfg.format, OutputFormat::Json);
        assert!(cfg.class_filter.is_empty());
    }

    #[test]
    fn test_attack_result_serialization_roundtrip() {
        let result = AttackResult {
            attack_id: "A1.1".to_string(),
            name: "Classic injection".to_string(),
            class: "Prompt Injection".to_string(),
            passed: true,
            latency_ns: 42_000,
            details: "Blocked correctly".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: AttackResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.attack_id, "A1.1");
        assert_eq!(parsed.name, "Classic injection");
        assert!(parsed.passed);
        assert_eq!(parsed.latency_ns, 42_000);
    }

    #[test]
    fn test_property_score_serialization_roundtrip() {
        let score = PropertyScore {
            property_id: "P4".to_string(),
            name: "Injection Resistance".to_string(),
            score: 85.5,
            tests_passed: 17,
            tests_total: 20,
        };
        let json = serde_json::to_string(&score).unwrap();
        let parsed: PropertyScore = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.property_id, "P4");
        assert_eq!(parsed.score, 85.5);
        assert_eq!(parsed.tests_passed, 17);
        assert_eq!(parsed.tests_total, 20);
    }

    #[test]
    fn test_benchmark_summary_serialization_roundtrip() {
        let summary = BenchmarkSummary {
            total_tests: 64,
            passed: 50,
            failed: 14,
            skipped: 0,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let parsed: BenchmarkSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_tests, 64);
        assert_eq!(parsed.passed, 50);
        assert_eq!(parsed.failed, 14);
        assert_eq!(parsed.skipped, 0);
    }

    #[test]
    fn test_benchmark_result_serialization_roundtrip() {
        let result = BenchmarkResult {
            framework: "MCPSEC".to_string(),
            version: "1.0.0".to_string(),
            timestamp: "2026-03-01T00:00:00Z".to_string(),
            gateway: "http://localhost:3000".to_string(),
            gateway_version: "6.0.0".to_string(),
            overall_score: 75.0,
            availability_score: 100.0,
            tier: 3,
            tier_name: "Strong".to_string(),
            properties: vec![],
            attacks: vec![],
            summary: BenchmarkSummary {
                total_tests: 0,
                passed: 0,
                failed: 0,
                skipped: 0,
            },
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: BenchmarkResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.framework, "MCPSEC");
        assert_eq!(parsed.version, "1.0.0");
        assert_eq!(parsed.overall_score, 75.0);
        assert_eq!(parsed.tier, 3);
        assert_eq!(parsed.tier_name, "Strong");
    }

    #[test]
    fn test_attack_result_debug_format() {
        let result = AttackResult {
            attack_id: "A2.1".to_string(),
            name: "Schema poisoning".to_string(),
            class: "Schema Integrity".to_string(),
            passed: false,
            latency_ns: 100_000,
            details: "Not detected".to_string(),
        };
        let debug = format!("{result:?}");
        assert!(debug.contains("A2.1"));
        assert!(debug.contains("Schema poisoning"));
    }

    #[test]
    fn test_benchmark_summary_failed_plus_passed_equals_total() {
        let summary = BenchmarkSummary {
            total_tests: 64,
            passed: 50,
            failed: 14,
            skipped: 0,
        };
        assert_eq!(
            summary.passed + summary.failed + summary.skipped,
            summary.total_tests
        );
    }
}
