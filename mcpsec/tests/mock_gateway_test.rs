// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//! End-to-end integration test: runs the full benchmark against a mock gateway
//! that simulates a "perfect" MCP gateway (one that passes all 116 tests).
//!
//! This validates the harness itself — if the mock is correct and the harness
//! scores 100%, the harness logic is sound.

use axum::{extract::Json, http::StatusCode, response::IntoResponse, routing::post, Router};
use mcpsec::{run_benchmark, BenchmarkConfig, GatewayConfig, OutputFormat};
use serde_json::{json, Value};
use std::io::ErrorKind;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

/// Shared state for the mock gateway.
struct MockState {
    /// Counter for rate-limiting simulation.
    request_count: AtomicU32,
}

async fn bind_local_listener() -> Option<tokio::net::TcpListener> {
    match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => Some(listener),
        Err(err) if err.kind() == ErrorKind::PermissionDenied => {
            eprintln!("skipping mock gateway test: local bind permission denied");
            None
        }
        Err(err) => panic!("failed to bind: {err}"),
    }
}

/// Does this payload belong to A17 (Legitimate Traffic Preservation)?
///
/// A correct gateway allows ordinary traffic, so the mock — which models a
/// correct gateway — must too. Before A17 existed the mock defaulted to 403 for
/// everything except 14 special cases, which meant the "perfect gateway" this
/// harness validates against was itself indistinguishable from a brick wall: it
/// scored 100% security and 0% availability.
///
/// Keyed on the explicit `_test_expect` marker rather than on tool/path. A
/// first attempt matched benign-looking parameters and wrongly allowed A4.7
/// ("Secret in error message"), which shares ("db", "query") with A17.10 — a
/// heuristic that silently turns a security test into a pass is exactly the
/// failure this class exists to catch.
fn is_a17_payload(payload: &Value) -> bool {
    payload.get("_test_expect").and_then(|v| v.as_str()) == Some("allow")
}

/// Mock gateway handler that returns the correct response for each test.
///
/// Strategy:
/// - A17 legitimate traffic (`_test_expect: "allow"`): 200 Allow, no findings
/// - Default: 403 Deny (passes is_deny, has_injection, has_dlp, most custom checks)
/// - Special cases identified by payload content for tests needing 200 or specific responses
///
/// The A17 arm is what stops this mock being a brick wall. Without it the
/// "perfect gateway" scored 100% security and 0% availability — it denied every
/// benign request, and nothing in the suite reported that.
async fn mock_evaluate(
    axum::extract::State(state): axum::extract::State<Arc<MockState>>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    let count = state.request_count.fetch_add(1, Ordering::Relaxed);

    let function = payload
        .get("function")
        .and_then(|f| f.as_str())
        .unwrap_or("");
    let tool = payload.get("tool").and_then(|t| t.as_str()).unwrap_or("");

    // A17: legitimate traffic must be allowed through, cleanly.
    if is_a17_payload(&payload) {
        return (
            StatusCode::OK,
            Json(json!({"verdict": "Allow", "inspection": {}})),
        );
    }

    // A4.8: Clean response false-positive check — must return Allow with no findings.
    if function == "read" && tool == "file" {
        if let Some(resp) = payload.get("_test_response") {
            if let Some(content) = resp.get("content").and_then(|c| c.as_array()) {
                if content.iter().any(|item| {
                    item.get("text")
                        .and_then(|t| t.as_str())
                        .is_some_and(|s| s.contains("Hello, World!"))
                }) {
                    return (StatusCode::OK, Json(json!({"verdict": "Allow"})));
                }
            }
        }
    }

    // A8.4: CEF injection — tool name contains pipe. Return 200 with safe CEF output.
    if tool.contains('|') {
        // Escape the pipe in CEF output (replace | with \\|)
        let safe_tool = tool.replace('|', "\\|");
        return (
            StatusCode::OK,
            Json(json!({
                "verdict": {"Deny": {"reason": "blocked"}},
                "cef_output": format!("CEF:0|vellaveto|gw|1.0|deny|tool_blocked|5|dvc=127.0.0.1 tool={safe_tool}")
            })),
        );
    }

    // A8.2: Audit entries with hash fields.
    if function == "audit_entries" {
        return (
            StatusCode::OK,
            Json(json!({
                "entries": [
                    {"id": "1", "entry_hash": "abc123", "prev_hash": "000000"},
                    {"id": "2", "entry_hash": "def456", "prev_hash": "abc123"},
                    {"id": "3", "entry_hash": "ghi789", "prev_hash": "def456"}
                ],
                "audit_enabled": true
            })),
        );
    }

    // A8.3: Collision check — different hashes for different entries.
    if function == "audit_collision_check" {
        return (
            StatusCode::OK,
            Json(json!({
                "hash_a": "sha256_ab_cd_different",
                "hash_b": "sha256_abc_d_different"
            })),
        );
    }

    // A8.4: CEF safe output.
    if function == "audit_verify" {
        // A8.7 also uses audit_verify — both pass with monotonic=true
        return (
            StatusCode::OK,
            Json(json!({"valid": false, "broken_at_index": 1, "monotonic": true})),
        );
    }

    // A10.1: ReDoS — return 400 (rejected).
    if function == "regex_compile" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Nested quantifier rejected"})),
        );
    }

    // A10.2: Oversized message — return 413.
    // Detect by checking if parameters.data is very large.
    if let Some(data) = payload
        .get("parameters")
        .and_then(|p| p.get("data"))
        .and_then(|d| d.as_str())
    {
        if data.len() > 1_000_000 {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({"error": "Message too large"})),
            );
        }
    }

    // A10.3: Parameter bomb — return 200 (handled without crash).
    if let Some(params) = payload.get("parameters").and_then(|p| p.as_object()) {
        if params.len() > 5000 {
            return (
                StatusCode::OK,
                Json(json!({"verdict": {"Deny": {"reason": "Too many parameters"}}})),
            );
        }
    }

    // A10.4: Rate limiting — return 429 after many requests.
    // The runner sends up to 100 rapid requests; trigger 429 after 50.
    if count > 50
        && tool == "file"
        && function == "read"
        && payload.get("_test_response").is_none()
        && payload.get("_test_context").is_none()
    {
        // Only trigger for the simple file/read payload (A10.4)
        if let Some(path) = payload
            .get("parameters")
            .and_then(|p| p.get("path"))
            .and_then(|p| p.as_str())
        {
            if path == "/tmp/test"
                && payload
                    .get("parameters")
                    .and_then(|p| p.as_object())
                    .is_some_and(|m| m.len() == 1)
            {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({"error": "Rate limited", "rate_limited": true})),
                );
            }
        }
    }

    // A16.2: Circuit breaker cooldown — must return 200 with half-open state.
    if function == "circuit_breaker_check" {
        if let Some(recovery) = payload
            .get("parameters")
            .and_then(|p| p.get("recovery_time_secs"))
        {
            if recovery.as_u64().is_some() {
                return (StatusCode::OK, Json(json!({"circuit_state": "HalfOpen"})));
            }
        }
    }

    // A16.3: Cascading failure — return cascade_protection active.
    if function == "cascading_failure_check" {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"cascade_protection": true})),
        );
    }

    // A6.5 / A16.4: Tracker exhaustion / counter overflow — any non-500 response.
    // A10.3: Parameter bomb — any non-500 response.
    // Default 403 handles these.

    // Default: return 403 Deny. This passes:
    // - is_deny (status 403)
    // - has_injection (falls back to is_deny)
    // - has_dlp (falls back to is_deny)
    // - detected (is_deny || has_dlp)
    // - tamper_detected (status 403 accepted)
    // - A7.3 custom (status != 500)
    // - A8.6 (is_deny)
    // - A8.7 (status 403 accepted)
    // - A16.1 (is_deny fallback)
    // - A16.4 (status != 500)
    (
        StatusCode::FORBIDDEN,
        Json(json!({"verdict": {"Deny": {"reason": "blocked by mock gateway"}}})),
    )
}

/// CEF injection test: tool name with pipe needs separate handling.
/// The default 403 handles A8.4 (cef_safe checks status 200 but also
/// falls through if status != 200... wait, cef_safe returns false for non-200).
/// We need to handle A8.4 specially.

#[tokio::test]
async fn test_full_benchmark_against_mock_gateway() {
    // Build the mock gateway
    let state = Arc::new(MockState {
        request_count: AtomicU32::new(0),
    });

    let app = Router::new()
        .route("/api/evaluate", post(mock_evaluate))
        .with_state(state);

    let Some(listener) = bind_local_listener().await else {
        return;
    };
    let addr = listener.local_addr().expect("failed to get address");

    // Spawn the mock server
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("mock server failed");
    });

    // Give the server a moment to start
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Run the full benchmark
    let config = BenchmarkConfig {
        gateway: GatewayConfig {
            base_url: format!("http://{addr}"),
            evaluate_path: "/api/evaluate".to_string(),
            auth_header: None,
        },
        format: OutputFormat::Json,
        timeout_secs: 10,
        concurrency: 1, // Sequential to preserve stateful test ordering
        class_filter: vec![],
    };

    let result = run_benchmark(&config).await;

    // Print results for debugging
    eprintln!("\nMock Gateway Benchmark Results:");
    eprintln!(
        "  Overall: {:.1}% — Tier {}: {}",
        result.overall_score, result.tier, result.tier_name
    );
    eprintln!(
        "  Tests: {}/{} passed",
        result.summary.passed, result.summary.total_tests
    );

    // Print failed tests for debugging
    let failed: Vec<_> = result.attacks.iter().filter(|a| !a.passed).collect();
    if !failed.is_empty() {
        eprintln!("\n  Failed tests:");
        for f in &failed {
            eprintln!("    {} ({}): {}", f.attack_id, f.name, f.details);
        }
    }

    // Assert high pass rate. The mock should pass nearly all tests.
    // Some edge-case tests (A8.4 CEF, A16.2 cooldown) may need tuning.
    assert_eq!(result.summary.total_tests, 116, "Should run all 116 tests");

    // The mock is designed to pass all 116 tests. If any fail, the mock
    // needs updating — this validates harness correctness, not a real gateway.
    assert_eq!(
        result.summary.passed,
        116,
        "Mock gateway should pass all 116 tests, got {}/{}. Failed: {:?}",
        result.summary.passed,
        result.summary.total_tests,
        failed
            .iter()
            .map(|f| f.attack_id.as_str())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_class_filter_against_mock() {
    let state = Arc::new(MockState {
        request_count: AtomicU32::new(0),
    });

    let app = Router::new()
        .route("/api/evaluate", post(mock_evaluate))
        .with_state(state);

    let Some(listener) = bind_local_listener().await else {
        return;
    };
    let addr = listener.local_addr().expect("failed to get address");

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("mock server failed");
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Run only A1 (injection) tests
    let config = BenchmarkConfig {
        gateway: GatewayConfig {
            base_url: format!("http://{addr}"),
            evaluate_path: "/api/evaluate".to_string(),
            auth_header: None,
        },
        format: OutputFormat::Json,
        timeout_secs: 10,
        concurrency: 1,
        class_filter: vec!["A1".to_string()],
    };

    let result = run_benchmark(&config).await;

    assert_eq!(
        result.summary.total_tests, 15,
        "A1 class should have 15 tests, got {}",
        result.summary.total_tests
    );

    // All A1 tests use has_injection which accepts is_deny, so 403 passes all
    assert_eq!(
        result.summary.passed, 15,
        "All A1 tests should pass against mock (403 → is_deny → has_injection)"
    );
}

// ── Deny-everything baseline ────────────────────────────────────────────────
//
// The mock above documents its own strategy as "Default: 403 Deny (passes
// is_deny, has_injection, has_dlp, most custom checks)" plus 14 special cases.
// That raises the question this test answers: how much of the benchmark is
// satisfied by refusing every request?
//
// It matters because MCPSEC's pass conditions lean on denial. Of the 105
// security tests, 57
// use `is_deny` (403/429 or a Deny verdict), and the 27 detection checks
// (`has_injection`, `has_dlp`) fall back to `is_deny` too. Exactly one test
// (`is_clean`, A4.8) checks for a false positive. So a gateway that blocks
// everything — useless, but perfectly "secure" by these checks — should score
// well, and the score cannot distinguish it from one that blocks the right
// things.
//
// This is a CHARACTERIZATION test: it records what the benchmark does today,
// not what it should do. When MCPSEC grows a real over-blocking axis this test
// SHOULD fail, and that failure is the signal the gap closed.

/// A gateway that denies every request with 403 and nothing else.
async fn deny_everything(Json(_payload): Json<Value>) -> impl IntoResponse {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "verdict": {"Deny": {"reason": "denied"}}
        })),
    )
}

#[tokio::test]
async fn deny_everything_gateway_scores_high_which_the_benchmark_should_penalise() {
    let app = Router::new().route("/api/evaluate", post(deny_everything));

    let Some(listener) = bind_local_listener().await else {
        return;
    };
    let addr = listener.local_addr().expect("failed to get address");
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("mock server failed");
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let config = BenchmarkConfig {
        gateway: GatewayConfig {
            base_url: format!("http://{addr}"),
            evaluate_path: "/api/evaluate".to_string(),
            auth_header: None,
        },
        format: OutputFormat::Json,
        timeout_secs: 10,
        concurrency: 1,
        class_filter: vec![],
    };

    let result = run_benchmark(&config).await;

    eprintln!("\n=== DENY-EVERYTHING GATEWAY (blocks 100% of traffic) ===");
    eprintln!(
        "  Security:     {:.1}% — Tier {}: {}",
        result.overall_score, result.tier, result.tier_name
    );
    eprintln!("  Availability: {:.1}%", result.availability_score);
    eprintln!(
        "  Tests: {}/{} passed",
        result.summary.passed, result.summary.total_tests
    );
    let failed: Vec<_> = result.attacks.iter().filter(|a| !a.passed).collect();
    eprintln!("  Failed ({}):", failed.len());
    for f in &failed {
        eprintln!("    {} ({}) [{}]", f.attack_id, f.name, f.class);
    }

    assert_eq!(result.summary.total_tests, 116, "should run all 116 tests");

    // The security axis is UNCHANGED by the availability work: refusal still
    // satisfies most of it by construction, and that is the finding this test
    // was written to record. Lower bound rather than an exact figure so
    // unrelated additions do not churn it.
    assert!(
        result.overall_score >= 80.0,
        "a deny-everything gateway still scores {:.1}% on the security axis. \
         If this dropped below 80, the security scoring itself changed — say so.",
        result.overall_score
    );

    // The availability axis is the point. A gateway that blocks 100% of traffic
    // must score 0 here. Before A17 existed there was exactly one
    // false-positive check in 105 tests and nothing reported this at all.
    assert_eq!(
        result.availability_score, 0.0,
        "a gateway that denies everything must score 0 on availability, got {:.1}%",
        result.availability_score
    );
}
