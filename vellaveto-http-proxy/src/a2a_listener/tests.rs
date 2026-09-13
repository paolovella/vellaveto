// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1

//! Tests for the parent module.
//!
//! Kept in a `tests.rs` child module rather than an inline `#[cfg(test)]`
//! block so the fixtures here — hard-coded test keys and `http://` URLs —
//! fall under the `paths-ignore` globs in `.github/codeql/codeql-config.yml`,
//! the same way every other test module in this repository does. Being a
//! child module, it keeps access to the parent's private items.

use super::*;
use tower::ServiceExt;
use vellaveto_config::{A2aSignatureConfig, TrustedAgentKey};

const TEST_PUBKEY_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

fn signature_config(trusted: bool) -> A2aSignatureConfig {
    A2aSignatureConfig {
        trusted_keys: if trusted {
            vec![TrustedAgentKey {
                key_id: "key-1".to_string(),
                public_key: TEST_PUBKEY_HEX.to_string(),
                issuer: "https://issuer.example.com".to_string(),
            }]
        } else {
            Vec::new()
        },
        ..Default::default()
    }
}

fn listener_config(require_agent_card: bool) -> A2aConfig {
    A2aConfig {
        enabled: true,
        // TEST-NET-1: routable-looking, never answers, so card fetch fails.
        upstream_url: Some("https://192.0.2.1".to_string()),
        listen_addr: Some("127.0.0.1:0".to_string()),
        require_agent_card,
        signature: signature_config(true),
        ..Default::default()
    }
}

fn build_state(cfg: &A2aConfig, audit_path: &std::path::Path) -> Arc<A2aListenerState> {
    let audit = Arc::new(vellaveto_audit::AuditLogger::new(audit_path.to_path_buf()));
    let policies: Vec<Policy> = Vec::new();
    let engine = PolicyEngine::with_policies(false, &policies).expect("engine");
    Arc::new(
        A2aListenerState::from_config(cfg, Arc::new(engine), Arc::new(policies), audit)
            .expect("listener state"),
    )
}

/// Drive one request through the real router and return the status plus the
/// `event` values the listener audited.
///
/// The status alone cannot distinguish a card-gate denial from a policy
/// denial — with no policies loaded the engine denies too — so the audit
/// record is what actually identifies which gate fired.
async fn post_body(cfg: &A2aConfig, body: &str) -> (StatusCode, Vec<String>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_path = dir.path().join("audit.jsonl");
    let app = router(build_state(cfg, &audit_path));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .expect("request");
    let status = app.oneshot(request).await.expect("response").status();

    let events = std::fs::read_to_string(&audit_path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter_map(|entry| {
            entry
                .pointer("/metadata/event")
                .or_else(|| entry.pointer("/context/event"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .collect();

    (status, events)
}

#[test]
fn test_build_verifier_loads_trusted_keys() {
    // The trust store was previously always empty because nothing called
    // add_trusted_key. This is the step that fills it.
    let verifier = build_verifier(&signature_config(true)).expect("verifier");
    assert_eq!(verifier.trusted_key_count(), 1);
}

#[test]
fn test_build_verifier_rejects_unusable_key() {
    let cfg = A2aSignatureConfig {
        trusted_keys: vec![TrustedAgentKey {
            key_id: "key-1".to_string(),
            public_key: "not-hex".to_string(),
            issuer: "https://issuer.example.com".to_string(),
        }],
        ..Default::default()
    };
    assert!(build_verifier(&cfg).is_err());
}

#[test]
fn test_from_config_requires_upstream_url() {
    let cfg = A2aConfig {
        enabled: true,
        upstream_url: None,
        ..Default::default()
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = Arc::new(vellaveto_audit::AuditLogger::new(
        dir.path().join("audit.jsonl"),
    ));
    let policies: Vec<Policy> = Vec::new();
    let engine = PolicyEngine::with_policies(false, &policies).expect("engine");
    let err = A2aListenerState::from_config(&cfg, Arc::new(engine), Arc::new(policies), audit)
        .expect_err("missing upstream must fail");
    assert!(err.contains("upstream_url is required"));
}

#[tokio::test]
async fn test_request_denied_when_agent_card_cannot_be_verified() {
    // This is the assertion that the enforcement path is real: with card
    // verification required and the card unobtainable, the request is
    // refused rather than forwarded. Before this listener existed, the
    // verifier was never consulted and this request would have gone through.
    let (status, events) = post_body(
        &listener_config(true),
        r#"{"jsonrpc":"2.0","id":1,"method":"message/send","params":{}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        events.iter().any(|e| e == "agent_card_rejected"),
        "the card gate must be what refused this request; audited events: {events:?}"
    );
}

#[tokio::test]
async fn test_card_check_skipped_when_not_required() {
    // With require_agent_card off, the card check is bypassed and the
    // request reaches the policy stage instead — so a 403 here would mean
    // the card gate was firing when it should not.
    let (_status, events) = post_body(
        &listener_config(false),
        r#"{"jsonrpc":"2.0","id":1,"method":"message/send","params":{}}"#,
    )
    .await;
    // The request is still denied here — an empty policy set is fail-closed —
    // but it must be the policy stage that denies it, never the card gate.
    assert!(
        !events.iter().any(|e| e == "agent_card_rejected"),
        "card verification must not run when require_agent_card is false; \
         audited events: {events:?}"
    );
}

#[tokio::test]
async fn test_oversized_body_is_rejected() {
    let mut cfg = listener_config(false);
    cfg.max_message_size = 128;
    let (status, _) = post_body(&cfg, &format!(r#"{{"padding":"{}"}}"#, "x".repeat(4096))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_malformed_json_is_rejected() {
    let (status, _) = post_body(&listener_config(false), "this is not json").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Build a `reqwest::Response` over a fixed body, without a live server.
fn response_with_body(body: Vec<u8>) -> reqwest::Response {
    reqwest::Response::from(
        axum::http::Response::builder()
            .status(200)
            .body(body)
            .expect("response"),
    )
}

#[tokio::test]
async fn test_upstream_body_within_cap_is_read() {
    let body = read_capped(response_with_body(vec![b'x'; 64]), 128)
        .await
        .expect("body within the cap is read");
    assert_eq!(body.len(), 64);
}

/// The request direction was already capped by `max_message_size`; before
/// this, the response direction was not — `json()` buffered whatever the
/// upstream sent. A compromised upstream could exhaust proxy memory with a
/// single reply.
#[tokio::test]
async fn test_oversized_upstream_body_is_rejected() {
    let err = read_capped(response_with_body(vec![b'x'; 4096]), 128)
        .await
        .expect_err("body over the cap must be refused");
    assert!(
        err.contains("max_message_size"),
        "error should name the bound that rejected it, got: {err}"
    );
}
