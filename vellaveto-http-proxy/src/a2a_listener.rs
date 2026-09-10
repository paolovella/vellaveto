// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1

//! A2A listener: the enforcement path for Agent Card signatures.
//!
//! `A2aProxyService` and `AgentCardSignatureVerifier` existed and were tested
//! but were never constructed outside their own module, so no A2A traffic was
//! ever mediated and no Agent Card was ever verified. This module is the
//! consumer that makes both run.
//!
//! It binds a dedicated listener on `a2a.listen_addr` and forwards to
//! `a2a.upstream_url`, which is the shape `A2aConfig` was already written for.
//! Nothing here touches the stdio relay.
//!
//! # Order of checks
//!
//! 1. Resolve and verify the upstream's Agent Card (cache-first).
//! 2. Run `A2aProxyService::process_request` for policy, DLP, injection,
//!    shadow-agent and circuit-breaker checks.
//! 3. Forward to the upstream only if both pass.
//!
//! A failure at either step is denied and audited with an ACIS envelope, the
//! same as every other transport.

use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde_json::{json, Value};

use vellaveto_audit::AuditLogger;
use vellaveto_config::{A2aConfig, A2aSignatureConfig};
use vellaveto_engine::PolicyEngine;
use vellaveto_mcp::a2a::{
    A2aProxyConfig, A2aProxyDecision, A2aProxyService, AgentCardCache, AgentCardFetcher,
    AgentCardSignatureVerifier, AgentSigningKey, SignatureEnforcementConfig,
};
use vellaveto_mcp::mediation::build_acis_envelope;
use vellaveto_types::{Action, DecisionOrigin, Policy, Verdict};

/// Everything the A2A listener needs to serve a request.
pub struct A2aListenerState {
    service: Arc<A2aProxyService>,
    fetcher: AgentCardFetcher,
    upstream_url: String,
    require_agent_card: bool,
    audit: Arc<AuditLogger>,
    client: reqwest::Client,
}

impl std::fmt::Debug for A2aListenerState {
    /// Manual impl: prints only non-sensitive fields. The fetcher holds the
    /// verifier and its trust store, and has its own redacting `Debug`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("A2aListenerState")
            .field("upstream_url", &self.upstream_url)
            .field("require_agent_card", &self.require_agent_card)
            .field("fetcher", &self.fetcher)
            .finish_non_exhaustive()
    }
}

/// Build an `AgentCardSignatureVerifier` from configuration.
///
/// This is the step that had no implementation: the verifier's trust store is
/// populated through `add_trusted_key`, and nothing ever called it, so the
/// store was always empty and no card could verify.
///
/// # Errors
///
/// Fails if a configured key is not a usable Ed25519 verifying key. Config
/// validation already checks the encoding, so this is the second gate rather
/// than the first.
pub fn build_verifier(cfg: &A2aSignatureConfig) -> Result<AgentCardSignatureVerifier, String> {
    let verifier = AgentCardSignatureVerifier::new(SignatureEnforcementConfig {
        enabled: cfg.enabled,
        max_token_lifetime_secs: cfg.max_token_lifetime_secs,
        clock_skew_secs: cfg.clock_skew_secs,
        require_card_hash_match: cfg.require_card_hash_match,
    });

    for key in &cfg.trusted_keys {
        let bytes = hex::decode(&key.public_key).map_err(|e| {
            format!(
                "a2a.signature.trusted_keys entry '{}' public_key is not hex: {e}",
                key.key_id
            )
        })?;
        let signing_key = AgentSigningKey::new(&key.key_id, &bytes, &key.issuer)
            .map_err(|e| format!("a2a.signature.trusted_keys entry '{}': {e}", key.key_id))?;
        verifier
            .add_trusted_key(signing_key)
            .map_err(|e| format!("a2a.signature.trusted_keys entry '{}': {e}", key.key_id))?;
    }

    Ok(verifier)
}

impl A2aListenerState {
    /// Assemble listener state from configuration.
    ///
    /// # Errors
    ///
    /// Fails if `upstream_url` is missing, a trusted key is unusable, or the
    /// HTTP client cannot be built.
    pub fn from_config(
        cfg: &A2aConfig,
        engine: Arc<PolicyEngine>,
        policies: Arc<Vec<Policy>>,
        audit: Arc<AuditLogger>,
    ) -> Result<Self, String> {
        let upstream_url = cfg
            .upstream_url
            .clone()
            .ok_or_else(|| "a2a.upstream_url is required when a2a.enabled is true".to_string())?;

        let verifier = Arc::new(build_verifier(&cfg.signature)?);
        let cache = Arc::new(AgentCardCache::new(cfg.agent_card_cache_secs));
        let timeout = Duration::from_millis(cfg.request_timeout_ms);

        let fetcher = AgentCardFetcher::new(
            verifier,
            cache.clone(),
            timeout,
            // Signatures are mandatory only when cards themselves are required
            // AND enforcement is on. Either switch off makes absence tolerable;
            // a present-but-invalid signature is still always a rejection.
            cfg.require_agent_card && cfg.signature.enabled,
        )
        .map_err(|e| format!("failed to build agent card fetcher: {e}"))?;

        let proxy_config = A2aProxyConfig {
            max_message_size: cfg.max_message_size,
            enable_circuit_breaker: cfg.enable_circuit_breaker,
            enable_shadow_agent_detection: cfg.enable_shadow_agent_detection,
            enable_dlp_scanning: cfg.enable_dlp_scanning,
            enable_injection_detection: cfg.enable_injection_detection,
            allowed_task_operations: cfg.allowed_task_operations.clone(),
            ..Default::default()
        };

        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| format!("failed to build A2A upstream client: {e}"))?;

        Ok(Self {
            service: Arc::new(A2aProxyService::new(proxy_config, engine, policies, cache)),
            fetcher,
            upstream_url,
            require_agent_card: cfg.require_agent_card,
            audit,
            client,
        })
    }
}

/// Router exposing the A2A JSON-RPC endpoint.
pub fn router(state: Arc<A2aListenerState>) -> Router {
    Router::new().route("/", post(handle_a2a)).with_state(state)
}

/// Bind and serve the A2A listener.
///
/// # Errors
///
/// Fails if `listen_addr` is missing or cannot be bound.
pub async fn serve(cfg: &A2aConfig, state: Arc<A2aListenerState>) -> Result<(), String> {
    let addr = cfg
        .listen_addr
        .clone()
        .ok_or_else(|| "a2a.listen_addr is required when a2a.enabled is true".to_string())?;

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("failed to bind A2A listener on {addr}: {e}"))?;

    tracing::info!(
        addr = %addr,
        upstream = %state.upstream_url,
        require_agent_card = state.require_agent_card,
        "A2A listener started with Agent Card signature enforcement"
    );

    axum::serve(listener, router(state))
        .await
        .map_err(|e| format!("A2A listener failed: {e}"))
}

/// Deny a request, audit it, and return a JSON-RPC error.
///
/// The client gets a generic message; the specific reason goes to the audit
/// record and the server log, matching how the other transports report denials.
async fn deny(state: &A2aListenerState, action: Action, reason: String, event: &str) -> Response {
    let verdict = Verdict::Deny {
        reason: reason.clone(),
    };
    let envelope = build_acis_envelope(
        &uuid::Uuid::new_v4().to_string(),
        &action,
        &verdict,
        DecisionOrigin::PolicyEngine,
        "a2a",
        &[],
        None,
        None,
        None,
        None,
    );

    if let Err(e) = state
        .audit
        .log_entry_with_acis(
            &action,
            &verdict,
            json!({
                "source": "a2a_listener",
                "event": event,
                "reason": reason,
                "upstream": state.upstream_url,
            }),
            envelope,
        )
        .await
    {
        tracing::warn!("Failed to audit A2A denial: {}", e);
    }

    tracing::warn!(event = %event, reason = %reason, "A2A request denied");

    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "jsonrpc": "2.0",
            "id": Value::Null,
            "error": { "code": -32600, "message": "Request denied" }
        })),
    )
        .into_response()
}

/// Handle one A2A JSON-RPC request.
async fn handle_a2a(State(state): State<Arc<A2aListenerState>>, body: Bytes) -> Response {
    // 1. Agent Card verification. This is the check the "Agent Card Ed25519
    //    signature enforcement" claim refers to, and the first thing that has
    //    ever actually run it.
    if state.require_agent_card {
        if let Err(e) = state.fetcher.fetch_and_verify(&state.upstream_url).await {
            return deny(
                &state,
                Action::new("a2a", "agent_card_verification", Value::Null),
                e.to_string(),
                "agent_card_rejected",
            )
            .await;
        }
    }

    // 2. Policy, DLP, injection, shadow-agent and circuit-breaker checks.
    let decision = match state.service.process_request(&body) {
        Ok(decision) => decision,
        Err(e) => {
            return deny(
                &state,
                Action::new("a2a", "process_request", Value::Null),
                e.to_string(),
                "a2a_request_rejected",
            )
            .await;
        }
    };

    let message = match decision {
        A2aProxyDecision::Block {
            reason, verdict, ..
        } => {
            let action = Action::new("a2a", "process_request", Value::Null);
            let reason = verdict
                .as_ref()
                .and_then(|v| match v {
                    Verdict::Deny { reason } => Some(reason.clone()),
                    _ => None,
                })
                .unwrap_or(reason);
            return deny(&state, action, reason, "a2a_policy_denied").await;
        }
        A2aProxyDecision::Forward { message, .. } | A2aProxyDecision::PassThrough { message } => {
            message
        }
    };

    // 3. Forward upstream.
    match state
        .client
        .post(&state.upstream_url)
        .json(&message)
        .send()
        .await
    {
        Ok(response) => {
            let status =
                StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            match response.json::<Value>().await {
                Ok(payload) => (status, Json(payload)).into_response(),
                Err(e) => {
                    tracing::warn!("A2A upstream returned an unreadable body: {}", e);
                    upstream_error()
                }
            }
        }
        Err(e) => {
            tracing::warn!("A2A upstream request failed: {}", e);
            state.service.record_upstream_failure(&state.upstream_url);
            upstream_error()
        }
    }
}

/// Generic upstream failure response — no upstream detail reaches the client.
fn upstream_error() -> Response {
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({
            "jsonrpc": "2.0",
            "id": Value::Null,
            "error": { "code": -32603, "message": "Upstream unavailable" }
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;
    use vellaveto_config::{A2aSignatureConfig, TrustedAgentKey};

    const TEST_PUBKEY_HEX: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

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
        let (status, _) =
            post_body(&cfg, &format!(r#"{{"padding":"{}"}}"#, "x".repeat(4096))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_malformed_json_is_rejected() {
        let (status, _) = post_body(&listener_config(false), "this is not json").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
}
