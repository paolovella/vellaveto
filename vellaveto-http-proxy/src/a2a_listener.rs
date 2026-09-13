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
    /// Cap on the upstream response body, from `a2a.max_message_size`.
    max_message_size: usize,
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

        // No redirect following, for the same reason the card fetcher refuses
        // it: the upstream is the one host an operator vetted, and a redirect
        // would hand a request that has already cleared policy and DLP to a
        // host nobody vetted, then return that host's response to the client.
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("failed to build A2A upstream client: {e}"))?;

        Ok(Self {
            service: Arc::new(A2aProxyService::new(proxy_config, engine, policies, cache)),
            fetcher,
            upstream_url,
            require_agent_card: cfg.require_agent_card,
            audit,
            client,
            max_message_size: cfg.max_message_size,
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
            // Bounded read: `json()` would buffer whatever the upstream sends.
            // The request direction is already capped by `max_message_size`;
            // the response direction gets the same cap rather than trusting a
            // host that may itself be compromised.
            let body = match read_capped(response, state.max_message_size).await {
                Ok(body) => body,
                Err(e) => {
                    tracing::warn!("A2A upstream body rejected: {}", e);
                    return upstream_error();
                }
            };
            match serde_json::from_slice::<Value>(&body) {
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

/// Read a response body, refusing to buffer more than `max_bytes`.
///
/// Streams and counts rather than trusting `Content-Length`, which the sender
/// controls independently of what it actually sends. Mirrors the card
/// fetcher's `read_capped_body`.
async fn read_capped(response: reqwest::Response, max_bytes: usize) -> Result<Vec<u8>, String> {
    let mut response = response;
    let mut body = Vec::new();

    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("failed reading upstream body: {e}"))?
    {
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(format!(
                "upstream response exceeds max_message_size ({max_bytes} bytes)"
            ));
        }
        body.extend_from_slice(&chunk);
    }

    Ok(body)
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
mod tests;
