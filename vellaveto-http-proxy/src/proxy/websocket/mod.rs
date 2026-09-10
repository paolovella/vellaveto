// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! WebSocket transport for MCP JSON-RPC messages (SEP-1288).
//!
//! Implements a WebSocket reverse proxy that sits between MCP clients and
//! an upstream MCP server. WebSocket messages (text frames) are parsed as
//! JSON-RPC, classified via `vellaveto_mcp::extractor`, evaluated against
//! loaded policies, and forwarded to the upstream server.
//!
//! Security invariants:
//! - **Fail-closed**: Unparseable messages close the connection (code 1008).
//! - **No binary frames**: Only text frames are accepted (code 1003 for binary).
//! - **Session binding**: Each WS connection is bound to exactly one session.
//! - **Canonicalization**: Re-serialized JSON forwarded (TOCTOU defense).

use axum::{
    extract::{
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, State,
    },
    http::HeaderMap,
    response::Response,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use vellaveto_mcp::extractor::{self, MessageType};
use vellaveto_mcp::inspection::{
    inspect_for_injection, scan_notification_for_secrets, scan_parameters_for_secrets,
    scan_response_for_secrets, scan_text_for_secrets, scan_tool_descriptions,
    scan_tool_descriptions_with_scanner,
};
use vellaveto_mcp::mediation::{
    build_acis_envelope_with_security_context, build_secondary_acis_envelope_with_security_context,
    mediate_with_security_context,
};
use vellaveto_mcp::output_validation::ValidationResult;
use vellaveto_types::acis::{AcisDecisionEnvelope, DecisionOrigin};
use vellaveto_types::{Action, EvaluationContext, RuntimeSecurityContext, Verdict};

use super::auth::{validate_agent_identity, validate_api_key, validate_oauth};
use super::call_chain::{
    check_privilege_escalation, sync_session_call_chain_from_headers, take_tracked_tool_call,
    track_pending_tool_call,
};
use super::origin::validate_origin;
use super::{server_request, ProxyState};
use crate::proxy_metrics::record_dlp_finding;

const INVALID_PRESENTED_APPROVAL_REASON: &str = "Supplied approval is not valid for this action";

/// Configuration for WebSocket transport.
#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    /// Maximum message size in bytes (default: 1 MB).
    pub max_message_size: usize,
    /// Idle timeout in seconds — close connection after no message activity (default: 300s).
    /// SECURITY (FIND-R182-001): True idle timeout that resets on every message.
    pub idle_timeout_secs: u64,
    /// Maximum messages per second per connection for client-to-upstream (default: 100).
    pub message_rate_limit: u32,
    /// Maximum messages per second per connection for upstream-to-client (default: 500).
    /// SECURITY (FIND-R46-WS-003): Rate limits on the upstream→client direction prevent
    /// a malicious upstream from flooding the client with responses.
    pub upstream_rate_limit: u32,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            max_message_size: 1_048_576,
            idle_timeout_secs: 300,
            message_rate_limit: 100,
            upstream_rate_limit: 500,
        }
    }
}

/// WebSocket close codes per RFC 6455.
const CLOSE_POLICY_VIOLATION: u16 = 1008;
const CLOSE_UNSUPPORTED_DATA: u16 = 1003;
/// Close code for oversized messages. Used by axum's `max_message_size`
/// automatically; kept here for documentation and test assertions.
#[cfg(test)]
const CLOSE_MESSAGE_TOO_BIG: u16 = 1009;
const CLOSE_NORMAL: u16 = 1000;

/// Global WebSocket metrics counters.
static WS_CONNECTIONS_TOTAL: AtomicU64 = AtomicU64::new(0);
static WS_MESSAGES_TOTAL: AtomicU64 = AtomicU64::new(0);

type UpstreamWsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
type UpstreamWsSink =
    futures_util::stream::SplitSink<UpstreamWsStream, tokio_tungstenite::tungstenite::Message>;

/// Record WebSocket connection metric.
fn record_ws_connection() {
    // SECURITY (FIND-R182-003): Use saturating arithmetic to prevent overflow.
    // SECURITY (CA-005): SeqCst for security-adjacent metrics counters.
    let _ = WS_CONNECTIONS_TOTAL.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
        Some(v.saturating_add(1))
    });
    metrics::counter!("vellaveto_ws_connections_total").increment(1);
}

/// Record WebSocket message metric.
fn record_ws_message(direction: &str) {
    // SECURITY (FIND-R182-003): Use saturating arithmetic to prevent overflow.
    // SECURITY (CA-005): SeqCst for security-adjacent metrics counters.
    let _ = WS_MESSAGES_TOTAL.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
        Some(v.saturating_add(1))
    });
    metrics::counter!(
        "vellaveto_ws_messages_total",
        "direction" => direction.to_string()
    )
    .increment(1);
}

fn decrement_ws_in_flight(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
        if value == 0 {
            None
        } else {
            Some(value - 1)
        }
    });
}

async fn send_text_to_upstream(
    upstream_sink: &Arc<Mutex<UpstreamWsSink>>,
    in_flight_client_requests: &Arc<AtomicU64>,
    parsed: &Value,
    forward_text: String,
) -> Result<(), tokio_tungstenite::tungstenite::Error> {
    let tracked = server_request::json_rpc_request_info(parsed).is_some();
    if tracked {
        let _ =
            in_flight_client_requests.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                Some(value.saturating_add(1))
            });
    }

    let result = {
        let mut sink = upstream_sink.lock().await;
        sink.send(tokio_tungstenite::tungstenite::Message::Text(
            forward_text.into(),
        ))
        .await
    };

    if tracked && result.is_err() {
        decrement_ws_in_flight(in_flight_client_requests);
    }

    result
}

/// Get current connection count (for testing).
#[cfg(test)]
pub(crate) fn ws_connections_count() -> u64 {
    WS_CONNECTIONS_TOTAL.load(Ordering::SeqCst)
}

/// Get current message count (for testing).
#[cfg(test)]
pub(crate) fn ws_messages_count() -> u64 {
    WS_MESSAGES_TOTAL.load(Ordering::SeqCst)
}

#[derive(Clone)]
struct WsHandshakeSecurity {
    oauth_claims: Option<crate::proxy::auth::OAuthValidationEvidence>,
    headers: HeaderMap,
}

fn build_ws_runtime_security_context(
    msg: &Value,
    action: &Action,
    headers: &HeaderMap,
    inputs: super::helpers::TransportSecurityInputs<'_>,
) -> Option<RuntimeSecurityContext> {
    super::helpers::build_runtime_security_context(msg, action, headers, inputs)
}

fn refresh_ws_acis_envelope(
    envelope: &AcisDecisionEnvelope,
    action: &Action,
    verdict: &Verdict,
    origin: DecisionOrigin,
    session_id: &str,
    eval_ctx: &EvaluationContext,
    security_context: Option<&RuntimeSecurityContext>,
) -> AcisDecisionEnvelope {
    build_acis_envelope_with_security_context(
        &envelope.decision_id,
        action,
        verdict,
        origin,
        "websocket",
        &envelope.findings,
        envelope.evaluation_us,
        Some(session_id),
        None,
        Some(eval_ctx),
        security_context,
    )
}

use vellaveto_types::is_unicode_format_char as is_unicode_format_char_ws;

/// Query parameters for the WebSocket upgrade endpoint.
#[derive(Debug, serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct WsQueryParams {
    /// Optional session ID for session resumption.
    #[serde(default)]
    pub session_id: Option<String>,
}

/// Handle WebSocket upgrade request at `/mcp/ws`.
///
/// Authenticates the request, validates origin, creates/resumes a session,
/// and upgrades the HTTP connection to a WebSocket.
pub async fn handle_ws_upgrade(
    State(state): State<ProxyState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    query: axum::extract::Query<WsQueryParams>,
    ws: WebSocketUpgrade,
) -> Response {
    // 1. Validate origin (CSRF / DNS rebinding defense)
    if let Err(resp) = validate_origin(&headers, &state.bind_addr, &state.allowed_origins) {
        return resp;
    }

    // 2. Authenticate before upgrade (API key or OAuth)
    if let Err(resp) = validate_api_key(&state, &headers) {
        return resp;
    }

    // SECURITY (FIND-R53-WS-001): Validate OAuth token at upgrade time.
    // Parity with HTTP POST (handlers.rs:154) and GET (handlers.rs:2864).
    // Without this, WS connections bypass token expiry checks.
    let oauth_claims = match validate_oauth(
        &state,
        &headers,
        "GET",
        &super::auth::build_effective_request_uri(
            &headers,
            state.bind_addr,
            &axum::http::Uri::from_static("/mcp/ws"),
            false,
        ),
        query.session_id.as_deref(),
    )
    .await
    {
        Ok(claims) => claims,
        Err(response) => return response,
    };

    // SECURITY (FIND-R53-WS-002, FIND-R159-003): Validate agent identity at upgrade time.
    // Parity with HTTP POST (handlers.rs:160) and GET (handlers.rs:2871).
    // FIND-R159-003: Identity MUST be stored in session (was previously discarded with `_`).
    let agent_identity = match validate_agent_identity(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };

    // SECURITY (FIND-R55-WS-004, FIND-R81-001): Validate session_id length and
    // control/format characters from query parameter. Parity with HTTP POST/GET
    // handlers (handlers.rs:154, handlers.rs:2928) which reject control chars.
    // SECURITY (FIND-R81-WS-001): Also reject Unicode format characters (zero-width,
    // bidi overrides, BOM) that can bypass string-based security checks.
    let ws_session_id = query.session_id.as_deref().filter(|id| {
        !id.is_empty()
            && id.len() <= 128
            && !id
                .chars()
                .any(|c| c.is_control() || is_unicode_format_char_ws(c))
    });

    // 3. Get or create session
    let session_id = state.sessions.get_or_create(ws_session_id);

    // SECURITY (FIND-R53-WS-003): Session ownership binding — prevent session fixation.
    // Parity with HTTP GET (handlers.rs:2914-2953).
    if let Some(ref claims) = oauth_claims {
        if let Some(mut session) = state.sessions.get_mut(&session_id) {
            match &session.oauth_subject {
                Some(owner) if owner != &claims.sub => {
                    tracing::warn!(
                        session_id = %session_id,
                        owner = %owner,
                        requester = %claims.sub,
                        "WS upgrade rejected: session owned by different principal"
                    );
                    return axum::response::IntoResponse::into_response((
                        axum::http::StatusCode::FORBIDDEN,
                        axum::Json(json!({
                            "error": "Session belongs to another principal"
                        })),
                    ));
                }
                None => {
                    // Bind session to this OAuth subject
                    session.oauth_subject = Some(claims.sub.clone());
                    // SECURITY (FIND-R73-SRV-006): Store token expiry, matching
                    // HTTP POST handler pattern to enforce token lifetime.
                    if claims.exp > 0 {
                        session.token_expires_at = Some(claims.exp);
                    }
                }
                _ => {
                    // Already owned by this principal — use earliest expiry
                    // SECURITY (FIND-R73-SRV-006): Parity with HTTP POST handler
                    // (R23-PROXY-6) — prevent long-lived tokens from extending
                    // sessions originally bound to short-lived tokens.
                    if claims.exp > 0 {
                        session.token_expires_at = Some(
                            session
                                .token_expires_at
                                .map_or(claims.exp, |existing| existing.min(claims.exp)),
                        );
                    }
                }
            }
        }
    }

    // SECURITY (FIND-R159-003): Store agent identity in session — parity with HTTP
    // POST (handlers.rs:295-298) and GET (handlers.rs:3641-3643). Without this,
    // ABAC policies referencing agent_identity would evaluate against None for
    // WebSocket connections, creating a policy bypass.
    if let Some(ref identity) = agent_identity {
        if let Some(mut session) = state.sessions.get_mut(&session_id) {
            session.agent_identity = Some(identity.clone());
        }
    } else if let Some(ref oauth_evidence) = oauth_claims {
        match oauth_evidence.projected_agent_identity() {
            Ok(Some(identity)) => {
                if let Some(mut session) = state.sessions.get_mut(&session_id) {
                    session.agent_identity.get_or_insert(identity);
                }
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(
                    "WebSocket transport identity claims validation failed: {}",
                    error
                );
                return axum::response::IntoResponse::into_response((
                    axum::http::StatusCode::UNAUTHORIZED,
                    axum::Json(json!({
                        "error": "Invalid authorization token"
                    })),
                ));
            }
        }
    }

    // SECURITY (FIND-R46-006): Validate and extract call chain from upgrade headers.
    // The call chain is synced once during upgrade and reused for all messages
    // in this WebSocket connection.
    if let Err(reason) = super::call_chain::validate_call_chain_header(&headers, &state.limits) {
        tracing::warn!(
            session_id = %session_id,
            "WS upgrade rejected: invalid call chain header: {}",
            reason
        );
        return axum::response::IntoResponse::into_response((
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(json!({
                "error": "Invalid request"
            })),
        ));
    }
    sync_session_call_chain_from_headers(
        &state.sessions,
        &session_id,
        &headers,
        state.call_chain_hmac_key.as_ref(),
        &state.limits,
    );

    let ws_config = state.ws_config.clone().unwrap_or_default();

    // Phase 28: Extract W3C Trace Context from the HTTP upgrade request headers.
    // The trace_id is used for correlating all audit entries during this WS session.
    let trace_ctx = super::trace_propagation::extract_trace_context(&headers);
    let ws_trace_id = trace_ctx
        .trace_id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string().replace('-', ""));

    tracing::info!(
        session_id = %session_id,
        trace_id = %ws_trace_id,
        peer = %addr,
        "WebSocket upgrade accepted"
    );

    // 4. Configure and upgrade
    ws.max_message_size(ws_config.max_message_size)
        .on_upgrade(move |socket| {
            handle_ws_connection(
                socket,
                state,
                session_id,
                ws_config,
                addr,
                ws_trace_id,
                WsHandshakeSecurity {
                    oauth_claims,
                    headers,
                },
            )
        })
}

/// Handle an established WebSocket connection.
///
/// Establishes an upstream WS connection, then relays messages bidirectionally
/// with policy enforcement on client→upstream messages and DLP/injection
/// scanning on upstream→client messages.
async fn handle_ws_connection(
    client_ws: WebSocket,
    state: ProxyState,
    session_id: String,
    ws_config: WebSocketConfig,
    peer_addr: SocketAddr,
    trace_id: String,
    handshake_security: WsHandshakeSecurity,
) {
    record_ws_connection();
    let start = std::time::Instant::now();
    tracing::debug!(
        session_id = %session_id,
        trace_id = %trace_id,
        "WebSocket connection established with trace context"
    );

    // Connect to upstream — use gateway default backend if configured
    let upstream_url = if let Some(ref gw) = state.gateway {
        match gw.route("") {
            Some(d) => convert_to_ws_url(&d.upstream_url),
            None => {
                tracing::error!(session_id = %session_id, "No healthy upstream for WebSocket");
                let (mut client_sink, _) = client_ws.split();
                let _ = client_sink
                    .send(Message::Close(Some(CloseFrame {
                        code: CLOSE_POLICY_VIOLATION,
                        reason: "No healthy upstream available".into(),
                    })))
                    .await;
                return;
            }
        }
    } else {
        convert_to_ws_url(&state.upstream_url)
    };

    // SECURITY (R256-WS-1): Enforce HTTPS/WSS for non-local upstream URLs.
    // Parity with fallback.rs, smart_fallback.rs, upstream.rs, and grpc/upstream.rs.
    if let Err(reason) = super::validate_upstream_url_scheme(&upstream_url) {
        tracing::warn!(
            session_id = %session_id,
            "Rejecting non-HTTPS/WSS upstream URL in WebSocket handler"
        );
        let (mut client_sink, _) = client_ws.split();
        let _ = client_sink
            .send(Message::Close(Some(CloseFrame {
                code: CLOSE_POLICY_VIOLATION,
                reason: reason.into(),
            })))
            .await;
        return;
    }

    let upstream_ws = match connect_upstream_ws(&upstream_url).await {
        Ok(ws) => ws,
        Err(e) => {
            tracing::error!(
                session_id = %session_id,
                "Failed to connect to upstream WebSocket: {}",
                e
            );
            // Send close frame to client
            let (mut client_sink, _) = client_ws.split();
            let _ = client_sink
                .send(Message::Close(Some(CloseFrame {
                    code: CLOSE_POLICY_VIOLATION,
                    reason: "Upstream connection failed".into(),
                })))
                .await;
            return;
        }
    };

    let (client_sink, client_stream) = client_ws.split();
    let (upstream_sink, upstream_stream) = upstream_ws.split();

    // Wrap sinks in Arc<Mutex> for shared access
    let client_sink = Arc::new(Mutex::new(client_sink));
    let upstream_sink = Arc::new(Mutex::new(upstream_sink));

    // Rate limiter state: track messages in the current second window
    let rate_counter = Arc::new(AtomicU64::new(0));
    let rate_window_start = Arc::new(std::sync::Mutex::new(std::time::Instant::now()));

    // SECURITY (FIND-R46-WS-003): Separate rate limiter for upstream→client direction
    let upstream_rate_counter = Arc::new(AtomicU64::new(0));
    let upstream_rate_window_start = Arc::new(std::sync::Mutex::new(std::time::Instant::now()));
    let in_flight_client_requests = Arc::new(AtomicU64::new(0));

    let idle_timeout = Duration::from_secs(ws_config.idle_timeout_secs);

    // SECURITY (FIND-R182-001): Shared last-activity tracker so idle timeout resets
    // on every message (true idle detection, not max-lifetime).
    let last_activity = Arc::new(AtomicU64::new(0));
    let connection_epoch = std::time::Instant::now();

    // Client → Vellaveto → Upstream relay
    let client_to_upstream = {
        let state = state.clone();
        let session_id = session_id.clone();
        let client_sink = client_sink.clone();
        let upstream_sink = upstream_sink.clone();
        let in_flight_client_requests = in_flight_client_requests.clone();
        let rate_counter = rate_counter.clone();
        let rate_window_start = rate_window_start.clone();
        let ws_config = ws_config.clone();
        let last_activity = last_activity.clone();
        let handshake_security = handshake_security.clone();

        relay_client_to_upstream(
            client_stream,
            client_sink,
            upstream_sink,
            in_flight_client_requests,
            state,
            session_id,
            ws_config,
            rate_counter,
            rate_window_start,
            last_activity,
            connection_epoch,
            handshake_security.oauth_claims,
            handshake_security.headers,
        )
    };

    // Upstream → Vellaveto → Client relay
    let upstream_to_client = {
        let state = state.clone();
        let session_id = session_id.clone();
        let client_sink = client_sink.clone();
        let upstream_sink = upstream_sink.clone();
        let ws_config = ws_config.clone();
        let last_activity = last_activity.clone();
        let in_flight_client_requests = in_flight_client_requests.clone();

        relay_upstream_to_client(
            upstream_stream,
            client_sink,
            upstream_sink,
            state,
            session_id,
            ws_config,
            upstream_rate_counter,
            upstream_rate_window_start,
            in_flight_client_requests,
            last_activity,
            connection_epoch,
        )
    };

    // SECURITY (FIND-R182-001): True idle timeout — check periodically and
    // close only if no message activity since last check.
    let idle_check = {
        let session_id = session_id.clone();
        let last_activity = last_activity.clone();
        async move {
            // Check every 10% of idle timeout (min 1s) for responsive detection.
            let check_interval = Duration::from_secs((ws_config.idle_timeout_secs / 10).max(1));
            let mut interval = tokio::time::interval(check_interval);
            interval.tick().await; // first tick is immediate, skip it
            loop {
                interval.tick().await;
                // SECURITY (R251-WS-1): SeqCst for cross-thread session timeout enforcement.
                let last_ms = last_activity.load(Ordering::SeqCst);
                // SECURITY (FIND-R190-002): Use saturating_sub to prevent underflow.
                // SECURITY (R255-PROXY-8): Use try_from to avoid truncation on 128-bit as_millis().
                let elapsed_since_activity = u64::try_from(connection_epoch.elapsed().as_millis())
                    .unwrap_or(u64::MAX)
                    .saturating_sub(last_ms);
                if elapsed_since_activity
                    >= u64::try_from(idle_timeout.as_millis()).unwrap_or(u64::MAX)
                {
                    tracing::info!(
                        session_id = %session_id,
                        idle_secs = elapsed_since_activity / 1000,
                        "WebSocket idle timeout ({}s), closing",
                        ws_config.idle_timeout_secs
                    );
                    break;
                }
            }
        }
    };

    // Run both relay loops with idle timeout
    tokio::select! {
        _ = client_to_upstream => {
            tracing::debug!(session_id = %session_id, "Client stream ended");
        }
        _ = upstream_to_client => {
            tracing::debug!(session_id = %session_id, "Upstream stream ended");
        }
        _ = idle_check => {}
    }

    // Clean shutdown: close both sides
    {
        let mut sink = client_sink.lock().await;
        let _ = sink
            .send(Message::Close(Some(CloseFrame {
                code: CLOSE_NORMAL,
                reason: "Session ended".into(),
            })))
            .await;
    }
    {
        let mut sink = upstream_sink.lock().await;
        let _ = sink.close().await;
    }

    let duration = start.elapsed();
    metrics::histogram!("vellaveto_ws_connection_duration_seconds").record(duration.as_secs_f64());

    tracing::info!(
        session_id = %session_id,
        peer = %peer_addr,
        duration_secs = duration.as_secs(),
        "WebSocket connection closed"
    );
}

/// Relay messages from client to upstream with policy enforcement.
#[allow(clippy::too_many_arguments)]
async fn relay_client_to_upstream(
    mut client_stream: futures_util::stream::SplitStream<WebSocket>,
    client_sink: Arc<Mutex<futures_util::stream::SplitSink<WebSocket, Message>>>,
    upstream_sink: Arc<
        Mutex<
            futures_util::stream::SplitSink<
                tokio_tungstenite::WebSocketStream<
                    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
                >,
                tokio_tungstenite::tungstenite::Message,
            >,
        >,
    >,
    in_flight_client_requests: Arc<AtomicU64>,
    state: ProxyState,
    session_id: String,
    ws_config: WebSocketConfig,
    rate_counter: Arc<AtomicU64>,
    rate_window_start: Arc<std::sync::Mutex<std::time::Instant>>,
    last_activity: Arc<AtomicU64>,
    connection_epoch: std::time::Instant,
    oauth_claims: Option<crate::proxy::auth::OAuthValidationEvidence>,
    handshake_headers: HeaderMap,
) {
    while let Some(msg_result) = client_stream.next().await {
        let msg = match msg_result {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!(session_id = %session_id, "Client WS error: {}", e);
                break;
            }
        };

        // SECURITY (FIND-R182-001): Update last-activity for true idle detection.
        // SECURITY (R251-WS-1): SeqCst ensures visibility to timeout checker thread.
        last_activity.store(
            u64::try_from(connection_epoch.elapsed().as_millis()).unwrap_or(u64::MAX),
            Ordering::SeqCst,
        );

        record_ws_message("client_to_upstream");

        // SECURITY (FIND-R52-WS-003): Per-message OAuth token expiry check.
        // After WebSocket upgrade, the HTTP auth middleware no longer runs.
        // A token that expires mid-connection must be rejected to prevent
        // indefinite access via a long-lived WebSocket.
        {
            let token_expired = state
                .sessions
                .get_mut(&session_id)
                .and_then(|s| {
                    s.token_expires_at.map(|exp| {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        now >= exp
                    })
                })
                .unwrap_or(false);
            if token_expired {
                tracing::warn!(
                    session_id = %session_id,
                    "SECURITY: OAuth token expired during WebSocket session, closing"
                );
                let error = json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32001,
                        "message": "Session expired"
                    },
                    "id": null
                });
                let error_text = serde_json::to_string(&error)
                    .unwrap_or_else(|_| r#"{"jsonrpc":"2.0","error":{"code":-32001,"message":"Session expired"},"id":null}"#.to_string());
                let mut sink = client_sink.lock().await;
                let _ = sink.send(Message::Text(error_text.into())).await;
                let _ = sink
                    .send(Message::Close(Some(CloseFrame {
                        code: CLOSE_POLICY_VIOLATION,
                        reason: "Token expired".into(),
                    })))
                    .await;
                break;
            }
        }

        match msg {
            Message::Text(text) => {
                // Rate limiting
                if !check_rate_limit(
                    &rate_counter,
                    &rate_window_start,
                    ws_config.message_rate_limit,
                ) {
                    tracing::warn!(
                        session_id = %session_id,
                        "WebSocket rate limit exceeded, closing"
                    );
                    let mut sink = client_sink.lock().await;
                    let _ = sink
                        .send(Message::Close(Some(CloseFrame {
                            code: CLOSE_POLICY_VIOLATION,
                            reason: "Rate limit exceeded".into(),
                        })))
                        .await;
                    break;
                }

                // SECURITY (FIND-R46-005): Reject JSON with duplicate keys before parsing.
                // Prevents parser-disagreement attacks (CVE-2017-12635, CVE-2020-16250)
                // where the proxy evaluates one key value but upstream sees another.
                if let Some(dup_key) = vellaveto_mcp::framing::find_duplicate_json_key(&text) {
                    tracing::warn!(
                        session_id = %session_id,
                        "SECURITY: Rejected WS message with duplicate key: \"{}\"",
                        dup_key
                    );
                    let mut sink = client_sink.lock().await;
                    let _ = sink
                        .send(Message::Close(Some(CloseFrame {
                            code: CLOSE_POLICY_VIOLATION,
                            reason: "Duplicate JSON key detected".into(),
                        })))
                        .await;
                    break;
                }

                // SECURITY (FIND-R53-WS-004): Reject WS messages with control characters.
                // Parity with HTTP GET event_id validation (handlers.rs:2899).
                // Control chars in JSON-RPC messages can be used for log injection
                // or to bypass string-based security checks.
                if text.chars().any(|c| {
                    // Allow standard JSON whitespace (\t, \n, \r) but reject other
                    // ASCII control chars and Unicode format chars (FIND-R54-011).
                    (c.is_control() && c != '\n' && c != '\r' && c != '\t')
                        || is_unicode_format_char_ws(c)
                }) {
                    tracing::warn!(
                        session_id = %session_id,
                        "SECURITY: Rejected WS message with control characters"
                    );
                    let error =
                        make_ws_error_response(None, -32600, "Message contains control characters");
                    let mut sink = client_sink.lock().await;
                    let _ = sink.send(Message::Text(error.into())).await;
                    continue;
                }

                // Parse JSON
                let parsed: Value = match serde_json::from_str(&text) {
                    Ok(v) => v,
                    Err(_) => {
                        tracing::warn!(
                            session_id = %session_id,
                            "Unparseable JSON in WebSocket text frame, closing (fail-closed)"
                        );
                        let mut sink = client_sink.lock().await;
                        let _ = sink
                            .send(Message::Close(Some(CloseFrame {
                                code: CLOSE_POLICY_VIOLATION,
                                reason: "Invalid JSON".into(),
                            })))
                            .await;
                        break;
                    }
                };

                // SECURITY (R258-TRANSPORT-1): JSON-RPC key case-folding smuggling defense.
                // Parity with stdio transport (framing.rs). Rejects top-level keys that
                // case-fold to JSON-RPC 2.0 keys but are not exact-case (CVE-2026-27896).
                if let Some(key) = vellaveto_mcp::framing::check_json_rpc_key_case_folding(&parsed)
                {
                    tracing::warn!(
                        session_id = %session_id,
                        "SECURITY: Rejected WS message with case-folding smuggle key: \"{}\"",
                        key
                    );
                    let mut sink = client_sink.lock().await;
                    let _ = sink
                        .send(Message::Close(Some(CloseFrame {
                            code: CLOSE_POLICY_VIOLATION,
                            reason: "JSON-RPC key case-folding smuggle detected".into(),
                        })))
                        .await;
                    break;
                }

                // SECURITY (FIND-R46-WS-001): Injection scanning on client→upstream text frames.
                // The HTTP proxy scans request bodies for injection; the WebSocket proxy must
                // do the same to maintain security parity. Fail-closed: if injection is detected
                // and blocking is enabled, deny the message.
                if !state.injection_disabled {
                    let scannable = extract_scannable_text_from_request(&parsed);
                    if !scannable.is_empty() {
                        let injection_matches: Vec<String> =
                            if let Some(ref scanner) = state.injection_scanner {
                                scanner
                                    .inspect(&scannable)
                                    .into_iter()
                                    .map(|s| s.to_string())
                                    .collect()
                            } else {
                                inspect_for_injection(&scannable)
                                    .into_iter()
                                    .map(|s| s.to_string())
                                    .collect()
                            };

                        if !injection_matches.is_empty() {
                            tracing::warn!(
                                "SECURITY: Injection in WS client request! Session: {}, Patterns: {:?}",
                                session_id,
                                injection_matches,
                            );

                            let verdict = if state.injection_blocking {
                                Verdict::Deny {
                                    reason: format!(
                                        "WS request injection blocked: {injection_matches:?}"
                                    ),
                                }
                            } else {
                                Verdict::Allow
                            };

                            let action = Action::new(
                                "vellaveto",
                                "ws_request_injection",
                                json!({
                                    "matched_patterns": injection_matches,
                                    "session": session_id,
                                    "transport": "websocket",
                                    "direction": "client_to_upstream",
                                }),
                            );
                            let request_payload = parsed
                                .get("params")
                                .or_else(|| parsed.get("result"))
                                .cloned();
                            let injection_security_context =
                                request_payload.as_ref().map(|payload| {
                                    super::helpers::parameter_injection_security_context(
                                        payload,
                                        state.injection_blocking,
                                        "request_injection",
                                    )
                                });
                            let envelope = build_secondary_acis_envelope_with_security_context(
                                &action,
                                &verdict,
                                DecisionOrigin::InjectionScanner,
                                "websocket",
                                Some(&session_id),
                                injection_security_context.as_ref(),
                            );
                            if let Err(e) = state
                                .audit
                                .log_entry_with_acis(
                                    &action,
                                    &verdict,
                                    json!({
                                        "source": "ws_proxy",
                                        "event": "ws_request_injection_detected",
                                    }),
                                    envelope,
                                )
                                .await
                            {
                                tracing::warn!("Failed to audit WS request injection: {}", e);
                            }

                            if state.injection_blocking {
                                let id = parsed.get("id");
                                let error = make_ws_error_response(
                                    id,
                                    -32001,
                                    "Request blocked: injection detected",
                                );
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                                continue;
                            }
                        }
                    }
                }

                let presented_approval_id = super::helpers::extract_approval_id_from_meta(&parsed);

                // Classify and evaluate
                let classified = extractor::classify_message(&parsed);
                match classified {
                    MessageType::ToolCall {
                        ref id,
                        ref tool_name,
                        ref arguments,
                    } => {
                        // SECURITY (FIND-R46-009): Strict tool name validation (MCP 2025-11-25).
                        // When enabled, reject tool names that don't conform to the spec format.
                        if state.streamable_http.strict_tool_name_validation {
                            if let Err(e) = vellaveto_types::validate_mcp_tool_name(tool_name) {
                                tracing::warn!(
                                    session_id = %session_id,
                                    "SECURITY: Rejecting invalid WS tool name '{}': {}",
                                    tool_name,
                                    e
                                );
                                let error =
                                    make_ws_error_response(Some(id), -32602, "Invalid tool name");
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                                continue;
                            }
                        }

                        let mut action = extractor::extract_action(tool_name, arguments);
                        let mut matched_approval_id: Option<String> = None;
                        let mut matched_approval_registry: Option<&'static str> = None;

                        // SECURITY (FIND-R75-002): DNS resolution for IP-based policy evaluation.
                        // Parity with HTTP handler (handlers.rs:717). Without this, policies
                        // using ip_rules are completely bypassed on the WebSocket transport.
                        if state.engine.has_ip_rules() {
                            super::helpers::resolve_domains(&mut action).await;
                        }

                        // SECURITY (FIND-R46-006): Call chain validation and privilege escalation check.
                        // Extract X-Upstream-Agents from the initial WS upgrade headers stored in session.
                        // For WebSocket, we sync the call chain once during upgrade and reuse it.
                        let upstream_chain = {
                            let session_ref = state.sessions.get_mut(&session_id);
                            session_ref
                                .map(|s| s.current_call_chain.clone())
                                .unwrap_or_default()
                        };
                        let current_agent_id = {
                            let session_ref = state.sessions.get_mut(&session_id);
                            session_ref.and_then(|s| s.oauth_subject.clone())
                        };

                        // SECURITY (FIND-R46-006): Privilege escalation detection.
                        if !upstream_chain.is_empty() {
                            let priv_check = check_privilege_escalation(
                                &state.engine,
                                &state.policies,
                                &action,
                                &upstream_chain,
                                current_agent_id.as_deref(),
                            );
                            if priv_check.escalation_detected {
                                let verdict = Verdict::Deny {
                                    reason: format!(
                                        "Privilege escalation: agent '{}' would be denied",
                                        priv_check
                                            .escalating_from_agent
                                            .as_deref()
                                            .unwrap_or("unknown")
                                    ),
                                };
                                let privilege_escalation_security_context =
                                    super::helpers::privilege_escalation_security_context(&action);
                                let envelope = build_secondary_acis_envelope_with_security_context(
                                    &action,
                                    &verdict,
                                    DecisionOrigin::PolicyEngine,
                                    "websocket",
                                    Some(&session_id),
                                    Some(&privilege_escalation_security_context),
                                );
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &action,
                                        &verdict,
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "event": "privilege_escalation_blocked",
                                            "escalating_from_agent": priv_check.escalating_from_agent,
                                            "upstream_deny_reason": priv_check.upstream_deny_reason,
                                        }),
                                        envelope,
                                    )
                                    .await
                                {
                                    tracing::warn!(
                                        "Failed to audit WS privilege escalation: {}",
                                        e
                                    );
                                }
                                let error =
                                    make_ws_error_response(Some(id), -32001, "Denied by policy");
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                                continue;
                            }
                        }

                        // SECURITY (FIND-R46-007): Rug-pull detection.
                        // Block calls to tools whose annotations changed since initial tools/list.
                        // SECURITY (R240-PROXY-1): Fall back to global registry on session miss.
                        let is_flagged = state
                            .sessions
                            .get_mut(&session_id)
                            .map(|s| s.flagged_tools.contains(tool_name))
                            .unwrap_or_else(|| state.sessions.is_tool_globally_flagged(tool_name));
                        if is_flagged {
                            let verdict = Verdict::Deny {
                                reason: format!(
                                    "Tool '{tool_name}' blocked: annotations changed (rug-pull detected)"
                                ),
                            };
                            let rug_pull_security_context =
                                super::helpers::rug_pull_security_context(&action);
                            let envelope = build_secondary_acis_envelope_with_security_context(
                                &action,
                                &verdict,
                                DecisionOrigin::CapabilityEnforcement,
                                "websocket",
                                Some(&session_id),
                                Some(&rug_pull_security_context),
                            );
                            if let Err(e) = state
                                .audit
                                .log_entry_with_acis(
                                    &action,
                                    &verdict,
                                    json!({
                                        "source": "ws_proxy",
                                        "session": session_id,
                                        "transport": "websocket",
                                        "event": "rug_pull_tool_blocked",
                                        "tool": tool_name,
                                    }),
                                    envelope,
                                )
                                .await
                            {
                                tracing::warn!("Failed to audit WS rug-pull block: {}", e);
                            }
                            let error =
                                make_ws_error_response(Some(id), -32001, "Denied by policy");
                            let mut sink = client_sink.lock().await;
                            let _ = sink.send(Message::Text(error.into())).await;
                            continue;
                        }

                        // SECURITY (FIND-R52-WS-001): DLP scan parameters for secret exfiltration.
                        // Matches HTTP handler's DLP check to maintain security parity.
                        {
                            let dlp_findings = scan_parameters_for_secrets(arguments);
                            // SECURITY (FIND-R55-WS-001): DLP on request params always blocks,
                            // matching HTTP handler. Previously gated on injection_blocking flag.
                            if !dlp_findings.is_empty() {
                                for finding in &dlp_findings {
                                    record_dlp_finding(&finding.pattern_name);
                                }
                                let patterns: Vec<String> = dlp_findings
                                    .iter()
                                    .map(|f| format!("{} at {}", f.pattern_name, f.location))
                                    .collect();
                                let audit_reason = format!(
                                    "DLP: secrets detected in tool parameters: {patterns:?}"
                                );
                                tracing::warn!(
                                    "SECURITY: DLP blocking WS tool '{}' in session {}: {}",
                                    tool_name,
                                    session_id,
                                    audit_reason
                                );
                                let dlp_action = extractor::extract_action(tool_name, arguments);
                                let dlp_verdict = Verdict::Deny {
                                    reason: audit_reason,
                                };
                                let parameter_security_context =
                                    super::helpers::parameter_dlp_security_context(
                                        arguments,
                                        true,
                                        "tool_parameter_dlp",
                                    );
                                let envelope = build_secondary_acis_envelope_with_security_context(
                                    &dlp_action,
                                    &dlp_verdict,
                                    DecisionOrigin::Dlp,
                                    "websocket",
                                    Some(&session_id),
                                    Some(&parameter_security_context),
                                );
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &dlp_action,
                                        &dlp_verdict,
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "event": "dlp_secret_blocked",
                                            "tool": tool_name,
                                            "findings": patterns,
                                        }),
                                        envelope,
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit WS DLP finding: {}", e);
                                }
                                let error = make_ws_error_response(
                                    Some(id),
                                    -32001,
                                    "Request blocked: security policy violation",
                                );
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                                continue;
                            }
                        }

                        // SECURITY (FIND-R52-WS-002): Memory poisoning detection.
                        // Check if tool call parameters contain replayed response data,
                        // matching the HTTP handler's memory poisoning check.
                        {
                            let poisoning_detected = state
                                .sessions
                                .get_mut(&session_id)
                                .and_then(|session| {
                                    let matches =
                                        session.memory_tracker.check_parameters(arguments);
                                    if !matches.is_empty() {
                                        for m in &matches {
                                            tracing::warn!(
                                                "SECURITY: Memory poisoning detected in WS tool '{}' (session {}): \
                                                 param '{}' contains replayed data (fingerprint: {})",
                                                tool_name,
                                                session_id,
                                                m.param_location,
                                                m.fingerprint
                                            );
                                        }
                                        Some(matches.len())
                                    } else {
                                        None
                                    }
                                });
                            if let Some(match_count) = poisoning_detected {
                                let poison_action = extractor::extract_action(tool_name, arguments);
                                let deny_reason = format!(
                                    "Memory poisoning detected: {match_count} replayed data fragment(s) in tool '{tool_name}'"
                                );
                                let poison_verdict = Verdict::Deny {
                                    reason: deny_reason,
                                };
                                let poisoning_security_context =
                                    super::helpers::memory_poisoning_security_context(
                                        arguments,
                                        "memory_poisoning",
                                    );
                                let envelope = build_secondary_acis_envelope_with_security_context(
                                    &poison_action,
                                    &poison_verdict,
                                    DecisionOrigin::MemoryPoisoning,
                                    "websocket",
                                    Some(&session_id),
                                    Some(&poisoning_security_context),
                                );
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &poison_action,
                                        &poison_verdict,
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "event": "memory_poisoning_detected",
                                            "matches": match_count,
                                            "tool": tool_name,
                                        }),
                                        envelope,
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit WS memory poisoning: {}", e);
                                }
                                let error = make_ws_error_response(
                                    Some(id),
                                    -32001,
                                    "Request blocked: security policy violation",
                                );
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                                continue;
                            }
                        }

                        // SECURITY (FIND-R46-008): Circuit breaker check.
                        // If the circuit is open for this tool, reject immediately.
                        if let Some(ref circuit_breaker) = state.circuit_breaker {
                            if let Err(reason) = circuit_breaker.can_proceed(tool_name) {
                                tracing::warn!(
                                    session_id = %session_id,
                                    "SECURITY: WS circuit breaker open for tool '{}': {}",
                                    tool_name,
                                    reason
                                );
                                let verdict = Verdict::Deny {
                                    reason: format!("Circuit breaker open: {reason}"),
                                };
                                // SECURITY (R251-ACIS-1): Use CircuitBreaker origin, not RateLimiter.
                                let circuit_breaker_security_context =
                                    super::helpers::circuit_breaker_security_context(&action);
                                let envelope = build_secondary_acis_envelope_with_security_context(
                                    &action,
                                    &verdict,
                                    DecisionOrigin::CircuitBreaker,
                                    "websocket",
                                    Some(&session_id),
                                    Some(&circuit_breaker_security_context),
                                );
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &action,
                                        &verdict,
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "event": "circuit_breaker_rejected",
                                            "tool": tool_name,
                                        }),
                                        envelope,
                                    )
                                    .await
                                {
                                    tracing::warn!(
                                        "Failed to audit WS circuit breaker rejection: {}",
                                        e
                                    );
                                }
                                let error = make_ws_error_response(
                                    Some(id),
                                    -32001,
                                    "Service temporarily unavailable",
                                );
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                                continue;
                            }
                        }

                        // SECURITY (FIND-R46-013): Tool registry trust check.
                        // If tool registry is configured, check trust level before evaluation.
                        if let Some(ref registry) = state.tool_registry {
                            let registry_eval_ctx = state
                                .sessions
                                .get(&session_id)
                                .map(|session| EvaluationContext {
                                    timestamp: None,
                                    agent_id: session.oauth_subject.clone(),
                                    agent_identity: session.agent_identity.clone(),
                                    call_counts: session.call_counts.clone(),
                                    previous_actions: session
                                        .action_history
                                        .iter()
                                        .cloned()
                                        .collect(),
                                    call_chain: session.current_call_chain.clone(),
                                    tenant_id: None,
                                    verification_tier: None,
                                    capability_token: None,
                                    session_state: None,
                                })
                                .unwrap_or_default();
                            let registry_runtime_security_context =
                                build_ws_runtime_security_context(
                                    &parsed,
                                    &action,
                                    &handshake_headers,
                                    super::helpers::TransportSecurityInputs {
                                        oauth_evidence: oauth_claims.as_ref(),
                                        eval_ctx: Some(&registry_eval_ctx),
                                        sessions: &state.sessions,
                                        session_id: Some(&session_id),
                                        trusted_request_signers: &state.trusted_request_signers,
                                        detached_signature_freshness: state
                                            .detached_signature_freshness,
                                    },
                                );
                            let trust = registry.check_trust_level(tool_name).await;
                            match trust {
                                vellaveto_mcp::tool_registry::TrustLevel::Unknown => {
                                    match super::helpers::presented_approval_matches_action(
                                        &state,
                                        &session_id,
                                        presented_approval_id.as_deref(),
                                        &action,
                                    )
                                    .await
                                    {
                                        Ok(Some(approval_id)) => {
                                            matched_approval_id = Some(approval_id);
                                            matched_approval_registry = Some("unknown_tool");
                                        }
                                        Ok(None) => {
                                            registry.register_unknown(tool_name).await;
                                            let verdict = Verdict::Deny {
                                                reason: "Unknown tool requires approval"
                                                    .to_string(),
                                            };
                                            let approval_security_context =
                                                super::helpers::unknown_tool_approval_gate_security_context(&action);
                                            let combined_security_context =
                                                super::helpers::merge_transport_security_context(
                                                    registry_runtime_security_context.as_ref(),
                                                    Some(&approval_security_context),
                                                );
                                            let effective_security_context =
                                                combined_security_context
                                                    .as_ref()
                                                    .unwrap_or(&approval_security_context);
                                            let envelope =
                                                build_secondary_acis_envelope_with_security_context(
                                                    &action,
                                                    &verdict,
                                                    DecisionOrigin::PolicyEngine,
                                                    "websocket",
                                                    Some(&session_id),
                                                    Some(effective_security_context),
                                                );
                                            if let Err(e) = state
                                                .audit
                                                .log_entry_with_acis(
                                                    &action,
                                                    &verdict,
                                                    json!({
                                                        "source": "ws_proxy",
                                                        "session": session_id,
                                                        "transport": "websocket",
                                                        "registry": "unknown_tool",
                                                        "tool": tool_name,
                                                    }),
                                                    envelope,
                                                )
                                                .await
                                            {
                                                tracing::warn!(
                                                    "Failed to audit WS unknown tool: {}",
                                                    e
                                                );
                                            }
                                            let approval_reason = "Approval required";
                                            let containment_context =
                                                super::helpers::approval_containment_context_from_security_context(
                                                    effective_security_context,
                                                    approval_reason,
                                                );
                                            let approval_id =
                                                super::helpers::create_pending_approval_with_context(
                                                    &state,
                                                    &session_id,
                                                    &action,
                                                    approval_reason,
                                                    containment_context,
                                                )
                                                .await;
                                            let error = make_ws_error_response_with_data(
                                                Some(id),
                                                -32001,
                                                approval_reason,
                                                Some(json!({
                                                    "verdict": "require_approval",
                                                    "reason": approval_reason,
                                                    "approval_id": approval_id,
                                                })),
                                            );
                                            let mut sink = client_sink.lock().await;
                                            let _ = sink.send(Message::Text(error.into())).await;
                                            continue;
                                        }
                                        Err(()) => {
                                            let verdict = Verdict::Deny {
                                                reason: INVALID_PRESENTED_APPROVAL_REASON
                                                    .to_string(),
                                            };
                                            let invalid_approval_security_context =
                                                super::helpers::invalid_presented_approval_security_context(&action);
                                            let combined_security_context =
                                                super::helpers::merge_transport_security_context(
                                                    registry_runtime_security_context.as_ref(),
                                                    Some(&invalid_approval_security_context),
                                                );
                                            let effective_security_context =
                                                combined_security_context
                                                    .as_ref()
                                                    .unwrap_or(&invalid_approval_security_context);
                                            let envelope =
                                                build_secondary_acis_envelope_with_security_context(
                                                    &action,
                                                    &verdict,
                                                    DecisionOrigin::PolicyEngine,
                                                    "websocket",
                                                    Some(&session_id),
                                                    Some(effective_security_context),
                                                );
                                            // SECURITY (R274-AUDIT-1): the result was bound to `_`, so a failed
                                            // audit write here was invisible. The denial below is unchanged —
                                            // this only makes the lost record observable.
                                            if let Err(e) = state
                                                .audit
                                                .log_entry_with_acis(
                                                    &action,
                                                    &verdict,
                                                    json!({
                                                        "source": "ws_proxy",
                                                        "session": session_id,
                                                        "transport": "websocket",
                                                        "registry": "unknown_tool",
                                                        "event": "presented_approval_replay_denied",
                                                        "approval_id": presented_approval_id,
                                                    }),
                                                    envelope,
                                                )
                                                .await
                                            {
                                                tracing::warn!("Failed to audit denial: {}", e);
                                            }
                                            let error = make_ws_error_response(
                                                Some(id),
                                                -32001,
                                                "Denied by policy",
                                            );
                                            let mut sink = client_sink.lock().await;
                                            let _ = sink.send(Message::Text(error.into())).await;
                                            continue;
                                        }
                                    }
                                }
                                vellaveto_mcp::tool_registry::TrustLevel::Untrusted {
                                    score: _,
                                } => {
                                    match super::helpers::presented_approval_matches_action(
                                        &state,
                                        &session_id,
                                        presented_approval_id.as_deref(),
                                        &action,
                                    )
                                    .await
                                    {
                                        Ok(Some(approval_id)) => {
                                            matched_approval_id = Some(approval_id);
                                            matched_approval_registry = Some("untrusted_tool");
                                        }
                                        Ok(None) => {
                                            let verdict = Verdict::Deny {
                                                reason: "Untrusted tool requires approval"
                                                    .to_string(),
                                            };
                                            let approval_security_context =
                                                super::helpers::untrusted_tool_approval_gate_security_context(&action);
                                            let combined_security_context =
                                                super::helpers::merge_transport_security_context(
                                                    registry_runtime_security_context.as_ref(),
                                                    Some(&approval_security_context),
                                                );
                                            let effective_security_context =
                                                combined_security_context
                                                    .as_ref()
                                                    .unwrap_or(&approval_security_context);
                                            let envelope =
                                                build_secondary_acis_envelope_with_security_context(
                                                    &action,
                                                    &verdict,
                                                    DecisionOrigin::PolicyEngine,
                                                    "websocket",
                                                    Some(&session_id),
                                                    Some(effective_security_context),
                                                );
                                            if let Err(e) = state
                                                .audit
                                                .log_entry_with_acis(
                                                    &action,
                                                    &verdict,
                                                    json!({
                                                        "source": "ws_proxy",
                                                        "session": session_id,
                                                        "transport": "websocket",
                                                        "registry": "untrusted_tool",
                                                        "tool": tool_name,
                                                    }),
                                                    envelope,
                                                )
                                                .await
                                            {
                                                tracing::warn!(
                                                    "Failed to audit WS untrusted tool: {}",
                                                    e
                                                );
                                            }
                                            let approval_reason = "Approval required";
                                            let containment_context =
                                                super::helpers::approval_containment_context_from_security_context(
                                                    effective_security_context,
                                                    approval_reason,
                                                );
                                            let approval_id =
                                                super::helpers::create_pending_approval_with_context(
                                                    &state,
                                                    &session_id,
                                                    &action,
                                                    approval_reason,
                                                    containment_context,
                                                )
                                                .await;
                                            let error = make_ws_error_response_with_data(
                                                Some(id),
                                                -32001,
                                                approval_reason,
                                                Some(json!({
                                                    "verdict": "require_approval",
                                                    "reason": approval_reason,
                                                    "approval_id": approval_id,
                                                })),
                                            );
                                            let mut sink = client_sink.lock().await;
                                            let _ = sink.send(Message::Text(error.into())).await;
                                            continue;
                                        }
                                        Err(()) => {
                                            let verdict = Verdict::Deny {
                                                reason: INVALID_PRESENTED_APPROVAL_REASON
                                                    .to_string(),
                                            };
                                            let invalid_approval_security_context =
                                                super::helpers::invalid_presented_approval_security_context(&action);
                                            let combined_security_context =
                                                super::helpers::merge_transport_security_context(
                                                    registry_runtime_security_context.as_ref(),
                                                    Some(&invalid_approval_security_context),
                                                );
                                            let effective_security_context =
                                                combined_security_context
                                                    .as_ref()
                                                    .unwrap_or(&invalid_approval_security_context);
                                            let envelope =
                                                build_secondary_acis_envelope_with_security_context(
                                                    &action,
                                                    &verdict,
                                                    DecisionOrigin::PolicyEngine,
                                                    "websocket",
                                                    Some(&session_id),
                                                    Some(effective_security_context),
                                                );
                                            // SECURITY (R274-AUDIT-1): the result was bound to `_`, so a failed
                                            // audit write here was invisible. The denial below is unchanged —
                                            // this only makes the lost record observable.
                                            if let Err(e) = state
                                                .audit
                                                .log_entry_with_acis(
                                                    &action,
                                                    &verdict,
                                                    json!({
                                                        "source": "ws_proxy",
                                                        "session": session_id,
                                                        "transport": "websocket",
                                                        "registry": "untrusted_tool",
                                                        "event": "presented_approval_replay_denied",
                                                        "approval_id": presented_approval_id,
                                                    }),
                                                    envelope,
                                                )
                                                .await
                                            {
                                                tracing::warn!("Failed to audit denial: {}", e);
                                            }
                                            let error = make_ws_error_response(
                                                Some(id),
                                                -32001,
                                                "Denied by policy",
                                            );
                                            let mut sink = client_sink.lock().await;
                                            let _ = sink.send(Message::Text(error.into())).await;
                                            continue;
                                        }
                                    }
                                }
                                vellaveto_mcp::tool_registry::TrustLevel::Trusted => {
                                    // Trusted — proceed to engine evaluation
                                }
                            }
                        }

                        // SECURITY (FIND-R130-002): Combine context read, evaluation,
                        // and session update into a single block holding the DashMap
                        // shard lock. Without this, concurrent WS connections sharing
                        // a session can bypass max_calls_in_window by racing: both
                        // clone the same stale call_counts, both pass evaluation, both
                        // increment. Matches HTTP handler R19-TOCTOU pattern
                        // (handlers.rs:725-789).

                        // Pre-compute security context BEFORE acquiring DashMap write lock
                        // to avoid deadlock — build_ws_runtime_security_context internally
                        // calls sessions.get()/get_mut() which would re-enter the lock.
                        let pre_eval_ctx = state
                            .sessions
                            .get(&session_id)
                            .map(|session| EvaluationContext {
                                timestamp: None,
                                agent_id: session.oauth_subject.clone(),
                                agent_identity: session.agent_identity.clone(),
                                call_chain: session.current_call_chain.clone(),
                                ..EvaluationContext::default()
                            })
                            .unwrap_or_else(|| EvaluationContext {
                                agent_id: oauth_claims.as_ref().map(|claims| claims.sub.clone()),
                                ..EvaluationContext::default()
                            });
                        let security_context = build_ws_runtime_security_context(
                            &parsed,
                            &action,
                            &handshake_headers,
                            super::helpers::TransportSecurityInputs {
                                oauth_evidence: oauth_claims.as_ref(),
                                eval_ctx: Some(&pre_eval_ctx),
                                sessions: &state.sessions,
                                session_id: Some(&session_id),
                                trusted_request_signers: &state.trusted_request_signers,
                                detached_signature_freshness: state.detached_signature_freshness,
                            },
                        );

                        // TOCTOU-safe evaluation + session update (write lock)
                        let (mediation_result, ctx) = if let Some(mut session) =
                            state.sessions.get_mut(&session_id)
                        {
                            let ctx = EvaluationContext {
                                timestamp: None,
                                agent_id: session.oauth_subject.clone(),
                                agent_identity: session.agent_identity.clone(),
                                call_counts: session.call_counts.clone(),
                                previous_actions: session.action_history.iter().cloned().collect(),
                                call_chain: session.current_call_chain.clone(),
                                tenant_id: None,
                                verification_tier: None,
                                capability_token: None,
                                session_state: None,
                            };
                            let result = mediate_with_security_context(
                                &uuid::Uuid::new_v4().to_string().replace('-', ""),
                                &action,
                                &state.engine,
                                Some(&ctx),
                                security_context.as_ref(),
                                "websocket",
                                &state.mediation_config,
                                Some(&session_id),
                                None,
                            );

                            // Atomically update session on Allow while still holding
                            // the shard lock — prevents TOCTOU bypass of call limits.
                            if matches!(result.verdict, Verdict::Allow) {
                                session.touch();
                                use crate::proxy::call_chain::{
                                    MAX_ACTION_HISTORY, MAX_CALL_COUNT_TOOLS,
                                };
                                if session.call_counts.len() < MAX_CALL_COUNT_TOOLS
                                    || session.call_counts.contains_key(tool_name)
                                {
                                    let count = session
                                        .call_counts
                                        .entry(tool_name.to_string())
                                        .or_insert(0);
                                    *count = count.saturating_add(1);
                                }
                                if session.action_history.len() >= MAX_ACTION_HISTORY {
                                    session.action_history.pop_front();
                                }
                                session.action_history.push_back(tool_name.to_string());
                            }

                            (result, ctx)
                        } else {
                            // No session — evaluate without context (fail-closed)
                            let ctx = EvaluationContext::default();
                            let result = mediate_with_security_context(
                                &uuid::Uuid::new_v4().to_string().replace('-', ""),
                                &action,
                                &state.engine,
                                None,
                                security_context.as_ref(),
                                "websocket",
                                &state.mediation_config,
                                Some(&session_id),
                                None,
                            );
                            (result, ctx)
                        };

                        let mut final_origin = mediation_result.origin;
                        let mut acis_envelope = mediation_result.envelope.clone();
                        let mut refresh_envelope = false;
                        let verdict = match mediation_result.verdict {
                            Verdict::RequireApproval { reason } => {
                                if matched_approval_id.is_some() {
                                    final_origin = DecisionOrigin::PolicyEngine;
                                    refresh_envelope = true;
                                    Verdict::Allow
                                } else {
                                    match super::helpers::presented_approval_matches_action(
                                        &state,
                                        &session_id,
                                        presented_approval_id.as_deref(),
                                        &action,
                                    )
                                    .await
                                    {
                                        Ok(Some(approval_id)) => {
                                            matched_approval_id = Some(approval_id);
                                            final_origin = DecisionOrigin::PolicyEngine;
                                            refresh_envelope = true;
                                            Verdict::Allow
                                        }
                                        Ok(None) => Verdict::RequireApproval { reason },
                                        Err(()) => Verdict::Deny {
                                            reason: {
                                                final_origin = DecisionOrigin::ApprovalGate;
                                                refresh_envelope = true;
                                                INVALID_PRESENTED_APPROVAL_REASON.to_string()
                                            },
                                        },
                                    }
                                }
                            }
                            other => other,
                        };
                        if refresh_envelope {
                            acis_envelope = refresh_ws_acis_envelope(
                                &acis_envelope,
                                &action,
                                &verdict,
                                final_origin,
                                &session_id,
                                &ctx,
                                security_context.as_ref(),
                            );
                        }

                        match verdict {
                            Verdict::Allow => {
                                // Phase 21: ABAC refinement — only runs when ABAC engine is configured
                                if let Some(ref abac) = state.abac_engine {
                                    let principal_id =
                                        ctx.agent_id.as_deref().unwrap_or("anonymous");
                                    let principal_type = ctx.principal_type();
                                    let session_risk = state
                                        .sessions
                                        .get_mut(&session_id)
                                        .and_then(|s| s.risk_score.clone());
                                    let abac_ctx = vellaveto_engine::abac::AbacEvalContext {
                                        eval_ctx: &ctx,
                                        principal_type,
                                        principal_id,
                                        risk_score: session_risk.as_ref(),
                                    };
                                    match abac.evaluate(&action, &abac_ctx) {
                                        vellaveto_engine::abac::AbacDecision::Deny {
                                            policy_id,
                                            reason,
                                        } => {
                                            let deny_verdict = Verdict::Deny {
                                                reason: reason.clone(),
                                            };
                                            let abac_security_context =
                                                super::helpers::abac_deny_security_context(&action);
                                            let envelope =
                                                build_secondary_acis_envelope_with_security_context(
                                                    &action,
                                                    &deny_verdict,
                                                    DecisionOrigin::PolicyEngine,
                                                    "websocket",
                                                    Some(&session_id),
                                                    Some(&abac_security_context),
                                                );
                                            if let Err(e) = state
                                                .audit
                                                .log_entry_with_acis(
                                                    &action,
                                                    &deny_verdict,
                                                    json!({
                                                        "source": "ws_proxy",
                                                        "session": session_id,
                                                        "transport": "websocket",
                                                        "event": "abac_deny",
                                                        "abac_policy": policy_id,
                                                    }),
                                                    envelope,
                                                )
                                                .await
                                            {
                                                tracing::warn!(
                                                    "Failed to audit WS ABAC deny: {}",
                                                    e
                                                );
                                            }
                                            // SECURITY (FIND-R46-012): Generic message to client;
                                            // detailed reason (ABAC policy_id, reason) is in
                                            // the audit log only.
                                            let error_resp = make_ws_error_response(
                                                Some(id),
                                                -32001,
                                                "Denied by policy",
                                            );
                                            let mut sink = client_sink.lock().await;
                                            let _ =
                                                sink.send(Message::Text(error_resp.into())).await;
                                            continue;
                                        }
                                        vellaveto_engine::abac::AbacDecision::Allow {
                                            policy_id,
                                        } => {
                                            if let Some(ref la) = state.least_agency {
                                                la.record_usage(
                                                    principal_id,
                                                    &session_id,
                                                    &policy_id,
                                                    tool_name,
                                                    &action.function,
                                                );
                                            }
                                        }
                                        vellaveto_engine::abac::AbacDecision::NoMatch => {
                                            // Fall through — existing Allow stands
                                        }
                                        #[allow(unreachable_patterns)]
                                        // AbacDecision is #[non_exhaustive]
                                        _ => {
                                            // SECURITY (FIND-R74-002): Future variants — fail-closed (deny).
                                            // Must send deny and continue, not fall through to Allow path.
                                            tracing::warn!(
                                                "Unknown AbacDecision variant — fail-closed"
                                            );
                                            let error_resp = make_ws_error_response(
                                                Some(id),
                                                -32001,
                                                "Denied by policy",
                                            );
                                            let mut sink = client_sink.lock().await;
                                            let _ =
                                                sink.send(Message::Text(error_resp.into())).await;
                                            continue;
                                        }
                                    }
                                }

                                // SECURITY (FIND-R46-013): Record tool call in registry on Allow
                                if let Some(ref registry) = state.tool_registry {
                                    registry.record_call(tool_name).await;
                                }

                                // NOTE: Session touch + call_counts/action_history
                                // update already performed inside the TOCTOU-safe
                                // block above (FIND-R130-002). No separate update here.

                                if super::helpers::consume_presented_approval(
                                    &state,
                                    &session_id,
                                    matched_approval_id.as_deref(),
                                    &action,
                                    security_context.as_ref(),
                                )
                                .await
                                .is_err()
                                {
                                    let deny_verdict = Verdict::Deny {
                                        reason: INVALID_PRESENTED_APPROVAL_REASON.to_string(),
                                    };
                                    let invalid_approval_security_context =
                                        super::helpers::invalid_presented_approval_security_context(
                                            &action,
                                        );
                                    let combined_security_context =
                                        super::helpers::merge_transport_security_context(
                                            security_context.as_ref(),
                                            Some(&invalid_approval_security_context),
                                        );
                                    let effective_security_context = combined_security_context
                                        .as_ref()
                                        .unwrap_or(&invalid_approval_security_context);
                                    let envelope =
                                        build_secondary_acis_envelope_with_security_context(
                                            &action,
                                            &deny_verdict,
                                            DecisionOrigin::ApprovalGate,
                                            "websocket",
                                            Some(&session_id),
                                            Some(effective_security_context),
                                        );
                                    let mut audit_metadata = json!({
                                        "source": "ws_proxy",
                                        "session": session_id,
                                        "transport": "websocket",
                                        "event": "presented_approval_replay_denied",
                                        "approval_id": matched_approval_id,
                                    });
                                    if let Some(registry) = matched_approval_registry {
                                        audit_metadata["registry"] = json!(registry);
                                    }
                                    // SECURITY (R274-AUDIT-1): the result was bound to `_`, so a failed
                                    // audit write here was invisible. The denial below is unchanged —
                                    // this only makes the lost record observable.
                                    if let Err(e) = state
                                        .audit
                                        .log_entry_with_acis(
                                            &action,
                                            &deny_verdict,
                                            audit_metadata,
                                            envelope,
                                        )
                                        .await
                                    {
                                        tracing::warn!("Failed to audit denial: {}", e);
                                    }
                                    let error_resp = make_ws_error_response(
                                        Some(id),
                                        -32001,
                                        "Denied by policy",
                                    );
                                    let mut sink = client_sink.lock().await;
                                    let _ = sink.send(Message::Text(error_resp.into())).await;
                                    continue;
                                }

                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &action,
                                        &Verdict::Allow,
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                        }),
                                        acis_envelope,
                                    )
                                    .await
                                {
                                    tracing::error!(
                                        "AUDIT FAILURE in WS proxy: security decision not recorded: {}",
                                        e
                                    );
                                    // SECURITY (FIND-CREATIVE-003): Strict audit mode — fail-closed.
                                    // No unaudited security decisions can occur.
                                    if state.audit_strict_mode {
                                        let error = make_ws_error_response(
                                            Some(id),
                                            -32000,
                                            "Audit logging failed — request denied (strict audit mode)",
                                        );
                                        let mut sink = client_sink.lock().await;
                                        let _ = sink.send(Message::Text(error.into())).await;
                                        continue;
                                    }
                                }

                                // Canonicalize and forward
                                let forward_text = if state.canonicalize {
                                    match serde_json::to_string(&parsed) {
                                        Ok(canonical) => canonical,
                                        Err(e) => {
                                            tracing::error!(
                                                "SECURITY: WS canonicalization failed: {}",
                                                e
                                            );
                                            let error_resp = make_ws_error_response(
                                                Some(id),
                                                -32603,
                                                "Internal error",
                                            );
                                            let mut sink = client_sink.lock().await;
                                            let _ =
                                                sink.send(Message::Text(error_resp.into())).await;
                                            continue;
                                        }
                                    }
                                } else {
                                    text.to_string()
                                };

                                // Track request→response mapping for output-schema
                                // enforcement when upstream omits result._meta.tool.
                                track_pending_tool_call(
                                    &state.sessions,
                                    &session_id,
                                    id,
                                    tool_name,
                                );

                                if let Err(e) = send_text_to_upstream(
                                    &upstream_sink,
                                    &in_flight_client_requests,
                                    &parsed,
                                    forward_text,
                                )
                                .await
                                {
                                    tracing::error!(
                                        session_id = %session_id,
                                        "Failed to forward to upstream: {}",
                                        e
                                    );
                                    break;
                                }
                            }
                            Verdict::Deny { ref reason } => {
                                // Audit the denial with detailed reason
                                let mut extra = json!({
                                    "source": "ws_proxy",
                                    "session": session_id,
                                    "transport": "websocket",
                                    "tool": tool_name,
                                });
                                if reason == INVALID_PRESENTED_APPROVAL_REASON
                                    && presented_approval_id.is_some()
                                {
                                    extra["event"] = json!("presented_approval_replay_denied");
                                    extra["approval_id"] = json!(presented_approval_id);
                                }
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(&action, &verdict, extra, acis_envelope)
                                    .await
                                {
                                    tracing::error!(
                                        "AUDIT FAILURE in WS proxy: security decision not recorded: {}",
                                        e
                                    );
                                    // SECURITY (FIND-CREATIVE-003): Strict audit mode — fail-closed.
                                    if state.audit_strict_mode {
                                        let error = make_ws_error_response(
                                            Some(id),
                                            -32000,
                                            "Audit logging failed — request denied (strict audit mode)",
                                        );
                                        let mut sink = client_sink.lock().await;
                                        let _ = sink.send(Message::Text(error.into())).await;
                                        continue;
                                    }
                                }

                                // SECURITY (FIND-R46-012): Generic message to client.
                                // Detailed reason is in the audit log only.
                                let _ = reason; // used in audit above
                                let error =
                                    make_ws_error_response(Some(id), -32001, "Denied by policy");
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                            }
                            Verdict::RequireApproval { ref reason, .. } => {
                                let approval_verdict = Verdict::RequireApproval {
                                    reason: reason.clone(),
                                };
                                let containment_context =
                                    super::helpers::approval_containment_context_from_envelope(
                                        &acis_envelope,
                                        reason,
                                    );
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &action,
                                        &approval_verdict,
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                        }),
                                        acis_envelope,
                                    )
                                    .await
                                {
                                    tracing::error!(
                                        "AUDIT FAILURE in WS proxy: security decision not recorded: {}",
                                        e
                                    );
                                    // SECURITY (FIND-CREATIVE-003): Strict audit mode — fail-closed.
                                    if state.audit_strict_mode {
                                        let error = make_ws_error_response(
                                            Some(id),
                                            -32000,
                                            "Audit logging failed — request denied (strict audit mode)",
                                        );
                                        let mut sink = client_sink.lock().await;
                                        let _ = sink.send(Message::Text(error.into())).await;
                                        continue;
                                    }
                                }
                                let approval_reason = "Approval required";
                                let approval_id =
                                    super::helpers::create_pending_approval_with_context(
                                        &state,
                                        &session_id,
                                        &action,
                                        reason,
                                        containment_context,
                                    )
                                    .await;
                                let error = make_ws_error_response_with_data(
                                    Some(id),
                                    -32001,
                                    approval_reason,
                                    Some(json!({
                                        "verdict": "require_approval",
                                        "reason": approval_reason,
                                        "approval_id": approval_id,
                                    })),
                                );
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                            }
                            // Fail-closed: unknown Verdict variants produce Deny
                            _ => {
                                let error =
                                    make_ws_error_response(Some(id), -32001, "Denied by policy");
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                            }
                        }
                    }
                    MessageType::ResourceRead { ref id, ref uri } => {
                        // SECURITY (FIND-R74-007): Check for memory poisoning in resource URI.
                        // ResourceRead is a likely exfiltration vector: a poisoned tool response
                        // says "read this file" and the agent issues resources/read for that URI.
                        // Parity with HTTP handler (handlers.rs:1472).
                        {
                            let poisoning_detected = state
                                .sessions
                                .get_mut(&session_id)
                                .and_then(|session| {
                                    let uri_params = json!({"uri": uri});
                                    let matches =
                                        session.memory_tracker.check_parameters(&uri_params);
                                    if !matches.is_empty() {
                                        for m in &matches {
                                            tracing::warn!(
                                                "SECURITY: Memory poisoning detected in WS resources/read (session {}): \
                                                 param '{}' contains replayed data (fingerprint: {})",
                                                session_id,
                                                m.param_location,
                                                m.fingerprint
                                            );
                                        }
                                        Some(matches.len())
                                    } else {
                                        None
                                    }
                                });
                            if let Some(match_count) = poisoning_detected {
                                let poison_action = extractor::extract_resource_action(uri);
                                let deny_reason = format!(
                                    "Memory poisoning detected: {match_count} replayed data fragment(s) in resources/read"
                                );
                                let resource_poison_verdict = Verdict::Deny {
                                    reason: deny_reason.clone(),
                                };
                                let poisoning_security_context =
                                    super::helpers::memory_poisoning_security_context(
                                        &json!({ "uri": uri }),
                                        "memory_poisoning",
                                    );
                                let envelope = build_secondary_acis_envelope_with_security_context(
                                    &poison_action,
                                    &resource_poison_verdict,
                                    DecisionOrigin::MemoryPoisoning,
                                    "websocket",
                                    Some(&session_id),
                                    Some(&poisoning_security_context),
                                );
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &poison_action,
                                        &resource_poison_verdict,
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "event": "memory_poisoning_detected",
                                            "matches": match_count,
                                            "uri": uri,
                                        }),
                                        envelope,
                                    )
                                    .await
                                {
                                    tracing::warn!(
                                        "Failed to audit WS resource memory poisoning: {}",
                                        e
                                    );
                                }
                                let error = make_ws_error_response(
                                    Some(id),
                                    -32001,
                                    "Request blocked: security policy violation",
                                );
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                                continue;
                            }
                        }

                        // SECURITY (FIND-R115-041): Rug-pull detection for resource URIs.
                        // If the upstream server was flagged (annotations changed since initial
                        // tools/list), block resource reads from that server.
                        // Parity with HTTP handler (handlers.rs:1555).
                        // SECURITY (R240-PROXY-1): Fall back to global registry on session miss.
                        {
                            let is_flagged = state
                                .sessions
                                .get_mut(&session_id)
                                .map(|s| s.flagged_tools.contains(uri.as_str()))
                                .unwrap_or_else(|| {
                                    state.sessions.is_tool_globally_flagged(uri.as_str())
                                });
                            if is_flagged {
                                let action = extractor::extract_resource_action(uri);
                                let verdict = Verdict::Deny {
                                    reason: format!(
                                        "Resource '{uri}' blocked: server flagged by rug-pull detection"
                                    ),
                                };
                                let rug_pull_security_context =
                                    super::helpers::rug_pull_security_context(&action);
                                let envelope = build_secondary_acis_envelope_with_security_context(
                                    &action,
                                    &verdict,
                                    DecisionOrigin::CapabilityEnforcement,
                                    "websocket",
                                    Some(&session_id),
                                    Some(&rug_pull_security_context),
                                );
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &action,
                                        &verdict,
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "event": "rug_pull_resource_blocked",
                                            "uri": uri,
                                        }),
                                        envelope,
                                    )
                                    .await
                                {
                                    tracing::warn!(
                                        "Failed to audit WS resource rug-pull block: {}",
                                        e
                                    );
                                }
                                let error =
                                    make_ws_error_response(Some(id), -32001, "Denied by policy");
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                                continue;
                            }
                        }

                        // Build action for resource read
                        let mut action = extractor::extract_resource_action(uri);
                        let mut matched_approval_id: Option<String> = None;

                        // SECURITY (FIND-R75-002): DNS resolution for resource reads.
                        // Parity with HTTP handler (handlers.rs:1543).
                        if state.engine.has_ip_rules() {
                            super::helpers::resolve_domains(&mut action).await;
                        }

                        // SECURITY (FIND-R116-004): DLP scan on resource URI.
                        // Parity with HTTP handler (handlers.rs:1598).
                        {
                            let uri_params = json!({"uri": uri});
                            let dlp_findings = scan_parameters_for_secrets(&uri_params);
                            if !dlp_findings.is_empty() {
                                for finding in &dlp_findings {
                                    record_dlp_finding(&finding.pattern_name);
                                }
                                tracing::warn!(
                                    "SECURITY: Secret detected in WS resource URI! Session: {}, URI: [redacted]",
                                    session_id,
                                );
                                let audit_verdict = Verdict::Deny {
                                    reason: "DLP blocked: secret detected in resource URI"
                                        .to_string(),
                                };
                                let parameter_security_context =
                                    super::helpers::parameter_dlp_security_context(
                                        &uri_params,
                                        true,
                                        "resource_uri_dlp",
                                    );
                                let envelope = build_secondary_acis_envelope_with_security_context(
                                    &action,
                                    &audit_verdict,
                                    DecisionOrigin::Dlp,
                                    "websocket",
                                    Some(&session_id),
                                    Some(&parameter_security_context),
                                );
                                if let Err(e) = state.audit.log_entry_with_acis(
                                    &action, &audit_verdict,
                                    json!({
                                        "source": "ws_proxy", "session": session_id,
                                        "transport": "websocket", "event": "resource_uri_dlp_alert",
                                    }),
                                    envelope,
                                ).await {
                                    tracing::warn!("Failed to audit WS resource URI DLP: {}", e);
                                }
                                let error = make_ws_error_response(
                                    Some(id),
                                    -32001,
                                    "Request blocked: security policy violation",
                                );
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                                continue;
                            }
                        }

                        // SECURITY (FIND-R115-042): Circuit breaker check for resource reads.
                        // Parity with HTTP handler (handlers.rs:1668) — prevent resource reads
                        // from hammering a failing upstream server.
                        if let Some(ref circuit_breaker) = state.circuit_breaker {
                            if let Err(reason) = circuit_breaker.can_proceed(uri) {
                                tracing::warn!(
                                    "SECURITY: WS circuit breaker open for resource '{}' in session {}: {}",
                                    uri,
                                    session_id,
                                    reason
                                );
                                let verdict = Verdict::Deny {
                                    reason: format!("Circuit breaker open: {reason}"),
                                };
                                // SECURITY (R251-ACIS-1): Use CircuitBreaker origin, not RateLimiter.
                                let circuit_breaker_security_context =
                                    super::helpers::circuit_breaker_security_context(&action);
                                let envelope = build_secondary_acis_envelope_with_security_context(
                                    &action,
                                    &verdict,
                                    DecisionOrigin::CircuitBreaker,
                                    "websocket",
                                    Some(&session_id),
                                    Some(&circuit_breaker_security_context),
                                );
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &action,
                                        &verdict,
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "event": "circuit_breaker_rejected",
                                            "uri": uri,
                                        }),
                                        envelope,
                                    )
                                    .await
                                {
                                    tracing::warn!(
                                        "Failed to audit WS resource circuit breaker rejection: {}",
                                        e
                                    );
                                }
                                let error = make_ws_error_response(
                                    Some(id),
                                    -32001,
                                    "Service temporarily unavailable",
                                );
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                                continue;
                            }
                        }

                        // SECURITY (FIND-R130-002): TOCTOU-safe context+eval+update
                        // for resource reads. Matches ToolCall fix above and HTTP
                        // handler FIND-R112-002 pattern (handlers.rs:1711-1774).

                        // Pre-compute security context BEFORE acquiring DashMap write lock
                        // to avoid deadlock — build_ws_runtime_security_context internally
                        // calls sessions.get()/get_mut() which would re-enter the lock.
                        let pre_eval_ctx = state
                            .sessions
                            .get(&session_id)
                            .map(|session| EvaluationContext {
                                timestamp: None,
                                agent_id: session.oauth_subject.clone(),
                                agent_identity: session.agent_identity.clone(),
                                call_chain: session.current_call_chain.clone(),
                                ..EvaluationContext::default()
                            })
                            .unwrap_or_else(|| EvaluationContext {
                                agent_id: oauth_claims.as_ref().map(|claims| claims.sub.clone()),
                                ..EvaluationContext::default()
                            });
                        let security_context = build_ws_runtime_security_context(
                            &parsed,
                            &action,
                            &handshake_headers,
                            super::helpers::TransportSecurityInputs {
                                oauth_evidence: oauth_claims.as_ref(),
                                eval_ctx: Some(&pre_eval_ctx),
                                sessions: &state.sessions,
                                session_id: Some(&session_id),
                                trusted_request_signers: &state.trusted_request_signers,
                                detached_signature_freshness: state.detached_signature_freshness,
                            },
                        );

                        // TOCTOU-safe evaluation + session update (write lock)
                        let (mediation_result, ctx) = if let Some(mut session) =
                            state.sessions.get_mut(&session_id)
                        {
                            let ctx = EvaluationContext {
                                timestamp: None,
                                agent_id: session.oauth_subject.clone(),
                                agent_identity: session.agent_identity.clone(),
                                call_counts: session.call_counts.clone(),
                                previous_actions: session.action_history.iter().cloned().collect(),
                                call_chain: session.current_call_chain.clone(),
                                tenant_id: None,
                                verification_tier: None,
                                capability_token: None,
                                session_state: None,
                            };
                            let result = mediate_with_security_context(
                                &uuid::Uuid::new_v4().to_string().replace('-', ""),
                                &action,
                                &state.engine,
                                Some(&ctx),
                                security_context.as_ref(),
                                "websocket",
                                &state.mediation_config,
                                Some(&session_id),
                                None,
                            );

                            // Atomically update session on Allow
                            if matches!(result.verdict, Verdict::Allow) {
                                session.touch();
                                use crate::proxy::call_chain::{
                                    MAX_ACTION_HISTORY, MAX_CALL_COUNT_TOOLS,
                                };
                                let resource_key = format!(
                                    "resources/read:{}",
                                    uri.chars().take(128).collect::<String>()
                                );
                                if session.call_counts.len() < MAX_CALL_COUNT_TOOLS
                                    || session.call_counts.contains_key(&resource_key)
                                {
                                    let count =
                                        session.call_counts.entry(resource_key).or_insert(0);
                                    *count = count.saturating_add(1);
                                }
                                if session.action_history.len() >= MAX_ACTION_HISTORY {
                                    session.action_history.pop_front();
                                }
                                session
                                    .action_history
                                    .push_back("resources/read".to_string());
                            }

                            (result, ctx)
                        } else {
                            let ctx = EvaluationContext::default();
                            let result = mediate_with_security_context(
                                &uuid::Uuid::new_v4().to_string().replace('-', ""),
                                &action,
                                &state.engine,
                                None,
                                security_context.as_ref(),
                                "websocket",
                                &state.mediation_config,
                                Some(&session_id),
                                None,
                            );
                            (result, ctx)
                        };

                        let mut final_origin = mediation_result.origin;
                        let mut acis_envelope = mediation_result.envelope.clone();
                        let mut refresh_envelope = false;
                        let verdict = match mediation_result.verdict {
                            Verdict::RequireApproval { reason } => {
                                match super::helpers::presented_approval_matches_action(
                                    &state,
                                    &session_id,
                                    presented_approval_id.as_deref(),
                                    &action,
                                )
                                .await
                                {
                                    Ok(Some(approval_id)) => {
                                        matched_approval_id = Some(approval_id);
                                        final_origin = DecisionOrigin::PolicyEngine;
                                        refresh_envelope = true;
                                        Verdict::Allow
                                    }
                                    Ok(None) => Verdict::RequireApproval { reason },
                                    Err(()) => {
                                        final_origin = DecisionOrigin::ApprovalGate;
                                        refresh_envelope = true;
                                        Verdict::Deny {
                                            reason: INVALID_PRESENTED_APPROVAL_REASON.to_string(),
                                        }
                                    }
                                }
                            }
                            other => other,
                        };
                        if refresh_envelope {
                            acis_envelope = refresh_ws_acis_envelope(
                                &acis_envelope,
                                &action,
                                &verdict,
                                final_origin,
                                &session_id,
                                &ctx,
                                security_context.as_ref(),
                            );
                        }

                        match verdict {
                            Verdict::Allow => {
                                // SECURITY (FIND-R116-002): ABAC refinement for resource reads.
                                // Parity with HTTP handler (handlers.rs:1783) and gRPC (service.rs:972).
                                if let Some(ref abac) = state.abac_engine {
                                    let principal_id =
                                        ctx.agent_id.as_deref().unwrap_or("anonymous");
                                    let principal_type = ctx.principal_type();
                                    let session_risk = state
                                        .sessions
                                        .get_mut(&session_id)
                                        .and_then(|s| s.risk_score.clone());
                                    let abac_ctx = vellaveto_engine::abac::AbacEvalContext {
                                        eval_ctx: &ctx,
                                        principal_type,
                                        principal_id,
                                        risk_score: session_risk.as_ref(),
                                    };
                                    match abac.evaluate(&action, &abac_ctx) {
                                        vellaveto_engine::abac::AbacDecision::Deny {
                                            policy_id,
                                            reason,
                                        } => {
                                            let deny_verdict = Verdict::Deny {
                                                reason: reason.clone(),
                                            };
                                            let abac_security_context =
                                                super::helpers::abac_deny_security_context(&action);
                                            let envelope =
                                                build_secondary_acis_envelope_with_security_context(
                                                    &action,
                                                    &deny_verdict,
                                                    DecisionOrigin::PolicyEngine,
                                                    "websocket",
                                                    Some(&session_id),
                                                    Some(&abac_security_context),
                                                );
                                            if let Err(e) = state
                                                .audit
                                                .log_entry_with_acis(
                                                    &action,
                                                    &deny_verdict,
                                                    json!({
                                                        "source": "ws_proxy",
                                                        "session": session_id,
                                                        "transport": "websocket",
                                                        "event": "abac_deny",
                                                        "abac_policy": policy_id,
                                                        "uri": uri,
                                                    }),
                                                    envelope,
                                                )
                                                .await
                                            {
                                                tracing::warn!(
                                                    "Failed to audit WS resource ABAC deny: {}",
                                                    e
                                                );
                                            }
                                            let error_resp = make_ws_error_response(
                                                Some(id),
                                                -32001,
                                                "Denied by policy",
                                            );
                                            let mut sink = client_sink.lock().await;
                                            let _ =
                                                sink.send(Message::Text(error_resp.into())).await;
                                            continue;
                                        }
                                        vellaveto_engine::abac::AbacDecision::Allow {
                                            policy_id,
                                        } => {
                                            // SECURITY (FIND-R192-002): record_usage parity.
                                            if let Some(ref la) = state.least_agency {
                                                la.record_usage(
                                                    principal_id,
                                                    &session_id,
                                                    &policy_id,
                                                    uri,
                                                    &action.function,
                                                );
                                            }
                                        }
                                        vellaveto_engine::abac::AbacDecision::NoMatch => {
                                            // Fall through — existing Allow stands
                                        }
                                        #[allow(unreachable_patterns)]
                                        _ => {
                                            tracing::warn!(
                                                "Unknown AbacDecision variant in WS resource_read — fail-closed"
                                            );
                                            let error_resp = make_ws_error_response(
                                                Some(id),
                                                -32001,
                                                "Denied by policy",
                                            );
                                            let mut sink = client_sink.lock().await;
                                            let _ =
                                                sink.send(Message::Text(error_resp.into())).await;
                                            continue;
                                        }
                                    }
                                }

                                // NOTE: Session touch + call_counts/action_history
                                // update already performed inside the TOCTOU-safe
                                // block above (FIND-R130-002). No separate update here.

                                if super::helpers::consume_presented_approval(
                                    &state,
                                    &session_id,
                                    matched_approval_id.as_deref(),
                                    &action,
                                    security_context.as_ref(),
                                )
                                .await
                                .is_err()
                                {
                                    let deny_verdict = Verdict::Deny {
                                        reason: INVALID_PRESENTED_APPROVAL_REASON.to_string(),
                                    };
                                    let invalid_approval_security_context =
                                        super::helpers::invalid_presented_approval_security_context(
                                            &action,
                                        );
                                    let combined_security_context =
                                        super::helpers::merge_transport_security_context(
                                            security_context.as_ref(),
                                            Some(&invalid_approval_security_context),
                                        );
                                    let effective_security_context = combined_security_context
                                        .as_ref()
                                        .unwrap_or(&invalid_approval_security_context);
                                    let envelope =
                                        build_secondary_acis_envelope_with_security_context(
                                            &action,
                                            &deny_verdict,
                                            DecisionOrigin::ApprovalGate,
                                            "websocket",
                                            Some(&session_id),
                                            Some(effective_security_context),
                                        );
                                    // SECURITY (R274-AUDIT-1): the result was bound to `_`, so a failed
                                    // audit write here was invisible. The denial below is unchanged —
                                    // this only makes the lost record observable.
                                    if let Err(e) = state
                                        .audit
                                        .log_entry_with_acis(
                                            &action,
                                            &deny_verdict,
                                            json!({
                                                "source": "ws_proxy",
                                                "session": session_id,
                                                "transport": "websocket",
                                                "event": "presented_approval_replay_denied",
                                                "approval_id": matched_approval_id,
                                                "uri": uri,
                                            }),
                                            envelope,
                                        )
                                        .await
                                    {
                                        tracing::warn!("Failed to audit denial: {}", e);
                                    }
                                    let error_resp = make_ws_error_response(
                                        Some(id),
                                        -32001,
                                        "Denied by policy",
                                    );
                                    let mut sink = client_sink.lock().await;
                                    let _ = sink.send(Message::Text(error_resp.into())).await;
                                    continue;
                                }

                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &action,
                                        &Verdict::Allow,
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "resource_uri": uri,
                                        }),
                                        acis_envelope,
                                    )
                                    .await
                                {
                                    tracing::error!(
                                        "AUDIT FAILURE in WS proxy: security decision not recorded: {}",
                                        e
                                    );
                                    // SECURITY (FIND-CREATIVE-003): Strict audit mode — fail-closed.
                                    if state.audit_strict_mode {
                                        let error = make_ws_error_response(
                                            Some(id),
                                            -32000,
                                            "Audit logging failed — request denied (strict audit mode)",
                                        );
                                        let mut sink = client_sink.lock().await;
                                        let _ = sink.send(Message::Text(error.into())).await;
                                        continue;
                                    }
                                }

                                // SECURITY (FIND-R46-011): Fail-closed on canonicalization
                                // failure. Do NOT fall back to original text.
                                let forward_text = if state.canonicalize {
                                    match serde_json::to_string(&parsed) {
                                        Ok(canonical) => canonical,
                                        Err(e) => {
                                            tracing::error!(
                                                "SECURITY: WS resource canonicalization failed: {}",
                                                e
                                            );
                                            let error_resp = make_ws_error_response(
                                                Some(id),
                                                -32603,
                                                "Internal error",
                                            );
                                            let mut sink = client_sink.lock().await;
                                            let _ =
                                                sink.send(Message::Text(error_resp.into())).await;
                                            continue;
                                        }
                                    }
                                } else {
                                    text.to_string()
                                };
                                if let Err(e) = send_text_to_upstream(
                                    &upstream_sink,
                                    &in_flight_client_requests,
                                    &parsed,
                                    forward_text,
                                )
                                .await
                                {
                                    tracing::error!("Failed to forward resource read: {}", e);
                                    break;
                                }
                            }
                            // SECURITY (FIND-R116-009): Separate handling for Deny vs RequireApproval
                            // with per-verdict audit logging. Parity with gRPC (service.rs:1051-1076).
                            Verdict::Deny { ref reason } => {
                                let mut audit_metadata = json!({
                                    "source": "ws_proxy",
                                    "session": session_id,
                                    "transport": "websocket",
                                    "resource_uri": uri,
                                });
                                if reason == INVALID_PRESENTED_APPROVAL_REASON
                                    && presented_approval_id.is_some()
                                {
                                    audit_metadata["event"] =
                                        json!("presented_approval_replay_denied");
                                    audit_metadata["approval_id"] = json!(presented_approval_id);
                                }
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &action,
                                        &Verdict::Deny {
                                            reason: reason.clone(),
                                        },
                                        audit_metadata,
                                        acis_envelope,
                                    )
                                    .await
                                {
                                    tracing::error!(
                                        "AUDIT FAILURE in WS proxy: security decision not recorded: {}",
                                        e
                                    );
                                    // SECURITY (FIND-CREATIVE-003): Strict audit mode — fail-closed.
                                    if state.audit_strict_mode {
                                        let error = make_ws_error_response(
                                            Some(id),
                                            -32000,
                                            "Audit logging failed — request denied (strict audit mode)",
                                        );
                                        let mut sink = client_sink.lock().await;
                                        let _ = sink.send(Message::Text(error.into())).await;
                                        continue;
                                    }
                                }
                                let error =
                                    make_ws_error_response(Some(id), -32001, "Denied by policy");
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                            }
                            Verdict::RequireApproval { ref reason, .. } => {
                                let approval_verdict = Verdict::RequireApproval {
                                    reason: reason.clone(),
                                };
                                let containment_context =
                                    super::helpers::approval_containment_context_from_envelope(
                                        &acis_envelope,
                                        reason,
                                    );
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &action,
                                        &approval_verdict,
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "resource_uri": uri,
                                            "event": "require_approval",
                                        }),
                                        acis_envelope,
                                    )
                                    .await
                                {
                                    tracing::error!(
                                        "AUDIT FAILURE in WS proxy: security decision not recorded: {}",
                                        e
                                    );
                                    // SECURITY (FIND-CREATIVE-003): Strict audit mode — fail-closed.
                                    if state.audit_strict_mode {
                                        let error = make_ws_error_response(
                                            Some(id),
                                            -32000,
                                            "Audit logging failed — request denied (strict audit mode)",
                                        );
                                        let mut sink = client_sink.lock().await;
                                        let _ = sink.send(Message::Text(error.into())).await;
                                        continue;
                                    }
                                }
                                let approval_id =
                                    super::helpers::create_pending_approval_with_context(
                                        &state,
                                        &session_id,
                                        &action,
                                        reason,
                                        containment_context,
                                    )
                                    .await;
                                let error = make_ws_error_response_with_data(
                                    Some(id),
                                    -32001,
                                    "Approval required",
                                    Some(json!({
                                        "verdict": "require_approval",
                                        "reason": reason,
                                        "approval_id": approval_id,
                                    })),
                                );
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                            }
                            #[allow(unreachable_patterns)]
                            _ => {
                                // SECURITY: Future variants — fail-closed.
                                tracing::warn!(
                                    "Unknown Verdict variant in WS resource_read — fail-closed"
                                );
                                let error =
                                    make_ws_error_response(Some(id), -32001, "Denied by policy");
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                            }
                        }
                    }
                    MessageType::Batch => {
                        // Reject batches per MCP spec
                        let action = Action::new(
                            "vellaveto",
                            "batch_rejected",
                            json!({
                                "session": session_id,
                                "transport": "websocket",
                            }),
                        );
                        let batch_verdict = Verdict::Deny {
                            reason: "JSON-RPC batching not supported".to_string(),
                        };
                        let batch_security_context =
                            super::helpers::batch_rejection_security_context(&action);
                        let envelope = build_secondary_acis_envelope_with_security_context(
                            &action,
                            &batch_verdict,
                            DecisionOrigin::PolicyEngine,
                            "websocket",
                            Some(&session_id),
                            Some(&batch_security_context),
                        );
                        if let Err(e) = state
                            .audit
                            .log_entry_with_acis(
                                &action,
                                &batch_verdict,
                                json!({
                                    "source": "ws_proxy",
                                    "event": "batch_rejected",
                                }),
                                envelope,
                            )
                            .await
                        {
                            tracing::warn!("Failed to audit WS batch rejection: {}", e);
                        }
                        let error = json!({
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -32600,
                                "message": "JSON-RPC batch requests are not supported"
                            },
                            "id": null
                        });
                        let error_text = serde_json::to_string(&error)
                            .unwrap_or_else(|_| r#"{"jsonrpc":"2.0","error":{"code":-32600,"message":"Batch not supported"},"id":null}"#.to_string());
                        let mut sink = client_sink.lock().await;
                        let _ = sink.send(Message::Text(error_text.into())).await;
                    }
                    MessageType::Invalid { ref id, ref reason } => {
                        tracing::warn!(
                            "Invalid JSON-RPC request in WebSocket transport: {}",
                            reason
                        );
                        let error =
                            make_ws_error_response(Some(id), -32600, "Invalid JSON-RPC request");
                        let mut sink = client_sink.lock().await;
                        let _ = sink.send(Message::Text(error.into())).await;
                    }
                    MessageType::SamplingRequest { ref id } => {
                        // SECURITY (FIND-R74-006): Call inspect_sampling() for full
                        // verdict (enabled + model filter + tool output check + rate limit),
                        // matching HTTP handler parity (handlers.rs:1681).
                        let params = parsed.get("params").cloned().unwrap_or(json!({}));
                        // SECURITY (FIND-R125-001): Per-session sampling rate limit
                        // parity with elicitation. Atomically read + increment.
                        let sampling_verdict = {
                            let mut session_ref = state.sessions.get_mut(&session_id);
                            let current_count =
                                session_ref.as_ref().map(|s| s.sampling_count).unwrap_or(0);
                            let verdict = vellaveto_mcp::elicitation::inspect_sampling(
                                &params,
                                &state.sampling_config,
                                current_count,
                            );
                            if matches!(verdict, vellaveto_mcp::elicitation::SamplingVerdict::Allow)
                            {
                                if let Some(ref mut s) = session_ref {
                                    s.sampling_count = s.sampling_count.saturating_add(1);
                                }
                            }
                            verdict
                        };
                        match sampling_verdict {
                            vellaveto_mcp::elicitation::SamplingVerdict::Allow => {
                                // Forward allowed sampling request
                                // SECURITY (FIND-R48-001): Fail-closed on canonicalization failure.
                                // Falling back to original text would create a TOCTOU gap.
                                let forward_text = if state.canonicalize {
                                    match serde_json::to_string(&parsed) {
                                        Ok(canonical) => canonical,
                                        Err(e) => {
                                            tracing::error!(
                                                "SECURITY: WS sampling canonicalization failed: {}",
                                                e
                                            );
                                            let error_resp = make_ws_error_response(
                                                Some(id),
                                                -32603,
                                                "Internal error",
                                            );
                                            let mut sink = client_sink.lock().await;
                                            let _ =
                                                sink.send(Message::Text(error_resp.into())).await;
                                            continue;
                                        }
                                    }
                                } else {
                                    text.to_string()
                                };
                                if let Err(e) = send_text_to_upstream(
                                    &upstream_sink,
                                    &in_flight_client_requests,
                                    &parsed,
                                    forward_text,
                                )
                                .await
                                {
                                    tracing::error!("Failed to forward sampling request: {}", e);
                                    break;
                                }
                            }
                            vellaveto_mcp::elicitation::SamplingVerdict::Deny { reason } => {
                                tracing::warn!(
                                    session_id = %session_id,
                                    "Blocked WS sampling/createMessage: {}",
                                    reason
                                );
                                let action = Action::new(
                                    "vellaveto",
                                    "ws_sampling_interception",
                                    json!({
                                        "method": "sampling/createMessage",
                                        "session": session_id,
                                        "transport": "websocket",
                                        "reason": &reason,
                                    }),
                                );
                                let verdict = Verdict::Deny {
                                    reason: reason.clone(),
                                };
                                let sampling_security_context =
                                    super::helpers::sampling_interception_security_context(&action);
                                let envelope = build_secondary_acis_envelope_with_security_context(
                                    &action,
                                    &verdict,
                                    DecisionOrigin::PolicyEngine,
                                    "websocket",
                                    Some(&session_id),
                                    Some(&sampling_security_context),
                                );
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &action,
                                        &verdict,
                                        json!({
                                            "source": "ws_proxy",
                                            "event": "ws_sampling_interception",
                                        }),
                                        envelope,
                                    )
                                    .await
                                {
                                    tracing::warn!(
                                        "Failed to audit WS sampling interception: {}",
                                        e
                                    );
                                }
                                // SECURITY: Generic message to client — detailed reason
                                // is in the audit log, not leaked to the client.
                                let error = make_ws_error_response(
                                    Some(id),
                                    -32001,
                                    "sampling/createMessage blocked by policy",
                                );
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                            }
                        }
                    }
                    MessageType::TaskRequest {
                        ref id,
                        ref task_method,
                        ref task_id,
                    } => {
                        // SECURITY (FIND-R76-001): Memory poisoning detection on task params.
                        // Parity with HTTP handler (handlers.rs:2027-2084). Agents could
                        // exfiltrate poisoned data via task management operations.
                        {
                            let task_params = parsed.get("params").cloned().unwrap_or(json!({}));
                            let poisoning_detected = state
                                .sessions
                                .get_mut(&session_id)
                                .and_then(|session| {
                                    let matches =
                                        session.memory_tracker.check_parameters(&task_params);
                                    if !matches.is_empty() {
                                        for m in &matches {
                                            tracing::warn!(
                                                "SECURITY: Memory poisoning detected in WS task '{}' (session {}): \
                                                 param '{}' contains replayed data (fingerprint: {})",
                                                task_method,
                                                session_id,
                                                m.param_location,
                                                m.fingerprint
                                            );
                                        }
                                        Some(matches.len())
                                    } else {
                                        None
                                    }
                                });
                            if let Some(match_count) = poisoning_detected {
                                let poison_action =
                                    extractor::extract_task_action(task_method, task_id.as_deref());
                                let deny_reason = format!(
                                    "Memory poisoning detected: {match_count} replayed data fragment(s) in task '{task_method}'"
                                );
                                let task_poison_verdict = Verdict::Deny {
                                    reason: deny_reason,
                                };
                                let poisoning_security_context =
                                    super::helpers::memory_poisoning_security_context(
                                        &task_params,
                                        "memory_poisoning",
                                    );
                                let envelope = build_secondary_acis_envelope_with_security_context(
                                    &poison_action,
                                    &task_poison_verdict,
                                    DecisionOrigin::MemoryPoisoning,
                                    "websocket",
                                    Some(&session_id),
                                    Some(&poisoning_security_context),
                                );
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &poison_action,
                                        &task_poison_verdict,
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "event": "memory_poisoning_detected",
                                            "matches": match_count,
                                            "task_method": task_method,
                                        }),
                                        envelope,
                                    )
                                    .await
                                {
                                    tracing::warn!(
                                        "Failed to audit WS task memory poisoning: {}",
                                        e
                                    );
                                }
                                let error = make_ws_error_response(
                                    Some(id),
                                    -32001,
                                    "Request blocked: security policy violation",
                                );
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                                continue;
                            }
                        }

                        // SECURITY (FIND-R76-001): DLP scan task request parameters.
                        // Parity with HTTP handler (handlers.rs:2086-2145). Agents could
                        // embed secrets in task_id or params to exfiltrate them.
                        {
                            let task_params = parsed.get("params").cloned().unwrap_or(json!({}));
                            let dlp_findings = scan_parameters_for_secrets(&task_params);
                            if !dlp_findings.is_empty() {
                                for finding in &dlp_findings {
                                    record_dlp_finding(&finding.pattern_name);
                                }
                                let patterns: Vec<String> = dlp_findings
                                    .iter()
                                    .map(|f| format!("{} at {}", f.pattern_name, f.location))
                                    .collect();
                                tracing::warn!(
                                    "SECURITY: DLP blocking WS task '{}' in session {}: {:?}",
                                    task_method,
                                    session_id,
                                    patterns
                                );
                                let dlp_action =
                                    extractor::extract_task_action(task_method, task_id.as_deref());
                                let task_dlp_verdict = Verdict::Deny {
                                    reason: format!(
                                        "DLP: secrets detected in task request: {patterns:?}"
                                    ),
                                };
                                let parameter_security_context =
                                    super::helpers::parameter_dlp_security_context(
                                        &task_params,
                                        true,
                                        "task_parameter_dlp",
                                    );
                                let envelope = build_secondary_acis_envelope_with_security_context(
                                    &dlp_action,
                                    &task_dlp_verdict,
                                    DecisionOrigin::Dlp,
                                    "websocket",
                                    Some(&session_id),
                                    Some(&parameter_security_context),
                                );
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &dlp_action,
                                        &task_dlp_verdict,
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "event": "dlp_secret_detected_task",
                                            "task_method": task_method,
                                            "findings": patterns,
                                        }),
                                        envelope,
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit WS task DLP: {}", e);
                                }
                                let error = make_ws_error_response(
                                    Some(id),
                                    -32001,
                                    "Request blocked: security policy violation",
                                );
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                                continue;
                            }
                        }

                        // Policy-evaluate task requests (async operations)
                        let action =
                            extractor::extract_task_action(task_method, task_id.as_deref());
                        let mut matched_approval_id: Option<String> = None;
                        // SECURITY (FIND-R130-002): TOCTOU-safe context+eval for task
                        // requests. Context is built inside the DashMap shard lock to
                        // prevent stale snapshot evaluation races.
                        // SECURITY (FIND-R190-006): Update session state on Allow
                        // (touch + call_counts + action_history) while still holding
                        // the shard lock, matching ToolCall/ResourceRead parity.

                        // Pre-compute security context BEFORE acquiring DashMap write lock
                        // to avoid deadlock — build_ws_runtime_security_context internally
                        // calls sessions.get()/get_mut() which would re-enter the lock.
                        let pre_eval_ctx = state
                            .sessions
                            .get(&session_id)
                            .map(|session| EvaluationContext {
                                timestamp: None,
                                agent_id: session.oauth_subject.clone(),
                                agent_identity: session.agent_identity.clone(),
                                call_chain: session.current_call_chain.clone(),
                                ..EvaluationContext::default()
                            })
                            .unwrap_or_else(|| EvaluationContext {
                                agent_id: oauth_claims.as_ref().map(|claims| claims.sub.clone()),
                                ..EvaluationContext::default()
                            });
                        let security_context = build_ws_runtime_security_context(
                            &parsed,
                            &action,
                            &handshake_headers,
                            super::helpers::TransportSecurityInputs {
                                oauth_evidence: oauth_claims.as_ref(),
                                eval_ctx: Some(&pre_eval_ctx),
                                sessions: &state.sessions,
                                session_id: Some(&session_id),
                                trusted_request_signers: &state.trusted_request_signers,
                                detached_signature_freshness: state.detached_signature_freshness,
                            },
                        );

                        // TOCTOU-safe evaluation + session update (write lock)
                        let (mediation_result, task_eval_ctx) = if let Some(mut session) =
                            state.sessions.get_mut(&session_id)
                        {
                            let ctx = EvaluationContext {
                                timestamp: None,
                                agent_id: session.oauth_subject.clone(),
                                agent_identity: session.agent_identity.clone(),
                                call_counts: session.call_counts.clone(),
                                previous_actions: session.action_history.iter().cloned().collect(),
                                call_chain: session.current_call_chain.clone(),
                                tenant_id: None,
                                verification_tier: None,
                                capability_token: None,
                                session_state: None,
                            };
                            let result = mediate_with_security_context(
                                &uuid::Uuid::new_v4().to_string().replace('-', ""),
                                &action,
                                &state.engine,
                                Some(&ctx),
                                security_context.as_ref(),
                                "websocket",
                                &state.mediation_config,
                                Some(&session_id),
                                None,
                            );

                            // Update session atomically on Allow
                            if matches!(result.verdict, Verdict::Allow) {
                                session.touch();
                                use crate::proxy::call_chain::{
                                    MAX_ACTION_HISTORY, MAX_CALL_COUNT_TOOLS,
                                };
                                if session.call_counts.len() < MAX_CALL_COUNT_TOOLS
                                    || session.call_counts.contains_key(task_method)
                                {
                                    let count = session
                                        .call_counts
                                        .entry(task_method.to_string())
                                        .or_insert(0);
                                    *count = count.saturating_add(1);
                                }
                                if session.action_history.len() >= MAX_ACTION_HISTORY {
                                    session.action_history.pop_front();
                                }
                                session.action_history.push_back(task_method.to_string());
                            }

                            (result, ctx)
                        } else {
                            let ctx = EvaluationContext::default();
                            let result = mediate_with_security_context(
                                &uuid::Uuid::new_v4().to_string().replace('-', ""),
                                &action,
                                &state.engine,
                                None,
                                security_context.as_ref(),
                                "websocket",
                                &state.mediation_config,
                                Some(&session_id),
                                None,
                            );
                            (result, ctx)
                        };

                        let mut final_origin = mediation_result.origin;
                        let mut acis_envelope = mediation_result.envelope.clone();
                        let mut refresh_envelope = false;
                        let verdict = match mediation_result.verdict {
                            Verdict::RequireApproval { reason } => {
                                match super::helpers::presented_approval_matches_action(
                                    &state,
                                    &session_id,
                                    presented_approval_id.as_deref(),
                                    &action,
                                )
                                .await
                                {
                                    Ok(Some(approval_id)) => {
                                        matched_approval_id = Some(approval_id);
                                        final_origin = DecisionOrigin::PolicyEngine;
                                        refresh_envelope = true;
                                        Verdict::Allow
                                    }
                                    Ok(None) => Verdict::RequireApproval { reason },
                                    Err(()) => {
                                        final_origin = DecisionOrigin::ApprovalGate;
                                        refresh_envelope = true;
                                        Verdict::Deny {
                                            reason: INVALID_PRESENTED_APPROVAL_REASON.to_string(),
                                        }
                                    }
                                }
                            }
                            other => other,
                        };
                        if refresh_envelope {
                            acis_envelope = refresh_ws_acis_envelope(
                                &acis_envelope,
                                &action,
                                &verdict,
                                final_origin,
                                &session_id,
                                &task_eval_ctx,
                                security_context.as_ref(),
                            );
                        }

                        match verdict {
                            Verdict::Allow => {
                                // SECURITY (FIND-R190-001): ABAC refinement for TaskRequest,
                                // matching ToolCall/ResourceRead parity.
                                if let Some(ref abac) = state.abac_engine {
                                    let principal_id =
                                        task_eval_ctx.agent_id.as_deref().unwrap_or("anonymous");
                                    let principal_type = task_eval_ctx.principal_type();
                                    let session_risk = state
                                        .sessions
                                        .get_mut(&session_id)
                                        .and_then(|s| s.risk_score.clone());
                                    let abac_ctx = vellaveto_engine::abac::AbacEvalContext {
                                        eval_ctx: &task_eval_ctx,
                                        principal_type,
                                        principal_id,
                                        risk_score: session_risk.as_ref(),
                                    };
                                    match abac.evaluate(&action, &abac_ctx) {
                                        vellaveto_engine::abac::AbacDecision::Deny {
                                            policy_id,
                                            reason,
                                        } => {
                                            let deny_verdict = Verdict::Deny {
                                                reason: reason.clone(),
                                            };
                                            let abac_security_context =
                                                super::helpers::abac_deny_security_context(&action);
                                            let envelope =
                                                build_secondary_acis_envelope_with_security_context(
                                                    &action,
                                                    &deny_verdict,
                                                    DecisionOrigin::PolicyEngine,
                                                    "websocket",
                                                    Some(&session_id),
                                                    Some(&abac_security_context),
                                                );
                                            if let Err(e) = state
                                                .audit
                                                .log_entry_with_acis(
                                                    &action,
                                                    &deny_verdict,
                                                    json!({
                                                        "source": "ws_proxy",
                                                        "session": session_id,
                                                        "transport": "websocket",
                                                        "event": "abac_deny",
                                                        "abac_policy": policy_id,
                                                        "task_method": task_method,
                                                    }),
                                                    envelope,
                                                )
                                                .await
                                            {
                                                tracing::warn!(
                                                    "Failed to audit WS task ABAC deny: {}",
                                                    e
                                                );
                                            }
                                            let error_resp = make_ws_error_response(
                                                Some(id),
                                                -32001,
                                                "Denied by policy",
                                            );
                                            let mut sink = client_sink.lock().await;
                                            let _ =
                                                sink.send(Message::Text(error_resp.into())).await;
                                            continue;
                                        }
                                        vellaveto_engine::abac::AbacDecision::Allow {
                                            policy_id,
                                        } => {
                                            if let Some(ref la) = state.least_agency {
                                                la.record_usage(
                                                    principal_id,
                                                    &session_id,
                                                    &policy_id,
                                                    task_method,
                                                    &action.function,
                                                );
                                            }
                                        }
                                        vellaveto_engine::abac::AbacDecision::NoMatch => {
                                            // Fall through — existing Allow stands
                                        }
                                        #[allow(unreachable_patterns)]
                                        _ => {
                                            tracing::warn!(
                                                "Unknown AbacDecision variant — fail-closed"
                                            );
                                            let error_resp = make_ws_error_response(
                                                Some(id),
                                                -32001,
                                                "Denied by policy",
                                            );
                                            let mut sink = client_sink.lock().await;
                                            let _ =
                                                sink.send(Message::Text(error_resp.into())).await;
                                            continue;
                                        }
                                    }
                                }

                                if super::helpers::consume_presented_approval(
                                    &state,
                                    &session_id,
                                    matched_approval_id.as_deref(),
                                    &action,
                                    security_context.as_ref(),
                                )
                                .await
                                .is_err()
                                {
                                    let deny_verdict = Verdict::Deny {
                                        reason: INVALID_PRESENTED_APPROVAL_REASON.to_string(),
                                    };
                                    let invalid_approval_security_context =
                                        super::helpers::invalid_presented_approval_security_context(
                                            &action,
                                        );
                                    let combined_security_context =
                                        super::helpers::merge_transport_security_context(
                                            security_context.as_ref(),
                                            Some(&invalid_approval_security_context),
                                        );
                                    let effective_security_context = combined_security_context
                                        .as_ref()
                                        .unwrap_or(&invalid_approval_security_context);
                                    let envelope =
                                        build_secondary_acis_envelope_with_security_context(
                                            &action,
                                            &deny_verdict,
                                            DecisionOrigin::ApprovalGate,
                                            "websocket",
                                            Some(&session_id),
                                            Some(effective_security_context),
                                        );
                                    // SECURITY (R274-AUDIT-1): the result was bound to `_`, so a failed
                                    // audit write here was invisible. The denial below is unchanged —
                                    // this only makes the lost record observable.
                                    if let Err(e) = state
                                        .audit
                                        .log_entry_with_acis(
                                            &action,
                                            &deny_verdict,
                                            json!({
                                                "source": "ws_proxy",
                                                "session": session_id,
                                                "transport": "websocket",
                                                "event": "presented_approval_replay_denied",
                                                "approval_id": matched_approval_id,
                                                "task_method": task_method,
                                                "task_id": task_id,
                                            }),
                                            envelope,
                                        )
                                        .await
                                    {
                                        tracing::warn!("Failed to audit denial: {}", e);
                                    }
                                    let error_resp = make_ws_error_response(
                                        Some(id),
                                        -32001,
                                        "Denied by policy",
                                    );
                                    let mut sink = client_sink.lock().await;
                                    let _ = sink.send(Message::Text(error_resp.into())).await;
                                    continue;
                                }

                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &action,
                                        &Verdict::Allow,
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "task_method": task_method,
                                        }),
                                        acis_envelope,
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit WS task allow: {}", e);
                                }
                                // SECURITY (FIND-R48-001): Fail-closed on canonicalization failure.
                                let forward_text = if state.canonicalize {
                                    match serde_json::to_string(&parsed) {
                                        Ok(canonical) => canonical,
                                        Err(e) => {
                                            tracing::error!(
                                                "SECURITY: WS task canonicalization failed: {}",
                                                e
                                            );
                                            let error_resp = make_ws_error_response(
                                                Some(id),
                                                -32603,
                                                "Internal error",
                                            );
                                            let mut sink = client_sink.lock().await;
                                            let _ =
                                                sink.send(Message::Text(error_resp.into())).await;
                                            continue;
                                        }
                                    }
                                } else {
                                    text.to_string()
                                };
                                if let Err(e) = send_text_to_upstream(
                                    &upstream_sink,
                                    &in_flight_client_requests,
                                    &parsed,
                                    forward_text,
                                )
                                .await
                                {
                                    tracing::error!("Failed to forward task request: {}", e);
                                    break;
                                }
                            }
                            Verdict::Deny { ref reason } => {
                                let mut audit_metadata = json!({
                                    "source": "ws_proxy",
                                    "session": session_id,
                                    "transport": "websocket",
                                    "task_method": task_method,
                                });
                                if reason == INVALID_PRESENTED_APPROVAL_REASON
                                    && presented_approval_id.is_some()
                                {
                                    audit_metadata["event"] =
                                        json!("presented_approval_replay_denied");
                                    audit_metadata["approval_id"] = json!(presented_approval_id);
                                    audit_metadata["task_id"] = json!(task_id);
                                }
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &action,
                                        &Verdict::Deny {
                                            reason: reason.clone(),
                                        },
                                        audit_metadata,
                                        acis_envelope,
                                    )
                                    .await
                                {
                                    tracing::error!(
                                        "AUDIT FAILURE in WS proxy: security decision not recorded: {}",
                                        e
                                    );
                                    // SECURITY (FIND-R213-002): Strict audit mode — fail-closed.
                                    if state.audit_strict_mode {
                                        let error = make_ws_error_response(
                                            Some(id),
                                            -32000,
                                            "Audit logging failed — request denied (strict audit mode)",
                                        );
                                        let mut sink = client_sink.lock().await;
                                        let _ = sink.send(Message::Text(error.into())).await;
                                        continue;
                                    }
                                }
                                // SECURITY (FIND-R55-WS-005): Generic denial message to prevent
                                // leaking policy names/details. Detailed reason is in audit log.
                                let denial =
                                    make_ws_error_response(Some(id), -32001, "Denied by policy");
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(denial.into())).await;
                            }
                            Verdict::RequireApproval { ref reason, .. } => {
                                let approval_verdict = Verdict::RequireApproval {
                                    reason: reason.clone(),
                                };
                                let containment_context =
                                    super::helpers::approval_containment_context_from_envelope(
                                        &acis_envelope,
                                        reason,
                                    );
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &action,
                                        &approval_verdict,
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "task_method": task_method,
                                        }),
                                        acis_envelope,
                                    )
                                    .await
                                {
                                    tracing::error!(
                                        "AUDIT FAILURE in WS proxy: security decision not recorded: {}",
                                        e
                                    );
                                    // SECURITY (FIND-R213-002): Strict audit mode — fail-closed.
                                    if state.audit_strict_mode {
                                        let error = make_ws_error_response(
                                            Some(id),
                                            -32000,
                                            "Audit logging failed — request denied (strict audit mode)",
                                        );
                                        let mut sink = client_sink.lock().await;
                                        let _ = sink.send(Message::Text(error.into())).await;
                                        continue;
                                    }
                                }
                                let approval_id =
                                    super::helpers::create_pending_approval_with_context(
                                        &state,
                                        &session_id,
                                        &action,
                                        reason,
                                        containment_context,
                                    )
                                    .await;
                                let denial = make_ws_error_response_with_data(
                                    Some(id),
                                    -32001,
                                    "Approval required",
                                    Some(json!({
                                        "verdict": "require_approval",
                                        "reason": reason,
                                        "approval_id": approval_id,
                                    })),
                                );
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(denial.into())).await;
                            }
                            _ => {
                                let denial =
                                    make_ws_error_response(Some(id), -32001, "Denied by policy");
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(denial.into())).await;
                            }
                        }
                    }
                    MessageType::ExtensionMethod {
                        ref id,
                        ref extension_id,
                        ref method,
                    } => {
                        // Policy-evaluate extension method calls
                        let params = parsed.get("params").cloned().unwrap_or(json!({}));

                        // SECURITY (FIND-R116-001): DLP scan extension method parameters.
                        // Parity with gRPC handle_extension_method (service.rs:1542).
                        let dlp_findings = scan_parameters_for_secrets(&params);
                        if !dlp_findings.is_empty() {
                            for finding in &dlp_findings {
                                record_dlp_finding(&finding.pattern_name);
                            }
                            let patterns: Vec<String> = dlp_findings
                                .iter()
                                .map(|f| format!("{}:{}", f.pattern_name, f.location))
                                .collect();
                            tracing::warn!(
                                "SECURITY: Secrets in WS extension method parameters! Session: {}, Extension: {}:{}, Findings: {:?}",
                                session_id, extension_id, method, patterns,
                            );
                            let action =
                                extractor::extract_extension_action(extension_id, method, &params);
                            let audit_verdict = Verdict::Deny {
                                reason: format!(
                                    "DLP blocked: secret detected in extension parameters: {patterns:?}"
                                ),
                            };
                            let parameter_security_context =
                                super::helpers::parameter_dlp_security_context(
                                    &params,
                                    true,
                                    "extension_parameter_dlp",
                                );
                            let envelope = build_secondary_acis_envelope_with_security_context(
                                &action,
                                &audit_verdict,
                                DecisionOrigin::Dlp,
                                "websocket",
                                Some(&session_id),
                                Some(&parameter_security_context),
                            );
                            if let Err(e) = state.audit.log_entry_with_acis(
                                &action, &audit_verdict,
                                json!({
                                    "source": "ws_proxy", "session": session_id, "transport": "websocket",
                                    "event": "ws_extension_parameter_dlp_alert",
                                    "extension_id": extension_id, "method": method, "findings": patterns,
                                }),
                                envelope,
                            ).await {
                                tracing::warn!("Failed to audit WS extension parameter DLP: {}", e);
                            }
                            let denial =
                                make_ws_error_response(Some(id), -32001, "Denied by policy");
                            let mut sink = client_sink.lock().await;
                            let _ = sink.send(Message::Text(denial.into())).await;
                            continue;
                        }

                        // SECURITY (FIND-R116-001): Memory poisoning detection for extension params.
                        // Parity with gRPC handle_extension_method (service.rs:1574).
                        if let Some(session) = state.sessions.get_mut(&session_id) {
                            let poisoning_matches =
                                session.memory_tracker.check_parameters(&params);
                            if !poisoning_matches.is_empty() {
                                for m in &poisoning_matches {
                                    tracing::warn!(
                                        "SECURITY: Memory poisoning in WS extension '{}:{}' (session {}): \
                                         param '{}' replayed data (fingerprint: {})",
                                        extension_id, method, session_id, m.param_location, m.fingerprint
                                    );
                                }
                                let action = extractor::extract_extension_action(
                                    extension_id,
                                    method,
                                    &params,
                                );
                                let deny_reason = format!(
                                    "Memory poisoning detected: {} replayed data fragment(s) in extension '{}:{}'",
                                    poisoning_matches.len(), extension_id, method
                                );
                                let ext_poison_verdict = Verdict::Deny {
                                    reason: deny_reason.clone(),
                                };
                                let poisoning_security_context =
                                    super::helpers::memory_poisoning_security_context(
                                        &params,
                                        "memory_poisoning",
                                    );
                                let envelope = build_secondary_acis_envelope_with_security_context(
                                    &action,
                                    &ext_poison_verdict,
                                    DecisionOrigin::MemoryPoisoning,
                                    "websocket",
                                    Some(&session_id),
                                    Some(&poisoning_security_context),
                                );
                                if let Err(e) = state.audit.log_entry_with_acis(
                                    &action,
                                    &ext_poison_verdict,
                                    json!({
                                        "source": "ws_proxy", "session": session_id, "transport": "websocket",
                                        "event": "memory_poisoning_detected",
                                        "matches": poisoning_matches.len(),
                                        "extension_id": extension_id, "method": method,
                                    }),
                                    envelope,
                                ).await {
                                    tracing::warn!("Failed to audit WS extension memory poisoning: {}", e);
                                }
                                let denial =
                                    make_ws_error_response(Some(id), -32001, "Denied by policy");
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(denial.into())).await;
                                continue;
                            }
                        }

                        let mut action =
                            extractor::extract_extension_action(extension_id, method, &params);
                        let mut matched_approval_id: Option<String> = None;

                        // SECURITY (FIND-R118-004): DNS resolution for extension methods.
                        // Parity with ToolCall (line 710) and ResourceRead (line 1439).
                        if state.engine.has_ip_rules() {
                            super::helpers::resolve_domains(&mut action).await;
                        }

                        let ext_key = format!("extension:{extension_id}:{method}");

                        // SECURITY (FIND-R130-002): TOCTOU-safe context+eval+update
                        // for extension methods. Matches ToolCall/ResourceRead fixes.

                        // Pre-compute security context BEFORE acquiring DashMap write lock
                        // to avoid deadlock — build_ws_runtime_security_context internally
                        // calls sessions.get()/get_mut() which would re-enter the lock.
                        let pre_eval_ctx = state
                            .sessions
                            .get(&session_id)
                            .map(|session| EvaluationContext {
                                timestamp: None,
                                agent_id: session.oauth_subject.clone(),
                                agent_identity: session.agent_identity.clone(),
                                call_chain: session.current_call_chain.clone(),
                                ..EvaluationContext::default()
                            })
                            .unwrap_or_else(|| EvaluationContext {
                                agent_id: oauth_claims.as_ref().map(|claims| claims.sub.clone()),
                                ..EvaluationContext::default()
                            });
                        let security_context = build_ws_runtime_security_context(
                            &parsed,
                            &action,
                            &handshake_headers,
                            super::helpers::TransportSecurityInputs {
                                oauth_evidence: oauth_claims.as_ref(),
                                eval_ctx: Some(&pre_eval_ctx),
                                sessions: &state.sessions,
                                session_id: Some(&session_id),
                                trusted_request_signers: &state.trusted_request_signers,
                                detached_signature_freshness: state.detached_signature_freshness,
                            },
                        );

                        // TOCTOU-safe evaluation + session update (write lock)
                        let (mediation_result, ctx) = if let Some(mut session) =
                            state.sessions.get_mut(&session_id)
                        {
                            let ctx = EvaluationContext {
                                timestamp: None,
                                agent_id: session.oauth_subject.clone(),
                                agent_identity: session.agent_identity.clone(),
                                call_counts: session.call_counts.clone(),
                                previous_actions: session.action_history.iter().cloned().collect(),
                                call_chain: session.current_call_chain.clone(),
                                tenant_id: None,
                                verification_tier: None,
                                capability_token: None,
                                session_state: None,
                            };
                            let result = mediate_with_security_context(
                                &uuid::Uuid::new_v4().to_string().replace('-', ""),
                                &action,
                                &state.engine,
                                Some(&ctx),
                                security_context.as_ref(),
                                "websocket",
                                &state.mediation_config,
                                Some(&session_id),
                                None,
                            );

                            // Atomically update session on Allow
                            if matches!(result.verdict, Verdict::Allow) {
                                session.touch();
                                use crate::proxy::call_chain::{
                                    MAX_ACTION_HISTORY, MAX_CALL_COUNT_TOOLS,
                                };
                                if session.call_counts.len() < MAX_CALL_COUNT_TOOLS
                                    || session.call_counts.contains_key(&ext_key)
                                {
                                    let count =
                                        session.call_counts.entry(ext_key.clone()).or_insert(0);
                                    *count = count.saturating_add(1);
                                }
                                if session.action_history.len() >= MAX_ACTION_HISTORY {
                                    session.action_history.pop_front();
                                }
                                session.action_history.push_back(ext_key.clone());
                            }

                            (result, ctx)
                        } else {
                            let ctx = EvaluationContext::default();
                            let result = mediate_with_security_context(
                                &uuid::Uuid::new_v4().to_string().replace('-', ""),
                                &action,
                                &state.engine,
                                None,
                                security_context.as_ref(),
                                "websocket",
                                &state.mediation_config,
                                Some(&session_id),
                                None,
                            );
                            (result, ctx)
                        };

                        let mut final_origin = mediation_result.origin;
                        let mut acis_envelope = mediation_result.envelope.clone();
                        let mut refresh_envelope = false;
                        let verdict = match mediation_result.verdict {
                            Verdict::RequireApproval { reason } => {
                                match super::helpers::presented_approval_matches_action(
                                    &state,
                                    &session_id,
                                    presented_approval_id.as_deref(),
                                    &action,
                                )
                                .await
                                {
                                    Ok(Some(approval_id)) => {
                                        matched_approval_id = Some(approval_id);
                                        final_origin = DecisionOrigin::PolicyEngine;
                                        refresh_envelope = true;
                                        Verdict::Allow
                                    }
                                    Ok(None) => Verdict::RequireApproval { reason },
                                    Err(()) => {
                                        final_origin = DecisionOrigin::ApprovalGate;
                                        refresh_envelope = true;
                                        Verdict::Deny {
                                            reason: INVALID_PRESENTED_APPROVAL_REASON.to_string(),
                                        }
                                    }
                                }
                            }
                            other => other,
                        };
                        if refresh_envelope {
                            acis_envelope = refresh_ws_acis_envelope(
                                &acis_envelope,
                                &action,
                                &verdict,
                                final_origin,
                                &session_id,
                                &ctx,
                                security_context.as_ref(),
                            );
                        }

                        match verdict {
                            Verdict::Allow => {
                                // SECURITY (FIND-R118-002): ABAC refinement for extension methods.
                                // Parity with ToolCall (line 1099) and ResourceRead (line 1498).
                                if let Some(ref abac) = state.abac_engine {
                                    let principal_id =
                                        ctx.agent_id.as_deref().unwrap_or("anonymous");
                                    let principal_type = ctx.principal_type();
                                    let session_risk = state
                                        .sessions
                                        .get_mut(&session_id)
                                        .and_then(|s| s.risk_score.clone());
                                    let abac_ctx = vellaveto_engine::abac::AbacEvalContext {
                                        eval_ctx: &ctx,
                                        principal_type,
                                        principal_id,
                                        risk_score: session_risk.as_ref(),
                                    };
                                    match abac.evaluate(&action, &abac_ctx) {
                                        vellaveto_engine::abac::AbacDecision::Deny {
                                            policy_id,
                                            reason,
                                        } => {
                                            let deny_verdict = Verdict::Deny {
                                                reason: reason.clone(),
                                            };
                                            let abac_security_context =
                                                super::helpers::abac_deny_security_context(&action);
                                            let envelope =
                                                build_secondary_acis_envelope_with_security_context(
                                                    &action,
                                                    &deny_verdict,
                                                    DecisionOrigin::PolicyEngine,
                                                    "websocket",
                                                    Some(&session_id),
                                                    Some(&abac_security_context),
                                                );
                                            if let Err(e) = state
                                                .audit
                                                .log_entry_with_acis(
                                                    &action,
                                                    &deny_verdict,
                                                    json!({
                                                        "source": "ws_proxy",
                                                        "session": session_id,
                                                        "transport": "websocket",
                                                        "event": "abac_deny",
                                                        "extension_id": extension_id,
                                                        "abac_policy": policy_id,
                                                    }),
                                                    envelope,
                                                )
                                                .await
                                            {
                                                tracing::warn!(
                                                    "Failed to audit WS extension ABAC deny: {}",
                                                    e
                                                );
                                            }
                                            let error_resp = make_ws_error_response(
                                                Some(id),
                                                -32001,
                                                "Denied by policy",
                                            );
                                            let mut sink = client_sink.lock().await;
                                            let _ =
                                                sink.send(Message::Text(error_resp.into())).await;
                                            continue;
                                        }
                                        vellaveto_engine::abac::AbacDecision::Allow {
                                            policy_id,
                                        } => {
                                            if let Some(ref la) = state.least_agency {
                                                la.record_usage(
                                                    principal_id,
                                                    &session_id,
                                                    &policy_id,
                                                    &ext_key,
                                                    method,
                                                );
                                            }
                                        }
                                        vellaveto_engine::abac::AbacDecision::NoMatch => {
                                            // Fall through — existing Allow stands
                                        }
                                        #[allow(unreachable_patterns)]
                                        // AbacDecision is #[non_exhaustive]
                                        _ => {
                                            // SECURITY: Future variants — fail-closed (deny).
                                            tracing::warn!(
                                                "Unknown AbacDecision variant — fail-closed"
                                            );
                                            let error_resp = make_ws_error_response(
                                                Some(id),
                                                -32001,
                                                "Denied by policy",
                                            );
                                            let mut sink = client_sink.lock().await;
                                            let _ =
                                                sink.send(Message::Text(error_resp.into())).await;
                                            continue;
                                        }
                                    }
                                }

                                // NOTE: Session touch + call_counts/action_history
                                // update already performed inside the TOCTOU-safe
                                // block above (FIND-R130-002). No separate update here.

                                if super::helpers::consume_presented_approval(
                                    &state,
                                    &session_id,
                                    matched_approval_id.as_deref(),
                                    &action,
                                    security_context.as_ref(),
                                )
                                .await
                                .is_err()
                                {
                                    let deny_verdict = Verdict::Deny {
                                        reason: INVALID_PRESENTED_APPROVAL_REASON.to_string(),
                                    };
                                    let invalid_approval_security_context =
                                        super::helpers::invalid_presented_approval_security_context(
                                            &action,
                                        );
                                    let combined_security_context =
                                        super::helpers::merge_transport_security_context(
                                            security_context.as_ref(),
                                            Some(&invalid_approval_security_context),
                                        );
                                    let effective_security_context = combined_security_context
                                        .as_ref()
                                        .unwrap_or(&invalid_approval_security_context);
                                    let envelope =
                                        build_secondary_acis_envelope_with_security_context(
                                            &action,
                                            &deny_verdict,
                                            DecisionOrigin::ApprovalGate,
                                            "websocket",
                                            Some(&session_id),
                                            Some(effective_security_context),
                                        );
                                    // SECURITY (R274-AUDIT-1): the result was bound to `_`, so a failed
                                    // audit write here was invisible. The denial below is unchanged —
                                    // this only makes the lost record observable.
                                    if let Err(e) = state
                                        .audit
                                        .log_entry_with_acis(
                                            &action,
                                            &deny_verdict,
                                            json!({
                                                "source": "ws_proxy",
                                                "session": session_id,
                                                "transport": "websocket",
                                                "event": "presented_approval_replay_denied",
                                                "approval_id": matched_approval_id,
                                                "extension_id": extension_id,
                                                "method": method,
                                            }),
                                            envelope,
                                        )
                                        .await
                                    {
                                        tracing::warn!("Failed to audit denial: {}", e);
                                    }
                                    let error_resp = make_ws_error_response(
                                        Some(id),
                                        -32001,
                                        "Denied by policy",
                                    );
                                    let mut sink = client_sink.lock().await;
                                    let _ = sink.send(Message::Text(error_resp.into())).await;
                                    continue;
                                }

                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &action,
                                        &Verdict::Allow,
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "extension_id": extension_id,
                                        }),
                                        acis_envelope,
                                    )
                                    .await
                                {
                                    tracing::error!(
                                        "AUDIT FAILURE in WS proxy: security decision not recorded: {}",
                                        e
                                    );
                                    // SECURITY (FIND-R215-007): Strict audit mode — fail-closed.
                                    // Parity with Deny and RequireApproval paths.
                                    if state.audit_strict_mode {
                                        let error = make_ws_error_response(
                                            Some(id),
                                            -32000,
                                            "Audit logging failed — request denied (strict audit mode)",
                                        );
                                        let mut sink = client_sink.lock().await;
                                        let _ = sink.send(Message::Text(error.into())).await;
                                        continue;
                                    }
                                }
                                // SECURITY (FIND-R48-001): Fail-closed on canonicalization failure.
                                let forward_text = if state.canonicalize {
                                    match serde_json::to_string(&parsed) {
                                        Ok(canonical) => canonical,
                                        Err(e) => {
                                            tracing::error!("SECURITY: WS extension canonicalization failed: {}", e);
                                            let error_resp = make_ws_error_response(
                                                Some(id),
                                                -32603,
                                                "Internal error",
                                            );
                                            let mut sink = client_sink.lock().await;
                                            let _ =
                                                sink.send(Message::Text(error_resp.into())).await;
                                            continue;
                                        }
                                    }
                                } else {
                                    text.to_string()
                                };
                                if let Err(e) = send_text_to_upstream(
                                    &upstream_sink,
                                    &in_flight_client_requests,
                                    &parsed,
                                    forward_text,
                                )
                                .await
                                {
                                    tracing::error!("Failed to forward extension request: {}", e);
                                    break;
                                }
                            }
                            Verdict::Deny { ref reason } => {
                                let mut audit_metadata = json!({
                                    "source": "ws_proxy",
                                    "session": session_id,
                                    "transport": "websocket",
                                    "extension_id": extension_id,
                                });
                                if reason == INVALID_PRESENTED_APPROVAL_REASON
                                    && presented_approval_id.is_some()
                                {
                                    audit_metadata["event"] =
                                        json!("presented_approval_replay_denied");
                                    audit_metadata["approval_id"] = json!(presented_approval_id);
                                    audit_metadata["method"] = json!(method);
                                }
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &action,
                                        &Verdict::Deny {
                                            reason: reason.clone(),
                                        },
                                        audit_metadata,
                                        acis_envelope,
                                    )
                                    .await
                                {
                                    tracing::error!(
                                        "AUDIT FAILURE in WS proxy: security decision not recorded: {}",
                                        e
                                    );
                                    // SECURITY (FIND-R213-002): Strict audit mode — fail-closed.
                                    if state.audit_strict_mode {
                                        let error = make_ws_error_response(
                                            Some(id),
                                            -32000,
                                            "Audit logging failed — request denied (strict audit mode)",
                                        );
                                        let mut sink = client_sink.lock().await;
                                        let _ = sink.send(Message::Text(error.into())).await;
                                        continue;
                                    }
                                }
                                // SECURITY (FIND-R213-001): Generic denial message — do not leak
                                // detailed policy reason to client. Reason is in the audit log.
                                let _ = reason;
                                let denial =
                                    make_ws_error_response(Some(id), -32001, "Denied by policy");
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(denial.into())).await;
                            }
                            Verdict::RequireApproval { ref reason, .. } => {
                                let approval_verdict = Verdict::RequireApproval {
                                    reason: reason.clone(),
                                };
                                let containment_context =
                                    super::helpers::approval_containment_context_from_envelope(
                                        &acis_envelope,
                                        reason,
                                    );
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &action,
                                        &approval_verdict,
                                        json!({
                                            "source": "ws_proxy",
                                            "session": session_id,
                                            "transport": "websocket",
                                            "extension_id": extension_id,
                                        }),
                                        acis_envelope,
                                    )
                                    .await
                                {
                                    tracing::error!(
                                        "AUDIT FAILURE in WS proxy: security decision not recorded: {}",
                                        e
                                    );
                                    // SECURITY (FIND-R213-002): Strict audit mode — fail-closed.
                                    if state.audit_strict_mode {
                                        let error = make_ws_error_response(
                                            Some(id),
                                            -32000,
                                            "Audit logging failed — request denied (strict audit mode)",
                                        );
                                        let mut sink = client_sink.lock().await;
                                        let _ = sink.send(Message::Text(error.into())).await;
                                        continue;
                                    }
                                }
                                let approval_id =
                                    super::helpers::create_pending_approval_with_context(
                                        &state,
                                        &session_id,
                                        &action,
                                        reason,
                                        containment_context,
                                    )
                                    .await;
                                let denial = make_ws_error_response_with_data(
                                    Some(id),
                                    -32001,
                                    "Approval required",
                                    Some(json!({
                                        "verdict": "require_approval",
                                        "reason": reason,
                                        "approval_id": approval_id,
                                    })),
                                );
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(denial.into())).await;
                            }
                            _ => {
                                let denial =
                                    make_ws_error_response(Some(id), -32001, "Denied by policy");
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(denial.into())).await;
                            }
                        }
                    }
                    MessageType::ElicitationRequest { ref id } => {
                        // SECURITY (FIND-R46-010): Policy checks for elicitation requests.
                        // Match the HTTP POST handler's elicitation inspection logic.
                        let params = parsed.get("params").cloned().unwrap_or(json!({}));
                        let elicitation_verdict = {
                            let mut session_ref = state.sessions.get_mut(&session_id);
                            let current_count = session_ref
                                .as_ref()
                                .map(|s| s.elicitation_count)
                                .unwrap_or(0);
                            let verdict = vellaveto_mcp::elicitation::inspect_elicitation(
                                &params,
                                &state.elicitation_config,
                                current_count,
                            );
                            // Pre-increment while holding the lock to close the TOCTOU gap
                            if matches!(
                                verdict,
                                vellaveto_mcp::elicitation::ElicitationVerdict::Allow
                            ) {
                                if let Some(ref mut s) = session_ref {
                                    // SECURITY (FIND-R51-008): Use saturating_add for consistency.
                                    s.elicitation_count = s.elicitation_count.saturating_add(1);
                                }
                            }
                            verdict
                        };
                        match elicitation_verdict {
                            vellaveto_mcp::elicitation::ElicitationVerdict::Allow => {
                                let action = Action::new(
                                    "vellaveto",
                                    "ws_forward_message",
                                    json!({
                                        "message_type": "elicitation_request",
                                        "session": session_id,
                                        "transport": "websocket",
                                        "direction": "client_to_upstream",
                                    }),
                                );
                                let elicitation_security_context =
                                    super::helpers::protocol_forward_channel_security_context(
                                        "ws_elicitation_forwarded",
                                        vellaveto_types::ContextChannel::ApprovalPrompt,
                                    );
                                let envelope = build_secondary_acis_envelope_with_security_context(
                                    &action,
                                    &Verdict::Allow,
                                    DecisionOrigin::PolicyEngine,
                                    "websocket",
                                    Some(&session_id),
                                    Some(&elicitation_security_context),
                                );
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &action,
                                        &Verdict::Allow,
                                        json!({
                                            "source": "ws_proxy",
                                            "event": "ws_elicitation_forwarded",
                                        }),
                                        envelope,
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit WS elicitation: {}", e);
                                }

                                // SECURITY (FIND-R48-001): Fail-closed on canonicalization failure.
                                let forward_text = if state.canonicalize {
                                    match serde_json::to_string(&parsed) {
                                        Ok(canonical) => canonical,
                                        Err(e) => {
                                            tracing::error!("SECURITY: WS elicitation canonicalization failed: {}", e);
                                            let error_resp = make_ws_error_response(
                                                Some(id),
                                                -32603,
                                                "Internal error",
                                            );
                                            let mut sink = client_sink.lock().await;
                                            let _ =
                                                sink.send(Message::Text(error_resp.into())).await;
                                            continue;
                                        }
                                    }
                                } else {
                                    text.to_string()
                                };
                                if let Err(e) = send_text_to_upstream(
                                    &upstream_sink,
                                    &in_flight_client_requests,
                                    &parsed,
                                    forward_text,
                                )
                                .await
                                {
                                    // Rollback pre-incremented count on forward failure
                                    if let Some(mut s) = state.sessions.get_mut(&session_id) {
                                        s.elicitation_count = s.elicitation_count.saturating_sub(1);
                                    }
                                    tracing::error!("Failed to forward elicitation: {}", e);
                                    break;
                                }
                            }
                            vellaveto_mcp::elicitation::ElicitationVerdict::Deny { reason } => {
                                tracing::warn!(
                                    session_id = %session_id,
                                    "Blocked WS elicitation/create: {}",
                                    reason
                                );
                                let action = Action::new(
                                    "vellaveto",
                                    "ws_elicitation_interception",
                                    json!({
                                        "method": "elicitation/create",
                                        "session": session_id,
                                        "transport": "websocket",
                                        "reason": &reason,
                                    }),
                                );
                                let verdict = Verdict::Deny {
                                    reason: reason.clone(),
                                };
                                let elicitation_security_context =
                                    super::helpers::elicitation_interception_security_context(
                                        &action,
                                    );
                                let envelope = build_secondary_acis_envelope_with_security_context(
                                    &action,
                                    &verdict,
                                    DecisionOrigin::PolicyEngine,
                                    "websocket",
                                    Some(&session_id),
                                    Some(&elicitation_security_context),
                                );
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &action,
                                        &verdict,
                                        json!({
                                            "source": "ws_proxy",
                                            "event": "ws_elicitation_interception",
                                        }),
                                        envelope,
                                    )
                                    .await
                                {
                                    tracing::warn!(
                                        "Failed to audit WS elicitation interception: {}",
                                        e
                                    );
                                }
                                // SECURITY (FIND-R46-012, FIND-R55-WS-006): Generic message to client.
                                let error =
                                    make_ws_error_response(Some(id), -32001, "Denied by policy");
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                            }
                        }
                    }
                    MessageType::PassThrough | MessageType::ProgressNotification { .. } => {
                        // SECURITY (FIND-R76-003): DLP scan PassThrough params for secrets.
                        // Parity with HTTP handler (handlers.rs:1795-1859). Agents could
                        // exfiltrate secrets via prompts/get, completion/complete, or any
                        // PassThrough method's parameters.
                        // SECURITY (FIND-R97-001): Remove method gate — JSON-RPC responses
                        // (sampling/elicitation replies) have no `method` field but carry
                        // data in `result`. Parity with stdio proxy FIND-R96-001.
                        if state.response_dlp_enabled {
                            let mut dlp_findings = scan_notification_for_secrets(&parsed);
                            // SECURITY (FIND-R97-001): Also scan `result` field for responses.
                            if let Some(result_val) = parsed.get("result") {
                                dlp_findings.extend(scan_parameters_for_secrets(result_val));
                            }
                            // SECURITY (FIND-R83-006): Cap combined findings from params+result
                            // scans to maintain per-scan invariant (1000).
                            dlp_findings.truncate(1000);
                            if !dlp_findings.is_empty() {
                                for finding in &dlp_findings {
                                    record_dlp_finding(&finding.pattern_name);
                                }
                                let patterns: Vec<String> = dlp_findings
                                    .iter()
                                    .map(|f| format!("{}:{}", f.pattern_name, f.location))
                                    .collect();
                                tracing::warn!(
                                    "SECURITY: Secrets in WS passthrough params! Session: {}, Findings: {:?}",
                                    session_id,
                                    patterns
                                );
                                let n_action = Action::new(
                                    "vellaveto",
                                    "notification_dlp_scan",
                                    json!({
                                        "findings": patterns,
                                        "session": session_id,
                                        "transport": "websocket",
                                    }),
                                );
                                let verdict = if state.response_dlp_blocking {
                                    Verdict::Deny {
                                        reason: format!(
                                            "Notification blocked: secrets detected ({patterns:?})"
                                        ),
                                    }
                                } else {
                                    Verdict::Allow
                                };
                                let notification_security_context =
                                    super::helpers::notification_dlp_security_context(
                                        &parsed,
                                        state.response_dlp_blocking,
                                    );
                                let envelope = build_secondary_acis_envelope_with_security_context(
                                    &n_action,
                                    &verdict,
                                    DecisionOrigin::Dlp,
                                    "websocket",
                                    Some(&session_id),
                                    Some(&notification_security_context),
                                );
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &n_action,
                                        &verdict,
                                        json!({
                                            "source": "ws_proxy",
                                            "event": "notification_dlp_alert",
                                            "blocked": state.response_dlp_blocking,
                                        }),
                                        envelope,
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit WS passthrough DLP: {}", e);
                                }
                                if state.response_dlp_blocking {
                                    // Drop the message silently (passthrough has no id to respond to)
                                    continue;
                                }
                            }
                        }

                        // SECURITY (FIND-R130-001): Injection scanning on PassThrough parameters.
                        // Parity with HTTP handler (handlers.rs FIND-R112-008) and gRPC handler
                        // (service.rs FIND-R113-001). An agent could inject prompt injection
                        // payloads via any PassThrough method's parameters.
                        if !state.injection_disabled {
                            let mut inj_parts = Vec::new();
                            if let Some(params) = parsed.get("params") {
                                extract_strings_recursive(params, &mut inj_parts, 0);
                            }
                            if let Some(result) = parsed.get("result") {
                                extract_strings_recursive(result, &mut inj_parts, 0);
                            }
                            let scannable = inj_parts.join("\n");
                            if !scannable.is_empty() {
                                let injection_matches: Vec<String> =
                                    if let Some(ref scanner) = state.injection_scanner {
                                        scanner
                                            .inspect(&scannable)
                                            .into_iter()
                                            .map(|s| s.to_string())
                                            .collect()
                                    } else {
                                        inspect_for_injection(&scannable)
                                            .into_iter()
                                            .map(|s| s.to_string())
                                            .collect()
                                    };

                                if !injection_matches.is_empty() {
                                    tracing::warn!(
                                        "SECURITY: Injection in WS passthrough params! \
                                         Session: {}, Patterns: {:?}",
                                        session_id,
                                        injection_matches,
                                    );

                                    let verdict = if state.injection_blocking {
                                        Verdict::Deny {
                                            reason: format!(
                                                "WS passthrough injection blocked: {injection_matches:?}"
                                            ),
                                        }
                                    } else {
                                        Verdict::Allow
                                    };

                                    let inj_action = Action::new(
                                        "vellaveto",
                                        "ws_passthrough_injection_scan",
                                        json!({
                                            "matched_patterns": injection_matches,
                                            "session": session_id,
                                            "transport": "websocket",
                                            "direction": "client_to_upstream",
                                        }),
                                    );
                                    let injection_security_context =
                                        super::helpers::notification_injection_security_context(
                                            &parsed,
                                            state.injection_blocking,
                                            "passthrough_injection",
                                        );
                                    let envelope =
                                        build_secondary_acis_envelope_with_security_context(
                                            &inj_action,
                                            &verdict,
                                            DecisionOrigin::InjectionScanner,
                                            "websocket",
                                            Some(&session_id),
                                            Some(&injection_security_context),
                                        );
                                    if let Err(e) = state
                                        .audit
                                        .log_entry_with_acis(
                                            &inj_action,
                                            &verdict,
                                            json!({
                                                "source": "ws_proxy",
                                                "event": "ws_passthrough_injection_detected",
                                                "blocking": state.injection_blocking,
                                            }),
                                            envelope,
                                        )
                                        .await
                                    {
                                        tracing::warn!(
                                            "Failed to audit WS passthrough injection: {}",
                                            e
                                        );
                                    }

                                    if state.injection_blocking {
                                        // Drop the message (passthrough has no id to respond to)
                                        continue;
                                    }
                                }
                            }
                        }

                        // SECURITY (IMP-R182-009): Memory poisoning check — parity with
                        // tool calls, resource reads, tasks, and extension methods.
                        if let Some(mut session) = state.sessions.get_mut(&session_id) {
                            let params_to_scan = parsed.get("params").cloned().unwrap_or(json!({}));
                            // SECURITY (IMP-R184-010): Also scan `result` field — parity
                            // with DLP scan which scans both params and result.
                            let mut poisoning_matches =
                                session.memory_tracker.check_parameters(&params_to_scan);
                            if let Some(result_val) = parsed.get("result") {
                                poisoning_matches
                                    .extend(session.memory_tracker.check_parameters(result_val));
                            }
                            if !poisoning_matches.is_empty() {
                                let method_name = parsed
                                    .get("method")
                                    .and_then(|m| m.as_str())
                                    .unwrap_or("unknown");
                                for m in &poisoning_matches {
                                    tracing::warn!(
                                        "SECURITY: Memory poisoning in WS passthrough '{}' (session {}): \
                                         param '{}' replayed data (fingerprint: {})",
                                        method_name,
                                        session_id,
                                        m.param_location,
                                        m.fingerprint
                                    );
                                }
                                let poison_action = Action::new(
                                    "vellaveto",
                                    "ws_passthrough_memory_poisoning",
                                    json!({
                                        "method": method_name,
                                        "session": session_id,
                                        "matches": poisoning_matches.len(),
                                        "transport": "websocket",
                                    }),
                                );
                                let passthrough_poison_verdict = Verdict::Deny {
                                    reason: format!(
                                        "WS passthrough blocked: memory poisoning ({} matches)",
                                        poisoning_matches.len()
                                    ),
                                };
                                let poisoning_security_context =
                                    super::helpers::notification_memory_poisoning_security_context(
                                        &parsed,
                                        "memory_poisoning",
                                    );
                                let envelope = build_secondary_acis_envelope_with_security_context(
                                    &poison_action,
                                    &passthrough_poison_verdict,
                                    DecisionOrigin::MemoryPoisoning,
                                    "websocket",
                                    Some(&session_id),
                                    Some(&poisoning_security_context),
                                );
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &poison_action,
                                        &passthrough_poison_verdict,
                                        json!({
                                            "source": "ws_proxy",
                                            "event": "ws_passthrough_memory_poisoning",
                                        }),
                                        envelope,
                                    )
                                    .await
                                {
                                    tracing::warn!(
                                        "Failed to audit WS passthrough memory poisoning: {}",
                                        e
                                    );
                                }
                                continue; // Drop the message
                            }
                            // Fingerprint for future poisoning detection.
                            session.memory_tracker.extract_from_value(&params_to_scan);
                            if let Some(result_val) = parsed.get("result") {
                                session.memory_tracker.extract_from_value(result_val);
                            }
                        } else {
                            // IMP-R186-005: Log when session is missing so the skip is observable.
                            tracing::warn!(
                                "Session {} not found for WS passthrough memory poisoning check",
                                session_id
                            );
                        }

                        // SECURITY (FIND-R46-WS-004): Audit log forwarded passthrough/notification messages
                        let msg_type = match &classified {
                            MessageType::ProgressNotification { .. } => "progress_notification",
                            _ => "passthrough",
                        };
                        let action = Action::new(
                            "vellaveto",
                            "ws_forward_message",
                            json!({
                                "message_type": msg_type,
                                "session": session_id,
                                "transport": "websocket",
                                "direction": "client_to_upstream",
                            }),
                        );
                        let protocol_security_context =
                            super::helpers::protocol_forward_security_context(
                                "ws_message_forwarded",
                            );
                        let envelope = build_secondary_acis_envelope_with_security_context(
                            &action,
                            &Verdict::Allow,
                            DecisionOrigin::PolicyEngine,
                            "websocket",
                            Some(&session_id),
                            Some(&protocol_security_context),
                        );
                        if let Err(e) = state
                            .audit
                            .log_entry_with_acis(
                                &action,
                                &Verdict::Allow,
                                json!({
                                    "source": "ws_proxy",
                                    "event": "ws_message_forwarded",
                                }),
                                envelope,
                            )
                            .await
                        {
                            tracing::warn!("Failed to audit WS passthrough: {}", e);
                        }

                        // SECURITY (FIND-R48-001): Fail-closed on canonicalization failure.
                        let forward_text = if state.canonicalize {
                            match serde_json::to_string(&parsed) {
                                Ok(canonical) => canonical,
                                Err(e) => {
                                    tracing::error!(
                                        "SECURITY: WS passthrough canonicalization failed: {}",
                                        e
                                    );
                                    continue;
                                }
                            }
                        } else {
                            text.to_string()
                        };
                        if let Err(e) = send_text_to_upstream(
                            &upstream_sink,
                            &in_flight_client_requests,
                            &parsed,
                            forward_text,
                        )
                        .await
                        {
                            tracing::error!("Failed to forward passthrough: {}", e);
                            break;
                        }
                    }
                }
            }
            Message::Binary(_data) => {
                // SECURITY: Binary frames not allowed for JSON-RPC
                tracing::warn!(
                    session_id = %session_id,
                    "Binary WebSocket frame rejected (JSON-RPC is text-only)"
                );

                // SECURITY (FIND-R46-WS-004): Audit log binary frame rejection
                let action = Action::new(
                    "vellaveto",
                    "ws_binary_frame_rejected",
                    json!({
                        "session": session_id,
                        "transport": "websocket",
                        "direction": "client_to_upstream",
                    }),
                );
                let binary_verdict = Verdict::Deny {
                    reason: "Binary frames not supported for JSON-RPC".to_string(),
                };
                let binary_security_context =
                    super::helpers::protocol_binary_rejection_security_context(
                        "ws_binary_frame_rejected",
                    );
                let envelope = build_secondary_acis_envelope_with_security_context(
                    &action,
                    &binary_verdict,
                    DecisionOrigin::PolicyEngine,
                    "websocket",
                    Some(&session_id),
                    Some(&binary_security_context),
                );
                if let Err(e) = state
                    .audit
                    .log_entry_with_acis(
                        &action,
                        &binary_verdict,
                        json!({
                            "source": "ws_proxy",
                            "event": "ws_binary_frame_rejected",
                        }),
                        envelope,
                    )
                    .await
                {
                    tracing::warn!("Failed to audit WS binary frame rejection: {}", e);
                }

                let mut sink = client_sink.lock().await;
                let _ = sink
                    .send(Message::Close(Some(CloseFrame {
                        code: CLOSE_UNSUPPORTED_DATA,
                        reason: "Binary frames not supported".into(),
                    })))
                    .await;
                break;
            }
            Message::Ping(data) => {
                let mut sink = client_sink.lock().await;
                let _ = sink.send(Message::Pong(data)).await;
            }
            Message::Pong(_) => {
                // Ignored
            }
            Message::Close(_) => {
                tracing::debug!(session_id = %session_id, "Client sent close frame");
                break;
            }
        }
    }
}

/// Relay messages from upstream to client with DLP and injection scanning.
#[allow(clippy::too_many_arguments)]
async fn relay_upstream_to_client(
    mut upstream_stream: futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    client_sink: Arc<Mutex<futures_util::stream::SplitSink<WebSocket, Message>>>,
    upstream_sink: Arc<Mutex<UpstreamWsSink>>,
    state: ProxyState,
    session_id: String,
    ws_config: WebSocketConfig,
    upstream_rate_counter: Arc<AtomicU64>,
    upstream_rate_window_start: Arc<std::sync::Mutex<std::time::Instant>>,
    in_flight_client_requests: Arc<AtomicU64>,
    last_activity: Arc<AtomicU64>,
    connection_epoch: std::time::Instant,
) {
    while let Some(msg_result) = upstream_stream.next().await {
        let msg = match msg_result {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!(session_id = %session_id, "Upstream WS error: {}", e);
                break;
            }
        };

        // SECURITY (FIND-R182-001): Update last-activity for true idle detection.
        // SECURITY (R251-WS-1): SeqCst ensures visibility to timeout checker thread.
        last_activity.store(
            u64::try_from(connection_epoch.elapsed().as_millis()).unwrap_or(u64::MAX),
            Ordering::SeqCst,
        );

        record_ws_message("upstream_to_client");

        // SECURITY (FIND-R46-WS-003): Rate limiting on upstream→client direction.
        // A malicious or compromised upstream could flood the client with messages.
        if !check_rate_limit(
            &upstream_rate_counter,
            &upstream_rate_window_start,
            ws_config.upstream_rate_limit,
        ) {
            tracing::warn!(
                session_id = %session_id,
                "WebSocket upstream rate limit exceeded ({}/s), dropping message",
                ws_config.upstream_rate_limit,
            );

            let action = Action::new(
                "vellaveto",
                "ws_upstream_rate_limit",
                json!({
                    "session": session_id,
                    "transport": "websocket",
                    "direction": "upstream_to_client",
                    "limit": ws_config.upstream_rate_limit,
                }),
            );
            let rate_verdict = Verdict::Deny {
                reason: "Upstream rate limit exceeded".to_string(),
            };
            let rate_limit_security_context =
                super::helpers::protocol_rate_limit_security_context("ws_upstream_rate_limit");
            let envelope = build_secondary_acis_envelope_with_security_context(
                &action,
                &rate_verdict,
                DecisionOrigin::RateLimiter,
                "websocket",
                Some(&session_id),
                Some(&rate_limit_security_context),
            );
            if let Err(e) = state
                .audit
                .log_entry_with_acis(
                    &action,
                    &rate_verdict,
                    json!({
                        "source": "ws_proxy",
                        "event": "ws_upstream_rate_limit_exceeded",
                    }),
                    envelope,
                )
                .await
            {
                tracing::warn!("Failed to audit WS upstream rate limit: {}", e);
            }

            metrics::counter!(
                "vellaveto_ws_upstream_rate_limited_total",
                "session" => session_id.clone()
            )
            .increment(1);

            // Drop the message (don't close the connection — upstream flood should not
            // disconnect the client, just throttle the flow)
            continue;
        }

        match msg {
            tokio_tungstenite::tungstenite::Message::Text(text) => {
                // Try to parse for scanning
                let forward = if let Ok(json_val) = serde_json::from_str::<Value>(&text) {
                    if server_request::is_json_rpc_response(&json_val) {
                        decrement_ws_in_flight(&in_flight_client_requests);
                    }

                    if let Some(info) = server_request::json_rpc_request_info(&json_val) {
                        if in_flight_client_requests.load(Ordering::SeqCst) == 0 {
                            tracing::warn!(
                                session_id = %session_id,
                                method = %info.method,
                                "SECURITY: Blocking unsolicited upstream WebSocket server request"
                            );
                            server_request::audit_unsolicited_server_request(
                                &state,
                                &session_id,
                                "websocket",
                                &info.method,
                                "ws_proxy",
                            )
                            .await;
                            let error = make_ws_error_response(
                                Some(&info.id),
                                -32001,
                                "Unsolicited server request",
                            );
                            let mut sink = upstream_sink.lock().await;
                            let _ = sink
                                .send(tokio_tungstenite::tungstenite::Message::Text(error.into()))
                                .await;
                            continue;
                        }
                    }

                    // Resolve tracked tool context for response-side schema checks.
                    let tracked_tool_name =
                        take_tracked_tool_call(&state.sessions, &session_id, json_val.get("id"));

                    // SECURITY (FIND-R75-003): Track whether DLP or injection was detected
                    // (even in log-only mode) to gate memory_tracker.record_response().
                    // Recording fingerprints from tainted responses would poison the tracker.
                    let mut dlp_found = false;
                    let mut injection_found = false;

                    // DLP scanning on responses
                    if state.response_dlp_enabled {
                        let dlp_findings = scan_response_for_secrets(&json_val);
                        if !dlp_findings.is_empty() {
                            dlp_found = true;
                            for finding in &dlp_findings {
                                record_dlp_finding(&finding.pattern_name);
                            }

                            let patterns: Vec<String> = dlp_findings
                                .iter()
                                .map(|f| format!("{}:{}", f.pattern_name, f.location))
                                .collect();

                            tracing::warn!(
                                "SECURITY: Secrets in WS response! Session: {}, Findings: {:?}",
                                session_id,
                                patterns,
                            );

                            let verdict = if state.response_dlp_blocking {
                                Verdict::Deny {
                                    reason: format!("WS response DLP blocked: {patterns:?}"),
                                }
                            } else {
                                Verdict::Allow
                            };

                            let action = Action::new(
                                "vellaveto",
                                "ws_response_dlp_scan",
                                json!({
                                    "findings": patterns,
                                    "session": session_id,
                                    "transport": "websocket",
                                }),
                            );
                            let dlp_security_context =
                                super::helpers::response_dlp_security_context(
                                    tracked_tool_name.as_deref(),
                                    &json_val,
                                    state.response_dlp_blocking,
                                );
                            let envelope = build_secondary_acis_envelope_with_security_context(
                                &action,
                                &verdict,
                                DecisionOrigin::Dlp,
                                "websocket",
                                Some(&session_id),
                                Some(&dlp_security_context),
                            );
                            if let Err(e) = state
                                .audit
                                .log_entry_with_acis(
                                    &action,
                                    &verdict,
                                    json!({
                                        "source": "ws_proxy",
                                        "event": "ws_response_dlp_alert",
                                    }),
                                    envelope,
                                )
                                .await
                            {
                                tracing::warn!("Failed to audit WS DLP: {}", e);
                            }

                            if state.response_dlp_blocking {
                                // Send error response instead
                                let id = json_val.get("id");
                                let error = make_ws_error_response(
                                    id,
                                    -32001,
                                    "Response blocked by DLP policy",
                                );
                                let mut sink = client_sink.lock().await;
                                let _ = sink.send(Message::Text(error.into())).await;
                                continue;
                            }
                        }
                    }

                    // Injection scanning
                    if !state.injection_disabled {
                        let text_to_scan = extract_scannable_text(&json_val);
                        if !text_to_scan.is_empty() {
                            let injection_matches: Vec<String> =
                                if let Some(ref scanner) = state.injection_scanner {
                                    scanner
                                        .inspect(&text_to_scan)
                                        .into_iter()
                                        .map(|s| s.to_string())
                                        .collect()
                                } else {
                                    inspect_for_injection(&text_to_scan)
                                        .into_iter()
                                        .map(|s| s.to_string())
                                        .collect()
                                };

                            if !injection_matches.is_empty() {
                                injection_found = true;
                                tracing::warn!(
                                    "SECURITY: Injection in WS response! Session: {}, Patterns: {:?}",
                                    session_id,
                                    injection_matches,
                                );

                                let verdict = if state.injection_blocking {
                                    Verdict::Deny {
                                        reason: format!(
                                            "WS response injection blocked: {injection_matches:?}"
                                        ),
                                    }
                                } else {
                                    Verdict::Allow
                                };

                                let action = Action::new(
                                    "vellaveto",
                                    "ws_response_injection",
                                    json!({
                                        "matched_patterns": injection_matches,
                                        "session": session_id,
                                        "transport": "websocket",
                                    }),
                                );
                                let injection_security_context =
                                    super::helpers::response_injection_security_context(
                                        tracked_tool_name.as_deref(),
                                        &json_val,
                                        state.injection_blocking,
                                        "response_injection",
                                    );
                                let envelope = build_secondary_acis_envelope_with_security_context(
                                    &action,
                                    &verdict,
                                    DecisionOrigin::InjectionScanner,
                                    "websocket",
                                    Some(&session_id),
                                    Some(&injection_security_context),
                                );
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &action,
                                        &verdict,
                                        json!({
                                            "source": "ws_proxy",
                                            "event": "ws_injection_detected",
                                        }),
                                        envelope,
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit WS injection: {}", e);
                                }

                                if state.injection_blocking {
                                    let id = json_val.get("id");
                                    let error = make_ws_error_response(
                                        id,
                                        -32001,
                                        "Response blocked: injection detected",
                                    );
                                    let mut sink = client_sink.lock().await;
                                    let _ = sink.send(Message::Text(error.into())).await;
                                    continue;
                                }
                            }
                        }
                    }

                    // SECURITY (FIND-R46-007): Rug-pull detection on tools/list responses.
                    // Check if this is a response to a tools/list request and extract
                    // annotations for rug-pull detection.
                    if json_val.get("result").is_some() {
                        // Check if result contains "tools" array (tools/list response)
                        if json_val
                            .get("result")
                            .and_then(|r| r.get("tools"))
                            .and_then(|t| t.as_array())
                            .is_some()
                        {
                            super::helpers::extract_annotations_from_response(
                                &json_val,
                                &session_id,
                                &state.sessions,
                                &state.audit,
                                &state.known_tools,
                            )
                            .await;

                            // Verify manifest if configured
                            if let Some(ref manifest_config) = state.manifest_config {
                                super::helpers::verify_manifest_from_response(
                                    &json_val,
                                    &session_id,
                                    &state.sessions,
                                    manifest_config,
                                    &state.audit,
                                )
                                .await;
                            }

                            // SECURITY (FIND-R130-003): Scan tool descriptions for embedded
                            // injection. Parity with HTTP upstream handler (upstream.rs:648-698).
                            if !state.injection_disabled {
                                let desc_findings =
                                    if let Some(ref scanner) = state.injection_scanner {
                                        scan_tool_descriptions_with_scanner(&json_val, scanner)
                                    } else {
                                        scan_tool_descriptions(&json_val)
                                    };
                                for finding in &desc_findings {
                                    injection_found = true;
                                    tracing::warn!(
                                        "SECURITY: Injection in tool '{}' description! \
                                         Session: {}, Patterns: {:?}",
                                        finding.tool_name,
                                        session_id,
                                        finding.matched_patterns
                                    );
                                    let action = Action::new(
                                        "vellaveto",
                                        "tool_description_injection",
                                        json!({
                                            "tool": finding.tool_name,
                                            "matched_patterns": finding.matched_patterns,
                                            "session": session_id,
                                            "transport": "websocket",
                                            "blocking": state.injection_blocking,
                                        }),
                                    );
                                    let tool_desc_verdict = Verdict::Deny {
                                        reason: format!(
                                            "Tool '{}' description contains injection: {:?}",
                                            finding.tool_name, finding.matched_patterns
                                        ),
                                    };
                                    let desc_security_context =
                                        super::helpers::tool_discovery_integrity_security_context(
                                            &finding.tool_name,
                                            vellaveto_types::ContextChannel::CommandLike,
                                            "tool_description_injection",
                                            true,
                                        );
                                    let envelope =
                                        build_secondary_acis_envelope_with_security_context(
                                            &action,
                                            &tool_desc_verdict,
                                            DecisionOrigin::InjectionScanner,
                                            "websocket",
                                            Some(&session_id),
                                            Some(&desc_security_context),
                                        );
                                    if let Err(e) = state
                                        .audit
                                        .log_entry_with_acis(
                                            &action,
                                            &tool_desc_verdict,
                                            json!({
                                                "source": "ws_proxy",
                                                "event": "tool_description_injection",
                                            }),
                                            envelope,
                                        )
                                        .await
                                    {
                                        tracing::warn!(
                                            "Failed to audit WS tool description injection: {}",
                                            e
                                        );
                                    }
                                }
                                if !desc_findings.is_empty() && state.injection_blocking {
                                    let id = json_val.get("id");
                                    let error = make_ws_error_response(
                                        id,
                                        -32001,
                                        "Response blocked: suspicious content in tool descriptions",
                                    );
                                    let mut sink = client_sink.lock().await;
                                    let _ = sink.send(Message::Text(error.into())).await;
                                    continue;
                                }
                            }
                        }
                    }

                    // SECURITY: Enforce output schema on WS structuredContent.
                    // SECURITY (FIND-R154-004): Track schema violations for the
                    // record_response guard below, even in non-blocking mode.
                    let schema_violation_found = validate_ws_structured_content_response(
                        &json_val,
                        &state,
                        &session_id,
                        tracked_tool_name.as_deref(),
                    )
                    .await;
                    if schema_violation_found {
                        let id = json_val.get("id");
                        let error = make_ws_error_response(
                            id,
                            -32001,
                            "Response blocked: output schema validation failed",
                        );
                        let mut sink = client_sink.lock().await;
                        let _ = sink.send(Message::Text(error.into())).await;
                        continue;
                    }

                    // SECURITY (FIND-R75-003, FIND-R154-004): Record response
                    // fingerprints for memory poisoning detection. Skip recording
                    // when DLP, injection, or schema violation was detected (even
                    // in log-only mode) to avoid poisoning the tracker with tainted
                    // data. Parity with stdio relay (relay.rs:2919).
                    if !dlp_found && !injection_found && !schema_violation_found {
                        if let Some(mut session) = state.sessions.get_mut(&session_id) {
                            session.memory_tracker.record_response(&json_val);
                        }
                    }

                    // SECURITY (FIND-R46-WS-004): Audit log forwarded upstream→client text messages
                    {
                        let msg_type = if json_val.get("result").is_some() {
                            "response"
                        } else if json_val.get("error").is_some() {
                            "error_response"
                        } else if json_val.get("method").is_some() {
                            "notification"
                        } else {
                            "unknown"
                        };
                        let action = Action::new(
                            "vellaveto",
                            "ws_forward_upstream_message",
                            json!({
                                "message_type": msg_type,
                                "session": session_id,
                                "transport": "websocket",
                                "direction": "upstream_to_client",
                            }),
                        );
                        let message_security_context =
                            super::helpers::protocol_message_forward_security_context(
                                &json_val,
                                "ws_upstream_message_forwarded",
                            );
                        let envelope = build_secondary_acis_envelope_with_security_context(
                            &action,
                            &Verdict::Allow,
                            DecisionOrigin::PolicyEngine,
                            "websocket",
                            Some(&session_id),
                            Some(&message_security_context),
                        );
                        if let Err(e) = state
                            .audit
                            .log_entry_with_acis(
                                &action,
                                &Verdict::Allow,
                                json!({
                                    "source": "ws_proxy",
                                    "event": "ws_upstream_message_forwarded",
                                }),
                                envelope,
                            )
                            .await
                        {
                            tracing::warn!("Failed to audit WS upstream message forward: {}", e);
                        }
                    }

                    // SECURITY (FIND-R48-001): Fail-closed on canonicalization failure.
                    if state.canonicalize {
                        match serde_json::to_string(&json_val) {
                            Ok(canonical) => canonical,
                            Err(e) => {
                                tracing::error!(
                                    "SECURITY: WS response canonicalization failed: {}",
                                    e
                                );
                                continue;
                            }
                        }
                    } else {
                        text.to_string()
                    }
                } else {
                    // SECURITY (FIND-R166-001): Non-JSON upstream text must still be
                    // scanned for DLP/injection before forwarding. A malicious upstream
                    // could exfiltrate secrets or inject payloads via non-JSON frames.
                    let text_str: &str = &text;
                    // SECURITY (FIND-R168-001): DLP scan with audit logging parity.
                    if state.response_dlp_enabled {
                        let findings = scan_text_for_secrets(text_str, "ws.upstream.non_json_text");
                        if !findings.is_empty() {
                            let patterns: Vec<String> = findings
                                .iter()
                                .map(|f| format!("{}:{}", f.pattern_name, f.location))
                                .collect();
                            tracing::warn!(
                                session_id = %session_id,
                                "DLP: non-JSON upstream text contains sensitive data ({} findings)",
                                findings.len(),
                            );
                            let verdict = if state.response_dlp_blocking {
                                Verdict::Deny {
                                    reason: format!("WS non-JSON DLP: {patterns:?}"),
                                }
                            } else {
                                Verdict::Allow
                            };
                            let action = Action::new(
                                "vellaveto",
                                "ws_nonjson_dlp_scan",
                                json!({ "findings": patterns, "session": session_id, "transport": "websocket" }),
                            );
                            // SECURITY (SE-004): Log audit failures instead of silently discarding.
                            let text_security_context = super::helpers::text_dlp_security_context(
                                text_str,
                                state.response_dlp_blocking,
                                "ws_nonjson_dlp",
                            );
                            let envelope = build_secondary_acis_envelope_with_security_context(
                                &action,
                                &verdict,
                                DecisionOrigin::Dlp,
                                "websocket",
                                Some(&session_id),
                                Some(&text_security_context),
                            );
                            if let Err(e) = state.audit.log_entry_with_acis(
                                &action, &verdict,
                                json!({ "source": "ws_proxy", "event": "ws_nonjson_dlp_alert" }),
                                envelope,
                            ).await {
                                tracing::error!(
                                    session_id = %session_id,
                                    error = %e,
                                    "AUDIT FAILURE: failed to log ws_nonjson_dlp_alert"
                                );
                            }
                            if state.response_dlp_blocking {
                                continue;
                            }
                        }
                    }
                    // SECURITY (FIND-R168-002): Injection scan with log-only mode
                    // parity. Always log detections; only block when injection_blocking.
                    {
                        let alerts: Vec<String> = if let Some(ref scanner) = state.injection_scanner
                        {
                            scanner
                                .inspect(text_str)
                                .into_iter()
                                .map(|s| s.to_string())
                                .collect()
                        } else {
                            inspect_for_injection(text_str)
                                .into_iter()
                                .map(|s| s.to_string())
                                .collect()
                        };
                        if !alerts.is_empty() {
                            tracing::warn!(
                                session_id = %session_id,
                                "Injection: non-JSON upstream text ({} alerts), blocking={}",
                                alerts.len(), state.injection_blocking,
                            );
                            let verdict = if state.injection_blocking {
                                Verdict::Deny {
                                    reason: format!(
                                        "WS non-JSON injection: {} alerts",
                                        alerts.len()
                                    ),
                                }
                            } else {
                                Verdict::Allow
                            };
                            let action = Action::new(
                                "vellaveto",
                                "ws_nonjson_injection_scan",
                                json!({ "alerts": alerts.len(), "session": session_id, "transport": "websocket" }),
                            );
                            // SECURITY (SE-004): Log audit failures instead of silently discarding.
                            let text_security_context =
                                super::helpers::text_injection_security_context(
                                    text_str,
                                    state.injection_blocking,
                                    "ws_nonjson_injection",
                                );
                            let envelope = build_secondary_acis_envelope_with_security_context(
                                &action,
                                &verdict,
                                DecisionOrigin::InjectionScanner,
                                "websocket",
                                Some(&session_id),
                                Some(&text_security_context),
                            );
                            if let Err(e) = state.audit.log_entry_with_acis(
                                &action, &verdict,
                                json!({ "source": "ws_proxy", "event": "ws_nonjson_injection_alert" }),
                                envelope,
                            ).await {
                                tracing::error!(
                                    session_id = %session_id,
                                    error = %e,
                                    "AUDIT FAILURE: failed to log ws_nonjson_injection_alert"
                                );
                            }
                            if state.injection_blocking {
                                continue;
                            }
                        }
                    }
                    text.to_string()
                };

                let mut sink = client_sink.lock().await;
                if let Err(e) = sink.send(Message::Text(forward.into())).await {
                    tracing::debug!("Failed to send to client: {}", e);
                    break;
                }
            }
            tokio_tungstenite::tungstenite::Message::Binary(data) => {
                // SECURITY (FIND-R46-WS-002): DLP scanning on upstream binary frames.
                // Binary from upstream is unusual for JSON-RPC but must be scanned
                // before being dropped, to detect and audit secret exfiltration attempts
                // via binary frames.
                tracing::warn!(
                    session_id = %session_id,
                    "Unexpected binary frame from upstream ({} bytes), scanning before drop",
                    data.len(),
                );

                // DLP scan the binary data as UTF-8 lossy
                if state.response_dlp_enabled {
                    let text_repr = String::from_utf8_lossy(&data);
                    if !text_repr.is_empty() {
                        let dlp_findings = scan_text_for_secrets(&text_repr, "ws_binary_frame");
                        if !dlp_findings.is_empty() {
                            for finding in &dlp_findings {
                                record_dlp_finding(&finding.pattern_name);
                            }
                            let patterns: Vec<String> = dlp_findings
                                .iter()
                                .map(|f| format!("{}:{}", f.pattern_name, f.location))
                                .collect();

                            tracing::warn!(
                                "SECURITY: Secrets in WS upstream binary frame! Session: {}, Findings: {:?}",
                                session_id,
                                patterns,
                            );

                            let action = Action::new(
                                "vellaveto",
                                "ws_binary_dlp_scan",
                                json!({
                                    "findings": patterns,
                                    "session": session_id,
                                    "transport": "websocket",
                                    "direction": "upstream_to_client",
                                    "binary_size": data.len(),
                                }),
                            );
                            let binary_dlp_verdict = Verdict::Deny {
                                reason: format!("WS binary frame DLP: {patterns:?}"),
                            };
                            let text_security_context = super::helpers::text_dlp_security_context(
                                &text_repr,
                                true,
                                "ws_binary_dlp",
                            );
                            let envelope = build_secondary_acis_envelope_with_security_context(
                                &action,
                                &binary_dlp_verdict,
                                DecisionOrigin::Dlp,
                                "websocket",
                                Some(&session_id),
                                Some(&text_security_context),
                            );
                            if let Err(e) = state
                                .audit
                                .log_entry_with_acis(
                                    &action,
                                    &binary_dlp_verdict,
                                    json!({
                                        "source": "ws_proxy",
                                        "event": "ws_binary_dlp_alert",
                                    }),
                                    envelope,
                                )
                                .await
                            {
                                tracing::warn!("Failed to audit WS binary DLP: {}", e);
                            }
                        }
                    }
                }

                // SECURITY (FIND-R46-WS-004): Audit log binary frame drop
                let action = Action::new(
                    "vellaveto",
                    "ws_upstream_binary_dropped",
                    json!({
                        "session": session_id,
                        "transport": "websocket",
                        "direction": "upstream_to_client",
                        "binary_size": data.len(),
                    }),
                );
                let upstream_binary_verdict = Verdict::Deny {
                    reason: "Binary frames not supported for JSON-RPC".to_string(),
                };
                let upstream_binary_security_context =
                    super::helpers::protocol_binary_rejection_security_context(
                        "ws_upstream_binary_dropped",
                    );
                let envelope = build_secondary_acis_envelope_with_security_context(
                    &action,
                    &upstream_binary_verdict,
                    DecisionOrigin::PolicyEngine,
                    "websocket",
                    Some(&session_id),
                    Some(&upstream_binary_security_context),
                );
                if let Err(e) = state
                    .audit
                    .log_entry_with_acis(
                        &action,
                        &upstream_binary_verdict,
                        json!({
                            "source": "ws_proxy",
                            "event": "ws_upstream_binary_dropped",
                        }),
                        envelope,
                    )
                    .await
                {
                    tracing::warn!("Failed to audit WS upstream binary drop: {}", e);
                }
            }
            tokio_tungstenite::tungstenite::Message::Ping(data) => {
                // Forward ping as pong to upstream (handled by tungstenite)
                let _ = data; // tungstenite auto-responds to pings
            }
            tokio_tungstenite::tungstenite::Message::Pong(_) => {}
            tokio_tungstenite::tungstenite::Message::Close(_) => {
                tracing::debug!(session_id = %session_id, "Upstream sent close frame");
                break;
            }
            tokio_tungstenite::tungstenite::Message::Frame(_) => {
                // Raw frame — ignore
            }
        }
    }
}

/// Convert an HTTP URL to a WebSocket URL.
///
/// `http://` → `ws://`, `https://` → `wss://`.
///
/// SECURITY (FIND-R124-001): Only allows http/https/ws/wss schemes.
/// Unknown schemes (ftp://, file://, gopher://) are rejected with a
/// warning and fall back to the original URL prefixed with `ws://`
/// to maintain fail-closed behavior. This gives parity with scheme
/// validation in HTTP and gRPC transports (FIND-R42-015).
pub fn convert_to_ws_url(http_url: &str) -> String {
    if let Some(rest) = http_url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = http_url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else if http_url.starts_with("wss://") || http_url.starts_with("ws://") {
        // Already a WebSocket URL — use as-is
        http_url.to_string()
    } else {
        // SECURITY (FIND-R124-001): Reject unknown schemes. Log warning
        // and return a URL that will fail to connect safely rather than
        // connecting to an unintended scheme (e.g., ftp://, file://).
        // SECURITY (FIND-R166-003): Sanitize logged value to prevent log injection
        // from URLs with control characters (possible in gateway mode).
        tracing::warn!(
            "convert_to_ws_url: rejecting URL with unsupported scheme: {}",
            vellaveto_types::sanitize_for_log(
                http_url.split("://").next().unwrap_or("unknown"),
                128,
            )
        );
        // Return invalid URL that will fail at connect_async()
        format!("ws://invalid-scheme-rejected.localhost/{}", http_url.len())
    }
}

/// Connect to an upstream WebSocket server.
///
/// Returns the split WebSocket stream or an error.
async fn connect_upstream_ws(
    url: &str,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    String,
> {
    let connect_timeout = Duration::from_secs(10);
    match tokio::time::timeout(connect_timeout, tokio_tungstenite::connect_async(url)).await {
        Ok(Ok((ws_stream, _response))) => Ok(ws_stream),
        Ok(Err(e)) => Err(format!("WebSocket connection error: {e}")),
        Err(_) => Err("WebSocket connection timeout (10s)".to_string()),
    }
}

/// Register output schemas and validate WS response `structuredContent`.
///
/// Returns true when the response should be blocked.
async fn validate_ws_structured_content_response(
    json_val: &Value,
    state: &ProxyState,
    session_id: &str,
    tracked_tool_name: Option<&str>,
) -> bool {
    // Keep WS behavior aligned with HTTP/SSE paths.
    state
        .output_schema_registry
        .register_from_tools_list(json_val);

    let Some(result) = json_val.get("result") else {
        return false;
    };
    let Some(structured) = result.get("structuredContent") else {
        return false;
    };

    let meta_tool_name = result
        .get("_meta")
        .and_then(|m| m.get("tool"))
        .and_then(|t| t.as_str());
    let tool_name = match (meta_tool_name, tracked_tool_name) {
        (Some(meta), Some(tracked)) if !meta.eq_ignore_ascii_case(tracked) => {
            tracing::warn!(
                "SECURITY: WS structuredContent tool mismatch (meta='{}', tracked='{}'); using tracked tool name",
                meta,
                tracked
            );
            tracked
        }
        (Some(meta), _) => meta,
        (None, Some(tracked)) => tracked,
        (None, None) => "unknown",
    };

    match state.output_schema_registry.validate(tool_name, structured) {
        ValidationResult::Invalid { violations } => {
            tracing::warn!(
                "SECURITY: WS structuredContent validation failed for tool '{}': {:?}",
                tool_name,
                violations
            );
            let action = Action::new(
                "vellaveto",
                "output_schema_violation",
                json!({
                    "tool": tool_name,
                    "violations": violations,
                    "session": session_id,
                    "transport": "websocket",
                }),
            );
            let schema_verdict = Verdict::Deny {
                reason: format!("WS structuredContent validation failed: {violations:?}"),
            };
            let schema_security_context =
                super::helpers::output_schema_violation_security_context(Some(tool_name), true);
            let envelope = build_secondary_acis_envelope_with_security_context(
                &action,
                &schema_verdict,
                DecisionOrigin::PolicyEngine,
                "websocket",
                Some(session_id),
                Some(&schema_security_context),
            );
            if let Err(e) = state
                .audit
                .log_entry_with_acis(
                    &action,
                    &schema_verdict,
                    json!({"source": "ws_proxy", "event": "output_schema_violation_ws"}),
                    envelope,
                )
                .await
            {
                tracing::warn!("Failed to audit WS output schema violation: {}", e);
            }
            true
        }
        ValidationResult::Valid => {
            tracing::debug!("WS structuredContent validated for tool '{}'", tool_name);
            false
        }
        ValidationResult::NoSchema => {
            tracing::debug!(
                "No output schema registered for WS tool '{}', skipping validation",
                tool_name
            );
            false
        }
    }
}

// NOTE: build_ws_evaluation_context() was removed in FIND-R130-002 fix.
// All callers now build EvaluationContext inline inside the DashMap shard
// lock to prevent TOCTOU races on call_counts/action_history.

/// Check per-connection rate limit. Returns true if within limit.
fn check_rate_limit(
    counter: &AtomicU64,
    window_start: &std::sync::Mutex<std::time::Instant>,
    max_per_sec: u32,
) -> bool {
    // SECURITY (FIND-R182-006): Fail-closed — zero rate limit blocks all messages.
    // Previously returned true (fail-open), which disabled rate limiting entirely.
    if max_per_sec == 0 {
        return false;
    }

    let now = std::time::Instant::now();
    let mut start = match window_start.lock() {
        Ok(guard) => guard,
        Err(e) => {
            tracing::error!("WS rate limiter mutex poisoned — fail-closed: {}", e);
            return false;
        }
    };

    if now.duration_since(*start) >= Duration::from_secs(1) {
        // Reset window
        *start = now;
        // SECURITY (FIND-R55-WS-003): Use SeqCst for security-critical rate limit counter.
        counter.store(1, Ordering::SeqCst);
        true
    } else {
        // SECURITY (FIND-R182-003): saturating arithmetic prevents overflow wrap-to-zero.
        // SECURITY (FIND-R155-WS-001): Conditional atomic increment — only increment if
        // within limit, reject otherwise. This eliminates the TOCTOU gap between
        // load()+compare and also prevents counter inflation from rejected requests.
        // The closure returns None when limit is reached, causing fetch_update to fail
        // without modifying the counter.
        let limit = max_per_sec as u64;
        match counter.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
            if v >= limit {
                None // Limit reached — do not increment
            } else {
                Some(v.saturating_add(1))
            }
        }) {
            Ok(_prev) => true, // Within limit, counter was incremented
            Err(_) => false,   // Limit exceeded, counter unchanged
        }
    }
}

/// Extract scannable text from a JSON-RPC request for injection scanning.
///
/// SECURITY (FIND-R46-WS-001): Scans tool call arguments, resource URIs,
/// and sampling request content for injection payloads in the client→upstream
/// direction. Matches the HTTP proxy's request-side injection scanning.
fn extract_scannable_text_from_request(json_val: &Value) -> String {
    let mut text_parts = Vec::new();

    // SECURITY (FIND-R224-002): Recursively scan the entire `params` subtree,
    // not just specific fields. Previous narrow extraction missed injection
    // payloads in TaskRequest (params.message), ExtensionMethod, and other
    // message types with non-standard parameter structures. This gives parity
    // with the HTTP handler's `extract_passthrough_text_for_injection` which
    // scans all of params recursively.
    if let Some(params) = json_val.get("params") {
        extract_strings_recursive(params, &mut text_parts, 0);
    }

    // SECURITY (FIND-R224-006): Also scan `result` field for injection payloads.
    // JSON-RPC response messages (sampling/elicitation replies) carry data in
    // `result` rather than `params`. Without this, upstream injection payloads
    // in response results bypass WS scanning while being caught by HTTP/gRPC.
    if let Some(result) = json_val.get("result") {
        extract_strings_recursive(result, &mut text_parts, 0);
    }

    text_parts.join("\n")
}

/// Recursively extract string values from a JSON value, with depth and count bounds.
///
/// SECURITY (FIND-R48-007): Added MAX_PARTS to prevent memory amplification
/// from messages containing many short strings.
fn extract_strings_recursive(val: &Value, parts: &mut Vec<String>, depth: usize) {
    // SECURITY (FIND-R154-005): Use depth 32 matching shared MAX_SCAN_DEPTH
    // in scanner_base.rs. Previous limit of 10 allowed injection payloads
    // nested between depth 11-32 to evade WS scanning while being caught
    // by the stdio relay and DLP scanner (both use MAX_SCAN_DEPTH=32).
    const MAX_DEPTH: usize = 32;
    const MAX_PARTS: usize = 1000;
    if depth > MAX_DEPTH || parts.len() >= MAX_PARTS {
        return;
    }
    match val {
        Value::String(s) => parts.push(s.clone()),
        Value::Array(arr) => {
            for item in arr {
                extract_strings_recursive(item, parts, depth + 1);
            }
        }
        Value::Object(map) => {
            for (key, v) in map {
                // SECURITY (FIND-R154-003): Also scan object keys for injection
                // payloads. Parity with stdio relay's traverse_json_strings_with_keys.
                // Without this, attackers can hide injection in JSON key names.
                if parts.len() < MAX_PARTS {
                    parts.push(key.clone());
                }
                extract_strings_recursive(v, parts, depth + 1);
            }
        }
        _ => {}
    }
}

/// Extract scannable text from a JSON-RPC response for injection scanning.
///
/// SECURITY (FIND-R130-004): Delegates to the shared `extract_text_from_result()`
/// which covers `resource.text`, `resource.blob` (base64-decoded), `annotations`,
/// and `_meta` — all missing from the previous WS-only implementation.
fn extract_scannable_text(json_val: &Value) -> String {
    let mut text_parts = Vec::new();

    // Scan result via shared extraction (covers content[].text, resource.text,
    // resource.blob, annotations, instructionsForUser, structuredContent, _meta).
    if let Some(result) = json_val.get("result") {
        let result_text = super::inspection::extract_text_from_result(result);
        if !result_text.is_empty() {
            text_parts.push(result_text);
        }
    }

    // Scan error messages (not covered by extract_text_from_result)
    if let Some(error) = json_val.get("error") {
        if let Some(msg) = error.get("message").and_then(|m| m.as_str()) {
            text_parts.push(msg.to_string());
        }
        // SECURITY (FIND-R168-005): Use as_str() first to avoid wrapping
        // string values in JSON quotes. Parity with scanner_base.rs.
        if let Some(data) = error.get("data") {
            if let Some(s) = data.as_str() {
                text_parts.push(s.to_string());
            } else {
                text_parts.push(data.to_string());
            }
        }
    }

    text_parts.join("\n")
}

/// Test-only compatibility helper for approval-store assertions.
#[cfg(test)]
async fn create_ws_approval(
    state: &ProxyState,
    session_id: &str,
    action: &Action,
    reason: &str,
) -> Option<String> {
    let store = state.approval_store.as_ref()?;
    let requested_by = state.sessions.get_mut(session_id).and_then(|session| {
        session
            .agent_identity
            .as_ref()
            .and_then(|identity| identity.subject.clone())
            .or_else(|| session.oauth_subject.clone())
    });
    match store
        .create(
            action.clone(),
            reason.to_string(),
            requested_by,
            Some(session_id.to_string()),
            Some(vellaveto_engine::acis::fingerprint_action(action)),
        )
        .await
    {
        Ok(id) => Some(id),
        Err(e) => {
            tracing::error!(
                session_id = %session_id,
                "Failed to create WebSocket approval (fail-closed): {}",
                e
            );
            None
        }
    }
}

/// Build a JSON-RPC error response string for WebSocket with optional `error.data`.
fn make_ws_error_response_with_data(
    id: Option<&Value>,
    code: i64,
    message: &str,
    data: Option<Value>,
) -> String {
    let mut error = serde_json::Map::new();
    error.insert("code".to_string(), Value::from(code));
    error.insert("message".to_string(), Value::from(message));
    if let Some(data) = data {
        error.insert("data".to_string(), data);
    }
    let response = json!({
        "jsonrpc": "2.0",
        "id": id.cloned().unwrap_or(Value::Null),
        "error": Value::Object(error),
    });
    serde_json::to_string(&response).unwrap_or_else(|_| {
        format!(r#"{{"jsonrpc":"2.0","error":{{"code":{code},"message":"{message}"}},"id":null}}"#)
    })
}

/// Build a JSON-RPC error response string for WebSocket.
fn make_ws_error_response(id: Option<&Value>, code: i64, message: &str) -> String {
    make_ws_error_response_with_data(id, code, message, None)
}

#[cfg(test)]
mod tests;
