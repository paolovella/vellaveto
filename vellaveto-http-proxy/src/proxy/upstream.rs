// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Upstream forwarding: canonicalization, JSON-RPC error building,
//! and the main `forward_to_upstream` relay function.

use axum::{
    body::Body,
    http::{
        header::{HeaderName, HeaderValue},
        StatusCode,
    },
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use serde_json::{json, Value};
use vellaveto_mcp::inspection::{
    inspect_for_injection, scan_response_for_secrets, scan_tool_descriptions,
    scan_tool_descriptions_with_scanner,
};
use vellaveto_mcp::mediation::build_secondary_acis_envelope_with_security_context;
use vellaveto_types::acis::DecisionOrigin;
use vellaveto_types::{Action, Verdict};

use super::call_chain::take_tracked_tool_call;
use super::helpers::{
    extract_annotations_from_response, output_schema_violation_security_context,
    read_bounded_response, response_dlp_security_context, response_injection_security_context,
    tool_discovery_integrity_security_context, verify_manifest_from_response,
};
use super::inspection::{
    check_sse_for_rug_pull_and_manifest, extract_text_from_result, register_schemas_from_sse,
    scan_sse_events_for_dlp, scan_sse_events_for_injection, scan_sse_events_for_output_schema,
};
use super::request_state;
use super::server_request;
use vellaveto_mcp::output_validation::ValidationResult;

use super::{ProxyState, MCP_PROTOCOL_VERSION_HEADER, MCP_PROTOCOL_VERSION_VALUE, MCP_SESSION_ID};
use crate::proxy_metrics::record_dlp_finding;

pub(super) struct UpstreamForwardOptions<'a> {
    pub auth_header: Option<&'a str>,
    pub trace_ctx: Option<(&'a str, Option<&'a str>)>,
    pub mcp_param_headers: &'a [(HeaderName, HeaderValue)],
    pub last_event_id: Option<&'a str>,
}

impl<'a> UpstreamForwardOptions<'a> {
    pub fn post(
        auth_header: Option<&'a str>,
        trace_ctx: Option<(&'a str, Option<&'a str>)>,
        mcp_param_headers: &'a [(HeaderName, HeaderValue)],
    ) -> Self {
        Self {
            auth_header,
            trace_ctx,
            mcp_param_headers,
            last_event_id: None,
        }
    }
}

/// If canonicalize mode is enabled, re-serialize the parsed JSON to canonical
/// form before forwarding. This ensures upstream sees exactly what was evaluated,
/// closing the TOCTOU gap.
///
/// SECURITY (R17-CANON-1): Returns `None` when canonicalization is enabled but
/// re-serialization fails, instead of falling back to original bytes.
/// Forwarding un-canonicalized bytes would reopen the TOCTOU gap that
/// canonicalization is designed to close.
pub(super) fn canonicalize_body(
    state: &ProxyState,
    parsed: &Value,
    original: Bytes,
) -> Option<Bytes> {
    if state.canonicalize {
        match serde_json::to_vec(parsed) {
            Ok(canonical) => Some(Bytes::from(canonical)),
            Err(e) => {
                tracing::error!(
                    "SECURITY: Canonicalization failed, rejecting request (fail-closed): {}",
                    e
                );
                None
            }
        }
    } else {
        Some(original)
    }
}

/// Build a JSON-RPC error response (fail-closed helper).
pub(super) fn make_jsonrpc_error(id: Option<&Value>, code: i64, message: &str) -> Response {
    let error_response = json!({
        "jsonrpc": "2.0",
        "id": id.cloned().unwrap_or(Value::Null),
        "error": {
            "code": code,
            "message": message,
        }
    });
    (StatusCode::OK, Json(error_response)).into_response()
}

/// Forward a request to the upstream MCP server.
///
/// If OAuth pass-through is enabled, the original Authorization header is
/// forwarded to upstream.
pub(super) async fn forward_to_upstream(
    state: &ProxyState,
    session_id: &str,
    body: Bytes,
    options: UpstreamForwardOptions<'_>,
) -> Response {
    forward_to_upstream_url(state, &state.upstream_url, session_id, body, options).await
}

/// Forward a GET request to the upstream MCP server for SSE resumability.
///
/// MCP 2025-11-25: Clients use GET /mcp with Accept: text/event-stream to
/// initiate or resume an SSE stream. When `last_event_id` is present, the
/// upstream server resumes from that event.
pub(super) async fn forward_get_to_upstream(
    state: &ProxyState,
    session_id: &str,
    auth_header: Option<&str>,
    trace_ctx: Option<(&str, Option<&str>)>,
    last_event_id: Option<&str>,
) -> Response {
    let mut request_builder = state
        .http_client
        .get(&state.upstream_url)
        .header("accept", "text/event-stream")
        .header(MCP_SESSION_ID, session_id)
        .header(MCP_PROTOCOL_VERSION_HEADER, MCP_PROTOCOL_VERSION_VALUE);

    // Forward Authorization header in OAuth pass-through mode
    if let Some(auth) = auth_header {
        request_builder = request_builder.header("authorization", auth);
    }

    // Phase 28: Inject W3C Trace Context headers for distributed tracing
    if let Some((traceparent, tracestate)) = trace_ctx {
        request_builder = request_builder.header("traceparent", traceparent);
        if let Some(ts) = tracestate {
            request_builder = request_builder.header("tracestate", ts);
        }
    }

    // MCP 2025-11-25: Forward Last-Event-ID for SSE resumption
    if let Some(event_id) = last_event_id {
        request_builder = request_builder.header("last-event-id", event_id);
    }

    let result = request_builder.send().await;

    match result {
        Ok(upstream_resp) => {
            let status = upstream_resp.status();

            // SECURITY: Validate upstream status code (same as POST path)
            let status =
                if status.is_redirection() || status.as_u16() < 200 || status.as_u16() == 407 {
                    tracing::warn!(
                        "SECURITY: Upstream GET returned suspicious status {} — mapping to 502",
                        status
                    );
                    StatusCode::BAD_GATEWAY
                } else {
                    status
                };

            let headers = upstream_resp.headers().clone();
            let content_type_result = headers.get("content-type").map(|v| v.to_str());
            if let Some(Err(_)) = content_type_result {
                tracing::warn!(
                    "Upstream GET returned non-UTF-8 Content-Type header — blocking response"
                );
                return (
                    StatusCode::BAD_GATEWAY,
                    "Upstream returned invalid Content-Type header",
                )
                    .into_response();
            }
            let content_type = content_type_result.and_then(|r| r.ok()).unwrap_or("");

            // GET /mcp must return SSE
            if !content_type.starts_with("text/event-stream") {
                tracing::warn!(
                    "Upstream GET /mcp returned non-SSE content-type: '{}'",
                    content_type
                );
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32000,
                            "message": "Upstream returned unexpected content type"
                        },
                        "id": null
                    })),
                )
                    .into_response();
            }

            // Read bounded SSE body and forward
            match super::helpers::read_bounded_response(
                upstream_resp,
                state.limits.max_response_body_bytes,
            )
            .await
            {
                Ok(sse_bytes) => {
                    match server_request::find_server_request_in_sse(
                        &sse_bytes,
                        state.limits.max_sse_event_bytes,
                    ) {
                        Ok(Some(info)) => {
                            tracing::warn!(
                                session_id = %session_id,
                                method = %info.method,
                                "SECURITY: Blocking unsolicited server request on GET SSE stream"
                            );
                            server_request::audit_unsolicited_server_request(
                                state,
                                session_id,
                                "sse",
                                &info.method,
                                "http_proxy",
                            )
                            .await;
                            return (
                                StatusCode::OK,
                                Json(json!({
                                    "jsonrpc": "2.0",
                                    "error": {
                                        "code": -32001,
                                        "message": "SSE response blocked: unsolicited server request",
                                    },
                                    "id": info.id,
                                })),
                            )
                                .into_response();
                        }
                        Ok(None) => {}
                        Err(server_request::SseServerRequestScanError::OversizedEvent) => {
                            tracing::warn!(
                                session_id = %session_id,
                                "SECURITY: Blocking GET SSE stream with oversized event before server-request validation"
                            );
                            server_request::audit_unsolicited_server_request(
                                state,
                                session_id,
                                "sse",
                                "unknown",
                                "http_proxy",
                            )
                            .await;
                            return (
                                StatusCode::OK,
                                Json(json!({
                                    "jsonrpc": "2.0",
                                    "error": {
                                        "code": -32001,
                                        "message": "SSE response blocked: invalid event",
                                    },
                                    "id": null,
                                })),
                            )
                                .into_response();
                        }
                    }

                    // SECURITY: Injection scanning on SSE events (same as POST path)
                    let injection_found = if !state.injection_disabled {
                        scan_sse_events_for_injection(&sse_bytes, session_id, state).await
                    } else {
                        false
                    };
                    if injection_found && state.injection_blocking {
                        return (
                            StatusCode::OK,
                            Json(json!({
                                "jsonrpc": "2.0",
                                "error": {
                                    "code": -32001,
                                    "message": "SSE response blocked: prompt injection detected",
                                },
                            })),
                        )
                            .into_response();
                    }

                    // DLP scanning (same as POST path)
                    let mut dlp_found = false;
                    if state.response_dlp_enabled {
                        dlp_found = scan_sse_events_for_dlp(&sse_bytes, session_id, state).await;
                        if dlp_found && state.response_dlp_blocking {
                            return (
                                StatusCode::OK,
                                Json(json!({
                                    "jsonrpc": "2.0",
                                    "error": {
                                        "code": -32002,
                                        "message": "SSE response blocked: secrets detected by DLP",
                                    },
                                })),
                            )
                                .into_response();
                        }
                    }

                    // SECURITY (FIND-R45-006): Register output schemas from SSE
                    // tools/list responses (same as POST path). Without this,
                    // schemas returned via GET SSE are never registered.
                    register_schemas_from_sse(&sse_bytes, state);

                    // SECURITY (FIND-R45-006): Validate structuredContent in SSE
                    // responses against registered output schemas (same as POST path).
                    let schema_violation_found =
                        scan_sse_events_for_output_schema(&sse_bytes, session_id, state).await;

                    // SECURITY (FIND-R45-005): Rug-pull detection and manifest
                    // verification for GET SSE responses. Without this, a server
                    // returning tools/list via GET SSE bypasses both checks.
                    check_sse_for_rug_pull_and_manifest(
                        &sse_bytes,
                        session_id,
                        state,
                        injection_found,
                        dlp_found,
                        schema_violation_found,
                    )
                    .await;

                    if schema_violation_found {
                        return (
                            StatusCode::OK,
                            Json(json!({
                                "jsonrpc": "2.0",
                                "error": {
                                    "code": -32001,
                                    "message": "SSE response blocked: output schema validation failed",
                                },
                            })),
                        )
                            .into_response();
                    }

                    // SECURITY (R12-RESP-10): Do NOT copy Mcp-Session-Id from upstream.
                    Response::builder()
                        .status(status)
                        .header("content-type", "text/event-stream")
                        .header("cache-control", "no-cache")
                        .body(Body::from(sse_bytes))
                        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
                }
                Err(e) => {
                    tracing::error!("Failed to read GET SSE response body: {}", e);
                    (
                        StatusCode::BAD_GATEWAY,
                        Json(json!({
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -32000,
                                "message": "Upstream server error"
                            },
                            "id": null
                        })),
                    )
                        .into_response()
                }
            }
        }
        Err(e) => {
            tracing::error!("GET upstream request failed: {}", e);
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32000,
                        "message": "Upstream server unavailable"
                    },
                    "id": null
                })),
            )
                .into_response()
        }
    }
}

/// Forward a request to a specific upstream URL.
///
/// This is the core forwarding function. `forward_to_upstream()` delegates here
/// with `state.upstream_url`. Gateway mode calls this directly with the
/// routed backend URL.
///
/// When `trace_ctx` is provided, `traceparent` and optionally `tracestate`
/// headers are injected into the upstream request for distributed tracing.
///
/// When `last_event_id` is provided (MCP 2025-11-25 resumability), the
/// `Last-Event-ID` header is forwarded to the upstream server.
pub(super) async fn forward_to_upstream_url(
    state: &ProxyState,
    upstream_url: &str,
    session_id: &str,
    body: Bytes,
    options: UpstreamForwardOptions<'_>,
) -> Response {
    // SECURITY (R240-PROXY-2): Enforce HTTPS for non-local upstream URLs.
    // This is the primary forwarding path — the R239 fix only covered the
    // legacy fallback path. Without this, authenticated MCP requests (including
    // Authorization headers) are sent over plaintext HTTP to arbitrary hosts.
    if let Err(reason) = super::validate_upstream_url_scheme(upstream_url) {
        tracing::warn!(
            "Rejecting non-HTTPS upstream URL in forward_to_upstream_url: {}",
            reason
        );
        return (
            axum::http::StatusCode::BAD_GATEWAY,
            "upstream scheme not allowed",
        )
            .into_response();
    }

    let mut request_builder = state
        .http_client
        .post(upstream_url)
        .header("content-type", "application/json")
        .header(MCP_SESSION_ID, session_id)
        .header(MCP_PROTOCOL_VERSION_HEADER, MCP_PROTOCOL_VERSION_VALUE);

    // Forward Authorization header in OAuth pass-through mode
    if let Some(auth) = options.auth_header {
        request_builder = request_builder.header("authorization", auth);
    }

    // Phase 28: Inject W3C Trace Context headers for distributed tracing
    if let Some((traceparent, tracestate)) = options.trace_ctx {
        request_builder = request_builder.header("traceparent", traceparent);
        if let Some(ts) = tracestate {
            request_builder = request_builder.header("tracestate", ts);
        }
    }

    for (name, value) in options.mcp_param_headers {
        request_builder = request_builder.header(name.clone(), value.clone());
    }

    // MCP 2025-11-25: Forward Last-Event-ID for SSE resumption on POST
    if let Some(event_id) = options.last_event_id {
        request_builder = request_builder.header("last-event-id", event_id);
    }

    let result = request_builder.body(body).send().await;

    match result {
        Ok(upstream_resp) => {
            let status = upstream_resp.status();

            // SECURITY (R11-RESP-3): Validate upstream status code before forwarding.
            // A malicious upstream could return 3xx redirects (SSRF), 401/407 (credential
            // harvesting), or 1xx (protocol confusion). Only allow 200-299 and 4xx-5xx.
            let status =
                if status.is_redirection() || status.as_u16() < 200 || status.as_u16() == 407 {
                    tracing::warn!(
                        "SECURITY: Upstream returned suspicious status {} — mapping to 502",
                        status
                    );
                    StatusCode::BAD_GATEWAY
                } else {
                    status
                };

            let headers = upstream_resp.headers().clone();
            // SECURITY (R33-PROXY-2): Non-UTF-8 Content-Type header previously
            // fell through to empty string, bypassing all scanning branches.
            // Now we reject non-UTF-8 Content-Type as suspicious — a legitimate
            // MCP server should never send non-UTF-8 content types.
            let content_type_result = headers.get("content-type").map(|v| v.to_str());
            if let Some(Err(_)) = content_type_result {
                tracing::warn!(
                    "Upstream returned non-UTF-8 Content-Type header — blocking response"
                );
                return (
                    StatusCode::BAD_GATEWAY,
                    "Upstream returned invalid Content-Type header",
                )
                    .into_response();
            }
            let content_type = content_type_result.and_then(|r| r.ok()).unwrap_or("");

            // Check if upstream is returning SSE
            if content_type.starts_with("text/event-stream") {
                // C-15 Exploit #6 fix: Buffer SSE response and scan each event's
                // data payload for injection patterns before forwarding.
                // Bounded read prevents OOM from infinite SSE streams.
                match read_bounded_response(upstream_resp, state.limits.max_response_body_bytes)
                    .await
                {
                    Ok(sse_bytes) => {
                        // SECURITY: Check for injection in SSE events. When
                        // injection_blocking is enabled, block the entire stream.
                        let injection_found = if !state.injection_disabled {
                            scan_sse_events_for_injection(&sse_bytes, session_id, state).await
                        } else {
                            false
                        };

                        if injection_found && state.injection_blocking {
                            return (
                                StatusCode::OK,
                                Json(json!({
                                    "jsonrpc": "2.0",
                                    "error": {
                                        "code": -32001,
                                        "message": "SSE response blocked: prompt injection detected",
                                    },
                                })),
                            )
                                .into_response();
                        }

                        // DLP + OutputSchemaRegistry scanning for SSE events.
                        // SECURITY (R32-PROXY-2): Track dlp_found outside the
                        // if-block so it can be passed to check_sse_for_rug_pull_and_manifest.
                        let mut dlp_found = false;
                        if state.response_dlp_enabled {
                            dlp_found =
                                scan_sse_events_for_dlp(&sse_bytes, session_id, state).await;
                            // SECURITY (R18-DLP-BLOCK): Block SSE stream if secrets detected
                            // and response_dlp_blocking is enabled.
                            if dlp_found && state.response_dlp_blocking {
                                return (
                                    StatusCode::OK,
                                    Json(json!({
                                        "jsonrpc": "2.0",
                                        "error": {
                                            "code": -32002,
                                            "message": "SSE response blocked: secrets detected by DLP",
                                        },
                                    })),
                                )
                                    .into_response();
                            }
                        }
                        // Register output schemas from SSE tools/list responses.
                        register_schemas_from_sse(&sse_bytes, state);

                        // Validate structuredContent in SSE responses against registered output schemas.
                        let schema_violation_found =
                            scan_sse_events_for_output_schema(&sse_bytes, session_id, state).await;

                        // SECURITY (R18-SSE-RUG): Rug-pull detection and manifest
                        // verification for SSE responses. Without this, a server
                        // returning tools/list via SSE would bypass both checks.
                        // SECURITY (R27-PROXY-1, R32-PROXY-2): Pass taint flags so
                        // record_response is skipped for suspicious SSE events.
                        check_sse_for_rug_pull_and_manifest(
                            &sse_bytes,
                            session_id,
                            state,
                            injection_found,
                            dlp_found,
                            schema_violation_found,
                        )
                        .await;

                        if schema_violation_found {
                            return (
                                StatusCode::OK,
                                Json(json!({
                                    "jsonrpc": "2.0",
                                    "error": {
                                        "code": -32001,
                                        "message": "SSE response blocked: output schema validation failed",
                                    },
                                })),
                            )
                                .into_response();
                        }

                        // SECURITY (R12-RESP-10): Do NOT copy Mcp-Session-Id from upstream.
                        // The proxy is the session authority. Forwarding the upstream's
                        // session ID would override proxy-managed session tracking,
                        // breaking rug-pull detection, rate limiting, and manifest verification.
                        // The caller's attach_session_header() sets the correct proxy session ID.
                        Response::builder()
                            .status(status)
                            .header("content-type", "text/event-stream")
                            .header("cache-control", "no-cache")
                            .body(Body::from(sse_bytes))
                            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
                    }
                    Err(e) => {
                        tracing::error!("Failed to read SSE response body: {}", e);
                        (
                            StatusCode::BAD_GATEWAY,
                            Json(json!({
                                "jsonrpc": "2.0",
                                "error": {
                                    "code": -32000,
                                    "message": "Upstream server error"
                                },
                                "id": null
                            })),
                        )
                            .into_response()
                    }
                }
            } else {
                // SECURITY (R12-RESP-2): Validate content type. MCP Streamable HTTP
                // only defines application/json and text/event-stream. Unexpected
                // content types could bypass all scanning (injection, DLP, schema).
                if !content_type.is_empty()
                    && !content_type.starts_with("application/json")
                    && !content_type.starts_with("text/json")
                {
                    tracing::warn!(
                        "SECURITY: Upstream returned unexpected content-type '{}' — \
                         blocking to prevent scan bypass",
                        content_type
                    );
                    return (
                        StatusCode::BAD_GATEWAY,
                        Json(json!({
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -32000,
                                "message": "Upstream returned unexpected content type"
                            },
                            "id": null
                        })),
                    )
                        .into_response();
                }

                // JSON response — read body, inspect, and forward
                // Bounded read prevents OOM from oversized responses.
                match read_bounded_response(upstream_resp, state.limits.max_response_body_bytes)
                    .await
                {
                    Ok(body_bytes) => {
                        // Try to parse and inspect the response
                        // Track whether injection blocking should prevent forwarding.
                        let mut blocked_by_injection: Option<String> = None;
                        let mut tracked_response_tool_name: Option<String> = None;
                        // SECURITY (R36-PROXY-1): Track detection state separately from
                        // blocking state. In log-only mode, blocked_by_injection remains
                        // None but injection_detected is true, preventing tainted responses
                        // from being fingerprinted by the memory tracker.
                        let mut injection_detected = false;
                        if let Ok(response_json) = serde_json::from_slice::<Value>(&body_bytes) {
                            // Consume tracked tool context for this response id (if any).
                            // This closes a bypass where upstream omits result._meta.tool,
                            // causing structuredContent validation to run as "unknown".
                            let tracked_tool_name = take_tracked_tool_call(
                                &state.sessions,
                                session_id,
                                response_json.get("id"),
                            );
                            tracked_response_tool_name = tracked_tool_name.clone();

                            // Inspect for injection patterns in tool results
                            if let Some(result) = response_json.get("result") {
                                let text_to_inspect = extract_text_from_result(result);
                                if !text_to_inspect.is_empty() && !state.injection_disabled {
                                    let matches: Vec<String> =
                                        if let Some(ref scanner) = state.injection_scanner {
                                            scanner
                                                .inspect(&text_to_inspect)
                                                .into_iter()
                                                .map(|s| s.to_string())
                                                .collect()
                                        } else {
                                            inspect_for_injection(&text_to_inspect)
                                                .into_iter()
                                                .map(|s| s.to_string())
                                                .collect()
                                        };
                                    if !matches.is_empty() {
                                        injection_detected = true;
                                        tracing::warn!(
                                            "SECURITY: Potential prompt injection in upstream response! \
                                             Session: {}, Patterns: {:?}",
                                            session_id,
                                            matches
                                        );
                                        // SECURITY: When injection_blocking is true, block the
                                        // response instead of just logging.
                                        let verdict = if state.injection_blocking {
                                            // SECURITY (R12-RESP-9): Log detailed patterns to audit
                                            // but return generic message to client to prevent
                                            // pattern oracle attacks.
                                            let audit_reason = format!(
                                                "Response blocked: prompt injection detected ({})",
                                                matches.join(", ")
                                            );
                                            blocked_by_injection = Some(
                                                "Response blocked: security policy violation"
                                                    .to_string(),
                                            );
                                            Verdict::Deny {
                                                reason: audit_reason,
                                            }
                                        } else {
                                            Verdict::Allow
                                        };
                                        let action = Action::new(
                                            "vellaveto",
                                            "response_inspection",
                                            json!({
                                                "matched_patterns": matches,
                                                "session": session_id,
                                                "blocking": state.injection_blocking,
                                            }),
                                        );
                                        let injection_security_context =
                                            response_injection_security_context(
                                                tracked_tool_name.as_deref(),
                                                &response_json,
                                                state.injection_blocking,
                                                "response_injection",
                                            );
                                        let envelope =
                                            build_secondary_acis_envelope_with_security_context(
                                                &action,
                                                &verdict,
                                                DecisionOrigin::InjectionScanner,
                                                "http",
                                                Some(session_id),
                                                Some(&injection_security_context),
                                            );
                                        if let Err(e) = state
                                            .audit
                                            .log_entry_with_acis(
                                                &action,
                                                &verdict,
                                                json!({
                                                    "source": "http_proxy",
                                                    "event": "prompt_injection_detected",
                                                }),
                                                envelope,
                                            )
                                            .await
                                        {
                                            tracing::warn!(
                                                "Failed to audit injection detection: {}",
                                                e
                                            );
                                        }
                                    }
                                }

                                // Extract tool annotations from tools/list responses
                                extract_annotations_from_response(
                                    &response_json,
                                    session_id,
                                    &state.sessions,
                                    &state.audit,
                                    &state.known_tools,
                                )
                                .await;

                                // P2: Scan tool descriptions for embedded injection
                                if !state.injection_disabled {
                                    let desc_findings = if let Some(ref scanner) =
                                        state.injection_scanner
                                    {
                                        scan_tool_descriptions_with_scanner(&response_json, scanner)
                                    } else {
                                        scan_tool_descriptions(&response_json)
                                    };
                                    for finding in &desc_findings {
                                        injection_detected = true;
                                        tracing::warn!(
                                            "SECURITY: Injection in tool '{}' description! Session: {}, Patterns: {:?}",
                                            finding.tool_name, session_id, finding.matched_patterns
                                        );
                                        // SECURITY (R111-003): Use a generic client-facing message to
                                        // avoid leaking matched pattern names to the caller. Detailed
                                        // pattern info is recorded in the audit log only.
                                        let client_reason = format!(
                                            "Tool '{}' blocked: suspicious content detected in description",
                                            finding.tool_name
                                        );
                                        let audit_reason = format!(
                                            "Tool '{}' description contains injection: {:?}",
                                            finding.tool_name, finding.matched_patterns
                                        );
                                        // SECURITY: Block when injection_blocking is enabled.
                                        if state.injection_blocking
                                            && blocked_by_injection.is_none()
                                        {
                                            blocked_by_injection = Some(client_reason);
                                        }
                                        let action = Action::new(
                                            "vellaveto",
                                            "tool_description_injection",
                                            json!({
                                                "tool": finding.tool_name,
                                                "matched_patterns": finding.matched_patterns,
                                                "session": session_id,
                                                "blocking": state.injection_blocking,
                                            }),
                                        );
                                        let desc_verdict = Verdict::Deny {
                                            reason: audit_reason,
                                        };
                                        let desc_security_context =
                                            tool_discovery_integrity_security_context(
                                                &finding.tool_name,
                                                vellaveto_types::ContextChannel::CommandLike,
                                                "tool_description_injection",
                                                true,
                                            );
                                        let envelope =
                                            build_secondary_acis_envelope_with_security_context(
                                                &action,
                                                &desc_verdict,
                                                DecisionOrigin::InjectionScanner,
                                                "http",
                                                Some(session_id),
                                                Some(&desc_security_context),
                                            );
                                        if let Err(e) = state.audit.log_entry_with_acis(
                                            &action,
                                            &desc_verdict,
                                            json!({"source": "http_proxy", "event": "tool_description_injection"}),
                                            envelope,
                                        ).await {
                                            tracing::warn!("Failed to audit tool description injection: {}", e);
                                            // SECURITY (R272-HTTP-1): strict audit mode. The request id is
                                            // not in scope on this response path, so the denial carries a
                                            // null id; the client correlates by the in-flight request.
                                            if let Some(deny) = super::handlers::audit_strict_deny(state, None, session_id) {
                                                return deny;
                                            }
                                        }
                                    }
                                }

                                // Phase 5: Verify tool manifest if configured
                                if let Some(ref manifest_cfg) = state.manifest_config {
                                    verify_manifest_from_response(
                                        &response_json,
                                        session_id,
                                        &state.sessions,
                                        manifest_cfg,
                                        &state.audit,
                                    )
                                    .await;
                                }

                                // Extract protocol version from initialize responses
                                if let Some(ver) = response_json
                                    .get("result")
                                    .and_then(|r| r.get("protocolVersion"))
                                    .and_then(|v| v.as_str())
                                {
                                    if let Some(mut session) = state.sessions.get_mut(session_id) {
                                        session.protocol_version = Some(ver.to_string());
                                        tracing::info!(
                                            "Session {}: negotiated protocol version {}",
                                            session_id,
                                            ver
                                        );
                                    }
                                }

                                // MCP 2025-06-18: Register output schemas from tools/list
                                state
                                    .output_schema_registry
                                    .register_from_tools_list(&response_json);

                                // MCP 2025-06-18: Validate structuredContent against registered schemas
                                if let Some(structured) = result.get("structuredContent") {
                                    let meta_tool_name = result
                                        .get("_meta")
                                        .and_then(|m| m.get("tool"))
                                        .and_then(|t| t.as_str());
                                    let tool_name = match (
                                        meta_tool_name,
                                        tracked_tool_name.as_deref(),
                                    ) {
                                        (Some(meta), Some(tracked))
                                            if !meta.eq_ignore_ascii_case(tracked) =>
                                        {
                                            tracing::warn!(
                                                "SECURITY: structuredContent tool mismatch (meta='{}', tracked='{}'); using tracked tool name",
                                                meta,
                                                tracked
                                            );
                                            tracked
                                        }
                                        (Some(meta), _) => meta,
                                        (None, Some(tracked)) => tracked,
                                        (None, None) => "unknown",
                                    };
                                    match state
                                        .output_schema_registry
                                        .validate(tool_name, structured)
                                    {
                                        ValidationResult::Invalid { violations } => {
                                            injection_detected = true;
                                            tracing::warn!(
                                                "SECURITY: structuredContent validation failed for tool '{}': {:?}",
                                                tool_name, violations
                                            );
                                            let action = Action::new(
                                                "vellaveto",
                                                "output_schema_violation",
                                                json!({
                                                    "tool": tool_name,
                                                    "violations": violations,
                                                    "session": session_id,
                                                }),
                                            );
                                            let schema_verdict = Verdict::Deny {
                                                reason: format!(
                                                    "structuredContent validation failed: {violations:?}"
                                                ),
                                            };
                                            let schema_security_context =
                                                output_schema_violation_security_context(
                                                    Some(tool_name),
                                                    true,
                                                );
                                            let envelope =
                                                build_secondary_acis_envelope_with_security_context(
                                                    &action,
                                                    &schema_verdict,
                                                    DecisionOrigin::PolicyEngine,
                                                    "http",
                                                    Some(session_id),
                                                    Some(&schema_security_context),
                                                );
                                            if let Err(e) = state.audit.log_entry_with_acis(
                                                &action,
                                                &schema_verdict,
                                                json!({"source": "http_proxy", "event": "output_schema_violation"}),
                                                envelope,
                                            ).await {
                                                tracing::warn!("Failed to audit output schema violation: {}", e);
                                                // SECURITY (R272-HTTP-1): strict audit mode. The request id is
                                                // not in scope on this response path, so the denial carries a
                                                // null id; the client correlates by the in-flight request.
                                                if let Some(deny) = super::handlers::audit_strict_deny(state, None, session_id) {
                                                    return deny;
                                                }
                                            }
                                            // SECURITY (R29-PROXY-2): Actually block the
                                            // response — previously only logged Deny but
                                            // forwarded the invalid structuredContent.
                                            if blocked_by_injection.is_none() {
                                                blocked_by_injection = Some(
                                                    "Response blocked: output schema validation failed".to_string(),
                                                );
                                            }
                                        }
                                        ValidationResult::Valid => {
                                            tracing::debug!(
                                                "structuredContent validated for tool '{}'",
                                                tool_name
                                            );
                                        }
                                        ValidationResult::NoSchema => {
                                            tracing::debug!(
                                                "No output schema registered for tool '{}', skipping validation",
                                                tool_name
                                            );
                                        }
                                    }
                                }
                            }

                            // Scan error fields for injection — malicious MCP servers can
                            // embed prompt injection in error messages relayed to the agent.
                            if let Some(error) = response_json.get("error") {
                                if !state.injection_disabled {
                                    let mut error_text_parts: Vec<String> = Vec::new();
                                    if let Some(msg) = error.get("message").and_then(|m| m.as_str())
                                    {
                                        error_text_parts.push(msg.to_string());
                                    }
                                    if let Some(data) = error.get("data") {
                                        if let Some(data_str) = data.as_str() {
                                            error_text_parts.push(data_str.to_string());
                                        } else {
                                            error_text_parts.push(data.to_string());
                                        }
                                    }
                                    let error_text = error_text_parts.join("\n");
                                    if !error_text.is_empty() {
                                        let matches: Vec<String> =
                                            if let Some(ref scanner) = state.injection_scanner {
                                                scanner
                                                    .inspect(&error_text)
                                                    .into_iter()
                                                    .map(|s| s.to_string())
                                                    .collect()
                                            } else {
                                                inspect_for_injection(&error_text)
                                                    .into_iter()
                                                    .map(|s| s.to_string())
                                                    .collect()
                                            };
                                        if !matches.is_empty() {
                                            injection_detected = true;
                                            tracing::warn!(
                                                "SECURITY: Potential prompt injection in error response! \
                                                 Session: {}, Patterns: {:?}",
                                                session_id,
                                                matches
                                            );
                                            // SECURITY: Block when injection_blocking is enabled.
                                            let verdict = if state.injection_blocking {
                                                // SECURITY (R12-RESP-9): Generic message to client.
                                                let audit_reason = format!(
                                                    "Error response blocked: prompt injection detected ({})",
                                                    matches.join(", ")
                                                );
                                                if blocked_by_injection.is_none() {
                                                    blocked_by_injection =
                                                        Some("Response blocked: security policy violation".to_string());
                                                }
                                                Verdict::Deny {
                                                    reason: audit_reason,
                                                }
                                            } else {
                                                Verdict::Allow
                                            };
                                            let action = Action::new(
                                                "vellaveto",
                                                "error_response_inspection",
                                                json!({
                                                    "matched_patterns": matches,
                                                    "session": session_id,
                                                    "blocking": state.injection_blocking,
                                                }),
                                            );
                                            let injection_security_context =
                                                response_injection_security_context(
                                                    None,
                                                    &response_json,
                                                    state.injection_blocking,
                                                    "error_response_injection",
                                                );
                                            let envelope =
                                                build_secondary_acis_envelope_with_security_context(
                                                    &action,
                                                    &verdict,
                                                    DecisionOrigin::InjectionScanner,
                                                    "http",
                                                    Some(session_id),
                                                    Some(&injection_security_context),
                                                );
                                            if let Err(e) = state
                                                .audit
                                                .log_entry_with_acis(
                                                    &action,
                                                    &verdict,
                                                    json!({
                                                        "source": "http_proxy",
                                                        "event": "prompt_injection_in_error",
                                                    }),
                                                    envelope,
                                                )
                                                .await
                                            {
                                                tracing::warn!(
                                                    "Failed to audit error injection detection: {}",
                                                    e
                                                );
                                            }
                                        }
                                    }
                                }
                            }

                            // NOTE: record_response moved AFTER injection/DLP blocking checks
                            // (R26-MCP-1) to avoid recording fingerprints from blocked responses.
                        }

                        // DLP response scanning: detect secrets in tool responses.
                        let mut blocked_by_dlp: Option<String> = None;
                        // SECURITY (R36-PROXY-1): Track DLP detection separately from
                        // blocking. Even in log-only mode, tainted responses must not
                        // be fingerprinted by the memory tracker.
                        let mut dlp_detected = false;
                        if state.response_dlp_enabled {
                            if let Ok(response_json) = serde_json::from_slice::<Value>(&body_bytes)
                            {
                                let dlp_findings = scan_response_for_secrets(&response_json);
                                if !dlp_findings.is_empty() {
                                    // IMPROVEMENT_PLAN 1.1: Record DLP metrics
                                    for finding in &dlp_findings {
                                        record_dlp_finding(&finding.pattern_name);
                                    }
                                    dlp_detected = true;
                                    let patterns: Vec<String> = dlp_findings
                                        .iter()
                                        .map(|f| format!("{}:{}", f.pattern_name, f.location))
                                        .collect();
                                    tracing::warn!(
                                        "SECURITY: Secrets detected in tool response! \
                                         Session: {}, Findings: {:?}, Blocking: {}",
                                        session_id,
                                        patterns,
                                        state.response_dlp_blocking,
                                    );

                                    // SECURITY (R18-DLP-BLOCK): When blocking is enabled,
                                    // record the reason so we can return an error instead
                                    // of forwarding the secret-containing response.
                                    // SECURITY (R111-001): Use a generic client-facing message to
                                    // avoid leaking internal DLP pattern names to the caller.
                                    if state.response_dlp_blocking {
                                        blocked_by_dlp = Some(
                                            "Response blocked: sensitive content detected"
                                                .to_string(),
                                        );
                                    }

                                    let verdict = if state.response_dlp_blocking {
                                        Verdict::Deny {
                                            reason: format!("Response DLP blocked: {patterns:?}"),
                                        }
                                    } else {
                                        Verdict::Allow
                                    };
                                    let action = Action::new(
                                        "vellaveto",
                                        "response_dlp_scan",
                                        json!({
                                            "findings": patterns,
                                            "session": session_id,
                                            "finding_count": dlp_findings.len(),
                                        }),
                                    );
                                    let dlp_security_context = response_dlp_security_context(
                                        tracked_response_tool_name.as_deref(),
                                        &response_json,
                                        state.response_dlp_blocking,
                                    );
                                    let envelope =
                                        build_secondary_acis_envelope_with_security_context(
                                            &action,
                                            &verdict,
                                            DecisionOrigin::Dlp,
                                            "http",
                                            Some(session_id),
                                            Some(&dlp_security_context),
                                        );
                                    if let Err(e) = state
                                        .audit
                                        .log_entry_with_acis(
                                            &action,
                                            &verdict,
                                            json!({
                                                "source": "http_proxy",
                                                "event": "response_dlp_alert",
                                                "blocked": state.response_dlp_blocking,
                                                "dlp_detail": format!(
                                                    "Secrets detected in response: {:?}",
                                                    patterns
                                                ),
                                            }),
                                            envelope,
                                        )
                                        .await
                                    {
                                        tracing::warn!(
                                            "Failed to audit response DLP finding: {}",
                                            e
                                        );
                                    }
                                }
                            }
                        }

                        // SECURITY: If injection_blocking is enabled and injection was
                        // detected, return a sanitized error instead of the unsafe response.
                        if let Some(reason) = blocked_by_injection {
                            return (
                                StatusCode::OK,
                                Json(json!({
                                    "jsonrpc": "2.0",
                                    "error": {
                                        "code": -32001,
                                        "message": reason,
                                    },
                                })),
                            )
                                .into_response();
                        }

                        // SECURITY (R18-DLP-BLOCK): If response DLP blocking is enabled
                        // and secrets were detected, return a sanitized error.
                        if let Some(reason) = blocked_by_dlp {
                            return (
                                StatusCode::OK,
                                Json(json!({
                                    "jsonrpc": "2.0",
                                    "error": {
                                        "code": -32002,
                                        "message": reason,
                                    },
                                })),
                            )
                                .into_response();
                        }

                        // OWASP ASI06 (R26-MCP-1, R36-PROXY-1): Record response fingerprints
                        // for memory poisoning detection ONLY if injection and DLP scanning
                        // found no issues. This uses detection flags (not blocking flags)
                        // so that log-only mode also prevents tainted fingerprinting.
                        // Previously, log-only mode left blocked_by_injection/blocked_by_dlp
                        // as None, allowing tainted responses to be fingerprinted.
                        if !injection_detected && !dlp_detected {
                            if let Ok(response_json) = serde_json::from_slice::<Value>(&body_bytes)
                            {
                                if let Some(mut session) = state.sessions.get_mut(session_id) {
                                    session.memory_tracker.record_response(&response_json);
                                }
                            }
                        }

                        // SECURITY: Seal multi-round-trip requestState before it
                        // reaches the model-visible channel, then attach optional
                        // content-bound attestation to the same JSON envelope.
                        let final_body = if let Ok(mut response_json) =
                            serde_json::from_slice::<Value>(&body_bytes)
                        {
                            let has_request_state = response_json
                                .get("result")
                                .and_then(Value::as_object)
                                .is_some_and(|result| result.contains_key("requestState"));
                            if has_request_state {
                                let Some(mut session) = state.sessions.get_mut(session_id) else {
                                    tracing::warn!(
                                        session_id = %session_id,
                                        "SECURITY: Upstream emitted requestState without session state"
                                    );
                                    return (
                                        StatusCode::BAD_GATEWAY,
                                        Json(json!({
                                            "jsonrpc": "2.0",
                                            "error": {
                                                "code": -32000,
                                                "message": "Upstream response rejected"
                                            },
                                            "id": null
                                        })),
                                    )
                                        .into_response();
                                };
                                match request_state::seal_response_request_state(
                                    &mut response_json,
                                    &mut session,
                                ) {
                                    Ok(true) => {
                                        tracing::debug!(
                                            session_id = %session_id,
                                            "Sealed upstream requestState continuation"
                                        );
                                    }
                                    Ok(false) => {}
                                    Err(error) => {
                                        tracing::warn!(
                                            session_id = %session_id,
                                            reason = error.message(),
                                            "SECURITY: Rejecting upstream requestState"
                                        );
                                        return (
                                            StatusCode::BAD_GATEWAY,
                                            Json(json!({
                                                "jsonrpc": "2.0",
                                                "error": {
                                                    "code": -32000,
                                                    "message": "Upstream response rejected"
                                                },
                                                "id": null
                                            })),
                                        )
                                            .into_response();
                                    }
                                }
                            }

                            // SECURITY: Content-bound attestation — sign scan
                            // results + content hash. Attached AFTER all scanning
                            // but BEFORE forwarding to the client.
                            if let Some(ref hmac_key) = state.attestation_hmac_key {
                                use vellaveto_types::security_context_token::{
                                    hash_content, mint_attestation,
                                };

                                let content_to_hash = response_json
                                    .get("result")
                                    .or_else(|| response_json.get("error"))
                                    .cloned()
                                    .unwrap_or(Value::Null);
                                let content_hash = hash_content(&content_to_hash);

                                let trust_tier = "Untrusted";

                                if let Ok(token) = mint_attestation(
                                    &content_hash,
                                    !injection_detected,
                                    !dlp_detected,
                                    true, // schema_valid — no schema violation survived to here
                                    trust_tier,
                                    5, // scan_passes
                                    hmac_key,
                                ) {
                                    if let Some(obj) = response_json.as_object_mut() {
                                        let meta = obj
                                            .entry("_meta")
                                            .or_insert_with(|| serde_json::json!({}));
                                        if let Some(meta_obj) = meta.as_object_mut() {
                                            if let Ok(token_val) = serde_json::to_value(&token) {
                                                meta_obj.insert(
                                                    "vellaveto_attestation".to_string(),
                                                    token_val,
                                                );
                                            }
                                        }
                                    }
                                }
                            }

                            match serde_json::to_vec(&response_json) {
                                Ok(bytes) => Bytes::from(bytes),
                                Err(error) => {
                                    tracing::error!(
                                        session_id = %session_id,
                                        "Failed to serialize sealed upstream response: {}",
                                        error
                                    );
                                    return (
                                        StatusCode::BAD_GATEWAY,
                                        Json(json!({
                                            "jsonrpc": "2.0",
                                            "error": {
                                                "code": -32000,
                                                "message": "Upstream response rejected"
                                            },
                                            "id": null
                                        })),
                                    )
                                        .into_response();
                                }
                            }
                        } else {
                            body_bytes
                        };

                        // Forward the raw bytes (no injection/DLP blocking triggered)
                        // SECURITY (R12-RESP-10): Do NOT copy Mcp-Session-Id from upstream.
                        // The proxy is the session authority — see SSE path comment above.
                        Response::builder()
                            .status(status)
                            .header("content-type", "application/json")
                            .body(Body::from(final_body))
                            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
                    }
                    Err(e) => {
                        tracing::error!("Failed to read upstream response body: {}", e);
                        (
                            StatusCode::BAD_GATEWAY,
                            Json(json!({
                                "jsonrpc": "2.0",
                                "error": {
                                    "code": -32000,
                                    "message": "Upstream server error"
                                },
                                "id": null
                            })),
                        )
                            .into_response()
                    }
                }
            }
        }
        Err(e) => {
            tracing::error!("Failed to connect to upstream: {}", e);
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32000,
                        "message": "Upstream server unavailable"
                    },
                    "id": null
                })),
            )
                .into_response()
        }
    }
}
