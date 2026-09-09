// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! HTTP handler functions: handle_mcp_post, handle_mcp_delete,
//! and handle_protected_resource_metadata.

use axum::{
    extract::{OriginalUri, Query, State},
    http::{
        header::{HeaderName, HeaderValue},
        HeaderMap, StatusCode,
    },
    response::{IntoResponse, Response},
    Extension, Json,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use bytes::Bytes;
use serde_json::{json, Value};
use std::collections::HashSet;
use vellaveto_mcp::extractor::{self, make_denial_response, MessageType};
use vellaveto_mcp::inspection::{
    inspect_for_injection, scan_notification_for_secrets, scan_parameters_for_secrets,
    scan_response_for_secrets,
};
use vellaveto_mcp::mediation::{
    build_acis_envelope_with_security_context, build_secondary_acis_envelope_with_security_context,
    mediate_with_security_context,
};
use vellaveto_mcp::wire::{CanonicalMessageKind, CanonicalRequest};
use vellaveto_types::acis::DecisionOrigin;
use vellaveto_types::McpProtocolVersion;
use vellaveto_types::{
    has_dangerous_chars, is_unicode_format_char, Action, EvaluationContext, Verdict,
};

use super::auth::{
    build_effective_request_uri, validate_agent_identity, validate_api_key, validate_oauth,
};
use super::call_chain::{
    build_audit_context, build_audit_context_with_chain, build_current_agent_entry,
    build_evaluation_context, check_privilege_escalation, sync_session_call_chain_from_headers,
    track_pending_tool_call, validate_call_chain_header, MAX_ACTION_HISTORY, MAX_CALL_COUNT_TOOLS,
};
use super::helpers::{
    abac_deny_security_context, approval_containment_context_from_envelope,
    approval_containment_context_from_security_context, batch_rejection_security_context,
    build_runtime_security_context, circuit_breaker_security_context, consume_presented_approval,
    create_pending_approval_with_context, elicitation_interception_security_context,
    extract_approval_id_from_meta, invalid_call_chain_security_context,
    invalid_presented_approval_security_context, memory_poisoning_security_context,
    merge_transport_security_context, notification_dlp_security_context,
    notification_injection_security_context, notification_memory_poisoning_security_context,
    parameter_dlp_security_context, parameter_injection_security_context,
    presented_approval_matches_action, privilege_escalation_security_context,
    protocol_forward_security_context, protocol_rejection_security_context, resolve_domains,
    response_dlp_security_context, response_injection_security_context, rug_pull_security_context,
    sampling_interception_security_context, session_termination_security_context,
    transport_failure_security_context, unknown_tool_approval_gate_security_context,
    untrusted_tool_approval_gate_security_context, TransportSecurityInputs,
};
use super::inspection::{attach_session_header, attach_trace_header};
use super::origin::validate_origin;
use super::request_state;
use super::trace_propagation;
use super::upstream::{
    canonicalize_body, forward_to_upstream, forward_to_upstream_url, make_jsonrpc_error,
    UpstreamForwardOptions,
};
use super::{
    McpQueryParams, ProxyState, TrustedProxyContext, MCP_METHOD_HEADER, MCP_NAME_HEADER,
    MCP_PROTOCOL_VERSION_HEADER, MCP_SESSION_ID,
};
use crate::proxy_metrics::record_dlp_finding;
use crate::session::ToolParamHeaderBindings;

// NOTE: MAX_RESPONSE_BODY_SIZE and MAX_SSE_EVENT_SIZE are now configurable
// via state.limits.max_response_body_bytes and state.limits.max_sse_event_bytes.
// See vellaveto_config::LimitsConfig for documentation and defaults.

/// FIND-R56-HTTP-007: Maximum length for MCP session IDs.
/// Server-generated IDs are UUIDs (36 chars); anything over 128 is suspicious.
const MAX_SESSION_ID_LENGTH: usize = 128;
const MAX_ROUTING_HEADER_BYTES: usize = 512;
const MCP_PARAM_HEADER_PREFIX: &str = "mcp-param-";
const MAX_MCP_PARAM_HEADERS: usize = 32;
const MAX_MCP_PARAM_HEADER_VALUE_BYTES: usize = 2048;
const MAX_MCP_PARAM_HEADER_TOTAL_BYTES: usize = 8192;
const INVALID_PRESENTED_APPROVAL_REASON: &str = "Supplied approval is not valid for this action";

pub(super) type ForwardedMcpParamHeaders = Vec<(HeaderName, HeaderValue)>;

fn protocol_version_error(message: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "jsonrpc": "2.0",
            "error": {
                "code": -32600,
                "message": message.into()
            },
            "id": null
        })),
    )
        .into_response()
}

fn adapter_deny_response(deny: &vellaveto_mcp::wire::AdapterDeny) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "jsonrpc": "2.0",
            "error": {
                "code": deny.code,
                "message": "Invalid request metadata"
            },
            "id": deny.id.clone().unwrap_or(Value::Null)
        })),
    )
        .into_response()
}

fn routing_header_error(message: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "jsonrpc": "2.0",
            "error": {
                "code": -32600,
                "message": message.into()
            },
            "id": null
        })),
    )
        .into_response()
}

fn mcp_param_header_error(message: impl Into<String>, id: Option<&Value>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "jsonrpc": "2.0",
            "error": {
                "code": -32600,
                "message": message.into()
            },
            "id": id.cloned().unwrap_or(Value::Null)
        })),
    )
        .into_response()
}

fn request_state_error(error: request_state::RequestStateError, id: Option<&Value>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "jsonrpc": "2.0",
            "error": {
                "code": -32600,
                "message": error.message()
            },
            "id": id.cloned().unwrap_or(Value::Null)
        })),
    )
        .into_response()
}

/// Deny a request whose audit entry could not be written, under strict mode.
///
/// SECURITY (FIND-CREATIVE-003, extended by R272-HTTP-1): `audit.strict_mode`
/// promises that "audit logging failures cause requests to be denied instead of
/// proceeding without an audit trail … every decision must be recorded". This
/// handler honoured that at 8 of its 47 audit-failure sites; the other 39
/// logged and carried on, so the same operator setting meant different things
/// depending on which branch a request took.
///
/// The 8 were hand-rolled copies of an identical block. gRPC already learned
/// this lesson and has `audit_strict_deny` (`grpc/service.rs:248`), though two
/// sites there bypass it — drift that started the same way. One function per
/// transport is what keeps the branches in step.
///
/// Returns `Some(response)` when strict mode demands fail-closed, so callers
/// read `if let Some(deny) = … { return deny; }`. `None` preserves the
/// documented default: log the failure and continue.
pub(super) fn audit_strict_deny(
    state: &ProxyState,
    id: Option<&Value>,
    session_id: &str,
) -> Option<Response> {
    if !state.audit_strict_mode {
        return None;
    }
    Some(attach_session_header(
        make_jsonrpc_error(
            id,
            -32000,
            "Audit logging failed — request denied (strict audit mode)",
        ),
        session_id,
    ))
}

pub(super) fn validate_mcp_protocol_version_header(
    state: &ProxyState,
    headers: &HeaderMap,
) -> Result<Option<McpProtocolVersion>, Box<Response>> {
    let supported = state.streamable_http.supported_protocol_versions();

    let Some(version_hdr) = headers.get(MCP_PROTOCOL_VERSION_HEADER) else {
        if state.streamable_http.require_protocol_version_header {
            tracing::warn!(
                "Inbound request missing required {} header",
                MCP_PROTOCOL_VERSION_HEADER
            );
            return Err(Box::new(protocol_version_error(
                "Missing MCP-Protocol-Version header",
            )));
        }

        tracing::debug!(
            "Inbound request missing optional {} header",
            MCP_PROTOCOL_VERSION_HEADER
        );
        return Ok(None);
    };

    let version = version_hdr.to_str().map_err(|_| {
        tracing::warn!("Invalid UTF-8 in {} header", MCP_PROTOCOL_VERSION_HEADER);
        Box::new(protocol_version_error(
            "Invalid MCP-Protocol-Version header encoding",
        ))
    })?;

    let parsed = version.parse::<McpProtocolVersion>().map_err(|_| {
        tracing::warn!(
            "Unknown MCP protocol version: '{}', supported: {:?}",
            version,
            supported
        );
        Box::new(protocol_version_error(format!(
            "Unsupported MCP protocol version. Supported versions: {}",
            supported.join(", ")
        )))
    })?;

    if !state.streamable_http.allows_protocol_version(parsed) {
        tracing::warn!(
            "MCP protocol version '{}' is below configured floor '{}'",
            parsed,
            state.streamable_http.protocol_version_floor
        );
        return Err(Box::new(protocol_version_error(format!(
            "MCP protocol version is below configured floor {}. Supported versions: {}",
            state.streamable_http.protocol_version_floor,
            supported.join(", ")
        ))));
    }

    Ok(Some(parsed))
}

fn read_routing_header<'a>(
    headers: &'a HeaderMap,
    header_name: &'static str,
) -> Result<Option<&'a str>, Box<Response>> {
    let Some(value) = headers.get(header_name) else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| {
        Box::new(routing_header_error(format!(
            "Invalid {header_name} header encoding"
        )))
    })?;
    if value.is_empty() {
        return Err(Box::new(routing_header_error(format!(
            "{header_name} header must not be empty"
        ))));
    }
    if value.len() > MAX_ROUTING_HEADER_BYTES {
        return Err(Box::new(routing_header_error(format!(
            "{header_name} header exceeds size limit"
        ))));
    }
    if has_dangerous_chars(value) {
        return Err(Box::new(routing_header_error(format!(
            "{header_name} header contains control or format characters"
        ))));
    }
    Ok(Some(value))
}

pub(super) fn validate_mcp_routing_headers(
    protocol_version: McpProtocolVersion,
    headers: &HeaderMap,
    msg: &Value,
    canonical: &CanonicalRequest,
) -> Result<(), Box<Response>> {
    let method_header = read_routing_header(headers, MCP_METHOD_HEADER)?;
    let name_header = read_routing_header(headers, MCP_NAME_HEADER)?;
    let must_have_routing_headers = protocol_version == McpProtocolVersion::V2026_07_28
        && matches!(
            canonical.kind,
            CanonicalMessageKind::Request | CanonicalMessageKind::Notification
        );

    if must_have_routing_headers && method_header.is_none() {
        return Err(Box::new(routing_header_error("Missing Mcp-Method header")));
    }

    if let Some(header_method) = method_header {
        let Some(body_method) = msg.get("method").and_then(Value::as_str) else {
            return Err(Box::new(routing_header_error(
                "Mcp-Method header is not valid for messages without a method",
            )));
        };
        if header_method != body_method {
            tracing::warn!(
                mcp_method_header = %header_method,
                body_method = %body_method,
                "MCP routing method header/body disagreement"
            );
            return Err(Box::new(routing_header_error(
                "Mcp-Method header does not match JSON-RPC method",
            )));
        }
    }

    let body_name = msg
        .get("params")
        .and_then(|params| params.get("name"))
        .and_then(Value::as_str);

    if must_have_routing_headers && body_name.is_some() && name_header.is_none() {
        return Err(Box::new(routing_header_error("Missing Mcp-Name header")));
    }

    if let Some(header_name) = name_header {
        let Some(body_name) = body_name else {
            return Err(Box::new(routing_header_error(
                "Mcp-Name header is not valid for messages without params.name",
            )));
        };
        if header_name != body_name {
            tracing::warn!(
                mcp_name_header = %header_name,
                body_name = %body_name,
                "MCP routing name header/body disagreement"
            );
            return Err(Box::new(routing_header_error(
                "Mcp-Name header does not match JSON-RPC params.name",
            )));
        }
    }

    Ok(())
}

fn validate_mcp_param_header_value(header_name: &str, value: &HeaderValue) -> Result<(), String> {
    let value = value
        .to_str()
        .map_err(|_| format!("{header_name} header value must be visible ASCII or encoded"))?;
    if value.len() > MAX_MCP_PARAM_HEADER_VALUE_BYTES {
        return Err(format!("{header_name} header value exceeds size limit"));
    }
    if has_dangerous_chars(value) {
        return Err(format!(
            "{header_name} header value contains control or format characters"
        ));
    }

    let lower = value.to_ascii_lowercase();
    if lower.starts_with("=?base64?") && value.ends_with("?=") {
        let encoded = &value["=?base64?".len()..value.len() - "?=".len()];
        BASE64_STANDARD
            .decode(encoded)
            .map_err(|_| format!("{header_name} header value has invalid base64 encoding"))?;
    }

    Ok(())
}

pub(super) fn validate_mcp_param_headers(
    state: &ProxyState,
    headers: &HeaderMap,
    msg: &Value,
) -> Result<ForwardedMcpParamHeaders, Box<Response>> {
    let id = msg.get("id");
    let allowed: HashSet<String> = state
        .streamable_http
        .allowed_mcp_param_headers
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect();
    let is_tool_call = msg
        .get("method")
        .and_then(Value::as_str)
        .is_some_and(|method| method == "tools/call");
    let mut forwarded = Vec::new();
    let mut seen = HashSet::new();
    let mut total_bytes = 0usize;

    for (name, value) in headers {
        let header_name = name.as_str();
        let Some(suffix) = header_name.strip_prefix(MCP_PARAM_HEADER_PREFIX) else {
            continue;
        };

        if !is_tool_call {
            return Err(Box::new(mcp_param_header_error(
                "Mcp-Param headers are only valid for tools/call requests",
                id,
            )));
        }

        vellaveto_config::validate_mcp_param_header_name(suffix).map_err(|reason| {
            Box::new(mcp_param_header_error(
                format!("Invalid {header_name} header: {reason}"),
                id,
            ))
        })?;

        let suffix_lower = suffix.to_ascii_lowercase();
        if !seen.insert(suffix_lower.clone()) {
            return Err(Box::new(mcp_param_header_error(
                format!("Duplicate {header_name} header"),
                id,
            )));
        }

        if !allowed.contains(&suffix_lower) {
            return Err(Box::new(mcp_param_header_error(
                format!("{header_name} header is not allowlisted"),
                id,
            )));
        }

        validate_mcp_param_header_value(header_name, value)
            .map_err(|reason| Box::new(mcp_param_header_error(reason, id)))?;

        total_bytes = total_bytes
            .saturating_add(header_name.len())
            .saturating_add(value.len());
        if forwarded.len() >= MAX_MCP_PARAM_HEADERS
            || total_bytes > MAX_MCP_PARAM_HEADER_TOTAL_BYTES
        {
            return Err(Box::new(mcp_param_header_error(
                "Mcp-Param headers exceed count or size limits",
                id,
            )));
        }

        forwarded.push((name.clone(), value.clone()));
    }

    Ok(forwarded)
}

pub(super) fn validate_observed_mcp_param_headers(
    state: &ProxyState,
    session_id: &str,
    tool_name: &str,
    headers: &ForwardedMcpParamHeaders,
    id: &Value,
) -> Result<(), Box<Response>> {
    let Some(session) = state.sessions.get_mut(session_id) else {
        return Err(Box::new(mcp_param_header_error(
            "Mcp-Param headers cannot be validated without session state",
            Some(id),
        )));
    };

    let Some(bindings) = session.tool_param_header_bindings().get(tool_name) else {
        if headers.is_empty() {
            return Ok(());
        }
        return Err(Box::new(mcp_param_header_error(
            "Mcp-Param headers require an observed x-mcp-header tool definition",
            Some(id),
        )));
    };

    match bindings {
        ToolParamHeaderBindings::Rejected(reason) => Err(Box::new(mcp_param_header_error(
            format!("Tool definition rejected: {reason}"),
            Some(id),
        ))),
        ToolParamHeaderBindings::Valid(allowed_by_schema) => {
            for (header_name, _) in headers {
                let suffix = header_name
                    .as_str()
                    .strip_prefix(MCP_PARAM_HEADER_PREFIX)
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                if !allowed_by_schema.contains(&suffix) {
                    return Err(Box::new(mcp_param_header_error(
                        format!(
                            "{} header was not declared by the tool's x-mcp-header schema",
                            header_name.as_str()
                        ),
                        Some(id),
                    )));
                }
            }
            Ok(())
        }
    }
}

/// Main POST /mcp handler.
///
/// Implements the Streamable HTTP transport:
/// 1. Validate OAuth token (if configured)
/// 2. Parse JSON-RPC body
/// 3. Manage session via Mcp-Session-Id header
/// 4. Classify and evaluate the message
/// 5. Forward allowed requests to upstream, return denials directly
pub async fn handle_mcp_post(
    State(state): State<ProxyState>,
    OriginalUri(original_uri): OriginalUri,
    Query(params): Query<McpQueryParams>,
    proxy_ctx: Option<Extension<TrustedProxyContext>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut body = body;

    // SECURITY (R8-HTTP-2): Validate Content-Type is application/json.
    // The MCP Streamable HTTP spec requires JSON content. Rejecting other
    // content types prevents bypass of WAF rules and request smuggling.
    if let Some(ct) = headers.get("content-type").and_then(|v| v.to_str().ok()) {
        if !ct.starts_with("application/json") {
            return (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                Json(json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32700,
                        "message": "Content-Type must be application/json"
                    }
                })),
            )
                .into_response();
        }
    }
    // If Content-Type is absent, allow it for backwards compatibility with
    // clients that don't set headers (POST body is still parsed as JSON).

    let protocol_version = match validate_mcp_protocol_version_header(&state, &headers) {
        Ok(Some(version)) => version,
        Ok(None) => state.streamable_http.protocol_version_floor,
        Err(response) => return *response,
    };

    // CSRF / DNS rebinding origin validation (TASK-015)
    if let Err(response) = validate_origin(&headers, &state.bind_addr, &state.allowed_origins) {
        return response;
    }

    // API key validation (if configured) — fast check before OAuth
    if let Err(response) = validate_api_key(&state, &headers) {
        return response;
    }

    // SECURITY (FIND-R73-SRV-011): Validate session ID length and reject control/format
    // characters before OAuth, matching the DELETE handler pattern.
    // SECURITY (FIND-R86-001): Also reject Unicode format characters (zero-width, bidi)
    // for parity with gRPC and WebSocket handlers.
    let client_session_id = headers
        .get(MCP_SESSION_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|id| {
            id.len() <= MAX_SESSION_ID_LENGTH
                && !id
                    .chars()
                    .any(|c| c.is_control() || is_unicode_format_char(c))
        });

    // If the header was present but filtered out, return 400.
    if headers.get(MCP_SESSION_ID).is_some() && client_session_id.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid session ID"}, "id": null})),
        )
            .into_response();
    }

    // OAuth 2.1 token validation (if configured)
    let from_trusted_proxy = proxy_ctx
        .map(|Extension(ctx)| ctx.from_trusted_proxy)
        .unwrap_or(false);
    let effective_uri =
        build_effective_request_uri(&headers, state.bind_addr, &original_uri, from_trusted_proxy);
    let oauth_claims =
        match validate_oauth(&state, &headers, "POST", &effective_uri, client_session_id).await {
            Ok(claims) => claims,
            Err(response) => return response,
        };
    // OWASP ASI07: Agent identity attestation via X-Agent-Identity JWT
    let agent_identity = match validate_agent_identity(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };

    // Phase 28: Extract W3C Trace Context from incoming request headers.
    // Creates a new trace context if none is present (fail-open for observability).
    let incoming_trace = trace_propagation::extract_trace_context(&headers);
    let (vellaveto_trace_ctx, _vellaveto_span_id) =
        trace_propagation::create_vellaveto_span(&incoming_trace);

    // Defense-in-depth: reject JSON with duplicate keys before parsing.
    // Prevents parser-disagreement attacks (CVE-2017-12635, CVE-2020-16250)
    // where the proxy evaluates one key value but upstream sees another.
    if let Ok(raw_str) = std::str::from_utf8(&body) {
        if let Some(dup_key) = vellaveto_mcp::framing::find_duplicate_json_key(raw_str) {
            tracing::warn!(
                "SECURITY: Rejected JSON-RPC message with duplicate key: \"{}\"",
                dup_key
            );
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32700,
                        "message": "Parse error: duplicate JSON key detected"
                    },
                    "id": null
                })),
            )
                .into_response();
        }
    }

    // Parse the JSON-RPC body
    let mut msg: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!("JSON-RPC parse error: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32700,
                        "message": "Parse error: invalid JSON"
                    },
                    "id": null
                })),
            )
                .into_response();
        }
    };

    // SECURITY (R258-TRANSPORT-1): JSON-RPC key case-folding smuggling defense.
    // Parity with stdio transport (framing.rs). Rejects top-level keys that
    // case-fold to JSON-RPC 2.0 keys but are not exact-case (CVE-2026-27896).
    if let Some(key) = vellaveto_mcp::framing::check_json_rpc_key_case_folding(&msg) {
        tracing::warn!(
            "SECURITY: Rejected JSON-RPC message with case-folding smuggle key: \"{}\"",
            key
        );
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32600,
                    "message": "Invalid Request: JSON-RPC key case-folding smuggle detected"
                },
                "id": null
            })),
        )
            .into_response();
    }

    match vellaveto_mcp::wire::normalize_inbound(protocol_version, &msg) {
        Ok(canonical) => {
            tracing::trace!(
                protocol_version = %canonical.protocol_version,
                method = %canonical.method,
                name = canonical.name.as_deref().unwrap_or(""),
                kind = ?canonical.kind,
                "Canonicalized inbound MCP request"
            );
            if let Err(response) =
                validate_mcp_routing_headers(protocol_version, &headers, &msg, &canonical)
            {
                return *response;
            }
        }
        Err(deny) => {
            tracing::warn!(
                protocol_version = %protocol_version,
                reason = %deny.message,
                kind = ?deny.kind,
                "MCP wire adapter denied inbound message"
            );
            if deny.kind.enforce_immediately() {
                return adapter_deny_response(&deny);
            }
        }
    }
    let mcp_param_headers = match validate_mcp_param_headers(&state, &headers, &msg) {
        Ok(headers) => headers,
        Err(response) => return *response,
    };

    // Session management
    let session_id = state.sessions.get_or_create(client_session_id);

    // SECURITY (R15-OAUTH-2): Atomic session ownership check + bind.
    if let Some(ref claims) = oauth_claims {
        if let Some(mut session) = state.sessions.get_mut(&session_id) {
            match &session.oauth_subject {
                Some(owner) if owner != &claims.sub => {
                    tracing::warn!(
                        "SECURITY: Session fixation attempt blocked — session {} owned by '{}', request from '{}'",
                        session_id, owner, claims.sub
                    );
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "jsonrpc": "2.0",
                            "error": {"code": -32001, "message": "Session owned by another user"},
                            "id": null
                        })),
                    )
                        .into_response();
                }
                None => {
                    session.oauth_subject = Some(claims.sub.clone());
                    if claims.exp > 0 {
                        session.token_expires_at = Some(claims.exp);
                    }
                }
                _ => {
                    // SECURITY (R23-PROXY-6): Use the EARLIEST token expiry
                    // to prevent a long-lived token from extending a session
                    // that was originally bound to a short-lived token.
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

    // SECURITY (FIND-R55-HTTP-002): Touch session to update last_activity timestamp
    // and increment request_count. Parity with GET handler (line 3015) and WS handler.
    if let Some(mut session) = state.sessions.get_mut(&session_id) {
        session.touch();
    }

    // OWASP ASI07: Store agent identity in session for context-aware evaluation
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
                    "OAuth transport identity claims validation failed: {}",
                    error
                );
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "Invalid authorization token"})),
                )
                    .into_response();
            }
        }
    }

    // Determine if we should pass through the Authorization header to upstream
    let auth_header_for_upstream = if state
        .oauth
        .as_ref()
        .is_some_and(|v| v.config().pass_through)
    {
        headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    } else {
        None
    };

    // OWASP ASI08: Reject malformed X-Upstream-Agents headers for all requests.
    // Previously this validation only ran on a subset of message types
    // (tools/call, resources/read, tasks/*), allowing malformed headers to pass
    // through on other MCP methods.
    // SECURITY (FIND-R44-052): This pre-match check validates the call chain
    // header for ALL message types (ToolCall, ResourceRead, TaskRequest, etc.).
    // Per-arm validate_call_chain_header calls are therefore unnecessary and
    // have been removed to avoid dead code.
    if let Err(reason) = validate_call_chain_header(&headers, &state.limits) {
        let method = msg
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown");
        let action = Action::new(
            "vellaveto",
            "invalid_call_chain_header",
            json!({
                "method": method,
                "reason": reason,
            }),
        );
        let verdict = Verdict::Deny {
            reason: format!("Invalid upstream call chain header: {reason}"),
        };
        let call_chain_security_context = invalid_call_chain_security_context();
        let envelope = build_secondary_acis_envelope_with_security_context(
            &action,
            &verdict,
            DecisionOrigin::PolicyEngine,
            "http",
            Some(&session_id),
            Some(&call_chain_security_context),
        );
        if let Err(e) = state
            .audit
            .log_entry_with_acis(
                &action,
                &verdict,
                build_audit_context(
                    &session_id,
                    json!({
                        "event": "invalid_call_chain_header",
                        "method": method,
                        "reason": reason,
                    }),
                    &oauth_claims,
                ),
                envelope,
            )
            .await
        {
            tracing::warn!("Failed to audit invalid call-chain header: {}", e);
            if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                return deny;
            }
        }

        // SECURITY (FIND-046): Generic message to client; detailed reason in server log.
        tracing::warn!(reason = %reason, "Call chain validation failed");
        let error_response = json!({
            "jsonrpc": "2.0",
            "id": msg.get("id").cloned().unwrap_or(Value::Null),
            "error": {
                "code": -32600,
                "message": "Invalid request"
            }
        });
        return attach_session_header(
            (StatusCode::OK, Json(error_response)).into_response(),
            &session_id,
        );
    }

    let request_state_was_unwrapped = {
        let Some(mut session) = state.sessions.get_mut(&session_id) else {
            return attach_session_header(
                request_state_error(
                    request_state::RequestStateError::MissingSession,
                    msg.get("id"),
                ),
                &session_id,
            );
        };
        match request_state::unwrap_inbound_request_state(&mut msg, &mut session) {
            Ok(was_unwrapped) => was_unwrapped,
            Err(error) => {
                tracing::warn!(
                    session_id = %session_id,
                    reason = error.message(),
                    "SECURITY: Rejected invalid MCP requestState continuation"
                );
                return attach_session_header(
                    request_state_error(error, msg.get("id")),
                    &session_id,
                );
            }
        }
    };
    if request_state_was_unwrapped {
        body = match serde_json::to_vec(&msg) {
            Ok(bytes) => Bytes::from(bytes),
            Err(error) => {
                tracing::error!(
                    session_id = %session_id,
                    "Failed to serialize request after requestState unwrap: {}",
                    error
                );
                return attach_session_header(
                    make_jsonrpc_error(msg.get("id"), -32603, "Internal error"),
                    &session_id,
                );
            }
        };
    }

    let presented_approval_id = extract_approval_id_from_meta(&msg);

    // Classify the message using shared extractor
    match extractor::classify_message(&msg) {
        MessageType::ToolCall {
            id,
            tool_name,
            arguments,
        } => {
            // MCP 2025-11-25: Strict tool name validation (Phase 30).
            // When enabled, reject tool names that don't conform to the spec format.
            if state.streamable_http.strict_tool_name_validation {
                if let Err(e) = vellaveto_types::validate_mcp_tool_name(&tool_name) {
                    tracing::warn!(
                        "SECURITY: Rejecting invalid tool name '{}': {}",
                        tool_name,
                        e
                    );
                    let error_response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32602,
                            "message": "Invalid tool name",
                        }
                    });
                    return attach_session_header(
                        (StatusCode::OK, Json(error_response)).into_response(),
                        &session_id,
                    );
                }
            }

            if let Err(response) = validate_observed_mcp_param_headers(
                &state,
                &session_id,
                &tool_name,
                &mcp_param_headers,
                &id,
            ) {
                return *response;
            }

            // NOTE (FIND-R44-052): validate_call_chain_header is handled by the
            // pre-match check above (line ~289). No per-arm call needed here.

            // OWASP ASI08: Extract call chain from upstream agents header
            // The header contains the chain of agents that have processed this request
            // BEFORE reaching us. This is the "upstream" chain used for depth checking.
            let upstream_chain = sync_session_call_chain_from_headers(
                &state.sessions,
                &session_id,
                &headers,
                state.call_chain_hmac_key.as_ref(),
                &state.limits,
            );

            // Build the full call chain by appending this request's context.
            // This includes ourselves and is used for audit purposes.
            let current_agent_id = oauth_claims.as_ref().map(|c| c.sub.as_str());
            let mut full_call_chain = upstream_chain.clone();
            if !upstream_chain.is_empty() || current_agent_id.is_some() {
                // Only add to chain if this is a multi-hop scenario or we have agent identity
                full_call_chain.push(build_current_agent_entry(
                    current_agent_id,
                    &tool_name,
                    "execute",
                    state.call_chain_hmac_key.as_ref(),
                ));
            }

            // Check rug-pull flags — block calls to tools with changed annotations.
            // SECURITY (R240-PROXY-1): Fall back to global registry when session is
            // missing (evicted by timeout or capacity pressure). This closes the
            // TOCTOU where session eviction dropped flagged_tools.
            let is_flagged = state
                .sessions
                .get_mut(&session_id)
                .map(|s| s.flagged_tools.contains(&tool_name))
                .unwrap_or_else(|| state.sessions.is_tool_globally_flagged(&tool_name));

            if is_flagged {
                let action = extractor::extract_action(&tool_name, &arguments);
                let verdict = Verdict::Deny {
                    reason: format!(
                        "Tool '{tool_name}' blocked: annotations changed since initial tools/list (rug-pull detected)"
                    ),
                };
                let rug_pull_security_context = rug_pull_security_context(&action);
                let envelope = build_secondary_acis_envelope_with_security_context(
                    &action,
                    &verdict,
                    DecisionOrigin::CapabilityEnforcement,
                    "http",
                    Some(&session_id),
                    Some(&rug_pull_security_context),
                );
                if let Err(e) = state
                    .audit
                    .log_entry_with_acis(
                        &action,
                        &verdict,
                        build_audit_context_with_chain(
                            &session_id,
                            json!({"tool": tool_name, "event": "rug_pull_tool_blocked"}),
                            &oauth_claims,
                            &full_call_chain,
                        ),
                        envelope,
                    )
                    .await
                {
                    tracing::warn!("Failed to audit rug-pull block: {}", e);
                    if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                        return deny;
                    }
                }

                // SECURITY (FIND-R112-009): Generic client message — the tool name
                // is NOT included. Detailed tool name is in the audit verdict only.
                let error_response = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32001,
                        "message": "Denied: annotation change detected (rug-pull protection)",
                    }
                });
                return attach_session_header(
                    (StatusCode::OK, Json(error_response)).into_response(),
                    &session_id,
                );
            }

            // P2: DLP scan parameters for secret exfiltration
            // SECURITY (R8-HTTP-3): Block tool calls with detected secrets,
            // matching the behavior of task request DLP scanning. Previously
            // findings were only logged and the request was forwarded.
            let dlp_findings = scan_parameters_for_secrets(&arguments);
            if !dlp_findings.is_empty() {
                // IMPROVEMENT_PLAN 1.1: Record DLP metrics
                for finding in &dlp_findings {
                    record_dlp_finding(&finding.pattern_name);
                }
                let patterns: Vec<String> = dlp_findings
                    .iter()
                    .map(|f| format!("{} at {}", f.pattern_name, f.location))
                    .collect();
                // SECURITY (R37-PROXY-3): Keep detailed reason for audit, generic for client
                let audit_reason =
                    format!("DLP: secrets detected in tool parameters: {patterns:?}");
                tracing::warn!(
                    "SECURITY: DLP blocking tool '{}' in session {}: {}",
                    tool_name,
                    session_id,
                    audit_reason
                );
                let dlp_action = extractor::extract_action(&tool_name, &arguments);
                let dlp_verdict = Verdict::Deny {
                    reason: audit_reason.clone(),
                };
                let parameter_security_context =
                    parameter_dlp_security_context(&arguments, true, "tool_parameter_dlp");
                let envelope = build_secondary_acis_envelope_with_security_context(
                    &dlp_action,
                    &dlp_verdict,
                    DecisionOrigin::Dlp,
                    "http",
                    Some(&session_id),
                    Some(&parameter_security_context),
                );
                if let Err(e) = state
                    .audit
                    .log_entry_with_acis(
                        &dlp_action,
                        &dlp_verdict,
                        build_audit_context(
                            &session_id,
                            json!({
                                "event": "dlp_secret_blocked",
                                "tool": tool_name,
                                "findings": patterns,
                            }),
                            &oauth_claims,
                        ),
                        envelope,
                    )
                    .await
                {
                    tracing::warn!("Failed to audit DLP finding: {}", e);
                    if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                        return deny;
                    }
                }
                let error_response = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32001,
                        "message": "Request blocked: security policy violation",
                    }
                });
                return attach_session_header(
                    (StatusCode::OK, Json(error_response)).into_response(),
                    &session_id,
                );
            }

            // OWASP ASI06: Check for memory poisoning (replayed response data in params)
            // SECURITY (R26-PROXY-2): Block requests when poisoning is detected (was log-only).
            if let Some(session) = state.sessions.get_mut(&session_id) {
                let poisoning_matches = session.memory_tracker.check_parameters(&arguments);
                if !poisoning_matches.is_empty() {
                    for m in &poisoning_matches {
                        tracing::warn!(
                            "SECURITY: Memory poisoning detected in tool '{}' (session {}): \
                             param '{}' contains replayed data (fingerprint: {})",
                            tool_name,
                            session_id,
                            m.param_location,
                            m.fingerprint
                        );
                    }
                    let action = extractor::extract_action(&tool_name, &arguments);
                    let deny_reason = format!(
                        "Memory poisoning detected: {} replayed data fragment(s) in tool '{}'",
                        poisoning_matches.len(),
                        tool_name
                    );
                    let poison_verdict = Verdict::Deny {
                        reason: deny_reason.clone(),
                    };
                    let poisoning_security_context =
                        memory_poisoning_security_context(&arguments, "memory_poisoning");
                    let envelope = build_secondary_acis_envelope_with_security_context(
                        &action,
                        &poison_verdict,
                        DecisionOrigin::MemoryPoisoning,
                        "http",
                        Some(&session_id),
                        Some(&poisoning_security_context),
                    );
                    if let Err(e) = state
                        .audit
                        .log_entry_with_acis(
                            &action,
                            &poison_verdict,
                            build_audit_context(
                                &session_id,
                                json!({
                                    "event": "memory_poisoning_detected",
                                    "matches": poisoning_matches.len(),
                                    "tool": tool_name,
                                }),
                                &oauth_claims,
                            ),
                            envelope,
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit memory poisoning: {}", e);
                        if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                            return deny;
                        }
                    }
                    let error_response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": "Request blocked: security policy violation",
                        }
                    });
                    return attach_session_header(
                        (StatusCode::OK, Json(error_response)).into_response(),
                        &session_id,
                    );
                }
            }

            let mut action = extractor::extract_action(&tool_name, &arguments);

            // =========================================================
            // Phase 3.1: Circuit Breaker Check (OWASP ASI08)
            // =========================================================
            // Check if the circuit is open for this tool. If so, reject the
            // request immediately without forwarding to upstream.
            if let Some(ref circuit_breaker) = state.circuit_breaker {
                if let Err(reason) = circuit_breaker.can_proceed(&tool_name) {
                    tracing::warn!(
                        "SECURITY: Circuit breaker open for tool '{}' in session {}: {}",
                        tool_name,
                        session_id,
                        reason
                    );
                    let verdict = Verdict::Deny {
                        reason: format!("Circuit breaker open: {reason}"),
                    };
                    // SECURITY (R251-ACIS-1): Use CircuitBreaker origin, not RateLimiter.
                    let circuit_breaker_security_context =
                        circuit_breaker_security_context(&action);
                    let envelope = build_secondary_acis_envelope_with_security_context(
                        &action,
                        &verdict,
                        DecisionOrigin::CircuitBreaker,
                        "http",
                        Some(&session_id),
                        Some(&circuit_breaker_security_context),
                    );
                    if let Err(e) = state
                        .audit
                        .log_entry_with_acis(
                            &action,
                            &verdict,
                            json!({
                                "source": "http_proxy",
                                "session": &session_id,
                                "event": "circuit_breaker_rejected",
                                "tool": tool_name,
                            }),
                            envelope,
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit circuit breaker rejection: {}", e);
                        if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                            return deny;
                        }
                    }
                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": "Service temporarily unavailable",
                        }
                    });
                    return attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    );
                }
            }

            let mut matched_approval_id: Option<String> = None;
            let mut matched_approval_registry: Option<&'static str> = None;

            // Tool registry check: if enabled, unknown or untrusted tools
            // require approval before engine evaluation. This runs before the
            // shard lock to avoid holding it during async registry reads.
            if let Some(ref registry) = state.tool_registry {
                let registry_eval_ctx = state
                    .sessions
                    .get(&session_id)
                    .map(|session| EvaluationContext {
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
                    })
                    .unwrap_or_else(|| EvaluationContext {
                        agent_id: oauth_claims.as_ref().map(|claims| claims.sub.clone()),
                        agent_identity: agent_identity.clone(),
                        ..EvaluationContext::default()
                    });
                let registry_runtime_security_context = build_runtime_security_context(
                    &msg,
                    &action,
                    &headers,
                    TransportSecurityInputs {
                        oauth_evidence: oauth_claims.as_ref(),
                        eval_ctx: Some(&registry_eval_ctx),
                        sessions: &state.sessions,
                        session_id: Some(&session_id),
                        trusted_request_signers: &state.trusted_request_signers,
                        detached_signature_freshness: state.detached_signature_freshness,
                    },
                );
                let trust = registry.check_trust_level(&tool_name).await;
                match trust {
                    vellaveto_mcp::tool_registry::TrustLevel::Unknown => {
                        match presented_approval_matches_action(
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
                            Ok(None) => {}
                            Err(()) => {
                                let verdict = Verdict::Deny {
                                    reason: INVALID_PRESENTED_APPROVAL_REASON.to_string(),
                                };
                                let invalid_approval_security_context =
                                    invalid_presented_approval_security_context(&action);
                                let combined_security_context = merge_transport_security_context(
                                    registry_runtime_security_context.as_ref(),
                                    Some(&invalid_approval_security_context),
                                );
                                let effective_security_context = combined_security_context
                                    .as_ref()
                                    .unwrap_or(&invalid_approval_security_context);
                                let envelope = build_secondary_acis_envelope_with_security_context(
                                    &action,
                                    &verdict,
                                    DecisionOrigin::PolicyEngine,
                                    "http",
                                    Some(&session_id),
                                    Some(effective_security_context),
                                );
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &action,
                                        &verdict,
                                        json!({
                                            "source": "http_proxy",
                                            "session": &session_id,
                                            "event": "presented_approval_replay_denied",
                                            "registry": "unknown_tool",
                                            "approval_id": presented_approval_id,
                                        }),
                                        envelope,
                                    )
                                    .await
                                {
                                    tracing::error!("AUDIT FAILURE: {}", e);
                                    if let Some(deny) =
                                        audit_strict_deny(&state, msg.get("id"), &session_id)
                                    {
                                        return deny;
                                    }
                                }
                                let response = json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "error": {
                                        "code": -32001,
                                        "message": "Denied by policy",
                                    }
                                });
                                return attach_session_header(
                                    (StatusCode::OK, Json(response)).into_response(),
                                    &session_id,
                                );
                            }
                        }
                        if matched_approval_id.is_none() {
                            registry.register_unknown(&tool_name).await;
                            // SECURITY (FIND-045): Generic message to client; detailed reason in audit log only.
                            let reason = "Approval required".to_string();
                            let verdict = Verdict::RequireApproval {
                                reason: reason.clone(),
                            };
                            let approval_security_context =
                                unknown_tool_approval_gate_security_context(&action);
                            let combined_security_context = merge_transport_security_context(
                                registry_runtime_security_context.as_ref(),
                                Some(&approval_security_context),
                            );
                            let effective_security_context = combined_security_context
                                .as_ref()
                                .unwrap_or(&approval_security_context);
                            let envelope = build_secondary_acis_envelope_with_security_context(
                                &action,
                                &verdict,
                                DecisionOrigin::PolicyEngine,
                                "http",
                                Some(&session_id),
                                Some(effective_security_context),
                            );
                            if let Err(e) = state.audit.log_entry_with_acis(
                                &action,
                                &verdict,
                                json!({"source": "http_proxy", "session": &session_id, "registry": "unknown_tool"}),
                                envelope,
                            ).await {
                                tracing::error!("AUDIT FAILURE: {}", e);
                                if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                                    return deny;
                                }
                            }
                            // Create pending approval if store is configured
                            let containment_context =
                                approval_containment_context_from_security_context(
                                    effective_security_context,
                                    &reason,
                                );
                            let approval_id = create_pending_approval_with_context(
                                &state,
                                &session_id,
                                &action,
                                &reason,
                                containment_context,
                            )
                            .await;
                            let error_data = json!({"verdict": "require_approval", "reason": reason, "approval_id": approval_id});
                            let response = make_denial_response(&id, &error_data.to_string());
                            return attach_session_header(
                                (StatusCode::OK, Json(response)).into_response(),
                                &session_id,
                            );
                        }
                    }
                    vellaveto_mcp::tool_registry::TrustLevel::Untrusted { score } => {
                        match presented_approval_matches_action(
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
                            Ok(None) => {}
                            Err(()) => {
                                let verdict = Verdict::Deny {
                                    reason: INVALID_PRESENTED_APPROVAL_REASON.to_string(),
                                };
                                let invalid_approval_security_context =
                                    invalid_presented_approval_security_context(&action);
                                let combined_security_context = merge_transport_security_context(
                                    registry_runtime_security_context.as_ref(),
                                    Some(&invalid_approval_security_context),
                                );
                                let effective_security_context = combined_security_context
                                    .as_ref()
                                    .unwrap_or(&invalid_approval_security_context);
                                let envelope = build_secondary_acis_envelope_with_security_context(
                                    &action,
                                    &verdict,
                                    DecisionOrigin::PolicyEngine,
                                    "http",
                                    Some(&session_id),
                                    Some(effective_security_context),
                                );
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &action,
                                        &verdict,
                                        json!({
                                            "source": "http_proxy",
                                            "session": &session_id,
                                            "event": "presented_approval_replay_denied",
                                            "registry": "untrusted_tool",
                                            "approval_id": presented_approval_id,
                                        }),
                                        envelope,
                                    )
                                    .await
                                {
                                    tracing::error!("AUDIT FAILURE: {}", e);
                                    if let Some(deny) =
                                        audit_strict_deny(&state, msg.get("id"), &session_id)
                                    {
                                        return deny;
                                    }
                                }
                                let response = json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "error": {
                                        "code": -32001,
                                        "message": "Denied by policy",
                                    }
                                });
                                return attach_session_header(
                                    (StatusCode::OK, Json(response)).into_response(),
                                    &session_id,
                                );
                            }
                        }
                        if matched_approval_id.is_none() {
                            // SECURITY (FIND-045): Don't leak trust scores to clients.
                            // Detailed reason (including score) goes to audit log only.
                            tracing::info!(tool = %tool_name, score = score, "Tool trust score below threshold");
                            let reason = "Approval required".to_string();
                            let verdict = Verdict::RequireApproval {
                                reason: reason.clone(),
                            };
                            let approval_security_context =
                                untrusted_tool_approval_gate_security_context(&action);
                            let combined_security_context = merge_transport_security_context(
                                registry_runtime_security_context.as_ref(),
                                Some(&approval_security_context),
                            );
                            let effective_security_context = combined_security_context
                                .as_ref()
                                .unwrap_or(&approval_security_context);
                            let envelope = build_secondary_acis_envelope_with_security_context(
                                &action,
                                &verdict,
                                DecisionOrigin::PolicyEngine,
                                "http",
                                Some(&session_id),
                                Some(effective_security_context),
                            );
                            if let Err(e) = state.audit.log_entry_with_acis(
                                &action,
                                &verdict,
                                json!({"source": "http_proxy", "session": &session_id, "registry": "untrusted_tool"}),
                                envelope,
                            ).await {
                                tracing::error!("AUDIT FAILURE: {}", e);
                                if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                                    return deny;
                                }
                            }
                            let containment_context =
                                approval_containment_context_from_security_context(
                                    effective_security_context,
                                    &reason,
                                );
                            let approval_id = create_pending_approval_with_context(
                                &state,
                                &session_id,
                                &action,
                                &reason,
                                containment_context,
                            )
                            .await;
                            let error_data = json!({"verdict": "require_approval", "reason": reason, "approval_id": approval_id});
                            let response = make_denial_response(&id, &error_data.to_string());
                            return attach_session_header(
                                (StatusCode::OK, Json(response)).into_response(),
                                &session_id,
                            );
                        }
                    }
                    vellaveto_mcp::tool_registry::TrustLevel::Trusted => {
                        // Trusted — proceed to engine evaluation
                    }
                }
            }

            // DNS rebinding protection: resolve target domains to IPs when any
            // policy has ip_rules configured.
            if state.engine.has_ip_rules() {
                resolve_domains(&mut action).await;
            }

            // SECURITY (DEADLOCK-FIX): Build security context BEFORE acquiring
            // the DashMap shard lock. `build_runtime_security_context` internally
            // reads from `state.sessions` for scope binding and nonce recording —
            // doing that inside a `get_mut` block deadlocks on the same shard.
            // Identity/chain data for provenance is read via a short-lived
            // `sessions.get()` (read lock), which doesn't conflict.
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
                    agent_identity: agent_identity.clone(),
                    ..EvaluationContext::default()
                });
            let security_context = build_runtime_security_context(
                &msg,
                &action,
                &headers,
                TransportSecurityInputs {
                    oauth_evidence: oauth_claims.as_ref(),
                    eval_ctx: Some(&pre_eval_ctx),
                    sessions: &state.sessions,
                    session_id: Some(&session_id),
                    trusted_request_signers: &state.trusted_request_signers,
                    detached_signature_freshness: state.detached_signature_freshness,
                },
            );

            // SECURITY (R19-TOCTOU): Combine context read, evaluation, and session
            // update into a single block that holds the DashMap shard lock. Without
            // this, concurrent requests clone the same call_counts snapshot, all pass
            // max_calls evaluation, and all increment — bypassing rate limits.
            //
            // This is safe because engine evaluation is synchronous (no await) and
            // fast (<5ms). The shard lock is released when `session` drops.
            // R244-PROXY-1: Return eval_ctx from closure so ACIS envelope gets agent identity.
            let (mediation_result, eval_ctx) =
                if let Some(mut session) = state.sessions.get_mut(&session_id) {
                    let eval_ctx = EvaluationContext {
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
                        Some(&eval_ctx),
                        security_context.as_ref(),
                        "http",
                        &state.mediation_config,
                        Some(&session_id),
                        None,
                    );

                    // Atomically update session while still holding the shard lock
                    if matches!(result.verdict, Verdict::Allow) {
                        // SECURITY (FIND-045): Cap call_counts to prevent unbounded HashMap growth.
                        if session.call_counts.len() < MAX_CALL_COUNT_TOOLS
                            || session.call_counts.contains_key(&tool_name)
                        {
                            // SECURITY (FIND-R108-003): Use saturating_add to prevent
                            // wrapping to zero which would bypass call-limit policies.
                            let count = session.call_counts.entry(tool_name.clone()).or_insert(0);
                            *count = count.saturating_add(1);
                        }
                        if session.action_history.len() >= MAX_ACTION_HISTORY {
                            session.action_history.pop_front();
                        }
                        session.action_history.push_back(tool_name.clone());
                    }

                    (result, eval_ctx)
                } else {
                    // Fall back to the current transport-authenticated identity when
                    // the session cannot be loaded.
                    let eval_ctx = EvaluationContext {
                        agent_id: oauth_claims.as_ref().map(|claims| claims.sub.clone()),
                        agent_identity: agent_identity.clone(),
                        ..EvaluationContext::default()
                    };
                    let result = mediate_with_security_context(
                        &uuid::Uuid::new_v4().to_string().replace('-', ""),
                        &action,
                        &state.engine,
                        Some(&eval_ctx),
                        security_context.as_ref(),
                        "http",
                        &state.mediation_config,
                        Some(&session_id),
                        None,
                    );
                    (result, eval_ctx)
                };
            let mut final_origin = mediation_result.origin;
            let mut acis_envelope = mediation_result.envelope.clone();
            let mut refresh_envelope = false;
            let trace = if params.trace && state.trace_enabled {
                mediation_result.trace.clone()
            } else {
                None
            };
            let verdict = match mediation_result.verdict {
                Verdict::RequireApproval { reason } => {
                    if matched_approval_id.is_some() {
                        final_origin = DecisionOrigin::PolicyEngine;
                        refresh_envelope = true;
                        Verdict::Allow
                    } else {
                        match presented_approval_matches_action(
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
                }
                other => other,
            };
            if refresh_envelope {
                let findings = acis_envelope.findings.clone();
                let evaluation_us = acis_envelope.evaluation_us;
                let decision_id = acis_envelope.decision_id.clone();
                acis_envelope = build_acis_envelope_with_security_context(
                    &decision_id,
                    &action,
                    &verdict,
                    final_origin,
                    "http",
                    &findings,
                    evaluation_us,
                    Some(&session_id),
                    None,
                    Some(&eval_ctx),
                    security_context.as_ref(),
                );
            }

            match verdict {
                Verdict::Allow => {
                    // OWASP ASI08: Check for privilege escalation before forwarding
                    let priv_check = check_privilege_escalation(
                        &state.engine,
                        &state.policies,
                        &action,
                        &full_call_chain,
                        current_agent_id,
                    );

                    if priv_check.escalation_detected {
                        // SECURITY (R33-PROXY-1): Internal deny reason contains policy details
                        // (upstream agent name + deny reason). Log the full details in the
                        // audit trail but return a generic message to the client.
                        let internal_reason = format!(
                            "Privilege escalation detected: agent '{}' would be denied ({})",
                            priv_check
                                .escalating_from_agent
                                .as_deref()
                                .unwrap_or("unknown"),
                            priv_check
                                .upstream_deny_reason
                                .as_deref()
                                .unwrap_or("unknown reason")
                        );
                        let verdict = Verdict::Deny {
                            reason: internal_reason.clone(),
                        };

                        // Audit the privilege escalation with full details
                        let privilege_escalation_security_context =
                            privilege_escalation_security_context(&action);
                        let envelope = build_secondary_acis_envelope_with_security_context(
                            &action,
                            &verdict,
                            DecisionOrigin::PolicyEngine,
                            "http",
                            Some(&session_id),
                            Some(&privilege_escalation_security_context),
                        );
                        if let Err(e) = state
                            .audit
                            .log_entry_with_acis(
                                &action,
                                &verdict,
                                build_audit_context_with_chain(
                                    &session_id,
                                    json!({
                                        "tool": tool_name,
                                        "event": "privilege_escalation_blocked",
                                        "escalating_from_agent": priv_check.escalating_from_agent,
                                        "upstream_deny_reason": priv_check.upstream_deny_reason,
                                    }),
                                    &oauth_claims,
                                    &full_call_chain,
                                ),
                                envelope,
                            )
                            .await
                        {
                            tracing::warn!("Failed to audit privilege escalation: {}", e);
                            if let Some(deny) =
                                audit_strict_deny(&state, msg.get("id"), &session_id)
                            {
                                return deny;
                            }
                        }

                        // Return generic message to client — no policy details leaked
                        let response = json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": {
                                "code": -32001,
                                "message": "Denied by policy"
                            }
                        });
                        return attach_session_header(
                            (StatusCode::OK, Json(response)).into_response(),
                            &session_id,
                        );
                    }

                    // Phase 21: ABAC refinement — only runs when ABAC engine is configured.
                    // If the PolicyEngine allowed the action, ABAC may still deny it
                    // based on principal/action/resource/condition constraints.
                    if let Some(ref abac) = state.abac_engine {
                        let abac_eval_ctx = build_evaluation_context(&state.sessions, &session_id)
                            .unwrap_or_default();
                        let principal_id = abac_eval_ctx.agent_id.as_deref().unwrap_or("anonymous");
                        let principal_type = abac_eval_ctx.principal_type();
                        let session_risk = state
                            .sessions
                            .get_mut(&session_id)
                            .and_then(|s| s.risk_score.clone());
                        let abac_ctx = vellaveto_engine::abac::AbacEvalContext {
                            eval_ctx: &abac_eval_ctx,
                            principal_type,
                            principal_id,
                            risk_score: session_risk.as_ref(),
                        };

                        match abac.evaluate(&action, &abac_ctx) {
                            vellaveto_engine::abac::AbacDecision::Deny { policy_id, reason } => {
                                let verdict = Verdict::Deny {
                                    reason: reason.clone(),
                                };
                                let abac_security_context = abac_deny_security_context(&action);
                                let envelope = build_secondary_acis_envelope_with_security_context(
                                    &action,
                                    &verdict,
                                    DecisionOrigin::PolicyEngine,
                                    "http",
                                    Some(&session_id),
                                    Some(&abac_security_context),
                                );
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &action,
                                        &verdict,
                                        build_audit_context_with_chain(
                                            &session_id,
                                            serde_json::json!({
                                                "tool": tool_name,
                                                "event": "abac_deny",
                                                "abac_policy": policy_id,
                                            }),
                                            &oauth_claims,
                                            &full_call_chain,
                                        ),
                                        envelope,
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit ABAC deny: {}", e);
                                    if let Some(deny) =
                                        audit_strict_deny(&state, msg.get("id"), &session_id)
                                    {
                                        return deny;
                                    }
                                }
                                let response = serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "error": {
                                        "code": -32001,
                                        "message": "Denied by policy"
                                    }
                                });
                                return attach_session_header(
                                    (StatusCode::OK, Json(response)).into_response(),
                                    &session_id,
                                );
                            }
                            vellaveto_engine::abac::AbacDecision::Allow { policy_id } => {
                                // Record for least-agency tracking
                                if let Some(ref la) = state.least_agency {
                                    la.record_usage(
                                        principal_id,
                                        &session_id,
                                        &policy_id,
                                        &tool_name,
                                        &action.function,
                                    );
                                }
                            }
                            vellaveto_engine::abac::AbacDecision::NoMatch => {
                                // Fall through — existing Allow verdict stands
                            }
                            #[allow(unreachable_patterns)] // AbacDecision is #[non_exhaustive]
                            _ => {
                                // SECURITY (FIND-R74-002): Future variants — fail-closed (deny).
                                // Must return a deny response, not fall through to Allow path.
                                tracing::warn!("Unknown AbacDecision variant — fail-closed");
                                let response = serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "error": {
                                        "code": -32001,
                                        "message": "Denied by policy"
                                    }
                                });
                                return attach_session_header(
                                    (StatusCode::OK, Json(response)).into_response(),
                                    &session_id,
                                );
                            }
                        }
                    }

                    // Record tool call in registry on Allow (for trust score tracking)
                    if let Some(ref registry) = state.tool_registry {
                        registry.record_call(&tool_name).await;
                    }

                    // Forward to upstream — canonicalize if configured (KL2 TOCTOU fix)
                    let forward_body = match canonicalize_body(&state, &msg, body) {
                        Some(b) => b,
                        None => {
                            return make_jsonrpc_error(
                                msg.get("id"),
                                -32603,
                                "Internal error: canonicalization failed",
                            )
                        }
                    };
                    // Phase 20: Gateway routing — resolve backend URL before forwarding
                    let gateway_decision = if let Some(ref gw) = state.gateway {
                        match gw.route(&tool_name) {
                            Some(decision) => {
                                tracing::debug!(
                                    tool = %tool_name,
                                    backend = %decision.backend_id,
                                    "Gateway routed"
                                );
                                Some(decision)
                            }
                            None => {
                                // All backends unhealthy — fail-closed
                                let gw_verdict = Verdict::Deny {
                                    reason: "No healthy backend available".into(),
                                };
                                let gateway_security_context = transport_failure_security_context(
                                    &action,
                                    "gateway_no_backend",
                                );
                                let envelope = build_secondary_acis_envelope_with_security_context(
                                    &action,
                                    &gw_verdict,
                                    DecisionOrigin::PolicyEngine,
                                    "http",
                                    Some(&session_id),
                                    Some(&gateway_security_context),
                                );
                                let _ = state
                                    .audit
                                    .log_entry_with_acis(
                                        &action,
                                        &gw_verdict,
                                        json!({"event": "gateway_no_backend", "tool": tool_name}),
                                        envelope,
                                    )
                                    .await;
                                return attach_session_header(
                                    make_jsonrpc_error(
                                        msg.get("id"),
                                        -32000,
                                        "Upstream unavailable",
                                    ),
                                    &session_id,
                                );
                            }
                        }
                    } else {
                        None
                    };

                    if consume_presented_approval(
                        &state,
                        &session_id,
                        matched_approval_id.as_deref(),
                        &action,
                        security_context.as_ref(),
                    )
                    .await
                    .is_err()
                    {
                        let verdict = Verdict::Deny {
                            reason: INVALID_PRESENTED_APPROVAL_REASON.to_string(),
                        };
                        let invalid_approval_security_context =
                            invalid_presented_approval_security_context(&action);
                        let combined_security_context = merge_transport_security_context(
                            security_context.as_ref(),
                            Some(&invalid_approval_security_context),
                        );
                        let effective_security_context = combined_security_context
                            .as_ref()
                            .unwrap_or(&invalid_approval_security_context);
                        let envelope = build_secondary_acis_envelope_with_security_context(
                            &action,
                            &verdict,
                            DecisionOrigin::ApprovalGate,
                            "http",
                            Some(&session_id),
                            Some(effective_security_context),
                        );
                        let mut audit_metadata = json!({
                            "source": "http_proxy",
                            "session": &session_id,
                            "event": "presented_approval_replay_denied",
                            "approval_id": matched_approval_id,
                        });
                        if let Some(registry) = matched_approval_registry {
                            audit_metadata["registry"] = json!(registry);
                        }
                        if let Err(e) = state
                            .audit
                            .log_entry_with_acis(&action, &verdict, audit_metadata, envelope)
                            .await
                        {
                            tracing::warn!("Failed to audit replayed presented approval: {}", e);
                            if let Some(deny) =
                                audit_strict_deny(&state, msg.get("id"), &session_id)
                            {
                                return deny;
                            }
                        }
                        let response = serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": {
                                "code": -32001,
                                "message": "Denied by policy"
                            }
                        });
                        return attach_session_header(
                            (StatusCode::OK, Json(response)).into_response(),
                            &session_id,
                        );
                    }

                    // Track request->tool mapping so response validation can resolve
                    // tool context even when upstream omits result._meta.tool.
                    track_pending_tool_call(&state.sessions, &session_id, &id, &tool_name);

                    // Phase 29: Cross-transport smart fallback path.
                    // When enabled and transport_health is available, try
                    // each transport in priority order before giving up.
                    if state.transport_config.cross_transport_fallback {
                        if let Some(ref health_tracker) = state.transport_health {
                            let client_pref_header = headers
                                .get(super::MCP_TRANSPORT_PREFERENCE_HEADER)
                                .and_then(|v| v.to_str().ok())
                                .map(super::discovery::parse_transport_preference);
                            let priorities = super::discovery::resolve_transport_priority(
                                &tool_name,
                                client_pref_header.as_deref(),
                                &state.transport_config,
                            );

                            let targets = build_transport_targets(
                                &state,
                                gateway_decision.as_ref(),
                                &priorities,
                            );

                            if !targets.is_empty() {
                                let per_attempt = std::time::Duration::from_secs(
                                    state.transport_config.fallback_timeout_secs,
                                );
                                let total = per_attempt.saturating_mul(priorities.len() as u32);

                                let mut chain = super::smart_fallback::SmartFallbackChain::new(
                                    &state.http_client,
                                    health_tracker,
                                    per_attempt,
                                    total,
                                );
                                if state.transport_config.stdio_fallback_enabled {
                                    if let Some(ref cmd) = state.transport_config.stdio_command {
                                        match chain.with_stdio(cmd.clone()) {
                                            Ok(updated) => chain = updated,
                                            Err(err) => tracing::warn!(
                                                "Invalid stdio fallback command: {}",
                                                err
                                            ),
                                        }
                                    }
                                }

                                match chain
                                    .execute(&targets, forward_body.clone(), &headers)
                                    .await
                                {
                                    Ok(result) => {
                                        // SECURITY (FIND-R43-013): Block dangerous status codes from smart fallback upstream.
                                        // 3xx can enable SSRF via redirect, 1xx are informational (incomplete),
                                        // and 407 (Proxy Authentication Required) leaks proxy topology.
                                        let safe_status = if (300..400).contains(&result.status)
                                            || result.status < 200
                                            || result.status == 407
                                        {
                                            tracing::warn!(
                                                status = result.status,
                                                "smart fallback upstream returned suspicious status — mapping to 502"
                                            );
                                            502
                                        } else {
                                            result.status
                                        };

                                        // Record gateway health on success.
                                        if let Some(ref gw) = state.gateway {
                                            if let Some(ref decision) = gateway_decision {
                                                gw.record_success(&decision.backend_id);
                                            }
                                        }
                                        // Audit if fallback occurred (>1 attempt).
                                        if result.history.attempts.len() > 1 {
                                            let fallback_security_context =
                                                protocol_forward_security_context(
                                                    "cross_transport_fallback",
                                                );
                                            let fallback_envelope =
                                                build_secondary_acis_envelope_with_security_context(
                                                    &action,
                                                    &Verdict::Allow,
                                                    DecisionOrigin::PolicyEngine,
                                                    "http",
                                                    Some(&session_id),
                                                    Some(&fallback_security_context),
                                                );
                                            let _ = state
                                                .audit
                                                .log_entry_with_acis(
                                                    &action,
                                                    &Verdict::Allow,
                                                    json!({
                                                        "event": "cross_transport_fallback",
                                                        "tool": tool_name,
                                                        "transport_used": format!("{:?}", result.transport_used),
                                                        "attempts": result.history.attempts.len(),
                                                        "total_duration_ms": result.history.total_duration_ms,
                                                    }),
                                                    fallback_envelope,
                                                )
                                                .await;
                                        }

                                        // SECURITY (FIND-R44-002): Run the same DLP and injection
                                        // inspection on smart-fallback responses that
                                        // forward_to_upstream_url applies. Without this, an
                                        // attacker who controls a fallback transport can exfiltrate
                                        // secrets or inject prompts undetected.
                                        let response_bytes = result.response;
                                        if let Ok(response_json) =
                                            serde_json::from_slice::<Value>(&response_bytes)
                                        {
                                            // DLP: scan for secrets
                                            if state.response_dlp_enabled {
                                                let dlp_findings =
                                                    scan_response_for_secrets(&response_json);
                                                if !dlp_findings.is_empty() {
                                                    for finding in &dlp_findings {
                                                        record_dlp_finding(&finding.pattern_name);
                                                    }
                                                    let patterns: Vec<String> = dlp_findings
                                                        .iter()
                                                        .map(|f| {
                                                            format!(
                                                                "{}:{}",
                                                                f.pattern_name, f.location
                                                            )
                                                        })
                                                        .collect();
                                                    tracing::warn!(
                                                        "SECURITY: Secrets detected in smart-fallback response! \
                                                         Session: {}, Findings: {:?}, Blocking: {}",
                                                        session_id,
                                                        patterns,
                                                        state.response_dlp_blocking,
                                                    );
                                                    if state.response_dlp_blocking {
                                                        let verdict = Verdict::Deny {
                                                            reason: format!(
                                                                "Smart-fallback response DLP blocked: {patterns:?}"
                                                            ),
                                                        };
                                                        let response_security_context =
                                                            response_dlp_security_context(
                                                                Some(&tool_name),
                                                                &response_json,
                                                                true,
                                                            );
                                                        let envelope =
                                                            build_secondary_acis_envelope_with_security_context(
                                                                &action,
                                                                &verdict,
                                                                DecisionOrigin::Dlp,
                                                                "http",
                                                                Some(&session_id),
                                                                Some(&response_security_context),
                                                            );
                                                        let _ = state
                                                            .audit
                                                            .log_entry_with_acis(
                                                                &action,
                                                                &verdict,
                                                                json!({
                                                                    "source": "http_proxy",
                                                                    "event": "smart_fallback_dlp_blocked",
                                                                    "blocked": true,
                                                                    "findings": patterns,
                                                                }),
                                                                envelope,
                                                            )
                                                            .await;
                                                        return attach_session_header(
                                                            StatusCode::BAD_GATEWAY.into_response(),
                                                            &session_id,
                                                        );
                                                    }
                                                }
                                            }

                                            // Injection: scan result text for prompt injection
                                            if !state.injection_disabled {
                                                if let Some(result_val) =
                                                    response_json.get("result")
                                                {
                                                    let text_to_inspect =
                                                        super::inspection::extract_text_from_result(
                                                            result_val,
                                                        );
                                                    if !text_to_inspect.is_empty() {
                                                        let matches: Vec<String> =
                                                            if let Some(ref scanner) =
                                                                state.injection_scanner
                                                            {
                                                                scanner
                                                                    .inspect(&text_to_inspect)
                                                                    .into_iter()
                                                                    .map(|s| s.to_string())
                                                                    .collect()
                                                            } else {
                                                                inspect_for_injection(
                                                                    &text_to_inspect,
                                                                )
                                                                .into_iter()
                                                                .map(|s| s.to_string())
                                                                .collect()
                                                            };
                                                        if !matches.is_empty() {
                                                            tracing::warn!(
                                                                "SECURITY: Prompt injection in smart-fallback response! \
                                                                 Session: {}, Patterns: {:?}",
                                                                session_id,
                                                                matches,
                                                            );
                                                            if state.injection_blocking {
                                                                let verdict = Verdict::Deny {
                                                                    reason: format!(
                                                                        "Smart-fallback response injection blocked: {matches:?}"
                                                                    ),
                                                                };
                                                                let response_security_context =
                                                                    response_injection_security_context(
                                                                        Some(&tool_name),
                                                                        &response_json,
                                                                        true,
                                                                        "smart_fallback_injection",
                                                                    );
                                                                let envelope = build_secondary_acis_envelope_with_security_context(
                                                                    &action,
                                                                    &verdict,
                                                                    DecisionOrigin::InjectionScanner,
                                                                    "http",
                                                                    Some(&session_id),
                                                                    Some(&response_security_context),
                                                                );
                                                                let _ = state
                                                                    .audit
                                                                    .log_entry_with_acis(
                                                                        &action,
                                                                        &verdict,
                                                                        json!({
                                                                            "source": "http_proxy",
                                                                            "event": "smart_fallback_injection_blocked",
                                                                            "patterns": matches,
                                                                        }),
                                                                        envelope,
                                                                    )
                                                                    .await;
                                                                return attach_session_header(
                                                                    StatusCode::BAD_GATEWAY
                                                                        .into_response(),
                                                                    &session_id,
                                                                );
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        } else {
                                            // SECURITY (R253-TH-003): Non-JSON response from smart
                                            // fallback — fail-closed. MCP is JSON-RPC, so non-JSON
                                            // is protocol-invalid and bypasses DLP/injection scanning.
                                            // Block rather than forward unscanned content.
                                            tracing::warn!(
                                                "SECURITY: Smart-fallback response is not valid JSON — \
                                                 blocking unscanned response (session: {})",
                                                session_id,
                                            );
                                            let verdict = Verdict::Deny {
                                                reason: "Smart-fallback response is not valid JSON — blocked (fail-closed)".to_string(),
                                            };
                                            let response_security_context =
                                                protocol_rejection_security_context(
                                                    "smart_fallback_non_json_blocked",
                                                );
                                            let envelope =
                                                build_secondary_acis_envelope_with_security_context(
                                                    &action,
                                                    &verdict,
                                                    DecisionOrigin::PolicyEngine,
                                                    "http",
                                                    Some(&session_id),
                                                    Some(&response_security_context),
                                                );
                                            let _ = state
                                                .audit
                                                .log_entry_with_acis(
                                                    &action,
                                                    &verdict,
                                                    json!({
                                                        "source": "http_proxy",
                                                        "event": "smart_fallback_non_json_blocked",
                                                        "session": session_id,
                                                    }),
                                                    envelope,
                                                )
                                                .await;
                                            return attach_session_header(
                                                StatusCode::BAD_GATEWAY.into_response(),
                                                &session_id,
                                            );
                                        }

                                        let response = axum::response::Response::builder()
                                            .status(safe_status)
                                            .header("content-type", "application/json")
                                            .body(axum::body::Body::from(response_bytes))
                                            .unwrap_or_else(|_| {
                                                StatusCode::BAD_GATEWAY.into_response()
                                            });
                                        let response = attach_session_header(response, &session_id);
                                        return attach_trace_header(response, trace);
                                    }
                                    Err(e) => {
                                        // All transports failed — fail-closed.
                                        if let Some(ref gw) = state.gateway {
                                            if let Some(ref decision) = gateway_decision {
                                                gw.record_failure(&decision.backend_id);
                                            }
                                        }
                                        tracing::warn!(
                                            tool = %tool_name,
                                            "cross-transport fallback failed: {}",
                                            e,
                                        );
                                        let fallback_fail_verdict = Verdict::Deny {
                                            reason: format!("all transports failed: {e}"),
                                        };
                                        let fallback_fail_security_context =
                                            transport_failure_security_context(
                                                &action,
                                                "cross_transport_fallback_failed",
                                            );
                                        let envelope =
                                            build_secondary_acis_envelope_with_security_context(
                                                &action,
                                                &fallback_fail_verdict,
                                                DecisionOrigin::PolicyEngine,
                                                "http",
                                                Some(&session_id),
                                                Some(&fallback_fail_security_context),
                                            );
                                        let _ = state
                                            .audit
                                            .log_entry_with_acis(
                                                &action,
                                                &fallback_fail_verdict,
                                                json!({
                                                    "event": "cross_transport_fallback_failed",
                                                    "tool": tool_name,
                                                }),
                                                envelope,
                                            )
                                            .await;
                                        return attach_session_header(
                                            make_jsonrpc_error(
                                                msg.get("id"),
                                                -32000,
                                                "Upstream unavailable",
                                            ),
                                            &session_id,
                                        );
                                    }
                                }
                            }
                        }
                    }

                    // Phase 28: Build upstream trace headers.
                    // For gateway mode, create a gateway child span so each
                    // backend gets its own traceparent with the gateway as parent.
                    let response = if let Some(ref decision) = gateway_decision {
                        let gw_child = vellaveto_trace_ctx.child();
                        let (gw_tp, gw_ts) =
                            trace_propagation::build_upstream_headers(&gw_child, "allow");
                        forward_to_upstream_url(
                            &state,
                            &decision.upstream_url,
                            &session_id,
                            forward_body,
                            UpstreamForwardOptions::post(
                                auth_header_for_upstream.as_deref(),
                                Some((gw_tp.as_str(), gw_ts.as_deref())),
                                &mcp_param_headers,
                            ),
                        )
                        .await
                    } else {
                        let (up_tp, up_ts) = trace_propagation::build_upstream_headers(
                            &vellaveto_trace_ctx,
                            "allow",
                        );
                        forward_to_upstream(
                            &state,
                            &session_id,
                            forward_body,
                            UpstreamForwardOptions::post(
                                auth_header_for_upstream.as_deref(),
                                Some((up_tp.as_str(), up_ts.as_deref())),
                                &mcp_param_headers,
                            ),
                        )
                        .await
                    };

                    // Phase 20: Record backend health from response
                    if let Some(ref gw) = state.gateway {
                        if let Some(ref decision) = gateway_decision {
                            if response.status().is_server_error() {
                                gw.record_failure(&decision.backend_id);
                            } else {
                                gw.record_success(&decision.backend_id);
                            }
                        }
                    }

                    let response = attach_session_header(response, &session_id);
                    attach_trace_header(response, trace)
                }
                Verdict::Deny { ref reason } => {
                    let reason = reason.clone();
                    let verdict = Verdict::Deny {
                        reason: reason.clone(),
                    };

                    let mut extra = json!({"tool": tool_name});
                    if reason == INVALID_PRESENTED_APPROVAL_REASON
                        && presented_approval_id.is_some()
                    {
                        extra["event"] = json!("presented_approval_replay_denied");
                        extra["approval_id"] = json!(presented_approval_id);
                    }
                    let audit_metadata = build_audit_context_with_chain(
                        &session_id,
                        extra,
                        &oauth_claims,
                        &full_call_chain,
                    );

                    if let Err(e) = state
                        .audit
                        .log_entry_with_acis(&action, &verdict, audit_metadata, acis_envelope)
                        .await
                    {
                        tracing::error!(
                            "AUDIT FAILURE in HTTP proxy: security decision not recorded: {}",
                            e
                        );
                        // SECURITY (FIND-CREATIVE-003): Strict audit mode — fail-closed
                        // if audit fails. No unaudited security decisions can occur.
                        if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                            return deny;
                        }
                    }

                    let mut response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            // SECURITY (R39-PROXY-1): Generic message — detailed reason
                            // is in the audit log, not leaked to the client.
                            "message": "Denied by policy"
                        }
                    });
                    if let Some(t) = &trace {
                        response["trace"] = serde_json::to_value(t).unwrap_or(Value::Null);
                    }
                    attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    )
                }
                Verdict::RequireApproval { ref reason } => {
                    let reason = reason.clone();
                    let verdict = Verdict::RequireApproval {
                        reason: reason.clone(),
                    };
                    let containment_context =
                        approval_containment_context_from_envelope(&acis_envelope, &reason);

                    // Create pending approval if store is configured
                    let approval_id = create_pending_approval_with_context(
                        &state,
                        &session_id,
                        &action,
                        &reason,
                        containment_context,
                    )
                    .await;
                    if let Some(ref approval_id) = approval_id {
                        tracing::info!(
                            "Created pending approval {} for tool '{}'",
                            approval_id,
                            tool_name
                        );
                    }

                    if let Err(e) = state
                        .audit
                        .log_entry_with_acis(
                            &action,
                            &verdict,
                            build_audit_context_with_chain(
                                &session_id,
                                json!({"tool": tool_name}),
                                &oauth_claims,
                                &full_call_chain,
                            ),
                            acis_envelope,
                        )
                        .await
                    {
                        tracing::error!(
                            "AUDIT FAILURE in HTTP proxy: security decision not recorded: {}",
                            e
                        );
                        // SECURITY (FIND-CREATIVE-003): Strict audit mode — fail-closed.
                        if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                            return deny;
                        }
                    }

                    let mut response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32002,
                            // SECURITY (R39-PROXY-1): Generic message — detailed reason
                            // is in the data field for the approval flow, not leaked.
                            "message": "Approval required",
                            "data": {
                                "type": "approval_required",
                                "reason": reason
                            }
                        }
                    });
                    if let Some(aid) = approval_id {
                        if let Some(data) =
                            response.get_mut("error").and_then(|e| e.get_mut("data"))
                        {
                            data["approval_id"] = Value::String(aid);
                        }
                    }
                    if let Some(t) = &trace {
                        response["trace"] = serde_json::to_value(t).unwrap_or(Value::Null);
                    }
                    attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    )
                }
                // Handle future Verdict variants - fail closed (deny)
                _ => {
                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": "Unknown verdict - failing closed"
                        }
                    });
                    attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    )
                }
            }
        }
        MessageType::ResourceRead { id, uri } => {
            // NOTE (FIND-R44-052): validate_call_chain_header is handled by the
            // pre-match check above (line ~289). No per-arm call needed here.

            // Keep per-request call-chain context in sync for resource policy checks.
            sync_session_call_chain_from_headers(
                &state.sessions,
                &session_id,
                &headers,
                state.call_chain_hmac_key.as_ref(),
                &state.limits,
            );

            // SECURITY (R27-PROXY-2): Check for memory poisoning in resource URI.
            // ResourceRead is a likely exfiltration vector: a poisoned tool response
            // says "read this file" and the agent issues resources/read for that URI.
            if let Some(session) = state.sessions.get_mut(&session_id) {
                let uri_params = serde_json::json!({"uri": uri});
                let poisoning_matches = session.memory_tracker.check_parameters(&uri_params);
                if !poisoning_matches.is_empty() {
                    for m in &poisoning_matches {
                        tracing::warn!(
                            "SECURITY: Memory poisoning detected in resources/read (session {}): \
                             param '{}' contains replayed data (fingerprint: {})",
                            session_id,
                            m.param_location,
                            m.fingerprint
                        );
                    }
                    let action = extractor::extract_resource_action(&uri);
                    let deny_reason = format!(
                        "Memory poisoning detected: {} replayed data fragment(s) in resources/read",
                        poisoning_matches.len()
                    );
                    let poison_verdict = Verdict::Deny {
                        reason: deny_reason.clone(),
                    };
                    let poisoning_security_context =
                        memory_poisoning_security_context(&uri_params, "memory_poisoning");
                    let envelope = build_secondary_acis_envelope_with_security_context(
                        &action,
                        &poison_verdict,
                        DecisionOrigin::MemoryPoisoning,
                        "http",
                        Some(&session_id),
                        Some(&poisoning_security_context),
                    );
                    if let Err(e) = state
                        .audit
                        .log_entry_with_acis(
                            &action,
                            &poison_verdict,
                            build_audit_context(
                                &session_id,
                                json!({
                                    "event": "memory_poisoning_detected",
                                    "matches": poisoning_matches.len(),
                                    "uri": uri,
                                }),
                                &oauth_claims,
                            ),
                            envelope,
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit memory poisoning: {}", e);
                        if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                            return deny;
                        }
                    }
                    let error_response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": "Request blocked: security policy violation"
                        }
                    });
                    return attach_session_header(
                        (StatusCode::OK, Json(error_response)).into_response(),
                        &session_id,
                    );
                }
            }

            // SECURITY (FIND-R112-005): Rug-pull detection for resource URIs.
            // If the upstream server was flagged (annotations changed since initial tools/list),
            // block resource reads from that server. The URI itself is checked against the
            // flagged_tools set, which contains both tool names and server identifiers recorded
            // during rug-pull detection.
            // SECURITY (R240-PROXY-1): Fall back to global registry on session miss.
            let is_flagged = state
                .sessions
                .get_mut(&session_id)
                .map(|s| s.flagged_tools.contains(uri.as_str()))
                .unwrap_or_else(|| state.sessions.is_tool_globally_flagged(uri.as_str()));
            if is_flagged {
                let action = extractor::extract_resource_action(&uri);
                let verdict = Verdict::Deny {
                    reason: format!(
                        "Resource '{uri}' blocked: server flagged by rug-pull detection"
                    ),
                };
                let rug_pull_security_context = rug_pull_security_context(&action);
                let envelope = build_secondary_acis_envelope_with_security_context(
                    &action,
                    &verdict,
                    DecisionOrigin::CapabilityEnforcement,
                    "http",
                    Some(&session_id),
                    Some(&rug_pull_security_context),
                );
                if let Err(e) = state
                    .audit
                    .log_entry_with_acis(
                        &action,
                        &verdict,
                        build_audit_context(
                            &session_id,
                            json!({
                                "event": "rug_pull_resource_blocked",
                                "uri": uri,
                            }),
                            &oauth_claims,
                        ),
                        envelope,
                    )
                    .await
                {
                    tracing::warn!("Failed to audit resource rug-pull block: {}", e);
                    if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                        return deny;
                    }
                }
                let error_response = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32001,
                        "message": "Denied by policy",
                    }
                });
                return attach_session_header(
                    (StatusCode::OK, Json(error_response)).into_response(),
                    &session_id,
                );
            }

            // SECURITY (FIND-R112-001): DLP scan on resource URI.
            // ResourceRead is a known exfiltration vector; the URI may encode secrets
            // (e.g., file:///proc/self/environ, paths with embedded API keys). Mirror
            // the ToolCall DLP scanning pattern to catch secret leakage in the URI.
            {
                let uri_params = serde_json::json!({"uri": &uri});
                let dlp_findings = scan_parameters_for_secrets(&uri_params);
                if !dlp_findings.is_empty() {
                    for finding in &dlp_findings {
                        record_dlp_finding(&finding.pattern_name);
                    }
                    let patterns: Vec<String> = dlp_findings
                        .iter()
                        .map(|f| format!("{} at {}", f.pattern_name, f.location))
                        .collect();
                    let audit_reason =
                        format!("DLP: secrets detected in resource URI: {patterns:?}");
                    tracing::warn!(
                        "SECURITY: DLP blocking resource read '{}' in session {}: {}",
                        uri,
                        session_id,
                        audit_reason
                    );
                    let dlp_action = extractor::extract_resource_action(&uri);
                    let dlp_verdict = Verdict::Deny {
                        reason: audit_reason.clone(),
                    };
                    let parameter_security_context =
                        parameter_dlp_security_context(&uri_params, true, "resource_uri_dlp");
                    let envelope = build_secondary_acis_envelope_with_security_context(
                        &dlp_action,
                        &dlp_verdict,
                        DecisionOrigin::Dlp,
                        "http",
                        Some(&session_id),
                        Some(&parameter_security_context),
                    );
                    if let Err(e) = state
                        .audit
                        .log_entry_with_acis(
                            &dlp_action,
                            &dlp_verdict,
                            build_audit_context(
                                &session_id,
                                json!({
                                    "event": "dlp_secret_blocked",
                                    "uri": uri,
                                    "findings": patterns,
                                }),
                                &oauth_claims,
                            ),
                            envelope,
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit resource DLP finding: {}", e);
                        if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                            return deny;
                        }
                    }
                    let error_response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": "Request blocked: sensitive content detected",
                        }
                    });
                    return attach_session_header(
                        (StatusCode::OK, Json(error_response)).into_response(),
                        &session_id,
                    );
                }
            }

            let mut action = extractor::extract_resource_action(&uri);
            let mut matched_approval_id: Option<String> = None;

            // DNS rebinding protection for resource reads
            if state.engine.has_ip_rules() {
                resolve_domains(&mut action).await;
            }

            // SECURITY (FIND-R112-004): Circuit breaker check for resource reads.
            // Mirror ToolCall circuit breaker pattern to prevent resource reads from
            // hammering a failing upstream server.
            if let Some(ref circuit_breaker) = state.circuit_breaker {
                if let Err(reason) = circuit_breaker.can_proceed(uri.as_str()) {
                    tracing::warn!(
                        "SECURITY: Circuit breaker open for resource '{}' in session {}: {}",
                        uri,
                        session_id,
                        reason
                    );
                    let verdict = Verdict::Deny {
                        reason: format!("Circuit breaker open: {reason}"),
                    };
                    // SECURITY (R251-ACIS-1): Use CircuitBreaker origin, not RateLimiter.
                    let circuit_breaker_security_context =
                        circuit_breaker_security_context(&action);
                    let envelope = build_secondary_acis_envelope_with_security_context(
                        &action,
                        &verdict,
                        DecisionOrigin::CircuitBreaker,
                        "http",
                        Some(&session_id),
                        Some(&circuit_breaker_security_context),
                    );
                    if let Err(e) = state
                        .audit
                        .log_entry_with_acis(
                            &action,
                            &verdict,
                            build_audit_context(
                                &session_id,
                                json!({
                                    "event": "circuit_breaker_rejected",
                                    "uri": uri,
                                }),
                                &oauth_claims,
                            ),
                            envelope,
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit resource circuit breaker rejection: {}", e);
                        if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                            return deny;
                        }
                    }
                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": "Service temporarily unavailable",
                        }
                    });
                    return attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    );
                }
            }

            // SECURITY (FIND-R112-002): Build evaluation context and run policy evaluation
            // inside a single `state.sessions.get_mut` block to eliminate the TOCTOU gap.
            // Without this, concurrent requests clone the same call_counts snapshot, all pass
            // max_calls evaluation, and all increment — bypassing rate limits.
            // Mirror the ToolCall TOCTOU fix (R19-TOCTOU).
            // R244-PROXY-1: Return eval_ctx so ACIS envelope gets agent identity.
            // Deadlock fix: build pre_eval_ctx + security_context BEFORE get_mut so that
            // build_runtime_security_context never acquires a read shard while get_mut holds
            // the write shard on the same DashMap.
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
                    agent_identity: agent_identity.clone(),
                    ..EvaluationContext::default()
                });
            let security_context = build_runtime_security_context(
                &msg,
                &action,
                &headers,
                TransportSecurityInputs {
                    oauth_evidence: oauth_claims.as_ref(),
                    eval_ctx: Some(&pre_eval_ctx),
                    sessions: &state.sessions,
                    session_id: Some(&session_id),
                    trusted_request_signers: &state.trusted_request_signers,
                    detached_signature_freshness: state.detached_signature_freshness,
                },
            );
            let (mediation_result, eval_ctx) =
                if let Some(mut session) = state.sessions.get_mut(&session_id) {
                    let eval_ctx = EvaluationContext {
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
                        Some(&eval_ctx),
                        security_context.as_ref(),
                        "http",
                        &state.mediation_config,
                        Some(&session_id),
                        None,
                    );

                    // Atomically update session while still holding the shard lock
                    if matches!(result.verdict, Verdict::Allow) {
                        let resource_key = format!(
                            "resources/read:{}",
                            uri.chars().take(128).collect::<String>()
                        );
                        if session.call_counts.len() < MAX_CALL_COUNT_TOOLS
                            || session.call_counts.contains_key(&resource_key)
                        {
                            let count = session.call_counts.entry(resource_key).or_insert(0);
                            *count = count.saturating_add(1);
                        }
                        if session.action_history.len() >= MAX_ACTION_HISTORY {
                            session.action_history.pop_front();
                        }
                        session
                            .action_history
                            .push_back("resources/read".to_string());
                    }

                    (result, eval_ctx)
                } else {
                    let eval_ctx = EvaluationContext {
                        agent_id: oauth_claims.as_ref().map(|claims| claims.sub.clone()),
                        agent_identity: agent_identity.clone(),
                        ..EvaluationContext::default()
                    };
                    let result = mediate_with_security_context(
                        &uuid::Uuid::new_v4().to_string().replace('-', ""),
                        &action,
                        &state.engine,
                        Some(&eval_ctx),
                        security_context.as_ref(),
                        "http",
                        &state.mediation_config,
                        Some(&session_id),
                        None,
                    );
                    (result, eval_ctx)
                };
            let mut final_origin = mediation_result.origin;
            let mut acis_envelope = mediation_result.envelope.clone();
            let mut refresh_envelope = false;
            let trace = if params.trace && state.trace_enabled {
                mediation_result.trace.clone()
            } else {
                None
            };
            let verdict = match mediation_result.verdict {
                Verdict::RequireApproval { reason } => match presented_approval_matches_action(
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
                },
                other => other,
            };
            if refresh_envelope {
                let findings = acis_envelope.findings.clone();
                let evaluation_us = acis_envelope.evaluation_us;
                let decision_id = acis_envelope.decision_id.clone();
                acis_envelope = build_acis_envelope_with_security_context(
                    &decision_id,
                    &action,
                    &verdict,
                    final_origin,
                    "http",
                    &findings,
                    evaluation_us,
                    Some(&session_id),
                    None,
                    Some(&eval_ctx),
                    security_context.as_ref(),
                );
            }

            match verdict {
                Verdict::Allow => {
                    // SECURITY (FIND-R112-003): ABAC refinement for resource reads.
                    // Mirror ToolCall ABAC evaluation (R21-PROXY-2): if the PolicyEngine
                    // allowed the action, ABAC may still deny it based on principal/action/
                    // resource/condition constraints.
                    if let Some(ref abac) = state.abac_engine {
                        let abac_eval_ctx = build_evaluation_context(&state.sessions, &session_id)
                            .unwrap_or_default();
                        let principal_id = abac_eval_ctx.agent_id.as_deref().unwrap_or("anonymous");
                        let principal_type = abac_eval_ctx.principal_type();
                        let session_risk = state
                            .sessions
                            .get_mut(&session_id)
                            .and_then(|s| s.risk_score.clone());
                        let abac_ctx = vellaveto_engine::abac::AbacEvalContext {
                            eval_ctx: &abac_eval_ctx,
                            principal_type,
                            principal_id,
                            risk_score: session_risk.as_ref(),
                        };
                        match abac.evaluate(&action, &abac_ctx) {
                            vellaveto_engine::abac::AbacDecision::Deny { policy_id, reason } => {
                                let verdict = Verdict::Deny {
                                    reason: reason.clone(),
                                };
                                let abac_security_context = abac_deny_security_context(&action);
                                let envelope = build_secondary_acis_envelope_with_security_context(
                                    &action,
                                    &verdict,
                                    DecisionOrigin::PolicyEngine,
                                    "http",
                                    Some(&session_id),
                                    Some(&abac_security_context),
                                );
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &action,
                                        &verdict,
                                        build_audit_context(
                                            &session_id,
                                            serde_json::json!({
                                                "uri": uri,
                                                "event": "abac_deny",
                                                "abac_policy": policy_id,
                                            }),
                                            &oauth_claims,
                                        ),
                                        envelope,
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit resource ABAC deny: {}", e);
                                    if let Some(deny) =
                                        audit_strict_deny(&state, msg.get("id"), &session_id)
                                    {
                                        return deny;
                                    }
                                }
                                let response = serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "error": {
                                        "code": -32001,
                                        "message": "Denied by policy"
                                    }
                                });
                                return attach_session_header(
                                    (StatusCode::OK, Json(response)).into_response(),
                                    &session_id,
                                );
                            }
                            vellaveto_engine::abac::AbacDecision::Allow { policy_id } => {
                                // SECURITY (FIND-R192-002): record_usage parity
                                // with ToolCall/TaskRequest/ExtensionMethod.
                                if let Some(ref la) = state.least_agency {
                                    la.record_usage(
                                        principal_id,
                                        &session_id,
                                        &policy_id,
                                        &uri,
                                        &action.function,
                                    );
                                }
                            }
                            vellaveto_engine::abac::AbacDecision::NoMatch => {
                                // Fall through — existing Allow verdict stands
                            }
                            #[allow(unreachable_patterns)]
                            _ => {
                                // SECURITY: Future variants — fail-closed (deny).
                                tracing::warn!(
                                    "Unknown AbacDecision variant in resource_read — fail-closed"
                                );
                                let response = serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "error": {
                                        "code": -32001,
                                        "message": "Denied by policy"
                                    }
                                });
                                return attach_session_header(
                                    (StatusCode::OK, Json(response)).into_response(),
                                    &session_id,
                                );
                            }
                        }
                    }

                    if consume_presented_approval(
                        &state,
                        &session_id,
                        matched_approval_id.as_deref(),
                        &action,
                        security_context.as_ref(),
                    )
                    .await
                    .is_err()
                    {
                        let verdict = Verdict::Deny {
                            reason: INVALID_PRESENTED_APPROVAL_REASON.to_string(),
                        };
                        let invalid_approval_security_context =
                            invalid_presented_approval_security_context(&action);
                        let combined_security_context = merge_transport_security_context(
                            security_context.as_ref(),
                            Some(&invalid_approval_security_context),
                        );
                        let effective_security_context = combined_security_context
                            .as_ref()
                            .unwrap_or(&invalid_approval_security_context);
                        let envelope = build_secondary_acis_envelope_with_security_context(
                            &action,
                            &verdict,
                            DecisionOrigin::ApprovalGate,
                            "http",
                            Some(&session_id),
                            Some(effective_security_context),
                        );
                        if let Err(e) = state
                            .audit
                            .log_entry_with_acis(
                                &action,
                                &verdict,
                                build_audit_context(
                                    &session_id,
                                    json!({
                                        "event": "presented_approval_replay_denied",
                                        "approval_id": matched_approval_id,
                                        "uri": uri,
                                    }),
                                    &oauth_claims,
                                ),
                                envelope,
                            )
                            .await
                        {
                            tracing::warn!("Failed to audit resource replayed approval: {}", e);
                            if let Some(deny) =
                                audit_strict_deny(&state, msg.get("id"), &session_id)
                            {
                                return deny;
                            }
                        }
                        let response = serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": {
                                "code": -32001,
                                "message": "Denied by policy"
                            }
                        });
                        return attach_session_header(
                            (StatusCode::OK, Json(response)).into_response(),
                            &session_id,
                        );
                    }

                    // Canonicalize if configured (KL2 TOCTOU fix)
                    let forward_body = match canonicalize_body(&state, &msg, body) {
                        Some(b) => b,
                        None => {
                            return make_jsonrpc_error(
                                msg.get("id"),
                                -32603,
                                "Internal error: canonicalization failed",
                            )
                        }
                    };
                    let (up_tp, up_ts) =
                        trace_propagation::build_upstream_headers(&vellaveto_trace_ctx, "allow");
                    let response = forward_to_upstream(
                        &state,
                        &session_id,
                        forward_body,
                        UpstreamForwardOptions::post(
                            auth_header_for_upstream.as_deref(),
                            Some((up_tp.as_str(), up_ts.as_deref())),
                            &mcp_param_headers,
                        ),
                    )
                    .await;
                    let response = attach_session_header(response, &session_id);
                    attach_trace_header(response, trace)
                }
                verdict => {
                    let (code, reason) = match &verdict {
                        Verdict::Deny { reason } => (-32001, reason.clone()),
                        Verdict::RequireApproval { reason } => (-32002, reason.clone()),
                        Verdict::Allow => (-32001, "Unexpected Allow verdict".to_string()),
                        // Handle future variants - fail closed
                        _ => (-32001, "Unknown verdict - failing closed".to_string()),
                    };

                    // Create pending approval for RequireApproval verdicts
                    let approval_id = if matches!(&verdict, Verdict::RequireApproval { .. }) {
                        let containment_context =
                            approval_containment_context_from_envelope(&acis_envelope, &reason);
                        let approval_id = create_pending_approval_with_context(
                            &state,
                            &session_id,
                            &action,
                            &reason,
                            containment_context,
                        )
                        .await;
                        if let Some(ref approval_id) = approval_id {
                            tracing::info!(
                                "Created pending approval {} for resource '{}'",
                                approval_id,
                                uri
                            );
                        }
                        approval_id
                    } else {
                        None
                    };

                    let mut audit_metadata = json!({"resource_uri": uri});
                    if code == -32001
                        && reason == INVALID_PRESENTED_APPROVAL_REASON
                        && presented_approval_id.is_some()
                    {
                        audit_metadata["event"] = json!("presented_approval_replay_denied");
                        audit_metadata["approval_id"] = json!(presented_approval_id);
                    }
                    if let Err(e) = state
                        .audit
                        .log_entry_with_acis(
                            &action,
                            &verdict,
                            build_audit_context(&session_id, audit_metadata, &oauth_claims),
                            acis_envelope,
                        )
                        .await
                    {
                        tracing::error!(
                            "AUDIT FAILURE in HTTP proxy: security decision not recorded: {}",
                            e
                        );
                        // SECURITY (FIND-CREATIVE-003): Strict audit mode — fail-closed.
                        if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                            return deny;
                        }
                    }

                    // SECURITY (R38-PROXY-4): Use generic message in client-facing
                    // response to avoid leaking policy names, blocked domains, CIDR
                    // ranges, etc. Detailed reason is preserved in the audit log above.
                    let generic_message = if code == -32002 {
                        "Approval required"
                    } else {
                        "Denied by policy"
                    };
                    let mut response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": code,
                            "message": generic_message,
                            "data": {
                                "type": if code == -32002 { "approval_required" } else { "denied" }
                            }
                        }
                    });
                    if let Some(aid) = approval_id {
                        if let Some(data) =
                            response.get_mut("error").and_then(|e| e.get_mut("data"))
                        {
                            data["approval_id"] = Value::String(aid);
                        }
                    }
                    if let Some(t) = &trace {
                        response["trace"] = serde_json::to_value(t).unwrap_or(Value::Null);
                    }
                    attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    )
                }
            }
        }
        MessageType::SamplingRequest { id } => {
            let params = msg.get("params").cloned().unwrap_or(json!({}));
            // SECURITY (FIND-R125-001): Per-session sampling rate limit parity with elicitation.
            // Atomically read + increment while holding the DashMap lock.
            let sampling_verdict = {
                let mut session_ref = state.sessions.get_mut(&session_id);
                let current_count = session_ref.as_ref().map(|s| s.sampling_count).unwrap_or(0);
                let verdict = vellaveto_mcp::elicitation::inspect_sampling(
                    &params,
                    &state.sampling_config,
                    current_count,
                );
                if matches!(verdict, vellaveto_mcp::elicitation::SamplingVerdict::Allow) {
                    if let Some(ref mut s) = session_ref {
                        s.sampling_count = s.sampling_count.saturating_add(1);
                    }
                }
                verdict
            };
            match sampling_verdict {
                vellaveto_mcp::elicitation::SamplingVerdict::Allow => {
                    // SECURITY (R21-PROXY-2): Use canonicalize_body() consistently
                    // (fail-closed). Previous inline fallback to body.clone() reopened
                    // the TOCTOU gap that canonicalization is designed to close.
                    let forward_body = match canonicalize_body(&state, &msg, body.clone()) {
                        Some(b) => b,
                        None => {
                            return make_jsonrpc_error(
                                msg.get("id"),
                                -32603,
                                "Internal error: canonicalization failed",
                            );
                        }
                    };
                    let (up_tp, up_ts) =
                        trace_propagation::build_upstream_headers(&vellaveto_trace_ctx, "allow");
                    let response = forward_to_upstream(
                        &state,
                        &session_id,
                        forward_body,
                        UpstreamForwardOptions::post(
                            auth_header_for_upstream.as_deref(),
                            Some((up_tp.as_str(), up_ts.as_deref())),
                            &mcp_param_headers,
                        ),
                    )
                    .await;
                    attach_session_header(response, &session_id)
                }
                vellaveto_mcp::elicitation::SamplingVerdict::Deny { reason } => {
                    tracing::warn!(
                        "Blocked sampling/createMessage in session {}: {}",
                        session_id,
                        reason
                    );

                    let action = Action::new(
                        "vellaveto",
                        "sampling_interception",
                        json!({"method": "sampling/createMessage", "session": session_id, "reason": &reason}),
                    );
                    let verdict = Verdict::Deny {
                        reason: reason.clone(),
                    };
                    let sampling_security_context = sampling_interception_security_context(&action);
                    let envelope = build_secondary_acis_envelope_with_security_context(
                        &action,
                        &verdict,
                        DecisionOrigin::PolicyEngine,
                        "http",
                        Some(&session_id),
                        Some(&sampling_security_context),
                    );
                    if let Err(e) = state
                        .audit
                        .log_entry_with_acis(
                            &action,
                            &verdict,
                            json!({"source": "http_proxy", "event": "sampling_interception"}),
                            envelope,
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit sampling interception: {}", e);
                        if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                            return deny;
                        }
                    }

                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            // SECURITY (R39-PROXY-3): Generic message — detailed reason
                            // is in the audit log, not leaked to the client.
                            "message": "sampling/createMessage blocked by policy"
                        }
                    });
                    attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    )
                }
            }
        }
        MessageType::PassThrough | MessageType::ProgressNotification { .. } => {
            // Forward — includes initialize, tools/list, notifications, progress, etc.
            // SECURITY (FIND-R148-002): ProgressNotification merged with PassThrough
            // for DLP + injection scanning parity with WS (mod.rs:2719) and gRPC
            // (service.rs:223). Previously ProgressNotification bypassed all scanning.
            // SECURITY: Audit pass-through requests for visibility. These bypass
            // policy evaluation but must have an audit trail.
            let method_name = msg
                .get("method")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown");
            let action = Action::new(
                "vellaveto",
                "pass_through",
                json!({
                    "method": method_name,
                    "session": &session_id,
                }),
            );
            let protocol_security_context =
                protocol_forward_security_context("pass_through_forwarded");
            let envelope = build_secondary_acis_envelope_with_security_context(
                &action,
                &Verdict::Allow,
                DecisionOrigin::PolicyEngine,
                "http",
                Some(&session_id),
                Some(&protocol_security_context),
            );
            if let Err(e) = state
                .audit
                .log_entry_with_acis(
                    &action,
                    &Verdict::Allow,
                    json!({"source": "http_proxy", "event": "pass_through_forwarded"}),
                    envelope,
                )
                .await
            {
                tracing::warn!("Failed to audit pass-through request: {}", e);
                if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                    return deny;
                }
            }

            // SECURITY (R18-NOTIF-DLP, R29-PROXY-3): Scan ALL PassThrough
            // params for secrets, not just notifications. An agent could
            // exfiltrate secrets via prompts/get, completion/complete, or any
            // PassThrough method's parameters.
            // SECURITY (FIND-R97-001): Remove method gate — JSON-RPC responses
            // (sampling/elicitation replies) have no `method` field but carry
            // data in `result`. Parity with stdio proxy FIND-R96-001.
            if state.response_dlp_enabled {
                let mut dlp_findings = scan_notification_for_secrets(&msg);
                // SECURITY (FIND-R97-001): Also scan `result` field for responses.
                if let Some(result_val) = msg.get("result") {
                    dlp_findings.extend(scan_parameters_for_secrets(result_val));
                }
                // SECURITY (FIND-R83-006): Cap combined findings from params+result
                // scans to maintain per-scan invariant (1000).
                dlp_findings.truncate(1000);
                if !dlp_findings.is_empty() {
                    // IMPROVEMENT_PLAN 1.1: Record DLP metrics
                    for finding in &dlp_findings {
                        record_dlp_finding(&finding.pattern_name);
                    }
                    let patterns: Vec<String> = dlp_findings
                        .iter()
                        .map(|f| format!("{}:{}", f.pattern_name, f.location))
                        .collect();
                    tracing::warn!(
                        "SECURITY: Secrets detected in notification params! \
                         Session: {}, Method: {}, Findings: {:?}",
                        session_id,
                        method_name,
                        patterns
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
                    let n_action = Action::new(
                        "vellaveto",
                        "notification_dlp_scan",
                        json!({
                            "findings": patterns,
                            "method": method_name,
                            "session": session_id,
                        }),
                    );
                    let notification_security_context =
                        notification_dlp_security_context(&msg, state.response_dlp_blocking);
                    let envelope = build_secondary_acis_envelope_with_security_context(
                        &n_action,
                        &verdict,
                        DecisionOrigin::Dlp,
                        "http",
                        Some(&session_id),
                        Some(&notification_security_context),
                    );
                    if let Err(e) = state
                        .audit
                        .log_entry_with_acis(
                            &n_action,
                            &verdict,
                            json!({
                                "source": "http_proxy",
                                "event": "notification_dlp_alert",
                                "blocked": state.response_dlp_blocking,
                            }),
                            envelope,
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit notification DLP: {}", e);
                        if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                            return deny;
                        }
                    }
                    if state.response_dlp_blocking {
                        return make_jsonrpc_error(
                            msg.get("id"),
                            -32002,
                            "Notification blocked: secrets detected in parameters",
                        );
                    }
                }
            }

            // SECURITY (FIND-R112-008): Injection scanning on PassThrough parameters.
            // Parity with WebSocket handler (websocket/mod.rs:600-677) which scans ALL
            // incoming messages. An agent could inject prompt injection payloads via
            // any PassThrough method's parameters (prompts/get, completion/complete, etc.).
            if !state.injection_disabled {
                let scannable = extract_passthrough_text_for_injection(&msg);
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
                            "SECURITY: Injection in HTTP passthrough params! \
                             Session: {}, Method: {}, Patterns: {:?}",
                            session_id,
                            method_name,
                            injection_matches,
                        );

                        let verdict = if state.injection_blocking {
                            Verdict::Deny {
                                reason: format!(
                                    "PassThrough injection blocked: {injection_matches:?}"
                                ),
                            }
                        } else {
                            Verdict::Allow
                        };

                        let inj_action = Action::new(
                            "vellaveto",
                            "passthrough_injection_scan",
                            json!({
                                "matched_patterns": injection_matches,
                                "method": method_name,
                                "session": session_id,
                            }),
                        );
                        let injection_security_context = notification_injection_security_context(
                            &msg,
                            state.injection_blocking,
                            "passthrough_injection",
                        );
                        let envelope = build_secondary_acis_envelope_with_security_context(
                            &inj_action,
                            &verdict,
                            DecisionOrigin::InjectionScanner,
                            "http",
                            Some(&session_id),
                            Some(&injection_security_context),
                        );
                        if let Err(e) = state
                            .audit
                            .log_entry_with_acis(
                                &inj_action,
                                &verdict,
                                json!({
                                    "source": "http_proxy",
                                    "event": "passthrough_injection_detected",
                                    "blocking": state.injection_blocking,
                                }),
                                envelope,
                            )
                            .await
                        {
                            tracing::warn!("Failed to audit passthrough injection: {}", e);
                            if let Some(deny) =
                                audit_strict_deny(&state, msg.get("id"), &session_id)
                            {
                                return deny;
                            }
                        }

                        if state.injection_blocking {
                            return make_jsonrpc_error(
                                msg.get("id"),
                                -32001,
                                "Request blocked: security policy violation",
                            );
                        }
                    }
                }
            }

            // SECURITY (IMP-R184-007): Memory poisoning check — parity with tool calls,
            // resource reads, extension methods, and WS/stdio passthrough handlers.
            if let Some(mut session) = state.sessions.get_mut(&session_id) {
                let params_to_scan = msg.get("params").cloned().unwrap_or(json!({}));
                let mut poisoning_matches =
                    session.memory_tracker.check_parameters(&params_to_scan);
                // IMP-R184-010: Also scan `result` field — parity with DLP (FIND-R96-001).
                if let Some(result_val) = msg.get("result") {
                    poisoning_matches.extend(session.memory_tracker.check_parameters(result_val));
                }
                if !poisoning_matches.is_empty() {
                    for m in &poisoning_matches {
                        tracing::warn!(
                            "SECURITY: Memory poisoning in HTTP passthrough '{}' (session {}): \
                             param '{}' replayed data (fingerprint: {})",
                            method_name,
                            session_id,
                            m.param_location,
                            m.fingerprint
                        );
                    }
                    let poison_action = Action::new(
                        "vellaveto",
                        "http_passthrough_memory_poisoning",
                        json!({
                            "method": method_name,
                            "session": &session_id,
                            "matches": poisoning_matches.len(),
                            "transport": "http",
                        }),
                    );
                    let pt_poison_verdict = Verdict::Deny {
                        reason: format!(
                            "HTTP passthrough blocked: memory poisoning ({} matches)",
                            poisoning_matches.len()
                        ),
                    };
                    let poisoning_security_context =
                        notification_memory_poisoning_security_context(&msg, "memory_poisoning");
                    let envelope = build_secondary_acis_envelope_with_security_context(
                        &poison_action,
                        &pt_poison_verdict,
                        DecisionOrigin::MemoryPoisoning,
                        "http",
                        Some(&session_id),
                        Some(&poisoning_security_context),
                    );
                    if let Err(e) = state
                        .audit
                        .log_entry_with_acis(
                            &poison_action,
                            &pt_poison_verdict,
                            json!({
                                "source": "http_proxy",
                                "event": "http_passthrough_memory_poisoning",
                            }),
                            envelope,
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit HTTP passthrough memory poisoning: {}", e);
                        if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                            return deny;
                        }
                    }
                    return make_jsonrpc_error(
                        msg.get("id"),
                        -32001,
                        "Request blocked: security policy violation",
                    );
                }
                // Fingerprint for future poisoning detection.
                session.memory_tracker.extract_from_value(&params_to_scan);
                if let Some(result_val) = msg.get("result") {
                    session.memory_tracker.extract_from_value(result_val);
                }
            } else {
                // IMP-R186-003: Log when session is missing so the skip is observable.
                tracing::warn!(
                    "Session {} not found for HTTP passthrough memory poisoning check",
                    session_id
                );
            }

            // Canonicalize if configured (KL2 TOCTOU fix)
            let forward_body = match canonicalize_body(&state, &msg, body) {
                Some(b) => b,
                None => {
                    return make_jsonrpc_error(
                        msg.get("id"),
                        -32603,
                        "Internal error: canonicalization failed",
                    )
                }
            };
            let (up_tp, up_ts) =
                trace_propagation::build_upstream_headers(&vellaveto_trace_ctx, "allow");
            let response = forward_to_upstream(
                &state,
                &session_id,
                forward_body,
                UpstreamForwardOptions::post(
                    auth_header_for_upstream.as_deref(),
                    Some((up_tp.as_str(), up_ts.as_deref())),
                    &mcp_param_headers,
                ),
            )
            .await;

            attach_session_header(response, &session_id)
        }
        MessageType::ElicitationRequest { id } => {
            // SECURITY (R38-PROXY-2): Pre-increment elicitation count while
            // holding the DashMap lock to prevent TOCTOU concurrent bypass.
            // Previous approach: read count → release lock → forward → increment
            // allowed concurrent requests to all read the same count and bypass.
            // New approach: read + increment atomically, then rollback on failure.
            let params = msg.get("params").cloned().unwrap_or(json!({}));
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
                    // SECURITY (R21-PROXY-2): Use canonicalize_body() consistently
                    // (fail-closed). Previous inline fallback to body.clone() reopened
                    // the TOCTOU gap that canonicalization is designed to close.
                    let forward_body = match canonicalize_body(&state, &msg, body.clone()) {
                        Some(b) => b,
                        None => {
                            // Rollback the pre-incremented count on failure
                            if let Some(mut s) = state.sessions.get_mut(&session_id) {
                                s.elicitation_count = s.elicitation_count.saturating_sub(1);
                            }
                            return make_jsonrpc_error(
                                msg.get("id"),
                                -32603,
                                "Internal error: canonicalization failed",
                            );
                        }
                    };
                    let (up_tp, up_ts) =
                        trace_propagation::build_upstream_headers(&vellaveto_trace_ctx, "allow");
                    let response = forward_to_upstream(
                        &state,
                        &session_id,
                        forward_body,
                        UpstreamForwardOptions::post(
                            auth_header_for_upstream.as_deref(),
                            Some((up_tp.as_str(), up_ts.as_deref())),
                            &mcp_param_headers,
                        ),
                    )
                    .await;

                    // SECURITY (R38-PROXY-2): Rollback the pre-incremented count
                    // if upstream rejects the request, so failed requests don't
                    // consume the elicitation budget.
                    if !response.status().is_success() {
                        if let Some(mut s) = state.sessions.get_mut(&session_id) {
                            s.elicitation_count = s.elicitation_count.saturating_sub(1);
                        }
                    }

                    attach_session_header(response, &session_id)
                }
                vellaveto_mcp::elicitation::ElicitationVerdict::Deny { reason } => {
                    tracing::warn!(
                        "Blocked elicitation/create in session {}: {}",
                        session_id,
                        reason
                    );

                    let action = Action::new(
                        "vellaveto",
                        "elicitation_interception",
                        json!({"method": "elicitation/create", "session": session_id, "reason": &reason}),
                    );
                    let verdict = Verdict::Deny {
                        reason: reason.clone(),
                    };
                    let elicitation_security_context =
                        elicitation_interception_security_context(&action);
                    let envelope = build_secondary_acis_envelope_with_security_context(
                        &action,
                        &verdict,
                        DecisionOrigin::PolicyEngine,
                        "http",
                        Some(&session_id),
                        Some(&elicitation_security_context),
                    );
                    if let Err(e) = state
                        .audit
                        .log_entry_with_acis(
                            &action,
                            &verdict,
                            json!({"source": "http_proxy", "event": "elicitation_interception"}),
                            envelope,
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit elicitation interception: {}", e);
                        if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                            return deny;
                        }
                    }

                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            // SECURITY (R39-PROXY-3): Generic message — detailed reason
                            // is in the audit log, not leaked to the client.
                            "message": "elicitation/create blocked by policy"
                        }
                    });
                    attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    )
                }
            }
        }
        MessageType::TaskRequest {
            id,
            task_method,
            task_id,
        } => {
            // NOTE (FIND-R44-052): validate_call_chain_header is handled by the
            // pre-match check above (line ~289). No per-arm call needed here.

            // Keep per-request call-chain context in sync for task policy checks.
            sync_session_call_chain_from_headers(
                &state.sessions,
                &session_id,
                &headers,
                state.call_chain_hmac_key.as_ref(),
                &state.limits,
            );

            // R4-1 FIX: Evaluate task requests against policies.
            // Task responses (especially tasks/get) can contain tool results
            // with sensitive data. tasks/cancel can disrupt workflows.
            tracing::debug!(
                "Task request in session {}: {} (task_id: {:?})",
                session_id,
                task_method,
                task_id
            );

            // SECURITY (R27-PROXY-2): Check for memory poisoning in task params.
            let task_params_for_poison = msg.get("params").cloned().unwrap_or(json!({}));
            if let Some(session) = state.sessions.get_mut(&session_id) {
                let poisoning_matches = session
                    .memory_tracker
                    .check_parameters(&task_params_for_poison);
                if !poisoning_matches.is_empty() {
                    for m in &poisoning_matches {
                        tracing::warn!(
                            "SECURITY: Memory poisoning detected in task '{}' (session {}): \
                             param '{}' contains replayed data (fingerprint: {})",
                            task_method,
                            session_id,
                            m.param_location,
                            m.fingerprint
                        );
                    }
                    let action = extractor::extract_task_action(&task_method, task_id.as_deref());
                    let deny_reason = format!(
                        "Memory poisoning detected: {} replayed data fragment(s) in task '{}'",
                        poisoning_matches.len(),
                        task_method
                    );
                    let task_poison_verdict = Verdict::Deny {
                        reason: deny_reason.clone(),
                    };
                    let poisoning_security_context = memory_poisoning_security_context(
                        &task_params_for_poison,
                        "memory_poisoning",
                    );
                    let envelope = build_secondary_acis_envelope_with_security_context(
                        &action,
                        &task_poison_verdict,
                        DecisionOrigin::MemoryPoisoning,
                        "http",
                        Some(&session_id),
                        Some(&poisoning_security_context),
                    );
                    if let Err(e) = state
                        .audit
                        .log_entry_with_acis(
                            &action,
                            &task_poison_verdict,
                            build_audit_context(
                                &session_id,
                                json!({
                                    "event": "memory_poisoning_detected",
                                    "matches": poisoning_matches.len(),
                                    "task_method": task_method,
                                }),
                                &oauth_claims,
                            ),
                            envelope,
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit memory poisoning: {}", e);
                        if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                            return deny;
                        }
                    }
                    let error_response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": "Request blocked: security policy violation"
                        }
                    });
                    return attach_session_header(
                        (StatusCode::OK, Json(error_response)).into_response(),
                        &session_id,
                    );
                }
            }

            // SECURITY (FIND-R222-008): Injection scanning on task request parameters.
            // Parity with PassThrough (line 2237) and gRPC (FIND-R222-001). An agent
            // could inject prompt injection payloads via task method parameters.
            if !state.injection_disabled {
                let scannable = extract_passthrough_text_for_injection(&msg);
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
                            "SECURITY: Injection in HTTP task request params! \
                             Session: {}, Method: {}, Patterns: {:?}",
                            session_id,
                            task_method,
                            injection_matches,
                        );

                        let inj_action = Action::new(
                            "vellaveto",
                            "task_injection_scan",
                            json!({
                                "matched_patterns": injection_matches,
                                "method": task_method,
                                "session": session_id,
                            }),
                        );
                        let verdict = if state.injection_blocking {
                            Verdict::Deny {
                                reason: format!(
                                    "Task request injection blocked: {injection_matches:?}"
                                ),
                            }
                        } else {
                            Verdict::Allow
                        };
                        let injection_security_context = parameter_injection_security_context(
                            &task_params_for_poison,
                            state.injection_blocking,
                            "task_injection",
                        );
                        let envelope = build_secondary_acis_envelope_with_security_context(
                            &inj_action,
                            &verdict,
                            DecisionOrigin::InjectionScanner,
                            "http",
                            Some(&session_id),
                            Some(&injection_security_context),
                        );
                        if let Err(e) = state
                            .audit
                            .log_entry_with_acis(
                                &inj_action,
                                &verdict,
                                json!({
                                    "source": "http_proxy",
                                    "event": "task_injection_detected",
                                    "blocking": state.injection_blocking,
                                }),
                                envelope,
                            )
                            .await
                        {
                            tracing::warn!("Failed to audit task injection: {}", e);
                            if let Some(deny) =
                                audit_strict_deny(&state, msg.get("id"), &session_id)
                            {
                                return deny;
                            }
                        }

                        if state.injection_blocking {
                            let response = json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "error": {
                                    "code": -32001,
                                    "message": "Request blocked: security policy violation"
                                }
                            });
                            return attach_session_header(
                                (StatusCode::OK, Json(response)).into_response(),
                                &session_id,
                            );
                        }
                    }
                }
            }

            // R4-1: DLP scan task request parameters for secret exfiltration.
            // An agent could embed secrets in the task_id field to exfiltrate
            // them via task management operations.
            let task_params = msg.get("params").cloned().unwrap_or(json!({}));
            let dlp_findings = scan_parameters_for_secrets(&task_params);
            if !dlp_findings.is_empty() {
                // IMPROVEMENT_PLAN 1.1: Record DLP metrics
                for finding in &dlp_findings {
                    record_dlp_finding(&finding.pattern_name);
                }
                tracing::warn!(
                    "SECURITY: DLP alert for task '{}' in session {}: {:?}",
                    task_method,
                    session_id,
                    dlp_findings
                        .iter()
                        .map(|f| &f.pattern_name)
                        .collect::<Vec<_>>()
                );
                let dlp_action = extractor::extract_task_action(&task_method, task_id.as_deref());
                let patterns: Vec<String> = dlp_findings
                    .iter()
                    .map(|f| format!("{} at {}", f.pattern_name, f.location))
                    .collect();
                // SECURITY (R37-PROXY-3): Keep detailed reason for audit, generic for client
                let audit_reason = format!("DLP: secrets detected in task request: {patterns:?}");
                let task_dlp_verdict = Verdict::Deny {
                    reason: audit_reason.clone(),
                };
                let parameter_security_context =
                    parameter_dlp_security_context(&task_params, true, "task_parameter_dlp");
                let envelope = build_secondary_acis_envelope_with_security_context(
                    &dlp_action,
                    &task_dlp_verdict,
                    DecisionOrigin::Dlp,
                    "http",
                    Some(&session_id),
                    Some(&parameter_security_context),
                );
                if let Err(e) = state
                    .audit
                    .log_entry_with_acis(
                        &dlp_action,
                        &task_dlp_verdict,
                        build_audit_context(
                            &session_id,
                            json!({
                                "event": "dlp_secret_detected_task",
                                "task_method": task_method,
                                "findings": patterns,
                            }),
                            &oauth_claims,
                        ),
                        envelope,
                    )
                    .await
                {
                    tracing::warn!("Failed to audit DLP finding: {}", e);
                    if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                        return deny;
                    }
                }
                let response = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32001,
                        "message": "Request blocked: security policy violation",
                    }
                });
                return attach_session_header(
                    (StatusCode::OK, Json(response)).into_response(),
                    &session_id,
                );
            }

            let action = extractor::extract_task_action(&task_method, task_id.as_deref());
            let mut matched_approval_id: Option<String> = None;

            // SECURITY (FIND-R190-007): TOCTOU-safe context+eval for task requests.
            // Read context and evaluate inside a single DashMap shard lock, matching
            // the ToolCall pattern (line 725-789). Without this, concurrent TaskRequests
            // can bypass max_calls_in_window by reading stale call_counts.
            // Deadlock fix: build pre_eval_ctx + security_context BEFORE get_mut so that
            // build_runtime_security_context never acquires a read shard while get_mut holds
            // the write shard on the same DashMap.
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
                    agent_identity: agent_identity.clone(),
                    ..EvaluationContext::default()
                });
            let security_context = build_runtime_security_context(
                &msg,
                &action,
                &headers,
                TransportSecurityInputs {
                    oauth_evidence: oauth_claims.as_ref(),
                    eval_ctx: Some(&pre_eval_ctx),
                    sessions: &state.sessions,
                    session_id: Some(&session_id),
                    trusted_request_signers: &state.trusted_request_signers,
                    detached_signature_freshness: state.detached_signature_freshness,
                },
            );
            let (mediation_result, eval_ctx) =
                if let Some(mut session) = state.sessions.get_mut(&session_id) {
                    let eval_ctx = EvaluationContext {
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
                        Some(&eval_ctx),
                        security_context.as_ref(),
                        "http",
                        &state.mediation_config,
                        Some(&session_id),
                        None,
                    );

                    // Atomically update session on Allow while holding shard lock
                    if matches!(result.verdict, Verdict::Allow) {
                        session.touch();
                        if session.call_counts.len() < MAX_CALL_COUNT_TOOLS
                            || session.call_counts.contains_key(&task_method)
                        {
                            let count = session.call_counts.entry(task_method.clone()).or_insert(0);
                            *count = count.saturating_add(1);
                        }
                        if session.action_history.len() >= MAX_ACTION_HISTORY {
                            session.action_history.pop_front();
                        }
                        session.action_history.push_back(task_method.clone());
                    }

                    (result, eval_ctx)
                } else {
                    let eval_ctx = EvaluationContext {
                        agent_id: oauth_claims.as_ref().map(|claims| claims.sub.clone()),
                        agent_identity: agent_identity.clone(),
                        ..EvaluationContext::default()
                    };
                    let result = mediate_with_security_context(
                        &uuid::Uuid::new_v4().to_string().replace('-', ""),
                        &action,
                        &state.engine,
                        Some(&eval_ctx),
                        security_context.as_ref(),
                        "http",
                        &state.mediation_config,
                        Some(&session_id),
                        None,
                    );
                    (result, eval_ctx)
                };

            let mut final_origin = mediation_result.origin;
            let mut acis_envelope = mediation_result.envelope.clone();
            let mut refresh_envelope = false;
            let trace = if params.trace && state.trace_enabled {
                mediation_result.trace.clone()
            } else {
                None
            };
            let verdict = match mediation_result.verdict {
                Verdict::RequireApproval { reason } => match presented_approval_matches_action(
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
                },
                other => other,
            };
            if refresh_envelope {
                let findings = acis_envelope.findings.clone();
                let evaluation_us = acis_envelope.evaluation_us;
                let decision_id = acis_envelope.decision_id.clone();
                acis_envelope = build_acis_envelope_with_security_context(
                    &decision_id,
                    &action,
                    &verdict,
                    final_origin,
                    "http",
                    &findings,
                    evaluation_us,
                    Some(&session_id),
                    None,
                    Some(&eval_ctx),
                    security_context.as_ref(),
                );
            }

            match verdict {
                Verdict::Allow => {
                    // SECURITY (FIND-R190-001): ABAC refinement for TaskRequest,
                    // matching ToolCall/ResourceRead parity.
                    if let Some(ref abac) = state.abac_engine {
                        let abac_eval_ctx = build_evaluation_context(&state.sessions, &session_id)
                            .unwrap_or_default();
                        let principal_id = abac_eval_ctx.agent_id.as_deref().unwrap_or("anonymous");
                        let principal_type = abac_eval_ctx.principal_type();
                        let session_risk = state
                            .sessions
                            .get_mut(&session_id)
                            .and_then(|s| s.risk_score.clone());
                        let abac_ctx = vellaveto_engine::abac::AbacEvalContext {
                            eval_ctx: &abac_eval_ctx,
                            principal_type,
                            principal_id,
                            risk_score: session_risk.as_ref(),
                        };

                        match abac.evaluate(&action, &abac_ctx) {
                            vellaveto_engine::abac::AbacDecision::Deny { policy_id, reason } => {
                                let verdict = Verdict::Deny {
                                    reason: reason.clone(),
                                };
                                let abac_security_context = abac_deny_security_context(&action);
                                let envelope = build_secondary_acis_envelope_with_security_context(
                                    &action,
                                    &verdict,
                                    DecisionOrigin::PolicyEngine,
                                    "http",
                                    Some(&session_id),
                                    Some(&abac_security_context),
                                );
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &action,
                                        &verdict,
                                        build_audit_context(
                                            &session_id,
                                            json!({
                                                "task_method": task_method,
                                                "event": "abac_deny",
                                                "abac_policy": policy_id,
                                            }),
                                            &oauth_claims,
                                        ),
                                        envelope,
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit task ABAC deny: {}", e);
                                    if let Some(deny) =
                                        audit_strict_deny(&state, msg.get("id"), &session_id)
                                    {
                                        return deny;
                                    }
                                }
                                return attach_session_header(
                                    make_jsonrpc_error(msg.get("id"), -32001, "Denied by policy"),
                                    &session_id,
                                );
                            }
                            vellaveto_engine::abac::AbacDecision::Allow { policy_id } => {
                                if let Some(ref la) = state.least_agency {
                                    la.record_usage(
                                        principal_id,
                                        &session_id,
                                        &policy_id,
                                        &task_method,
                                        &action.function,
                                    );
                                }
                            }
                            vellaveto_engine::abac::AbacDecision::NoMatch => {}
                            #[allow(unreachable_patterns)]
                            _ => {
                                tracing::warn!("Unknown AbacDecision variant — fail-closed");
                                return attach_session_header(
                                    make_jsonrpc_error(msg.get("id"), -32001, "Denied by policy"),
                                    &session_id,
                                );
                            }
                        }
                    }

                    if consume_presented_approval(
                        &state,
                        &session_id,
                        matched_approval_id.as_deref(),
                        &action,
                        security_context.as_ref(),
                    )
                    .await
                    .is_err()
                    {
                        let verdict = Verdict::Deny {
                            reason: INVALID_PRESENTED_APPROVAL_REASON.to_string(),
                        };
                        let invalid_approval_security_context =
                            invalid_presented_approval_security_context(&action);
                        let combined_security_context = merge_transport_security_context(
                            security_context.as_ref(),
                            Some(&invalid_approval_security_context),
                        );
                        let effective_security_context = combined_security_context
                            .as_ref()
                            .unwrap_or(&invalid_approval_security_context);
                        let envelope = build_secondary_acis_envelope_with_security_context(
                            &action,
                            &verdict,
                            DecisionOrigin::ApprovalGate,
                            "http",
                            Some(&session_id),
                            Some(effective_security_context),
                        );
                        if let Err(e) = state
                            .audit
                            .log_entry_with_acis(
                                &action,
                                &verdict,
                                build_audit_context(
                                    &session_id,
                                    json!({
                                        "event": "presented_approval_replay_denied",
                                        "approval_id": matched_approval_id,
                                        "task_method": task_method,
                                        "task_id": task_id,
                                    }),
                                    &oauth_claims,
                                ),
                                envelope,
                            )
                            .await
                        {
                            tracing::warn!("Failed to audit task replayed approval: {}", e);
                            if let Some(deny) =
                                audit_strict_deny(&state, msg.get("id"), &session_id)
                            {
                                return deny;
                            }
                        }
                        return attach_session_header(
                            make_jsonrpc_error(msg.get("id"), -32001, "Denied by policy"),
                            &session_id,
                        );
                    }

                    if let Err(e) = state
                        .audit
                        .log_entry_with_acis(
                            &action,
                            &Verdict::Allow,
                            build_audit_context(
                                &session_id,
                                json!({
                                    "event": "task_request_forwarded",
                                    "task_method": task_method,
                                    "task_id": task_id,
                                }),
                                &oauth_claims,
                            ),
                            acis_envelope,
                        )
                        .await
                    {
                        tracing::error!(
                            "AUDIT FAILURE in HTTP proxy: security decision not recorded: {}",
                            e
                        );
                        // SECURITY (FIND-CREATIVE-003): Strict audit mode — fail-closed.
                        if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                            return deny;
                        }
                    }

                    let forward_body = match canonicalize_body(&state, &msg, body) {
                        Some(b) => b,
                        None => {
                            return make_jsonrpc_error(
                                msg.get("id"),
                                -32603,
                                "Internal error: canonicalization failed",
                            )
                        }
                    };
                    let (up_tp, up_ts) =
                        trace_propagation::build_upstream_headers(&vellaveto_trace_ctx, "allow");
                    let response = forward_to_upstream(
                        &state,
                        &session_id,
                        forward_body,
                        UpstreamForwardOptions::post(
                            auth_header_for_upstream.as_deref(),
                            Some((up_tp.as_str(), up_ts.as_deref())),
                            &mcp_param_headers,
                        ),
                    )
                    .await;
                    let response = attach_trace_header(response, trace);
                    attach_session_header(response, &session_id)
                }
                Verdict::Deny { reason } => {
                    let verdict = Verdict::Deny {
                        reason: reason.clone(),
                    };
                    let mut audit_metadata = json!({
                        "event": "task_request_denied",
                        "task_method": task_method,
                        "task_id": task_id,
                    });
                    if reason == INVALID_PRESENTED_APPROVAL_REASON
                        && presented_approval_id.is_some()
                    {
                        audit_metadata["event"] = json!("presented_approval_replay_denied");
                        audit_metadata["approval_id"] = json!(presented_approval_id);
                    }
                    if let Err(e) = state
                        .audit
                        .log_entry_with_acis(
                            &action,
                            &verdict,
                            build_audit_context(&session_id, audit_metadata, &oauth_claims),
                            acis_envelope,
                        )
                        .await
                    {
                        tracing::error!(
                            "AUDIT FAILURE in HTTP proxy: security decision not recorded: {}",
                            e
                        );
                        // SECURITY (FIND-CREATIVE-003): Strict audit mode — fail-closed.
                        if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                            return deny;
                        }
                    }
                    // SECURITY (R38-PROXY-4): Use generic message in client-facing
                    // response to avoid leaking policy names, blocked domains, CIDR
                    // ranges, etc. Detailed reason is preserved in the audit log above.
                    let mut response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": "Denied by policy",
                            "data": {
                                "type": "policy_denial"
                            }
                        }
                    });
                    if let Some(t) = trace {
                        response["trace"] = serde_json::to_value(t).unwrap_or(Value::Null);
                    }
                    attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    )
                }
                Verdict::RequireApproval { reason } => {
                    let verdict = Verdict::RequireApproval {
                        reason: reason.clone(),
                    };
                    let containment_context =
                        approval_containment_context_from_envelope(&acis_envelope, &reason);
                    let approval_id = create_pending_approval_with_context(
                        &state,
                        &session_id,
                        &action,
                        &reason,
                        containment_context,
                    )
                    .await;
                    if let Err(e) = state
                        .audit
                        .log_entry_with_acis(
                            &action,
                            &verdict,
                            build_audit_context(
                                &session_id,
                                json!({
                                    "event": "task_request_requires_approval",
                                    "task_method": task_method,
                                    "task_id": task_id,
                                }),
                                &oauth_claims,
                            ),
                            acis_envelope,
                        )
                        .await
                    {
                        tracing::error!(
                            "AUDIT FAILURE in HTTP proxy: security decision not recorded: {}",
                            e
                        );
                        // SECURITY (FIND-CREATIVE-003): Strict audit mode — fail-closed.
                        if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                            return deny;
                        }
                    }
                    // SECURITY (R38-PROXY-4): Use generic message in client-facing
                    // response. Detailed reason is preserved in the audit log above.
                    let mut response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32002,
                            "message": "Approval required",
                            "data": {
                                "type": "approval_required"
                            }
                        }
                    });
                    if let Some(aid) = approval_id {
                        if let Some(data) = response
                            .get_mut("error")
                            .and_then(|error| error.get_mut("data"))
                        {
                            data["approval_id"] = Value::String(aid);
                        }
                    }
                    if let Some(t) = trace {
                        response["trace"] = serde_json::to_value(t).unwrap_or(Value::Null);
                    }
                    attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    )
                }
                _ => {
                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": "Unknown verdict - failing closed"
                        }
                    });
                    attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    )
                }
            }
        }
        MessageType::Batch => {
            tracing::warn!("Rejected JSON-RPC batch request in session {}", session_id);
            // SECURITY: Audit batch rejection (R4-12).
            let batch_action = Action::new(
                "vellaveto",
                "batch_rejected",
                json!({
                    "session": &session_id,
                }),
            );
            let batch_verdict = Verdict::Deny {
                reason: "JSON-RPC batching not supported".to_string(),
            };
            let batch_security_context = batch_rejection_security_context(&batch_action);
            let envelope = build_secondary_acis_envelope_with_security_context(
                &batch_action,
                &batch_verdict,
                DecisionOrigin::PolicyEngine,
                "http",
                Some(&session_id),
                Some(&batch_security_context),
            );
            if let Err(e) = state
                .audit
                .log_entry_with_acis(
                    &batch_action,
                    &batch_verdict,
                    json!({"source": "http_proxy", "event": "batch_rejected"}),
                    envelope,
                )
                .await
            {
                tracing::warn!("Failed to audit batch rejection: {}", e);
                if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                    return deny;
                }
            }
            // SECURITY (FIND-R92-001): Use BATCH_NOT_ALLOWED for parity with
            // make_batch_error_response() and correct semantic error code.
            let response = json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {
                    "code": vellaveto_types::json_rpc::BATCH_NOT_ALLOWED,
                    "message": "JSON-RPC batching is not supported (MCP 2025-06-18)"
                }
            });
            attach_session_header(
                (StatusCode::OK, Json(response)).into_response(),
                &session_id,
            )
        }
        MessageType::ExtensionMethod {
            ref id,
            ref extension_id,
            ref method,
        } => {
            // Policy-evaluate extension method calls
            let params = msg.get("params").cloned().unwrap_or(json!({}));

            // SECURITY (FIND-R222-008): Injection scanning on extension method parameters.
            // Parity with gRPC (FIND-R222-001), PassThrough (line 2237), and TaskRequest.
            if !state.injection_disabled {
                let scannable = extract_passthrough_text_for_injection(&msg);
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
                            "SECURITY: Injection in HTTP extension method params! \
                             Session: {}, Extension: {}:{}, Patterns: {:?}",
                            session_id,
                            extension_id,
                            method,
                            injection_matches,
                        );

                        let inj_action = Action::new(
                            "vellaveto",
                            "extension_injection_scan",
                            json!({
                                "matched_patterns": injection_matches,
                                "extension_id": extension_id,
                                "method": method,
                                "session": session_id,
                            }),
                        );
                        let verdict = if state.injection_blocking {
                            Verdict::Deny {
                                reason: format!(
                                    "Extension injection blocked: {injection_matches:?}"
                                ),
                            }
                        } else {
                            Verdict::Allow
                        };
                        let injection_security_context = parameter_injection_security_context(
                            &params,
                            state.injection_blocking,
                            "extension_injection",
                        );
                        let envelope = build_secondary_acis_envelope_with_security_context(
                            &inj_action,
                            &verdict,
                            DecisionOrigin::InjectionScanner,
                            "http",
                            Some(&session_id),
                            Some(&injection_security_context),
                        );
                        if let Err(e) = state
                            .audit
                            .log_entry_with_acis(
                                &inj_action,
                                &verdict,
                                json!({
                                    "source": "http_proxy",
                                    "event": "extension_injection_detected",
                                    "blocking": state.injection_blocking,
                                }),
                                envelope,
                            )
                            .await
                        {
                            tracing::warn!("Failed to audit extension injection: {}", e);
                            if let Some(deny) =
                                audit_strict_deny(&state, msg.get("id"), &session_id)
                            {
                                return deny;
                            }
                        }

                        if state.injection_blocking {
                            return make_jsonrpc_error(
                                Some(id),
                                -32001,
                                "Request blocked: security policy violation",
                            );
                        }
                    }
                }
            }

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
                    "SECURITY: Secrets in HTTP extension method parameters! Session: {}, Extension: {}:{}, Findings: {:?}",
                    session_id, extension_id, method, patterns,
                );
                let action = extractor::extract_extension_action(extension_id, method, &params);
                let audit_verdict = Verdict::Deny {
                    reason: format!(
                        "DLP blocked: secret detected in extension parameters: {patterns:?}"
                    ),
                };
                let parameter_security_context =
                    parameter_dlp_security_context(&params, true, "extension_parameter_dlp");
                let envelope = build_secondary_acis_envelope_with_security_context(
                    &action,
                    &audit_verdict,
                    DecisionOrigin::Dlp,
                    "http",
                    Some(&session_id),
                    Some(&parameter_security_context),
                );
                if let Err(e) = state.audit.log_entry_with_acis(
                    &action, &audit_verdict,
                    build_audit_context(&session_id, json!({
                        "event": "extension_parameter_dlp_alert",
                        "extension_id": extension_id, "method": method, "findings": patterns,
                    }), &oauth_claims),
                    envelope,
                ).await {
                    tracing::warn!("Failed to audit extension parameter DLP: {}", e);
                    if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                        return deny;
                    }
                }
                return make_jsonrpc_error(Some(id), -32001, "Denied by policy");
            }

            // SECURITY (FIND-R116-001): Memory poisoning detection for extension params.
            // Parity with gRPC handle_extension_method (service.rs:1574).
            if let Some(session) = state.sessions.get_mut(&session_id) {
                let poisoning_matches = session.memory_tracker.check_parameters(&params);
                if !poisoning_matches.is_empty() {
                    for m in &poisoning_matches {
                        tracing::warn!(
                            "SECURITY: Memory poisoning in HTTP extension '{}:{}' (session {}): \
                             param '{}' replayed data (fingerprint: {})",
                            extension_id,
                            method,
                            session_id,
                            m.param_location,
                            m.fingerprint
                        );
                    }
                    let action = extractor::extract_extension_action(extension_id, method, &params);
                    let deny_reason = format!(
                        "Memory poisoning detected: {} replayed data fragment(s) in extension '{}:{}'",
                        poisoning_matches.len(), extension_id, method
                    );
                    let ext_poison_verdict = Verdict::Deny {
                        reason: deny_reason.clone(),
                    };
                    let poisoning_security_context =
                        memory_poisoning_security_context(&params, "memory_poisoning");
                    let envelope = build_secondary_acis_envelope_with_security_context(
                        &action,
                        &ext_poison_verdict,
                        DecisionOrigin::MemoryPoisoning,
                        "http",
                        Some(&session_id),
                        Some(&poisoning_security_context),
                    );
                    if let Err(e) = state
                        .audit
                        .log_entry_with_acis(
                            &action,
                            &ext_poison_verdict,
                            build_audit_context(
                                &session_id,
                                json!({
                                    "event": "memory_poisoning_detected",
                                    "matches": poisoning_matches.len(),
                                    "extension_id": extension_id, "method": method,
                                }),
                                &oauth_claims,
                            ),
                            envelope,
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit extension memory poisoning: {}", e);
                        if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                            return deny;
                        }
                    }
                    return make_jsonrpc_error(Some(id), -32001, "Denied by policy");
                }
            }

            let mut action = extractor::extract_extension_action(extension_id, method, &params);
            let mut matched_approval_id: Option<String> = None;

            // SECURITY (FIND-R118-004): DNS resolution for extension methods.
            // Parity with ToolCall (line 721) and ResourceRead (line 1660).
            if state.engine.has_ip_rules() {
                resolve_domains(&mut action).await;
            }

            let ext_key = format!("extension:{extension_id}:{method}");

            // Deadlock fix: build pre_eval_ctx + security_context BEFORE get_mut so that
            // build_runtime_security_context never acquires a read shard while get_mut holds
            // the write shard on the same DashMap.
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
                    agent_identity: agent_identity.clone(),
                    ..EvaluationContext::default()
                });
            let security_context = build_runtime_security_context(
                &msg,
                &action,
                &headers,
                TransportSecurityInputs {
                    oauth_evidence: oauth_claims.as_ref(),
                    eval_ctx: Some(&pre_eval_ctx),
                    sessions: &state.sessions,
                    session_id: Some(&session_id),
                    trusted_request_signers: &state.trusted_request_signers,
                    detached_signature_freshness: state.detached_signature_freshness,
                },
            );
            let (mediation_result, eval_ctx) =
                if let Some(mut session) = state.sessions.get_mut(&session_id) {
                    let eval_ctx = EvaluationContext {
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
                        Some(&eval_ctx),
                        security_context.as_ref(),
                        "http",
                        &state.mediation_config,
                        Some(&session_id),
                        None,
                    );

                    if matches!(result.verdict, Verdict::Allow) {
                        if session.call_counts.len() < MAX_CALL_COUNT_TOOLS
                            || session.call_counts.contains_key(&ext_key)
                        {
                            let count = session.call_counts.entry(ext_key.clone()).or_insert(0);
                            *count = count.saturating_add(1);
                        }
                        if session.action_history.len() >= MAX_ACTION_HISTORY {
                            session.action_history.pop_front();
                        }
                        session.action_history.push_back(ext_key.clone());
                    }

                    (result, eval_ctx)
                } else {
                    let eval_ctx = EvaluationContext {
                        agent_id: oauth_claims.as_ref().map(|claims| claims.sub.clone()),
                        agent_identity: agent_identity.clone(),
                        ..EvaluationContext::default()
                    };
                    let result = mediate_with_security_context(
                        &uuid::Uuid::new_v4().to_string().replace('-', ""),
                        &action,
                        &state.engine,
                        Some(&eval_ctx),
                        security_context.as_ref(),
                        "http",
                        &state.mediation_config,
                        Some(&session_id),
                        None,
                    );
                    (result, eval_ctx)
                };

            let mut final_origin = mediation_result.origin;
            let mut acis_envelope = mediation_result.envelope.clone();
            let mut refresh_envelope = false;
            let verdict = match mediation_result.verdict {
                Verdict::RequireApproval { reason } => match presented_approval_matches_action(
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
                },
                other => other,
            };
            if refresh_envelope {
                let findings = acis_envelope.findings.clone();
                let evaluation_us = acis_envelope.evaluation_us;
                let decision_id = acis_envelope.decision_id.clone();
                acis_envelope = build_acis_envelope_with_security_context(
                    &decision_id,
                    &action,
                    &verdict,
                    final_origin,
                    "http",
                    &findings,
                    evaluation_us,
                    Some(&session_id),
                    None,
                    Some(&eval_ctx),
                    security_context.as_ref(),
                );
            }

            match verdict {
                Verdict::Allow => {
                    // SECURITY (FIND-R118-002): ABAC refinement for extension methods.
                    // Parity with ToolCall (line 859) and ResourceRead (line 1778).
                    if let Some(ref abac) = state.abac_engine {
                        let abac_eval_ctx = build_evaluation_context(&state.sessions, &session_id)
                            .unwrap_or_default();
                        let principal_id = abac_eval_ctx.agent_id.as_deref().unwrap_or("anonymous");
                        let principal_type = abac_eval_ctx.principal_type();
                        let session_risk = state
                            .sessions
                            .get_mut(&session_id)
                            .and_then(|s| s.risk_score.clone());
                        let abac_ctx = vellaveto_engine::abac::AbacEvalContext {
                            eval_ctx: &abac_eval_ctx,
                            principal_type,
                            principal_id,
                            risk_score: session_risk.as_ref(),
                        };

                        match abac.evaluate(&action, &abac_ctx) {
                            vellaveto_engine::abac::AbacDecision::Deny { policy_id, reason } => {
                                let verdict = Verdict::Deny {
                                    reason: reason.clone(),
                                };
                                let abac_security_context = abac_deny_security_context(&action);
                                let envelope = build_secondary_acis_envelope_with_security_context(
                                    &action,
                                    &verdict,
                                    DecisionOrigin::PolicyEngine,
                                    "http",
                                    Some(&session_id),
                                    Some(&abac_security_context),
                                );
                                if let Err(e) = state
                                    .audit
                                    .log_entry_with_acis(
                                        &action,
                                        &verdict,
                                        build_audit_context(
                                            &session_id,
                                            serde_json::json!({
                                                "extension_id": extension_id,
                                                "method": method,
                                                "event": "abac_deny",
                                                "abac_policy": policy_id,
                                            }),
                                            &oauth_claims,
                                        ),
                                        envelope,
                                    )
                                    .await
                                {
                                    tracing::warn!("Failed to audit extension ABAC deny: {}", e);
                                    if let Some(deny) =
                                        audit_strict_deny(&state, msg.get("id"), &session_id)
                                    {
                                        return deny;
                                    }
                                }
                                let response = serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "error": {
                                        "code": -32001,
                                        "message": "Denied by policy"
                                    }
                                });
                                return attach_session_header(
                                    (StatusCode::OK, Json(response)).into_response(),
                                    &session_id,
                                );
                            }
                            vellaveto_engine::abac::AbacDecision::Allow { policy_id } => {
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
                                // Fall through — existing Allow verdict stands
                            }
                            #[allow(unreachable_patterns)] // AbacDecision is #[non_exhaustive]
                            _ => {
                                // SECURITY: Future variants — fail-closed (deny).
                                tracing::warn!("Unknown AbacDecision variant — fail-closed");
                                let response = serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "error": {
                                        "code": -32001,
                                        "message": "Denied by policy"
                                    }
                                });
                                return attach_session_header(
                                    (StatusCode::OK, Json(response)).into_response(),
                                    &session_id,
                                );
                            }
                        }
                    }

                    if consume_presented_approval(
                        &state,
                        &session_id,
                        matched_approval_id.as_deref(),
                        &action,
                        security_context.as_ref(),
                    )
                    .await
                    .is_err()
                    {
                        let verdict = Verdict::Deny {
                            reason: INVALID_PRESENTED_APPROVAL_REASON.to_string(),
                        };
                        let invalid_approval_security_context =
                            invalid_presented_approval_security_context(&action);
                        let combined_security_context = merge_transport_security_context(
                            security_context.as_ref(),
                            Some(&invalid_approval_security_context),
                        );
                        let effective_security_context = combined_security_context
                            .as_ref()
                            .unwrap_or(&invalid_approval_security_context);
                        let envelope = build_secondary_acis_envelope_with_security_context(
                            &action,
                            &verdict,
                            DecisionOrigin::ApprovalGate,
                            "http",
                            Some(&session_id),
                            Some(effective_security_context),
                        );
                        if let Err(e) = state
                            .audit
                            .log_entry_with_acis(
                                &action,
                                &verdict,
                                build_audit_context(
                                    &session_id,
                                    json!({
                                        "event": "presented_approval_replay_denied",
                                        "approval_id": matched_approval_id,
                                        "extension_id": extension_id,
                                        "method": method,
                                    }),
                                    &oauth_claims,
                                ),
                                envelope,
                            )
                            .await
                        {
                            tracing::warn!("Failed to audit extension replayed approval: {}", e);
                            if let Some(deny) =
                                audit_strict_deny(&state, msg.get("id"), &session_id)
                            {
                                return deny;
                            }
                        }
                        return attach_session_header(
                            make_jsonrpc_error(msg.get("id"), -32001, "Denied by policy"),
                            &session_id,
                        );
                    }

                    if let Err(e) = state
                        .audit
                        .log_entry_with_acis(
                            &action,
                            &Verdict::Allow,
                            build_audit_context(
                                &session_id,
                                json!({
                                    "event": "extension_method_allowed",
                                    "extension_id": extension_id,
                                    "method": method,
                                }),
                                &oauth_claims,
                            ),
                            acis_envelope,
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit extension allow: {}", e);
                        if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                            return deny;
                        }
                    }
                    let forward_body = match canonicalize_body(&state, &msg, body) {
                        Some(b) => b,
                        None => {
                            return make_jsonrpc_error(
                                msg.get("id"),
                                -32603,
                                "Internal error: canonicalization failed",
                            )
                        }
                    };
                    let (up_tp, up_ts) =
                        trace_propagation::build_upstream_headers(&vellaveto_trace_ctx, "allow");
                    let response = forward_to_upstream(
                        &state,
                        &session_id,
                        forward_body,
                        UpstreamForwardOptions::post(
                            auth_header_for_upstream.as_deref(),
                            Some((up_tp.as_str(), up_ts.as_deref())),
                            &mcp_param_headers,
                        ),
                    )
                    .await;
                    attach_session_header(response, &session_id)
                }
                Verdict::Deny { reason } => {
                    let ext_deny_verdict = Verdict::Deny {
                        reason: reason.clone(),
                    };
                    let mut audit_metadata = json!({
                        "event": "extension_method_denied",
                        "extension_id": extension_id,
                        "method": method,
                        "reason": &reason,
                    });
                    if reason == INVALID_PRESENTED_APPROVAL_REASON
                        && presented_approval_id.is_some()
                    {
                        audit_metadata["event"] = json!("presented_approval_replay_denied");
                        audit_metadata["approval_id"] = json!(presented_approval_id);
                    }
                    if let Err(e) = state
                        .audit
                        .log_entry_with_acis(
                            &action,
                            &ext_deny_verdict,
                            build_audit_context(&session_id, audit_metadata, &oauth_claims),
                            acis_envelope,
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit extension deny: {}", e);
                        if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                            return deny;
                        }
                    }
                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": "Denied by policy"
                        }
                    });
                    attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    )
                }
                Verdict::RequireApproval { reason } => {
                    let verdict = Verdict::RequireApproval {
                        reason: reason.clone(),
                    };
                    let containment_context =
                        approval_containment_context_from_envelope(&acis_envelope, &reason);
                    let approval_id = create_pending_approval_with_context(
                        &state,
                        &session_id,
                        &action,
                        &reason,
                        containment_context,
                    )
                    .await;
                    if let Err(e) = state
                        .audit
                        .log_entry_with_acis(
                            &action,
                            &verdict,
                            build_audit_context(
                                &session_id,
                                json!({
                                    "event": "extension_method_requires_approval",
                                    "extension_id": extension_id,
                                    "method": method,
                                }),
                                &oauth_claims,
                            ),
                            acis_envelope,
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit extension approval request: {}", e);
                        if let Some(deny) = audit_strict_deny(&state, msg.get("id"), &session_id) {
                            return deny;
                        }
                    }
                    let mut response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32002,
                            "message": "Approval required",
                            "data": {
                                "type": "approval_required"
                            }
                        }
                    });
                    if let Some(aid) = approval_id {
                        if let Some(data) = response
                            .get_mut("error")
                            .and_then(|error| error.get_mut("data"))
                        {
                            data["approval_id"] = Value::String(aid);
                        }
                    }
                    attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    )
                }
                _ => {
                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {
                            "code": -32001,
                            "message": "Denied by policy"
                        }
                    });
                    attach_session_header(
                        (StatusCode::OK, Json(response)).into_response(),
                        &session_id,
                    )
                }
            }
        }
        MessageType::Invalid { id, reason } => {
            // SECURITY (FIND-R80-001): Log the detailed reason at warn level but do NOT
            // include attacker-controlled `reason` in the client response. This prevents
            // information leakage that could help attackers craft better payloads.
            tracing::warn!("Invalid JSON-RPC request: {}", reason);
            let response = json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32600,
                    "message": "Invalid JSON-RPC request"
                }
            });
            attach_session_header(
                (StatusCode::OK, Json(response)).into_response(),
                &session_id,
            )
        }
    }
}

/// DELETE /mcp handler — session termination (MCP spec).
///
/// When OAuth is configured, verifies that the authenticated user owns the
/// session before allowing deletion. Prevents cross-user session termination.
pub async fn handle_mcp_delete(
    State(state): State<ProxyState>,
    OriginalUri(original_uri): OriginalUri,
    proxy_ctx: Option<Extension<TrustedProxyContext>>,
    headers: HeaderMap,
) -> Response {
    // CSRF / DNS rebinding origin validation (TASK-015)
    if let Err(response) = validate_origin(&headers, &state.bind_addr, &state.allowed_origins) {
        return response;
    }

    // API key validation (if configured) — fast check before OAuth
    if let Err(response) = validate_api_key(&state, &headers) {
        return response;
    }

    // SECURITY (FIND-R44-053): Reject oversized session IDs to prevent
    // memory abuse or hash-flooding attacks. Server-generated IDs are UUIDs
    // (36 chars); anything over MAX_SESSION_ID_LENGTH is suspicious.
    // SECURITY (FIND-R86-001): Also reject Unicode format characters for
    // parity with gRPC and WebSocket handlers.
    let session_id = headers
        .get(MCP_SESSION_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|id| {
            id.len() <= MAX_SESSION_ID_LENGTH
                && !id
                    .chars()
                    .any(|c| c.is_control() || is_unicode_format_char(c))
        });

    // If the header was present but filtered out due to length or control chars, return 400.
    if headers.get(MCP_SESSION_ID).is_some() && session_id.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid session ID"})),
        )
            .into_response();
    }

    // OAuth 2.1 token validation (if configured)
    let from_trusted_proxy = proxy_ctx
        .map(|Extension(ctx)| ctx.from_trusted_proxy)
        .unwrap_or(false);
    let effective_uri =
        build_effective_request_uri(&headers, state.bind_addr, &original_uri, from_trusted_proxy);
    let oauth_claims =
        match validate_oauth(&state, &headers, "DELETE", &effective_uri, session_id).await {
            Ok(claims) => claims,
            Err(response) => return response,
        };

    // SECURITY (FIND-R159-001): Validate call chain header on DELETE for parity
    // with POST (line 323) and GET (line 3649). Prevents oversized or malformed
    // X-Upstream-Agents headers from reaching downstream code.
    if let Err(reason) = validate_call_chain_header(&headers, &state.limits) {
        tracing::warn!("DELETE /mcp: call chain validation failed: {}", reason);
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid request"})),
        )
            .into_response();
    }

    match session_id {
        Some(id) => {
            // Session ownership check: when OAuth is active, only the session
            // owner can delete their session. Prevents User A from terminating
            // User B's session by guessing the UUID.
            if let Some(ref claims) = oauth_claims {
                if let Some(session) = state.sessions.get_mut(id) {
                    if let Some(ref owner) = session.oauth_subject {
                        if owner != &claims.sub {
                            tracing::warn!(
                                "SECURITY: User '{}' attempted to delete session {} owned by '{}'",
                                claims.sub,
                                id,
                                owner
                            );
                            return (
                                StatusCode::FORBIDDEN,
                                Json(json!({"error": "Session owned by another user"})),
                            )
                                .into_response();
                        }
                    }
                    // Drop the session lock before removing
                    drop(session);
                }
            }

            if state.sessions.remove(id) {
                tracing::info!("Session terminated: {}", id);
                // SECURITY (FIND-R55-HTTP-004): Audit session termination for SOC 2 CC6.1.
                {
                    let audit_action = vellaveto_types::Action {
                        tool: "session".to_string(),
                        function: "terminate".to_string(),
                        parameters: serde_json::Value::Object(serde_json::Map::new()),
                        target_paths: Vec::new(),
                        target_domains: Vec::new(),
                        resolved_ips: Vec::new(),
                    };
                    let session_security_context = session_termination_security_context();
                    let envelope = build_secondary_acis_envelope_with_security_context(
                        &audit_action,
                        &vellaveto_types::Verdict::Allow,
                        DecisionOrigin::SessionGuard,
                        "http",
                        Some(id),
                        Some(&session_security_context),
                    );
                    if let Err(e) = state
                        .audit
                        .log_entry_with_acis(
                            &audit_action,
                            &vellaveto_types::Verdict::Allow,
                            serde_json::json!({
                                "session_id": id,
                                "transport": "http",
                                "event": "session_terminated",
                            }),
                            envelope,
                        )
                        .await
                    {
                        // SECURITY (R272-HTTP-1): deliberately NOT fail-closed.
                        // `state.sessions.remove(id)` above has already
                        // succeeded and cannot be undone here, so returning a
                        // denial would tell the client the termination failed
                        // when it did not. Strict mode denies requests so an
                        // unaudited decision does not take effect; this effect
                        // has already taken effect. The warning is the honest
                        // signal, and the gap is the audit record, not the
                        // enforcement.
                        tracing::warn!("Failed to audit session termination: {}", e);
                    }
                }
                // MCP spec: 204 No Content on successful session termination
                StatusCode::NO_CONTENT.into_response()
            } else {
                tracing::debug!("DELETE for unknown session: {}", id);
                StatusCode::NOT_FOUND.into_response()
            }
        }
        None => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Missing Mcp-Session-Id header"})),
        )
            .into_response(),
    }
}

/// GET /.well-known/oauth-protected-resource handler (RFC 9728).
///
/// Returns protected resource metadata when OAuth is configured, enabling
/// clients to discover authorization requirements before making requests.
pub async fn handle_protected_resource_metadata(State(state): State<ProxyState>) -> Response {
    match &state.oauth {
        Some(validator) => {
            let config = validator.config();
            let mut metadata = serde_json::json!({
                "resource": config.expected_resource.as_deref().unwrap_or(&config.audience),
                "authorization_servers": [config.issuer],
                "scopes_supported": config.required_scopes,
                "bearer_methods_supported": ["header"],
                "resource_documentation": "https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization"
            });
            if config.dpop_mode != crate::oauth::DpopMode::Off {
                metadata["dpop_signing_alg_values_supported"] =
                    serde_json::json!(config.dpop_allowed_algorithms);
            }
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                Json(metadata),
            )
                .into_response()
        }
        None => {
            // OAuth not configured — return 404 as there's no protected resource
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

/// Build transport targets for the smart fallback chain (Phase 29).
///
/// In gateway mode, uses `BackendConfig.transport_urls` for per-transport endpoints.
/// In single-server mode, derives targets from `upstream_url`, `grpc_port`, and
/// WebSocket path conventions.
pub(crate) fn build_transport_targets(
    state: &ProxyState,
    gateway_decision: Option<&vellaveto_types::RoutingDecision>,
    priorities: &[vellaveto_types::TransportProtocol],
) -> Vec<super::smart_fallback::TransportTarget> {
    use vellaveto_types::TransportProtocol;

    let mut targets = Vec::new();

    if let Some(ref gw) = state.gateway {
        // Gateway mode: use backend transport_urls.
        if let Some(decision) = gateway_decision {
            let config = gw.backend_config(&decision.backend_id);
            for proto in priorities {
                let url = config
                    .and_then(|c| c.transport_urls.get(proto))
                    .cloned()
                    .unwrap_or_else(|| {
                        // Fall back to the primary backend URL for HTTP.
                        if *proto == TransportProtocol::Http {
                            decision.upstream_url.clone()
                        } else {
                            String::new()
                        }
                    });
                if !url.is_empty() {
                    targets.push(super::smart_fallback::TransportTarget {
                        protocol: *proto,
                        url,
                        upstream_id: decision.backend_id.clone(),
                    });
                }
            }
        }
    } else {
        // Single-server mode: derive from upstream_url + grpc_port.
        for proto in priorities {
            let url = match proto {
                TransportProtocol::Http => state.upstream_url.clone(),
                TransportProtocol::Grpc => {
                    if let Some(grpc_port) = state.grpc_port {
                        // Extract host from upstream_url via simple string parsing.
                        let host =
                            extract_host_from_url(&state.upstream_url).unwrap_or("127.0.0.1");
                        // SECURITY (FIND-R43-029): Wrap IPv6 addresses in brackets
                        // to produce valid URLs (e.g., "http://[::1]:50051").
                        if host.contains(':') {
                            format!("http://[{host}]:{grpc_port}")
                        } else {
                            format!("http://{host}:{grpc_port}")
                        }
                    } else {
                        continue;
                    }
                }
                TransportProtocol::WebSocket => {
                    // SECURITY (FIND-R43-014): Only replace scheme prefix, not occurrences in path/query.
                    let ws_url = if state.upstream_url.starts_with("https://") {
                        format!("wss://{}", &state.upstream_url["https://".len()..])
                    } else if state.upstream_url.starts_with("http://") {
                        format!("ws://{}", &state.upstream_url["http://".len()..])
                    } else {
                        state.upstream_url.clone()
                    };
                    if ws_url.ends_with("/mcp") {
                        format!("{ws_url}/ws")
                    } else {
                        format!("{}/ws", ws_url.trim_end_matches('/'))
                    }
                }
                TransportProtocol::Stdio => "stdio://local".to_string(),
            };
            targets.push(super::smart_fallback::TransportTarget {
                protocol: *proto,
                url,
                upstream_id: "default".to_string(),
            });
        }
    }

    targets
}

/// Extract host from a URL string without the `url` crate.
/// Returns the host portion (between `://` and the next `/` or `:`).
///
/// SECURITY (FIND-R42-003): Handles userinfo (`user:pass@host`) by stripping
/// everything before the last `@` in the authority component. Also handles
/// IPv6 addresses in brackets (`[::1]:8080`).
pub(crate) fn extract_host_from_url(url: &str) -> Option<&str> {
    let after_scheme = url.find("://").map(|i| &url[i + 3..]).unwrap_or(url);
    // SECURITY (FIND-R44-004): Strip fragment before authority parsing.
    // Fragments (#...) are not part of the authority per RFC 3986 but
    // if present they can cause discrepancy between this parser and reqwest.
    let no_fragment = after_scheme.split('#').next().unwrap_or(after_scheme);
    // Strip path and query to get authority component.
    let authority = no_fragment.split('/').next().unwrap_or(no_fragment);
    // SECURITY (FIND-R42-003): Strip userinfo (user:pass@host) to prevent
    // SSRF via @-smuggling (e.g., "http://safe@evil/path").
    // SECURITY (FIND-R43-023): Also handle URL-encoded @ (%40) in authority
    // to prevent bypass of userinfo stripping (e.g., "http://safe%40evil/path").
    let host_port = match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => match authority.rfind("%40") {
            Some(i) => &authority[i + 3..],
            None => authority,
        },
    };
    // Handle IPv6 addresses in brackets (e.g., "[::1]:8080").
    if host_port.starts_with('[') {
        let end = host_port.find(']')?;
        let ipv6 = &host_port[1..end];
        if ipv6.is_empty() {
            return None;
        }
        // SECURITY (FIND-R44-051): Strip IPv6 zone ID (e.g., "fe80::1%25eth0"
        // → "fe80::1"). Zone IDs are link-local scope identifiers encoded as
        // %25<zone> in URIs (RFC 6874). Strip them so the raw IPv6 address is
        // matched against allow-lists without the interface suffix.
        let ipv6 = ipv6.split("%25").next().unwrap_or(ipv6);
        if ipv6.is_empty() {
            return None;
        }
        return Some(ipv6);
    }
    // SECURITY (FIND-R44-023): Reject host_port containing percent-encoded
    // special characters (%25xx). Double-encoding like %2540 (which decodes to
    // %40, then @) can bypass the userinfo stripping above. Fail-closed: any
    // %25 in the non-bracketed host_port is suspicious and rejected.
    // NOTE: This check is placed after the IPv6 bracket branch because %25
    // is legitimately used for zone IDs in bracketed IPv6 addresses (RFC 6874).
    if host_port.contains("%25") {
        return None;
    }
    // IPv4 or hostname: strip port.
    let host = host_port.split(':').next().unwrap_or(host_port);
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

// ═══════════════════════════════════════════════════
// GET /mcp — SSE Resumability (MCP 2025-11-25, Phase 30)
// ═══════════════════════════════════════════════════

/// Header name for SSE resumption.
const LAST_EVENT_ID_HEADER: &str = "last-event-id";

/// GET /mcp handler for SSE stream initiation/resumption.
///
/// MCP 2025-11-25 requires servers to support GET /mcp for clients to
/// initiate or resume SSE streams. The client sends `Accept: text/event-stream`
/// and optionally `Last-Event-ID` for resumption.
///
/// Gated behind `streamable_http.resumability_enabled` — returns 405 when disabled.
///
/// SECURITY (R45): Full security peer to `handle_mcp_post` — includes session
/// ownership binding, agent identity validation, call chain validation, audit
/// logging, and gateway mode rejection (no tool-based routing for SSE resumption).
pub async fn handle_mcp_get(
    State(state): State<ProxyState>,
    OriginalUri(original_uri): OriginalUri,
    proxy_ctx: Option<Extension<TrustedProxyContext>>,
    headers: HeaderMap,
) -> Response {
    // Gate: resumability must be enabled
    // SECURITY (FIND-R45-013): Generic error message — do not leak config details.
    if !state.streamable_http.resumability_enabled {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            Json(json!({
                "error": "Method not allowed"
            })),
        )
            .into_response();
    }

    // Validate Accept header — must request text/event-stream
    let accept = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !accept.contains("text/event-stream") {
        return (
            StatusCode::NOT_ACCEPTABLE,
            Json(json!({
                "error": "Not acceptable"
            })),
        )
            .into_response();
    }

    if let Err(response) = validate_mcp_protocol_version_header(&state, &headers) {
        return *response;
    }

    // CSRF / DNS rebinding origin validation (same as POST)
    if let Err(response) = validate_origin(&headers, &state.bind_addr, &state.allowed_origins) {
        return response;
    }

    // API key validation (same as POST)
    if let Err(response) = validate_api_key(&state, &headers) {
        return response;
    }

    // SECURITY (FIND-R73-SRV-011): Validate session ID length and reject control chars
    // before OAuth, matching the DELETE and POST handler patterns.
    // SECURITY (FIND-R86-001): Also reject Unicode format characters for
    // parity with gRPC and WebSocket handlers.
    let client_session_id = headers
        .get(MCP_SESSION_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|id| {
            id.len() <= MAX_SESSION_ID_LENGTH
                && !id
                    .chars()
                    .any(|c| c.is_control() || is_unicode_format_char(c))
        });

    if headers.get(MCP_SESSION_ID).is_some() && client_session_id.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid session ID"})),
        )
            .into_response();
    }

    // OAuth 2.1 token validation (FIND-R45-001: extract claims for session binding)
    let from_trusted_proxy = proxy_ctx
        .map(|Extension(ctx)| ctx.from_trusted_proxy)
        .unwrap_or(false);
    let effective_uri =
        build_effective_request_uri(&headers, state.bind_addr, &original_uri, from_trusted_proxy);
    let oauth_claims =
        match validate_oauth(&state, &headers, "GET", &effective_uri, client_session_id).await {
            Ok(claims) => claims,
            Err(response) => return response,
        };

    // SECURITY (FIND-R45-002): Agent identity attestation via X-Agent-Identity JWT
    // (same as POST path). Without this, GET requests bypass identity validation.
    let agent_identity = match validate_agent_identity(&state, &headers).await {
        Ok(identity) => identity,
        Err(response) => return response,
    };

    // Extract and validate Last-Event-ID
    let last_event_id = headers
        .get(LAST_EVENT_ID_HEADER)
        .and_then(|v| v.to_str().ok());

    // SECURITY: Fail-closed on oversized event IDs
    if let Some(event_id) = last_event_id {
        if event_id.len() > state.streamable_http.max_event_id_length {
            tracing::warn!(
                "SECURITY: Rejecting oversized Last-Event-ID ({} bytes, max {})",
                event_id.len(),
                state.streamable_http.max_event_id_length
            );
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "Invalid request"
                })),
            )
                .into_response();
        }
        // SECURITY (FIND-R45-010): Reject event IDs with control characters.
        // Also reject URL-scheme prefixes to prevent SSRF via upstream event ID parsing.
        // SECURITY (FIND-R86-001): Also reject Unicode format characters for
        // parity with gRPC and WebSocket handlers.
        if event_id
            .chars()
            .any(|c| c.is_control() || is_unicode_format_char(c))
        {
            tracing::warn!("SECURITY: Rejecting Last-Event-ID with control/format characters");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "Invalid request"
                })),
            )
                .into_response();
        }
    }

    // Session management (session ID length validated inside get_or_create)
    let session_id = state.sessions.get_or_create(client_session_id);

    // SECURITY (FIND-R45-001): Atomic session ownership check + bind.
    // Without this, an attacker can hijack another user's SSE stream by
    // providing their session ID in the GET request.
    if let Some(ref claims) = oauth_claims {
        if let Some(mut session) = state.sessions.get_mut(&session_id) {
            match &session.oauth_subject {
                Some(owner) if owner != &claims.sub => {
                    tracing::warn!(
                        "SECURITY: Session fixation attempt on GET blocked — session {} owned by '{}', request from '{}'",
                        session_id, owner, claims.sub
                    );
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "jsonrpc": "2.0",
                            "error": {"code": -32001, "message": "Session owned by another user"},
                            "id": null
                        })),
                    )
                        .into_response();
                }
                None => {
                    session.oauth_subject = Some(claims.sub.clone());
                    if claims.exp > 0 {
                        session.token_expires_at = Some(claims.exp);
                    }
                }
                _ => {
                    // SECURITY (R23-PROXY-6): Use the EARLIEST token expiry
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

    // SECURITY (FIND-R45-002): Store agent identity in session for context-aware evaluation
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
                    "OAuth transport identity claims validation failed: {}",
                    error
                );
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "Invalid authorization token"})),
                )
                    .into_response();
            }
        }
    }

    // SECURITY (FIND-R45-003): Validate call chain header (same as POST pre-match check).
    // Without this, malformed X-Upstream-Agents headers pass through on GET.
    if let Err(reason) = validate_call_chain_header(&headers, &state.limits) {
        let action = Action::new(
            "vellaveto",
            "invalid_call_chain_header",
            json!({
                "method": "GET /mcp",
                "reason": reason,
            }),
        );
        let verdict = Verdict::Deny {
            reason: format!("Invalid upstream call chain header: {reason}"),
        };
        let call_chain_security_context = invalid_call_chain_security_context();
        let envelope = build_secondary_acis_envelope_with_security_context(
            &action,
            &verdict,
            DecisionOrigin::PolicyEngine,
            "http",
            Some(&session_id),
            Some(&call_chain_security_context),
        );
        if let Err(e) = state
            .audit
            .log_entry_with_acis(
                &action,
                &verdict,
                build_audit_context(
                    &session_id,
                    json!({
                        "event": "invalid_call_chain_header",
                        "method": "GET /mcp",
                        "reason": reason,
                    }),
                    &oauth_claims,
                ),
                envelope,
            )
            .await
        {
            tracing::warn!("Failed to audit invalid call-chain header on GET: {}", e);
            // SECURITY (FIND-R206-004): Strict audit mode parity with HTTP POST.
            if let Some(deny) = audit_strict_deny(&state, None, &session_id) {
                return deny;
            }
        }
        tracing::warn!(reason = %reason, "GET /mcp: Call chain validation failed");
        return attach_session_header(
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "jsonrpc": "2.0",
                    "error": {"code": -32600, "message": "Invalid request"},
                    "id": null
                })),
            )
                .into_response(),
            &session_id,
        );
    }

    // SECURITY (FIND-R45-009 + FIND-R45-014): Touch session to update
    // activity timestamp and increment request_count. Without this, GET
    // requests don't extend session lifetime and aren't counted for rate
    // limiting, enabling DoS via repeated reconnections (FIND-R45-011).
    if let Some(mut session) = state.sessions.get_mut(&session_id) {
        session.touch();
    }

    // SECURITY (FIND-R45-008): Reject GET in gateway mode. SSE resumption
    // reconnects to a session-scoped stream, but in gateway mode the backend
    // is determined per-tool-call. Without session-scoped backend tracking,
    // we cannot route the GET to the correct upstream.
    if state.gateway.is_some() {
        tracing::warn!(
            "GET /mcp not supported in gateway mode — backend selection requires tool routing"
        );
        return attach_session_header(
            (
                StatusCode::NOT_IMPLEMENTED,
                Json(json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32000,
                        "message": "SSE resumability not available in gateway mode"
                    },
                    "id": null
                })),
            )
                .into_response(),
            &session_id,
        );
    }

    // Phase 28: Extract W3C Trace Context
    let incoming_trace = trace_propagation::extract_trace_context(&headers);
    let (vellaveto_trace_ctx, _vellaveto_span_id) =
        trace_propagation::create_vellaveto_span(&incoming_trace);

    // Determine Authorization header for upstream
    let auth_header_for_upstream = if state
        .oauth
        .as_ref()
        .is_some_and(|v| v.config().pass_through)
    {
        headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    } else {
        None
    };

    let (up_tp, up_ts) = trace_propagation::build_upstream_headers(&vellaveto_trace_ctx, "sse_get");

    // SECURITY (FIND-R45-004): Audit log the SSE resumption request.
    // Without this, GET /mcp requests leave no audit trail, preventing
    // forensic analysis and compliance evidence.
    let sse_action = Action::new(
        "vellaveto",
        "sse_resumption",
        json!({
            "session": &session_id,
            "has_last_event_id": last_event_id.is_some(),
        }),
    );
    let sse_security_context = protocol_forward_security_context("sse_resumption");
    let envelope = build_secondary_acis_envelope_with_security_context(
        &sse_action,
        &Verdict::Allow,
        DecisionOrigin::PolicyEngine,
        "http",
        Some(&session_id),
        Some(&sse_security_context),
    );
    if let Err(e) = state
        .audit
        .log_entry_with_acis(
            &sse_action,
            &Verdict::Allow,
            build_audit_context(
                &session_id,
                json!({
                    "event": "sse_get_request",
                    "last_event_id_present": last_event_id.is_some(),
                }),
                &oauth_claims,
            ),
            envelope,
        )
        .await
    {
        tracing::warn!("Failed to audit SSE GET request: {}", e);
        // SECURITY (FIND-R206-004): Strict audit mode parity with HTTP POST.
        if let Some(deny) = audit_strict_deny(&state, None, &session_id) {
            return deny;
        }
    }

    // Forward GET to upstream
    let response = super::upstream::forward_get_to_upstream(
        &state,
        &session_id,
        auth_header_for_upstream.as_deref(),
        Some((up_tp.as_str(), up_ts.as_deref())),
        last_event_id,
    )
    .await;

    attach_session_header(response, &session_id)
}

/// Extract scannable text from a PassThrough JSON-RPC message for injection scanning.
///
/// SECURITY (FIND-R112-008): Recursively extracts string values from `params` and
/// `result` fields. Bounded to prevent memory amplification from deeply nested or
/// highly branched JSON structures.
fn extract_passthrough_text_for_injection(msg: &Value) -> String {
    // SECURITY (FIND-R155-002): Raised from 10 to 32 for parity with WS handler
    // (FIND-R154-005) and shared MAX_SCAN_DEPTH in scanner_base.rs. Previous limit
    // allowed injection payloads nested at depth 11-32 to evade HTTP scanning.
    const MAX_DEPTH: usize = 32;
    const MAX_PARTS: usize = 1000;
    let mut parts = Vec::new();

    // Scan params (client→upstream direction)
    if let Some(params) = msg.get("params") {
        extract_strings_for_injection(params, &mut parts, 0, MAX_DEPTH, MAX_PARTS);
    }
    // Scan result (upstream→client direction, e.g. sampling/elicitation responses)
    if let Some(result) = msg.get("result") {
        extract_strings_for_injection(result, &mut parts, 0, MAX_DEPTH, MAX_PARTS);
    }

    parts.join("\n")
}

/// Recursively extract string values from a JSON value with depth and count bounds.
fn extract_strings_for_injection(
    val: &Value,
    parts: &mut Vec<String>,
    depth: usize,
    max_depth: usize,
    max_parts: usize,
) {
    if depth > max_depth || parts.len() >= max_parts {
        return;
    }
    match val {
        Value::String(s) => parts.push(s.clone()),
        Value::Array(arr) => {
            for item in arr {
                extract_strings_for_injection(item, parts, depth + 1, max_depth, max_parts);
            }
        }
        Value::Object(map) => {
            for (key, v) in map {
                // SECURITY (FIND-R155-001): Also scan object keys for injection
                // payloads. Parity with WS extract_strings_recursive (FIND-R154-003).
                if parts.len() < max_parts {
                    parts.push(key.clone());
                }
                extract_strings_for_injection(v, parts, depth + 1, max_depth, max_parts);
            }
        }
        _ => {}
    }
}
