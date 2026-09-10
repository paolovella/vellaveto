// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! McpService gRPC implementation.
//!
//! Implements the tonic-generated `McpService` trait with the same policy
//! evaluation pipeline as the HTTP and WebSocket handlers:
//! 1. Convert proto → JSON
//! 2. Classify message
//! 3. Evaluate policy (tool calls, resource reads)
//! 4. Audit
//! 5. Forward to upstream
//! 6. DLP/injection scan response
//! 7. Convert JSON → proto

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use vellaveto_mcp::extractor::{self, MessageType};
use vellaveto_mcp::inspection::{
    inspect_for_injection, scan_notification_for_secrets, scan_parameters_for_secrets,
    scan_response_for_secrets, scan_tool_descriptions, scan_tool_descriptions_with_scanner,
};
use vellaveto_mcp::mediation::{
    build_acis_envelope_with_security_context, build_secondary_acis_envelope_with_security_context,
};
use vellaveto_mcp::output_validation::ValidationResult;
use vellaveto_types::acis::DecisionOrigin;
use vellaveto_types::{Action, EvaluationContext, RuntimeSecurityContext, Verdict};

use super::convert::{
    json_to_proto_response, make_proto_denial_response, make_proto_error_response,
    make_proto_error_response_with_data, proto_request_to_json,
};
use super::interceptors::{
    contains_dangerous_chars, extract_or_generate_request_id, extract_request_signature,
    extract_session_id,
};
use super::proto::{
    mcp_service_server::McpService, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse,
    SubscribeRequest,
};
use super::upstream::UpstreamForwarder;
use super::ProxyState;
use crate::proxy::call_chain::{
    check_privilege_escalation, MAX_ACTION_HISTORY, MAX_CALL_COUNT_TOOLS,
};
use crate::proxy::helpers::{
    abac_deny_security_context, approval_containment_context_from_security_context,
    batch_rejection_security_context, build_runtime_security_context_with_request_signature,
    circuit_breaker_security_context, create_pending_approval_with_context,
    elicitation_interception_security_context, invalid_presented_approval_security_context,
    memory_poisoning_security_context, notification_dlp_security_context,
    notification_injection_security_context, notification_memory_poisoning_security_context,
    output_schema_violation_security_context, parameter_dlp_security_context,
    parameter_injection_security_context, privilege_escalation_security_context,
    protocol_forward_security_context, require_approval_security_context, resolve_domains,
    response_dlp_security_context, response_injection_security_context, rug_pull_security_context,
    sampling_interception_security_context, tool_discovery_integrity_security_context,
    unknown_tool_approval_gate_security_context, untrusted_tool_approval_gate_security_context,
};
use crate::proxy_metrics::record_dlp_finding;

/// Global gRPC metrics counters.
static GRPC_REQUESTS_TOTAL: AtomicU64 = AtomicU64::new(0);
static GRPC_MESSAGES_TOTAL: AtomicU64 = AtomicU64::new(0);
const INVALID_PRESENTED_APPROVAL_REASON: &str = "Supplied approval is not valid for this action";

fn record_grpc_request() {
    // SECURITY (FIND-R55-GRPC-012): SeqCst on security-adjacent metrics counters
    // to ensure visibility across threads for rate limiting and audit decisions.
    // SECURITY (FIND-R155-GRPC-001): Use fetch_update + saturating_add to prevent
    // overflow wrap-to-zero. Parity with WS counters (websocket/mod.rs:91-93).
    let _ = GRPC_REQUESTS_TOTAL.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
        Some(v.saturating_add(1))
    });
    metrics::counter!("vellaveto_grpc_requests_total").increment(1);
}

fn record_grpc_message(direction: &str) {
    // SECURITY (FIND-R55-GRPC-012): SeqCst on security-adjacent metrics counters.
    // SECURITY (FIND-R155-GRPC-001): Use fetch_update + saturating_add to prevent
    // overflow wrap-to-zero. Parity with WS counters (websocket/mod.rs:101-103).
    let _ = GRPC_MESSAGES_TOTAL.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
        Some(v.saturating_add(1))
    });
    metrics::counter!(
        "vellaveto_grpc_messages_total",
        "direction" => direction.to_string()
    )
    .increment(1);
}

pub(super) fn build_grpc_runtime_security_context(
    msg: &Value,
    action: &Action,
    request_signature_header: Option<&str>,
    inputs: crate::proxy::helpers::TransportSecurityInputs<'_>,
) -> Option<RuntimeSecurityContext> {
    build_runtime_security_context_with_request_signature(
        msg,
        action,
        request_signature_header,
        inputs,
    )
}

fn merge_grpc_security_context(
    runtime_security_context: Option<&RuntimeSecurityContext>,
    verdict_security_context: Option<&RuntimeSecurityContext>,
) -> Option<RuntimeSecurityContext> {
    crate::proxy::helpers::merge_transport_security_context(
        runtime_security_context,
        verdict_security_context,
    )
}

#[derive(Clone, Copy)]
struct GrpcRequestContext<'a> {
    session_id: &'a str,
    request_signature_header: Option<&'a str>,
}

async fn sync_transport_agent_identity(
    state: &Arc<ProxyState>,
    metadata: &tonic::metadata::MetadataMap,
    session_id: &str,
) -> Result<(), Status> {
    let workload_claims = super::interceptors::extract_workload_claims(metadata)?;

    if let Some(identity_token) = super::interceptors::extract_agent_identity_token(metadata) {
        if let Some(ref oauth_validator) = state.oauth {
            match oauth_validator
                .validate_token(&format!("Bearer {identity_token}"))
                .await
            {
                Ok(claims) => {
                    let identity = crate::proxy::auth::build_validated_agent_identity(
                        claims,
                        &identity_token,
                        workload_claims.unwrap_or_default(),
                    )
                    .map_err(|error| {
                        tracing::warn!("gRPC agent identity claims validation failed: {}", error);
                        Status::unauthenticated("Invalid agent identity token")
                    })?;
                    if let Some(mut session) = state.sessions.get_mut(session_id) {
                        session.agent_identity = Some(identity);
                    }
                }
                Err(e) => {
                    tracing::warn!("gRPC agent identity JWT validation failed: {}", e);
                    return Err(Status::unauthenticated("Invalid agent identity token"));
                }
            }
        }
        return Ok(());
    }

    let Some(ref oauth_validator) = state.oauth else {
        return Ok(());
    };
    let auth_header = match metadata
        .get("authorization")
        .and_then(|value| value.to_str().ok())
    {
        Some(header) => header,
        None => return Ok(()),
    };
    let bearer_token = match crate::oauth::extract_bearer_token(auth_header) {
        Ok(token) => token,
        Err(_) => return Ok(()),
    };
    let has_transport_claims = workload_claims
        .as_ref()
        .is_some_and(|claims| !claims.is_empty());
    let has_token_claims = crate::proxy::auth::extract_custom_jwt_claims(bearer_token)
        .is_some_and(|claims| !claims.is_empty());
    if !has_transport_claims && !has_token_claims {
        return Ok(());
    }

    match oauth_validator.validate_token(auth_header).await {
        Ok(claims) => {
            let identity = crate::proxy::auth::build_validated_agent_identity(
                claims,
                bearer_token,
                workload_claims.unwrap_or_default(),
            )
            .map_err(|error| {
                tracing::warn!(
                    "gRPC transport identity claims validation failed: {}",
                    error
                );
                Status::unauthenticated("Invalid authorization token")
            })?;
            if let Some(mut session) = state.sessions.get_mut(session_id) {
                if session.agent_identity.is_none() {
                    session.agent_identity = Some(identity);
                }
            }
        }
        Err(e) => {
            tracing::warn!(
                "gRPC OAuth validation failed for transport identity sync: {}",
                e
            );
            return Err(Status::unauthenticated("Invalid authorization token"));
        }
    }

    Ok(())
}

/// The MCP gRPC service implementation.
pub struct McpGrpcService {
    state: Arc<ProxyState>,
    upstream: UpstreamForwarder,
    /// SECURITY (FIND-R55-GRPC-010): Per-stream message rate limit (messages/sec).
    /// 0 means unlimited.
    stream_message_rate_limit: u32,
}

impl McpGrpcService {
    pub fn new(state: Arc<ProxyState>, stream_message_rate_limit: u32) -> Self {
        let upstream = UpstreamForwarder::new(state.clone());
        Self {
            state,
            upstream,
            stream_message_rate_limit,
        }
    }

    /// SECURITY (FIND-R206-001): Check audit_strict_mode after an audit
    /// logging failure. Returns `Some(denial)` if strict mode demands we
    /// fail-closed; `None` if we can continue (non-strict).
    fn audit_strict_deny(
        &self,
        proto_req: &JsonRpcRequest,
        context: &str,
    ) -> Option<JsonRpcResponse> {
        if self.state.audit_strict_mode {
            tracing::error!(
                "gRPC audit strict mode: denying request after audit failure ({})",
                context
            );
            Some(make_proto_denial_response(
                proto_req,
                "Audit logging failed — request denied (strict audit mode)",
            ))
        } else {
            None
        }
    }

    fn approval_required_response(
        &self,
        proto_req: &JsonRpcRequest,
        approval_id: Option<String>,
    ) -> JsonRpcResponse {
        let mut data = json!({
            "type": "approval_required",
            "reason": "Approval required",
        });
        if let Some(approval_id) = approval_id {
            data["approval_id"] = Value::String(approval_id);
        }
        make_proto_error_response_with_data(proto_req, -32001, "Approval required", &data)
    }

    /// Evaluate a single JSON-RPC request through the policy pipeline.
    ///
    /// Returns the response proto. Policy denials and transport errors are
    /// encoded as JSON-RPC error responses inside a successful gRPC status
    /// (matching HTTP/WS behavior).
    async fn evaluate_request(
        &self,
        proto_req: &JsonRpcRequest,
        session_id: &str,
        request_signature_header: Option<&str>,
    ) -> JsonRpcResponse {
        let request_context = GrpcRequestContext {
            session_id,
            request_signature_header,
        };
        // 1. Convert proto → JSON
        let json_req = match proto_request_to_json(proto_req) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("gRPC proto→JSON conversion failed: {}", e);
                return make_proto_error_response(proto_req, -32603, "Internal conversion error");
            }
        };

        // SECURITY (R258-TRANSPORT-2): Defense-in-depth duplicate key check on gRPC.
        // While proto→JSON conversion uses BTreeMap (no dupes), this guards against
        // future conversion changes and maintains parity with HTTP/WS transports.
        {
            let serialized = serde_json::to_string(&json_req).unwrap_or_default();
            if let Some(dup_key) = vellaveto_mcp::framing::find_duplicate_json_key(&serialized) {
                tracing::warn!(
                    session_id = %session_id,
                    "SECURITY: Rejected gRPC message with duplicate key: \"{}\"",
                    dup_key
                );
                return make_proto_error_response(proto_req, -32600, "Duplicate JSON key detected");
            }
        }

        // SECURITY (R258-TRANSPORT-1): JSON-RPC key case-folding smuggling defense.
        // Parity with stdio/HTTP/WS transports (CVE-2026-27896).
        if let Some(key) = vellaveto_mcp::framing::check_json_rpc_key_case_folding(&json_req) {
            tracing::warn!(
                session_id = %session_id,
                "SECURITY: Rejected gRPC message with case-folding smuggle key: \"{}\"",
                key
            );
            return make_proto_error_response(
                proto_req,
                -32600,
                "JSON-RPC key case-folding smuggle detected",
            );
        }

        // SECURITY (FIND-R54-004): Reject gRPC messages with control/Unicode format
        // characters. Parity with HTTP body check and WS frame check (FIND-R53-WS-004).
        if json_contains_dangerous_chars(&json_req, 0) {
            tracing::warn!(
                session_id = %session_id,
                "SECURITY: Rejected gRPC message with control/Unicode format characters"
            );
            return make_proto_error_response(
                proto_req,
                -32600,
                "Message contains control characters",
            );
        }

        // 2. Classify
        let classified = extractor::classify_message(&json_req);

        // 3. Process by message type
        match classified {
            MessageType::ToolCall {
                ref id,
                ref tool_name,
                ref arguments,
            } => {
                self.handle_tool_call(
                    proto_req,
                    &json_req,
                    request_context,
                    id,
                    tool_name,
                    arguments,
                )
                .await
            }
            MessageType::ResourceRead { ref id, ref uri } => {
                self.handle_resource_read(proto_req, &json_req, request_context, id, uri)
                    .await
            }
            MessageType::SamplingRequest { id: _ } => {
                // SECURITY (BUG-R110-007): Full inspect_sampling() parity with HTTP handler
                // (handlers.rs:1711) and WebSocket handler (websocket/mod.rs:1560).
                // Previous code only checked `enabled` — missing rate limit, model filter,
                // and tool output checks.
                let params = json_req.get("params").cloned().unwrap_or(json!({}));
                let sampling_verdict = {
                    let mut session_ref = self.state.sessions.get_mut(session_id);
                    let current_count = session_ref.as_ref().map(|s| s.sampling_count).unwrap_or(0);
                    let verdict = vellaveto_mcp::elicitation::inspect_sampling(
                        &params,
                        &self.state.sampling_config,
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
                        self.forward_and_scan(proto_req, &json_req, session_id)
                            .await
                    }
                    vellaveto_mcp::elicitation::SamplingVerdict::Deny { reason } => {
                        tracing::warn!(
                            "Blocked sampling/createMessage in gRPC session {}: {}",
                            session_id,
                            reason
                        );
                        let action = Action::new(
                            "vellaveto",
                            "sampling_interception",
                            json!({
                                "method": "sampling/createMessage",
                                "session": session_id,
                                "transport": "grpc",
                                "reason": &reason,
                            }),
                        );
                        let verdict = Verdict::Deny {
                            reason: reason.clone(),
                        };
                        let sampling_security_context =
                            sampling_interception_security_context(&action);
                        let envelope = build_secondary_acis_envelope_with_security_context(
                            &action,
                            &verdict,
                            DecisionOrigin::PolicyEngine,
                            "grpc",
                            Some(session_id),
                            Some(&sampling_security_context),
                        );
                        if let Err(e) = self
                            .state
                            .audit
                            .log_entry_with_acis(
                                &action,
                                &verdict,
                                json!({
                                    "source": "grpc_proxy",
                                    "event": "sampling_interception",
                                }),
                                envelope,
                            )
                            .await
                        {
                            tracing::warn!("Failed to audit gRPC sampling interception: {}", e);
                            if let Some(deny) =
                                self.audit_strict_deny(proto_req, "sampling interception")
                            {
                                return deny;
                            }
                        }
                        make_proto_denial_response(proto_req, "Sampling request denied")
                    }
                }
            }
            MessageType::ElicitationRequest { .. } => {
                // SECURITY (FIND-R54-GRPC-007): Inspect elicitation requests.
                // Parity with HTTP handler's elicitation interception (handlers.rs:1843).
                let params = json_req.get("params").cloned().unwrap_or(json!({}));
                let elicitation_verdict = {
                    let mut session_ref = self.state.sessions.get_mut(session_id);
                    let current_count = session_ref
                        .as_ref()
                        .map(|s| s.elicitation_count)
                        .unwrap_or(0);
                    let verdict = vellaveto_mcp::elicitation::inspect_elicitation(
                        &params,
                        &self.state.elicitation_config,
                        current_count,
                    );
                    if matches!(
                        verdict,
                        vellaveto_mcp::elicitation::ElicitationVerdict::Allow
                    ) {
                        if let Some(ref mut s) = session_ref {
                            s.elicitation_count = s.elicitation_count.saturating_add(1);
                        }
                    }
                    verdict
                };
                match elicitation_verdict {
                    vellaveto_mcp::elicitation::ElicitationVerdict::Allow => {
                        self.forward_and_scan(proto_req, &json_req, session_id)
                            .await
                    }
                    vellaveto_mcp::elicitation::ElicitationVerdict::Deny { reason } => {
                        tracing::warn!(
                            "Blocked elicitation/create in gRPC session {}: {}",
                            session_id,
                            reason
                        );
                        let action = Action::new(
                            "vellaveto",
                            "elicitation_interception",
                            json!({
                                "method": "elicitation/create",
                                "session": session_id,
                                "transport": "grpc",
                                "reason": &reason,
                            }),
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
                            "grpc",
                            Some(session_id),
                            Some(&elicitation_security_context),
                        );
                        if let Err(e) = self
                            .state
                            .audit
                            .log_entry_with_acis(
                                &action,
                                &verdict,
                                json!({
                                    "source": "grpc_proxy",
                                    "event": "elicitation_interception",
                                }),
                                envelope,
                            )
                            .await
                        {
                            tracing::warn!("Failed to audit gRPC elicitation interception: {}", e);
                            if let Some(deny) =
                                self.audit_strict_deny(proto_req, "elicitation interception")
                            {
                                return deny;
                            }
                        }
                        make_proto_denial_response(
                            proto_req,
                            "elicitation/create blocked by policy",
                        )
                    }
                }
            }
            MessageType::ProgressNotification { .. } => {
                // SECURITY (FIND-R155-GRPC-003): DLP scan, injection detection, and
                // memory poisoning check for ProgressNotification messages. Previous
                // code only called forward_and_scan() which scans the *response*, not
                // the incoming notification params. Parity with PassThrough branch
                // (service.rs:273-527) and WS handler which treats ProgressNotification
                // identically to PassThrough (websocket/mod.rs:3095).

                // DLP scan notification parameters for secret exfiltration.
                if self.state.response_dlp_enabled {
                    let mut dlp_findings = scan_notification_for_secrets(&json_req);
                    if let Some(result_val) = json_req.get("result") {
                        dlp_findings.extend(scan_parameters_for_secrets(result_val));
                    }
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
                            "SECURITY: Secrets in gRPC ProgressNotification params! Session: {}, Findings: {:?}",
                            session_id,
                            patterns
                        );
                        let n_action = Action::new(
                            "vellaveto",
                            "notification_dlp_scan",
                            json!({
                                "findings": patterns,
                                "session": session_id,
                                "transport": "grpc",
                                "message_type": "progress_notification",
                            }),
                        );
                        let verdict = if self.state.response_dlp_blocking {
                            Verdict::Deny {
                                reason: format!(
                                    "ProgressNotification blocked: secrets detected ({:?})",
                                    patterns
                                ),
                            }
                        } else {
                            Verdict::Allow
                        };
                        let notification_security_context = notification_dlp_security_context(
                            &json_req,
                            self.state.response_dlp_blocking,
                        );
                        let envelope = build_secondary_acis_envelope_with_security_context(
                            &n_action,
                            &verdict,
                            DecisionOrigin::Dlp,
                            "grpc",
                            Some(session_id),
                            Some(&notification_security_context),
                        );
                        if let Err(e) = self
                            .state
                            .audit
                            .log_entry_with_acis(
                                &n_action,
                                &verdict,
                                json!({
                                    "source": "grpc_proxy",
                                    "event": "notification_dlp_alert",
                                    "blocked": self.state.response_dlp_blocking,
                                    "message_type": "progress_notification",
                                }),
                                envelope,
                            )
                            .await
                        {
                            tracing::warn!("Failed to audit gRPC ProgressNotification DLP: {}", e);
                        }
                        if self.state.response_dlp_blocking {
                            return make_proto_error_response(
                                proto_req,
                                -32002,
                                "Notification blocked: secrets detected in parameters",
                            );
                        }
                    }
                }

                let method_name = json_req
                    .get("method")
                    .and_then(|m| m.as_str())
                    .unwrap_or("notifications/progress");

                // Injection scanning on ProgressNotification parameters.
                if !self.state.injection_disabled {
                    let scannable = extract_passthrough_text_for_injection(&json_req);
                    if !scannable.is_empty() {
                        let injection_matches: Vec<String> =
                            if let Some(ref scanner) = self.state.injection_scanner {
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
                                "SECURITY: Injection in gRPC ProgressNotification params! \
                                 Session: {}, Method: {}, Patterns: {:?}",
                                session_id,
                                method_name,
                                injection_matches,
                            );

                            let verdict = if self.state.injection_blocking {
                                Verdict::Deny {
                                    reason: format!(
                                        "ProgressNotification injection blocked: {:?}",
                                        injection_matches
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
                                    "transport": "grpc",
                                    "message_type": "progress_notification",
                                }),
                            );
                            let injection_security_context =
                                notification_injection_security_context(
                                    &json_req,
                                    self.state.injection_blocking,
                                    "passthrough_injection",
                                );
                            let envelope = build_secondary_acis_envelope_with_security_context(
                                &inj_action,
                                &verdict,
                                DecisionOrigin::InjectionScanner,
                                "grpc",
                                Some(session_id),
                                Some(&injection_security_context),
                            );
                            if let Err(e) = self
                                .state
                                .audit
                                .log_entry_with_acis(
                                    &inj_action,
                                    &verdict,
                                    json!({
                                        "source": "grpc_proxy",
                                        "event": "passthrough_injection_detected",
                                        "blocking": self.state.injection_blocking,
                                        "message_type": "progress_notification",
                                    }),
                                    envelope,
                                )
                                .await
                            {
                                tracing::warn!(
                                    "Failed to audit gRPC ProgressNotification injection: {}",
                                    e
                                );
                                if let Some(deny) =
                                    self.audit_strict_deny(proto_req, "notification injection")
                                {
                                    return deny;
                                }
                            }

                            if self.state.injection_blocking {
                                return make_proto_error_response(
                                    proto_req,
                                    -32001,
                                    "Request blocked: security policy violation",
                                );
                            }
                        }
                    }
                }

                // Memory poisoning check — parity with PassThrough branch.
                if let Some(mut session) = self.state.sessions.get_mut(session_id) {
                    let params_to_scan = json_req.get("params").cloned().unwrap_or(json!({}));
                    let mut poisoning_matches =
                        session.memory_tracker.check_parameters(&params_to_scan);
                    if let Some(result_val) = json_req.get("result") {
                        poisoning_matches
                            .extend(session.memory_tracker.check_parameters(result_val));
                    }
                    if !poisoning_matches.is_empty() {
                        for m in &poisoning_matches {
                            tracing::warn!(
                                "SECURITY: Memory poisoning in gRPC ProgressNotification '{}' (session {}): \
                                 param '{}' replayed data (fingerprint: {})",
                                method_name,
                                session_id,
                                m.param_location,
                                m.fingerprint
                            );
                        }
                        let poison_action = Action::new(
                            "vellaveto",
                            "grpc_passthrough_memory_poisoning",
                            json!({
                                "method": method_name,
                                "session": session_id,
                                "matches": poisoning_matches.len(),
                                "transport": "grpc",
                                "message_type": "progress_notification",
                            }),
                        );
                        let poison_verdict = Verdict::Deny {
                            reason: format!(
                                "gRPC ProgressNotification blocked: memory poisoning ({} matches)",
                                poisoning_matches.len()
                            ),
                        };
                        let poisoning_security_context =
                            notification_memory_poisoning_security_context(
                                &json_req,
                                "memory_poisoning",
                            );
                        let envelope = build_secondary_acis_envelope_with_security_context(
                            &poison_action,
                            &poison_verdict,
                            DecisionOrigin::MemoryPoisoning,
                            "grpc",
                            Some(session_id),
                            Some(&poisoning_security_context),
                        );
                        if let Err(e) = self
                            .state
                            .audit
                            .log_entry_with_acis(
                                &poison_action,
                                &poison_verdict,
                                json!({
                                    "source": "grpc_proxy",
                                    "event": "grpc_passthrough_memory_poisoning",
                                    "message_type": "progress_notification",
                                }),
                                envelope,
                            )
                            .await
                        {
                            tracing::warn!(
                                "Failed to audit gRPC ProgressNotification memory poisoning: {}",
                                e
                            );
                        }
                        return make_proto_error_response(
                            proto_req,
                            -32001,
                            "Request blocked: security policy violation",
                        );
                    }
                    session.memory_tracker.extract_from_value(&params_to_scan);
                    if let Some(result_val) = json_req.get("result") {
                        session.memory_tracker.extract_from_value(result_val);
                    }
                } else {
                    tracing::warn!(
                        "Session {} not found for gRPC ProgressNotification memory poisoning check",
                        session_id
                    );
                }

                // Audit log the forwarded ProgressNotification.
                let action = Action::new("progress_notification", method_name, json!({}));
                let protocol_security_context =
                    protocol_forward_security_context("progress_notification_forwarded");
                let envelope = build_secondary_acis_envelope_with_security_context(
                    &action,
                    &Verdict::Allow,
                    DecisionOrigin::PolicyEngine,
                    "grpc",
                    Some(session_id),
                    Some(&protocol_security_context),
                );
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry_with_acis(
                        &action,
                        &Verdict::Allow,
                        json!({
                            "source": "grpc_proxy",
                            "session": session_id,
                            "transport": "grpc",
                            "event": "progress_notification_forwarded",
                        }),
                        envelope,
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC progress notification: {}", e);
                    if let Some(deny) = self.audit_strict_deny(proto_req, "progress notification") {
                        return deny;
                    }
                }
                self.forward_and_scan(proto_req, &json_req, session_id)
                    .await
            }
            MessageType::TaskRequest {
                ref id,
                ref task_method,
                ref task_id,
            } => {
                self.handle_task_request(
                    proto_req,
                    &json_req,
                    request_context,
                    id,
                    task_method,
                    task_id.as_deref(),
                )
                .await
            }
            MessageType::ExtensionMethod {
                ref id,
                ref extension_id,
                ref method,
            } => {
                self.handle_extension_method(
                    proto_req,
                    &json_req,
                    request_context,
                    id,
                    extension_id,
                    method,
                )
                .await
            }
            MessageType::Batch => {
                let action = Action::new(
                    "vellaveto",
                    "batch_rejected",
                    json!({
                        "session": session_id,
                        "transport": "grpc",
                    }),
                );
                let batch_verdict = Verdict::Deny {
                    reason: "JSON-RPC batching not supported".to_string(),
                };
                let batch_security_context = batch_rejection_security_context(&action);
                let envelope = build_secondary_acis_envelope_with_security_context(
                    &action,
                    &batch_verdict,
                    DecisionOrigin::PolicyEngine,
                    "grpc",
                    Some(session_id),
                    Some(&batch_security_context),
                );
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry_with_acis(
                        &action,
                        &batch_verdict,
                        json!({
                            "source": "grpc_proxy",
                            "event": "batch_rejected",
                        }),
                        envelope,
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC batch rejection: {}", e);
                    if let Some(deny) = self.audit_strict_deny(proto_req, "batch rejection") {
                        return deny;
                    }
                }
                make_proto_error_response(
                    proto_req,
                    -32600,
                    "JSON-RPC batch requests are not supported",
                )
            }
            MessageType::Invalid { ref reason, .. } => {
                tracing::warn!("Invalid JSON-RPC request in gRPC transport: {}", reason);
                make_proto_error_response(proto_req, -32600, "Invalid JSON-RPC request")
            }
            MessageType::PassThrough => {
                // SECURITY (FIND-R77-002): DLP scan PassThrough params for secrets.
                // Parity with HTTP handler (handlers.rs:1795-1859) and WS handler.
                // Agents could exfiltrate secrets via prompts/get, completion/complete,
                // or any PassThrough method's parameters.
                // SECURITY (FIND-R97-001): Remove method gate — JSON-RPC responses
                // (sampling/elicitation replies) have no `method` field but carry
                // data in `result`. Parity with stdio proxy FIND-R96-001.
                if self.state.response_dlp_enabled {
                    let mut dlp_findings = scan_notification_for_secrets(&json_req);
                    // SECURITY (FIND-R97-001): Also scan `result` field for responses.
                    if let Some(result_val) = json_req.get("result") {
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
                            "SECURITY: Secrets in gRPC passthrough params! Session: {}, Findings: {:?}",
                            session_id,
                            patterns
                        );
                        let n_action = Action::new(
                            "vellaveto",
                            "notification_dlp_scan",
                            json!({
                                "findings": patterns,
                                "session": session_id,
                                "transport": "grpc",
                            }),
                        );
                        let verdict = if self.state.response_dlp_blocking {
                            Verdict::Deny {
                                reason: format!(
                                    "Notification blocked: secrets detected ({:?})",
                                    patterns
                                ),
                            }
                        } else {
                            Verdict::Allow
                        };
                        let notification_security_context = notification_dlp_security_context(
                            &json_req,
                            self.state.response_dlp_blocking,
                        );
                        let envelope = build_secondary_acis_envelope_with_security_context(
                            &n_action,
                            &verdict,
                            DecisionOrigin::Dlp,
                            "grpc",
                            Some(session_id),
                            Some(&notification_security_context),
                        );
                        if let Err(e) = self
                            .state
                            .audit
                            .log_entry_with_acis(
                                &n_action,
                                &verdict,
                                json!({
                                    "source": "grpc_proxy",
                                    "event": "notification_dlp_alert",
                                    "blocked": self.state.response_dlp_blocking,
                                }),
                                envelope,
                            )
                            .await
                        {
                            tracing::warn!("Failed to audit gRPC passthrough DLP: {}", e);
                        }
                        if self.state.response_dlp_blocking {
                            return make_proto_error_response(
                                proto_req,
                                -32002,
                                "Notification blocked: secrets detected in parameters",
                            );
                        }
                    }
                }

                let method_name = json_req
                    .get("method")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown");

                // SECURITY (FIND-R113-001): Injection scanning on PassThrough parameters.
                // Parity with HTTP handler (handlers.rs:2199-2277, FIND-R112-008) and
                // WebSocket handler (pre-classify scan on all incoming messages).
                if !self.state.injection_disabled {
                    let scannable = extract_passthrough_text_for_injection(&json_req);
                    if !scannable.is_empty() {
                        let injection_matches: Vec<String> =
                            if let Some(ref scanner) = self.state.injection_scanner {
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
                                "SECURITY: Injection in gRPC passthrough params! \
                                 Session: {}, Method: {}, Patterns: {:?}",
                                session_id,
                                method_name,
                                injection_matches,
                            );

                            let verdict = if self.state.injection_blocking {
                                Verdict::Deny {
                                    reason: format!(
                                        "PassThrough injection blocked: {:?}",
                                        injection_matches
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
                                    "transport": "grpc",
                                }),
                            );
                            let injection_security_context =
                                notification_injection_security_context(
                                    &json_req,
                                    self.state.injection_blocking,
                                    "passthrough_injection",
                                );
                            let envelope = build_secondary_acis_envelope_with_security_context(
                                &inj_action,
                                &verdict,
                                DecisionOrigin::InjectionScanner,
                                "grpc",
                                Some(session_id),
                                Some(&injection_security_context),
                            );
                            if let Err(e) = self
                                .state
                                .audit
                                .log_entry_with_acis(
                                    &inj_action,
                                    &verdict,
                                    json!({
                                        "source": "grpc_proxy",
                                        "event": "passthrough_injection_detected",
                                        "blocking": self.state.injection_blocking,
                                    }),
                                    envelope,
                                )
                                .await
                            {
                                tracing::warn!("Failed to audit gRPC passthrough injection: {}", e);
                                if let Some(deny) =
                                    self.audit_strict_deny(proto_req, "passthrough injection")
                                {
                                    return deny;
                                }
                            }

                            if self.state.injection_blocking {
                                // SECURITY (FIND-R113-001): Generic client message;
                                // detailed reason in audit log.
                                return make_proto_error_response(
                                    proto_req,
                                    -32001,
                                    "Request blocked: security policy violation",
                                );
                            }
                        }
                    }
                }

                // SECURITY (IMP-R184-007): Memory poisoning check — parity with tool calls,
                // resource reads, extension methods, and HTTP/WS/stdio passthrough.
                if let Some(mut session) = self.state.sessions.get_mut(session_id) {
                    let params_to_scan = json_req.get("params").cloned().unwrap_or(json!({}));
                    let mut poisoning_matches =
                        session.memory_tracker.check_parameters(&params_to_scan);
                    if let Some(result_val) = json_req.get("result") {
                        poisoning_matches
                            .extend(session.memory_tracker.check_parameters(result_val));
                    }
                    if !poisoning_matches.is_empty() {
                        for m in &poisoning_matches {
                            tracing::warn!(
                                "SECURITY: Memory poisoning in gRPC passthrough '{}' (session {}): \
                                 param '{}' replayed data (fingerprint: {})",
                                method_name,
                                session_id,
                                m.param_location,
                                m.fingerprint
                            );
                        }
                        let poison_action = Action::new(
                            "vellaveto",
                            "grpc_passthrough_memory_poisoning",
                            json!({
                                "method": method_name,
                                "session": session_id,
                                "matches": poisoning_matches.len(),
                                "transport": "grpc",
                            }),
                        );
                        let poison_verdict = Verdict::Deny {
                            reason: format!(
                                "gRPC passthrough blocked: memory poisoning ({} matches)",
                                poisoning_matches.len()
                            ),
                        };
                        let poisoning_security_context =
                            notification_memory_poisoning_security_context(
                                &json_req,
                                "memory_poisoning",
                            );
                        let envelope = build_secondary_acis_envelope_with_security_context(
                            &poison_action,
                            &poison_verdict,
                            DecisionOrigin::MemoryPoisoning,
                            "grpc",
                            Some(session_id),
                            Some(&poisoning_security_context),
                        );
                        if let Err(e) = self
                            .state
                            .audit
                            .log_entry_with_acis(
                                &poison_action,
                                &poison_verdict,
                                json!({
                                    "source": "grpc_proxy",
                                    "event": "grpc_passthrough_memory_poisoning",
                                }),
                                envelope,
                            )
                            .await
                        {
                            tracing::warn!(
                                "Failed to audit gRPC passthrough memory poisoning: {}",
                                e
                            );
                        }
                        return make_proto_error_response(
                            proto_req,
                            -32001,
                            "Request blocked: security policy violation",
                        );
                    }
                    session.memory_tracker.extract_from_value(&params_to_scan);
                    if let Some(result_val) = json_req.get("result") {
                        session.memory_tracker.extract_from_value(result_val);
                    }
                } else {
                    // IMP-R186-004: Log when session is missing so the skip is observable.
                    tracing::warn!(
                        "Session {} not found for gRPC passthrough memory poisoning check",
                        session_id
                    );
                }

                // SECURITY (FIND-R55-GRPC-005): Audit log PassThrough messages.
                // Parity with HTTP handler (handlers.rs:1731-1757) and WS handler
                // (websocket/mod.rs:1809-1838). PassThrough bypasses policy evaluation
                // but must have an audit trail for observability.
                let action = Action::new("passthrough", method_name, json!({}));
                let protocol_security_context =
                    protocol_forward_security_context("pass_through_forwarded");
                let envelope = build_secondary_acis_envelope_with_security_context(
                    &action,
                    &Verdict::Allow,
                    DecisionOrigin::PolicyEngine,
                    "grpc",
                    Some(session_id),
                    Some(&protocol_security_context),
                );
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry_with_acis(
                        &action,
                        &Verdict::Allow,
                        json!({
                            "source": "grpc_proxy",
                            "session": session_id,
                            "transport": "grpc",
                            "event": "pass_through_forwarded",
                        }),
                        envelope,
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC pass-through: {}", e);
                    if let Some(deny) = self.audit_strict_deny(proto_req, "pass-through") {
                        return deny;
                    }
                }
                self.forward_and_scan(proto_req, &json_req, session_id)
                    .await
            }
        }
    }

    /// Handle a tool call: extract action, evaluate policy, audit, forward or deny.
    #[allow(deprecated)] // evaluate_action_with_context: migration tracked in FIND-CREATIVE-005
    async fn handle_tool_call(
        &self,
        proto_req: &JsonRpcRequest,
        json_req: &Value,
        request_context: GrpcRequestContext<'_>,
        _id: &Value,
        tool_name: &str,
        arguments: &Value,
    ) -> JsonRpcResponse {
        let session_id = request_context.session_id;
        let request_signature_header = request_context.request_signature_header;
        // SECURITY (FIND-R54-005): Strict MCP tool name validation.
        // Parity with HTTP handler (handlers.rs:354).
        if self.state.streamable_http.strict_tool_name_validation {
            if let Err(e) = vellaveto_types::validate_mcp_tool_name(tool_name) {
                tracing::warn!(
                    "SECURITY: Rejecting invalid gRPC tool name '{}': {}",
                    tool_name,
                    e
                );
                return make_proto_error_response(proto_req, -32602, "Invalid tool name");
            }
        }

        // SECURITY (FIND-R53-GRPC-001): DLP scan parameters for secret exfiltration.
        // Parity with HTTP handler (handlers.rs:457) and WS (websocket/mod.rs:700).
        let dlp_findings = scan_parameters_for_secrets(arguments);
        if !dlp_findings.is_empty() {
            for finding in &dlp_findings {
                record_dlp_finding(&finding.pattern_name);
            }

            let patterns: Vec<String> = dlp_findings
                .iter()
                .map(|f| format!("{}:{}", f.pattern_name, f.location))
                .collect();

            tracing::warn!(
                "SECURITY: Secrets in gRPC tool call parameters! Session: {}, Tool: {}, Findings: {:?}",
                session_id,
                tool_name,
                patterns,
            );

            let action = extractor::extract_action(tool_name, arguments);
            // SECURITY (R111-002): Keep detailed pattern names in the audit verdict only.
            // The client-facing denial message must not leak internal DLP pattern names.
            let audit_verdict = Verdict::Deny {
                reason: format!("DLP blocked: secret detected in parameters: {:?}", patterns),
            };
            let parameter_security_context =
                parameter_dlp_security_context(arguments, true, "tool_parameter_dlp");
            let envelope = build_secondary_acis_envelope_with_security_context(
                &action,
                &audit_verdict,
                DecisionOrigin::Dlp,
                "grpc",
                Some(session_id),
                Some(&parameter_security_context),
            );
            if let Err(e) = self
                .state
                .audit
                .log_entry_with_acis(
                    &action,
                    &audit_verdict,
                    json!({
                        "source": "grpc_proxy",
                        "session": session_id,
                        "transport": "grpc",
                        "event": "grpc_parameter_dlp_alert",
                        "findings": patterns,
                    }),
                    envelope,
                )
                .await
            {
                tracing::warn!("Failed to audit gRPC parameter DLP: {}", e);
            }

            return make_proto_denial_response(
                proto_req,
                "Response blocked: sensitive content detected",
            );
        }

        // SECURITY (FIND-R53-GRPC-002): Rug-pull detection — block calls to tools
        // with changed annotations since initial tools/list.
        // Parity with HTTP handler (handlers.rs:404-434) and WS (websocket/mod.rs:682).
        // SECURITY (R240-PROXY-1): Fall back to global registry on session miss.
        let is_flagged = self
            .state
            .sessions
            .get_mut(session_id)
            .map(|s| s.flagged_tools.contains(tool_name))
            .unwrap_or_else(|| self.state.sessions.is_tool_globally_flagged(tool_name));

        if is_flagged {
            let action = extractor::extract_action(tool_name, arguments);
            let verdict = Verdict::Deny {
                reason: format!(
                    "Tool '{}' blocked: annotations changed since initial tools/list (rug-pull detected)",
                    tool_name
                ),
            };
            let rug_pull_security_context = rug_pull_security_context(&action);
            let envelope = build_secondary_acis_envelope_with_security_context(
                &action,
                &verdict,
                DecisionOrigin::CapabilityEnforcement,
                "grpc",
                Some(session_id),
                Some(&rug_pull_security_context),
            );
            if let Err(e) = self
                .state
                .audit
                .log_entry_with_acis(
                    &action,
                    &verdict,
                    json!({
                        "source": "grpc_proxy",
                        "session": session_id,
                        "transport": "grpc",
                        "event": "rug_pull_tool_blocked",
                        "tool": tool_name,
                    }),
                    envelope,
                )
                .await
            {
                tracing::warn!("Failed to audit gRPC rug-pull block: {}", e);
            }

            // SECURITY (FIND-R112-009): Generic client message — the tool name
            // is NOT included. Detailed tool name is in the audit log only.
            return make_proto_denial_response(
                proto_req,
                "Denied: annotation change detected (rug-pull protection)",
            );
        }

        // SECURITY (FIND-R53-GRPC-003): Memory poisoning detection — block requests
        // when replayed response data is detected in parameters.
        // Parity with HTTP handler (handlers.rs:512-570) and WS (websocket/mod.rs:751-810).
        if let Some(session) = self.state.sessions.get_mut(session_id) {
            let poisoning_matches = session.memory_tracker.check_parameters(arguments);
            if !poisoning_matches.is_empty() {
                for m in &poisoning_matches {
                    tracing::warn!(
                        "SECURITY: Memory poisoning detected in gRPC tool '{}' (session {}): \
                         param '{}' contains replayed data (fingerprint: {})",
                        tool_name,
                        session_id,
                        m.param_location,
                        m.fingerprint
                    );
                }
                let action = extractor::extract_action(tool_name, arguments);
                let deny_reason = format!(
                    "Memory poisoning detected: {} replayed data fragment(s) in tool '{}'",
                    poisoning_matches.len(),
                    tool_name
                );
                let mp_verdict = Verdict::Deny {
                    reason: deny_reason.clone(),
                };
                let poisoning_security_context =
                    memory_poisoning_security_context(arguments, "memory_poisoning");
                let envelope = build_secondary_acis_envelope_with_security_context(
                    &action,
                    &mp_verdict,
                    DecisionOrigin::MemoryPoisoning,
                    "grpc",
                    Some(session_id),
                    Some(&poisoning_security_context),
                );
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry_with_acis(
                        &action,
                        &mp_verdict,
                        json!({
                            "source": "grpc_proxy",
                            "session": session_id,
                            "transport": "grpc",
                            "event": "memory_poisoning_detected",
                            "matches": poisoning_matches.len(),
                            "tool": tool_name,
                        }),
                        envelope,
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC memory poisoning: {}", e);
                }

                // Drop session borrow before returning
                drop(session);

                // SECURITY (FIND-R118-001): Generic client message — detailed deny_reason
                // is in the audit log only, not exposed to client.
                return make_proto_denial_response(proto_req, "Denied by policy");
            }
        }

        let mut action = extractor::extract_action(tool_name, arguments);
        let mut matched_approval_id: Option<String> = None;
        let mut matched_approval_registry: Option<&'static str> = None;

        // SECURITY (IMP-R218-002): Requester identity for self-approval prevention
        // is derived inside create_pending_approval_with_context (helpers.rs),
        // which reads it from the session itself. Nothing to pass in here.

        // SECURITY (FIND-R77-001): DNS resolution for IP-based policy evaluation.
        // Parity with HTTP handler (handlers.rs:717) and WS handler (websocket/mod.rs:710).
        // Without this, policies using ip_rules are bypassed on the gRPC transport.
        if self.state.engine.has_ip_rules() {
            resolve_domains(&mut action).await;
        }

        // SECURITY (FIND-R54-006): Circuit breaker check.
        // Parity with HTTP handler (handlers.rs:576) and WS (websocket/mod.rs:892).
        if let Some(ref circuit_breaker) = self.state.circuit_breaker {
            if let Err(reason) = circuit_breaker.can_proceed(tool_name) {
                tracing::warn!(
                    "SECURITY: gRPC circuit breaker open for tool '{}' in session {}: {}",
                    tool_name,
                    session_id,
                    reason
                );
                let verdict = Verdict::Deny {
                    reason: format!("Circuit breaker open: {}", reason),
                };
                // SECURITY (R251-ACIS-1): Use CircuitBreaker origin, not RateLimiter.
                let circuit_breaker_security_context = circuit_breaker_security_context(&action);
                let envelope = build_secondary_acis_envelope_with_security_context(
                    &action,
                    &verdict,
                    DecisionOrigin::CircuitBreaker,
                    "grpc",
                    Some(session_id),
                    Some(&circuit_breaker_security_context),
                );
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry_with_acis(
                        &action,
                        &verdict,
                        json!({
                            "source": "grpc_proxy",
                            "session": session_id,
                            "transport": "grpc",
                            "event": "circuit_breaker_rejected",
                            "tool": tool_name,
                        }),
                        envelope,
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC circuit breaker rejection: {}", e);
                }
                return make_proto_denial_response(proto_req, "Service temporarily unavailable");
            }
        }

        // SECURITY (FIND-R54-007): Tool registry trust check.
        // Parity with HTTP handler (handlers.rs:621) and WS (websocket/mod.rs:936).
        if let Some(ref registry) = self.state.tool_registry {
            let registry_eval_ctx = self.build_evaluation_context(session_id);
            let registry_runtime_security_context = build_grpc_runtime_security_context(
                json_req,
                &action,
                request_signature_header,
                crate::proxy::helpers::TransportSecurityInputs {
                    oauth_evidence: None,
                    eval_ctx: Some(&registry_eval_ctx),
                    sessions: &self.state.sessions,
                    session_id: Some(session_id),
                    trusted_request_signers: &self.state.trusted_request_signers,
                    detached_signature_freshness: self.state.detached_signature_freshness,
                },
            );
            let trust = registry.check_trust_level(tool_name).await;
            match trust {
                vellaveto_mcp::tool_registry::TrustLevel::Unknown => {
                    match crate::proxy::helpers::presented_approval_matches_action(
                        &self.state,
                        session_id,
                        crate::proxy::helpers::extract_approval_id_from_meta(json_req).as_deref(),
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
                                reason: "Unknown tool requires approval".to_string(),
                            };
                            let approval_security_context =
                                unknown_tool_approval_gate_security_context(&action);
                            let combined_security_context = merge_grpc_security_context(
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
                                "grpc",
                                Some(session_id),
                                Some(effective_security_context),
                            );
                            if let Err(e) = self
                                .state
                                .audit
                                .log_entry_with_acis(
                                    &action,
                                    &verdict,
                                    json!({
                                        "source": "grpc_proxy",
                                        "session": session_id,
                                        "transport": "grpc",
                                        "registry": "unknown_tool",
                                        "tool": tool_name,
                                    }),
                                    envelope,
                                )
                                .await
                            {
                                tracing::warn!("Failed to audit gRPC unknown tool: {}", e);
                                // SECURITY (R275-GRPC-1): this path returns
                                // approval_required_response and continues — an
                                // approval is created and handed to the client. It
                                // is the only shape in this file that does not deny
                                // right after its audit, so it is the only one where
                                // strict mode has anything left to enforce.
                                if let Some(deny) =
                                    self.audit_strict_deny(proto_req, "unknown tool")
                                {
                                    return deny;
                                }
                            }
                            let approval_reason = "Unknown tool requires approval";
                            let containment_context =
                                approval_containment_context_from_security_context(
                                    effective_security_context,
                                    approval_reason,
                                );
                            let approval_id = create_pending_approval_with_context(
                                &self.state,
                                session_id,
                                &action,
                                approval_reason,
                                containment_context,
                            )
                            .await;
                            return self.approval_required_response(proto_req, approval_id);
                        }
                        Err(()) => {
                            let verdict = Verdict::Deny {
                                reason: INVALID_PRESENTED_APPROVAL_REASON.to_string(),
                            };
                            let invalid_approval_security_context =
                                invalid_presented_approval_security_context(&action);
                            let combined_security_context = merge_grpc_security_context(
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
                                "grpc",
                                Some(session_id),
                                Some(effective_security_context),
                            );
                            // SECURITY (R274-AUDIT-1): the result was bound to `_`, so a failed
                            // audit write here was invisible. The denial below is unchanged —
                            // this only makes the lost record observable.
                            if let Err(e) = self
                                .state
                                .audit
                                .log_entry_with_acis(
                                    &action,
                                    &verdict,
                                    json!({
                                        "source": "grpc_proxy",
                                        "session": session_id,
                                        "transport": "grpc",
                                        "registry": "unknown_tool",
                                        "approval_id": crate::proxy::helpers::extract_approval_id_from_meta(json_req),
                                        "event": "presented_approval_replay_denied",
                                    }),
                                    envelope,
                                ).await {
                                tracing::warn!("Failed to audit denial: {}", e);
                            }
                            return make_proto_denial_response(proto_req, "Denied by policy");
                        }
                    }
                }
                vellaveto_mcp::tool_registry::TrustLevel::Untrusted { score: _ } => {
                    match crate::proxy::helpers::presented_approval_matches_action(
                        &self.state,
                        session_id,
                        crate::proxy::helpers::extract_approval_id_from_meta(json_req).as_deref(),
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
                                reason: "Untrusted tool requires approval".to_string(),
                            };
                            let approval_security_context =
                                untrusted_tool_approval_gate_security_context(&action);
                            let combined_security_context = merge_grpc_security_context(
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
                                "grpc",
                                Some(session_id),
                                Some(effective_security_context),
                            );
                            if let Err(e) = self
                                .state
                                .audit
                                .log_entry_with_acis(
                                    &action,
                                    &verdict,
                                    json!({
                                        "source": "grpc_proxy",
                                        "session": session_id,
                                        "transport": "grpc",
                                        "registry": "untrusted_tool",
                                        "tool": tool_name,
                                    }),
                                    envelope,
                                )
                                .await
                            {
                                tracing::warn!("Failed to audit gRPC untrusted tool: {}", e);
                                // SECURITY (R275-GRPC-1): this path returns
                                // approval_required_response and continues — an
                                // approval is created and handed to the client. It
                                // is the only shape in this file that does not deny
                                // right after its audit, so it is the only one where
                                // strict mode has anything left to enforce.
                                if let Some(deny) =
                                    self.audit_strict_deny(proto_req, "untrusted tool")
                                {
                                    return deny;
                                }
                            }
                            let approval_reason = "Untrusted tool requires approval";
                            let containment_context =
                                approval_containment_context_from_security_context(
                                    effective_security_context,
                                    approval_reason,
                                );
                            let approval_id = create_pending_approval_with_context(
                                &self.state,
                                session_id,
                                &action,
                                approval_reason,
                                containment_context,
                            )
                            .await;
                            return self.approval_required_response(proto_req, approval_id);
                        }
                        Err(()) => {
                            let verdict = Verdict::Deny {
                                reason: INVALID_PRESENTED_APPROVAL_REASON.to_string(),
                            };
                            let invalid_approval_security_context =
                                invalid_presented_approval_security_context(&action);
                            let combined_security_context = merge_grpc_security_context(
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
                                "grpc",
                                Some(session_id),
                                Some(effective_security_context),
                            );
                            // SECURITY (R274-AUDIT-1): the result was bound to `_`, so a failed
                            // audit write here was invisible. The denial below is unchanged —
                            // this only makes the lost record observable.
                            if let Err(e) = self
                                .state
                                .audit
                                .log_entry_with_acis(
                                    &action,
                                    &verdict,
                                    json!({
                                        "source": "grpc_proxy",
                                        "session": session_id,
                                        "transport": "grpc",
                                        "registry": "untrusted_tool",
                                        "approval_id": crate::proxy::helpers::extract_approval_id_from_meta(json_req),
                                        "event": "presented_approval_replay_denied",
                                    }),
                                    envelope,
                                ).await {
                                tracing::warn!("Failed to audit denial: {}", e);
                            }
                            return make_proto_denial_response(proto_req, "Denied by policy");
                        }
                    }
                }
                vellaveto_mcp::tool_registry::TrustLevel::Trusted => {
                    // Trusted — proceed to engine evaluation
                }
            }
        }

        // SECURITY (FIND-R160-001): TOCTOU-safe context+eval+update.
        // Hold DashMap shard lock across context build, evaluation, and session
        // update to prevent concurrent gRPC requests from reading stale
        // call_counts and bypassing max_calls_in_window.
        // Also extract risk_score and call_chain for post-eval ABAC/priv checks.
        let (verdict, ctx, session_risk, call_chain) =
            if let Some(mut session) = self.state.sessions.get_mut(session_id) {
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
                let risk = session.risk_score.clone();
                let chain = session.current_call_chain.clone();

                let verdict = match self.state.engine.evaluate_action_with_context(
                    &action,
                    &self.state.policies,
                    Some(&ctx),
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::error!(session_id = %session_id, "Policy evaluation error: {}", e);
                        Verdict::Deny {
                            reason: format!("Policy evaluation failed: {}", e),
                        }
                    }
                };

                // Atomically update session on Allow (within same shard lock)
                if matches!(verdict, Verdict::Allow) {
                    session.touch();
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

                (verdict, ctx, risk, chain)
            } else {
                // No session — evaluate without context
                let verdict = match self.state.engine.evaluate_action_with_context(
                    &action,
                    &self.state.policies,
                    None,
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::error!(session_id = %session_id, "Policy evaluation error: {}", e);
                        Verdict::Deny {
                            reason: format!("Policy evaluation failed: {}", e),
                        }
                    }
                };
                (verdict, EvaluationContext::default(), None, vec![])
            };
        let verdict = match verdict {
            Verdict::RequireApproval { reason } => {
                if matched_approval_id.is_some() {
                    Verdict::Allow
                } else {
                    match crate::proxy::helpers::presented_approval_matches_action(
                        &self.state,
                        session_id,
                        crate::proxy::helpers::extract_approval_id_from_meta(json_req).as_deref(),
                        &action,
                    )
                    .await
                    {
                        Ok(Some(approval_id)) => {
                            matched_approval_id = Some(approval_id);
                            Verdict::Allow
                        }
                        Ok(None) => Verdict::RequireApproval { reason },
                        Err(()) => Verdict::Deny {
                            reason: INVALID_PRESENTED_APPROVAL_REASON.to_string(),
                        },
                    }
                }
            }
            other => other,
        };

        let security_context = build_grpc_runtime_security_context(
            json_req,
            &action,
            request_signature_header,
            crate::proxy::helpers::TransportSecurityInputs {
                oauth_evidence: None,
                eval_ctx: Some(&ctx),
                sessions: &self.state.sessions,
                session_id: Some(session_id),
                trusted_request_signers: &self.state.trusted_request_signers,
                detached_signature_freshness: self.state.detached_signature_freshness,
            },
        );

        match &verdict {
            Verdict::Allow => {
                // Phase 21: ABAC refinement — only runs when ABAC engine is configured
                if let Some(ref abac) = self.state.abac_engine {
                    let principal_id = ctx.agent_id.as_deref().unwrap_or("anonymous");
                    let principal_type = ctx.principal_type();
                    // NOTE: session_risk extracted in TOCTOU-safe block above (FIND-R160-001).
                    let abac_ctx = vellaveto_engine::abac::AbacEvalContext {
                        eval_ctx: &ctx,
                        principal_type,
                        principal_id,
                        risk_score: session_risk.as_ref(),
                    };
                    match abac.evaluate(&action, &abac_ctx) {
                        vellaveto_engine::abac::AbacDecision::Deny { policy_id, reason } => {
                            let deny_verdict = Verdict::Deny {
                                reason: reason.clone(),
                            };
                            let abac_security_context = abac_deny_security_context(&action);
                            let envelope = build_secondary_acis_envelope_with_security_context(
                                &action,
                                &deny_verdict,
                                DecisionOrigin::PolicyEngine,
                                "grpc",
                                Some(session_id),
                                Some(&abac_security_context),
                            );
                            if let Err(e) = self
                                .state
                                .audit
                                .log_entry_with_acis(
                                    &action,
                                    &deny_verdict,
                                    json!({
                                        "source": "grpc_proxy",
                                        "session": session_id,
                                        "transport": "grpc",
                                        "event": "abac_deny",
                                        "abac_policy": policy_id,
                                    }),
                                    envelope,
                                )
                                .await
                            {
                                tracing::warn!("Failed to audit gRPC ABAC deny: {}", e);
                            }
                            // SECURITY (FIND-R116-003): Generic client-facing message.
                            // The policy_id and reason are preserved in the audit log above.
                            return make_proto_denial_response(proto_req, "Denied by policy");
                        }
                        vellaveto_engine::abac::AbacDecision::Allow { policy_id } => {
                            if let Some(ref la) = self.state.least_agency {
                                la.record_usage(
                                    principal_id,
                                    session_id,
                                    &policy_id,
                                    tool_name,
                                    &action.function,
                                );
                            }
                        }
                        vellaveto_engine::abac::AbacDecision::NoMatch => {
                            // Fall through — existing Allow stands
                        }
                        #[allow(unreachable_patterns)] // AbacDecision is #[non_exhaustive]
                        _ => {
                            // SECURITY (FIND-R75-001): Future variants — fail-closed (deny).
                            // Must return denial, not fall through to Allow path.
                            // Parity with HTTP handler (handlers.rs) and WS handler (FIND-R74-002).
                            tracing::warn!("Unknown AbacDecision variant — fail-closed");
                            return make_proto_denial_response(proto_req, "Denied by policy");
                        }
                    }
                }

                // SECURITY (FIND-R54-002): Privilege escalation check.
                // Parity with HTTP handler (handlers.rs:762).
                // NOTE: call_chain extracted in TOCTOU-safe block above (FIND-R160-001).
                if !call_chain.is_empty() {
                    let current_agent_id = ctx.agent_id.as_deref();
                    let priv_check = check_privilege_escalation(
                        &self.state.engine,
                        &self.state.policies,
                        &action,
                        &call_chain,
                        current_agent_id,
                    );
                    if priv_check.escalation_detected {
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
                        let priv_verdict = Verdict::Deny {
                            reason: internal_reason,
                        };
                        let privilege_escalation_security_context =
                            privilege_escalation_security_context(&action);
                        let envelope = build_secondary_acis_envelope_with_security_context(
                            &action,
                            &priv_verdict,
                            DecisionOrigin::PolicyEngine,
                            "grpc",
                            Some(session_id),
                            Some(&privilege_escalation_security_context),
                        );
                        if let Err(e) = self
                            .state
                            .audit
                            .log_entry_with_acis(
                                &action,
                                &priv_verdict,
                                json!({
                                    "source": "grpc_proxy",
                                    "session": session_id,
                                    "transport": "grpc",
                                    "event": "privilege_escalation_blocked",
                                    "escalating_from_agent": priv_check.escalating_from_agent,
                                    "upstream_deny_reason": priv_check.upstream_deny_reason,
                                }),
                                envelope,
                            )
                            .await
                        {
                            tracing::warn!("Failed to audit gRPC privilege escalation: {}", e);
                        }
                        return make_proto_denial_response(proto_req, "Denied by policy");
                    }
                }

                // SECURITY (FIND-R115-043): Record tool call in registry for trust scoring.
                // Parity with HTTP handler (handlers.rs:959) and WS (websocket/mod.rs:1201).
                if let Some(ref registry) = self.state.tool_registry {
                    registry.record_call(tool_name).await;
                }

                // NOTE: Session touch + call_counts/action_history update already
                // performed inside the TOCTOU-safe block above (FIND-R160-001).

                if crate::proxy::helpers::consume_presented_approval(
                    &self.state,
                    session_id,
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
                        invalid_presented_approval_security_context(&action);
                    let combined_security_context = merge_grpc_security_context(
                        security_context.as_ref(),
                        Some(&invalid_approval_security_context),
                    );
                    let effective_security_context = combined_security_context
                        .as_ref()
                        .unwrap_or(&invalid_approval_security_context);
                    let envelope = build_secondary_acis_envelope_with_security_context(
                        &action,
                        &deny_verdict,
                        DecisionOrigin::ApprovalGate,
                        "grpc",
                        Some(session_id),
                        Some(effective_security_context),
                    );
                    let mut audit_metadata = json!({
                        "source": "grpc_proxy",
                        "session": session_id,
                        "transport": "grpc",
                        "event": "presented_approval_replay_denied",
                        "approval_id": matched_approval_id,
                    });
                    if let Some(registry) = matched_approval_registry {
                        audit_metadata["registry"] = json!(registry);
                    }
                    // SECURITY (R274-AUDIT-1): the result was bound to `_`, so a failed
                    // audit write here was invisible. The denial below is unchanged —
                    // this only makes the lost record observable.
                    if let Err(e) = self
                        .state
                        .audit
                        .log_entry_with_acis(&action, &deny_verdict, audit_metadata, envelope)
                        .await
                    {
                        tracing::warn!("Failed to audit denial: {}", e);
                    }
                    return make_proto_denial_response(proto_req, "Denied by policy");
                }

                // Audit the allow
                let acis_envelope = build_acis_envelope_with_security_context(
                    &uuid::Uuid::new_v4().to_string().replace('-', ""),
                    &action,
                    &Verdict::Allow,
                    DecisionOrigin::PolicyEngine,
                    "grpc",
                    &[],
                    None,
                    Some(session_id),
                    None,
                    Some(&ctx),
                    security_context.as_ref(),
                );
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry_with_acis(
                        &action,
                        &Verdict::Allow,
                        json!({
                            "source": "grpc_proxy",
                            "session": session_id,
                            "transport": "grpc",
                        }),
                        acis_envelope,
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC allow: {}", e);
                    if let Some(deny) = self.audit_strict_deny(proto_req, "allow verdict") {
                        return deny;
                    }
                }

                // Forward and scan response
                self.forward_and_scan(proto_req, json_req, session_id).await
            }
            Verdict::Deny { reason } => {
                let acis_envelope = build_acis_envelope_with_security_context(
                    &uuid::Uuid::new_v4().to_string().replace('-', ""),
                    &action,
                    &verdict,
                    DecisionOrigin::PolicyEngine,
                    "grpc",
                    &[],
                    None,
                    Some(session_id),
                    None,
                    Some(&ctx),
                    security_context.as_ref(),
                );
                let mut audit_metadata = json!({
                    "source": "grpc_proxy",
                    "session": session_id,
                    "transport": "grpc",
                });
                let presented_approval_id =
                    crate::proxy::helpers::extract_approval_id_from_meta(json_req);
                if reason == INVALID_PRESENTED_APPROVAL_REASON && presented_approval_id.is_some() {
                    audit_metadata["event"] = json!("presented_approval_replay_denied");
                    audit_metadata["approval_id"] = json!(presented_approval_id);
                    if let Some(registry) = matched_approval_registry {
                        audit_metadata["registry"] = json!(registry);
                    }
                }
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry_with_acis(&action, &verdict, audit_metadata, acis_envelope)
                    .await
                {
                    tracing::warn!("Failed to audit gRPC deny: {}", e);
                    // SECURITY (FIND-R213-003): Strict audit mode — fail-closed on verdict audit failure.
                    if let Some(deny) = self.audit_strict_deny(proto_req, "tool deny") {
                        return deny;
                    }
                }
                // SECURITY (FIND-R113-003): Generic deny message; detailed reason in audit log
                let _ = reason;
                make_proto_denial_response(proto_req, "Denied by policy")
            }
            Verdict::RequireApproval { reason, .. } => {
                let approval_security_context = require_approval_security_context(&action);
                let approval_verdict = Verdict::RequireApproval {
                    reason: reason.clone(),
                };
                let combined_security_context = merge_grpc_security_context(
                    security_context.as_ref(),
                    Some(&approval_security_context),
                );
                let acis_envelope = build_acis_envelope_with_security_context(
                    &uuid::Uuid::new_v4().to_string().replace('-', ""),
                    &action,
                    &approval_verdict,
                    DecisionOrigin::ApprovalGate,
                    "grpc",
                    &[],
                    None,
                    Some(session_id),
                    None,
                    Some(&ctx),
                    combined_security_context.as_ref(),
                );
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry_with_acis(
                        &action,
                        &approval_verdict,
                        json!({
                            "source": "grpc_proxy",
                            "session": session_id,
                            "transport": "grpc",
                        }),
                        acis_envelope,
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC approval request: {}", e);
                    // SECURITY (FIND-R213-003): Strict audit mode — fail-closed on verdict audit failure.
                    if let Some(deny) = self.audit_strict_deny(proto_req, "tool require_approval") {
                        return deny;
                    }
                }
                let containment_context = approval_containment_context_from_security_context(
                    combined_security_context
                        .as_ref()
                        .unwrap_or(&approval_security_context),
                    reason,
                );
                let approval_id = create_pending_approval_with_context(
                    &self.state,
                    session_id,
                    &action,
                    reason,
                    containment_context,
                )
                .await;
                self.approval_required_response(proto_req, approval_id)
            }
            // Fail-closed: unknown Verdict variants produce Deny
            _ => make_proto_denial_response(proto_req, "Denied by policy"),
        }
    }

    /// Handle a resource read: extract action, evaluate, forward or deny.
    #[allow(deprecated)] // evaluate_action_with_context: migration tracked in FIND-CREATIVE-005
    async fn handle_resource_read(
        &self,
        proto_req: &JsonRpcRequest,
        json_req: &Value,
        request_context: GrpcRequestContext<'_>,
        _id: &Value,
        uri: &str,
    ) -> JsonRpcResponse {
        let session_id = request_context.session_id;
        let request_signature_header = request_context.request_signature_header;
        let presented_approval_id = crate::proxy::helpers::extract_approval_id_from_meta(json_req);

        // SECURITY (IMP-R218-002): Requester identity for self-approval prevention
        // is derived inside create_pending_approval_with_context (helpers.rs),
        // which reads it from the session itself. Nothing to pass in here.

        // SECURITY (FIND-R110-HTTP-002): Memory poisoning detection for resource URIs.
        // Parity with HTTP handler (handlers.rs:1491-1546, R27-PROXY-2).
        // ResourceRead is a likely exfiltration vector: a poisoned tool response says
        // "read this file" and the agent issues resources/read for that URI. Without this
        // check, the gRPC transport allows poisoned resource reads that HTTP blocks.
        if let Some(session) = self.state.sessions.get_mut(session_id) {
            let uri_params = serde_json::json!({"uri": uri});
            let poisoning_matches = session.memory_tracker.check_parameters(&uri_params);
            if !poisoning_matches.is_empty() {
                for m in &poisoning_matches {
                    tracing::warn!(
                        "SECURITY: Memory poisoning detected in gRPC resources/read (session {}): \
                         param '{}' contains replayed data (fingerprint: {})",
                        session_id,
                        m.param_location,
                        m.fingerprint
                    );
                }
                let action = extractor::extract_resource_action(uri);
                let deny_reason = format!(
                    "Memory poisoning detected: {} replayed data fragment(s) in resources/read",
                    poisoning_matches.len()
                );
                let mp_verdict = Verdict::Deny {
                    reason: deny_reason.clone(),
                };
                let poisoning_security_context =
                    memory_poisoning_security_context(&uri_params, "memory_poisoning");
                let envelope = build_secondary_acis_envelope_with_security_context(
                    &action,
                    &mp_verdict,
                    DecisionOrigin::MemoryPoisoning,
                    "grpc",
                    Some(session_id),
                    Some(&poisoning_security_context),
                );
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry_with_acis(
                        &action,
                        &mp_verdict,
                        json!({
                            "source": "grpc_proxy",
                            "session": session_id,
                            "transport": "grpc",
                            "event": "memory_poisoning_detected",
                            "matches": poisoning_matches.len(),
                            "uri": uri,
                        }),
                        envelope,
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC resource memory poisoning: {}", e);
                }

                // Drop session borrow before returning
                drop(session);

                // SECURITY (FIND-R118-001): Generic client message.
                return make_proto_denial_response(proto_req, "Denied by policy");
            }
        }

        // SECURITY (FIND-R115-041): Rug-pull detection for resource URIs.
        // If the upstream server was flagged (annotations changed since initial tools/list),
        // block resource reads from that server. Parity with HTTP handler (handlers.rs:1555).
        // SECURITY (R240-PROXY-1): Fall back to global registry on session miss.
        let is_flagged = self
            .state
            .sessions
            .get_mut(session_id)
            .map(|s| s.flagged_tools.contains(uri))
            .unwrap_or_else(|| self.state.sessions.is_tool_globally_flagged(uri));
        if is_flagged {
            let action = extractor::extract_resource_action(uri);
            let verdict = Verdict::Deny {
                reason: format!(
                    "Resource '{}' blocked: server flagged by rug-pull detection",
                    uri
                ),
            };
            let rug_pull_security_context = rug_pull_security_context(&action);
            let envelope = build_secondary_acis_envelope_with_security_context(
                &action,
                &verdict,
                DecisionOrigin::CapabilityEnforcement,
                "grpc",
                Some(session_id),
                Some(&rug_pull_security_context),
            );
            if let Err(e) = self
                .state
                .audit
                .log_entry_with_acis(
                    &action,
                    &verdict,
                    json!({
                        "source": "grpc_proxy",
                        "session": session_id,
                        "transport": "grpc",
                        "event": "rug_pull_resource_blocked",
                        "uri": uri,
                    }),
                    envelope,
                )
                .await
            {
                tracing::warn!("Failed to audit gRPC resource rug-pull block: {}", e);
            }
            return make_proto_denial_response(proto_req, "Denied by policy");
        }

        let mut action = extractor::extract_resource_action(uri);
        let mut matched_approval_id: Option<String> = None;

        // SECURITY (FIND-R116-007): DNS resolution for resource reads.
        // Parity with HTTP handler (handlers.rs:1662) and WS handler (websocket/mod.rs:1439).
        if self.state.engine.has_ip_rules() {
            super::super::helpers::resolve_domains(&mut action).await;
        }

        // SECURITY (FIND-R116-004): DLP scan on resource URI.
        // Parity with HTTP handler (handlers.rs:1598).
        let uri_params = json!({"uri": uri});
        let dlp_findings = scan_parameters_for_secrets(&uri_params);
        if !dlp_findings.is_empty() {
            for finding in &dlp_findings {
                record_dlp_finding(&finding.pattern_name);
            }
            tracing::warn!(
                "SECURITY: Secret detected in gRPC resource URI! Session: {}, URI: [redacted]",
                session_id,
            );
            let audit_verdict = Verdict::Deny {
                reason: "DLP blocked: secret detected in resource URI".to_string(),
            };
            let parameter_security_context =
                parameter_dlp_security_context(&uri_params, true, "resource_uri_dlp");
            let envelope = build_secondary_acis_envelope_with_security_context(
                &action,
                &audit_verdict,
                DecisionOrigin::Dlp,
                "grpc",
                Some(session_id),
                Some(&parameter_security_context),
            );
            if let Err(e) = self
                .state
                .audit
                .log_entry_with_acis(
                    &action,
                    &audit_verdict,
                    json!({
                        "source": "grpc_proxy", "session": session_id,
                        "transport": "grpc", "event": "resource_uri_dlp_alert",
                    }),
                    envelope,
                )
                .await
            {
                tracing::warn!("Failed to audit gRPC resource URI DLP: {}", e);
            }
            return make_proto_denial_response(
                proto_req,
                "Response blocked: sensitive content detected",
            );
        }

        // SECURITY (FIND-R115-042): Circuit breaker check for resource reads.
        // Parity with HTTP handler (handlers.rs:1668) — prevent resource reads from
        // hammering a failing upstream server.
        if let Some(ref circuit_breaker) = self.state.circuit_breaker {
            if let Err(reason) = circuit_breaker.can_proceed(uri) {
                tracing::warn!(
                    "SECURITY: gRPC circuit breaker open for resource '{}' in session {}: {}",
                    uri,
                    session_id,
                    reason
                );
                let verdict = Verdict::Deny {
                    reason: format!("Circuit breaker open: {}", reason),
                };
                // SECURITY (R251-ACIS-1): Use CircuitBreaker origin, not RateLimiter.
                let circuit_breaker_security_context = circuit_breaker_security_context(&action);
                let envelope = build_secondary_acis_envelope_with_security_context(
                    &action,
                    &verdict,
                    DecisionOrigin::CircuitBreaker,
                    "grpc",
                    Some(session_id),
                    Some(&circuit_breaker_security_context),
                );
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry_with_acis(
                        &action,
                        &verdict,
                        json!({
                            "source": "grpc_proxy",
                            "session": session_id,
                            "transport": "grpc",
                            "event": "circuit_breaker_rejected",
                            "uri": uri,
                        }),
                        envelope,
                    )
                    .await
                {
                    tracing::warn!(
                        "Failed to audit gRPC resource circuit breaker rejection: {}",
                        e
                    );
                }
                return make_proto_denial_response(proto_req, "Service temporarily unavailable");
            }
        }

        // SECURITY (FIND-R160-001): TOCTOU-safe context+eval+update for resource_read.
        let resource_key = format!(
            "resources/read:{}",
            uri.chars().take(128).collect::<String>()
        );
        let (verdict, ctx, session_risk) = if let Some(mut session) =
            self.state.sessions.get_mut(session_id)
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
            let risk = session.risk_score.clone();

            let verdict = match self.state.engine.evaluate_action_with_context(
                &action,
                &self.state.policies,
                Some(&ctx),
            ) {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(session_id = %session_id, "Resource policy evaluation error: {}", e);
                    Verdict::Deny {
                        reason: format!("Policy evaluation failed: {}", e),
                    }
                }
            };

            if matches!(verdict, Verdict::Allow) {
                session.touch();
                if session.call_counts.len() < MAX_CALL_COUNT_TOOLS
                    || session.call_counts.contains_key(&resource_key)
                {
                    let count = session.call_counts.entry(resource_key.clone()).or_insert(0);
                    *count = count.saturating_add(1);
                }
                if session.action_history.len() >= MAX_ACTION_HISTORY {
                    session.action_history.pop_front();
                }
                session
                    .action_history
                    .push_back("resources/read".to_string());
            }

            (verdict, ctx, risk)
        } else {
            let verdict = match self.state.engine.evaluate_action_with_context(
                &action,
                &self.state.policies,
                None,
            ) {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(session_id = %session_id, "Resource policy evaluation error: {}", e);
                    Verdict::Deny {
                        reason: format!("Policy evaluation failed: {}", e),
                    }
                }
            };
            (verdict, EvaluationContext::default(), None)
        };

        let verdict = match verdict {
            Verdict::RequireApproval { reason } => {
                match crate::proxy::helpers::presented_approval_matches_action(
                    &self.state,
                    session_id,
                    presented_approval_id.as_deref(),
                    &action,
                )
                .await
                {
                    Ok(Some(approval_id)) => {
                        matched_approval_id = Some(approval_id);
                        Verdict::Allow
                    }
                    Ok(None) => Verdict::RequireApproval { reason },
                    Err(()) => Verdict::Deny {
                        reason: INVALID_PRESENTED_APPROVAL_REASON.to_string(),
                    },
                }
            }
            other => other,
        };

        let security_context = build_grpc_runtime_security_context(
            json_req,
            &action,
            request_signature_header,
            crate::proxy::helpers::TransportSecurityInputs {
                oauth_evidence: None,
                eval_ctx: Some(&ctx),
                sessions: &self.state.sessions,
                session_id: Some(session_id),
                trusted_request_signers: &self.state.trusted_request_signers,
                detached_signature_freshness: self.state.detached_signature_freshness,
            },
        );

        match &verdict {
            Verdict::Allow => {
                // SECURITY (FIND-R114-004): ABAC refinement — parity with handle_tool_call.
                if let Some(ref abac) = self.state.abac_engine {
                    let principal_id = ctx.agent_id.as_deref().unwrap_or("anonymous");
                    let principal_type = ctx.principal_type();
                    // NOTE: session_risk extracted in TOCTOU-safe block above (FIND-R160-001).
                    let abac_ctx = vellaveto_engine::abac::AbacEvalContext {
                        eval_ctx: &ctx,
                        principal_type,
                        principal_id,
                        risk_score: session_risk.as_ref(),
                    };
                    match abac.evaluate(&action, &abac_ctx) {
                        vellaveto_engine::abac::AbacDecision::Deny { policy_id, reason } => {
                            let deny_verdict = Verdict::Deny {
                                reason: reason.clone(),
                            };
                            let abac_security_context = abac_deny_security_context(&action);
                            let envelope = build_secondary_acis_envelope_with_security_context(
                                &action,
                                &deny_verdict,
                                DecisionOrigin::PolicyEngine,
                                "grpc",
                                Some(session_id),
                                Some(&abac_security_context),
                            );
                            if let Err(e) = self
                                .state
                                .audit
                                .log_entry_with_acis(
                                    &action,
                                    &deny_verdict,
                                    json!({
                                        "source": "grpc_proxy", "session": session_id,
                                        "transport": "grpc", "event": "abac_deny",
                                        "abac_policy": policy_id, "uri": uri,
                                    }),
                                    envelope,
                                )
                                .await
                            {
                                tracing::warn!("Failed to audit gRPC resource ABAC deny: {}", e);
                            }
                            // SECURITY (FIND-R116-003): Generic client-facing message.
                            return make_proto_denial_response(proto_req, "Denied by policy");
                        }
                        vellaveto_engine::abac::AbacDecision::Allow { policy_id } => {
                            // SECURITY (FIND-R192-002): record_usage parity.
                            if let Some(ref la) = self.state.least_agency {
                                la.record_usage(
                                    principal_id,
                                    session_id,
                                    &policy_id,
                                    uri,
                                    &action.function,
                                );
                            }
                        }
                        vellaveto_engine::abac::AbacDecision::NoMatch => {}
                        #[allow(unreachable_patterns)]
                        _ => {
                            tracing::warn!(
                                "Unknown AbacDecision variant in resource_read — fail-closed"
                            );
                            return make_proto_denial_response(proto_req, "Denied by policy");
                        }
                    }
                }

                // NOTE: Session touch + call_counts/action_history update already
                // performed inside the TOCTOU-safe block above (FIND-R160-001).

                if crate::proxy::helpers::consume_presented_approval(
                    &self.state,
                    session_id,
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
                        invalid_presented_approval_security_context(&action);
                    let combined_security_context = merge_grpc_security_context(
                        security_context.as_ref(),
                        Some(&invalid_approval_security_context),
                    );
                    let effective_security_context = combined_security_context
                        .as_ref()
                        .unwrap_or(&invalid_approval_security_context);
                    let envelope = build_secondary_acis_envelope_with_security_context(
                        &action,
                        &deny_verdict,
                        DecisionOrigin::ApprovalGate,
                        "grpc",
                        Some(session_id),
                        Some(effective_security_context),
                    );
                    // SECURITY (R274-AUDIT-1): the result was bound to `_`, so a failed
                    // audit write here was invisible. The denial below is unchanged —
                    // this only makes the lost record observable.
                    if let Err(e) = self
                        .state
                        .audit
                        .log_entry_with_acis(
                            &action,
                            &deny_verdict,
                            json!({
                                "source": "grpc_proxy",
                                "session": session_id,
                                "transport": "grpc",
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
                    return make_proto_denial_response(proto_req, "Denied by policy");
                }

                // SECURITY (FIND-R114-007): Audit Allow verdict for resource reads.
                let acis_envelope = build_acis_envelope_with_security_context(
                    &uuid::Uuid::new_v4().to_string().replace('-', ""),
                    &action,
                    &Verdict::Allow,
                    DecisionOrigin::PolicyEngine,
                    "grpc",
                    &[],
                    None,
                    Some(session_id),
                    None,
                    Some(&ctx),
                    security_context.as_ref(),
                );
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry_with_acis(
                        &action,
                        &Verdict::Allow,
                        json!({
                            "source": "grpc_proxy", "session": session_id,
                            "transport": "grpc", "uri": uri,
                        }),
                        acis_envelope,
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC resource allow: {}", e);
                    if let Some(deny) = self.audit_strict_deny(proto_req, "resource allow") {
                        return deny;
                    }
                }

                self.forward_and_scan(proto_req, json_req, session_id).await
            }
            Verdict::Deny { reason } => {
                let acis_envelope = build_acis_envelope_with_security_context(
                    &uuid::Uuid::new_v4().to_string().replace('-', ""),
                    &action,
                    &verdict,
                    DecisionOrigin::PolicyEngine,
                    "grpc",
                    &[],
                    None,
                    Some(session_id),
                    None,
                    Some(&ctx),
                    security_context.as_ref(),
                );
                let mut audit_metadata = json!({
                    "source": "grpc_proxy", "session": session_id,
                    "transport": "grpc", "uri": uri,
                });
                if reason == INVALID_PRESENTED_APPROVAL_REASON && presented_approval_id.is_some() {
                    audit_metadata["event"] = json!("presented_approval_replay_denied");
                    audit_metadata["approval_id"] = json!(presented_approval_id);
                }
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry_with_acis(&action, &verdict, audit_metadata, acis_envelope)
                    .await
                {
                    tracing::warn!("Failed to audit gRPC resource deny: {}", e);
                    // SECURITY (FIND-R213-003): Strict audit mode — fail-closed on verdict audit failure.
                    if let Some(deny) = self.audit_strict_deny(proto_req, "resource deny") {
                        return deny;
                    }
                }
                // SECURITY (FIND-R113-003): Generic deny message; detailed reason in audit log
                let _ = reason;
                make_proto_denial_response(proto_req, "Denied by policy")
            }
            Verdict::RequireApproval { reason, .. } => {
                let approval_security_context = require_approval_security_context(&action);
                let combined_security_context = merge_grpc_security_context(
                    security_context.as_ref(),
                    Some(&approval_security_context),
                );
                let acis_envelope = build_acis_envelope_with_security_context(
                    &uuid::Uuid::new_v4().to_string().replace('-', ""),
                    &action,
                    &verdict,
                    DecisionOrigin::ApprovalGate,
                    "grpc",
                    &[],
                    None,
                    Some(session_id),
                    None,
                    Some(&ctx),
                    combined_security_context.as_ref(),
                );
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry_with_acis(
                        &action,
                        &verdict,
                        json!({
                            "source": "grpc_proxy", "session": session_id,
                            "transport": "grpc", "uri": uri,
                        }),
                        acis_envelope,
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC resource approval request: {}", e);
                    // SECURITY (FIND-R213-003): Strict audit mode — fail-closed on verdict audit failure.
                    if let Some(deny) =
                        self.audit_strict_deny(proto_req, "resource require_approval")
                    {
                        return deny;
                    }
                }
                // SECURITY (FIND-R211-002): Create pending approval in store — parity
                // with HTTP handler (handlers.rs:1927) and WS (create_ws_approval).
                let containment_context = approval_containment_context_from_security_context(
                    combined_security_context
                        .as_ref()
                        .unwrap_or(&approval_security_context),
                    reason,
                );
                let approval_id = create_pending_approval_with_context(
                    &self.state,
                    session_id,
                    &action,
                    reason,
                    containment_context,
                )
                .await;
                self.approval_required_response(proto_req, approval_id)
            }
            // SECURITY (FIND-R113-003): Generic deny message; detailed reason in audit log
            _ => make_proto_denial_response(proto_req, "Denied by policy"),
        }
    }

    /// Forward a request to upstream and scan the response for secrets/injection.
    async fn forward_and_scan(
        &self,
        proto_req: &JsonRpcRequest,
        json_req: &Value,
        session_id: &str,
    ) -> JsonRpcResponse {
        // Forward
        let response_json = match self.upstream.forward_json(json_req).await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::error!(session_id = %session_id, "Upstream forwarding error: {}", e);
                return make_proto_error_response(proto_req, -32603, "Upstream error");
            }
        };

        // SECURITY (FIND-R55-GRPC-002): Track whether DLP or injection findings
        // were detected, to skip memory_tracker recording for tainted responses.
        // Parity with HTTP handler (inspection.rs:638-641).
        let mut dlp_found = false;
        let mut injection_found = false;

        // DLP scan response
        if self.state.response_dlp_enabled {
            let dlp_findings = scan_response_for_secrets(&response_json);
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
                    "SECURITY: Secrets in gRPC response! Session: {}, Findings: {:?}",
                    session_id,
                    patterns,
                );

                let verdict = if self.state.response_dlp_blocking {
                    Verdict::Deny {
                        reason: format!("gRPC response DLP blocked: {:?}", patterns),
                    }
                } else {
                    Verdict::Allow
                };

                let action = Action::new(
                    "vellaveto",
                    "grpc_response_dlp_scan",
                    json!({
                        "findings": patterns,
                        "session": session_id,
                        "transport": "grpc",
                    }),
                );
                let response_tool_name = json_req
                    .get("method")
                    .and_then(|method| method.as_str())
                    .and_then(|method| match method {
                        "tools/call" => json_req
                            .get("params")
                            .and_then(|params| params.get("name"))
                            .and_then(|name| name.as_str()),
                        "resources/read" => Some("resources/read"),
                        _ => None,
                    });
                let dlp_security_context = response_dlp_security_context(
                    response_tool_name,
                    &response_json,
                    self.state.response_dlp_blocking,
                );
                let envelope = build_secondary_acis_envelope_with_security_context(
                    &action,
                    &verdict,
                    DecisionOrigin::Dlp,
                    "grpc",
                    Some(session_id),
                    Some(&dlp_security_context),
                );
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry_with_acis(
                        &action,
                        &verdict,
                        json!({
                            "source": "grpc_proxy",
                            "event": "grpc_response_dlp_alert",
                        }),
                        envelope,
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC DLP: {}", e);
                }

                if self.state.response_dlp_blocking {
                    return make_proto_error_response(
                        proto_req,
                        -32001,
                        "Response blocked by DLP policy",
                    );
                }
            }
        }

        // Injection scan response
        if !self.state.injection_disabled {
            let text_to_scan = extract_scannable_text(&response_json);
            if !text_to_scan.is_empty() {
                let injection_matches: Vec<String> =
                    if let Some(ref scanner) = self.state.injection_scanner {
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
                        "SECURITY: Injection in gRPC response! Session: {}, Patterns: {:?}",
                        session_id,
                        injection_matches,
                    );

                    let verdict = if self.state.injection_blocking {
                        Verdict::Deny {
                            reason: format!(
                                "gRPC response injection blocked: {:?}",
                                injection_matches
                            ),
                        }
                    } else {
                        Verdict::Allow
                    };

                    let action = Action::new(
                        "vellaveto",
                        "grpc_response_injection",
                        json!({
                            "matched_patterns": injection_matches,
                            "session": session_id,
                            "transport": "grpc",
                        }),
                    );
                    let response_tool_name = json_req
                        .get("method")
                        .and_then(|method| method.as_str())
                        .and_then(|method| match method {
                            "tools/call" => json_req
                                .get("params")
                                .and_then(|params| params.get("name"))
                                .and_then(|name| name.as_str()),
                            "resources/read" => Some("resources/read"),
                            _ => None,
                        });
                    let injection_security_context = response_injection_security_context(
                        response_tool_name,
                        &response_json,
                        self.state.injection_blocking,
                        "response_injection",
                    );
                    let envelope = build_secondary_acis_envelope_with_security_context(
                        &action,
                        &verdict,
                        DecisionOrigin::InjectionScanner,
                        "grpc",
                        Some(session_id),
                        Some(&injection_security_context),
                    );
                    if let Err(e) = self
                        .state
                        .audit
                        .log_entry_with_acis(
                            &action,
                            &verdict,
                            json!({
                                "source": "grpc_proxy",
                                "event": "grpc_injection_detected",
                            }),
                            envelope,
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit gRPC injection: {}", e);
                    }

                    if self.state.injection_blocking {
                        return make_proto_error_response(
                            proto_req,
                            -32001,
                            "Response blocked: injection detected",
                        );
                    }
                }
            }
        }

        // SECURITY (FIND-R115-040): Rug-pull detection on tools/list responses.
        // Extract annotations and flag tools with changed annotations. Also register
        // output schemas from tool definitions. Parity with WS handler
        // (websocket/mod.rs:3045-3076, 3326-3338) and HTTP handler (inspection.rs).
        if response_json
            .get("result")
            .and_then(|r| r.get("tools"))
            .and_then(|t| t.as_array())
            .is_some()
        {
            super::super::helpers::extract_annotations_from_response(
                &response_json,
                session_id,
                &self.state.sessions,
                &self.state.audit,
                &self.state.known_tools,
            )
            .await;

            // Verify manifest if configured
            if let Some(ref manifest_config) = self.state.manifest_config {
                super::super::helpers::verify_manifest_from_response(
                    &response_json,
                    session_id,
                    &self.state.sessions,
                    manifest_config,
                    &self.state.audit,
                )
                .await;
            }

            // SECURITY (FIND-R130-003): Scan tool descriptions for embedded injection.
            // Parity with HTTP upstream handler (upstream.rs:648-698).
            if !self.state.injection_disabled {
                let desc_findings = if let Some(ref scanner) = self.state.injection_scanner {
                    scan_tool_descriptions_with_scanner(&response_json, scanner)
                } else {
                    scan_tool_descriptions(&response_json)
                };
                for finding in &desc_findings {
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
                            "transport": "grpc",
                            "blocking": self.state.injection_blocking,
                        }),
                    );
                    let desc_verdict = Verdict::Deny {
                        reason: format!(
                            "Tool '{}' description contains injection: {:?}",
                            finding.tool_name, finding.matched_patterns
                        ),
                    };
                    let desc_security_context = tool_discovery_integrity_security_context(
                        &finding.tool_name,
                        vellaveto_types::ContextChannel::CommandLike,
                        "tool_description_injection",
                        true,
                    );
                    let envelope = build_secondary_acis_envelope_with_security_context(
                        &action,
                        &desc_verdict,
                        DecisionOrigin::InjectionScanner,
                        "grpc",
                        Some(session_id),
                        Some(&desc_security_context),
                    );
                    if let Err(e) = self
                        .state
                        .audit
                        .log_entry_with_acis(
                            &action,
                            &desc_verdict,
                            json!({
                                "source": "grpc_proxy",
                                "event": "tool_description_injection",
                            }),
                            envelope,
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit gRPC tool description injection: {}", e);
                        // SECURITY (FIND-R206-001): strict audit mode parity
                        if self.state.audit_strict_mode {
                            return make_proto_error_response(
                                proto_req,
                                -32603,
                                "Audit logging failed — request denied (strict audit mode)",
                            );
                        }
                    }
                }
                if !desc_findings.is_empty() && self.state.injection_blocking {
                    return make_proto_error_response(
                        proto_req,
                        -32603,
                        "Response blocked: suspicious content in tool descriptions",
                    );
                }
            }
        }

        // SECURITY (FIND-R115-040): Register output schemas from tools/list responses.
        // Parity with WS handler (websocket/mod.rs:3338) and HTTP handler (inspection.rs:693).
        // register_from_tools_list checks for result.tools internally.
        self.state
            .output_schema_registry
            .register_from_tools_list(&response_json);

        // Transport parity: feed discovery the same tools/list.
        super::super::helpers::ingest_tools_for_discovery(&self.state, &response_json);

        // SECURITY (FIND-R53-GRPC-004): Output schema validation.
        // Parity with WS handler (websocket/mod.rs:2327-2370).
        let mut schema_violation_found = false;
        if let Some(method) = json_req.get("method").and_then(|m| m.as_str()) {
            if method == "tools/call" {
                let tool_name = json_req
                    .get("params")
                    .and_then(|p| p.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("");
                if !tool_name.is_empty() {
                    match self
                        .state
                        .output_schema_registry
                        .validate(tool_name, &response_json)
                    {
                        ValidationResult::Invalid { violations } => {
                            schema_violation_found = true;
                            tracing::warn!(
                                "SECURITY: gRPC output schema violation for tool '{}': {:?}",
                                tool_name,
                                violations,
                            );

                            let action = Action::new(
                                "vellaveto",
                                "output_schema_violation",
                                json!({
                                    "tool": tool_name,
                                    "violations": violations,
                                    "session": session_id,
                                    "transport": "grpc",
                                }),
                            );
                            let schema_verdict = Verdict::Deny {
                                reason: format!(
                                    "gRPC structuredContent validation failed: {:?}",
                                    violations
                                ),
                            };
                            let schema_security_context =
                                output_schema_violation_security_context(Some(tool_name), false);
                            let envelope = build_secondary_acis_envelope_with_security_context(
                                &action,
                                &schema_verdict,
                                DecisionOrigin::PolicyEngine,
                                "grpc",
                                Some(session_id),
                                Some(&schema_security_context),
                            );
                            if let Err(e) = self
                                .state
                                .audit
                                .log_entry_with_acis(
                                    &action,
                                    &schema_verdict,
                                    json!({
                                        "source": "grpc_proxy",
                                        "event": "output_schema_violation_grpc",
                                    }),
                                    envelope,
                                )
                                .await
                            {
                                tracing::warn!(
                                    "Failed to audit gRPC output schema violation: {}",
                                    e
                                );
                                // SECURITY (FIND-R206-001): strict audit mode parity
                                if self.state.audit_strict_mode {
                                    return make_proto_error_response(
                                        proto_req,
                                        -32603,
                                        "Audit logging failed — request denied (strict audit mode)",
                                    );
                                }
                            }
                        }
                        ValidationResult::Valid => {
                            tracing::debug!(
                                "gRPC structuredContent validated for tool '{}'",
                                tool_name
                            );
                        }
                        ValidationResult::NoSchema => {}
                    }
                }
            }
        }

        // SECURITY (FIND-R55-GRPC-002, FIND-R77-003): Record response for memory poisoning
        // tracking. Parity with HTTP handler (inspection.rs:638-641). Skip recording when
        // injection, DLP, or schema violation detected (even in log-only mode) to avoid
        // poisoning the tracker with tainted data.
        if !injection_found && !dlp_found && !schema_violation_found {
            if let Some(mut session) = self.state.sessions.get_mut(session_id) {
                session.memory_tracker.record_response(&response_json);
            }
        }

        // Convert response JSON to proto
        match json_to_proto_response(&response_json) {
            Ok(resp) => resp,
            Err(e) => {
                tracing::error!("gRPC JSON→proto response conversion failed: {}", e);
                make_proto_error_response(proto_req, -32603, "Response conversion error")
            }
        }
    }

    /// Handle a task request: extract action, evaluate policy, audit, forward or deny.
    #[allow(deprecated)] // evaluate_action_with_context: migration tracked in FIND-CREATIVE-005
    async fn handle_task_request(
        &self,
        proto_req: &JsonRpcRequest,
        json_req: &Value,
        request_context: GrpcRequestContext<'_>,
        _id: &Value,
        task_method: &str,
        task_id: Option<&str>,
    ) -> JsonRpcResponse {
        let session_id = request_context.session_id;
        let request_signature_header = request_context.request_signature_header;
        let presented_approval_id = crate::proxy::helpers::extract_approval_id_from_meta(json_req);

        // SECURITY (IMP-R218-002): Requester identity for self-approval prevention
        // is derived inside create_pending_approval_with_context (helpers.rs),
        // which reads it from the session itself. Nothing to pass in here.

        // SECURITY (FIND-R222-001): Injection scanning on task parameters.
        // Parity with PassThrough handler (service.rs:639) and WS handler
        // (websocket/mod.rs pre-classify scan). Task methods (tasks/send,
        // tasks/sendSubscribe) carry a `message` parameter vulnerable to
        // prompt injection attacks.
        let params = json_req.get("params").cloned().unwrap_or(json!({}));

        if !self.state.injection_disabled {
            let scannable = extract_passthrough_text_for_injection(json_req);
            if !scannable.is_empty() {
                let injection_matches: Vec<String> =
                    if let Some(ref scanner) = self.state.injection_scanner {
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
                        "SECURITY: Injection in gRPC task params! \
                         Session: {}, Method: {}, Patterns: {:?}",
                        session_id,
                        task_method,
                        injection_matches,
                    );

                    let verdict = if self.state.injection_blocking {
                        Verdict::Deny {
                            reason: format!("Task injection blocked: {:?}", injection_matches),
                        }
                    } else {
                        Verdict::Allow
                    };

                    let inj_action = extractor::extract_task_action(task_method, task_id);
                    let injection_security_context = parameter_injection_security_context(
                        &params,
                        self.state.injection_blocking,
                        "task_injection",
                    );
                    let envelope = build_secondary_acis_envelope_with_security_context(
                        &inj_action,
                        &verdict,
                        DecisionOrigin::InjectionScanner,
                        "grpc",
                        Some(session_id),
                        Some(&injection_security_context),
                    );
                    if let Err(e) = self
                        .state
                        .audit
                        .log_entry_with_acis(
                            &inj_action,
                            &verdict,
                            json!({
                                "source": "grpc_proxy",
                                "event": "task_injection_detected",
                                "blocking": self.state.injection_blocking,
                                "session": session_id,
                                "transport": "grpc",
                                "task_method": task_method,
                            }),
                            envelope,
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit gRPC task injection: {}", e);
                        if let Some(deny) = self.audit_strict_deny(proto_req, "task injection") {
                            return deny;
                        }
                    }

                    if self.state.injection_blocking {
                        return make_proto_denial_response(
                            proto_req,
                            "Request blocked: injection detected",
                        );
                    }
                }
            }
        }

        // SECURITY (FIND-R60-002): DLP scan task parameters for secret exfiltration.
        // Parity with tools/call handler (service.rs:354) and WS (websocket/mod.rs:700).
        // Task methods (tasks/send, tasks/sendSubscribe) carry a `message` parameter that
        // may contain secrets — apply the same DLP scanning as tools/call.
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
                "SECURITY: Secrets in gRPC task request parameters! Session: {}, Method: {}, Findings: {:?}",
                session_id,
                task_method,
                patterns,
            );

            let action = extractor::extract_task_action(task_method, task_id);
            let verdict = Verdict::Deny {
                reason: format!(
                    "DLP blocked: secret detected in task parameters: {:?}",
                    patterns
                ),
            };
            let parameter_security_context =
                parameter_dlp_security_context(&params, true, "task_parameter_dlp");
            let envelope = build_secondary_acis_envelope_with_security_context(
                &action,
                &verdict,
                DecisionOrigin::Dlp,
                "grpc",
                Some(session_id),
                Some(&parameter_security_context),
            );
            if let Err(e) = self
                .state
                .audit
                .log_entry_with_acis(
                    &action,
                    &verdict,
                    json!({
                        "source": "grpc_proxy",
                        "session": session_id,
                        "transport": "grpc",
                        "event": "grpc_task_parameter_dlp_alert",
                        "task_method": task_method,
                        "findings": patterns,
                    }),
                    envelope,
                )
                .await
            {
                tracing::warn!("Failed to audit gRPC task parameter DLP: {}", e);
            }

            // SECURITY (FIND-R114-002): Generic client-facing message. Pattern names
            // are in the audit record only, matching handle_tool_call (line 444).
            return make_proto_denial_response(
                proto_req,
                "Response blocked: sensitive content detected",
            );
        }

        // SECURITY (FIND-R60-002): Memory poisoning detection for task parameters.
        // Parity with tools/call handler (service.rs:449-497) and WS (websocket/mod.rs:751-810).
        if let Some(session) = self.state.sessions.get_mut(session_id) {
            let poisoning_matches = session.memory_tracker.check_parameters(&params);
            if !poisoning_matches.is_empty() {
                for m in &poisoning_matches {
                    tracing::warn!(
                        "SECURITY: Memory poisoning detected in gRPC task '{}' (session {}): \
                         param '{}' contains replayed data (fingerprint: {})",
                        task_method,
                        session_id,
                        m.param_location,
                        m.fingerprint
                    );
                }
                let action = extractor::extract_task_action(task_method, task_id);
                let deny_reason = format!(
                    "Memory poisoning detected: {} replayed data fragment(s) in task '{}'",
                    poisoning_matches.len(),
                    task_method
                );
                let mp_verdict = Verdict::Deny {
                    reason: deny_reason.clone(),
                };
                let poisoning_security_context =
                    memory_poisoning_security_context(&params, "memory_poisoning");
                let envelope = build_secondary_acis_envelope_with_security_context(
                    &action,
                    &mp_verdict,
                    DecisionOrigin::MemoryPoisoning,
                    "grpc",
                    Some(session_id),
                    Some(&poisoning_security_context),
                );
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry_with_acis(
                        &action,
                        &mp_verdict,
                        json!({
                            "source": "grpc_proxy",
                            "session": session_id,
                            "transport": "grpc",
                            "event": "memory_poisoning_detected",
                            "matches": poisoning_matches.len(),
                            "task_method": task_method,
                        }),
                        envelope,
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC task memory poisoning: {}", e);
                }

                // Drop session borrow before returning
                drop(session);

                // SECURITY (FIND-R118-001): Generic client message.
                return make_proto_denial_response(proto_req, "Denied by policy");
            }
        }

        let action = extractor::extract_task_action(task_method, task_id);
        let mut matched_approval_id: Option<String> = None;

        // SECURITY (FIND-R160-001): TOCTOU-safe context+eval for task requests.
        // No session update needed for tasks, but context must be read atomically
        // to prevent stale call_counts from bypassing max_calls_in_window.
        let (verdict, ctx) = if let Some(session) = self.state.sessions.get_mut(session_id) {
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
            let verdict = match self.state.engine.evaluate_action_with_context(
                &action,
                &self.state.policies,
                Some(&ctx),
            ) {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(session_id = %session_id, "Task policy evaluation error: {}", e);
                    Verdict::Deny {
                        reason: format!("Policy evaluation failed: {}", e),
                    }
                }
            };
            (verdict, ctx)
        } else {
            let verdict = match self.state.engine.evaluate_action_with_context(
                &action,
                &self.state.policies,
                None,
            ) {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(session_id = %session_id, "Task policy evaluation error: {}", e);
                    Verdict::Deny {
                        reason: format!("Policy evaluation failed: {}", e),
                    }
                }
            };
            (verdict, EvaluationContext::default())
        };

        let verdict = match verdict {
            Verdict::RequireApproval { reason } => {
                match crate::proxy::helpers::presented_approval_matches_action(
                    &self.state,
                    session_id,
                    presented_approval_id.as_deref(),
                    &action,
                )
                .await
                {
                    Ok(Some(approval_id)) => {
                        matched_approval_id = Some(approval_id);
                        Verdict::Allow
                    }
                    Ok(None) => Verdict::RequireApproval { reason },
                    Err(()) => Verdict::Deny {
                        reason: INVALID_PRESENTED_APPROVAL_REASON.to_string(),
                    },
                }
            }
            other => other,
        };

        let security_context = build_grpc_runtime_security_context(
            json_req,
            &action,
            request_signature_header,
            crate::proxy::helpers::TransportSecurityInputs {
                oauth_evidence: None,
                eval_ctx: Some(&ctx),
                sessions: &self.state.sessions,
                session_id: Some(session_id),
                trusted_request_signers: &self.state.trusted_request_signers,
                detached_signature_freshness: self.state.detached_signature_freshness,
            },
        );

        match &verdict {
            Verdict::Allow => {
                // SECURITY (FIND-R190-001): ABAC refinement for TaskRequest,
                // matching ToolCall/ResourceRead/ExtensionMethod parity.
                if let Some(ref abac) = self.state.abac_engine {
                    let principal_id = ctx.agent_id.as_deref().unwrap_or("anonymous");
                    let principal_type = ctx.principal_type();
                    let session_risk = self
                        .state
                        .sessions
                        .get_mut(session_id)
                        .and_then(|s| s.risk_score.clone());
                    let abac_ctx = vellaveto_engine::abac::AbacEvalContext {
                        eval_ctx: &ctx,
                        principal_type,
                        principal_id,
                        risk_score: session_risk.as_ref(),
                    };
                    match abac.evaluate(&action, &abac_ctx) {
                        vellaveto_engine::abac::AbacDecision::Deny { policy_id, reason } => {
                            let deny_verdict = Verdict::Deny {
                                reason: reason.clone(),
                            };
                            let abac_security_context = abac_deny_security_context(&action);
                            let envelope = build_secondary_acis_envelope_with_security_context(
                                &action,
                                &deny_verdict,
                                DecisionOrigin::PolicyEngine,
                                "grpc",
                                Some(session_id),
                                Some(&abac_security_context),
                            );
                            if let Err(e) = self
                                .state
                                .audit
                                .log_entry_with_acis(
                                    &action,
                                    &deny_verdict,
                                    json!({
                                        "source": "grpc_proxy",
                                        "session": session_id,
                                        "transport": "grpc",
                                        "event": "abac_deny",
                                        "abac_policy": policy_id,
                                        "task_method": task_method,
                                    }),
                                    envelope,
                                )
                                .await
                            {
                                tracing::warn!("Failed to audit gRPC task ABAC deny: {}", e);
                            }
                            return make_proto_denial_response(proto_req, "Denied by policy");
                        }
                        vellaveto_engine::abac::AbacDecision::Allow { policy_id } => {
                            if let Some(ref la) = self.state.least_agency {
                                la.record_usage(
                                    principal_id,
                                    session_id,
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
                                "Unknown AbacDecision variant in task_request — fail-closed"
                            );
                            return make_proto_denial_response(proto_req, "Denied by policy");
                        }
                    }
                }

                if crate::proxy::helpers::consume_presented_approval(
                    &self.state,
                    session_id,
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
                        invalid_presented_approval_security_context(&action);
                    let combined_security_context = merge_grpc_security_context(
                        security_context.as_ref(),
                        Some(&invalid_approval_security_context),
                    );
                    let effective_security_context = combined_security_context
                        .as_ref()
                        .unwrap_or(&invalid_approval_security_context);
                    let envelope = build_secondary_acis_envelope_with_security_context(
                        &action,
                        &deny_verdict,
                        DecisionOrigin::ApprovalGate,
                        "grpc",
                        Some(session_id),
                        Some(effective_security_context),
                    );
                    // SECURITY (R274-AUDIT-1): the result was bound to `_`, so a failed
                    // audit write here was invisible. The denial below is unchanged —
                    // this only makes the lost record observable.
                    if let Err(e) = self
                        .state
                        .audit
                        .log_entry_with_acis(
                            &action,
                            &deny_verdict,
                            json!({
                                "source": "grpc_proxy",
                                "session": session_id,
                                "transport": "grpc",
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
                    return make_proto_denial_response(proto_req, "Denied by policy");
                }
                let acis_envelope = build_acis_envelope_with_security_context(
                    &uuid::Uuid::new_v4().to_string().replace('-', ""),
                    &action,
                    &Verdict::Allow,
                    DecisionOrigin::PolicyEngine,
                    "grpc",
                    &[],
                    None,
                    Some(session_id),
                    None,
                    Some(&ctx),
                    security_context.as_ref(),
                );
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry_with_acis(
                        &action,
                        &Verdict::Allow,
                        json!({
                            "source": "grpc_proxy",
                            "session": session_id,
                            "transport": "grpc",
                            "task_method": task_method,
                        }),
                        acis_envelope,
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC task allow: {}", e);
                    if let Some(deny) = self.audit_strict_deny(proto_req, "task allow") {
                        return deny;
                    }
                }
                self.forward_and_scan(proto_req, json_req, session_id).await
            }
            Verdict::Deny { reason } => {
                let acis_envelope = build_acis_envelope_with_security_context(
                    &uuid::Uuid::new_v4().to_string().replace('-', ""),
                    &action,
                    &verdict,
                    DecisionOrigin::PolicyEngine,
                    "grpc",
                    &[],
                    None,
                    Some(session_id),
                    None,
                    Some(&ctx),
                    security_context.as_ref(),
                );
                let mut audit_metadata = json!({
                    "source": "grpc_proxy",
                    "session": session_id,
                    "transport": "grpc",
                    "task_method": task_method,
                });
                if reason == INVALID_PRESENTED_APPROVAL_REASON && presented_approval_id.is_some() {
                    audit_metadata["event"] = json!("presented_approval_replay_denied");
                    audit_metadata["approval_id"] = json!(presented_approval_id);
                    audit_metadata["task_id"] = json!(task_id);
                }
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry_with_acis(&action, &verdict, audit_metadata, acis_envelope)
                    .await
                {
                    tracing::warn!("Failed to audit gRPC task deny: {}", e);
                    // SECURITY (FIND-R213-003): Strict audit mode — fail-closed on verdict audit failure.
                    if let Some(deny) = self.audit_strict_deny(proto_req, "task deny") {
                        return deny;
                    }
                }
                // SECURITY (FIND-R113-003): Generic deny message; detailed reason in audit log
                let _ = reason;
                make_proto_denial_response(proto_req, "Denied by policy")
            }
            Verdict::RequireApproval { reason, .. } => {
                let approval_security_context = require_approval_security_context(&action);
                let approval_verdict = Verdict::RequireApproval {
                    reason: reason.clone(),
                };
                let combined_security_context = merge_grpc_security_context(
                    security_context.as_ref(),
                    Some(&approval_security_context),
                );
                let acis_envelope = build_acis_envelope_with_security_context(
                    &uuid::Uuid::new_v4().to_string().replace('-', ""),
                    &action,
                    &approval_verdict,
                    DecisionOrigin::ApprovalGate,
                    "grpc",
                    &[],
                    None,
                    Some(session_id),
                    None,
                    Some(&ctx),
                    combined_security_context.as_ref(),
                );
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry_with_acis(
                        &action,
                        &approval_verdict,
                        json!({
                            "source": "grpc_proxy",
                            "session": session_id,
                            "transport": "grpc",
                            "task_method": task_method,
                        }),
                        acis_envelope,
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC task approval request: {}", e);
                    // SECURITY (FIND-R213-003): Strict audit mode — fail-closed on verdict audit failure.
                    if let Some(deny) = self.audit_strict_deny(proto_req, "task require_approval") {
                        return deny;
                    }
                }
                let containment_context = approval_containment_context_from_security_context(
                    combined_security_context
                        .as_ref()
                        .unwrap_or(&approval_security_context),
                    reason,
                );
                let approval_id = create_pending_approval_with_context(
                    &self.state,
                    session_id,
                    &action,
                    reason,
                    containment_context,
                )
                .await;
                self.approval_required_response(proto_req, approval_id)
            }
            // SECURITY (FIND-R113-003): Generic deny message; detailed reason in audit log
            _ => make_proto_denial_response(proto_req, "Denied by policy"),
        }
    }

    /// Handle an extension method: extract action, evaluate policy, audit, forward or deny.
    #[allow(deprecated)] // evaluate_action_with_context: migration tracked in FIND-CREATIVE-005
    async fn handle_extension_method(
        &self,
        proto_req: &JsonRpcRequest,
        json_req: &Value,
        request_context: GrpcRequestContext<'_>,
        _id: &Value,
        extension_id: &str,
        method: &str,
    ) -> JsonRpcResponse {
        let session_id = request_context.session_id;
        let request_signature_header = request_context.request_signature_header;
        let presented_approval_id = crate::proxy::helpers::extract_approval_id_from_meta(json_req);

        // SECURITY (FIND-R222-001): Injection scanning on extension method parameters.
        // Parity with PassThrough handler and handle_task_request.
        let params = json_req.get("params").cloned().unwrap_or(json!({}));

        if !self.state.injection_disabled {
            let scannable = extract_passthrough_text_for_injection(json_req);
            if !scannable.is_empty() {
                let injection_matches: Vec<String> =
                    if let Some(ref scanner) = self.state.injection_scanner {
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
                        "SECURITY: Injection in gRPC extension params! \
                         Session: {}, Extension: {}:{}, Patterns: {:?}",
                        session_id,
                        extension_id,
                        method,
                        injection_matches,
                    );

                    let verdict = if self.state.injection_blocking {
                        Verdict::Deny {
                            reason: format!("Extension injection blocked: {:?}", injection_matches),
                        }
                    } else {
                        Verdict::Allow
                    };

                    let inj_action =
                        extractor::extract_extension_action(extension_id, method, &params);
                    let injection_security_context = parameter_injection_security_context(
                        &params,
                        self.state.injection_blocking,
                        "extension_injection",
                    );
                    let envelope = build_secondary_acis_envelope_with_security_context(
                        &inj_action,
                        &verdict,
                        DecisionOrigin::InjectionScanner,
                        "grpc",
                        Some(session_id),
                        Some(&injection_security_context),
                    );
                    if let Err(e) = self
                        .state
                        .audit
                        .log_entry_with_acis(
                            &inj_action,
                            &verdict,
                            json!({
                                "source": "grpc_proxy",
                                "event": "extension_injection_detected",
                                "blocking": self.state.injection_blocking,
                                "session": session_id,
                                "transport": "grpc",
                                "extension_id": extension_id,
                                "method": method,
                            }),
                            envelope,
                        )
                        .await
                    {
                        tracing::warn!("Failed to audit gRPC extension injection: {}", e);
                        if let Some(deny) = self.audit_strict_deny(proto_req, "extension injection")
                        {
                            return deny;
                        }
                    }

                    if self.state.injection_blocking {
                        return make_proto_denial_response(
                            proto_req,
                            "Request blocked: injection detected",
                        );
                    }
                }
            }
        }

        // SECURITY (FIND-R114-003): DLP scan extension method parameters.
        // Parity with handle_tool_call (line 401) and handle_task_request (line 1244).
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
                "SECURITY: Secrets in gRPC extension method parameters! Session: {}, Extension: {}:{}, Findings: {:?}",
                session_id, extension_id, method, patterns,
            );
            let action = extractor::extract_extension_action(extension_id, method, &params);
            let audit_verdict = Verdict::Deny {
                reason: format!(
                    "DLP blocked: secret detected in extension parameters: {:?}",
                    patterns
                ),
            };
            let parameter_security_context =
                parameter_dlp_security_context(&params, true, "extension_parameter_dlp");
            let envelope = build_secondary_acis_envelope_with_security_context(
                &action,
                &audit_verdict,
                DecisionOrigin::Dlp,
                "grpc",
                Some(session_id),
                Some(&parameter_security_context),
            );
            if let Err(e) = self
                .state
                .audit
                .log_entry_with_acis(
                    &action,
                    &audit_verdict,
                    json!({
                        "source": "grpc_proxy", "session": session_id, "transport": "grpc",
                        "event": "grpc_extension_parameter_dlp_alert",
                        "extension_id": extension_id, "method": method, "findings": patterns,
                    }),
                    envelope,
                )
                .await
            {
                tracing::warn!("Failed to audit gRPC extension parameter DLP: {}", e);
            }
            return make_proto_denial_response(
                proto_req,
                "Response blocked: sensitive content detected",
            );
        }

        // SECURITY (FIND-R114-003): Memory poisoning detection for extension method params.
        // Parity with handle_task_request (line 1300).
        if let Some(session) = self.state.sessions.get_mut(session_id) {
            let poisoning_matches = session.memory_tracker.check_parameters(&params);
            if !poisoning_matches.is_empty() {
                for m in &poisoning_matches {
                    tracing::warn!(
                        "SECURITY: Memory poisoning detected in gRPC extension '{}:{}' (session {}): \
                         param '{}' contains replayed data (fingerprint: {})",
                        extension_id, method, session_id, m.param_location, m.fingerprint
                    );
                }
                let action = extractor::extract_extension_action(extension_id, method, &params);
                let deny_reason =
                    format!(
                    "Memory poisoning detected: {} replayed data fragment(s) in extension '{}:{}'",
                    poisoning_matches.len(), extension_id, method
                );
                let mp_verdict = Verdict::Deny {
                    reason: deny_reason.clone(),
                };
                let poisoning_security_context =
                    memory_poisoning_security_context(&params, "memory_poisoning");
                let envelope = build_secondary_acis_envelope_with_security_context(
                    &action,
                    &mp_verdict,
                    DecisionOrigin::MemoryPoisoning,
                    "grpc",
                    Some(session_id),
                    Some(&poisoning_security_context),
                );
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry_with_acis(
                        &action,
                        &mp_verdict,
                        json!({
                            "source": "grpc_proxy", "session": session_id, "transport": "grpc",
                            "event": "memory_poisoning_detected",
                            "matches": poisoning_matches.len(),
                            "extension_id": extension_id, "method": method,
                        }),
                        envelope,
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC extension memory poisoning: {}", e);
                }
                // SECURITY (FIND-R118-001): Generic client message.
                return make_proto_denial_response(proto_req, "Denied by policy");
            }
        }

        let mut action = extractor::extract_extension_action(extension_id, method, &params);
        let mut matched_approval_id: Option<String> = None;

        // SECURITY (FIND-R118-004): DNS resolution for extension methods.
        // Parity with handle_tool_call (line 637) and handle_resource_read (line 1047).
        if self.state.engine.has_ip_rules() {
            super::super::helpers::resolve_domains(&mut action).await;
        }

        // SECURITY (FIND-R160-001): TOCTOU-safe context+eval+update for extension methods.
        let ext_key = format!("extension:{}:{}", extension_id, method);
        let (verdict, ctx, session_risk) = if let Some(mut session) =
            self.state.sessions.get_mut(session_id)
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
            let risk = session.risk_score.clone();

            let verdict = match self.state.engine.evaluate_action_with_context(
                &action,
                &self.state.policies,
                Some(&ctx),
            ) {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(session_id = %session_id, "Extension policy evaluation error: {}", e);
                    Verdict::Deny {
                        reason: format!("Policy evaluation failed: {}", e),
                    }
                }
            };

            if matches!(verdict, Verdict::Allow) {
                session.touch();
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

            (verdict, ctx, risk)
        } else {
            let verdict = match self.state.engine.evaluate_action_with_context(
                &action,
                &self.state.policies,
                None,
            ) {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(session_id = %session_id, "Extension policy evaluation error: {}", e);
                    Verdict::Deny {
                        reason: format!("Policy evaluation failed: {}", e),
                    }
                }
            };
            (verdict, EvaluationContext::default(), None)
        };

        let verdict = match verdict {
            Verdict::RequireApproval { reason } => {
                match crate::proxy::helpers::presented_approval_matches_action(
                    &self.state,
                    session_id,
                    presented_approval_id.as_deref(),
                    &action,
                )
                .await
                {
                    Ok(Some(approval_id)) => {
                        matched_approval_id = Some(approval_id);
                        Verdict::Allow
                    }
                    Ok(None) => Verdict::RequireApproval { reason },
                    Err(()) => Verdict::Deny {
                        reason: INVALID_PRESENTED_APPROVAL_REASON.to_string(),
                    },
                }
            }
            other => other,
        };

        let security_context = build_grpc_runtime_security_context(
            json_req,
            &action,
            request_signature_header,
            crate::proxy::helpers::TransportSecurityInputs {
                oauth_evidence: None,
                eval_ctx: Some(&ctx),
                sessions: &self.state.sessions,
                session_id: Some(session_id),
                trusted_request_signers: &self.state.trusted_request_signers,
                detached_signature_freshness: self.state.detached_signature_freshness,
            },
        );

        match &verdict {
            Verdict::Allow => {
                // SECURITY (FIND-R118-002): ABAC refinement for extension methods.
                if let Some(ref abac) = self.state.abac_engine {
                    let principal_id = ctx.agent_id.as_deref().unwrap_or("anonymous");
                    let principal_type = ctx.principal_type();
                    // NOTE: session_risk extracted in TOCTOU-safe block above (FIND-R160-001).
                    let abac_ctx = vellaveto_engine::abac::AbacEvalContext {
                        eval_ctx: &ctx,
                        principal_type,
                        principal_id,
                        risk_score: session_risk.as_ref(),
                    };
                    match abac.evaluate(&action, &abac_ctx) {
                        vellaveto_engine::abac::AbacDecision::Deny { policy_id, reason } => {
                            let deny_verdict = Verdict::Deny {
                                reason: reason.clone(),
                            };
                            let abac_security_context = abac_deny_security_context(&action);
                            let envelope = build_secondary_acis_envelope_with_security_context(
                                &action,
                                &deny_verdict,
                                DecisionOrigin::PolicyEngine,
                                "grpc",
                                Some(session_id),
                                Some(&abac_security_context),
                            );
                            if let Err(e) = self
                                .state
                                .audit
                                .log_entry_with_acis(
                                    &action,
                                    &deny_verdict,
                                    json!({
                                        "source": "grpc_proxy",
                                        "session": session_id,
                                        "transport": "grpc",
                                        "event": "abac_deny",
                                        "extension_id": extension_id,
                                        "abac_policy": policy_id,
                                    }),
                                    envelope,
                                )
                                .await
                            {
                                tracing::warn!("Failed to audit gRPC extension ABAC deny: {}", e);
                            }
                            return make_proto_denial_response(proto_req, "Denied by policy");
                        }
                        vellaveto_engine::abac::AbacDecision::Allow { policy_id } => {
                            if let Some(ref la) = self.state.least_agency {
                                la.record_usage(
                                    principal_id,
                                    session_id,
                                    &policy_id,
                                    &ext_key,
                                    method,
                                );
                            }
                        }
                        vellaveto_engine::abac::AbacDecision::NoMatch => {
                            // Fall through — existing Allow stands
                        }
                        #[allow(unreachable_patterns)] // AbacDecision is #[non_exhaustive]
                        _ => {
                            // SECURITY: Future variants — fail-closed (deny).
                            tracing::warn!("Unknown AbacDecision variant — fail-closed");
                            return make_proto_denial_response(proto_req, "Denied by policy");
                        }
                    }
                }

                // NOTE: Session touch + call_counts/action_history update already
                // performed inside the TOCTOU-safe block above (FIND-R160-001).

                if crate::proxy::helpers::consume_presented_approval(
                    &self.state,
                    session_id,
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
                        invalid_presented_approval_security_context(&action);
                    let combined_security_context = merge_grpc_security_context(
                        security_context.as_ref(),
                        Some(&invalid_approval_security_context),
                    );
                    let effective_security_context = combined_security_context
                        .as_ref()
                        .unwrap_or(&invalid_approval_security_context);
                    let envelope = build_secondary_acis_envelope_with_security_context(
                        &action,
                        &deny_verdict,
                        DecisionOrigin::ApprovalGate,
                        "grpc",
                        Some(session_id),
                        Some(effective_security_context),
                    );
                    // SECURITY (R274-AUDIT-1): the result was bound to `_`, so a failed
                    // audit write here was invisible. The denial below is unchanged —
                    // this only makes the lost record observable.
                    if let Err(e) = self
                        .state
                        .audit
                        .log_entry_with_acis(
                            &action,
                            &deny_verdict,
                            json!({
                                "source": "grpc_proxy",
                                "session": session_id,
                                "transport": "grpc",
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
                    return make_proto_denial_response(proto_req, "Denied by policy");
                }

                let acis_envelope = build_acis_envelope_with_security_context(
                    &uuid::Uuid::new_v4().to_string().replace('-', ""),
                    &action,
                    &Verdict::Allow,
                    DecisionOrigin::PolicyEngine,
                    "grpc",
                    &[],
                    None,
                    Some(session_id),
                    None,
                    Some(&ctx),
                    security_context.as_ref(),
                );
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry_with_acis(
                        &action,
                        &Verdict::Allow,
                        json!({
                            "source": "grpc_proxy",
                            "session": session_id,
                            "transport": "grpc",
                            "extension_id": extension_id,
                        }),
                        acis_envelope,
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC extension allow: {}", e);
                    if let Some(deny) = self.audit_strict_deny(proto_req, "extension allow") {
                        return deny;
                    }
                }
                self.forward_and_scan(proto_req, json_req, session_id).await
            }
            Verdict::Deny { reason } => {
                let acis_envelope = build_acis_envelope_with_security_context(
                    &uuid::Uuid::new_v4().to_string().replace('-', ""),
                    &action,
                    &verdict,
                    DecisionOrigin::PolicyEngine,
                    "grpc",
                    &[],
                    None,
                    Some(session_id),
                    None,
                    Some(&ctx),
                    security_context.as_ref(),
                );
                let mut audit_metadata = json!({
                    "source": "grpc_proxy",
                    "session": session_id,
                    "transport": "grpc",
                    "extension_id": extension_id,
                });
                if reason == INVALID_PRESENTED_APPROVAL_REASON && presented_approval_id.is_some() {
                    audit_metadata["event"] = json!("presented_approval_replay_denied");
                    audit_metadata["approval_id"] = json!(presented_approval_id);
                    audit_metadata["method"] = json!(method);
                }
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry_with_acis(&action, &verdict, audit_metadata, acis_envelope)
                    .await
                {
                    tracing::warn!("Failed to audit gRPC extension deny: {}", e);
                    // SECURITY (FIND-R213-003): Strict audit mode — fail-closed on verdict audit failure.
                    if let Some(deny) = self.audit_strict_deny(proto_req, "extension deny") {
                        return deny;
                    }
                }
                // SECURITY (FIND-R113-003): Generic deny message; detailed reason in audit log
                let _ = reason;
                make_proto_denial_response(proto_req, "Denied by policy")
            }
            Verdict::RequireApproval { reason, .. } => {
                let approval_security_context = require_approval_security_context(&action);
                let verdict = Verdict::RequireApproval {
                    reason: reason.clone(),
                };
                let combined_security_context = merge_grpc_security_context(
                    security_context.as_ref(),
                    Some(&approval_security_context),
                );
                let acis_envelope = build_acis_envelope_with_security_context(
                    &uuid::Uuid::new_v4().to_string().replace('-', ""),
                    &action,
                    &verdict,
                    DecisionOrigin::ApprovalGate,
                    "grpc",
                    &[],
                    None,
                    Some(session_id),
                    None,
                    Some(&ctx),
                    combined_security_context.as_ref(),
                );
                if let Err(e) = self
                    .state
                    .audit
                    .log_entry_with_acis(
                        &action,
                        &verdict,
                        json!({
                            "source": "grpc_proxy",
                            "session": session_id,
                            "transport": "grpc",
                            "extension_id": extension_id,
                        }),
                        acis_envelope,
                    )
                    .await
                {
                    tracing::warn!("Failed to audit gRPC extension approval request: {}", e);
                    if let Some(deny) =
                        self.audit_strict_deny(proto_req, "extension require_approval")
                    {
                        return deny;
                    }
                }
                let containment_context = approval_containment_context_from_security_context(
                    combined_security_context
                        .as_ref()
                        .unwrap_or(&approval_security_context),
                    reason,
                );
                let approval_id = create_pending_approval_with_context(
                    &self.state,
                    session_id,
                    &action,
                    reason,
                    containment_context,
                )
                .await;
                self.approval_required_response(proto_req, approval_id)
            }
            // SECURITY (FIND-R113-003): Generic deny message; detailed reason in audit log
            _ => make_proto_denial_response(proto_req, "Denied by policy"),
        }
    }

    /// Build an EvaluationContext for policy evaluation.
    ///
    /// SECURITY (FIND-R54-002): Now includes `agent_identity` and `call_chain`
    /// from the session, matching the HTTP handler's `build_evaluation_context`
    /// (call_chain.rs:82). Without these, context-aware policies that check
    /// agent identity or call chain depth are ineffective on gRPC.
    fn build_evaluation_context(&self, session_id: &str) -> EvaluationContext {
        let mut ctx = EvaluationContext::default();

        if let Some(session) = self.state.sessions.get_mut(session_id) {
            ctx.call_counts = session.call_counts.clone();
            ctx.previous_actions = session.action_history.iter().cloned().collect();
            if let Some(ref agent_id) = session.oauth_subject {
                ctx.agent_id = Some(agent_id.clone());
            }
            ctx.agent_identity = session.agent_identity.clone();
            ctx.call_chain = session.current_call_chain.clone();
        }

        ctx
    }
}

/// SECURITY (FIND-R54-004, IMP-R166-001): Delegates to canonical
/// `vellaveto_types::json_has_dangerous_chars` for control/format char detection.
fn json_contains_dangerous_chars(val: &Value, depth: usize) -> bool {
    vellaveto_types::json_has_dangerous_chars(val, depth)
}

/// Extract scannable text from a JSON-RPC response for injection scanning.
///
/// SECURITY (IMP-R166-002): Delegates to shared `extract_text_from_result()` for
/// full scan coverage (content[].text, resource.text, resource.blob, annotations,
/// instructionsForUser, structuredContent, _meta). Parity with WebSocket transport.
fn extract_scannable_text(json_val: &Value) -> String {
    let mut text_parts = Vec::new();

    // Scan result via shared extraction — covers all 7 response fields.
    if let Some(result) = json_val.get("result") {
        let result_text = super::super::inspection::extract_text_from_result(result);
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
        // string values in JSON quotes. Parity with scanner_base.rs line 330.
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

/// Extract scannable text from a PassThrough JSON-RPC message for injection scanning.
///
/// SECURITY (FIND-R113-001): Recursively extracts string values from `params` and
/// `result` fields. Bounded to prevent memory amplification from deeply nested or
/// highly branched JSON structures. Parity with HTTP handler's
/// `extract_passthrough_text_for_injection` (handlers.rs).
fn extract_passthrough_text_for_injection(msg: &Value) -> String {
    // SECURITY (FIND-R155-002): Raised from 10 to 32 for parity with WS handler
    // (FIND-R154-005) and shared MAX_SCAN_DEPTH in scanner_base.rs. Previous limit
    // allowed injection payloads nested at depth 11-32 to evade gRPC scanning.
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

#[tonic::async_trait]
impl McpService for McpGrpcService {
    /// Unary call: one JSON-RPC request → one JSON-RPC response.
    async fn call(
        &self,
        request: Request<JsonRpcRequest>,
    ) -> Result<Response<JsonRpcResponse>, Status> {
        record_grpc_request();
        record_grpc_message("unary_request");

        let metadata = request.metadata().clone();
        let session_id = extract_session_id(&metadata)
            .unwrap_or_else(|| self.state.sessions.get_or_create(None));
        let _request_id = extract_or_generate_request_id(&metadata);

        // SECURITY (FIND-R54-GRPC-003): Per-request OAuth token expiry check.
        // Matches WS handler's per-message token expiry check (websocket/mod.rs:443).
        {
            let token_expired = self
                .state
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
                    "SECURITY: OAuth token expired during gRPC session"
                );
                return Err(Status::unauthenticated("Token expired"));
            }
        }

        // SECURITY (FIND-R110-HTTP-001): Session ownership check + bind for gRPC unary calls.
        // Parity with HTTP handler (handlers.rs:247, R15-OAUTH-2) and WS handler.
        // Without this, an attacker with a stolen session ID can send gRPC calls on
        // another user's session by supplying their session ID in metadata. When OAuth
        // is active, the session must be owned by the authenticated subject.
        if let Some(authorization) = metadata.get("authorization") {
            if let Some(ref oauth_validator) = self.state.oauth {
                let auth_header = authorization.to_str().unwrap_or("").to_string();
                match oauth_validator.validate_token(&auth_header).await {
                    Ok(claims) => {
                        if let Some(mut session) = self.state.sessions.get_mut(&session_id) {
                            match &session.oauth_subject {
                                Some(owner) if owner != &claims.sub => {
                                    tracing::warn!(
                                        "SECURITY: gRPC session fixation attempt blocked \
                                         — session {} owned by '{}', request from '{}'",
                                        session_id,
                                        owner,
                                        claims.sub
                                    );
                                    return Err(Status::permission_denied(
                                        "Session owned by another user",
                                    ));
                                }
                                None => {
                                    session.oauth_subject = Some(claims.sub.clone());
                                    if claims.exp > 0 {
                                        session.token_expires_at = Some(claims.exp);
                                    }
                                }
                                _ => {
                                    // SECURITY (R23-PROXY-6): Use the EARLIEST token expiry.
                                    if claims.exp > 0 {
                                        session.token_expires_at = Some(
                                            session
                                                .token_expires_at
                                                .map_or(claims.exp, |existing| {
                                                    existing.min(claims.exp)
                                                }),
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "gRPC unary OAuth validation failed for session ownership check: {}",
                            e
                        );
                        return Err(Status::unauthenticated("Invalid authorization token"));
                    }
                }
            }
        }

        // SECURITY (FIND-R54-GRPC-005): Sync validated transport identity and
        // explicit workload claims into the session. Parity with HTTP/WS.
        sync_transport_agent_identity(&self.state, &metadata, &session_id).await?;

        // SECURITY (FIND-R54-002): Sync call chain from metadata to session.
        // Parity with HTTP handler's sync_session_call_chain_from_headers.
        {
            let upstream_chain = super::interceptors::extract_call_chain_from_metadata(
                &metadata,
                &self.state.limits,
            );
            if let Some(mut session) = self.state.sessions.get_mut(&session_id) {
                session.current_call_chain = upstream_chain;
            }
        }

        let request_signature = extract_request_signature(&metadata);
        let proto_req = request.into_inner();
        let response = self
            .evaluate_request(&proto_req, &session_id, request_signature.as_deref())
            .await;

        record_grpc_message("unary_response");
        Ok(Response::new(response))
    }

    type StreamCallStream = ReceiverStream<Result<JsonRpcResponse, Status>>;

    /// Bidirectional streaming: per-message policy evaluation.
    async fn stream_call(
        &self,
        request: Request<Streaming<JsonRpcRequest>>,
    ) -> Result<Response<Self::StreamCallStream>, Status> {
        let metadata = request.metadata().clone();
        let session_id = extract_session_id(&metadata)
            .unwrap_or_else(|| self.state.sessions.get_or_create(None));

        // SECURITY (FIND-R110-HTTP-001): Session ownership check + bind for gRPC streaming.
        // Parity with HTTP handler (handlers.rs:247, R15-OAUTH-2) and the unary call handler.
        // Without this, an attacker can hijack another user's gRPC stream by supplying their
        // session ID in the initial metadata.
        if let Some(authorization) = metadata.get("authorization") {
            if let Some(ref oauth_validator) = self.state.oauth {
                let auth_header = authorization.to_str().unwrap_or("").to_string();
                match oauth_validator.validate_token(&auth_header).await {
                    Ok(claims) => {
                        if let Some(mut session) = self.state.sessions.get_mut(&session_id) {
                            match &session.oauth_subject {
                                Some(owner) if owner != &claims.sub => {
                                    tracing::warn!(
                                        "SECURITY: gRPC stream session fixation attempt blocked \
                                         — session {} owned by '{}', request from '{}'",
                                        session_id,
                                        owner,
                                        claims.sub
                                    );
                                    return Err(Status::permission_denied(
                                        "Session owned by another user",
                                    ));
                                }
                                None => {
                                    session.oauth_subject = Some(claims.sub.clone());
                                    if claims.exp > 0 {
                                        session.token_expires_at = Some(claims.exp);
                                    }
                                }
                                _ => {
                                    // SECURITY (R23-PROXY-6): Use the EARLIEST token expiry.
                                    if claims.exp > 0 {
                                        session.token_expires_at = Some(
                                            session
                                                .token_expires_at
                                                .map_or(claims.exp, |existing| {
                                                    existing.min(claims.exp)
                                                }),
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "gRPC stream OAuth validation failed for session ownership check: {}",
                            e
                        );
                        return Err(Status::unauthenticated("Invalid authorization token"));
                    }
                }
            }
        }

        // SECURITY (FIND-R54-GRPC-005): Sync validated transport identity and
        // explicit workload claims into the session at stream start.
        sync_transport_agent_identity(&self.state, &metadata, &session_id).await?;

        // SECURITY (FIND-R54-002): Sync call chain from metadata at stream start.
        {
            let upstream_chain = super::interceptors::extract_call_chain_from_metadata(
                &metadata,
                &self.state.limits,
            );
            if let Some(mut session) = self.state.sessions.get_mut(&session_id) {
                session.current_call_chain = upstream_chain;
            }
        }

        let request_signature = extract_request_signature(&metadata);
        let mut stream = request.into_inner();
        let (tx, rx) = mpsc::channel(32);

        let state = self.state.clone();
        let stream_rate_limit = self.stream_message_rate_limit;

        tokio::spawn(async move {
            // SECURITY (FIND-R208-008): Use constructor instead of manual struct
            // construction to ensure any future initialization logic is not bypassed.
            let svc = McpGrpcService::new(state, stream_rate_limit);

            // SECURITY (FIND-R55-GRPC-010): Per-message rate limiting for streaming RPCs.
            // Uses a counter-per-second window matching the WS handler's check_rate_limit
            // (websocket/mod.rs:2507). SeqCst ordering for security-critical counter.
            let rate_counter = AtomicU64::new(0);
            let rate_window_start = std::sync::Mutex::new(std::time::Instant::now());

            while let Ok(Some(proto_req)) = stream.message().await {
                record_grpc_message("stream_request");

                // SECURITY (FIND-R155-GRPC-001): Fail-closed — zero rate limit blocks
                // all messages. Parity with WS check_rate_limit (websocket/mod.rs:4209).
                if stream_rate_limit == 0 {
                    tracing::warn!(
                        session_id = %session_id,
                        "SECURITY: gRPC stream rate limit is 0 — blocking all messages (fail-closed)"
                    );
                    let _ = tx
                        .send(Err(Status::resource_exhausted(
                            "Stream rate limit is zero — all messages blocked",
                        )))
                        .await;
                    break;
                }

                // SECURITY (FIND-R55-GRPC-010): Check per-message rate limit.
                if stream_rate_limit > 0 {
                    let now = std::time::Instant::now();
                    // Compute rate limit inside a sync block to avoid holding
                    // MutexGuard across .await (MutexGuard is !Send).
                    let within_limit = match rate_window_start.lock() {
                        Err(_e) => {
                            // Mutex poisoned — fail-closed. The error is handled
                            // after releasing the lock scope (no .await while held).
                            None
                        }
                        Ok(mut start) => {
                            if now.duration_since(*start) >= std::time::Duration::from_secs(1) {
                                *start = now;
                                rate_counter.store(1, Ordering::SeqCst);
                                Some(true)
                            } else {
                                // SECURITY (FIND-R155-GRPC-002): Use fetch_update + saturating_add
                                // to prevent overflow wrap-to-zero resetting rate limit counter.
                                // Parity with WS check_rate_limit (websocket/mod.rs:4236-4238).
                                let prev = rate_counter.fetch_update(
                                    Ordering::SeqCst,
                                    Ordering::SeqCst,
                                    |v| Some(v.saturating_add(1)),
                                );
                                let count = match prev {
                                    Ok(previous) => previous.saturating_add(1),
                                    Err(_) => unreachable!("infallible closure"),
                                };
                                Some(count <= stream_rate_limit as u64)
                            }
                        }
                    };
                    // Handle poisoned mutex outside the lock scope (safe to .await).
                    if within_limit.is_none() {
                        tracing::error!("gRPC stream rate limiter mutex poisoned — fail-closed");
                        let _ = tx
                            .send(Err(Status::resource_exhausted("Rate limiter unavailable")))
                            .await;
                        break;
                    }
                    let within_limit = within_limit.unwrap_or(false);
                    if !within_limit {
                        tracing::warn!(
                            session_id = %session_id,
                            limit = stream_rate_limit,
                            "SECURITY: gRPC stream rate limit exceeded, closing stream"
                        );
                        let _ = tx
                            .send(Err(Status::resource_exhausted(
                                "Stream rate limit exceeded",
                            )))
                            .await;
                        break;
                    }
                }

                // SECURITY (FIND-R54-GRPC-003): Per-message OAuth token expiry check.
                {
                    let token_expired = svc
                        .state
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
                            "SECURITY: OAuth token expired during gRPC stream"
                        );
                        let _ = tx.send(Err(Status::unauthenticated("Token expired"))).await;
                        break;
                    }
                }

                let response = svc
                    .evaluate_request(&proto_req, &session_id, request_signature.as_deref())
                    .await;
                record_grpc_message("stream_response");

                if tx.send(Ok(response)).await.is_err() {
                    break;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    type SubscribeStream = ReceiverStream<Result<JsonRpcNotification, Status>>;

    /// Server-streaming: subscribe to notifications from upstream.
    async fn subscribe(
        &self,
        request: Request<SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let metadata = request.metadata().clone();
        let session_id = extract_session_id(&metadata)
            .unwrap_or_else(|| self.state.sessions.get_or_create(None));
        let subscribe_req = request.into_inner();

        // SECURITY (FIND-R208-001): Token expiry check — parity with call()/stream_call().
        {
            let token_expired = self
                .state
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
                    "SECURITY: OAuth token expired during gRPC subscribe"
                );
                return Err(Status::unauthenticated("Token expired"));
            }
        }

        // SECURITY (FIND-R208-001): Session ownership check — parity with call().
        if let Some(authorization) = metadata.get("authorization") {
            if let Some(ref oauth_validator) = self.state.oauth {
                let auth_header = authorization.to_str().unwrap_or("").to_string();
                match oauth_validator.validate_token(&auth_header).await {
                    Ok(claims) => {
                        if let Some(mut session) = self.state.sessions.get_mut(&session_id) {
                            match &session.oauth_subject {
                                Some(owner) if owner != &claims.sub => {
                                    tracing::warn!(
                                        "SECURITY: gRPC subscribe session fixation blocked \
                                         — session {} owned by '{}', request from '{}'",
                                        session_id,
                                        owner,
                                        claims.sub
                                    );
                                    return Err(Status::permission_denied(
                                        "Session owned by another user",
                                    ));
                                }
                                None => {
                                    session.oauth_subject = Some(claims.sub.clone());
                                    if claims.exp > 0 {
                                        session.token_expires_at = Some(claims.exp);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("gRPC subscribe OAuth validation failed: {}", e);
                        return Err(Status::unauthenticated("Invalid authorization token"));
                    }
                }
            }
        }

        // SECURITY (FIND-R224-003): Sync validated transport identity and
        // explicit workload claims so subscribe gets the same agent context.
        sync_transport_agent_identity(&self.state, &metadata, &session_id).await?;

        // SECURITY (FIND-R224-008): Extract call chain from metadata — parity
        // with call() and stream_call(). Without this, policies that reference
        // call chain depth/entries are not evaluated for subscribe requests.
        {
            let upstream_chain = super::interceptors::extract_call_chain_from_metadata(
                &metadata,
                &self.state.limits,
            );
            if let Some(mut session) = self.state.sessions.get_mut(&session_id) {
                session.current_call_chain = upstream_chain;
            }
        }

        // SECURITY (FIND-R208-003): Validate subscribe methods for control/format characters
        // before logging to prevent log injection.
        for method in &subscribe_req.methods {
            if contains_dangerous_chars(method) {
                return Err(Status::invalid_argument(
                    "Subscribe method contains invalid characters",
                ));
            }
        }

        let (tx, rx) = mpsc::channel(32);

        let _state = self.state.clone();

        // Upstream notification forwarding is not supported — subscribe returns an
        // open stream that completes when the client disconnects. Notifications are
        // delivered via the HTTP SSE transport instead.
        tokio::spawn(async move {
            tracing::info!(
                session_id = %session_id,
                methods = ?subscribe_req.methods,
                "gRPC notification subscription opened"
            );

            // Keep the stream open until the client disconnects.
            // Notifications are delivered via the HTTP SSE transport.
            let _ = tx.closed().await;

            tracing::info!(
                session_id = %session_id,
                "gRPC notification subscription closed"
            );
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}
