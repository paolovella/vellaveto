// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Utility functions for the HTTP proxy: DNS resolution, bounded reads,
//! annotation extraction, and manifest verification.

use axum::http::HeaderMap;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bytes::Bytes;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use vellaveto_approval::{
    review_safe_provenance_summary, ApprovalContainmentContext, ApprovalStatus,
};
use vellaveto_audit::AuditLogger;
use vellaveto_canonical::{
    canonical_request_hash, canonical_request_preimage, CanonicalRequestInput,
};
use vellaveto_config::{ManifestConfig, ToolManifest};
use vellaveto_engine::acis::fingerprint_action;
use vellaveto_mcp::mediation::build_secondary_acis_envelope_with_security_context;
use vellaveto_mcp::output_contracts::infer_observed_output_channel;
use vellaveto_types::acis::{AcisDecisionEnvelope, DecisionOrigin};
use vellaveto_types::{
    Action, AgentIdentity, ClientProvenance, ContextChannel, EvaluationContext, LineageRef,
    ReplayStatus, RequestSignature, RuntimeSecurityContext, SemanticRiskScore, SemanticTaint,
    SessionKeyScope, SignatureVerificationStatus, SinkClass, TrustTier, Verdict,
    WorkloadBindingStatus, WorkloadIdentity,
};

use super::auth::OAuthValidationEvidence;
use super::ProxyState;
use crate::proxy::X_REQUEST_SIGNATURE;
use crate::session::{SessionStore, ToolParamHeaderBindings};

const MAX_REQUEST_SIGNATURE_HEADER_BYTES: usize = 8192;

pub(super) type TrustedRequestSignerMap =
    std::collections::HashMap<String, super::TrustedRequestSigner>;

#[derive(Clone, Copy)]
pub(super) struct TransportSecurityInputs<'a> {
    pub oauth_evidence: Option<&'a OAuthValidationEvidence>,
    pub eval_ctx: Option<&'a EvaluationContext>,
    pub sessions: &'a SessionStore,
    pub session_id: Option<&'a str>,
    pub trusted_request_signers: &'a TrustedRequestSignerMap,
    pub detached_signature_freshness: super::DetachedSignatureFreshnessConfig,
}

/// Resolve target domains to IP addresses for DNS rebinding protection.
///
/// Populates `action.resolved_ips` with the IP addresses that each target domain
/// resolves to. If DNS resolution fails for a domain, no IPs are added for it —
/// the engine will deny the action fail-closed if IP rules are configured.
pub(super) async fn resolve_domains(action: &mut Action) {
    /// SECURITY (IMP-R160-003): Cap resolved IPs to prevent OOM from domains with
    /// many A/AAAA records. Parity with stdio relay (FIND-R80-004).
    const MAX_RESOLVED_IPS: usize = 100;

    if action.target_domains.is_empty() {
        return;
    }
    let mut resolved = Vec::new();
    for domain in &action.target_domains {
        if resolved.len() >= MAX_RESOLVED_IPS {
            tracing::warn!(
                domain = %domain,
                "Resolved IPs cap ({}) reached — skipping remaining domains",
                MAX_RESOLVED_IPS,
            );
            break;
        }
        // Strip port if present (domain might be "example.com:8080")
        let host = domain.split(':').next().unwrap_or(domain);
        match tokio::net::lookup_host((host, 0)).await {
            Ok(addrs) => {
                for addr in addrs {
                    if resolved.len() >= MAX_RESOLVED_IPS {
                        tracing::warn!(
                            domain = %domain,
                            "Resolved IPs cap ({}) reached during DNS iteration",
                            MAX_RESOLVED_IPS,
                        );
                        break;
                    }
                    resolved.push(addr.ip().to_string());
                }
            }
            Err(e) => {
                tracing::warn!(
                    domain = %domain,
                    error = %e,
                    "DNS resolution failed — resolved_ips will be empty for this domain"
                );
                // Fail-closed: engine will deny if ip_rules configured but no IPs resolved
            }
        }
    }
    action.resolved_ips = resolved;
}

fn rpc_meta(msg: &Value) -> Option<&Value> {
    msg.get("_meta")
        .or_else(|| msg.get("params").and_then(|params| params.get("_meta")))
}

fn extract_runtime_security_context(msg: &Value) -> Option<RuntimeSecurityContext> {
    let meta = rpc_meta(msg)?;
    let candidate = meta
        .get("vellaveto_security_context")
        .or_else(|| meta.get("vellavetoSecurityContext"))?
        .clone();
    match serde_json::from_value::<RuntimeSecurityContext>(candidate) {
        Ok(security_context) => match security_context.validate() {
            Ok(()) => Some(security_context),
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "Ignoring invalid vellaveto security context from HTTP request metadata"
                );
                None
            }
        },
        Err(error) => {
            tracing::warn!(
                error = %error,
                "Ignoring malformed vellaveto security context from HTTP request metadata"
            );
            None
        }
    }
}

fn infer_sink_class(action: &Action) -> SinkClass {
    let tool = action.tool.to_ascii_lowercase();
    let function = action.function.to_ascii_lowercase();

    if action.tool == "resources" && action.function == "read" {
        return SinkClass::ReadOnly;
    }
    if contains_security_keyword(&tool, &function, &["approval", "consent", "prompt"]) {
        return SinkClass::ApprovalUi;
    }
    if contains_security_keyword(
        &tool,
        &function,
        &[
            "secret",
            "credential",
            "token",
            "password",
            "apikey",
            "api_key",
            "auth",
        ],
    ) {
        return SinkClass::CredentialAccess;
    }
    if contains_security_keyword(
        &tool,
        &function,
        &["policy", "config", "rule", "governance"],
    ) {
        return SinkClass::PolicyMutation;
    }
    if contains_security_keyword(&tool, &function, &["memory", "memo", "cache", "store"]) {
        return SinkClass::MemoryWrite;
    }
    if contains_security_keyword(
        &tool,
        &function,
        &[
            "exec", "execute", "run", "shell", "bash", "python", "node", "script", "command",
            "spawn", "terminal",
        ],
    ) {
        return SinkClass::CodeExecution;
    }
    if !action.target_domains.is_empty() {
        return SinkClass::NetworkEgress;
    }
    if !action.target_paths.is_empty() {
        if looks_like_mutating_action(&tool, &function) {
            return SinkClass::FilesystemWrite;
        }
        return SinkClass::ReadOnly;
    }
    if looks_like_mutating_action(&tool, &function) {
        return SinkClass::LowRiskWrite;
    }
    if looks_like_read_only_action(&tool, &function) {
        return SinkClass::ReadOnly;
    }
    SinkClass::LowRiskWrite
}

fn contains_security_keyword(tool: &str, function: &str, keywords: &[&str]) -> bool {
    keywords
        .iter()
        .any(|keyword| tool.contains(keyword) || function.contains(keyword))
}

fn looks_like_mutating_action(tool: &str, function: &str) -> bool {
    contains_security_keyword(
        tool,
        function,
        &[
            "write", "edit", "update", "delete", "remove", "create", "append", "save", "set",
        ],
    )
}

fn looks_like_read_only_action(tool: &str, function: &str) -> bool {
    contains_security_keyword(
        tool,
        function,
        &[
            "read", "get", "list", "fetch", "view", "show", "search", "query",
        ],
    )
}

#[derive(Debug, Deserialize)]
struct DpopPayload {
    #[serde(default)]
    iat: u64,
    #[serde(default)]
    jti: String,
}

fn decode_dpop_request_signature(
    headers: &HeaderMap,
    client_key_id: Option<&str>,
) -> Option<RequestSignature> {
    client_key_id?;

    let proof_jwt = headers
        .get("dpop")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    let header = jsonwebtoken::decode_header(proof_jwt).ok()?;
    let payload_segment = proof_jwt.split('.').nth(1)?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_segment).ok()?;
    let payload = serde_json::from_slice::<DpopPayload>(&payload_bytes).ok()?;
    let created_at = i64::try_from(payload.iat)
        .ok()
        .and_then(|iat| chrono::DateTime::<chrono::Utc>::from_timestamp(iat, 0))
        .map(|timestamp| timestamp.to_rfc3339());

    Some(RequestSignature {
        key_id: client_key_id.map(str::to_string),
        algorithm: Some(format!("{:?}", header.alg)),
        nonce: (!payload.jti.trim().is_empty()).then_some(payload.jti),
        created_at,
        signature: None,
    })
}

fn oauth_client_key_id(oauth_evidence: Option<&OAuthValidationEvidence>) -> Option<String> {
    oauth_evidence
        .and_then(|evidence| evidence.claims.cnf.as_ref())
        .and_then(|cnf| cnf.jkt.clone())
}

#[derive(Debug, Clone, Default)]
struct DetachedRequestSignatureEvidence {
    request_signature: Option<RequestSignature>,
    signature_status: SignatureVerificationStatus,
}

fn decode_detached_request_signature_value(
    header_value: Option<&str>,
) -> DetachedRequestSignatureEvidence {
    let header_value = match header_value.map(str::trim) {
        Some(value) if !value.is_empty() => value,
        Some(_) => {
            return DetachedRequestSignatureEvidence {
                request_signature: None,
                signature_status: SignatureVerificationStatus::Invalid,
            };
        }
        None => return DetachedRequestSignatureEvidence::default(),
    };

    if header_value.len() > MAX_REQUEST_SIGNATURE_HEADER_BYTES {
        return DetachedRequestSignatureEvidence {
            request_signature: None,
            signature_status: SignatureVerificationStatus::Invalid,
        };
    }

    let payload = match URL_SAFE_NO_PAD.decode(header_value) {
        Ok(payload) => payload,
        Err(_) => {
            return DetachedRequestSignatureEvidence {
                request_signature: None,
                signature_status: SignatureVerificationStatus::Invalid,
            };
        }
    };
    let signature = match serde_json::from_slice::<RequestSignature>(&payload) {
        Ok(signature) => signature,
        Err(_) => {
            return DetachedRequestSignatureEvidence {
                request_signature: None,
                signature_status: SignatureVerificationStatus::Invalid,
            };
        }
    };
    if signature.validate().is_err() {
        return DetachedRequestSignatureEvidence {
            request_signature: None,
            signature_status: SignatureVerificationStatus::Invalid,
        };
    }

    DetachedRequestSignatureEvidence {
        request_signature: Some(signature),
        signature_status: SignatureVerificationStatus::Missing,
    }
}

fn decode_detached_request_signature(headers: &HeaderMap) -> DetachedRequestSignatureEvidence {
    let header_value = headers
        .get(X_REQUEST_SIGNATURE)
        .and_then(|value| value.to_str().ok());
    decode_detached_request_signature_value(header_value)
}

fn merge_signature_status(
    transport_status: SignatureVerificationStatus,
    detached_status: SignatureVerificationStatus,
) -> SignatureVerificationStatus {
    match transport_status {
        SignatureVerificationStatus::Verified => SignatureVerificationStatus::Verified,
        SignatureVerificationStatus::Invalid => SignatureVerificationStatus::Invalid,
        SignatureVerificationStatus::Expired => SignatureVerificationStatus::Expired,
        SignatureVerificationStatus::Error => SignatureVerificationStatus::Error,
        SignatureVerificationStatus::Missing => detached_status,
    }
}

fn infer_workload_platform(subject: &str) -> String {
    if subject.starts_with("spiffe://") {
        "spiffe".to_string()
    } else if subject.starts_with("did:") {
        "did".to_string()
    } else {
        "jwt".to_string()
    }
}

fn agent_identity_from_eval_ctx(eval_ctx: Option<&EvaluationContext>) -> Option<&AgentIdentity> {
    eval_ctx.and_then(|ctx| ctx.agent_identity.as_ref())
}

fn transport_workload_claim_str<'a>(
    eval_ctx: Option<&'a EvaluationContext>,
    oauth_evidence: Option<&'a OAuthValidationEvidence>,
    key: &str,
) -> Option<&'a str> {
    agent_identity_from_eval_ctx(eval_ctx)
        .and_then(|identity| identity.claim_str(key))
        .or_else(|| match key {
            "workload_id" => {
                oauth_evidence.and_then(|evidence| evidence.workload_claims.workload_id())
            }
            "spiffe_id" => oauth_evidence.and_then(|evidence| evidence.workload_claims.spiffe_id()),
            "namespace" => oauth_evidence.and_then(|evidence| evidence.workload_claims.namespace()),
            "service_account" => {
                oauth_evidence.and_then(|evidence| evidence.workload_claims.service_account())
            }
            "process_identity" => {
                oauth_evidence.and_then(|evidence| evidence.workload_claims.process_identity())
            }
            "attestation_level" => {
                oauth_evidence.and_then(|evidence| evidence.workload_claims.attestation_level())
            }
            "session_key_scope" => {
                oauth_evidence.and_then(|evidence| evidence.workload_claims.session_key_scope())
            }
            _ => None,
        })
}

fn transport_workload_claim_bool(
    eval_ctx: Option<&EvaluationContext>,
    oauth_evidence: Option<&OAuthValidationEvidence>,
    key: &str,
) -> Option<bool> {
    agent_identity_from_eval_ctx(eval_ctx)
        .and_then(|identity| identity.claims.get(key))
        .and_then(Value::as_bool)
        .or_else(|| match key {
            "execution_is_ephemeral" => oauth_evidence
                .and_then(|evidence| evidence.workload_claims.execution_is_ephemeral()),
            _ => None,
        })
}

fn workload_id_from_transport(
    eval_ctx: Option<&EvaluationContext>,
    oauth_evidence: Option<&OAuthValidationEvidence>,
) -> Option<String> {
    transport_workload_claim_str(eval_ctx, oauth_evidence, "workload_id")
        .map(str::to_string)
        .or_else(|| {
            transport_workload_claim_str(eval_ctx, oauth_evidence, "spiffe_id").map(str::to_string)
        })
        .or_else(|| {
            agent_identity_from_eval_ctx(eval_ctx)
                .and_then(|identity| identity.subject.as_deref())
                .map(str::trim)
                .filter(|subject| !subject.is_empty())
                .map(str::to_string)
        })
        .or_else(|| {
            oauth_evidence.and_then(|evidence| {
                let subject = evidence.claims.sub.trim();
                (!subject.is_empty()
                    && (subject.starts_with("spiffe://") || subject.starts_with("did:")))
                .then(|| subject.to_string())
            })
        })
}

fn build_workload_identity(
    eval_ctx: Option<&EvaluationContext>,
    oauth_evidence: Option<&OAuthValidationEvidence>,
) -> Option<WorkloadIdentity> {
    let workload_id = workload_id_from_transport(eval_ctx, oauth_evidence)?;

    Some(WorkloadIdentity {
        platform: Some(infer_workload_platform(&workload_id)),
        workload_id,
        namespace: transport_workload_claim_str(eval_ctx, oauth_evidence, "namespace")
            .map(str::to_string),
        service_account: transport_workload_claim_str(eval_ctx, oauth_evidence, "service_account")
            .map(str::to_string),
        process_identity: transport_workload_claim_str(
            eval_ctx,
            oauth_evidence,
            "process_identity",
        )
        .map(str::to_string),
        attestation_level: transport_workload_claim_str(
            eval_ctx,
            oauth_evidence,
            "attestation_level",
        )
        .map(str::to_string)
        .or_else(|| Some("jwt".to_string())),
    })
}

fn build_session_key_scope(
    eval_ctx: Option<&EvaluationContext>,
    oauth_evidence: Option<&OAuthValidationEvidence>,
) -> SessionKeyScope {
    match transport_workload_claim_str(eval_ctx, oauth_evidence, "session_key_scope") {
        Some("ephemeral_execution") => SessionKeyScope::EphemeralExecution,
        Some("ephemeral_session") => SessionKeyScope::EphemeralSession,
        Some("persisted_client") => SessionKeyScope::PersistedClient,
        Some("persisted_service") => SessionKeyScope::PersistedService,
        _ => SessionKeyScope::Unknown,
    }
}

fn execution_is_ephemeral(
    eval_ctx: Option<&EvaluationContext>,
    oauth_evidence: Option<&OAuthValidationEvidence>,
    session_key_scope: SessionKeyScope,
) -> bool {
    if matches!(
        session_key_scope,
        SessionKeyScope::EphemeralExecution | SessionKeyScope::EphemeralSession
    ) {
        return true;
    }

    transport_workload_claim_bool(eval_ctx, oauth_evidence, "execution_is_ephemeral")
        .unwrap_or(false)
}

fn build_workload_binding_status(
    eval_ctx: Option<&EvaluationContext>,
    workload_identity: Option<&WorkloadIdentity>,
    oauth_evidence: Option<&OAuthValidationEvidence>,
) -> WorkloadBindingStatus {
    if workload_identity.is_some() {
        WorkloadBindingStatus::Bound
    } else if agent_identity_from_eval_ctx(eval_ctx).is_some() {
        WorkloadBindingStatus::Unverified
    } else if oauth_evidence.is_some() {
        WorkloadBindingStatus::Missing
    } else {
        WorkloadBindingStatus::Unknown
    }
}

fn build_client_provenance_from_transport(
    oauth_evidence: Option<&OAuthValidationEvidence>,
    eval_ctx: Option<&EvaluationContext>,
    session_scope_binding: Option<&str>,
    dpop_request_signature: Option<RequestSignature>,
    detached_signature: DetachedRequestSignatureEvidence,
) -> Option<ClientProvenance> {
    let transport_signature_status = oauth_evidence.map_or_else(
        || SignatureVerificationStatus::Missing,
        OAuthValidationEvidence::signature_status,
    );
    let signature_status = merge_signature_status(
        transport_signature_status,
        detached_signature.signature_status,
    );
    if oauth_evidence.is_none()
        && detached_signature.request_signature.is_none()
        && signature_status == SignatureVerificationStatus::Missing
    {
        return None;
    }

    let client_key_id = oauth_client_key_id(oauth_evidence).or_else(|| {
        detached_signature
            .request_signature
            .as_ref()
            .and_then(|signature| signature.key_id.clone())
    });
    let request_signature = if oauth_evidence.is_some_and(|evidence| evidence.dpop_proof_verified) {
        merge_request_signature(
            dpop_request_signature.or_else(|| {
                Some(RequestSignature {
                    key_id: client_key_id.clone(),
                    algorithm: Some("dpop+jwt".to_string()),
                    nonce: None,
                    created_at: None,
                    signature: None,
                })
            }),
            detached_signature.request_signature,
        )
    } else {
        detached_signature.request_signature
    };
    let workload_identity = build_workload_identity(eval_ctx, oauth_evidence);
    let workload_binding_status =
        build_workload_binding_status(eval_ctx, workload_identity.as_ref(), oauth_evidence);
    let session_key_scope = build_session_key_scope(eval_ctx, oauth_evidence);

    Some(ClientProvenance {
        request_signature,
        signature_status,
        client_key_id,
        session_key_scope,
        workload_identity,
        workload_binding_status,
        replay_status: oauth_evidence.map_or_else(
            || ReplayStatus::NotChecked,
            OAuthValidationEvidence::replay_status,
        ),
        session_scope_binding: session_scope_binding.map(std::string::ToString::to_string),
        canonical_request_hash: None,
        execution_is_ephemeral: execution_is_ephemeral(eval_ctx, oauth_evidence, session_key_scope),
    })
}

fn transport_session_scope_binding(
    sessions: &SessionStore,
    session_id: Option<&str>,
) -> Option<String> {
    let session_id = session_id?;
    // SECURITY (DEADLOCK-FIX): Use try_get instead of get to avoid deadlock
    // when the caller already holds a get_mut() write lock on the same DashMap
    // shard (e.g., inside the TOCTOU-protected evaluation block in handlers).
    // If the shard is locked, fall back to None — the caller should pre-compute
    // the security context outside the lock to avoid this path.
    match sessions.try_get(session_id) {
        dashmap::try_result::TryResult::Present(session) => {
            Some(session.session_scope_binding.clone())
        }
        dashmap::try_result::TryResult::Absent => None,
        dashmap::try_result::TryResult::Locked => {
            tracing::debug!(
                session_id = %session_id,
                "DashMap shard locked — session_scope_binding unavailable for provenance"
            );
            None
        }
    }
}

fn build_client_provenance(
    headers: &HeaderMap,
    oauth_evidence: Option<&OAuthValidationEvidence>,
    eval_ctx: Option<&EvaluationContext>,
    sessions: &SessionStore,
    session_id: Option<&str>,
) -> Option<ClientProvenance> {
    let detached_signature = decode_detached_request_signature(headers);
    build_client_provenance_from_transport(
        oauth_evidence,
        eval_ctx,
        transport_session_scope_binding(sessions, session_id).as_deref(),
        decode_dpop_request_signature(headers, oauth_client_key_id(oauth_evidence).as_deref()),
        detached_signature,
    )
}

fn merge_request_signature(
    existing: Option<RequestSignature>,
    transport: Option<RequestSignature>,
) -> Option<RequestSignature> {
    match (existing, transport) {
        (None, None) => None,
        (Some(signature), None) | (None, Some(signature)) => Some(signature),
        (Some(mut existing), Some(transport)) => {
            if existing.key_id.is_none() {
                existing.key_id = transport.key_id;
            }
            if existing.algorithm.is_none() {
                existing.algorithm = transport.algorithm;
            }
            if existing.nonce.is_none() {
                existing.nonce = transport.nonce;
            }
            if existing.created_at.is_none() {
                existing.created_at = transport.created_at;
            }
            if existing.signature.is_none() {
                existing.signature = transport.signature;
            }
            Some(existing)
        }
    }
}

fn merge_transport_owned_request_signature(
    existing: Option<RequestSignature>,
    transport: Option<RequestSignature>,
) -> Option<RequestSignature> {
    match (existing, transport) {
        (None, None) => None,
        (Some(existing), None) => Some(existing),
        (None, Some(transport)) => Some(transport),
        (Some(existing), Some(mut transport)) => {
            if transport.key_id.is_none() {
                transport.key_id = existing.key_id;
            }
            if transport.algorithm.is_none() {
                transport.algorithm = existing.algorithm;
            }
            if transport.nonce.is_none() {
                transport.nonce = existing.nonce;
            }
            if transport.created_at.is_none() {
                transport.created_at = existing.created_at;
            }
            if transport.signature.is_none() {
                transport.signature = existing.signature;
            }
            Some(transport)
        }
    }
}

fn merge_signature_verification_status(
    existing: SignatureVerificationStatus,
    transport: SignatureVerificationStatus,
) -> SignatureVerificationStatus {
    use SignatureVerificationStatus::{Error, Expired, Invalid, Missing, Verified};

    match (existing, transport) {
        (Error, _) | (_, Error) => Error,
        (Invalid, _) | (_, Invalid) => Invalid,
        (Expired, _) | (_, Expired) => Expired,
        (Verified, _) | (_, Verified) => Verified,
        (Missing, Missing) => Missing,
    }
}

fn merge_replay_status(existing: ReplayStatus, transport: ReplayStatus) -> ReplayStatus {
    use ReplayStatus::{Fresh, NotChecked, ReplayDetected};

    match (existing, transport) {
        (ReplayDetected, _) | (_, ReplayDetected) => ReplayDetected,
        (Fresh, _) | (_, Fresh) => Fresh,
        (NotChecked, NotChecked) => NotChecked,
    }
}

fn workload_identity_conflicts(existing: &WorkloadIdentity, transport: &WorkloadIdentity) -> bool {
    existing.workload_id != transport.workload_id
        || option_values_conflict(existing.platform.as_deref(), transport.platform.as_deref())
        || option_values_conflict(
            existing.namespace.as_deref(),
            transport.namespace.as_deref(),
        )
        || option_values_conflict(
            existing.service_account.as_deref(),
            transport.service_account.as_deref(),
        )
        || option_values_conflict(
            existing.process_identity.as_deref(),
            transport.process_identity.as_deref(),
        )
        || option_values_conflict(
            existing.attestation_level.as_deref(),
            transport.attestation_level.as_deref(),
        )
}

fn option_values_conflict<T: PartialEq + ?Sized>(
    existing: Option<&T>,
    transport: Option<&T>,
) -> bool {
    matches!((existing, transport), (Some(existing), Some(transport)) if existing != transport)
}

fn merge_workload_identity(
    existing: Option<WorkloadIdentity>,
    transport: Option<WorkloadIdentity>,
) -> (Option<WorkloadIdentity>, bool) {
    match (existing, transport) {
        (None, None) => (None, false),
        (Some(existing), None) => (Some(existing), false),
        (None, Some(transport)) => (Some(transport), false),
        (Some(mut existing), Some(transport)) => {
            if workload_identity_conflicts(&existing, &transport) {
                return (Some(transport), true);
            }

            if existing.platform.is_none() {
                existing.platform = transport.platform;
            }
            if existing.namespace.is_none() {
                existing.namespace = transport.namespace;
            }
            if existing.service_account.is_none() {
                existing.service_account = transport.service_account;
            }
            if existing.process_identity.is_none() {
                existing.process_identity = transport.process_identity;
            }
            if existing.attestation_level.is_none() {
                existing.attestation_level = transport.attestation_level;
            }
            if existing.workload_id.is_empty() {
                existing.workload_id = transport.workload_id;
            }

            (Some(existing), false)
        }
    }
}

fn merge_workload_binding_status(
    existing: WorkloadBindingStatus,
    transport: WorkloadBindingStatus,
    workload_identity_conflict: bool,
) -> WorkloadBindingStatus {
    use WorkloadBindingStatus::{Bound, Mismatch, Missing, Unknown, Unverified};

    if workload_identity_conflict || matches!(existing, Mismatch) || matches!(transport, Mismatch) {
        return Mismatch;
    }
    if matches!(existing, Missing) || matches!(transport, Missing) {
        return Missing;
    }
    if matches!(existing, Unverified) || matches!(transport, Unverified) {
        return Unverified;
    }
    if matches!(existing, Bound) || matches!(transport, Bound) {
        return Bound;
    }

    Unknown
}

fn merge_session_key_scope(
    existing: SessionKeyScope,
    transport: SessionKeyScope,
) -> SessionKeyScope {
    if transport == SessionKeyScope::Unknown {
        existing
    } else {
        transport
    }
}

fn merge_execution_is_ephemeral(
    existing: bool,
    transport: bool,
    merged_session_key_scope: SessionKeyScope,
) -> bool {
    match merged_session_key_scope {
        SessionKeyScope::EphemeralExecution | SessionKeyScope::EphemeralSession => true,
        SessionKeyScope::PersistedClient | SessionKeyScope::PersistedService => false,
        SessionKeyScope::Unknown => {
            if transport {
                true
            } else {
                existing
            }
        }
    }
}

fn merge_client_provenance(
    existing: Option<ClientProvenance>,
    transport: Option<ClientProvenance>,
) -> Option<ClientProvenance> {
    match (existing, transport) {
        (None, None) => None,
        (Some(provenance), None) | (None, Some(provenance)) => Some(provenance),
        (Some(mut existing), Some(transport)) => {
            existing.request_signature = merge_transport_owned_request_signature(
                existing.request_signature,
                transport.request_signature,
            );

            if transport.client_key_id.is_some() {
                existing.client_key_id = transport.client_key_id;
            }
            existing.signature_status = merge_signature_verification_status(
                existing.signature_status,
                transport.signature_status,
            );
            existing.session_key_scope =
                merge_session_key_scope(existing.session_key_scope, transport.session_key_scope);
            let (merged_workload_identity, workload_identity_conflict) =
                merge_workload_identity(existing.workload_identity, transport.workload_identity);
            existing.workload_identity = merged_workload_identity;
            existing.workload_binding_status = merge_workload_binding_status(
                existing.workload_binding_status,
                transport.workload_binding_status,
                workload_identity_conflict,
            );
            existing.replay_status =
                merge_replay_status(existing.replay_status, transport.replay_status);
            if transport.session_scope_binding.is_some() {
                existing.session_scope_binding = transport.session_scope_binding;
            }
            if transport.canonical_request_hash.is_some() {
                existing.canonical_request_hash = transport.canonical_request_hash;
            }
            existing.execution_is_ephemeral = merge_execution_is_ephemeral(
                existing.execution_is_ephemeral,
                transport.execution_is_ephemeral,
                existing.session_key_scope,
            );
            Some(existing)
        }
    }
}

fn lineage_refs_from_call_chain(eval_ctx: Option<&EvaluationContext>) -> Vec<LineageRef> {
    const MAX_LINEAGE_REFS: usize = 64;

    eval_ctx
        .map(|ctx| {
            ctx.call_chain
                .iter()
                .take(MAX_LINEAGE_REFS)
                .map(|entry| {
                    let mut hasher = Sha256::new();
                    hasher.update(entry.agent_id.as_bytes());
                    hasher.update(b"|");
                    hasher.update(entry.tool.as_bytes());
                    hasher.update(b"|");
                    hasher.update(entry.function.as_bytes());
                    hasher.update(b"|");
                    hasher.update(entry.timestamp.as_bytes());

                    let trust_tier = match entry.verified {
                        Some(true) => Some(TrustTier::Verified),
                        Some(false) => Some(TrustTier::Untrusted),
                        None => Some(TrustTier::Low),
                    };

                    LineageRef {
                        id: format!("call-chain:{}", hex::encode(hasher.finalize())),
                        channel: ContextChannel::ToolOutput,
                        content_hash: entry.hmac.clone(),
                        source: Some(entry.agent_id.clone()),
                        trust_tier,
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn infer_trust_tier(
    security_context: &RuntimeSecurityContext,
    oauth_evidence: Option<&OAuthValidationEvidence>,
    eval_ctx: Option<&EvaluationContext>,
) -> Option<TrustTier> {
    if security_context
        .client_provenance
        .as_ref()
        .is_some_and(|provenance| {
            provenance.signature_status == SignatureVerificationStatus::Expired
        })
    {
        return Some(TrustTier::Quarantined);
    }
    if security_context
        .client_provenance
        .as_ref()
        .is_some_and(|provenance| provenance.replay_status == ReplayStatus::ReplayDetected)
    {
        return Some(TrustTier::Quarantined);
    }
    if security_context
        .client_provenance
        .as_ref()
        .is_some_and(|provenance| {
            matches!(
                provenance.signature_status,
                SignatureVerificationStatus::Invalid | SignatureVerificationStatus::Error
            )
        })
    {
        return Some(TrustTier::Untrusted);
    }
    if security_context
        .client_provenance
        .as_ref()
        .is_some_and(|provenance| {
            provenance.workload_binding_status == WorkloadBindingStatus::Mismatch
        })
    {
        return Some(TrustTier::Untrusted);
    }
    if security_context
        .client_provenance
        .as_ref()
        .is_some_and(|provenance| {
            provenance.signature_status == SignatureVerificationStatus::Verified
        })
        || eval_ctx
            .and_then(|ctx| ctx.agent_identity.as_ref())
            .is_some()
    {
        return Some(TrustTier::Verified);
    }
    if oauth_evidence.is_some() {
        return Some(TrustTier::Medium);
    }
    if !security_context.lineage_refs.is_empty() {
        return Some(TrustTier::Low);
    }
    None
}

fn routing_identity_from_eval_ctx(eval_ctx: Option<&EvaluationContext>) -> Option<&str> {
    eval_ctx.and_then(|ctx| {
        ctx.agent_identity
            .as_ref()
            .and_then(|identity| identity.subject.as_deref())
            .or(ctx.agent_id.as_deref())
    })
}

fn attach_canonical_request_hash(
    action: &Action,
    eval_ctx: Option<&EvaluationContext>,
    security_context: &mut RuntimeSecurityContext,
) {
    let Some(provenance) = security_context.client_provenance.as_mut() else {
        return;
    };

    let input = CanonicalRequestInput::from_action(
        action,
        provenance.session_scope_binding.as_deref(),
        Some(&*provenance),
        routing_identity_from_eval_ctx(eval_ctx),
    );
    if let Ok(hash) = canonical_request_hash(&input) {
        provenance.canonical_request_hash = Some(hash);
    }
}

fn verify_detached_request_signature(
    action: &Action,
    inputs: TransportSecurityInputs<'_>,
    security_context: &mut RuntimeSecurityContext,
) {
    if inputs.trusted_request_signers.is_empty() {
        return;
    }

    let Some(provenance) = security_context.client_provenance.as_mut() else {
        return;
    };
    if provenance.signature_status != SignatureVerificationStatus::Missing {
        return;
    }
    let Some(request_signature) = provenance.request_signature.as_ref() else {
        return;
    };
    let Some(request_nonce) = request_signature.nonce.clone() else {
        provenance.signature_status = SignatureVerificationStatus::Invalid;
        return;
    };
    let Some(created_at) = request_signature.created_at.as_deref() else {
        provenance.signature_status = SignatureVerificationStatus::Invalid;
        return;
    };
    let Some(key_id) = request_signature.key_id.as_deref() else {
        provenance.signature_status = SignatureVerificationStatus::Invalid;
        return;
    };
    let Some(trusted_signer) = inputs.trusted_request_signers.get(key_id) else {
        provenance.signature_status = SignatureVerificationStatus::Invalid;
        return;
    };
    if !request_signature
        .algorithm
        .as_deref()
        .is_some_and(|algorithm| algorithm.eq_ignore_ascii_case("ed25519"))
    {
        provenance.signature_status = SignatureVerificationStatus::Invalid;
        return;
    }
    let Some(signature_hex) = request_signature.signature.as_deref() else {
        provenance.signature_status = SignatureVerificationStatus::Invalid;
        return;
    };
    let signature_bytes = match hex::decode(signature_hex) {
        Ok(bytes) => bytes,
        Err(_) => {
            provenance.signature_status = SignatureVerificationStatus::Invalid;
            return;
        }
    };
    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(signature) => signature,
        Err(_) => {
            provenance.signature_status = SignatureVerificationStatus::Invalid;
            return;
        }
    };
    let verifying_key = match VerifyingKey::from_bytes(&trusted_signer.public_key) {
        Ok(verifying_key) => verifying_key,
        Err(_) => {
            provenance.signature_status = SignatureVerificationStatus::Error;
            return;
        }
    };
    let input = CanonicalRequestInput::from_action(
        action,
        provenance.session_scope_binding.as_deref(),
        Some(&*provenance),
        routing_identity_from_eval_ctx(inputs.eval_ctx),
    );
    let preimage = match canonical_request_preimage(&input) {
        Ok(preimage) => preimage,
        Err(_) => {
            provenance.signature_status = SignatureVerificationStatus::Error;
            return;
        }
    };
    provenance.signature_status = if verifying_key.verify(&preimage, &signature).is_ok() {
        SignatureVerificationStatus::Verified
    } else {
        SignatureVerificationStatus::Invalid
    };
    if provenance.signature_status != SignatureVerificationStatus::Verified {
        return;
    }
    let created_at_secs = match vellaveto_types::time_util::parse_iso8601_secs(created_at) {
        Ok(timestamp) => timestamp,
        Err(_) => {
            provenance.signature_status = SignatureVerificationStatus::Invalid;
            return;
        }
    };
    let now_secs = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => {
            provenance.signature_status = SignatureVerificationStatus::Error;
            return;
        }
    };
    if created_at_secs
        > now_secs.saturating_add(inputs.detached_signature_freshness.max_future_skew_secs)
        || now_secs.saturating_sub(created_at_secs)
            > inputs.detached_signature_freshness.max_age_secs
    {
        provenance.signature_status = SignatureVerificationStatus::Expired;
        return;
    }
    if provenance.signature_status != SignatureVerificationStatus::Verified {
        return;
    }
    if !apply_trusted_request_signer_metadata(provenance, trusted_signer) {
        provenance.signature_status = SignatureVerificationStatus::Invalid;
        return;
    }
    let Some(session_id) = inputs.session_id else {
        return;
    };
    // SECURITY (DEADLOCK-FIX): Use try_get_mut instead of get_mut to avoid
    // deadlock when the caller already holds a get_mut() write lock on the
    // same DashMap shard. If the shard is locked, nonce recording is skipped —
    // signature verification still completes, and the caller's TOCTOU block
    // serializes requests on this session so replay within the same lock is
    // not possible.
    let Some(mut session) = inputs.sessions.try_get_mut(session_id).try_unwrap() else {
        return;
    };
    provenance.replay_status = merge_replay_status(
        provenance.replay_status,
        session.record_verified_request_nonce(&request_nonce),
    );
}

fn apply_trusted_request_signer_metadata(
    provenance: &mut ClientProvenance,
    trusted_signer: &super::TrustedRequestSigner,
) -> bool {
    if trusted_signer_conflicts_with_transport(provenance, trusted_signer) {
        return false;
    }
    if provenance.session_key_scope == SessionKeyScope::Unknown
        && trusted_signer.session_key_scope != SessionKeyScope::Unknown
    {
        provenance.session_key_scope = trusted_signer.session_key_scope;
    }
    provenance.execution_is_ephemeral |= trusted_signer.execution_is_ephemeral
        || matches!(
            trusted_signer.session_key_scope,
            SessionKeyScope::EphemeralExecution | SessionKeyScope::EphemeralSession
        );
    let Some(workload_identity) = trusted_signer.workload_identity.as_ref() else {
        return true;
    };

    match provenance.workload_identity.as_ref() {
        Some(existing_identity) if existing_identity == workload_identity => {
            provenance.workload_binding_status = WorkloadBindingStatus::Bound;
        }
        Some(_) => {
            provenance.workload_binding_status = WorkloadBindingStatus::Mismatch;
        }
        None => {
            provenance.workload_identity = Some(workload_identity.clone());
            provenance.workload_binding_status = WorkloadBindingStatus::Bound;
        }
    }
    true
}

fn trusted_signer_conflicts_with_transport(
    provenance: &ClientProvenance,
    trusted_signer: &super::TrustedRequestSigner,
) -> bool {
    if trusted_signer.session_key_scope != SessionKeyScope::Unknown
        && provenance.session_key_scope != SessionKeyScope::Unknown
        && provenance.session_key_scope != trusted_signer.session_key_scope
    {
        return true;
    }

    if trusted_signer.execution_is_ephemeral
        && matches!(
            provenance.session_key_scope,
            SessionKeyScope::PersistedClient | SessionKeyScope::PersistedService
        )
    {
        return true;
    }

    matches!(
        trusted_signer.session_key_scope,
        SessionKeyScope::PersistedClient | SessionKeyScope::PersistedService
    ) && provenance.execution_is_ephemeral
}

fn build_runtime_security_context_from_transport(
    msg: &Value,
    action: &Action,
    transport_provenance: Option<ClientProvenance>,
    inputs: TransportSecurityInputs<'_>,
) -> Option<RuntimeSecurityContext> {
    let mut security_context = extract_runtime_security_context(msg).unwrap_or_default();

    security_context.client_provenance =
        merge_client_provenance(security_context.client_provenance, transport_provenance);
    if security_context.sink_class.is_none() {
        security_context.sink_class = Some(infer_sink_class(action));
    }
    if security_context.lineage_refs.is_empty() {
        security_context.lineage_refs = lineage_refs_from_call_chain(inputs.eval_ctx);
    }
    verify_detached_request_signature(action, inputs, &mut security_context);
    let inferred_trust_tier =
        infer_trust_tier(&security_context, inputs.oauth_evidence, inputs.eval_ctx);
    security_context.effective_trust_tier =
        match (security_context.effective_trust_tier, inferred_trust_tier) {
            (Some(explicit), Some(inferred)) => Some(explicit.meet(inferred)),
            (Some(explicit), None) => Some(explicit),
            (None, Some(inferred)) => Some(inferred),
            (None, None) => None,
        };
    attach_canonical_request_hash(action, inputs.eval_ctx, &mut security_context);

    if security_context == RuntimeSecurityContext::default() {
        None
    } else {
        Some(security_context)
    }
}

pub(super) fn build_runtime_security_context(
    msg: &Value,
    action: &Action,
    headers: &HeaderMap,
    inputs: TransportSecurityInputs<'_>,
) -> Option<RuntimeSecurityContext> {
    build_runtime_security_context_from_transport(
        msg,
        action,
        build_client_provenance(
            headers,
            inputs.oauth_evidence,
            inputs.eval_ctx,
            inputs.sessions,
            inputs.session_id,
        ),
        inputs,
    )
}

#[cfg(feature = "grpc")]
pub(super) fn build_runtime_security_context_with_request_signature(
    msg: &Value,
    action: &Action,
    request_signature_header: Option<&str>,
    inputs: TransportSecurityInputs<'_>,
) -> Option<RuntimeSecurityContext> {
    build_runtime_security_context_from_transport(
        msg,
        action,
        build_client_provenance_from_transport(
            inputs.oauth_evidence,
            inputs.eval_ctx,
            transport_session_scope_binding(inputs.sessions, inputs.session_id).as_deref(),
            None,
            decode_detached_request_signature_value(request_signature_header),
        ),
        inputs,
    )
}

pub(super) fn merge_transport_security_context(
    runtime_security_context: Option<&RuntimeSecurityContext>,
    verdict_security_context: Option<&RuntimeSecurityContext>,
) -> Option<RuntimeSecurityContext> {
    let merged = match (
        runtime_security_context.cloned(),
        verdict_security_context.cloned(),
    ) {
        (None, None) => return None,
        (Some(context), None) | (None, Some(context)) => context,
        (Some(mut runtime), Some(verdict)) => {
            if runtime.client_provenance.is_none() {
                runtime.client_provenance = verdict.client_provenance;
            }
            for taint in verdict.semantic_taint {
                if !runtime.semantic_taint.contains(&taint) {
                    runtime.semantic_taint.push(taint);
                }
            }
            runtime.effective_trust_tier =
                match (runtime.effective_trust_tier, verdict.effective_trust_tier) {
                    (Some(runtime_tier), Some(verdict_tier)) => {
                        Some(runtime_tier.meet(verdict_tier))
                    }
                    (Some(runtime_tier), None) => Some(runtime_tier),
                    (None, Some(verdict_tier)) => Some(verdict_tier),
                    (None, None) => None,
                };
            if runtime.sink_class.is_none() {
                runtime.sink_class = verdict.sink_class;
            }
            for lineage in verdict.lineage_refs {
                if !runtime.lineage_refs.contains(&lineage) {
                    runtime.lineage_refs.push(lineage);
                }
            }
            if !matches!(
                verdict.containment_mode,
                None | Some(vellaveto_types::ContainmentMode::Disabled)
            ) {
                runtime.containment_mode = verdict.containment_mode;
            }
            if let Some(score) = verdict.semantic_risk_score {
                runtime.merge_semantic_risk_score(score);
            }
            runtime
        }
    };

    if merged == RuntimeSecurityContext::default() {
        None
    } else {
        Some(merged)
    }
}

pub(super) fn tool_discovery_integrity_security_context(
    lineage_id: &str,
    observed_channel: ContextChannel,
    source: &str,
    quarantined: bool,
) -> RuntimeSecurityContext {
    let effective_trust_tier = Some(if quarantined {
        TrustTier::Quarantined
    } else {
        TrustTier::Untrusted
    });
    let mut semantic_taint = vec![SemanticTaint::Untrusted, SemanticTaint::IntegrityFailed];
    if quarantined {
        semantic_taint.push(SemanticTaint::Quarantined);
    }

    RuntimeSecurityContext {
        semantic_taint,
        effective_trust_tier,
        sink_class: None,
        lineage_refs: vec![LineageRef {
            id: lineage_id.to_string(),
            channel: observed_channel,
            content_hash: None,
            source: Some(source.to_string()),
            trust_tier: effective_trust_tier,
        }],
        containment_mode: Some(if quarantined {
            vellaveto_types::ContainmentMode::Quarantine
        } else {
            vellaveto_types::ContainmentMode::Enforce
        }),
        semantic_risk_score: Some(SemanticRiskScore {
            value: 55u8
                .saturating_add(observed_channel.semantic_risk_weight())
                .saturating_add(if quarantined { 20 } else { 0 })
                .min(100),
        }),
        ..RuntimeSecurityContext::default()
    }
}

fn dlp_security_context(
    observed_channel: ContextChannel,
    blocking: bool,
    lineage_id: &str,
    source: &str,
) -> RuntimeSecurityContext {
    let effective_trust_tier = Some(if blocking {
        TrustTier::Quarantined
    } else {
        TrustTier::Untrusted
    });
    let mut semantic_taint = vec![SemanticTaint::Sensitive];
    if blocking {
        semantic_taint.push(SemanticTaint::Quarantined);
    }

    RuntimeSecurityContext {
        semantic_taint,
        effective_trust_tier,
        sink_class: None,
        lineage_refs: vec![LineageRef {
            id: lineage_id.to_string(),
            channel: observed_channel,
            content_hash: None,
            source: Some(source.to_string()),
            trust_tier: effective_trust_tier,
        }],
        containment_mode: Some(if blocking {
            vellaveto_types::ContainmentMode::Quarantine
        } else {
            vellaveto_types::ContainmentMode::Sanitize
        }),
        semantic_risk_score: Some(SemanticRiskScore {
            value: 55u8
                .saturating_add(observed_channel.semantic_risk_weight())
                .saturating_add(if blocking { 20 } else { 0 })
                .min(100),
        }),
        ..RuntimeSecurityContext::default()
    }
}

fn extract_strings_for_channel_inference(
    value: &Value,
    parts: &mut Vec<String>,
    depth: usize,
    max_depth: usize,
    max_parts: usize,
) {
    if depth > max_depth || parts.len() >= max_parts {
        return;
    }

    match value {
        Value::String(text) => parts.push(text.clone()),
        Value::Array(items) => {
            for item in items {
                extract_strings_for_channel_inference(item, parts, depth + 1, max_depth, max_parts);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                if parts.len() >= max_parts {
                    break;
                }
                parts.push(key.clone());
                extract_strings_for_channel_inference(item, parts, depth + 1, max_depth, max_parts);
            }
        }
        _ => {}
    }
}

fn contains_url(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("http://")
        || lower.contains("https://")
        || lower.contains("file://")
        || lower.contains("ssh://")
        || lower.contains("mailto:")
        || lower.contains("www.")
}

fn looks_like_command(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let trimmed = lower.trim_start();

    if trimmed.contains("```bash")
        || trimmed.contains("```sh")
        || trimmed.contains("```shell")
        || trimmed.contains("```powershell")
        || trimmed.contains("cmd /c")
        || trimmed.contains("powershell -")
    {
        return true;
    }

    trimmed.lines().any(|line| {
        let line = line.trim_start();
        line.starts_with("curl ")
            || line.starts_with("wget ")
            || line.starts_with("bash ")
            || line.starts_with("sh ")
            || line.starts_with("python ")
            || line.starts_with("python3 ")
            || line.starts_with("node ")
            || line.starts_with("npm ")
            || line.starts_with("chmod ")
            || line.starts_with("rm ")
            || line.starts_with("sudo ")
            || line.starts_with("git clone ")
            || line.starts_with("kubectl ")
            || line.starts_with("docker ")
    })
}

fn text_observed_channel(text: &str) -> ContextChannel {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return ContextChannel::FreeText;
    }
    if looks_like_command(trimmed) {
        return ContextChannel::CommandLike;
    }
    if contains_url(trimmed) {
        return ContextChannel::Url;
    }
    ContextChannel::FreeText
}

fn wrapped_value_observed_channel(value: &Value) -> ContextChannel {
    const MAX_DEPTH: usize = 16;
    const MAX_PARTS: usize = 256;

    let response_channel = infer_observed_output_channel(None, &json!({ "result": value }));
    if !matches!(response_channel, ContextChannel::ToolOutput) {
        return response_channel;
    }

    let mut parts = Vec::new();
    extract_strings_for_channel_inference(value, &mut parts, 0, MAX_DEPTH, MAX_PARTS);

    let mut saw_free_text = false;
    let mut saw_url = false;
    let mut saw_command_like = false;
    for part in parts {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        if looks_like_command(trimmed) {
            saw_command_like = true;
        }
        if contains_url(trimmed) {
            saw_url = true;
        }
        saw_free_text = true;
    }

    if saw_command_like {
        ContextChannel::CommandLike
    } else if saw_url {
        ContextChannel::Url
    } else if saw_free_text {
        ContextChannel::FreeText
    } else if value.is_object() || value.is_array() {
        ContextChannel::Data
    } else {
        ContextChannel::FreeText
    }
}

fn message_payload_observed_channel(message: &Value) -> ContextChannel {
    if let Some(params) = message.get("params") {
        return wrapped_value_observed_channel(params);
    }
    if let Some(result) = message.get("result") {
        return wrapped_value_observed_channel(result);
    }
    ContextChannel::FreeText
}

pub(super) fn response_dlp_security_context(
    tool_name: Option<&str>,
    response: &Value,
    blocking: bool,
) -> RuntimeSecurityContext {
    dlp_security_context(
        infer_observed_output_channel(tool_name, response),
        blocking,
        "response_dlp",
        "response_dlp",
    )
}

pub(super) fn notification_dlp_security_context(
    message: &Value,
    blocking: bool,
) -> RuntimeSecurityContext {
    dlp_security_context(
        message_payload_observed_channel(message),
        blocking,
        "notification_dlp",
        "notification_dlp",
    )
}

pub(super) fn parameter_dlp_security_context(
    params: &Value,
    blocking: bool,
    source: &str,
) -> RuntimeSecurityContext {
    dlp_security_context(
        wrapped_value_observed_channel(params),
        blocking,
        "parameter_dlp",
        source,
    )
}

pub(super) fn text_dlp_security_context(
    text: &str,
    blocking: bool,
    source: &str,
) -> RuntimeSecurityContext {
    dlp_security_context(text_observed_channel(text), blocking, "text_dlp", source)
}

fn injection_security_context(
    observed_channel: ContextChannel,
    blocking: bool,
    source: &str,
) -> RuntimeSecurityContext {
    let effective_trust_tier = Some(if blocking {
        TrustTier::Quarantined
    } else {
        TrustTier::Untrusted
    });
    let mut semantic_taint = vec![SemanticTaint::Untrusted];
    if blocking {
        semantic_taint.push(SemanticTaint::Quarantined);
    }

    RuntimeSecurityContext {
        semantic_taint,
        effective_trust_tier,
        sink_class: None,
        lineage_refs: vec![LineageRef {
            id: "injection_detected".to_string(),
            channel: observed_channel,
            content_hash: None,
            source: Some(source.to_string()),
            trust_tier: effective_trust_tier,
        }],
        containment_mode: Some(if blocking {
            vellaveto_types::ContainmentMode::Quarantine
        } else {
            vellaveto_types::ContainmentMode::Enforce
        }),
        semantic_risk_score: Some(SemanticRiskScore {
            value: 50u8
                .saturating_add(observed_channel.semantic_risk_weight())
                .saturating_add(if blocking { 20 } else { 0 })
                .min(100),
        }),
        ..RuntimeSecurityContext::default()
    }
}

pub(super) fn response_injection_security_context(
    tool_name: Option<&str>,
    response: &Value,
    blocking: bool,
    source: &str,
) -> RuntimeSecurityContext {
    injection_security_context(
        infer_observed_output_channel(tool_name, response),
        blocking,
        source,
    )
}

pub(super) fn notification_injection_security_context(
    message: &Value,
    blocking: bool,
    source: &str,
) -> RuntimeSecurityContext {
    injection_security_context(message_payload_observed_channel(message), blocking, source)
}

pub(super) fn parameter_injection_security_context(
    params: &Value,
    blocking: bool,
    source: &str,
) -> RuntimeSecurityContext {
    injection_security_context(wrapped_value_observed_channel(params), blocking, source)
}

pub(super) fn text_injection_security_context(
    text: &str,
    blocking: bool,
    source: &str,
) -> RuntimeSecurityContext {
    injection_security_context(text_observed_channel(text), blocking, source)
}

pub(super) fn memory_poisoning_security_context(
    value: &Value,
    source: &str,
) -> RuntimeSecurityContext {
    let observed_channel = wrapped_value_observed_channel(value);

    RuntimeSecurityContext {
        semantic_taint: vec![
            SemanticTaint::Untrusted,
            SemanticTaint::IntegrityFailed,
            SemanticTaint::Quarantined,
        ],
        effective_trust_tier: Some(TrustTier::Quarantined),
        sink_class: None,
        lineage_refs: vec![LineageRef {
            id: "memory_poisoning".to_string(),
            channel: observed_channel,
            content_hash: None,
            source: Some(source.to_string()),
            trust_tier: Some(TrustTier::Quarantined),
        }],
        containment_mode: Some(vellaveto_types::ContainmentMode::Quarantine),
        semantic_risk_score: Some(SemanticRiskScore {
            value: 60u8
                .saturating_add(observed_channel.semantic_risk_weight())
                .saturating_add(20)
                .min(100),
        }),
        ..RuntimeSecurityContext::default()
    }
}

pub(super) fn notification_memory_poisoning_security_context(
    message: &Value,
    source: &str,
) -> RuntimeSecurityContext {
    let observed_channel = message_payload_observed_channel(message);

    RuntimeSecurityContext {
        semantic_taint: vec![
            SemanticTaint::Untrusted,
            SemanticTaint::IntegrityFailed,
            SemanticTaint::Quarantined,
        ],
        effective_trust_tier: Some(TrustTier::Quarantined),
        sink_class: None,
        lineage_refs: vec![LineageRef {
            id: "memory_poisoning".to_string(),
            channel: observed_channel,
            content_hash: None,
            source: Some(source.to_string()),
            trust_tier: Some(TrustTier::Quarantined),
        }],
        containment_mode: Some(vellaveto_types::ContainmentMode::Quarantine),
        semantic_risk_score: Some(SemanticRiskScore {
            value: 60u8
                .saturating_add(observed_channel.semantic_risk_weight())
                .saturating_add(20)
                .min(100),
        }),
        ..RuntimeSecurityContext::default()
    }
}

pub(super) fn output_schema_violation_security_context(
    tool_name: Option<&str>,
    blocking: bool,
) -> RuntimeSecurityContext {
    let effective_trust_tier = Some(if blocking {
        TrustTier::Quarantined
    } else {
        TrustTier::Untrusted
    });
    let mut semantic_taint = vec![SemanticTaint::Untrusted, SemanticTaint::IntegrityFailed];
    if blocking {
        semantic_taint.push(SemanticTaint::Quarantined);
    }

    let observed_channel = if tool_name == Some("resources/read") {
        ContextChannel::ResourceContent
    } else {
        ContextChannel::Data
    };

    RuntimeSecurityContext {
        semantic_taint,
        effective_trust_tier,
        sink_class: None,
        lineage_refs: vec![LineageRef {
            id: "output_schema".to_string(),
            channel: observed_channel,
            content_hash: None,
            source: Some("output_schema_validation".to_string()),
            trust_tier: effective_trust_tier,
        }],
        containment_mode: Some(if blocking {
            vellaveto_types::ContainmentMode::Quarantine
        } else {
            vellaveto_types::ContainmentMode::Enforce
        }),
        semantic_risk_score: Some(SemanticRiskScore {
            value: 50u8
                .saturating_add(observed_channel.semantic_risk_weight())
                .saturating_add(if blocking { 20 } else { 0 })
                .min(100),
        }),
        ..RuntimeSecurityContext::default()
    }
}

struct GuardSecurityContextSpec {
    lineage_id: &'static str,
    observed_channel: Option<ContextChannel>,
    source: &'static str,
    effective_trust_tier: TrustTier,
    containment_mode: vellaveto_types::ContainmentMode,
    semantic_taint: Vec<SemanticTaint>,
    extra_risk: u8,
}

struct ExplicitSecurityContextSpec {
    lineage_id: &'static str,
    observed_channel: ContextChannel,
    source: &'static str,
    effective_trust_tier: TrustTier,
    sink_class: SinkClass,
    containment_mode: vellaveto_types::ContainmentMode,
    semantic_taint: Vec<SemanticTaint>,
    extra_risk: u8,
}

struct NetworkSecurityContextSpec {
    lineage_id: &'static str,
    observed_channel: ContextChannel,
    source: &'static str,
    effective_trust_tier: TrustTier,
    containment_mode: vellaveto_types::ContainmentMode,
    semantic_taint: Vec<SemanticTaint>,
    extra_risk: u8,
}

fn default_guard_observed_channel(action: &Action) -> ContextChannel {
    if action.tool == "resources" && action.function == "read" {
        ContextChannel::ResourceContent
    } else {
        ContextChannel::ToolOutput
    }
}

fn guard_security_context(
    action: &Action,
    spec: GuardSecurityContextSpec,
) -> RuntimeSecurityContext {
    let sink_class = infer_sink_class(action);
    let observed_channel = spec
        .observed_channel
        .unwrap_or_else(|| default_guard_observed_channel(action));
    let trust_tier = Some(spec.effective_trust_tier);

    RuntimeSecurityContext {
        semantic_taint: spec.semantic_taint,
        effective_trust_tier: trust_tier,
        sink_class: Some(sink_class),
        lineage_refs: vec![LineageRef {
            id: spec.lineage_id.to_string(),
            channel: observed_channel,
            content_hash: None,
            source: Some(spec.source.to_string()),
            trust_tier,
        }],
        containment_mode: Some(spec.containment_mode),
        semantic_risk_score: Some(SemanticRiskScore {
            value: sink_class
                .semantic_risk_weight()
                .saturating_add(observed_channel.semantic_risk_weight())
                .saturating_add(spec.extra_risk)
                .min(100),
        }),
        ..RuntimeSecurityContext::default()
    }
}

fn explicit_security_context(spec: ExplicitSecurityContextSpec) -> RuntimeSecurityContext {
    let trust_tier = Some(spec.effective_trust_tier);

    RuntimeSecurityContext {
        semantic_taint: spec.semantic_taint,
        effective_trust_tier: Some(spec.effective_trust_tier),
        sink_class: Some(spec.sink_class),
        lineage_refs: vec![LineageRef {
            id: spec.lineage_id.to_string(),
            channel: spec.observed_channel,
            content_hash: None,
            source: Some(spec.source.to_string()),
            trust_tier,
        }],
        containment_mode: Some(spec.containment_mode),
        semantic_risk_score: Some(SemanticRiskScore {
            value: spec
                .sink_class
                .semantic_risk_weight()
                .saturating_add(spec.observed_channel.semantic_risk_weight())
                .saturating_add(spec.extra_risk)
                .min(100),
        }),
        ..RuntimeSecurityContext::default()
    }
}

fn network_security_context(spec: NetworkSecurityContextSpec) -> RuntimeSecurityContext {
    explicit_security_context(ExplicitSecurityContextSpec {
        lineage_id: spec.lineage_id,
        observed_channel: spec.observed_channel,
        source: spec.source,
        effective_trust_tier: spec.effective_trust_tier,
        sink_class: SinkClass::NetworkEgress,
        containment_mode: spec.containment_mode,
        semantic_taint: spec.semantic_taint,
        extra_risk: spec.extra_risk,
    })
}

pub(super) fn rug_pull_security_context(action: &Action) -> RuntimeSecurityContext {
    guard_security_context(
        action,
        GuardSecurityContextSpec {
            lineage_id: "rug_pull",
            observed_channel: None,
            source: "rug_pull_tool_blocked",
            effective_trust_tier: TrustTier::Quarantined,
            containment_mode: vellaveto_types::ContainmentMode::Quarantine,
            semantic_taint: vec![
                SemanticTaint::Untrusted,
                SemanticTaint::IntegrityFailed,
                SemanticTaint::Quarantined,
            ],
            extra_risk: 30,
        },
    )
}

pub(super) fn protocol_forward_security_context(source: &'static str) -> RuntimeSecurityContext {
    protocol_forward_channel_security_context(source, ContextChannel::Data)
}

pub(super) fn protocol_forward_channel_security_context(
    source: &'static str,
    observed_channel: ContextChannel,
) -> RuntimeSecurityContext {
    network_security_context(NetworkSecurityContextSpec {
        lineage_id: source,
        observed_channel,
        source,
        effective_trust_tier: TrustTier::Unknown,
        containment_mode: vellaveto_types::ContainmentMode::Observe,
        semantic_taint: Vec::new(),
        extra_risk: 0,
    })
}

pub(super) fn protocol_message_forward_security_context(
    message: &Value,
    source: &'static str,
) -> RuntimeSecurityContext {
    protocol_forward_channel_security_context(source, message_payload_observed_channel(message))
}

pub(super) fn session_termination_security_context() -> RuntimeSecurityContext {
    explicit_security_context(ExplicitSecurityContextSpec {
        lineage_id: "session_terminated",
        observed_channel: ContextChannel::Memory,
        source: "session_terminated",
        effective_trust_tier: TrustTier::High,
        sink_class: SinkClass::MemoryWrite,
        containment_mode: vellaveto_types::ContainmentMode::Observe,
        semantic_taint: Vec::new(),
        extra_risk: 0,
    })
}

pub(super) fn invalid_call_chain_security_context() -> RuntimeSecurityContext {
    network_security_context(NetworkSecurityContextSpec {
        lineage_id: "invalid_call_chain_header",
        observed_channel: ContextChannel::Data,
        source: "invalid_call_chain_header",
        effective_trust_tier: TrustTier::Quarantined,
        containment_mode: vellaveto_types::ContainmentMode::Quarantine,
        semantic_taint: vec![SemanticTaint::IntegrityFailed, SemanticTaint::Quarantined],
        extra_risk: 20,
    })
}

pub(super) fn oauth_dpop_failure_security_context(
    dpop_reason: &str,
    has_dpop_header: bool,
) -> RuntimeSecurityContext {
    let quarantined = has_dpop_header && dpop_reason != "missing_proof";

    network_security_context(NetworkSecurityContextSpec {
        lineage_id: "oauth_dpop_validation_failed",
        observed_channel: ContextChannel::Data,
        source: "oauth_dpop_validation_failed",
        effective_trust_tier: if quarantined {
            TrustTier::Quarantined
        } else {
            TrustTier::Unknown
        },
        containment_mode: if quarantined {
            vellaveto_types::ContainmentMode::Quarantine
        } else {
            vellaveto_types::ContainmentMode::Enforce
        },
        semantic_taint: if quarantined {
            vec![SemanticTaint::IntegrityFailed, SemanticTaint::Quarantined]
        } else {
            Vec::new()
        },
        extra_risk: if quarantined { 20 } else { 10 },
    })
}

pub(super) fn protocol_rejection_security_context(source: &'static str) -> RuntimeSecurityContext {
    network_security_context(NetworkSecurityContextSpec {
        lineage_id: source,
        observed_channel: ContextChannel::Data,
        source,
        effective_trust_tier: TrustTier::Quarantined,
        containment_mode: vellaveto_types::ContainmentMode::Quarantine,
        semantic_taint: vec![SemanticTaint::Untrusted, SemanticTaint::Quarantined],
        extra_risk: 15,
    })
}

pub(super) fn protocol_binary_rejection_security_context(
    source: &'static str,
) -> RuntimeSecurityContext {
    protocol_rejection_security_context(source)
}

pub(super) fn protocol_rate_limit_security_context(source: &'static str) -> RuntimeSecurityContext {
    network_security_context(NetworkSecurityContextSpec {
        lineage_id: source,
        observed_channel: ContextChannel::Data,
        source,
        effective_trust_tier: TrustTier::Unknown,
        containment_mode: vellaveto_types::ContainmentMode::Enforce,
        semantic_taint: Vec::new(),
        extra_risk: 10,
    })
}

pub(super) fn circuit_breaker_security_context(action: &Action) -> RuntimeSecurityContext {
    guard_security_context(
        action,
        GuardSecurityContextSpec {
            lineage_id: "circuit_breaker",
            observed_channel: None,
            source: "circuit_breaker_rejected",
            effective_trust_tier: TrustTier::Unknown,
            containment_mode: vellaveto_types::ContainmentMode::Enforce,
            semantic_taint: Vec::new(),
            extra_risk: 10,
        },
    )
}

pub(super) fn transport_failure_security_context(
    action: &Action,
    source: &'static str,
) -> RuntimeSecurityContext {
    guard_security_context(
        action,
        GuardSecurityContextSpec {
            lineage_id: source,
            observed_channel: None,
            source,
            effective_trust_tier: TrustTier::Unknown,
            containment_mode: vellaveto_types::ContainmentMode::Enforce,
            semantic_taint: Vec::new(),
            extra_risk: 15,
        },
    )
}

pub(super) fn privilege_escalation_security_context(action: &Action) -> RuntimeSecurityContext {
    guard_security_context(
        action,
        GuardSecurityContextSpec {
            lineage_id: "privilege_escalation",
            observed_channel: None,
            source: "privilege_escalation_blocked",
            effective_trust_tier: TrustTier::Low,
            containment_mode: vellaveto_types::ContainmentMode::Enforce,
            semantic_taint: vec![SemanticTaint::Untrusted],
            extra_risk: 25,
        },
    )
}

pub(super) fn abac_deny_security_context(action: &Action) -> RuntimeSecurityContext {
    guard_security_context(
        action,
        GuardSecurityContextSpec {
            lineage_id: "abac_deny",
            observed_channel: None,
            source: "abac_deny",
            effective_trust_tier: TrustTier::Unknown,
            containment_mode: vellaveto_types::ContainmentMode::Enforce,
            semantic_taint: Vec::new(),
            extra_risk: 5,
        },
    )
}

pub(super) fn sampling_interception_security_context(action: &Action) -> RuntimeSecurityContext {
    guard_security_context(
        action,
        GuardSecurityContextSpec {
            lineage_id: "sampling_interception",
            observed_channel: Some(ContextChannel::FreeText),
            source: "sampling_interception",
            effective_trust_tier: TrustTier::Unknown,
            containment_mode: vellaveto_types::ContainmentMode::Enforce,
            semantic_taint: vec![SemanticTaint::Untrusted],
            extra_risk: 15,
        },
    )
}

pub(super) fn elicitation_interception_security_context(action: &Action) -> RuntimeSecurityContext {
    guard_security_context(
        action,
        GuardSecurityContextSpec {
            lineage_id: "elicitation_interception",
            observed_channel: Some(ContextChannel::ApprovalPrompt),
            source: "elicitation_interception",
            effective_trust_tier: TrustTier::Unknown,
            containment_mode: vellaveto_types::ContainmentMode::Enforce,
            semantic_taint: vec![SemanticTaint::Untrusted],
            extra_risk: 20,
        },
    )
}

pub(super) fn batch_rejection_security_context(action: &Action) -> RuntimeSecurityContext {
    guard_security_context(
        action,
        GuardSecurityContextSpec {
            lineage_id: "batch_rejected",
            observed_channel: Some(ContextChannel::FreeText),
            source: "batch_rejected",
            effective_trust_tier: TrustTier::Unknown,
            containment_mode: vellaveto_types::ContainmentMode::Enforce,
            semantic_taint: Vec::new(),
            extra_risk: 10,
        },
    )
}

pub(super) fn unknown_tool_approval_gate_security_context(
    action: &Action,
) -> RuntimeSecurityContext {
    guard_security_context(
        action,
        GuardSecurityContextSpec {
            lineage_id: "unknown_tool_approval_gate",
            observed_channel: None,
            source: "unknown_tool_approval_gate",
            effective_trust_tier: TrustTier::Unknown,
            containment_mode: vellaveto_types::ContainmentMode::RequireApproval,
            semantic_taint: Vec::new(),
            extra_risk: 15,
        },
    )
}

pub(super) fn untrusted_tool_approval_gate_security_context(
    action: &Action,
) -> RuntimeSecurityContext {
    guard_security_context(
        action,
        GuardSecurityContextSpec {
            lineage_id: "untrusted_tool_approval_gate",
            observed_channel: None,
            source: "untrusted_tool_approval_gate",
            effective_trust_tier: TrustTier::Untrusted,
            containment_mode: vellaveto_types::ContainmentMode::RequireApproval,
            semantic_taint: vec![SemanticTaint::Untrusted],
            extra_risk: 20,
        },
    )
}

pub(super) fn invalid_presented_approval_security_context(
    action: &Action,
) -> RuntimeSecurityContext {
    guard_security_context(
        action,
        GuardSecurityContextSpec {
            lineage_id: "approval_scope_mismatch",
            observed_channel: Some(ContextChannel::ApprovalPrompt),
            source: "presented_approval_invalid",
            effective_trust_tier: TrustTier::Quarantined,
            containment_mode: vellaveto_types::ContainmentMode::Quarantine,
            semantic_taint: vec![SemanticTaint::IntegrityFailed, SemanticTaint::Quarantined],
            extra_risk: 25,
        },
    )
}

#[cfg(any(feature = "grpc", test))]
pub(super) fn require_approval_security_context(action: &Action) -> RuntimeSecurityContext {
    guard_security_context(
        action,
        GuardSecurityContextSpec {
            lineage_id: "require_approval",
            observed_channel: None,
            source: "require_approval",
            effective_trust_tier: TrustTier::Unknown,
            containment_mode: vellaveto_types::ContainmentMode::RequireApproval,
            semantic_taint: Vec::new(),
            extra_risk: 15,
        },
    )
}

pub(super) fn approval_containment_context_from_security_context(
    security_context: &RuntimeSecurityContext,
    reason: &str,
) -> Option<ApprovalContainmentContext> {
    let provenance_summary =
        review_safe_provenance_summary(security_context.client_provenance.as_ref());
    let context = ApprovalContainmentContext {
        semantic_taint: security_context.semantic_taint.clone(),
        lineage_channels: security_context
            .lineage_refs
            .iter()
            .map(|lineage| lineage.channel)
            .collect(),
        effective_trust_tier: security_context.effective_trust_tier,
        sink_class: security_context.sink_class,
        containment_mode: security_context.containment_mode,
        semantic_risk_score: security_context.semantic_risk_score,
        signature_status: provenance_summary.signature_status,
        client_key_id: provenance_summary.client_key_id,
        workload_binding_status: provenance_summary.workload_binding_status,
        replay_status: provenance_summary.replay_status,
        session_key_scope: provenance_summary.session_key_scope,
        session_scope_binding: provenance_summary.session_scope_binding,
        canonical_request_hash: provenance_summary.canonical_request_hash,
        execution_is_ephemeral: provenance_summary.execution_is_ephemeral,
        counterfactual_review_required: reason.contains("counterfactual review required"),
    }
    .normalized();

    context.is_meaningful().then_some(context)
}

pub(super) fn approval_containment_context_from_envelope(
    envelope: &AcisDecisionEnvelope,
    reason: &str,
) -> Option<ApprovalContainmentContext> {
    let provenance_summary = review_safe_provenance_summary(envelope.client_provenance.as_ref());
    let context = ApprovalContainmentContext {
        semantic_taint: envelope.semantic_taint.clone(),
        lineage_channels: envelope
            .lineage_refs
            .iter()
            .map(|lineage| lineage.channel)
            .collect(),
        effective_trust_tier: envelope.effective_trust_tier,
        sink_class: envelope.sink_class,
        containment_mode: envelope.containment_mode,
        semantic_risk_score: envelope.semantic_risk_score,
        signature_status: provenance_summary.signature_status,
        client_key_id: provenance_summary.client_key_id,
        workload_binding_status: provenance_summary.workload_binding_status,
        replay_status: provenance_summary.replay_status,
        session_key_scope: provenance_summary.session_key_scope,
        session_scope_binding: provenance_summary.session_scope_binding,
        canonical_request_hash: provenance_summary.canonical_request_hash,
        execution_is_ephemeral: provenance_summary.execution_is_ephemeral,
        counterfactual_review_required: reason.contains("counterfactual review required"),
    }
    .normalized();

    context.is_meaningful().then_some(context)
}

/// Extract a presented approval ID from a JSON-RPC message `_meta`.
///
/// Accepts both top-level `_meta` and nested `params._meta`, matching the
/// stdio relay path. Length-capped and control-char filtered so malformed
/// approval IDs fail closed before any store lookup.
pub(super) fn extract_approval_id_from_meta(msg: &Value) -> Option<String> {
    vellaveto_approval::extract_presented_approval_id_from_rpc_meta(msg)
}

/// Validate a presented approval against the current proxy session and action.
pub(super) async fn presented_approval_matches_action(
    state: &ProxyState,
    session_id: &str,
    presented_approval_id: Option<&str>,
    action: &Action,
) -> Result<Option<String>, ()> {
    let Some(approval_id) = presented_approval_id else {
        return Ok(None);
    };

    let Some(store) = state.approval_store.as_ref() else {
        tracing::warn!(
            approval_id = %approval_id,
            "Presented approval cannot be verified without an approval store"
        );
        return Err(());
    };

    let approval = match store.get(approval_id).await {
        Ok(approval) => approval,
        Err(e) => {
            tracing::warn!(
                approval_id = %approval_id,
                error = ?e,
                "Presented approval lookup failed"
            );
            return Err(());
        }
    };

    if approval.status != ApprovalStatus::Approved {
        tracing::warn!(
            approval_id = %approval_id,
            status = ?approval.status,
            "Presented approval is not approved"
        );
        return Err(());
    }

    // Fail closed on approvals that predate action-fingerprint binding.
    if approval.action_fingerprint.is_none() {
        tracing::warn!(
            approval_id = %approval_id,
            "Presented approval missing action fingerprint binding"
        );
        return Err(());
    }

    let action_fingerprint = fingerprint_action(action);
    let session_scope_binding = state
        .sessions
        .get(session_id)
        .map(|session| session.session_scope_binding.clone())
        .ok_or(())?;
    if !approval.scope_matches(
        Some(session_scope_binding.as_str()),
        Some(action_fingerprint.as_str()),
    ) {
        tracing::warn!(
            approval_id = %approval_id,
            session_id = %session_id,
            "Presented approval scope does not match the current proxy session and action"
        );
        return Err(());
    }

    Ok(Some(approval_id.to_string()))
}

/// Consume a presented approval once the request is about to be forwarded.
pub(super) async fn consume_presented_approval(
    state: &ProxyState,
    session_id: &str,
    approval_id: Option<&str>,
    action: &Action,
    security_context: Option<&RuntimeSecurityContext>,
) -> Result<(), ()> {
    let Some(approval_id) = approval_id else {
        return Ok(());
    };

    let Some(store) = state.approval_store.as_ref() else {
        tracing::warn!(
            approval_id = %approval_id,
            "Presented approval cannot be consumed without an approval store"
        );
        return Err(());
    };

    let action_fingerprint = fingerprint_action(action);
    let session_scope_binding = state
        .sessions
        .get(session_id)
        .map(|session| session.session_scope_binding.clone())
        .ok_or(())?;
    let approval = match store.get(approval_id).await {
        Ok(approval) => approval,
        Err(e) => {
            tracing::warn!(
                approval_id = %approval_id,
                error = ?e,
                "Presented approval lookup failed during consume"
            );
            return Err(());
        }
    };
    if let Some(ref containment_context) = approval.containment_context {
        if !containment_context.stable_provenance_satisfied_by(security_context) {
            tracing::warn!(
                approval_id = %approval_id,
                session_id = %session_id,
                "Presented approval provenance summary does not match current transport provenance"
            );
            return Err(());
        }
    }
    match store
        .consume_approved(
            approval_id,
            Some(session_scope_binding.as_str()),
            Some(action_fingerprint.as_str()),
        )
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => {
            tracing::warn!(
                approval_id = %approval_id,
                session_id = %session_id,
                "Presented approval could not be consumed for this proxy session and action"
            );
            Err(())
        }
        Err(e) => {
            tracing::warn!(
                approval_id = %approval_id,
                error = ?e,
                "Presented approval consume failed"
            );
            Err(())
        }
    }
}

pub(super) async fn create_pending_approval_with_context(
    state: &ProxyState,
    session_id: &str,
    action: &Action,
    reason: &str,
    containment_context: Option<ApprovalContainmentContext>,
) -> Option<String> {
    let store = state.approval_store.as_ref()?;
    let (requested_by, session_scope_binding) = state
        .sessions
        .get(session_id)
        .map(|session| {
            (
                session
                    .agent_identity
                    .as_ref()
                    .and_then(|identity| identity.subject.clone())
                    .or_else(|| session.oauth_subject.clone()),
                session.session_scope_binding.clone(),
            )
        })
        .map_or((None, None), |(requested_by, binding)| {
            (requested_by, Some(binding))
        });
    match store
        .create_with_context(
            action.clone(),
            reason.to_string(),
            requested_by,
            session_scope_binding,
            Some(fingerprint_action(action)),
            containment_context,
        )
        .await
    {
        Ok(id) => Some(id),
        Err(error) => {
            tracing::error!(
                session_id = %session_id,
                error = %error,
                "Failed to create pending approval with containment context"
            );
            None
        }
    }
}

/// Read a response body with a size limit to prevent OOM.
///
/// Uses chunked reading so oversized responses are rejected before fully
/// buffering into memory. This prevents a malicious or misconfigured upstream
/// from sending an infinite SSE stream or oversized JSON response.
pub(super) async fn read_bounded_response(
    mut resp: reqwest::Response,
    max_size: usize,
) -> Result<Bytes, String> {
    // Fast path: if Content-Length is known and exceeds limit, reject immediately
    if let Some(len) = resp.content_length() {
        // SECURITY (R240-P3-PROXY-1): Compare in u64 space to avoid truncation on 32-bit.
        if len > max_size as u64 {
            return Err(format!("Response too large: {len} bytes (max {max_size})"));
        }
    }

    let capacity = std::cmp::min(
        resp.content_length()
            .map(|l| l.min(max_size as u64) as usize)
            .unwrap_or(8192),
        max_size,
    );
    let mut body = Vec::with_capacity(capacity);

    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        // SECURITY (FIND-R74-001): Use saturating_add to prevent theoretical overflow.
        if body.len().saturating_add(chunk.len()) > max_size {
            return Err(format!("Response exceeded {max_size} byte limit"));
        }
        body.extend_from_slice(&chunk);
    }

    Ok(Bytes::from(body))
}

// Message classification and action extraction use the shared
// vellaveto_mcp::extractor module to ensure identical behavior
// between the stdio and HTTP proxies (Challenge 3 fix).

const MAX_MCP_PARAM_SCHEMA_PROPERTIES: usize = 256;
const MAX_MCP_PARAM_SCHEMA_HEADERS_PER_TOOL: usize = 32;

fn is_primitive_mcp_header_type(property_schema: &Value) -> bool {
    matches!(
        property_schema.get("type").and_then(Value::as_str),
        Some("string" | "number" | "integer" | "boolean")
    )
}

fn extract_mcp_param_header_bindings_from_response(
    response: &Value,
) -> Option<HashMap<String, ToolParamHeaderBindings>> {
    let tools = response
        .get("result")
        .and_then(|result| result.get("tools"))
        .and_then(Value::as_array)?;
    let mut bindings = HashMap::new();

    for tool in tools {
        let Some(name) = tool.get("name").and_then(Value::as_str) else {
            continue;
        };
        let normalized_name = vellaveto_mcp::extractor::normalize_method(name);
        if normalized_name.is_empty() {
            continue;
        }

        let mut header_names = HashSet::new();
        let mut rejected_reason = None;
        let properties = tool
            .get("inputSchema")
            .and_then(|schema| schema.get("properties"))
            .and_then(Value::as_object);

        if let Some(properties) = properties {
            if properties.len() > MAX_MCP_PARAM_SCHEMA_PROPERTIES {
                rejected_reason = Some(format!(
                    "inputSchema.properties exceeds {MAX_MCP_PARAM_SCHEMA_PROPERTIES} entries"
                ));
            } else {
                for (property_name, property_schema) in properties {
                    let Some(header_name) =
                        property_schema.get("x-mcp-header").and_then(Value::as_str)
                    else {
                        continue;
                    };

                    if let Err(reason) =
                        vellaveto_config::validate_mcp_param_header_name(header_name)
                    {
                        rejected_reason =
                            Some(format!("{property_name} x-mcp-header invalid: {reason}"));
                        break;
                    }
                    if !is_primitive_mcp_header_type(property_schema) {
                        rejected_reason = Some(format!(
                            "{property_name} x-mcp-header is only valid on primitive types"
                        ));
                        break;
                    }
                    if header_names.len() >= MAX_MCP_PARAM_SCHEMA_HEADERS_PER_TOOL {
                        rejected_reason = Some(format!(
                            "x-mcp-header count exceeds {MAX_MCP_PARAM_SCHEMA_HEADERS_PER_TOOL}"
                        ));
                        break;
                    }
                    let normalized_header = header_name.to_ascii_lowercase();
                    if !header_names.insert(normalized_header) {
                        rejected_reason = Some(format!(
                            "{property_name} x-mcp-header duplicates another header name"
                        ));
                        break;
                    }
                }
            }
        }

        let entry = match rejected_reason {
            Some(reason) => ToolParamHeaderBindings::Rejected(reason),
            None => ToolParamHeaderBindings::Valid(header_names),
        };
        bindings.insert(normalized_name, entry);
    }

    Some(bindings)
}

/// Extract tool annotations from a tools/list response and update session state.
///
/// Delegates to the shared `vellaveto_mcp::rug_pull` module for detection logic,
/// then updates session state and audits any detected events.
pub(super) async fn extract_annotations_from_response(
    response: &Value,
    session_id: &str,
    sessions: &SessionStore,
    audit: &AuditLogger,
    known_tools: &std::collections::HashSet<String>,
) {
    let param_header_bindings = extract_mcp_param_header_bindings_from_response(response);

    // Extract current known tools and first-list flag from session
    let (known, is_first_list) = match sessions.get_mut(session_id) {
        Some(mut s) => {
            let first = !s.tools_list_seen;
            s.tools_list_seen = true;
            (s.known_tools.clone(), first)
        }
        None => return,
    };

    // Run shared detection algorithm with squatting detection
    let result = vellaveto_mcp::rug_pull::detect_rug_pull_and_squatting(
        response,
        &known,
        is_first_list,
        known_tools,
    );

    // Update session state with detection results
    // SECURITY (FIND-R52-SESSION-001): Use bounded `insert_known_tool` instead of
    // direct assignment to enforce the MAX_KNOWN_TOOLS capacity limit.
    if let Some(mut s) = sessions.get_mut(session_id) {
        // Clear existing tools first, then re-insert through bounded method.
        // This ensures the updated set respects capacity limits.
        s.known_tools.clear();
        for (name, annotations) in &result.updated_known {
            if !s.insert_known_tool(name.clone(), annotations.clone()) {
                tracing::warn!(
                    session_id = %session_id,
                    "Known tools capacity reached during rug-pull update; truncating"
                );
                break;
            }
        }
        if let Some(bindings) = param_header_bindings {
            s.tool_param_header_bindings.clear();
            for (name, binding) in bindings {
                if !s.insert_tool_param_header_bindings(name, binding) {
                    tracing::warn!(
                        session_id = %session_id,
                        "Tool parameter-header binding capacity reached during tools/list update; truncating"
                    );
                    break;
                }
            }
        }
        for name in result.flagged_tool_names() {
            // SECURITY (FIND-R51-014): Use bounded insertion for flagged tools.
            s.insert_flagged_tool(name.to_string());
            // SECURITY (R240-PROXY-1): Also record in global registry so the flag
            // survives session eviction (timeout or capacity pressure).
            sessions.flag_tool_globally(name.to_string());
        }
    }

    // Audit any detected events
    vellaveto_mcp::rug_pull::audit_rug_pull_events(&result, audit, "http_proxy").await;
}

/// Verify a tools/list response against the session's pinned manifest.
///
/// On the first tools/list response, builds and pins the manifest.
/// On subsequent responses, verifies against the pinned manifest and
/// audits any discrepancies.
pub(super) async fn verify_manifest_from_response(
    response: &Value,
    session_id: &str,
    sessions: &SessionStore,
    manifest_config: &ManifestConfig,
    audit: &AuditLogger,
) {
    if !manifest_config.enabled {
        return;
    }

    // Check if we already have a pinned manifest
    let has_pinned = sessions
        .get_mut(session_id)
        .map(|s| s.pinned_manifest.is_some())
        .unwrap_or(false);

    if !has_pinned {
        // First tools/list: pin the manifest
        if let Some(manifest) = ToolManifest::from_tools_list(response) {
            tracing::info!(
                "Session {}: pinned tool manifest ({} tools)",
                session_id,
                manifest.tools.len()
            );
            if let Some(mut s) = sessions.get_mut(session_id) {
                s.pinned_manifest = Some(manifest);
            }
        }
    } else {
        // Subsequent tools/list: verify against pinned
        let pinned = sessions
            .get_mut(session_id)
            .and_then(|s| s.pinned_manifest.clone());

        if let Some(pinned) = pinned {
            if let Err(discrepancies) = manifest_config.verify_manifest(&pinned, response) {
                tracing::warn!(
                    "SECURITY: Session {}: tool manifest verification FAILED: {:?}",
                    session_id,
                    discrepancies
                );
                let action = Action::new(
                    "vellaveto",
                    "manifest_verification",
                    serde_json::json!({
                        "session": session_id,
                        "discrepancies": discrepancies,
                        "pinned_tool_count": pinned.tools.len(),
                    }),
                );
                let manifest_verdict = Verdict::Deny {
                    reason: format!("Manifest verification failed: {discrepancies:?}"),
                };
                let manifest_security_context = tool_discovery_integrity_security_context(
                    "manifest_verification",
                    ContextChannel::ToolOutput,
                    "manifest_verification_failed",
                    false,
                );
                let envelope = build_secondary_acis_envelope_with_security_context(
                    &action,
                    &manifest_verdict,
                    DecisionOrigin::PolicyEngine,
                    "http",
                    Some(session_id),
                    Some(&manifest_security_context),
                );
                if let Err(e) = audit
                    .log_entry_with_acis(
                        &action,
                        &manifest_verdict,
                        serde_json::json!({
                            "source": "http_proxy",
                            "event": "manifest_verification_failed",
                        }),
                        envelope,
                    )
                    .await
                {
                    tracing::warn!("Failed to audit manifest failure: {}", e);
                }
            }
        }
    }
}

/// Feed a `tools/list` response into the discovery engine.
///
/// The stdio relay has done this since R24-MCP-1
/// (`vellaveto-mcp/src/proxy/bridge/relay.rs`); the HTTP-family transports
/// constructed a `DiscoveryEngine` and never fed it, so topology discovery
/// silently indexed nothing outside stdio. Call this wherever a transport
/// registers output schemas from a tools/list response, so the two stay in step.
///
/// `ingest_tools_list` ignores payloads without a `tools` array, so this is safe
/// to call on any response. Indexing is advisory: a failure is logged and the
/// response proceeds, matching the relay.
///
/// A no-op without the `discovery` feature, so call sites need no cfg of their own.
#[cfg(feature = "discovery")]
pub(super) fn ingest_tools_for_discovery(state: &ProxyState, response_json: &Value) {
    let Some(ref engine) = state.discovery_engine else {
        return;
    };
    let Some(result_value) = response_json.get("result") else {
        return;
    };
    // Identify the server by its upstream URL — the only stable server-scoped
    // identifier the HTTP transports share.
    let server_id = state.upstream_url.as_str();
    match engine.ingest_tools_list(server_id, result_value) {
        Ok(count) => {
            if count > 0 {
                tracing::debug!(
                    server_id = server_id,
                    count = count,
                    "Discovery engine ingested tools from tools/list response"
                );
            }
        }
        Err(e) => {
            // Advisory only — don't block the response on indexing failure.
            tracing::warn!(
                server_id = server_id,
                error = %e,
                "Discovery engine failed to ingest tools/list response"
            );
        }
    }
}

/// No-op stand-in when the `discovery` feature is off, so the transport call
/// sites stay identical across feature combinations.
#[cfg(not(feature = "discovery"))]
pub(super) fn ingest_tools_for_discovery(_state: &ProxyState, _response_json: &Value) {}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`), kernel
    //! `formal/verus/verified_replay_provenance.rs`.
    //!
    //! `merge_replay_status` gets a TOTAL discharge over all nine ordered pairs
    //! of `ReplayStatus`, plus the lattice properties the kernel proves: the
    //! merge is commutative, idempotent, and absorbing at `ReplayDetected`.
    //!
    //! The trust rule is bound where it is actually enforced. The kernel maps
    //! `ReplayDetected` to rank 0 (`Quarantined`); production does that inside
    //! `infer_trust_tier` rather than in a standalone function, so the binding
    //! drives `infer_trust_tier` with a context carrying each status.
    //!
    //! The kernel also caps `NotChecked` at rank 1 (`Unknown`). Production
    //! returns `None` there — no tier inferred, so no cap applied. That half is
    //! pinned rather than bound; see `REPLAY-NOTCHECKED-1` in the registry.

    use super::*;

    const ALL_STATUSES: [ReplayStatus; 3] = [
        ReplayStatus::NotChecked,
        ReplayStatus::Fresh,
        ReplayStatus::ReplayDetected,
    ];

    fn spec_replay_rank(s: ReplayStatus) -> u8 {
        match s {
            ReplayStatus::NotChecked => 0,
            ReplayStatus::Fresh => 1,
            ReplayStatus::ReplayDetected => 2,
        }
    }

    fn spec_merge_replay(a: ReplayStatus, b: ReplayStatus) -> ReplayStatus {
        match (a, b) {
            (ReplayStatus::ReplayDetected, _) | (_, ReplayStatus::ReplayDetected) => {
                ReplayStatus::ReplayDetected
            }
            (ReplayStatus::Fresh, _) | (_, ReplayStatus::Fresh) => ReplayStatus::Fresh,
            _ => ReplayStatus::NotChecked,
        }
    }

    fn spec_effective_trust_rank(replay_status: ReplayStatus, base_trust_rank: u8) -> u8 {
        match replay_status {
            ReplayStatus::ReplayDetected => 0,
            ReplayStatus::NotChecked => {
                if base_trust_rank > 1 {
                    1
                } else {
                    base_trust_rank
                }
            }
            ReplayStatus::Fresh => base_trust_rank,
        }
    }

    fn context_with(status: ReplayStatus) -> RuntimeSecurityContext {
        RuntimeSecurityContext {
            client_provenance: Some(ClientProvenance {
                replay_status: status,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn test_merge_replay_matches_verus_spec_total_domain() {
        let mut checked = 0usize;
        for a in ALL_STATUSES {
            for b in ALL_STATUSES {
                assert_eq!(
                    merge_replay_status(a, b),
                    spec_merge_replay(a, b),
                    "PARITY-HAND-1: merge_replay_status disagrees at ({a:?}, {b:?})"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 9, "total domain is 3x3; enumeration collapsed");
    }

    /// A merge that is not absorbing at `ReplayDetected` would let a later
    /// clean transport observation launder a detected replay.
    #[test]
    fn test_merge_is_commutative_idempotent_and_absorbing() {
        for a in ALL_STATUSES {
            assert_eq!(
                merge_replay_status(a, a),
                a,
                "PARITY-HAND-1: merge is not idempotent at {a:?}"
            );
            assert_eq!(
                merge_replay_status(a, ReplayStatus::ReplayDetected),
                ReplayStatus::ReplayDetected,
                "PARITY-HAND-1: a detected replay was laundered by merging {a:?} into it"
            );
            for b in ALL_STATUSES {
                assert_eq!(
                    merge_replay_status(a, b),
                    merge_replay_status(b, a),
                    "PARITY-HAND-1: merge is not commutative at ({a:?}, {b:?})"
                );
                let merged = spec_replay_rank(merge_replay_status(a, b));
                assert!(
                    merged >= spec_replay_rank(a) && merged >= spec_replay_rank(b),
                    "PARITY-HAND-1: merging ({a:?}, {b:?}) lowered the replay rank"
                );
            }
        }
    }

    #[test]
    fn test_replay_detected_quarantines_in_infer_trust_tier() {
        assert_eq!(
            infer_trust_tier(&context_with(ReplayStatus::ReplayDetected), None, None),
            Some(TrustTier::Quarantined),
            "PARITY-HAND-1: a detected replay was not quarantined — the containment the kernel \
             proves did not reach production"
        );
        assert_eq!(
            spec_effective_trust_rank(ReplayStatus::ReplayDetected, 6),
            0,
            "PARITY-HAND-1: the kernel must map ReplayDetected to rank 0"
        );
    }

    /// REPLAY-NOTCHECKED-1, pinned. Measured behaviour: `NotChecked` and
    /// `Fresh` both yield `None` from `infer_trust_tier`, so no cap is applied
    /// for an unverified replay status, while the kernel caps it at `Unknown`.
    /// Asserted rather than skipped, so this fails if either side moves —
    /// including if the gap closes.
    #[test]
    fn test_pinned_notchecked_cap_is_kernel_only() {
        assert_eq!(
            spec_effective_trust_rank(ReplayStatus::NotChecked, 6),
            1,
            "REPLAY-NOTCHECKED-1: the kernel is expected to cap NotChecked at Unknown"
        );
        assert_eq!(
            infer_trust_tier(&context_with(ReplayStatus::NotChecked), None, None),
            None,
            "REPLAY-NOTCHECKED-1: production is expected to infer no tier for NotChecked, so no \
             cap is applied. If this changed, re-check whether the gap closed and bind that half."
        );
        assert_eq!(
            infer_trust_tier(&context_with(ReplayStatus::Fresh), None, None),
            None,
            "REPLAY-NOTCHECKED-1: production is expected to infer no tier for Fresh"
        );
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        assert_eq!(
            spec_merge_replay(ReplayStatus::Fresh, ReplayStatus::ReplayDetected),
            ReplayStatus::ReplayDetected
        );
        assert_eq!(
            spec_merge_replay(ReplayStatus::NotChecked, ReplayStatus::Fresh),
            ReplayStatus::Fresh
        );
        assert_eq!(
            spec_merge_replay(ReplayStatus::NotChecked, ReplayStatus::NotChecked),
            ReplayStatus::NotChecked
        );
        assert_eq!(spec_effective_trust_rank(ReplayStatus::Fresh, 6), 6);
        assert_eq!(
            spec_effective_trust_rank(ReplayStatus::ReplayDetected, 6),
            0
        );
    }
}
