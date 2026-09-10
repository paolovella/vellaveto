// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! MCP stdio proxy bridge.
//!
//! Sits between an agent (stdin/stdout) and a child MCP server (spawned subprocess).
//! Intercepts `tools/call` requests, evaluates them against policies, and either
//! forwards allowed calls or returns denial responses directly.

mod builder;
mod evaluation;
mod helpers;
mod relay;
#[cfg(test)]
mod tests;

use vellaveto_approval::ApprovalStore;
use vellaveto_audit::AuditLogger;
use vellaveto_config::ManifestConfig;
use vellaveto_engine::circuit_breaker::CircuitBreakerManager;
use vellaveto_engine::deputy::DeputyValidator;
use vellaveto_engine::PolicyEngine;
use vellaveto_types::Policy;

use crate::auth_level::AuthLevelTracker;
use crate::inspection::InjectionScanner;
use crate::mediation::MediationConfig;
use crate::output_validation::OutputSchemaRegistry;
pub use crate::rug_pull::ToolAnnotations;
use crate::sampling_detector::SamplingDetector;
use crate::schema_poisoning::SchemaLineageTracker;
use crate::shadow_agent::ShadowAgentDetector;
use crate::task_state::TaskStateManager;

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Default request timeout: 30 seconds.
/// Callback type for lightweight verdict notifications (desktop app integration).
/// Arguments: (tool, method, verdict, reason).
pub type VerdictNotifyFn = dyn Fn(&str, &str, &str, &str) + Send + Sync;

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The proxy bridge that sits between agent and child MCP server.
pub struct ProxyBridge {
    engine: PolicyEngine,
    policies: Vec<Policy>,
    audit: Arc<AuditLogger>,
    /// When true, an audit write failure denies the request instead of being
    /// logged and ignored.
    ///
    /// SECURITY (R271-MCP-1): `audit.strict_mode` promises that "audit logging
    /// failures cause requests to be denied instead of proceeding without an
    /// audit trail … every decision must be recorded". The HTTP transports
    /// honour it; the stdio relay had no notion of it at all, so the same
    /// setting meant different things depending on how an agent connected.
    audit_strict_mode: bool,
    request_timeout: Duration,
    enable_trace: bool,
    /// Optional custom injection scanner. When `None`, uses the default
    /// patterns via `scan_response_for_injection()`.
    injection_scanner: Option<InjectionScanner>,
    /// When true, injection scanning is completely disabled.
    injection_disabled: bool,
    /// When true, injection matches block the response instead of just logging (H4).
    injection_blocking: bool,
    /// Optional approval store for RequireApproval verdicts.
    approval_store: Option<Arc<ApprovalStore>>,
    /// Optional manifest verification config. When set, the first tools/list
    /// response is pinned and subsequent responses are verified against it.
    manifest_config: Option<ManifestConfig>,
    /// Optional path for persisting flagged (rug-pulled) tool names as JSONL.
    /// When set, flagged tools are appended to this file and loaded on startup.
    flagged_tools_path: Option<PathBuf>,
    /// Output schema registry for structuredContent validation (MCP 2025-06-18).
    /// Populated from tools/list responses, validated on tools/call responses.
    output_schema_registry: Arc<OutputSchemaRegistry>,
    /// When true, block responses that fail output schema validation.
    /// Default: true (fail-closed).
    /// SECURITY (R233-MCPSEC-8): Changed from false to true — schema validation
    /// bypass is fail-open; operators must explicitly opt out via builder.
    output_schema_blocking: bool,
    /// When true, scan tool responses for secrets (DLP response scanning).
    /// Default: true.
    response_dlp_enabled: bool,
    /// When true, block responses containing secrets. Default: false (log-only).
    response_dlp_blocking: bool,
    /// Known legitimate tool names for squatting detection.
    /// Built from DEFAULT_KNOWN_TOOLS + any config overrides.
    known_tools: HashSet<String>,
    /// Elicitation interception configuration (MCP 2025-06-18).
    /// Controls whether `elicitation/create` requests are allowed or blocked.
    elicitation_config: vellaveto_config::ElicitationConfig,
    /// Sampling request policy configuration.
    /// Controls whether `sampling/createMessage` requests are allowed or blocked.
    sampling_config: vellaveto_config::SamplingConfig,
    /// Tool registry for tracking tool trust scores (P2.1).
    /// None when tool registry is disabled.
    tool_registry: Option<Arc<crate::tool_registry::ToolRegistry>>,
    /// Canonical mediation settings used by the stdio bridge after the relay's
    /// transport-specific prechecks have run.
    mediation_config: MediationConfig,

    // ═══════════════════════════════════════════════════════════════════
    // Phase 1 & 2 Security Managers (Phase 3.1 Integration)
    // ═══════════════════════════════════════════════════════════════════
    /// Task state manager for async task lifecycle tracking (Phase 1).
    task_state: Option<Arc<TaskStateManager>>,

    /// Phase 1: Extension registry for allow/block pattern enforcement.
    extension_registry: Option<Arc<crate::extension_registry::ExtensionRegistry>>,

    /// Phase 2: Per-tool rate limiting and quota enforcement.
    tool_quota_tracker: Option<std::sync::Mutex<crate::tool_quota::ToolQuotaTracker>>,

    /// Phase 2: Secret substitution engine (outbound: secret→placeholder, inbound: placeholder→secret).
    secret_substitution: Option<crate::secret_substitution::SecretSubstitutionEngine>,

    /// Phase 2: Server reputation tracker.
    reputation_tracker: Option<std::sync::Mutex<crate::reputation::ReputationTracker>>,

    /// Agent behavioral baseline tracker (cross-session).
    agent_baseline: std::sync::Mutex<vellaveto_engine::agent_baseline::AgentBaselineTracker>,

    /// Phase 6: Source trust config for auto-tainting.
    source_trust_config: Option<vellaveto_config::channel_separation::SourceTrustConfig>,

    /// Phase 6: Sink classification config.
    sink_classification_config:
        Option<vellaveto_config::channel_separation::SinkClassificationConfig>,

    /// Phase 6: Intent scope config for session-level enforcement.
    intent_scope_config: Option<vellaveto_config::channel_separation::IntentScopeConfig>,

    /// Auth level tracker for step-up authentication (Phase 1).
    auth_level: Option<Arc<AuthLevelTracker>>,

    /// Circuit breaker for cascading failure protection (Phase 2, ASI08).
    circuit_breaker: Option<Arc<CircuitBreakerManager>>,

    /// Deputy validator for confused deputy prevention (Phase 2, ASI02).
    deputy: Option<Arc<DeputyValidator>>,

    /// Shadow agent detector for agent impersonation detection (Phase 2).
    shadow_agent: Option<Arc<ShadowAgentDetector>>,

    /// Schema lineage tracker for schema poisoning detection (Phase 2, ASI05).
    schema_lineage: Option<Arc<SchemaLineageTracker>>,

    /// Sampling detector for sampling attack prevention (Phase 2).
    sampling_detector: Option<Arc<SamplingDetector>>,

    // ═══════════════════════════════════════════════════════════════════
    // Phase 8: ETDI Cryptographic Tool Security
    // ═══════════════════════════════════════════════════════════════════
    /// ETDI signature verifier for tool definition verification.
    etdi_verifier: Option<Arc<crate::etdi::ToolSignatureVerifier>>,
    /// ETDI attestation chain manager.
    etdi_attestations: Option<Arc<crate::etdi::AttestationChain>>,
    /// ETDI version pin manager.
    etdi_version_pins: Option<Arc<crate::etdi::VersionPinManager>>,
    /// Whether to require ETDI signatures for all tools.
    etdi_require_signatures: bool,

    // ═══════════════════════════════════════════════════════════════════
    // Phase 9: Memory Injection Defense (MINJA)
    // ═══════════════════════════════════════════════════════════════════
    /// Memory security manager for MINJA defense.
    /// When set, memory entries are tracked for taint propagation,
    /// provenance, and namespace isolation.
    memory_security: Option<Arc<crate::memory_security::MemorySecurityManager>>,

    // ═══════════════════════════════════════════════════════════════════
    // Phase 19: EU AI Act Article 50 Runtime Transparency
    // ═══════════════════════════════════════════════════════════════════
    /// When true, inject `_meta.vellaveto_ai_mediated = true` into responses.
    transparency_marking: bool,
    /// Tool patterns requiring human oversight (Art 14 glob patterns).
    human_oversight_tools: Vec<String>,

    // ═══════════════════════════════════════════════════════════════════
    // Phase 24: Art 50(2) Decision Explanations
    // ═══════════════════════════════════════════════════════════════════
    /// Verbosity level for per-verdict decision explanations.
    explanation_verbosity: vellaveto_types::ExplanationVerbosity,

    // ═══════════════════════════════════════════════════════════════════
    // Phase 21: ABAC Attribute-Based Access Control
    // ═══════════════════════════════════════════════════════════════════
    /// SECURITY (FIND-R78-002): Optional ABAC engine for attribute-based
    /// access control refinement. When set, policy-engine Allow verdicts
    /// are further evaluated against ABAC forbid-override rules, achieving
    /// parity with the HTTP/WebSocket/gRPC proxy handlers.
    abac_engine: Option<Arc<vellaveto_engine::abac::AbacEngine>>,

    // ═══════════════════════════════════════════════════════════════════
    // Phase 30: MCP 2025-11-25 Spec Compliance
    // ═══════════════════════════════════════════════════════════════════
    /// SECURITY (FIND-R78-001): When true, validate tool names against MCP spec
    /// format before evaluation. Parity with HTTP/WebSocket/gRPC proxy modes.
    strict_tool_name_validation: bool,

    // ═══════════════════════════════════════════════════════════════════
    // R227: Tool Capability Drift Detection
    // ═══════════════════════════════════════════════════════════════════
    /// When true, tools whose schemas have drifted from their initially
    /// registered versions are blocked (added to flagged_tools).
    /// Default: false (log-only — schema lineage tracker already emits alerts).
    block_tool_drift: bool,

    // ═══════════════════════════════════════════════════════════════════
    // R227: Discovery Engine Integration (R24-MCP-1)
    // ═══════════════════════════════════════════════════════════════════
    /// Discovery engine for tool metadata indexing and intent-based search.
    /// When set, tools from `tools/list` responses are automatically indexed
    /// for later discovery queries. Indexing failures are logged but don't
    /// block the response (advisory, not security-critical).
    #[cfg(feature = "discovery")]
    discovery_engine: Option<Arc<crate::discovery::DiscoveryEngine>>,

    // ═══════════════════════════════════════════════════════════════════
    // Topology Guard Integration (live topology updates from relay)
    // ═══════════════════════════════════════════════════════════════════
    /// Topology guard for pre-policy tool call filtering.
    /// When set, `tools/list` responses are parsed and upserted into the
    /// guard for incremental topology updates. Advisory only — upsert
    /// failures are logged but don't block the response.
    #[cfg(feature = "discovery")]
    topology_guard: Option<Arc<vellaveto_discovery::guard::TopologyGuard>>,

    // ═══════════════════════════════════════════════════════════════════
    // Phase 71: Cross-Call DLP Tracking (R233-DLP-1)
    // ═══════════════════════════════════════════════════════════════════
    /// When true, enable cross-call DLP tracking per session to detect
    /// secrets split across sequential tool calls.
    cross_call_dlp_enabled: bool,

    // ═══════════════════════════════════════════════════════════════════
    // TI-2026-001: Sharded Exfiltration Detection (R233-MCPSEC-2)
    // ═══════════════════════════════════════════════════════════════════
    /// When true, enable sharded exfiltration detection per session.
    sharded_exfil_enabled: bool,

    // ═══════════════════════════════════════════════════════════════════
    // Consumer Shield: Bidirectional PII Sanitization
    // ═══════════════════════════════════════════════════════════════════
    /// When set, outbound requests are sanitized (PII replaced with
    /// placeholders) and inbound responses are desanitized (placeholders
    /// restored to original values). Enables privacy-preserving AI interactions.
    #[cfg(feature = "consumer-shield")]
    shield_sanitizer: Option<Arc<vellaveto_mcp_shield::QuerySanitizer>>,

    // ═══════════════════════════════════════════════════════════════════
    // Consumer Shield: Stylometric Fingerprint Resistance
    // ═══════════════════════════════════════════════════════════════════
    /// When set, outbound requests are normalized to strip writing style
    /// fingerprints (whitespace patterns, punctuation, emoji, filler words).
    /// Applied AFTER PII sanitization to prevent stylometric analysis.
    #[cfg(feature = "consumer-shield")]
    shield_stylometric: Option<Arc<vellaveto_mcp_shield::StylometricNormalizer>>,

    // ═══════════════════════════════════════════════════════════════════
    // Consumer Shield: Context Isolation
    // ═══════════════════════════════════════════════════════════════════
    /// When set, tracks per-session context windows. Context from one
    /// session is never leaked to another at the provider level.
    #[cfg(feature = "consumer-shield")]
    shield_context_isolator: Option<Arc<vellaveto_mcp_shield::ContextIsolator>>,

    // ═══════════════════════════════════════════════════════════════════
    // Consumer Shield: Session Unlinkability
    // ═══════════════════════════════════════════════════════════════════
    /// When set, each session consumes a fresh blind credential from the
    /// vault. The provider cannot correlate sessions to the same user.
    #[cfg(feature = "consumer-shield")]
    shield_session_unlinker: Option<Arc<tokio::sync::Mutex<vellaveto_mcp_shield::SessionUnlinker>>>,

    // ═══════════════════════════════════════════════════════════════════
    // Consumer Shield: Desanitize Responses Flag
    // ═══════════════════════════════════════════════════════════════════
    /// When false, inbound response desanitization is skipped — PII placeholders
    /// are preserved in responses returned to the agent.
    #[cfg(feature = "consumer-shield")]
    shield_desanitize_responses: bool,

    // ═══════════════════════════════════════════════════════════════════
    // Desktop App: Lightweight Verdict Notifications
    // ═══════════════════════════════════════════════════════════════════
    /// Optional callback for lightweight verdict notifications (desktop app integration).
    /// Called on every tools/call verdict with (tool, method, verdict, reason).
    /// The callback must be non-blocking — file I/O is acceptable but not network.
    verdict_notify: Option<Arc<VerdictNotifyFn>>,

    // ═══════════════════════════════════════════════════════════════════
    // Content-Bound Attestation (SecurityContextToken HMAC)
    // ═══════════════════════════════════════════════════════════════════
    /// Optional HMAC-SHA256 key for content-bound attestation.
    /// When set, `vellaveto_attestation` is attached to `_meta` on every
    /// proxied response, binding scan results (injection, DLP, schema) to
    /// the SHA-256 hash of the response content. Consumers verify with
    /// their SDK's `verify_attestation()` method.
    /// Read from `VELLAVETO_ATTESTATION_SECRET` env var at startup.
    attestation_hmac_key: Option<Vec<u8>>,
}

impl ProxyBridge {
    pub fn new(engine: PolicyEngine, policies: Vec<Policy>, audit: Arc<AuditLogger>) -> Self {
        Self {
            engine,
            policies,
            audit,
            audit_strict_mode: false,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            enable_trace: false,
            injection_scanner: None,
            injection_disabled: false,
            injection_blocking: false,
            approval_store: None,
            manifest_config: None,
            flagged_tools_path: None,
            output_schema_registry: Arc::new(OutputSchemaRegistry::new()),
            output_schema_blocking: true,
            response_dlp_enabled: true,
            response_dlp_blocking: false,
            known_tools: crate::rug_pull::build_known_tools(&[]),
            elicitation_config: vellaveto_config::ElicitationConfig::default(),
            sampling_config: vellaveto_config::SamplingConfig::default(),
            tool_registry: None,
            mediation_config: MediationConfig {
                dlp_enabled: false,
                dlp_blocking: false,
                injection_enabled: false,
                injection_blocking: false,
                ..MediationConfig::default()
            },
            // Phase 1 & 2 managers (default: disabled)
            task_state: None,
            extension_registry: None,
            tool_quota_tracker: None,
            secret_substitution: None,
            reputation_tracker: None,
            agent_baseline: std::sync::Mutex::new(
                vellaveto_engine::agent_baseline::AgentBaselineTracker::new(10),
            ),
            source_trust_config: None,
            sink_classification_config: None,
            intent_scope_config: None,
            auth_level: None,
            circuit_breaker: None,
            deputy: None,
            shadow_agent: None,
            schema_lineage: None,
            sampling_detector: None,
            // Phase 8: ETDI (default: disabled)
            etdi_verifier: None,
            etdi_attestations: None,
            etdi_version_pins: None,
            etdi_require_signatures: false,
            // Phase 9: MINJA (default: disabled)
            memory_security: None,
            // Phase 19: Transparency (default: disabled)
            transparency_marking: false,
            human_oversight_tools: Vec::new(),
            // Phase 24: Art 50(2) explanations (default: disabled)
            explanation_verbosity: vellaveto_types::ExplanationVerbosity::None,
            // Phase 21: ABAC (default: disabled)
            abac_engine: None,
            // Phase 30: MCP 2025-11-25 tool name validation (default: disabled)
            strict_tool_name_validation: false,
            // R227: Tool drift blocking (default: disabled)
            block_tool_drift: false,
            // R227: Discovery engine (default: disabled)
            #[cfg(feature = "discovery")]
            discovery_engine: None,
            // Topology guard (default: disabled)
            #[cfg(feature = "discovery")]
            topology_guard: None,
            // Phase 71: Cross-call DLP (default: disabled)
            cross_call_dlp_enabled: false,
            // TI-2026-001: Sharded exfil (default: disabled)
            sharded_exfil_enabled: false,
            // Consumer shield (default: disabled)
            #[cfg(feature = "consumer-shield")]
            shield_sanitizer: None,
            #[cfg(feature = "consumer-shield")]
            shield_stylometric: None,
            #[cfg(feature = "consumer-shield")]
            shield_context_isolator: None,
            #[cfg(feature = "consumer-shield")]
            shield_session_unlinker: None,
            #[cfg(feature = "consumer-shield")]
            shield_desanitize_responses: true,
            // Desktop notification (default: disabled)
            verdict_notify: None,
            // Content-bound attestation (default: disabled)
            attestation_hmac_key: None,
        }
    }
}
