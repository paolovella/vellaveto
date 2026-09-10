// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Builder methods for `ProxyBridge`.
//!
//! Each method follows the builder pattern: `fn with_*(mut self, ...) -> Self`.

use super::ProxyBridge;

use vellaveto_approval::ApprovalStore;
use vellaveto_config::ManifestConfig;
use vellaveto_engine::circuit_breaker::CircuitBreakerManager;
use vellaveto_engine::deputy::DeputyValidator;

use crate::auth_level::AuthLevelTracker;
use crate::inspection::InjectionScanner;
use crate::sampling_detector::SamplingDetector;
use crate::schema_poisoning::SchemaLineageTracker;
use crate::shadow_agent::ShadowAgentDetector;
use crate::task_state::TaskStateManager;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

impl ProxyBridge {
    /// Set an approval store for handling RequireApproval verdicts.
    /// When set, RequireApproval verdicts create pending approvals with
    /// the approval_id included in the JSON-RPC error response data.
    pub fn with_approval_store(mut self, store: Arc<ApprovalStore>) -> Self {
        self.approval_store = Some(store);
        self
    }

    /// Deny requests whose audit entry could not be written.
    ///
    /// SECURITY (R271-MCP-1): mirrors `audit.strict_mode` on the HTTP paths so
    /// the setting means the same thing over stdio. Defaults to false, which
    /// keeps the previous behaviour: log the failure and continue.
    pub fn with_audit_strict_mode(mut self, strict: bool) -> Self {
        self.audit_strict_mode = strict;
        self
    }

    /// Set manifest verification config. When set, the proxy pins the first
    /// tools/list response as a manifest and verifies subsequent responses.
    pub fn with_manifest_config(mut self, config: ManifestConfig) -> Self {
        self.manifest_config = Some(config);
        self
    }

    /// Set the request timeout for forwarded requests.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Enable evaluation trace recording. When enabled, tool call evaluations
    /// use `evaluate_action_traced()` and include the trace in audit metadata.
    pub fn with_trace(mut self, enable: bool) -> Self {
        self.enable_trace = enable;
        self
    }

    /// Set a custom injection scanner built from configuration.
    /// When set, this scanner is used instead of the default patterns.
    pub fn with_injection_scanner(mut self, scanner: InjectionScanner) -> Self {
        self.injection_scanner = Some(scanner);
        self
    }

    /// Disable injection scanning entirely.
    pub fn with_injection_disabled(mut self, disabled: bool) -> Self {
        self.injection_disabled = disabled;
        self
    }

    /// Enable injection blocking mode (H4).
    /// When enabled, injection matches replace the response with an error
    /// instead of just logging. Default: false (log-only).
    pub fn with_injection_blocking(mut self, blocking: bool) -> Self {
        self.injection_blocking = blocking;
        self
    }

    /// Set the file path for persisting flagged (rug-pulled) tool names.
    /// When set, flagged tools are appended to this JSONL file and reloaded on proxy start.
    pub fn with_flagged_tools_path(mut self, path: PathBuf) -> Self {
        self.flagged_tools_path = Some(path);
        self
    }

    /// Enable output schema blocking mode.
    /// When enabled, structuredContent that fails schema validation is blocked.
    pub fn with_output_schema_blocking(mut self, blocking: bool) -> Self {
        self.output_schema_blocking = blocking;
        self
    }

    /// Enable/disable DLP scanning of tool responses.
    pub fn with_response_dlp_enabled(mut self, enabled: bool) -> Self {
        self.response_dlp_enabled = enabled;
        self
    }

    /// Enable DLP response blocking mode.
    /// When enabled, responses containing secrets are blocked instead of just logged.
    pub fn with_response_dlp_blocking(mut self, blocking: bool) -> Self {
        self.response_dlp_blocking = blocking;
        self
    }

    /// Set the elicitation interception configuration.
    /// When `enabled: false` (default), all elicitation requests are blocked.
    pub fn with_elicitation_config(mut self, config: vellaveto_config::ElicitationConfig) -> Self {
        self.elicitation_config = config;
        self
    }

    /// Set the sampling request policy configuration.
    /// When `enabled: false` (default), all sampling requests are blocked.
    pub fn with_sampling_config(mut self, config: vellaveto_config::SamplingConfig) -> Self {
        self.sampling_config = config;
        self
    }

    /// Set the tool registry for trust score tracking (P2.1).
    /// When set, unknown or untrusted tools require approval before forwarding.
    pub fn with_tool_registry(mut self, registry: Arc<crate::tool_registry::ToolRegistry>) -> Self {
        self.tool_registry = Some(registry);
        self
    }

    /// Override the canonical mediation settings used after transport-specific
    /// prechecks in the stdio bridge.
    pub fn with_mediation_config(mut self, config: crate::mediation::MediationConfig) -> Self {
        self.mediation_config = config;
        self
    }

    // ═══════════════════════════════════════════════════════════════════
    // Phase 1 & 2 Manager Builder Methods (Phase 3.1 Integration)
    // ═══════════════════════════════════════════════════════════════════

    /// Set the task state manager for async task lifecycle tracking.
    /// When set, async task limits and cancellation policies are enforced.
    pub fn with_task_state(mut self, manager: Arc<TaskStateManager>) -> Self {
        self.task_state = Some(manager);
        self
    }

    /// Phase 2: Set the tool quota tracker for per-tool rate limiting.
    pub fn with_tool_quota_tracker(mut self, tracker: crate::tool_quota::ToolQuotaTracker) -> Self {
        self.tool_quota_tracker = Some(std::sync::Mutex::new(tracker));
        self
    }

    /// Phase 2: Set the server reputation tracker.
    pub fn with_reputation_tracker(
        mut self,
        tracker: crate::reputation::ReputationTracker,
    ) -> Self {
        self.reputation_tracker = Some(std::sync::Mutex::new(tracker));
        self
    }

    /// Phase 2: Set the secret substitution engine.
    pub fn with_secret_substitution(
        mut self,
        engine: crate::secret_substitution::SecretSubstitutionEngine,
    ) -> Self {
        self.secret_substitution = Some(engine);
        self
    }

    /// Phase 1: Set the extension registry for allow/block pattern enforcement.
    pub fn with_extension_registry(
        mut self,
        registry: Arc<crate::extension_registry::ExtensionRegistry>,
    ) -> Self {
        self.extension_registry = Some(registry);
        self
    }

    /// Set the auth level tracker for step-up authentication.
    /// When set, sensitive operations may require elevated authentication.
    pub fn with_auth_level(mut self, tracker: Arc<AuthLevelTracker>) -> Self {
        self.auth_level = Some(tracker);
        self
    }

    /// Set the circuit breaker manager for cascading failure protection.
    /// When set, failing tools are automatically circuit-broken.
    pub fn with_circuit_breaker(mut self, manager: Arc<CircuitBreakerManager>) -> Self {
        self.circuit_breaker = Some(manager);
        self
    }

    /// Set the deputy validator for confused deputy prevention.
    /// When set, delegation chains and principal bindings are enforced.
    pub fn with_deputy(mut self, validator: Arc<DeputyValidator>) -> Self {
        self.deputy = Some(validator);
        self
    }

    /// Set the shadow agent detector for agent impersonation detection.
    /// When set, agent fingerprints are verified against known agents.
    pub fn with_shadow_agent(mut self, detector: Arc<ShadowAgentDetector>) -> Self {
        self.shadow_agent = Some(detector);
        self
    }

    /// Set the schema lineage tracker for schema poisoning detection.
    /// When set, tool schemas are monitored for suspicious mutations.
    pub fn with_schema_lineage(mut self, tracker: Arc<SchemaLineageTracker>) -> Self {
        self.schema_lineage = Some(tracker);
        self
    }

    /// Set the sampling detector for sampling attack prevention.
    /// When set, sampling requests are rate-limited and content-scanned.
    pub fn with_sampling_detector(mut self, detector: Arc<SamplingDetector>) -> Self {
        self.sampling_detector = Some(detector);
        self
    }

    // ═══════════════════════════════════════════════════════════════════
    // Phase 8: ETDI Builder Methods
    // ═══════════════════════════════════════════════════════════════════

    /// Set the ETDI signature verifier for tool definition verification.
    /// When set, tool signatures are verified against the trusted signers list.
    pub fn with_etdi_verifier(mut self, verifier: Arc<crate::etdi::ToolSignatureVerifier>) -> Self {
        self.etdi_verifier = Some(verifier);
        self
    }

    /// Set the ETDI attestation chain manager.
    /// When set, tool attestation chains are tracked and verified.
    pub fn with_etdi_attestations(
        mut self,
        attestations: Arc<crate::etdi::AttestationChain>,
    ) -> Self {
        self.etdi_attestations = Some(attestations);
        self
    }

    /// Set the ETDI version pin manager.
    /// When set, tools are checked against version pins before being allowed.
    pub fn with_etdi_version_pins(mut self, pins: Arc<crate::etdi::VersionPinManager>) -> Self {
        self.etdi_version_pins = Some(pins);
        self
    }

    /// Set whether to require ETDI signatures for all tools.
    /// When true, unsigned tools are blocked. Default: false.
    pub fn with_etdi_require_signatures(mut self, require: bool) -> Self {
        self.etdi_require_signatures = require;
        self
    }

    // ═══════════════════════════════════════════════════════════════════
    // Phase 9: MINJA Builder Methods
    // ═══════════════════════════════════════════════════════════════════

    /// Set the memory security manager for MINJA defense.
    /// When set, memory entries are tracked for taint propagation,
    /// provenance tracking, and namespace isolation.
    pub fn with_memory_security(
        mut self,
        manager: Arc<crate::memory_security::MemorySecurityManager>,
    ) -> Self {
        self.memory_security = Some(manager);
        self
    }

    // ═══════════════════════════════════════════════════════════════════
    // Phase 19: EU AI Act Article 50 Runtime Transparency
    // ═══════════════════════════════════════════════════════════════════

    /// Enable Art 50(1) transparency marking.
    /// When true, `_meta.vellaveto_ai_mediated = true` is injected into tool
    /// responses before forwarding to the agent.
    pub fn with_transparency_marking(mut self, enabled: bool) -> Self {
        self.transparency_marking = enabled;
        self
    }

    /// Set tool patterns requiring human oversight per Art 14.
    /// Tools matching these glob patterns trigger an audit event
    /// for human oversight tracking.
    pub fn with_human_oversight_tools(mut self, patterns: Vec<String>) -> Self {
        self.human_oversight_tools = patterns;
        self
    }

    // ═══════════════════════════════════════════════════════════════════
    // Phase 24: Art 50(2) Decision Explanation
    // ═══════════════════════════════════════════════════════════════════

    /// Set the decision explanation verbosity level for Art 50(2).
    /// When not `None`, per-verdict structured explanations are injected
    /// into `_meta.vellaveto_decision_explanation` in tool responses.
    pub fn with_explanation_verbosity(
        mut self,
        verbosity: vellaveto_types::ExplanationVerbosity,
    ) -> Self {
        self.explanation_verbosity = verbosity;
        self
    }

    // ═══════════════════════════════════════════════════════════════════
    // Phase 21: ABAC Attribute-Based Access Control
    // ═══════════════════════════════════════════════════════════════════

    /// SECURITY (FIND-R78-002): Set the ABAC engine for attribute-based access
    /// control refinement. When set, policy-engine Allow verdicts are further
    /// evaluated against ABAC forbid-override rules, achieving parity with the
    /// HTTP/WebSocket/gRPC proxy handlers.
    pub fn with_abac_engine(mut self, engine: Arc<vellaveto_engine::abac::AbacEngine>) -> Self {
        self.abac_engine = Some(engine);
        self
    }

    // ═══════════════════════════════════════════════════════════════════
    // Phase 30: MCP 2025-11-25 Spec Compliance
    // ═══════════════════════════════════════════════════════════════════

    /// SECURITY (FIND-R78-001): Enable strict MCP tool name validation.
    /// When true, tool names are validated against the MCP 2025-11-25 spec
    /// format (1-64 chars, `[a-zA-Z0-9_\-./]`, no `..`/`//`) before policy
    /// evaluation. This achieves parity with the HTTP/WebSocket/gRPC proxy.
    pub fn with_strict_tool_name_validation(mut self, enabled: bool) -> Self {
        self.strict_tool_name_validation = enabled;
        self
    }

    // ═══════════════════════════════════════════════════════════════════
    // R227: Tool Capability Drift Detection
    // ═══════════════════════════════════════════════════════════════════

    /// When true, tools whose schemas have drifted from their initially
    /// registered versions are blocked (flagged as rug-pulled).
    /// Default: false (log-only).
    pub fn with_block_tool_drift(mut self, block: bool) -> Self {
        self.block_tool_drift = block;
        self
    }

    // ═══════════════════════════════════════════════════════════════════
    // R227: Discovery Engine Integration (R24-MCP-1)
    // ═══════════════════════════════════════════════════════════════════

    /// Set the discovery engine for tool metadata indexing.
    /// When set, tools from `tools/list` responses are automatically indexed
    /// for later discovery/search queries via natural language.
    #[cfg(feature = "discovery")]
    pub fn with_discovery_engine(mut self, engine: Arc<crate::discovery::DiscoveryEngine>) -> Self {
        self.discovery_engine = Some(engine);
        self
    }

    // ═══════════════════════════════════════════════════════════════════
    // Topology Guard Integration (live topology updates from relay)
    // ═══════════════════════════════════════════════════════════════════

    /// Set the topology guard for live topology updates.
    /// When set, `tools/list` responses are parsed and upserted into the
    /// guard for incremental topology updates.
    #[cfg(feature = "discovery")]
    pub fn with_topology_guard(
        mut self,
        guard: Arc<vellaveto_discovery::guard::TopologyGuard>,
    ) -> Self {
        self.topology_guard = Some(guard);
        self
    }

    // ═══════════════════════════════════════════════════════════════════
    // Phase 71: Cross-Call DLP Tracking (R233-DLP-1)
    // ═══════════════════════════════════════════════════════════════════

    /// Enable cross-call DLP tracking. When enabled, each session maintains
    /// overlap buffers to detect secrets split across sequential tool calls.
    pub fn with_cross_call_dlp(mut self, enabled: bool) -> Self {
        self.cross_call_dlp_enabled = enabled;
        self
    }

    // ═══════════════════════════════════════════════════════════════════
    // TI-2026-001: Sharded Exfiltration Detection (R233-MCPSEC-2)
    // ═══════════════════════════════════════════════════════════════════

    /// Enable sharded exfiltration detection. When enabled, each session
    /// tracks high-entropy parameter fragments and alerts when cumulative
    /// suspicious bytes exceed the threshold within a time window.
    pub fn with_sharded_exfil(mut self, enabled: bool) -> Self {
        self.sharded_exfil_enabled = enabled;
        self
    }

    // ═══════════════════════════════════════════════════════════════════
    // Consumer Shield: Bidirectional PII Sanitization
    // ═══════════════════════════════════════════════════════════════════

    /// Set the shield sanitizer for bidirectional PII sanitization.
    /// When set, outbound request parameters are sanitized (PII replaced)
    /// and inbound response content is desanitized (PII restored).
    #[cfg(feature = "consumer-shield")]
    pub fn with_shield_sanitizer(
        mut self,
        sanitizer: Arc<vellaveto_mcp_shield::QuerySanitizer>,
    ) -> Self {
        self.shield_sanitizer = Some(sanitizer);
        self
    }

    /// Set the stylometric normalizer for writing style fingerprint resistance.
    /// Applied AFTER PII sanitization on outbound requests. Strips whitespace
    /// patterns, punctuation idiosyncrasies, emoji, and filler words.
    #[cfg(feature = "consumer-shield")]
    pub fn with_shield_stylometric(
        mut self,
        normalizer: Arc<vellaveto_mcp_shield::StylometricNormalizer>,
    ) -> Self {
        self.shield_stylometric = Some(normalizer);
        self
    }

    /// Set the context isolator for per-session context window management.
    /// Records conversation context per session; prevents cross-session
    /// context leakage at the provider level.
    #[cfg(feature = "consumer-shield")]
    pub fn with_context_isolator(
        mut self,
        isolator: Arc<vellaveto_mcp_shield::ContextIsolator>,
    ) -> Self {
        self.shield_context_isolator = Some(isolator);
        self
    }

    /// Set the session unlinker for credential-based session unlinkability.
    /// Each session consumes a fresh blind credential so the provider cannot
    /// correlate sessions to the same user.
    #[cfg(feature = "consumer-shield")]
    pub fn with_session_unlinker(
        mut self,
        unlinker: Arc<tokio::sync::Mutex<vellaveto_mcp_shield::SessionUnlinker>>,
    ) -> Self {
        self.shield_session_unlinker = Some(unlinker);
        self
    }

    /// Set whether to desanitize inbound responses (restore PII from placeholders).
    /// When false, PII placeholders are preserved in responses.
    #[cfg(feature = "consumer-shield")]
    pub fn with_shield_desanitize_responses(mut self, desanitize: bool) -> Self {
        self.shield_desanitize_responses = desanitize;
        self
    }

    /// Override the known tools set for squatting detection.
    pub fn with_known_tools(mut self, tools: std::collections::HashSet<String>) -> Self {
        self.known_tools = tools;
        self
    }

    /// Minimum attestation HMAC key length (bytes).
    /// SECURITY (R259-ATT-1): Keys shorter than 32 bytes are trivially brute-forceable.
    const MIN_ATTESTATION_KEY_LEN: usize = 32;

    /// Set the HMAC-SHA256 key for content-bound attestation.
    /// When set, every proxied response gets a `_meta.vellaveto_attestation`
    /// token binding scan results to the response content hash.
    /// Consumers verify with their SDK's `verify_attestation()` method.
    ///
    /// SECURITY (R259-ATT-1): Keys shorter than 32 bytes are rejected and
    /// attestation is left disabled (fail-closed). An error is logged so
    /// operators notice the misconfiguration.
    pub fn with_attestation_key(mut self, key: Vec<u8>) -> Self {
        let key_len = key.len();
        if key_len < Self::MIN_ATTESTATION_KEY_LEN {
            tracing::error!(
                "VELLAVETO_ATTESTATION_SECRET too short ({} bytes, minimum {}). \
                 Content-bound attestation will be DISABLED.",
                key_len,
                Self::MIN_ATTESTATION_KEY_LEN,
            );
            return self; // Attestation stays None (disabled)
        }
        self.attestation_hmac_key = Some(key);
        self
    }

    // Phase 6: Channel Separation

    /// Set source trust classification for auto-tainting.
    pub fn with_source_trust_config(
        mut self,
        config: vellaveto_config::channel_separation::SourceTrustConfig,
    ) -> Self {
        self.source_trust_config = Some(config);
        self
    }

    /// Set sink classification rules.
    pub fn with_sink_classification_config(
        mut self,
        config: vellaveto_config::channel_separation::SinkClassificationConfig,
    ) -> Self {
        self.sink_classification_config = Some(config);
        self
    }

    /// Set intent scope for session-level enforcement.
    pub fn with_intent_scope_config(
        mut self,
        config: vellaveto_config::channel_separation::IntentScopeConfig,
    ) -> Self {
        self.intent_scope_config = Some(config);
        self
    }

    // Desktop App: Verdict Notifications

    /// Set a lightweight verdict notification callback.
    pub fn with_verdict_notify(mut self, notify: Arc<super::VerdictNotifyFn>) -> Self {
        self.verdict_notify = Some(notify);
        self
    }
}
