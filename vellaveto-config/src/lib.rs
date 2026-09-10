// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Configuration types and validation for the Vellaveto MCP tool firewall.
//!
//! Parses and validates TOML policy configuration files including policy rules,
//! network constraints, ABAC attributes, compliance settings, observability,
//! and deployment options. All config structs use `deny_unknown_fields` and
//! bounded `validate()` methods to reject invalid or oversized input.

pub mod observability;
pub mod validation;

// ═══════════════════════════════════════════════════════════════════════════════
// EXTRACTED SUBMODULES (modularization refactor)
// ═══════════════════════════════════════════════════════════════════════════════
pub mod channel_separation;
pub mod detection;
pub mod enterprise;
pub mod etdi;
pub mod extension;
pub mod gateway;
pub mod iam;
pub mod manifest;
pub mod mcp_protocol;
pub mod memory_nhi;
pub mod policy_templates;
pub mod rag_defense_config;
pub mod semantic_guardrails_config;
pub mod supply_chain;
pub mod threat_detection;
pub mod transport;

// ═══════════════════════════════════════════════════════════════════════════════
// EXTRACTED CONFIG SUBMODULES (Phase 16.6 split)
// ═══════════════════════════════════════════════════════════════════════════════
pub mod a2a;
pub mod abac;
pub mod acis;
pub mod audit_store;
pub mod billing;
pub mod cluster;
pub mod compliance;
pub mod config_validate;
pub mod deployment;
pub mod discovery;
pub mod evidence_pack;
pub mod fips;
pub mod governance;
pub mod grpc_transport;
pub mod licensing;
pub mod limits;
pub mod metering;
pub mod policy_lifecycle;
pub mod policy_rule;
pub mod projector;
pub mod schema_canonical;
pub mod tool_registry;
pub mod topology;
pub mod zk_audit;

pub mod bulk;
pub mod cedar;
pub mod shield;

#[cfg(test)]
mod tests;

// ═══════════════════════════════════════════════════════════════════════════════
// RE-EXPORTS — preserve the public API
// ═══════════════════════════════════════════════════════════════════════════════

pub use observability::{
    ArizeConfig, HeliconeConfig, LangfuseConfig, ObservabilityConfig, OtlpConfig, OtlpProtocol,
    WebhookExporterConfig,
};

pub use detection::{
    AuditConfig, AuditExportConfig, CustomPiiPattern, DlpConfig, InjectionConfig,
    MemoryTrackingConfig, MultimodalPolicyConfig, RateLimitConfig,
};

pub use supply_chain::{SupplyChainConfig, MAX_BINARY_SIZE};

pub use manifest::{
    ManifestAnnotations, ManifestConfig, ManifestEnforcement, ManifestToolEntry,
    ManifestVerification, ToolManifest,
};

pub use schema_canonical::{
    canonical_schema_bytes, canonical_schema_hash, manifest_input_schema_hash, SchemaCanonicalError,
};

pub use mcp_protocol::{
    validate_mcp_param_header_name, AsyncTaskConfig, CimdConfig, ElicitationConfig,
    ResourceIndicatorConfig, SamplingConfig, SecretSubstitution, StepUpAuthConfig,
    StreamableHttpConfig, ToolQuota, MAX_ALLOWED_MCP_PARAM_HEADERS, MAX_ALLOWED_MODELS,
    MAX_ALLOWED_RESOURCES, MAX_ALLOW_CANCELLATION, MAX_BLOCKED_FIELD_TYPES, MAX_CAPABILITIES,
    MAX_MCP_PARAM_HEADER_NAME_LENGTH, MAX_SECRET_SUBSTITUTIONS, MAX_TOOL_QUOTAS, MAX_TRIGGER_TOOLS,
};

pub use etdi::{AllowedSignersConfig, AttestationConfig, EtdiConfig, VersionPinningConfig};

pub use threat_detection::{
    AdvancedThreatConfig, BehavioralDetectionConfig, CircuitBreakerConfig, CrossAgentConfig,
    DataFlowTrackingConfig, DeputyConfig, SamplingDetectionConfig, SchemaPoisoningConfig,
    SemanticDetectionConfig, ShadowAgentConfig, MAX_ALLOWED_SAMPLING_MODELS, MAX_BEHAVIORAL_AGENTS,
    MAX_BEHAVIORAL_TOOLS_PER_AGENT, MAX_CLUSTER_KEY_PREFIX_LEN, MAX_CLUSTER_REDIS_POOL_SIZE,
    MAX_CROSS_AGENT_TRUSTED_AGENTS, MAX_DATA_FLOW_FINDINGS, MAX_DATA_FLOW_FINGERPRINTS,
    MAX_KNOWN_AGENTS, MAX_NON_DELEGATABLE_TOOLS, MAX_PROTECTED_TOOL_PATTERNS,
    MAX_SEMANTIC_EXTRA_TEMPLATES, MAX_TRACKED_SCHEMAS,
};

pub use enterprise::{
    JitAccessConfig, OpaConfig, SpiffeConfig, ThreatIntelConfig, ThreatIntelProvider, TlsConfig,
    TlsKexPolicy, TlsMode,
};

pub use iam::{IamConfig, M2mClient, M2mConfig};

pub use memory_nhi::{
    DpopConfig, MemorySecurityConfig, NamespaceConfig, NhiConfig, VerificationConfig,
};

pub use semantic_guardrails_config::{
    AnthropicBackendConfig, IntentClassificationConfig, JailbreakDetectionConfig, NlPolicyConfig,
    OpenAiBackendConfig, SemanticGuardrailsConfig,
};

pub use rag_defense_config::{
    ContextBudgetConfig, DocumentVerificationConfig, EmbeddingAnomalyConfig, GroundingConfig,
    RagDefenseConfig, RetrievalSecurityConfig,
};

// Re-exports from Phase 16.6 split submodules
pub use a2a::{A2aConfig, A2aSignatureConfig, TrustedAgentKey};
pub use abac::AbacConfig;
pub use acis::{AcisConfig, TrustedRequestSignerConfig};
pub use audit_store::AuditStoreConfig;
pub use billing::BillingConfig;
pub use cluster::ClusterConfig;
pub use compliance::{
    AiActRiskClass, ComplianceConfig, EuAiActConfig, OwaspAsiConfig, Soc2Config,
    TrustServicesCategory,
};
pub use config_validate::{
    MAX_ALLOWED_SERVERS, MAX_CUSTOM_PII_PATTERNS, MAX_DISABLED_INJECTION_PATTERNS,
    MAX_EXTRA_INJECTION_PATTERNS, MAX_KNOWN_TOOL_NAMES, MAX_POLICIES, MAX_TRUSTED_KEYS,
};
pub use deployment::{
    DeploymentConfig, DeploymentMode, LeaderElectionConfig, ServiceDiscoveryConfig,
    ServiceDiscoveryMode,
};
pub use discovery::DiscoveryConfig;
pub use evidence_pack::{DoraConfig, Nis2Config};
pub use extension::ExtensionConfig;
pub use fips::FipsConfig;
pub use gateway::{BackendConfig, GatewayConfig};
pub use governance::GovernanceConfig;
pub use grpc_transport::GrpcTransportConfig;
pub use licensing::{LicenseTier, LicenseValidation, LicensingConfig, TierLimits};
pub use limits::LimitsConfig;
pub use metering::MeteringConfig;
pub use policy_lifecycle::PolicyLifecycleConfig;
pub use policy_rule::PolicyRule;
pub use projector::ProjectorConfig;
pub use shield::{ShieldConfig, ShieldCustomPiiPattern};
pub use tool_registry::ToolRegistryConfig;
pub use topology::TopologyConfig;
pub use transport::TransportConfig;
pub use zk_audit::ZkAuditConfig;

use serde::{Deserialize, Serialize};
use vellaveto_types::{Policy, PolicyType};

pub(crate) fn default_true() -> bool {
    true
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    #[serde(default)]
    pub policies: Vec<PolicyRule>,

    /// Optional injection scanning configuration.
    /// When absent, defaults are used (scanning enabled, default patterns only).
    #[serde(default)]
    pub injection: InjectionConfig,

    /// Optional DLP (Data Loss Prevention) scanning configuration.
    /// When absent, defaults are used (scanning enabled, block on finding).
    #[serde(default)]
    pub dlp: DlpConfig,

    /// Optional multimodal content inspection configuration.
    /// Controls scanning of image/audio/video/PDF content for hidden
    /// prompt injection attacks. When absent, scanning is disabled.
    #[serde(default)]
    pub multimodal: MultimodalPolicyConfig,

    /// Optional rate limiting configuration.
    /// When absent, all rate limits are unconfigured (env vars or defaults apply).
    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    /// Optional audit log configuration (redaction level).
    #[serde(default)]
    pub audit: AuditConfig,

    /// Optional supply chain verification configuration.
    #[serde(default)]
    pub supply_chain: SupplyChainConfig,

    /// Optional tool manifest verification configuration.
    #[serde(default)]
    pub manifest: ManifestConfig,

    /// Memory poisoning defense configuration.
    #[serde(default)]
    pub memory_tracking: MemoryTrackingConfig,

    /// Elicitation interception configuration (MCP 2025-06-18).
    #[serde(default)]
    pub elicitation: ElicitationConfig,

    /// Sampling request policy configuration.
    #[serde(default)]
    pub sampling: SamplingConfig,

    /// Audit log export configuration for SIEM integration.
    #[serde(default)]
    pub audit_export: AuditExportConfig,

    /// Maximum percent-decoding iterations for path normalization.
    /// Paths requiring more iterations fail-closed to `"/"` (attack indicator).
    /// Default: 20 (from `vellaveto_engine::DEFAULT_MAX_PATH_DECODE_ITERATIONS`).
    /// Set to 0 to disable iterative decoding (single pass only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_path_decode_iterations: Option<u32>,

    /// Known tool names used for squatting detection. Tools with names
    /// similar to these (Levenshtein distance <= 2 or homoglyph matches)
    /// are flagged. When empty, the built-in default list is used.
    #[serde(default)]
    pub known_tool_names: Vec<String>,

    /// Tool registry configuration.
    #[serde(default)]
    pub tool_registry: ToolRegistryConfig,

    /// Allowed origins for CSRF / DNS rebinding protection.
    ///
    /// When non-empty, the HTTP proxy validates that the `Origin` header (if present)
    /// matches one of these values. When empty, the proxy uses automatic localhost
    /// detection based on the bind address: if bound to `127.0.0.1`, `localhost`,
    /// or `[::1]`, only localhost origins are accepted.
    ///
    /// Requests without an `Origin` header are always allowed (non-browser clients).
    ///
    /// # TOML Example
    ///
    /// ```toml
    /// allowed_origins = ["http://localhost:3001", "http://127.0.0.1:3001"]
    /// ```
    #[serde(default)]
    pub allowed_origins: Vec<String>,

    /// Behavioral anomaly detection configuration (P4.1).
    #[serde(default)]
    pub behavioral: BehavioralDetectionConfig,

    /// Cross-request data flow tracking configuration (P4.2).
    #[serde(default)]
    pub data_flow: DataFlowTrackingConfig,

    /// Semantic injection detection configuration (P4.3).
    /// Requires the `semantic-detection` feature flag on `vellaveto-mcp`.
    #[serde(default)]
    pub semantic_detection: SemanticDetectionConfig,

    /// Distributed clustering configuration (P3.4).
    /// When enabled, Vellaveto instances share approval and rate limit state
    /// via Redis, enabling horizontal scaling behind a load balancer.
    #[serde(default)]
    pub cluster: ClusterConfig,

    // ═══════════════════════════════════════════════════
    // MCP 2025-11-25 CONFIGURATION
    // ═══════════════════════════════════════════════════
    /// Async task lifecycle configuration (MCP 2025-11-25).
    #[serde(default)]
    pub async_tasks: AsyncTaskConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 2: TOOL QUOTAS
    // ═══════════════════════════════════════════════════
    /// Per-tool rate limits and quotas.
    /// Simpler alternative to writing full Conditional policies with
    /// MaxCallsInWindow context conditions. Each entry specifies a tool
    /// pattern and its maximum calls per time window.
    ///
    /// # TOML Example
    ///
    /// ```toml
    /// [[tool_quotas]]
    /// tool_pattern = "execute_command"
    /// max_calls = 10
    /// window_secs = 60
    ///
    /// [[tool_quotas]]
    /// tool_pattern = "write_*"
    /// max_calls = 50
    /// window_secs = 300
    /// ```
    #[serde(default)]
    pub tool_quotas: Vec<ToolQuota>,

    /// Phase 2: Secret substitution — replace secrets with placeholders before
    /// model visibility, restore at execution boundaries.
    #[serde(default)]
    pub secret_substitutions: Vec<SecretSubstitution>,

    /// Phase 2: Declarative policy templates — high-level intent that expands
    /// to full policy rules during config loading.
    #[serde(default)]
    pub policy_templates: Vec<crate::policy_templates::PolicyTemplate>,

    // ═══════════════════════════════════════════════════
    // PHASE 6: CONTROL/DATA CHANNEL SEPARATION
    // ═══════════════════════════════════════════════════
    /// Phase 6.1: Source trust classification — classify tools/servers as
    /// untrusted/verified to drive auto-tainting.
    #[serde(default)]
    pub source_trust: crate::channel_separation::SourceTrustConfig,

    /// Phase 6.1C: Sink classification — policy-driven tool→sink mapping.
    #[serde(default)]
    pub sink_classification: crate::channel_separation::SinkClassificationConfig,

    /// Phase 6.2: Intent scope — constrain what tools/sinks the agent can use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent_scope: Option<crate::channel_separation::IntentScopeConfig>,

    /// RFC 8707 Resource Indicator configuration.
    #[serde(default)]
    pub resource_indicator: ResourceIndicatorConfig,

    /// CIMD (Capability-Indexed Message Dispatch) configuration.
    #[serde(default)]
    pub cimd: CimdConfig,

    /// Step-up authentication configuration.
    #[serde(default)]
    pub step_up_auth: StepUpAuthConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 2: ADVANCED THREAT DETECTION CONFIGURATION
    // ═══════════════════════════════════════════════════
    /// Circuit breaker configuration for cascading failure protection.
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,

    /// Confused deputy prevention configuration.
    #[serde(default)]
    pub deputy: DeputyConfig,

    /// Shadow agent detection configuration.
    #[serde(default)]
    pub shadow_agent: ShadowAgentConfig,

    /// Schema poisoning detection configuration.
    #[serde(default)]
    pub schema_poisoning: SchemaPoisoningConfig,

    /// Sampling attack detection configuration.
    #[serde(default)]
    pub sampling_detection: SamplingDetectionConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 3.2: CROSS-AGENT SECURITY CONFIGURATION
    // ═══════════════════════════════════════════════════
    /// Cross-agent security configuration for multi-agent systems.
    /// Controls trust relationships, message signing, and privilege escalation detection.
    #[serde(default)]
    pub cross_agent: CrossAgentConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 3.3: ADVANCED THREAT DETECTION CONFIGURATION
    // ═══════════════════════════════════════════════════
    /// Advanced threat detection configuration.
    /// Controls goal tracking, workflow monitoring, namespace security, and more.
    #[serde(default)]
    pub advanced_threat: AdvancedThreatConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 5: ENTERPRISE HARDENING CONFIGURATION
    // ═══════════════════════════════════════════════════
    /// TLS/mTLS configuration for secure transport.
    #[serde(default)]
    pub tls: TlsConfig,

    /// SPIFFE/SPIRE workload identity configuration.
    #[serde(default)]
    pub spiffe: SpiffeConfig,

    /// OPA (Open Policy Agent) integration configuration.
    #[serde(default)]
    pub opa: OpaConfig,

    /// Threat intelligence feed configuration.
    #[serde(default)]
    pub threat_intel: ThreatIntelConfig,

    /// Just-In-Time (JIT) access configuration.
    #[serde(default)]
    pub jit_access: JitAccessConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 8: ETDI CRYPTOGRAPHIC TOOL SECURITY
    // ═══════════════════════════════════════════════════
    /// ETDI (Enhanced Tool Definition Interface) configuration.
    /// Provides cryptographic verification of tool definitions to prevent
    /// rug-pulls, tool squatting, and supply chain attacks.
    #[serde(default)]
    pub etdi: EtdiConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 9: MEMORY INJECTION DEFENSE (MINJA)
    // ═══════════════════════════════════════════════════
    /// Memory security configuration for MINJA defense.
    /// Controls taint propagation, provenance tracking, trust decay,
    /// quarantine, and namespace isolation.
    #[serde(default)]
    pub memory_security: MemorySecurityConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 10: NON-HUMAN IDENTITY (NHI) LIFECYCLE
    // ═══════════════════════════════════════════════════
    /// Non-Human Identity (NHI) lifecycle management configuration.
    /// Controls agent identity registration, attestation, behavioral
    /// baselines, credential rotation, and delegation chains.
    #[serde(default)]
    pub nhi: NhiConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 12: SEMANTIC GUARDRAILS
    // ═══════════════════════════════════════════════════
    /// Semantic guardrails configuration for LLM-based policy evaluation.
    /// Enables intent classification, natural language policies, and jailbreak
    /// detection beyond pattern matching.
    #[serde(default)]
    pub semantic_guardrails: SemanticGuardrailsConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 13: RAG POISONING DEFENSE CONFIGURATION
    // ═══════════════════════════════════════════════════
    /// RAG (Retrieval-Augmented Generation) poisoning defense configuration.
    /// Protects against document injection, embedding manipulation, and
    /// context window flooding in RAG systems.
    #[serde(default)]
    pub rag_defense: RagDefenseConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 14: A2A PROTOCOL SECURITY
    // ═══════════════════════════════════════════════════
    /// A2A (Agent-to-Agent) protocol security configuration.
    /// Secures A2A traffic using message interception, policy evaluation,
    /// agent card verification, and existing security managers.
    #[serde(default)]
    pub a2a: A2aConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 15: OBSERVABILITY PLATFORM INTEGRATION
    // ═══════════════════════════════════════════════════
    /// AI observability platform integration configuration.
    /// Enables deep integration with platforms like Langfuse, Arize, and Helicone
    /// for tracing, evaluation, and observability of security decisions.
    #[serde(default)]
    pub observability: ObservabilityConfig,

    // ═══════════════════════════════════════════════════
    // SERVER CONFIGURATION
    // ═══════════════════════════════════════════════════
    /// Metrics endpoint authentication (FIND-004).
    /// When true (default), `/metrics` and `/api/metrics` endpoints require
    /// API key authentication. Set to false to allow unauthenticated access
    /// for Prometheus scrapers in trusted network environments.
    ///
    /// SECURITY NOTE: Metrics expose policy counts, pending approval counts,
    /// and evaluation statistics. Only disable authentication when the metrics
    /// endpoint is protected by network-level controls (e.g., internal VPC only).
    #[serde(default = "default_true")]
    pub metrics_require_auth: bool,

    // ═══════════════════════════════════════════════════
    // RUNTIME LIMITS CONFIGURATION
    // ═══════════════════════════════════════════════════
    /// Runtime limits for proxy and MCP processing.
    /// Controls memory bounds, timeouts, and chain lengths.
    #[serde(default)]
    pub limits: LimitsConfig,

    // ═══════════════════════════════════════════════════
    // COMPLIANCE EVIDENCE CONFIGURATION
    // ═══════════════════════════════════════════════════
    /// Compliance evidence generation configuration (EU AI Act, SOC 2).
    #[serde(default)]
    pub compliance: ComplianceConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 17.4: PROTOCOL EXTENSION FRAMEWORK
    // ═══════════════════════════════════════════════════
    /// Protocol extension framework configuration.
    /// When enabled, allows registering extensions that handle `x-` prefixed methods.
    #[serde(default)]
    pub extension: ExtensionConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 18: MCP JUNE 2026 SPEC COMPLIANCE
    // ═══════════════════════════════════════════════════
    /// Transport discovery and negotiation configuration.
    /// Controls the `/.well-known/mcp-transport` endpoint and upstream fallback.
    #[serde(default)]
    pub transport: TransportConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 20: MCP GATEWAY MODE
    // ═══════════════════════════════════════════════════
    /// Gateway configuration for multi-backend MCP routing.
    /// When enabled, Vellaveto routes tool calls to different upstream
    /// MCP servers based on tool name prefix matching.
    #[serde(default)]
    pub gateway: GatewayConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 21: ADVANCED AUTHORIZATION (ABAC)
    // ═══════════════════════════════════════════════════
    /// Attribute-Based Access Control (ABAC) configuration.
    /// Cedar-style permit/forbid policies with principal/action/resource
    /// matching, least-agency enforcement, identity federation, and
    /// continuous authorization.
    #[serde(default)]
    pub abac: AbacConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 23: RESEARCH & FUTURE
    // ═══════════════════════════════════════════════════
    /// FIPS 140-3 compliance mode configuration (Phase 23.3).
    /// When enabled, restricts cryptographic operations to NIST-approved algorithms.
    /// Requires the `fips` feature flag on `vellaveto-mcp`.
    #[serde(default)]
    pub fips: FipsConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 26: SHADOW AI DETECTION & GOVERNANCE
    // ═══════════════════════════════════════════════════
    /// Governance configuration for shadow AI discovery and least agency enforcement.
    /// Controls passive traffic analysis for unregistered agents/tools/servers,
    /// and automatic revocation of unused permissions.
    #[serde(default)]
    pub governance: GovernanceConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 27: KUBERNETES-NATIVE DEPLOYMENT
    // ═══════════════════════════════════════════════════
    /// Deployment configuration for Kubernetes-native operation.
    /// Controls deployment mode, leader election, and service discovery.
    #[serde(default)]
    pub deployment: DeploymentConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 30: MCP 2025-11-25 STREAMABLE HTTP
    // ═══════════════════════════════════════════════════
    /// Streamable HTTP configuration for MCP 2025-11-25 compliance.
    /// Controls SSE resumability, strict tool name validation, and retry directives.
    #[serde(default)]
    pub streamable_http: StreamableHttpConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 34: TOOL DISCOVERY SERVICE
    // ═══════════════════════════════════════════════════
    /// Tool discovery service configuration.
    /// Enables intent-based tool search with TF-IDF scoring, token budgets,
    /// and TTL-based schema lifecycle management.
    #[serde(default)]
    pub discovery: DiscoveryConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 35.1: MODEL PROJECTOR
    // ═══════════════════════════════════════════════════
    /// Model projector configuration for model-specific tool schema projection.
    /// Controls schema translation between canonical format and model-native formats
    /// (Claude, OpenAI, DeepSeek, Qwen, Generic).
    #[serde(default)]
    pub projector: ProjectorConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 37: ZERO-KNOWLEDGE AUDIT TRAILS
    // ═══════════════════════════════════════════════════
    /// Zero-Knowledge audit trail configuration.
    /// Enables Pedersen commitments and optional Groth16 batch proofs
    /// for privacy-preserving audit verification.
    #[serde(default)]
    pub zk_audit: ZkAuditConfig,

    // ═══════════════════════════════════════════════════
    // LICENSING & TIER MANAGEMENT
    // ═══════════════════════════════════════════════════
    /// License tier configuration and key validation.
    /// Fail-closed: invalid/missing/expired key defaults to Community tier.
    #[serde(default)]
    pub licensing: LicensingConfig,

    /// Enterprise IAM configuration (OIDC/SAML/session/SCIM).
    #[serde(default)]
    pub iam: IamConfig,

    // ═══════════════════════════════════════════════════
    // BILLING WEBHOOK CONFIGURATION
    // ═══════════════════════════════════════════════════
    /// Billing webhook configuration for Paddle and Stripe.
    #[serde(default)]
    pub billing: BillingConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 43: CENTRALIZED AUDIT STORE
    // ═══════════════════════════════════════════════════
    /// Centralized audit store configuration for dual-writing to PostgreSQL
    /// and structured audit log querying.
    #[serde(default)]
    pub audit_store: AuditStoreConfig,

    // Phase 47: Policy Lifecycle Management
    #[serde(default)]
    pub policy_lifecycle: PolicyLifecycleConfig,

    // ═══════════════════════════════════════════════════
    // PHASE 50: USAGE METERING & BILLING FOUNDATION
    // ═══════════════════════════════════════════════════
    /// Usage metering configuration for per-tenant billing.
    /// When enabled, tracks evaluations/policies/approvals per billing period
    /// and enforces hard evaluation quotas by license tier.
    #[serde(default)]
    pub metering: MeteringConfig,

    // ═══════════════════════════════════════════════════
    // TOPOLOGY CRAWLING (ActionEngine-inspired)
    // ═══════════════════════════════════════════════════
    /// Topology crawling configuration for live MCP server discovery.
    /// When enabled, periodically probes MCP servers to build a topology
    /// graph used for pre-policy tool call filtering.
    #[serde(default)]
    pub topology: TopologyConfig,

    // ═══════════════════════════════════════════════════
    // CONSUMER SHIELD CONFIGURATION
    // ═══════════════════════════════════════════════════
    /// Consumer shield configuration for bidirectional PII sanitization,
    /// session isolation, and encrypted local audit.
    #[serde(default)]
    pub shield: ShieldConfig,

    // ═══════════════════════════════════════════════════
    // ACIS (AGENT-CONSUMER INTERACTION SURFACE)
    // ═══════════════════════════════════════════════════
    /// ACIS decision envelope configuration — controls envelope emission,
    /// session/identity binding requirements, and transport defaults.
    #[serde(default)]
    pub acis: AcisConfig,
}

impl PolicyConfig {
    /// Parse config from a JSON string.
    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json_str)
    }

    /// Parse config from a TOML string.
    pub fn from_toml(toml_str: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(toml_str)
    }

    /// Convert PolicyRules into vellaveto_types::Policy structs.
    ///
    /// Phase 2: Also expands `policy_templates` into full policy rules.
    ///
    /// SECURITY (R229-CFG-1): Each constructed Policy is validated via `Policy::validate()`
    /// to enforce bounds on path/domain/CIDR entries and reject dangerous characters.
    /// Invalid policies are logged and skipped (fail-closed: excluded from active set).
    pub fn to_policies(&self) -> Vec<Policy> {
        // Phase 2: Expand policy templates into PolicyRules and prepend them.
        let mut all_rules: Vec<&PolicyRule> = self.policies.iter().collect();
        let mut expanded_rules: Vec<PolicyRule> = Vec::new();
        for tpl in &self.policy_templates {
            if let Err(e) = tpl.validate() {
                tracing::warn!("Skipping invalid policy template '{}': {}", tpl.name, e);
                continue;
            }
            let expanded_json = tpl.expand();
            match serde_json::from_value::<PolicyRule>(expanded_json) {
                Ok(rule) => expanded_rules.push(rule),
                Err(e) => {
                    tracing::warn!("Failed to expand policy template '{}': {}", tpl.name, e);
                }
            }
        }
        let expanded_refs: Vec<&PolicyRule> = expanded_rules.iter().collect();
        // Templates come first so they're included in the policy set
        let combined: Vec<&PolicyRule> = expanded_refs
            .into_iter()
            .chain(all_rules.drain(..))
            .collect();

        combined
            .iter()
            .filter_map(|rule| {
                let id = rule
                    .id
                    .clone()
                    .unwrap_or_else(|| format!("{}:{}", rule.tool_pattern, rule.function_pattern));
                // SECURITY (R19-CFG-1): Default to 0, not 100
                let priority = rule.priority.unwrap_or(0);
                let policy = Policy {
                    id: id.clone(),
                    name: rule.name.clone(),
                    policy_type: rule.policy_type.clone(),
                    priority,
                    // SECURITY (R12-CFG-1): Preserve path_rules and network_rules
                    // from config. Previously hardcoded to None, silently discarding
                    // all file-path and domain constraints from config-defined policies.
                    path_rules: rule.path_rules.clone(),
                    network_rules: rule.network_rules.clone(),
                };
                // SECURITY (R229-CFG-1): Validate constructed policy.
                if let Err(e) = policy.validate() {
                    tracing::warn!(
                        policy_id = %id,
                        error = %e,
                        "Skipping invalid policy from config"
                    );
                    return None;
                }
                Some(policy)
            })
            .collect()
    }
}
