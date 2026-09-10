// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! MCP Streamable HTTP reverse proxy.
//!
//! Implements the Streamable HTTP transport (MCP spec 2025-11-25) as a
//! reverse proxy that intercepts tool calls, evaluates policies, and
//! forwards allowed requests to an upstream MCP server.

mod auth;
pub mod call_chain;
pub mod discovery;
mod fallback;
pub mod gateway;
#[cfg(feature = "grpc")]
pub mod grpc;
mod handlers;
mod helpers;
mod inspection;
pub mod origin;
mod request_state;
mod server_request;
pub mod smart_fallback;
#[cfg(test)]
mod tests;
pub mod trace_propagation;
pub mod transport_health;
mod upstream;
pub mod websocket;

pub use call_chain::PrivilegeEscalationCheck;
pub use discovery::handle_transport_discovery;
pub use handlers::{
    handle_mcp_delete, handle_mcp_get, handle_mcp_post, handle_protected_resource_metadata,
};
pub use websocket::{handle_ws_upgrade, WebSocketConfig};

use hmac::Hmac;
use sha2::Sha256;
use std::net::SocketAddr;
use std::sync::Arc;
use vellaveto_approval::ApprovalStore;
use vellaveto_audit::AuditLogger;
use vellaveto_config::ManifestConfig;
use vellaveto_engine::PolicyEngine;
use vellaveto_engine::{circuit_breaker::CircuitBreakerManager, deputy::DeputyValidator};
use vellaveto_mcp::extension_registry::ExtensionRegistry;
use vellaveto_mcp::inspection::InjectionScanner;
use vellaveto_mcp::mediation::MediationConfig;
use vellaveto_mcp::output_validation::OutputSchemaRegistry;
use vellaveto_mcp::{
    auth_level::AuthLevelTracker, sampling_detector::SamplingDetector,
    schema_poisoning::SchemaLineageTracker, shadow_agent::ShadowAgentDetector,
};
use vellaveto_types::{Policy, SessionKeyScope, WorkloadIdentity};

use crate::oauth::OAuthValidator;
use crate::session::SessionStore;

/// HMAC-SHA256 type alias for call chain signing (FIND-015).
pub type HmacSha256 = Hmac<Sha256>;

/// Query parameters for POST /mcp.
#[derive(Debug, serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct McpQueryParams {
    /// When true, include evaluation trace in the response.
    #[serde(default)]
    pub trace: bool,
}

/// Detached request-signature freshness policy applied before replay checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetachedSignatureFreshnessConfig {
    pub max_age_secs: u64,
    pub max_future_skew_secs: u64,
}

impl Default for DetachedSignatureFreshnessConfig {
    fn default() -> Self {
        Self {
            max_age_secs: 600,
            max_future_skew_secs: 300,
        }
    }
}

impl From<&vellaveto_config::AcisConfig> for DetachedSignatureFreshnessConfig {
    fn from(acis: &vellaveto_config::AcisConfig) -> Self {
        Self {
            max_age_secs: acis.detached_request_signature_max_age_secs,
            max_future_skew_secs: acis.detached_request_signature_max_future_skew_secs,
        }
    }
}

/// Trusted detached signer metadata used at verification time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedRequestSigner {
    pub public_key: [u8; 32],
    pub session_key_scope: SessionKeyScope,
    pub execution_is_ephemeral: bool,
    pub workload_identity: Option<WorkloadIdentity>,
}

/// Shared state for the HTTP proxy handlers.
#[derive(Clone)]
pub struct ProxyState {
    pub engine: Arc<PolicyEngine>,
    pub policies: Arc<Vec<Policy>>,
    pub audit: Arc<AuditLogger>,
    pub sessions: Arc<SessionStore>,
    pub upstream_url: String,
    pub http_client: reqwest::Client,
    /// When true, responses may be padded to fixed size buckets — but only for
    /// clients that explicitly negotiate it. A padded body is not valid JSON, so
    /// a client that did not ask always gets the unpadded body.
    pub traffic_padding: bool,

    /// When true, correlation and tracing headers are not propagated upstream.
    ///
    /// `traceparent`, `tracestate`, and the `x-*-trace-id` family let an
    /// upstream operator link a user's requests across sessions, which is
    /// exactly what the Consumer Shield exists to prevent. Off by default
    /// because stripping them also breaks distributed tracing through the proxy.
    pub strip_privacy_headers: bool,
    /// OAuth 2.1 JWT validator. When `Some`, all MCP requests require a valid Bearer token.
    pub oauth: Option<Arc<OAuthValidator>>,
    /// Custom injection scanner. When `Some`, uses configured patterns instead of defaults.
    pub injection_scanner: Option<Arc<InjectionScanner>>,
    /// When true, injection scanning is completely disabled.
    pub injection_disabled: bool,
    /// When true, injection matches block the response instead of just logging (H4).
    pub injection_blocking: bool,
    /// API key for authenticating requests. None disables auth (--allow-anonymous).
    pub api_key: Option<Arc<String>>,
    /// Optional approval store for RequireApproval verdicts.
    /// When set, creates pending approvals with approval_id in error response data.
    pub approval_store: Option<Arc<ApprovalStore>>,
    /// Optional manifest verification config. When set, tools/list responses
    /// are verified against a pinned manifest per session.
    pub manifest_config: Option<ManifestConfig>,
    /// Allowed origins for CSRF / DNS rebinding protection. If non-empty,
    /// Origin must be in the allowlist. If empty and the proxy is bound to a
    /// loopback address, only localhost origins are accepted. If empty and
    /// bound to a non-loopback address, falls back to same-origin check
    /// (Origin host must match Host header).
    /// Requests without an Origin header are always allowed (non-browser clients).
    pub allowed_origins: Vec<String>,
    /// The socket address the proxy is bound to. Used for automatic localhost
    /// origin validation when `allowed_origins` is empty.
    pub bind_addr: SocketAddr,
    /// When true, re-serialize parsed JSON-RPC messages before forwarding to
    /// upstream. This closes the TOCTOU gap where the proxy evaluates a parsed
    /// representation but forwards original bytes that could differ (e.g., due to
    /// duplicate keys or parser-specific handling). Duplicate keys are always
    /// rejected regardless of this setting.
    pub canonicalize: bool,
    /// Output schema registry for structuredContent validation (MCP 2025-06-18).
    pub output_schema_registry: Arc<OutputSchemaRegistry>,
    /// When true, scan tool responses for secrets (DLP response scanning).
    pub response_dlp_enabled: bool,
    /// When true, block responses that contain detected secrets instead of just logging.
    /// SECURITY (R18-DLP-BLOCK): Without this, DLP is log-only and secrets still reach the client.
    pub response_dlp_blocking: bool,
    /// Strict audit mode (FIND-CREATIVE-003): When true, audit logging failures
    /// cause requests to be denied instead of proceeding without an audit trail.
    /// This enforces non-repudiation guarantees — no unaudited security decisions
    /// can occur. Default: false (backward compatible).
    pub audit_strict_mode: bool,
    /// Shared mediation-stage controls for provenance and semantic containment.
    /// HTTP handlers keep their existing request scanners and use this config
    /// for ACIS binding, provenance, and sink/lineage enforcement.
    pub mediation_config: MediationConfig,
    /// Trusted detached request-signature signers keyed by `RequestSignature.key_id`.
    /// Used to promote detached per-request signatures from metadata to verified provenance.
    pub trusted_request_signers: Arc<std::collections::HashMap<String, TrustedRequestSigner>>,
    /// Freshness limits for verified detached request signatures.
    pub detached_signature_freshness: DetachedSignatureFreshnessConfig,
    /// Known legitimate tool names for squatting detection.
    /// Built from DEFAULT_KNOWN_TOOLS + any config overrides.
    pub known_tools: std::collections::HashSet<String>,
    /// Elicitation interception configuration (MCP 2025-06-18).
    /// Controls whether `elicitation/create` requests are allowed or blocked.
    pub elicitation_config: vellaveto_config::ElicitationConfig,
    /// Sampling request policy configuration.
    /// Controls whether `sampling/createMessage` requests are allowed or blocked.
    pub sampling_config: vellaveto_config::SamplingConfig,
    /// Tool registry for tracking tool trust scores (P2.1).
    /// None when tool registry is disabled.
    pub tool_registry: Option<Arc<vellaveto_mcp::tool_registry::ToolRegistry>>,
    /// HMAC-SHA256 key for signing and verifying X-Upstream-Agents call chain entries (FIND-015).
    /// When `Some`, Vellaveto signs its own chain entries and verifies incoming ones.
    /// When `None`, chain signing/verification is disabled (backward compatible).
    pub call_chain_hmac_key: Option<[u8; 32]>,
    /// When true, the `?trace=true` query parameter is honored and evaluation
    /// traces are included in responses. When false (the default), trace output
    /// is silently suppressed regardless of the client query parameter.
    ///
    /// SECURITY: Traces expose internal policy names, patterns, and constraint
    /// configurations. Leaving this disabled prevents information leakage to
    /// authenticated clients.
    pub trace_enabled: bool,

    // =========================================================================
    // Phase 3.1 Security Managers
    // =========================================================================
    /// Circuit breaker for cascading failure prevention (OWASP ASI08).
    /// When a tool fails repeatedly, the circuit opens and subsequent calls are rejected.
    pub circuit_breaker: Option<Arc<CircuitBreakerManager>>,

    /// Shadow agent detector for agent impersonation detection.
    /// Tracks known agent fingerprints and alerts on impersonation attempts.
    pub shadow_agent: Option<Arc<ShadowAgentDetector>>,

    /// Deputy validator for confused deputy attack prevention (OWASP ASI02).
    /// Tracks delegation chains and validates action permissions.
    pub deputy: Option<Arc<DeputyValidator>>,

    /// Schema lineage tracker for schema poisoning detection (OWASP ASI05).
    /// Tracks tool schema changes and alerts on suspicious mutations.
    pub schema_lineage: Option<Arc<SchemaLineageTracker>>,

    /// Auth level tracker for step-up authentication.
    /// Tracks session auth levels and enforces step-up requirements.
    pub auth_level: Option<Arc<AuthLevelTracker>>,

    /// Sampling detector for sampling attack prevention.
    /// Tracks sampling request patterns and enforces rate limits.
    pub sampling_detector: Option<Arc<SamplingDetector>>,

    // =========================================================================
    // Runtime Limits
    // =========================================================================
    /// Configurable runtime limits for memory bounds, timeouts, and chain lengths.
    /// Provides operator control over previously hardcoded security constants.
    pub limits: vellaveto_config::LimitsConfig,

    // =========================================================================
    // WebSocket Transport (Phase 17.1 — SEP-1288)
    // =========================================================================
    /// WebSocket transport configuration. When `Some`, the `/mcp/ws` endpoint
    /// is active with the specified message size, idle timeout, and rate limit.
    /// When `None`, WebSocket requests use default configuration.
    pub ws_config: Option<WebSocketConfig>,

    // =========================================================================
    // Protocol Extensions (Phase 17.4)
    // =========================================================================
    /// Extension registry for `x-` prefixed protocol extensions.
    /// When `Some`, extension method calls are routed to registered handlers
    /// before falling back to upstream forwarding.
    pub extension_registry: Option<Arc<ExtensionRegistry>>,

    // =========================================================================
    // Phase 18: Transport Discovery & Negotiation
    // =========================================================================
    /// Transport discovery and negotiation configuration.
    pub transport_config: vellaveto_config::TransportConfig,

    /// gRPC listen port, when gRPC transport is enabled.
    /// Used by the discovery endpoint to advertise the gRPC endpoint.
    pub grpc_port: Option<u16>,

    // =========================================================================
    // Phase 20: MCP Gateway Mode
    // =========================================================================
    /// Multi-backend gateway router. When `Some`, tool calls are routed to
    /// different upstream MCP servers based on tool name prefix matching.
    /// When `None`, all requests use `upstream_url` (single-server mode).
    pub gateway: Option<Arc<gateway::GatewayRouter>>,

    // =========================================================================
    // Phase 21: Advanced Authorization (ABAC)
    // =========================================================================
    /// ABAC policy engine for Cedar-style permit/forbid evaluation.
    /// When `Some`, refines Allow verdicts from the PolicyEngine.
    /// When `None`, behavior is identical to pre-Phase 21.
    pub abac_engine: Option<Arc<vellaveto_engine::abac::AbacEngine>>,
    /// Least-agency tracker for permission usage monitoring.
    /// When `Some`, records which permissions each agent actually uses.
    pub least_agency: Option<Arc<vellaveto_engine::least_agency::LeastAgencyTracker>>,
    /// Continuous authorization config for risk-based deny.
    pub continuous_auth_config: Option<vellaveto_config::abac::ContinuousAuthConfig>,

    // =========================================================================
    // Phase 29: Cross-Transport Smart Fallback
    // =========================================================================
    /// Per-transport circuit breaker tracker. When `Some` and
    /// `transport_config.cross_transport_fallback` is true, failed transports
    /// trigger automatic fallback to the next transport in priority order.
    pub transport_health: Option<Arc<transport_health::TransportHealthTracker>>,

    // =========================================================================
    // Phase 30: MCP 2025-11-25 Streamable HTTP
    // =========================================================================
    /// Streamable HTTP configuration for SSE resumability, strict tool name
    /// validation, and retry directives.
    pub streamable_http: vellaveto_config::StreamableHttpConfig,

    // =========================================================================
    // Phase 39: Agent Identity Federation
    // =========================================================================
    /// Federation resolver for cross-organization agent identity validation.
    /// When `Some`, incoming JWTs are checked against federation trust anchors
    /// before falling back to the local OAuth validator.
    pub federation: Option<Arc<crate::federation::FederationResolver>>,

    // =========================================================================
    // Phase 34: Tool Discovery Service
    // =========================================================================
    /// Tool discovery engine for intent-based tool search.
    /// When `Some`, the proxy intercepts `vv_discover` tool calls and returns
    /// discovered tool schemas without forwarding to upstream.
    #[cfg(feature = "discovery")]
    pub discovery_engine: Option<std::sync::Arc<vellaveto_mcp::discovery::DiscoveryEngine>>,

    // =========================================================================
    // Phase 35.3: Model Projector
    // =========================================================================
    /// Model projector registry for cross-model tool schema translation.
    /// When `Some`, tool schemas can be projected to model-specific formats.
    #[cfg(feature = "projector")]
    pub projector_registry: Option<std::sync::Arc<vellaveto_mcp::projector::ProjectorRegistry>>,

    // =========================================================================
    // Content-Bound Attestation (SecurityContextToken HMAC)
    // =========================================================================
    /// Optional HMAC-SHA256 key for content-bound attestation.
    /// When set, `vellaveto_attestation` is attached to `_meta` on every
    /// JSON response, binding scan results to the response content hash.
    /// Read from `VELLAVETO_ATTESTATION_SECRET` env var at startup.
    pub attestation_hmac_key: Option<Vec<u8>>,
}

/// Per-request trust signal for forwarded-header handling.
///
/// FIND-R56-HTTP-002: `from_trusted_proxy` is `pub(crate)` to prevent external
/// code from constructing a `TrustedProxyContext { from_trusted_proxy: true }`
/// and injecting it as a spoofed trust signal. Use `is_from_trusted_proxy()`
/// for read access from outside the crate.
#[derive(Clone, Copy, Debug)]
pub struct TrustedProxyContext {
    pub(crate) from_trusted_proxy: bool,
}

impl TrustedProxyContext {
    /// Create a new `TrustedProxyContext`.
    pub fn new(from_trusted_proxy: bool) -> Self {
        Self { from_trusted_proxy }
    }

    /// Returns whether the request came from a trusted reverse proxy.
    pub fn is_from_trusted_proxy(&self) -> bool {
        self.from_trusted_proxy
    }
}

/// MCP Session ID header name.
const MCP_SESSION_ID: &str = "mcp-session-id";

/// MCP protocol version header (MCP 2025-06-18 spec requirement).
const MCP_PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";

/// MCP method routing header (MCP 2026-07-28).
const MCP_METHOD_HEADER: &str = "mcp-method";

/// MCP name routing header (MCP 2026-07-28).
const MCP_NAME_HEADER: &str = "mcp-name";

/// The protocol version value this proxy speaks.
/// FIND-R56-HTTP-006: Renamed from `MCP_PROTOCOL_VERSION` to avoid confusion
/// with `MCP_PROTOCOL_VERSION_HEADER` (the header name).
const MCP_PROTOCOL_VERSION_VALUE: &str = "2026-07-28";

/// Supported MCP protocol versions for incoming requests.
/// Policy still applies a configurable version floor before accepting them.
#[cfg(test)]
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] =
    &["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"];

/// Header for client transport preference negotiation (MCP June 2026).
/// Clients may send a comma-separated list of preferred transports.
/// Used in request handling when transport-preference-aware routing is active.
const MCP_TRANSPORT_PREFERENCE_HEADER: &str = "mcp-transport-preference";

/// OWASP ASI08: Header for tracking upstream agents in multi-hop MCP scenarios.
/// Contains a JSON-encoded array of CallChainEntry objects from previous hops.
/// This header is added by Vellaveto when forwarding requests downstream
/// and read when receiving requests from upstream.
pub const X_UPSTREAM_AGENTS: &str = "x-upstream-agents";

/// SECURITY (FIND-R41-001): Allowlist of headers forwarded to upstream.
/// Only these headers are forwarded to prevent leaking internal/sensitive
/// headers (e.g., authorization, cookies) to upstream backends.
/// Shared by `fallback.rs` and `smart_fallback.rs`.
pub(crate) const FORWARDED_HEADERS: &[&str] = &[
    "content-type",
    "accept",
    "user-agent",
    "traceparent",
    "tracestate",
    "x-request-id",
];

/// Maximum response body size from upstream (16 MB).
/// SECURITY (FIND-R41-004, FIND-R42-020): Prevents unbounded memory
/// allocation from malicious upstream responses.
/// Shared by `fallback.rs` and `smart_fallback.rs`.
pub(crate) const MAX_RESPONSE_BODY_BYTES: usize = 16 * 1024 * 1024;

/// SECURITY (R240-PROXY-1/2): Validate that an upstream URL uses HTTPS for non-local hosts.
/// Only allows plaintext HTTP for localhost/127.0.0.1/[::1] (local development).
/// Returns `Ok(())` if the URL is safe to use, `Err(reason)` if it should be rejected.
pub(crate) fn validate_upstream_url_scheme(url: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|_| "invalid upstream URL".to_string())?;
    match parsed.scheme() {
        "https" | "wss" => Ok(()),
        "http" | "ws" => {
            let host = parsed
                .host_str()
                .ok_or_else(|| "upstream URL must include a host".to_string())?;
            if is_loopback_upstream_host(host) {
                Ok(())
            } else {
                Err("HTTPS required for non-local upstream".to_string())
            }
        }
        _ => Err("unsupported upstream URL scheme".to_string()),
    }
}

fn is_loopback_upstream_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    let host_for_ip = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    host_for_ip
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

/// OWASP ASI07: Header for cryptographically attested agent identity.
/// Contains a signed JWT with claims identifying the agent (issuer, subject, custom claims).
/// Provides stronger identity guarantees than the simple agent_id string derived from OAuth.
const X_AGENT_IDENTITY: &str = "x-agent-identity";

/// Header carrying authenticated workload claims for transport provenance.
/// The value is a base64url-encoded JSON object with allowlisted workload fields.
const X_WORKLOAD_CLAIMS: &str = "x-workload-claims";

/// Header carrying detached per-request signature metadata for provenance.
/// The value is a base64url-encoded `RequestSignature` JSON object.
const X_REQUEST_SIGNATURE: &str = "x-request-signature";
