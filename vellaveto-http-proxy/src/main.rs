// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Vellaveto MCP HTTP Proxy — Streamable HTTP reverse proxy.
//!
//! This binary runs an HTTP reverse proxy that sits between MCP clients and
//! an upstream MCP server. It intercepts JSON-RPC messages over the Streamable
//! HTTP transport, evaluates tool calls against loaded policies, and forwards
//! allowed requests.

use anyhow::{Context, Result};
use axum::{
    extract::{Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use clap::{Parser, ValueEnum};
use governor::{Quota, RateLimiter};
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use vellaveto_audit::AuditLogger;
use vellaveto_config::PolicyConfig;
use vellaveto_engine::PolicyEngine;
use vellaveto_http_proxy::oauth::{
    default_dpop_allowed_algorithms, DpopMode, OAuthConfig, OAuthValidator,
};
use vellaveto_http_proxy::proxy::{self, ProxyState};
use vellaveto_http_proxy::session::SessionStore;
use vellaveto_mcp::output_validation::OutputSchemaRegistry;

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum OAuthDpopModeArg {
    Off,
    Optional,
    Required,
}

impl From<OAuthDpopModeArg> for DpopMode {
    fn from(value: OAuthDpopModeArg) -> Self {
        match value {
            OAuthDpopModeArg::Off => DpopMode::Off,
            OAuthDpopModeArg::Optional => DpopMode::Optional,
            OAuthDpopModeArg::Required => DpopMode::Required,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum OAuthSecurityProfileArg {
    /// Backwards-compatible behavior with minimal startup constraints.
    Standard,
    /// Enforce sender-constrained token posture at startup.
    Hardened,
}

/// SECURITY (R237-TLS-1): TLS handshake timeout — 10 seconds to prevent
/// Slowloris-style attacks that hold connections in mid-handshake indefinitely.
const TLS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// SECURITY (R236-TLS-2): TLS listener wrapper implementing axum's Listener
/// trait. Accepts TCP connections, performs TLS handshake, and returns the
/// encrypted stream.
struct TlsListener {
    inner: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, addr) = match self.inner.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::error!("TCP accept failed: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
            };
            // SECURITY (R237-TLS-1): Timeout the TLS handshake to prevent
            // Slowloris DoS attacks that hold connections in mid-handshake.
            match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, self.acceptor.accept(stream)).await {
                Ok(Ok(tls_stream)) => return (tls_stream, addr),
                Ok(Err(e)) => {
                    tracing::warn!(peer = %addr, "TLS handshake failed: {e}");
                }
                Err(_) => {
                    tracing::warn!(peer = %addr, "TLS handshake timed out after {}s", TLS_HANDSHAKE_TIMEOUT.as_secs());
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

#[derive(Parser)]
#[command(
    name = "vellaveto-http-proxy",
    version,
    about = "Vellaveto MCP Streamable HTTP reverse proxy"
)]
struct Args {
    /// Upstream MCP server URL (e.g., http://localhost:8000/mcp)
    #[arg(long)]
    upstream: String,

    /// Listen address (host:port)
    #[arg(long, default_value = "127.0.0.1:3001")]
    listen: String,

    /// Policy config file path (JSON or TOML)
    #[arg(short, long)]
    config: String,

    /// Audit log file path
    #[arg(long, default_value = "audit.log")]
    audit_log: String,

    /// Session timeout in seconds
    #[arg(long, default_value_t = 1800)]
    session_timeout: u64,

    /// Maximum concurrent sessions
    #[arg(long, default_value_t = 1000)]
    max_sessions: usize,

    /// Strict policy evaluation mode
    #[arg(long)]
    strict: bool,

    /// OAuth 2.1 issuer URL (enables OAuth token validation)
    #[arg(long)]
    oauth_issuer: Option<String>,

    /// OAuth 2.1 expected audience claim
    #[arg(long, default_value = "mcp-server")]
    oauth_audience: String,

    /// OAuth 2.1 JWKS endpoint URL (defaults to {issuer}/.well-known/jwks.json)
    #[arg(long)]
    oauth_jwks_uri: Option<String>,

    /// Required OAuth scopes (comma-separated)
    #[arg(long, value_delimiter = ',')]
    oauth_scopes: Vec<String>,

    /// Forward the OAuth Bearer token to the upstream MCP server
    #[arg(long)]
    oauth_pass_through: bool,

    /// Explicitly acknowledge and allow forwarding bearer tokens upstream.
    /// Use only when the upstream server must validate tokens directly.
    #[arg(long, default_value_t = false)]
    unsafe_oauth_pass_through: bool,

    /// Expected RFC 8707 resource indicator for OAuth token validation.
    /// When set, JWT tokens must contain a matching `resource` claim.
    #[arg(long)]
    oauth_expected_resource: Option<String>,

    /// DPoP proof mode for OAuth requests (`off`, `optional`, `required`).
    #[arg(long, value_enum, default_value_t = OAuthDpopModeArg::Off)]
    oauth_dpop_mode: OAuthDpopModeArg,

    /// OAuth hardening profile.
    /// `hardened` enforces RFC 8707 expected resource and sender-constrained DPoP.
    #[arg(long, value_enum, default_value_t = OAuthSecurityProfileArg::Standard)]
    oauth_security_profile: OAuthSecurityProfileArg,

    /// Maximum allowed clock skew for DPoP proof iat validation (seconds).
    #[arg(long, default_value_t = 300)]
    oauth_dpop_max_clock_skew_secs: u64,

    /// Require access-token binding via DPoP `ath` claim.
    #[arg(long, default_value_t = true)]
    oauth_dpop_require_ath: bool,

    /// Allow starting without VELLAVETO_API_KEY (unauthenticated mode).
    /// WARNING: All MCP endpoints will have no access control beyond OAuth (if configured).
    #[arg(long, default_value_t = false)]
    allow_anonymous: bool,

    /// Absolute session lifetime in seconds. Sessions older than this are
    /// expired regardless of activity. 0 = no absolute limit (default: 86400 = 24h).
    #[arg(long, default_value_t = 86400)]
    session_max_lifetime: u64,

    /// Disable re-serialization of JSON-RPC messages before forwarding to upstream.
    /// By default, messages are re-serialized (canonicalized) to close the TOCTOU gap
    /// where the proxy evaluates a parsed representation but forwards original bytes.
    /// Use --no-canonicalize only if upstream requires exact byte-for-byte forwarding.
    #[arg(long)]
    no_canonicalize: bool,

    /// Maximum requests per second (global rate limit). 0 = no limit.
    #[arg(long, default_value_t = 200)]
    rate_limit: u32,

    /// Maximum WebSocket message size in bytes (default: 1048576 = 1 MB).
    #[arg(long, default_value_t = 1_048_576)]
    ws_max_message_size: usize,

    /// WebSocket idle timeout in seconds (default: 300). 0 = no timeout.
    #[arg(long, default_value_t = 300)]
    ws_idle_timeout: u64,

    /// Maximum WebSocket messages per second per connection (default: 100). 0 = no limit.
    #[arg(long, default_value_t = 100)]
    ws_message_rate_limit: u32,

    /// gRPC transport listen port (default: 50051). Requires --features grpc.
    #[arg(long, default_value_t = 50051)]
    grpc_port: u16,

    /// gRPC maximum message size in bytes (default: 4194304 = 4 MB).
    #[arg(long, default_value_t = 4_194_304)]
    grpc_max_message_size: usize,

    /// Upstream gRPC URL for native gRPC-to-gRPC forwarding.
    /// When absent, gRPC requests are converted to HTTP and forwarded to --upstream.
    #[arg(long)]
    upstream_grpc_url: Option<String>,

    /// Enable gRPC transport (requires --features grpc at compile time).
    #[arg(long)]
    grpc: bool,
}

fn resolve_oauth_security(args: &Args) -> Result<DpopMode> {
    let mut dpop_mode: DpopMode = args.oauth_dpop_mode.into();

    if args.oauth_issuer.is_none() {
        return Ok(dpop_mode);
    }

    if args.oauth_security_profile == OAuthSecurityProfileArg::Hardened {
        if args.oauth_expected_resource.is_none() {
            anyhow::bail!("Hardened OAuth profile requires --oauth-expected-resource (RFC 8707).");
        }

        if dpop_mode != DpopMode::Required {
            tracing::warn!(
                "Hardened OAuth profile overrides DPoP mode to required (sender-constrained tokens)"
            );
            dpop_mode = DpopMode::Required;
        }
    } else {
        if dpop_mode == DpopMode::Off {
            tracing::warn!(
                "OAuth is enabled with DPoP mode off. \
                 Consider --oauth-security-profile hardened for sender-constrained tokens."
            );
        }
        if args.oauth_expected_resource.is_none() {
            tracing::warn!(
                "OAuth is enabled without --oauth-expected-resource. \
                 Configure RFC 8707 resource binding to reduce token replay risk across resource servers."
            );
        }
    }

    if args.oauth_pass_through {
        if !args.unsafe_oauth_pass_through {
            anyhow::bail!(
                "--oauth-pass-through is blocked by default. Re-run with \
                 --unsafe-oauth-pass-through only if this deployment requires it."
            );
        }

        if args.oauth_expected_resource.is_none() {
            anyhow::bail!(
                "--oauth-pass-through requires --oauth-expected-resource \
                 to prevent cross-resource token replay."
            );
        }

        if dpop_mode != DpopMode::Required {
            anyhow::bail!(
                "--oauth-pass-through requires --oauth-dpop-mode required \
                 (sender-constrained proof)."
            );
        }

        tracing::warn!(
            "UNSAFE MODE: OAuth bearer token pass-through enabled; \
             upstream token handling is now part of the trust boundary."
        );
    } else if args.unsafe_oauth_pass_through {
        tracing::warn!(
            "--unsafe-oauth-pass-through was set but --oauth-pass-through is disabled; ignoring."
        );
    }

    Ok(dpop_mode)
}

fn build_trusted_request_signers(
    policy_config: &PolicyConfig,
) -> Result<HashMap<String, crate::proxy::TrustedRequestSigner>> {
    let mut trusted_request_signers = HashMap::new();
    let mut trusted_request_signer_keys = std::collections::HashSet::new();
    for signer in &policy_config.acis.trusted_request_signers {
        let key_bytes = hex::decode(&signer.public_key).with_context(|| {
            format!(
                "Invalid acis.trusted_request_signers public key for key_id '{}'",
                signer.key_id
            )
        })?;
        let key_array: [u8; 32] = key_bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!(
                "acis.trusted_request_signers public key for '{}' must be 32 bytes",
                signer.key_id
            )
        })?;
        trusted_request_signer_keys
            .insert(key_array)
            .then_some(())
            .ok_or_else(|| {
                anyhow::anyhow!("duplicate acis.trusted_request_signers public key is not allowed")
            })?;
        trusted_request_signers
            .insert(
                signer.key_id.clone(),
                crate::proxy::TrustedRequestSigner {
                    public_key: key_array,
                    session_key_scope: signer.session_key_scope,
                    execution_is_ephemeral: signer.execution_is_ephemeral,
                    workload_identity: signer.workload_identity.clone(),
                },
            )
            .is_none()
            .then_some(())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "duplicate acis.trusted_request_signers key_id '{}' is not allowed",
                    signer.key_id
                )
            })?;
    }
    Ok(trusted_request_signers)
}

fn parse_trusted_proxies_env() -> Vec<std::net::IpAddr> {
    std::env::var("VELLAVETO_TRUSTED_PROXIES")
        .ok()
        .map(|value| {
            value
                .split(',')
                .filter_map(|raw| {
                    let trimmed = raw.trim();
                    if trimmed.is_empty() {
                        return None;
                    }
                    match trimmed.parse::<std::net::IpAddr>() {
                        Ok(ip) => Some(ip),
                        Err(_) => {
                            tracing::warn!(
                                proxy_ip = %trimmed,
                                "Invalid trusted proxy IP in VELLAVETO_TRUSTED_PROXIES"
                            );
                            None
                        }
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    // SECURITY: Warn if upstream does not use TLS
    if args.upstream.starts_with("http://") {
        tracing::warn!(
            "SECURITY: Upstream URL uses plaintext HTTP ({}). \
             Tool-call payloads and credentials will be transmitted unencrypted. \
             Use https:// in production.",
            args.upstream
        );
    }

    // Load and compile policies
    let policy_config = PolicyConfig::load_file(&args.config)
        .map_err(|e| anyhow::anyhow!("Failed to load config: {e}"))?;

    // SEC-006: Validate DLP patterns compile at startup (fail-closed).
    // If any pattern is invalid, fail immediately rather than silently skipping
    // secret detection for that pattern at runtime.
    if let Err(failures) = vellaveto_mcp::inspection::validate_dlp_patterns() {
        for (name, error) in &failures {
            tracing::error!("DLP pattern '{}' failed to compile: {}", name, error);
        }
        anyhow::bail!(
            "DLP pattern validation failed: {} pattern(s) could not compile. \
             Fix the patterns or disable DLP scanning.",
            failures.len()
        );
    }

    // Validate injection patterns compile at startup (fail-closed).
    if let Err(error) = vellaveto_mcp::inspection::validate_injection_patterns() {
        tracing::error!("Injection pattern compilation failed: {}", error);
        anyhow::bail!(
            "Injection pattern validation failed: {error}. Injection detection unavailable."
        );
    }

    let mut policies = policy_config.to_policies();
    PolicyEngine::sort_policies(&mut policies);

    tracing::info!("Loaded {} policies from {}", policies.len(), args.config);

    let engine = match PolicyEngine::with_policies(args.strict, &policies) {
        Ok(mut engine) => {
            if let Some(max_iter) = policy_config.max_path_decode_iterations {
                engine.set_max_path_decode_iterations(max_iter);
                tracing::info!(
                    max_path_decode_iterations = max_iter,
                    "custom path decode iteration limit"
                );
            }
            tracing::info!(
                "Compiled {} policies (pre-compiled evaluation path active)",
                policies.len()
            );
            engine
        }
        Err(errors) => {
            for err in &errors {
                tracing::error!("Policy compilation error: {}", err);
            }
            anyhow::bail!(
                "Failed to compile {} policies — fix config and retry",
                errors.len()
            );
        }
    };

    // Exploit #7 fix: require VELLAVETO_API_KEY unless --allow-anonymous is set.
    // Matches the pattern from vellaveto-server — a security product must not ship
    // with zero access control by default.
    let api_key = std::env::var("VELLAVETO_API_KEY")
        .ok()
        .filter(|s| !s.is_empty())
        .map(Arc::new);

    if api_key.is_some() {
        tracing::info!("API key authentication enabled for MCP endpoints");
    } else if args.allow_anonymous {
        tracing::warn!(
            "No VELLAVETO_API_KEY set and --allow-anonymous specified — MCP endpoints are UNAUTHENTICATED"
        );
    } else {
        anyhow::bail!(
            "VELLAVETO_API_KEY environment variable is required.\n\
             Set it to enable authentication for MCP endpoints, or pass \
             --allow-anonymous to explicitly opt in to unauthenticated mode.\n\
             Example: VELLAVETO_API_KEY=your-secret-key vellaveto-http-proxy --upstream http://localhost:8000/mcp --config policy.toml"
        );
    }

    // FIND-015: Load HMAC key for call chain signing/verification.
    // Read from VELLAVETO_CHAIN_HMAC_KEY env var (hex-encoded 32-byte key).
    // When set, Vellaveto signs its own call chain entries and verifies incoming ones.
    let call_chain_hmac_key: Option<[u8; 32]> = std::env::var("VELLAVETO_CHAIN_HMAC_KEY")
        .ok()
        .filter(|s| !s.is_empty())
        .and_then(|hex_str| {
            match hex::decode(&hex_str) {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes);
                    tracing::info!("FIND-015: Call chain HMAC signing/verification enabled");
                    Some(key)
                }
                Ok(bytes) => {
                    tracing::warn!(
                        "VELLAVETO_CHAIN_HMAC_KEY must be exactly 32 bytes (64 hex chars), got {} bytes — chain signing disabled",
                        bytes.len()
                    );
                    None
                }
                Err(e) => {
                    tracing::warn!(
                        "VELLAVETO_CHAIN_HMAC_KEY is not valid hex — chain signing disabled: {}",
                        e
                    );
                    None
                }
            }
        });

    // Initialize audit logger
    let audit_path = PathBuf::from(&args.audit_log);
    let mut audit_logger = AuditLogger::new(audit_path.clone());

    // Wire custom PII patterns from config into audit logger
    if !policy_config.audit.custom_pii_patterns.is_empty() {
        let pii_patterns: Vec<vellaveto_audit::CustomPiiPattern> = policy_config
            .audit
            .custom_pii_patterns
            .iter()
            .map(|p| vellaveto_audit::CustomPiiPattern {
                name: p.name.clone(),
                pattern: p.pattern.clone(),
            })
            .collect();
        tracing::info!(
            "Custom PII patterns loaded: {} patterns",
            pii_patterns.len()
        );
        audit_logger = audit_logger.with_custom_pii_patterns(&pii_patterns);
    }

    let audit = Arc::new(audit_logger);

    if let Err(e) = audit.initialize_chain().await {
        tracing::warn!("Failed to initialize audit chain: {}", e);
    }

    tracing::info!("Audit log: {}", audit_path.display());

    // Session store
    let session_store =
        SessionStore::new(Duration::from_secs(args.session_timeout), args.max_sessions);
    let session_store = if args.session_max_lifetime > 0 {
        session_store.with_max_lifetime(Duration::from_secs(args.session_max_lifetime))
    } else {
        session_store
    };
    let sessions = Arc::new(session_store);

    tracing::info!(
        "Session store: timeout={}s, max={}, max_lifetime={}s",
        args.session_timeout,
        args.max_sessions,
        args.session_max_lifetime
    );

    // HTTP client for upstream
    // SECURITY (R11-RESP-9): Disable automatic redirect following to prevent SSRF.
    // A malicious upstream could return 3xx redirects to internal services (e.g.,
    // http://169.254.169.254 for cloud metadata). The proxy should not blindly
    // follow redirects — it should treat them as errors.
    let http_client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .read_timeout(Duration::from_secs(60))
        .timeout(Duration::from_secs(300))
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(10)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("Failed to create HTTP client")?;

    // OAuth 2.1 validator (optional)
    let oauth = if let Some(ref issuer) = args.oauth_issuer {
        let dpop_mode = resolve_oauth_security(&args)?;

        let config = OAuthConfig {
            issuer: issuer.clone(),
            audience: args.oauth_audience.clone(),
            jwks_uri: args.oauth_jwks_uri.clone(),
            required_scopes: args.oauth_scopes.clone(),
            pass_through: args.oauth_pass_through,
            allowed_algorithms: vellaveto_http_proxy::oauth::default_allowed_algorithms(),
            expected_resource: args.oauth_expected_resource.clone(),
            clock_skew_leeway: Duration::from_secs(30),
            require_audience: true,
            dpop_mode,
            dpop_allowed_algorithms: default_dpop_allowed_algorithms(),
            dpop_require_ath: args.oauth_dpop_require_ath,
            dpop_max_clock_skew: Duration::from_secs(args.oauth_dpop_max_clock_skew_secs),
        };
        tracing::info!(
            "OAuth 2.1 enabled: issuer={}, audience={}, scopes={:?}, pass_through={}, dpop_mode={:?}, profile={:?}",
            config.issuer,
            config.audience,
            config.required_scopes,
            config.pass_through,
            config.dpop_mode,
            args.oauth_security_profile,
        );
        Some(Arc::new(OAuthValidator::new(config, http_client.clone())))
    } else {
        tracing::info!("OAuth 2.1 not configured — all requests accepted without token validation");
        None
    };

    // Build injection scanner from config (supports extra/disabled patterns)
    let injection_disabled = !policy_config.injection.enabled;
    let injection_scanner = {
        let ic = &policy_config.injection;
        if ic.enabled {
            if !ic.extra_patterns.is_empty() || !ic.disabled_patterns.is_empty() {
                match vellaveto_mcp::inspection::InjectionScanner::from_config(
                    &ic.extra_patterns,
                    &ic.disabled_patterns,
                ) {
                    Some(scanner) => {
                        tracing::info!(
                            "Injection scanner: {} active patterns ({} extra, {} disabled)",
                            scanner.patterns().len(),
                            ic.extra_patterns.len(),
                            ic.disabled_patterns.len(),
                        );
                        Some(Arc::new(scanner))
                    }
                    None => {
                        tracing::warn!(
                            "Injection scanner: failed to compile custom patterns, using defaults"
                        );
                        None
                    }
                }
            } else {
                tracing::info!("Injection scanner: default patterns");
                None
            }
        } else {
            tracing::info!("Injection scanner: DISABLED by configuration");
            None
        }
    };

    // SECURITY (R9-9): Warn when injection detection is active but blocking
    // is disabled. This means injections are detected and logged but the
    // malicious response is still forwarded to the agent.
    if policy_config.injection.enabled && !policy_config.injection.block_on_injection {
        tracing::warn!(
            "Injection scanning is enabled but block_on_injection=false — \
             injections will be DETECTED but NOT BLOCKED. Set \
             [injection] block_on_injection=true in config to enforce blocking."
        );
    }

    // Keep a reference for post-shutdown audit flush (Challenge 15 fix)
    let shutdown_audit = audit.clone();

    // Parse bind address for DNS rebinding defense (TASK-015).
    // validate_origin uses this to automatically restrict origins on loopback binds.
    let bind_addr: std::net::SocketAddr = args
        .listen
        .parse()
        .context(format!("Invalid listen address: {}", args.listen))?;
    let trusted_proxies = Arc::new(parse_trusted_proxies_env());
    if !trusted_proxies.is_empty() {
        tracing::info!(
            trusted_proxies = ?trusted_proxies,
            "Trusted proxy header processing enabled"
        );
    }

    // Phase 39: Federation resolver
    let federation = if policy_config.abac.federation.enabled
        && !policy_config.abac.federation.trust_anchors.is_empty()
    {
        match vellaveto_http_proxy::federation::FederationResolver::new(
            &policy_config.abac.federation,
            http_client.clone(),
        ) {
            Ok(resolver) => {
                tracing::info!(
                    anchors = policy_config.abac.federation.trust_anchors.len(),
                    "Federation resolver initialized"
                );
                Some(std::sync::Arc::new(resolver))
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to initialize federation resolver");
                None
            }
        }
    } else {
        None
    };

    // Build shared state
    let state = ProxyState {
        engine: Arc::new(engine),
        policies: Arc::new(policies),
        audit,
        sessions: sessions.clone(),
        upstream_url: args.upstream.clone(),
        traffic_padding: policy_config.shield.traffic_padding,
        strip_privacy_headers: policy_config.shield.strip_privacy_headers,
        http_client,
        oauth,
        injection_scanner,
        injection_disabled,
        injection_blocking: policy_config.injection.block_on_injection,
        api_key,
        approval_store: None,
        manifest_config: None,
        allowed_origins: policy_config.allowed_origins.clone(),
        bind_addr,
        // SECURITY (R10-FRAME-2): Default to canonicalize=true (safe mode).
        // The env var VELLAVETO_NO_CANONICALIZE=true or --no-canonicalize opt out.
        canonicalize: !args.no_canonicalize
            && !std::env::var("VELLAVETO_NO_CANONICALIZE")
                .ok()
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
        output_schema_registry: Arc::new(OutputSchemaRegistry::new()),
        response_dlp_enabled: true,
        response_dlp_blocking: std::env::var("VELLAVETO_DLP_BLOCKING")
            .ok()
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false),
        audit_strict_mode: policy_config.audit.strict_mode,
        mediation_config: vellaveto_mcp::mediation::MediationConfig {
            // The HTTP proxy already runs request-side DLP/injection scanning
            // before mediation. Keep the shared mediation layer focused on
            // provenance and semantic containment until the transports converge.
            dlp_enabled: false,
            dlp_blocking: false,
            injection_enabled: false,
            injection_blocking: false,
            require_session_id: policy_config.acis.require_session_id,
            require_agent_identity: policy_config.acis.require_agent_identity,
            require_verified_signature: policy_config.acis.require_verified_signature,
            require_workload_binding: policy_config.acis.require_workload_binding,
            require_ephemeral_client_provenance: policy_config
                .acis
                .require_ephemeral_client_provenance,
            deny_replay: policy_config.acis.deny_replay,
            block_tainted_privileged_sinks: policy_config.acis.block_tainted_privileged_sinks,
            require_lineage_for_privileged_sinks: policy_config
                .acis
                .require_lineage_for_privileged_sinks,
            containment_mode: policy_config.acis.containment_mode,
            ..vellaveto_mcp::mediation::MediationConfig::default()
        },
        trusted_request_signers: Arc::new(build_trusted_request_signers(&policy_config)?),
        detached_signature_freshness: (&policy_config.acis).into(),
        known_tools: vellaveto_mcp::rug_pull::build_known_tools(&[]),
        elicitation_config: policy_config.elicitation.clone(),
        sampling_config: policy_config.sampling.clone(),
        tool_registry: None,
        call_chain_hmac_key,
        // SECURITY: Trace output is opt-in via env var. When disabled (default),
        // the ?trace=true query parameter is silently ignored. This prevents
        // leaking internal policy names, patterns, and constraint configurations
        // to authenticated clients.
        trace_enabled: std::env::var("VELLAVETO_TRACE_ENABLED")
            .ok()
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false),

        // Phase 3.1 Security Managers - disabled by default in HTTP proxy
        // These are initialized via vellaveto-server when running in server mode
        circuit_breaker: None,
        shadow_agent: None,
        deputy: None,
        schema_lineage: None,
        auth_level: None,
        sampling_detector: None,

        // Runtime limits from config
        limits: policy_config.limits.clone(),

        // WebSocket transport configuration (Phase 17.1)
        ws_config: Some(proxy::WebSocketConfig {
            max_message_size: args.ws_max_message_size,
            idle_timeout_secs: args.ws_idle_timeout,
            message_rate_limit: args.ws_message_rate_limit,
            upstream_rate_limit: 500,
        }),

        // Protocol extensions (Phase 17.4) — disabled for now; wired up in
        // vellaveto-server when extension config is enabled.
        extension_registry: None,

        // Transport discovery & negotiation (Phase 18)
        transport_config: policy_config.transport.clone(),
        grpc_port: if args.grpc {
            Some(args.grpc_port)
        } else {
            None
        },

        // Phase 20: MCP Gateway Mode
        gateway: if policy_config.gateway.enabled {
            match proxy::gateway::GatewayRouter::from_config(&policy_config.gateway) {
                Ok(router) => {
                    let gw = Arc::new(router);
                    tracing::info!("Gateway mode: {} backends", gw.backend_count());
                    Some(gw)
                }
                Err(e) => {
                    // Fail-closed: invalid gateway config prevents startup
                    return Err(anyhow::anyhow!("Gateway config error: {e}"));
                }
            }
        } else {
            None
        },

        // Phase 21: Advanced Authorization (ABAC)
        abac_engine: if policy_config.abac.enabled {
            match vellaveto_engine::abac::AbacEngine::new(
                &policy_config.abac.policies,
                &policy_config.abac.entities,
            ) {
                Ok(engine) => {
                    tracing::info!(
                        "ABAC engine: {} policies, {} entities",
                        policy_config.abac.policies.len(),
                        policy_config.abac.entities.len()
                    );
                    Some(Arc::new(engine))
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("ABAC config error: {e}"));
                }
            }
        } else {
            None
        },
        least_agency: if policy_config.abac.least_agency.enabled {
            Some(Arc::new(
                vellaveto_engine::least_agency::LeastAgencyTracker::new(
                    policy_config.abac.least_agency.narrow_threshold,
                ),
            ))
        } else {
            None
        },
        continuous_auth_config: if policy_config.abac.continuous_auth.enabled {
            Some(policy_config.abac.continuous_auth.clone())
        } else {
            None
        },
        transport_health: if policy_config.transport.cross_transport_fallback {
            Some(std::sync::Arc::new(
                proxy::transport_health::TransportHealthTracker::new(
                    policy_config
                        .transport
                        .transport_circuit_breaker_failure_threshold,
                    2, // success threshold for half-open recovery
                    policy_config
                        .transport
                        .transport_circuit_breaker_open_duration_secs,
                ),
            ))
        } else {
            None
        },
        streamable_http: policy_config.streamable_http.clone(),
        federation,
        #[cfg(feature = "discovery")]
        discovery_engine: if policy_config.discovery.enabled {
            Some(std::sync::Arc::new(
                vellaveto_mcp::discovery::DiscoveryEngine::new(policy_config.discovery.clone()),
            ))
        } else {
            None
        },
        #[cfg(feature = "projector")]
        projector_registry: if policy_config.projector.enabled {
            let family = parse_model_family(&policy_config.projector.default_model_family);
            match vellaveto_mcp::projector::ProjectorRegistry::with_defaults(family) {
                Ok(registry) => {
                    tracing::info!(
                        "Model projector enabled (default family: {})",
                        policy_config.projector.default_model_family
                    );
                    Some(std::sync::Arc::new(registry))
                }
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "Failed to initialize projector registry: {}",
                        e
                    ));
                }
            }
        } else {
            None
        },

        // Content-bound attestation HMAC key.
        // SECURITY (R259-ATT-1): Enforce minimum 32-byte key length.
        // Short HMAC keys are trivially brute-forceable.
        attestation_hmac_key: std::env::var("VELLAVETO_ATTESTATION_SECRET")
            .ok()
            .filter(|s| !s.is_empty())
            .and_then(|s| {
                if s.len() < 32 {
                    tracing::error!(
                        "VELLAVETO_ATTESTATION_SECRET too short ({} bytes, minimum 32). \
                         Content-bound attestation will be DISABLED.",
                        s.len()
                    );
                    return None;
                }
                Some(s.into_bytes())
            }),
    };

    // Phase 20: Spawn gateway health checker if gateway is enabled
    if let Some(ref gw) = state.gateway {
        proxy::gateway::spawn_health_checker(
            gw.clone(),
            state.http_client.clone(),
            policy_config.gateway.health_check_interval_secs,
        );
        tracing::info!(
            "Gateway health checker started (interval={}s)",
            policy_config.gateway.health_check_interval_secs
        );
    }

    if state.canonicalize {
        tracing::info!("TOCTOU canonicalization enabled — forwarding re-serialized JSON");
    } else {
        tracing::warn!(
            "SECURITY: TOCTOU canonicalization DISABLED via VELLAVETO_NO_CANONICALIZE env var"
        );
    }

    // Log WebSocket transport configuration
    tracing::info!(
        "WebSocket transport: /mcp/ws (max_message={}B, idle_timeout={}s, rate_limit={}/s)",
        args.ws_max_message_size,
        args.ws_idle_timeout,
        args.ws_message_rate_limit,
    );

    // TASK-015: Log DNS rebinding defense configuration
    if state.allowed_origins.is_empty() {
        if bind_addr.ip().is_loopback() {
            tracing::info!(
                bind_addr = %bind_addr,
                "DNS rebinding defense: auto-restricting origins to localhost variants"
            );
        } else {
            tracing::info!(
                bind_addr = %bind_addr,
                "Origin validation: same-origin check (non-loopback bind)"
            );
        }
    } else {
        tracing::info!(
            allowed_origins = ?state.allowed_origins,
            "Origin validation: using explicit allowlist"
        );
    }

    // Build rate limiter (global, token-bucket)
    let global_rate_limiter = match std::num::NonZeroU32::new(args.rate_limit) {
        Some(rate_limit) => {
            let quota = Quota::per_second(rate_limit);
            let limiter = Arc::new(RateLimiter::direct(quota));
            tracing::info!(rps = args.rate_limit, "Global rate limiting enabled");
            Some(limiter)
        }
        None => {
            tracing::info!("Rate limiting disabled");
            None
        }
    };

    // Clone state for gRPC server before moving into axum router.
    #[cfg(feature = "grpc")]
    let grpc_proxy_state = state.clone();

    // Build router
    // SECURITY (R8-HTTP-1): Apply a 1 MB request body limit to prevent
    // resource exhaustion from oversized payloads. Matches vellaveto-server.
    let mut app = axum::Router::new()
        .route(
            "/mcp",
            axum::routing::post(proxy::handle_mcp_post)
                .delete(proxy::handle_mcp_delete)
                .get(proxy::handle_mcp_get),
        )
        .route("/mcp/ws", axum::routing::get(proxy::handle_ws_upgrade))
        .route("/health", axum::routing::get(health))
        // RFC 9728: Protected Resource Metadata endpoint for OAuth discovery
        .route(
            "/.well-known/oauth-protected-resource",
            axum::routing::get(proxy::handle_protected_resource_metadata),
        )
        // MCP June 2026: Transport discovery endpoint (Phase 18)
        .route(
            "/.well-known/mcp-transport",
            axum::routing::get(proxy::handle_transport_discovery),
        )
        .layer(axum::extract::DefaultBodyLimit::max(1_048_576))
        .layer(axum::middleware::from_fn(security_headers))
        .layer(axum::middleware::from_fn(request_id))
        .layer(axum::middleware::from_fn_with_state(
            trusted_proxies.clone(),
            trusted_proxy_context,
        ))
        .with_state(state);

    if let Some(limiter) = global_rate_limiter {
        app = app.layer(axum::middleware::from_fn(move |request, next: Next| {
            let limiter = limiter.clone();
            async move {
                if limiter.check().is_err() {
                    return StatusCode::TOO_MANY_REQUESTS.into_response();
                }
                next.run(request).await
            }
        }));
    }

    // Spawn background session cleanup task
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            sessions.evict_expired();
            // SECURITY (R240-PROXY-1): Also clean up expired global flagged-tool entries.
            sessions.evict_expired_global_flags();
        }
    });

    // Spawn periodic audit heartbeat task.
    // IMPROVEMENT_PLAN 10.6: Heartbeat entries enable detection of log truncation/gaps.
    let heartbeat_interval: u64 = std::env::var("VELLAVETO_HEARTBEAT_INTERVAL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);

    if heartbeat_interval > 0 {
        let heartbeat_audit = shutdown_audit.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(heartbeat_interval));
            let mut sequence: u64 = 0;
            // Skip the first immediate tick — heartbeat starts after first interval
            interval.tick().await;
            loop {
                interval.tick().await;
                sequence = sequence.saturating_add(1);
                if let Err(e) = heartbeat_audit
                    .log_heartbeat(heartbeat_interval, sequence)
                    .await
                {
                    tracing::warn!("Failed to log audit heartbeat: {}", e);
                }
            }
        });
        tracing::info!(
            "Audit heartbeat task enabled (every {}s)",
            heartbeat_interval
        );
    }

    // Start gRPC server if enabled and compiled with the grpc feature.
    #[cfg(feature = "grpc")]
    let grpc_shutdown_token = {
        let token = tokio_util::sync::CancellationToken::new();
        if args.grpc {
            let grpc_listen_addr: std::net::SocketAddr =
                format!("{}:{}", bind_addr.ip(), args.grpc_port)
                    .parse()
                    .context(format!("Invalid gRPC listen address: {}", args.grpc_port))?;

            let grpc_config = vellaveto_http_proxy::proxy::grpc::GrpcConfig {
                listen_addr: grpc_listen_addr,
                max_message_size: args.grpc_max_message_size,
                upstream_grpc_url: args.upstream_grpc_url.clone(),
                health_enabled: true,
                stream_message_rate_limit: 100,
            };

            let grpc_state = grpc_proxy_state.clone();
            let grpc_shutdown = token.clone();

            tokio::spawn(async move {
                if let Err(e) = vellaveto_http_proxy::proxy::grpc::start_grpc_server(
                    grpc_state,
                    grpc_config,
                    grpc_shutdown,
                )
                .await
                {
                    tracing::error!("gRPC server error: {}", e);
                }
            });

            tracing::info!(
                "gRPC transport listening on {} (max_message={}B)",
                grpc_listen_addr,
                args.grpc_max_message_size,
            );
        }
        token
    };

    #[cfg(not(feature = "grpc"))]
    {
        if args.grpc {
            tracing::warn!(
                "--grpc flag set but binary was compiled without grpc feature. \
                 Rebuild with `--features grpc` to enable gRPC transport."
            );
        }
    }

    // Start HTTP server
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .context(format!("Failed to bind to {bind_addr}"))?;

    // SECURITY (R236-TLS-2): Build TLS acceptor from config. If TLS is enabled,
    // serve over TLS; otherwise fall back to plaintext.
    let tls_acceptor = vellaveto_tls::build_tls_acceptor(&policy_config.tls)
        .map_err(|e| anyhow::anyhow!("TLS configuration error: {e}"))?;

    let scheme = if tls_acceptor.is_some() {
        "https"
    } else {
        "http"
    };
    tracing::info!(
        "Vellaveto HTTP proxy listening on {scheme}://{} → upstream {} (TLS mode: {:?})",
        args.listen,
        args.upstream,
        policy_config.tls.mode
    );

    let shutdown_closure = async move {
        shutdown_signal().await;
        // Cancel gRPC server when HTTP server shuts down.
        #[cfg(feature = "grpc")]
        grpc_shutdown_token.cancel();
    };

    match tls_acceptor {
        Some(acceptor) => {
            use axum::serve::ListenerExt;
            let tls_listener = TlsListener {
                inner: listener,
                acceptor,
            }
            .tap_io(|_| {});
            axum::serve(
                tls_listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown_closure)
            .await
            .context("TLS server error")?;
        }
        None => {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown_closure)
            .await
            .context("Server error")?;
        }
    }

    // Challenge 15 fix: Flush audit log before exit.
    // Matches the pattern from vellaveto-server/src/main.rs.
    tracing::info!("Flushing audit log...");
    if let Err(e) = shutdown_audit.sync().await {
        tracing::error!("Failed to flush audit log on shutdown: {}", e);
    }
    // Create a final checkpoint to capture entries since the last periodic checkpoint
    match shutdown_audit.create_checkpoint().await {
        Ok(cp) => tracing::info!(
            "Shutdown checkpoint created: {} ({} entries)",
            cp.id,
            cp.entry_count
        ),
        Err(e) => tracing::debug!("Shutdown checkpoint skipped: {}", e),
    }

    tracing::info!("Proxy shut down gracefully");
    Ok(())
}

/// Parse a model family string from config into a `ModelFamily` enum.
#[cfg(feature = "projector")]
fn parse_model_family(s: &str) -> vellaveto_types::ModelFamily {
    match s {
        "claude" => vellaveto_types::ModelFamily::Claude,
        "openai" => vellaveto_types::ModelFamily::OpenAi,
        "deepseek" => vellaveto_types::ModelFamily::DeepSeek,
        "qwen" => vellaveto_types::ModelFamily::Qwen,
        "generic" => vellaveto_types::ModelFamily::Generic,
        other if other.starts_with("custom:") => {
            vellaveto_types::ModelFamily::Custom(other[7..].to_string())
        }
        other => vellaveto_types::ModelFamily::Custom(other.to_string()),
    }
}

fn connection_ip_from_request(request: &Request) -> std::net::IpAddr {
    request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
}

fn is_connection_from_trusted_proxy(
    request: &Request,
    trusted_proxies: &[std::net::IpAddr],
) -> bool {
    if trusted_proxies.is_empty() {
        return false;
    }
    trusted_proxies.contains(&connection_ip_from_request(request))
}

async fn trusted_proxy_context(
    State(trusted_proxies): State<Arc<Vec<std::net::IpAddr>>>,
    mut request: Request,
    next: Next,
) -> Response {
    let from_trusted_proxy = is_connection_from_trusted_proxy(&request, &trusted_proxies);
    request
        .extensions_mut()
        .insert(proxy::TrustedProxyContext::new(from_trusted_proxy));
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request as HttpRequest;

    fn build_request(headers: &[(&str, &str)]) -> Request {
        let mut builder = HttpRequest::builder().uri("/mcp").method("POST");
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        builder.body(axum::body::Body::empty()).unwrap()
    }

    fn base_args() -> Args {
        Args {
            upstream: "http://127.0.0.1:8000/mcp".to_string(),
            listen: "127.0.0.1:3001".to_string(),
            config: "policy.toml".to_string(),
            audit_log: "audit.log".to_string(),
            session_timeout: 1800,
            max_sessions: 1000,
            strict: false,
            oauth_issuer: Some("https://issuer.example".to_string()),
            oauth_audience: "mcp-server".to_string(),
            oauth_jwks_uri: None,
            oauth_scopes: vec![],
            oauth_pass_through: false,
            unsafe_oauth_pass_through: false,
            oauth_expected_resource: None,
            oauth_dpop_mode: OAuthDpopModeArg::Off,
            oauth_security_profile: OAuthSecurityProfileArg::Standard,
            oauth_dpop_max_clock_skew_secs: 300,
            oauth_dpop_require_ath: true,
            allow_anonymous: false,
            session_max_lifetime: 86400,
            no_canonicalize: false,
            rate_limit: 200,
            ws_max_message_size: 1_048_576,
            ws_idle_timeout: 300,
            ws_message_rate_limit: 100,
            grpc_port: 50051,
            grpc_max_message_size: 4_194_304,
            upstream_grpc_url: None,
            grpc: false,
        }
    }

    #[test]
    fn hardened_profile_requires_expected_resource() {
        let mut args = base_args();
        args.oauth_security_profile = OAuthSecurityProfileArg::Hardened;

        let err = resolve_oauth_security(&args).expect_err("expected hardened validation error");
        assert!(err
            .to_string()
            .contains("requires --oauth-expected-resource"));
    }

    #[test]
    fn hardened_profile_enforces_required_dpop() {
        let mut args = base_args();
        args.oauth_security_profile = OAuthSecurityProfileArg::Hardened;
        args.oauth_expected_resource = Some("https://mcp.example".to_string());
        args.oauth_dpop_mode = OAuthDpopModeArg::Optional;

        let mode = resolve_oauth_security(&args).expect("hardened profile should resolve");
        assert_eq!(mode, DpopMode::Required);
    }

    #[test]
    fn pass_through_requires_explicit_unsafe_flag() {
        let mut args = base_args();
        args.oauth_pass_through = true;
        args.oauth_expected_resource = Some("https://mcp.example".to_string());
        args.oauth_dpop_mode = OAuthDpopModeArg::Required;

        let err = resolve_oauth_security(&args).expect_err("expected unsafe-gate validation");
        assert!(err.to_string().contains("--unsafe-oauth-pass-through"));
    }

    #[test]
    fn pass_through_requires_expected_resource() {
        let mut args = base_args();
        args.oauth_pass_through = true;
        args.unsafe_oauth_pass_through = true;
        args.oauth_dpop_mode = OAuthDpopModeArg::Required;

        let err = resolve_oauth_security(&args).expect_err("expected resource requirement");
        assert!(err.to_string().contains("--oauth-expected-resource"));
    }

    #[test]
    fn pass_through_requires_required_dpop() {
        let mut args = base_args();
        args.oauth_pass_through = true;
        args.unsafe_oauth_pass_through = true;
        args.oauth_expected_resource = Some("https://mcp.example".to_string());
        args.oauth_dpop_mode = OAuthDpopModeArg::Optional;

        let err = resolve_oauth_security(&args).expect_err("expected dpop requirement");
        assert!(err.to_string().contains("--oauth-dpop-mode required"));
    }

    #[test]
    fn pass_through_allowed_with_strict_inputs() {
        let mut args = base_args();
        args.oauth_pass_through = true;
        args.unsafe_oauth_pass_through = true;
        args.oauth_expected_resource = Some("https://mcp.example".to_string());
        args.oauth_dpop_mode = OAuthDpopModeArg::Required;

        let mode = resolve_oauth_security(&args).expect("strict pass-through settings should pass");
        assert_eq!(mode, DpopMode::Required);
    }

    #[test]
    fn standard_profile_preserves_configured_dpop_mode() {
        let mut args = base_args();
        args.oauth_dpop_mode = OAuthDpopModeArg::Optional;
        args.oauth_expected_resource = None;

        let mode = resolve_oauth_security(&args)
            .expect("standard profile should preserve configured mode");
        assert_eq!(mode, DpopMode::Optional);
    }

    #[test]
    fn oauth_not_configured_returns_requested_mode_without_validation() {
        let mut args = base_args();
        args.oauth_issuer = None;
        args.oauth_security_profile = OAuthSecurityProfileArg::Hardened;
        args.oauth_dpop_mode = OAuthDpopModeArg::Off;

        let mode =
            resolve_oauth_security(&args).expect("oauth-disabled run should skip oauth validation");
        assert_eq!(mode, DpopMode::Off);
    }

    #[test]
    fn test_is_connection_from_trusted_proxy_requires_config() {
        let request = build_request(&[]);
        assert!(
            !is_connection_from_trusted_proxy(&request, &[]),
            "empty trusted_proxies must not trust forwarded headers"
        );
    }

    #[test]
    fn test_is_connection_from_trusted_proxy_matches_direct_peer() {
        let request = build_request(&[]);
        let trusted = vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)];
        assert!(is_connection_from_trusted_proxy(&request, &trusted));
    }

    #[test]
    fn test_is_connection_from_trusted_proxy_rejects_untrusted_peer() {
        let request = build_request(&[]);
        let trusted = vec!["10.0.0.1".parse().unwrap()];
        assert!(!is_connection_from_trusted_proxy(&request, &trusted));
    }
}

/// Middleware that adds standard security headers to all proxy responses.
async fn security_headers(request: Request, next: Next) -> Response {
    let from_trusted_proxy = request
        .extensions()
        .get::<proxy::TrustedProxyContext>()
        .map(|ctx| ctx.is_from_trusted_proxy())
        .unwrap_or(false);
    let has_forwarded_proto = request.headers().contains_key("x-forwarded-proto");
    let forwarded_proto_https = request
        .headers()
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .map(|s| s.eq_ignore_ascii_case("https"))
        .unwrap_or(false);

    let is_https = request.uri().scheme_str() == Some("https")
        || (from_trusted_proxy && forwarded_proto_https);

    if has_forwarded_proto && !from_trusted_proxy {
        tracing::warn!("Ignoring x-forwarded-proto from untrusted peer");
    }

    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        header::HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static("default-src 'none'"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::HeaderName::from_static("x-permitted-cross-domain-policies"),
        HeaderValue::from_static("none"),
    );
    if is_https {
        headers.insert(
            header::HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    response
}

/// Middleware that adds a unique request ID to every response.
async fn request_id(request: Request, next: Next) -> Response {
    let incoming_id = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        // SECURITY (IMP-R154-007): Reject control AND Unicode format chars
        // (zero-width, bidi, TAG) to prevent log/header injection via
        // client-supplied request identifiers.
        .filter(|s| s.len() <= 128 && !vellaveto_types::has_dangerous_chars(s))
        .map(|s| s.to_string());

    let mut response = next.run(request).await;
    let id = incoming_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    if let Ok(val) = HeaderValue::from_str(&id) {
        response
            .headers_mut()
            .insert(header::HeaderName::from_static("x-request-id"), val);
    }
    response
}

/// Health check response with security scanning subsystem status (SEC-006).
#[derive(Serialize)]
struct HealthResponse {
    status: String,
    scanning: ScanningStatus,
}

/// Status of security scanning subsystems.
#[derive(Serialize)]
struct ScanningStatus {
    dlp_available: bool,
    injection_available: bool,
}

async fn health() -> Json<HealthResponse> {
    let dlp_available = vellaveto_mcp::inspection::is_dlp_available();
    let injection_available = vellaveto_mcp::inspection::is_injection_available();

    let status = if dlp_available && injection_available {
        "ok".to_string()
    } else {
        "degraded".to_string()
    };

    Json(HealthResponse {
        status,
        scanning: ScanningStatus {
            dlp_available,
            injection_available,
        },
    })
}

async fn shutdown_signal() {
    let ctrl_c = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {}
            Err(err) => {
                tracing::error!(
                    error = %err,
                    "Failed to install Ctrl+C handler; SIGINT shutdown disabled"
                );
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(err) => {
                tracing::error!(
                    error = %err,
                    "Failed to install SIGTERM handler; SIGTERM shutdown disabled"
                );
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received SIGINT, starting graceful shutdown...");
        },
        _ = terminate => {
            tracing::info!("Received SIGTERM, starting graceful shutdown...");
        },
    }
}
