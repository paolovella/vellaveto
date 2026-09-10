// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! VellaVeto HTTP server with policy evaluation, dashboard, and management API.

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use clap::{Parser, Subcommand};
use serde_json::json;
use std::sync::Arc;
use vellaveto_approval::ApprovalStore;
use vellaveto_audit::AuditLogger;
use vellaveto_canonical::CanonicalPolicies;
use vellaveto_config::PolicyConfig;
use vellaveto_engine::PolicyEngine;
use vellaveto_server::{iam, routes, AppState, RateLimits};
use vellaveto_types::{Action, Policy, Verdict};

/// SECURITY (R237-TLS-1): TLS handshake timeout — 10 seconds to prevent
/// Slowloris-style attacks that hold connections in mid-handshake indefinitely.
const TLS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// SECURITY (R236-TLS-1): TLS listener wrapper implementing axum's Listener
/// trait. Accepts TCP connections, performs TLS handshake, and returns the
/// encrypted stream. Handshake failures are logged and retried (the Listener
/// trait requires infallible accept).
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
    name = "vellaveto",
    version,
    about = "Vellaveto policy engine — CLI and HTTP server"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the HTTP server
    Serve {
        #[arg(short, long, default_value_t = 3000)]
        port: u16,
        #[arg(short, long)]
        config: String,
        /// Bind address (default: 127.0.0.1). Use 0.0.0.0 to listen on all interfaces.
        #[arg(short, long, default_value = "127.0.0.1")]
        bind: String,
        /// Allow starting without VELLAVETO_API_KEY (unauthenticated mode).
        /// WARNING: Mutating endpoints will have no access control.
        #[arg(long, default_value_t = false)]
        allow_anonymous: bool,
        /// Watch the policy config file for changes and auto-reload.
        #[arg(long, default_value_t = false)]
        watch: bool,
        /// Open the dashboard in the default browser after startup.
        #[arg(long, default_value_t = false)]
        open: bool,
    },
    /// One-shot action evaluation
    Evaluate {
        #[arg(long)]
        tool: String,
        #[arg(long)]
        function: String,
        #[arg(long, default_value = "{}")]
        params: String,
        #[arg(short, long)]
        config: String,
    },
    /// Validate a config file with comprehensive checks
    Check {
        /// Path to the configuration file
        #[arg(short, long)]
        config: String,
        /// Strict mode: treat warnings as errors
        #[arg(long, default_value_t = false)]
        strict: bool,
        /// Output format (text or json)
        #[arg(long, default_value = "text")]
        format: String,
        /// Skip best practice checks
        #[arg(long, default_value_t = false)]
        no_best_practices: bool,
        /// Skip security checks
        #[arg(long, default_value_t = false)]
        no_security_checks: bool,
    },
    /// List canonical policies as TOML
    Policies {
        #[arg(long)]
        preset: String,
    },
    /// Verify audit log integrity (hash chain + checkpoint signatures)
    Verify {
        /// Path to the audit log file (e.g., audit.log)
        #[arg(short, long)]
        audit: String,
        /// Trusted Ed25519 verifying key (hex-encoded 32-byte public key).
        /// When set, rejects checkpoints signed by any other key.
        #[arg(long)]
        trusted_key: Option<String>,
        /// Also list rotated audit log files and their sizes.
        #[arg(long, default_value_t = false)]
        list_rotated: bool,
    },
    /// Compute SHA-256 hash of a binary (for supply_chain.allowed_servers config)
    HashBinary {
        /// Path to the binary to hash
        path: String,
    },
    // ═══════════════════════════════════════════════════════════════════════════════
    // Phase 8: ETDI Cryptographic Tool Security Commands
    // ═══════════════════════════════════════════════════════════════════════════════
    /// Generate an Ed25519 keypair for signing tool definitions (ETDI)
    GenerateKey {
        /// Path to write the private key (hex-encoded)
        #[arg(long)]
        private_key: std::path::PathBuf,
        /// Path to write the public key (hex-encoded)
        #[arg(long)]
        public_key: std::path::PathBuf,
    },
    /// Sign a tool definition (ETDI)
    SignTool {
        /// Tool name
        #[arg(long)]
        tool: String,
        /// Path to the tool definition JSON file
        #[arg(long)]
        definition: std::path::PathBuf,
        /// Path to the private key file
        #[arg(long)]
        key: std::path::PathBuf,
        /// Signer identity (optional, e.g., SPIFFE ID)
        #[arg(long)]
        signer: Option<String>,
        /// Path to write the signature JSON
        #[arg(long)]
        output: std::path::PathBuf,
        /// Signature expiry in days (optional)
        #[arg(long)]
        expires_in_days: Option<u32>,
    },
    /// Verify a tool signature (ETDI)
    VerifySignature {
        /// Tool name
        #[arg(long)]
        tool: String,
        /// Path to the tool definition JSON file
        #[arg(long)]
        definition: std::path::PathBuf,
        /// Path to the signature JSON file
        #[arg(long)]
        signature: std::path::PathBuf,
    },
    /// Batch-evaluate actions from a JSON file against a policy config
    Simulate {
        /// Path to policy config (TOML)
        #[arg(short, long)]
        config: String,
        /// Path to actions JSON file (array of {tool, function, parameters})
        #[arg(short, long)]
        actions: String,
        /// Output format: text or json
        #[arg(long, default_value = "text")]
        format: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Serve {
            port,
            config,
            bind,
            allow_anonymous,
            watch,
            open,
        } => cmd_serve(port, config, bind, allow_anonymous, watch, open).await,
        Commands::Evaluate {
            tool,
            function,
            params,
            config,
        } => cmd_evaluate(tool, function, params, config).await,
        Commands::Check {
            config,
            strict,
            format,
            no_best_practices,
            no_security_checks,
        } => {
            cmd_check(
                config,
                strict,
                format,
                no_best_practices,
                no_security_checks,
            )
            .await
        }
        Commands::Policies { preset } => cmd_policies(preset),
        Commands::Verify {
            audit,
            trusted_key,
            list_rotated,
        } => cmd_verify(audit, trusted_key, list_rotated).await,
        Commands::HashBinary { path } => cmd_hash_binary(path),
        Commands::GenerateKey {
            private_key,
            public_key,
        } => cmd_generate_key(private_key, public_key),
        Commands::SignTool {
            tool,
            definition,
            key,
            signer,
            output,
            expires_in_days,
        } => cmd_sign_tool(tool, definition, key, signer, output, expires_in_days).await,
        Commands::VerifySignature {
            tool,
            definition,
            signature,
        } => cmd_verify_signature(tool, definition, signature).await,
        Commands::Simulate {
            config,
            actions,
            format,
        } => cmd_simulate(config, actions, format).await,
    }
}

async fn cmd_serve(
    port: u16,
    config: String,
    bind: String,
    allow_anonymous: bool,
    watch: bool,
    open_browser: bool,
) -> Result<()> {
    let policy_config = PolicyConfig::load_file(&config)
        .map_err(|e| anyhow::anyhow!("Failed to load config: {e}"))?;
    vellaveto_server::opa::configure_runtime_client(&policy_config.opa)
        .map_err(|e| anyhow::anyhow!("Failed to initialize OPA runtime: {e}"))?;

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

    let iam_state = if policy_config.iam.enabled {
        Some(Arc::new(
            iam::IamState::new(policy_config.iam.clone())
                .await
                .map_err(|e| anyhow::anyhow!("Failed to initialize IAM: {e}"))?,
        ))
    } else {
        None
    };

    let mut policies = policy_config.to_policies();
    PolicyEngine::sort_policies(&mut policies);

    tracing::info!("Loaded {} policies from {}", policies.len(), config);

    let config_dir = std::path::Path::new(&config)
        .parent()
        .unwrap_or(std::path::Path::new("."));
    let audit_path = config_dir.join("audit.log");

    // Load or generate Ed25519 signing key for audit checkpoints.
    // VELLAVETO_SIGNING_KEY: hex-encoded 32-byte Ed25519 seed.
    // If unset, a key is auto-generated (logged public key for verification).
    let signing_key = match std::env::var("VELLAVETO_SIGNING_KEY") {
        Ok(hex_key) if !hex_key.is_empty() => {
            let bytes = hex::decode(&hex_key)
                .map_err(|e| anyhow::anyhow!("Invalid VELLAVETO_SIGNING_KEY hex: {e}"))?;
            if bytes.len() != 32 {
                anyhow::bail!(
                    "VELLAVETO_SIGNING_KEY must be exactly 32 bytes (64 hex chars), got {}",
                    bytes.len()
                );
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&bytes);
            tracing::info!("Loaded Ed25519 signing key from VELLAVETO_SIGNING_KEY");
            AuditLogger::signing_key_from_bytes(&key_bytes)
        }
        _ => {
            let key = AuditLogger::generate_signing_key();
            let vk = hex::encode(
                ed25519_dalek::SigningKey::from_bytes(&key.to_bytes())
                    .verifying_key()
                    .as_bytes(),
            );
            tracing::warn!("SECURITY: VELLAVETO_SIGNING_KEY not set — using ephemeral signing key. Audit checkpoints cannot be verified across restarts. Set VELLAVETO_SIGNING_KEY for persistent tamper detection.");
            tracing::info!("Auto-generated Ed25519 signing key (verifying key: {})", vk);
            key
        }
    };

    // Optional trusted verifying key for checkpoint verification.
    // VELLAVETO_TRUSTED_KEY: hex-encoded 32-byte Ed25519 public key.
    // When set, verify_checkpoints() rejects checkpoints signed by any other key,
    // preventing an attacker with file write access from forging checkpoints.
    let mut audit_logger = AuditLogger::new(audit_path.clone()).with_signing_key(signing_key);

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

    // Apply audit redaction level from config
    if let Some(ref level_str) = policy_config.audit.redaction_level {
        match level_str.as_str() {
            "Off" | "off" => {
                audit_logger =
                    audit_logger.with_redaction_level(vellaveto_audit::RedactionLevel::Off);
                tracing::info!("Audit redaction: OFF (raw values logged)");
            }
            "KeysOnly" | "keys_only" => {
                audit_logger =
                    audit_logger.with_redaction_level(vellaveto_audit::RedactionLevel::KeysOnly);
                tracing::info!("Audit redaction: KeysOnly (sensitive keys redacted)");
            }
            "KeysAndPatterns" | "keys_and_patterns" => {
                tracing::info!("Audit redaction: KeysAndPatterns (keys + PII patterns redacted)");
            }
            other => {
                tracing::warn!(
                    "Unknown audit redaction_level '{}', using default (KeysAndPatterns)",
                    other
                );
            }
        }
    }

    // Configurable audit log rotation size.
    // VELLAVETO_LOG_MAX_SIZE: max bytes before rotating (default: 100MB). Set to 0 to disable.
    if let Ok(max_size_str) = std::env::var("VELLAVETO_LOG_MAX_SIZE") {
        if let Ok(max_size) = max_size_str.parse::<u64>() {
            audit_logger = audit_logger.with_max_file_size(max_size);
            if max_size == 0 {
                tracing::warn!("SECURITY: Audit log rotation disabled (VELLAVETO_LOG_MAX_SIZE=0). Disk exhaustion will prevent future audit logging.");
            } else {
                tracing::info!("Audit log rotation threshold: {} bytes", max_size);
            }
        } else {
            tracing::warn!(
                "Invalid VELLAVETO_LOG_MAX_SIZE '{}', using default (100 MB)",
                max_size_str
            );
        }
    }

    if let Ok(trusted_key) = std::env::var("VELLAVETO_TRUSTED_KEY") {
        if !trusted_key.is_empty() {
            // Validate the key format early
            let key_bytes = hex::decode(&trusted_key)
                .map_err(|e| anyhow::anyhow!("Invalid VELLAVETO_TRUSTED_KEY hex: {e}"))?;
            if key_bytes.len() != 32 {
                anyhow::bail!(
                    "VELLAVETO_TRUSTED_KEY must be exactly 32 bytes (64 hex chars), got {}",
                    key_bytes.len()
                );
            }
            tracing::info!("Checkpoint trust anchor pinned to key: {}", trusted_key);
            audit_logger = audit_logger.with_trusted_key(trusted_key);
        }
    }

    // Phase 43: Attach PostgreSQL sink if configured and feature-enabled
    #[cfg(feature = "postgres-store")]
    let pg_sink: Option<std::sync::Arc<dyn vellaveto_audit::sink::AuditSink>> = {
        if policy_config.audit_store.enabled
            && policy_config.audit_store.backend
                == vellaveto_types::audit_store::AuditStoreBackend::Postgres
        {
            let db_url = policy_config
                .audit_store
                .database_url
                .as_deref()
                .ok_or_else(|| {
                    anyhow::anyhow!("audit_store.database_url required when backend=postgres")
                })?;
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(policy_config.audit_store.pool_size)
                .acquire_timeout(std::time::Duration::from_secs(
                    policy_config.audit_store.connect_timeout_secs as u64,
                ))
                .connect(db_url)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to connect to audit store database: {}", e))?;
            let sink_config = vellaveto_audit::sink::postgres::PostgresSinkConfig {
                buffer_size: policy_config.audit_store.sink_buffer_size as usize,
                batch_size: policy_config.audit_store.batch_insert_size as usize,
                flush_interval_ms: policy_config.audit_store.flush_interval_ms as u64,
                table_name: policy_config.audit_store.table_name.clone(),
            };
            let sink = vellaveto_audit::sink::postgres::PostgresAuditSink::new(
                pool.clone(),
                sink_config,
                policy_config.audit_store.auto_migrate,
            )
            .await
            .map_err(|e| anyhow::anyhow!("Failed to initialize audit sink: {}", e))?;
            let sink_arc: std::sync::Arc<dyn vellaveto_audit::sink::AuditSink> =
                std::sync::Arc::new(sink);
            tracing::info!(
                table = %policy_config.audit_store.table_name,
                "PostgreSQL audit sink initialized"
            );
            audit_logger = audit_logger.with_sink(sink_arc.clone(), false);
            Some(sink_arc)
        } else {
            None
        }
    };
    #[cfg(not(feature = "postgres-store"))]
    let pg_sink: Option<std::sync::Arc<dyn vellaveto_audit::sink::AuditSink>> = None;

    let audit = Arc::new(audit_logger);

    // Initialize hash chain from existing log
    if let Err(e) = audit.initialize_chain().await {
        tracing::warn!("Failed to initialize audit chain: {}", e);
    }

    let approval_path = config_dir.join("approvals.jsonl");
    let approvals = Arc::new(ApprovalStore::new(
        approval_path.clone(),
        std::time::Duration::from_secs(900),
    ));

    // Load existing approvals from persistence file
    match approvals.load_from_file().await {
        Ok(count) if count > 0 => tracing::info!(
            "Loaded {} approval records from {}",
            count,
            approval_path.display()
        ),
        Ok(_) => {}
        Err(e) => tracing::warn!(
            "Failed to load approvals from {}: {}",
            approval_path.display(),
            e
        ),
    }

    // Read API key from environment variable for auth middleware.
    // Exploit #7 fix: require VELLAVETO_API_KEY unless --allow-anonymous is set.
    // A security product must not ship with zero access control by default.
    let api_key = std::env::var("VELLAVETO_API_KEY")
        .ok()
        .filter(|s| !s.is_empty())
        .map(Arc::new);

    if api_key.is_some() {
        tracing::info!("API key authentication enabled for mutating endpoints");
    } else if allow_anonymous {
        tracing::warn!(
            "No VELLAVETO_API_KEY set and --allow-anonymous specified — mutating endpoints are UNAUTHENTICATED"
        );
    } else {
        anyhow::bail!(
            "VELLAVETO_API_KEY environment variable is required.\n\
             Set it to enable authentication for mutating endpoints, or pass \
             --allow-anonymous to explicitly opt in to unauthenticated mode.\n\
             Example: VELLAVETO_API_KEY=your-secret-key vellaveto serve --config policy.toml"
        );
    }

    // Configure per-category rate limits.
    // Config file values are the base; environment variables override them.
    // Set to 0 or omit to disable rate limiting for a category.
    let rl_cfg = &policy_config.rate_limit;

    let env_or = |env_name: &str, config_val: Option<u32>| -> Option<u32> {
        std::env::var(env_name)
            .ok()
            .and_then(|s| s.parse().ok())
            .or(config_val)
    };

    let eff_evaluate_rps = env_or("VELLAVETO_RATE_EVALUATE", rl_cfg.evaluate_rps);
    let eff_evaluate_burst = env_or("VELLAVETO_RATE_EVALUATE_BURST", rl_cfg.evaluate_burst);
    let eff_admin_rps = env_or("VELLAVETO_RATE_ADMIN", rl_cfg.admin_rps);
    let eff_admin_burst = env_or("VELLAVETO_RATE_ADMIN_BURST", rl_cfg.admin_burst);
    let eff_readonly_rps = env_or("VELLAVETO_RATE_READONLY", rl_cfg.readonly_rps);
    let eff_readonly_burst = env_or("VELLAVETO_RATE_READONLY_BURST", rl_cfg.readonly_burst);
    let eff_per_ip_rps = env_or("VELLAVETO_RATE_PER_IP", rl_cfg.per_ip_rps);
    let eff_per_ip_burst = env_or("VELLAVETO_RATE_PER_IP_BURST", rl_cfg.per_ip_burst);
    let eff_per_ip_max_capacity: Option<usize> =
        std::env::var("VELLAVETO_RATE_PER_IP_MAX_CAPACITY")
            .ok()
            .and_then(|s| s.parse().ok())
            .or(rl_cfg.per_ip_max_capacity);

    let mut rate_limits_val = RateLimits::new_with_burst(
        eff_evaluate_rps,
        eff_evaluate_burst,
        eff_admin_rps,
        eff_admin_burst,
        eff_readonly_rps,
        eff_readonly_burst,
    );

    // Per-IP rate limiting: independent bucket per client IP address.
    if let Some(rps) = eff_per_ip_rps.and_then(std::num::NonZeroU32::new) {
        let burst = eff_per_ip_burst.and_then(std::num::NonZeroU32::new);
        rate_limits_val = rate_limits_val.with_per_ip_config(rps, burst, eff_per_ip_max_capacity);
        tracing::info!(
            "Per-IP rate limiting enabled: {} req/s per IP{}{}",
            rps,
            burst.map_or(String::new(), |b| format!(", burst {b}")),
            eff_per_ip_max_capacity.map_or(String::new(), |c| format!(", max {c} IPs")),
        );
    }

    // Per-principal rate limiting: independent bucket per principal key.
    // Principal is identified by X-Principal header, Bearer token, or client IP fallback.
    let eff_per_principal_rps = env_or("VELLAVETO_RATE_PER_PRINCIPAL", rl_cfg.per_principal_rps);
    let eff_per_principal_burst = env_or(
        "VELLAVETO_RATE_PER_PRINCIPAL_BURST",
        rl_cfg.per_principal_burst,
    );
    if let Some(rps) = eff_per_principal_rps.and_then(std::num::NonZeroU32::new) {
        let burst = eff_per_principal_burst.and_then(std::num::NonZeroU32::new);
        rate_limits_val = rate_limits_val.with_per_principal_config(rps, burst, None);
        tracing::info!(
            "Per-principal rate limiting enabled: {} req/s per principal{}",
            rps,
            burst.map_or(String::new(), |b| format!(", burst {b}")),
        );
    }

    let rate_limits = Arc::new(rate_limits_val);

    if rate_limits.evaluate.is_some()
        || rate_limits.admin.is_some()
        || rate_limits.readonly.is_some()
    {
        let fmt_cat = |rps: Option<u32>, burst: Option<u32>| -> String {
            match rps.filter(|&r| r > 0) {
                Some(r) => match burst.filter(|&b| b > 0) {
                    Some(b) => format!("{r} rps (burst {b})"),
                    None => format!("{r} rps"),
                },
                None => "off".to_string(),
            }
        };
        tracing::info!(
            "Rate limiting enabled — evaluate: {}, admin: {}, readonly: {}",
            fmt_cat(eff_evaluate_rps, eff_evaluate_burst),
            fmt_cat(eff_admin_rps, eff_admin_burst),
            fmt_cat(eff_readonly_rps, eff_readonly_burst),
        );
    }

    // Parse CORS allowed origins from environment variable.
    // Default (unset or empty): localhost only. Set to "*" for any origin.
    // Comma-separated list: "https://app.example.com,https://admin.example.com"
    let cors_origins: Vec<String> = std::env::var("VELLAVETO_CORS_ORIGINS")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|o| o.trim().to_string())
                .filter(|o| !o.is_empty())
                .collect()
        })
        .unwrap_or_default();

    if cors_origins.is_empty() {
        tracing::info!("CORS: localhost only (strict default)");
    } else if cors_origins.iter().any(|o| o == "*") {
        tracing::warn!("CORS: allowing ANY origin (VELLAVETO_CORS_ORIGINS=*)");
    } else {
        tracing::info!("CORS: allowed origins: {:?}", cors_origins);
    }

    // Parse trusted proxy IPs for secure X-Forwarded-For handling.
    // When configured, per-IP rate limiting uses the rightmost untrusted XFF entry.
    // When empty (default), proxy headers are ignored and connection IP is used directly.
    let trusted_proxies: Vec<std::net::IpAddr> = std::env::var("VELLAVETO_TRUSTED_PROXIES")
        .ok()
        .map(|s| {
            s.split(',')
                .filter_map(|ip| {
                    let trimmed = ip.trim();
                    match trimmed.parse::<std::net::IpAddr>() {
                        Ok(ip) => Some(ip),
                        Err(_) => {
                            if !trimmed.is_empty() {
                                tracing::warn!("Invalid trusted proxy IP: {:?}", trimmed);
                            }
                            None
                        }
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    if !trusted_proxies.is_empty() {
        tracing::info!(
            "Trusted proxies configured: {:?} — X-Forwarded-For headers will be trusted from these IPs",
            trusted_proxies
        );
    }

    // SECURITY (R13-LEG-4): Pre-compile policies and REFUSE to start on
    // compilation failure. The legacy evaluation path bypasses path_rules,
    // network_rules, and context_conditions — silently degrading to it would
    // drop all advanced security constraints. Matches vellaveto-http-proxy behavior.
    #[allow(unused_mut)] // mut needed when `discovery` feature enables set_topology_guard
    let mut engine = match PolicyEngine::with_policies(false, &policies) {
        Ok(mut compiled) => {
            if let Some(max_iter) = policy_config.max_path_decode_iterations {
                compiled.set_max_path_decode_iterations(max_iter);
                tracing::info!(
                    max_path_decode_iterations = max_iter,
                    "custom path decode iteration limit"
                );
            }
            tracing::info!(
                "Pre-compiled {} policies — zero-Mutex evaluation enabled",
                policies.len()
            );
            compiled
        }
        Err(errors) => {
            for e in &errors {
                tracing::error!("Policy compilation error: {}", e);
            }
            anyhow::bail!(
                "Failed to compile {} policies — fix config and retry. \
                 The server refuses to start with invalid policies to prevent \
                 silent degradation to the legacy evaluation path.",
                errors.len()
            );
        }
    };

    // Initialize Prometheus metrics recorder.
    let prometheus_handle = vellaveto_server::metrics::init_prometheus();

    // Set initial gauge values
    vellaveto_server::metrics::set_policies_loaded(policies.len() as f64);

    // Initialize tool registry if enabled (P2.1)
    let tool_registry: Option<Arc<vellaveto_mcp::tool_registry::ToolRegistry>> =
        if policy_config.tool_registry.enabled {
            let registry_path = if policy_config.tool_registry.persistence_path.is_empty() {
                config_dir.join("tool_registry.jsonl")
            } else {
                std::path::PathBuf::from(&policy_config.tool_registry.persistence_path)
            };
            let registry = vellaveto_mcp::tool_registry::ToolRegistry::with_threshold(
                &registry_path,
                policy_config.tool_registry.trust_threshold,
            );
            // Load existing entries
            match registry.load().await {
                Ok(count) if count > 0 => {
                    tracing::info!(
                        "Loaded {} tool registry entries from {}",
                        count,
                        registry_path.display()
                    );
                }
                Ok(_) => {
                    tracing::info!(
                        "Tool registry initialized (empty) at {}",
                        registry_path.display()
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to load tool registry from {}: {}",
                        registry_path.display(),
                        e
                    );
                }
            }
            tracing::info!(
                "Tool registry enabled with trust threshold {}",
                policy_config.tool_registry.trust_threshold
            );
            Some(Arc::new(registry))
        } else {
            None
        };

    // Initialize cluster backend (P3.4) if enabled.
    let cluster: Option<Arc<dyn vellaveto_cluster::ClusterBackend>> =
        if policy_config.cluster.enabled && policy_config.cluster.backend == "redis" {
            #[cfg(feature = "redis-backend")]
            {
                let backend = vellaveto_cluster::redis_backend::RedisBackend::new(
                    &policy_config.cluster.redis_url,
                    policy_config.cluster.redis_pool_size,
                    &policy_config.cluster.key_prefix,
                )
                .map_err(|e| {
                    anyhow::anyhow!("Failed to initialize Redis cluster backend: {}", e)
                })?;
                // SECURITY (FIND-044): Redact credentials from Redis URL before logging.
                // Redis URLs commonly embed passwords (redis://:pass@host:6379).
                let redacted_url = {
                    let raw = &policy_config.cluster.redis_url;
                    match url::Url::parse(raw) {
                        Ok(mut parsed) => {
                            if parsed.password().is_some() {
                                let _ = parsed.set_password(Some("***"));
                            }
                            parsed.to_string()
                        }
                        Err(_) => "***invalid-url***".to_string(),
                    }
                };
                tracing::info!(
                    "Cluster backend: Redis (url={}, pool_size={}, prefix={})",
                    redacted_url,
                    policy_config.cluster.redis_pool_size,
                    policy_config.cluster.key_prefix,
                );
                Some(Arc::new(backend))
            }
            #[cfg(not(feature = "redis-backend"))]
            {
                anyhow::bail!(
                    "Cluster backend 'redis' requires the 'redis-backend' feature. \
                     Build with: cargo build --features vellaveto-cluster/redis-backend"
                );
            }
        } else if policy_config.cluster.enabled {
            // "local" backend with clustering enabled — use LocalBackend wrapper
            let backend = vellaveto_cluster::local::LocalBackend::new(approvals.clone());
            tracing::info!("Cluster backend: local (single-instance mode)");
            Some(Arc::new(backend))
        } else {
            None
        };

    // Initialize topology guard + recrawl scheduler for pre-policy tool filtering.
    let (topology_guard, topology_probe, recrawl_trigger, topology_shutdown) = if policy_config
        .topology
        .enabled
    {
        let guard = Arc::new(vellaveto_discovery::guard::TopologyGuard::new());
        // Wire topology guard into the policy engine for pre-evaluation filtering.
        #[cfg(feature = "discovery")]
        {
            engine.set_topology_guard(Arc::clone(&guard));
        }

        // Build StaticProbe (starts empty, populated by relay tools/list intercepts)
        let probe = Arc::new(vellaveto_discovery::crawler::StaticProbe::new(vec![]));

        // Build crawler
        let crawl_config = vellaveto_discovery::CrawlConfig {
            server_timeout: std::time::Duration::from_secs(
                policy_config.topology.server_timeout_secs,
            ),
            continue_on_error: policy_config.topology.continue_on_error,
            max_concurrent: policy_config.topology.max_concurrent,
        };
        let crawler = Arc::new(vellaveto_discovery::TopologyCrawler::new(
            Arc::clone(&probe) as Arc<dyn vellaveto_discovery::McpServerProbe>,
            crawl_config,
        ));

        // Build recrawl scheduler
        let recrawl_config = vellaveto_discovery::RecrawlConfig {
            interval: std::time::Duration::from_secs(policy_config.topology.recrawl_interval_secs),
            on_unknown_tool: policy_config.topology.on_unknown_tool_recrawl,
            debounce: std::time::Duration::from_secs(30),
            max_consecutive_failures: policy_config.topology.max_consecutive_failures,
        };
        let scheduler = vellaveto_discovery::RecrawlScheduler::new(
            Arc::clone(&crawler),
            Arc::clone(&guard),
            recrawl_config,
        );
        let trigger = scheduler.trigger_handle();

        // Spawn scheduler background task with cancellation token
        let shutdown_token = tokio_util::sync::CancellationToken::new();
        let scheduler_token = shutdown_token.clone();
        tokio::spawn(async move {
            scheduler.run(scheduler_token).await;
        });

        tracing::info!(
            "Topology guard + recrawl scheduler enabled (recrawl_interval={}s, fallback_mode={})",
            policy_config.topology.recrawl_interval_secs,
            policy_config.topology.fallback_mode,
        );
        (
            Some(guard),
            Some(probe),
            Some(trigger),
            Some(shutdown_token),
        )
    } else {
        (None, None, None, None)
    };

    let state = AppState {
        policy_state: Arc::new(ArcSwap::from_pointee(vellaveto_server::PolicySnapshot {
            engine,
            policies,
            compliance_config: policy_config.compliance.clone(),
        })),
        audit: audit.clone(),
        config_path: Arc::new(config.clone()),
        approvals: approvals.clone(),
        api_key,
        rate_limits,
        cors_origins,
        metrics: Arc::new(vellaveto_server::Metrics::default()),
        trusted_proxies: Arc::new(trusted_proxies),
        policy_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        prometheus_handle,
        tool_registry,
        cluster,
        // RBAC configuration (Phase 2) — default: disabled, all requests get Admin
        // To enable: set rbac.enabled = true in config and optionally configure JWT
        rbac_config: vellaveto_server::rbac::RbacConfig::default(),
        // Tenant configuration (Phase 3) — default: disabled, single-tenant mode
        // To enable: set tenant.enabled = true in config
        tenant_config: vellaveto_server::tenant::TenantConfig::default(),
        tenant_store: None,
        tenant_rate_limiter: Arc::new(vellaveto_server::PerTenantRateLimiter::new()),
        // Idempotency key store (Phase 5) — default: disabled
        // To enable: set idempotency.enabled = true in config
        idempotency: vellaveto_server::idempotency::IdempotencyStore::new(
            vellaveto_server::idempotency::IdempotencyConfig::default(),
        ),
        signup_lock: Arc::new(tokio::sync::Mutex::new(())),
        webhook_dedup: Arc::new(vellaveto_server::routes::billing::WebhookDedup::new(
            std::time::Duration::from_secs(600), // 10-minute TTL
        )),

        // Phase 1 & 2 Security Managers — initialized from PolicyConfig
        task_state: if policy_config.async_tasks.enabled {
            Some(Arc::new(
                vellaveto_mcp::task_state::TaskStateManager::with_config(
                    policy_config.async_tasks.max_concurrent_tasks,
                    policy_config.async_tasks.max_task_duration_secs,
                    policy_config.async_tasks.require_self_cancel,
                    policy_config.async_tasks.allow_cancellation.clone(),
                ),
            ))
        } else {
            None
        },
        auth_level: if policy_config.step_up_auth.enabled {
            Some(Arc::new(
                vellaveto_mcp::auth_level::AuthLevelTracker::with_default_expiry(
                    std::time::Duration::from_secs(policy_config.step_up_auth.step_up_expiry_secs),
                ),
            ))
        } else {
            None
        },
        iam_state: iam_state.clone(),
        circuit_breaker: if policy_config.circuit_breaker.enabled {
            Some(Arc::new(
                vellaveto_engine::circuit_breaker::CircuitBreakerManager::with_config(
                    policy_config.circuit_breaker.failure_threshold,
                    policy_config.circuit_breaker.success_threshold,
                    policy_config.circuit_breaker.open_duration_secs,
                    policy_config.circuit_breaker.half_open_max_requests,
                ),
            ))
        } else {
            None
        },
        deputy: if policy_config.deputy.enabled {
            Some(Arc::new(vellaveto_engine::deputy::DeputyValidator::new(
                policy_config.deputy.max_delegation_depth,
            )))
        } else {
            None
        },
        shadow_agent: if policy_config.shadow_agent.enabled {
            Some(Arc::new(
                vellaveto_mcp::shadow_agent::ShadowAgentDetector::new(
                    policy_config.shadow_agent.max_known_agents,
                ),
            ))
        } else {
            None
        },
        schema_lineage: if policy_config.schema_poisoning.enabled {
            Some(Arc::new(
                vellaveto_mcp::schema_poisoning::SchemaLineageTracker::new(
                    policy_config.schema_poisoning.mutation_threshold,
                    policy_config.schema_poisoning.min_observations,
                    policy_config.schema_poisoning.max_tracked_schemas,
                ),
            ))
        } else {
            None
        },
        sampling_detector: if policy_config.sampling_detection.enabled {
            Some(Arc::new(
                vellaveto_mcp::sampling_detector::SamplingDetector::with_config(
                    policy_config.sampling_detection.max_requests_per_window,
                    policy_config.sampling_detection.window_secs,
                    policy_config.sampling_detection.max_prompt_length,
                    policy_config.sampling_detection.allowed_models.clone(),
                    policy_config.sampling_detection.block_sensitive_patterns,
                ),
            ))
        } else {
            None
        },
        // Phase 6: Observability
        exec_graph_store: None,
        // Phase 8: ETDI Cryptographic Tool Security — initialized from PolicyConfig
        etdi_store: if policy_config.etdi.enabled {
            let data_path = policy_config
                .etdi
                .data_path
                .as_deref()
                .unwrap_or("etdi_data");
            Some(Arc::new(vellaveto_mcp::etdi::EtdiStore::new(data_path)))
        } else {
            None
        },
        etdi_verifier: if policy_config.etdi.enabled {
            Some(Arc::new(vellaveto_mcp::etdi::ToolSignatureVerifier::new(
                policy_config.etdi.allowed_signers.clone(),
            )))
        } else {
            None
        },
        etdi_attestations: if policy_config.etdi.enabled && policy_config.etdi.attestation.enabled {
            // AttestationChain requires the store, but we can't reference etdi_store here
            // because struct initialization is unordered. We create a new store Arc.
            let data_path = policy_config
                .etdi
                .data_path
                .as_deref()
                .unwrap_or("etdi_data");
            let store = Arc::new(vellaveto_mcp::etdi::EtdiStore::new(data_path));
            Some(Arc::new(vellaveto_mcp::etdi::AttestationChain::new(store)))
        } else {
            None
        },
        etdi_version_pins: if policy_config.etdi.enabled
            && policy_config.etdi.version_pinning.enabled
        {
            let data_path = policy_config
                .etdi
                .data_path
                .as_deref()
                .unwrap_or("etdi_data");
            let store = Arc::new(vellaveto_mcp::etdi::EtdiStore::new(data_path));
            let blocking = policy_config.etdi.version_pinning.enforcement == "block";
            Some(Arc::new(vellaveto_mcp::etdi::VersionPinManager::new(
                store, blocking,
            )))
        } else {
            None
        },
        // Phase 9: Memory Injection Defense (MINJA) — initialized from PolicyConfig
        memory_security: if policy_config.memory_security.enabled {
            Some(Arc::new(
                vellaveto_mcp::memory_security::MemorySecurityManager::new(
                    policy_config.memory_security.clone(),
                ),
            ))
        } else {
            None
        },
        // Phase 10: Non-Human Identity (NHI) Lifecycle — initialized from PolicyConfig
        nhi: if policy_config.nhi.enabled {
            Some(Arc::new(vellaveto_mcp::nhi::NhiManager::new(
                policy_config.nhi.clone(),
            )))
        } else {
            None
        },

        // Phase 15: AI Observability Platform Integration
        #[cfg(feature = "observability-exporters")]
        observability: match vellaveto_server::observability::ObservabilityManager::new(
            &policy_config.observability,
        ) {
            Ok(Some(mgr)) => Some(Arc::new(mgr)),
            Ok(None) => None,
            Err(e) => {
                tracing::warn!("Failed to initialize observability: {}", e);
                None
            }
        },
        #[cfg(not(feature = "observability-exporters"))]
        observability: None,

        // Phase 26: Shadow AI Discovery & Governance
        shadow_ai_discovery: if policy_config.governance.shadow_ai_discovery {
            // FIND-R44-017: Populate registered agents from config
            let registered: std::collections::HashSet<String> = policy_config
                .governance
                .registered_agents
                .iter()
                .cloned()
                .collect();
            let approved: std::collections::HashSet<String> = policy_config
                .governance
                .approved_tools
                .iter()
                .cloned()
                .collect();
            let known: std::collections::HashSet<String> = policy_config
                .governance
                .known_servers
                .iter()
                .cloned()
                .collect();
            Some(Arc::new(
                vellaveto_mcp::shadow_ai_discovery::ShadowAiDiscovery::with_server_registration(
                    registered,
                    approved,
                    known,
                    policy_config.governance.require_agent_registration,
                    policy_config.governance.require_server_registration,
                ),
            ))
        } else {
            None
        },
        least_agency_tracker: Some(Arc::new(
            vellaveto_engine::least_agency::LeastAgencyTracker::new_with_config(
                0.5,
                policy_config.governance.least_agency_enforcement,
                policy_config.governance.auto_revoke_after_secs,
            ),
        )),

        // Server Configuration (FIND-004, FIND-005)
        metrics_require_auth: policy_config.metrics_require_auth,
        audit_strict_mode: policy_config.audit.strict_mode,

        // Phase 27: Kubernetes-Native Deployment
        leader_election: {
            use vellaveto_config::DeploymentMode;
            match policy_config.deployment.mode {
                DeploymentMode::Standalone => {
                    if policy_config.deployment.leader_election.enabled {
                        let id = policy_config.deployment.effective_instance_id();
                        Some(Arc::new(
                            vellaveto_cluster::leader_local::LocalLeaderElection::new(id).map_err(
                                |e| anyhow::anyhow!("Failed to create leader election: {e}"),
                            )?,
                        )
                            as Arc<dyn vellaveto_cluster::leader::LeaderElection>)
                    } else {
                        None
                    }
                }
                _ => {
                    // Clustered / Kubernetes modes use local leader election as placeholder
                    // until kube-rs backend is implemented behind a feature gate.
                    let id = policy_config.deployment.effective_instance_id();
                    Some(Arc::new(
                        vellaveto_cluster::leader_local::LocalLeaderElection::new(id).map_err(
                            |e| anyhow::anyhow!("Failed to create leader election: {e}"),
                        )?,
                    )
                        as Arc<dyn vellaveto_cluster::leader::LeaderElection>)
                }
            }
        },
        service_discovery: {
            use vellaveto_config::ServiceDiscoveryMode;
            match policy_config.deployment.service_discovery.mode {
                ServiceDiscoveryMode::Static => None, // no static endpoints configured at server level
                ServiceDiscoveryMode::Dns => {
                    if let Some(ref dns_name) = policy_config.deployment.service_discovery.dns_name
                    {
                        let interval = std::time::Duration::from_secs(
                            policy_config
                                .deployment
                                .service_discovery
                                .refresh_interval_secs,
                        );
                        match vellaveto_cluster::discovery_dns::DnsServiceDiscovery::new(
                            dns_name.clone(),
                            interval,
                        ) {
                            Ok(disc) => Some(Arc::new(disc)
                                as Arc<dyn vellaveto_cluster::discovery::ServiceDiscovery>),
                            Err(e) => {
                                tracing::error!("Invalid DNS discovery config: {}", e);
                                None
                            }
                        }
                    } else {
                        tracing::warn!(
                            "DNS service discovery mode requires dns_name; falling back to none"
                        );
                        None
                    }
                }
                ServiceDiscoveryMode::Kubernetes => {
                    tracing::info!("Kubernetes service discovery is a future feature; using none");
                    None
                }
            }
        },
        deployment_config: policy_config.deployment.clone(),
        start_time: std::time::Instant::now(),

        // SECURITY (FIND-P27-001): Cache discovered endpoint count to avoid DNS
        // lookup on every /health request. Updated by background task below.
        cached_discovered_endpoints: Arc::new(std::sync::atomic::AtomicU64::new(0)),

        // SECURITY (FIND-P27-004): Resolve instance ID once at startup.
        cached_instance_id: Arc::new(policy_config.deployment.effective_instance_id()),

        // Topology Crawling (ActionEngine-inspired live discovery)
        topology_guard,
        topology_probe,
        recrawl_trigger,

        // Phase 34: Tool Discovery Service
        discovery_engine: if policy_config.discovery.enabled {
            Some(Arc::new(vellaveto_mcp::discovery::DiscoveryEngine::new(
                policy_config.discovery.clone(),
            )))
        } else {
            None
        },
        discovery_audit: if policy_config.discovery.enabled {
            Some(Arc::clone(&audit))
        } else {
            None
        },

        // Phase 35.3: Model Projector
        projector_registry: if policy_config.projector.enabled {
            let family = parse_model_family(&policy_config.projector.default_model_family);
            match vellaveto_mcp::projector::ProjectorRegistry::with_defaults(family) {
                Ok(registry) => {
                    tracing::info!(
                        "Model projector enabled (default family: {})",
                        policy_config.projector.default_model_family
                    );
                    Some(Arc::new(registry))
                }
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "Failed to initialize projector registry: {e}"
                    ));
                }
            }
        } else {
            None
        },

        // Phase 37: Zero-Knowledge Audit Trails
        zk_proofs: if policy_config.zk_audit.enabled {
            tracing::info!(
                "ZK audit enabled (batch_proof={})",
                policy_config.zk_audit.batch_proof_enabled
            );
            Some(Arc::new(std::sync::Mutex::new(Vec::new())))
        } else {
            None
        },
        zk_audit_enabled: policy_config.zk_audit.enabled,
        zk_audit_config: policy_config.zk_audit.clone(),
        federation_resolver: {
            let fed = &policy_config.abac.federation;
            if fed.enabled && !fed.trust_anchors.is_empty() {
                tracing::info!(
                    anchors = fed.trust_anchors.len(),
                    "Federation resolver initialized"
                );
                Some(std::sync::Arc::new(
                    vellaveto_server::FederationResolver::new(fed.clone()),
                ))
            } else {
                None
            }
        },
        billing_config: {
            let licensing_validation = policy_config.licensing.resolve();
            tracing::info!(
                tier = %licensing_validation.tier,
                reason = %licensing_validation.reason,
                "License tier resolved"
            );
            Arc::new(vellaveto_server::BillingState {
                paddle: policy_config.billing.paddle.clone(),
                stripe: policy_config.billing.stripe.clone(),
                enabled: policy_config.billing.enabled,
                licensing_validation,
            })
        },

        // Setup wizard state
        setup_completed: {
            let marker = vellaveto_server::setup_wizard::setup_complete_marker_path(&config);
            let completed = marker.exists();
            if completed {
                tracing::info!(
                    "Setup wizard: previously completed (marker found at {:?})",
                    marker
                );
            } else {
                tracing::warn!(
                    "Setup wizard: not yet completed — visit http://{}:{}/setup to configure",
                    bind,
                    port
                );
            }
            Arc::new(std::sync::atomic::AtomicBool::new(completed))
        },
        wizard_sessions: Arc::new(dashmap::DashMap::new()),

        // Phase 43: Centralized Audit Store
        audit_query: {
            #[cfg(feature = "postgres-store")]
            {
                if policy_config.audit_store.enabled
                    && policy_config.audit_store.backend
                        == vellaveto_types::audit_store::AuditStoreBackend::Postgres
                {
                    let db_url = policy_config
                        .audit_store
                        .database_url
                        .as_deref()
                        .unwrap_or("");
                    // Create a separate pool for queries (read path)
                    if let Ok(pool) = sqlx::postgres::PgPoolOptions::new()
                        .max_connections(policy_config.audit_store.pool_size)
                        .acquire_timeout(std::time::Duration::from_secs(
                            policy_config.audit_store.connect_timeout_secs as u64,
                        ))
                        .connect(db_url)
                        .await
                    {
                        match vellaveto_audit::query::postgres::PostgresAuditQuery::new(
                            pool,
                            policy_config.audit_store.table_name.clone(),
                        ) {
                            Ok(query) => Arc::new(query)
                                as Arc<dyn vellaveto_audit::query::AuditQueryService>,
                            Err(e) => {
                                tracing::warn!(error = %e, "Invalid audit store table_name, falling back to file query");
                                Arc::new(vellaveto_audit::query::file::FileAuditQuery::new(
                                    Arc::clone(&audit),
                                ))
                                    as Arc<dyn vellaveto_audit::query::AuditQueryService>
                            }
                        }
                    } else {
                        tracing::warn!("Failed to create query pool, falling back to file query");
                        Arc::new(vellaveto_audit::query::file::FileAuditQuery::new(
                            Arc::clone(&audit),
                        ))
                            as Arc<dyn vellaveto_audit::query::AuditQueryService>
                    }
                } else {
                    Arc::new(vellaveto_audit::query::file::FileAuditQuery::new(
                        Arc::clone(&audit),
                    )) as Arc<dyn vellaveto_audit::query::AuditQueryService>
                }
            }
            #[cfg(not(feature = "postgres-store"))]
            {
                Arc::new(vellaveto_audit::query::file::FileAuditQuery::new(
                    Arc::clone(&audit),
                )) as Arc<dyn vellaveto_audit::query::AuditQueryService>
            }
        },
        audit_store_status: vellaveto_types::audit_store::AuditStoreStatus {
            enabled: policy_config.audit_store.enabled,
            backend: policy_config.audit_store.backend,
            sink_healthy: pg_sink.as_ref().is_some_and(|s| s.is_healthy()),
            pending_count: pg_sink.as_ref().map(|s| s.pending_count()).unwrap_or(0),
        },
        // Phase 47: Policy Lifecycle Management
        policy_lifecycle_store: if policy_config.policy_lifecycle.enabled {
            Some(Arc::new(
                vellaveto_server::policy_lifecycle::InMemoryPolicyVersionStore::new(
                    policy_config.policy_lifecycle.clone(),
                ),
            ))
        } else {
            None
        },
        policy_lifecycle_config: policy_config.policy_lifecycle.clone(),
        staging_snapshot: Arc::new(ArcSwap::from_pointee(None)),
        usage_tracker: if policy_config.metering.enabled {
            Some(Arc::new(
                vellaveto_server::usage_tracker::TenantUsageTracker::new(
                    policy_config.metering.clone(),
                ),
            ))
        } else {
            None
        },
    };

    tracing::info!("Audit log: {}", audit_path.display());
    tracing::info!("Approvals log: {}", approval_path.display());

    // Spawn periodic approval expiry task.
    // When clustering is enabled, uses the cluster backend (e.g., Redis TTL-based expiry).
    // Otherwise, uses the local ApprovalStore directly.
    let expiry_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let expired = match expiry_state.expire_stale_approvals().await {
                Ok(count) => count,
                Err(e) => {
                    tracing::warn!("Failed to expire stale approvals: {:?}", e);
                    0
                }
            };
            if expired > 0 {
                tracing::info!("Expired {} stale approvals", expired);
            }
        }
    });

    // SECURITY (FIND-P27-001): Spawn background service discovery refresh.
    // Caches endpoint count so /health and /api/deployment/info never call discover() directly.
    if let Some(ref sd) = state.service_discovery {
        let sd_clone = sd.clone();
        let cached_count = state.cached_discovered_endpoints.clone();
        let refresh_secs = state
            .deployment_config
            .service_discovery
            .refresh_interval_secs;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(refresh_secs));
            loop {
                interval.tick().await;
                match sd_clone.discover().await {
                    Ok(eps) => {
                        cached_count.store(eps.len() as u64, std::sync::atomic::Ordering::SeqCst);
                    }
                    Err(e) => {
                        tracing::warn!("Service discovery refresh failed: {:?}", e);
                        // SECURITY: fail-closed — set to 0 on error so we don't report stale data.
                        cached_count.store(0, std::sync::atomic::Ordering::SeqCst);
                    }
                }
            }
        });
    }

    // Spawn periodic audit checkpoint task.
    // Creates a signed Ed25519 checkpoint every VELLAVETO_CHECKPOINT_INTERVAL seconds (default: 300).
    let checkpoint_interval: u64 = std::env::var("VELLAVETO_CHECKPOINT_INTERVAL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);

    if checkpoint_interval > 0 {
        let checkpoint_audit = state.audit.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(checkpoint_interval));
            // Skip the first immediate tick — no point checkpointing an empty/just-loaded log
            interval.tick().await;
            loop {
                interval.tick().await;
                match checkpoint_audit.create_checkpoint().await {
                    Ok(cp) => tracing::info!(
                        "Audit checkpoint created: {} ({} entries)",
                        cp.id,
                        cp.entry_count
                    ),
                    Err(e) => tracing::warn!("Failed to create audit checkpoint: {}", e),
                }
            }
        });
        tracing::info!(
            "Audit checkpoint task enabled (every {}s)",
            checkpoint_interval
        );
    } else {
        tracing::warn!("SECURITY: Audit checkpoint interval is 0 — checkpoints disabled. Tamper evidence requires periodic checkpoints.");
    }

    // Spawn periodic audit heartbeat task.
    // Logs heartbeat entries every VELLAVETO_HEARTBEAT_INTERVAL seconds (default: 300).
    // IMPROVEMENT_PLAN 10.6: Heartbeat entries enable detection of log truncation/gaps.
    let heartbeat_interval: u64 = std::env::var("VELLAVETO_HEARTBEAT_INTERVAL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);

    if heartbeat_interval > 0 {
        let heartbeat_audit = state.audit.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(heartbeat_interval));
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
    } else {
        tracing::warn!("SECURITY: Audit heartbeat interval is 0 — heartbeat disabled. Log gap detection requires periodic heartbeats.");
    }

    // Spawn periodic SOC 2 access review report generation (Phase 38).
    {
        let snapshot = state.policy_state.load();
        let schedule = snapshot.compliance_config.soc2.access_review.schedule;
        let ar_enabled = snapshot.compliance_config.soc2.enabled
            && snapshot.compliance_config.soc2.access_review.enabled;
        if ar_enabled {
            if let Some(sched) = schedule {
                let sched_secs = match sched {
                    vellaveto_types::compliance::ReviewSchedule::Daily => 86_400u64,
                    vellaveto_types::compliance::ReviewSchedule::Weekly => 604_800u64,
                    vellaveto_types::compliance::ReviewSchedule::Monthly => 2_592_000u64,
                };
                let ar_audit = state.audit.clone();
                let ar_policy_state = state.policy_state.clone();
                let ar_least_agency = state.least_agency_tracker.clone();
                tokio::spawn(async move {
                    let mut interval =
                        tokio::time::interval(std::time::Duration::from_secs(sched_secs));
                    interval.tick().await; // Skip first immediate tick
                    loop {
                        interval.tick().await;
                        let snap = ar_policy_state.load();
                        let period_days = snap
                            .compliance_config
                            .soc2
                            .access_review
                            .default_period_days;
                        let now = chrono::Utc::now();
                        let period_end = now.to_rfc3339();
                        let period_start =
                            (now - chrono::Duration::days(i64::from(period_days))).to_rfc3339();
                        match ar_audit.load_entries().await {
                            Ok(entries) => {
                                // Collect least-agency data
                                let la_data = if let Some(ref tracker) = ar_least_agency {
                                    let mut pairs = std::collections::HashSet::new();
                                    for entry in &entries {
                                        if entry.action.tool == "vellaveto" {
                                            continue;
                                        }
                                        if entry.timestamp.as_str() < period_start.as_str()
                                            || entry.timestamp.as_str() > period_end.as_str()
                                        {
                                            continue;
                                        }
                                        let aid = entry
                                            .metadata
                                            .get("agent_id")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or(&entry.action.tool);
                                        let sid = entry
                                            .metadata
                                            .get("session_id")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("unknown");
                                        pairs.insert((aid.to_string(), sid.to_string()));
                                    }
                                    let mut m = std::collections::HashMap::new();
                                    for (a, s) in pairs {
                                        if let Some(r) = tracker.generate_report(&a, &s) {
                                            m.insert((a, s), r);
                                        }
                                    }
                                    m
                                } else {
                                    std::collections::HashMap::new()
                                };
                                let report = vellaveto_audit::access_review::generate_access_review(
                                    &entries,
                                    &snap.compliance_config.soc2.organization_name,
                                    &period_start,
                                    &period_end,
                                    &la_data,
                                );
                                tracing::info!(
                                    total_agents = report.total_agents,
                                    total_evaluations = report.total_evaluations,
                                    "Scheduled access review report generated"
                                );
                                let _ = ar_audit
                                    .log_access_review_event(
                                        "scheduled",
                                        serde_json::json!({
                                            "period_days": period_days,
                                            "total_agents": report.total_agents,
                                            "total_evaluations": report.total_evaluations,
                                        }),
                                    )
                                    .await;
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Scheduled access review failed to load entries: {}",
                                    e
                                );
                                let _ = ar_audit
                                    .log_access_review_event(
                                        "error",
                                        serde_json::json!({
                                            "error": e.to_string(),
                                        }),
                                    )
                                    .await;
                            }
                        }
                    }
                });
                tracing::info!(
                    schedule = ?sched,
                    interval_secs = sched_secs,
                    "SOC 2 access review scheduler enabled"
                );
            }
        }
    }

    // Spawn periodic per-IP rate limit bucket cleanup (every 10 minutes)
    if state.rate_limits.per_ip.is_some() {
        let cleanup_limits = state.rate_limits.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(600));
            interval.tick().await; // Skip first immediate tick
            loop {
                interval.tick().await;
                if let Some(ref per_ip) = cleanup_limits.per_ip {
                    let before = per_ip.len();
                    per_ip.cleanup(std::time::Duration::from_secs(3600));
                    let removed = before.saturating_sub(per_ip.len());
                    if removed > 0 {
                        tracing::debug!(
                            "Cleaned up {} stale per-IP rate limit buckets ({} remaining)",
                            removed,
                            per_ip.len()
                        );
                    }
                }
            }
        });
    }

    // Spawn periodic per-principal rate limit bucket cleanup (every 10 minutes)
    if state.rate_limits.per_principal.is_some() {
        let cleanup_limits = state.rate_limits.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(600));
            interval.tick().await; // Skip first immediate tick
            loop {
                interval.tick().await;
                if let Some(ref per_principal) = cleanup_limits.per_principal {
                    let before = per_principal.len();
                    per_principal.cleanup(std::time::Duration::from_secs(3600));
                    let removed = before.saturating_sub(per_principal.len());
                    if removed > 0 {
                        tracing::debug!(
                            "Cleaned up {} stale per-principal rate limit buckets ({} remaining)",
                            removed,
                            per_principal.len()
                        );
                    }
                }
            }
        });
    }

    // Optionally watch the config file for changes and auto-reload
    if watch {
        if let Err(e) = vellaveto_server::spawn_config_watcher(state.clone()) {
            tracing::warn!("Failed to start config file watcher: {}", e);
        }
    }

    // SIGHUP handler: reload policies from the config file without restarting.
    // This provides an operator-friendly mechanism for hot policy reload via
    // `kill -HUP <pid>` in addition to the existing file watcher and API endpoint.
    #[cfg(unix)]
    {
        let sighup_state = state.clone();
        tokio::spawn(async move {
            let mut sighup =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("Failed to install SIGHUP handler: {}", e);
                        return;
                    }
                };
            tracing::info!("SIGHUP handler installed — send HUP to reload policies");
            loop {
                sighup.recv().await;
                tracing::info!("Received SIGHUP, reloading policies...");
                match vellaveto_server::reload_policies_from_file(&sighup_state, "sighup").await {
                    Ok(count) => {
                        tracing::info!("SIGHUP: reloaded {} policies", count);
                        vellaveto_server::metrics::set_policies_loaded(count as f64);
                    }
                    Err(e) => {
                        tracing::error!("SIGHUP: policy reload failed: {}", e);
                    }
                }
            }
        });
    }

    // SECURITY (FIND-033): Warn loudly when RBAC is disabled.
    // In the default config, all requests receive the Admin role, which grants
    // unrestricted access to all endpoints. This is intentional for development
    // but dangerous in production.
    if !state.rbac_config.enabled {
        tracing::warn!(
            "RBAC is DISABLED — all requests receive Admin privileges. \
             Set rbac.enabled=true in production to enforce access control."
        );
    }

    // Keep a reference to audit for shutdown flush
    let shutdown_audit = state.audit.clone();
    let shutdown_sink = pg_sink.clone();

    let app = routes::build_router(state);

    // R226: Warn when binding to all interfaces (NeighborJack / Backslash MCP vulnerability).
    // Binding to 0.0.0.0 or :: exposes the server to all network interfaces, including
    // adjacent networks. This is intentional in Docker/K8s but dangerous on developer machines.
    if bind == "0.0.0.0" || bind == "::" || bind == "[::]" {
        tracing::warn!(
            bind_address = %bind,
            "Server binding to ALL network interfaces. This exposes Vellaveto to \
             adjacent network attackers (NeighborJack). Use 127.0.0.1 for local-only \
             access, or ensure firewall rules restrict access in production."
        );
    }

    let listener = tokio::net::TcpListener::bind(format!("{bind}:{port}"))
        .await
        .context("Failed to bind to address")?;

    // SECURITY (R236-TLS-1): Build TLS acceptor from config. If TLS is enabled,
    // serve over TLS; otherwise fall back to plaintext.
    let tls_acceptor = vellaveto_tls::build_tls_acceptor(&policy_config.tls)
        .map_err(|e| anyhow::anyhow!("TLS configuration error: {e}"))?;

    let scheme = if tls_acceptor.is_some() {
        "https"
    } else {
        "http"
    };
    tracing::info!(
        "Vellaveto server listening on {scheme}://{}:{} (TLS mode: {:?})",
        bind,
        port,
        policy_config.tls.mode
    );

    if open_browser {
        let url = format!("{scheme}://{bind}:{port}/dashboard");
        tokio::task::spawn_blocking(move || {
            if let Err(e) = open_url_in_browser(&url) {
                tracing::warn!("Failed to open browser: {}", e);
            }
        });
    }

    match tls_acceptor {
        Some(acceptor) => {
            // Use tap_io wrapper to satisfy axum's Connected trait bounds
            // (orphan rules prevent direct Connected impl for external types).
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
            .with_graceful_shutdown(shutdown_signal())
            .await
            .context("TLS server error")?;
        }
        None => {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown_signal())
            .await
            .context("Server error")?;
        }
    }

    // Cancel the topology recrawl scheduler if it was started.
    if let Some(ref token) = topology_shutdown {
        token.cancel();
        tracing::info!("Topology recrawl scheduler cancelled");
    }

    // Flush audit log with a 30-second timeout to prevent hanging on shutdown.
    let shutdown_deadline = std::time::Duration::from_secs(30);
    let cleanup = async {
        // This ensures Allow/RequireApproval entries (which skip per-write fsync)
        // are not lost on graceful shutdown.
        if let Err(e) = shutdown_audit.sync().await {
            tracing::warn!("Failed to sync audit log during shutdown: {}", e);
        }
        // Flush and shut down the audit sink (Phase 43)
        if let Some(ref sink) = shutdown_sink {
            if let Err(e) = sink.shutdown().await {
                tracing::warn!("Failed to shut down audit sink: {}", e);
            } else {
                tracing::info!("Audit sink shut down successfully");
            }
        }
        // Create a final checkpoint to capture any entries since the last periodic checkpoint
        match shutdown_audit.create_checkpoint().await {
            Ok(cp) => tracing::info!(
                "Shutdown checkpoint created: {} ({} entries)",
                cp.id,
                cp.entry_count
            ),
            Err(e) => tracing::debug!("Shutdown checkpoint skipped: {}", e),
        }
    };
    if tokio::time::timeout(shutdown_deadline, cleanup)
        .await
        .is_err()
    {
        tracing::warn!("Shutdown cleanup timed out after 30s — exiting without full flush");
    }

    tracing::info!("Server shut down gracefully");
    Ok(())
}

async fn cmd_evaluate(
    tool: String,
    function: String,
    params: String,
    config: String,
) -> Result<()> {
    let parameters: serde_json::Value =
        serde_json::from_str(&params).context("Invalid JSON in --params")?;

    let action = Action::new(tool, function, parameters);

    let policy_config = PolicyConfig::load_file(&config)
        .map_err(|e| anyhow::anyhow!("Failed to load config: {e}"))?;

    let mut policies = policy_config.to_policies();
    PolicyEngine::sort_policies(&mut policies);

    let mut engine = PolicyEngine::with_policies(false, &policies).map_err(|errors| {
        let msgs: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
        anyhow::anyhow!("Policy compilation errors: {}", msgs.join("; "))
    })?;
    if let Some(max_iter) = policy_config.max_path_decode_iterations {
        engine.set_max_path_decode_iterations(max_iter);
    }
    let verdict = engine
        .evaluate_action(&action, &policies)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let (final_verdict, opa_decision) = if matches!(verdict, Verdict::Allow) {
        match vellaveto_server::opa::OpaClient::new(&policy_config.opa)
            .map_err(|e| anyhow::anyhow!("Failed to initialize OPA client: {e}"))?
        {
            Some(opa_client) => {
                let input = vellaveto_server::opa::OpaInput {
                    tool: action.tool.clone(),
                    function: action.function.clone(),
                    parameters: action.parameters.clone(),
                    principal: None,
                    session_id: None,
                    context: json!({
                        "source": "cli",
                        "vellaveto_verdict": verdict.clone(),
                    }),
                };

                match opa_client.evaluate(&input).await {
                    Ok(decision) if decision.allow => (verdict, Some(decision)),
                    Ok(decision) => (
                        Verdict::Deny {
                            // SECURITY (R239-SRV-1): Use fixed denial reason.
                            // The OPA reason comes from an external server and
                            // may contain control characters or injection
                            // patterns. The raw reason is still available in the
                            // OpaDecision metadata for auditing.
                            reason: "Denied by OPA policy".to_string(),
                        },
                        Some(decision),
                    ),
                    Err(e) if opa_client.fail_open() => {
                        tracing::warn!("OPA evaluation failed in fail-open mode: {}", e);
                        (verdict, None)
                    }
                    Err(e) => (
                        Verdict::Deny {
                            reason: format!("OPA evaluation failed (fail-closed): {e}"),
                        },
                        None,
                    ),
                }
            }
            None => (verdict, None),
        }
    } else {
        (verdict, None)
    };

    let output = serde_json::to_string_pretty(&json!({
        "action": action,
        "verdict": final_verdict,
        "opa_decision": opa_decision,
        "policies_loaded": policies.len(),
    }))?;

    println!("{output}");
    Ok(())
}

async fn cmd_check(
    config: String,
    strict: bool,
    format: String,
    no_best_practices: bool,
    no_security_checks: bool,
) -> Result<()> {
    use vellaveto_config::validation::{PolicyValidator, ValidationCategory, ValidationFinding};

    // Load the configuration
    let policy_config = PolicyConfig::load_file(&config)
        .map_err(|e| anyhow::anyhow!("Failed to load config: {e}"))?;

    // Build the validator with options
    let mut validator = PolicyValidator::new();
    if strict {
        validator = validator.strict();
    }
    if no_best_practices {
        validator = validator.with_best_practices(false);
    }
    if no_security_checks {
        validator = validator.with_security_checks(false);
    }

    // Run validation
    let mut result = validator.validate(&policy_config);

    // Compile the policies with the same call `cmd_serve` makes at startup.
    //
    // The validator checks schema, semantics, security and best practices, but
    // it never compiled anything — so a config the server refuses to start with
    // could pass `check` with "0 errors" and exit 0. That is the worst possible
    // direction for this tool to be wrong in: `check` exists to be trusted in
    // CI and before a deploy. `examples/presets/devops-agent.toml` shipped
    // broken for exactly this reason (issue #407) — it used an unknown
    // constraint operator, which only the compiler rejects.
    //
    // Compiling here rather than reimplementing the compiler's rules is the
    // point: a second implementation of "valid" is how the two drifted apart.
    let policies = policy_config.to_policies();
    if let Err(compile_errors) = PolicyEngine::with_policies(false, &policies) {
        for e in &compile_errors {
            result.findings.push(
                ValidationFinding::error("POLICY_COMPILE", &e.reason)
                    .at(&e.policy_id)
                    .with_category(ValidationCategory::Semantic)
                    .with_suggestion(
                        "The server refuses to start on this policy. Fix it before deploying.",
                    ),
            );
        }
        result.summary.errors = result.summary.errors.saturating_add(compile_errors.len());
        result = result.finalize();
    }

    // Output results
    if format == "json" {
        let output = serde_json::to_string_pretty(&result)?;
        println!("{output}");
    } else {
        // Text format
        println!("{}", result.to_text());

        // Also show policy summary
        println!("\nPolicies loaded: {}", policies.len());
        for (i, p) in policies.iter().enumerate() {
            println!(
                "  [{}] id={:?} name={:?} type={} priority={}",
                i,
                p.id,
                p.name,
                match &p.policy_type {
                    vellaveto_types::PolicyType::Allow => "Allow",
                    vellaveto_types::PolicyType::Deny => "Deny",
                    vellaveto_types::PolicyType::Conditional { .. } => "Conditional",
                    _ => "Unknown",
                },
                p.priority
            );
        }
    }

    // Exit with error code if invalid
    if result.has_errors() {
        anyhow::bail!(
            "Configuration validation failed with {} errors",
            result.summary.errors
        );
    }

    Ok(())
}

fn cmd_policies(preset: String) -> Result<()> {
    let policies: Vec<Policy> = match preset.as_str() {
        "dangerous" => CanonicalPolicies::block_dangerous_tools(),
        "network" => CanonicalPolicies::network_security(),
        "development" => CanonicalPolicies::development_environment(),
        "deny-all" => vec![CanonicalPolicies::deny_all()],
        "allow-all" => vec![CanonicalPolicies::allow_all()],
        _ => {
            anyhow::bail!(
                "Unknown preset: '{preset}'. Available: dangerous, network, development, deny-all, allow-all"
            );
        }
    };

    let rules: Vec<vellaveto_config::PolicyRule> = policies
        .iter()
        .map(|p| vellaveto_config::PolicyRule {
            name: p.name.clone(),
            tool_pattern: extract_tool_pattern(&p.id),
            function_pattern: extract_function_pattern(&p.id),
            policy_type: p.policy_type.clone(),
            priority: Some(p.priority),
            id: Some(p.id.clone()),
            path_rules: p.path_rules.clone(),
            network_rules: p.network_rules.clone(),
        })
        .collect();

    let config = PolicyConfig {
        policies: rules,
        injection: Default::default(),
        dlp: Default::default(),
        multimodal: Default::default(),
        rate_limit: Default::default(),
        audit: Default::default(),
        supply_chain: Default::default(),
        manifest: Default::default(),
        memory_tracking: Default::default(),
        elicitation: Default::default(),
        sampling: Default::default(),
        audit_export: Default::default(),
        max_path_decode_iterations: None,
        known_tool_names: Default::default(),
        tool_registry: Default::default(),
        allowed_origins: Default::default(),
        behavioral: Default::default(),
        data_flow: Default::default(),
        semantic_detection: Default::default(),
        cluster: Default::default(),
        async_tasks: Default::default(),
        resource_indicator: Default::default(),
        cimd: Default::default(),
        step_up_auth: Default::default(),
        circuit_breaker: Default::default(),
        deputy: Default::default(),
        shadow_agent: Default::default(),
        schema_poisoning: Default::default(),
        sampling_detection: Default::default(),
        cross_agent: Default::default(),
        advanced_threat: Default::default(),
        tls: Default::default(),
        spiffe: Default::default(),
        opa: Default::default(),
        threat_intel: Default::default(),
        jit_access: Default::default(),
        etdi: Default::default(),
        memory_security: Default::default(),
        nhi: Default::default(),
        semantic_guardrails: Default::default(),
        rag_defense: Default::default(),
        a2a: Default::default(),
        observability: Default::default(),
        metrics_require_auth: true,
        limits: Default::default(),
        compliance: Default::default(),
        extension: Default::default(),
        transport: Default::default(),
        gateway: Default::default(),
        abac: Default::default(),
        fips: Default::default(),
        governance: Default::default(),
        deployment: Default::default(),
        streamable_http: Default::default(),
        discovery: Default::default(),
        projector: Default::default(),
        zk_audit: Default::default(),
        licensing: Default::default(),
        iam: Default::default(),
        billing: Default::default(),
        audit_store: Default::default(),
        policy_lifecycle: Default::default(),
        metering: Default::default(),
        topology: Default::default(),
        shield: Default::default(),
        acis: Default::default(),
        tool_quotas: Default::default(),
        secret_substitutions: Default::default(),
        policy_templates: Default::default(),
        source_trust: Default::default(),
        sink_classification: Default::default(),
        intent_scope: Default::default(),
    };
    let toml_str =
        toml::to_string_pretty(&config).context("Failed to serialize policies to TOML")?;

    println!("{toml_str}");
    Ok(())
}

async fn cmd_verify(audit: String, trusted_key: Option<String>, list_rotated: bool) -> Result<()> {
    let audit_path = std::path::PathBuf::from(&audit);
    if !audit_path.exists() {
        anyhow::bail!("Audit log not found: {audit}");
    }

    let mut logger = AuditLogger::new(audit_path);
    if let Some(ref key) = trusted_key {
        // Validate key format early
        let key_bytes =
            hex::decode(key).map_err(|e| anyhow::anyhow!("Invalid --trusted-key hex: {e}"))?;
        if key_bytes.len() != 32 {
            anyhow::bail!(
                "--trusted-key must be exactly 32 bytes (64 hex chars), got {}",
                key_bytes.len()
            );
        }
        logger = logger.with_trusted_key(key.clone());
    }

    // Phase 1: Verify hash chain
    println!("Verifying hash chain...");
    let chain_result = logger
        .verify_chain()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to verify chain: {e}"))?;

    if chain_result.valid {
        println!(
            "  Hash chain: OK ({} entries verified)",
            chain_result.entries_checked
        );
    } else {
        println!(
            "  Hash chain: BROKEN at entry {}",
            chain_result
                .first_broken_at
                .map_or("unknown".to_string(), |i| i.to_string())
        );
    }

    // Phase 2: Verify checkpoints
    println!("Verifying checkpoints...");
    let cp_result = logger
        .verify_checkpoints()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to verify checkpoints: {e}"))?;

    if cp_result.checkpoints_checked == 0 {
        println!("  Checkpoints: none found (skipped)");
    } else if cp_result.valid {
        println!(
            "  Checkpoints: OK ({} verified{})",
            cp_result.checkpoints_checked,
            if trusted_key.is_some() {
                ", key pinned"
            } else {
                ""
            }
        );
    } else {
        println!(
            "  Checkpoints: INVALID at checkpoint {}",
            cp_result
                .first_invalid_at
                .map_or("unknown".to_string(), |i| i.to_string())
        );
        if let Some(ref reason) = cp_result.failure_reason {
            println!("  Reason: {reason}");
        }
    }

    // Phase 3: Check for duplicate entry IDs
    println!("Checking for duplicate entry IDs...");
    let has_duplicates = match logger.detect_duplicate_ids().await {
        Ok(duplicates) if duplicates.is_empty() => {
            println!("  Duplicates: none");
            false
        }
        Ok(duplicates) => {
            println!(
                "  WARNING: {} duplicate entry ID(s) found:",
                duplicates.len()
            );
            for (id, count) in &duplicates {
                println!("    {id} (appears {count} times)");
            }
            true
        }
        Err(e) => {
            println!("  Failed to check for duplicates: {e}");
            false
        }
    };

    // Phase 4: List rotated files if requested
    if list_rotated {
        println!("Rotated log files:");
        match logger.list_rotated_files() {
            Ok(files) if files.is_empty() => {
                println!("  (none)");
            }
            Ok(files) => {
                for path in &files {
                    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
                    println!("  {} ({} bytes)", path.display(), size);
                }
                println!("  Total rotated files: {}", files.len());
            }
            Err(e) => {
                println!("  Failed to list rotated files: {e}");
            }
        }
    }

    // Summary — exit codes:
    //   0 = all valid
    //   1 = chain or checkpoint integrity failure
    //   2 = duplicate entry IDs detected (possible replay attack)
    // Duplicates are checked first because they indicate a specific attack
    // vector (replay) that is actionable regardless of chain status.
    let chain_ok = chain_result.valid && cp_result.valid;
    println!();
    if has_duplicates {
        if chain_ok {
            println!(
                "Audit log integrity: FAILED (duplicate entry IDs detected — possible replay attack)"
            );
        } else {
            println!(
                "Audit log integrity: FAILED (chain/checkpoint invalid + duplicate entry IDs)"
            );
        }
        std::process::exit(2);
    } else if chain_ok {
        println!("Audit log integrity: VERIFIED");
    } else {
        println!("Audit log integrity: FAILED");
        std::process::exit(1);
    }

    Ok(())
}

/// Open a URL in the user's default browser.
///
/// Uses platform-specific commands: `xdg-open` (Linux), `open` (macOS),
/// `cmd /c start` (Windows). Failures are non-fatal.
fn open_url_in_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    let result = std::process::Command::new("xdg-open").arg(url).spawn();
    #[cfg(target_os = "macos")]
    let result = std::process::Command::new("open").arg(url).spawn();
    #[cfg(target_os = "windows")]
    let result = std::process::Command::new("cmd")
        .args(["/c", "start", "", url])
        .spawn();
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    let result: std::io::Result<std::process::Child> = Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "unsupported platform",
    ));

    result.map(|_| ()).context("browser open failed")
}

/// Wait for SIGTERM or SIGINT (Ctrl+C) for graceful shutdown.
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

fn cmd_hash_binary(path: String) -> Result<()> {
    let hash = vellaveto_config::SupplyChainConfig::compute_hash(&path)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("\"{path}\" = \"{hash}\"");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// ETDI Cryptographic Tool Security Commands
// ═══════════════════════════════════════════════════════════════════════════════

fn cmd_generate_key(
    private_key_path: std::path::PathBuf,
    public_key_path: std::path::PathBuf,
) -> Result<()> {
    use vellaveto_mcp::etdi::ToolSigner;

    let signer =
        ToolSigner::generate().map_err(|e| anyhow::anyhow!("Key generation failed: {e}"))?;

    let private_key = signer.private_key_hex();
    let public_key = signer.public_key_hex();
    let fingerprint = signer.fingerprint();

    std::fs::write(&private_key_path, &private_key).context("Failed to write private key")?;
    std::fs::write(&public_key_path, public_key).context("Failed to write public key")?;

    println!("Generated Ed25519 keypair:");
    println!("  Private key: {}", private_key_path.display());
    println!("  Public key:  {}", public_key_path.display());
    println!("  Fingerprint: {fingerprint}");
    println!();
    println!("Add the fingerprint to your config:");
    println!("  [etdi.allowed_signers]");
    println!("  fingerprints = [\"{fingerprint}\"]");

    Ok(())
}

async fn cmd_sign_tool(
    tool: String,
    definition_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
    signer_identity: Option<String>,
    output_path: std::path::PathBuf,
    expires_in_days: Option<u32>,
) -> Result<()> {
    use vellaveto_mcp::etdi::ToolSigner;

    // Read private key
    let key_hex = std::fs::read_to_string(&key_path)
        .with_context(|| format!("Failed to read key file: {}", key_path.display()))?;
    let key_hex = key_hex.trim();

    // Read definition
    let definition_json = std::fs::read_to_string(&definition_path)
        .with_context(|| format!("Failed to read definition: {}", definition_path.display()))?;
    let schema: serde_json::Value = serde_json::from_str(&definition_json)
        .with_context(|| format!("Invalid JSON in definition: {}", definition_path.display()))?;

    // Create signer
    let signer = ToolSigner::from_private_key_hex(key_hex, signer_identity)
        .map_err(|e| anyhow::anyhow!("Invalid private key: {e}"))?;

    // Sign the tool
    let signature = signer.sign_tool(&tool, &schema, expires_in_days);

    // Write signature
    let signature_json = serde_json::to_string_pretty(&signature)?;
    std::fs::write(&output_path, &signature_json)
        .with_context(|| format!("Failed to write signature: {}", output_path.display()))?;

    println!("Signed tool '{tool}'");
    println!("  Signature ID: {}", signature.signature_id);
    println!("  Algorithm:    {}", signature.algorithm);
    println!("  Signed at:    {}", signature.signed_at);
    if let Some(ref exp) = signature.expires_at {
        println!("  Expires at:   {exp}");
    }
    println!("  Output:       {}", output_path.display());

    Ok(())
}

async fn cmd_verify_signature(
    tool: String,
    definition_path: std::path::PathBuf,
    signature_path: std::path::PathBuf,
) -> Result<()> {
    use vellaveto_config::AllowedSignersConfig;
    use vellaveto_mcp::etdi::ToolSignatureVerifier;

    // Read definition
    let definition_json = std::fs::read_to_string(&definition_path)
        .with_context(|| format!("Failed to read definition: {}", definition_path.display()))?;
    let schema: serde_json::Value = serde_json::from_str(&definition_json)
        .with_context(|| format!("Invalid JSON in definition: {}", definition_path.display()))?;

    // Read signature
    let sig_json = std::fs::read_to_string(&signature_path)
        .with_context(|| format!("Failed to read signature: {}", signature_path.display()))?;
    let signature: vellaveto_types::ToolSignature = serde_json::from_str(&sig_json)
        .with_context(|| format!("Invalid signature JSON: {}", signature_path.display()))?;

    // Verify (trust all signers for CLI verification)
    let allowed = AllowedSignersConfig {
        fingerprints: signature.key_fingerprint.clone().into_iter().collect(),
        spiffe_ids: signature.signer_spiffe_id.clone().into_iter().collect(),
    };
    let verifier = ToolSignatureVerifier::new(allowed);
    let result = verifier.verify_tool_signature(&tool, &schema, &signature);

    println!("Verification result for tool '{tool}':");
    println!("  Valid:         {}", result.valid);
    println!("  Signer trusted: {}", result.signer_trusted);
    println!("  Expired:       {}", result.expired);
    println!("  Message:       {}", result.message);

    if result.is_fully_verified() {
        println!();
        println!("VERIFICATION PASSED");
        Ok(())
    } else {
        println!();
        println!("VERIFICATION FAILED");
        anyhow::bail!("Signature verification failed: {}", result.message)
    }
}

async fn cmd_simulate(config: String, actions_path: String, format: String) -> Result<()> {
    // Load policy config
    let policy_config = PolicyConfig::load_file(&config)
        .map_err(|e| anyhow::anyhow!("Failed to load config: {e}"))?;
    let mut policies = policy_config.to_policies();
    PolicyEngine::sort_policies(&mut policies);
    let engine = PolicyEngine::with_policies(false, &policies).map_err(|errors| {
        let msgs: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
        anyhow::anyhow!("Policy compilation errors: {}", msgs.join("; "))
    })?;

    // Read actions JSON file
    let actions_json =
        std::fs::read_to_string(&actions_path).context("Failed to read actions file")?;
    let actions: Vec<Action> =
        serde_json::from_str(&actions_json).context("Invalid JSON in actions file")?;

    if actions.is_empty() {
        anyhow::bail!("Actions file is empty");
    }

    let batch_start = std::time::Instant::now();
    let mut results = Vec::with_capacity(actions.len());
    let mut allowed = 0usize;
    let mut denied = 0usize;
    let mut errors = 0usize;

    for (i, action) in actions.iter().enumerate() {
        match engine.evaluate_action_traced_with_context(action, None) {
            Ok((verdict, trace)) => {
                match &verdict {
                    Verdict::Allow => allowed += 1,
                    Verdict::Deny { .. } => denied += 1,
                    _ => {}
                }
                results.push((i, verdict, Some(trace), None::<String>));
            }
            Err(e) => {
                errors += 1;
                results.push((
                    i,
                    Verdict::Deny {
                        reason: "Evaluation error".to_string(),
                    },
                    None,
                    Some(e.to_string()),
                ));
            }
        }
    }

    let total_us = batch_start.elapsed().as_micros() as u64;

    if format == "json" {
        let json_results: Vec<serde_json::Value> = results
            .iter()
            .map(|(i, verdict, trace, error)| {
                json!({
                    "action_index": i,
                    "verdict": verdict,
                    "trace": trace,
                    "error": error,
                })
            })
            .collect();
        let output = serde_json::to_string_pretty(&json!({
            "results": json_results,
            "summary": {
                "total": actions.len(),
                "allowed": allowed,
                "denied": denied,
                "errors": errors,
                "duration_us": total_us,
            }
        }))?;
        println!("{output}");
    } else {
        // Text format
        for (i, verdict, trace, error) in &results {
            let tool_func = format!("{}:{}", actions[*i].tool, actions[*i].function);
            let (verdict_str, detail) = match verdict {
                Verdict::Allow => ("ALLOW", String::new()),
                Verdict::Deny { reason } => ("DENY ", format!(" ({reason})")),
                Verdict::RequireApproval { reason, .. } => ("APPVL", format!(" ({reason})")),
                _ => ("???  ", String::new()),
            };
            let duration = trace
                .as_ref()
                .map(|t| format!("{}μs", t.duration_us))
                .unwrap_or_default();
            if let Some(err) = error {
                println!("Action {}: {:<30} → ERROR ({})", i + 1, tool_func, err);
            } else {
                println!(
                    "Action {}: {:<30} → {} {}{}",
                    i + 1,
                    tool_func,
                    verdict_str,
                    duration,
                    detail
                );
            }
        }
        println!();
        println!(
            "Summary: {allowed} allowed, {denied} denied, {errors} errors ({total_us}μs total)"
        );
    }

    Ok(())
}

/// Parse a model family string from config into a `ModelFamily` enum.
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

fn extract_tool_pattern(id: &str) -> String {
    if let Some((tool, _)) = id.split_once(':') {
        tool.to_string()
    } else {
        id.to_string()
    }
}

fn extract_function_pattern(id: &str) -> String {
    if let Some((_, func)) = id.split_once(':') {
        func.to_string()
    } else {
        "*".to_string()
    }
}
