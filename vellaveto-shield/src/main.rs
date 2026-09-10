// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Vellaveto Consumer Shield
//!
//! Privacy-preserving proxy that sits between a user and an AI provider's
//! MCP server. Sanitizes PII from outbound queries, desanitizes responses,
//! and maintains an encrypted local audit trail.
//!
//! Usage:
//! ```sh
//! vellaveto-shield --config shield.toml -- /path/to/mcp-server [args...]
//! ```

use anyhow::{Context, Result};
use clap::Parser;
use std::sync::Arc;
use tokio::process::Command;
use vellaveto_audit::AuditLogger;
use vellaveto_config::PolicyConfig;
use vellaveto_engine::PolicyEngine;
use vellaveto_mcp::proxy::ProxyBridge;
use vellaveto_types::command::resolve_executable;

#[derive(Parser)]
#[command(
    name = "vellaveto-shield",
    version,
    about = "Consumer AI shield with bidirectional PII sanitization and encrypted audit"
)]
struct Cli {
    /// Path to the policy configuration file (TOML)
    #[arg(short, long)]
    config: String,

    /// Encryption passphrase for local audit store.
    /// If not provided, checks VELLAVETO_SHIELD_PASSPHRASE env var, then prompts interactively.
    /// Prefer env var to avoid /proc/pid/cmdline exposure.
    #[arg(long)]
    passphrase: Option<String>,

    /// Request timeout in seconds (default: 30)
    #[arg(long, default_value_t = 30)]
    timeout: u64,

    /// Path to a warrant canary JSON file to verify at startup
    #[arg(long)]
    canary: Option<String>,

    /// The MCP server command and arguments (after --)
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    if cli.command.is_empty() {
        anyhow::bail!("No MCP server command specified. Usage: vellaveto-shield --config shield.toml -- /path/to/mcp-server [args...]");
    }

    // Load policies
    let policy_config = PolicyConfig::load_file(&cli.config)
        .map_err(|e| anyhow::anyhow!("Failed to load config '{}': {}", cli.config, e))?;
    let policies = policy_config.to_policies();
    tracing::info!("Loaded {} policies from {}", policies.len(), cli.config);

    // Validate shield config
    if !policy_config.shield.enabled {
        tracing::warn!("Shield is not enabled in config — running as standard proxy");
    }

    // SECURITY (R237-SHLD-1): Prefer env var over CLI arg to avoid /proc/pid/cmdline exposure.
    // Priority: --passphrase CLI > VELLAVETO_SHIELD_PASSPHRASE env > interactive prompt.
    let passphrase = if let Some(p) = cli.passphrase {
        p
    } else if let Ok(p) = std::env::var("VELLAVETO_SHIELD_PASSPHRASE") {
        p
    } else if policy_config.shield.enabled {
        rpassword::prompt_password("Shield audit passphrase: ")
            .context("Failed to read passphrase")?
    } else {
        String::new()
    };

    // Set up audit logging
    let config_dir = std::path::Path::new(&cli.config)
        .parent()
        .unwrap_or(std::path::Path::new("."));
    let audit_path = config_dir.join("shield-audit.log");
    let audit = Arc::new(AuditLogger::new(audit_path.clone()));

    // SECURITY: Fail-closed — refuse to start with broken audit chain.
    audit
        .initialize_chain()
        .await
        .context("Failed to initialize audit chain — refusing to start")?;
    tracing::info!("Audit log: {}", audit_path.display());

    // Set up encrypted audit store (only in local audit mode)
    let mut _audit_manager = None;
    if policy_config.shield.enabled
        && !passphrase.is_empty()
        && policy_config.shield.audit_mode == "local"
    {
        let enc_path = config_dir.join("shield-audit.enc");
        let store = vellaveto_mcp_shield::EncryptedAuditStore::new(enc_path, &passphrase)
            .context("Failed to initialize encrypted audit store")?;
        let manager = vellaveto_mcp_shield::LocalAuditManager::new(audit_path.clone(), store);
        let manager = if policy_config.shield.merkle_proofs {
            manager.with_merkle()
        } else {
            manager
        };
        #[cfg(feature = "zk-audit")]
        let manager = if policy_config.shield.zk_commitments {
            tracing::info!("ZK commitments: ENABLED");
            manager.with_zk_commitments()
        } else {
            manager
        };
        _audit_manager = Some(manager);
        tracing::info!("Encrypted audit store: ENABLED (local mode)");
    } else if policy_config.shield.enabled && policy_config.shield.audit_mode == "remote" {
        tracing::info!("Audit mode: remote — encrypted local store skipped");
    }

    // Set up shield sanitizer
    let shield_sanitizer = if policy_config.shield.enabled && policy_config.shield.sanitize_queries
    {
        let custom_patterns: Vec<vellaveto_audit::CustomPiiPattern> = policy_config
            .shield
            .custom_pii_patterns
            .iter()
            .map(|p| vellaveto_audit::CustomPiiPattern {
                name: p.name.clone(),
                pattern: p.pattern.clone(),
            })
            .collect();
        // Sanitizer profile, not the audit profile: this text is going to a
        // provider, so file paths must be replaced. Audit keeps them.
        let scanner = vellaveto_audit::PiiScanner::new_for_sanitizer(&custom_patterns);
        let sanitizer = Arc::new(vellaveto_mcp_shield::QuerySanitizer::new(scanner));
        tracing::info!("Shield sanitizer: ENABLED");
        Some(sanitizer)
    } else {
        None
    };

    // Optional: Verify warrant canary
    if let Some(canary_path) = &cli.canary {
        let canary_json = std::fs::read_to_string(canary_path)
            .context(format!("Failed to read canary file: {canary_path}"))?;
        let canary: vellaveto_canary::WarrantCanary =
            serde_json::from_str(&canary_json).context("Failed to parse canary JSON")?;
        match vellaveto_canary::verify_canary(&canary) {
            Ok(verification) => {
                if !verification.signature_valid {
                    tracing::error!("Warrant canary signature INVALID");
                    anyhow::bail!("Warrant canary signature verification failed");
                }
                if verification.expired {
                    tracing::warn!(
                        "Warrant canary EXPIRED ({} days ago)",
                        -verification.days_remaining
                    );
                } else {
                    tracing::info!(
                        "Warrant canary valid ({} days remaining)",
                        verification.days_remaining
                    );
                }
            }
            Err(e) => {
                tracing::error!("Warrant canary verification error: {}", e);
                anyhow::bail!("Warrant canary verification failed: {e}");
            }
        }
    }

    // Verify child binary integrity
    let (child_cmd, child_args) = cli
        .command
        .split_first()
        .context("Command list is empty after validation")?;

    let path_env = std::env::var_os("PATH");
    let resolved_child_cmd = resolve_executable(child_cmd, path_env.as_deref())
        .map_err(|e| anyhow::anyhow!("Failed to resolve MCP server command '{child_cmd}': {e}"))?;

    let resolved_child_cmd_display = resolved_child_cmd.display().to_string();

    if let Err(reason) = policy_config
        .supply_chain
        .verify_binary(&resolved_child_cmd.to_string_lossy())
    {
        tracing::error!("Supply chain verification FAILED: {}", reason);
        anyhow::bail!(
            "Refusing to spawn MCP server '{resolved_child_cmd_display}': supply chain verification failed — {reason}"
        );
    } else if policy_config.supply_chain.enabled {
        tracing::info!(
            "Supply chain verification passed for '{}'",
            resolved_child_cmd_display
        );
    }

    // Spawn child MCP server with env_clear (security)
    let mut cmd = Command::new(&resolved_child_cmd);
    cmd.args(child_args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .env_clear();

    for key in &["PATH", "HOME", "USER", "LANG", "TERM", "TMPDIR"] {
        if let Ok(val) = std::env::var(key) {
            cmd.env(key, val);
        }
    }
    cmd.env("TZ", "UTC");

    let mut child = cmd.spawn().context(format!(
        "Failed to spawn child MCP server: {resolved_child_cmd_display}"
    ))?;

    let child_pid_display = child
        .id()
        .map(|pid| pid.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    tracing::info!(
        "Spawned child MCP server (PID {}): {} {:?}",
        child_pid_display,
        resolved_child_cmd_display,
        child_args
    );

    // Startup crash check
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    match child.try_wait() {
        Ok(Some(status)) => {
            anyhow::bail!(
                "Child MCP server exited immediately (PID {child_pid_display}, status: {status}). \
                 Check that '{resolved_child_cmd_display}' is a valid executable."
            );
        }
        Ok(None) => {
            tracing::debug!("Child process {} is running", child_pid_display);
        }
        Err(e) => {
            tracing::warn!("Could not check child process status: {}", e);
        }
    }

    let child_stdin = child.stdin.take().context("Failed to get child stdin")?;
    let child_stdout = child.stdout.take().context("Failed to get child stdout")?;

    // Create proxy bridge
    let mut engine = PolicyEngine::with_policies(false, &policies).map_err(|errors| {
        for e in &errors {
            tracing::error!("Policy validation error: {}", e);
        }
        anyhow::anyhow!("{} policy validation errors", errors.len())
    })?;
    if let Some(max_iter) = policy_config.max_path_decode_iterations {
        engine.set_max_path_decode_iterations(max_iter);
    }

    let timeout = std::time::Duration::from_secs(cli.timeout);
    let mut bridge = ProxyBridge::new(engine, policies, audit).with_timeout(timeout);

    // Wire DLP scanning
    let dlp_config = &policy_config.dlp;
    bridge = bridge
        .with_response_dlp_enabled(dlp_config.enabled)
        .with_response_dlp_blocking(dlp_config.block_on_finding);
    if dlp_config.enabled {
        tracing::info!(
            "DLP scanning: ENABLED (blocking: {})",
            dlp_config.block_on_finding
        );
    }

    // Wire sampling controls
    bridge = bridge
        .with_sampling_config(policy_config.sampling.clone())
        .with_elicitation_config(policy_config.elicitation.clone());

    // Wire shield sanitizer and desanitize flag
    if let Some(sanitizer) = shield_sanitizer {
        bridge = bridge.with_shield_sanitizer(sanitizer);
    }
    bridge = bridge.with_shield_desanitize_responses(policy_config.shield.desanitize_responses);

    // Wire injection scanner from config
    let injection_config = &policy_config.injection;
    if injection_config.enabled {
        bridge = bridge.with_injection_blocking(injection_config.block_on_injection);
        if !injection_config.extra_patterns.is_empty()
            || !injection_config.disabled_patterns.is_empty()
        {
            if let Some(scanner) = vellaveto_mcp::inspection::InjectionScanner::from_config(
                &injection_config.extra_patterns,
                &injection_config.disabled_patterns,
            ) {
                bridge = bridge.with_injection_scanner(scanner);
            }
        }
        tracing::info!(
            "Injection scanning: ENABLED (blocking: {})",
            injection_config.block_on_injection
        );
    } else {
        bridge = bridge.with_injection_disabled(true);
    }

    // Set up stylometric normalizer and wire into bridge
    if policy_config.shield.enabled {
        let level = match policy_config.shield.stylometric_level.as_str() {
            "level1" => vellaveto_mcp_shield::NormalizationLevel::Level1,
            "level2" => vellaveto_mcp_shield::NormalizationLevel::Level2,
            _ => vellaveto_mcp_shield::NormalizationLevel::None,
        };
        if level != vellaveto_mcp_shield::NormalizationLevel::None {
            tracing::info!("Stylometric normalizer: {:?}", level);
            let normalizer = Arc::new(vellaveto_mcp_shield::StylometricNormalizer::new(level));
            bridge = bridge.with_shield_stylometric(normalizer);
        }
    }

    // Set up credential vault + session unlinker and wire into bridge
    if policy_config.shield.enabled
        && policy_config.shield.session_unlinkability
        && !passphrase.is_empty()
    {
        let vault_path = config_dir.join("shield-credentials.enc");
        let vault_store = vellaveto_mcp_shield::EncryptedAuditStore::new(vault_path, &passphrase)
            .context("Failed to initialize credential vault")?;
        let vault = vellaveto_mcp_shield::CredentialVault::new(
            vault_store,
            policy_config.shield.credential_pool_size,
            policy_config.shield.replenish_threshold,
        )
        .context("Failed to load credential vault")?;
        let status = vault.status();
        tracing::info!(
            "Credential vault: {} available, {} total (replenish: {})",
            status.available,
            status.total,
            status.needs_replenishment
        );
        let unlinker = vellaveto_mcp_shield::SessionUnlinker::new(vault);
        let unlinker = Arc::new(tokio::sync::Mutex::new(unlinker));
        bridge = bridge.with_session_unlinker(unlinker.clone());

        // Spawn background credential replenishment task
        let replenish_interval = policy_config.shield.credential_epoch_interval.max(10);
        let replenish_unlinker = unlinker.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(replenish_interval));
            loop {
                interval.tick().await;
                let guard = replenish_unlinker.lock().await;
                let vault = guard.vault();
                if vault.status().needs_replenishment {
                    match vault.replenish() {
                        Ok(added) if added > 0 => {
                            tracing::info!(
                                "Credential vault replenished: {} credentials added",
                                added
                            );
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!("Credential vault replenishment failed: {}", e);
                        }
                    }
                }
            }
        });
        tracing::info!(
            "Credential replenishment task: ENABLED (interval: {}s)",
            replenish_interval
        );
    }

    // Set up context isolation and wire into bridge
    if policy_config.shield.enabled && policy_config.shield.session_isolation {
        let isolator = Arc::new(vellaveto_mcp_shield::ContextIsolator::new());
        tracing::info!("Context isolation: ENABLED");
        bridge = bridge.with_context_isolator(isolator);
    }

    if policy_config.shield.traffic_padding {
        tracing::info!("Traffic padding: ENABLED (HTTP transport only)");
    }

    tracing::info!(
        "Shield ready — timeout: {}s, sanitize: {}, session_isolation: {}, unlinkability: {}",
        cli.timeout,
        policy_config.shield.sanitize_queries,
        policy_config.shield.session_isolation,
        policy_config.shield.session_unlinkability
    );

    // Run the proxy
    let agent_stdin = tokio::io::stdin();
    let agent_stdout = tokio::io::stdout();

    let proxy_result = bridge
        .run(agent_stdin, agent_stdout, child_stdin, child_stdout)
        .await;

    // Clean up
    let _ = child.kill().await;
    let _ = child.wait().await;

    match proxy_result {
        Ok(()) => {
            tracing::info!("Shield shut down cleanly");
            Ok(())
        }
        Err(e) => {
            tracing::error!("Shield error: {}", e);
            Err(anyhow::anyhow!("Shield error: {e}"))
        }
    }
}
