// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Vellaveto MCP Stdio Proxy
//!
//! Transparent proxy that sits between an agent and an MCP server,
//! intercepting `tools/call` requests and evaluating them against policies.
//!
//! Usage:
//! ```sh
//! vellaveto-proxy --config policy.toml -- /path/to/mcp-server [args...]
//! ```

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
#[cfg(test)]
use std::path::PathBuf;
use std::sync::Arc;
use tokio::process::Command;
use vellaveto_audit::AuditLogger;
use vellaveto_config::PolicyConfig;
use vellaveto_engine::PolicyEngine;
use vellaveto_mcp::proxy::ProxyBridge;
use vellaveto_types::command::resolve_executable;

mod notification_writer;
mod presets;

#[derive(Parser)]
#[command(
    name = "vellaveto-proxy",
    version,
    about = "MCP stdio proxy with policy enforcement",
    after_help = "\
Examples:
  # Instant protection (pick a level):
  vellaveto-proxy --protect shield -- npx @modelcontextprotocol/server-filesystem /tmp
  vellaveto-proxy --protect fortress -- python -m mcp_server
  vellaveto-proxy --protect vault -- ./my-server

  # Run with built-in defaults (no config needed):
  vellaveto-proxy -- npx @modelcontextprotocol/server-filesystem /tmp

  # Run with a named preset:
  vellaveto-proxy --preset dev-laptop -- python -m mcp_server

  # Run with an explicit config file:
  vellaveto-proxy --config policy.toml -- ./my-server

  # Generate a starter config file:
  vellaveto-proxy init
  vellaveto-proxy init --preset ci-agent

  # List available presets:
  vellaveto-proxy --list-presets"
)]
struct Cli {
    /// Path to the policy configuration file (TOML).
    /// If omitted, uses --protect, --preset, or built-in defaults.
    #[arg(short, long)]
    config: Option<String>,

    /// Use a built-in policy preset (e.g., dev-laptop, ci-agent, sandworm-hardened).
    /// Mutually exclusive with --config and --protect.
    #[arg(long)]
    preset: Option<String>,

    /// Easy protection level: shield, fortress, or vault.
    /// Shield: 8 policies — credentials, SANDWORM defense, exfil, system files.
    /// Fortress: 11 policies — shield + package configs, sudo approval, memory tracking.
    /// Vault: 11 policies — deny-by-default, reads allowed, writes need approval.
    /// Mutually exclusive with --config and --preset.
    #[arg(long)]
    protect: Option<String>,

    /// List available presets and exit
    #[arg(long)]
    list_presets: bool,

    /// Enable strict mode for policy evaluation
    #[arg(long, default_value_t = false)]
    strict: bool,

    /// Request timeout in seconds (default: 30). Requests forwarded to the child
    /// server that don't receive a response within this time will be timed out.
    #[arg(long, default_value_t = 30)]
    timeout: u64,

    /// Enable evaluation trace logging. Traces include per-policy evaluation
    /// details and are emitted at DEBUG level.
    #[arg(long, default_value_t = false)]
    trace: bool,

    /// Write lightweight notification events to a JSONL file for desktop app
    /// integration. Each line is a JSON object with ts, tool, action, verdict,
    /// reason, and severity fields.
    #[arg(long)]
    notification_file: Option<String>,

    #[command(subcommand)]
    subcommand: Option<Commands>,

    /// The MCP server command and arguments (after --)
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a starter config file in the current directory
    Init {
        /// Preset to use as the starting template (default: shield)
        #[arg(long, default_value = "shield")]
        preset: String,

        /// Output file path (default: vellaveto.toml)
        #[arg(short, long, default_value = "vellaveto.toml")]
        output: String,
    },
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

    // Handle --list-presets
    if cli.list_presets {
        println!("Protection levels (easy mode):\n");
        for (name, desc) in presets::list_protection_levels() {
            println!("  {name:<25} {desc}");
        }
        println!("\n  Usage: vellaveto-proxy --protect <LEVEL> -- <COMMAND>\n");
        println!("Professional presets:\n");
        for (name, desc) in presets::list_presets() {
            if !presets::is_protection_level(name) {
                println!("  {name:<25} {desc}");
            }
        }
        println!("\n  Usage: vellaveto-proxy --preset <NAME> -- <COMMAND>");
        return Ok(());
    }

    // Handle `init` subcommand
    if let Some(Commands::Init { preset, output }) = &cli.subcommand {
        let toml_content = presets::preset_toml(preset).ok_or_else(|| {
            let available: Vec<&str> = presets::list_presets().iter().map(|(n, _)| *n).collect();
            anyhow::anyhow!(
                "Unknown preset '{}'. Available: {}",
                preset,
                available.join(", ")
            )
        })?;
        let path = std::path::Path::new(output.as_str());
        if path.exists() {
            anyhow::bail!(
                "'{output}' already exists. Remove it first or use -o to specify a different path."
            );
        }
        std::fs::write(path, toml_content)
            .with_context(|| format!("Failed to write '{output}'"))?;
        println!("Created {output} (preset: {preset})");
        println!("\nRun with:");
        println!("  vellaveto-proxy --config {output} -- <COMMAND>");
        return Ok(());
    }

    if cli.command.is_empty() {
        anyhow::bail!(
            "No MCP server command specified.\n\n\
             Usage: vellaveto-proxy [OPTIONS] -- <COMMAND>\n\n\
             Examples:\n  \
             vellaveto-proxy --protect shield -- npx @modelcontextprotocol/server-filesystem /tmp\n  \
             vellaveto-proxy --preset dev-laptop -- python -m mcp_server\n  \
             vellaveto-proxy --config policy.toml -- ./my-server\n\n\
             Run 'vellaveto-proxy --help' for more options."
        );
    }

    // Validate --config, --preset, and --protect are mutually exclusive
    let specified_count = [
        cli.config.is_some(),
        cli.preset.is_some(),
        cli.protect.is_some(),
    ]
    .iter()
    .filter(|&&v| v)
    .count();
    if specified_count > 1 {
        anyhow::bail!(
            "Cannot specify more than one of --config, --preset, and --protect. Use one only."
        );
    }

    // Validate --protect value
    if let Some(ref level) = cli.protect {
        if !presets::is_protection_level(level) {
            let levels: Vec<&str> = presets::list_protection_levels()
                .iter()
                .map(|(n, _)| *n)
                .collect();
            anyhow::bail!(
                "Unknown protection level '{}'. Available levels: {}\n\n\
                 Usage: vellaveto-proxy --protect <LEVEL> -- <COMMAND>",
                level,
                levels.join(", ")
            );
        }
    }

    // Load policies: --config > --preset > --protect > built-in default
    let (policy_config, config_source) = if let Some(ref config_path) = cli.config {
        let pc = PolicyConfig::load_file(config_path)
            .map_err(|e| anyhow::anyhow!("Failed to load config '{config_path}': {e}"))?;
        (pc, format!("file: {config_path}"))
    } else if let Some(ref preset_name) = cli.preset {
        let pc = presets::load_preset(preset_name).map_err(|e| anyhow::anyhow!("{e}"))?;
        (pc, format!("preset: {preset_name}"))
    } else if let Some(ref level) = cli.protect {
        let pc = presets::load_preset(level).map_err(|e| anyhow::anyhow!("{e}"))?;
        (pc, format!("protect: {level}"))
    } else {
        let pc = presets::default_config().map_err(|e| anyhow::anyhow!("{e}"))?;
        (pc, "built-in default".to_string())
    };

    let policies = policy_config.to_policies();
    tracing::info!("Loaded {} policies ({})", policies.len(), config_source);

    // Set up audit logging
    let audit_path = if let Some(ref config_path) = cli.config {
        let config_dir = std::path::Path::new(config_path)
            .parent()
            .unwrap_or(std::path::Path::new("."));
        config_dir.join("proxy-audit.log")
    } else {
        std::path::Path::new("./proxy-audit.log").to_path_buf()
    };
    let audit = Arc::new(AuditLogger::new(audit_path.clone()));

    // SECURITY (R230-PROXY-1): Fail-closed — refuse to start with broken audit chain.
    audit.initialize_chain().await.context(
        "Failed to initialize audit chain — refusing to start with potentially tampered audit log",
    )?;
    tracing::info!("Audit log: {}", audit_path.display());

    // Verify child binary integrity before spawn (supply chain protection)
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

    // Spawn child MCP server
    // SECURITY (FIND-GAP-011): Clear the environment of the child process to
    // prevent accidental leakage of secrets (e.g., API keys, tokens) from the
    // proxy's environment into the child. Only forward minimal required variables.
    let mut cmd = Command::new(&resolved_child_cmd);
    cmd.args(child_args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .env_clear();

    // Forward only required environment variables.
    // SECURITY (FIND-GAP-011): Only forward variables needed for child process
    // execution. Secrets (API keys, tokens) are NOT forwarded.
    //
    // Base: OS-level variables needed for any child process.
    // Runtime: Node.js/Python/Ruby env vars needed by most MCP servers.
    // Without these, `npx`-based MCP servers fail to resolve packages.
    let forward_vars: &[&str] = &[
        // Base OS
        "PATH",
        "HOME",
        "USER",
        "LANG",
        "TERM",
        "TMPDIR",
        "SHELL",
        // Node.js / npm / nvm / fnm — required for npx-based MCP servers
        "NODE_PATH",
        "NODE_ENV",
        "NVM_DIR",
        "NVM_BIN",
        "FNM_DIR",
        "NPM_CONFIG_PREFIX",
        "NPM_CONFIG_CACHE",
        "COREPACK_HOME",
        // Python — required for `python -m` MCP servers
        "PYTHONPATH",
        "VIRTUAL_ENV",
        "CONDA_PREFIX",
        "CONDA_DEFAULT_ENV",
        // XDG directories — package managers use these for cache/config
        "XDG_DATA_HOME",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_RUNTIME_DIR",
        // Locale
        "LC_ALL",
        "LC_CTYPE",
    ];
    for key in forward_vars {
        if let Ok(val) = std::env::var(key) {
            cmd.env(key, val);
        }
    }
    // SECURITY (R231-PROXY-1): Force UTC timezone for child process to ensure
    // consistent timestamp behavior regardless of parent's TZ setting.
    cmd.env("TZ", "UTC");

    let mut child = cmd.spawn().context(format!(
        "Failed to spawn child MCP server: {resolved_child_cmd_display}"
    ))?;

    // FIND-R56-PROXY-002: Use descriptive string instead of PID 0 when child.id()
    // returns None (possible on some platforms before the child has started).
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

    // Fix #25: Brief startup check — detect immediate crashes (bad binary, missing
    // deps, wrong architecture) before entering the proxy loop.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    match child.try_wait() {
        Ok(Some(status)) => {
            anyhow::bail!(
                "Child MCP server exited immediately (PID {child_pid_display}, status: {status}). \
                 Check that '{resolved_child_cmd_display}' is a valid executable."
            );
        }
        Ok(None) => {
            // Still running — good
            tracing::debug!("Child process {} is running", child_pid_display);
        }
        Err(e) => {
            tracing::warn!("Could not check child process status: {}", e);
        }
    }

    let child_stdin = child.stdin.take().context("Failed to get child stdin")?;
    let child_stdout = child.stdout.take().context("Failed to get child stdout")?;

    // Create proxy bridge with pre-compiled policies and configurable timeout
    let mut engine = PolicyEngine::with_policies(cli.strict, &policies).map_err(|errors| {
        for e in &errors {
            tracing::error!("Policy validation error: {}", e);
        }
        anyhow::anyhow!("{} policy validation errors", errors.len())
    })?;
    if let Some(max_iter) = policy_config.max_path_decode_iterations {
        engine.set_max_path_decode_iterations(max_iter);
        tracing::info!(
            max_path_decode_iterations = max_iter,
            "custom path decode iteration limit"
        );
    }
    let timeout = std::time::Duration::from_secs(cli.timeout);
    let mut bridge = ProxyBridge::new(engine, policies, audit)
        .with_timeout(timeout)
        .with_trace(cli.trace)
        // SECURITY (R271-MCP-1): honour audit.strict_mode over stdio, as the
        // HTTP transports already do. First read of policy_config.audit here.
        .with_audit_strict_mode(policy_config.audit.strict_mode);
    bridge = bridge.with_mediation_config(vellaveto_mcp::mediation::MediationConfig {
        dlp_enabled: false,
        dlp_blocking: false,
        injection_enabled: false,
        injection_blocking: false,
        include_timing: policy_config.acis.include_timing,
        include_findings: policy_config.acis.include_findings,
        require_session_id: policy_config.acis.require_session_id,
        require_agent_identity: policy_config.acis.require_agent_identity,
        require_verified_signature: policy_config.acis.require_verified_signature,
        require_workload_binding: policy_config.acis.require_workload_binding,
        require_ephemeral_client_provenance: policy_config.acis.require_ephemeral_client_provenance,
        deny_replay: policy_config.acis.deny_replay,
        block_tainted_privileged_sinks: policy_config.acis.block_tainted_privileged_sinks,
        require_lineage_for_privileged_sinks: policy_config
            .acis
            .require_lineage_for_privileged_sinks,
        containment_mode: policy_config.acis.containment_mode,
    });

    // Build injection scanner from config (supports extra/disabled patterns)
    let injection_config = &policy_config.injection;
    if injection_config.enabled {
        if !injection_config.extra_patterns.is_empty()
            || !injection_config.disabled_patterns.is_empty()
        {
            if let Some(scanner) = vellaveto_mcp::inspection::InjectionScanner::from_config(
                &injection_config.extra_patterns,
                &injection_config.disabled_patterns,
            ) {
                tracing::info!(
                    "Injection scanner: {} active patterns ({} extra, {} disabled)",
                    scanner.patterns().len(),
                    injection_config.extra_patterns.len(),
                    injection_config.disabled_patterns.len(),
                );
                bridge = bridge.with_injection_scanner(scanner);
            }
        } else {
            tracing::info!("Injection scanner: default patterns");
        }
    } else {
        tracing::info!("Injection scanner: DISABLED by configuration");
        bridge = bridge.with_injection_disabled(true);
    }

    // Phase 71 (R233-DLP-1): Wire cross-call DLP tracker when DLP is enabled.
    if injection_config.enabled {
        bridge = bridge.with_cross_call_dlp(true);
        tracing::info!("Cross-call DLP: ENABLED");
    }

    // TI-2026-001 (R233-MCPSEC-2): Wire sharded exfiltration detection when DLP is enabled.
    if injection_config.enabled {
        bridge = bridge.with_sharded_exfil(true);
        tracing::info!("Sharded exfiltration detection: ENABLED");
    }

    // SECURITY (FIND-R78-001): MCP 2025-11-25 tool name validation parity with HTTP proxy.
    if policy_config.streamable_http.strict_tool_name_validation {
        bridge = bridge.with_strict_tool_name_validation(true);
        tracing::info!("MCP tool name validation: ENABLED (strict)");
    }

    // SECURITY (GAP-R60-016): Wire ABAC engine for attribute-based access control.
    // Without this, ABAC forbid-override policies are completely inactive in stdio mode,
    // allowing actions that should be denied by ABAC rules.
    if policy_config.abac.enabled {
        match vellaveto_engine::abac::AbacEngine::new(
            &policy_config.abac.policies,
            &policy_config.abac.entities,
        ) {
            Ok(abac_engine) => {
                tracing::info!(
                    "ABAC engine: {} policies, {} entities",
                    policy_config.abac.policies.len(),
                    policy_config.abac.entities.len()
                );
                bridge = bridge.with_abac_engine(Arc::new(abac_engine));
            }
            Err(e) => {
                // Fail-closed: invalid ABAC config prevents startup
                anyhow::bail!("ABAC config error: {e}");
            }
        }
    }

    // SECURITY (GAP-R60-017): Wire circuit breaker for cascading failure prevention (ASI08).
    if policy_config.circuit_breaker.enabled {
        let cb = vellaveto_engine::circuit_breaker::CircuitBreakerManager::with_config(
            policy_config.circuit_breaker.failure_threshold,
            policy_config.circuit_breaker.success_threshold,
            policy_config.circuit_breaker.open_duration_secs,
            policy_config.circuit_breaker.half_open_max_requests,
        );
        tracing::info!("Circuit breaker: ENABLED");
        bridge = bridge.with_circuit_breaker(Arc::new(cb));
    }

    // SECURITY (GAP-R60-017): Wire deputy validator for confused deputy prevention (ASI02).
    if policy_config.deputy.enabled {
        let deputy = vellaveto_engine::deputy::DeputyValidator::new(
            policy_config.deputy.max_delegation_depth,
        );
        tracing::info!(
            "Deputy validator: ENABLED (max depth: {})",
            policy_config.deputy.max_delegation_depth
        );
        bridge = bridge.with_deputy(Arc::new(deputy));
    }

    // SECURITY (GAP-R60-017): Wire schema lineage tracker for schema poisoning detection (ASI05).
    if policy_config.schema_poisoning.enabled {
        let tracker = vellaveto_mcp::schema_poisoning::SchemaLineageTracker::new(
            policy_config.schema_poisoning.mutation_threshold,
            policy_config.schema_poisoning.min_observations,
            policy_config.schema_poisoning.max_tracked_schemas,
        );
        tracing::info!("Schema lineage tracker: ENABLED");
        bridge = bridge.with_schema_lineage(Arc::new(tracker));
    }

    // SECURITY (GAP-R60-017): Wire shadow agent detector for rogue agent detection (ASI10).
    if policy_config.shadow_agent.enabled {
        let detector = vellaveto_mcp::shadow_agent::ShadowAgentDetector::new(
            policy_config.shadow_agent.max_known_agents,
        );
        tracing::info!(
            "Shadow agent detector: ENABLED (max known: {})",
            policy_config.shadow_agent.max_known_agents
        );
        bridge = bridge.with_shadow_agent(Arc::new(detector));
    }

    // Wire sampling detector for rate-limit/content/model enforcement.
    if policy_config.sampling_detection.enabled {
        let detector = vellaveto_mcp::sampling_detector::SamplingDetector::with_config(
            policy_config.sampling_detection.max_requests_per_window,
            policy_config.sampling_detection.window_secs,
            policy_config.sampling_detection.max_prompt_length,
            policy_config.sampling_detection.allowed_models.clone(),
            policy_config.sampling_detection.block_sensitive_patterns,
        );
        tracing::info!("Sampling detector: ENABLED");
        bridge = bridge.with_sampling_detector(Arc::new(detector));
    }

    // Wire topology guard into ProxyBridge for live topology updates from tools/list.
    #[cfg(feature = "discovery")]
    if policy_config.topology.enabled {
        let guard = Arc::new(vellaveto_discovery::guard::TopologyGuard::new());
        bridge = bridge.with_topology_guard(Arc::clone(&guard));
        tracing::info!("Topology guard: ENABLED (stdio proxy)");
    }

    // Phase 9: Wire MINJA memory security manager for taint tracking.
    if policy_config.memory_security.enabled {
        let manager = vellaveto_mcp::memory_security::MemorySecurityManager::new(
            policy_config.memory_security.clone(),
        );
        bridge = bridge.with_memory_security(Arc::new(manager));
        tracing::info!("Memory security (MINJA): ENABLED");
    }

    // Phase 8: Wire ETDI for cryptographic tool verification.
    if policy_config.etdi.enabled {
        let data_path = policy_config
            .etdi
            .data_path
            .as_deref()
            .unwrap_or("etdi_data");
        let store = Arc::new(vellaveto_mcp::etdi::EtdiStore::new(data_path));
        if let Err(e) = store.load().await {
            tracing::warn!("Failed to load ETDI store: {} — starting fresh", e);
        }
        let verifier = Arc::new(vellaveto_mcp::etdi::ToolSignatureVerifier::new(
            policy_config.etdi.allowed_signers.clone(),
        ));
        bridge = bridge.with_etdi_verifier(verifier);
        bridge = bridge.with_etdi_require_signatures(policy_config.etdi.require_signatures);
        tracing::info!(
            "ETDI signature verification: ENABLED (require_signatures={})",
            policy_config.etdi.require_signatures,
        );
        if policy_config.etdi.version_pinning.enabled {
            let blocking = policy_config.etdi.version_pinning.is_blocking();
            let pin_manager = Arc::new(vellaveto_mcp::etdi::VersionPinManager::new(
                Arc::clone(&store),
                blocking,
            ));
            bridge = bridge.with_etdi_version_pins(pin_manager);
            tracing::info!(
                "ETDI version pinning: ENABLED (enforcement={})",
                policy_config.etdi.version_pinning.enforcement,
            );
        }
        if policy_config.etdi.attestation.enabled {
            let attestation_chain = Arc::new(vellaveto_mcp::etdi::AttestationChain::new(
                Arc::clone(&store),
            ));
            bridge = bridge.with_etdi_attestations(attestation_chain);
            tracing::info!("ETDI attestation chain: ENABLED");
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Dead code activation: wire all config-to-bridge gaps
    // ═══════════════════════════════════════════════════════════════════

    // Wire injection blocking from config.
    if injection_config.block_on_injection {
        bridge = bridge.with_injection_blocking(true);
        tracing::info!("Injection blocking: ENABLED");
    }

    // Wire DLP response scanning from config.
    if policy_config.dlp.enabled {
        bridge = bridge.with_response_dlp_enabled(true);
        if policy_config.dlp.block_on_finding {
            bridge = bridge.with_response_dlp_blocking(true);
            tracing::info!("DLP response scanning: BLOCKING");
        } else {
            tracing::info!("DLP response scanning: MONITOR");
        }
    }

    // Wire elicitation config.
    bridge = bridge.with_elicitation_config(policy_config.elicitation.clone());
    if policy_config.elicitation.enabled {
        tracing::info!("Elicitation controls: ENABLED");
    }

    // Wire sampling config.
    bridge = bridge.with_sampling_config(policy_config.sampling.clone());
    if policy_config.sampling.enabled {
        tracing::info!("Sampling controls: ENABLED");
    }

    // Wire manifest verification for rug-pull detection.
    if policy_config.manifest.enabled {
        bridge = bridge.with_manifest_config(policy_config.manifest.clone());
        tracing::info!("Manifest verification (rug-pull detection): ENABLED");
    }

    // Wire known tool names for squatting detection.
    if !policy_config.known_tool_names.is_empty() {
        tracing::info!(
            "Custom known tools: {} entries",
            policy_config.known_tool_names.len()
        );
        bridge = bridge.with_known_tools(vellaveto_mcp::rug_pull::build_known_tools(
            &policy_config.known_tool_names,
        ));
    }

    // Wire tool quotas for per-tool rate limiting (Phase 2).
    if !policy_config.tool_quotas.is_empty() {
        let tracker =
            vellaveto_mcp::tool_quota::ToolQuotaTracker::new(policy_config.tool_quotas.clone());
        tracing::info!("Tool quotas: {} rules", policy_config.tool_quotas.len());
        bridge = bridge.with_tool_quota_tracker(tracker);
    }

    // Wire secret substitution for outbound/inbound secret masking (Phase 2).
    {
        let sub_count = policy_config.secret_substitutions.len();
        if sub_count > 0 {
            let engine = vellaveto_mcp::secret_substitution::SecretSubstitutionEngine::new(
                &policy_config.secret_substitutions,
            );
            tracing::info!("Secret substitution: {sub_count} rules");
            bridge = bridge.with_secret_substitution(engine);
        }
    }

    // Wire EU AI Act transparency marking (Phase 19).
    if policy_config.compliance.eu_ai_act.transparency_marking {
        bridge = bridge.with_transparency_marking(true);
        tracing::info!("EU AI Act Art 50 transparency marking: ENABLED");
    }
    if !policy_config
        .compliance
        .eu_ai_act
        .human_oversight_tools
        .is_empty()
    {
        bridge = bridge.with_human_oversight_tools(
            policy_config
                .compliance
                .eu_ai_act
                .human_oversight_tools
                .clone(),
        );
    }

    // Wire tool drift blocking (R227).
    if policy_config.governance.block_tool_drift {
        bridge = bridge.with_block_tool_drift(true);
        tracing::info!("Tool drift blocking: ENABLED");
    }

    // Phase 6: Wire channel separation configs.
    if !policy_config.source_trust.untrusted_tools.is_empty()
        || !policy_config.source_trust.verified_tools.is_empty()
        || !policy_config.source_trust.server_trust.is_empty()
    {
        tracing::info!(
            "Source trust: {} untrusted, {} verified tool patterns",
            policy_config.source_trust.untrusted_tools.len(),
            policy_config.source_trust.verified_tools.len(),
        );
        bridge = bridge.with_source_trust_config(policy_config.source_trust.clone());
    }
    if !policy_config.sink_classification.rules.is_empty() {
        tracing::info!(
            "Sink classification: {} rules",
            policy_config.sink_classification.rules.len()
        );
        bridge = bridge.with_sink_classification_config(policy_config.sink_classification.clone());
    }
    if let Some(ref scope) = policy_config.intent_scope {
        tracing::info!(
            "Intent scope: {} allowed, {} denied tool patterns, action={:?}",
            scope.allowed_tools.len(),
            scope.denied_tools.len(),
            scope.out_of_scope_action,
        );
        bridge = bridge.with_intent_scope_config(scope.clone());
    }

    // Wire content-bound attestation HMAC key from env var.
    // SECURITY (R259-ATT-1): with_attestation_key() enforces >= 32 bytes.
    if let Ok(secret) = std::env::var("VELLAVETO_ATTESTATION_SECRET") {
        if !secret.is_empty() {
            bridge = bridge.with_attestation_key(secret.into_bytes());
            tracing::info!("Content-bound attestation: ENABLED");
        }
    }

    // Wire notification writer for desktop app integration (--notification-file).
    if let Some(ref nf_path) = cli.notification_file {
        let writer = Arc::new(
            notification_writer::NotificationWriter::new(std::path::PathBuf::from(nf_path))
                .map_err(|e| anyhow::anyhow!("{e}"))?,
        );
        tracing::info!("Notification file: {}", writer.path().display());
        let w = Arc::clone(&writer);
        bridge =
            bridge.with_verdict_notify(Arc::new(
                move |tool, method, verdict, reason| match verdict {
                    "deny" | "require_approval" => {
                        w.write_deny(tool, method, "", reason, "");
                    }
                    _ => {
                        w.write_allow(tool, method, "");
                    }
                },
            ));
    }
    tracing::info!("Request timeout: {}s, trace: {}", cli.timeout, cli.trace);

    // Run the proxy
    let agent_stdin = tokio::io::stdin();
    let agent_stdout = tokio::io::stdout();

    let proxy_result = bridge
        .run(agent_stdin, agent_stdout, child_stdin, child_stdout)
        .await;

    // Clean up child process — kill and then reap to prevent zombies
    let _ = child.kill().await;
    let _ = child.wait().await;

    match proxy_result {
        Ok(()) => {
            tracing::info!("Proxy shut down cleanly");
            Ok(())
        }
        Err(e) => {
            tracing::error!("Proxy error: {}", e);
            Err(anyhow::anyhow!("Proxy error: {e}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::OsString;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        let nanos = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_nanos(),
            Err(_) => 0,
        };
        dir.push(format!("{}_{}_{}", prefix, std::process::id(), nanos));
        dir
    }

    #[test]
    fn resolve_child_command_keeps_explicit_relative_path() {
        let temp_dir = unique_temp_dir("relative-path");
        std::fs::create_dir_all(&temp_dir).unwrap();

        let candidate = temp_dir.join("mock-server");
        std::fs::write(&candidate, b"#!/bin/sh\necho ok\n").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut perms = std::fs::metadata(&candidate)
                .unwrap_or_else(|e| panic!("metadata failed: {e}"))
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&candidate, perms)
                .unwrap_or_else(|e| panic!("set executable bit failed: {e}"));
        }

        let relative = "./mock-server";
        let original_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&temp_dir).unwrap();
        let resolved = resolve_executable(relative, None)
            .unwrap_or_else(|e| panic!("relative path should not require PATH: {e}"));
        std::env::set_current_dir(original_cwd).unwrap();

        assert_eq!(resolved, candidate);

        let _ = std::fs::remove_file(&candidate);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn resolve_child_command_resolves_bare_name_from_path() {
        let temp_dir = unique_temp_dir("vellaveto_proxy_path_resolve");
        std::fs::create_dir_all(&temp_dir)
            .unwrap_or_else(|e| panic!("create temp dir failed: {e}"));

        let candidate = temp_dir.join("mock-mcp-server");
        std::fs::write(&candidate, b"#!/bin/sh\necho ok\n")
            .unwrap_or_else(|e| panic!("write candidate command failed: {e}"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut perms = std::fs::metadata(&candidate)
                .unwrap_or_else(|e| panic!("metadata failed: {e}"))
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&candidate, perms)
                .unwrap_or_else(|e| panic!("set executable bit failed: {e}"));
        }

        let path_env = std::env::join_paths([temp_dir.clone()])
            .unwrap_or_else(|e| panic!("join_paths failed: {e}"));
        let resolved = resolve_executable("mock-mcp-server", Some(path_env.as_os_str()))
            .unwrap_or_else(|e| panic!("expected command to resolve from PATH: {e}"));

        assert_eq!(resolved, candidate);

        let _ = std::fs::remove_file(&candidate);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn resolve_child_command_rejects_missing_bare_name() {
        let temp_dir = unique_temp_dir("vellaveto_proxy_path_missing");
        std::fs::create_dir_all(&temp_dir)
            .unwrap_or_else(|e| panic!("create temp dir failed: {e}"));

        let path_env: OsString = std::env::join_paths([temp_dir.clone()])
            .unwrap_or_else(|e| panic!("join_paths failed: {e}"));
        let err = resolve_executable("definitely-not-present", Some(path_env.as_os_str()))
            .expect_err("missing command should fail");

        assert!(
            err.to_string().contains("not found in PATH"),
            "unexpected error: {err}"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn resolve_child_command_rejects_non_executable_candidate_on_unix() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let temp_dir = unique_temp_dir("vellaveto_proxy_path_nonexec");
            std::fs::create_dir_all(&temp_dir)
                .unwrap_or_else(|e| panic!("create temp dir failed: {e}"));

            let candidate = temp_dir.join("mock-mcp-server");
            std::fs::write(&candidate, b"not executable")
                .unwrap_or_else(|e| panic!("write candidate command failed: {e}"));

            let mut perms = std::fs::metadata(&candidate)
                .unwrap_or_else(|e| panic!("metadata failed: {e}"))
                .permissions();
            perms.set_mode(0o644);
            std::fs::set_permissions(&candidate, perms)
                .unwrap_or_else(|e| panic!("set permissions failed: {e}"));

            let path_env = std::env::join_paths([temp_dir.clone()])
                .unwrap_or_else(|e| panic!("join_paths failed: {e}"));

            let err = resolve_executable("mock-mcp-server", Some(path_env.as_os_str()))
                .expect_err("non-executable command should not resolve");
            assert!(
                err.to_string().contains("not found in PATH"),
                "unexpected error: {err}"
            );

            let _ = std::fs::remove_file(&candidate);
            let _ = std::fs::remove_dir_all(&temp_dir);
        }
    }
}
