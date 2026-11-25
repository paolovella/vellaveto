// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Governance configuration for Shadow AI Discovery and Least Agency Enforcement (Phase 26).

use serde::{Deserialize, Serialize};
use vellaveto_types::EnforcementMode;

/// Maximum number of approved tools in governance config.
pub const MAX_GOVERNANCE_APPROVED_TOOLS: usize = 1_000;

/// Maximum number of known servers in governance config.
pub const MAX_GOVERNANCE_KNOWN_SERVERS: usize = 200;

/// Maximum auto-revoke window (7 days).
pub const MAX_AUTO_REVOKE_SECS: u64 = 604_800;

/// Maximum number of registered agents in governance config (FIND-R44-017).
pub const MAX_GOVERNANCE_REGISTERED_AGENTS: usize = 10_000;

/// Maximum length for a single tool name string (FIND-R44-047).
pub const MAX_TOOL_NAME_LENGTH: usize = 256;

/// Maximum length for a single server ID string (FIND-R44-047).
pub const MAX_SERVER_ID_LENGTH: usize = 512;

/// Maximum length for a single registered agent ID string (FIND-R44-017).
pub const MAX_AGENT_ID_LENGTH: usize = 256;

/// Maximum discovery window (24 hours) (FIND-R44-048).
pub const MAX_DISCOVERY_WINDOW_SECS: u64 = 86_400;

/// Governance configuration for shadow AI discovery and least agency enforcement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GovernanceConfig {
    /// Enable shadow AI discovery (passive traffic analysis).
    /// Default: false.
    #[serde(default)]
    pub shadow_ai_discovery: bool,

    /// When true, agents not in the registered list are denied (fail-closed).
    /// Only effective when `shadow_ai_discovery` is true.
    /// Default: false (monitor-only).
    #[serde(default)]
    pub require_agent_registration: bool,

    /// When true, tool calls from MCP servers not in `known_servers` are denied (fail-closed).
    /// Only effective when `known_servers` is non-empty.
    /// Default: false (monitor-only).
    ///
    /// SECURITY (SANDWORM-001): Without this, a rogue MCP server injected via
    /// config tampering (e.g. SANDWORM_MODE attack) can register tools and have
    /// them execute through the policy engine. Enable this with a populated
    /// `known_servers` list to enforce a server allowlist.
    #[serde(default)]
    pub require_server_registration: bool,

    /// Time window (seconds) for aggregating discovery observations.
    /// Default: 300 (5 minutes).
    #[serde(default = "default_discovery_window")]
    pub discovery_window_secs: u64,

    /// List of approved tool names. Empty = all tools approved (no filtering).
    #[serde(default)]
    pub approved_tools: Vec<String>,

    /// List of known MCP server IDs. Empty = all servers allowed.
    #[serde(default)]
    pub known_servers: Vec<String>,

    /// List of registered agent IDs (FIND-R44-017).
    /// Agents in this list are considered registered; unregistered agents
    /// are flagged by the shadow AI discovery engine.
    #[serde(default)]
    pub registered_agents: Vec<String>,

    /// Least agency enforcement mode.
    /// - `Monitor` (default): Report unused permissions without revoking.
    /// - `Enforce`: Auto-revoke unused permissions after `auto_revoke_after_secs`.
    #[serde(default)]
    pub least_agency_enforcement: EnforcementMode,

    /// Seconds of inactivity before a permission is eligible for auto-revocation.
    /// Only effective in `Enforce` mode.
    /// Default: 3600 (1 hour).
    #[serde(default = "default_auto_revoke")]
    pub auto_revoke_after_secs: u64,

    /// Emit audit events for least agency reports and auto-revocations.
    /// Default: true.
    #[serde(default = "crate::default_true")]
    pub emit_agency_audit_events: bool,

    /// R227: When true, block tools whose schemas have drifted from their
    /// initially registered versions (schema poisoning → hard block).
    /// Default: false (log-only — relies on schema lineage tracker alerts).
    #[serde(default)]
    pub block_tool_drift: bool,

    // ═══════════════════════════════════════════════════════════════════
    // Denial gates for detections that previously had none.
    //
    // Four scanners in the stdio relay used to scan, log a warning, write an
    // ACIS audit entry and then forward the request regardless: the firewall
    // would detect a tool call carrying a credential outward and let it
    // through. No configuration could change that, because no gate existed.
    //
    // Each defaults to false, so upgrading changes nothing. That is a
    // deliberate choice rather than a fail-closed one: these four had no gate
    // at all before, so defaulting them to blocking would silently start
    // denying traffic that every existing deployment currently allows, on
    // heuristics (rate patterns, jailbreak phrasing) that can false-positive.
    // Compare `injection.block_on_injection` and `dlp.block_on_finding`, which
    // default to TRUE: those have always blocked, so fail-closed is the
    // behaviour-preserving default there and log-only is the
    // behaviour-preserving default here.
    //
    // The shipped proxies log a warning at startup when a detection is enabled
    // but its gate is off, so the gap is visible rather than silent.
    //
    // SCOPE: these gate the stdio relay, the HTTP proxy, WebSocket and gRPC.
    // When this comment was first written they covered stdio alone, because
    // each scanner had exactly one call site in the workspace; the other three
    // transports now run them too, so one setting applies everywhere a tool
    // call is mediated.
    // ═══════════════════════════════════════════════════════════════════
    /// When true, tool calls whose parameters match jailbreak patterns
    /// (MITRE AML.T0054) are denied rather than only audited.
    /// Default: false (log-only).
    #[serde(default)]
    pub block_on_jailbreak: bool,

    /// When true, tool calls whose parameters appear to carry tokens or
    /// credentials are denied rather than only audited.
    /// Default: false (log-only).
    #[serde(default)]
    pub block_on_token_leakage: bool,

    /// When true, tool calls carrying memory-query poisoning indicators
    /// (MINJA) are denied rather than only audited.
    /// Default: false (log-only).
    #[serde(default)]
    pub block_on_memory_poisoning: bool,

    /// When true, tool calls that trip denial-of-wallet detection — rate
    /// spikes, recursive loops, token exhaustion — are denied rather than
    /// only audited. The thresholds themselves are not yet configurable.
    /// Default: false (log-only).
    #[serde(default)]
    pub block_on_denial_of_wallet: bool,
}

fn default_discovery_window() -> u64 {
    300
}

fn default_auto_revoke() -> u64 {
    3600
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        Self {
            shadow_ai_discovery: false,
            require_agent_registration: false,
            require_server_registration: false,
            discovery_window_secs: 300,
            approved_tools: Vec::new(),
            known_servers: Vec::new(),
            registered_agents: Vec::new(),
            least_agency_enforcement: EnforcementMode::Monitor,
            auto_revoke_after_secs: 3600,
            emit_agency_audit_events: true,
            block_tool_drift: false,
            // Log-only by default: see the comment on these fields for why
            // these four differ from block_on_injection / block_on_finding.
            block_on_jailbreak: false,
            block_on_token_leakage: false,
            block_on_memory_poisoning: false,
            block_on_denial_of_wallet: false,
        }
    }
}

impl GovernanceConfig {
    /// Validate governance configuration bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.approved_tools.len() > MAX_GOVERNANCE_APPROVED_TOOLS {
            return Err(format!(
                "governance.approved_tools has {} entries, max is {}",
                self.approved_tools.len(),
                MAX_GOVERNANCE_APPROVED_TOOLS
            ));
        }
        // FIND-R44-047: Per-string length validation on approved_tools
        for (i, tool) in self.approved_tools.iter().enumerate() {
            if tool.len() > MAX_TOOL_NAME_LENGTH {
                return Err(format!(
                    "governance.approved_tools[{}] length {} exceeds max {}",
                    i,
                    tool.len(),
                    MAX_TOOL_NAME_LENGTH
                ));
            }
            // SECURITY (FIND-R51-015, FIND-R63-CFG-005): Reject control and Unicode
            // format characters (zero-width, bidi overrides, BOM) in governance strings.
            if vellaveto_types::has_dangerous_chars(tool) {
                return Err(format!(
                    "governance.approved_tools[{i}] contains control or format characters"
                ));
            }
        }
        if self.known_servers.len() > MAX_GOVERNANCE_KNOWN_SERVERS {
            return Err(format!(
                "governance.known_servers has {} entries, max is {}",
                self.known_servers.len(),
                MAX_GOVERNANCE_KNOWN_SERVERS
            ));
        }
        // FIND-R44-047: Per-string length validation on known_servers
        for (i, server) in self.known_servers.iter().enumerate() {
            if server.len() > MAX_SERVER_ID_LENGTH {
                return Err(format!(
                    "governance.known_servers[{}] length {} exceeds max {}",
                    i,
                    server.len(),
                    MAX_SERVER_ID_LENGTH
                ));
            }
            // SECURITY (FIND-R51-015, FIND-R63-CFG-005): Reject control and format characters.
            if vellaveto_types::has_dangerous_chars(server) {
                return Err(format!(
                    "governance.known_servers[{i}] contains control or format characters"
                ));
            }
        }
        // FIND-R44-017: Validate registered_agents count and per-string length
        if self.registered_agents.len() > MAX_GOVERNANCE_REGISTERED_AGENTS {
            return Err(format!(
                "governance.registered_agents has {} entries, max is {}",
                self.registered_agents.len(),
                MAX_GOVERNANCE_REGISTERED_AGENTS
            ));
        }
        for (i, agent) in self.registered_agents.iter().enumerate() {
            if agent.len() > MAX_AGENT_ID_LENGTH {
                return Err(format!(
                    "governance.registered_agents[{}] length {} exceeds max {}",
                    i,
                    agent.len(),
                    MAX_AGENT_ID_LENGTH
                ));
            }
            // SECURITY (FIND-R51-015, FIND-R63-CFG-005): Reject control and format characters.
            if vellaveto_types::has_dangerous_chars(agent) {
                return Err(format!(
                    "governance.registered_agents[{i}] contains control or format characters"
                ));
            }
        }
        if self.auto_revoke_after_secs == 0 {
            return Err("governance.auto_revoke_after_secs must be > 0".to_string());
        }
        if self.auto_revoke_after_secs > MAX_AUTO_REVOKE_SECS {
            return Err(format!(
                "governance.auto_revoke_after_secs must be <= {}, got {}",
                MAX_AUTO_REVOKE_SECS, self.auto_revoke_after_secs
            ));
        }
        if self.discovery_window_secs == 0 {
            return Err("governance.discovery_window_secs must be > 0".to_string());
        }
        // FIND-R44-048: Upper bound on discovery_window_secs
        if self.discovery_window_secs > MAX_DISCOVERY_WINDOW_SECS {
            return Err(format!(
                "governance.discovery_window_secs must be <= {} (24 hours), got {}",
                MAX_DISCOVERY_WINDOW_SECS, self.discovery_window_secs
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod denial_gate_tests {
    use super::GovernanceConfig;

    #[test]
    fn four_new_denial_gates_default_to_log_only() {
        // These four detections had no gate at all before, so "off" is the
        // behaviour-preserving default. Contrast injection.block_on_injection
        // and dlp.block_on_finding, which default to true because those paths
        // have always blocked.
        let g = GovernanceConfig::default();
        assert!(!g.block_on_jailbreak);
        assert!(!g.block_on_token_leakage);
        assert!(!g.block_on_memory_poisoning);
        assert!(!g.block_on_denial_of_wallet);
    }

    #[test]
    fn denial_gates_round_trip_through_toml() {
        // deny_unknown_fields is set on this struct, so a typo in a field name
        // is a hard error rather than a silently ignored setting -- which for
        // a security gate is the difference between "enabled" and "thought it
        // was enabled".
        let toml = r#"
block_on_jailbreak = true
block_on_token_leakage = true
block_on_memory_poisoning = true
block_on_denial_of_wallet = true
"#;
        let g: GovernanceConfig = toml::from_str(toml).expect("valid config");
        assert!(g.block_on_jailbreak);
        assert!(g.block_on_token_leakage);
        assert!(g.block_on_memory_poisoning);
        assert!(g.block_on_denial_of_wallet);
        // Untouched fields keep their defaults.
        assert!(!g.block_tool_drift);
    }

    #[test]
    fn misspelled_denial_gate_is_rejected() {
        let toml = "block_on_jailbrake = true\n";
        assert!(
            toml::from_str::<GovernanceConfig>(toml).is_err(),
            "deny_unknown_fields must reject a misspelled gate rather than ignore it"
        );
    }
}
