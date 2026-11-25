// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Built-in policy presets for zero-config usage.
//!
//! Embeds preset TOML configs from `vellaveto-proxy/presets/` at compile time
//!
//! NOTE: this directory, not `examples/presets/`. The two are separate copies
//! with no sync check. This comment used to name `examples/presets/`, and that
//! is plausibly how issue #407 came to be fixed in the copy nobody loads while
//! `--preset devops-agent` stayed broken: a reader follows the comment, edits
//! `examples/`, and believes they changed what ships. Both directories are now
//! compile-checked by
//! `vellaveto-integration/tests/shipped_presets_compile.rs`.
//! so users can run `vellaveto-proxy --preset dev-laptop` without a config file.
//!
//! Protection levels (`shield`, `fortress`, `vault`) are beginner-friendly
//! presets accessible via `--protect <LEVEL>`. They are also available as
//! regular presets via `--preset`.

use vellaveto_config::PolicyConfig;

/// Protection level definitions: (name, description).
/// These are the beginner-friendly presets shown first in `--list-presets`.
const PROTECTION_LEVELS: &[(&str, &str)] = &[
    (
        "shield",
        "Entry-level — credential protection, SANDWORM defense, exfil blocking, injection/DLP scanning",
    ),
    (
        "fortress",
        "Strong — shield + system file protection, package config tampering, sudo approval, memory tracking",
    ),
    (
        "vault",
        "Maximum — deny-by-default with safe read operations, file writes require approval",
    ),
];

/// Available preset definitions: (name, description, embedded TOML content).
/// Protection levels are listed first, then professional presets.
const PRESETS: &[(&str, &str, &str)] = &[
    // --- Protection levels (beginner-friendly) ---
    (
        "shield",
        "Entry-level — credential protection, SANDWORM defense, exfil blocking, injection/DLP scanning",
        include_str!("../presets/shield.toml"),
    ),
    (
        "fortress",
        "Strong — shield + system file protection, package config tampering, sudo approval, memory tracking",
        include_str!("../presets/fortress.toml"),
    ),
    (
        "vault",
        "Maximum — deny-by-default with safe read operations, file writes require approval",
        include_str!("../presets/vault.toml"),
    ),
    // --- Professional presets ---
    (
        "dev-laptop",
        "Developer laptop — comprehensive workstation protection with SANDWORM defense",
        include_str!("../presets/dev-laptop.toml"),
    ),
    (
        "ci-agent",
        "CI/CD pipeline — strict network/path controls, supply chain protection",
        include_str!("../presets/ci-agent.toml"),
    ),
    (
        "code-review-agent",
        "Code review — read-only source access, git history, default deny",
        include_str!("../presets/code-review-agent.toml"),
    ),
    (
        "browser-agent",
        "Browser automation — JS execution controls, phishing defense, download restrictions",
        include_str!("../presets/browser-agent.toml"),
    ),
    (
        "database-agent",
        "Database access — SQL injection blocking, schema change approval, credential protection",
        include_str!("../presets/database-agent.toml"),
    ),
    (
        "api-gateway-agent",
        "API gateway — domain allowlisting, blocks internal networks",
        include_str!("../presets/api-gateway-agent.toml"),
    ),
    (
        "rag-agent",
        "RAG agent — vector DB access controls, response scanning",
        include_str!("../presets/rag-agent.toml"),
    ),
    (
        "data-science-agent",
        "Data science — notebook/ML controls, data export restrictions",
        include_str!("../presets/data-science-agent.toml"),
    ),
    (
        "customer-support-agent",
        "Customer support — CRM/ticketing controls, PII redaction",
        include_str!("../presets/customer-support-agent.toml"),
    ),
    (
        "devops-agent",
        "DevOps/infrastructure — secrets management approval, namespace protection, credential blocking",
        include_str!("../presets/devops-agent.toml"),
    ),
    (
        "compliance-starter",
        "All 12 compliance frameworks — EU AI Act, NIS2, DORA, SOC 2, and 8 more",
        include_str!("../presets/compliance-starter.toml"),
    ),
    (
        "financial-agent",
        "Financial services — DORA/NIS2 controls, strict audit",
        include_str!("../presets/financial-agent.toml"),
    ),
    (
        "healthcare-agent",
        "Healthcare — HIPAA-aligned controls, PHI protection",
        include_str!("../presets/healthcare-agent.toml"),
    ),
    (
        "sandworm-hardened",
        "Maximum security — all defensive layers, default deny",
        include_str!("../presets/sandworm-hardened.toml"),
    ),
    (
        "consumer-shield",
        "Consumer privacy — PII sanitization, encrypted audit",
        include_str!("../presets/consumer-shield.toml"),
    ),
];

/// Built-in default config TOML used when no --config or --preset is given.
/// Blocks credential files, enables non-blocking injection scanning, allows
/// everything else. This provides basic protection with zero configuration.
const DEFAULT_CONFIG_TOML: &str = r#"# Vellaveto built-in default configuration
# Generated automatically when no --config or --preset is specified.
# Run `vellaveto-proxy init` to create a customizable config file.

# --- Block credential and secret files ---
[[policies]]
name = "Block credential files"
tool_pattern = "*"
function_pattern = "*"
priority = 300
id = "default:*:credential-block"

[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
parameter_constraints = [
  { param = "*", op = "glob", pattern = "/home/*/.aws/**",       on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "/home/*/.ssh/**",       on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "/home/*/.gnupg/**",     on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "**/.env",               on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "**/.env.*",             on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "**/credentials.json",   on_match = "deny", on_missing = "skip" },
  { param = "*", op = "glob", pattern = "**/secrets.yaml",       on_match = "deny", on_missing = "skip" },
]

# --- Allow all other tool calls ---
[[policies]]
name = "Default allow"
tool_pattern = "*"
function_pattern = "*"
priority = 1
id = "default:*:allow"
policy_type = "Allow"

# --- Injection detection (non-blocking) ---
[injection]
enabled = true
block_on_injection = false
"#;

/// Load a named preset and parse it into a `PolicyConfig`.
///
/// Returns `Err` with a descriptive message if the preset name is unknown
/// or the embedded TOML fails to parse (which would be a build-time bug).
pub fn load_preset(name: &str) -> Result<PolicyConfig, String> {
    let toml = preset_toml(name).ok_or_else(|| {
        let available: Vec<&str> = PRESETS.iter().map(|(n, _, _)| *n).collect();
        format!(
            "Unknown preset '{}'. Available presets: {}",
            name,
            available.join(", ")
        )
    })?;
    PolicyConfig::from_toml(toml).map_err(|e| format!("Failed to parse preset '{name}': {e}"))
}

/// List all available presets as `(name, description)` pairs.
pub fn list_presets() -> Vec<(&'static str, &'static str)> {
    PRESETS.iter().map(|(n, d, _)| (*n, *d)).collect()
}

/// Get the raw TOML content for a named preset.
pub fn preset_toml(name: &str) -> Option<&'static str> {
    PRESETS
        .iter()
        .find(|(n, _, _)| *n == name)
        .map(|(_, _, toml)| *toml)
}

/// Check whether a name is a protection level (shield/fortress/vault).
pub fn is_protection_level(name: &str) -> bool {
    PROTECTION_LEVELS.iter().any(|(n, _)| *n == name)
}

/// List protection levels as `(name, description)` pairs.
pub fn list_protection_levels() -> Vec<(&'static str, &'static str)> {
    PROTECTION_LEVELS.to_vec()
}

/// Load the built-in default configuration.
///
/// This is used when no `--config` or `--preset` flag is provided.
/// Returns `Err` only if the compile-time constant TOML is malformed (a build bug).
pub fn default_config() -> Result<PolicyConfig, String> {
    PolicyConfig::from_toml(DEFAULT_CONFIG_TOML)
        .map_err(|e| format!("built-in default config is invalid (this is a bug): {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_presets_parse_successfully() {
        for (name, _, toml) in PRESETS {
            let result = PolicyConfig::from_toml(toml);
            assert!(
                result.is_ok(),
                "Preset '{}' failed to parse: {}",
                name,
                result.unwrap_err()
            );
        }
    }

    #[test]
    fn test_default_config_parses() {
        let config = default_config().expect("default config should parse");
        let policies = config.to_policies();
        assert!(
            policies.len() >= 2,
            "default config should have at least 2 policies"
        );
    }

    #[test]
    fn test_load_preset_valid() {
        let config = load_preset("dev-laptop").expect("dev-laptop should load");
        let policies = config.to_policies();
        assert!(!policies.is_empty(), "dev-laptop should have policies");
    }

    #[test]
    fn test_load_preset_unknown() {
        let err = load_preset("nonexistent").unwrap_err();
        assert!(err.contains("Unknown preset"));
        assert!(err.contains("dev-laptop")); // lists available
    }

    #[test]
    fn test_list_presets_not_empty() {
        let presets = list_presets();
        assert!(!presets.is_empty());
        let names: Vec<&str> = presets.iter().map(|(n, _)| *n).collect();
        assert!(names.contains(&"dev-laptop"));
        assert!(names.contains(&"ci-agent"));
        assert!(names.contains(&"sandworm-hardened"));
    }

    #[test]
    fn test_preset_toml_returns_content() {
        let toml = preset_toml("dev-laptop");
        assert!(toml.is_some());
        assert!(toml.unwrap().contains("[[policies]]"));
    }

    #[test]
    fn test_preset_toml_unknown_returns_none() {
        assert!(preset_toml("does-not-exist").is_none());
    }

    #[test]
    fn test_default_config_toml_is_valid() {
        assert!(DEFAULT_CONFIG_TOML.contains("credential"));
        assert!(DEFAULT_CONFIG_TOML.contains("[injection]"));
    }

    // --- Protection level tests ---

    #[test]
    fn test_shield_preset_parses() {
        let config = load_preset("shield").expect("shield should load");
        let policies = config.to_policies();
        assert!(
            policies.len() >= 8,
            "shield should have at least 8 policies, got {}",
            policies.len()
        );
    }

    #[test]
    fn test_fortress_preset_parses() {
        let config = load_preset("fortress").expect("fortress should load");
        let policies = config.to_policies();
        assert!(
            policies.len() >= 11,
            "fortress should have at least 11 policies, got {}",
            policies.len()
        );
    }

    #[test]
    fn test_vault_preset_parses() {
        let config = load_preset("vault").expect("vault should load");
        let policies = config.to_policies();
        assert!(
            policies.len() >= 11,
            "vault should have at least 11 policies, got {}",
            policies.len()
        );
    }

    #[test]
    fn test_shield_has_injection_blocking() {
        let config = load_preset("shield").expect("shield should load");
        assert!(config.injection.enabled, "shield should enable injection");
        assert!(
            config.injection.block_on_injection,
            "shield should block on injection"
        );
    }

    #[test]
    fn test_shield_has_dlp_blocking() {
        let config = load_preset("shield").expect("shield should load");
        assert!(config.dlp.enabled, "shield should enable DLP");
        assert!(
            config.dlp.block_on_finding,
            "shield should block on DLP finding"
        );
    }

    #[test]
    fn test_vault_has_shadow_agent_detection() {
        let config = load_preset("vault").expect("vault should load");
        assert!(
            config.shadow_agent.enabled,
            "vault should enable shadow agent detection"
        );
    }

    #[test]
    fn test_is_protection_level() {
        assert!(is_protection_level("shield"));
        assert!(is_protection_level("fortress"));
        assert!(is_protection_level("vault"));
        assert!(!is_protection_level("dev-laptop"));
        assert!(!is_protection_level("sandworm-hardened"));
        assert!(!is_protection_level("nonexistent"));
    }

    #[test]
    fn test_list_protection_levels() {
        let levels = list_protection_levels();
        assert_eq!(levels.len(), 3);
        assert_eq!(levels[0].0, "shield");
        assert_eq!(levels[1].0, "fortress");
        assert_eq!(levels[2].0, "vault");
    }

    #[test]
    fn test_protection_levels_appear_first_in_presets() {
        let presets = list_presets();
        assert_eq!(presets[0].0, "shield");
        assert_eq!(presets[1].0, "fortress");
        assert_eq!(presets[2].0, "vault");
    }

    #[test]
    fn test_list_presets_includes_protection_levels() {
        let presets = list_presets();
        let names: Vec<&str> = presets.iter().map(|(n, _)| *n).collect();
        assert!(names.contains(&"shield"));
        assert!(names.contains(&"fortress"));
        assert!(names.contains(&"vault"));
    }

    // --- Enhanced preset feature tests ---

    #[test]
    fn test_shield_has_memory_tracking() {
        let config = load_preset("shield").expect("shield should load");
        assert!(
            config.memory_tracking.enabled,
            "shield should enable memory tracking"
        );
        assert!(
            !config.memory_tracking.block_on_match,
            "shield memory tracking should be non-blocking (monitor-only)"
        );
    }

    #[test]
    fn test_fortress_has_memory_tracking_blocking() {
        let config = load_preset("fortress").expect("fortress should load");
        assert!(
            config.memory_tracking.enabled,
            "fortress should enable memory tracking"
        );
        assert!(
            config.memory_tracking.block_on_match,
            "fortress memory tracking should be blocking"
        );
    }

    #[test]
    fn test_fortress_has_shadow_agent_detection() {
        let config = load_preset("fortress").expect("fortress should load");
        assert!(
            config.shadow_agent.enabled,
            "fortress should enable shadow agent detection"
        );
    }

    #[test]
    fn test_vault_has_elicitation_enabled() {
        let config = load_preset("vault").expect("vault should load");
        assert!(
            config.elicitation.enabled,
            "vault should enable elicitation controls"
        );
    }

    #[test]
    fn test_dev_laptop_has_full_protection() {
        let config = load_preset("dev-laptop").expect("dev-laptop should load");
        let policies = config.to_policies();
        assert!(
            policies.len() >= 9,
            "dev-laptop should have at least 9 policies, got {}",
            policies.len()
        );
        assert!(
            config.injection.enabled && config.injection.block_on_injection,
            "dev-laptop should have blocking injection"
        );
        assert!(
            config.dlp.enabled && config.dlp.block_on_finding,
            "dev-laptop should have blocking DLP"
        );
    }

    #[test]
    fn test_ci_agent_has_supply_chain_protection() {
        let config = load_preset("ci-agent").expect("ci-agent should load");
        let policies = config.to_policies();
        assert!(
            policies.len() >= 7,
            "ci-agent should have at least 7 policies, got {}",
            policies.len()
        );
        assert!(
            config.injection.enabled && config.injection.block_on_injection,
            "ci-agent should have blocking injection"
        );
        assert!(
            config.dlp.enabled && config.dlp.block_on_finding,
            "ci-agent should have blocking DLP"
        );
    }

    #[test]
    fn test_database_agent_has_injection_and_dlp() {
        let config = load_preset("database-agent").expect("database-agent should load");
        let policies = config.to_policies();
        assert!(
            policies.len() >= 6,
            "database-agent should have at least 6 policies, got {}",
            policies.len()
        );
        assert!(
            config.injection.enabled && config.injection.block_on_injection,
            "database-agent should have blocking injection"
        );
        assert!(
            config.dlp.enabled && config.dlp.block_on_finding,
            "database-agent should have blocking DLP"
        );
    }

    #[test]
    fn test_browser_agent_has_full_protection() {
        let config = load_preset("browser-agent").expect("browser-agent should load");
        let policies = config.to_policies();
        assert!(
            policies.len() >= 7,
            "browser-agent should have at least 7 policies, got {}",
            policies.len()
        );
    }

    #[test]
    fn test_devops_agent_has_credential_blocking() {
        let config = load_preset("devops-agent").expect("devops-agent should load");
        let policies = config.to_policies();
        assert!(
            policies.len() >= 11,
            "devops-agent should have at least 11 policies, got {}",
            policies.len()
        );
        assert!(
            config.dlp.enabled && config.dlp.block_on_finding,
            "devops-agent should have blocking DLP"
        );
    }

    #[test]
    fn test_all_protection_levels_have_injection_and_dlp() {
        for level in ["shield", "fortress", "vault"] {
            let config = load_preset(level).unwrap_or_else(|e| panic!("{level} should load: {e}"));
            assert!(
                config.injection.enabled && config.injection.block_on_injection,
                "{level} should have blocking injection"
            );
            assert!(
                config.dlp.enabled && config.dlp.block_on_finding,
                "{level} should have blocking DLP"
            );
        }
    }

    #[test]
    fn test_shield_has_source_trust() {
        let config = load_preset("shield").expect("shield should load");
        assert!(
            !config.source_trust.untrusted_tools.is_empty(),
            "shield should have untrusted tool patterns"
        );
    }

    #[test]
    fn test_shield_has_sink_classification() {
        let config = load_preset("shield").expect("shield should load");
        assert!(
            !config.sink_classification.rules.is_empty(),
            "shield should have sink classification rules"
        );
    }

    #[test]
    fn test_fortress_has_intent_scope() {
        let config = load_preset("fortress").expect("fortress should load");
        assert!(
            config.intent_scope.is_some(),
            "fortress should have intent scope config"
        );
    }

    #[test]
    fn test_vault_has_strict_intent_scope() {
        let config = load_preset("vault").expect("vault should load");
        let scope = config
            .intent_scope
            .expect("vault should have intent scope config");
        assert!(
            !scope.denied_tools.is_empty(),
            "vault intent scope should deny some tools"
        );
        assert_eq!(
            scope.out_of_scope_action,
            vellaveto_config::channel_separation::OutOfScopeAction::Deny,
            "vault intent scope should deny out-of-scope actions"
        );
    }

    #[test]
    fn test_all_protection_levels_have_source_trust() {
        for level in ["shield", "fortress", "vault"] {
            let config = load_preset(level).unwrap_or_else(|e| panic!("{level} should load: {e}"));
            assert!(
                !config.source_trust.untrusted_tools.is_empty(),
                "{level} should have untrusted tool patterns"
            );
        }
    }
    #[test]
    fn test_preset_descriptions_mention_key_features() {
        let presets = list_presets();
        let shield_desc = presets.iter().find(|(n, _)| *n == "shield").unwrap().1;
        assert!(
            shield_desc.contains("SANDWORM"),
            "shield description should mention SANDWORM defense"
        );
        let fortress_desc = presets.iter().find(|(n, _)| *n == "fortress").unwrap().1;
        assert!(
            fortress_desc.contains("memory tracking") || fortress_desc.contains("package config"),
            "fortress description should mention memory tracking or package config"
        );
        let vault_desc = presets.iter().find(|(n, _)| *n == "vault").unwrap().1;
        assert!(
            vault_desc.contains("deny") || vault_desc.contains("Deny"),
            "vault description should mention deny-by-default"
        );
    }
}
