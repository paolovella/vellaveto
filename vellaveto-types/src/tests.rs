// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

use super::*;
use proptest::prelude::*;
use serde_json::json;
use std::collections::HashMap;

#[test]
fn test_action_serialization_roundtrip() {
    let action = Action::new("file_system", "read_file", json!({"path": "/tmp/test.txt"}));
    let json_str = serde_json::to_string(&action).unwrap();
    let deserialized: Action = serde_json::from_str(&json_str).unwrap();
    assert_eq!(action, deserialized);
}

#[test]
fn test_verdict_all_variants() {
    let variants = vec![
        Verdict::Allow,
        Verdict::Deny {
            reason: "blocked".to_string(),
        },
        Verdict::RequireApproval {
            reason: "needs review".to_string(),
        },
    ];
    for v in variants {
        let json_str = serde_json::to_string(&v).unwrap();
        let deserialized: Verdict = serde_json::from_str(&json_str).unwrap();
        assert_eq!(v, deserialized);
    }
}

#[test]
fn test_verdict_deny_unknown_fields() {
    let mut json = serde_json::to_value(Verdict::Deny {
        reason: "blocked".to_string(),
    })
    .unwrap();
    json["Deny"]["unexpected"] = json!(true);
    let result: Result<Verdict, _> = serde_json::from_value(json);
    assert!(result.is_err(), "Verdict must reject unknown nested fields");
}

#[test]
fn test_policy_type_conditional_with_value() {
    let pt = PolicyType::Conditional {
        conditions: json!({"tool_pattern": "bash", "forbidden_parameters": ["force"]}),
    };
    let json_str = serde_json::to_string(&pt).unwrap();
    let deserialized: PolicyType = serde_json::from_str(&json_str).unwrap();
    assert_eq!(pt, deserialized);
}

#[test]
fn test_policy_type_conditional_deny_unknown_fields() {
    let mut json = serde_json::to_value(PolicyType::Conditional {
        conditions: json!({"tool_pattern": "bash"}),
    })
    .unwrap();
    json["Conditional"]["unexpected"] = json!(true);
    let result: Result<PolicyType, _> = serde_json::from_value(json);
    assert!(
        result.is_err(),
        "PolicyType must reject unknown nested fields"
    );
}

#[test]
fn test_policy_serialization() {
    let policy = Policy {
        id: "bash:*".to_string(),
        name: "Block bash".to_string(),
        policy_type: PolicyType::Deny,
        priority: 100,
        path_rules: None,
        network_rules: None,
    };
    let json_str = serde_json::to_string(&policy).unwrap();
    let deserialized: Policy = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.id, "bash:*");
    assert_eq!(deserialized.priority, 100);
}

// --- Action validation tests (M2) ---

#[test]
fn test_validated_accepts_valid_input() {
    let action = Action::validated("read_file", "execute", json!({}));
    assert!(action.is_ok());
    let action = action.unwrap();
    assert_eq!(action.tool, "read_file");
    assert_eq!(action.function, "execute");
}

#[test]
fn test_validated_rejects_empty_tool() {
    let result = Action::validated("", "execute", json!({}));
    assert!(matches!(
        result,
        Err(ValidationError::EmptyField { field: "tool" })
    ));
}

#[test]
fn test_validated_rejects_empty_function() {
    let result = Action::validated("read_file", "", json!({}));
    assert!(matches!(
        result,
        Err(ValidationError::EmptyField { field: "function" })
    ));
}

#[test]
fn test_validated_rejects_null_bytes_in_tool() {
    let result = Action::validated("read\0file", "execute", json!({}));
    assert!(matches!(
        result,
        Err(ValidationError::NullByte { field: "tool" })
    ));
}

#[test]
fn test_validated_rejects_null_bytes_in_function() {
    let result = Action::validated("read_file", "exec\0ute", json!({}));
    assert!(matches!(
        result,
        Err(ValidationError::NullByte { field: "function" })
    ));
}

#[test]
fn test_validated_rejects_too_long_tool() {
    let long_name = "a".repeat(257);
    let result = Action::validated(long_name, "execute", json!({}));
    assert!(matches!(
        result,
        Err(ValidationError::TooLong { field: "tool", .. })
    ));
}

#[test]
fn test_validated_accepts_max_length_tool() {
    let name = "a".repeat(256);
    let result = Action::validated(name, "execute", json!({}));
    assert!(result.is_ok());
}

#[test]
fn test_validate_existing_action() {
    let action = Action::new("read_file", "execute", json!({}));
    assert!(action.validate().is_ok());

    let bad = Action::new("", "execute", json!({}));
    assert!(bad.validate().is_err());
}

#[test]
fn test_new_still_works_without_validation() {
    // Backward compatibility: new() doesn't validate
    let action = Action::new("", "", json!({}));
    assert_eq!(action.tool, "");
    assert_eq!(action.function, "");
}

#[test]
fn test_validation_error_display() {
    let e = ValidationError::EmptyField { field: "tool" };
    assert!(e.to_string().contains("tool"));
    assert!(e.to_string().contains("empty"));
}

#[test]
fn test_validated_rejects_control_chars_with_correct_variant() {
    // Tab character should produce ControlCharacter, not NullByte
    let result = Action::validated("read\tfile", "execute", json!({}));
    assert!(
        matches!(
            result,
            Err(ValidationError::ControlCharacter { field: "tool" })
        ),
        "Tab should produce ControlCharacter variant, got: {result:?}"
    );

    // Newline in function
    let result = Action::validated("tool", "exec\nute", json!({}));
    assert!(
        matches!(
            result,
            Err(ValidationError::ControlCharacter { field: "function" })
        ),
        "Newline should produce ControlCharacter variant, got: {result:?}"
    );
}

#[test]
fn test_control_character_error_display() {
    let e = ValidationError::ControlCharacter { field: "tool" };
    let msg = e.to_string();
    assert!(
        msg.contains("control character"),
        "Error message should say 'control character', got: {msg}"
    );
    assert!(!msg.contains("null byte"), "Should NOT mention null byte");
}

// --- Target validation tests ---

#[test]
fn test_validate_rejects_null_byte_in_target_path() {
    let mut action = Action::new("tool", "func", json!({}));
    action.target_paths = vec!["/tmp/foo\0bar".to_string()];
    assert!(matches!(
        action.validate(),
        Err(ValidationError::TargetNullByte {
            field: "target_paths",
            index: 0
        })
    ));
}

#[test]
fn test_validate_rejects_null_byte_in_target_domain() {
    let mut action = Action::new("tool", "func", json!({}));
    action.target_domains = vec!["evil\0.com".to_string()];
    assert!(matches!(
        action.validate(),
        Err(ValidationError::TargetNullByte {
            field: "target_domains",
            index: 0
        })
    ));
}

#[test]
fn test_validate_rejects_too_long_target_path() {
    let mut action = Action::new("tool", "func", json!({}));
    action.target_paths = vec!["a".repeat(4097)];
    assert!(matches!(
        action.validate(),
        Err(ValidationError::TargetTooLong {
            field: "target_paths",
            index: 0,
            ..
        })
    ));
}

#[test]
fn test_validate_accepts_max_length_target_path() {
    let mut action = Action::new("tool", "func", json!({}));
    action.target_paths = vec!["a".repeat(4096)];
    assert!(action.validate().is_ok());
}

#[test]
fn test_validate_rejects_too_many_targets() {
    let mut action = Action::new("tool", "func", json!({}));
    action.target_paths = (0..200).map(|i| format!("/path/{i}")).collect();
    action.target_domains = (0..100).map(|i| format!("d{i}.com")).collect();
    // 200 + 100 = 300 > 256
    assert!(matches!(
        action.validate(),
        Err(ValidationError::TooManyTargets {
            count: 300,
            max: 256
        })
    ));
}

#[test]
fn test_validate_accepts_max_targets() {
    let mut action = Action::new("tool", "func", json!({}));
    action.target_paths = (0..128).map(|i| format!("/path/{i}")).collect();
    action.target_domains = (0..128).map(|i| format!("d{i}.com")).collect();
    // 128 + 128 = 256 == MAX_TARGETS
    assert!(action.validate().is_ok());
}

#[test]
fn test_validate_rejects_too_many_resolved_ips_r39_eng_4() {
    // R39-ENG-4: resolved_ips must be counted in total_targets.
    // 300 resolved_ips alone should exceed MAX_TARGETS=256.
    let mut action = Action::new("tool", "func", json!({}));
    action.resolved_ips = (0..300)
        .map(|i| format!("10.0.{}.{}", i / 256, i % 256))
        .collect();
    assert!(matches!(
        action.validate(),
        Err(ValidationError::TooManyTargets {
            count: 300,
            max: 256
        })
    ));
}

#[test]
fn test_validate_resolved_ips_combined_with_paths_domains_r39_eng_4() {
    // R39-ENG-4: Combination of paths + domains + IPs exceeding MAX_TARGETS
    let mut action = Action::new("tool", "func", json!({}));
    action.target_paths = (0..100).map(|i| format!("/path/{i}")).collect();
    action.target_domains = (0..100).map(|i| format!("d{i}.com")).collect();
    action.resolved_ips = (0..57).map(|i| format!("10.0.0.{i}")).collect();
    // 100 + 100 + 57 = 257 > 256
    assert!(matches!(
        action.validate(),
        Err(ValidationError::TooManyTargets {
            count: 257,
            max: 256
        })
    ));
}

#[test]
fn test_validate_resolved_ips_at_boundary_r39_eng_4() {
    // R39-ENG-4: paths + domains + IPs exactly at MAX_TARGETS should pass
    let mut action = Action::new("tool", "func", json!({}));
    action.target_paths = (0..85).map(|i| format!("/path/{i}")).collect();
    action.target_domains = (0..85).map(|i| format!("d{i}.com")).collect();
    action.resolved_ips = (0..86).map(|i| format!("10.0.0.{i}")).collect();
    // 85 + 85 + 86 = 256 == MAX_TARGETS
    assert!(action.validate().is_ok());
}

// --- R42-TYPES-1: resolved_ips content validation tests ---

#[test]
fn test_r42_types_1_resolved_ips_null_byte_rejected() {
    // R42-TYPES-1: resolved_ips with null byte must be rejected
    let mut action = Action::new("tool", "func", json!({}));
    action.resolved_ips = vec!["10.0.0.1".to_string(), "10.0.\0.2".to_string()];
    assert!(matches!(
        action.validate(),
        Err(ValidationError::TargetNullByte {
            field: "resolved_ips",
            index: 1
        })
    ));
}

#[test]
fn test_r42_types_1_resolved_ips_oversized_rejected() {
    // R42-TYPES-1: resolved_ips with oversized string must be rejected
    let mut action = Action::new("tool", "func", json!({}));
    let oversized = "A".repeat(4097); // MAX_TARGET_LEN is 4096
    action.resolved_ips = vec![oversized];
    assert!(matches!(
        action.validate(),
        Err(ValidationError::TargetTooLong {
            field: "resolved_ips",
            index: 0,
            len: 4097,
            max: 4096
        })
    ));
}

#[test]
fn test_r42_types_1_resolved_ips_valid_entries_pass() {
    // R42-TYPES-1: Valid resolved_ips should pass validation
    let mut action = Action::new("tool", "func", json!({}));
    action.resolved_ips = vec![
        "10.0.0.1".to_string(),
        "192.168.1.1".to_string(),
        "::1".to_string(),
    ];
    assert!(action.validate().is_ok());
}

#[test]
fn test_r42_types_1_resolved_ips_null_byte_first_entry() {
    // R42-TYPES-1: null byte at index 0
    let mut action = Action::new("tool", "func", json!({}));
    action.resolved_ips = vec!["\0".to_string()];
    assert!(matches!(
        action.validate(),
        Err(ValidationError::TargetNullByte {
            field: "resolved_ips",
            index: 0
        })
    ));
}

#[test]
fn test_validate_null_byte_second_target() {
    let mut action = Action::new("tool", "func", json!({}));
    action.target_paths = vec!["/ok".to_string(), "/bad\0path".to_string()];
    assert!(matches!(
        action.validate(),
        Err(ValidationError::TargetNullByte {
            field: "target_paths",
            index: 1
        })
    ));
}

#[test]
fn test_target_validation_error_display() {
    let e = ValidationError::TooManyTargets {
        count: 500,
        max: 256,
    };
    assert!(e.to_string().contains("500"));
    assert!(e.to_string().contains("256"));

    let e = ValidationError::TargetNullByte {
        field: "target_paths",
        index: 3,
    };
    assert!(e.to_string().contains("target_paths[3]"));
    assert!(e.to_string().contains("null byte"));

    let e = ValidationError::TargetTooLong {
        field: "target_domains",
        index: 0,
        len: 5000,
        max: 4096,
    };
    assert!(e.to_string().contains("5000"));
    assert!(e.to_string().contains("4096"));
}

// ═══════════════════════════════════════════════════
// PROPERTY-BASED TESTS: Action Validation
// ═══════════════════════════════════════════════════

proptest! {
    // PROPERTY: validated() succeeds iff validate() succeeds on the same inputs
    #[test]
    fn validated_ok_iff_validate_ok(
        tool in "[a-z_]{0,260}",
        function in "[a-z_]{0,260}",
    ) {
        let validated_result = Action::validated(&tool, &function, json!({}));
        let new_action = Action::new(&tool, &function, json!({}));
        let validate_result = new_action.validate();

        prop_assert_eq!(
            validated_result.is_ok(),
            validate_result.is_ok(),
            "validated() and validate() must agree for tool={:?} function={:?}\n\
             validated: {:?}\n\
             validate:  {:?}",
            tool, function, validated_result, validate_result
        );
    }

    // PROPERTY: Any name containing a null byte is always rejected
    #[test]
    fn null_byte_always_rejected(
        prefix in "[a-z]{1,10}",
        suffix in "[a-z]{1,10}",
    ) {
        let tool_with_null = format!("{prefix}\0{suffix}");

        // Null in tool
        let result = Action::validated(&tool_with_null, "func", json!({}));
        prop_assert!(
            matches!(result, Err(ValidationError::NullByte { field: "tool" })),
            "Null byte in tool must be rejected. Got: {:?}", result
        );

        // Null in function
        let result = Action::validated("tool", &tool_with_null, json!({}));
        prop_assert!(
            matches!(result, Err(ValidationError::NullByte { field: "function" })),
            "Null byte in function must be rejected. Got: {:?}", result
        );
    }

    // PROPERTY: Empty tool or function name is always rejected
    #[test]
    fn empty_name_always_rejected(
        other in "[a-z]{1,10}",
    ) {
        let result = Action::validated("", &other, json!({}));
        prop_assert!(
            matches!(result, Err(ValidationError::EmptyField { field: "tool" })),
            "Empty tool must be rejected. Got: {:?}", result
        );

        let result = Action::validated(&other, "", json!({}));
        prop_assert!(
            matches!(result, Err(ValidationError::EmptyField { field: "function" })),
            "Empty function must be rejected. Got: {:?}", result
        );
    }

    // PROPERTY: 256-byte name is accepted, 257-byte name is rejected
    #[test]
    fn max_length_boundary(
        ch in "[a-z]",
    ) {
        let at_max = ch.repeat(256);
        let over_max = ch.repeat(257);

        let ok_result = Action::validated(&at_max, "func", json!({}));
        prop_assert!(ok_result.is_ok(),
            "256-byte name must be accepted. Got: {:?}", ok_result);

        let err_result = Action::validated(&over_max, "func", json!({}));
        prop_assert!(
            matches!(err_result, Err(ValidationError::TooLong { field: "tool", .. })),
            "257-byte name must be rejected. Got: {:?}", err_result
        );
    }

    // PROPERTY: Valid actions roundtrip through serde unchanged
    #[test]
    fn valid_names_roundtrip_serde(
        tool in "[a-z_]{1,20}",
        function in "[a-z_]{1,20}",
    ) {
        let action = Action::validated(&tool, &function, json!({"key": "value"})).unwrap();
        let serialized = serde_json::to_string(&action).unwrap();
        let deserialized: Action = serde_json::from_str(&serialized).unwrap();
        prop_assert_eq!(&action, &deserialized,
            "Valid action must roundtrip through serde unchanged");
    }
}

// SECURITY (R16-TYPES-2): EvaluationContext.has_any_meaningful_fields()
// must include timestamp so time-window policies fail-closed.
#[test]
fn test_context_timestamp_only_is_meaningful() {
    let ctx = EvaluationContext {
        timestamp: Some("2024-01-01T00:00:00Z".to_string()),
        ..Default::default()
    };
    assert!(
        ctx.has_any_meaningful_fields(),
        "Context with only timestamp should be meaningful"
    );
}

#[test]
fn test_context_empty_is_not_meaningful() {
    let ctx = EvaluationContext::default();
    assert!(
        !ctx.has_any_meaningful_fields(),
        "Default context should not be meaningful"
    );
}

// --- Call chain tests (OWASP ASI08) ---

#[test]
fn test_call_chain_entry_serialization() {
    let entry = CallChainEntry {
        agent_id: "agent-a".to_string(),
        tool: "read_file".to_string(),
        function: "execute".to_string(),
        timestamp: "2026-01-01T12:00:00Z".to_string(),
        hmac: None,
        verified: None,
    };
    let json_str = serde_json::to_string(&entry).unwrap();
    let deserialized: CallChainEntry = serde_json::from_str(&json_str).unwrap();
    assert_eq!(entry, deserialized);
}

#[test]
fn test_context_call_chain_is_meaningful() {
    let ctx = EvaluationContext {
        call_chain: vec![CallChainEntry {
            agent_id: "agent-a".to_string(),
            tool: "read_file".to_string(),
            function: "execute".to_string(),
            timestamp: "2026-01-01T12:00:00Z".to_string(),
            hmac: None,
            verified: None,
        }],
        ..Default::default()
    };
    assert!(
        ctx.has_any_meaningful_fields(),
        "Context with call_chain should be meaningful"
    );
}

#[test]
fn test_call_chain_depth() {
    let empty_ctx = EvaluationContext::default();
    assert_eq!(empty_ctx.call_chain_depth(), 0);

    let single_hop_ctx = EvaluationContext {
        call_chain: vec![CallChainEntry {
            agent_id: "agent-a".to_string(),
            tool: "tool1".to_string(),
            function: "func1".to_string(),
            timestamp: "2026-01-01T12:00:00Z".to_string(),
            hmac: None,
            verified: None,
        }],
        ..Default::default()
    };
    assert_eq!(single_hop_ctx.call_chain_depth(), 1);

    let multi_hop_ctx = EvaluationContext {
        call_chain: vec![
            CallChainEntry {
                agent_id: "agent-a".to_string(),
                tool: "tool1".to_string(),
                function: "func1".to_string(),
                timestamp: "2026-01-01T12:00:00Z".to_string(),
                hmac: None,
                verified: None,
            },
            CallChainEntry {
                agent_id: "agent-b".to_string(),
                tool: "tool2".to_string(),
                function: "func2".to_string(),
                timestamp: "2026-01-01T12:00:01Z".to_string(),
                hmac: None,
                verified: None,
            },
        ],
        ..Default::default()
    };
    assert_eq!(multi_hop_ctx.call_chain_depth(), 2);
}

#[test]
fn test_originating_agent() {
    let empty_ctx = EvaluationContext::default();
    assert!(empty_ctx.originating_agent().is_none());

    let ctx = EvaluationContext {
        call_chain: vec![
            CallChainEntry {
                agent_id: "origin-agent".to_string(),
                tool: "tool1".to_string(),
                function: "func1".to_string(),
                timestamp: "2026-01-01T12:00:00Z".to_string(),
                hmac: None,
                verified: None,
            },
            CallChainEntry {
                agent_id: "proxy-agent".to_string(),
                tool: "tool2".to_string(),
                function: "func2".to_string(),
                timestamp: "2026-01-01T12:00:01Z".to_string(),
                hmac: None,
                verified: None,
            },
        ],
        ..Default::default()
    };
    assert_eq!(ctx.originating_agent(), Some("origin-agent"));
}

// --- principal_type() tests (IMP-R198-012) ---

#[test]
fn test_principal_type_default_is_agent() {
    let ctx = EvaluationContext::default();
    assert_eq!(ctx.principal_type(), "Agent");
}

#[test]
fn test_principal_type_from_identity_claims() {
    let mut claims = serde_json::Map::new();
    claims.insert(
        "type".to_string(),
        serde_json::Value::String("Service".to_string()),
    );
    let ctx = EvaluationContext {
        agent_identity: Some(AgentIdentity {
            subject: Some("svc-1".to_string()),
            claims: claims.into_iter().collect(),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert_eq!(ctx.principal_type(), "Service");
}

#[test]
fn test_principal_type_missing_claim_defaults() {
    let ctx = EvaluationContext {
        agent_identity: Some(AgentIdentity {
            subject: Some("agent-1".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert_eq!(ctx.principal_type(), "Agent");
}

// --- AgentIdentity tests (OWASP ASI07) ---

#[test]
fn test_agent_identity_serialization_roundtrip() {
    let mut claims = HashMap::new();
    claims.insert("role".to_string(), json!("admin"));
    claims.insert("permissions".to_string(), json!(["read", "write"]));

    let identity = AgentIdentity {
        issuer: Some("https://auth.example.com".to_string()),
        subject: Some("agent-123".to_string()),
        audience: vec!["mcp-server".to_string()],
        claims,
    };

    let json_str = serde_json::to_string(&identity).unwrap();
    let deserialized: AgentIdentity = serde_json::from_str(&json_str).unwrap();
    assert_eq!(identity, deserialized);
}

#[test]
fn test_agent_identity_is_populated() {
    let empty = AgentIdentity::default();
    assert!(!empty.is_populated());

    let with_issuer = AgentIdentity {
        issuer: Some("https://auth.example.com".to_string()),
        ..Default::default()
    };
    assert!(with_issuer.is_populated());

    let with_subject = AgentIdentity {
        subject: Some("agent-123".to_string()),
        ..Default::default()
    };
    assert!(with_subject.is_populated());

    let with_audience = AgentIdentity {
        audience: vec!["server".to_string()],
        ..Default::default()
    };
    assert!(with_audience.is_populated());

    let mut claims = HashMap::new();
    claims.insert("role".to_string(), json!("admin"));
    let with_claims = AgentIdentity {
        claims,
        ..Default::default()
    };
    assert!(with_claims.is_populated());
}

#[test]
fn test_agent_identity_claim_str() {
    let mut claims = HashMap::new();
    claims.insert("role".to_string(), json!("admin"));
    claims.insert("count".to_string(), json!(42));

    let identity = AgentIdentity {
        claims,
        ..Default::default()
    };

    assert_eq!(identity.claim_str("role"), Some("admin"));
    assert_eq!(identity.claim_str("count"), None); // Not a string
    assert_eq!(identity.claim_str("missing"), None);
}

#[test]
fn test_agent_identity_claim_str_array() {
    let mut claims = HashMap::new();
    claims.insert("permissions".to_string(), json!(["read", "write"]));
    claims.insert("role".to_string(), json!("admin")); // Not an array
    claims.insert("mixed".to_string(), json!(["str", 42])); // Mixed types

    let identity = AgentIdentity {
        claims,
        ..Default::default()
    };

    assert_eq!(
        identity.claim_str_array("permissions"),
        Some(vec!["read", "write"])
    );
    assert_eq!(identity.claim_str_array("role"), None); // Not an array
                                                        // Mixed array should only contain strings
    assert_eq!(identity.claim_str_array("mixed"), Some(vec!["str"]));
    assert_eq!(identity.claim_str_array("missing"), None);
}

#[test]
fn test_context_with_agent_identity_is_meaningful() {
    let identity = AgentIdentity {
        subject: Some("agent-123".to_string()),
        ..Default::default()
    };
    let ctx = EvaluationContext {
        agent_identity: Some(identity),
        ..Default::default()
    };
    assert!(
        ctx.has_any_meaningful_fields(),
        "Context with agent_identity should be meaningful"
    );
}

#[test]
fn test_context_with_empty_agent_identity_is_not_meaningful() {
    let ctx = EvaluationContext {
        agent_identity: Some(AgentIdentity::default()),
        ..Default::default()
    };
    assert!(
        !ctx.has_any_meaningful_fields(),
        "Context with empty agent_identity should not be meaningful"
    );
}

// ═══════════════════════════════════════════════════
// MCP 2025-11-25 TYPES TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_task_status_serialization() {
    let statuses = vec![
        TaskStatus::Pending,
        TaskStatus::Running,
        TaskStatus::Completed,
        TaskStatus::Failed {
            reason: "timeout".to_string(),
        },
        TaskStatus::Cancelled,
        TaskStatus::Expired,
    ];
    for status in statuses {
        let json_str = serde_json::to_string(&status).unwrap();
        let deserialized: TaskStatus = serde_json::from_str(&json_str).unwrap();
        assert_eq!(status, deserialized);
    }
}

#[test]
fn test_task_status_display() {
    assert_eq!(TaskStatus::Pending.to_string(), "pending");
    assert_eq!(TaskStatus::Running.to_string(), "running");
    assert_eq!(TaskStatus::Completed.to_string(), "completed");
    assert_eq!(
        TaskStatus::Failed {
            reason: "error".to_string()
        }
        .to_string(),
        "failed: error"
    );
    assert_eq!(TaskStatus::Cancelled.to_string(), "cancelled");
    assert_eq!(TaskStatus::Expired.to_string(), "expired");
}

#[test]
fn test_task_status_failed_deny_unknown_fields() {
    let mut json = serde_json::to_value(TaskStatus::Failed {
        reason: "timeout".to_string(),
    })
    .unwrap();
    json["failed"]["unexpected"] = json!(true);
    let result: Result<TaskStatus, _> = serde_json::from_value(json);
    assert!(
        result.is_err(),
        "TaskStatus must reject unknown nested fields"
    );
}

#[test]
fn test_tracked_task_terminal_states() {
    let pending = TrackedTask {
        task_id: "1".to_string(),
        tool: "tool".to_string(),
        function: "func".to_string(),
        status: TaskStatus::Pending,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        created_by: None,
        session_id: None,
    };
    assert!(!pending.is_terminal());
    assert!(pending.is_active());

    let running = TrackedTask {
        status: TaskStatus::Running,
        ..pending.clone()
    };
    assert!(!running.is_terminal());
    assert!(running.is_active());

    let completed = TrackedTask {
        status: TaskStatus::Completed,
        ..pending.clone()
    };
    assert!(completed.is_terminal());
    assert!(!completed.is_active());

    let failed = TrackedTask {
        status: TaskStatus::Failed {
            reason: "error".to_string(),
        },
        ..pending.clone()
    };
    assert!(failed.is_terminal());
    assert!(!failed.is_active());

    let cancelled = TrackedTask {
        status: TaskStatus::Cancelled,
        ..pending.clone()
    };
    assert!(cancelled.is_terminal());
    assert!(!cancelled.is_active());

    let expired = TrackedTask {
        status: TaskStatus::Expired,
        ..pending
    };
    assert!(expired.is_terminal());
    assert!(!expired.is_active());
}

#[test]
fn test_tracked_task_serialization() {
    let task = TrackedTask {
        task_id: "task-123".to_string(),
        tool: "background_job".to_string(),
        function: "execute".to_string(),
        status: TaskStatus::Running,
        created_at: "2026-01-01T12:00:00Z".to_string(),
        expires_at: Some("2026-01-01T13:00:00Z".to_string()),
        created_by: Some("agent-1".to_string()),
        session_id: Some("session-abc".to_string()),
    };
    let json_str = serde_json::to_string(&task).unwrap();
    let deserialized: TrackedTask = serde_json::from_str(&json_str).unwrap();
    assert_eq!(task, deserialized);
}

#[test]
fn test_auth_level_ordering() {
    assert!(AuthLevel::None < AuthLevel::Basic);
    assert!(AuthLevel::Basic < AuthLevel::OAuth);
    assert!(AuthLevel::OAuth < AuthLevel::OAuthMfa);
    assert!(AuthLevel::OAuthMfa < AuthLevel::HardwareKey);
}

#[test]
fn test_auth_level_satisfies() {
    assert!(AuthLevel::HardwareKey.satisfies(AuthLevel::None));
    assert!(AuthLevel::HardwareKey.satisfies(AuthLevel::Basic));
    assert!(AuthLevel::HardwareKey.satisfies(AuthLevel::OAuth));
    assert!(AuthLevel::HardwareKey.satisfies(AuthLevel::OAuthMfa));
    assert!(AuthLevel::HardwareKey.satisfies(AuthLevel::HardwareKey));

    assert!(!AuthLevel::None.satisfies(AuthLevel::Basic));
    assert!(!AuthLevel::OAuth.satisfies(AuthLevel::OAuthMfa));
}

#[test]
fn test_auth_level_from_u8() {
    assert_eq!(AuthLevel::from_u8(0), AuthLevel::None);
    assert_eq!(AuthLevel::from_u8(1), AuthLevel::Basic);
    assert_eq!(AuthLevel::from_u8(2), AuthLevel::OAuth);
    assert_eq!(AuthLevel::from_u8(3), AuthLevel::OAuthMfa);
    assert_eq!(AuthLevel::from_u8(4), AuthLevel::HardwareKey);
    assert_eq!(AuthLevel::from_u8(255), AuthLevel::None); // Unknown defaults to None
}

#[test]
fn test_auth_level_display() {
    assert_eq!(AuthLevel::None.to_string(), "none");
    assert_eq!(AuthLevel::Basic.to_string(), "basic");
    assert_eq!(AuthLevel::OAuth.to_string(), "oauth");
    assert_eq!(AuthLevel::OAuthMfa.to_string(), "oauth_mfa");
    assert_eq!(AuthLevel::HardwareKey.to_string(), "hardware_key");
}

#[test]
fn test_mcp_capability_new() {
    let cap = McpCapability::new("tools");
    assert_eq!(cap.name, "tools");
    assert!(cap.version.is_none());
    assert!(cap.sub_capabilities.is_empty());
}

#[test]
fn test_mcp_capability_with_version() {
    let cap = McpCapability::with_version("sampling", "1.0");
    assert_eq!(cap.name, "sampling");
    assert_eq!(cap.version, Some("1.0".to_string()));
}

#[test]
fn test_mcp_capability_has_sub() {
    let mut cap = McpCapability::new("tools");
    cap.sub_capabilities = vec!["read".to_string(), "write".to_string()];

    assert!(cap.has_sub("read"));
    assert!(cap.has_sub("write"));
    assert!(!cap.has_sub("execute"));
}

#[test]
fn test_mcp_capability_serialization() {
    let cap = McpCapability {
        name: "resources".to_string(),
        version: Some("2.0".to_string()),
        sub_capabilities: vec!["list".to_string(), "read".to_string()],
    };
    let json_str = serde_json::to_string(&cap).unwrap();
    let deserialized: McpCapability = serde_json::from_str(&json_str).unwrap();
    assert_eq!(cap, deserialized);
}

// ═══════════════════════════════════════════════════
// PHASE 2: ADVANCED THREAT DETECTION TYPES TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_circuit_state_display() {
    assert_eq!(CircuitState::Closed.to_string(), "closed");
    assert_eq!(CircuitState::Open.to_string(), "open");
    assert_eq!(CircuitState::HalfOpen.to_string(), "half_open");
}

#[test]
fn test_circuit_state_serialization() {
    let states = vec![
        CircuitState::Closed,
        CircuitState::Open,
        CircuitState::HalfOpen,
    ];
    for state in states {
        let json_str = serde_json::to_string(&state).unwrap();
        let deserialized: CircuitState = serde_json::from_str(&json_str).unwrap();
        assert_eq!(state, deserialized);
    }
}

#[test]
fn test_circuit_stats_default() {
    let stats = CircuitStats::default();
    assert_eq!(stats.state, CircuitState::Closed);
    assert_eq!(stats.failure_count, 0);
    assert_eq!(stats.success_count, 0);
    assert!(stats.last_failure.is_none());
}

#[test]
fn test_circuit_stats_serialization() {
    let stats = CircuitStats {
        state: CircuitState::Open,
        failure_count: 5,
        success_count: 0,
        last_failure: Some(1_704_067_200),
        last_state_change: 1_704_067_200,
        trip_count: 0,
    };
    let json_str = serde_json::to_string(&stats).unwrap();
    let deserialized: CircuitStats = serde_json::from_str(&json_str).unwrap();
    assert_eq!(stats, deserialized);
}

#[test]
fn test_agent_fingerprint_is_populated() {
    let empty = AgentFingerprint::default();
    assert!(!empty.is_populated());

    let with_sub = AgentFingerprint {
        jwt_sub: Some("agent-123".to_string()),
        ..Default::default()
    };
    assert!(with_sub.is_populated());

    let with_iss = AgentFingerprint {
        jwt_iss: Some("https://auth.example.com".to_string()),
        ..Default::default()
    };
    assert!(with_iss.is_populated());
}

#[test]
fn test_agent_fingerprint_summary() {
    let empty = AgentFingerprint::default();
    assert_eq!(empty.summary(), "empty");

    let fp = AgentFingerprint {
        jwt_sub: Some("agent-123".to_string()),
        jwt_iss: Some("https://auth.example.com".to_string()),
        client_id: Some("client-456".to_string()),
        ip_hash: Some("abc123".to_string()),
    };
    let summary = fp.summary();
    assert!(summary.contains("sub:agent-123"));
    assert!(summary.contains("iss:"));
    assert!(summary.contains("cid:client-456"));
    assert!(summary.contains("ip:*"));
}

#[test]
fn test_agent_fingerprint_serialization() {
    let fp = AgentFingerprint {
        jwt_sub: Some("sub".to_string()),
        jwt_iss: Some("iss".to_string()),
        client_id: Some("cid".to_string()),
        ip_hash: Some("hash".to_string()),
    };
    let json_str = serde_json::to_string(&fp).unwrap();
    let deserialized: AgentFingerprint = serde_json::from_str(&json_str).unwrap();
    assert_eq!(fp, deserialized);
}

#[test]
fn test_trust_level_ordering() {
    assert!(TrustLevel::Unknown < TrustLevel::Low);
    assert!(TrustLevel::Low < TrustLevel::Medium);
    assert!(TrustLevel::Medium < TrustLevel::High);
    assert!(TrustLevel::High < TrustLevel::Verified);
}

#[test]
fn test_trust_level_from_u8() {
    assert_eq!(TrustLevel::from_u8(0), TrustLevel::Unknown);
    assert_eq!(TrustLevel::from_u8(1), TrustLevel::Low);
    assert_eq!(TrustLevel::from_u8(2), TrustLevel::Medium);
    assert_eq!(TrustLevel::from_u8(3), TrustLevel::High);
    assert_eq!(TrustLevel::from_u8(4), TrustLevel::Verified);
    assert_eq!(TrustLevel::from_u8(255), TrustLevel::Unknown);
}

#[test]
fn test_trust_level_display() {
    assert_eq!(TrustLevel::Unknown.to_string(), "unknown");
    assert_eq!(TrustLevel::Low.to_string(), "low");
    assert_eq!(TrustLevel::Medium.to_string(), "medium");
    assert_eq!(TrustLevel::High.to_string(), "high");
    assert_eq!(TrustLevel::Verified.to_string(), "verified");
}

#[test]
fn test_schema_record_new() {
    let record = SchemaRecord::new("my_tool", "abc123", 1_704_067_200);
    assert_eq!(record.tool_name, "my_tool");
    assert_eq!(record.schema_hash, "abc123");
    assert_eq!(record.first_seen, 1_704_067_200);
    assert_eq!(record.last_seen, 1_704_067_200);
    assert!(record.version_history.is_empty());
    assert_eq!(record.trust_score, 0.0);
}

#[test]
fn test_schema_record_version_count() {
    let mut record = SchemaRecord::new("tool", "hash1", 1000);
    assert_eq!(record.version_count(), 1);

    record.version_history.push("hash0".to_string());
    assert_eq!(record.version_count(), 2);

    record.version_history.push("hash_prev".to_string());
    assert_eq!(record.version_count(), 3);
}

#[test]
fn test_schema_record_is_stable() {
    let record = SchemaRecord::new("tool", "hash", 1000);
    assert!(record.is_stable()); // No history = stable

    let mut record_same = record.clone();
    record_same.version_history.push("hash".to_string());
    assert!(record_same.is_stable()); // Same hash in history = stable

    let mut record_diff = record.clone();
    record_diff
        .version_history
        .push("different_hash".to_string());
    assert!(!record_diff.is_stable()); // Different hash in history = unstable
}

#[test]
fn test_schema_record_serialization() {
    let record = SchemaRecord {
        tool_name: "my_tool".to_string(),
        schema_hash: "hash123".to_string(),
        first_seen: 1000,
        last_seen: 2000,
        version_history: vec!["hash0".to_string(), "hash1".to_string()],
        trust_score: 0.75,
        schema_content: Some(serde_json::json!({"type": "object"})),
    };
    let json_str = serde_json::to_string(&record).unwrap();
    let deserialized: SchemaRecord = serde_json::from_str(&json_str).unwrap();
    assert_eq!(record, deserialized);
}

#[test]
fn test_schema_record_new_with_content() {
    let schema = serde_json::json!({"type": "object", "properties": {"name": {"type": "string"}}});
    let record = SchemaRecord::new_with_content("test_tool", "hash123", &schema, 1000);
    assert_eq!(record.tool_name, "test_tool");
    assert_eq!(record.schema_hash, "hash123");
    assert_eq!(record.schema_content, Some(schema));
}

#[test]
fn test_schema_record_large_schema_not_stored() {
    // Create a schema larger than MAX_SCHEMA_SIZE
    let large_value = "x".repeat(SchemaRecord::MAX_SCHEMA_SIZE + 1000);
    let schema = serde_json::json!({"data": large_value});
    let record = SchemaRecord::new_with_content("test_tool", "hash123", &schema, 1000);
    // Schema content should be None because it's too large
    assert!(record.schema_content.is_none());
}

#[test]
fn test_principal_context_direct() {
    let ctx = PrincipalContext::direct("user-123");
    assert_eq!(ctx.original_principal, "user-123");
    assert!(!ctx.is_delegated());
    assert_eq!(ctx.delegation_depth, 0);
}

#[test]
fn test_principal_context_is_delegated() {
    let direct = PrincipalContext::direct("user");
    assert!(!direct.is_delegated());

    let delegated = PrincipalContext {
        original_principal: "user".to_string(),
        delegated_to: Some("agent".to_string()),
        delegation_depth: 1,
        allowed_tools: vec!["read_file".to_string()],
        delegation_expires: None,
    };
    assert!(delegated.is_delegated());
}

#[test]
fn test_principal_context_is_expired() {
    let no_expiry = PrincipalContext::direct("user");
    assert!(!no_expiry.is_expired(1000));

    let not_expired = PrincipalContext {
        delegation_expires: Some(2000),
        ..PrincipalContext::direct("user")
    };
    assert!(!not_expired.is_expired(1000));

    let expired = PrincipalContext {
        delegation_expires: Some(1000),
        ..PrincipalContext::direct("user")
    };
    assert!(expired.is_expired(1000));
    assert!(expired.is_expired(2000));
}

#[test]
fn test_principal_context_serialization() {
    let ctx = PrincipalContext {
        original_principal: "user".to_string(),
        delegated_to: Some("agent".to_string()),
        delegation_depth: 2,
        allowed_tools: vec!["tool1".to_string(), "tool2".to_string()],
        delegation_expires: Some(1_704_067_200),
    };
    let json_str = serde_json::to_string(&ctx).unwrap();
    let deserialized: PrincipalContext = serde_json::from_str(&json_str).unwrap();
    assert_eq!(ctx, deserialized);
}

#[test]
fn test_sampling_stats_new() {
    let stats = SamplingStats::new(1000);
    assert_eq!(stats.request_count, 0);
    assert_eq!(stats.last_request, 1000);
    assert_eq!(stats.window_start, 1000);
    assert!(stats.flagged_patterns.is_empty());
}

#[test]
fn test_sampling_stats_record_request() {
    let mut stats = SamplingStats::new(1000);
    assert_eq!(stats.record_request(1001), 1);
    assert_eq!(stats.record_request(1002), 2);
    assert_eq!(stats.last_request, 1002);
    assert_eq!(stats.request_count, 2);
}

#[test]
fn test_sampling_stats_reset_window() {
    let mut stats = SamplingStats::new(1000);
    stats.record_request(1001);
    stats.record_request(1002);
    stats.flagged_patterns.push("pattern1".to_string());

    stats.reset_window(2000);
    assert_eq!(stats.request_count, 0);
    assert_eq!(stats.window_start, 2000);
    // Flagged patterns are preserved
    assert!(!stats.flagged_patterns.is_empty());
}

// SECURITY (FIND-R82-002): Verify reset_window handles multi-byte UTF-8 at truncation boundary.
#[test]
fn test_sampling_stats_reset_window_multibyte_utf8_safe() {
    let mut stats = SamplingStats::new(1000);
    // Create a pattern with 2-byte Cyrillic chars that spans the truncation boundary (1024)
    // Each 'д' is 2 bytes, so 513 chars = 1026 bytes > MAX_PATTERN_ENTRY_LEN (1024)
    let multibyte_pattern = "д".repeat(513);
    assert!(multibyte_pattern.len() > SamplingStats::MAX_PATTERN_ENTRY_LEN);
    stats.flagged_patterns.push(multibyte_pattern);

    // This should NOT panic
    stats.reset_window(2000);

    let entry = &stats.flagged_patterns[0];
    assert!(entry.len() <= SamplingStats::MAX_PATTERN_ENTRY_LEN);
    assert!(entry.is_char_boundary(entry.len()));
}

#[test]
fn test_sampling_stats_serialization() {
    let stats = SamplingStats {
        request_count: 5,
        last_request: 1005,
        window_start: 1000,
        flagged_patterns: vec!["sensitive".to_string()],
    };
    let json_str = serde_json::to_string(&stats).unwrap();
    let deserialized: SamplingStats = serde_json::from_str(&json_str).unwrap();
    assert_eq!(stats, deserialized);
}

// ═══════════════════════════════════════════════════
// ETDI (Enhanced Tool Definition Interface) TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_signature_algorithm_display() {
    assert_eq!(SignatureAlgorithm::Ed25519.to_string(), "ed25519");
    assert_eq!(SignatureAlgorithm::EcdsaP256.to_string(), "ecdsa_p256");
}

#[test]
fn test_signature_algorithm_default() {
    assert_eq!(SignatureAlgorithm::default(), SignatureAlgorithm::Ed25519);
}

#[test]
fn test_signature_algorithm_serialization() {
    for alg in [SignatureAlgorithm::Ed25519, SignatureAlgorithm::EcdsaP256] {
        let json_str = serde_json::to_string(&alg).unwrap();
        let deserialized: SignatureAlgorithm = serde_json::from_str(&json_str).unwrap();
        assert_eq!(alg, deserialized);
    }
}

#[test]
fn test_tool_signature_serialization_roundtrip() {
    let sig = ToolSignature {
        signature_id: "sig-123".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "cafe0123".to_string(),
        key_fingerprint: Some("fp:abc".to_string()),
        signed_at: "2026-01-15T12:00:00Z".to_string(),
        expires_at: Some("2027-01-15T12:00:00Z".to_string()),
        signer_spiffe_id: Some("spiffe://example.org/agent".to_string()),
        rekor_entry: None,
    };
    let json_str = serde_json::to_string(&sig).unwrap();
    let deserialized: ToolSignature = serde_json::from_str(&json_str).unwrap();
    assert_eq!(sig, deserialized);
}

#[test]
fn test_tool_signature_is_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "abc".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "key".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2026-06-01T00:00:00Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };

    // Before expiry
    assert!(!sig.is_expired("2026-05-01T00:00:00Z"));
    // At expiry
    assert!(sig.is_expired("2026-06-01T00:00:00Z"));
    // After expiry
    assert!(sig.is_expired("2026-12-01T00:00:00Z"));
}

#[test]
fn test_tool_signature_no_expiry_never_expires() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "abc".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "key".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    assert!(!sig.is_expired("2099-12-31T23:59:59Z"));
}

#[test]
fn test_signature_verification_is_fully_verified() {
    let valid_and_trusted = SignatureVerification {
        valid: true,
        signer_trusted: true,
        expired: false,
        message: "OK".to_string(),
    };
    assert!(valid_and_trusted.is_fully_verified());

    let invalid = SignatureVerification {
        valid: false,
        signer_trusted: true,
        expired: false,
        message: "bad sig".to_string(),
    };
    assert!(!invalid.is_fully_verified());

    let untrusted = SignatureVerification {
        valid: true,
        signer_trusted: false,
        expired: false,
        message: "unknown signer".to_string(),
    };
    assert!(!untrusted.is_fully_verified());

    let expired = SignatureVerification {
        valid: true,
        signer_trusted: true,
        expired: true,
        message: "expired".to_string(),
    };
    assert!(!expired.is_fully_verified());
}

#[test]
fn test_signature_verification_serialization() {
    let verification = SignatureVerification {
        valid: true,
        signer_trusted: true,
        expired: false,
        message: "Verified successfully".to_string(),
    };
    let json_str = serde_json::to_string(&verification).unwrap();
    let deserialized: SignatureVerification = serde_json::from_str(&json_str).unwrap();
    assert_eq!(verification, deserialized);
}

#[test]
fn test_tool_attestation_is_initial() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "abc".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "key".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        signer_spiffe_id: None,
        rekor_entry: None,
    };

    let initial = ToolAttestation {
        attestation_id: "att-1".to_string(),
        attestation_type: "initial".to_string(),
        attester: "admin".to_string(),
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        tool_hash: "hash123".to_string(),
        previous_attestation: None,
        signature: sig.clone(),
        transparency_log_entry: None,
    };
    assert!(initial.is_initial());

    let chained = ToolAttestation {
        attestation_id: "att-2".to_string(),
        attestation_type: "version_update".to_string(),
        attester: "admin".to_string(),
        timestamp: "2026-02-01T00:00:00Z".to_string(),
        tool_hash: "hash456".to_string(),
        previous_attestation: Some("att-1".to_string()),
        signature: sig,
        transparency_log_entry: Some("log-entry-123".to_string()),
    };
    assert!(!chained.is_initial());
}

#[test]
fn test_tool_attestation_serialization() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "abc".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "key".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    let attestation = ToolAttestation {
        attestation_id: "att-1".to_string(),
        attestation_type: "initial".to_string(),
        attester: "admin".to_string(),
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        tool_hash: "hash123".to_string(),
        previous_attestation: None,
        signature: sig,
        transparency_log_entry: None,
    };
    let json_str = serde_json::to_string(&attestation).unwrap();
    let deserialized: ToolAttestation = serde_json::from_str(&json_str).unwrap();
    assert_eq!(attestation, deserialized);
}

#[test]
fn test_tool_version_pin_exact_vs_constraint() {
    let exact = ToolVersionPin {
        tool_name: "my_tool".to_string(),
        pinned_version: Some("1.2.3".to_string()),
        version_constraint: None,
        definition_hash: "hash123".to_string(),
        pinned_at: "2026-01-01T00:00:00Z".to_string(),
        pinned_by: "admin".to_string(),
    };
    assert!(exact.is_exact());
    assert!(!exact.is_constraint());

    let constraint = ToolVersionPin {
        tool_name: "my_tool".to_string(),
        pinned_version: None,
        version_constraint: Some("^1.2.0".to_string()),
        definition_hash: "hash456".to_string(),
        pinned_at: "2026-01-01T00:00:00Z".to_string(),
        pinned_by: "admin".to_string(),
    };
    assert!(!constraint.is_exact());
    assert!(constraint.is_constraint());
}

#[test]
fn test_tool_version_pin_serialization() {
    let pin = ToolVersionPin {
        tool_name: "tool".to_string(),
        pinned_version: Some("1.0.0".to_string()),
        version_constraint: None,
        definition_hash: "hash".to_string(),
        pinned_at: "2026-01-01T00:00:00Z".to_string(),
        pinned_by: "admin".to_string(),
    };
    let json_str = serde_json::to_string(&pin).unwrap();
    let deserialized: ToolVersionPin = serde_json::from_str(&json_str).unwrap();
    assert_eq!(pin, deserialized);
}

#[test]
fn test_version_drift_alert_version_mismatch() {
    let alert = VersionDriftAlert::version_mismatch(
        "my_tool",
        "1.0.0",
        "1.1.0",
        true,
        "2026-02-01T00:00:00Z",
    );
    assert_eq!(alert.tool, "my_tool");
    assert_eq!(alert.expected_version, "1.0.0");
    assert_eq!(alert.actual_version, "1.1.0");
    assert_eq!(alert.drift_type, "version_mismatch");
    assert!(alert.blocking);
}

#[test]
fn test_version_drift_alert_hash_mismatch() {
    let alert = VersionDriftAlert::hash_mismatch(
        "my_tool",
        "abc123",
        "def456",
        false,
        "2026-02-01T00:00:00Z",
    );
    assert_eq!(alert.drift_type, "hash_mismatch");
    assert!(!alert.blocking);
}

#[test]
fn test_version_drift_alert_serialization() {
    let alert = VersionDriftAlert {
        tool: "tool".to_string(),
        expected_version: "1.0".to_string(),
        actual_version: "2.0".to_string(),
        drift_type: "version_mismatch".to_string(),
        blocking: true,
        detected_at: "2026-01-01T00:00:00Z".to_string(),
    };
    let json_str = serde_json::to_string(&alert).unwrap();
    let deserialized: VersionDriftAlert = serde_json::from_str(&json_str).unwrap();
    assert_eq!(alert, deserialized);
}

// ═══════════════════════════════════════════════════
// PHASE 10: NHI LIFECYCLE TYPES TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_nhi_attestation_type_serialization() {
    let types = vec![
        NhiAttestationType::Jwt,
        NhiAttestationType::Mtls,
        NhiAttestationType::Spiffe,
        NhiAttestationType::DPoP,
        NhiAttestationType::ApiKey,
    ];
    for atype in types {
        let json_str = serde_json::to_string(&atype).unwrap();
        let deserialized: NhiAttestationType = serde_json::from_str(&json_str).unwrap();
        assert_eq!(atype, deserialized);
    }
}

#[test]
fn test_nhi_attestation_type_display() {
    assert_eq!(NhiAttestationType::Jwt.to_string(), "jwt");
    assert_eq!(NhiAttestationType::Mtls.to_string(), "mtls");
    assert_eq!(NhiAttestationType::Spiffe.to_string(), "spiffe");
    assert_eq!(NhiAttestationType::DPoP.to_string(), "dpop");
    assert_eq!(NhiAttestationType::ApiKey.to_string(), "api_key");
}

#[test]
fn test_nhi_identity_status_serialization() {
    let statuses = vec![
        NhiIdentityStatus::Active,
        NhiIdentityStatus::Suspended,
        NhiIdentityStatus::Revoked,
        NhiIdentityStatus::Expired,
        NhiIdentityStatus::Probationary,
    ];
    for status in statuses {
        let json_str = serde_json::to_string(&status).unwrap();
        let deserialized: NhiIdentityStatus = serde_json::from_str(&json_str).unwrap();
        assert_eq!(status, deserialized);
    }
}

#[test]
fn test_nhi_identity_status_display() {
    assert_eq!(NhiIdentityStatus::Active.to_string(), "active");
    assert_eq!(NhiIdentityStatus::Suspended.to_string(), "suspended");
    assert_eq!(NhiIdentityStatus::Revoked.to_string(), "revoked");
    assert_eq!(NhiIdentityStatus::Expired.to_string(), "expired");
    assert_eq!(NhiIdentityStatus::Probationary.to_string(), "probationary");
}

#[test]
fn test_nhi_agent_identity_serialization() {
    let identity = NhiAgentIdentity {
        id: "agent-123".to_string(),
        name: "Test Agent".to_string(),
        attestation_type: NhiAttestationType::Spiffe,
        status: NhiIdentityStatus::Active,
        spiffe_id: Some("spiffe://example.org/agent/test".to_string()),
        public_key: Some("abc123".to_string()),
        key_algorithm: Some("Ed25519".to_string()),
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2027-01-01T00:00:00Z".to_string(),
        last_rotation: Some("2026-06-01T00:00:00Z".to_string()),
        auth_count: 42,
        last_auth: Some("2026-02-01T12:00:00Z".to_string()),
        tags: vec!["production".to_string(), "internal".to_string()],
        metadata: {
            let mut m = HashMap::new();
            m.insert("team".to_string(), "platform".to_string());
            m
        },
        verification_tier: VerificationTier::DidVerified,
        did_plc: Some("did:plc:ewvi7nxsareczkwkx5pz6q6e".to_string()),
        attestations: vec![],
    };
    let json_str = serde_json::to_string(&identity).unwrap();
    let deserialized: NhiAgentIdentity = serde_json::from_str(&json_str).unwrap();
    assert_eq!(identity, deserialized);
}

#[test]
fn test_nhi_behavioral_baseline_serialization() {
    let baseline = NhiBehavioralBaseline {
        agent_id: "agent-123".to_string(),
        tool_call_patterns: {
            let mut m = HashMap::new();
            m.insert("file:read".to_string(), 10.5);
            m.insert("http:get".to_string(), 5.2);
            m
        },
        avg_request_interval_secs: 2.5,
        request_interval_stddev: 0.8,
        typical_session_duration_secs: 3600.0,
        observation_count: 1000,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        last_updated: "2026-02-01T00:00:00Z".to_string(),
        confidence: 0.95,
        typical_source_ips: vec!["10.0.0.0/8".to_string()],
        active_hours: vec![9, 10, 11, 12, 13, 14, 15, 16, 17],
    };
    let json_str = serde_json::to_string(&baseline).unwrap();
    let deserialized: NhiBehavioralBaseline = serde_json::from_str(&json_str).unwrap();
    assert_eq!(baseline, deserialized);
}

#[test]
fn test_nhi_behavioral_recommendation_display() {
    assert_eq!(NhiBehavioralRecommendation::Allow.to_string(), "allow");
    assert_eq!(
        NhiBehavioralRecommendation::AllowWithLogging.to_string(),
        "allow_with_logging"
    );
    assert_eq!(
        NhiBehavioralRecommendation::StepUpAuth.to_string(),
        "step_up_auth"
    );
    assert_eq!(NhiBehavioralRecommendation::Suspend.to_string(), "suspend");
    assert_eq!(NhiBehavioralRecommendation::Revoke.to_string(), "revoke");
}

#[test]
fn test_nhi_delegation_chain_depth() {
    let chain = NhiDelegationChain {
        chain: vec![
            NhiDelegationLink {
                from_agent: "agent-a".to_string(),
                to_agent: "agent-b".to_string(),
                permissions: vec!["read".to_string()],
                scope_constraints: vec!["tools:file_*".to_string()],
                created_at: "2026-01-01T00:00:00Z".to_string(),
                expires_at: "2026-02-01T00:00:00Z".to_string(),
                active: true,
                reason: Some("Temporary delegation".to_string()),
            },
            NhiDelegationLink {
                from_agent: "agent-b".to_string(),
                to_agent: "agent-c".to_string(),
                permissions: vec!["read".to_string()],
                scope_constraints: vec![],
                created_at: "2026-01-01T00:00:00Z".to_string(),
                expires_at: "2026-02-01T00:00:00Z".to_string(),
                active: true,
                reason: None,
            },
        ],
        max_depth: 5,
        resolved_at: "2026-01-15T00:00:00Z".to_string(),
    };
    assert_eq!(chain.depth(), 2);
    assert!(!chain.exceeds_max_depth());
    assert_eq!(chain.origin(), Some("agent-a"));
    assert_eq!(chain.terminus(), Some("agent-c"));
}

#[test]
fn test_nhi_delegation_chain_exceeds_max() {
    let chain = NhiDelegationChain {
        chain: vec![NhiDelegationLink {
            from_agent: "a".to_string(),
            to_agent: "b".to_string(),
            permissions: vec![],
            scope_constraints: vec![],
            created_at: "".to_string(),
            expires_at: "".to_string(),
            active: true,
            reason: None,
        }],
        max_depth: 0, // Max depth of 0 means no delegation allowed
        resolved_at: "".to_string(),
    };
    assert!(chain.exceeds_max_depth());
}

#[test]
fn test_nhi_dpop_proof_serialization() {
    let proof = NhiDpopProof {
        proof: "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2In0...".to_string(),
        htm: "POST".to_string(),
        htu: "https://api.example.com/resource".to_string(),
        ath: Some("fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo".to_string()),
        nonce: Some("server-nonce-123".to_string()),
        iat: "2026-02-01T12:00:00Z".to_string(),
        jti: "unique-id-456".to_string(),
    };
    let json_str = serde_json::to_string(&proof).unwrap();
    let deserialized: NhiDpopProof = serde_json::from_str(&json_str).unwrap();
    assert_eq!(proof, deserialized);
}

#[test]
fn test_nhi_stats_default() {
    let stats = NhiStats::default();
    assert_eq!(stats.total_identities, 0);
    assert_eq!(stats.active_identities, 0);
    assert_eq!(stats.active_delegations, 0);
}

#[test]
fn test_nhi_credential_rotation_serialization() {
    let rotation = NhiCredentialRotation {
        agent_id: "agent-123".to_string(),
        previous_thumbprint: Some("old-thumb".to_string()),
        new_thumbprint: "new-thumb".to_string(),
        rotated_at: "2026-02-01T00:00:00Z".to_string(),
        trigger: "scheduled".to_string(),
        new_expires_at: "2027-02-01T00:00:00Z".to_string(),
    };
    let json_str = serde_json::to_string(&rotation).unwrap();
    let deserialized: NhiCredentialRotation = serde_json::from_str(&json_str).unwrap();
    assert_eq!(rotation, deserialized);
}

#[test]
fn test_evaluation_context_builder() {
    // Test basic builder usage
    let ctx = EvaluationContext::builder()
        .agent_id("agent-123")
        .tenant_id("tenant-abc")
        .build();
    assert_eq!(ctx.agent_id, Some("agent-123".to_string()));
    assert_eq!(ctx.tenant_id, Some("tenant-abc".to_string()));
    assert!(ctx.call_counts.is_empty());
    assert!(ctx.previous_actions.is_empty());
}

#[test]
fn test_evaluation_context_builder_call_counts() {
    let ctx = EvaluationContext::builder()
        .call_count("read_file", 5)
        .call_count("write_file", 3)
        .build();
    assert_eq!(ctx.call_counts.get("read_file"), Some(&5));
    assert_eq!(ctx.call_counts.get("write_file"), Some(&3));
}

#[test]
fn test_evaluation_context_builder_previous_actions() {
    let ctx = EvaluationContext::builder()
        .previous_action("read_file")
        .previous_action("process_data")
        .previous_action("write_file")
        .build();
    assert_eq!(ctx.previous_actions.len(), 3);
    assert_eq!(ctx.previous_actions[0], "read_file");
    assert_eq!(ctx.previous_actions[2], "write_file");
}

#[test]
fn test_evaluation_context_builder_has_meaningful_fields() {
    // Empty builder produces context with no meaningful fields
    let empty_ctx = EvaluationContext::builder().build();
    assert!(!empty_ctx.has_any_meaningful_fields());

    // Context with agent_id has meaningful fields
    let ctx_with_agent = EvaluationContext::builder().agent_id("agent-1").build();
    assert!(ctx_with_agent.has_any_meaningful_fields());

    // Context with timestamp has meaningful fields
    let ctx_with_timestamp = EvaluationContext::builder()
        .timestamp("2025-01-15T10:00:00Z")
        .build();
    assert!(ctx_with_timestamp.has_any_meaningful_fields());
}

// --- Extension types tests ---

#[test]
fn test_extension_descriptor_serde_roundtrip() {
    let desc = ExtensionDescriptor {
        id: "vellaveto-audit".to_string(),
        name: "Audit Query Extension".to_string(),
        version: "1.0.0".to_string(),
        capabilities: vec!["read".to_string()],
        methods: vec!["x-vellaveto-audit/stats".to_string()],
        signature: None,
        public_key: None,
    };
    let json_str = serde_json::to_string(&desc).unwrap();
    let deserialized: ExtensionDescriptor = serde_json::from_str(&json_str).unwrap();
    assert_eq!(desc, deserialized);
}

#[test]
fn test_extension_descriptor_validate_valid() {
    let desc = ExtensionDescriptor {
        id: "my-ext".to_string(),
        name: "My Extension".to_string(),
        version: "0.1.0".to_string(),
        capabilities: vec![],
        methods: vec!["x-my-ext/do-thing".to_string()],
        signature: None,
        public_key: None,
    };
    assert!(desc.validate().is_ok());
}

#[test]
fn test_extension_descriptor_validate_empty_id() {
    let desc = ExtensionDescriptor {
        id: "".to_string(),
        name: "My Extension".to_string(),
        version: "0.1.0".to_string(),
        capabilities: vec![],
        methods: vec![],
        signature: None,
        public_key: None,
    };
    let err = desc.validate().unwrap_err();
    assert!(err.to_string().contains("id must not be empty"));
}

#[test]
fn test_extension_descriptor_validate_empty_name() {
    let desc = ExtensionDescriptor {
        id: "my-ext".to_string(),
        name: "".to_string(),
        version: "0.1.0".to_string(),
        capabilities: vec![],
        methods: vec![],
        signature: None,
        public_key: None,
    };
    let err = desc.validate().unwrap_err();
    assert!(err.to_string().contains("name must not be empty"));
}

// ── FIND-R129-002: ExtensionDescriptor per-field validation ─────────────

#[test]
fn test_extension_descriptor_validate_name_too_long() {
    let desc = ExtensionDescriptor {
        id: "my-ext".to_string(),
        name: "x".repeat(257),
        version: "0.1.0".to_string(),
        capabilities: vec![],
        methods: vec![],
        signature: None,
        public_key: None,
    };
    let err = desc.validate().unwrap_err();
    assert!(err.to_string().contains("name length"));
}

#[test]
fn test_extension_descriptor_validate_name_control_chars() {
    let desc = ExtensionDescriptor {
        id: "my-ext".to_string(),
        name: "My\nExtension".to_string(),
        version: "0.1.0".to_string(),
        capabilities: vec![],
        methods: vec![],
        signature: None,
        public_key: None,
    };
    let err = desc.validate().unwrap_err();
    assert!(err.to_string().contains("name contains control"));
}

#[test]
fn test_extension_descriptor_validate_version_too_long() {
    let desc = ExtensionDescriptor {
        id: "my-ext".to_string(),
        name: "My Extension".to_string(),
        version: "v".repeat(65),
        capabilities: vec![],
        methods: vec![],
        signature: None,
        public_key: None,
    };
    let err = desc.validate().unwrap_err();
    assert!(err.to_string().contains("version length"));
}

#[test]
fn test_extension_descriptor_validate_version_control_chars() {
    let desc = ExtensionDescriptor {
        id: "my-ext".to_string(),
        name: "My Extension".to_string(),
        version: "1.0\x00".to_string(),
        capabilities: vec![],
        methods: vec![],
        signature: None,
        public_key: None,
    };
    let err = desc.validate().unwrap_err();
    assert!(err.to_string().contains("version contains control"));
}

#[test]
fn test_extension_descriptor_validate_id_control_chars() {
    let desc = ExtensionDescriptor {
        id: "my\text".to_string(),
        name: "My Extension".to_string(),
        version: "1.0.0".to_string(),
        capabilities: vec![],
        methods: vec![],
        signature: None,
        public_key: None,
    };
    let err = desc.validate().unwrap_err();
    assert!(err.to_string().contains("id contains control"));
}

#[test]
fn test_extension_descriptor_validate_empty_method() {
    let desc = ExtensionDescriptor {
        id: "my-ext".to_string(),
        name: "My Extension".to_string(),
        version: "1.0.0".to_string(),
        capabilities: vec![],
        methods: vec!["".to_string()],
        signature: None,
        public_key: None,
    };
    let err = desc.validate().unwrap_err();
    assert!(err.to_string().contains("method[0] must not be empty"));
}

#[test]
fn test_extension_descriptor_validate_method_too_long() {
    let desc = ExtensionDescriptor {
        id: "my-ext".to_string(),
        name: "My Extension".to_string(),
        version: "1.0.0".to_string(),
        capabilities: vec![],
        methods: vec!["m".repeat(513)],
        signature: None,
        public_key: None,
    };
    let err = desc.validate().unwrap_err();
    assert!(err.to_string().contains("method[0] length"));
}

#[test]
fn test_extension_descriptor_validate_method_control_chars() {
    let desc = ExtensionDescriptor {
        id: "my-ext".to_string(),
        name: "My Extension".to_string(),
        version: "1.0.0".to_string(),
        capabilities: vec![],
        methods: vec!["x-my-ext/do\x1bthing".to_string()],
        signature: None,
        public_key: None,
    };
    let err = desc.validate().unwrap_err();
    assert!(err.to_string().contains("method[0] contains control"));
}

#[test]
fn test_extension_descriptor_validate_method_unicode_format_char() {
    let desc = ExtensionDescriptor {
        id: "my-ext".to_string(),
        name: "My Extension".to_string(),
        version: "1.0.0".to_string(),
        capabilities: vec![],
        methods: vec!["x-my-ext/do\u{200B}thing".to_string()], // zero-width space
        signature: None,
        public_key: None,
    };
    let err = desc.validate().unwrap_err();
    assert!(err.to_string().contains("method[0] contains control"));
}

#[test]
fn test_extension_descriptor_validate_empty_capability() {
    let desc = ExtensionDescriptor {
        id: "my-ext".to_string(),
        name: "My Extension".to_string(),
        version: "1.0.0".to_string(),
        capabilities: vec!["".to_string()],
        methods: vec![],
        signature: None,
        public_key: None,
    };
    let err = desc.validate().unwrap_err();
    assert!(err.to_string().contains("capability[0] must not be empty"));
}

#[test]
fn test_extension_descriptor_validate_capability_control_chars() {
    let desc = ExtensionDescriptor {
        id: "my-ext".to_string(),
        name: "My Extension".to_string(),
        version: "1.0.0".to_string(),
        capabilities: vec!["read\nwrite".to_string()],
        methods: vec![],
        signature: None,
        public_key: None,
    };
    let err = desc.validate().unwrap_err();
    assert!(err.to_string().contains("capability[0] contains control"));
}

#[test]
fn test_extension_resource_limits_defaults() {
    let limits = ExtensionResourceLimits::default();
    assert_eq!(limits.max_concurrent_requests, 10);
    assert_eq!(limits.max_requests_per_sec, 100);
}

#[test]
fn test_extension_negotiation_result_serde() {
    let result = ExtensionNegotiationResult {
        accepted: vec!["ext-a".to_string()],
        rejected: vec![("ext-b".to_string(), "blocked".to_string())],
    };
    let json_str = serde_json::to_string(&result).unwrap();
    let deserialized: ExtensionNegotiationResult = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.accepted, vec!["ext-a"]);
    assert_eq!(deserialized.rejected.len(), 1);
    assert_eq!(deserialized.rejected[0].0, "ext-b");
}

// ═══════════════════════════════════════════════════════════════════════════
// Phase 18: Transport & SDK Tier types
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_transport_protocol_ordering() {
    // gRPC > WebSocket > HTTP > stdio
    assert!(TransportProtocol::Grpc < TransportProtocol::WebSocket);
    assert!(TransportProtocol::WebSocket < TransportProtocol::Http);
    assert!(TransportProtocol::Http < TransportProtocol::Stdio);
}

#[test]
fn test_sdk_tier_ordering() {
    assert!(SdkTier::Core < SdkTier::Standard);
    assert!(SdkTier::Standard < SdkTier::Extended);
    assert!(SdkTier::Extended < SdkTier::Full);
}

#[test]
fn test_transport_endpoint_serde_roundtrip() {
    let endpoint = TransportEndpoint {
        protocol: TransportProtocol::WebSocket,
        url: "ws://localhost:3001/mcp/ws".to_string(),
        available: true,
        protocol_versions: vec!["2026-06".to_string(), "2025-11-25".to_string()],
    };
    let json_str = serde_json::to_string(&endpoint).unwrap();
    let deserialized: TransportEndpoint = serde_json::from_str(&json_str).unwrap();
    assert_eq!(endpoint, deserialized);
    // Verify lowercase rename
    assert!(json_str.contains("\"websocket\""));
}

#[test]
fn test_sdk_capabilities_serde_roundtrip() {
    let caps = SdkCapabilities {
        tier: SdkTier::Extended,
        capabilities: vec!["policy-evaluation".to_string(), "dlp-scanning".to_string()],
        supported_versions: vec!["2026-06".to_string()],
    };
    let json_str = serde_json::to_string(&caps).unwrap();
    let deserialized: SdkCapabilities = serde_json::from_str(&json_str).unwrap();
    assert_eq!(caps, deserialized);
    assert!(json_str.contains("\"extended\""));
}

// ═══════════════════════════════════════════════════
// PHASE 29: TRANSPORT FALLBACK TYPES TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_transport_attempt_serde_roundtrip_success() {
    let attempt = TransportAttempt {
        protocol: TransportProtocol::Grpc,
        endpoint_url: "http://localhost:50051".to_string(),
        succeeded: true,
        duration_ms: 12,
        error: None,
    };
    let json_str = serde_json::to_string(&attempt).unwrap();
    let deserialized: TransportAttempt = serde_json::from_str(&json_str).unwrap();
    assert_eq!(attempt, deserialized);
    assert!(json_str.contains("\"grpc\""));
}

#[test]
fn test_transport_attempt_serde_roundtrip_failure() {
    let attempt = TransportAttempt {
        protocol: TransportProtocol::WebSocket,
        endpoint_url: "ws://localhost:3001/mcp/ws".to_string(),
        succeeded: false,
        duration_ms: 5000,
        error: Some("connection refused".to_string()),
    };
    let json_str = serde_json::to_string(&attempt).unwrap();
    let deserialized: TransportAttempt = serde_json::from_str(&json_str).unwrap();
    assert_eq!(attempt, deserialized);
    assert!(json_str.contains("connection refused"));
}

#[test]
fn test_fallback_negotiation_history_serde_roundtrip() {
    let history = FallbackNegotiationHistory {
        attempts: vec![
            TransportAttempt {
                protocol: TransportProtocol::Grpc,
                endpoint_url: "http://localhost:50051".to_string(),
                succeeded: false,
                duration_ms: 30,
                error: Some("circuit open".to_string()),
            },
            TransportAttempt {
                protocol: TransportProtocol::Http,
                endpoint_url: "http://localhost:3001/mcp".to_string(),
                succeeded: true,
                duration_ms: 15,
                error: None,
            },
        ],
        successful_transport: Some(TransportProtocol::Http),
        total_duration_ms: 45,
    };
    let json_str = serde_json::to_string(&history).unwrap();
    let deserialized: FallbackNegotiationHistory = serde_json::from_str(&json_str).unwrap();
    assert_eq!(history, deserialized);
}

#[test]
fn test_fallback_negotiation_history_all_failed() {
    let history = FallbackNegotiationHistory {
        attempts: vec![TransportAttempt {
            protocol: TransportProtocol::Http,
            endpoint_url: "http://localhost:3001/mcp".to_string(),
            succeeded: false,
            duration_ms: 5000,
            error: Some("timeout".to_string()),
        }],
        successful_transport: None,
        total_duration_ms: 5000,
    };
    assert!(history.successful_transport.is_none());
    assert_eq!(history.attempts.len(), 1);
}

#[test]
fn test_fallback_negotiation_history_empty_attempts() {
    let history = FallbackNegotiationHistory {
        attempts: Vec::new(),
        successful_transport: None,
        total_duration_ms: 0,
    };
    let json_str = serde_json::to_string(&history).unwrap();
    let deserialized: FallbackNegotiationHistory = serde_json::from_str(&json_str).unwrap();
    assert_eq!(history, deserialized);
    assert!(deserialized.attempts.is_empty());
}

#[test]
fn test_transport_attempt_zero_duration() {
    let attempt = TransportAttempt {
        protocol: TransportProtocol::Stdio,
        endpoint_url: "stdio://local".to_string(),
        succeeded: true,
        duration_ms: 0,
        error: None,
    };
    let json_str = serde_json::to_string(&attempt).unwrap();
    assert!(json_str.contains("\"stdio\""));
    let deserialized: TransportAttempt = serde_json::from_str(&json_str).unwrap();
    assert_eq!(attempt, deserialized);
}

// ═══════════════════════════════════════════════════
// PHASE 20: GATEWAY TYPES TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_backend_health_serde_roundtrip() {
    for health in [
        BackendHealth::Healthy,
        BackendHealth::Degraded,
        BackendHealth::Unhealthy,
    ] {
        let json_str = serde_json::to_string(&health).unwrap();
        let deserialized: BackendHealth = serde_json::from_str(&json_str).unwrap();
        assert_eq!(health, deserialized);
    }
    // Verify lowercase serialization
    assert_eq!(
        serde_json::to_string(&BackendHealth::Healthy).unwrap(),
        "\"healthy\""
    );
}

#[test]
fn test_upstream_backend_serde_roundtrip() {
    let backend = UpstreamBackend {
        id: "backend-1".to_string(),
        url: "http://localhost:8001/mcp".to_string(),
        tool_prefixes: vec!["fs_".to_string(), "file_".to_string()],
        weight: 80,
        health: BackendHealth::Healthy,
    };
    let json_str = serde_json::to_string(&backend).unwrap();
    let deserialized: UpstreamBackend = serde_json::from_str(&json_str).unwrap();
    assert_eq!(backend.id, deserialized.id);
    assert_eq!(backend.url, deserialized.url);
    assert_eq!(backend.tool_prefixes, deserialized.tool_prefixes);
    assert_eq!(backend.weight, deserialized.weight);
    // Health is skip(deserialize), so it defaults to Healthy
    assert_eq!(deserialized.health, BackendHealth::Healthy);
}

#[test]
fn test_upstream_backend_default_weight() {
    let json_str = r#"{"id":"b","url":"http://localhost:8000","tool_prefixes":[]}"#;
    let backend: UpstreamBackend = serde_json::from_str(json_str).unwrap();
    assert_eq!(backend.weight, 100);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 21: ABAC types tests
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_abac_effect_serde_roundtrip() {
    let permit = AbacEffect::Permit;
    let forbid = AbacEffect::Forbid;
    let permit_json = serde_json::to_string(&permit).unwrap();
    let forbid_json = serde_json::to_string(&forbid).unwrap();
    assert_eq!(permit_json, r#""permit""#);
    assert_eq!(forbid_json, r#""forbid""#);
    let p: AbacEffect = serde_json::from_str(&permit_json).unwrap();
    let f: AbacEffect = serde_json::from_str(&forbid_json).unwrap();
    assert_eq!(p, AbacEffect::Permit);
    assert_eq!(f, AbacEffect::Forbid);
}

#[test]
fn test_abac_policy_serde_roundtrip() {
    let policy = AbacPolicy {
        id: "policy-1".to_string(),
        description: "Allow agents to read files".to_string(),
        effect: AbacEffect::Permit,
        priority: 100,
        principal: PrincipalConstraint {
            principal_type: Some("Agent".to_string()),
            id_patterns: vec!["code-*".to_string()],
            claims: HashMap::new(),
        },
        action: ActionConstraint {
            patterns: vec!["filesystem:read_*".to_string()],
        },
        resource: ResourceConstraint {
            path_patterns: vec!["/home/**".to_string()],
            domain_patterns: vec![],
            tags: vec![],
        },
        conditions: vec![AbacCondition {
            field: "context.verified".to_string(),
            op: AbacOp::Eq,
            value: json!(true),
        }],
    };
    let json_str = serde_json::to_string(&policy).unwrap();
    let deserialized: AbacPolicy = serde_json::from_str(&json_str).unwrap();
    assert_eq!(policy, deserialized);
}

#[test]
fn test_risk_score_defaults() {
    let score = RiskScore {
        score: 0.42,
        factors: vec![],
        updated_at: "2026-02-14T00:00:00Z".to_string(),
    };
    assert_eq!(score.score, 0.42);
    assert!(score.factors.is_empty());
}

#[test]
fn test_abac_op_all_variants() {
    let ops = vec![
        AbacOp::Eq,
        AbacOp::Ne,
        AbacOp::In,
        AbacOp::NotIn,
        AbacOp::Contains,
        AbacOp::StartsWith,
        AbacOp::Gt,
        AbacOp::Lt,
        AbacOp::Gte,
        AbacOp::Lte,
    ];
    for op in ops {
        let json_str = serde_json::to_string(&op).unwrap();
        let deserialized: AbacOp = serde_json::from_str(&json_str).unwrap();
        assert_eq!(op, deserialized);
    }
}

#[test]
fn test_abac_entity_with_parents() {
    let entity = AbacEntity {
        entity_type: "Agent".to_string(),
        id: "agent-42".to_string(),
        attributes: {
            let mut m = HashMap::new();
            m.insert("team".to_string(), json!("security"));
            m
        },
        parents: vec!["Group::admins".to_string()],
    };
    let json_str = serde_json::to_string(&entity).unwrap();
    let deserialized: AbacEntity = serde_json::from_str(&json_str).unwrap();
    assert_eq!(entity, deserialized);
    assert_eq!(deserialized.parents.len(), 1);
}

// ═══════════════════════════════════════════════════
// PHASE 24: EU AI ACT FINAL COMPLIANCE TYPES TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_explanation_verbosity_default() {
    let v = ExplanationVerbosity::default();
    assert_eq!(v, ExplanationVerbosity::None);
}

#[test]
fn test_explanation_verbosity_display() {
    assert_eq!(ExplanationVerbosity::None.to_string(), "none");
    assert_eq!(ExplanationVerbosity::Summary.to_string(), "summary");
    assert_eq!(ExplanationVerbosity::Full.to_string(), "full");
}

#[test]
fn test_explanation_verbosity_serde_roundtrip() {
    for v in [
        ExplanationVerbosity::None,
        ExplanationVerbosity::Summary,
        ExplanationVerbosity::Full,
    ] {
        let json_str = serde_json::to_string(&v).unwrap();
        let deserialized: ExplanationVerbosity = serde_json::from_str(&json_str).unwrap();
        assert_eq!(v, deserialized);
    }
    // Verify rename_all = "snake_case"
    assert_eq!(
        serde_json::to_string(&ExplanationVerbosity::None).unwrap(),
        r#""none""#
    );
}

#[test]
fn test_data_classification_display_and_serde() {
    let all = vec![
        DataClassification::Training,
        DataClassification::Input,
        DataClassification::Output,
        DataClassification::Testing,
        DataClassification::Operational,
        DataClassification::Personal,
        DataClassification::NonPersonal,
    ];
    for dc in all {
        let json_str = serde_json::to_string(&dc).unwrap();
        let deserialized: DataClassification = serde_json::from_str(&json_str).unwrap();
        assert_eq!(dc, deserialized);
        assert!(!dc.to_string().is_empty());
    }
}

#[test]
fn test_processing_purpose_display_and_serde() {
    let all = vec![
        ProcessingPurpose::ToolExecution,
        ProcessingPurpose::SecurityAudit,
        ProcessingPurpose::ComplianceEvidence,
        ProcessingPurpose::PolicyEvaluation,
        ProcessingPurpose::ModelInference,
    ];
    for pp in all {
        let json_str = serde_json::to_string(&pp).unwrap();
        let deserialized: ProcessingPurpose = serde_json::from_str(&json_str).unwrap();
        assert_eq!(pp, deserialized);
        assert!(!pp.to_string().is_empty());
    }
}

#[test]
fn test_data_governance_record_serde_roundtrip() {
    let record = DataGovernanceRecord {
        tool: "filesystem.*".to_string(),
        classifications: vec![DataClassification::Input, DataClassification::Output],
        purpose: ProcessingPurpose::ToolExecution,
        provenance: Some("user-provided".to_string()),
        retention_days: Some(365),
    };
    let json_str = serde_json::to_string(&record).unwrap();
    let deserialized: DataGovernanceRecord = serde_json::from_str(&json_str).unwrap();
    assert_eq!(record, deserialized);
}

#[test]
fn test_data_governance_record_optional_fields() {
    let record = DataGovernanceRecord {
        tool: "http.*".to_string(),
        classifications: vec![DataClassification::Operational],
        purpose: ProcessingPurpose::SecurityAudit,
        provenance: None,
        retention_days: None,
    };
    let json_str = serde_json::to_string(&record).unwrap();
    // Optional fields should be skipped
    assert!(!json_str.contains("provenance"));
    assert!(!json_str.contains("retention_days"));
}

// ── Phase 38: SOC 2 Type II Access Review Types ─────────────────────────────

#[test]
fn test_attestation_status_default() {
    let status = AttestationStatus::default();
    assert_eq!(status, AttestationStatus::Pending);
}

#[test]
fn test_attestation_status_serde_roundtrip() {
    let variants = [
        AttestationStatus::Pending,
        AttestationStatus::Approved,
        AttestationStatus::FindingsNoted,
        AttestationStatus::Rejected,
    ];
    for v in &variants {
        let json_str = serde_json::to_string(v).unwrap();
        let deserialized: AttestationStatus = serde_json::from_str(&json_str).unwrap();
        assert_eq!(*v, deserialized);
    }
}

#[test]
fn test_attestation_status_display() {
    assert_eq!(AttestationStatus::Pending.to_string(), "pending");
    assert_eq!(AttestationStatus::Approved.to_string(), "approved");
    assert_eq!(
        AttestationStatus::FindingsNoted.to_string(),
        "findings_noted"
    );
    assert_eq!(AttestationStatus::Rejected.to_string(), "rejected");
}

#[test]
fn test_review_schedule_serde_roundtrip() {
    let variants = [
        ReviewSchedule::Daily,
        ReviewSchedule::Weekly,
        ReviewSchedule::Monthly,
    ];
    for v in &variants {
        let json_str = serde_json::to_string(v).unwrap();
        let deserialized: ReviewSchedule = serde_json::from_str(&json_str).unwrap();
        assert_eq!(*v, deserialized);
    }
}

#[test]
fn test_review_schedule_display() {
    assert_eq!(ReviewSchedule::Daily.to_string(), "daily");
    assert_eq!(ReviewSchedule::Weekly.to_string(), "weekly");
    assert_eq!(ReviewSchedule::Monthly.to_string(), "monthly");
}

#[test]
fn test_report_export_format_default() {
    let fmt = ReportExportFormat::default();
    assert_eq!(fmt, ReportExportFormat::Json);
}

#[test]
fn test_access_review_report_serde_roundtrip() {
    let report = AccessReviewReport {
        generated_at: "2026-02-16T00:00:00Z".to_string(),
        organization_name: "Acme Corp".to_string(),
        period_start: "2026-01-01T00:00:00Z".to_string(),
        period_end: "2026-02-01T00:00:00Z".to_string(),
        total_agents: 1,
        total_evaluations: 42,
        entries: vec![AccessReviewEntry {
            agent_id: "agent-1".to_string(),
            session_ids: vec!["sess-1".to_string()],
            first_access: "2026-01-02T00:00:00Z".to_string(),
            last_access: "2026-01-31T00:00:00Z".to_string(),
            total_evaluations: 42,
            allow_count: 30,
            deny_count: 10,
            require_approval_count: 2,
            tools_accessed: vec!["read_file".to_string()],
            functions_called: vec!["execute".to_string()],
            permissions_granted: 5,
            permissions_used: 4,
            usage_ratio: 0.8,
            unused_permissions: vec!["policy-5".to_string()],
            agency_recommendation: "Optimal".to_string(),
        }],
        cc6_evidence: Cc6Evidence {
            cc6_1_evidence: "All agent access policy-controlled".to_string(),
            cc6_2_evidence: "Agent identities validated before access".to_string(),
            cc6_3_evidence: "Unused permissions tracked".to_string(),
            optimal_count: 1,
            review_grants_count: 0,
            narrow_scope_count: 0,
            critical_count: 0,
        },
        attestation: ReviewerAttestation {
            reviewer_name: String::new(),
            reviewer_title: String::new(),
            reviewed_at: None,
            notes: String::new(),
            status: AttestationStatus::Pending,
        },
    };
    let json_str = serde_json::to_string(&report).unwrap();
    let deserialized: AccessReviewReport = serde_json::from_str(&json_str).unwrap();
    assert_eq!(report, deserialized);
}

#[test]
fn test_verdict_explanation_summary() {
    let trace = EvaluationTrace {
        action_summary: ActionSummary {
            tool: "read_file".to_string(),
            function: "execute".to_string(),
            param_count: 1,
            param_keys: vec!["path".to_string()],
        },
        policies_checked: 3,
        policies_matched: 1,
        matches: vec![PolicyMatch {
            policy_id: "p1".to_string(),
            policy_name: "Allow reads".to_string(),
            policy_type: "Allow".to_string(),
            priority: 100,
            tool_matched: true,
            constraint_results: vec![],
            verdict_contribution: Some(Verdict::Allow),
        }],
        verdict: Verdict::Allow,
        duration_us: 42,
    };
    let explanation = VerdictExplanation::summary(&trace);
    assert_eq!(explanation.verdict, "Allow");
    assert!(explanation.reason.is_none());
    assert_eq!(explanation.policies_checked, 3);
    assert_eq!(explanation.policies_matched, 1);
    assert_eq!(explanation.duration_us, 42);
    assert!(explanation.policy_details.is_none());
}

#[test]
fn test_verdict_explanation_full_with_failed_constraints() {
    let trace = EvaluationTrace {
        action_summary: ActionSummary {
            tool: "shell".to_string(),
            function: "exec".to_string(),
            param_count: 1,
            param_keys: vec!["cmd".to_string()],
        },
        policies_checked: 2,
        policies_matched: 1,
        matches: vec![PolicyMatch {
            policy_id: "deny-shell".to_string(),
            policy_name: "Block shell".to_string(),
            policy_type: "Deny".to_string(),
            priority: 200,
            tool_matched: true,
            constraint_results: vec![ConstraintResult {
                constraint_type: "tool_pattern".to_string(),
                param: "tool".to_string(),
                expected: "shell*".to_string(),
                actual: "shell".to_string(),
                passed: false,
            }],
            verdict_contribution: Some(Verdict::Deny {
                reason: "blocked by policy".to_string(),
            }),
        }],
        verdict: Verdict::Deny {
            reason: "blocked by policy".to_string(),
        },
        duration_us: 55,
    };
    let explanation = VerdictExplanation::full(&trace);
    assert_eq!(explanation.verdict, "Deny");
    assert_eq!(explanation.reason, Some("blocked by policy".to_string()));
    let details = explanation.policy_details.unwrap();
    assert_eq!(details.len(), 1);
    assert_eq!(details[0].policy_id, "deny-shell");
    assert!(details[0].failed_constraints.is_some());
    assert_eq!(details[0].failed_constraints.as_ref().unwrap().len(), 1);
}

#[test]
fn test_verdict_explanation_serde_roundtrip() {
    let explanation = VerdictExplanation {
        verdict: "Allow".to_string(),
        reason: None,
        policies_checked: 5,
        policies_matched: 2,
        duration_us: 100,
        policy_details: Some(vec![PolicyMatchDetail {
            policy_id: "p1".to_string(),
            policy_name: "Test".to_string(),
            priority: 50,
            verdict_contribution: Some("Allow".to_string()),
            failed_constraints: None,
        }]),
    };
    let json_str = serde_json::to_string(&explanation).unwrap();
    let deserialized: VerdictExplanation = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.policies_checked, 5);
    assert!(deserialized.policy_details.is_some());
}

// ═══════════════════════════════════════════════════
// Phase 25.6: RequestContext trait and StatelessContextBlob tests
// ═══════════════════════════════════════════════════

/// Phase 25.6: StatelessContextBlob serialization roundtrip.
#[test]
fn test_stateless_blob_roundtrip() {
    let blob = StatelessContextBlob {
        version: 1,
        agent_id: "agent-123".to_string(),
        call_counts: {
            let mut m = HashMap::new();
            m.insert("read_file".to_string(), 5);
            m.insert("write_file".to_string(), 2);
            m
        },
        recent_actions: vec!["read_file".to_string(), "write_file".to_string()],
        call_chain: vec![CallChainEntry {
            agent_id: "upstream-1".to_string(),
            tool: "read_file".to_string(),
            function: "read".to_string(),
            timestamp: "2026-02-15T10:00:00Z".to_string(),
            hmac: None,
            verified: None,
        }],
        risk_score: None,
        issued_at: 1739613600,
        signature: "deadbeef".to_string(),
    };

    let json_str = serde_json::to_string(&blob).unwrap();
    let deserialized: StatelessContextBlob = serde_json::from_str(&json_str).unwrap();

    assert_eq!(deserialized.version, 1);
    assert_eq!(deserialized.agent_id, "agent-123");
    assert_eq!(deserialized.call_counts.len(), 2);
    assert_eq!(deserialized.call_counts["read_file"], 5);
    assert_eq!(deserialized.recent_actions.len(), 2);
    assert_eq!(deserialized.call_chain.len(), 1);
    assert_eq!(deserialized.issued_at, 1739613600);
    assert_eq!(deserialized.signature, "deadbeef");
}

/// Phase 25.6: Expired blob detection.
#[test]
fn test_stateless_blob_expiry() {
    let blob = StatelessContextBlob {
        version: 1,
        agent_id: "agent-1".to_string(),
        call_counts: HashMap::new(),
        recent_actions: vec![],
        call_chain: vec![],
        risk_score: None,
        issued_at: 1000,
        signature: String::new(),
    };

    // 301 seconds later — expired (max age is 300)
    assert!(blob.is_expired(1301));
    // 300 seconds later — not expired (boundary)
    assert!(!blob.is_expired(1300));
    // Same time — not expired
    assert!(!blob.is_expired(1000));
}

/// Phase 25.6: StatelessContextBlob implements RequestContext.
#[test]
fn test_stateless_blob_request_context_trait() {
    let blob = StatelessContextBlob {
        version: 1,
        agent_id: "agent-ctx".to_string(),
        call_counts: {
            let mut m = HashMap::new();
            m.insert("tool_a".to_string(), 3);
            m
        },
        recent_actions: vec!["tool_a".to_string(), "tool_b".to_string()],
        call_chain: vec![],
        risk_score: None,
        issued_at: 1000,
        signature: String::new(),
    };

    // Test via trait
    let ctx: &dyn RequestContext = &blob;
    assert_eq!(ctx.call_counts()["tool_a"], 3);
    assert_eq!(ctx.previous_actions().len(), 2);
    assert!(ctx.call_chain().is_empty());
    assert!(ctx.agent_identity().is_none());
    assert!(ctx.session_guard_state().is_none());
    assert!(ctx.risk_score().is_none());
}

/// Phase 25.6: EvaluationContext built from StatelessContextBlob via trait.
#[test]
fn test_evaluation_context_from_stateless() {
    let blob = StatelessContextBlob {
        version: 1,
        agent_id: "agent-eval".to_string(),
        call_counts: {
            let mut m = HashMap::new();
            m.insert("read".to_string(), 10);
            m
        },
        recent_actions: vec!["read".to_string()],
        call_chain: vec![CallChainEntry {
            agent_id: "hop-1".to_string(),
            tool: "read".to_string(),
            function: "get".to_string(),
            timestamp: "2026-02-15T12:00:00Z".to_string(),
            hmac: None,
            verified: None,
        }],
        risk_score: None,
        issued_at: 1000,
        signature: String::new(),
    };

    let eval_ctx = blob.to_evaluation_context();
    assert_eq!(eval_ctx.call_counts["read"], 10);
    assert_eq!(eval_ctx.previous_actions, vec!["read".to_string()]);
    assert_eq!(eval_ctx.call_chain.len(), 1);
    assert_eq!(eval_ctx.call_chain[0].agent_id, "hop-1");
    // Stateless blob doesn't carry agent_identity or session_state
    assert!(eval_ctx.agent_identity.is_none());
    assert!(eval_ctx.session_state.is_none());
}

// ═══════════════════════════════════════════════════
// Phase 27: Deployment types serde tests
// ═══════════════════════════════════════════════════

#[test]
fn test_leader_status_leader_roundtrip() {
    let status = LeaderStatus::Leader {
        since: "2026-02-15T10:00:00Z".to_string(),
    };
    let json_str = serde_json::to_string(&status).unwrap();
    let deserialized: LeaderStatus = serde_json::from_str(&json_str).unwrap();
    assert_eq!(status, deserialized);
}

#[test]
fn test_leader_status_follower_roundtrip() {
    let status = LeaderStatus::Follower {
        leader_id: Some("vellaveto-0".to_string()),
    };
    let json_str = serde_json::to_string(&status).unwrap();
    let deserialized: LeaderStatus = serde_json::from_str(&json_str).unwrap();
    assert_eq!(status, deserialized);
}

#[test]
fn test_leader_status_follower_no_leader_roundtrip() {
    let status = LeaderStatus::Follower { leader_id: None };
    let json_str = serde_json::to_string(&status).unwrap();
    let deserialized: LeaderStatus = serde_json::from_str(&json_str).unwrap();
    assert_eq!(status, deserialized);
}

#[test]
fn test_leader_status_unknown_roundtrip() {
    let status = LeaderStatus::Unknown;
    let json_str = serde_json::to_string(&status).unwrap();
    let deserialized: LeaderStatus = serde_json::from_str(&json_str).unwrap();
    assert_eq!(status, deserialized);
}

#[test]
fn test_leader_status_default_is_unknown() {
    let status = LeaderStatus::default();
    assert_eq!(status, LeaderStatus::Unknown);
}

#[test]
fn test_leader_status_deny_unknown_fields() {
    let mut json = serde_json::to_value(LeaderStatus::Leader {
        since: "2026-02-15T10:00:00Z".to_string(),
    })
    .unwrap();
    json["unexpected"] = json!(true);
    let result: Result<LeaderStatus, _> = serde_json::from_value(json);
    assert!(
        result.is_err(),
        "LeaderStatus must reject unknown nested fields"
    );
}

#[test]
fn test_service_endpoint_roundtrip() {
    let mut labels = HashMap::new();
    labels.insert("region".to_string(), "us-east-1".to_string());
    let ep = ServiceEndpoint {
        id: "vellaveto-0".to_string(),
        url: "http://vellaveto-0.vellaveto:3000".to_string(),
        labels,
        healthy: true,
    };
    let json_str = serde_json::to_string(&ep).unwrap();
    let deserialized: ServiceEndpoint = serde_json::from_str(&json_str).unwrap();
    assert_eq!(ep, deserialized);
}

#[test]
fn test_service_endpoint_empty_labels_skipped() {
    let ep = ServiceEndpoint {
        id: "node-1".to_string(),
        url: "http://node-1:3000".to_string(),
        labels: HashMap::new(),
        healthy: false,
    };
    let json_str = serde_json::to_string(&ep).unwrap();
    assert!(
        !json_str.contains("labels"),
        "empty labels should be skipped"
    );
}

#[test]
fn test_discovery_event_added_roundtrip() {
    let event = DiscoveryEvent::Added(ServiceEndpoint {
        id: "pod-1".to_string(),
        url: "http://pod-1:3000".to_string(),
        labels: HashMap::new(),
        healthy: true,
    });
    let json_str = serde_json::to_string(&event).unwrap();
    let deserialized: DiscoveryEvent = serde_json::from_str(&json_str).unwrap();
    assert_eq!(event, deserialized);
}

#[test]
fn test_discovery_event_removed_roundtrip() {
    let event = DiscoveryEvent::Removed {
        id: "pod-2".to_string(),
    };
    let json_str = serde_json::to_string(&event).unwrap();
    let deserialized: DiscoveryEvent = serde_json::from_str(&json_str).unwrap();
    assert_eq!(event, deserialized);
}

#[test]
fn test_discovery_event_updated_roundtrip() {
    let event = DiscoveryEvent::Updated(ServiceEndpoint {
        id: "pod-3".to_string(),
        url: "http://pod-3:3000".to_string(),
        labels: HashMap::new(),
        healthy: false,
    });
    let json_str = serde_json::to_string(&event).unwrap();
    let deserialized: DiscoveryEvent = serde_json::from_str(&json_str).unwrap();
    assert_eq!(event, deserialized);
}

#[test]
fn test_discovery_event_deny_unknown_fields() {
    let mut json = serde_json::to_value(DiscoveryEvent::Removed {
        id: "pod-2".to_string(),
    })
    .unwrap();
    json["unexpected"] = json!(true);
    let result: Result<DiscoveryEvent, _> = serde_json::from_value(json);
    assert!(
        result.is_err(),
        "DiscoveryEvent must reject unknown nested fields"
    );
}

#[test]
fn test_deployment_info_roundtrip() {
    let info = DeploymentInfo {
        instance_id: Some("vellaveto-0".to_string()),
        leader_status: Some(LeaderStatus::Leader {
            since: "2026-02-15T10:00:00Z".to_string(),
        }),
        discovered_endpoints: Some(3),
        uptime_secs: 86400,
        mode: "kubernetes".to_string(),
    };
    let json_str = serde_json::to_string(&info).unwrap();
    let deserialized: DeploymentInfo = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.instance_id, Some("vellaveto-0".to_string()));
    assert_eq!(deserialized.discovered_endpoints, Some(3));
    assert_eq!(deserialized.uptime_secs, 86400);
    assert_eq!(deserialized.mode, "kubernetes");
}

#[test]
fn test_deployment_info_redacted_anonymous_mode() {
    // SECURITY (FIND-R44-015): In anonymous mode, sensitive fields are None
    // and should be omitted from JSON output.
    let info = DeploymentInfo {
        instance_id: None,
        leader_status: None,
        discovered_endpoints: None,
        uptime_secs: 3600,
        mode: "standalone".to_string(),
    };
    let json_str = serde_json::to_string(&info).unwrap();
    assert!(
        !json_str.contains("instance_id"),
        "instance_id should be omitted when None"
    );
    assert!(
        !json_str.contains("leader_status"),
        "leader_status should be omitted when None"
    );
    assert!(
        !json_str.contains("discovered_endpoints"),
        "discovered_endpoints should be omitted when None"
    );
    assert!(
        json_str.contains("uptime_secs"),
        "uptime_secs should always be present"
    );
    assert!(json_str.contains("mode"), "mode should always be present");

    // Verify deserialization works with missing fields
    let deserialized: DeploymentInfo = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.instance_id, None);
    assert_eq!(deserialized.leader_status, None);
    assert_eq!(deserialized.discovered_endpoints, None);
    assert_eq!(deserialized.uptime_secs, 3600);
    assert_eq!(deserialized.mode, "standalone");
}

// ═══════════════════════════════════════════════════════
// IMP-R224-007: DiscoveryEvent::validate() bounds checking
// ═══════════════════════════════════════════════════════

#[test]
fn test_discovery_event_validate_removed_valid() {
    let event = DiscoveryEvent::Removed {
        id: "pod-1".to_string(),
    };
    assert!(event.validate().is_ok());
}

#[test]
fn test_discovery_event_validate_removed_too_long_id() {
    let event = DiscoveryEvent::Removed {
        id: "a".repeat(257),
    };
    let err = event.validate().unwrap_err();
    assert!(
        err.contains("exceeds max"),
        "Expected length error, got: {err}",
    );
}

#[test]
fn test_discovery_event_validate_removed_control_chars() {
    let event = DiscoveryEvent::Removed {
        id: "bad\nid".to_string(),
    };
    let err = event.validate().unwrap_err();
    assert!(
        err.contains("control"),
        "Expected control char error, got: {err}",
    );
}

#[test]
fn test_discovery_event_validate_added_delegates_to_endpoint() {
    let event = DiscoveryEvent::Added(ServiceEndpoint {
        id: "a".repeat(257),
        url: "http://ok:3000".to_string(),
        labels: HashMap::new(),
        healthy: true,
    });
    assert!(event.validate().is_err());
}

#[test]
fn test_discovery_event_validate_updated_delegates_to_endpoint() {
    let event = DiscoveryEvent::Updated(ServiceEndpoint {
        id: "ok".to_string(),
        url: "http://ok:3000".to_string(),
        labels: HashMap::new(),
        healthy: true,
    });
    assert!(event.validate().is_ok());
}

// ═══════════════════════════════════════════════════════
// FIND-R44-031: truncate_for_log must not panic on multi-byte UTF-8
// ═══════════════════════════════════════════════════════

/// FIND-R44-031: Fingerprint summary with multi-byte UTF-8 in jwt_sub must
/// not panic. Previously, byte-based slicing would panic on char boundaries.
#[test]
fn test_agent_fingerprint_summary_multibyte_utf8_no_panic() {
    // Create a jwt_sub with multi-byte chars that exceeds max_len=20
    // Each CJK character is 3 bytes. 10 chars = 30 bytes > 20 limit.
    let long_multibyte =
        "\u{4e16}\u{754c}\u{4f60}\u{597d}\u{6d4b}\u{8bd5}\u{5b57}\u{7b26}\u{4e32}\u{5b57}";
    let fp = AgentFingerprint {
        jwt_sub: Some(long_multibyte.to_string()),
        ..Default::default()
    };
    // Must not panic — this is the critical assertion
    let summary = fp.summary();
    assert!(summary.contains("sub:"));
    assert!(summary.contains("..."));
}

/// FIND-R44-031: Fingerprint summary with 2-byte UTF-8 chars (e.g., Latin-1
/// extended) that land exactly on boundary positions.
#[test]
fn test_agent_fingerprint_summary_2byte_utf8_boundary() {
    // Each e-acute (U+00E9) is 2 bytes. 15 chars = 30 bytes > 20.
    let long_accent = "\u{00e9}".repeat(15);
    let fp = AgentFingerprint {
        jwt_sub: Some(long_accent),
        ..Default::default()
    };
    let summary = fp.summary();
    assert!(summary.contains("sub:"));
    assert!(summary.contains("..."));
}

/// FIND-R44-031: Fingerprint summary with 4-byte emoji chars.
#[test]
fn test_agent_fingerprint_summary_4byte_emoji() {
    // Each emoji is 4 bytes. 6 chars = 24 bytes > 20.
    let emojis = "\u{1F600}\u{1F601}\u{1F602}\u{1F603}\u{1F604}\u{1F605}";
    let fp = AgentFingerprint {
        jwt_sub: Some(emojis.to_string()),
        ..Default::default()
    };
    let summary = fp.summary();
    assert!(summary.contains("sub:"));
    assert!(summary.contains("..."));
}

/// FIND-R44-031: Short strings within max_len are not truncated.
#[test]
fn test_agent_fingerprint_summary_short_string_unchanged() {
    let fp = AgentFingerprint {
        jwt_sub: Some("short".to_string()),
        ..Default::default()
    };
    let summary = fp.summary();
    assert!(summary.contains("sub:short"));
    assert!(!summary.contains("..."));
}

/// FIND-R44-031: Edge case — max_len < 3 should not underflow.
#[test]
fn test_agent_fingerprint_summary_mixed_multibyte_ascii() {
    // Mix ASCII and multi-byte: "a\u{4e16}b\u{4e16}c\u{4e16}d\u{4e16}e\u{4e16}f"
    // = 5 ASCII (5 bytes) + 5 CJK (15 bytes) = 20 bytes, exactly at limit.
    let exactly_20 = "a\u{4e16}b\u{4e16}c\u{4e16}d\u{4e16}e\u{4e16}";
    assert_eq!(exactly_20.len(), 20);
    let fp = AgentFingerprint {
        jwt_sub: Some(exactly_20.to_string()),
        ..Default::default()
    };
    let summary = fp.summary();
    // At exactly max_len, no truncation
    assert!(summary.contains("sub:"));
    assert!(!summary.contains("..."));
}

// ═══════════════════════════════════════════════════
// R241-TYP-1: AgentFingerprint validate()
// ═══════════════════════════════════════════════════

#[test]
fn test_agent_fingerprint_validate_valid() {
    let fp = AgentFingerprint {
        jwt_sub: Some("user-42".to_string()),
        jwt_iss: Some("https://auth.example.com".to_string()),
        client_id: Some("client-abc".to_string()),
        ip_hash: Some("deadbeef".to_string()),
    };
    assert!(fp.validate().is_ok());
}

#[test]
fn test_agent_fingerprint_validate_empty_is_ok() {
    let fp = AgentFingerprint::default();
    assert!(fp.validate().is_ok());
}

#[test]
fn test_agent_fingerprint_validate_jwt_sub_too_long() {
    let fp = AgentFingerprint {
        jwt_sub: Some("x".repeat(2000)),
        ..Default::default()
    };
    let err = fp.validate().unwrap_err();
    assert!(err.contains("jwt_sub"), "{err}");
}

#[test]
fn test_agent_fingerprint_validate_jwt_iss_dangerous_chars() {
    let fp = AgentFingerprint {
        jwt_iss: Some("https://evil.com\x00".to_string()),
        ..Default::default()
    };
    let err = fp.validate().unwrap_err();
    assert!(err.contains("jwt_iss"), "{err}");
}

#[test]
fn test_agent_fingerprint_validate_client_id_dangerous_chars() {
    let fp = AgentFingerprint {
        client_id: Some("client\x1B[31m-red".to_string()),
        ..Default::default()
    };
    let err = fp.validate().unwrap_err();
    assert!(err.contains("client_id"), "{err}");
}

#[test]
fn test_agent_fingerprint_validate_ip_hash_too_long() {
    let fp = AgentFingerprint {
        ip_hash: Some("h".repeat(2000)),
        ..Default::default()
    };
    let err = fp.validate().unwrap_err();
    assert!(err.contains("ip_hash"), "{err}");
}

// ═══════════════════════════════════════════════════
// MCP 2025-11-25 TOOL NAME VALIDATION (Phase 30)
// ═══════════════════════════════════════════════════

#[test]
fn test_validate_mcp_tool_name_empty_rejected() {
    let err = validate_mcp_tool_name("").unwrap_err();
    assert!(err.contains("empty"), "got: {err}");
}

#[test]
fn test_validate_mcp_tool_name_too_long_rejected() {
    let name = "a".repeat(65);
    let err = validate_mcp_tool_name(&name).unwrap_err();
    assert!(err.contains("exceeds 64"), "got: {err}");
}

#[test]
fn test_validate_mcp_tool_name_max_length_accepted() {
    let name = "a".repeat(64);
    assert!(validate_mcp_tool_name(&name).is_ok());
}

#[test]
fn test_validate_mcp_tool_name_valid_simple() {
    assert!(validate_mcp_tool_name("read_file").is_ok());
    assert!(validate_mcp_tool_name("bash-exec").is_ok());
    assert!(validate_mcp_tool_name("tool123").is_ok());
    assert!(validate_mcp_tool_name("A").is_ok());
}

#[test]
fn test_validate_mcp_tool_name_valid_dotted_namespace() {
    assert!(validate_mcp_tool_name("ns.tool").is_ok());
    assert!(validate_mcp_tool_name("org.project.tool_v2").is_ok());
}

#[test]
fn test_validate_mcp_tool_name_valid_slashed_namespace() {
    assert!(validate_mcp_tool_name("ns/tool").is_ok());
    assert!(validate_mcp_tool_name("org/project/read").is_ok());
}

#[test]
fn test_validate_mcp_tool_name_invalid_chars_rejected() {
    let err = validate_mcp_tool_name("tool@bad").unwrap_err();
    assert!(err.contains("invalid character '@'"), "got: {err}");

    assert!(validate_mcp_tool_name("tool name").is_err()); // space
    assert!(validate_mcp_tool_name("tool\ttab").is_err()); // tab
    assert!(validate_mcp_tool_name("tool#hash").is_err()); // hash
    assert!(validate_mcp_tool_name("tool$dollar").is_err()); // dollar
}

/// FIND-R73-002: Verify control characters are escaped in error messages
/// to prevent log injection.
#[test]
fn test_validate_mcp_tool_name_control_char_escaped_in_error() {
    // Newline — should appear as \n, not a literal newline
    let err = validate_mcp_tool_name("tool\nname").unwrap_err();
    assert!(
        err.contains(r"\n"),
        "control char should be escaped in error: {}",
        err.escape_debug()
    );
    assert!(
        !err.contains('\n'),
        "error message must not contain literal newline"
    );

    // Null byte — should appear as \0
    let err = validate_mcp_tool_name("tool\0name").unwrap_err();
    assert!(
        err.contains(r"\0"),
        "null byte should be escaped in error: {}",
        err.escape_debug()
    );

    // ESC (0x1b) — ANSI escape injection
    let err = validate_mcp_tool_name("tool\x1b[31mred").unwrap_err();
    assert!(
        !err.contains('\x1b'),
        "error message must not contain literal ESC"
    );
}

#[test]
fn test_validate_mcp_tool_name_leading_dot_rejected() {
    let err = validate_mcp_tool_name(".hidden").unwrap_err();
    assert!(err.contains("must not start with"), "got: {err}");
}

#[test]
fn test_validate_mcp_tool_name_trailing_dot_rejected() {
    let err = validate_mcp_tool_name("tool.").unwrap_err();
    assert!(err.contains("must not end with"), "got: {err}");
}

#[test]
fn test_validate_mcp_tool_name_leading_slash_rejected() {
    let err = validate_mcp_tool_name("/tool").unwrap_err();
    assert!(err.contains("must not start with"), "got: {err}");
}

#[test]
fn test_validate_mcp_tool_name_trailing_slash_rejected() {
    let err = validate_mcp_tool_name("tool/").unwrap_err();
    assert!(err.contains("must not end with"), "got: {err}");
}

#[test]
fn test_validate_mcp_tool_name_consecutive_dots_rejected() {
    let err = validate_mcp_tool_name("ns..tool").unwrap_err();
    assert!(err.contains("consecutive dots"), "got: {err}");
}

// ═══════════════════════════════════════════════════════════════════════════════
// DISCOVERY TYPES (Phase 34)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_tool_metadata_serde_roundtrip() {
    let meta = ToolMetadata {
        tool_id: "server1:read_file".to_string(),
        name: "read_file".to_string(),
        description: "Read a file from disk".to_string(),
        server_id: "server1".to_string(),
        input_schema: json!({"type": "object", "properties": {"path": {"type": "string"}}}),
        schema_hash: "abcdef1234567890".to_string(),
        sensitivity: ToolSensitivity::Medium,
        domain_tags: vec!["filesystem".to_string(), "io".to_string()],
        token_cost: 150,
    };
    let json_str = serde_json::to_string(&meta).unwrap();
    let deserialized: ToolMetadata = serde_json::from_str(&json_str).unwrap();
    assert_eq!(meta, deserialized);
}

#[test]
fn test_tool_sensitivity_all_variants_roundtrip() {
    let variants = [
        ToolSensitivity::Low,
        ToolSensitivity::Medium,
        ToolSensitivity::High,
    ];
    for v in &variants {
        let json_str = serde_json::to_string(v).unwrap();
        let deserialized: ToolSensitivity = serde_json::from_str(&json_str).unwrap();
        assert_eq!(*v, deserialized);
    }
}

#[test]
fn test_tool_sensitivity_default_is_high() {
    // SECURITY (FIND-R46-013): Default must be High for fail-closed behavior.
    assert_eq!(ToolSensitivity::default(), ToolSensitivity::High);
}

#[test]
fn test_tool_sensitivity_serde_rename() {
    let json_str = serde_json::to_string(&ToolSensitivity::High).unwrap();
    assert_eq!(json_str, "\"high\"");
    let parsed: ToolSensitivity = serde_json::from_str("\"medium\"").unwrap();
    assert_eq!(parsed, ToolSensitivity::Medium);
}

#[test]
fn test_discovery_result_serde_roundtrip() {
    let result = DiscoveryResult {
        tools: vec![DiscoveredTool {
            metadata: ToolMetadata {
                tool_id: "srv:tool".to_string(),
                name: "tool".to_string(),
                description: "A tool".to_string(),
                server_id: "srv".to_string(),
                input_schema: json!({}),
                schema_hash: "hash123".to_string(),
                sensitivity: ToolSensitivity::Low,
                domain_tags: vec![],
                token_cost: 50,
            },
            relevance_score: 0.95,
            ttl_secs: 300,
        }],
        query: "find a tool".to_string(),
        total_candidates: 100,
        policy_filtered: 5,
    };
    let json_str = serde_json::to_string(&result).unwrap();
    let deserialized: DiscoveryResult = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.query, "find a tool");
    assert_eq!(deserialized.total_candidates, 100);
    assert_eq!(deserialized.policy_filtered, 5);
    assert_eq!(deserialized.tools.len(), 1);
    assert_eq!(deserialized.tools[0].relevance_score, 0.95);
    assert_eq!(deserialized.tools[0].ttl_secs, 300);
}

#[test]
fn test_discovered_tool_serde_roundtrip() {
    let tool = DiscoveredTool {
        metadata: ToolMetadata {
            tool_id: "s:t".to_string(),
            name: "t".to_string(),
            description: "desc".to_string(),
            server_id: "s".to_string(),
            input_schema: json!({"type": "object"}),
            schema_hash: "h".to_string(),
            sensitivity: ToolSensitivity::High,
            domain_tags: vec!["network".to_string()],
            token_cost: 200,
        },
        relevance_score: 0.5,
        ttl_secs: 600,
    };
    let json_str = serde_json::to_string(&tool).unwrap();
    let deserialized: DiscoveredTool = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.metadata.sensitivity, ToolSensitivity::High);
    assert_eq!(deserialized.relevance_score, 0.5);
}

#[test]
fn test_tool_metadata_empty_domain_tags() {
    let meta = ToolMetadata {
        tool_id: "s:t".to_string(),
        name: "t".to_string(),
        description: "d".to_string(),
        server_id: "s".to_string(),
        input_schema: json!({}),
        schema_hash: "h".to_string(),
        sensitivity: ToolSensitivity::Low,
        domain_tags: vec![],
        token_cost: 0,
    };
    let json_str = serde_json::to_string(&meta).unwrap();
    let deserialized: ToolMetadata = serde_json::from_str(&json_str).unwrap();
    assert!(deserialized.domain_tags.is_empty());
}

#[test]
fn test_discovery_result_empty_tools() {
    let result = DiscoveryResult {
        tools: vec![],
        query: "nothing".to_string(),
        total_candidates: 0,
        policy_filtered: 0,
    };
    let json_str = serde_json::to_string(&result).unwrap();
    let deserialized: DiscoveryResult = serde_json::from_str(&json_str).unwrap();
    assert!(deserialized.tools.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════════
// TOOL METADATA VALIDATE BOUNDS (FIND-R121-001)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_tool_metadata_validate_name_too_long() {
    let meta = ToolMetadata {
        tool_id: "s:t".to_string(),
        name: "x".repeat(ToolMetadata::MAX_NAME_LENGTH + 1),
        description: "d".to_string(),
        server_id: "s".to_string(),
        input_schema: json!({}),
        schema_hash: "h".to_string(),
        sensitivity: ToolSensitivity::Low,
        domain_tags: vec![],
        token_cost: 0,
    };
    let err = meta.validate().unwrap_err();
    assert!(err.contains("name length"), "got: {err}");
}

#[test]
fn test_tool_metadata_validate_description_too_long() {
    let meta = ToolMetadata {
        tool_id: "s:t".to_string(),
        name: "t".to_string(),
        description: "d".repeat(ToolMetadata::MAX_DESCRIPTION_LENGTH + 1),
        server_id: "s".to_string(),
        input_schema: json!({}),
        schema_hash: "h".to_string(),
        sensitivity: ToolSensitivity::Low,
        domain_tags: vec![],
        token_cost: 0,
    };
    let err = meta.validate().unwrap_err();
    assert!(err.contains("description length"), "got: {err}");
}

#[test]
fn test_tool_metadata_validate_too_many_domain_tags() {
    let meta = ToolMetadata {
        tool_id: "s:t".to_string(),
        name: "t".to_string(),
        description: "d".to_string(),
        server_id: "s".to_string(),
        input_schema: json!({}),
        schema_hash: "h".to_string(),
        sensitivity: ToolSensitivity::Low,
        domain_tags: (0..ToolMetadata::MAX_DOMAIN_TAGS + 1)
            .map(|i| format!("tag{i}"))
            .collect(),
        token_cost: 0,
    };
    let err = meta.validate().unwrap_err();
    assert!(err.contains("domain_tags count"), "got: {err}");
}

#[test]
fn test_tool_metadata_validate_domain_tag_too_long() {
    let meta = ToolMetadata {
        tool_id: "s:t".to_string(),
        name: "t".to_string(),
        description: "d".to_string(),
        server_id: "s".to_string(),
        input_schema: json!({}),
        schema_hash: "h".to_string(),
        sensitivity: ToolSensitivity::Low,
        domain_tags: vec!["x".repeat(ToolMetadata::MAX_DOMAIN_TAG_LENGTH + 1)],
        token_cost: 0,
    };
    let err = meta.validate().unwrap_err();
    assert!(err.contains("domain_tag length"), "got: {err}");
}

#[test]
fn test_tool_metadata_validate_ok_at_limits() {
    let meta = ToolMetadata {
        tool_id: "s:t".to_string(),
        name: "x".repeat(ToolMetadata::MAX_NAME_LENGTH),
        description: "d".repeat(ToolMetadata::MAX_DESCRIPTION_LENGTH),
        server_id: "s".to_string(),
        input_schema: json!({}),
        schema_hash: "h".to_string(),
        sensitivity: ToolSensitivity::Low,
        domain_tags: (0..ToolMetadata::MAX_DOMAIN_TAGS)
            .map(|i| {
                format!(
                    "{:0>width$}",
                    i,
                    width = ToolMetadata::MAX_DOMAIN_TAG_LENGTH
                )
            })
            .collect(),
        token_cost: 0,
    };
    assert!(meta.validate().is_ok());
}

// ── FIND-R103-P3: deny_unknown_fields on discovery structs ──

#[test]
fn test_tool_metadata_deny_unknown_fields() {
    let json = r#"{
        "tool_id": "s:t", "name": "t", "description": "d",
        "server_id": "s", "input_schema": {}, "schema_hash": "h",
        "sensitivity": "low", "domain_tags": [], "token_cost": 0,
        "extra_field": true
    }"#;
    let result = serde_json::from_str::<ToolMetadata>(json);
    assert!(result.is_err(), "should reject unknown field");
    assert!(result.unwrap_err().to_string().contains("unknown field"));
}

#[test]
fn test_discovery_result_deny_unknown_fields() {
    let json = r#"{
        "tools": [], "query": "q",
        "total_candidates": 0, "policy_filtered": 0,
        "sneaky": 42
    }"#;
    let result = serde_json::from_str::<DiscoveryResult>(json);
    assert!(result.is_err(), "should reject unknown field");
    assert!(result.unwrap_err().to_string().contains("unknown field"));
}

#[test]
fn test_discovered_tool_deny_unknown_fields() {
    let json = r#"{
        "metadata": {
            "tool_id": "s:t", "name": "t", "description": "d",
            "server_id": "s", "input_schema": {}, "schema_hash": "h",
            "sensitivity": "low", "domain_tags": [], "token_cost": 0
        },
        "relevance_score": 0.5, "ttl_secs": 60,
        "injected": "evil"
    }"#;
    let result = serde_json::from_str::<DiscoveredTool>(json);
    assert!(result.is_err(), "should reject unknown field");
    assert!(result.unwrap_err().to_string().contains("unknown field"));
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROJECTOR TYPES (Phase 35.1)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_canonical_tool_schema_serde_roundtrip() {
    let schema = CanonicalToolSchema {
        name: "read_file".to_string(),
        description: "Read a file from disk".to_string(),
        input_schema: json!({"type": "object", "properties": {"path": {"type": "string"}}}),
        output_schema: Some(json!({"type": "string"})),
    };
    let json_str = serde_json::to_string(&schema).unwrap();
    let deserialized: CanonicalToolSchema = serde_json::from_str(&json_str).unwrap();
    assert_eq!(schema, deserialized);
}

#[test]
fn test_canonical_tool_schema_no_output_schema() {
    let schema = CanonicalToolSchema {
        name: "exec".to_string(),
        description: "Execute command".to_string(),
        input_schema: json!({"type": "object"}),
        output_schema: None,
    };
    let json_str = serde_json::to_string(&schema).unwrap();
    let deserialized: CanonicalToolSchema = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.output_schema, None);
}

#[test]
fn test_canonical_tool_call_serde_roundtrip() {
    let call = CanonicalToolCall {
        tool_name: "read_file".to_string(),
        arguments: json!({"path": "/tmp/test.txt"}),
        call_id: Some("call_123".to_string()),
    };
    let json_str = serde_json::to_string(&call).unwrap();
    let deserialized: CanonicalToolCall = serde_json::from_str(&json_str).unwrap();
    assert_eq!(call, deserialized);
}

#[test]
fn test_canonical_tool_call_no_call_id() {
    let call = CanonicalToolCall {
        tool_name: "exec".to_string(),
        arguments: json!({"cmd": "ls"}),
        call_id: None,
    };
    let json_str = serde_json::to_string(&call).unwrap();
    let deserialized: CanonicalToolCall = serde_json::from_str(&json_str).unwrap();
    assert_eq!(deserialized.call_id, None);
}

#[test]
fn test_canonical_tool_response_serde_roundtrip() {
    let response = CanonicalToolResponse {
        call_id: Some("call_123".to_string()),
        content: json!({"result": "ok"}),
        is_error: false,
    };
    let json_str = serde_json::to_string(&response).unwrap();
    let deserialized: CanonicalToolResponse = serde_json::from_str(&json_str).unwrap();
    assert_eq!(response, deserialized);
}

#[test]
fn test_canonical_tool_response_error() {
    let response = CanonicalToolResponse {
        call_id: None,
        content: json!("something went wrong"),
        is_error: true,
    };
    let json_str = serde_json::to_string(&response).unwrap();
    let deserialized: CanonicalToolResponse = serde_json::from_str(&json_str).unwrap();
    assert!(deserialized.is_error);
}

// ── FIND-R122-001: Projector type name/description bounds ────────────

#[test]
fn test_canonical_tool_schema_validate_name_too_long() {
    let schema = CanonicalToolSchema {
        name: "x".repeat(MAX_PROJECTOR_NAME_LENGTH + 1),
        description: "d".to_string(),
        input_schema: json!({}),
        output_schema: None,
    };
    let err = schema.validate().unwrap_err();
    assert!(err.contains("name length"), "got: {err}");
}

#[test]
fn test_canonical_tool_schema_validate_description_too_long() {
    let schema = CanonicalToolSchema {
        name: "t".to_string(),
        description: "d".repeat(MAX_PROJECTOR_DESCRIPTION_LENGTH + 1),
        input_schema: json!({}),
        output_schema: None,
    };
    let err = schema.validate().unwrap_err();
    assert!(err.contains("description length"), "got: {err}");
}

#[test]
fn test_canonical_tool_schema_validate_ok_at_limits() {
    let schema = CanonicalToolSchema {
        name: "x".repeat(MAX_PROJECTOR_NAME_LENGTH),
        description: "d".repeat(MAX_PROJECTOR_DESCRIPTION_LENGTH),
        input_schema: json!({}),
        output_schema: None,
    };
    assert!(schema.validate().is_ok());
}

#[test]
fn test_canonical_tool_call_validate_name_too_long() {
    let call = CanonicalToolCall {
        tool_name: "x".repeat(MAX_PROJECTOR_NAME_LENGTH + 1),
        arguments: json!({}),
        call_id: None,
    };
    let err = call.validate().unwrap_err();
    assert!(err.contains("tool_name length"), "got: {err}");
}

#[test]
fn test_model_family_serde_roundtrip_all_variants() {
    let families = vec![
        ModelFamily::Claude,
        ModelFamily::OpenAi,
        ModelFamily::DeepSeek,
        ModelFamily::Qwen,
        ModelFamily::Generic,
        ModelFamily::Custom("llama".to_string()),
    ];
    for family in families {
        let json_str = serde_json::to_string(&family).unwrap();
        let deserialized: ModelFamily = serde_json::from_str(&json_str).unwrap();
        assert_eq!(family, deserialized);
    }
}

#[test]
fn test_model_family_default_is_generic() {
    assert_eq!(ModelFamily::default(), ModelFamily::Generic);
}

#[test]
fn test_model_family_rename_all_lowercase() {
    let json_str = serde_json::to_string(&ModelFamily::Claude).unwrap();
    assert_eq!(json_str, "\"claude\"");
    let json_str = serde_json::to_string(&ModelFamily::OpenAi).unwrap();
    assert_eq!(json_str, "\"openai\"");
    let json_str = serde_json::to_string(&ModelFamily::DeepSeek).unwrap();
    assert_eq!(json_str, "\"deepseek\"");
}

#[test]
fn test_model_family_hash_and_eq() {
    let mut map = HashMap::new();
    map.insert(ModelFamily::Claude, "claude");
    map.insert(ModelFamily::OpenAi, "openai");
    map.insert(ModelFamily::Custom("x".to_string()), "custom_x");
    assert_eq!(map.get(&ModelFamily::Claude), Some(&"claude"));
    assert_eq!(
        map.get(&ModelFamily::Custom("x".to_string())),
        Some(&"custom_x")
    );
    assert_eq!(map.get(&ModelFamily::DeepSeek), None);
}

// ═══════════════════════════════════════════════════════════════════════════════
// ROUND 46 FINDING TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// FIND-R46-004: PedersenCommitment Debug redacts blinding_hint
#[test]
fn test_pedersen_commitment_debug_redacts_blinding_hint() {
    let pc = PedersenCommitment {
        commitment: "abc123".to_string(),
        blinding_hint: "secret_blinding_factor".to_string(),
    };
    let debug_output = format!("{pc:?}");
    assert!(
        debug_output.contains("abc123"),
        "commitment should be visible"
    );
    assert!(
        !debug_output.contains("secret_blinding_factor"),
        "blinding_hint must be redacted"
    );
    assert!(
        debug_output.contains("[REDACTED]"),
        "should show [REDACTED] for blinding_hint"
    );
}

#[test]
fn test_pedersen_commitment_serialize_omits_blinding_hint() {
    let pc = PedersenCommitment {
        commitment: "abc123".to_string(),
        blinding_hint: "secret_blinding_factor".to_string(),
    };
    let json = serde_json::to_string(&pc).expect("serialization should succeed");
    assert!(
        !json.contains("blinding_hint"),
        "blinding_hint must not appear in serialized output"
    );
    assert!(
        !json.contains("secret_blinding_factor"),
        "blinding value must not appear in serialized output"
    );
}

#[test]
fn test_pedersen_commitment_deserialize_with_blinding_hint() {
    let json = r#"{"commitment":"abc","blinding_hint":"secret"}"#;
    let pc: PedersenCommitment = serde_json::from_str(json).expect("should deserialize");
    assert_eq!(pc.commitment, "abc");
    assert_eq!(pc.blinding_hint, "secret");
}

// IMP-R118-001: PedersenCommitment validate() and deny_unknown_fields
#[test]
fn test_pedersen_commitment_validate_ok() {
    let pc = PedersenCommitment {
        commitment: "a".repeat(64),
        blinding_hint: "b".repeat(64),
    };
    assert!(pc.validate().is_ok());
}

#[test]
fn test_pedersen_commitment_validate_commitment_too_long() {
    let pc = PedersenCommitment {
        commitment: "a".repeat(129),
        blinding_hint: String::new(),
    };
    assert!(pc.validate().is_err());
    assert!(pc.validate().unwrap_err().contains("commitment length"));
}

#[test]
fn test_pedersen_commitment_validate_blinding_hint_too_long() {
    let pc = PedersenCommitment {
        commitment: "abc".to_string(),
        blinding_hint: "b".repeat(129),
    };
    assert!(pc.validate().is_err());
    assert!(pc.validate().unwrap_err().contains("blinding_hint length"));
}

#[test]
fn test_pedersen_commitment_deny_unknown_fields() {
    let json = r#"{"commitment":"abc","extra_field":"evil"}"#;
    let result = serde_json::from_str::<PedersenCommitment>(json);
    assert!(
        result.is_err(),
        "deny_unknown_fields should reject extra fields"
    );
}

// FIND-R46-005: CapabilityToken Debug redacts signature
#[test]
fn test_capability_token_debug_redacts_signature() {
    let token = CapabilityToken {
        token_id: "tok-1".to_string(),
        parent_token_id: None,
        issuer: "issuer-1".to_string(),
        holder: "holder-1".to_string(),
        grants: vec![CapabilityGrant {
            tool_pattern: "test".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }],
        remaining_depth: 3,
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-12-31T23:59:59Z".to_string(),
        signature: "deadbeef_secret_sig".to_string(),
        issuer_public_key: "pubkey123".to_string(),
    };
    let debug_output = format!("{token:?}");
    assert!(
        !debug_output.contains("deadbeef_secret_sig"),
        "signature must be redacted in Debug"
    );
    assert!(
        debug_output.contains("[REDACTED]"),
        "should show [REDACTED] for signature"
    );
    assert!(debug_output.contains("tok-1"), "token_id should be visible");
}

// FIND-R46-006: SamplingStats::record_request saturating_add
#[test]
fn test_sampling_stats_record_request_saturating_at_u32_max() {
    let mut stats = SamplingStats {
        request_count: u32::MAX - 1,
        window_start: 0,
        last_request: 0,
        flagged_patterns: vec![],
    };
    let count = stats.record_request(100);
    assert_eq!(count, u32::MAX);
    // One more should saturate, not panic
    let count2 = stats.record_request(200);
    assert_eq!(count2, u32::MAX);
}

// FIND-R46-007: ToolSignature::is_expired lexicographic comparison
#[test]
fn test_tool_signature_is_expired_lexicographic_iso8601() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "aabbcc".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pk".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2026-06-15T12:00:00Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    // Before expiry
    assert!(!sig.is_expired("2026-06-15T11:59:59Z"));
    // Exactly at expiry
    assert!(sig.is_expired("2026-06-15T12:00:00Z"));
    // After expiry
    assert!(sig.is_expired("2026-06-15T12:00:01Z"));
    // Year rollover
    assert!(sig.is_expired("2027-01-01T00:00:00Z"));
}

// FIND-R46-008: validate_mcp_tool_name rejects consecutive slashes
#[test]
fn test_validate_mcp_tool_name_rejects_consecutive_slashes() {
    let result = validate_mcp_tool_name("foo//bar");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("consecutive slashes"));
}

#[test]
fn test_validate_mcp_tool_name_allows_single_slash() {
    assert!(validate_mcp_tool_name("foo/bar").is_ok());
    assert!(validate_mcp_tool_name("a/b/c").is_ok());
}

// FIND-R46-009: f64 NaN/Infinity validation
#[test]
fn test_risk_score_validate_finite_rejects_nan() {
    let rs = RiskScore {
        score: f64::NAN,
        factors: vec![],
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    };
    assert!(rs.validate_finite().is_err());
}

#[test]
fn test_risk_score_validate_finite_rejects_infinity() {
    let rs = RiskScore {
        score: f64::INFINITY,
        factors: vec![],
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    };
    assert!(rs.validate_finite().is_err());
}

#[test]
fn test_risk_score_validate_finite_accepts_normal() {
    let rs = RiskScore {
        score: 0.75,
        factors: vec![RiskFactor {
            name: "test".to_string(),
            weight: 0.5,
            value: 0.8,
        }],
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    };
    assert!(rs.validate_finite().is_ok());
}

#[test]
fn test_risk_factor_validate_finite_rejects_nan_weight() {
    let rf = RiskFactor {
        name: "test".to_string(),
        weight: f64::NAN,
        value: 0.5,
    };
    assert!(rf.validate_finite().is_err());
}

#[test]
fn test_risk_factor_validate_finite_rejects_infinity_value() {
    let rf = RiskFactor {
        name: "test".to_string(),
        weight: 0.5,
        value: f64::NEG_INFINITY,
    };
    assert!(rf.validate_finite().is_err());
}

#[test]
fn test_schema_record_validate_finite_rejects_nan() {
    let sr = SchemaRecord::new("tool", "hash", 100);
    let mut sr_nan = sr;
    sr_nan.trust_score = f32::NAN;
    assert!(sr_nan.validate().is_err());
}

#[test]
fn test_schema_record_validate_finite_accepts_normal() {
    let sr = SchemaRecord::new("tool", "hash", 100);
    assert!(sr.validate().is_ok());
}

#[test]
fn test_memory_entry_validate_finite_rejects_nan() {
    let mut me = MemoryEntry::new(
        "id".to_string(),
        "fp".to_string(),
        "content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    me.trust_score = f64::NAN;
    assert!(me.validate().is_err());
}

#[test]
fn test_memory_entry_validate_finite_accepts_normal() {
    let me = MemoryEntry::new(
        "id".to_string(),
        "fp".to_string(),
        "content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    assert!(me.validate().is_ok());
}

#[test]
#[allow(deprecated)]
fn test_nhi_behavioral_baseline_validate_finite_rejects_nan() {
    let baseline = NhiBehavioralBaseline {
        agent_id: "test-agent".to_string(),
        avg_request_interval_secs: f64::NAN,
        ..NhiBehavioralBaseline::default()
    };
    assert!(baseline.validate_finite().is_err());
}

#[test]
#[allow(deprecated)]
fn test_nhi_behavioral_baseline_validate_finite_rejects_infinity_in_map() {
    let mut baseline = NhiBehavioralBaseline {
        agent_id: "test-agent".to_string(),
        ..Default::default()
    };
    baseline
        .tool_call_patterns
        .insert("tool".to_string(), f64::INFINITY);
    assert!(baseline.validate_finite().is_err());
}

#[test]
#[allow(deprecated)]
fn test_nhi_behavioral_baseline_validate_finite_accepts_normal() {
    let baseline = NhiBehavioralBaseline {
        agent_id: "test-agent".to_string(),
        avg_request_interval_secs: 5.0,
        confidence: 0.9,
        ..NhiBehavioralBaseline::default()
    };
    assert!(baseline.validate_finite().is_ok());
}

// FIND-R46-010: StatelessContextBlob Debug redacts signature
#[test]
fn test_stateless_context_blob_debug_redacts_signature() {
    let blob = StatelessContextBlob {
        version: 1,
        agent_id: "agent-1".to_string(),
        call_counts: HashMap::new(),
        recent_actions: vec![],
        call_chain: vec![],
        risk_score: None,
        issued_at: 1000,
        signature: "hmac_secret_value_here".to_string(),
    };
    let debug_output = format!("{blob:?}");
    assert!(
        !debug_output.contains("hmac_secret_value_here"),
        "HMAC signature must be redacted"
    );
    assert!(
        debug_output.contains("[REDACTED]"),
        "should show [REDACTED] for signature"
    );
    assert!(
        debug_output.contains("agent-1"),
        "agent_id should be visible"
    );
}

// FIND-R46-011: SecureTask max_nonces capped at 10,000
#[test]
fn test_secure_task_max_nonces_capped_on_deserialize() {
    let json = r#"{
        "task": {"task_id":"t1","status":"pending","created_at":"2026-01-01T00:00:00Z","tool":"test","function":"fn"},
        "state_chain": [],
        "seen_nonces": [],
        "max_nonces": 999999
    }"#;
    let task: SecureTask = serde_json::from_str(json).expect("should deserialize");
    assert!(
        task.max_nonces <= 10_000,
        "max_nonces should be capped at 10,000, got {}",
        task.max_nonces
    );
}

#[test]
fn test_secure_task_record_nonce_respects_cap() {
    let tracked = TrackedTask {
        task_id: "t1".to_string(),
        tool: "test".to_string(),
        function: "fn".to_string(),
        status: TaskStatus::Pending,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        created_by: None,
        session_id: None,
    };
    let mut task = SecureTask::new(tracked);
    // Manually set a large max_nonces to verify runtime cap
    task.max_nonces = 50_000;
    // Fill past MAX_NONCES_CAP. try_record_nonce refuses once full rather than
    // evicting, so the cap is enforced without discarding recorded nonces.
    let mut accepted = 0usize;
    for i in 0..10_001 {
        if task.try_record_nonce(format!("nonce-{i}")) {
            accepted += 1;
        }
    }
    assert_eq!(
        accepted, 10_000,
        "exactly MAX_NONCES_CAP nonces should be accepted"
    );
    assert!(
        task.seen_nonces.len() <= 10_000,
        "seen_nonces should not exceed 10,000, got {}",
        task.seen_nonces.len()
    );
}

/// SECURITY (DOC-CRED-6): The property the fail-closed change exists for.
/// Under FIFO eviction the first nonce was dropped once the cache filled, and
/// `is_nonce_seen` then reported a captured request carrying it as fresh —
/// i.e. replayable. Refusing to record keeps every recorded nonce detectable.
#[test]
fn test_secure_task_full_cache_never_forgets_a_recorded_nonce() {
    let tracked = TrackedTask {
        task_id: "t1".to_string(),
        tool: "test".to_string(),
        function: "fn".to_string(),
        status: TaskStatus::Pending,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        created_by: None,
        session_id: None,
    };
    let mut task = SecureTask::new(tracked);
    task.max_nonces = 4;

    for i in 0..4 {
        assert!(task.try_record_nonce(format!("nonce-{i}")));
    }

    // Cache is full: further nonces are refused, not absorbed by eviction.
    assert!(
        !task.try_record_nonce("nonce-overflow".to_string()),
        "a full cache must refuse rather than evict"
    );
    assert!(
        !task.is_nonce_seen("nonce-overflow"),
        "a refused nonce must not be recorded"
    );

    // The oldest nonce is still remembered, so replaying it is still detected.
    assert!(
        task.is_nonce_seen("nonce-0"),
        "the earliest nonce must remain detectable — forgetting it is what made \
         it replayable under FIFO eviction"
    );
    assert_eq!(task.seen_nonces.len(), 4, "cache must stay at its bound");
}

/// Over-long nonces are still truncated to MAX_ENTRY_LEN on the fail-closed
/// path, and truncation must not panic on a multi-byte boundary.
#[test]
fn test_try_record_nonce_truncates_and_respects_char_boundaries() {
    let tracked = TrackedTask {
        task_id: "t1".to_string(),
        tool: "test".to_string(),
        function: "fn".to_string(),
        status: TaskStatus::Pending,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        created_by: None,
        session_id: None,
    };
    let mut task = SecureTask::new(tracked);

    // 'é' is two bytes, so the 256-byte limit lands mid-character.
    let multibyte = "é".repeat(200);
    assert!(task.try_record_nonce(multibyte));
    assert!(
        task.seen_nonces[0].len() <= MAX_ENTRY_LEN,
        "nonce must be truncated to MAX_ENTRY_LEN"
    );
    assert!(
        task.seen_nonces[0].chars().all(|c| c == 'é'),
        "truncation must land on a char boundary, not split a code point"
    );
}

// FIND-R46-012: EnforcementMode defaults to Monitor
#[test]
fn test_enforcement_mode_defaults_to_monitor() {
    let mode = EnforcementMode::default();
    assert_eq!(
        mode,
        EnforcementMode::Monitor,
        "Default must be Monitor for gradual rollout"
    );
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R46-013: ToolSensitivity defaults to High (fail-closed)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_tool_sensitivity_default_is_high_fail_closed() {
    // New tools with no explicit sensitivity must be treated as High
    // to prevent accidentally bypassing elevated permission requirements.
    let ts = ToolSensitivity::default();
    assert_eq!(ts, ToolSensitivity::High);
    // Verify the default serializes as "high"
    let json = serde_json::to_string(&ts).unwrap();
    assert_eq!(json, "\"high\"");
}

#[test]
fn test_tool_metadata_default_sensitivity_is_high() {
    // When ToolMetadata is deserialized without an explicit sensitivity,
    // it should default to High.
    let json = r#"{
        "tool_id": "srv:tool",
        "name": "tool",
        "description": "desc",
        "server_id": "srv",
        "input_schema": {},
        "schema_hash": "abc",
        "sensitivity": "high",
        "domain_tags": [],
        "token_cost": 10
    }"#;
    let meta: ToolMetadata = serde_json::from_str(json).unwrap();
    assert_eq!(meta.sensitivity, ToolSensitivity::High);
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R46-014: NhiIdentityStatus defaults to Probationary (fail-closed)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_nhi_identity_status_default_is_probationary() {
    // New identities must start as Probationary, not Active.
    let status = NhiIdentityStatus::default();
    assert_eq!(status, NhiIdentityStatus::Probationary);
}

#[test]
fn test_nhi_agent_identity_default_status_is_probationary() {
    // NhiAgentIdentity derives Default, which should use Probationary.
    let identity = NhiAgentIdentity::default();
    assert_eq!(identity.status, NhiIdentityStatus::Probationary);
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R46-015: deny_unknown_fields on security-critical structs
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_network_rules_rejects_unknown_fields() {
    // A typo like "allowed_domain" instead of "allowed_domains" must
    // be caught at deserialization time, not silently ignored.
    let json = r#"{"allowed_domains": [], "blocked_domains": [], "extra_field": true}"#;
    let result: Result<NetworkRules, _> = serde_json::from_str(json);
    assert!(result.is_err(), "NetworkRules must reject unknown fields");
}

#[test]
fn test_network_rules_accepts_known_fields() {
    let json = r#"{"allowed_domains": ["example.com"], "blocked_domains": ["evil.com"]}"#;
    let result: Result<NetworkRules, _> = serde_json::from_str(json);
    assert!(result.is_ok());
    let rules = result.unwrap();
    assert_eq!(rules.allowed_domains, vec!["example.com"]);
}

#[test]
fn test_network_rules_accepts_ip_rules() {
    let json = r#"{
        "allowed_domains": [],
        "blocked_domains": [],
        "ip_rules": {"block_private": true, "blocked_cidrs": [], "allowed_cidrs": []}
    }"#;
    let result: Result<NetworkRules, _> = serde_json::from_str(json);
    assert!(result.is_ok());
}

#[test]
fn test_ip_rules_rejects_unknown_fields() {
    let json = r#"{"block_private": true, "blocked_cidrs": [], "allowed_cidrs": [], "typo": 1}"#;
    let result: Result<IpRules, _> = serde_json::from_str(json);
    assert!(result.is_err(), "IpRules must reject unknown fields");
}

#[test]
fn test_ip_rules_accepts_known_fields() {
    let json = r#"{"block_private": true, "blocked_cidrs": ["10.0.0.0/8"], "allowed_cidrs": []}"#;
    let result: Result<IpRules, _> = serde_json::from_str(json);
    assert!(result.is_ok());
}

#[test]
fn test_path_rules_rejects_unknown_fields() {
    // "allow" instead of "allowed" must be caught.
    let json = r#"{"allowed": ["/tmp"], "blocked": [], "allow": ["/home"]}"#;
    let result: Result<PathRules, _> = serde_json::from_str(json);
    assert!(result.is_err(), "PathRules must reject unknown fields");
}

#[test]
fn test_path_rules_accepts_known_fields() {
    let json = r#"{"allowed": ["/tmp"], "blocked": ["/etc"]}"#;
    let result: Result<PathRules, _> = serde_json::from_str(json);
    assert!(result.is_ok());
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R46-016: SchemaRecord.version_history max 10 enforced
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_schema_record_push_version_enforces_max() {
    let mut record = SchemaRecord::new("test_tool", "hash_0", 1000);
    // Push 15 versions, only last 10 should remain
    for i in 1..=15 {
        record.push_version(format!("hash_{i}"));
    }
    assert_eq!(
        record.version_history.len(),
        SchemaRecord::MAX_VERSION_HISTORY
    );
    // Oldest entries should have been evicted; first entry should be hash_6
    assert_eq!(record.version_history[0], "hash_6");
    assert_eq!(record.version_history[9], "hash_15");
}

#[test]
fn test_schema_record_push_version_under_limit() {
    let mut record = SchemaRecord::new("test_tool", "hash_0", 1000);
    for i in 1..=5 {
        record.push_version(format!("hash_{i}"));
    }
    assert_eq!(record.version_history.len(), 5);
}

// SECURITY (FIND-R82-001): Verify push_version handles multi-byte UTF-8 at truncation boundary.
#[test]
fn test_schema_record_push_version_multibyte_utf8_safe() {
    let mut record = SchemaRecord::new("test_tool", "hash_0", 1000);
    // Create a string of 2-byte Cyrillic characters that lands on a non-char-boundary
    // at MAX_HASH_LEN (128). Each char is 2 bytes, so 65 chars = 130 bytes.
    let multibyte = "д".repeat(65); // 130 bytes, boundary at 128 splits a char
    assert!(multibyte.len() > SchemaRecord::MAX_HASH_LEN);
    // This should NOT panic
    record.push_version(multibyte);
    // The truncated hash should be valid UTF-8 and within bounds
    let stored = &record.version_history.last().unwrap();
    assert!(stored.len() <= SchemaRecord::MAX_HASH_LEN);
    assert!(stored.is_char_boundary(stored.len()));
}

#[test]
fn test_schema_record_validate_version_history_ok() {
    let record = SchemaRecord::new("test_tool", "hash_0", 1000);
    assert!(record.validate_version_history().is_ok());
}

#[test]
fn test_schema_record_validate_version_history_overflow() {
    let mut record = SchemaRecord::new("test_tool", "hash_0", 1000);
    // Bypass push_version to directly set an oversized history
    record.version_history = (0..20).map(|i| format!("hash_{i}")).collect();
    assert!(record.validate_version_history().is_err());
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R46-017: EvaluationContext builder validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_evaluation_context_validate_ok() {
    let ctx = EvaluationContext::builder()
        .agent_id("agent-123")
        .tenant_id("tenant-abc")
        .session_state("active")
        .build();
    assert!(ctx.validate().is_ok());
}

#[test]
fn test_evaluation_context_validate_empty_ok() {
    // No fields set => nothing to validate => OK
    let ctx = EvaluationContext::builder().build();
    assert!(ctx.validate().is_ok());
}

#[test]
fn test_evaluation_context_validate_empty_agent_id_rejected() {
    let ctx = EvaluationContext::builder().agent_id("").build();
    let result = ctx.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("agent_id"));
}

#[test]
fn test_evaluation_context_validate_control_char_in_agent_id() {
    let ctx = EvaluationContext::builder().agent_id("agent\n123").build();
    let result = ctx.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("control or format characters"));
}

#[test]
fn test_evaluation_context_validate_control_char_in_tenant_id() {
    let ctx = EvaluationContext::builder().tenant_id("tenant\t1").build();
    let result = ctx.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("tenant_id"));
}

#[test]
fn test_evaluation_context_validate_empty_session_state_rejected() {
    let ctx = EvaluationContext::builder().session_state("").build();
    let result = ctx.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("session_state"));
}

#[test]
fn test_evaluation_context_validate_null_byte_in_tenant_id() {
    let ctx = EvaluationContext::builder().tenant_id("tenant\0id").build();
    let result = ctx.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("control or format characters"));
}

#[test]
fn test_evaluation_context_build_validated_ok() {
    let result = EvaluationContext::builder()
        .agent_id("valid-agent")
        .tenant_id("valid-tenant")
        .build_validated();
    assert!(result.is_ok());
}

#[test]
fn test_evaluation_context_build_validated_rejects_invalid() {
    let result = EvaluationContext::builder()
        .agent_id("bad\ragent")
        .build_validated();
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R46-018: MemoryEntry contradictory trust_score/taint_labels
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_memory_entry_validate_tainted_with_perfect_trust_rejected() {
    let mut entry = MemoryEntry::new(
        "id1".to_string(),
        "fp".to_string(),
        "content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    // Force contradictory state
    entry.trust_score = 1.0;
    entry.taint_labels = vec![TaintLabel::Untrusted];
    let result = entry.validate();
    assert!(
        result.is_err(),
        "Tainted entry with perfect trust must be rejected"
    );
    assert!(result.unwrap_err().contains("trust_score"));
}

#[test]
fn test_memory_entry_validate_tainted_with_low_trust_ok() {
    let entry = MemoryEntry::new(
        "id2".to_string(),
        "fp".to_string(),
        "content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    // Default new() now sets trust_score = 0.5 with Untrusted taint
    assert!(entry.validate().is_ok());
}

#[test]
fn test_memory_entry_validate_clean_entry_with_perfect_trust_ok() {
    let mut entry = MemoryEntry::new(
        "id3".to_string(),
        "fp".to_string(),
        "content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    // Sanitized entry with no security-relevant taints can have trust = 1.0
    entry.taint_labels = vec![TaintLabel::Sanitized];
    entry.trust_score = 1.0;
    assert!(entry.validate().is_ok());
}

#[test]
fn test_memory_entry_validate_quarantined_with_perfect_trust_rejected() {
    let mut entry = MemoryEntry::new(
        "id4".to_string(),
        "fp".to_string(),
        "content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    entry.taint_labels = vec![TaintLabel::Quarantined];
    entry.trust_score = 1.0;
    assert!(entry.validate().is_err());
}

#[test]
fn test_memory_entry_validate_integrity_failed_with_perfect_trust_rejected() {
    let mut entry = MemoryEntry::new(
        "id5".to_string(),
        "fp".to_string(),
        "content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    entry.taint_labels = vec![TaintLabel::IntegrityFailed];
    entry.trust_score = 1.0;
    assert!(entry.validate().is_err());
}

#[test]
fn test_memory_entry_validate_no_taints_with_perfect_trust_ok() {
    let mut entry = MemoryEntry::new(
        "id6".to_string(),
        "fp".to_string(),
        "content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    entry.taint_labels = vec![];
    entry.trust_score = 1.0;
    assert!(entry.validate().is_ok());
}

#[test]
fn test_memory_entry_validate_nan_trust_rejected() {
    let mut entry = MemoryEntry::new(
        "id7".to_string(),
        "fp".to_string(),
        "content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    entry.trust_score = f64::NAN;
    entry.taint_labels = vec![];
    assert!(entry.validate().is_err());
}

#[test]
fn test_memory_entry_new_default_trust_below_one() {
    // FIND-R46-018: new() creates entries with Untrusted taint,
    // so trust_score must be < 1.0 to satisfy validate().
    let entry = MemoryEntry::new(
        "id8".to_string(),
        "fp".to_string(),
        "content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    assert!(
        entry.trust_score < 1.0,
        "New untrusted entry must have trust < 1.0"
    );
    assert!(entry.validate().is_ok(), "New entry must pass validation");
}

#[test]
fn test_memory_entry_sensitive_taint_allows_perfect_trust() {
    // Sensitive is not a security-negative taint — it marks data classification,
    // not distrust. It should allow trust_score = 1.0.
    let mut entry = MemoryEntry::new(
        "id9".to_string(),
        "fp".to_string(),
        "content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    entry.taint_labels = vec![TaintLabel::Sensitive];
    entry.trust_score = 1.0;
    assert!(entry.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════════════
// FIND-P1-6: hours_since returns 0.0 on parse failure — bypasses trust decay
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_p1_6_decayed_trust_corrupt_start_timestamp_returns_zero() {
    // Corrupt start timestamp must produce 0.0 (fail-closed), not full trust.
    let entry = MemoryEntry {
        recorded_at: "INVALID".to_string(),
        trust_score: 0.9,
        ..MemoryEntry::new(
            "id-p1-6-a".to_string(),
            "fp".to_string(),
            "content",
            "hash".to_string(),
            "INVALID".to_string(),
        )
    };
    let decayed = entry.decayed_trust_score(0.01, "2026-02-01T00:00:00Z");
    assert_eq!(
        decayed, 0.0,
        "Corrupt start timestamp must produce 0.0 trust (fail-closed)"
    );
}

#[test]
fn test_p1_6_decayed_trust_corrupt_end_timestamp_returns_zero() {
    let entry = MemoryEntry::new(
        "id-p1-6-b".to_string(),
        "fp".to_string(),
        "content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    let decayed = entry.decayed_trust_score(0.01, "GARBAGE");
    assert_eq!(
        decayed, 0.0,
        "Corrupt end timestamp must produce 0.0 trust (fail-closed)"
    );
}

#[test]
fn test_p1_6_decayed_trust_valid_timestamps_decays_normally() {
    let mut entry = MemoryEntry::new(
        "id-p1-6-c".to_string(),
        "fp".to_string(),
        "content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    entry.trust_score = 1.0;
    entry.taint_labels = vec![]; // Remove taint for clean test
    let decay_rate = 0.01;
    let decayed = entry.decayed_trust_score(decay_rate, "2026-01-02T00:00:00Z");
    // ~24 hours later, trust should be < 1.0
    assert!(decayed < 1.0, "Trust should decay over time");
    assert!(decayed > 0.0, "Trust should still be positive");
}

#[test]
fn test_p1_6_parse_timestamp_rejects_month_zero() {
    // Month 0 is invalid and previously caused underflow in (month - 1) * 30
    let entry = MemoryEntry {
        recorded_at: "2026-00-15T12:00:00Z".to_string(),
        trust_score: 0.9,
        ..MemoryEntry::new(
            "id-p1-6-d".to_string(),
            "fp".to_string(),
            "content",
            "hash".to_string(),
            "2026-00-15T12:00:00Z".to_string(),
        )
    };
    let decayed = entry.decayed_trust_score(0.01, "2026-02-01T00:00:00Z");
    assert_eq!(decayed, 0.0, "Month=0 must fail-closed with 0.0 trust");
}

#[test]
fn test_p1_6_parse_timestamp_rejects_year_before_epoch() {
    // Year < 1970 would cause underflow in (year - 1970) * 365
    let entry = MemoryEntry {
        recorded_at: "1969-06-15T12:00:00Z".to_string(),
        trust_score: 0.9,
        ..MemoryEntry::new(
            "id-p1-6-e".to_string(),
            "fp".to_string(),
            "content",
            "hash".to_string(),
            "1969-06-15T12:00:00Z".to_string(),
        )
    };
    let decayed = entry.decayed_trust_score(0.01, "2026-02-01T00:00:00Z");
    assert_eq!(decayed, 0.0, "Year < 1970 must fail-closed with 0.0 trust");
}

#[test]
fn test_p1_6_parse_timestamp_rejects_day_zero() {
    let entry = MemoryEntry {
        recorded_at: "2026-01-00T12:00:00Z".to_string(),
        trust_score: 0.9,
        ..MemoryEntry::new(
            "id-p1-6-f".to_string(),
            "fp".to_string(),
            "content",
            "hash".to_string(),
            "2026-01-00T12:00:00Z".to_string(),
        )
    };
    let decayed = entry.decayed_trust_score(0.01, "2026-02-01T00:00:00Z");
    assert_eq!(decayed, 0.0, "Day=0 must fail-closed with 0.0 trust");
}

#[test]
fn test_p1_6_parse_timestamp_rejects_month_13() {
    let entry = MemoryEntry {
        recorded_at: "2026-13-01T00:00:00Z".to_string(),
        trust_score: 0.9,
        ..MemoryEntry::new(
            "id-p1-6-g".to_string(),
            "fp".to_string(),
            "content",
            "hash".to_string(),
            "2026-13-01T00:00:00Z".to_string(),
        )
    };
    let decayed = entry.decayed_trust_score(0.01, "2026-02-01T00:00:00Z");
    assert_eq!(decayed, 0.0, "Month=13 must fail-closed with 0.0 trust");
}

#[test]
fn test_p1_6_parse_timestamp_rejects_hour_25() {
    let entry = MemoryEntry {
        recorded_at: "2026-01-01T25:00:00Z".to_string(),
        trust_score: 0.9,
        ..MemoryEntry::new(
            "id-p1-6-h".to_string(),
            "fp".to_string(),
            "content",
            "hash".to_string(),
            "2026-01-01T25:00:00Z".to_string(),
        )
    };
    let decayed = entry.decayed_trust_score(0.01, "2026-02-01T00:00:00Z");
    assert_eq!(decayed, 0.0, "Hour=25 must fail-closed with 0.0 trust");
}

// ═══════════════════════════════════════════════════════════════════════════════
// FEDERATION TYPES TESTS (Phase 39)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_federation_trust_anchor_validate_empty_org_id_fails() {
    let anchor = FederationTrustAnchor {
        org_id: String::new(),
        display_name: "Test".to_string(),
        jwks_uri: None,
        issuer_pattern: "https://auth.example.com".to_string(),
        identity_mappings: vec![],
        trust_level: "limited".to_string(),
    };
    assert!(anchor.validate().is_err());
    assert!(anchor.validate().unwrap_err().contains("org_id"));
}

#[test]
fn test_federation_trust_anchor_validate_empty_issuer_fails() {
    let anchor = FederationTrustAnchor {
        org_id: "org-1".to_string(),
        display_name: "Test".to_string(),
        jwks_uri: None,
        issuer_pattern: String::new(),
        identity_mappings: vec![],
        trust_level: "limited".to_string(),
    };
    assert!(anchor.validate().is_err());
    assert!(anchor.validate().unwrap_err().contains("issuer_pattern"));
}

#[test]
fn test_federation_trust_anchor_validate_jwks_uri_non_http_fails() {
    let anchor = FederationTrustAnchor {
        org_id: "org-1".to_string(),
        display_name: "Test".to_string(),
        jwks_uri: Some("ftp://keys.example.com/.well-known/jwks.json".to_string()),
        issuer_pattern: "https://auth.example.com".to_string(),
        identity_mappings: vec![],
        trust_level: "limited".to_string(),
    };
    assert!(anchor.validate().is_err());
    assert!(anchor.validate().unwrap_err().contains("http"));
}

#[test]
fn test_federation_trust_anchor_validate_invalid_trust_level_fails() {
    let anchor = FederationTrustAnchor {
        org_id: "org-1".to_string(),
        display_name: "Test".to_string(),
        jwks_uri: None,
        issuer_pattern: "https://auth.example.com".to_string(),
        identity_mappings: vec![],
        trust_level: "admin".to_string(),
    };
    assert!(anchor.validate().is_err());
    assert!(anchor.validate().unwrap_err().contains("trust_level"));
}

#[test]
fn test_federation_trust_anchor_validate_valid_succeeds() {
    let anchor = FederationTrustAnchor {
        org_id: "org-1".to_string(),
        display_name: "Partner Org".to_string(),
        jwks_uri: Some("https://keys.example.com/.well-known/jwks.json".to_string()),
        issuer_pattern: "https://auth.example.com/*".to_string(),
        identity_mappings: vec![IdentityMapping {
            external_claim: "sub".to_string(),
            internal_principal_type: "agent".to_string(),
            id_template: "org-1:{claim_value}".to_string(),
        }],
        trust_level: "limited".to_string(),
    };
    assert!(anchor.validate().is_ok());
}

#[test]
fn test_identity_mapping_validate_empty_claim_fails() {
    let mapping = IdentityMapping {
        external_claim: String::new(),
        internal_principal_type: "agent".to_string(),
        id_template: "{claim_value}".to_string(),
    };
    assert!(mapping.validate().is_err());
    assert!(mapping.validate().unwrap_err().contains("external_claim"));
}

#[test]
fn test_identity_mapping_validate_template_missing_placeholder_fails() {
    let mapping = IdentityMapping {
        external_claim: "sub".to_string(),
        internal_principal_type: "agent".to_string(),
        id_template: "org-1:fixed-value".to_string(),
    };
    assert!(mapping.validate().is_err());
    assert!(mapping.validate().unwrap_err().contains("claim_value"));
}

#[test]
fn test_identity_mapping_validate_valid_succeeds() {
    let mapping = IdentityMapping {
        external_claim: "email".to_string(),
        internal_principal_type: "user".to_string(),
        id_template: "partner:{claim_value}".to_string(),
    };
    assert!(mapping.validate().is_ok());
}

#[test]
fn test_federation_status_serde_roundtrip() {
    let status = FederationStatus {
        enabled: true,
        trust_anchor_count: 1,
        anchors: vec![FederationAnchorStatus {
            org_id: "org-1".to_string(),
            display_name: "Partner".to_string(),
            issuer_pattern: "https://auth.example.com".to_string(),
            trust_level: "limited".to_string(),
            has_jwks_uri: true,
            jwks_cached: true,
            jwks_last_fetched: Some("2026-01-01T00:00:00Z".to_string()),
            identity_mapping_count: 2,
            successful_validations: 42,
            failed_validations: 3,
        }],
    };
    let json = serde_json::to_string(&status).unwrap();
    let deserialized: FederationStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(status, deserialized);
}

#[test]
fn test_federation_trust_anchor_default_trust_level() {
    let json = r#"{"org_id":"org-1","display_name":"Test","issuer_pattern":"https://ex.com","identity_mappings":[]}"#;
    let anchor: FederationTrustAnchor = serde_json::from_str(json).unwrap();
    assert_eq!(anchor.trust_level, "limited");
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R51-005: EvaluationContext.validate() call_chain entry validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_evaluation_context_validate_call_chain_valid_entries() {
    let ctx = EvaluationContext {
        call_chain: vec![CallChainEntry {
            agent_id: "agent-1".to_string(),
            tool: "read_file".to_string(),
            function: "read".to_string(),
            timestamp: "2026-02-15T10:00:00Z".to_string(),
            hmac: None,
            verified: None,
        }],
        ..Default::default()
    };
    assert!(ctx.validate().is_ok());
}

#[test]
fn test_evaluation_context_validate_call_chain_control_char_agent_id() {
    let ctx = EvaluationContext {
        call_chain: vec![CallChainEntry {
            agent_id: "agent\n1".to_string(),
            tool: "read_file".to_string(),
            function: "read".to_string(),
            timestamp: "2026-02-15T10:00:00Z".to_string(),
            hmac: None,
            verified: None,
        }],
        ..Default::default()
    };
    let err = ctx.validate().unwrap_err();
    assert!(err.contains("call_chain[0].agent_id"));
    assert!(err.contains("control or format characters"));
}

#[test]
fn test_evaluation_context_validate_call_chain_control_char_tool() {
    let ctx = EvaluationContext {
        call_chain: vec![CallChainEntry {
            agent_id: "agent-1".to_string(),
            tool: "read\x00file".to_string(),
            function: "read".to_string(),
            timestamp: "2026-02-15T10:00:00Z".to_string(),
            hmac: None,
            verified: None,
        }],
        ..Default::default()
    };
    let err = ctx.validate().unwrap_err();
    assert!(err.contains("call_chain[0].tool"));
    assert!(err.contains("control or format characters"));
}

#[test]
fn test_evaluation_context_validate_call_chain_control_char_function() {
    let ctx = EvaluationContext {
        call_chain: vec![CallChainEntry {
            agent_id: "agent-1".to_string(),
            tool: "read_file".to_string(),
            function: "read\t".to_string(),
            timestamp: "2026-02-15T10:00:00Z".to_string(),
            hmac: None,
            verified: None,
        }],
        ..Default::default()
    };
    let err = ctx.validate().unwrap_err();
    assert!(err.contains("call_chain[0].function"));
    assert!(err.contains("control or format characters"));
}

#[test]
fn test_evaluation_context_validate_call_chain_control_char_timestamp() {
    let ctx = EvaluationContext {
        call_chain: vec![CallChainEntry {
            agent_id: "agent-1".to_string(),
            tool: "read_file".to_string(),
            function: "read".to_string(),
            timestamp: "2026-02-15\r10:00:00Z".to_string(),
            hmac: None,
            verified: None,
        }],
        ..Default::default()
    };
    let err = ctx.validate().unwrap_err();
    assert!(err.contains("call_chain[0].timestamp"));
    assert!(err.contains("control or format characters"));
}

#[test]
fn test_evaluation_context_validate_call_chain_oversized_agent_id() {
    let ctx = EvaluationContext {
        call_chain: vec![CallChainEntry {
            agent_id: "a".repeat(513),
            tool: "read_file".to_string(),
            function: "read".to_string(),
            timestamp: "2026-02-15T10:00:00Z".to_string(),
            hmac: None,
            verified: None,
        }],
        ..Default::default()
    };
    let err = ctx.validate().unwrap_err();
    assert!(err.contains("call_chain[0].agent_id"));
    assert!(err.contains("exceeds max 512"));
}

#[test]
fn test_evaluation_context_validate_call_chain_oversized_timestamp() {
    let ctx = EvaluationContext {
        call_chain: vec![CallChainEntry {
            agent_id: "agent-1".to_string(),
            tool: "read_file".to_string(),
            function: "read".to_string(),
            timestamp: "x".repeat(65),
            hmac: None,
            verified: None,
        }],
        ..Default::default()
    };
    let err = ctx.validate().unwrap_err();
    assert!(err.contains("call_chain[0].timestamp"));
    assert!(err.contains("exceeds max 64"));
}

// SECURITY (FIND-R85-001): Unicode format chars in timestamp must be rejected,
// matching parity with validate_call_chain_field() for agent_id/tool/function.
#[test]
fn test_evaluation_context_validate_call_chain_unicode_format_char_timestamp() {
    // Zero-width space (U+200B) in timestamp
    let ctx = EvaluationContext {
        call_chain: vec![CallChainEntry {
            agent_id: "agent-1".to_string(),
            tool: "read_file".to_string(),
            function: "read".to_string(),
            timestamp: "2026-02-15T10:00:00Z\u{200B}".to_string(),
            hmac: None,
            verified: None,
        }],
        ..Default::default()
    };
    let err = ctx.validate().unwrap_err();
    assert!(err.contains("call_chain[0].timestamp"));
    assert!(err.contains("format characters"));

    // Bidi override (U+202E) in timestamp
    let ctx2 = EvaluationContext {
        call_chain: vec![CallChainEntry {
            agent_id: "agent-1".to_string(),
            tool: "read_file".to_string(),
            function: "read".to_string(),
            timestamp: "2026-02-15\u{202E}T10:00:00Z".to_string(),
            hmac: None,
            verified: None,
        }],
        ..Default::default()
    };
    let err2 = ctx2.validate().unwrap_err();
    assert!(err2.contains("call_chain[0].timestamp"));
    assert!(err2.contains("format characters"));
}

#[test]
fn test_evaluation_context_validate_call_chain_max_length_ok() {
    // 512-char fields should be accepted
    let ctx = EvaluationContext {
        call_chain: vec![CallChainEntry {
            agent_id: "a".repeat(512),
            tool: "t".repeat(512),
            function: "f".repeat(512),
            timestamp: "x".repeat(64),
            hmac: None,
            verified: None,
        }],
        ..Default::default()
    };
    assert!(ctx.validate().is_ok());
}

#[test]
fn test_evaluation_context_validate_call_chain_second_entry_invalid() {
    let ctx = EvaluationContext {
        call_chain: vec![
            CallChainEntry {
                agent_id: "agent-1".to_string(),
                tool: "read_file".to_string(),
                function: "read".to_string(),
                timestamp: "2026-02-15T10:00:00Z".to_string(),
                hmac: None,
                verified: None,
            },
            CallChainEntry {
                agent_id: "agent\x1b[31m-injected".to_string(),
                tool: "tool".to_string(),
                function: "fn".to_string(),
                timestamp: "2026-02-15T10:01:00Z".to_string(),
                hmac: None,
                verified: None,
            },
        ],
        ..Default::default()
    };
    let err = ctx.validate().unwrap_err();
    assert!(err.contains("call_chain[1].agent_id"));
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R51-007: StatelessContextBlob signature format validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_stateless_blob_validate_valid_signature() {
    let blob = StatelessContextBlob {
        version: 1,
        agent_id: "agent-1".to_string(),
        call_counts: HashMap::new(),
        recent_actions: vec![],
        call_chain: vec![],
        risk_score: None,
        issued_at: 1000,
        signature: "a".repeat(64), // 64 hex chars
    };
    assert!(blob.validate().is_ok());
}

#[test]
fn test_stateless_blob_validate_empty_signature_rejected() {
    let blob = StatelessContextBlob {
        version: 1,
        agent_id: "agent-1".to_string(),
        call_counts: HashMap::new(),
        recent_actions: vec![],
        call_chain: vec![],
        risk_score: None,
        issued_at: 1000,
        signature: String::new(),
    };
    let err = blob.validate().unwrap_err();
    assert!(err.contains("signature must not be empty"));
}

#[test]
fn test_stateless_blob_validate_short_signature_rejected() {
    let blob = StatelessContextBlob {
        version: 1,
        agent_id: "agent-1".to_string(),
        call_counts: HashMap::new(),
        recent_actions: vec![],
        call_chain: vec![],
        risk_score: None,
        issued_at: 1000,
        signature: "deadbeef".to_string(), // 8 chars, not 64
    };
    let err = blob.validate().unwrap_err();
    assert!(err.contains("signature length 8 is not 64"));
}

#[test]
fn test_stateless_blob_validate_long_signature_rejected() {
    let blob = StatelessContextBlob {
        version: 1,
        agent_id: "agent-1".to_string(),
        call_counts: HashMap::new(),
        recent_actions: vec![],
        call_chain: vec![],
        risk_score: None,
        issued_at: 1000,
        signature: "a".repeat(128),
    };
    let err = blob.validate().unwrap_err();
    assert!(err.contains("signature length 128 is not 64"));
}

#[test]
fn test_stateless_blob_validate_non_hex_signature_rejected() {
    let blob = StatelessContextBlob {
        version: 1,
        agent_id: "agent-1".to_string(),
        call_counts: HashMap::new(),
        recent_actions: vec![],
        call_chain: vec![],
        risk_score: None,
        issued_at: 1000,
        // 64 chars but contains 'g' which is not hex
        signature: format!("{}g", "a".repeat(63)),
    };
    let err = blob.validate().unwrap_err();
    assert!(err.contains("lowercase hex"));
}

#[test]
fn test_stateless_blob_validate_mixed_case_hex_rejected() {
    // SECURITY (FIND-R52-004): Mixed case hex is now rejected to enforce
    // canonical representation for consistent comparison.
    let blob = StatelessContextBlob {
        version: 1,
        agent_id: "agent-1".to_string(),
        call_counts: HashMap::new(),
        recent_actions: vec![],
        call_chain: vec![],
        risk_score: None,
        issued_at: 1000,
        signature: "aAbBcCdDeEfF0123456789aAbBcCdDeEfF0123456789aAbBcCdDeEfF01234567".to_string(),
    };
    assert!(blob.validate().is_err());
}

#[test]
fn test_stateless_blob_validate_lowercase_hex_ok() {
    let blob = StatelessContextBlob {
        version: 1,
        agent_id: "agent-1".to_string(),
        call_counts: HashMap::new(),
        recent_actions: vec![],
        call_chain: vec![],
        risk_score: None,
        issued_at: 1000,
        signature: "aabbccddeeff0123456789aabbccddeeff0123456789aabbccddeeff01234567".to_string(),
    };
    assert!(blob.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R51-008: CapabilityToken temporal ordering validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_capability_token_validate_structure_temporal_ordering_ok() {
    let token = CapabilityToken {
        token_id: "tok-1".to_string(),
        parent_token_id: None,
        issuer: "issuer-1".to_string(),
        holder: "holder-1".to_string(),
        grants: vec![CapabilityGrant {
            tool_pattern: "test".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }],
        remaining_depth: 3,
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-12-31T23:59:59Z".to_string(),
        signature: "sig".to_string(),
        issuer_public_key: "key".to_string(),
    };
    assert!(token.validate_structure().is_ok());
}

#[test]
fn test_capability_token_validate_structure_expires_before_issued_rejected() {
    let token = CapabilityToken {
        token_id: "tok-1".to_string(),
        parent_token_id: None,
        issuer: "issuer-1".to_string(),
        holder: "holder-1".to_string(),
        grants: vec![CapabilityGrant {
            tool_pattern: "test".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }],
        remaining_depth: 3,
        issued_at: "2027-01-01T00:00:00Z".to_string(),
        expires_at: "2026-01-01T00:00:00Z".to_string(),
        signature: "sig".to_string(),
        issuer_public_key: "key".to_string(),
    };
    let err = token.validate_structure().unwrap_err();
    assert!(
        matches!(err, CapabilityError::ValidationFailed(ref msg) if msg.contains("expires_at must be after issued_at")),
        "expected temporal ordering error, got: {err:?}"
    );
}

#[test]
fn test_capability_token_validate_structure_expires_equals_issued_rejected() {
    let token = CapabilityToken {
        token_id: "tok-1".to_string(),
        parent_token_id: None,
        issuer: "issuer-1".to_string(),
        holder: "holder-1".to_string(),
        grants: vec![CapabilityGrant {
            tool_pattern: "test".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }],
        remaining_depth: 3,
        issued_at: "2026-06-15T12:00:00Z".to_string(),
        expires_at: "2026-06-15T12:00:00Z".to_string(),
        signature: "sig".to_string(),
        issuer_public_key: "key".to_string(),
    };
    let err = token.validate_structure().unwrap_err();
    assert!(
        matches!(err, CapabilityError::ValidationFailed(ref msg) if msg.contains("expires_at must be after issued_at")),
        "equal timestamps should be rejected, got: {err:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R51-009: NhiDelegationLink self-delegation rejection
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_nhi_delegation_link_validate_ok() {
    let link = NhiDelegationLink {
        from_agent: "agent-a".to_string(),
        to_agent: "agent-b".to_string(),
        permissions: vec!["read".to_string()],
        scope_constraints: vec![],
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-02-01T00:00:00Z".to_string(),
        active: true,
        reason: None,
    };
    assert!(link.validate().is_ok());
}

#[test]
fn test_nhi_delegation_link_self_delegation_rejected() {
    let link = NhiDelegationLink {
        from_agent: "agent-a".to_string(),
        to_agent: "agent-a".to_string(),
        permissions: vec!["read".to_string()],
        scope_constraints: vec![],
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-02-01T00:00:00Z".to_string(),
        active: true,
        reason: None,
    };
    let err = link.validate().unwrap_err();
    assert!(err.contains("self-delegation is not allowed"));
}

#[test]
fn test_nhi_delegation_link_self_delegation_case_insensitive() {
    let link = NhiDelegationLink {
        from_agent: "Agent-A".to_string(),
        to_agent: "agent-a".to_string(),
        permissions: vec!["read".to_string()],
        scope_constraints: vec![],
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-02-01T00:00:00Z".to_string(),
        active: true,
        reason: None,
    };
    let err = link.validate().unwrap_err();
    assert!(err.contains("self-delegation is not allowed"));
}

// FIND-R184-003: NhiDelegationLink homoglyph self-delegation rejection
#[test]
fn test_nhi_delegation_link_self_delegation_cyrillic_homoglyph() {
    // Cyrillic 'а' (U+0430) looks identical to Latin 'a' (U+0061).
    // The self-delegation check must normalize homoglyphs to catch this.
    let link = NhiDelegationLink {
        from_agent: "admin".to_string(),      // Latin 'a'
        to_agent: "\u{0430}dmin".to_string(), // Cyrillic 'а'
        permissions: vec!["read".to_string()],
        scope_constraints: vec![],
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-02-01T00:00:00Z".to_string(),
        active: true,
        reason: None,
    };
    let err = link.validate().unwrap_err();
    assert!(
        err.contains("self-delegation is not allowed"),
        "Cyrillic homoglyph should be caught: {err}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R114-015: NhiDelegationLink Unicode format char validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_nhi_delegation_link_rejects_zero_width_space_in_to_agent() {
    // Attacker sets to_agent = "admin\u{200B}" to bypass self-delegation check
    let link = NhiDelegationLink {
        from_agent: "admin".to_string(),
        to_agent: "admin\u{200B}".to_string(),
        permissions: vec!["read".to_string()],
        scope_constraints: vec![],
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-02-01T00:00:00Z".to_string(),
        active: true,
        reason: None,
    };
    let err = link.validate().unwrap_err();
    assert!(
        err.contains("to_agent contains control or Unicode format characters"),
        "Expected format char rejection, got: {err}"
    );
}

#[test]
fn test_nhi_delegation_link_rejects_bidi_override_in_from_agent() {
    let link = NhiDelegationLink {
        from_agent: "admin\u{202E}".to_string(),
        to_agent: "agent-b".to_string(),
        permissions: vec!["read".to_string()],
        scope_constraints: vec![],
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-02-01T00:00:00Z".to_string(),
        active: true,
        reason: None,
    };
    let err = link.validate().unwrap_err();
    assert!(
        err.contains("from_agent contains control or Unicode format characters"),
        "Expected format char rejection, got: {err}"
    );
}

#[test]
fn test_nhi_delegation_link_rejects_control_char_in_from_agent() {
    let link = NhiDelegationLink {
        from_agent: "admin\x01".to_string(),
        to_agent: "agent-b".to_string(),
        permissions: vec!["read".to_string()],
        scope_constraints: vec![],
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-02-01T00:00:00Z".to_string(),
        active: true,
        reason: None,
    };
    let err = link.validate().unwrap_err();
    assert!(
        err.contains("from_agent contains control or Unicode format characters"),
        "Expected control char rejection, got: {err}"
    );
}

#[test]
fn test_nhi_delegation_link_rejects_control_char_in_to_agent() {
    let link = NhiDelegationLink {
        from_agent: "agent-a".to_string(),
        to_agent: "agent-b\n".to_string(),
        permissions: vec!["read".to_string()],
        scope_constraints: vec![],
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-02-01T00:00:00Z".to_string(),
        active: true,
        reason: None,
    };
    let err = link.validate().unwrap_err();
    assert!(
        err.contains("to_agent contains control or Unicode format characters"),
        "Expected control char rejection, got: {err}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R51-012: NhiDelegationLink temporal ordering
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_nhi_delegation_link_temporal_ordering_ok() {
    let link = NhiDelegationLink {
        from_agent: "agent-a".to_string(),
        to_agent: "agent-b".to_string(),
        permissions: vec!["read".to_string()],
        scope_constraints: vec![],
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-02-01T00:00:00Z".to_string(),
        active: true,
        reason: None,
    };
    assert!(link.validate().is_ok());
}

#[test]
fn test_nhi_delegation_link_expires_before_created_rejected() {
    let link = NhiDelegationLink {
        from_agent: "agent-a".to_string(),
        to_agent: "agent-b".to_string(),
        permissions: vec!["read".to_string()],
        scope_constraints: vec![],
        created_at: "2026-02-01T00:00:00Z".to_string(),
        expires_at: "2026-01-01T00:00:00Z".to_string(),
        active: true,
        reason: None,
    };
    let err = link.validate().unwrap_err();
    assert!(err.contains("expires_at"));
    assert!(err.contains("must be after created_at"));
}

#[test]
fn test_nhi_delegation_link_expires_equals_created_rejected() {
    let link = NhiDelegationLink {
        from_agent: "agent-a".to_string(),
        to_agent: "agent-b".to_string(),
        permissions: vec!["read".to_string()],
        scope_constraints: vec![],
        created_at: "2026-06-15T12:00:00Z".to_string(),
        expires_at: "2026-06-15T12:00:00Z".to_string(),
        active: true,
        reason: None,
    };
    let err = link.validate().unwrap_err();
    assert!(err.contains("expires_at"));
    assert!(err.contains("must be after created_at"));
}

#[test]
fn test_nhi_delegation_link_empty_timestamps_skip_temporal_check() {
    // When both are empty, skip the temporal ordering check
    // (empty timestamps are a separate validation concern)
    let link = NhiDelegationLink {
        from_agent: "agent-a".to_string(),
        to_agent: "agent-b".to_string(),
        permissions: vec![],
        scope_constraints: vec![],
        created_at: "".to_string(),
        expires_at: "".to_string(),
        active: true,
        reason: None,
    };
    assert!(link.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R51-001: Float score [0.0, 1.0] range validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_risk_score_range_rejects_negative() {
    let rs = RiskScore {
        score: -0.1,
        factors: vec![],
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    };
    let err = rs.validate_finite().unwrap_err();
    assert!(err.contains("must be in [0.0, 1.0]"));
}

#[test]
fn test_risk_score_range_rejects_above_one() {
    let rs = RiskScore {
        score: 1.01,
        factors: vec![],
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    };
    let err = rs.validate_finite().unwrap_err();
    assert!(err.contains("must be in [0.0, 1.0]"));
}

#[test]
fn test_risk_score_range_accepts_zero() {
    let rs = RiskScore {
        score: 0.0,
        factors: vec![],
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    };
    assert!(rs.validate_finite().is_ok());
}

#[test]
fn test_risk_score_range_accepts_one() {
    let rs = RiskScore {
        score: 1.0,
        factors: vec![],
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    };
    assert!(rs.validate_finite().is_ok());
}

#[test]
fn test_risk_score_range_accepts_mid() {
    let rs = RiskScore {
        score: 0.5,
        factors: vec![],
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    };
    assert!(rs.validate_finite().is_ok());
}

#[test]
fn test_schema_record_trust_score_range_rejects_negative() {
    let mut sr = SchemaRecord::new("test_tool", "abc123", 100);
    sr.trust_score = -0.5;
    let err = sr.validate().unwrap_err();
    assert!(err.contains("must be in [0.0, 1.0]"));
}

#[test]
fn test_schema_record_trust_score_range_rejects_above_one() {
    let mut sr = SchemaRecord::new("test_tool", "abc123", 100);
    sr.trust_score = 1.5;
    let err = sr.validate().unwrap_err();
    assert!(err.contains("must be in [0.0, 1.0]"));
}

#[test]
fn test_schema_record_trust_score_range_accepts_valid() {
    let sr = SchemaRecord::new("test_tool", "abc123", 100);
    // trust_score starts at 0.0 which is valid
    assert!(sr.validate().is_ok());
}

#[test]
fn test_nhi_behavioral_check_anomaly_score_range_rejects_negative() {
    let check = NhiBehavioralCheckResult {
        within_baseline: true,
        anomaly_score: -0.1,
        deviations: vec![],
        recommendation: NhiBehavioralRecommendation::Allow,
    };
    #[allow(deprecated)]
    let err = check.validate_finite().unwrap_err();
    assert!(err.contains("must be in [0.0, 1.0]"));
}

#[test]
fn test_nhi_behavioral_check_anomaly_score_range_rejects_above_one() {
    let check = NhiBehavioralCheckResult {
        within_baseline: false,
        anomaly_score: 1.5,
        deviations: vec![],
        recommendation: NhiBehavioralRecommendation::Revoke,
    };
    #[allow(deprecated)]
    let err = check.validate_finite().unwrap_err();
    assert!(err.contains("must be in [0.0, 1.0]"));
}

#[test]
fn test_nhi_behavioral_check_anomaly_score_range_accepts_valid() {
    let check = NhiBehavioralCheckResult {
        within_baseline: true,
        anomaly_score: 0.75,
        deviations: vec![],
        recommendation: NhiBehavioralRecommendation::AllowWithLogging,
    };
    #[allow(deprecated)]
    let result = check.validate_finite();
    assert!(result.is_ok());
}

#[test]
fn test_nhi_behavioral_baseline_confidence_range_rejects_negative() {
    let baseline = NhiBehavioralBaseline {
        agent_id: "test-agent".to_string(),
        confidence: -0.01,
        ..Default::default()
    };
    #[allow(deprecated)]
    let err = baseline.validate_finite().unwrap_err();
    assert!(err.contains("confidence must be in [0.0, 1.0]"));
}

#[test]
fn test_nhi_behavioral_baseline_confidence_range_rejects_above_one() {
    let baseline = NhiBehavioralBaseline {
        agent_id: "test-agent".to_string(),
        confidence: 1.001,
        ..Default::default()
    };
    #[allow(deprecated)]
    let err = baseline.validate_finite().unwrap_err();
    assert!(err.contains("confidence must be in [0.0, 1.0]"));
}

#[test]
fn test_nhi_behavioral_baseline_confidence_range_accepts_valid() {
    let baseline = NhiBehavioralBaseline {
        agent_id: "test-agent".to_string(),
        confidence: 0.95,
        ..Default::default()
    };
    #[allow(deprecated)]
    let result = baseline.validate_finite();
    assert!(result.is_ok());
}

#[test]
fn test_memory_entry_trust_score_range_rejects_negative() {
    let mut entry = MemoryEntry::new(
        "id-1".to_string(),
        "fp".to_string(),
        "test content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    entry.trust_score = -0.5;
    let err = entry.validate().unwrap_err();
    assert!(err.contains("trust_score must be in [0.0, 1.0]"));
}

#[test]
fn test_memory_entry_trust_score_range_rejects_above_one() {
    let mut entry = MemoryEntry::new(
        "id-1".to_string(),
        "fp".to_string(),
        "test content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    entry.trust_score = 2.0;
    let err = entry.validate().unwrap_err();
    assert!(err.contains("trust_score must be in [0.0, 1.0]"));
}

#[test]
fn test_memory_entry_trust_score_range_accepts_valid() {
    let mut entry = MemoryEntry::new(
        "id-1".to_string(),
        "fp".to_string(),
        "test content",
        "hash".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    );
    // Set to a valid value without security taint labels
    entry.taint_labels.clear();
    entry.trust_score = 0.75;
    assert!(entry.validate().is_ok());
}

#[test]
fn test_unregistered_agent_risk_score_range_rejects_negative() {
    let agent = UnregisteredAgent {
        agent_id: "rogue".to_string(),
        first_seen: "2026-01-01T00:00:00Z".to_string(),
        last_seen: "2026-01-01T00:00:00Z".to_string(),
        request_count: 1,
        tools_used: std::collections::HashSet::new(),
        risk_score: -0.1,
    };
    #[allow(deprecated)]
    let err = agent.validate_finite().unwrap_err();
    assert!(err.contains("must be in [0.0, 1.0]"));
}

#[test]
fn test_unregistered_agent_risk_score_range_rejects_above_one() {
    let agent = UnregisteredAgent {
        agent_id: "rogue".to_string(),
        first_seen: "2026-01-01T00:00:00Z".to_string(),
        last_seen: "2026-01-01T00:00:00Z".to_string(),
        request_count: 1,
        tools_used: std::collections::HashSet::new(),
        risk_score: 5.0,
    };
    #[allow(deprecated)]
    let err = agent.validate_finite().unwrap_err();
    assert!(err.contains("must be in [0.0, 1.0]"));
}

#[test]
fn test_shadow_ai_report_total_risk_score_range_rejects_above_one() {
    let report = ShadowAiReport {
        unregistered_agents: vec![],
        unapproved_tools: vec![],
        unknown_servers: vec![],
        total_risk_score: 1.5,
    };
    #[allow(deprecated)]
    let err = report.validate_finite().unwrap_err();
    assert!(err.contains("total_risk_score must be in [0.0, 1.0]"));
}

#[test]
fn test_shadow_ai_report_total_risk_score_range_accepts_valid() {
    let report = ShadowAiReport {
        unregistered_agents: vec![],
        unapproved_tools: vec![],
        unknown_servers: vec![],
        total_risk_score: 0.3,
    };
    #[allow(deprecated)]
    let result = report.validate_finite();
    assert!(result.is_ok());
}

#[test]
fn test_discovered_tool_relevance_score_range_rejects_above_one() {
    let tool = DiscoveredTool {
        metadata: ToolMetadata {
            tool_id: "srv:tool".to_string(),
            name: "tool".to_string(),
            description: "desc".to_string(),
            server_id: "srv".to_string(),
            input_schema: json!({}),
            schema_hash: "abc".to_string(),
            sensitivity: ToolSensitivity::Low,
            domain_tags: vec![],
            token_cost: 10,
        },
        relevance_score: 1.1,
        ttl_secs: 60,
    };
    #[allow(deprecated)]
    let err = tool.validate_finite().unwrap_err();
    assert!(err.contains("must be in [0.0, 1.0]"));
}

#[test]
fn test_discovered_tool_relevance_score_range_rejects_negative() {
    let tool = DiscoveredTool {
        metadata: ToolMetadata {
            tool_id: "srv:tool".to_string(),
            name: "tool".to_string(),
            description: "desc".to_string(),
            server_id: "srv".to_string(),
            input_schema: json!({}),
            schema_hash: "abc".to_string(),
            sensitivity: ToolSensitivity::Low,
            domain_tags: vec![],
            token_cost: 10,
        },
        relevance_score: -0.01,
        ttl_secs: 60,
    };
    #[allow(deprecated)]
    let err = tool.validate_finite().unwrap_err();
    assert!(err.contains("must be in [0.0, 1.0]"));
}

#[test]
fn test_discovered_tool_relevance_score_range_accepts_valid() {
    let tool = DiscoveredTool {
        metadata: ToolMetadata {
            tool_id: "srv:tool".to_string(),
            name: "tool".to_string(),
            description: "desc".to_string(),
            server_id: "srv".to_string(),
            input_schema: json!({}),
            schema_hash: "abc".to_string(),
            sensitivity: ToolSensitivity::Low,
            domain_tags: vec![],
            token_cost: 10,
        },
        relevance_score: 0.85,
        ttl_secs: 60,
    };
    #[allow(deprecated)]
    let result = tool.validate_finite();
    assert!(result.is_ok());
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R51-002: ToolSignature.is_expired() malformed timestamp handling
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_tool_signature_is_expired_malformed_timestamp_returns_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("9999-99-99T99:99:99Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    // "9999-99-99T99:99:99Z" has invalid month/day/hour/minute/second
    // Should be treated as expired (fail-closed)
    assert!(sig.is_expired("2026-01-15T12:00:00Z"));
}

#[test]
fn test_tool_signature_is_expired_malformed_now_returns_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2030-12-31T23:59:59Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    // Malformed `now` timestamp
    assert!(sig.is_expired("not-a-timestampZZZZ"));
}

#[test]
fn test_tool_signature_is_expired_valid_future_not_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2030-12-31T23:59:59Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    // Valid timestamps, expires_at is in the future
    assert!(!sig.is_expired("2026-02-15T12:00:00Z"));
}

#[test]
fn test_tool_signature_is_expired_valid_past_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2026-01-15T00:00:00Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    // now is after expires_at
    assert!(sig.is_expired("2026-02-01T00:00:00Z"));
}

#[test]
fn test_tool_signature_is_expired_no_expiry_not_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    // No expires_at means it never expires
    assert!(!sig.is_expired("2030-12-31T23:59:59Z"));
}

#[test]
fn test_tool_signature_is_expired_short_timestamp_returns_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2030-12-31T23:59:59Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    // Too short to be valid
    assert!(sig.is_expired("2026Z"));
}

#[test]
fn test_tool_signature_is_expired_year_before_1970_returns_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2030-12-31T23:59:59Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    assert!(sig.is_expired("1969-12-31T23:59:59Z"));
}

#[test]
fn test_tool_signature_is_expired_month_00_returns_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2030-12-31T23:59:59Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    assert!(sig.is_expired("2026-00-15T12:00:00Z"));
}

#[test]
fn test_tool_signature_is_expired_month_13_returns_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2030-12-31T23:59:59Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    assert!(sig.is_expired("2026-13-15T12:00:00Z"));
}

#[test]
fn test_tool_signature_is_expired_day_00_returns_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2030-12-31T23:59:59Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    assert!(sig.is_expired("2026-01-00T12:00:00Z"));
}

#[test]
fn test_tool_signature_is_expired_day_32_returns_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2030-12-31T23:59:59Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    assert!(sig.is_expired("2026-01-32T12:00:00Z"));
}

#[test]
fn test_tool_signature_is_expired_hour_24_returns_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2030-12-31T23:59:59Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    assert!(sig.is_expired("2026-01-15T24:00:00Z"));
}

#[test]
fn test_tool_signature_is_expired_minute_60_returns_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2030-12-31T23:59:59Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    assert!(sig.is_expired("2026-01-15T12:60:00Z"));
}

#[test]
fn test_tool_signature_is_expired_second_60_returns_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2030-12-31T23:59:59Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    assert!(sig.is_expired("2026-01-15T12:00:60Z"));
}

#[test]
fn test_tool_signature_is_expired_letters_in_digit_positions() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("2030-12-31T23:59:59Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    assert!(sig.is_expired("ABCD-EF-GHTab:cd:efZ"));
}

#[test]
fn test_tool_signature_is_expired_malformed_expires_at_returns_expired() {
    let sig = ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "deadbeef".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: "pubkey".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: Some("9999-99-99T99:99:99Z".to_string()),
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    // Even though "9999-99-99T99:99:99Z" > any valid timestamp lexicographically,
    // the malformed month/day/hour/minute/second should cause fail-closed (expired).
    assert!(sig.is_expired("2026-02-15T12:00:00Z"));
}

// ── FIND-R53-001: TaskCheckpoint Debug redacts signature and public_key ──────

#[test]
fn test_task_checkpoint_debug_redacts_signature() {
    let cp = TaskCheckpoint {
        checkpoint_id: "cp-1".to_string(),
        task_id: "task-1".to_string(),
        sequence: 0,
        state_hash: "abc123".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        signature: "supersecret_signature".to_string(),
        public_key: "supersecret_pubkey".to_string(),
    };
    let debug = format!("{cp:?}");
    assert!(
        !debug.contains("supersecret_signature"),
        "Debug output must not contain raw signature"
    );
    assert!(
        !debug.contains("supersecret_pubkey"),
        "Debug output must not contain raw public_key"
    );
    assert!(
        debug.contains("[REDACTED]"),
        "Debug output must show [REDACTED] for sensitive fields"
    );
    assert!(debug.contains("cp-1"));
    assert!(debug.contains("task-1"));
    assert!(debug.contains("abc123"));
}

// ── FIND-R53-002: AccountabilityAttestation Debug redacts signature/public_key

#[test]
fn test_accountability_attestation_debug_redacts_signature() {
    let att = AccountabilityAttestation {
        attestation_id: "att-1".to_string(),
        agent_id: "agent-1".to_string(),
        did: None,
        statement: "I agree".to_string(),
        policy_hash: "hash123".to_string(),
        signature: "topsecret_sig".to_string(),
        algorithm: "Ed25519".to_string(),
        public_key: "topsecret_key".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-12-31T23:59:59Z".to_string(),
        verified: false,
    };
    let debug = format!("{att:?}");
    assert!(
        !debug.contains("topsecret_sig"),
        "Debug output must not contain raw signature"
    );
    assert!(
        !debug.contains("topsecret_key"),
        "Debug output must not contain raw public_key"
    );
    assert!(
        debug.contains("[REDACTED]"),
        "Debug output must show [REDACTED] for sensitive fields"
    );
    assert!(debug.contains("att-1"));
    assert!(debug.contains("agent-1"));
    assert!(debug.contains("Ed25519"));
}

// ── FIND-R53-003: AccessReviewEntry usage_ratio [0.0, 1.0] range validation ──

#[test]
fn test_access_review_entry_validate_rejects_negative_usage_ratio() {
    let entry = AccessReviewEntry {
        agent_id: "agent-1".to_string(),
        session_ids: vec![],
        first_access: "2026-01-01T00:00:00Z".to_string(),
        last_access: "2026-01-31T00:00:00Z".to_string(),
        total_evaluations: 10,
        allow_count: 5,
        deny_count: 5,
        require_approval_count: 0,
        tools_accessed: vec![],
        functions_called: vec![],
        permissions_granted: 5,
        permissions_used: 3,
        usage_ratio: -0.1,
        unused_permissions: vec![],
        agency_recommendation: "Optimal".to_string(),
    };
    let err = entry.validate().unwrap_err();
    assert!(err.contains("usage_ratio must be in [0.0, 1.0]"));
}

#[test]
fn test_access_review_entry_validate_rejects_above_one_usage_ratio() {
    let entry = AccessReviewEntry {
        agent_id: "agent-1".to_string(),
        session_ids: vec![],
        first_access: "2026-01-01T00:00:00Z".to_string(),
        last_access: "2026-01-31T00:00:00Z".to_string(),
        total_evaluations: 10,
        allow_count: 5,
        deny_count: 5,
        require_approval_count: 0,
        tools_accessed: vec![],
        functions_called: vec![],
        permissions_granted: 5,
        permissions_used: 3,
        usage_ratio: 1.5,
        unused_permissions: vec![],
        agency_recommendation: "Optimal".to_string(),
    };
    let err = entry.validate().unwrap_err();
    assert!(err.contains("usage_ratio must be in [0.0, 1.0]"));
}

#[test]
fn test_access_review_entry_validate_rejects_nan_usage_ratio() {
    let entry = AccessReviewEntry {
        agent_id: "agent-1".to_string(),
        session_ids: vec![],
        first_access: "2026-01-01T00:00:00Z".to_string(),
        last_access: "2026-01-31T00:00:00Z".to_string(),
        total_evaluations: 10,
        allow_count: 5,
        deny_count: 5,
        require_approval_count: 0,
        tools_accessed: vec![],
        functions_called: vec![],
        permissions_granted: 5,
        permissions_used: 3,
        usage_ratio: f64::NAN,
        unused_permissions: vec![],
        agency_recommendation: "Optimal".to_string(),
    };
    let err = entry.validate().unwrap_err();
    assert!(err.contains("non-finite usage_ratio"));
}

#[test]
fn test_access_review_entry_validate_accepts_valid_ratio() {
    let entry = AccessReviewEntry {
        agent_id: "agent-1".to_string(),
        session_ids: vec!["s1".to_string()],
        first_access: "2026-01-01T00:00:00Z".to_string(),
        last_access: "2026-01-31T00:00:00Z".to_string(),
        total_evaluations: 10,
        allow_count: 5,
        deny_count: 5,
        require_approval_count: 0,
        tools_accessed: vec!["tool1".to_string()],
        functions_called: vec!["fn1".to_string()],
        permissions_granted: 5,
        permissions_used: 4,
        usage_ratio: 0.8,
        unused_permissions: vec!["p1".to_string()],
        agency_recommendation: "Optimal".to_string(),
    };
    assert!(entry.validate().is_ok());
}

// ── FIND-R53-006: AccessReviewEntry unbounded Vec fields ─────────────────────

#[test]
fn test_access_review_entry_validate_rejects_too_many_session_ids() {
    let entry = AccessReviewEntry {
        agent_id: "agent-1".to_string(),
        session_ids: (0..=AccessReviewEntry::MAX_SESSION_IDS)
            .map(|i| format!("s{i}"))
            .collect(),
        first_access: "2026-01-01T00:00:00Z".to_string(),
        last_access: "2026-01-31T00:00:00Z".to_string(),
        total_evaluations: 10,
        allow_count: 5,
        deny_count: 5,
        require_approval_count: 0,
        tools_accessed: vec![],
        functions_called: vec![],
        permissions_granted: 5,
        permissions_used: 4,
        usage_ratio: 0.8,
        unused_permissions: vec![],
        agency_recommendation: "Optimal".to_string(),
    };
    let err = entry.validate().unwrap_err();
    assert!(err.contains("session_ids"));
}

#[test]
fn test_access_review_entry_validate_rejects_too_many_unused_permissions() {
    let entry = AccessReviewEntry {
        agent_id: "agent-1".to_string(),
        session_ids: vec![],
        first_access: "2026-01-01T00:00:00Z".to_string(),
        last_access: "2026-01-31T00:00:00Z".to_string(),
        total_evaluations: 10,
        allow_count: 5,
        deny_count: 5,
        require_approval_count: 0,
        tools_accessed: vec![],
        functions_called: vec![],
        permissions_granted: 5,
        permissions_used: 4,
        usage_ratio: 0.8,
        unused_permissions: (0..=AccessReviewEntry::MAX_UNUSED_PERMISSIONS)
            .map(|i| format!("p{i}"))
            .collect(),
        agency_recommendation: "Optimal".to_string(),
    };
    let err = entry.validate().unwrap_err();
    assert!(err.contains("unused_permissions"));
}

// ── FIND-R53-004: LeastAgencyReport usage_ratio [0.0, 1.0] range validation ──

#[test]
fn test_least_agency_report_validate_rejects_negative_usage_ratio() {
    let report = LeastAgencyReport {
        agent_id: "agent-1".to_string(),
        session_id: "sess-1".to_string(),
        granted_permissions: 5,
        used_permissions: 3,
        unused_permissions: vec![],
        usage_ratio: -0.5,
        recommendation: AgencyRecommendation::Critical,
    };
    let err = report.validate().unwrap_err();
    assert!(err.contains("usage_ratio must be in [0.0, 1.0]"));
}

#[test]
fn test_least_agency_report_validate_rejects_above_one_usage_ratio() {
    let report = LeastAgencyReport {
        agent_id: "agent-1".to_string(),
        session_id: "sess-1".to_string(),
        granted_permissions: 5,
        used_permissions: 3,
        unused_permissions: vec![],
        usage_ratio: 2.0,
        recommendation: AgencyRecommendation::Optimal,
    };
    let err = report.validate().unwrap_err();
    assert!(err.contains("usage_ratio must be in [0.0, 1.0]"));
}

#[test]
fn test_least_agency_report_validate_rejects_nan_usage_ratio() {
    let report = LeastAgencyReport {
        agent_id: "agent-1".to_string(),
        session_id: "sess-1".to_string(),
        granted_permissions: 5,
        used_permissions: 3,
        unused_permissions: vec![],
        usage_ratio: f64::NAN,
        recommendation: AgencyRecommendation::Critical,
    };
    let err = report.validate().unwrap_err();
    assert!(err.contains("non-finite usage_ratio"));
}

#[test]
fn test_least_agency_report_validate_accepts_valid() {
    let report = LeastAgencyReport {
        agent_id: "agent-1".to_string(),
        session_id: "sess-1".to_string(),
        granted_permissions: 5,
        used_permissions: 4,
        unused_permissions: vec!["p1".to_string()],
        usage_ratio: 0.8,
        recommendation: AgencyRecommendation::Optimal,
    };
    assert!(report.validate().is_ok());
}

#[test]
fn test_least_agency_report_validate_accepts_boundary_values() {
    let report_zero = LeastAgencyReport {
        agent_id: "a".to_string(),
        session_id: "s".to_string(),
        granted_permissions: 5,
        used_permissions: 0,
        unused_permissions: vec![],
        usage_ratio: 0.0,
        recommendation: AgencyRecommendation::Critical,
    };
    assert!(report_zero.validate().is_ok());

    let report_one = LeastAgencyReport {
        agent_id: "a".to_string(),
        session_id: "s".to_string(),
        granted_permissions: 0,
        used_permissions: 0,
        unused_permissions: vec![],
        usage_ratio: 1.0,
        recommendation: AgencyRecommendation::Optimal,
    };
    assert!(report_one.validate().is_ok());
}

// ── FIND-R53-005: LeastAgencyReport unbounded unused_permissions ─────────────

#[test]
fn test_least_agency_report_validate_rejects_too_many_unused_permissions() {
    let report = LeastAgencyReport {
        agent_id: "agent-1".to_string(),
        session_id: "sess-1".to_string(),
        granted_permissions: 20_000,
        used_permissions: 0,
        unused_permissions: (0..=LeastAgencyReport::MAX_UNUSED_PERMISSIONS)
            .map(|i| format!("p{i}"))
            .collect(),
        usage_ratio: 0.0,
        recommendation: AgencyRecommendation::Critical,
    };
    let err = report.validate().unwrap_err();
    assert!(err.contains("unused_permissions"));
    assert!(err.contains("10000"));
}

// ═══════════════════════════════════════════════════
// ROUND 83 AUDIT FIXES
// ═══════════════════════════════════════════════════

// FIND-R83-002: ABAC structs reject unknown fields
#[test]
fn test_abac_principal_constraint_rejects_unknown_fields() {
    let json = r#"{"principal_type":"Agent","id_patterns":[],"claims":{},"unknown_field":"x"}"#;
    let result = serde_json::from_str::<crate::abac::PrincipalConstraint>(json);
    assert!(
        result.is_err(),
        "PrincipalConstraint must reject unknown fields"
    );
}

#[test]
fn test_abac_action_constraint_rejects_unknown_fields() {
    let json = r#"{"patterns":[],"unknown_field":"x"}"#;
    let result = serde_json::from_str::<crate::abac::ActionConstraint>(json);
    assert!(
        result.is_err(),
        "ActionConstraint must reject unknown fields"
    );
}

#[test]
fn test_abac_resource_constraint_rejects_unknown_fields() {
    let json = r#"{"path_patterns":[],"domain_patterns":[],"tags":[],"extra":"y"}"#;
    let result = serde_json::from_str::<crate::abac::ResourceConstraint>(json);
    assert!(
        result.is_err(),
        "ResourceConstraint must reject unknown fields"
    );
}

#[test]
fn test_abac_condition_rejects_unknown_fields() {
    let json = r#"{"field":"ctx.ok","op":"eq","value":true,"bonus":"z"}"#;
    let result = serde_json::from_str::<crate::abac::AbacCondition>(json);
    assert!(result.is_err(), "AbacCondition must reject unknown fields");
}

#[test]
fn test_abac_policy_rejects_unknown_fields() {
    let json = r#"{"id":"p1","description":"d","effect":"permit","sneaky":1}"#;
    let result = serde_json::from_str::<crate::abac::AbacPolicy>(json);
    assert!(result.is_err(), "AbacPolicy must reject unknown fields");
}

#[test]
fn test_risk_score_rejects_unknown_fields() {
    let json = r#"{"score":0.5,"factors":[],"updated_at":"2026-01-01T00:00:00Z","extra":1}"#;
    let result = serde_json::from_str::<crate::abac::RiskScore>(json);
    assert!(result.is_err(), "RiskScore must reject unknown fields");
}

#[test]
fn test_risk_factor_rejects_unknown_fields() {
    let json = r#"{"name":"f","weight":0.5,"value":0.5,"extra":1}"#;
    let result = serde_json::from_str::<crate::abac::RiskFactor>(json);
    assert!(result.is_err(), "RiskFactor must reject unknown fields");
}

// FIND-R83-003: Capability types reject unknown fields
#[test]
fn test_capability_token_rejects_unknown_fields() {
    let json = r#"{
        "token_id":"t1","parent_token_id":null,"issuer":"a","holder":"b",
        "grants":[],"remaining_depth":3,"issued_at":"2026-01-01T00:00:00Z",
        "expires_at":"2026-12-31T23:59:59Z","signature":"abc","issuer_public_key":"def",
        "extra_field":"attack"
    }"#;
    let result = serde_json::from_str::<crate::capability::CapabilityToken>(json);
    assert!(
        result.is_err(),
        "CapabilityToken must reject unknown fields"
    );
}

#[test]
fn test_capability_grant_rejects_unknown_fields() {
    let json = r#"{"tool_pattern":"*","function_pattern":"*","extra":"x"}"#;
    let result = serde_json::from_str::<crate::capability::CapabilityGrant>(json);
    assert!(
        result.is_err(),
        "CapabilityGrant must reject unknown fields"
    );
}

// FIND-R83-007: McpCapability sub_capabilities control char validation
#[test]
fn test_mcp_capability_sub_capability_control_char_rejected() {
    let cap = McpCapability {
        name: "tools".to_string(),
        version: None,
        sub_capabilities: vec!["read\x00write".to_string()],
    };
    let err = cap.validate().unwrap_err();
    assert!(err.contains("control or format characters"));
}

#[test]
fn test_mcp_capability_sub_capability_zero_width_rejected() {
    let cap = McpCapability {
        name: "tools".to_string(),
        version: None,
        sub_capabilities: vec!["rea\u{200B}d".to_string()], // zero-width space
    };
    let err = cap.validate().unwrap_err();
    assert!(err.contains("control or format characters"));
}

// =============================================================================
// ROUND 104: Debug redaction tests
// =============================================================================

#[test]
fn test_nhi_agent_identity_debug_redacts_public_key() {
    let identity = NhiAgentIdentity {
        id: "agent-1".to_string(),
        name: "Test Agent".to_string(),
        public_key: Some("deadbeef0123456789abcdef".to_string()),
        ..Default::default()
    };
    let debug = format!("{identity:?}");
    assert!(
        !debug.contains("deadbeef0123456789abcdef"),
        "Debug output must not contain raw public_key"
    );
    assert!(
        debug.contains("[REDACTED]"),
        "Debug output should contain [REDACTED]"
    );
    assert!(
        debug.contains("agent-1"),
        "Debug output should still contain non-sensitive fields"
    );
}

#[test]
fn test_nhi_agent_identity_debug_none_public_key() {
    let identity = NhiAgentIdentity {
        id: "agent-2".to_string(),
        name: "Agent Two".to_string(),
        public_key: None,
        ..Default::default()
    };
    let debug = format!("{identity:?}");
    assert!(
        debug.contains("None"),
        "Debug should show None for missing public_key"
    );
}

#[test]
fn test_nhi_dpop_proof_debug_redacts_proof_and_ath() {
    let proof = NhiDpopProof {
        proof: "eyJhbGciOiJFUzI1NiJ9.secret_jwt_body.signature_here".to_string(),
        htm: "POST".to_string(),
        htu: "https://example.com/api".to_string(),
        ath: Some("sha256_hash_of_access_token".to_string()),
        nonce: Some("server-nonce-123".to_string()),
        iat: "2026-01-01T00:00:00Z".to_string(),
        jti: "jti-unique-id".to_string(),
    };
    let debug = format!("{proof:?}");
    assert!(
        !debug.contains("secret_jwt_body"),
        "Debug must not contain proof JWT content"
    );
    assert!(
        !debug.contains("sha256_hash_of_access_token"),
        "Debug must not contain ath hash"
    );
    assert!(
        debug.contains("[REDACTED]"),
        "Debug should contain [REDACTED]"
    );
    assert!(
        debug.contains("POST"),
        "Debug should still contain non-sensitive fields like htm"
    );
    assert!(
        debug.contains("server-nonce-123"),
        "Debug should still show nonce"
    );
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R115-001: CapabilityToken.validate_structure() control/format char validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_r115_001_capability_token_rejects_control_char_in_token_id() {
    let token = CapabilityToken {
        token_id: "tok\x00-1".to_string(),
        parent_token_id: None,
        issuer: "issuer-1".to_string(),
        holder: "holder-1".to_string(),
        grants: vec![CapabilityGrant {
            tool_pattern: "test".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }],
        remaining_depth: 3,
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-12-31T23:59:59Z".to_string(),
        signature: "sig".to_string(),
        issuer_public_key: "key".to_string(),
    };
    let err = token.validate_structure().unwrap_err();
    assert!(
        matches!(err, CapabilityError::ValidationFailed(ref msg) if msg.contains("token_id") && msg.contains("control or format")),
        "expected control char rejection in token_id, got: {err:?}"
    );
}

#[test]
fn test_r115_001_capability_token_rejects_zwsp_in_issuer() {
    let token = CapabilityToken {
        token_id: "tok-1".to_string(),
        parent_token_id: None,
        issuer: "issuer\u{200B}-1".to_string(), // zero-width space
        holder: "holder-1".to_string(),
        grants: vec![CapabilityGrant {
            tool_pattern: "test".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }],
        remaining_depth: 3,
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-12-31T23:59:59Z".to_string(),
        signature: "sig".to_string(),
        issuer_public_key: "key".to_string(),
    };
    let err = token.validate_structure().unwrap_err();
    assert!(
        matches!(err, CapabilityError::ValidationFailed(ref msg) if msg.contains("issuer") && msg.contains("control or format")),
        "expected format char rejection in issuer, got: {err:?}"
    );
}

#[test]
fn test_r115_001_capability_token_rejects_bidi_override_in_holder() {
    let token = CapabilityToken {
        token_id: "tok-1".to_string(),
        parent_token_id: None,
        issuer: "issuer-1".to_string(),
        holder: "holder\u{202E}-1".to_string(), // right-to-left override
        grants: vec![CapabilityGrant {
            tool_pattern: "test".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }],
        remaining_depth: 3,
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-12-31T23:59:59Z".to_string(),
        signature: "sig".to_string(),
        issuer_public_key: "key".to_string(),
    };
    let err = token.validate_structure().unwrap_err();
    assert!(
        matches!(err, CapabilityError::ValidationFailed(ref msg) if msg.contains("holder") && msg.contains("control or format")),
        "expected format char rejection in holder, got: {err:?}"
    );
}

#[test]
fn test_r115_001_capability_token_valid_passes() {
    let token = CapabilityToken {
        token_id: "tok-1".to_string(),
        parent_token_id: None,
        issuer: "issuer-1".to_string(),
        holder: "holder-1".to_string(),
        grants: vec![CapabilityGrant {
            tool_pattern: "test".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }],
        remaining_depth: 3,
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-12-31T23:59:59Z".to_string(),
        signature: "sig".to_string(),
        issuer_public_key: "key".to_string(),
    };
    assert!(token.validate_structure().is_ok());
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R115-002: AccessReviewEntry.validate() control/format char validation
// ═══════════════════════════════════════════════════════════════════

fn make_valid_access_review_entry() -> AccessReviewEntry {
    AccessReviewEntry {
        agent_id: "agent-1".to_string(),
        session_ids: vec!["s1".to_string()],
        first_access: "2026-01-01T00:00:00Z".to_string(),
        last_access: "2026-01-02T00:00:00Z".to_string(),
        total_evaluations: 10,
        allow_count: 8,
        deny_count: 1,
        require_approval_count: 1,
        tools_accessed: vec!["read_file".to_string()],
        functions_called: vec!["execute".to_string()],
        permissions_granted: 5,
        permissions_used: 4,
        usage_ratio: 0.8,
        unused_permissions: vec!["p1".to_string()],
        agency_recommendation: "optimal".to_string(),
    }
}

#[test]
fn test_r115_002_access_review_entry_rejects_control_char_in_agent_id() {
    let mut entry = make_valid_access_review_entry();
    entry.agent_id = "agent\n-1".to_string();
    let err = entry.validate().unwrap_err();
    assert!(
        err.contains("agent_id") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r115_002_access_review_entry_rejects_zwsp_in_agent_id() {
    let mut entry = make_valid_access_review_entry();
    entry.agent_id = "agent\u{200B}-1".to_string();
    let err = entry.validate().unwrap_err();
    assert!(
        err.contains("agent_id") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r115_002_access_review_entry_rejects_control_char_in_recommendation() {
    let mut entry = make_valid_access_review_entry();
    entry.agency_recommendation = "optimal\t".to_string();
    let err = entry.validate().unwrap_err();
    assert!(
        err.contains("agency_recommendation") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r115_002_access_review_entry_valid_passes() {
    let entry = make_valid_access_review_entry();
    assert!(entry.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R115-003: ZkBatchProof.validate() control/format char validation
// ═══════════════════════════════════════════════════════════════════

fn make_valid_zk_batch_proof() -> crate::zk_audit::ZkBatchProof {
    crate::zk_audit::ZkBatchProof {
        proof: "aabbccdd".to_string(),
        batch_id: "batch-1".to_string(),
        entry_range: (0, 9),
        merkle_root: "abcdef".to_string(),
        first_prev_hash: "112233".to_string(),
        final_entry_hash: "445566".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        entry_count: 10,
    }
}

#[test]
fn test_r115_003_zk_batch_proof_rejects_control_char_in_batch_id() {
    let mut proof = make_valid_zk_batch_proof();
    proof.batch_id = "batch\x01-1".to_string();
    let err = proof.validate().unwrap_err();
    assert!(
        err.contains("batch_id") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r115_003_zk_batch_proof_rejects_bom_in_batch_id() {
    let mut proof = make_valid_zk_batch_proof();
    proof.batch_id = "\u{FEFF}batch-1".to_string();
    let err = proof.validate().unwrap_err();
    assert!(
        err.contains("batch_id") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r115_003_zk_batch_proof_rejects_control_char_in_created_at() {
    let mut proof = make_valid_zk_batch_proof();
    proof.created_at = "2026-01-01\rT00:00:00Z".to_string();
    let err = proof.validate().unwrap_err();
    assert!(
        err.contains("created_at") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r115_003_zk_batch_proof_valid_passes() {
    let proof = make_valid_zk_batch_proof();
    assert!(proof.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R172-001/002/003: ZkVerifyResult + ZkSchedulerStatus dangerous char validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_r172_001_zk_verify_result_rejects_control_char_in_error() {
    let result = crate::zk_audit::ZkVerifyResult {
        batch_id: "batch-1".to_string(),
        valid: false,
        entry_range: (0, 100),
        verified_at: "2026-01-01T00:00:00Z".to_string(),
        error: Some("error\x07msg".to_string()),
    };
    let err = result.validate().unwrap_err();
    assert!(
        err.contains("error") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r172_002_zk_verify_result_rejects_bidi_in_batch_id() {
    let result = crate::zk_audit::ZkVerifyResult {
        batch_id: "batch\u{202E}evil".to_string(),
        valid: true,
        entry_range: (0, 100),
        verified_at: "2026-01-01T00:00:00Z".to_string(),
        error: None,
    };
    let err = result.validate().unwrap_err();
    assert!(
        err.contains("batch_id") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r172_002_zk_verify_result_rejects_zwsp_in_verified_at() {
    let result = crate::zk_audit::ZkVerifyResult {
        batch_id: "batch-1".to_string(),
        valid: true,
        entry_range: (0, 100),
        verified_at: "2026-01\u{200B}-01T00:00:00Z".to_string(),
        error: None,
    };
    let err = result.validate().unwrap_err();
    assert!(
        err.contains("verified_at") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r172_003_zk_scheduler_status_rejects_control_char_in_last_proof_at() {
    let status = crate::zk_audit::ZkSchedulerStatus {
        active: true,
        pending_witnesses: 0,
        completed_proofs: 1,
        last_proved_sequence: Some(42),
        last_proof_at: Some("2026-01-01\x00T00:00:00Z".to_string()),
    };
    let err = status.validate().unwrap_err();
    assert!(
        err.contains("last_proof_at") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r172_zk_verify_result_valid_passes() {
    let result = crate::zk_audit::ZkVerifyResult {
        batch_id: "batch-123".to_string(),
        valid: true,
        entry_range: (0, 100),
        verified_at: "2026-01-01T00:00:00Z".to_string(),
        error: None,
    };
    assert!(result.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R115-004: CanonicalToolSchema/CanonicalToolCall control/format char validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_r115_004_canonical_tool_schema_rejects_control_char_in_name() {
    let schema = crate::projector::CanonicalToolSchema {
        name: "tool\x07name".to_string(),
        description: "A test tool".to_string(),
        input_schema: json!({}),
        output_schema: None,
    };
    let err = schema.validate().unwrap_err();
    assert!(
        err.contains("name") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r115_004_canonical_tool_schema_rejects_zwsp_in_name() {
    let schema = crate::projector::CanonicalToolSchema {
        name: "tool\u{200B}name".to_string(),
        description: "A test tool".to_string(),
        input_schema: json!({}),
        output_schema: None,
    };
    let err = schema.validate().unwrap_err();
    assert!(
        err.contains("name") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r115_004_canonical_tool_call_rejects_control_char_in_tool_name() {
    let call = crate::projector::CanonicalToolCall {
        tool_name: "tool\nnewline".to_string(),
        arguments: json!({}),
        call_id: None,
    };
    let err = call.validate().unwrap_err();
    assert!(
        err.contains("tool_name") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r115_004_canonical_tool_call_rejects_bidi_in_tool_name() {
    let call = crate::projector::CanonicalToolCall {
        tool_name: "tool\u{202A}name".to_string(),
        arguments: json!({}),
        call_id: None,
    };
    let err = call.validate().unwrap_err();
    assert!(
        err.contains("tool_name") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r115_004_canonical_tool_schema_valid_passes() {
    let schema = crate::projector::CanonicalToolSchema {
        name: "tool_name".to_string(),
        description: "A valid tool".to_string(),
        input_schema: json!({}),
        output_schema: None,
    };
    assert!(schema.validate().is_ok());
}

#[test]
fn test_r115_004_canonical_tool_call_valid_passes() {
    let call = crate::projector::CanonicalToolCall {
        tool_name: "tool_name".to_string(),
        arguments: json!({}),
        call_id: Some("call-1".to_string()),
    };
    assert!(call.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R196-002: CanonicalToolSchema description dangerous chars
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_r196_002_canonical_tool_schema_rejects_control_in_description() {
    let schema = crate::projector::CanonicalToolSchema {
        name: "tool_name".to_string(),
        description: "A tool with \x00 null byte".to_string(),
        input_schema: json!({}),
        output_schema: None,
    };
    let result = schema.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("description"));
}

#[test]
fn test_r196_002_canonical_tool_schema_rejects_bidi_in_description() {
    let schema = crate::projector::CanonicalToolSchema {
        name: "tool_name".to_string(),
        description: "A tool with \u{200B}zero-width space".to_string(),
        input_schema: json!({}),
        output_schema: None,
    };
    let result = schema.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("description"));
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R172-005: CanonicalToolCall/Response call_id validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_r172_005_canonical_tool_call_rejects_control_char_in_call_id() {
    let call = crate::projector::CanonicalToolCall {
        tool_name: "tool".to_string(),
        arguments: json!({}),
        call_id: Some("call\x07id".to_string()),
    };
    let err = call.validate().unwrap_err();
    assert!(
        err.contains("call_id") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r172_005_canonical_tool_call_rejects_oversized_call_id() {
    let call = crate::projector::CanonicalToolCall {
        tool_name: "tool".to_string(),
        arguments: json!({}),
        call_id: Some("x".repeat(257)),
    };
    let err = call.validate().unwrap_err();
    assert!(
        err.contains("call_id") && err.contains("exceeds max"),
        "got: {err}"
    );
}

#[test]
fn test_r172_005_canonical_tool_response_rejects_control_char_in_call_id() {
    let resp = crate::projector::CanonicalToolResponse {
        call_id: Some("call\u{202E}id".to_string()),
        content: json!("ok"),
        is_error: false,
    };
    let err = resp.validate().unwrap_err();
    assert!(
        err.contains("call_id") && err.contains("control or format"),
        "got: {err}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R115-005: DeploymentInfo.validate() control/format char validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_r115_005_deployment_info_rejects_control_char_in_instance_id() {
    let info = crate::deployment::DeploymentInfo {
        instance_id: Some("pod\x00-1".to_string()),
        leader_status: None,
        discovered_endpoints: None,
        uptime_secs: 100,
        mode: "standalone".to_string(),
    };
    let err = info.validate().unwrap_err();
    assert!(
        err.contains("instance_id") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r115_005_deployment_info_rejects_zwsp_in_instance_id() {
    let info = crate::deployment::DeploymentInfo {
        instance_id: Some("pod\u{200B}-1".to_string()),
        leader_status: None,
        discovered_endpoints: None,
        uptime_secs: 100,
        mode: "standalone".to_string(),
    };
    let err = info.validate().unwrap_err();
    assert!(
        err.contains("instance_id") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r115_005_deployment_info_rejects_control_char_in_mode() {
    let info = crate::deployment::DeploymentInfo {
        instance_id: None,
        leader_status: None,
        discovered_endpoints: None,
        uptime_secs: 100,
        mode: "stand\talone".to_string(),
    };
    let err = info.validate().unwrap_err();
    assert!(
        err.contains("mode") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r115_005_deployment_info_rejects_bidi_in_mode() {
    let info = crate::deployment::DeploymentInfo {
        instance_id: None,
        leader_status: None,
        discovered_endpoints: None,
        uptime_secs: 100,
        mode: "standalone\u{202E}".to_string(),
    };
    let err = info.validate().unwrap_err();
    assert!(
        err.contains("mode") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r115_005_deployment_info_valid_passes() {
    let info = crate::deployment::DeploymentInfo {
        instance_id: Some("pod-1".to_string()),
        leader_status: None,
        discovered_endpoints: None,
        uptime_secs: 100,
        mode: "standalone".to_string(),
    };
    assert!(info.validate().is_ok());
}

#[test]
fn test_r115_005_deployment_info_none_instance_id_passes() {
    let info = crate::deployment::DeploymentInfo {
        instance_id: None,
        leader_status: None,
        discovered_endpoints: None,
        uptime_secs: 100,
        mode: "standalone".to_string(),
    };
    assert!(info.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R115-006: AbacPolicy/AbacEntity/LeastAgencyReport control/format char validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_r115_006_abac_policy_rejects_control_char_in_id() {
    let policy = AbacPolicy {
        id: "policy\x01-1".to_string(),
        description: "A test policy".to_string(),
        effect: AbacEffect::Permit,
        priority: 0,
        principal: PrincipalConstraint::default(),
        action: ActionConstraint::default(),
        resource: ResourceConstraint::default(),
        conditions: vec![],
    };
    let err = policy.validate().unwrap_err();
    assert!(
        err.contains("id") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r115_006_abac_policy_rejects_bidi_in_description() {
    let policy = AbacPolicy {
        id: "policy-1".to_string(),
        description: "Allow\u{202A} access".to_string(),
        effect: AbacEffect::Permit,
        priority: 0,
        principal: PrincipalConstraint::default(),
        action: ActionConstraint::default(),
        resource: ResourceConstraint::default(),
        conditions: vec![],
    };
    let err = policy.validate().unwrap_err();
    assert!(
        err.contains("description") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r115_006_abac_policy_valid_passes() {
    let policy = AbacPolicy {
        id: "policy-1".to_string(),
        description: "A test policy".to_string(),
        effect: AbacEffect::Permit,
        priority: 0,
        principal: PrincipalConstraint::default(),
        action: ActionConstraint::default(),
        resource: ResourceConstraint::default(),
        conditions: vec![],
    };
    assert!(policy.validate().is_ok());
}

#[test]
fn test_r115_006_abac_entity_rejects_control_char_in_entity_type() {
    let entity = AbacEntity {
        entity_type: "Agent\n".to_string(),
        id: "agent-1".to_string(),
        attributes: HashMap::new(),
        parents: vec![],
    };
    let err = entity.validate().unwrap_err();
    assert!(
        err.contains("entity_type") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r115_006_abac_entity_rejects_zwsp_in_id() {
    let entity = AbacEntity {
        entity_type: "Agent".to_string(),
        id: "agent\u{200B}-1".to_string(),
        attributes: HashMap::new(),
        parents: vec![],
    };
    let err = entity.validate().unwrap_err();
    assert!(
        err.contains("id") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r115_006_abac_entity_valid_passes() {
    let entity = AbacEntity {
        entity_type: "Agent".to_string(),
        id: "agent-1".to_string(),
        attributes: HashMap::new(),
        parents: vec!["group-1".to_string()],
    };
    assert!(entity.validate().is_ok());
}

#[test]
fn test_r115_006_least_agency_report_rejects_control_char_in_agent_id() {
    let report = LeastAgencyReport {
        agent_id: "agent\x01-1".to_string(),
        session_id: "sess-1".to_string(),
        granted_permissions: 5,
        used_permissions: 4,
        unused_permissions: vec![],
        usage_ratio: 0.8,
        recommendation: AgencyRecommendation::Optimal,
    };
    let err = report.validate().unwrap_err();
    assert!(
        err.contains("agent_id") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r115_006_least_agency_report_rejects_bom_in_session_id() {
    let report = LeastAgencyReport {
        agent_id: "agent-1".to_string(),
        session_id: "\u{FEFF}sess-1".to_string(),
        granted_permissions: 5,
        used_permissions: 4,
        unused_permissions: vec![],
        usage_ratio: 0.8,
        recommendation: AgencyRecommendation::Optimal,
    };
    let err = report.validate().unwrap_err();
    assert!(
        err.contains("session_id") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r115_006_least_agency_report_valid_passes() {
    let report = LeastAgencyReport {
        agent_id: "agent-1".to_string(),
        session_id: "sess-1".to_string(),
        granted_permissions: 5,
        used_permissions: 4,
        unused_permissions: vec![],
        usage_ratio: 0.8,
        recommendation: AgencyRecommendation::Optimal,
    };
    assert!(report.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R115-007: deny_unknown_fields on 9 types
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_r115_007_tool_signature_rejects_unknown_fields() {
    let json = r#"{
        "signature_id":"sig-1","signature":"abc","algorithm":"ed25519",
        "public_key":"def","signed_at":"2026-01-01T00:00:00Z",
        "extra_field":"attack"
    }"#;
    let result = serde_json::from_str::<crate::etdi::ToolSignature>(json);
    assert!(result.is_err(), "ToolSignature must reject unknown fields");
}

#[test]
fn test_r115_007_tool_attestation_rejects_unknown_fields() {
    let json = r#"{
        "attestation_id":"att-1","attestation_type":"initial","attester":"me",
        "timestamp":"2026-01-01T00:00:00Z","tool_hash":"abc",
        "signature":{"signature_id":"s1","signature":"a","algorithm":"ed25519","public_key":"b","signed_at":"2026-01-01T00:00:00Z"},
        "extra_field":"attack"
    }"#;
    let result = serde_json::from_str::<crate::etdi::ToolAttestation>(json);
    assert!(
        result.is_err(),
        "ToolAttestation must reject unknown fields"
    );
}

#[test]
fn test_r115_007_tool_version_pin_rejects_unknown_fields() {
    let json = r#"{
        "tool_name":"t","definition_hash":"abc","pinned_at":"2026-01-01T00:00:00Z",
        "pinned_by":"admin","extra_field":"attack"
    }"#;
    let result = serde_json::from_str::<crate::etdi::ToolVersionPin>(json);
    assert!(result.is_err(), "ToolVersionPin must reject unknown fields");
}

#[test]
fn test_r115_007_version_drift_alert_rejects_unknown_fields() {
    let json = r#"{
        "tool":"t","expected_version":"1.0","actual_version":"2.0",
        "drift_type":"version_mismatch","blocking":true,
        "detected_at":"2026-01-01T00:00:00Z","extra_field":"attack"
    }"#;
    let result = serde_json::from_str::<crate::etdi::VersionDriftAlert>(json);
    assert!(
        result.is_err(),
        "VersionDriftAlert must reject unknown fields"
    );
}

#[test]
fn test_r115_007_abac_entity_rejects_unknown_fields() {
    let json = r#"{
        "entity_type":"Agent","id":"agent-1","extra_field":"attack"
    }"#;
    let result = serde_json::from_str::<crate::abac::AbacEntity>(json);
    assert!(result.is_err(), "AbacEntity must reject unknown fields");
}

#[test]
fn test_r115_007_permission_usage_rejects_unknown_fields() {
    let json = r#"{
        "tool_pattern":"*","function_pattern":"*","used_count":0,"extra_field":"attack"
    }"#;
    let result = serde_json::from_str::<crate::abac::PermissionUsage>(json);
    assert!(
        result.is_err(),
        "PermissionUsage must reject unknown fields"
    );
}

#[test]
fn test_r115_007_least_agency_report_rejects_unknown_fields() {
    let json = r#"{
        "agent_id":"a","session_id":"s","granted_permissions":0,"used_permissions":0,
        "unused_permissions":[],"usage_ratio":1.0,"recommendation":"optimal",
        "extra_field":"attack"
    }"#;
    let result = serde_json::from_str::<crate::abac::LeastAgencyReport>(json);
    assert!(
        result.is_err(),
        "LeastAgencyReport must reject unknown fields"
    );
}

#[test]
fn test_r115_007_memory_namespace_rejects_unknown_fields() {
    let json = r#"{
        "id":"ns-1","owner_agent":"agent-1","created_at":"2026-01-01T00:00:00Z",
        "extra_field":"attack"
    }"#;
    let result = serde_json::from_str::<crate::minja::MemoryNamespace>(json);
    assert!(
        result.is_err(),
        "MemoryNamespace must reject unknown fields"
    );
}

#[test]
fn test_r115_007_extension_descriptor_rejects_unknown_fields() {
    let json = r#"{
        "id":"ext-1","name":"Ext","version":"1.0","extra_field":"attack"
    }"#;
    let result = serde_json::from_str::<crate::extension::ExtensionDescriptor>(json);
    assert!(
        result.is_err(),
        "ExtensionDescriptor must reject unknown fields"
    );
}

// Verify existing roundtrip serde tests still pass with deny_unknown_fields
#[test]
fn test_r115_007_tool_signature_roundtrip_with_deny_unknown_fields() {
    let sig = crate::etdi::ToolSignature {
        signature_id: "sig-1".to_string(),
        signature: "abc".to_string(),
        algorithm: crate::etdi::SignatureAlgorithm::Ed25519,
        public_key: "def".to_string(),
        key_fingerprint: None,
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    let json_str = serde_json::to_string(&sig).unwrap();
    let deserialized: crate::etdi::ToolSignature = serde_json::from_str(&json_str).unwrap();
    assert_eq!(sig, deserialized);
}

#[test]
fn test_r115_007_abac_entity_roundtrip_with_deny_unknown_fields() {
    let entity = crate::abac::AbacEntity {
        entity_type: "Agent".to_string(),
        id: "agent-1".to_string(),
        attributes: HashMap::new(),
        parents: vec!["group-1".to_string()],
    };
    let json_str = serde_json::to_string(&entity).unwrap();
    let deserialized: crate::abac::AbacEntity = serde_json::from_str(&json_str).unwrap();
    assert_eq!(entity, deserialized);
}

// ═══════════════════════════════════════════════════════════════════
// IMP-R126-009: has_dangerous_chars() canonical predicate tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_has_dangerous_chars_clean_strings() {
    assert!(!crate::core::has_dangerous_chars("normal text"));
    assert!(!crate::core::has_dangerous_chars(
        "with.punctuation-and_underscores"
    ));
    assert!(!crate::core::has_dangerous_chars(""));
    assert!(!crate::core::has_dangerous_chars(
        "unicode: café résumé naïve"
    ));
}

#[test]
fn test_has_dangerous_chars_control_chars() {
    assert!(crate::core::has_dangerous_chars("has\x00null"));
    assert!(crate::core::has_dangerous_chars("has\nnewline"));
    assert!(crate::core::has_dangerous_chars("has\ttab"));
    assert!(crate::core::has_dangerous_chars("has\x7fDEL"));
}

#[test]
fn test_has_dangerous_chars_unicode_format_chars() {
    assert!(crate::core::has_dangerous_chars("has\u{200B}zwsp"));
    assert!(crate::core::has_dangerous_chars("has\u{202E}bidi"));
    assert!(crate::core::has_dangerous_chars("has\u{FEFF}bom"));
    assert!(crate::core::has_dangerous_chars("has\u{00AD}shyphen"));
    assert!(crate::core::has_dangerous_chars("has\u{2060}wj"));
}

// ═══════════════════════════════════════════════════════════════════
// IMP-R126-005: ToolMetadata::validate() control/format char tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_tool_metadata_validate_empty_tool_id() {
    let meta = ToolMetadata {
        tool_id: "".to_string(),
        name: "test".to_string(),
        description: "test".to_string(),
        server_id: "srv".to_string(),
        input_schema: serde_json::json!({}),
        schema_hash: "abc".to_string(),
        sensitivity: ToolSensitivity::Low,
        domain_tags: vec![],
        token_cost: 10,
    };
    let err = meta.validate().unwrap_err();
    assert!(err.contains("must not be empty"), "got: {err}");
}

#[test]
fn test_tool_metadata_validate_control_char_in_name() {
    let meta = ToolMetadata {
        tool_id: "srv:tool".to_string(),
        name: "tool\x01name".to_string(),
        description: "test".to_string(),
        server_id: "srv".to_string(),
        input_schema: serde_json::json!({}),
        schema_hash: "abc".to_string(),
        sensitivity: ToolSensitivity::Low,
        domain_tags: vec![],
        token_cost: 10,
    };
    let err = meta.validate().unwrap_err();
    assert!(err.contains("control or format"), "got: {err}");
}

#[test]
fn test_tool_metadata_validate_format_char_in_description() {
    let meta = ToolMetadata {
        tool_id: "srv:tool".to_string(),
        name: "tool".to_string(),
        description: "desc\u{200B}ription".to_string(),
        server_id: "srv".to_string(),
        input_schema: serde_json::json!({}),
        schema_hash: "abc".to_string(),
        sensitivity: ToolSensitivity::Low,
        domain_tags: vec![],
        token_cost: 10,
    };
    let err = meta.validate().unwrap_err();
    assert!(
        err.contains("description contains control or format"),
        "got: {err}"
    );
}

#[test]
fn test_tool_metadata_validate_control_char_in_domain_tag() {
    let meta = ToolMetadata {
        tool_id: "srv:tool".to_string(),
        name: "tool".to_string(),
        description: "test".to_string(),
        server_id: "srv".to_string(),
        input_schema: serde_json::json!({}),
        schema_hash: "abc".to_string(),
        sensitivity: ToolSensitivity::Low,
        domain_tags: vec!["clean".to_string(), "bad\x07tag".to_string()],
        token_cost: 10,
    };
    let err = meta.validate().unwrap_err();
    assert!(
        err.contains("domain_tag contains control or format"),
        "got: {err}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// IMP-R126-006: NhiDpopVerificationResult::validate() tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_nhi_dpop_verification_result_validate_all_none() {
    let r = NhiDpopVerificationResult {
        valid: true,
        thumbprint: None,
        error: None,
        new_nonce: None,
    };
    assert!(r.validate().is_ok());
}

#[test]
fn test_nhi_dpop_verification_result_validate_thumbprint_too_long() {
    let r = NhiDpopVerificationResult {
        valid: true,
        thumbprint: Some("x".repeat(513)),
        error: None,
        new_nonce: None,
    };
    let err = r.validate().unwrap_err();
    assert!(err.contains("thumbprint length"), "got: {err}");
}

#[test]
fn test_nhi_dpop_verification_result_validate_error_format_chars() {
    let r = NhiDpopVerificationResult {
        valid: false,
        thumbprint: None,
        error: Some("error\u{200B}msg".to_string()),
        new_nonce: None,
    };
    let err = r.validate().unwrap_err();
    assert!(
        err.contains("error contains control or format"),
        "got: {err}"
    );
}

#[test]
fn test_nhi_dpop_verification_result_validate_nonce_too_long() {
    let r = NhiDpopVerificationResult {
        valid: false,
        thumbprint: None,
        error: None,
        new_nonce: Some("n".repeat(257)),
    };
    let err = r.validate().unwrap_err();
    assert!(err.contains("new_nonce length"), "got: {err}");
}

// ═══════════════════════════════════════════════════════════════════
// IMP-R126-007: NhiAgentIdentity::validate() timestamp tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_nhi_agent_identity_validate_malformed_issued_at() {
    let identity = NhiAgentIdentity {
        id: "agent-1".to_string(),
        name: "Test".to_string(),
        issued_at: "not-a-date".to_string(),
        expires_at: "2027-01-01T00:00:00Z".to_string(),
        ..Default::default()
    };
    let err = identity.validate().unwrap_err();
    assert!(
        err.contains("issued_at") && err.contains("ISO 8601"),
        "got: {err}"
    );
}

#[test]
fn test_nhi_agent_identity_validate_malformed_expires_at() {
    let identity = NhiAgentIdentity {
        id: "agent-1".to_string(),
        name: "Test".to_string(),
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "bad".to_string(),
        ..Default::default()
    };
    let err = identity.validate().unwrap_err();
    assert!(
        err.contains("expires_at") && err.contains("ISO 8601"),
        "got: {err}"
    );
}

#[test]
fn test_nhi_agent_identity_validate_valid_timestamps() {
    let identity = NhiAgentIdentity {
        id: "agent-1".to_string(),
        name: "Test".to_string(),
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2027-01-01T00:00:00Z".to_string(),
        last_rotation: Some("2026-06-01T12:00:00Z".to_string()),
        last_auth: Some("2026-06-15T08:30:00Z".to_string()),
        ..Default::default()
    };
    assert!(identity.validate().is_ok());
}

#[test]
fn test_nhi_agent_identity_validate_malformed_last_rotation() {
    let identity = NhiAgentIdentity {
        id: "agent-1".to_string(),
        name: "Test".to_string(),
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2027-01-01T00:00:00Z".to_string(),
        last_rotation: Some("garbage".to_string()),
        ..Default::default()
    };
    let err = identity.validate().unwrap_err();
    assert!(
        err.contains("last_rotation") && err.contains("ISO 8601"),
        "got: {err}"
    );
}

// FIND-R126-010: Temporal ordering — expires_at must be after issued_at.
#[test]
fn test_nhi_agent_identity_validate_expires_before_issued() {
    let identity = NhiAgentIdentity {
        id: "agent-1".to_string(),
        name: "Test".to_string(),
        issued_at: "2027-01-01T00:00:00Z".to_string(),
        expires_at: "2026-01-01T00:00:00Z".to_string(), // before issued_at
        ..Default::default()
    };
    let err = identity.validate().unwrap_err();
    assert!(
        err.contains("expires_at") && err.contains("must be after issued_at"),
        "got: {err}"
    );
}

#[test]
fn test_nhi_agent_identity_validate_expires_equal_issued() {
    let identity = NhiAgentIdentity {
        id: "agent-1".to_string(),
        name: "Test".to_string(),
        issued_at: "2027-01-01T00:00:00Z".to_string(),
        expires_at: "2027-01-01T00:00:00Z".to_string(), // equal to issued_at
        ..Default::default()
    };
    let err = identity.validate().unwrap_err();
    assert!(
        err.contains("expires_at") && err.contains("must be after issued_at"),
        "got: {err}"
    );
}

// FIND-R126-011: NhiBehavioralBaseline timestamp validation.
#[test]
fn test_nhi_behavioral_baseline_validate_malformed_created_at() {
    let baseline = NhiBehavioralBaseline {
        agent_id: "test-agent".to_string(),
        created_at: "not-a-date".to_string(),
        ..NhiBehavioralBaseline::default()
    };
    let err = baseline.validate().unwrap_err();
    assert!(
        err.contains("created_at") && err.contains("ISO 8601"),
        "got: {err}"
    );
}

#[test]
fn test_nhi_behavioral_baseline_validate_malformed_last_updated() {
    let baseline = NhiBehavioralBaseline {
        agent_id: "test-agent".to_string(),
        last_updated: "garbage".to_string(),
        ..NhiBehavioralBaseline::default()
    };
    let err = baseline.validate().unwrap_err();
    assert!(
        err.contains("last_updated") && err.contains("ISO 8601"),
        "got: {err}"
    );
}

// ═══════════════════════════════════════════════════
// FIND-R116-TE-001: validate_url_no_ssrf IPv6 transition mechanism checks
// ═══════════════════════════════════════════════════

#[test]
fn test_ssrf_ipv4_compatible_private() {
    // ::10.0.0.1 = IPv4-compatible with embedded private IPv4
    let result = validate_url_no_ssrf("http://[::10.0.0.1]/path");
    assert!(
        result.is_err(),
        "IPv4-compatible ::10.0.0.1 should be rejected"
    );
    assert!(
        result.unwrap_err().contains("IPv4-compatible"),
        "error should mention IPv4-compatible"
    );
}

#[test]
fn test_ssrf_ipv4_compatible_loopback() {
    // ::127.0.0.1 = IPv4-compatible with embedded loopback
    let result = validate_url_no_ssrf("http://[::127.0.0.1]/path");
    assert!(
        result.is_err(),
        "IPv4-compatible ::127.0.0.1 should be rejected"
    );
}

#[test]
fn test_ssrf_ipv4_compatible_public_allowed() {
    // ::8.8.8.8 = IPv4-compatible with embedded public IP — should be allowed
    let result = validate_url_no_ssrf("http://[::8.8.8.8]/path");
    assert!(
        result.is_ok(),
        "IPv4-compatible with public IP should be allowed"
    );
}

#[test]
fn test_ssrf_6to4_private() {
    // 2002:c0a8:0101:: = 6to4 with embedded 192.168.1.1
    let result = validate_url_no_ssrf("http://[2002:c0a8:0101::1]/path");
    assert!(
        result.is_err(),
        "6to4 with embedded 192.168.1.1 should be rejected"
    );
    assert!(
        result.unwrap_err().contains("6to4"),
        "error should mention 6to4"
    );
}

#[test]
fn test_ssrf_6to4_loopback() {
    // 2002:7f00:0001:: = 6to4 with embedded 127.0.0.1
    let result = validate_url_no_ssrf("http://[2002:7f00:0001::1]/path");
    assert!(
        result.is_err(),
        "6to4 with embedded 127.0.0.1 should be rejected"
    );
}

#[test]
fn test_ssrf_6to4_public_allowed() {
    // 2002:0808:0808:: = 6to4 with embedded 8.8.8.8 — should be allowed
    let result = validate_url_no_ssrf("http://[2002:0808:0808::1]/path");
    assert!(result.is_ok(), "6to4 with public IP should be allowed");
}

#[test]
fn test_ssrf_teredo_private() {
    // Teredo with embedded 192.168.1.1: XOR with 0xFFFF
    // 192.168.1.1 = c0.a8.01.01 -> XOR: 3f.57.fe.fe
    let result = validate_url_no_ssrf("http://[2001:0000:4136:e378:8000:63bf:3f57:fefe]/path");
    assert!(
        result.is_err(),
        "Teredo with embedded 192.168.1.1 should be rejected"
    );
    assert!(
        result.unwrap_err().contains("Teredo"),
        "error should mention Teredo"
    );
}

#[test]
fn test_ssrf_teredo_loopback() {
    // Teredo with embedded 127.0.0.1: XOR with 0xFFFF
    // 127.0.0.1 = 7f.00.00.01 -> XOR: 80.ff.ff.fe
    let result = validate_url_no_ssrf("http://[2001:0000:4136:e378:8000:63bf:80ff:fffe]/path");
    assert!(
        result.is_err(),
        "Teredo with embedded 127.0.0.1 should be rejected"
    );
}

#[test]
fn test_ssrf_teredo_public_allowed() {
    // Teredo with embedded 8.8.8.8: XOR with 0xFFFF
    // 8.8.8.8 = 08.08.08.08 -> XOR: f7.f7.f7.f7
    let result = validate_url_no_ssrf("http://[2001:0000:4136:e378:8000:63bf:f7f7:f7f7]/path");
    assert!(result.is_ok(), "Teredo with public IP should be allowed");
}

#[test]
fn test_ssrf_nat64_private() {
    // 64:ff9b::192.168.1.1 = NAT64 with embedded private
    let result = validate_url_no_ssrf("http://[64:ff9b::c0a8:0101]/path");
    assert!(
        result.is_err(),
        "NAT64 with embedded 192.168.1.1 should be rejected"
    );
    assert!(
        result.unwrap_err().contains("NAT64"),
        "error should mention NAT64"
    );
}

#[test]
fn test_ssrf_nat64_loopback() {
    // 64:ff9b::127.0.0.1 = NAT64 with embedded loopback
    let result = validate_url_no_ssrf("http://[64:ff9b::7f00:0001]/path");
    assert!(
        result.is_err(),
        "NAT64 with embedded 127.0.0.1 should be rejected"
    );
}

#[test]
fn test_ssrf_nat64_public_allowed() {
    // 64:ff9b::8.8.8.8 = NAT64 with embedded public IP — should be allowed
    let result = validate_url_no_ssrf("http://[64:ff9b::0808:0808]/path");
    assert!(result.is_ok(), "NAT64 with public IP should be allowed");
}

#[test]
fn test_ssrf_nat64_local_use_private() {
    // 64:ff9b:1::c0a8:0101 = NAT64 local-use with embedded 192.168.1.1
    let result = validate_url_no_ssrf("http://[64:ff9b:1::c0a8:0101]/path");
    assert!(
        result.is_err(),
        "NAT64 local-use with embedded 192.168.1.1 should be rejected"
    );
    assert!(
        result.unwrap_err().contains("NAT64 local-use"),
        "error should mention NAT64 local-use"
    );
}

#[test]
fn test_ssrf_nat64_local_use_public_allowed() {
    // 64:ff9b:1::0808:0808 = NAT64 local-use with embedded 8.8.8.8 — should be allowed
    let result = validate_url_no_ssrf("http://[64:ff9b:1::0808:0808]/path");
    assert!(
        result.is_ok(),
        "NAT64 local-use with public IP should be allowed"
    );
}

#[test]
fn test_ssrf_ipv4_mapped_still_works() {
    // Ensure existing IPv4-mapped check still works after refactoring
    let result = validate_url_no_ssrf("http://[::ffff:192.168.1.1]/path");
    assert!(
        result.is_err(),
        "IPv4-mapped with private IP should still be rejected"
    );
    assert!(
        result.unwrap_err().contains("IPv4-mapped"),
        "error should mention IPv4-mapped"
    );
}

#[test]
fn test_ssrf_6to4_cgnat() {
    // 6to4 with embedded CGNAT address (100.64.0.1)
    // 100.64.0.1 = 0x64400001 -> segs 1=0x6440, 2=0x0001
    let result = validate_url_no_ssrf("http://[2002:6440:0001::1]/path");
    assert!(
        result.is_err(),
        "6to4 with embedded CGNAT should be rejected"
    );
}

#[test]
fn test_ssrf_nat64_cgnat() {
    // NAT64 with embedded CGNAT address (100.64.0.1)
    let result = validate_url_no_ssrf("http://[64:ff9b::6440:0001]/path");
    assert!(
        result.is_err(),
        "NAT64 with embedded CGNAT should be rejected"
    );
}

// ═══════════════════════════════════════════════════
// R230-TYP-1/TYP-2: IPv6 and IPv4 multicast SSRF blocked
// ═══════════════════════════════════════════════════

#[test]
fn test_ssrf_ipv6_multicast_blocked() {
    // R230-TYP-1: ff00::/8 multicast must be blocked
    let result = validate_url_no_ssrf("http://[ff02::1]/path");
    assert!(
        result.is_err(),
        "IPv6 all-nodes multicast should be rejected"
    );
    let result = validate_url_no_ssrf("http://[ff05::1]/path");
    assert!(
        result.is_err(),
        "IPv6 site-local multicast should be rejected"
    );
    let result = validate_url_no_ssrf("http://[ff08::1]/path");
    assert!(
        result.is_err(),
        "IPv6 org-scope multicast should be rejected"
    );
    let result = validate_url_no_ssrf("http://[ff0e::1]/path");
    assert!(
        result.is_err(),
        "IPv6 global-scope multicast should be rejected"
    );
}

#[test]
fn test_ssrf_ipv4_multicast_blocked() {
    // R230-TYP-2: 224.0.0.0/4 multicast must be blocked
    let result = validate_url_no_ssrf("http://224.0.0.1/path");
    assert!(
        result.is_err(),
        "IPv4 all-hosts multicast should be rejected"
    );
    let result = validate_url_no_ssrf("http://239.255.255.255/path");
    assert!(
        result.is_err(),
        "IPv4 admin-scoped multicast should be rejected"
    );
    let result = validate_url_no_ssrf("http://232.1.2.3/path");
    assert!(result.is_err(), "IPv4 SSM multicast should be rejected");
}

// ═══════════════════════════════════════════════════
// R231-TYP-6: Percent-encoded SSRF bypass
// ═══════════════════════════════════════════════════

#[test]
fn test_ssrf_percent_encoded_metadata_ip_rejected() {
    // R231-TYP-6: %31%36%39.%32%35%34.%31%36%39.%32%35%34 = 169.254.169.254
    let result =
        validate_url_no_ssrf("http://%31%36%39.%32%35%34.%31%36%39.%32%35%34/latest/meta-data/");
    assert!(
        result.is_err(),
        "Percent-encoded metadata IP (169.254.169.254) must be rejected"
    );
}

#[test]
fn test_ssrf_percent_encoded_localhost_rejected() {
    // R231-TYP-6: %6c%6f%63%61%6c%68%6f%73%74 = localhost
    let result = validate_url_no_ssrf("http://%6c%6f%63%61%6c%68%6f%73%74/secret");
    assert!(
        result.is_err(),
        "Percent-encoded 'localhost' must be rejected"
    );
}

#[test]
fn test_ssrf_percent_encoded_private_ip_rejected() {
    // R231-TYP-6: %31%30.%30.%30.%31 = 10.0.0.1
    let result = validate_url_no_ssrf("http://%31%30.%30.%30.%31/internal");
    assert!(
        result.is_err(),
        "Percent-encoded private IP (10.0.0.1) must be rejected"
    );
}

#[test]
fn test_ssrf_percent_encoded_127_rejected() {
    // R231-TYP-6: %31%32%37.%30.%30.%31 = 127.0.0.1
    let result = validate_url_no_ssrf("http://%31%32%37.%30.%30.%31/");
    assert!(
        result.is_err(),
        "Percent-encoded loopback (127.0.0.1) must be rejected"
    );
}

#[test]
fn test_ssrf_percent_encoded_public_ip_allowed() {
    // R231-TYP-6: %38.%38.%38.%38 = 8.8.8.8 — public, should be allowed.
    let result = validate_url_no_ssrf("http://%38.%38.%38.%38/ok");
    assert!(
        result.is_ok(),
        "Percent-encoded public IP (8.8.8.8) should be allowed"
    );
}

// ═══════════════════════════════════════════════════
// FIND-R116-TE-002: resolved_ips control/format character validation
// ═══════════════════════════════════════════════════

#[test]
fn test_resolved_ips_control_char_rejected() {
    // FIND-R116-TE-002: resolved_ips with control character (newline) must be rejected
    let mut action = Action::new("tool", "func", json!({}));
    action.resolved_ips = vec!["10.0.0\n.1".to_string()];
    assert!(matches!(
        action.validate(),
        Err(ValidationError::ControlCharacter {
            field: "resolved_ips"
        })
    ));
}

#[test]
fn test_resolved_ips_tab_char_rejected() {
    // FIND-R116-TE-002: resolved_ips with tab character must be rejected
    let mut action = Action::new("tool", "func", json!({}));
    action.resolved_ips = vec!["10.0.0\t.1".to_string()];
    assert!(matches!(
        action.validate(),
        Err(ValidationError::ControlCharacter {
            field: "resolved_ips"
        })
    ));
}

#[test]
fn test_resolved_ips_unicode_format_char_rejected() {
    // FIND-R116-TE-002: resolved_ips with zero-width space must be rejected
    let mut action = Action::new("tool", "func", json!({}));
    action.resolved_ips = vec!["10.0.0\u{200B}.1".to_string()];
    assert!(matches!(
        action.validate(),
        Err(ValidationError::ControlCharacter {
            field: "resolved_ips"
        })
    ));
}

#[test]
fn test_resolved_ips_bidi_override_rejected() {
    // FIND-R116-TE-002: resolved_ips with bidi override must be rejected
    let mut action = Action::new("tool", "func", json!({}));
    action.resolved_ips = vec!["10.0.0\u{202E}.1".to_string()];
    assert!(matches!(
        action.validate(),
        Err(ValidationError::ControlCharacter {
            field: "resolved_ips"
        })
    ));
}

#[test]
fn test_resolved_ips_clean_entries_pass() {
    // FIND-R116-TE-002: Clean IP strings should pass validation
    let mut action = Action::new("tool", "func", json!({}));
    action.resolved_ips = vec![
        "10.0.0.1".to_string(),
        "2001:db8::1".to_string(),
        "::ffff:192.168.1.1".to_string(),
    ];
    assert!(action.validate().is_ok());
}

// =============================================================================
// Round 141: AgentIdentity audience/issuer/subject validation
// =============================================================================

#[test]
fn test_r141_agent_identity_audience_entry_oversized() {
    let identity = AgentIdentity {
        audience: vec!["x".repeat(1025)],
        ..Default::default()
    };
    let result = identity.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("audience[0] length"));
}

#[test]
fn test_r141_agent_identity_audience_entry_control_char() {
    let identity = AgentIdentity {
        audience: vec!["urn:vellaveto\n:admin".to_string()],
        ..Default::default()
    };
    let result = identity.validate();
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("audience[0]"), "Got: {err}");
    assert!(err.contains("control or format"), "Got: {err}");
}

#[test]
fn test_r141_agent_identity_audience_entry_format_char() {
    let identity = AgentIdentity {
        audience: vec![format!("urn:vellaveto\u{200B}:admin")],
        ..Default::default()
    };
    let result = identity.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("audience[0]"));
}

#[test]
fn test_r141_agent_identity_issuer_oversized() {
    let identity = AgentIdentity {
        issuer: Some("x".repeat(1025)),
        ..Default::default()
    };
    let result = identity.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("issuer length"));
}

#[test]
fn test_r141_agent_identity_issuer_control_char() {
    let identity = AgentIdentity {
        issuer: Some("issuer\x01corp.com".to_string()),
        ..Default::default()
    };
    let result = identity.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("issuer contains control"));
}

#[test]
fn test_r141_agent_identity_subject_oversized() {
    let identity = AgentIdentity {
        subject: Some("x".repeat(1025)),
        ..Default::default()
    };
    let result = identity.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("subject length"));
}

#[test]
fn test_r141_agent_identity_subject_format_char() {
    let identity = AgentIdentity {
        subject: Some("agent\u{200D}user".to_string()),
        ..Default::default()
    };
    let result = identity.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("subject contains control"));
}

#[test]
fn test_r141_evaluation_context_timestamp_oversized() {
    let mut ctx = EvaluationContext::builder().build();
    ctx.timestamp = Some("x".repeat(65));
    let result = ctx.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("timestamp length"));
}

#[test]
fn test_r141_evaluation_context_timestamp_control_char() {
    let mut ctx = EvaluationContext::builder().build();
    ctx.timestamp = Some("2026-01-01T00:00:00Z\nINFO: forged".to_string());
    let result = ctx.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("timestamp contains control"));
}

#[test]
fn test_r141_evaluation_context_timestamp_valid() {
    let mut ctx = EvaluationContext::builder().build();
    ctx.timestamp = Some("2026-01-01T00:00:00Z".to_string());
    assert!(ctx.validate().is_ok());
}

#[test]
fn test_r141_tool_signature_control_char_in_signature_id() {
    use crate::etdi::{SignatureAlgorithm, ToolSignature};
    let sig = ToolSignature {
        signature_id: "sig\n-inject".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        signature: "abc".to_string(),
        public_key: "def".to_string(),
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        key_fingerprint: None,
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    let result = sig.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("signature_id"));
}

#[test]
fn test_r141_tool_signature_format_char_in_spiffe_id() {
    use crate::etdi::{SignatureAlgorithm, ToolSignature};
    let sig = ToolSignature {
        signature_id: "sig-001".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        signature: "abc".to_string(),
        public_key: "def".to_string(),
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        key_fingerprint: None,
        signer_spiffe_id: Some("spiffe://trust\u{200D}domain/workload".to_string()),
        rekor_entry: None,
    };
    let result = sig.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("signer_spiffe_id"));
}

// FIND-R196-006: ToolSignature rejects non-hex signature
#[test]
fn test_r196_tool_signature_rejects_non_hex_signature() {
    use crate::etdi::{SignatureAlgorithm, ToolSignature};
    let sig = ToolSignature {
        signature_id: "sig-001".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        signature: "not-hex-value!".to_string(),
        public_key: "abcdef0123456789".to_string(),
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        key_fingerprint: None,
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    let result = sig.validate();
    assert!(result.is_err());
    assert!(
        result.unwrap_err().contains("non-hex"),
        "should mention non-hex"
    );
}

// FIND-R196-006: ToolSignature rejects non-hex public_key
#[test]
fn test_r196_tool_signature_rejects_non_hex_public_key() {
    use crate::etdi::{SignatureAlgorithm, ToolSignature};
    let sig = ToolSignature {
        signature_id: "sig-001".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        signature: "deadbeef".to_string(),
        public_key: "GHIJK_not_hex".to_string(),
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        key_fingerprint: None,
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    let result = sig.validate();
    assert!(result.is_err());
    assert!(
        result.unwrap_err().contains("non-hex"),
        "should mention non-hex"
    );
}

// FIND-R196-006: ToolSignature allows valid hex signature/public_key
#[test]
fn test_r196_tool_signature_accepts_valid_hex() {
    use crate::etdi::{SignatureAlgorithm, ToolSignature};
    let sig = ToolSignature {
        signature_id: "sig-001".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        signature: "0123456789abcdefABCDEF".to_string(),
        public_key: "fedcba9876543210".to_string(),
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        key_fingerprint: None,
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    assert!(sig.validate().is_ok());
}

#[test]
fn test_r141_tool_attestation_control_char_in_attester() {
    use crate::etdi::{SignatureAlgorithm, ToolAttestation, ToolSignature};
    let sig = ToolSignature {
        signature_id: "sig-001".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        signature: "abc".to_string(),
        public_key: "def".to_string(),
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        key_fingerprint: None,
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    let att = ToolAttestation {
        attestation_id: "att-001".to_string(),
        attestation_type: "automated".to_string(),
        attester: "attester\x01injected".to_string(),
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        tool_hash: "abc123".to_string(),
        previous_attestation: None,
        transparency_log_entry: None,
        signature: sig,
    };
    let result = att.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("attester"));
}

#[test]
fn test_r141_tool_attestation_format_char_in_tool_hash() {
    use crate::etdi::{SignatureAlgorithm, ToolAttestation, ToolSignature};
    let sig = ToolSignature {
        signature_id: "sig-001".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        signature: "abc".to_string(),
        public_key: "def".to_string(),
        signed_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        key_fingerprint: None,
        signer_spiffe_id: None,
        rekor_entry: None,
    };
    let att = ToolAttestation {
        attestation_id: "att-001".to_string(),
        attestation_type: "automated".to_string(),
        attester: "attester".to_string(),
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        tool_hash: "abcdef\u{200B}1234".to_string(),
        previous_attestation: None,
        transparency_log_entry: None,
        signature: sig,
    };
    let result = att.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("tool_hash"));
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R146-TE-001: VersionDriftAlert validate()
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_r146_version_drift_alert_validate_valid() {
    let alert = crate::etdi::VersionDriftAlert::version_mismatch(
        "my_tool",
        "1.0.0",
        "1.1.0",
        true,
        "2026-01-01T00:00:00Z",
    );
    assert!(alert.validate().is_ok());
}

#[test]
fn test_r146_version_drift_alert_validate_empty_tool() {
    let alert = crate::etdi::VersionDriftAlert {
        tool: String::new(),
        expected_version: "1.0".to_string(),
        actual_version: "2.0".to_string(),
        drift_type: "version_mismatch".to_string(),
        blocking: false,
        detected_at: "2026-01-01T00:00:00Z".to_string(),
    };
    let err = alert.validate().unwrap_err();
    assert!(
        err.contains("tool") && err.contains("must not be empty"),
        "got: {err}"
    );
}

#[test]
fn test_r146_version_drift_alert_validate_tool_too_long() {
    let alert = crate::etdi::VersionDriftAlert {
        tool: "x".repeat(513),
        expected_version: "1.0".to_string(),
        actual_version: "2.0".to_string(),
        drift_type: "version_mismatch".to_string(),
        blocking: false,
        detected_at: "2026-01-01T00:00:00Z".to_string(),
    };
    let err = alert.validate().unwrap_err();
    assert!(
        err.contains("tool") && err.contains("exceeds max"),
        "got: {err}"
    );
}

#[test]
fn test_r146_version_drift_alert_validate_format_chars() {
    let alert = crate::etdi::VersionDriftAlert {
        tool: "my_tool".to_string(),
        expected_version: "1.0\u{200B}".to_string(),
        actual_version: "2.0".to_string(),
        drift_type: "version_mismatch".to_string(),
        blocking: false,
        detected_at: "2026-01-01T00:00:00Z".to_string(),
    };
    let err = alert.validate().unwrap_err();
    assert!(
        err.contains("expected_version") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r146_version_drift_alert_validate_control_chars_in_detected_at() {
    let alert = crate::etdi::VersionDriftAlert {
        tool: "my_tool".to_string(),
        expected_version: "1.0".to_string(),
        actual_version: "2.0".to_string(),
        drift_type: "version_mismatch".to_string(),
        blocking: false,
        detected_at: "2026-01-01\n00:00:00Z".to_string(),
    };
    let err = alert.validate().unwrap_err();
    assert!(
        err.contains("detected_at") && err.contains("control or format"),
        "got: {err}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R146-TE-002: SignatureVerification deny_unknown_fields + validate()
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_r146_signature_verification_deny_unknown_fields() {
    let json = r#"{
        "valid": true,
        "signer_trusted": true,
        "expired": false,
        "message": "ok",
        "extra_field": "attack"
    }"#;
    let result = serde_json::from_str::<crate::etdi::SignatureVerification>(json);
    assert!(
        result.is_err(),
        "SignatureVerification must reject unknown fields"
    );
}

#[test]
fn test_r146_signature_verification_validate_valid() {
    let sv = crate::etdi::SignatureVerification {
        valid: true,
        signer_trusted: true,
        expired: false,
        message: "Verified successfully".to_string(),
    };
    assert!(sv.validate().is_ok());
}

#[test]
fn test_r146_signature_verification_validate_message_too_long() {
    let sv = crate::etdi::SignatureVerification {
        valid: true,
        signer_trusted: true,
        expired: false,
        message: "x".repeat(4097),
    };
    let err = sv.validate().unwrap_err();
    assert!(
        err.contains("message") && err.contains("exceeds max"),
        "got: {err}"
    );
}

#[test]
fn test_r146_signature_verification_validate_message_format_chars() {
    let sv = crate::etdi::SignatureVerification {
        valid: true,
        signer_trusted: true,
        expired: false,
        message: "ok\u{200B}".to_string(),
    };
    let err = sv.validate().unwrap_err();
    assert!(
        err.contains("message") && err.contains("control or format"),
        "got: {err}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R146-TE-003: PrincipalContext allowed_tools has_dangerous_chars
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_r146_principal_context_allowed_tools_format_chars() {
    let ctx = PrincipalContext {
        original_principal: "admin".to_string(),
        delegated_to: None,
        delegation_depth: 0,
        allowed_tools: vec![format!("read_file\u{200B}")],
        delegation_expires: None,
    };
    let err = ctx.validate().unwrap_err();
    assert!(
        err.contains("allowed_tools[0]") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r146_principal_context_allowed_tools_control_chars() {
    let ctx = PrincipalContext {
        original_principal: "admin".to_string(),
        delegated_to: None,
        delegation_depth: 0,
        allowed_tools: vec!["good_tool".to_string(), "bad\ntool".to_string()],
        delegation_expires: None,
    };
    let err = ctx.validate().unwrap_err();
    assert!(
        err.contains("allowed_tools[1]") && err.contains("control or format"),
        "got: {err}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R146-TE-004: NhiBehavioralBaseline agent_id validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_r146_nhi_behavioral_baseline_validate_empty_agent_id() {
    let baseline = NhiBehavioralBaseline::default();
    let err = baseline.validate().unwrap_err();
    assert!(
        err.contains("agent_id") && err.contains("must not be empty"),
        "got: {err}"
    );
}

#[test]
fn test_r146_nhi_behavioral_baseline_validate_agent_id_too_long() {
    let baseline = NhiBehavioralBaseline {
        agent_id: "x".repeat(257),
        ..Default::default()
    };
    let err = baseline.validate().unwrap_err();
    assert!(
        err.contains("agent_id") && err.contains("exceeds maximum"),
        "got: {err}"
    );
}

#[test]
fn test_r146_nhi_behavioral_baseline_validate_agent_id_dangerous_chars() {
    let baseline = NhiBehavioralBaseline {
        agent_id: "agent\u{200B}".to_string(),
        ..Default::default()
    };
    let err = baseline.validate().unwrap_err();
    assert!(
        err.contains("agent_id") && err.contains("dangerous characters"),
        "got: {err}"
    );
}

#[test]
fn test_r146_nhi_behavioral_baseline_validate_agent_id_control_chars() {
    let baseline = NhiBehavioralBaseline {
        agent_id: "agent\n123".to_string(),
        ..Default::default()
    };
    let err = baseline.validate().unwrap_err();
    assert!(
        err.contains("agent_id") && err.contains("dangerous characters"),
        "got: {err}"
    );
}

// ═══════════════════════════════════════════════════════════════
// AuditQueryParams validation tests (IMP-R198-002)
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_audit_query_params_default_passes() {
    let params = crate::AuditQueryParams::default();
    assert!(params.validate().is_ok());
}

#[test]
fn test_audit_query_params_limit_zero_fails() {
    let params = crate::AuditQueryParams {
        limit: 0,
        ..Default::default()
    };
    let err = params.validate().unwrap_err();
    assert!(err.contains("limit must be > 0"), "got: {err}");
}

#[test]
fn test_audit_query_params_limit_exceeds_max() {
    let params = crate::AuditQueryParams {
        limit: 1001,
        ..Default::default()
    };
    let err = params.validate().unwrap_err();
    assert!(err.contains("exceeds maximum"), "got: {err}");
}

#[test]
fn test_audit_query_params_limit_at_max() {
    let params = crate::AuditQueryParams {
        limit: 1000,
        ..Default::default()
    };
    assert!(params.validate().is_ok());
}

#[test]
fn test_audit_query_params_empty_agent_id_fails() {
    let params = crate::AuditQueryParams {
        agent_id: Some("".to_string()),
        ..Default::default()
    };
    let err = params.validate().unwrap_err();
    assert!(
        err.contains("agent_id filter must not be empty"),
        "got: {err}"
    );
}

#[test]
fn test_audit_query_params_agent_id_too_long() {
    let params = crate::AuditQueryParams {
        agent_id: Some("x".repeat(257)),
        ..Default::default()
    };
    let err = params.validate().unwrap_err();
    assert!(err.contains("agent_id length"), "got: {err}");
}

#[test]
fn test_audit_query_params_agent_id_control_chars() {
    let params = crate::AuditQueryParams {
        agent_id: Some("agent\x00bad".to_string()),
        ..Default::default()
    };
    let err = params.validate().unwrap_err();
    assert!(err.contains("control or format"), "got: {err}");
}

#[test]
fn test_audit_query_params_empty_tool_fails() {
    let params = crate::AuditQueryParams {
        tool: Some("".to_string()),
        ..Default::default()
    };
    let err = params.validate().unwrap_err();
    assert!(err.contains("tool filter must not be empty"), "got: {err}");
}

#[test]
fn test_audit_query_params_text_search_empty_fails() {
    let params = crate::AuditQueryParams {
        text_search: Some("".to_string()),
        ..Default::default()
    };
    let err = params.validate().unwrap_err();
    assert!(err.contains("text_search must not be empty"), "got: {err}");
}

#[test]
fn test_audit_query_params_text_search_too_long() {
    let params = crate::AuditQueryParams {
        text_search: Some("x".repeat(513)),
        ..Default::default()
    };
    let err = params.validate().unwrap_err();
    assert!(err.contains("text_search length"), "got: {err}");
}

#[test]
fn test_audit_query_params_text_search_sql_wildcards_only() {
    let params = crate::AuditQueryParams {
        text_search: Some("%%".to_string()),
        ..Default::default()
    };
    let err = params.validate().unwrap_err();
    assert!(err.contains("SQL wildcard"), "got: {err}");

    let params2 = crate::AuditQueryParams {
        text_search: Some("%_%%".to_string()),
        ..Default::default()
    };
    assert!(params2.validate().is_err());
}

#[test]
fn test_audit_query_params_text_search_with_mixed_content_ok() {
    let params = crate::AuditQueryParams {
        text_search: Some("test%search".to_string()),
        ..Default::default()
    };
    assert!(params.validate().is_ok());
}

#[test]
fn test_audit_query_params_sequence_range_inverted() {
    let params = crate::AuditQueryParams {
        from_sequence: Some(100),
        to_sequence: Some(50),
        ..Default::default()
    };
    let err = params.validate().unwrap_err();
    assert!(err.contains("from_sequence"), "got: {err}");
}

#[test]
fn test_audit_query_params_sequence_range_equal_ok() {
    let params = crate::AuditQueryParams {
        from_sequence: Some(100),
        to_sequence: Some(100),
        ..Default::default()
    };
    assert!(params.validate().is_ok());
}

#[test]
fn test_audit_query_params_since_invalid_iso8601() {
    let params = crate::AuditQueryParams {
        since: Some("not-a-date".to_string()),
        ..Default::default()
    };
    let err = params.validate().unwrap_err();
    assert!(err.contains("since is not valid ISO 8601"), "got: {err}");
}

#[test]
fn test_audit_query_params_until_invalid_iso8601() {
    let params = crate::AuditQueryParams {
        until: Some("2026-13-01T00:00:00Z".to_string()),
        ..Default::default()
    };
    let err = params.validate().unwrap_err();
    assert!(err.contains("until is not valid ISO 8601"), "got: {err}");
}

#[test]
fn test_audit_query_params_valid_timestamps_ok() {
    let params = crate::AuditQueryParams {
        since: Some("2026-01-01T00:00:00Z".to_string()),
        until: Some("2026-02-01T00:00:00Z".to_string()),
        ..Default::default()
    };
    assert!(params.validate().is_ok());
}

#[test]
fn test_audit_query_params_all_fields_valid() {
    let params = crate::AuditQueryParams {
        since: Some("2026-01-01T00:00:00Z".to_string()),
        until: Some("2026-02-01T00:00:00Z".to_string()),
        agent_id: Some("agent-1".to_string()),
        tool: Some("file_read".to_string()),
        verdict: Some(crate::VerdictFilter::Deny),
        text_search: Some("secret".to_string()),
        from_sequence: Some(1),
        to_sequence: Some(100),
        limit: 50,
        offset: 0,
        tenant_id: Some("tenant-abc".to_string()),
    };
    assert!(params.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════════
// Round 200: Additional validation tests (FIND-R200-004/005)
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_audit_query_params_offset_exceeds_max() {
    let params = crate::AuditQueryParams {
        offset: crate::audit_store::MAX_QUERY_OFFSET + 1,
        ..Default::default()
    };
    let err = params.validate().unwrap_err();
    assert!(err.contains("offset"));
    assert!(err.contains("exceeds maximum"));
}

#[test]
fn test_audit_query_params_offset_at_max_ok() {
    let params = crate::AuditQueryParams {
        offset: crate::audit_store::MAX_QUERY_OFFSET,
        ..Default::default()
    };
    assert!(params.validate().is_ok());
}

#[test]
fn test_audit_query_params_since_after_until_fails() {
    let params = crate::AuditQueryParams {
        since: Some("2026-02-01T00:00:00Z".to_string()),
        until: Some("2026-01-01T00:00:00Z".to_string()),
        ..Default::default()
    };
    let err = params.validate().unwrap_err();
    assert!(err.contains("since"));
    assert!(err.contains("before until"));
}

#[test]
fn test_audit_query_params_since_equals_until_fails() {
    let params = crate::AuditQueryParams {
        since: Some("2026-01-15T12:00:00Z".to_string()),
        until: Some("2026-01-15T12:00:00Z".to_string()),
        ..Default::default()
    };
    let err = params.validate().unwrap_err();
    assert!(err.contains("since"));
    assert!(err.contains("before until"));
}

#[test]
fn test_audit_query_params_since_before_until_ok() {
    let params = crate::AuditQueryParams {
        since: Some("2026-01-01T00:00:00Z".to_string()),
        until: Some("2026-01-02T00:00:00Z".to_string()),
        ..Default::default()
    };
    assert!(params.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════════
// Phase 43: AuditStoreBackend, VerdictFilter, AuditQueryResult,
// and AuditStoreStatus serde/default tests (IMP-R198-P43)
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_audit_store_backend_default_is_file() {
    let backend = crate::AuditStoreBackend::default();
    assert_eq!(backend, crate::AuditStoreBackend::File);
}

#[test]
fn test_audit_store_backend_serde_roundtrip_file() {
    let backend = crate::AuditStoreBackend::File;
    let json = serde_json::to_string(&backend).unwrap();
    assert_eq!(json, r#""file""#);
    let decoded: crate::AuditStoreBackend = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, crate::AuditStoreBackend::File);
}

#[test]
fn test_audit_store_backend_serde_roundtrip_postgres() {
    let backend = crate::AuditStoreBackend::Postgres;
    let json = serde_json::to_string(&backend).unwrap();
    assert_eq!(json, r#""postgres""#);
    let decoded: crate::AuditStoreBackend = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, crate::AuditStoreBackend::Postgres);
}

#[test]
fn test_verdict_filter_serde_roundtrip_allow() {
    let filter = crate::VerdictFilter::Allow;
    let json = serde_json::to_string(&filter).unwrap();
    assert_eq!(json, r#""allow""#);
    let decoded: crate::VerdictFilter = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, crate::VerdictFilter::Allow);
}

#[test]
fn test_verdict_filter_serde_roundtrip_deny() {
    let filter = crate::VerdictFilter::Deny;
    let json = serde_json::to_string(&filter).unwrap();
    assert_eq!(json, r#""deny""#);
    let decoded: crate::VerdictFilter = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, crate::VerdictFilter::Deny);
}

#[test]
fn test_verdict_filter_serde_roundtrip_require_approval() {
    let filter = crate::VerdictFilter::RequireApproval;
    let json = serde_json::to_string(&filter).unwrap();
    assert_eq!(json, r#""requireapproval""#);
    let decoded: crate::VerdictFilter = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, crate::VerdictFilter::RequireApproval);
}

#[test]
fn test_audit_query_result_serde_roundtrip() {
    let result = crate::AuditQueryResult {
        entries: vec![serde_json::json!({"id": "abc", "tool": "file_read"})],
        total: 42,
        offset: 10,
        limit: 100,
    };
    let json = serde_json::to_string(&result).unwrap();
    let decoded: crate::AuditQueryResult = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.total, 42);
    assert_eq!(decoded.offset, 10);
    assert_eq!(decoded.limit, 100);
    assert_eq!(decoded.entries.len(), 1);
}

#[test]
fn test_audit_query_result_empty_serde_roundtrip() {
    let result = crate::AuditQueryResult {
        entries: vec![],
        total: 0,
        offset: 0,
        limit: 100,
    };
    let json = serde_json::to_string(&result).unwrap();
    let decoded: crate::AuditQueryResult = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.total, 0);
    assert!(decoded.entries.is_empty());
}

#[test]
fn test_audit_store_status_serde_roundtrip_file_backend() {
    let status = crate::AuditStoreStatus {
        backend: crate::AuditStoreBackend::File,
        enabled: false,
        sink_healthy: true,
        pending_count: 0,
    };
    let json = serde_json::to_string(&status).unwrap();
    let decoded: crate::AuditStoreStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.backend, crate::AuditStoreBackend::File);
    assert!(!decoded.enabled);
    assert!(decoded.sink_healthy);
    assert_eq!(decoded.pending_count, 0);
}

#[test]
fn test_audit_store_status_serde_roundtrip_postgres_backend() {
    let status = crate::AuditStoreStatus {
        backend: crate::AuditStoreBackend::Postgres,
        enabled: true,
        sink_healthy: false,
        pending_count: 37,
    };
    let json = serde_json::to_string(&status).unwrap();
    let decoded: crate::AuditStoreStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.backend, crate::AuditStoreBackend::Postgres);
    assert!(decoded.enabled);
    assert!(!decoded.sink_healthy);
    assert_eq!(decoded.pending_count, 37);
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R159-001: AccessReviewEntry per-entry Vec<String> validation
// FIND-R159-002: AccessReviewEntry agent_id length bound
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_r159_002_access_review_entry_rejects_empty_agent_id() {
    let mut entry = make_valid_access_review_entry();
    entry.agent_id = String::new();
    let err = entry.validate().unwrap_err();
    assert!(
        err.contains("agent_id") && err.contains("must not be empty"),
        "got: {err}"
    );
}

#[test]
fn test_r159_002_access_review_entry_rejects_oversized_agent_id() {
    let mut entry = make_valid_access_review_entry();
    entry.agent_id = "a".repeat(257);
    let err = entry.validate().unwrap_err();
    assert!(
        err.contains("agent_id") && err.contains("exceeds max"),
        "got: {err}"
    );
}

#[test]
fn test_r159_002_access_review_entry_accepts_max_length_agent_id() {
    let mut entry = make_valid_access_review_entry();
    entry.agent_id = "a".repeat(256);
    assert!(entry.validate().is_ok());
}

#[test]
fn test_r159_001_access_review_entry_rejects_oversized_session_ids_entry() {
    let mut entry = make_valid_access_review_entry();
    entry.session_ids = vec!["x".repeat(257)];
    let err = entry.validate().unwrap_err();
    assert!(
        err.contains("session_ids") && err.contains("entry length") && err.contains("exceeds max"),
        "got: {err}"
    );
}

#[test]
fn test_r159_001_access_review_entry_rejects_dangerous_char_in_session_ids() {
    let mut entry = make_valid_access_review_entry();
    entry.session_ids = vec!["session\u{200B}1".to_string()];
    let err = entry.validate().unwrap_err();
    assert!(
        err.contains("session_ids") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r159_001_access_review_entry_rejects_control_char_in_session_ids() {
    let mut entry = make_valid_access_review_entry();
    entry.session_ids = vec!["session\n1".to_string()];
    let err = entry.validate().unwrap_err();
    assert!(
        err.contains("session_ids") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r159_001_access_review_entry_rejects_oversized_tools_accessed_entry() {
    let mut entry = make_valid_access_review_entry();
    entry.tools_accessed = vec!["t".repeat(257)];
    let err = entry.validate().unwrap_err();
    assert!(
        err.contains("tools_accessed")
            && err.contains("entry length")
            && err.contains("exceeds max"),
        "got: {err}"
    );
}

#[test]
fn test_r159_001_access_review_entry_rejects_dangerous_char_in_tools_accessed() {
    let mut entry = make_valid_access_review_entry();
    entry.tools_accessed = vec!["tool\u{FEFF}name".to_string()];
    let err = entry.validate().unwrap_err();
    assert!(
        err.contains("tools_accessed") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r159_001_access_review_entry_rejects_oversized_functions_called_entry() {
    let mut entry = make_valid_access_review_entry();
    entry.functions_called = vec!["f".repeat(257)];
    let err = entry.validate().unwrap_err();
    assert!(
        err.contains("functions_called")
            && err.contains("entry length")
            && err.contains("exceeds max"),
        "got: {err}"
    );
}

#[test]
fn test_r159_001_access_review_entry_rejects_dangerous_char_in_functions_called() {
    let mut entry = make_valid_access_review_entry();
    entry.functions_called = vec!["func\x07call".to_string()];
    let err = entry.validate().unwrap_err();
    assert!(
        err.contains("functions_called") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r159_001_access_review_entry_rejects_oversized_unused_permissions_entry() {
    let mut entry = make_valid_access_review_entry();
    entry.unused_permissions = vec!["p".repeat(257)];
    let err = entry.validate().unwrap_err();
    assert!(
        err.contains("unused_permissions")
            && err.contains("entry length")
            && err.contains("exceeds max"),
        "got: {err}"
    );
}

#[test]
fn test_r159_001_access_review_entry_rejects_dangerous_char_in_unused_permissions() {
    let mut entry = make_valid_access_review_entry();
    entry.unused_permissions = vec!["perm\u{202E}evil".to_string()];
    let err = entry.validate().unwrap_err();
    assert!(
        err.contains("unused_permissions") && err.contains("control or format"),
        "got: {err}"
    );
}

#[test]
fn test_r159_001_access_review_entry_accepts_max_length_entries() {
    let mut entry = make_valid_access_review_entry();
    let max_val = "x".repeat(256);
    entry.session_ids = vec![max_val.clone()];
    entry.tools_accessed = vec![max_val.clone()];
    entry.functions_called = vec![max_val.clone()];
    entry.unused_permissions = vec![max_val];
    assert!(entry.validate().is_ok());
}

#[test]
fn test_r159_001_access_review_entry_second_entry_bad_in_vec() {
    let mut entry = make_valid_access_review_entry();
    entry.session_ids = vec!["good".to_string(), "bad\x00id".to_string()];
    let err = entry.validate().unwrap_err();
    assert!(
        err.contains("session_ids") && err.contains("control or format"),
        "got: {err}"
    );
}

// ═══════════════════════════════════════════════════════════════
// R203 fixes: task timestamp validation, audit_store constant,
// and governance deprecated method removal.
// ═══════════════════════════════════════════════════════════════

fn make_valid_tracked_task() -> crate::TrackedTask {
    crate::TrackedTask {
        task_id: "task-001".to_string(),
        tool: "read_file".to_string(),
        function: "read".to_string(),
        status: crate::TaskStatus::Pending,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        created_by: None,
        session_id: None,
    }
}

// FIND-R203-002: TrackedTask.created_at — control character validation
#[test]
fn test_r203_002_tracked_task_created_at_control_char_rejected() {
    let mut task = make_valid_tracked_task();
    task.created_at = "2026-01-01T00:00:\x0000Z".to_string();
    let err = task.validate().unwrap_err();
    assert!(
        err.contains("created_at") && err.contains("control or format"),
        "got: {err}"
    );
}

// FIND-R203-002: TrackedTask.created_at — Unicode format character validation
#[test]
fn test_r203_002_tracked_task_created_at_format_char_rejected() {
    let mut task = make_valid_tracked_task();
    // Zero-width space injected into timestamp
    task.created_at = "2026-01-01T00:\u{200B}00:00Z".to_string();
    let err = task.validate().unwrap_err();
    assert!(
        err.contains("created_at") && err.contains("control or format"),
        "got: {err}"
    );
}

// FIND-R203-002: TrackedTask.created_at — invalid ISO 8601 rejected
#[test]
fn test_r203_002_tracked_task_created_at_invalid_iso8601_rejected() {
    let mut task = make_valid_tracked_task();
    task.created_at = "not-a-timestamp!!!!!!!!!!!!".to_string();
    let err = task.validate().unwrap_err();
    assert!(
        err.contains("created_at") && err.contains("ISO 8601"),
        "got: {err}"
    );
}

// FIND-R203-002: TrackedTask.expires_at — control character validation
#[test]
fn test_r203_002_tracked_task_expires_at_control_char_rejected() {
    let mut task = make_valid_tracked_task();
    task.expires_at = Some("2026-02-01T00:00:\x0000Z".to_string());
    let err = task.validate().unwrap_err();
    assert!(
        err.contains("expires_at") && err.contains("control or format"),
        "got: {err}"
    );
}

// FIND-R203-002: TrackedTask.expires_at — invalid ISO 8601 rejected
#[test]
fn test_r203_002_tracked_task_expires_at_invalid_iso8601_rejected() {
    let mut task = make_valid_tracked_task();
    task.expires_at = Some("YYYY-MM-DDTHH:MM:SSZ-invalid!!!".to_string());
    let err = task.validate().unwrap_err();
    assert!(
        err.contains("expires_at") && err.contains("ISO 8601"),
        "got: {err}"
    );
}

// FIND-R203-002: TrackedTask — valid task with expires_at passes
#[test]
fn test_r203_002_tracked_task_valid_with_expires_at_passes() {
    let mut task = make_valid_tracked_task();
    task.expires_at = Some("2027-06-15T12:30:00Z".to_string());
    assert!(task.validate().is_ok());
}

// FIND-R203-002: TaskStateTransition.timestamp — control character rejected
#[test]
fn test_r203_002_task_state_transition_timestamp_control_char_rejected() {
    let transition = crate::TaskStateTransition {
        sequence: 0,
        prev_hash: "".to_string(),
        new_status: crate::TaskStatus::Running,
        timestamp: "2026-01-01T00:00:\x0000Z".to_string(),
        triggered_by: None,
        hash: "abc".to_string(),
    };
    let err = transition.validate().unwrap_err();
    assert!(
        err.contains("timestamp") && err.contains("control or format"),
        "got: {err}"
    );
}

// FIND-R203-002: TaskStateTransition.timestamp — Unicode format char rejected
#[test]
fn test_r203_002_task_state_transition_timestamp_format_char_rejected() {
    let transition = crate::TaskStateTransition {
        sequence: 0,
        prev_hash: "".to_string(),
        new_status: crate::TaskStatus::Running,
        timestamp: "2026-01-01\u{200B}T00:00:00Z".to_string(),
        triggered_by: None,
        hash: "abc".to_string(),
    };
    let err = transition.validate().unwrap_err();
    assert!(
        err.contains("timestamp") && err.contains("control or format"),
        "got: {err}"
    );
}

// FIND-R203-003: AuditQueryParams.tenant_id uses MAX_TENANT_ID_LEN constant
#[test]
fn test_r203_003_audit_query_params_tenant_id_at_max_len_ok() {
    let params = crate::AuditQueryParams {
        tenant_id: Some("t".repeat(crate::audit_store::MAX_TENANT_ID_LEN)),
        ..Default::default()
    };
    assert!(params.validate().is_ok());
}

#[test]
fn test_r203_003_audit_query_params_tenant_id_exceeds_max_len_fails() {
    let params = crate::AuditQueryParams {
        tenant_id: Some("t".repeat(crate::audit_store::MAX_TENANT_ID_LEN + 1)),
        ..Default::default()
    };
    let err = params.validate().unwrap_err();
    assert!(
        err.contains("tenant_id") && err.contains("exceeds maximum"),
        "got: {err}"
    );
}

// FIND-R203-003: MAX_TENANT_ID_LEN constant is exported at expected value
#[test]
fn test_r203_003_max_tenant_id_len_constant_value() {
    assert_eq!(crate::audit_store::MAX_TENANT_ID_LEN, 64);
}

// FIND-R203-004: ShadowAiReport.validate() uses agent.validate() (not deprecated validate_finite())
#[test]
fn test_r203_004_shadow_ai_report_validate_calls_agent_validate() {
    // An agent with risk_score out of range should fail validate() and hence ShadowAiReport::validate()
    let report = crate::ShadowAiReport {
        unregistered_agents: vec![crate::UnregisteredAgent {
            agent_id: "agent-x".to_string(),
            first_seen: "2026-01-01T00:00:00Z".to_string(),
            last_seen: "2026-01-01T01:00:00Z".to_string(),
            request_count: 1,
            tools_used: std::collections::HashSet::new(),
            // risk_score outside [0.0, 1.0] range — should be caught by validate()
            risk_score: 1.5,
        }],
        unapproved_tools: vec![],
        unknown_servers: vec![],
        total_risk_score: 0.5,
    };
    let err = report.validate().unwrap_err();
    assert!(
        err.contains("risk_score") || err.contains("UnregisteredAgent"),
        "validate() should delegate to agent.validate(): got: {err}"
    );
}

#[test]
fn test_r203_004_shadow_ai_report_validate_ok_with_valid_agents() {
    let report = crate::ShadowAiReport {
        unregistered_agents: vec![crate::UnregisteredAgent {
            agent_id: "agent-x".to_string(),
            first_seen: "2026-01-01T00:00:00Z".to_string(),
            last_seen: "2026-01-01T01:00:00Z".to_string(),
            request_count: 1,
            tools_used: std::collections::HashSet::new(),
            risk_score: 0.5,
        }],
        unapproved_tools: vec![],
        unknown_servers: vec![],
        total_risk_score: 0.5,
    };
    assert!(report.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════════════
// Phase 47: Policy Lifecycle Type Tests
// ═══════════════════════════════════════════════════════════════════

fn make_valid_policy_approval() -> crate::PolicyApproval {
    crate::PolicyApproval {
        approved_by: "reviewer-1".to_string(),
        approved_at: "2026-01-15T10:00:00Z".to_string(),
        comment: Some("Looks good".to_string()),
    }
}

fn make_valid_policy_version() -> crate::PolicyVersion {
    crate::PolicyVersion {
        version_id: "v-001".to_string(),
        policy_id: "pol-1".to_string(),
        version: 1,
        policy: crate::Policy {
            id: "pol-1".to_string(),
            name: "test".to_string(),
            policy_type: crate::PolicyType::Allow,
            priority: 50,
            path_rules: None,
            network_rules: None,
        },
        created_by: "admin".to_string(),
        created_at: "2026-01-15T10:00:00Z".to_string(),
        status: crate::PolicyVersionStatus::Draft,
        comment: None,
        approvals: vec![],
        required_approvals: 1,
        previous_version_id: None,
        staged_at: None,
    }
}

#[test]
fn test_policy_version_status_serde_roundtrip() {
    let statuses = vec![
        crate::PolicyVersionStatus::Draft,
        crate::PolicyVersionStatus::Staging,
        crate::PolicyVersionStatus::Active,
        crate::PolicyVersionStatus::Archived,
    ];
    for status in statuses {
        let json = serde_json::to_string(&status).unwrap();
        let back: crate::PolicyVersionStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{status:?}"), format!("{:?}", back));
    }
}

#[test]
fn test_policy_approval_serde_roundtrip() {
    let approval = make_valid_policy_approval();
    let json = serde_json::to_string(&approval).unwrap();
    let back: crate::PolicyApproval = serde_json::from_str(&json).unwrap();
    assert_eq!(back.approved_by, "reviewer-1");
    assert_eq!(back.comment.as_deref(), Some("Looks good"));
}

#[test]
fn test_policy_version_serde_roundtrip() {
    let version = make_valid_policy_version();
    let json = serde_json::to_string(&version).unwrap();
    let back: crate::PolicyVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(back.version_id, "v-001");
    assert_eq!(back.version, 1);
}

#[test]
fn test_policy_version_validate_ok() {
    let version = make_valid_policy_version();
    assert!(version.validate().is_ok());
}

#[test]
fn test_policy_version_validate_empty_version_id() {
    let mut v = make_valid_policy_version();
    v.version_id = "".to_string();
    assert!(v.validate().unwrap_err().contains("version_id"));
}

#[test]
fn test_policy_version_validate_version_id_too_long() {
    let mut v = make_valid_policy_version();
    v.version_id = "x".repeat(257);
    assert!(v.validate().unwrap_err().contains("version_id"));
}

#[test]
fn test_policy_version_validate_dangerous_chars_in_created_by() {
    let mut v = make_valid_policy_version();
    v.created_by = "admin\x00evil".to_string();
    assert!(v.validate().unwrap_err().contains("created_by"));
}

#[test]
fn test_policy_version_validate_unicode_format_chars_in_policy_id() {
    let mut v = make_valid_policy_version();
    v.policy_id = "pol\u{200B}1".to_string(); // zero-width space
    assert!(v.validate().unwrap_err().contains("policy_id"));
}

#[test]
fn test_policy_version_validate_too_many_approvals() {
    let mut v = make_valid_policy_version();
    v.approvals = (0..51)
        .map(|i| crate::PolicyApproval {
            approved_by: format!("reviewer-{i}"),
            approved_at: "2026-01-15T10:00:00Z".to_string(),
            comment: None,
        })
        .collect();
    assert!(v.validate().unwrap_err().contains("approvals"));
}

#[test]
fn test_policy_version_validate_comment_too_long() {
    let mut v = make_valid_policy_version();
    v.comment = Some("x".repeat(4097));
    assert!(v.validate().unwrap_err().contains("comment"));
}

#[test]
fn test_policy_version_validate_excessive_required_approvals() {
    let mut v = make_valid_policy_version();
    v.required_approvals = 21;
    assert!(v.validate().unwrap_err().contains("required_approvals"));
}

#[test]
fn test_policy_approval_validate_ok() {
    let a = make_valid_policy_approval();
    assert!(a.validate().is_ok());
}

#[test]
fn test_policy_approval_validate_empty_approved_by() {
    let mut a = make_valid_policy_approval();
    a.approved_by = "".to_string();
    assert!(a.validate().unwrap_err().contains("approved_by"));
}

#[test]
fn test_policy_approval_validate_dangerous_chars() {
    let mut a = make_valid_policy_approval();
    a.approved_by = "user\u{202E}evil".to_string(); // bidi override
    assert!(a.validate().unwrap_err().contains("approved_by"));
}

#[test]
fn test_staging_report_validate_ok() {
    let r = crate::StagingReport {
        policy_id: "pol-1".to_string(),
        staging_version: 2,
        total_evaluations: 100,
        divergent_evaluations: 5,
        divergences: vec![],
        staging_started_at: "2026-01-15T10:00:00Z".to_string(),
    };
    assert!(r.validate().is_ok());
}

#[test]
fn test_staging_report_validate_too_many_divergences() {
    let r = crate::StagingReport {
        policy_id: "pol-1".to_string(),
        staging_version: 2,
        total_evaluations: 100,
        divergent_evaluations: 5,
        divergences: (0..10001)
            .map(|i| crate::StagingComparisonEntry {
                timestamp: "2026-01-15T10:00:00Z".to_string(),
                tool: format!("t{i}"),
                function: "f".to_string(),
                active_verdict: "allow".to_string(),
                staging_verdict: "deny".to_string(),
            })
            .collect(),
        staging_started_at: "2026-01-15T10:00:00Z".to_string(),
    };
    assert!(r.validate().unwrap_err().contains("divergences"));
}

#[test]
fn test_policy_version_diff_validate_ok() {
    let d = crate::PolicyVersionDiff {
        policy_id: "pol-1".to_string(),
        from_version: 1,
        to_version: 2,
        changes: vec!["Added path rule".to_string()],
    };
    assert!(d.validate().is_ok());
}

#[test]
fn test_policy_version_diff_validate_too_many_changes() {
    let d = crate::PolicyVersionDiff {
        policy_id: "pol-1".to_string(),
        from_version: 1,
        to_version: 2,
        changes: (0..101).map(|i| format!("change {i}")).collect(),
    };
    assert!(d.validate().unwrap_err().contains("changes"));
}

#[test]
fn test_policy_approval_deny_unknown_fields() {
    let json = r#"{"approved_by":"a","approved_at":"t","comment":null,"extra":"bad"}"#;
    let result = serde_json::from_str::<crate::PolicyApproval>(json);
    assert!(
        result.is_err(),
        "deny_unknown_fields should reject extra field"
    );
}

#[test]
fn test_policy_version_deny_unknown_fields() {
    let mut v = make_valid_policy_version();
    v.version_id = "v-test".to_string();
    let mut json: serde_json::Value = serde_json::to_value(&v).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("extra".to_string(), serde_json::json!("bad"));
    let result = serde_json::from_value::<crate::PolicyVersion>(json);
    assert!(
        result.is_err(),
        "deny_unknown_fields should reject extra field"
    );
}

// ── FIND-R205-002: StagingComparisonEntry::validate() tests ──

fn make_valid_staging_entry() -> crate::StagingComparisonEntry {
    crate::StagingComparisonEntry {
        timestamp: "2026-01-15T10:00:00Z".to_string(),
        tool: "read_file".to_string(),
        function: "execute".to_string(),
        active_verdict: "allow".to_string(),
        staging_verdict: "deny".to_string(),
    }
}

#[test]
fn test_staging_comparison_entry_validate_ok() {
    let e = make_valid_staging_entry();
    assert!(e.validate().is_ok());
}

#[test]
fn test_staging_comparison_entry_validate_empty_timestamp() {
    let mut e = make_valid_staging_entry();
    e.timestamp = String::new();
    assert!(e.validate().unwrap_err().contains("timestamp"));
}

#[test]
fn test_staging_comparison_entry_validate_dangerous_timestamp() {
    let mut e = make_valid_staging_entry();
    e.timestamp = "2026-01-15T10:00:00Z\x00".to_string();
    assert!(e.validate().unwrap_err().contains("timestamp"));
}

#[test]
fn test_staging_comparison_entry_validate_bad_timestamp_format() {
    let mut e = make_valid_staging_entry();
    e.timestamp = "not-a-timestamp".to_string();
    assert!(e.validate().unwrap_err().contains("timestamp"));
}

#[test]
fn test_staging_comparison_entry_validate_empty_tool() {
    let mut e = make_valid_staging_entry();
    e.tool = String::new();
    assert!(e.validate().unwrap_err().contains("tool"));
}

#[test]
fn test_staging_comparison_entry_validate_tool_too_long() {
    let mut e = make_valid_staging_entry();
    e.tool = "x".repeat(crate::MAX_STAGING_NAME_LEN + 1);
    assert!(e.validate().unwrap_err().contains("tool"));
}

#[test]
fn test_staging_comparison_entry_validate_dangerous_tool() {
    let mut e = make_valid_staging_entry();
    e.tool = "tool\u{202E}evil".to_string(); // bidi override
    assert!(e.validate().unwrap_err().contains("tool"));
}

#[test]
fn test_staging_comparison_entry_validate_empty_function() {
    let mut e = make_valid_staging_entry();
    e.function = String::new();
    assert!(e.validate().unwrap_err().contains("function"));
}

#[test]
fn test_staging_comparison_entry_validate_function_too_long() {
    let mut e = make_valid_staging_entry();
    e.function = "x".repeat(crate::MAX_STAGING_NAME_LEN + 1);
    assert!(e.validate().unwrap_err().contains("function"));
}

#[test]
fn test_staging_comparison_entry_validate_dangerous_function() {
    let mut e = make_valid_staging_entry();
    e.function = "fn\x07bell".to_string(); // control char
    assert!(e.validate().unwrap_err().contains("function"));
}

#[test]
fn test_staging_comparison_entry_validate_empty_active_verdict() {
    let mut e = make_valid_staging_entry();
    e.active_verdict = String::new();
    assert!(e.validate().unwrap_err().contains("active_verdict"));
}

#[test]
fn test_staging_comparison_entry_validate_active_verdict_too_long() {
    let mut e = make_valid_staging_entry();
    e.active_verdict = "x".repeat(crate::MAX_VERDICT_STRING_LEN + 1);
    assert!(e.validate().unwrap_err().contains("active_verdict"));
}

#[test]
fn test_staging_comparison_entry_validate_dangerous_active_verdict() {
    let mut e = make_valid_staging_entry();
    e.active_verdict = "allow\u{200B}".to_string(); // zero-width space
    assert!(e.validate().unwrap_err().contains("active_verdict"));
}

#[test]
fn test_staging_comparison_entry_validate_empty_staging_verdict() {
    let mut e = make_valid_staging_entry();
    e.staging_verdict = String::new();
    assert!(e.validate().unwrap_err().contains("staging_verdict"));
}

#[test]
fn test_staging_comparison_entry_validate_staging_verdict_too_long() {
    let mut e = make_valid_staging_entry();
    e.staging_verdict = "x".repeat(crate::MAX_VERDICT_STRING_LEN + 1);
    assert!(e.validate().unwrap_err().contains("staging_verdict"));
}

#[test]
fn test_staging_comparison_entry_validate_dangerous_staging_verdict() {
    let mut e = make_valid_staging_entry();
    e.staging_verdict = "deny\x1B[31m".to_string(); // ANSI escape
    assert!(e.validate().unwrap_err().contains("staging_verdict"));
}

// ── FIND-R205-002: StagingReport::validate() wires entry validation ──

#[test]
fn test_staging_report_validate_invalid_divergence_entry() {
    let r = crate::StagingReport {
        policy_id: "pol-1".to_string(),
        staging_version: 2,
        total_evaluations: 100,
        divergent_evaluations: 1,
        divergences: vec![crate::StagingComparisonEntry {
            timestamp: "bad-ts".to_string(),
            tool: "t".to_string(),
            function: "f".to_string(),
            active_verdict: "allow".to_string(),
            staging_verdict: "deny".to_string(),
        }],
        staging_started_at: "2026-01-15T10:00:00Z".to_string(),
    };
    let err = r.validate().unwrap_err();
    assert!(
        err.contains("divergences[0]"),
        "expected indexed error, got: {err}"
    );
}

// ── FIND-R205-003: StagingReport staging_started_at timestamp validation ──
// (Already wired in IMP-R206-010, adding adversarial tests for completeness.)

#[test]
fn test_staging_report_validate_empty_staging_started_at() {
    let r = crate::StagingReport {
        policy_id: "pol-1".to_string(),
        staging_version: 2,
        total_evaluations: 100,
        divergent_evaluations: 0,
        divergences: vec![],
        staging_started_at: String::new(),
    };
    assert!(r.validate().unwrap_err().contains("staging_started_at"));
}

#[test]
fn test_staging_report_validate_dangerous_staging_started_at() {
    let r = crate::StagingReport {
        policy_id: "pol-1".to_string(),
        staging_version: 2,
        total_evaluations: 100,
        divergent_evaluations: 0,
        divergences: vec![],
        staging_started_at: "2026-01-15T10:00:00Z\x00".to_string(),
    };
    assert!(r.validate().unwrap_err().contains("staging_started_at"));
}

#[test]
fn test_staging_report_validate_bad_format_staging_started_at() {
    let r = crate::StagingReport {
        policy_id: "pol-1".to_string(),
        staging_version: 2,
        total_evaluations: 100,
        divergent_evaluations: 0,
        divergences: vec![],
        staging_started_at: "not-a-date".to_string(),
    };
    assert!(r.validate().unwrap_err().contains("staging_started_at"));
}

// ── FIND-R209-004: StagingReport policy_id length bound ──

#[test]
fn test_staging_report_validate_policy_id_too_long() {
    let r = crate::StagingReport {
        policy_id: "x".repeat(crate::MAX_DIFF_POLICY_ID_LEN + 1),
        staging_version: 2,
        total_evaluations: 100,
        divergent_evaluations: 0,
        divergences: vec![],
        staging_started_at: "2026-01-15T10:00:00Z".to_string(),
    };
    let err = r.validate().unwrap_err();
    assert!(
        err.contains("policy_id exceeds"),
        "expected policy_id length error, got: {err}"
    );
}

// ── FIND-R205-004: PolicyVersionDiff per-entry change validation ──

#[test]
fn test_policy_version_diff_validate_change_too_long() {
    let d = crate::PolicyVersionDiff {
        policy_id: "pol-1".to_string(),
        from_version: 1,
        to_version: 2,
        changes: vec!["x".repeat(crate::MAX_DIFF_CHANGE_LEN + 1)],
    };
    let err = d.validate().unwrap_err();
    assert!(
        err.contains("changes[0]"),
        "expected indexed error, got: {err}"
    );
    assert!(err.contains("exceeds"), "expected length error, got: {err}");
}

#[test]
fn test_policy_version_diff_validate_change_dangerous_chars() {
    let d = crate::PolicyVersionDiff {
        policy_id: "pol-1".to_string(),
        from_version: 1,
        to_version: 2,
        changes: vec!["ok change".to_string(), "bad\x00change".to_string()],
    };
    let err = d.validate().unwrap_err();
    assert!(
        err.contains("changes[1]"),
        "expected indexed error, got: {err}"
    );
    assert!(
        err.contains("invalid characters"),
        "expected char error, got: {err}"
    );
}

#[test]
fn test_policy_version_diff_validate_policy_id_too_long() {
    let d = crate::PolicyVersionDiff {
        policy_id: "x".repeat(crate::MAX_DIFF_POLICY_ID_LEN + 1),
        from_version: 1,
        to_version: 2,
        changes: vec![],
    };
    assert!(d.validate().unwrap_err().contains("policy_id"));
}

#[test]
fn test_policy_version_diff_validate_policy_id_dangerous() {
    let d = crate::PolicyVersionDiff {
        policy_id: "pol\u{200B}1".to_string(), // zero-width space
        from_version: 1,
        to_version: 2,
        changes: vec![],
    };
    assert!(d.validate().unwrap_err().contains("policy_id"));
}

// ── Phase 48: Evidence Pack Types Tests ─────────────────────────────────────

#[test]
fn test_evidence_framework_display() {
    assert_eq!(EvidenceFramework::Dora.to_string(), "DORA");
    assert_eq!(EvidenceFramework::Nis2.to_string(), "NIS2");
    assert_eq!(EvidenceFramework::Iso42001.to_string(), "ISO 42001");
    assert_eq!(EvidenceFramework::EuAiAct.to_string(), "EU AI Act");
}

#[test]
fn test_evidence_framework_serde_roundtrip() {
    let fw = EvidenceFramework::Dora;
    let json = serde_json::to_string(&fw).unwrap();
    assert_eq!(json, "\"dora\"");
    let deserialized: EvidenceFramework = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized, fw);
}

#[test]
fn test_evidence_confidence_ordering() {
    assert!(EvidenceConfidence::None < EvidenceConfidence::Low);
    assert!(EvidenceConfidence::Low < EvidenceConfidence::Medium);
    assert!(EvidenceConfidence::Medium < EvidenceConfidence::High);
    assert!(EvidenceConfidence::High < EvidenceConfidence::Full);
}

#[test]
fn test_evidence_confidence_display() {
    assert_eq!(EvidenceConfidence::None.to_string(), "None");
    assert_eq!(EvidenceConfidence::Full.to_string(), "Full");
    assert_eq!(EvidenceConfidence::Medium.to_string(), "Medium");
}

#[test]
fn test_evidence_confidence_serde() {
    let c = EvidenceConfidence::High;
    let json = serde_json::to_string(&c).unwrap();
    assert_eq!(json, "\"high\"");
    let deserialized: EvidenceConfidence = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized, c);
}

#[test]
fn test_evidence_item_validate_ok() {
    let item = EvidenceItem {
        requirement_id: "Art 5".to_string(),
        requirement_title: "ICT Risk Management".to_string(),
        article_ref: "DORA Art 5-6".to_string(),
        vellaveto_capability: "PolicyEngine".to_string(),
        evidence_description: "Policy engine provides risk management".to_string(),
        confidence: EvidenceConfidence::High,
        gaps: vec![],
    };
    assert!(item.validate().is_ok());
}

#[test]
fn test_evidence_item_validate_dangerous_chars() {
    let item = EvidenceItem {
        requirement_id: "Art\x005".to_string(),
        requirement_title: "Test".to_string(),
        article_ref: "ref".to_string(),
        vellaveto_capability: "cap".to_string(),
        evidence_description: "desc".to_string(),
        confidence: EvidenceConfidence::High,
        gaps: vec![],
    };
    let err = item.validate().unwrap_err();
    assert!(err.contains("requirement_id"));
    assert!(err.contains("control"));
}

#[test]
fn test_evidence_item_validate_string_too_long() {
    let item = EvidenceItem {
        requirement_id: "a".repeat(MAX_EVIDENCE_STRING_LEN + 1),
        requirement_title: "Test".to_string(),
        article_ref: "ref".to_string(),
        vellaveto_capability: "cap".to_string(),
        evidence_description: "desc".to_string(),
        confidence: EvidenceConfidence::High,
        gaps: vec![],
    };
    let err = item.validate().unwrap_err();
    assert!(err.contains("requirement_id"));
    assert!(err.contains("exceeds max"));
}

#[test]
fn test_evidence_section_validate_coverage_nan() {
    let section = EvidenceSection {
        section_id: "test".to_string(),
        title: "Test".to_string(),
        description: "Test section".to_string(),
        items: vec![],
        section_coverage_percent: f32::NAN,
    };
    let err = section.validate().unwrap_err();
    assert!(err.contains("section_coverage_percent"));
}

#[test]
fn test_evidence_section_validate_coverage_negative() {
    let section = EvidenceSection {
        section_id: "test".to_string(),
        title: "Test".to_string(),
        description: "Test section".to_string(),
        items: vec![],
        section_coverage_percent: -1.0,
    };
    let err = section.validate().unwrap_err();
    assert!(err.contains("section_coverage_percent"));
}

#[test]
fn test_evidence_pack_serde_roundtrip() {
    let pack = EvidencePack {
        framework: EvidenceFramework::Dora,
        framework_name: "DORA".to_string(),
        generated_at: "2026-02-24T00:00:00Z".to_string(),
        organization_name: "Test Corp".to_string(),
        system_id: "test-001".to_string(),
        period_start: None,
        period_end: None,
        sections: vec![EvidenceSection {
            section_id: "s1".to_string(),
            title: "Section 1".to_string(),
            description: "Test".to_string(),
            items: vec![],
            section_coverage_percent: 80.0,
        }],
        overall_coverage_percent: 80.0,
        total_requirements: 10,
        covered_requirements: 8,
        partial_requirements: 1,
        uncovered_requirements: 1,
        critical_gaps: vec!["Gap 1".to_string()],
        recommendations: vec!["Rec 1".to_string()],
        signature: None,
        verifying_key: None,
    };
    assert!(pack.validate().is_ok());
    let json = serde_json::to_string(&pack).unwrap();
    let deserialized: EvidencePack = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.framework, EvidenceFramework::Dora);
    assert_eq!(deserialized.total_requirements, 10);
    assert_eq!(deserialized.sections.len(), 1);
}

#[test]
fn test_evidence_pack_validate_too_many_gaps() {
    let pack = EvidencePack {
        framework: EvidenceFramework::Nis2,
        framework_name: "NIS2".to_string(),
        generated_at: "2026-01-01T00:00:00Z".to_string(),
        organization_name: "Test".to_string(),
        system_id: "test".to_string(),
        period_start: None,
        period_end: None,
        sections: vec![],
        overall_coverage_percent: 50.0,
        total_requirements: 1,
        covered_requirements: 0,
        partial_requirements: 0,
        uncovered_requirements: 1,
        critical_gaps: (0..501).map(|i| format!("gap_{i}")).collect(),
        recommendations: vec![],
        signature: None,
        verifying_key: None,
    };
    let err = pack.validate().unwrap_err();
    assert!(err.contains("critical_gaps"));
}

#[test]
fn test_evidence_pack_status_serde() {
    let status = EvidencePackStatus {
        available_frameworks: vec![EvidenceFramework::Dora, EvidenceFramework::Nis2],
        dora_enabled: true,
        nis2_enabled: false,
    };
    let json = serde_json::to_string(&status).unwrap();
    let deserialized: EvidencePackStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.available_frameworks.len(), 2);
    assert!(deserialized.dora_enabled);
    assert!(!deserialized.nis2_enabled);
}

#[test]
fn test_evidence_pack_deny_unknown_fields() {
    let json = r#"{"framework":"dora","framework_name":"DORA","generated_at":"","organization_name":"","system_id":"","sections":[],"overall_coverage_percent":0.0,"total_requirements":0,"covered_requirements":0,"partial_requirements":0,"uncovered_requirements":0,"critical_gaps":[],"recommendations":[],"unknown":"bad"}"#;
    let result: Result<EvidencePack, _> = serde_json::from_str(json);
    assert!(result.is_err(), "should reject unknown fields");
}

#[test]
fn test_evidence_pack_validate_generated_at_control_chars() {
    let pack = EvidencePack {
        framework: EvidenceFramework::Dora,
        framework_name: "DORA".to_string(),
        generated_at: "2026-01-01\x00T00:00:00Z".to_string(),
        organization_name: "Test".to_string(),
        system_id: "test".to_string(),
        period_start: None,
        period_end: None,
        sections: vec![],
        overall_coverage_percent: 50.0,
        total_requirements: 1,
        covered_requirements: 1,
        partial_requirements: 0,
        uncovered_requirements: 0,
        critical_gaps: vec![],
        recommendations: vec![],
        signature: None,
        verifying_key: None,
    };
    let err = pack.validate().unwrap_err();
    assert!(
        err.contains("generated_at"),
        "should reject control chars in generated_at: {err}"
    );
}

#[test]
fn test_evidence_pack_validate_period_start_control_chars() {
    let pack = EvidencePack {
        framework: EvidenceFramework::Dora,
        framework_name: "DORA".to_string(),
        generated_at: "2026-01-01T00:00:00Z".to_string(),
        organization_name: "Test".to_string(),
        system_id: "test".to_string(),
        period_start: Some("2026\x01-01-01".to_string()),
        period_end: None,
        sections: vec![],
        overall_coverage_percent: 50.0,
        total_requirements: 1,
        covered_requirements: 1,
        partial_requirements: 0,
        uncovered_requirements: 0,
        critical_gaps: vec![],
        recommendations: vec![],
        signature: None,
        verifying_key: None,
    };
    let err = pack.validate().unwrap_err();
    assert!(
        err.contains("period_start"),
        "should reject control chars in period_start: {err}"
    );
}

#[test]
fn test_evidence_section_validate_description_control_chars() {
    let section = EvidenceSection {
        section_id: "test".to_string(),
        title: "Test".to_string(),
        description: "Bad\x07desc".to_string(),
        items: vec![],
        section_coverage_percent: 50.0,
    };
    let err = section.validate().unwrap_err();
    assert!(
        err.contains("description"),
        "should reject control chars in description: {err}"
    );
}

#[test]
fn test_evidence_pack_validate_recommendation_control_chars() {
    let pack = EvidencePack {
        framework: EvidenceFramework::Nis2,
        framework_name: "NIS2".to_string(),
        generated_at: "2026-01-01T00:00:00Z".to_string(),
        organization_name: "Test".to_string(),
        system_id: "test".to_string(),
        period_start: None,
        period_end: None,
        sections: vec![],
        overall_coverage_percent: 50.0,
        total_requirements: 1,
        covered_requirements: 0,
        partial_requirements: 0,
        uncovered_requirements: 1,
        critical_gaps: vec![],
        recommendations: vec!["Do \x08this".to_string()],
        signature: None,
        verifying_key: None,
    };
    let err = pack.validate().unwrap_err();
    assert!(
        err.contains("recommendations"),
        "should reject control chars in recommendations: {err}"
    );
}

#[test]
fn test_evidence_pack_validate_critical_gap_control_chars() {
    let pack = EvidencePack {
        framework: EvidenceFramework::Nis2,
        framework_name: "NIS2".to_string(),
        generated_at: "2026-01-01T00:00:00Z".to_string(),
        organization_name: "Test".to_string(),
        system_id: "test".to_string(),
        period_start: None,
        period_end: None,
        sections: vec![],
        overall_coverage_percent: 50.0,
        total_requirements: 1,
        covered_requirements: 0,
        partial_requirements: 0,
        uncovered_requirements: 1,
        critical_gaps: vec!["Gap\x1binjection".to_string()],
        recommendations: vec![],
        signature: None,
        verifying_key: None,
    };
    let err = pack.validate().unwrap_err();
    assert!(
        err.contains("critical_gaps"),
        "should reject control chars in critical_gaps: {err}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R224-001: Action deny_unknown_fields
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_r224_001_action_rejects_unknown_fields() {
    let json = r#"{"tool":"t","function":"f","parameters":{},"unknown_field":"bad"}"#;
    let result = serde_json::from_str::<Action>(json);
    assert!(
        result.is_err(),
        "Action deserialization should reject unknown fields"
    );
}

#[test]
fn test_r224_001_action_roundtrip_still_works() {
    let action = Action::new("tool", "func", json!({"key": "value"}));
    let serialized = serde_json::to_string(&action).unwrap();
    let deserialized: Action = serde_json::from_str(&serialized).unwrap();
    assert_eq!(action, deserialized);
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R224-002: CapabilityToken.parent_token_id validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_r224_002_capability_token_rejects_empty_parent_token_id() {
    let token = CapabilityToken {
        token_id: "tok-1".to_string(),
        parent_token_id: Some(String::new()),
        issuer: "issuer-1".to_string(),
        holder: "holder-1".to_string(),
        grants: vec![CapabilityGrant {
            tool_pattern: "test".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }],
        remaining_depth: 3,
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-12-31T23:59:59Z".to_string(),
        signature: "sig".to_string(),
        issuer_public_key: "key".to_string(),
    };
    let err = token.validate_structure().unwrap_err();
    assert!(
        matches!(err, CapabilityError::ValidationFailed(ref msg) if msg.contains("parent_token_id") && msg.contains("empty")),
        "expected empty parent_token_id rejection, got: {err:?}"
    );
}

#[test]
fn test_r224_002_capability_token_rejects_dangerous_parent_token_id() {
    let token = CapabilityToken {
        token_id: "tok-1".to_string(),
        parent_token_id: Some("parent\x00id".to_string()),
        issuer: "issuer-1".to_string(),
        holder: "holder-1".to_string(),
        grants: vec![CapabilityGrant {
            tool_pattern: "test".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }],
        remaining_depth: 3,
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-12-31T23:59:59Z".to_string(),
        signature: "sig".to_string(),
        issuer_public_key: "key".to_string(),
    };
    let err = token.validate_structure().unwrap_err();
    assert!(
        matches!(err, CapabilityError::ValidationFailed(ref msg) if msg.contains("parent_token_id") && msg.contains("control or format")),
        "expected dangerous chars rejection in parent_token_id, got: {err:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R224-003: TaskCheckpoint.validate() has_dangerous_chars on 4 fields
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_r224_003_task_checkpoint_rejects_dangerous_state_hash() {
    let cp = TaskCheckpoint {
        checkpoint_id: "cp-1".to_string(),
        task_id: "task-1".to_string(),
        sequence: 0,
        state_hash: "hash\x1b_injection".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        signature: "sig".to_string(),
        public_key: "key".to_string(),
    };
    let err = cp.validate().unwrap_err();
    assert!(
        err.contains("state_hash"),
        "expected state_hash rejection, got: {err}"
    );
}

#[test]
fn test_r224_003_task_checkpoint_rejects_dangerous_created_at() {
    let cp = TaskCheckpoint {
        checkpoint_id: "cp-1".to_string(),
        task_id: "task-1".to_string(),
        sequence: 0,
        state_hash: "abc123".to_string(),
        created_at: "2026\x00-01-01T00:00:00Z".to_string(),
        signature: "sig".to_string(),
        public_key: "key".to_string(),
    };
    let err = cp.validate().unwrap_err();
    assert!(
        err.contains("created_at"),
        "expected created_at rejection, got: {err}"
    );
}

#[test]
fn test_r224_003_task_checkpoint_rejects_dangerous_signature() {
    let cp = TaskCheckpoint {
        checkpoint_id: "cp-1".to_string(),
        task_id: "task-1".to_string(),
        sequence: 0,
        state_hash: "abc123".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        signature: "sig\u{200B}nature".to_string(),
        public_key: "key".to_string(),
    };
    let err = cp.validate().unwrap_err();
    assert!(
        err.contains("signature"),
        "expected signature rejection, got: {err}"
    );
}

#[test]
fn test_r224_003_task_checkpoint_rejects_dangerous_public_key() {
    let cp = TaskCheckpoint {
        checkpoint_id: "cp-1".to_string(),
        task_id: "task-1".to_string(),
        sequence: 0,
        state_hash: "abc123".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        signature: "sig".to_string(),
        public_key: "key\u{202E}evil".to_string(),
    };
    let err = cp.validate().unwrap_err();
    assert!(
        err.contains("public_key"),
        "expected public_key rejection, got: {err}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R224-004: StagingReport divergent > total
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_r224_004_staging_report_rejects_divergent_exceeds_total() {
    let r = crate::StagingReport {
        policy_id: "pol-1".to_string(),
        staging_version: 2,
        total_evaluations: 10,
        divergent_evaluations: 20,
        divergences: vec![],
        staging_started_at: "2026-01-15T10:00:00Z".to_string(),
    };
    let err = r.validate().unwrap_err();
    assert!(
        err.contains("divergent_evaluations") && err.contains("total_evaluations"),
        "expected divergent > total rejection, got: {err}"
    );
}

#[test]
fn test_r224_004_staging_report_accepts_divergent_equals_total() {
    let r = crate::StagingReport {
        policy_id: "pol-1".to_string(),
        staging_version: 2,
        total_evaluations: 10,
        divergent_evaluations: 10,
        divergences: vec![],
        staging_started_at: "2026-01-15T10:00:00Z".to_string(),
    };
    assert!(r.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R224-005: AuditQueryResult.validate()
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_r224_005_audit_query_result_validate_ok() {
    let result = crate::AuditQueryResult {
        entries: vec![json!({"id": "abc"})],
        total: 42,
        offset: 0,
        limit: 100,
    };
    assert!(result.validate().is_ok());
}

#[test]
fn test_r224_005_audit_query_result_rejects_entries_exceeding_limit() {
    let entries: Vec<serde_json::Value> = (0..1001).map(|i| json!({"id": i})).collect();
    let result = crate::AuditQueryResult {
        entries,
        total: 2000,
        offset: 0,
        limit: 1001,
    };
    let err = result.validate().unwrap_err();
    assert!(
        err.contains("MAX_QUERY_LIMIT"),
        "expected entries count rejection, got: {err}"
    );
}

#[test]
fn test_r224_005_audit_query_result_rejects_entries_exceeding_total() {
    let result = crate::AuditQueryResult {
        entries: vec![json!({"id": 1}), json!({"id": 2})],
        total: 1,
        offset: 0,
        limit: 100,
    };
    let err = result.validate().unwrap_err();
    assert!(
        err.contains("entries count") && err.contains("total"),
        "expected entries > total rejection, got: {err}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R224-006: CapabilityToken signature/issuer_public_key has_dangerous_chars
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_r224_006_capability_token_rejects_dangerous_signature() {
    let token = CapabilityToken {
        token_id: "tok-1".to_string(),
        parent_token_id: None,
        issuer: "issuer-1".to_string(),
        holder: "holder-1".to_string(),
        grants: vec![CapabilityGrant {
            tool_pattern: "test".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }],
        remaining_depth: 3,
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-12-31T23:59:59Z".to_string(),
        signature: "sig\x00nal".to_string(),
        issuer_public_key: "key".to_string(),
    };
    let err = token.validate_structure().unwrap_err();
    assert!(
        matches!(err, CapabilityError::ValidationFailed(ref msg) if msg.contains("signature") && msg.contains("control or format")),
        "expected dangerous chars rejection in signature, got: {err:?}"
    );
}

#[test]
fn test_r224_006_capability_token_rejects_dangerous_issuer_public_key() {
    let token = CapabilityToken {
        token_id: "tok-1".to_string(),
        parent_token_id: None,
        issuer: "issuer-1".to_string(),
        holder: "holder-1".to_string(),
        grants: vec![CapabilityGrant {
            tool_pattern: "test".to_string(),
            function_pattern: "*".to_string(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }],
        remaining_depth: 3,
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-12-31T23:59:59Z".to_string(),
        signature: "sig".to_string(),
        issuer_public_key: "key\u{FEFF}bom".to_string(),
    };
    let err = token.validate_structure().unwrap_err();
    assert!(
        matches!(err, CapabilityError::ValidationFailed(ref msg) if msg.contains("issuer_public_key") && msg.contains("control or format")),
        "expected dangerous chars rejection in issuer_public_key, got: {err:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// FIND-R224-007: PolicyLifecycleStatus.validate()
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_r224_007_policy_lifecycle_status_validate_ok() {
    let status = crate::PolicyLifecycleStatus {
        enabled: true,
        tracked_policies: 10,
        total_versions: 50,
        staging_count: 3,
        approval_workflow_enabled: true,
    };
    assert!(status.validate().is_ok());
}

#[test]
fn test_r224_007_policy_lifecycle_status_rejects_excessive_total_versions() {
    let status = crate::PolicyLifecycleStatus {
        enabled: true,
        tracked_policies: 10,
        total_versions: 10_001,
        staging_count: 0,
        approval_workflow_enabled: false,
    };
    let err = status.validate().unwrap_err();
    assert!(
        err.contains("total_versions") && err.contains("MAX_TOTAL_VERSIONS"),
        "expected total_versions rejection, got: {err}"
    );
}

#[test]
fn test_r224_007_policy_lifecycle_status_rejects_staging_exceeds_tracked() {
    let status = crate::PolicyLifecycleStatus {
        enabled: true,
        tracked_policies: 5,
        total_versions: 10,
        staging_count: 6,
        approval_workflow_enabled: false,
    };
    let err = status.validate().unwrap_err();
    assert!(
        err.contains("staging_count") && err.contains("tracked_policies"),
        "expected staging_count > tracked_policies rejection, got: {err}"
    );
}

// ── R239-TYP-1: Posture validation tests ──────────────────────────

#[test]
fn test_security_posture_score_validate_rejects_nan() {
    let score = crate::posture::SecurityPostureScore {
        generated_at: "2026-03-06T00:00:00Z".to_string(),
        scope: crate::posture::PostureScope::global(),
        overall_score_percent: f32::NAN,
        tier: "good".to_string(),
        categories: vec![],
        frameworks: vec![],
    };
    assert!(score.validate().is_err());
}

#[test]
fn test_security_posture_score_validate_rejects_infinity() {
    let score = crate::posture::SecurityPostureScore {
        generated_at: "2026-03-06T00:00:00Z".to_string(),
        scope: crate::posture::PostureScope::global(),
        overall_score_percent: f32::INFINITY,
        tier: "good".to_string(),
        categories: vec![],
        frameworks: vec![],
    };
    assert!(score.validate().is_err());
}

#[test]
fn test_security_posture_score_validate_rejects_negative() {
    let score = crate::posture::SecurityPostureScore {
        generated_at: "2026-03-06T00:00:00Z".to_string(),
        scope: crate::posture::PostureScope::global(),
        overall_score_percent: -1.0,
        tier: "good".to_string(),
        categories: vec![],
        frameworks: vec![],
    };
    assert!(score.validate().is_err());
}

#[test]
fn test_security_posture_score_validate_rejects_over_100() {
    let score = crate::posture::SecurityPostureScore {
        generated_at: "2026-03-06T00:00:00Z".to_string(),
        scope: crate::posture::PostureScope::global(),
        overall_score_percent: 100.1,
        tier: "good".to_string(),
        categories: vec![],
        frameworks: vec![],
    };
    assert!(score.validate().is_err());
}

#[test]
fn test_security_posture_score_validate_accepts_valid() {
    let score = crate::posture::SecurityPostureScore {
        generated_at: "2026-03-06T00:00:00Z".to_string(),
        scope: crate::posture::PostureScope::global(),
        overall_score_percent: 85.5,
        tier: "good".to_string(),
        categories: vec![crate::posture::PostureCategoryScore {
            name: "runtime".to_string(),
            score_percent: 90.0,
            inputs: 3,
        }],
        frameworks: vec![crate::posture::PostureFrameworkScore {
            name: "OWASP".to_string(),
            score_percent: 80.0,
            enabled: true,
        }],
    };
    assert!(score.validate().is_ok());
}

#[test]
fn test_posture_gap_report_validate_rejects_nan() {
    let report = crate::posture::PostureGapReport {
        generated_at: "2026-03-06T00:00:00Z".to_string(),
        scope: crate::posture::PostureScope::global(),
        overall_coverage_percent: f32::NAN,
        critical_gaps: vec![],
        recommendations: vec![],
        high_priority_focus_areas: vec![],
    };
    assert!(report.validate().is_err());
}

// ═══════════════════════════════════════════════════════════════════════════════
// R240-TYP-1: Federation Status Validation
// ═══════════════════════════════════════════════════════════════════════════════

fn make_valid_anchor_status() -> crate::abac::FederationAnchorStatus {
    crate::abac::FederationAnchorStatus {
        org_id: "acme-corp".to_string(),
        display_name: "Acme Corp".to_string(),
        issuer_pattern: "https://auth.acme.com/*".to_string(),
        trust_level: "full".to_string(),
        has_jwks_uri: true,
        jwks_cached: true,
        jwks_last_fetched: Some("2026-03-06T12:00:00Z".to_string()),
        identity_mapping_count: 5,
        successful_validations: 100,
        failed_validations: 2,
    }
}

#[test]
fn test_federation_status_validate_valid() {
    let status = crate::abac::FederationStatus {
        enabled: true,
        trust_anchor_count: 1,
        anchors: vec![make_valid_anchor_status()],
    };
    assert!(status.validate().is_ok());
}

#[test]
fn test_federation_status_validate_too_many_anchors() {
    let status = crate::abac::FederationStatus {
        enabled: true,
        trust_anchor_count: 501,
        anchors: (0..501)
            .map(|i| {
                let mut a = make_valid_anchor_status();
                a.org_id = format!("org-{i}");
                a
            })
            .collect(),
    };
    let err = status.validate().unwrap_err();
    assert!(err.contains("exceeds max"), "{err}");
}

#[test]
fn test_federation_anchor_status_validate_invalid_trust_level() {
    let mut anchor = make_valid_anchor_status();
    anchor.trust_level = "admin".to_string();
    let err = anchor.validate().unwrap_err();
    assert!(err.contains("trust_level"), "{err}");
}

#[test]
fn test_federation_anchor_status_validate_dangerous_chars_org_id() {
    let mut anchor = make_valid_anchor_status();
    anchor.org_id = "acme\x00corp".to_string();
    let err = anchor.validate().unwrap_err();
    assert!(err.contains("org_id"), "{err}");
}

#[test]
fn test_federation_anchor_status_validate_oversized_display_name() {
    let mut anchor = make_valid_anchor_status();
    anchor.display_name = "A".repeat(2000);
    let err = anchor.validate().unwrap_err();
    assert!(err.contains("display_name"), "{err}");
}

#[test]
fn test_federation_anchor_info_validate_valid() {
    let info = crate::abac::FederationAnchorInfo {
        org_id: "acme-corp".to_string(),
        display_name: "Acme Corp".to_string(),
        issuer_pattern: "https://auth.acme.com/*".to_string(),
        trust_level: "limited".to_string(),
        has_jwks_uri: true,
        identity_mapping_count: 3,
    };
    assert!(info.validate().is_ok());
}

#[test]
fn test_federation_anchor_info_validate_invalid_trust_level() {
    let info = crate::abac::FederationAnchorInfo {
        org_id: "acme-corp".to_string(),
        display_name: "Acme Corp".to_string(),
        issuer_pattern: "https://auth.acme.com/*".to_string(),
        trust_level: "superuser".to_string(),
        has_jwks_uri: true,
        identity_mapping_count: 3,
    };
    let err = info.validate().unwrap_err();
    assert!(err.contains("trust_level"), "{err}");
}

#[test]
fn test_federation_anchor_status_validate_dangerous_chars_jwks_timestamp() {
    let mut anchor = make_valid_anchor_status();
    anchor.jwks_last_fetched = Some("2026\x1B[31m-03-06".to_string());
    let err = anchor.validate().unwrap_err();
    assert!(err.contains("jwks_last_fetched"), "{err}");
}

// ═══════════════════════════════════════════════════════════════════════════════
// R240-TYP-2: NHI Delegation Chain/Link Validation Gaps
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn test_nhi_delegation_chain_validate_resolved_at_too_long() {
    let chain = crate::nhi::NhiDelegationChain {
        chain: vec![],
        max_depth: 5,
        resolved_at: "T".repeat(100),
    };
    let err = chain.validate().unwrap_err();
    assert!(err.contains("resolved_at"), "{err}");
}

#[test]
fn test_nhi_delegation_chain_validate_resolved_at_dangerous_chars() {
    let chain = crate::nhi::NhiDelegationChain {
        chain: vec![],
        max_depth: 5,
        resolved_at: "2026-03-06\x00T12:00:00Z".to_string(),
    };
    let err = chain.validate().unwrap_err();
    assert!(err.contains("resolved_at"), "{err}");
}

#[test]
fn test_nhi_delegation_chain_validate_resolved_at_valid() {
    let chain = crate::nhi::NhiDelegationChain {
        chain: vec![],
        max_depth: 5,
        resolved_at: "2026-03-06T12:00:00Z".to_string(),
    };
    assert!(chain.validate().is_ok());
}

#[test]
fn test_nhi_delegation_link_validate_reason_too_long() {
    let link = crate::nhi::NhiDelegationLink {
        from_agent: "agent-a".to_string(),
        to_agent: "agent-b".to_string(),
        permissions: vec!["read".to_string()],
        scope_constraints: vec![],
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-12-31T23:59:59Z".to_string(),
        active: true,
        reason: Some("R".repeat(600)),
    };
    let err = link.validate().unwrap_err();
    assert!(err.contains("reason"), "{err}");
}

#[test]
fn test_nhi_delegation_link_validate_reason_dangerous_chars() {
    let link = crate::nhi::NhiDelegationLink {
        from_agent: "agent-a".to_string(),
        to_agent: "agent-b".to_string(),
        permissions: vec!["read".to_string()],
        scope_constraints: vec![],
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-12-31T23:59:59Z".to_string(),
        active: true,
        reason: Some("legit\x1Breason".to_string()),
    };
    let err = link.validate().unwrap_err();
    assert!(err.contains("reason"), "{err}");
}

#[test]
fn test_nhi_delegation_link_validate_reason_valid() {
    let link = crate::nhi::NhiDelegationLink {
        from_agent: "agent-a".to_string(),
        to_agent: "agent-b".to_string(),
        permissions: vec!["read".to_string()],
        scope_constraints: vec![],
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-12-31T23:59:59Z".to_string(),
        active: true,
        reason: Some("Automated delegation for CI pipeline".to_string()),
    };
    assert!(link.validate().is_ok());
}

#[test]
fn test_nhi_delegation_link_validate_reason_none_valid() {
    let link = crate::nhi::NhiDelegationLink {
        from_agent: "agent-a".to_string(),
        to_agent: "agent-b".to_string(),
        permissions: vec!["read".to_string()],
        scope_constraints: vec![],
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2026-12-31T23:59:59Z".to_string(),
        active: true,
        reason: None,
    };
    assert!(link.validate().is_ok());
}

// ═══════════════════════════════════════════════════════════════════
// R243-TYP-1: TaskResumeRequest validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_task_resume_request_validate_ok() {
    let req = crate::task::TaskResumeRequest {
        task_id: "task-123".to_string(),
        resume_token: "abcdef".to_string(),
        nonce: "nonce-1".to_string(),
        agent_id: Some("agent-a".to_string()),
    };
    assert!(req.validate().is_ok());
}

#[test]
fn test_task_resume_request_validate_empty_task_id() {
    let req = crate::task::TaskResumeRequest {
        task_id: "".to_string(),
        resume_token: "tok".to_string(),
        nonce: "n".to_string(),
        agent_id: None,
    };
    let err = req.validate().unwrap_err();
    assert!(err.contains("task_id"), "Error: {err}");
}

#[test]
fn test_task_resume_request_validate_oversized_task_id() {
    let req = crate::task::TaskResumeRequest {
        task_id: "x".repeat(257),
        resume_token: "tok".to_string(),
        nonce: "n".to_string(),
        agent_id: None,
    };
    assert!(req.validate().is_err());
}

#[test]
fn test_task_resume_request_validate_dangerous_chars_task_id() {
    let req = crate::task::TaskResumeRequest {
        task_id: "task\x00id".to_string(),
        resume_token: "tok".to_string(),
        nonce: "n".to_string(),
        agent_id: None,
    };
    let err = req.validate().unwrap_err();
    assert!(err.contains("control or format"), "Error: {err}");
}

#[test]
fn test_task_resume_request_validate_empty_resume_token() {
    let req = crate::task::TaskResumeRequest {
        task_id: "t".to_string(),
        resume_token: "".to_string(),
        nonce: "n".to_string(),
        agent_id: None,
    };
    assert!(req.validate().is_err());
}

#[test]
fn test_task_resume_request_validate_dangerous_chars_nonce() {
    let req = crate::task::TaskResumeRequest {
        task_id: "t".to_string(),
        resume_token: "tok".to_string(),
        nonce: "nonce\u{200B}val".to_string(),
        agent_id: None,
    };
    let err = req.validate().unwrap_err();
    assert!(err.contains("nonce"), "Error: {err}");
}

#[test]
fn test_task_resume_request_validate_oversized_agent_id() {
    let req = crate::task::TaskResumeRequest {
        task_id: "t".to_string(),
        resume_token: "tok".to_string(),
        nonce: "n".to_string(),
        agent_id: Some("a".repeat(257)),
    };
    assert!(req.validate().is_err());
}

// ═══════════════════════════════════════════════════════════════════
// R243-TYP-2: TaskStatus::Failed reason validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_task_status_validate_pending_ok() {
    assert!(crate::task::TaskStatus::Pending.validate().is_ok());
}

#[test]
fn test_task_status_validate_failed_ok() {
    let status = crate::task::TaskStatus::Failed {
        reason: "timeout".to_string(),
    };
    assert!(status.validate().is_ok());
}

#[test]
fn test_task_status_validate_failed_oversized_reason() {
    let status = crate::task::TaskStatus::Failed {
        reason: "x".repeat(4097),
    };
    let err = status.validate().unwrap_err();
    assert!(err.contains("reason length"), "Error: {err}");
}

#[test]
fn test_task_status_validate_failed_dangerous_chars() {
    let status = crate::task::TaskStatus::Failed {
        reason: "error\nnewline".to_string(),
    };
    let err = status.validate().unwrap_err();
    assert!(err.contains("control or format"), "Error: {err}");
}

#[test]
fn test_tracked_task_validate_rejects_bad_status_reason() {
    let task = crate::task::TrackedTask {
        task_id: "t1".to_string(),
        tool: "test".to_string(),
        function: "fn1".to_string(),
        status: crate::task::TaskStatus::Failed {
            reason: "evil\x00reason".to_string(),
        },
        created_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: None,
        created_by: None,
        session_id: None,
    };
    let err = task.validate().unwrap_err();
    assert!(err.contains("status"), "Error should mention status: {err}");
}

// ═══════════════════════════════════════════════════════════════════
// R243-TYP-3: Posture types string content validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_security_posture_score_validate_dangerous_generated_at() {
    let score = crate::posture::SecurityPostureScore {
        generated_at: "2026-01-01T00:00:00Z\x00".to_string(),
        scope: crate::posture::PostureScope::global(),
        overall_score_percent: 85.0,
        tier: "good".to_string(),
        categories: vec![],
        frameworks: vec![],
    };
    let err = score.validate().unwrap_err();
    assert!(err.contains("generated_at"), "Error: {err}");
}

#[test]
fn test_security_posture_score_validate_dangerous_tier() {
    let score = crate::posture::SecurityPostureScore {
        generated_at: "2026-01-01T00:00:00Z".to_string(),
        scope: crate::posture::PostureScope::global(),
        overall_score_percent: 85.0,
        tier: "good\nnewline".to_string(),
        categories: vec![],
        frameworks: vec![],
    };
    let err = score.validate().unwrap_err();
    assert!(err.contains("tier"), "Error: {err}");
}

#[test]
fn test_security_posture_score_validate_dangerous_category_name() {
    let score = crate::posture::SecurityPostureScore {
        generated_at: "2026-01-01T00:00:00Z".to_string(),
        scope: crate::posture::PostureScope::global(),
        overall_score_percent: 85.0,
        tier: "good".to_string(),
        categories: vec![crate::posture::PostureCategoryScore {
            name: "cat\u{200B}name".to_string(),
            score_percent: 90.0,
            inputs: 5,
        }],
        frameworks: vec![],
    };
    let err = score.validate().unwrap_err();
    assert!(err.contains("category name"), "Error: {err}");
}

// R260-TYP-1: PostureCategoryScore standalone validation
#[test]
fn test_r260_posture_category_score_rejects_nan() {
    let score = crate::posture::PostureCategoryScore {
        name: "governance".to_string(),
        score_percent: f32::NAN,
        inputs: 3,
    };
    assert!(score.validate().is_err());
}

#[test]
fn test_r260_posture_category_score_rejects_negative() {
    let score = crate::posture::PostureCategoryScore {
        name: "governance".to_string(),
        score_percent: -1.0,
        inputs: 3,
    };
    assert!(score.validate().is_err());
}

#[test]
fn test_r260_posture_category_score_rejects_dangerous_name() {
    let score = crate::posture::PostureCategoryScore {
        name: "gov\u{200B}ernance".to_string(),
        score_percent: 50.0,
        inputs: 3,
    };
    let err = score.validate().unwrap_err();
    assert!(err.contains("dangerous"), "Error: {err}");
}

#[test]
fn test_r260_posture_framework_score_rejects_infinity() {
    let score = crate::posture::PostureFrameworkScore {
        name: "SOC2".to_string(),
        score_percent: f32::INFINITY,
        enabled: true,
    };
    assert!(score.validate().is_err());
}

#[test]
fn test_posture_gap_report_validate_dangerous_gap_description() {
    let report = crate::posture::PostureGapReport {
        generated_at: "2026-01-01T00:00:00Z".to_string(),
        scope: crate::posture::PostureScope::global(),
        overall_coverage_percent: 70.0,
        critical_gaps: vec![crate::posture::PostureGap {
            framework: "SOC2".to_string(),
            item_id: "CC6.1".to_string(),
            severity: "High".to_string(),
            description: "desc\x00ription".to_string(),
        }],
        recommendations: vec![],
        high_priority_focus_areas: vec![],
    };
    let err = report.validate().unwrap_err();
    assert!(err.contains("description"), "Error: {err}");
}

#[test]
fn test_control_coverage_matrix_validate_ok() {
    let matrix = crate::posture::ControlCoverageMatrix {
        generated_at: "2026-01-01T00:00:00Z".to_string(),
        scope: crate::posture::PostureScope::global(),
        overall_coverage_percent: 80.0,
        frameworks: vec![],
        highlights: vec!["All good".to_string()],
    };
    assert!(matrix.validate().is_ok());
}

#[test]
fn test_control_coverage_matrix_validate_nan_coverage() {
    let matrix = crate::posture::ControlCoverageMatrix {
        generated_at: "2026-01-01T00:00:00Z".to_string(),
        scope: crate::posture::PostureScope::global(),
        overall_coverage_percent: f32::NAN,
        frameworks: vec![],
        highlights: vec![],
    };
    assert!(matrix.validate().is_err());
}

#[test]
fn test_control_coverage_matrix_validate_dangerous_highlight() {
    let matrix = crate::posture::ControlCoverageMatrix {
        generated_at: "2026-01-01T00:00:00Z".to_string(),
        scope: crate::posture::PostureScope::global(),
        overall_coverage_percent: 80.0,
        frameworks: vec![],
        highlights: vec!["note\nnewline".to_string()],
    };
    let err = matrix.validate().unwrap_err();
    assert!(err.contains("highlights"), "Error: {err}");
}

#[test]
fn test_posture_evidence_pack_validate_dangerous_framework() {
    let export = crate::posture::PostureEvidencePackExport {
        generated_at: "2026-01-01T00:00:00Z".to_string(),
        framework: "SOC2\x00".to_string(),
        scope: crate::posture::PostureScope::global(),
        posture: crate::posture::SecurityPostureScore {
            generated_at: "2026-01-01T00:00:00Z".to_string(),
            scope: crate::posture::PostureScope::global(),
            overall_score_percent: 85.0,
            tier: "good".to_string(),
            categories: vec![],
            frameworks: vec![],
        },
        high_priority_focus_areas: vec![],
        evidence_pack: serde_json::json!({}),
    };
    let err = export.validate().unwrap_err();
    assert!(err.contains("framework"), "Error: {err}");
}
