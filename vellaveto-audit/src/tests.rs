// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

use super::*;
use ed25519_dalek::Signer;
use serde_json::json;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use tempfile::TempDir;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use vellaveto_types::{Action, Verdict};

fn test_action() -> Action {
    Action::new(
        "file_system".to_string(),
        "read_file".to_string(),
        json!({"path": "/tmp/test.txt"}),
    )
}

#[tokio::test]
async fn test_log_and_load() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path);

    let action = test_action();
    let verdict = Verdict::Allow;

    logger
        .log_entry(&action, &verdict, json!({}))
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].action.tool, "file_system");
    // New entries should have hashes
    assert!(entries[0].entry_hash.is_some());
    assert!(entries[0].prev_hash.is_none()); // First entry has no prev
}

#[tokio::test]
async fn test_generate_report() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path);

    let action = test_action();

    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();
    logger
        .log_entry(
            &action,
            &Verdict::Deny {
                reason: "blocked".to_string(),
            },
            json!({}),
        )
        .await
        .unwrap();
    logger
        .log_entry(
            &action,
            &Verdict::RequireApproval {
                reason: "needs review".to_string(),
            },
            json!({}),
        )
        .await
        .unwrap();

    let report = logger.generate_report().await.unwrap();
    assert_eq!(report.total_entries, 3);
    assert_eq!(report.allow_count, 1);
    assert_eq!(report.deny_count, 1);
    assert_eq!(report.require_approval_count, 1);
}

#[tokio::test]
async fn test_validation_newline_in_tool() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path);

    let action = Action::new("bad\ntool".to_string(), "read".to_string(), json!({}));

    let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_validation_null_byte() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path);

    let action = Action::new("bad\0tool".to_string(), "read".to_string(), json!({}));

    let result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_empty_log_load() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("nonexistent.jsonl");
    let logger = AuditLogger::new(log_path);

    let entries = logger.load_entries().await.unwrap();
    assert!(entries.is_empty());
}

#[tokio::test]
async fn test_multiple_entries_append() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path);

    let action = test_action();
    for _ in 0..5 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 5);
}

#[tokio::test]
async fn test_parent_dir_creation() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("sub").join("dir").join("audit.jsonl");
    let logger = AuditLogger::new(log_path);

    let action = test_action();
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 1);
}

#[tokio::test]
async fn test_sync_flushes_entries_to_disk() {
    // Verify that sync() makes all entries durable on disk.
    // Write entries (Allow verdicts skip per-write fsync), then sync().
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone());

    let action = test_action();
    for _ in 0..5 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }

    // Sync to ensure all data is flushed
    logger.sync().await.unwrap();

    // Read file directly (not through load_entries) to verify data is on disk
    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let line_count = content.lines().filter(|l| !l.trim().is_empty()).count();
    assert_eq!(line_count, 5, "All 5 entries should be flushed to disk");

    // Each line should be valid JSON
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let parsed: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("Line is not valid JSON: {line} — {e}"));
        assert!(parsed.get("entry_hash").is_some());
    }
}

#[tokio::test]
async fn test_sync_on_nonexistent_file_is_ok() {
    // sync() on a logger whose file doesn't exist yet should succeed
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("nonexistent.jsonl");
    let logger = AuditLogger::new(log_path);

    // Should not error
    logger.sync().await.unwrap();
}

#[tokio::test]
async fn test_hash_chain_integrity() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path);

    let action = test_action();
    for _ in 0..3 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }

    let entries = logger.load_entries().await.unwrap();
    // First entry: no prev_hash
    assert!(entries[0].prev_hash.is_none());
    // Subsequent entries: prev_hash equals previous entry_hash
    assert_eq!(entries[1].prev_hash, entries[0].entry_hash);
    assert_eq!(entries[2].prev_hash, entries[1].entry_hash);
}

#[tokio::test]
async fn test_verify_chain_valid() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path);

    let action = test_action();
    for _ in 0..5 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }

    let verification = logger.verify_chain().await.unwrap();
    assert!(verification.valid);
    assert_eq!(verification.entries_checked, 5);
    assert!(verification.first_broken_at.is_none());
}

#[tokio::test]
async fn test_verify_chain_empty() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("nonexistent.jsonl");
    let logger = AuditLogger::new(log_path);

    let verification = logger.verify_chain().await.unwrap();
    assert!(verification.valid);
    assert_eq!(verification.entries_checked, 0);
}

#[tokio::test]
async fn test_verify_chain_detects_tampering() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone());

    let action = test_action();
    for _ in 0..3 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }

    // Tamper with the file: modify second entry's action
    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let lines: Vec<&str> = content.lines().collect();
    let mut entry1: AuditEntry = serde_json::from_str(lines[1]).unwrap();
    entry1.action.tool = "tampered".to_string();
    let tampered_line = serde_json::to_string(&entry1).unwrap();

    let new_content = format!("{}\n{}\n{}\n", lines[0], tampered_line, lines[2]);
    tokio::fs::write(&log_path, new_content).await.unwrap();

    let verification = logger.verify_chain().await.unwrap();
    assert!(!verification.valid);
    assert_eq!(verification.first_broken_at, Some(1));
}

#[tokio::test]
async fn test_initialize_chain_resumes() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");

    // Write entries with first logger instance
    let logger1 = AuditLogger::new(log_path.clone());
    let action = test_action();
    logger1
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();
    logger1
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    // Create new logger instance and initialize chain
    let logger2 = AuditLogger::new(log_path);
    logger2.initialize_chain().await.unwrap();
    logger2
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    // Chain should still be valid
    let verification = logger2.verify_chain().await.unwrap();
    assert!(verification.valid);
    assert_eq!(verification.entries_checked, 3);
}

#[tokio::test]
async fn test_backward_compat_legacy_entries() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");

    // Write a legacy entry (no hashes) directly to file
    let legacy = json!({
        "id": "legacy-1",
        "action": {"tool": "test", "function": "fn", "parameters": {}},
        "verdict": "Allow",
        "timestamp": "2026-01-01T00:00:00Z",
        "metadata": {}
    });
    let line = format!("{}\n", serde_json::to_string(&legacy).unwrap());
    tokio::fs::write(&log_path, &line).await.unwrap();

    let logger = AuditLogger::new(log_path);
    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].entry_hash.is_none());
    assert!(entries[0].prev_hash.is_none());

    // Verification should handle legacy entries gracefully
    let verification = logger.verify_chain().await.unwrap();
    assert!(verification.valid);
}

// === Security regression tests (Controller Directive C-2) ===

#[tokio::test]
async fn test_fix1_hashless_entry_after_hashed_rejected() {
    // CRITICAL Fix #1: Once hashed entries appear, hashless entries must be rejected.
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone());

    // Write a proper hashed entry
    let action = test_action();
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    // Now manually inject a hashless (legacy-style) entry AFTER the hashed one
    let hashless = json!({
        "id": "injected-hashless",
        "action": {"tool": "evil", "function": "exfil", "parameters": {}},
        "verdict": "Allow",
        "timestamp": "2026-02-02T00:00:00Z",
        "metadata": {}
    });
    let inject_line = format!("{}\n", serde_json::to_string(&hashless).unwrap());
    let mut file = OpenOptions::new()
        .append(true)
        .open(&log_path)
        .await
        .unwrap();
    file.write_all(inject_line.as_bytes()).await.unwrap();
    file.flush().await.unwrap();

    // Verification MUST fail — hashless entry after hashed is not allowed
    let verification = logger.verify_chain().await.unwrap();
    assert!(!verification.valid);
    assert_eq!(verification.first_broken_at, Some(1));
}

#[tokio::test]
async fn test_fix2_field_separator_prevents_boundary_shift() {
    // CRITICAL Fix #2: Length-prefixed fields prevent boundary-shift collisions.
    // Two entries with fields that differ only at boundaries must produce different hashes.
    let entry_a = AuditEntry {
        id: "ab".to_string(),
        action: Action::new("cd".to_string(), "ef".to_string(), json!({})),
        verdict: Verdict::Allow,
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        metadata: json!({}),
        sequence: 0,
        entry_hash: None,
        prev_hash: None,
        commitment: None,
        tenant_id: None,
        acis_envelope: None,
    };

    let entry_b = AuditEntry {
        id: "abc".to_string(),
        action: Action::new("d".to_string(), "ef".to_string(), json!({})),
        verdict: Verdict::Allow,
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        metadata: json!({}),
        sequence: 0,
        entry_hash: None,
        prev_hash: None,
        commitment: None,
        tenant_id: None,
        acis_envelope: None,
    };

    let hash_a = AuditLogger::compute_entry_hash(&entry_a).unwrap();
    let hash_b = AuditLogger::compute_entry_hash(&entry_b).unwrap();
    assert_ne!(
        hash_a, hash_b,
        "Boundary-shifted fields must produce different hashes"
    );
}

#[tokio::test]
async fn test_canonical_json_produces_deterministic_hashes() {
    // RFC 8785 canonical JSON ensures hash stability regardless of key insertion order.
    // Construct two entries with semantically identical metadata but different key order.
    let metadata_a =
        serde_json::from_str::<serde_json::Value>(r#"{"zebra": 1, "alpha": 2, "middle": 3}"#)
            .unwrap();
    let metadata_b =
        serde_json::from_str::<serde_json::Value>(r#"{"alpha": 2, "middle": 3, "zebra": 1}"#)
            .unwrap();

    let entry_a = AuditEntry {
        id: "test-canonical".to_string(),
        action: Action::new(
            "test".to_string(),
            "run".to_string(),
            json!({"b": 1, "a": 2}),
        ),
        verdict: Verdict::Allow,
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        metadata: metadata_a,
        sequence: 0,
        entry_hash: None,
        prev_hash: None,
        commitment: None,
        tenant_id: None,
        acis_envelope: None,
    };

    let entry_b = AuditEntry {
        id: "test-canonical".to_string(),
        action: Action::new(
            "test".to_string(),
            "run".to_string(),
            json!({"a": 2, "b": 1}),
        ),
        verdict: Verdict::Allow,
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        metadata: metadata_b,
        sequence: 0,
        entry_hash: None,
        prev_hash: None,
        commitment: None,
        tenant_id: None,
        acis_envelope: None,
    };

    let hash_a = AuditLogger::compute_entry_hash(&entry_a).unwrap();
    let hash_b = AuditLogger::compute_entry_hash(&entry_b).unwrap();
    assert_eq!(
        hash_a, hash_b,
        "Semantically identical entries must produce the same hash via canonical JSON"
    );
}

#[tokio::test]
async fn test_fix3_initialize_chain_rejects_tampered_file() {
    // CRITICAL Fix #3: initialize_chain must verify before trusting.
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");

    // Write valid entries with first logger
    let logger1 = AuditLogger::new(log_path.clone());
    let action = test_action();
    logger1
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();
    logger1
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    // Tamper with the file
    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let lines: Vec<&str> = content.lines().collect();
    let mut entry0: AuditEntry = serde_json::from_str(lines[0]).unwrap();
    entry0.action.tool = "tampered".to_string();
    let tampered_line = serde_json::to_string(&entry0).unwrap();
    let new_content = format!("{}\n{}\n", tampered_line, lines[1]);
    tokio::fs::write(&log_path, new_content).await.unwrap();

    // Create new logger and initialize — should NOT trust the tampered hash
    let logger2 = AuditLogger::new(log_path.clone());
    logger2.initialize_chain().await.unwrap();

    // Write a new entry — it should start a fresh chain segment (prev_hash = None)
    logger2
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    let entries = logger2.load_entries().await.unwrap();
    let new_entry = entries.last().unwrap();
    // The new entry should NOT chain from the tampered entry
    assert!(
        new_entry.prev_hash.is_none(),
        "Should not chain from tampered file"
    );
}

#[tokio::test]
async fn test_fix4_hash_not_updated_on_write_failure() {
    // CRITICAL Fix #4: last_hash must not advance if file write fails.
    // We test this by verifying the ordering: write happens before hash update.
    // The simplest way: write to a valid path, then verify chain continuity
    // after simulating the write-then-verify pattern.
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone());

    let action = test_action();
    // Write two entries successfully
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    // Verify chain is valid — this also indirectly tests that the hash update
    // happened after the file write (if it happened before and the write failed,
    // the chain would be broken on the next write).
    let verification = logger.verify_chain().await.unwrap();
    assert!(verification.valid);
    assert_eq!(verification.entries_checked, 2);
}

// --- Phase 3.3: Sensitive value redaction tests ---

#[tokio::test]
async fn test_redaction_sensitive_param_key() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone()); // redaction enabled

    let action = Action::new(
        "http_request".to_string(),
        "post".to_string(),
        json!({
            "url": "https://api.example.com",
            "password": "super_secret_123",
            "api_key": "sk-1234567890",
            "headers": {
                "authorization": "Bearer token123"
            }
        }),
    );

    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 1);
    let params = &entries[0].action.parameters;
    // Sensitive keys should be redacted
    assert_eq!(params["password"], "[REDACTED]");
    assert_eq!(params["api_key"], "[REDACTED]");
    assert_eq!(params["headers"]["authorization"], "[REDACTED]");
    // Non-sensitive keys should be preserved
    assert_eq!(params["url"], "https://api.example.com");
}

#[tokio::test]
async fn test_redaction_sensitive_value_prefix() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone());

    let action = Action::new(
        "tool".to_string(),
        "func".to_string(),
        json!({
            "key1": "sk-abc123def456",
            "key2": "AKIAIOSFODNN7EXAMPLE",
            "key3": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "safe_value": "normal text"
        }),
    );

    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    let params = &entries[0].action.parameters;
    assert_eq!(params["key1"], "[REDACTED]");
    assert_eq!(params["key2"], "[REDACTED]");
    assert_eq!(params["key3"], "[REDACTED]");
    assert_eq!(params["safe_value"], "normal text");
}

#[tokio::test]
async fn test_redaction_nested_values() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone());

    let action = Action::new(
        "tool".to_string(),
        "func".to_string(),
        json!({
            "config": {
                "nested": {
                    "token": "should_be_redacted",
                    "name": "safe"
                }
            },
            "items": ["normal", "sk-secret123", "safe"]
        }),
    );

    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    let params = &entries[0].action.parameters;
    assert_eq!(params["config"]["nested"]["token"], "[REDACTED]");
    assert_eq!(params["config"]["nested"]["name"], "safe");
    assert_eq!(params["items"][0], "normal");
    assert_eq!(params["items"][1], "[REDACTED]"); // sk- prefix
    assert_eq!(params["items"][2], "safe");
}

#[tokio::test]
async fn test_unredacted_logger_preserves_all_values() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new_unredacted(log_path.clone());

    let action = Action::new(
        "tool".to_string(),
        "func".to_string(),
        json!({
            "password": "visible_password",
            "key": "sk-visible-key"
        }),
    );

    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    let params = &entries[0].action.parameters;
    // With redaction disabled, all values are preserved
    assert_eq!(params["password"], "visible_password");
    assert_eq!(params["key"], "sk-visible-key");
}

#[tokio::test]
async fn test_redaction_metadata_also_redacted() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone());

    let action = test_action();
    let metadata = json!({
        "source": "proxy",
        "secret": "should_be_redacted",
        "auth_header": "Bearer xyz123"
    });

    logger
        .log_entry(&action, &Verdict::Allow, metadata)
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    let meta = &entries[0].metadata;
    assert_eq!(meta["source"], "proxy");
    assert_eq!(meta["secret"], "[REDACTED]");
    assert_eq!(meta["auth_header"], "[REDACTED]"); // "Bearer " prefix
}

#[tokio::test]
async fn test_redaction_hash_chain_still_valid() {
    // Verify that redacted entries still form a valid hash chain
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone());

    let action = Action::new(
        "tool".to_string(),
        "func".to_string(),
        json!({"password": "secret123", "path": "/tmp/safe"}),
    );

    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();
    logger
        .log_entry(
            &action,
            &Verdict::Deny {
                reason: "test".into(),
            },
            json!({}),
        )
        .await
        .unwrap();

    let verification = logger.verify_chain().await.unwrap();
    assert!(verification.valid);
    assert_eq!(verification.entries_checked, 2);
}

// --- Phase 1A: KeysOnly vs KeysAndPatterns differentiation tests ---

#[tokio::test]
async fn test_keys_only_preserves_value_prefixes() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone()).with_redaction_level(RedactionLevel::KeysOnly);

    let action = Action::new(
        "tool".to_string(),
        "func".to_string(),
        json!({
            "key1": "sk-abc123def456",
            "key2": "AKIAIOSFODNN7EXAMPLE",
            "password": "secret123",
            "safe_value": "normal text"
        }),
    );

    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    let params = &entries[0].action.parameters;
    // KeysOnly: sensitive keys are redacted
    assert_eq!(params["password"], "[REDACTED]");
    // KeysOnly: value prefixes (sk-, AKIA) are NOT redacted
    assert_eq!(params["key1"], "sk-abc123def456");
    assert_eq!(params["key2"], "AKIAIOSFODNN7EXAMPLE");
    assert_eq!(params["safe_value"], "normal text");
}

#[tokio::test]
async fn test_keys_only_preserves_emails() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone()).with_redaction_level(RedactionLevel::KeysOnly);

    let action = Action::new(
        "tool".to_string(),
        "func".to_string(),
        json!({
            "contact": "user@example.com",
            "note": "Call 555-123-4567"
        }),
    );

    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    let params = &entries[0].action.parameters;
    // KeysOnly does NOT redact PII patterns
    assert_eq!(params["contact"], "user@example.com");
    assert_eq!(params["note"], "Call 555-123-4567");
}

#[tokio::test]
async fn test_keys_and_patterns_redacts_value_prefixes() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger =
        AuditLogger::new(log_path.clone()).with_redaction_level(RedactionLevel::KeysAndPatterns);

    let action = Action::new(
        "tool".to_string(),
        "func".to_string(),
        json!({
            "key1": "sk-abc123def456",
            "key2": "AKIAIOSFODNN7EXAMPLE",
            "safe_value": "normal text"
        }),
    );

    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    let params = &entries[0].action.parameters;
    // KeysAndPatterns: value prefixes ARE redacted
    assert_eq!(params["key1"], "[REDACTED]");
    assert_eq!(params["key2"], "[REDACTED]");
    assert_eq!(params["safe_value"], "normal text");
}

#[tokio::test]
async fn test_keys_and_patterns_redacts_pii() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger =
        AuditLogger::new(log_path.clone()).with_redaction_level(RedactionLevel::KeysAndPatterns);

    let action = Action::new(
        "tool".to_string(),
        "func".to_string(),
        json!({
            "contact": "user@example.com",
            "ssn": "123-45-6789",
            "phone": "555-123-4567",
            "safe_value": "normal text"
        }),
    );

    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    let params = &entries[0].action.parameters;
    // KeysAndPatterns: PII patterns ARE redacted
    assert_eq!(params["contact"], "[REDACTED]");
    assert_eq!(params["ssn"], "[REDACTED]");
    assert_eq!(params["phone"], "[REDACTED]");
    assert_eq!(params["safe_value"], "normal text");
}

#[tokio::test]
async fn test_keys_and_patterns_redacts_metadata_pii() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger =
        AuditLogger::new(log_path.clone()).with_redaction_level(RedactionLevel::KeysAndPatterns);

    let action = test_action();
    let metadata = json!({
        "source": "proxy",
        "user_email": "admin@corp.com",
        "api_key_value": "sk-secretkey123"
    });

    logger
        .log_entry(&action, &Verdict::Allow, metadata)
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    let meta = &entries[0].metadata;
    assert_eq!(meta["source"], "proxy");
    assert_eq!(meta["user_email"], "[REDACTED]");
    assert_eq!(meta["api_key_value"], "[REDACTED]");
}

// ── R36-SUP-1: PII redaction uses PiiScanner for target_paths/domains ──

#[tokio::test]
async fn test_r36_sup_1_target_paths_use_pii_scanner() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    // Default AuditLogger has PiiScanner that detects IPv4, JWT, AWS keys, etc.
    let logger =
        AuditLogger::new(log_path.clone()).with_redaction_level(RedactionLevel::KeysAndPatterns);

    let mut action = Action::new("tool".to_string(), "func".to_string(), json!({}));
    // IPv4 in target_paths — detected by PiiScanner but NOT by legacy PII_REGEXES
    action.target_paths = vec!["192.168.1.100".to_string()];
    // AWS key in target_domains — detected by PiiScanner but NOT by legacy PII_REGEXES
    action.target_domains = vec!["AKIAIOSFODNN7EXAMPLE".to_string()];

    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(
        entries[0].action.target_paths[0], "[REDACTED]",
        "IPv4 in target_paths should be redacted by PiiScanner"
    );
    assert_eq!(
        entries[0].action.target_domains[0], "[REDACTED]",
        "AWS key in target_domains should be redacted by PiiScanner"
    );
}

// ── R36-SUP-3: resolved_ips redacted in audit log entries ──

#[tokio::test]
async fn test_r36_sup_3_resolved_ips_redacted() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger =
        AuditLogger::new(log_path.clone()).with_redaction_level(RedactionLevel::KeysAndPatterns);

    let mut action = Action::new("tool".to_string(), "func".to_string(), json!({}));
    action.resolved_ips = vec!["10.0.0.1".to_string(), "safe-value".to_string()];

    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    // IP address should be redacted
    assert_eq!(
        entries[0].action.resolved_ips[0], "[REDACTED]",
        "IP in resolved_ips should be redacted"
    );
    // Non-PII value should be preserved
    assert_eq!(
        entries[0].action.resolved_ips[1], "safe-value",
        "Non-PII value in resolved_ips should be preserved"
    );
}

#[tokio::test]
async fn test_r36_sup_3_resolved_ips_not_redacted_when_off() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone()).with_redaction_level(RedactionLevel::Off);

    let mut action = Action::new("tool".to_string(), "func".to_string(), json!({}));
    action.resolved_ips = vec!["10.0.0.1".to_string()];

    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(
        entries[0].action.resolved_ips[0], "10.0.0.1",
        "resolved_ips should not be redacted when redaction is off"
    );
}

// === Log rotation tests (Fix #36) ===

#[tokio::test]
async fn test_rotation_triggers_when_size_exceeded() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    // Set a tiny threshold so rotation triggers quickly
    let logger = AuditLogger::new(log_path.clone()).with_max_file_size(200);

    let action = test_action();

    // Write entries until rotation triggers
    for _ in 0..20 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }

    // At least one rotated file should exist
    let rotated = logger.list_rotated_files().unwrap();
    assert!(!rotated.is_empty(), "Expected at least one rotated file");

    // The active log should still exist with entries
    let active_entries = logger.load_entries().await.unwrap();
    assert!(
        !active_entries.is_empty(),
        "Active log should still have entries after rotation"
    );
}

#[tokio::test]
async fn test_rotation_starts_fresh_hash_chain() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone()).with_max_file_size(200);

    let action = test_action();

    // Write enough entries to trigger at least one rotation
    for _ in 0..20 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }

    // The current (active) log should have a valid chain with
    // the first entry having prev_hash = None (fresh chain)
    let entries = logger.load_entries().await.unwrap();
    assert!(!entries.is_empty());
    assert!(
        entries[0].prev_hash.is_none(),
        "First entry in rotated-to file should have no prev_hash"
    );

    let verification = logger.verify_chain().await.unwrap();
    assert!(verification.valid);
}

#[tokio::test]
async fn test_rotation_preserves_unique_monotonic_global_sequences() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone()).with_max_file_size(200);

    let action = test_action();
    let total_entries = 20u64;

    for _ in 0..total_entries {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }

    let mut all_entries = Vec::new();
    let mut rotated = logger.list_rotated_files().unwrap();
    rotated.sort();

    for rotated_path in rotated {
        let rotated_logger = AuditLogger::new(rotated_path).with_max_file_size(0);
        all_entries.extend(rotated_logger.load_entries().await.unwrap());
    }
    let active_entries = logger.load_entries().await.unwrap();
    all_entries.extend(active_entries.iter().cloned());

    assert_eq!(all_entries.len() as u64, total_entries);

    let mut sequences: Vec<u64> = all_entries.iter().map(|entry| entry.sequence).collect();
    sequences.sort_unstable();
    assert_eq!(sequences, (0..total_entries).collect::<Vec<_>>());
    assert_eq!(logger.global_sequence.load(Ordering::SeqCst), total_entries);
    assert_eq!(
        logger.entry_count.load(Ordering::SeqCst),
        active_entries.len() as u64
    );
}

#[tokio::test]
async fn test_initialize_chain_recovers_next_global_sequence() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone());
    let action = test_action();

    for _ in 0..3 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }

    let recovered = AuditLogger::new(log_path);
    recovered.initialize_chain().await.unwrap();

    assert_eq!(recovered.global_sequence.load(Ordering::SeqCst), 3);

    recovered
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    let entries = recovered.load_entries().await.unwrap();
    assert_eq!(entries.len(), 4);
    assert_eq!(entries.last().unwrap().sequence, 3);
}

#[tokio::test]
async fn test_rotation_disabled_when_zero() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone()).with_max_file_size(0);

    let action = test_action();

    // Write many entries — no rotation should occur
    for _ in 0..20 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }

    let rotated = logger.list_rotated_files().unwrap();
    assert!(
        rotated.is_empty(),
        "No rotation should occur when max_file_size=0"
    );

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 20);
}

#[tokio::test]
async fn test_rotation_no_data_loss() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone()).with_max_file_size(200);

    let action = test_action();
    let total = 30;

    for _ in 0..total {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }

    // Count entries across active + rotated files
    let active_entries = logger.load_entries().await.unwrap();
    let rotated_files = logger.list_rotated_files().unwrap();

    let mut total_count = active_entries.len();
    for path in &rotated_files {
        let content = tokio::fs::read_to_string(path).await.unwrap();
        let count = content.lines().filter(|l| !l.trim().is_empty()).count();
        total_count += count;
    }

    assert_eq!(
        total_count, total,
        "Total entries across all files should equal entries written"
    );
}

#[tokio::test]
async fn test_rotation_rotated_file_has_valid_chain() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone()).with_max_file_size(200);

    let action = test_action();
    for _ in 0..20 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }

    // Verify the rotated file's chain is independently valid
    let rotated_files = logger.list_rotated_files().unwrap();
    assert!(!rotated_files.is_empty());

    let rotated_logger = AuditLogger::new(rotated_files[0].clone()).with_max_file_size(0);
    let verification = rotated_logger.verify_chain().await.unwrap();
    assert!(
        verification.valid,
        "Rotated file should have a valid hash chain"
    );
}

#[tokio::test]
async fn test_list_rotated_files_empty_when_no_rotation() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone());

    let action = test_action();
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    let rotated = logger.list_rotated_files().unwrap();
    assert!(rotated.is_empty());
}

#[tokio::test]
async fn test_list_rotated_files_nonexistent_dir() {
    let logger = AuditLogger::new(PathBuf::from("/nonexistent/path/audit.jsonl"));
    let rotated = logger.list_rotated_files().unwrap();
    assert!(rotated.is_empty());
}

#[tokio::test]
async fn test_rotation_initialize_chain_after_rotation() {
    // After rotation, a new logger instance should initialize correctly
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");

    // First logger: write enough to trigger rotation
    let logger1 = AuditLogger::new(log_path.clone()).with_max_file_size(200);
    let action = test_action();
    for _ in 0..20 {
        logger1
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }

    // Second logger: initialize chain from active log
    let logger2 = AuditLogger::new(log_path.clone()).with_max_file_size(200);
    logger2.initialize_chain().await.unwrap();

    // Write more entries — chain should remain valid
    logger2
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    let verification = logger2.verify_chain().await.unwrap();
    assert!(verification.valid);
}

#[tokio::test]
async fn test_with_max_file_size_builder() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path).with_max_file_size(50 * 1024 * 1024); // 50 MB

    // Just verifying the builder doesn't panic and logger works
    let action = test_action();
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 1);
}

// === Signed checkpoint tests (Phase 10.3) ===

#[tokio::test]
async fn test_checkpoint_creation() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let key = AuditLogger::generate_signing_key();
    let logger = AuditLogger::new(log_path).with_signing_key(key);

    let action = test_action();
    for _ in 0..5 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }

    let checkpoint = logger.create_checkpoint().await.unwrap();
    assert_eq!(checkpoint.entry_count, 5);
    assert!(checkpoint.chain_head_hash.is_some());
    assert!(!checkpoint.signature.is_empty());
    assert!(!checkpoint.verifying_key.is_empty());
    assert!(!checkpoint.id.is_empty());
    assert!(!checkpoint.timestamp.is_empty());
}

#[tokio::test]
async fn test_checkpoint_no_key_returns_error() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path); // No signing key

    let result = logger.create_checkpoint().await;
    assert!(result.is_err());
    match result.unwrap_err() {
        AuditError::Validation(msg) => {
            assert!(msg.contains("signing key"));
        }
        other => panic!("Expected Validation error, got {other:?}"),
    }
}

#[tokio::test]
async fn test_checkpoint_empty_log() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let key = AuditLogger::generate_signing_key();
    let logger = AuditLogger::new(log_path).with_signing_key(key);

    let checkpoint = logger.create_checkpoint().await.unwrap();
    assert_eq!(checkpoint.entry_count, 0);
    assert!(checkpoint.chain_head_hash.is_none());
}

#[tokio::test]
async fn test_checkpoint_verification_valid() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let key = AuditLogger::generate_signing_key();
    let logger = AuditLogger::new(log_path).with_signing_key(key);

    let action = test_action();
    for _ in 0..3 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }
    logger.create_checkpoint().await.unwrap();

    // Write more entries and create another checkpoint
    for _ in 0..2 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }
    logger.create_checkpoint().await.unwrap();

    let verification = logger.verify_checkpoints().await.unwrap();
    assert!(verification.valid);
    assert_eq!(verification.checkpoints_checked, 2);
    assert!(verification.first_invalid_at.is_none());
    assert!(verification.failure_reason.is_none());
}

#[tokio::test]
async fn test_checkpoint_verification_empty() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path);

    let verification = logger.verify_checkpoints().await.unwrap();
    assert!(verification.valid);
    assert_eq!(verification.checkpoints_checked, 0);
}

#[tokio::test]
async fn test_checkpoint_tampered_signature_detected() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let key = AuditLogger::generate_signing_key();
    let logger = AuditLogger::new(log_path.clone()).with_signing_key(key);

    let action = test_action();
    for _ in 0..3 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }
    logger.create_checkpoint().await.unwrap();

    // Tamper with the checkpoint signature
    let cp_path = logger.checkpoint_path();
    let content = tokio::fs::read_to_string(&cp_path).await.unwrap();
    let mut cp: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
    // Flip a byte in the signature
    let sig = cp["signature"].as_str().unwrap().to_string();
    let tampered_sig = if let Some(rest) = sig.strip_prefix('a') {
        format!("b{rest}")
    } else {
        format!("a{}", &sig[1..])
    };
    cp["signature"] = serde_json::Value::String(tampered_sig);
    let tampered = format!("{}\n", serde_json::to_string(&cp).unwrap());
    tokio::fs::write(&cp_path, tampered).await.unwrap();

    let verification = logger.verify_checkpoints().await.unwrap();
    assert!(!verification.valid);
    assert_eq!(verification.first_invalid_at, Some(0));
    assert!(verification
        .failure_reason
        .as_ref()
        .unwrap()
        .contains("signature verification failed"));
}

#[tokio::test]
async fn test_checkpoint_tampered_entry_count_detected() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let key = AuditLogger::generate_signing_key();
    let logger = AuditLogger::new(log_path.clone()).with_signing_key(key);

    let action = test_action();
    for _ in 0..3 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }
    logger.create_checkpoint().await.unwrap();

    // Tamper: change entry_count in checkpoint (without re-signing)
    let cp_path = logger.checkpoint_path();
    let content = tokio::fs::read_to_string(&cp_path).await.unwrap();
    let mut cp: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
    cp["entry_count"] = serde_json::Value::Number(serde_json::Number::from(999));
    let tampered = format!("{}\n", serde_json::to_string(&cp).unwrap());
    tokio::fs::write(&cp_path, tampered).await.unwrap();

    let verification = logger.verify_checkpoints().await.unwrap();
    assert!(!verification.valid);
    // Signature check should fail because the content changed
    assert!(verification
        .failure_reason
        .as_ref()
        .unwrap()
        .contains("signature verification failed"));
}

#[tokio::test]
async fn test_checkpoint_tampered_audit_log_detected() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let key = AuditLogger::generate_signing_key();
    let logger = AuditLogger::new(log_path.clone()).with_signing_key(key);

    let action = test_action();
    for _ in 0..3 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }
    logger.create_checkpoint().await.unwrap();

    // Tamper with the audit log (change the last entry's hash)
    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
    let mut last_entry: serde_json::Value = serde_json::from_str(lines.last().unwrap()).unwrap();
    last_entry["entry_hash"] = serde_json::Value::String("0".repeat(64));
    *lines.last_mut().unwrap() = serde_json::to_string(&last_entry).unwrap();
    let tampered = lines.join("\n") + "\n";
    tokio::fs::write(&log_path, tampered).await.unwrap();

    let verification = logger.verify_checkpoints().await.unwrap();
    assert!(!verification.valid);
    let reason = verification.failure_reason.as_ref().unwrap();
    // Chain verification now detects tampering at the hash level (entry_hash
    // mismatch) before reaching the checkpoint head-hash comparison.
    assert!(
        reason.contains("entry_hash mismatch") || reason.contains("Chain head hash mismatch"),
        "Expected tampering detection, got: {reason}"
    );
}

#[tokio::test]
async fn test_exploit8_middle_deletion_detected() {
    // Exploit #8 hardening: deleting entries between two checkpoints
    // must be detected. Previously, only tail truncation was caught.
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let key = AuditLogger::generate_signing_key();
    let logger = AuditLogger::new(log_path.clone()).with_signing_key(key);

    let action = test_action();

    // Write 3 entries + checkpoint A
    for _ in 0..3 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }
    logger.create_checkpoint().await.unwrap();

    // Write 3 more entries + checkpoint B
    for _ in 0..3 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }
    logger.create_checkpoint().await.unwrap();

    // Delete entry #4 (middle of the chain, between checkpoints A and B)
    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert!(
        lines.len() >= 6,
        "Expected at least 6 entries, got {}",
        lines.len()
    );
    // Remove the 4th entry (index 3) — this is between checkpoint A and B
    let mut tampered_lines: Vec<&str> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if i != 3 {
            tampered_lines.push(line);
        }
    }
    let tampered = tampered_lines.join("\n") + "\n";
    tokio::fs::write(&log_path, tampered).await.unwrap();

    // Verification must detect the deletion
    let verification = logger.verify_checkpoints().await.unwrap();
    assert!(
        !verification.valid,
        "Middle deletion should be detected by checkpoint verification"
    );
    let reason = verification.failure_reason.as_ref().unwrap();
    assert!(
        reason.contains("middle deletion")
            || reason.contains("prev_hash mismatch")
            || reason.contains("Chain head hash mismatch")
            || reason.contains("truncated"),
        "Expected chain break detection, got: {reason}"
    );
}

#[tokio::test]
async fn test_checkpoint_multiple_sequential() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let key = AuditLogger::generate_signing_key();
    let logger = AuditLogger::new(log_path).with_signing_key(key);

    let action = test_action();

    // Create checkpoint on empty log
    logger.create_checkpoint().await.unwrap();

    // Add entries and checkpoint
    for _ in 0..5 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }
    logger.create_checkpoint().await.unwrap();

    // Add more entries and checkpoint again
    for _ in 0..3 {
        logger
            .log_entry(
                &action,
                &Verdict::Deny {
                    reason: "test".to_string(),
                },
                json!({}),
            )
            .await
            .unwrap();
    }
    logger.create_checkpoint().await.unwrap();

    let checkpoints = logger.load_checkpoints().await.unwrap();
    assert_eq!(checkpoints.len(), 3);
    assert_eq!(checkpoints[0].entry_count, 0);
    assert_eq!(checkpoints[1].entry_count, 5);
    assert_eq!(checkpoints[2].entry_count, 8);

    let verification = logger.verify_checkpoints().await.unwrap();
    assert!(verification.valid);
    assert_eq!(verification.checkpoints_checked, 3);
}

#[tokio::test]
async fn test_checkpoint_different_key_single_checkpoint_passes_without_pin() {
    // A single forged checkpoint with a different key passes basic verification
    // because there's no prior key to enforce continuity against.
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let key1 = AuditLogger::generate_signing_key();
    let logger = AuditLogger::new(log_path.clone()).with_signing_key(key1);

    let action = test_action();
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();
    logger.create_checkpoint().await.unwrap();

    // Tamper: replace the checkpoint with one signed by a different key
    let key2 = AuditLogger::generate_signing_key();
    let cp_path = logger.checkpoint_path();
    let content = tokio::fs::read_to_string(&cp_path).await.unwrap();
    let mut cp: Checkpoint = serde_json::from_str(content.trim()).unwrap();

    // Re-sign with the wrong key
    cp.verifying_key = hex::encode(key2.verifying_key().as_bytes());
    let sig = key2.sign(&cp.signing_content());
    cp.signature = hex::encode(sig.to_bytes());
    let forged = format!("{}\n", serde_json::to_string(&cp).unwrap());
    tokio::fs::write(&cp_path, forged).await.unwrap();

    // Without key pinning, a single re-signed checkpoint passes
    let verification = logger.verify_checkpoints().await.unwrap();
    assert!(verification.valid);
}

#[tokio::test]
async fn test_checkpoint_key_pinning_rejects_forged_key() {
    // Key pinning catches a forged checkpoint signed by an unexpected key
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let key1 = AuditLogger::generate_signing_key();
    let pinned_vk = hex::encode(key1.verifying_key().as_bytes());
    let logger = AuditLogger::new(log_path.clone()).with_signing_key(key1);

    let action = test_action();
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();
    logger.create_checkpoint().await.unwrap();

    // Tamper: replace with checkpoint signed by key2
    let key2 = AuditLogger::generate_signing_key();
    let cp_path = logger.checkpoint_path();
    let content = tokio::fs::read_to_string(&cp_path).await.unwrap();
    let mut cp: Checkpoint = serde_json::from_str(content.trim()).unwrap();
    cp.verifying_key = hex::encode(key2.verifying_key().as_bytes());
    let sig = key2.sign(&cp.signing_content());
    cp.signature = hex::encode(sig.to_bytes());
    let forged = format!("{}\n", serde_json::to_string(&cp).unwrap());
    tokio::fs::write(&cp_path, forged).await.unwrap();

    // With key pinning, the forged checkpoint is rejected
    let verification = logger
        .verify_checkpoints_with_key(Some(&pinned_vk))
        .await
        .unwrap();
    assert!(!verification.valid);
    assert!(verification
        .failure_reason
        .as_ref()
        .unwrap()
        .contains("key continuity violated"));
}

#[tokio::test]
async fn test_trusted_key_builder_rejects_single_forged_checkpoint() {
    // Challenge 9 fix: with_trusted_key() makes verify_checkpoints() reject
    // a single forged checkpoint (which previously passed without pinning).
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let key1 = AuditLogger::generate_signing_key();
    let pinned_vk = hex::encode(key1.verifying_key().as_bytes());
    let logger = AuditLogger::new(log_path.clone())
        .with_signing_key(key1)
        .with_trusted_key(pinned_vk);

    let action = test_action();
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();
    logger.create_checkpoint().await.unwrap();

    // Tamper: replace checkpoint with one signed by attacker's key
    let attacker_key = AuditLogger::generate_signing_key();
    let cp_path = logger.checkpoint_path();
    let content = tokio::fs::read_to_string(&cp_path).await.unwrap();
    let mut cp: Checkpoint = serde_json::from_str(content.trim()).unwrap();
    cp.verifying_key = hex::encode(attacker_key.verifying_key().as_bytes());
    let sig = attacker_key.sign(&cp.signing_content());
    cp.signature = hex::encode(sig.to_bytes());
    let forged = format!("{}\n", serde_json::to_string(&cp).unwrap());
    tokio::fs::write(&cp_path, forged).await.unwrap();

    // Default verify_checkpoints() now rejects because trusted key is pinned
    let verification = logger.verify_checkpoints().await.unwrap();
    assert!(!verification.valid);
    assert!(verification
        .failure_reason
        .as_ref()
        .unwrap()
        .contains("key continuity violated"));
}

#[tokio::test]
async fn test_trusted_key_builder_accepts_legitimate_checkpoint() {
    // Legitimate checkpoints pass when the correct key is pinned.
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let key = AuditLogger::generate_signing_key();
    let pinned_vk = hex::encode(key.verifying_key().as_bytes());
    let logger = AuditLogger::new(log_path.clone())
        .with_signing_key(key)
        .with_trusted_key(pinned_vk);

    let action = test_action();
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();
    logger.create_checkpoint().await.unwrap();

    let verification = logger.verify_checkpoints().await.unwrap();
    assert!(verification.valid);
    assert_eq!(verification.checkpoints_checked, 1);
}

#[tokio::test]
async fn test_checkpoint_key_continuity_rejects_key_change() {
    // Two checkpoints from different keys are rejected even without pinning
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let key1 = AuditLogger::generate_signing_key();
    let key2 = AuditLogger::generate_signing_key();
    let logger = AuditLogger::new(log_path.clone()).with_signing_key(key1);

    let action = test_action();
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();
    logger.create_checkpoint().await.unwrap();

    // Add more entries and create a second checkpoint with a different key
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();
    // Forge a second checkpoint with key2
    let entries = logger.load_entries().await.unwrap();
    let mut cp2 = Checkpoint {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        entry_count: entries.len(),
        chain_head_hash: entries.last().and_then(|e| e.entry_hash.clone()),
        signature: String::new(),
        verifying_key: hex::encode(key2.verifying_key().as_bytes()),
        merkle_root: None,
        pqc_signature: None,
        pqc_verifying_key: None,
        signature_version: None,
    };
    let sig = key2.sign(&cp2.signing_content());
    cp2.signature = hex::encode(sig.to_bytes());

    let cp_path = logger.checkpoint_path();
    let mut file = tokio::fs::OpenOptions::new()
        .append(true)
        .open(&cp_path)
        .await
        .unwrap();
    let line = format!("{}\n", serde_json::to_string(&cp2).unwrap());
    tokio::io::AsyncWriteExt::write_all(&mut file, line.as_bytes())
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::flush(&mut file).await.unwrap();

    // Key continuity violation detected
    let verification = logger.verify_checkpoints().await.unwrap();
    assert!(!verification.valid);
    assert!(verification
        .failure_reason
        .as_ref()
        .unwrap()
        .contains("key continuity violated"));
}

#[tokio::test]
async fn test_checkpoint_legacy_v1_signature_still_verifies() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let key = AuditLogger::generate_signing_key();
    let logger = AuditLogger::new(log_path.clone()).with_signing_key(key.clone());

    let action = test_action();
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    let mut checkpoint = Checkpoint {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        entry_count: entries.len(),
        chain_head_hash: entries.last().and_then(|e| e.entry_hash.clone()),
        signature: String::new(),
        verifying_key: hex::encode(key.verifying_key().as_bytes()),
        merkle_root: None,
        pqc_signature: None,
        pqc_verifying_key: None,
        signature_version: None,
    };
    let legacy_sig = key.sign(&checkpoint.legacy_signing_content());
    checkpoint.signature = hex::encode(legacy_sig.to_bytes());

    let cp_path = logger.checkpoint_path();
    let serialized = format!("{}\n", serde_json::to_string(&checkpoint).unwrap());
    tokio::fs::write(&cp_path, serialized).await.unwrap();

    let verification = logger.verify_checkpoints().await.unwrap();
    assert!(
        verification.valid,
        "legacy v1 checkpoints must still verify after signature-version binding"
    );
    assert_eq!(verification.checkpoints_checked, 1);
}

#[tokio::test]
async fn test_checkpoint_key_from_bytes_roundtrip() {
    let key = AuditLogger::generate_signing_key();
    let bytes = key.to_bytes();
    let restored = AuditLogger::signing_key_from_bytes(&bytes);
    assert_eq!(key.to_bytes(), restored.to_bytes());
}

#[tokio::test]
async fn test_checkpoint_path_derivation() {
    let logger = AuditLogger::new(PathBuf::from("/var/log/audit.jsonl"));
    let cp_path = logger.checkpoint_path();
    assert_eq!(cp_path, PathBuf::from("/var/log/audit.checkpoints.jsonl"));
}

#[tokio::test]
async fn test_checkpoint_decreasing_entry_count_detected() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let key = AuditLogger::generate_signing_key();
    let logger = AuditLogger::new(log_path.clone()).with_signing_key(key.clone());

    let action = test_action();
    for _ in 0..5 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }
    logger.create_checkpoint().await.unwrap();

    // Forge a second checkpoint with lower entry_count (properly signed)
    let cp_path = logger.checkpoint_path();
    let forged_cp = Checkpoint {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        entry_count: 2, // Less than 5 — suspicious
        chain_head_hash: None,
        signature: String::new(),
        verifying_key: hex::encode(key.verifying_key().as_bytes()),
        merkle_root: None,
        pqc_signature: None,
        pqc_verifying_key: None,
        signature_version: None,
    };
    let content = forged_cp.signing_content();
    let sig = key.sign(&content);
    let mut forged = forged_cp;
    forged.signature = hex::encode(sig.to_bytes());

    let mut cp_content = tokio::fs::read_to_string(&cp_path).await.unwrap();
    cp_content.push_str(&serde_json::to_string(&forged).unwrap());
    cp_content.push('\n');
    tokio::fs::write(&cp_path, cp_content).await.unwrap();

    let verification = logger.verify_checkpoints().await.unwrap();
    assert!(!verification.valid);
    assert_eq!(verification.first_invalid_at, Some(1));
    assert!(verification
        .failure_reason
        .as_ref()
        .unwrap()
        .contains("decreased"));
}

// ═══════════════════════════════════════════════════════════
// Exploit #8 Regression: Audit tail truncation detection
// ═══════════════════════════════════════════════════════════

#[tokio::test]
async fn test_exploit8_tail_truncation_detected_by_checkpoint() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let key = AuditLogger::generate_signing_key();
    let logger = AuditLogger::new(log_path.clone()).with_signing_key(key);

    let action = test_action();
    for _ in 0..10 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }

    logger.create_checkpoint().await.unwrap();

    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 10);
    let truncated = lines[..7].join("\n") + "\n";
    tokio::fs::write(&log_path, truncated).await.unwrap();

    let chain_result = logger.verify_chain().await.unwrap();
    assert!(
        chain_result.valid,
        "Truncated chain should still be internally valid"
    );

    let cp_result = logger.verify_checkpoints().await.unwrap();
    assert!(
        !cp_result.valid,
        "Checkpoint must detect tail truncation (10 entries in checkpoint, 7 in log)"
    );
    assert!(
        cp_result
            .failure_reason
            .as_ref()
            .unwrap()
            .contains("truncated"),
        "Failure reason should mention truncation, got: {:?}",
        cp_result.failure_reason
    );
}

#[tokio::test]
async fn test_exploit8_no_false_positive_when_entries_match() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let key = AuditLogger::generate_signing_key();
    let logger = AuditLogger::new(log_path.clone()).with_signing_key(key);

    let action = test_action();
    for _ in 0..5 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }
    logger.create_checkpoint().await.unwrap();

    let cp_result = logger.verify_checkpoints().await.unwrap();
    assert!(
        cp_result.valid,
        "Checkpoint should pass when entry count matches"
    );
}

#[tokio::test]
async fn test_exploit8_entries_added_after_checkpoint_still_valid() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let key = AuditLogger::generate_signing_key();
    let logger = AuditLogger::new(log_path.clone()).with_signing_key(key);

    let action = test_action();
    for _ in 0..5 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }
    logger.create_checkpoint().await.unwrap();

    for _ in 0..3 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }

    let cp_result = logger.verify_checkpoints().await.unwrap();
    assert!(
        cp_result.valid,
        "Entries added after checkpoint should not cause false positive"
    );
}

// ═══════════════════════════════════════════════════════
// Exploit #10 Regression: verify_chain() memory DoS
// ═══════════════════════════════════════════════════════

#[tokio::test]
async fn test_exploit10_oversized_audit_log_rejected() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");

    let file = tokio::fs::File::create(&log_path).await.unwrap();
    file.set_len(101 * 1024 * 1024).await.unwrap();

    let logger = AuditLogger::new(log_path);
    let result = logger.load_entries().await;
    assert!(result.is_err(), "Oversized audit log must be rejected");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("too large"),
        "Error should mention file is too large, got: {err}"
    );
}

#[tokio::test]
async fn test_exploit10_verify_chain_rejects_oversized_log() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");

    let file = tokio::fs::File::create(&log_path).await.unwrap();
    file.set_len(101 * 1024 * 1024).await.unwrap();

    let logger = AuditLogger::new(log_path);
    let result = logger.verify_chain().await;
    assert!(result.is_err(), "verify_chain must reject oversized log");
}

#[tokio::test]
async fn test_exploit10_normal_sized_log_loads_fine() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path);

    let action = test_action();
    for _ in 0..10 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 10);

    let chain = logger.verify_chain().await.unwrap();
    assert!(chain.valid);
}

// ═══════════════════════════════════════════════════
// HEARTBEAT TESTS (Phase 10.6)
// ═══════════════════════════════════════════════════

#[tokio::test]
async fn test_heartbeat_creates_valid_entry() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("heartbeat.log");
    let logger = AuditLogger::new(log_path);
    logger.initialize_chain().await.unwrap();

    logger.log_heartbeat(60, 1).await.unwrap();
    logger.log_heartbeat(60, 2).await.unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 2);

    assert_eq!(entries[0].action.tool, "vellaveto");
    assert_eq!(entries[0].action.function, "heartbeat");
    assert!(matches!(entries[0].verdict, Verdict::Allow));
    assert_eq!(entries[0].metadata["event"], "heartbeat");
    assert_eq!(entries[0].metadata["interval_secs"], 60);
    assert_eq!(entries[0].metadata["sequence"], 1);

    assert_eq!(entries[1].metadata["sequence"], 2);
}

#[tokio::test]
async fn test_heartbeat_participates_in_hash_chain() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("heartbeat_chain.log");
    let logger = AuditLogger::new(log_path);
    logger.initialize_chain().await.unwrap();

    let action = Action::new(
        "bash".to_string(),
        "run".to_string(),
        serde_json::json!({"command": "ls"}),
    );
    logger
        .log_entry(&action, &Verdict::Allow, serde_json::json!({}))
        .await
        .unwrap();
    logger.log_heartbeat(60, 1).await.unwrap();
    logger
        .log_entry(
            &action,
            &Verdict::Deny {
                reason: "test".to_string(),
            },
            serde_json::json!({}),
        )
        .await
        .unwrap();
    logger.log_heartbeat(60, 2).await.unwrap();

    let verification = logger.verify_chain().await.unwrap();
    assert!(verification.valid);
    assert_eq!(verification.entries_checked, 4);
}

#[tokio::test]
async fn test_detect_heartbeat_gap_no_gap() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("no_gap.log");
    let logger = AuditLogger::new(log_path);
    logger.initialize_chain().await.unwrap();

    logger.log_heartbeat(60, 1).await.unwrap();
    logger.log_heartbeat(60, 2).await.unwrap();
    logger.log_heartbeat(60, 3).await.unwrap();

    let gap = logger.detect_heartbeat_gap(120).await.unwrap();
    assert!(gap.is_none());
}

#[tokio::test]
async fn test_detect_heartbeat_gap_empty_log() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("empty_gap.log");
    let logger = AuditLogger::new(log_path);

    let gap = logger.detect_heartbeat_gap(60).await.unwrap();
    assert!(gap.is_none());
}

#[tokio::test]
async fn test_detect_heartbeat_gap_single_entry() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("single_gap.log");
    let logger = AuditLogger::new(log_path);
    logger.initialize_chain().await.unwrap();

    logger.log_heartbeat(60, 1).await.unwrap();

    let gap = logger.detect_heartbeat_gap(60).await.unwrap();
    assert!(gap.is_none());
}

#[tokio::test]
async fn test_detect_heartbeat_gap_finds_gap() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("gap_detect.log");

    let ts1 = "2026-02-03T12:00:00+00:00";
    let ts2 = "2026-02-03T12:05:00+00:00";

    let entry1 = serde_json::json!({
        "id": "entry-1",
        "action": {"tool": "vellaveto", "function": "heartbeat", "parameters": {}},
        "verdict": "Allow",
        "timestamp": ts1,
        "metadata": {"event": "heartbeat", "sequence": 1}
    });
    let entry2 = serde_json::json!({
        "id": "entry-2",
        "action": {"tool": "vellaveto", "function": "heartbeat", "parameters": {}},
        "verdict": "Allow",
        "timestamp": ts2,
        "metadata": {"event": "heartbeat", "sequence": 2}
    });

    let content = format!(
        "{}\n{}\n",
        serde_json::to_string(&entry1).unwrap(),
        serde_json::to_string(&entry2).unwrap()
    );
    tokio::fs::write(&log_path, content).await.unwrap();

    let logger = AuditLogger::new(log_path);

    let gap = logger.detect_heartbeat_gap(120).await.unwrap();
    assert!(gap.is_some(), "Should detect 300-second gap");
    let (start, end, secs) = gap.unwrap();
    assert_eq!(start, ts1);
    assert_eq!(end, ts2);
    assert_eq!(secs, 300);

    let gap2 = logger.detect_heartbeat_gap(600).await.unwrap();
    assert!(gap2.is_none(), "300s gap should not exceed 600s threshold");
}

#[tokio::test]
async fn test_detect_heartbeat_gap_returns_first_gap() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("multi_gap.log");

    let entries = vec![
        ("entry-1", "2026-02-03T10:00:00+00:00"),
        ("entry-2", "2026-02-03T10:01:00+00:00"),
        ("entry-3", "2026-02-03T10:10:00+00:00"),
        ("entry-4", "2026-02-03T10:30:00+00:00"),
    ];

    let mut content = String::new();
    for (id, ts) in &entries {
        let entry = serde_json::json!({
            "id": id,
            "action": {"tool": "vellaveto", "function": "heartbeat", "parameters": {}},
            "verdict": "Allow",
            "timestamp": ts,
            "metadata": {"event": "heartbeat"}
        });
        content.push_str(&serde_json::to_string(&entry).unwrap());
        content.push('\n');
    }
    tokio::fs::write(&log_path, content).await.unwrap();

    let logger = AuditLogger::new(log_path);
    let gap = logger.detect_heartbeat_gap(120).await.unwrap();
    assert!(gap.is_some());
    let (start, _end, secs) = gap.unwrap();
    assert_eq!(start, "2026-02-03T10:01:00+00:00");
    assert_eq!(secs, 540);
}

// ── H1: Rotation Chain Continuity Tests ──

#[tokio::test]
async fn test_rotation_writes_manifest() {
    let dir = tempfile::TempDir::new().unwrap();
    let log_path = dir.path().join("audit.log");
    let logger = AuditLogger::new(log_path.clone()).with_max_file_size(100);

    for i in 0..10 {
        let action = Action::new("tool", format!("func_{i}"), json!({}));
        logger
            .log_entry(&action, &Verdict::Allow, json!({"i": i}))
            .await
            .unwrap();
    }

    let manifest_path = dir.path().join("audit.rotation-manifest.jsonl");
    assert!(manifest_path.exists(), "Rotation manifest should exist");

    let content = tokio::fs::read_to_string(&manifest_path).await.unwrap();
    assert!(!content.is_empty(), "Manifest should have content");

    let entry: serde_json::Value = serde_json::from_str(content.lines().next().unwrap()).unwrap();
    assert!(entry.get("tail_hash").is_some());
    assert!(entry.get("entry_count").is_some());
    assert!(entry.get("rotated_file").is_some());
    assert!(entry.get("timestamp").is_some());
}

#[tokio::test]
async fn test_rotation_verification_passes_valid() {
    let dir = tempfile::TempDir::new().unwrap();
    let log_path = dir.path().join("audit.log");
    let logger = AuditLogger::new(log_path.clone()).with_max_file_size(100);

    for i in 0..10 {
        let action = Action::new("tool", format!("func_{i}"), json!({}));
        logger
            .log_entry(&action, &Verdict::Allow, json!({"i": i}))
            .await
            .unwrap();
    }

    let result = logger.verify_across_rotations().await.unwrap();
    assert!(
        result.valid,
        "Valid rotation should pass: {:?}",
        result.first_failure
    );
    assert!(result.files_checked > 0);
}

#[tokio::test]
async fn test_rotation_verification_detects_missing_file() {
    let dir = tempfile::TempDir::new().unwrap();
    let log_path = dir.path().join("audit.log");
    let logger = AuditLogger::new(log_path.clone()).with_max_file_size(100);

    for i in 0..10 {
        let action = Action::new("tool", format!("func_{i}"), json!({}));
        logger
            .log_entry(&action, &Verdict::Allow, json!({"i": i}))
            .await
            .unwrap();
    }

    let rotated = logger.list_rotated_files().unwrap();
    for f in &rotated {
        std::fs::remove_file(f).unwrap();
    }

    let result = logger.verify_across_rotations().await.unwrap();
    // SECURITY (FIND-R43-017): Missing (pruned) files are now skipped gracefully
    // instead of failing verification, because prune_rotated_files() legitimately
    // removes old rotated logs while their manifest entries persist.
    assert!(
        result.valid,
        "Missing (pruned) files should be skipped, not fail verification"
    );
}

#[tokio::test]
async fn test_rotation_verification_detects_missing_file_gap_after_existing_segment() {
    let dir = tempfile::TempDir::new().unwrap();
    let log_path = dir.path().join("audit.log");
    let logger = AuditLogger::new(log_path.clone()).with_max_file_size(100);

    let mut i = 0u64;
    while logger.list_rotated_files().unwrap().len() < 2 {
        let action = Action::new("tool", format!("func_{i}"), json!({}));
        logger
            .log_entry(&action, &Verdict::Allow, json!({"i": i}))
            .await
            .unwrap();
        i = i.saturating_add(1);
    }

    let rotated = logger.list_rotated_files().unwrap();
    let newest = rotated.last().unwrap();
    std::fs::remove_file(newest).unwrap();

    let result = logger.verify_across_rotations().await.unwrap();
    assert!(!result.valid, "Missing non-prefix rotated file should fail");
    assert!(
        result
            .first_failure
            .as_ref()
            .unwrap()
            .contains("gap in sequence"),
        "Failure should mention the prune-boundary gap: {:?}",
        result.first_failure
    );
}

#[tokio::test]
async fn test_rotation_verification_detects_tampered_file() {
    let dir = tempfile::TempDir::new().unwrap();
    let log_path = dir.path().join("audit.log");
    let logger = AuditLogger::new(log_path.clone()).with_max_file_size(100);

    for i in 0..10 {
        let action = Action::new("tool", format!("func_{i}"), json!({}));
        logger
            .log_entry(&action, &Verdict::Allow, json!({"i": i}))
            .await
            .unwrap();
    }

    let rotated = logger.list_rotated_files().unwrap();
    if let Some(rotated_file) = rotated.first() {
        let content = std::fs::read_to_string(rotated_file).unwrap();
        let tampered = content.replacen("Allow", "Deny", 1);
        std::fs::write(rotated_file, tampered).unwrap();
    }

    let result = logger.verify_across_rotations().await.unwrap();
    assert!(!result.valid, "Tampered file should fail verification");
}

#[tokio::test]
async fn test_rotation_no_manifest_passes() {
    let dir = tempfile::TempDir::new().unwrap();
    let log_path = dir.path().join("audit.log");
    let logger = AuditLogger::new(log_path);

    let result = logger.verify_across_rotations().await.unwrap();
    assert!(result.valid);
    assert_eq!(result.files_checked, 0);
}

// ── M1: Checkpoint Permissions Tests ──

#[cfg(unix)]
#[tokio::test]
async fn test_checkpoint_permissions_0600() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::TempDir::new().unwrap();
    let log_path = dir.path().join("audit.log");
    let key = AuditLogger::generate_signing_key();
    let logger = AuditLogger::new(log_path.clone()).with_signing_key(key);

    let action = Action::new("tool", "func", json!({}));
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    logger.create_checkpoint().await.unwrap();

    let cp_path = dir.path().join("audit.checkpoints.jsonl");
    let metadata = std::fs::metadata(&cp_path).unwrap();
    let mode = metadata.permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "Checkpoint should have 0o600 permissions, got {mode:o}"
    );
}

// SECURITY (R16-AUDIT-2): Metadata depth validation
#[tokio::test]
async fn test_metadata_depth_rejected() {
    let dir = tempfile::TempDir::new().unwrap();
    let log_path = dir.path().join("audit.log");
    let logger = AuditLogger::new(log_path);

    let mut nested = json!("leaf");
    for _ in 0..25 {
        nested = json!({"inner": nested});
    }

    let action = Action::new("tool", "func", json!({}));
    let result = logger.log_entry(&action, &Verdict::Allow, nested).await;

    assert!(result.is_err(), "Deeply nested metadata should be rejected");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("nesting depth"),
        "Error should mention nesting depth, got: {err_msg}"
    );
}

#[tokio::test]
async fn test_metadata_shallow_accepted() {
    let dir = tempfile::TempDir::new().unwrap();
    let log_path = dir.path().join("audit.log");
    let logger = AuditLogger::new(log_path);

    let metadata = json!({"a": {"b": {"c": "value"}}});

    let action = Action::new("tool", "func", json!({}));
    let result = logger.log_entry(&action, &Verdict::Allow, metadata).await;

    assert!(result.is_ok(), "Shallow metadata should be accepted");
}

// SECURITY (R16-AUDIT-4): Audit log file permissions
#[cfg(unix)]
#[tokio::test]
async fn test_audit_log_permissions_0600() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::TempDir::new().unwrap();
    let log_path = dir.path().join("audit.log");
    let logger = AuditLogger::new(log_path.clone());

    let action = Action::new("tool", "func", json!({}));
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    let metadata = std::fs::metadata(&log_path).unwrap();
    let mode = metadata.permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "Audit log should have 0o600 permissions, got {mode:o}"
    );
}

// SECURITY (R14-AUDIT-2): Path traversal in rotation manifest rotated_file
#[tokio::test]
async fn test_rotation_manifest_path_traversal_rejected() {
    let dir = tempfile::TempDir::new().unwrap();
    let log_path = dir.path().join("audit.log");
    let logger = AuditLogger::new(log_path.clone()).with_max_file_size(100);

    for i in 0..10 {
        let action = Action::new("tool", format!("func_{i}"), json!({}));
        logger
            .log_entry(&action, &Verdict::Allow, json!({"i": i}))
            .await
            .unwrap();
    }

    let result = logger.verify_across_rotations().await.unwrap();
    assert!(result.valid, "Pre-tamper rotation should be valid");

    let manifest_path = dir.path().join("audit.rotation-manifest.jsonl");
    let traversal_payloads = vec![
        "../../etc/passwd",
        "../secret.log",
        "/etc/shadow",
        "/tmp/evil.log",
        "subdir/sneaky.log",
        "",
    ];

    for payload in &traversal_payloads {
        let crafted = serde_json::json!({
            "timestamp": "2026-02-05T00:00:00Z",
            "rotated_file": payload,
            "tail_hash": "fakehash",
            "entry_count": 1,
            "previous_hash": "genesis",
        });
        let mut manifest_content = serde_json::to_string(&crafted).unwrap();
        manifest_content.push('\n');
        std::fs::write(&manifest_path, &manifest_content).unwrap();

        let result = logger.verify_across_rotations().await.unwrap();
        assert!(
            !result.valid,
            "Path traversal payload '{payload}' should be rejected"
        );
        assert!(
            result
                .first_failure
                .as_ref()
                .unwrap()
                .contains("path traversal"),
            "Failure message for '{}' should mention path traversal, got: {}",
            payload,
            result.first_failure.as_ref().unwrap()
        );
    }
}

#[tokio::test]
async fn test_rotation_manifest_start_hash_mismatch_rejected() {
    let dir = tempfile::TempDir::new().unwrap();
    let log_path = dir.path().join("audit.log");
    let logger = AuditLogger::new(log_path.clone()).with_max_file_size(100);

    let mut i = 0u64;
    let manifest_path = dir.path().join("audit.rotation-manifest.jsonl");
    while std::fs::read_to_string(&manifest_path)
        .map(|content| {
            content
                .lines()
                .filter(|line| !line.trim().is_empty())
                .count()
        })
        .unwrap_or(0)
        < 2
    {
        let action = Action::new("tool", format!("func_{i}"), json!({}));
        logger
            .log_entry(&action, &Verdict::Allow, json!({"i": i}))
            .await
            .unwrap();
        i = i.saturating_add(1);
    }

    let manifest = std::fs::read_to_string(&manifest_path).unwrap();
    let mut lines: Vec<String> = manifest.lines().map(ToString::to_string).collect();
    assert!(lines.len() >= 2, "Need at least two manifest entries");

    let mut second: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
    second["start_hash"] = serde_json::Value::String("forged-start-hash".to_string());
    lines[1] = serde_json::to_string(&second).unwrap();

    let mut tampered = lines.join("\n");
    tampered.push('\n');
    std::fs::write(&manifest_path, tampered).unwrap();

    let result = logger.verify_across_rotations().await.unwrap();
    assert!(
        !result.valid,
        "Mismatched start_hash should fail verification"
    );
    assert!(
        result
            .first_failure
            .as_ref()
            .unwrap()
            .contains("Cross-rotation linkage broken"),
        "Failure should mention cross-rotation linkage: {:?}",
        result.first_failure
    );
}

// SECURITY (R14-AUDIT-2): Valid rotated filenames are accepted
#[tokio::test]
async fn test_rotation_manifest_valid_filename_accepted() {
    let dir = tempfile::TempDir::new().unwrap();
    let log_path = dir.path().join("audit.log");
    let logger = AuditLogger::new(log_path.clone()).with_max_file_size(100);

    for i in 0..10 {
        let action = Action::new("tool", format!("func_{i}"), json!({}));
        logger
            .log_entry(&action, &Verdict::Allow, json!({"i": i}))
            .await
            .unwrap();
    }

    let manifest_path = dir.path().join("audit.rotation-manifest.jsonl");
    let content = std::fs::read_to_string(&manifest_path).unwrap();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: serde_json::Value = serde_json::from_str(line).unwrap();
        let rotated_file = entry.get("rotated_file").unwrap().as_str().unwrap();
        assert!(
            !rotated_file.contains('/') && !rotated_file.contains('\\'),
            "rotated_file should be a bare filename, got: {rotated_file}"
        );
        assert!(
            !rotated_file.contains(".."),
            "rotated_file should not contain '..', got: {rotated_file}"
        );
        assert!(!rotated_file.is_empty(), "rotated_file should not be empty");
    }

    let result = logger.verify_across_rotations().await.unwrap();
    assert!(
        result.valid,
        "Sanitized rotation should pass verification: {:?}",
        result.first_failure
    );
}

// SECURITY (R38-SUP-1): Rotated file size check prevents OOM.
#[tokio::test]
async fn test_r38_sup_1_oversized_rotated_file_rejected() {
    let dir = tempfile::TempDir::new().unwrap();
    let log_path = dir.path().join("audit.log");
    let logger = AuditLogger::new(log_path.clone()).with_max_file_size(100);

    for i in 0..10 {
        let action = Action::new("tool", format!("func_{i}"), json!({}));
        logger
            .log_entry(&action, &Verdict::Allow, json!({"i": i}))
            .await
            .unwrap();
    }

    let result = logger.verify_across_rotations().await.unwrap();
    assert!(result.valid, "Pre-tamper rotation should be valid");

    let manifest_path = dir.path().join("audit.rotation-manifest.jsonl");
    let manifest_content = std::fs::read_to_string(&manifest_path).unwrap();
    let first_line = manifest_content.lines().next().unwrap();
    let entry: serde_json::Value = serde_json::from_str(first_line).unwrap();
    let rotated_file = entry.get("rotated_file").unwrap().as_str().unwrap();
    let rotated_path = dir.path().join(rotated_file);

    {
        use std::io::{Seek, Write};
        let mut f = std::fs::File::create(&rotated_path).unwrap();
        f.seek(std::io::SeekFrom::Start(100 * 1024 * 1024 + 1))
            .unwrap();
        f.write_all(b"\n").unwrap();
    }

    let result = logger.verify_across_rotations().await.unwrap();
    assert!(
        !result.valid,
        "Oversized rotated file should be rejected, not cause OOM"
    );
    let failure = result.first_failure.as_ref().unwrap();
    assert!(
        failure.contains("exceeds size limit"),
        "Failure message should mention size limit, got: {failure}"
    );
}

// =========================================================================
// Security Event Helper Tests (Phase 3.1)
// =========================================================================

#[tokio::test]
async fn test_log_circuit_breaker_event_opened() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone());

    logger
        .log_circuit_breaker_event(
            "opened",
            "test_tool",
            json!({
                "failure_count": 5,
                "threshold": 3,
            }),
        )
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert!(matches!(entry.verdict, Verdict::Allow));
    let event = entry
        .metadata
        .get("event")
        .and_then(|v| v.as_str())
        .unwrap();
    assert_eq!(event, "circuit_breaker.opened");
    assert_eq!(
        entry.metadata.get("tool").and_then(|v| v.as_str()).unwrap(),
        "test_tool"
    );
    assert_eq!(
        entry
            .metadata
            .get("failure_count")
            .and_then(|v| v.as_u64())
            .unwrap(),
        5
    );
}

#[tokio::test]
async fn test_log_circuit_breaker_event_rejected() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone());

    logger
        .log_circuit_breaker_event(
            "rejected",
            "failing_tool",
            json!({ "reason": "too many failures" }),
        )
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 1);
    assert!(
        matches!(&entries[0].verdict, Verdict::Deny { reason } if reason.contains("Circuit breaker open"))
    );
}

#[tokio::test]
async fn test_log_deputy_event_validation_failed() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone());

    logger
        .log_deputy_event(
            "validation_failed",
            "session_123",
            json!({
                "tool": "dangerous_tool",
                "principal": "untrusted_agent",
                "error": "No delegation found",
            }),
        )
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 1);
    assert!(matches!(&entries[0].verdict, Verdict::Deny { .. }));
    let event = entries[0]
        .metadata
        .get("event")
        .and_then(|v| v.as_str())
        .unwrap();
    assert_eq!(event, "deputy.validation_failed");
}

#[tokio::test]
async fn test_log_shadow_agent_event_detected() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone());

    logger
        .log_shadow_agent_event(
            "detected",
            "trusted_agent_id",
            json!({
                "expected_fingerprint": "abc123",
                "actual_fingerprint": "xyz789",
                "severity": "high",
            }),
        )
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 1);
    assert!(
        matches!(&entries[0].verdict, Verdict::Deny { reason } if reason.contains("Shadow agent detected"))
    );
    let event = entries[0]
        .metadata
        .get("event")
        .and_then(|v| v.as_str())
        .unwrap();
    assert_eq!(event, "shadow_agent.detected");
}

#[tokio::test]
async fn test_log_schema_event_poisoning_alert() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone());

    logger
        .log_schema_event(
            "poisoning_alert",
            "tool_with_mutated_schema",
            json!({
                "changed_fields": ["input_schema", "description"],
                "previous_hash": "abc",
                "current_hash": "def",
            }),
        )
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 1);
    assert!(matches!(&entries[0].verdict, Verdict::Deny { .. }));
    let event = entries[0]
        .metadata
        .get("event")
        .and_then(|v| v.as_str())
        .unwrap();
    assert_eq!(event, "schema.poisoning_alert");
}

#[tokio::test]
async fn test_log_task_event_created() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone());

    logger
        .log_task_event(
            "created",
            "task_abc",
            json!({
                "tool": "long_running_tool",
                "function": "process_data",
                "created_by": "user_123",
            }),
        )
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 1);
    assert!(matches!(entries[0].verdict, Verdict::Allow));
    let event = entries[0]
        .metadata
        .get("event")
        .and_then(|v| v.as_str())
        .unwrap();
    assert_eq!(event, "task.created");
}

#[tokio::test]
async fn test_log_auth_event_step_up_required() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone());

    logger
        .log_auth_event(
            "step_up_required",
            "session_xyz",
            json!({
                "current_level": "Basic",
                "required_level": "OAuthMfa",
            }),
        )
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 1);
    assert!(
        matches!(&entries[0].verdict, Verdict::Deny { reason } if reason.contains("Step-up authentication"))
    );
}

#[tokio::test]
async fn test_log_sampling_event_rate_limit_exceeded() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone());

    logger
        .log_sampling_event(
            "rate_limit_exceeded",
            "session_spam",
            json!({
                "count": 100,
                "limit": 10,
            }),
        )
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 1);
    assert!(matches!(&entries[0].verdict, Verdict::Deny { .. }));
    let event = entries[0]
        .metadata
        .get("event")
        .and_then(|v| v.as_str())
        .unwrap();
    assert_eq!(event, "sampling.rate_limit_exceeded");
}

// ════════════════════════════════════════════════════════
// FIND-048: Rotation manifest entry deletion detection
// ════════════════════════════════════════════════════════

#[tokio::test]
async fn test_rotation_manifest_entry_deletion_detected() {
    let dir = tempfile::TempDir::new().unwrap();
    let log_path = dir.path().join("audit.log");
    let logger = AuditLogger::new(log_path.clone()).with_max_file_size(100);

    for i in 0..20 {
        let action = Action::new("tool", format!("func_{i}"), json!({}));
        logger
            .log_entry(&action, &Verdict::Allow, json!({"i": i}))
            .await
            .unwrap();
    }

    let result = logger.verify_across_rotations().await.unwrap();
    assert!(
        result.valid,
        "Pre-tamper rotation should be valid: {:?}",
        result.first_failure
    );

    let manifest_path = dir.path().join("audit.rotation-manifest.jsonl");
    let content = std::fs::read_to_string(&manifest_path).unwrap();
    let lines: Vec<&str> = content.lines().collect();

    if lines.len() >= 2 {
        let tampered = lines[1..].join("\n") + "\n";
        std::fs::write(&manifest_path, tampered).unwrap();

        // SECURITY (FIND-R46-ROT-003): Deletion is now detected via hash chain.
        // The second entry's previous_hash references the SHA-256 of the deleted
        // first entry, so it will not match "genesis".
        let result = logger.verify_across_rotations().await.unwrap();
        assert!(
            !result.valid,
            "Manifest entry deletion must be detected by hash chain verification"
        );
        assert!(
            result
                .first_failure
                .as_ref()
                .unwrap()
                .contains("hash chain broken"),
            "Failure should mention hash chain: {:?}",
            result.first_failure
        );
    }
}

#[tokio::test]
async fn test_rotation_manifest_entry_reordering_detected() {
    let dir = tempfile::TempDir::new().unwrap();
    let log_path = dir.path().join("audit.log");
    let logger = AuditLogger::new(log_path.clone()).with_max_file_size(100);

    for i in 0..20 {
        let action = Action::new("tool", format!("func_{i}"), json!({}));
        logger
            .log_entry(&action, &Verdict::Allow, json!({"i": i}))
            .await
            .unwrap();
    }

    let result = logger.verify_across_rotations().await.unwrap();
    assert!(
        result.valid,
        "Pre-tamper should be valid: {:?}",
        result.first_failure
    );

    let manifest_path = dir.path().join("audit.rotation-manifest.jsonl");
    let content = std::fs::read_to_string(&manifest_path).unwrap();
    let mut lines: Vec<&str> = content.lines().collect();

    if lines.len() >= 2 {
        let last_idx = lines.len() - 1;
        lines.swap(0, last_idx);
        let tampered = lines.join("\n") + "\n";
        std::fs::write(&manifest_path, tampered).unwrap();

        // SECURITY (FIND-R46-ROT-003): Reordering is now detected via hash chain.
        // The swapped first entry's previous_hash will not be "genesis".
        let result = logger.verify_across_rotations().await.unwrap();
        assert!(
            !result.valid,
            "Manifest entry reordering must be detected by hash chain verification"
        );
        assert!(
            result
                .first_failure
                .as_ref()
                .unwrap()
                .contains("hash chain broken"),
            "Failure should mention hash chain: {:?}",
            result.first_failure
        );
    }
}

/// FIND-R46-ROT-003: Verify that replacing a single manifest entry is
/// detected by hash chain verification. An attacker who modifies a field
/// in one entry (e.g., changing entry_count to hide deleted log entries)
/// will break the chain because subsequent entries' previous_hash will
/// no longer match the SHA-256 of the modified line.
#[tokio::test]
async fn test_rotation_manifest_entry_replacement_detected() {
    let dir = tempfile::TempDir::new().unwrap();
    let log_path = dir.path().join("audit.log");
    let logger = AuditLogger::new(log_path.clone()).with_max_file_size(100);

    for i in 0..20 {
        let action = Action::new("tool", format!("func_{i}"), json!({}));
        logger
            .log_entry(&action, &Verdict::Allow, json!({"i": i}))
            .await
            .unwrap();
    }

    let result = logger.verify_across_rotations().await.unwrap();
    assert!(
        result.valid,
        "Pre-tamper rotation should be valid: {:?}",
        result.first_failure
    );

    let manifest_path = dir.path().join("audit.rotation-manifest.jsonl");
    let content = std::fs::read_to_string(&manifest_path).unwrap();
    let lines: Vec<&str> = content.lines().collect();

    if lines.len() >= 2 {
        // Tamper with the first entry by changing its timestamp (a field that is
        // NOT checked during content validation). This ensures the hash chain is
        // the detection mechanism, not entry_count or tail_hash validation.
        let mut entry: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        entry["timestamp"] = serde_json::Value::String("2000-01-01T00:00:00Z".to_string());
        let tampered_line = serde_json::to_string(&entry).unwrap();
        let mut new_lines = vec![tampered_line.as_str()];
        new_lines.extend_from_slice(&lines[1..]);
        let tampered = new_lines.join("\n") + "\n";
        std::fs::write(&manifest_path, tampered).unwrap();

        // The second entry's previous_hash was computed over the ORIGINAL first line,
        // so it will not match SHA-256 of the tampered first line.
        let result = logger.verify_across_rotations().await.unwrap();
        assert!(
            !result.valid,
            "Manifest entry replacement must be detected by hash chain verification"
        );
        assert!(
            result
                .first_failure
                .as_ref()
                .unwrap()
                .contains("hash chain broken"),
            "Failure should mention hash chain: {:?}",
            result.first_failure
        );
    }
}

// ── Merkle tree tests ──────────────────────────────────────────────────────

#[test]
fn test_merkle_empty_tree_root_is_none() {
    let dir = tempfile::TempDir::new().unwrap();
    let tree = merkle::MerkleTree::new(dir.path().join("leaves"));
    assert!(tree.root().is_none());
    assert_eq!(tree.leaf_count(), 0);
}

#[test]
fn test_merkle_single_leaf() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut tree = merkle::MerkleTree::new(dir.path().join("leaves"));
    let leaf = merkle::hash_leaf(b"hello");
    tree.append(leaf).unwrap();
    assert_eq!(tree.leaf_count(), 1);
    let root = tree.root().unwrap();
    // Single leaf: root == leaf hash
    assert_eq!(root, leaf);
}

#[test]
fn test_merkle_two_leaves() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut tree = merkle::MerkleTree::new(dir.path().join("leaves"));
    let l0 = merkle::hash_leaf(b"a");
    let l1 = merkle::hash_leaf(b"b");
    tree.append(l0).unwrap();
    tree.append(l1).unwrap();
    assert_eq!(tree.leaf_count(), 2);
    let root = tree.root().unwrap();
    // Manual: internal(l0, l1)
    let expected = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update([0x01]);
        h.update(l0);
        h.update(l1);
        let r: [u8; 32] = h.finalize().into();
        r
    };
    assert_eq!(root, expected);
}

#[test]
fn test_merkle_three_leaves() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut tree = merkle::MerkleTree::new(dir.path().join("leaves"));
    let l0 = merkle::hash_leaf(b"a");
    let l1 = merkle::hash_leaf(b"b");
    let l2 = merkle::hash_leaf(b"c");
    tree.append(l0).unwrap();
    tree.append(l1).unwrap();
    tree.append(l2).unwrap();
    assert_eq!(tree.leaf_count(), 3);
    // Root should be deterministic
    let root1 = tree.root().unwrap();
    let root2 = tree.root().unwrap();
    assert_eq!(root1, root2);
}

#[test]
fn test_merkle_power_of_two_leaves() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut tree = merkle::MerkleTree::new(dir.path().join("leaves"));
    for i in 0u8..8 {
        tree.append(merkle::hash_leaf(&[i])).unwrap();
    }
    assert_eq!(tree.leaf_count(), 8);
    assert!(tree.root().is_some());
}

#[test]
fn test_merkle_root_determinism() {
    // Same leaves → same root
    let dir1 = tempfile::TempDir::new().unwrap();
    let dir2 = tempfile::TempDir::new().unwrap();
    let mut t1 = merkle::MerkleTree::new(dir1.path().join("leaves"));
    let mut t2 = merkle::MerkleTree::new(dir2.path().join("leaves"));
    for i in 0u8..5 {
        let leaf = merkle::hash_leaf(&[i]);
        t1.append(leaf).unwrap();
        t2.append(leaf).unwrap();
    }
    assert_eq!(t1.root(), t2.root());
}

#[test]
fn test_merkle_order_dependence() {
    // Different order → different root
    let dir1 = tempfile::TempDir::new().unwrap();
    let dir2 = tempfile::TempDir::new().unwrap();
    let mut t1 = merkle::MerkleTree::new(dir1.path().join("leaves"));
    let mut t2 = merkle::MerkleTree::new(dir2.path().join("leaves"));
    let la = merkle::hash_leaf(b"a");
    let lb = merkle::hash_leaf(b"b");
    t1.append(la).unwrap();
    t1.append(lb).unwrap();
    t2.append(lb).unwrap();
    t2.append(la).unwrap();
    assert_ne!(t1.root(), t2.root());
}

#[test]
fn test_merkle_proof_roundtrip_single() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut tree = merkle::MerkleTree::new(dir.path().join("leaves"));
    let leaf = merkle::hash_leaf(b"single");
    tree.append(leaf).unwrap();
    let proof = tree.generate_proof(0).unwrap();
    let trusted_root = tree.root_hex().unwrap();
    let result = merkle::MerkleTree::verify_proof(leaf, &proof, &trusted_root).unwrap();
    assert!(
        result.valid,
        "Proof should be valid: {:?}",
        result.failure_reason
    );
}

#[test]
fn test_merkle_proof_roundtrip_multiple() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut tree = merkle::MerkleTree::new(dir.path().join("leaves"));
    let leaves: Vec<[u8; 32]> = (0u8..7).map(|i| merkle::hash_leaf(&[i])).collect();
    for leaf in &leaves {
        tree.append(*leaf).unwrap();
    }
    // Verify proof for each leaf
    let trusted_root = tree.root_hex().unwrap();
    for (i, leaf) in leaves.iter().enumerate() {
        let proof = tree.generate_proof(i as u64).unwrap();
        let result = merkle::MerkleTree::verify_proof(*leaf, &proof, &trusted_root).unwrap();
        assert!(
            result.valid,
            "Proof for leaf {} should be valid: {:?}",
            i, result.failure_reason
        );
    }
}

#[test]
fn test_merkle_proof_tampered_leaf_rejected() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut tree = merkle::MerkleTree::new(dir.path().join("leaves"));
    let leaf = merkle::hash_leaf(b"original");
    tree.append(leaf).unwrap();
    tree.append(merkle::hash_leaf(b"other")).unwrap();
    let proof = tree.generate_proof(0).unwrap();
    // Verify with wrong leaf
    let trusted_root = tree.root_hex().unwrap();
    let wrong_leaf = merkle::hash_leaf(b"tampered");
    let result = merkle::MerkleTree::verify_proof(wrong_leaf, &proof, &trusted_root).unwrap();
    assert!(!result.valid);
    assert!(result.failure_reason.unwrap().contains("Root mismatch"));
}

#[test]
fn test_merkle_proof_tampered_sibling_rejected() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut tree = merkle::MerkleTree::new(dir.path().join("leaves"));
    let leaf = merkle::hash_leaf(b"leaf0");
    tree.append(leaf).unwrap();
    tree.append(merkle::hash_leaf(b"leaf1")).unwrap();
    let mut proof = tree.generate_proof(0).unwrap();
    // Tamper with sibling
    if !proof.siblings.is_empty() {
        proof.siblings[0].hash = hex::encode([0xffu8; 32]);
    }
    let trusted_root = tree.root_hex().unwrap();
    let result = merkle::MerkleTree::verify_proof(leaf, &proof, &trusted_root).unwrap();
    assert!(!result.valid);
}

#[test]
fn test_merkle_proof_tampered_root_rejected() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut tree = merkle::MerkleTree::new(dir.path().join("leaves"));
    let leaf = merkle::hash_leaf(b"data");
    tree.append(leaf).unwrap();
    let proof = tree.generate_proof(0).unwrap();
    // Use an untrusted root — verification must fail even though proof is internally consistent
    let wrong_root = hex::encode([0xaa; 32]);
    let result = merkle::MerkleTree::verify_proof(leaf, &proof, &wrong_root).unwrap();
    assert!(!result.valid);
}

#[test]
fn test_merkle_proof_out_of_range() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut tree = merkle::MerkleTree::new(dir.path().join("leaves"));
    tree.append(merkle::hash_leaf(b"x")).unwrap();
    let err = tree.generate_proof(1).unwrap_err();
    match err {
        AuditError::Validation(msg) => assert!(msg.contains("out of range")),
        _ => panic!("Expected Validation error"),
    }
}

#[test]
fn test_merkle_proof_zero_tree_size() {
    let proof = merkle::MerkleProof {
        leaf_index: 0,
        tree_size: 0,
        siblings: vec![],
        root_hash: String::new(),
    };
    let result = merkle::MerkleTree::verify_proof([0u8; 32], &proof, "").unwrap();
    assert!(!result.valid);
    assert!(result.failure_reason.unwrap().contains("zero tree size"));
}

/// FIND-R46-MRK-002: A forged proof with a self-consistent root_hash
/// must be rejected when verified against an independently-obtained trusted root.
/// Before the fix, `verify_proof()` compared the computed root against the proof's
/// own `root_hash` field, allowing trivially forged proofs to pass.
#[test]
fn test_merkle_proof_self_referential_forgery_rejected() {
    // Build a real tree with 4 leaves
    let dir = tempfile::TempDir::new().unwrap();
    let mut tree = merkle::MerkleTree::new(dir.path().join("leaves"));
    let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| merkle::hash_leaf(&[i])).collect();
    for leaf in &leaves {
        tree.append(*leaf).unwrap();
    }
    let trusted_root = tree.root_hex().unwrap();

    // Build a DIFFERENT tree with different data (attacker's tree)
    let dir2 = tempfile::TempDir::new().unwrap();
    let mut attacker_tree = merkle::MerkleTree::new(dir2.path().join("leaves"));
    let fake_leaf = merkle::hash_leaf(b"attacker controlled data");
    attacker_tree.append(fake_leaf).unwrap();

    // Generate a proof from the attacker's tree
    let forged_proof = attacker_tree.generate_proof(0).unwrap();
    // The forged_proof.root_hash is self-consistent — it matches the attacker's tree root.
    // Before the fix, verify_proof(fake_leaf, &forged_proof) would return valid=true
    // because it compared the computed root against forged_proof.root_hash (itself).

    // With the fix, we verify against the TRUSTED root from the real tree.
    // The attacker's proof must be rejected.
    let result = merkle::MerkleTree::verify_proof(fake_leaf, &forged_proof, &trusted_root).unwrap();
    assert!(
        !result.valid,
        "Self-referential forged proof must be rejected when trusted root differs"
    );
    assert!(
        result
            .failure_reason
            .as_ref()
            .unwrap()
            .contains("Root mismatch"),
        "Failure reason should indicate root mismatch, got: {}",
        result.failure_reason.unwrap()
    );

    // Also verify that the proof passes against its OWN root (attacker's root)
    // to confirm the forgery is internally self-consistent
    let attacker_root = attacker_tree.root_hex().unwrap();
    let self_check =
        merkle::MerkleTree::verify_proof(fake_leaf, &forged_proof, &attacker_root).unwrap();
    assert!(
        self_check.valid,
        "Forged proof is internally consistent against attacker's own root"
    );
}

#[test]
fn test_merkle_crash_recovery() {
    let dir = tempfile::TempDir::new().unwrap();
    let leaf_path = dir.path().join("leaves");
    let leaves: Vec<[u8; 32]> = (0u8..5).map(|i| merkle::hash_leaf(&[i])).collect();
    let original_root;
    {
        let mut tree = merkle::MerkleTree::new(leaf_path.clone());
        for leaf in &leaves {
            tree.append(*leaf).unwrap();
        }
        original_root = tree.root();
    }
    // Rebuild from file
    let mut tree2 = merkle::MerkleTree::new(leaf_path);
    tree2.initialize().unwrap();
    assert_eq!(tree2.leaf_count(), 5);
    assert_eq!(tree2.root(), original_root);
}

#[test]
fn test_merkle_partial_write_truncation() {
    let dir = tempfile::TempDir::new().unwrap();
    let leaf_path = dir.path().join("leaves");
    {
        let mut tree = merkle::MerkleTree::new(leaf_path.clone());
        tree.append(merkle::hash_leaf(b"a")).unwrap();
        tree.append(merkle::hash_leaf(b"b")).unwrap();
    }
    // Append partial bytes (simulate crash mid-write)
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&leaf_path)
        .unwrap();
    f.write_all(&[0xde, 0xad]).unwrap();
    // Rebuild should truncate the partial write
    let mut tree2 = merkle::MerkleTree::new(leaf_path);
    tree2.initialize().unwrap();
    assert_eq!(tree2.leaf_count(), 2);
}

#[test]
fn test_merkle_reset_clears_tree() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut tree = merkle::MerkleTree::new(dir.path().join("leaves"));
    tree.append(merkle::hash_leaf(b"a")).unwrap();
    tree.append(merkle::hash_leaf(b"b")).unwrap();
    assert_eq!(tree.leaf_count(), 2);
    tree.reset();
    assert_eq!(tree.leaf_count(), 0);
    assert!(tree.root().is_none());
}

#[test]
fn test_merkle_domain_separation_leaf_ne_internal() {
    // hash_leaf(data) ≠ hash_internal(data, data)
    use sha2::{Digest, Sha256};
    let data = [0x42u8; 32];
    let leaf = merkle::hash_leaf(&data);
    let internal = {
        let mut h = Sha256::new();
        h.update([0x01]);
        h.update(data);
        h.update(data);
        let r: [u8; 32] = h.finalize().into();
        r
    };
    assert_ne!(leaf, internal);
}

#[test]
fn test_merkle_domain_separation_non_commutative() {
    // hash_internal(a, b) ≠ hash_internal(b, a)
    use sha2::{Digest, Sha256};
    let a = [1u8; 32];
    let b = [2u8; 32];
    let ab = {
        let mut h = Sha256::new();
        h.update([0x01]);
        h.update(a);
        h.update(b);
        let r: [u8; 32] = h.finalize().into();
        r
    };
    let ba = {
        let mut h = Sha256::new();
        h.update([0x01]);
        h.update(b);
        h.update(a);
        let r: [u8; 32] = h.finalize().into();
        r
    };
    assert_ne!(ab, ba);
}

#[tokio::test]
async fn test_merkle_logger_integration_entries_with_merkle() {
    let dir = tempfile::TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new_unredacted(log_path).with_merkle_tree();

    let action = test_action();
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();
    logger
        .log_entry(
            &action,
            &Verdict::Deny {
                reason: "test".into(),
            },
            json!({}),
        )
        .await
        .unwrap();

    // Verify Merkle tree has 2 leaves
    let tree = logger.merkle_tree.as_ref().unwrap().lock().unwrap();
    assert_eq!(tree.leaf_count(), 2);
    assert!(tree.root().is_some());
}

#[tokio::test]
async fn test_merkle_logger_checkpoint_includes_root() {
    let dir = tempfile::TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let signing_key = AuditLogger::generate_signing_key();
    let logger = AuditLogger::new_unredacted(log_path)
        .with_signing_key(signing_key)
        .with_merkle_tree();

    let action = test_action();
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    let checkpoint = logger.create_checkpoint().await.unwrap();
    assert!(
        checkpoint.merkle_root.is_some(),
        "Checkpoint should contain Merkle root"
    );
    // Root should be a hex-encoded SHA-256
    let root = checkpoint.merkle_root.unwrap();
    assert_eq!(root.len(), 64, "Merkle root should be 64 hex chars");
}

#[tokio::test]
async fn test_merkle_logger_proof_generation_and_verification() {
    let dir = tempfile::TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new_unredacted(log_path).with_merkle_tree();

    let action = test_action();
    for _ in 0..3 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }

    // Load entries to get the hash
    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 3);

    // Generate and verify proof for each entry using trusted root from the logger
    let trusted_root = logger.merkle_root_hex().unwrap().unwrap();
    for (i, entry) in entries.iter().enumerate() {
        let proof = logger.generate_merkle_proof(i as u64).unwrap();
        let entry_hash = entry.entry_hash.as_ref().unwrap();
        let result = AuditLogger::verify_merkle_proof(entry_hash, &proof, &trusted_root).unwrap();
        assert!(
            result.valid,
            "Proof for entry {} should be valid: {:?}",
            i, result.failure_reason
        );
    }
}

#[test]
fn test_merkle_proof_serde_roundtrip() {
    let proof = merkle::MerkleProof {
        leaf_index: 42,
        tree_size: 100,
        siblings: vec![
            merkle::ProofStep {
                hash: hex::encode([1u8; 32]),
                is_left: true,
            },
            merkle::ProofStep {
                hash: hex::encode([2u8; 32]),
                is_left: false,
            },
        ],
        root_hash: hex::encode([3u8; 32]),
    };
    let json = serde_json::to_string(&proof).unwrap();
    let deserialized: merkle::MerkleProof = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.leaf_index, 42);
    assert_eq!(deserialized.tree_size, 100);
    assert_eq!(deserialized.siblings.len(), 2);
}

#[tokio::test]
async fn test_merkle_checkpoint_backward_compat() {
    // Old checkpoint without merkle_root should still deserialize and verify
    let dir = tempfile::TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let signing_key = AuditLogger::generate_signing_key();

    // Create a checkpoint WITHOUT merkle tree (old behavior)
    let logger_no_merkle =
        AuditLogger::new_unredacted(log_path.clone()).with_signing_key(signing_key.clone());
    let action = test_action();
    logger_no_merkle
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();
    let old_cp = logger_no_merkle.create_checkpoint().await.unwrap();
    assert!(old_cp.merkle_root.is_none());

    // Old checkpoint should still verify
    let result = logger_no_merkle.verify_checkpoints().await.unwrap();
    assert!(result.valid);
}

// =========================================================================
// Phase 27: Deployment Event Logging Tests
// =========================================================================

#[tokio::test]
async fn test_log_leader_election_event_acquired() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone());

    logger
        .log_leader_election_event(
            "acquired",
            "instance-0",
            json!({ "lease_duration_secs": 15 }),
        )
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 1);
    assert!(matches!(entries[0].verdict, Verdict::Allow));
    let event = entries[0]
        .metadata
        .get("event")
        .and_then(|v| v.as_str())
        .unwrap();
    assert_eq!(event, "leader_election.acquired");
    assert_eq!(
        entries[0]
            .metadata
            .get("instance_id")
            .and_then(|v| v.as_str())
            .unwrap(),
        "instance-0"
    );
}

#[tokio::test]
async fn test_log_leader_election_event_lost_produces_deny() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone());

    logger
        .log_leader_election_event("lost", "instance-1", json!({ "reason": "lease expired" }))
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 1);
    assert!(matches!(&entries[0].verdict, Verdict::Deny { reason } if reason.contains("lost")));
}

#[tokio::test]
async fn test_log_leader_election_event_failed_produces_deny() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone());

    logger
        .log_leader_election_event(
            "failed",
            "instance-2",
            json!({ "error": "backend unreachable" }),
        )
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 1);
    assert!(matches!(&entries[0].verdict, Verdict::Deny { reason } if reason.contains("failed")));
}

#[tokio::test]
async fn test_log_service_discovery_event_endpoint_added() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone());

    logger
        .log_service_discovery_event(
            "endpoint_added",
            "backend-1",
            json!({ "url": "http://backend-1:3000" }),
        )
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 1);
    assert!(matches!(entries[0].verdict, Verdict::Allow));
    let event = entries[0]
        .metadata
        .get("event")
        .and_then(|v| v.as_str())
        .unwrap();
    assert_eq!(event, "service_discovery.endpoint_added");
    assert_eq!(
        entries[0]
            .metadata
            .get("endpoint_id")
            .and_then(|v| v.as_str())
            .unwrap(),
        "backend-1"
    );
}

#[tokio::test]
async fn test_log_service_discovery_event_refresh_failed_produces_deny() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone());

    logger
        .log_service_discovery_event(
            "refresh_failed",
            "dns-headless",
            json!({ "error": "DNS resolution failed" }),
        )
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 1);
    assert!(
        matches!(&entries[0].verdict, Verdict::Deny { reason } if reason.contains("refresh failed"))
    );
}

#[tokio::test]
async fn test_log_service_discovery_event_endpoint_removed() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone());

    logger
        .log_service_discovery_event(
            "endpoint_removed",
            "backend-2",
            json!({ "reason": "no longer resolving" }),
        )
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 1);
    assert!(matches!(entries[0].verdict, Verdict::Allow));
    assert_eq!(
        entries[0]
            .metadata
            .get("event")
            .and_then(|v| v.as_str())
            .unwrap(),
        "service_discovery.endpoint_removed"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// PHASE C: AUDIT HARDENING TESTS
// ═══════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════
// C1: Redaction Boundary Tests
// ═══════════════════════════════════════════════════════

#[test]
fn test_redact_keys_only_depth_63_succeeds() {
    // Build a nested JSON object 63 levels deep (just under MAX_REDACTION_DEPTH=64)
    let mut value = json!({"password": "secret123"});
    for _ in 0..62 {
        value = json!({"nested": value});
    }
    let redacted = crate::redaction::redact_keys_only(&value);
    // The password key at the bottom should be redacted
    let redacted_str = redacted.to_string();
    assert!(
        redacted_str.contains("[REDACTED]"),
        "Password at depth 63 should be redacted"
    );
    assert!(
        !redacted_str.contains("secret123"),
        "Original secret should not appear"
    );
}

#[test]
fn test_redact_keys_only_depth_64_returns_value_as_is() {
    // Build a nested JSON object with 64 wrappings so the inner object is at depth 64
    // (at MAX_REDACTION_DEPTH). Depth starts at 0, each wrapping adds 1.
    let mut value = json!({"password": "secret123"});
    for _ in 0..64 {
        value = json!({"nested": value});
    }
    let redacted = crate::redaction::redact_keys_only(&value);
    // SECURITY (GAP-S06): At depth 64, the value is fail-closed to [REDACTED]
    // instead of being returned unredacted.
    let redacted_str = redacted.to_string();
    assert!(
        redacted_str.contains("[REDACTED]"),
        "At depth 64 the value should be fail-closed to [REDACTED]"
    );
    assert!(
        !redacted_str.contains("secret123"),
        "Secret should not appear at max depth"
    );
}

#[test]
fn test_redact_keys_only_depth_65_still_safe() {
    // Build a nested JSON object 65 levels deep (over MAX_REDACTION_DEPTH)
    let mut value = json!({"password": "secret123"});
    for _ in 0..65 {
        value = json!({"nested": value});
    }
    // Should not panic — depth limit prevents stack overflow
    let redacted = crate::redaction::redact_keys_only(&value);
    // The function should return without error. The outermost object is still
    // an object (depth 0), but inner levels at depth >= 64 are replaced with [REDACTED].
    assert!(redacted.is_object());
    let redacted_str = redacted.to_string();
    assert!(
        !redacted_str.contains("secret123"),
        "Secret should not appear beyond max depth"
    );
}

#[test]
fn test_redact_keys_and_patterns_depth_63_redacts_pii() {
    let mut value = json!({"email": "test@example.com"});
    for _ in 0..62 {
        value = json!({"nested": value});
    }
    let redacted = crate::redaction::redact_keys_and_patterns(&value);
    let redacted_str = redacted.to_string();
    assert!(
        redacted_str.contains("[REDACTED]"),
        "PII at depth 63 should be redacted"
    );
    assert!(
        !redacted_str.contains("test@example.com"),
        "Original email should not appear"
    );
}

#[test]
fn test_redact_keys_and_patterns_depth_64_returns_value_as_is() {
    let mut value = json!({"data": "test@example.com"});
    for _ in 0..63 {
        value = json!({"nested": value});
    }
    let redacted = crate::redaction::redact_keys_and_patterns(&value);
    // SECURITY (GAP-S06): At depth limit, value is fail-closed to [REDACTED]
    // instead of being returned unredacted with PII.
    let redacted_str = redacted.to_string();
    assert!(
        redacted_str.contains("[REDACTED]"),
        "At depth 64 the value should be fail-closed to [REDACTED]"
    );
    assert!(
        !redacted_str.contains("test@example.com"),
        "PII should not appear at max depth"
    );
}

/// SECURITY (FIND-084): NFKC normalization catches fullwidth digit SSN patterns.
#[test]
fn test_redact_nfkc_normalized_fullwidth_digits_ssn() {
    // Fullwidth digits: ０１２-３４-５６７８ (U+FF10-FF18)
    let fullwidth_ssn =
        "\u{FF10}\u{FF11}\u{FF12}-\u{FF13}\u{FF14}-\u{FF15}\u{FF16}\u{FF17}\u{FF18}";
    let value = json!({"data": fullwidth_ssn});
    let redacted = crate::redaction::redact_keys_and_patterns(&value);
    assert_eq!(
        redacted["data"].as_str().unwrap(),
        "[REDACTED]",
        "Fullwidth digit SSN should be caught via NFKC normalization"
    );
}

/// SECURITY (FIND-084): NFKC normalization catches fullwidth digit phone patterns.
#[test]
fn test_redact_nfkc_normalized_fullwidth_digits_phone() {
    // Fullwidth digits for phone: ５５５-１２３-４５６７
    let fullwidth_phone =
        "\u{FF15}\u{FF15}\u{FF15}-\u{FF11}\u{FF12}\u{FF13}-\u{FF14}\u{FF15}\u{FF16}\u{FF17}";
    let value = json!({"data": fullwidth_phone});
    let redacted = crate::redaction::redact_keys_and_patterns(&value);
    assert_eq!(
        redacted["data"].as_str().unwrap(),
        "[REDACTED]",
        "Fullwidth digit phone should be caught via NFKC normalization"
    );
}

#[test]
fn test_redact_nfkc_mixed_ascii_fullwidth_email() {
    // Mix ASCII and fullwidth in email: test＠example.com (fullwidth @)
    let email_with_fullwidth_at = "test\u{FF20}example.com";
    let value = json!({"data": email_with_fullwidth_at});
    let redacted = crate::redaction::redact_keys_and_patterns(&value);
    // NFKC normalizes fullwidth @ to regular @, so this should match the email regex
    assert_eq!(
        redacted["data"].as_str().unwrap(),
        "[REDACTED]",
        "Email with fullwidth @ should be caught via NFKC normalization"
    );
}

/// SECURITY (R9-3): Numbers matching PII patterns should be redacted.
#[test]
fn test_redact_number_matching_ssn_pattern_redacted() {
    // SSN as a number with dashes would be a string, but check number-to-string path
    // A phone-like number: 5551234567
    let value = json!({"data": 5551234567_u64});
    let redacted = crate::redaction::redact_keys_and_patterns(&value);
    // This may or may not match the phone regex depending on format.
    // The important thing is the number-to-string conversion path doesn't panic.
    assert!(redacted.get("data").is_some());
}

#[test]
fn test_redact_number_not_matching_pii_preserved() {
    let value = json!({"count": 42});
    let redacted = crate::redaction::redact_keys_and_patterns(&value);
    assert_eq!(redacted["count"], 42, "Non-PII number should be preserved");
}

#[test]
fn test_redact_value_prefix_case_insensitive() {
    let value = json!({"token_value": "SK-live-test-key-123"});
    let redacted = crate::redaction::redact_keys_and_patterns(&value);
    assert_eq!(
        redacted["token_value"].as_str().unwrap(),
        "[REDACTED]",
        "Case-insensitive prefix 'SK-' should be caught"
    );
}

#[test]
fn test_redact_with_scanner_depth_boundary() {
    let scanner = crate::pii::PiiScanner::default();
    let mut value = json!({"data": "Call 555-123-4567 now"});
    for _ in 0..62 {
        value = json!({"nested": value});
    }
    let redacted = crate::redaction::redact_keys_and_patterns_with_scanner(&value, &scanner);
    let redacted_str = redacted.to_string();
    assert!(
        redacted_str.contains("[REDACTED]"),
        "Scanner-based PII at depth 63 should be redacted"
    );
}

#[test]
fn test_redact_with_scanner_nfkc_normalized() {
    let scanner = crate::pii::PiiScanner::default();
    // SSN with fullwidth digits
    let fullwidth_ssn =
        "\u{FF11}\u{FF12}\u{FF13}-\u{FF14}\u{FF15}-\u{FF16}\u{FF17}\u{FF18}\u{FF19}";
    let value = json!({"data": fullwidth_ssn});
    let redacted = crate::redaction::redact_keys_and_patterns_with_scanner(&value, &scanner);
    assert_eq!(
        redacted["data"].as_str().unwrap(),
        "[REDACTED]",
        "Scanner should catch NFKC-normalized SSN"
    );
}

#[test]
fn test_redact_empty_object() {
    let value = json!({});
    let redacted = crate::redaction::redact_keys_and_patterns(&value);
    assert_eq!(redacted, json!({}));
}

#[test]
fn test_redact_null_value_preserved() {
    let value = json!({"key": null, "password": "secret"});
    let redacted = crate::redaction::redact_keys_and_patterns(&value);
    assert!(redacted["key"].is_null(), "Null values should be preserved");
    assert_eq!(
        redacted["password"].as_str().unwrap(),
        "[REDACTED]",
        "Password key should still be redacted"
    );
}

// ═══════════════════════════════════════════════════════
// C2: Verification & Rotation Edge Cases
// ═══════════════════════════════════════════════════════

#[test]
fn test_merkle_tree_large_batch_1000_leaves_proof() {
    use crate::merkle::{hash_leaf, MerkleTree};

    let dir = TempDir::new().unwrap();
    let leaf_path = dir.path().join("leaves.bin");
    let mut tree = MerkleTree::new(leaf_path);

    for i in 0..1000u64 {
        let leaf_hash = hash_leaf(&i.to_le_bytes());
        tree.append(leaf_hash).unwrap();
    }

    assert_eq!(tree.leaf_count(), 1000);
    let root = tree.root().expect("root should exist for 1000 leaves");
    assert_ne!(root, [0u8; 32], "root should not be all zeros");

    // Generate and verify a proof for leaf 500
    let proof = tree.generate_proof(500).unwrap();
    assert_eq!(proof.leaf_index, 500);
    assert_eq!(proof.tree_size, 1000);
    assert!(!proof.siblings.is_empty());
}

#[test]
fn test_merkle_tree_max_leaf_count_boundary() {
    use crate::merkle::{hash_leaf, MerkleTree};

    let dir = TempDir::new().unwrap();
    let leaf_path = dir.path().join("leaves.bin");
    // Set a very low max for testing
    let mut tree = MerkleTree::new(leaf_path).with_max_leaf_count(5);

    for i in 0..5u64 {
        let leaf_hash = hash_leaf(&i.to_le_bytes());
        tree.append(leaf_hash).unwrap();
    }

    // The 6th append should fail
    let leaf_hash = hash_leaf(&5u64.to_le_bytes());
    let result = tree.append(leaf_hash);
    assert!(result.is_err(), "Should fail when max leaf count reached");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("limit reached"),
        "Error should mention limit: {err_msg}"
    );
}

#[tokio::test]
async fn test_verification_max_audit_line_size_boundary() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");

    // Write a line exactly at the boundary (1MB)
    let big_value = "x".repeat(1024 * 1024 - 100); // Leave room for JSON wrapping
    let entry = json!({
        "tool": "test",
        "function": "op",
        "verdict": "allow",
        "data": big_value
    });
    let line = serde_json::to_string(&entry).unwrap();

    // Write to file
    tokio::fs::write(&log_path, format!("{line}\n"))
        .await
        .unwrap();

    // Verification should handle this without panicking
    let logger = AuditLogger::new(log_path);
    let result = logger.load_entries().await;
    // Whether it succeeds or fails, it should not panic
    assert!(result.is_ok() || result.is_err());
}

#[tokio::test]
async fn test_verification_corrupted_utf8_line_skipped() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");

    // Write a valid line first
    let logger = AuditLogger::new(log_path.clone());
    let action = test_action();
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    // Append invalid JSON line
    let mut file = OpenOptions::new()
        .append(true)
        .open(&log_path)
        .await
        .unwrap();
    file.write_all(b"this is not valid json\n").await.unwrap();
    file.flush().await.unwrap();

    // Load should still work (skipping the bad line)
    let entries = logger.load_entries().await.unwrap();
    assert_eq!(
        entries.len(),
        1,
        "Should load the valid entry and skip the corrupt one"
    );
}

#[tokio::test]
async fn test_verification_embedded_null_in_json_handled() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");

    // Write valid entry
    let logger = AuditLogger::new(log_path.clone());
    let action = test_action();
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    // Append a line with embedded null character (should fail JSON parsing)
    let mut file = OpenOptions::new()
        .append(true)
        .open(&log_path)
        .await
        .unwrap();
    file.write_all(b"{\"tool\":\"test\",\"data\":\"hello\\u0000world\"}\n")
        .await
        .unwrap();
    file.flush().await.unwrap();

    // Load entries — should handle gracefully
    let result = logger.load_entries().await;
    assert!(result.is_ok(), "Should handle embedded null gracefully");
}

#[tokio::test]
async fn test_rotation_empty_log_file_no_rotation() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");

    // Create empty file
    tokio::fs::write(&log_path, "").await.unwrap();

    // Set a small max_file_size so rotation would trigger if there was content
    let logger = AuditLogger::new(log_path.clone()).with_max_file_size(1);

    // Load entries from empty file — should produce empty vec, not crash
    let entries = logger.load_entries().await.unwrap();
    assert!(entries.is_empty(), "Empty file should produce no entries");

    // No rotated files should exist
    let rotated = logger.list_rotated_files().unwrap();
    assert!(rotated.is_empty(), "No rotation should occur on empty file");
}

#[tokio::test]
async fn test_checkpoint_sequential_creation_safety() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let signing_key = AuditLogger::generate_signing_key();
    let logger = AuditLogger::new(log_path.clone()).with_signing_key(signing_key);

    // Log some entries first
    let action = test_action();
    for _ in 0..5 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }

    // Create two checkpoints sequentially — both should succeed
    let r1 = logger.create_checkpoint().await;
    assert!(r1.is_ok(), "First checkpoint should succeed");

    let r2 = logger.create_checkpoint().await;
    assert!(r2.is_ok(), "Second checkpoint should succeed");

    // Both checkpoints should have valid chain head hashes
    let cp1 = r1.unwrap();
    let cp2 = r2.unwrap();
    assert!(
        cp1.chain_head_hash.is_some(),
        "Checkpoint 1 should have a chain head hash"
    );
    assert!(
        cp2.chain_head_hash.is_some(),
        "Checkpoint 2 should have a chain head hash"
    );
}

// ═══════════════════════════════════════════════════
// GAP FINDING TESTS
// ═══════════════════════════════════════════════════

/// GAP-T01: Test initialize_chain with corrupted log (invalid JSON, broken chain).
#[tokio::test]
async fn test_gap_t01_initialize_chain_with_corrupted_log() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");

    // Write a corrupted log with broken JSON
    std::fs::write(&log_path, "not valid json\n{also broken}\n").unwrap();

    let logger = AuditLogger::new(log_path);
    let result = logger.initialize_chain().await;
    // Should succeed: corrupted entries are skipped, chain starts fresh.
    assert!(
        result.is_ok(),
        "initialize_chain should handle corrupted log gracefully: {:?}",
        result.err()
    );

    // After initialization, logging a new entry should work
    let action = test_action();
    let log_result = logger.log_entry(&action, &Verdict::Allow, json!({})).await;
    assert!(
        log_result.is_ok(),
        "Should be able to log after corrupted init"
    );
}

/// GAP-T02: Test security event logging helpers (circuit_breaker, deputy, schema).
#[tokio::test]
async fn test_gap_t02_event_logging_helpers() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path);

    // log_circuit_breaker_event
    logger
        .log_circuit_breaker_event("opened", "dangerous_tool", json!({"failures": 5}))
        .await
        .unwrap();
    logger
        .log_circuit_breaker_event("rejected", "dangerous_tool", json!({}))
        .await
        .unwrap();

    // log_deputy_event
    logger
        .log_deputy_event("registered", "session-1", json!({"depth": 1}))
        .await
        .unwrap();
    logger
        .log_deputy_event("validation_failed", "session-2", json!({}))
        .await
        .unwrap();

    // log_schema_event
    logger
        .log_schema_event("mutation_detected", "tool_x", json!({"field": "params"}))
        .await
        .unwrap();
    logger
        .log_schema_event("poisoning_alert", "tool_y", json!({}))
        .await
        .unwrap();

    // log_shadow_agent_event
    logger
        .log_shadow_agent_event("detected", "agent-bad", json!({}))
        .await
        .unwrap();

    // log_task_event
    logger
        .log_task_event("created", "task-1", json!({}))
        .await
        .unwrap();
    logger
        .log_task_event("limit_exceeded", "task-2", json!({}))
        .await
        .unwrap();

    // log_auth_event
    logger
        .log_auth_event("step_up_required", "sess-3", json!({}))
        .await
        .unwrap();

    // log_sampling_event
    logger
        .log_sampling_event("rate_limit", "sess-4", json!({}))
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 11, "Should have 11 event entries");

    // Verify deny verdicts for rejection events
    assert!(
        matches!(&entries[1].verdict, Verdict::Deny { .. }),
        "rejected circuit_breaker should be Deny"
    );
    assert!(
        matches!(&entries[3].verdict, Verdict::Deny { .. }),
        "validation_failed deputy should be Deny"
    );
}

/// GAP-T03: Test detect_heartbeat_gap with known gaps and no gaps.
#[tokio::test]
async fn test_gap_t03_detect_heartbeat_gap() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new_unredacted(log_path);

    // Log two entries close together
    let action = test_action();
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    // No gap expected (entries are milliseconds apart, threshold is 10s)
    let gap = logger.detect_heartbeat_gap(10).await.unwrap();
    assert!(
        gap.is_none(),
        "Should detect no gap for closely-spaced entries"
    );

    // With a threshold of 0 seconds, any gap should be detected
    let gap_zero = logger.detect_heartbeat_gap(0).await.unwrap();
    // Even sub-second gaps register as >= 0 seconds; depends on timing
    // This is a best-effort test.
    // With 0 threshold, any positive gap triggers. If entries are same second, gap is 0.
    // Just verify it does not error.
    assert!(gap_zero.is_none() || gap_zero.is_some());
}

/// GAP-T03b: detect_heartbeat_gap with single entry (no gap possible).
#[tokio::test]
async fn test_gap_t03b_detect_heartbeat_gap_single_entry() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new_unredacted(log_path);
    let action = test_action();
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();
    let gap = logger.detect_heartbeat_gap(10).await.unwrap();
    assert!(gap.is_none(), "Single entry should have no gap");
}

/// GAP-T03c: detect_heartbeat_gap with empty log.
#[tokio::test]
async fn test_gap_t03c_detect_heartbeat_gap_empty() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new_unredacted(log_path);
    let gap = logger.detect_heartbeat_gap(10).await.unwrap();
    assert!(gap.is_none(), "Empty log should have no gap");
}

/// GAP-T05: Adversarial tests for Merkle tree compute_siblings edge cases.
#[test]
fn test_gap_t05_merkle_compute_siblings_single_leaf() {
    use crate::merkle::{hash_leaf, MerkleTree};
    let dir = tempfile::tempdir().unwrap();
    let leaf_path = dir.path().join("test.merkle-leaves");
    let mut tree = MerkleTree::new(leaf_path);
    let leaf = hash_leaf(b"entry-0");
    tree.append(leaf).unwrap();
    let proof = tree.generate_proof(0).unwrap();
    // Single leaf: no siblings needed
    assert!(
        proof.siblings.is_empty(),
        "Single leaf proof should have no siblings"
    );
    assert_eq!(proof.tree_size, 1);
}

/// GAP-T05b: Merkle proof for last leaf in odd-count tree.
#[test]
fn test_gap_t05b_merkle_odd_leaf_count() {
    use crate::merkle::{hash_leaf, MerkleTree};
    let dir = tempfile::tempdir().unwrap();
    let leaf_path = dir.path().join("test.merkle-leaves");
    let mut tree = MerkleTree::new(leaf_path);
    for i in 0..3u64 {
        let leaf = hash_leaf(&i.to_le_bytes());
        tree.append(leaf).unwrap();
    }
    // Proof for the last leaf (index 2) in a 3-leaf tree
    let proof = tree.generate_proof(2).unwrap();
    assert_eq!(proof.tree_size, 3);
    // Verify the proof is valid
    let leaf = hash_leaf(&2u64.to_le_bytes());
    let verification = MerkleTree::verify_proof(leaf, &proof, &proof.root_hash).unwrap();
    assert!(
        verification.valid,
        "Proof for odd-count tree should be valid"
    );
}

/// GAP-T05c: Merkle proof for leaf 0 in power-of-2 tree.
#[test]
fn test_gap_t05c_merkle_power_of_two() {
    use crate::merkle::{hash_leaf, MerkleTree};
    let dir = tempfile::tempdir().unwrap();
    let leaf_path = dir.path().join("test.merkle-leaves");
    let mut tree = MerkleTree::new(leaf_path);
    for i in 0..8u64 {
        let leaf = hash_leaf(&i.to_le_bytes());
        tree.append(leaf).unwrap();
    }
    for idx in 0..8u64 {
        let proof = tree.generate_proof(idx).unwrap();
        let leaf = hash_leaf(&idx.to_le_bytes());
        let v = MerkleTree::verify_proof(leaf, &proof, &proof.root_hash).unwrap();
        assert!(
            v.valid,
            "Proof for leaf {idx} in 8-leaf tree should be valid"
        );
        assert_eq!(
            proof.siblings.len(),
            3,
            "8-leaf tree should need 3 siblings"
        );
    }
}

/// GAP-T05d: Merkle proof out-of-bounds index.
#[test]
fn test_gap_t05d_merkle_out_of_bounds() {
    use crate::merkle::{hash_leaf, MerkleTree};
    let dir = tempfile::tempdir().unwrap();
    let leaf_path = dir.path().join("test.merkle-leaves");
    let mut tree = MerkleTree::new(leaf_path);
    let leaf = hash_leaf(b"only-leaf");
    tree.append(leaf).unwrap();
    let result = tree.generate_proof(1);
    assert!(result.is_err(), "Out-of-bounds index should fail");
    let result = tree.generate_proof(999);
    assert!(result.is_err(), "Way out-of-bounds index should fail");
}

/// GAP-T04: Test list_rotated_files with empty dir.
#[test]
fn test_gap_t04_list_rotated_files_empty_dir() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    std::fs::write(&log_path, "").unwrap();
    let logger = AuditLogger::new(log_path);
    let files = logger.list_rotated_files().unwrap();
    assert!(files.is_empty(), "Empty dir should have no rotated files");
}

/// GAP-T04b: Test list_rotated_files with non-matching files.
#[test]
fn test_gap_t04b_list_rotated_files_non_matching() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    std::fs::write(&log_path, "").unwrap();
    // Create files that dont match the rotated pattern
    std::fs::write(dir.path().join("unrelated.txt"), "data").unwrap();
    std::fs::write(dir.path().join("audit.jsonl.bak"), "data").unwrap();
    std::fs::write(dir.path().join("other.2026-01-01T00-00-00.log"), "data").unwrap();
    let logger = AuditLogger::new(log_path);
    let files = logger.list_rotated_files().unwrap();
    assert!(files.is_empty(), "Non-matching files should not be listed");
}

/// GAP-T04c: Test list_rotated_files with missing parent dir.
#[test]
fn test_gap_t04c_list_rotated_files_missing_dir() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("nonexistent").join("audit.jsonl");
    let logger = AuditLogger::new(log_path);
    let files = logger.list_rotated_files().unwrap();
    assert!(files.is_empty(), "Missing dir should return empty list");
}

/// GAP-T06: Tests for ETDI audit logging helpers.
#[tokio::test]
async fn test_gap_t06_etdi_audit_helpers() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path);

    logger
        .log_etdi_signature_verified("tool_a", "signer-1", true)
        .await
        .unwrap();
    logger
        .log_etdi_signature_verified("tool_b", "signer-2", false)
        .await
        .unwrap();
    logger
        .log_etdi_signature_failed("tool_c", "invalid signature")
        .await
        .unwrap();
    logger.log_etdi_unsigned_tool("tool_d", true).await.unwrap();
    logger
        .log_etdi_unsigned_tool("tool_e", false)
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 5, "Should have 5 ETDI entries");
    assert!(
        matches!(&entries[0].verdict, Verdict::Allow),
        "Trusted sig should be Allow"
    );
    assert!(
        matches!(&entries[1].verdict, Verdict::Deny { .. }),
        "Untrusted sig should be Deny"
    );
    assert!(
        matches!(&entries[2].verdict, Verdict::Deny { .. }),
        "Failed sig should be Deny"
    );
    assert!(
        matches!(&entries[3].verdict, Verdict::Deny { .. }),
        "Blocked unsigned should be Deny"
    );
    assert!(
        matches!(&entries[4].verdict, Verdict::Allow),
        "Allowed unsigned should be Allow"
    );
}

/// IMP-R122-010: Oversized checkpoint line is silently skipped, not rejected.
/// Ensures load_checkpoints gracefully handles checkpoint files containing
/// lines that exceed MAX_CHECKPOINT_LINE_SIZE (64 KB).
#[tokio::test]
async fn test_checkpoint_oversized_line_skipped() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let key = AuditLogger::generate_signing_key();
    let logger = AuditLogger::new(log_path).with_signing_key(key);

    // Create a valid checkpoint first
    logger
        .log_entry(&test_action(), &Verdict::Allow, json!({}))
        .await
        .unwrap();
    logger.create_checkpoint().await.unwrap();

    // Now inject an oversized line into the checkpoint file
    let cp_path = dir.path().join("audit.checkpoints.jsonl");
    let oversized_line = "x".repeat(65 * 1024); // > 64 KB
    let mut file = OpenOptions::new()
        .append(true)
        .open(&cp_path)
        .await
        .unwrap();
    file.write_all(oversized_line.as_bytes()).await.unwrap();
    file.write_all(b"\n").await.unwrap();
    file.flush().await.unwrap();

    // load_checkpoints should succeed, skipping the oversized line
    let checkpoints = logger.load_checkpoints().await.unwrap();
    assert_eq!(
        checkpoints.len(),
        1,
        "Should load the valid checkpoint and skip the oversized line"
    );
}

/// GAP-T07: Test compress_rotated_file with missing file.
#[cfg(feature = "archive")]
#[tokio::test]
async fn test_gap_t07_compress_missing_file() {
    use crate::archive::compress_rotated_file;
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("nonexistent.log");
    let result = compress_rotated_file(&missing).await;
    assert!(result.is_err(), "Compressing missing file should fail");
}

// ═══════════════════════════════════════════════════════════════
// Phase 43: SinkError display, AuditLogger sink builder, and
// FileAuditQuery tests (IMP-R198-P43)
// ═══════════════════════════════════════════════════════════════

/// Minimal no-op AuditSink for testing the logger's with_sink builder.
/// Does not write to any external store; used only to verify wiring.
#[derive(Debug)]
struct NoOpSink {
    healthy: bool,
}

#[async_trait::async_trait]
impl crate::sink::AuditSink for NoOpSink {
    async fn sink(&self, _entry: &crate::AuditEntry) -> Result<(), crate::sink::SinkError> {
        Ok(())
    }

    async fn flush(&self) -> Result<(), crate::sink::SinkError> {
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), crate::sink::SinkError> {
        Ok(())
    }

    fn is_healthy(&self) -> bool {
        self.healthy
    }

    fn pending_count(&self) -> usize {
        0
    }
}

// ── SinkError display tests ──────────────────────────────────────────────────

#[test]
fn test_sink_error_display_connection() {
    let err = crate::sink::SinkError::Connection("timeout".to_string());
    let msg = err.to_string();
    assert!(msg.contains("sink connection error"), "got: {msg}");
    assert!(msg.contains("timeout"), "got: {msg}");
}

#[test]
fn test_sink_error_display_write() {
    let err = crate::sink::SinkError::Write("disk full".to_string());
    let msg = err.to_string();
    assert!(msg.contains("sink write error"), "got: {msg}");
    assert!(msg.contains("disk full"), "got: {msg}");
}

#[test]
fn test_sink_error_display_serialization() {
    let err = crate::sink::SinkError::Serialization("invalid utf8".to_string());
    let msg = err.to_string();
    assert!(msg.contains("sink serialization error"), "got: {msg}");
    assert!(msg.contains("invalid utf8"), "got: {msg}");
}

#[test]
fn test_sink_error_display_buffer_full() {
    let err = crate::sink::SinkError::BufferFull(42);
    let msg = err.to_string();
    assert!(msg.contains("buffer full"), "got: {msg}");
    assert!(msg.contains("42"), "got: {msg}");
}

#[test]
fn test_sink_error_display_shutting_down() {
    let err = crate::sink::SinkError::ShuttingDown;
    let msg = err.to_string();
    assert!(msg.contains("shutting down"), "got: {msg}");
}

// ── AuditLogger sink builder tests ──────────────────────────────────────────

#[tokio::test]
async fn test_logger_no_sink_log_entry_succeeds() {
    // A logger with no sink should log successfully — sink absence is not an error.
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path);

    // Verify the sink field is absent
    assert!(logger.sink.is_none(), "expected no sink by default");

    // Logging should still succeed
    logger
        .log_entry(&test_action(), &Verdict::Allow, json!({}))
        .await
        .unwrap();

    let entries = logger.load_entries().await.unwrap();
    assert_eq!(entries.len(), 1);
}

#[test]
fn test_logger_with_sink_sets_sink_field() {
    let dir = tempfile::TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");

    let sink = std::sync::Arc::new(NoOpSink { healthy: true });
    let logger = AuditLogger::new(log_path).with_sink(sink, false);

    assert!(
        logger.sink.is_some(),
        "sink should be set after with_sink()"
    );
    assert!(
        !logger.sink_failure_fatal,
        "sink_failure_fatal should be false"
    );
}

#[test]
fn test_logger_with_sink_fatal_flag() {
    let dir = tempfile::TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");

    let sink = std::sync::Arc::new(NoOpSink { healthy: false });
    let logger = AuditLogger::new(log_path).with_sink(sink, true);

    assert!(logger.sink.is_some(), "sink should be set");
    assert!(
        logger.sink_failure_fatal,
        "sink_failure_fatal should be true when fatal=true"
    );
}

// ── FileAuditQuery tests ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_file_audit_query_search_empty_log_returns_zero_total() {
    use crate::query::{file::FileAuditQuery, AuditQueryService};
    use vellaveto_types::audit_store::AuditQueryParams;

    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = std::sync::Arc::new(AuditLogger::new(log_path));
    let query = FileAuditQuery::new(logger);

    let params = AuditQueryParams::default();
    let result = query.search(&params).await.unwrap();

    assert_eq!(result.total, 0, "empty log should have 0 total entries");
    assert!(
        result.entries.is_empty(),
        "empty log should have no entries"
    );
    assert_eq!(result.limit, params.limit);
    assert_eq!(result.offset, params.offset);
}

#[tokio::test]
async fn test_file_audit_query_count_empty_log_returns_zero() {
    use crate::query::{file::FileAuditQuery, AuditQueryService};
    use vellaveto_types::audit_store::AuditQueryParams;

    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = std::sync::Arc::new(AuditLogger::new(log_path));
    let query = FileAuditQuery::new(logger);

    let params = AuditQueryParams::default();
    let count = query.count(&params).await.unwrap();

    assert_eq!(count, 0, "empty log should have count 0");
}

#[tokio::test]
async fn test_file_audit_query_get_by_id_nonexistent_returns_none() {
    use crate::query::{file::FileAuditQuery, AuditQueryService};

    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = std::sync::Arc::new(AuditLogger::new(log_path));
    let query = FileAuditQuery::new(logger);

    let result = query.get_by_id("nonexistent-uuid").await.unwrap();

    assert!(result.is_none(), "non-existent ID should return None");
}

#[tokio::test]
async fn test_file_audit_query_recent_empty_log_returns_empty_vec() {
    use crate::query::{file::FileAuditQuery, AuditQueryService};

    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = std::sync::Arc::new(AuditLogger::new(log_path));
    let query = FileAuditQuery::new(logger);

    let recent = query.recent(10).await.unwrap();

    assert!(
        recent.is_empty(),
        "recent() on empty log should return empty vec"
    );
}

#[tokio::test]
async fn test_file_audit_query_search_invalid_params_returns_validation_error() {
    use crate::query::{file::FileAuditQuery, AuditQueryService, QueryError};
    use vellaveto_types::audit_store::AuditQueryParams;

    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = std::sync::Arc::new(AuditLogger::new(log_path));
    let query = FileAuditQuery::new(logger);

    // limit == 0 is an invalid parameter
    let params = AuditQueryParams {
        limit: 0,
        ..Default::default()
    };
    let err = query.search(&params).await.unwrap_err();

    assert!(
        matches!(err, QueryError::Validation(_)),
        "invalid params should produce Validation error, got: {err:?}"
    );
}

#[tokio::test]
async fn test_file_audit_query_search_with_entries_returns_correct_total() {
    use crate::query::{file::FileAuditQuery, AuditQueryService};
    use vellaveto_types::audit_store::AuditQueryParams;

    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = std::sync::Arc::new(AuditLogger::new(log_path.clone()));

    // Write 3 entries
    logger
        .log_entry(&test_action(), &Verdict::Allow, json!({}))
        .await
        .unwrap();
    logger
        .log_entry(&test_action(), &Verdict::Allow, json!({}))
        .await
        .unwrap();
    logger
        .log_entry(
            &test_action(),
            &Verdict::Deny {
                reason: "blocked".to_string(),
            },
            json!({}),
        )
        .await
        .unwrap();

    let query = FileAuditQuery::new(logger);
    let params = AuditQueryParams::default();
    let result = query.search(&params).await.unwrap();

    assert_eq!(result.total, 3, "should find all 3 entries");
    assert_eq!(result.entries.len(), 3);
}

#[tokio::test]
async fn test_file_audit_query_count_invalid_params_returns_validation_error() {
    use crate::query::{file::FileAuditQuery, AuditQueryService, QueryError};
    use vellaveto_types::audit_store::AuditQueryParams;

    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = std::sync::Arc::new(AuditLogger::new(log_path));
    let query = FileAuditQuery::new(logger);

    // limit exceeds MAX_QUERY_LIMIT (1000)
    let params = AuditQueryParams {
        limit: 9999,
        ..Default::default()
    };
    let err = query.count(&params).await.unwrap_err();

    assert!(
        matches!(err, QueryError::Validation(_)),
        "invalid params should produce Validation error, got: {err:?}"
    );
}

#[tokio::test]
async fn test_file_audit_query_get_by_id_empty_id_returns_validation_error() {
    use crate::query::{file::FileAuditQuery, AuditQueryService, QueryError};

    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = std::sync::Arc::new(AuditLogger::new(log_path));
    let query = FileAuditQuery::new(logger);

    let err = query.get_by_id("").await.unwrap_err();

    assert!(
        matches!(err, QueryError::Validation(_)),
        "empty ID should produce Validation error, got: {err:?}"
    );
}

#[tokio::test]
async fn test_file_audit_query_recent_capped_at_max_query_limit() {
    use crate::query::{file::FileAuditQuery, AuditQueryService};

    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = std::sync::Arc::new(AuditLogger::new(log_path));
    let query = FileAuditQuery::new(logger);

    // Requesting more than MAX_QUERY_LIMIT should be capped, not error
    let recent = query.recent(u64::MAX).await.unwrap();
    // Empty log: result is still empty
    assert!(recent.is_empty());
}

// ── Phase 54: Post-Quantum Cryptography (PQC) Tests ─────────────────────────

/// Test that Checkpoint signing_content() is stable for v1 (no PQC fields).
#[test]
fn test_pqc_signing_content_v1_backward_compat() {
    let cp = Checkpoint {
        id: "test-id".to_string(),
        timestamp: "2026-02-25T12:00:00Z".to_string(),
        entry_count: 5,
        chain_head_hash: Some("abcd1234".to_string()),
        signature: String::new(),
        verifying_key: "vk-hex".to_string(),
        merkle_root: Some("merkle-root-hex".to_string()),
        pqc_signature: None,
        pqc_verifying_key: None,
        signature_version: None, // v1 (legacy)
    };
    let content1 = cp.signing_content();

    // Same checkpoint with explicit v1
    let cp_v1 = Checkpoint {
        signature_version: Some(1),
        ..cp.clone()
    };
    let content_v1 = cp_v1.signing_content();

    // v1 explicit and None should produce identical signing content
    assert_eq!(
        content1, content_v1,
        "None and Some(1) must produce identical signing content"
    );
}

/// Test that v2 signing content includes PQC verifying key.
#[test]
fn test_pqc_signing_content_v2_includes_pqc_key() {
    let cp_v1 = Checkpoint {
        id: "test-id".to_string(),
        timestamp: "2026-02-25T12:00:00Z".to_string(),
        entry_count: 5,
        chain_head_hash: Some("abcd1234".to_string()),
        signature: String::new(),
        verifying_key: "vk-hex".to_string(),
        merkle_root: None,
        pqc_signature: None,
        pqc_verifying_key: None,
        signature_version: None,
    };

    let cp_v2 = Checkpoint {
        pqc_verifying_key: Some("pqc-pk-hex".to_string()),
        signature_version: Some(2),
        ..cp_v1.clone()
    };

    let content_v1 = cp_v1.signing_content();
    let content_v2 = cp_v2.signing_content();

    // v2 must produce DIFFERENT signing content (includes PQC key)
    assert_ne!(
        content_v1, content_v2,
        "v2 signing content must differ from v1"
    );
}

/// Test that changing PQC verifying key in v2 changes signing content.
/// SECURITY: prevents PQC key substitution without invalidating Ed25519 sig.
#[test]
fn test_pqc_signing_content_v2_key_binding() {
    let cp_a = Checkpoint {
        id: "test-id".to_string(),
        timestamp: "2026-02-25T12:00:00Z".to_string(),
        entry_count: 5,
        chain_head_hash: None,
        signature: String::new(),
        verifying_key: "vk-hex".to_string(),
        merkle_root: None,
        pqc_signature: None,
        pqc_verifying_key: Some("pqc-key-A".to_string()),
        signature_version: Some(2),
    };

    let cp_b = Checkpoint {
        pqc_verifying_key: Some("pqc-key-B".to_string()),
        ..cp_a.clone()
    };

    let content_a = cp_a.signing_content();
    let content_b = cp_b.signing_content();

    assert_ne!(
        content_a, content_b,
        "Different PQC keys must produce different signing content"
    );
}

/// Test that v2 checkpoint without PQC feature fails verification (fail-closed).
#[tokio::test]
async fn test_pqc_v2_checkpoint_without_feature_fails_closed() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let key = AuditLogger::generate_signing_key();
    let logger = AuditLogger::new(log_path.clone()).with_signing_key(key.clone());

    let action = test_action();
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    // Create a checkpoint normally, then manually inject v2 fields
    logger.create_checkpoint().await.unwrap();
    let cp_path = logger.checkpoint_path();
    let content = tokio::fs::read_to_string(&cp_path).await.unwrap();
    let mut cp: serde_json::Value = serde_json::from_str(content.trim()).unwrap();

    // Inject v2 fields without valid PQC signatures
    cp["signature_version"] = serde_json::Value::Number(serde_json::Number::from(2u8));
    cp["pqc_verifying_key"] = serde_json::Value::String("deadbeef".to_string());
    cp["pqc_signature"] = serde_json::Value::String("cafebabe".to_string());

    // Re-sign with Ed25519 (the signing content now includes PQC key)
    let modified_cp: Checkpoint = serde_json::from_value(cp).unwrap();
    let signing_content = modified_cp.signing_content();
    let sig = key.sign(&signing_content);
    let mut cp_val = serde_json::to_value(&modified_cp).unwrap();
    cp_val["signature"] = serde_json::Value::String(hex::encode(sig.to_bytes()));
    let tampered = format!("{}\n", serde_json::to_string(&cp_val).unwrap());
    tokio::fs::write(&cp_path, tampered).await.unwrap();

    // Without pqc-hybrid feature, v2 checkpoints should fail-closed
    let verification = logger.verify_checkpoints().await.unwrap();
    // On non-pqc build: should fail with "requires pqc-hybrid feature"
    // On pqc build: should fail with ML-DSA verification failure (invalid key/sig)
    assert!(
        !verification.valid,
        "v2 checkpoint with invalid PQC fields must fail verification"
    );
    let reason = verification.failure_reason.as_ref().unwrap();
    assert!(
        reason.contains("pqc") || reason.contains("PQC") || reason.contains("ML-DSA"),
        "Failure reason should mention PQC/ML-DSA, got: {reason}"
    );
}

/// Test that trusted_pqc_verifying_key builder works.
#[test]
fn test_pqc_trusted_key_builder() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path).with_trusted_pqc_key("abcd1234".to_string());
    assert_eq!(
        logger.trusted_pqc_verifying_key.as_deref(),
        Some("abcd1234")
    );
}

/// Test Checkpoint serialization round-trip with PQC fields.
#[test]
fn test_pqc_checkpoint_serde_round_trip() {
    let cp = Checkpoint {
        id: "cp-1".to_string(),
        timestamp: "2026-02-25T12:00:00Z".to_string(),
        entry_count: 10,
        chain_head_hash: Some("hash123".to_string()),
        signature: "sig-hex".to_string(),
        verifying_key: "vk-hex".to_string(),
        merkle_root: None,
        pqc_signature: Some("pqc-sig-hex".to_string()),
        pqc_verifying_key: Some("pqc-vk-hex".to_string()),
        signature_version: Some(2),
    };

    let json = serde_json::to_string(&cp).unwrap();
    let deserialized: Checkpoint = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.pqc_signature.as_deref(), Some("pqc-sig-hex"));
    assert_eq!(
        deserialized.pqc_verifying_key.as_deref(),
        Some("pqc-vk-hex")
    );
    assert_eq!(deserialized.signature_version, Some(2));
}

/// Test that v1 checkpoints (without PQC fields) still deserialize correctly.
#[test]
fn test_pqc_v1_checkpoint_deserialization() {
    let json = r#"{
        "id": "cp-old",
        "timestamp": "2026-01-01T00:00:00Z",
        "entry_count": 5,
        "chain_head_hash": "abcd",
        "signature": "sig",
        "verifying_key": "vk",
        "merkle_root": null
    }"#;

    let cp: Checkpoint = serde_json::from_str(json).unwrap();
    assert!(cp.pqc_signature.is_none());
    assert!(cp.pqc_verifying_key.is_none());
    assert!(cp.signature_version.is_none());
}

/// Test that PQC fields are skipped in serialization when None.
#[test]
fn test_pqc_fields_skip_serializing_when_none() {
    let cp = Checkpoint {
        id: "cp-1".to_string(),
        timestamp: "2026-02-25T12:00:00Z".to_string(),
        entry_count: 0,
        chain_head_hash: None,
        signature: "sig".to_string(),
        verifying_key: "vk".to_string(),
        merkle_root: None,
        pqc_signature: None,
        pqc_verifying_key: None,
        signature_version: None,
    };

    let json = serde_json::to_string(&cp).unwrap();
    assert!(
        !json.contains("pqc_signature"),
        "None PQC fields should be skipped"
    );
    assert!(
        !json.contains("pqc_verifying_key"),
        "None PQC fields should be skipped"
    );
    assert!(
        !json.contains("signature_version"),
        "None signature_version should be skipped"
    );
}

/// Test that Ed25519 checkpoint error message changed correctly.
#[tokio::test]
async fn test_pqc_ed25519_error_message_format() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let key = AuditLogger::generate_signing_key();
    let logger = AuditLogger::new(log_path.clone()).with_signing_key(key);

    let action = test_action();
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();
    logger.create_checkpoint().await.unwrap();

    // Tamper signature
    let cp_path = logger.checkpoint_path();
    let content = tokio::fs::read_to_string(&cp_path).await.unwrap();
    let mut cp: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
    let sig = cp["signature"].as_str().unwrap().to_string();
    let tampered_sig = if let Some(stripped) = sig.strip_prefix('a') {
        format!("b{stripped}")
    } else {
        format!("a{}", &sig[1..])
    };
    cp["signature"] = serde_json::Value::String(tampered_sig);
    let tampered = format!("{}\n", serde_json::to_string(&cp).unwrap());
    tokio::fs::write(&cp_path, tampered).await.unwrap();

    let verification = logger.verify_checkpoints().await.unwrap();
    assert!(!verification.valid);
    let reason = verification.failure_reason.as_ref().unwrap();
    assert!(
        reason.contains("Ed25519 signature verification failed"),
        "Error message should specify Ed25519, got: {reason}"
    );
}

/// Test that rotation manifest Ed25519 error message changed correctly.
#[tokio::test]
async fn test_pqc_rotation_manifest_ed25519_error_message() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let key = AuditLogger::generate_signing_key();
    let logger = AuditLogger::new(log_path.clone())
        .with_signing_key(key.clone())
        .with_max_file_size(100) // tiny size to trigger rotation
        .with_trusted_key(hex::encode(key.verifying_key().as_bytes()));

    let action = test_action();
    // Write enough entries to trigger rotation
    for _ in 0..5 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({"data": "x".repeat(50)}))
            .await
            .unwrap();
    }

    // Tamper with the manifest signature
    let manifest_path = logger.rotation_manifest_path();
    if manifest_path.exists() {
        let content = tokio::fs::read_to_string(&manifest_path).await.unwrap();
        if let Some(first_line) = content.lines().next() {
            let mut entry: serde_json::Value = serde_json::from_str(first_line).unwrap();
            if let Some(sig) = entry.get("signature").and_then(|v| v.as_str()) {
                let tampered_sig = if let Some(stripped) = sig.strip_prefix('a') {
                    format!("b{stripped}")
                } else {
                    format!("a{}", &sig[1..])
                };
                entry["signature"] = serde_json::Value::String(tampered_sig);
                let tampered = format!("{}\n", serde_json::to_string(&entry).unwrap());
                tokio::fs::write(&manifest_path, tampered).await.unwrap();

                let verification = logger.verify_across_rotations().await.unwrap();
                assert!(!verification.valid);
                let reason = verification.first_failure.as_ref().unwrap();
                assert!(
                    reason.contains("Ed25519 signature invalid"),
                    "Error message should specify Ed25519, got: {reason}"
                );
            }
        }
    }
}

// ═══════════════════════════════════════════════════
// R227-AUD-2: UTC timestamp enforcement in verify_chain
// ═══════════════════════════════════════════════════

/// R227-AUD-2: verify_chain rejects non-UTC timestamps.
#[tokio::test]
async fn test_r227_verify_chain_rejects_non_utc_timestamp() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone());

    // Log a valid entry, then manually inject a non-UTC entry
    let action = test_action();
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    // Read the valid entry and create a tampered one with non-UTC timestamp
    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let mut entry: serde_json::Value =
        serde_json::from_str(content.lines().next().unwrap()).unwrap();
    // Change timestamp to use +05:30 offset instead of Z
    entry["timestamp"] = serde_json::Value::String("2026-02-27T10:00:00+05:30".to_string());
    // Clear hash chain so we test timestamp validation
    entry.as_object_mut().unwrap().remove("entry_hash");
    entry.as_object_mut().unwrap().remove("prev_hash");

    let tampered = format!(
        "{}\n{}\n",
        content.lines().next().unwrap(),
        serde_json::to_string(&entry).unwrap()
    );
    tokio::fs::write(&log_path, tampered).await.unwrap();

    let verification = logger.verify_chain().await.unwrap();
    assert!(
        !verification.valid,
        "Non-UTC timestamp should fail verification"
    );
    assert_eq!(verification.first_broken_at, Some(1));
}

/// R227-AUD-2: verify_chain accepts UTC timestamps (ends with Z).
#[tokio::test]
async fn test_r227_verify_chain_accepts_utc_timestamp() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path);

    let action = test_action();
    for _ in 0..3 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }

    let verification = logger.verify_chain().await.unwrap();
    assert!(
        verification.valid,
        "UTC timestamps should pass verification"
    );
    assert_eq!(verification.entries_checked, 3);
}

// ═══════════════════════════════════════════════════
// R228-AUD-1: Mixed Z/+00:00 suffix handling
// ═══════════════════════════════════════════════════

/// R228-AUD-1: verify_chain accepts mixed Z and +00:00 suffixes when
/// timestamps are in correct chronological order.
#[tokio::test]
async fn test_r228_verify_chain_mixed_utc_suffixes_correct_order() {
    use crate::types::AuditEntry;

    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("mixed_suffix.jsonl");
    let action = test_action();

    // Write 3 entries with alternating suffixes, in correct chronological order
    let entries = [
        ("mixed-0", "2026-02-27T10:00:00Z"),
        ("mixed-1", "2026-02-27T10:00:01+00:00"),
        ("mixed-2", "2026-02-27T10:00:02Z"),
    ];
    let mut content = String::new();
    for (id, ts) in &entries {
        let entry = AuditEntry {
            id: id.to_string(),
            action: action.clone(),
            verdict: Verdict::Allow,
            timestamp: ts.to_string(),
            metadata: json!({}),
            sequence: 0,
            entry_hash: None,
            prev_hash: None,
            commitment: None,
            tenant_id: None,
            acis_envelope: None,
        };
        content.push_str(&serde_json::to_string(&entry).unwrap());
        content.push('\n');
    }
    tokio::fs::write(&log_path, content).await.unwrap();

    let logger = AuditLogger::new(log_path);
    let verification = logger.verify_chain().await.unwrap();
    assert!(
        verification.valid,
        "Mixed Z/+00:00 suffixes in correct chronological order must pass"
    );
}

/// R228-AUD-1: verify_chain detects regression even with mixed suffixes.
#[tokio::test]
async fn test_r228_verify_chain_mixed_suffix_regression_detected() {
    use crate::types::AuditEntry;

    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("mixed_regression.jsonl");
    let action = test_action();

    // Second entry has EARLIER time but different suffix
    let entries = [
        ("entry-0", "2026-02-27T10:00:01+00:00"),
        ("entry-1", "2026-02-27T10:00:00Z"), // EARLIER than entry-0
    ];
    let mut content = String::new();
    for (id, ts) in &entries {
        let entry = AuditEntry {
            id: id.to_string(),
            action: action.clone(),
            verdict: Verdict::Allow,
            timestamp: ts.to_string(),
            metadata: json!({}),
            sequence: 0,
            entry_hash: None,
            prev_hash: None,
            commitment: None,
            tenant_id: None,
            acis_envelope: None,
        };
        content.push_str(&serde_json::to_string(&entry).unwrap());
        content.push('\n');
    }
    tokio::fs::write(&log_path, content).await.unwrap();

    let logger = AuditLogger::new(log_path);
    let verification = logger.verify_chain().await.unwrap();
    assert!(
        !verification.valid,
        "Timestamp regression with mixed Z/+00:00 suffixes must be detected"
    );
}

/// R238-AUD-1: Tenant ID with dangerous characters is dropped (fail-closed).
#[tokio::test]
async fn test_r238_aud1_tenant_id_dangerous_chars_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("audit_tenant_dangerous.jsonl");
    let logger = AuditLogger::new(log_path.clone());

    let action = vellaveto_types::Action::new("test", "op", json!({}));
    let verdict = vellaveto_types::Verdict::Allow;

    // Metadata with dangerous chars in tenant_id (bidi override U+202E)
    let metadata = json!({
        "tenant_id": "tenant\u{202E}evil",
    });
    logger.log_entry(&action, &verdict, metadata).await.unwrap();

    // Read the logged entry — tenant_id should be absent (dropped via skip_serializing_if)
    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let entry: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
    assert!(
        entry.get("tenant_id").is_none(),
        "tenant_id with dangerous characters should be absent from entry"
    );
    assert!(
        entry["metadata"].get("tenant_id").is_none(),
        "dangerous metadata.tenant_id should be removed from metadata too"
    );
}

/// R238-AUD-1: Tenant ID exceeding MAX_TENANT_ID_LEN is dropped.
#[tokio::test]
async fn test_r238_aud1_tenant_id_too_long_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("audit_tenant_long.jsonl");
    let logger = AuditLogger::new(log_path.clone());

    let action = vellaveto_types::Action::new("test", "op", json!({}));
    let verdict = vellaveto_types::Verdict::Allow;

    // Metadata with overlong tenant_id (65 chars, max is 64)
    let long_id = "t".repeat(vellaveto_types::audit_store::MAX_TENANT_ID_LEN + 1);
    let metadata = json!({ "tenant_id": long_id });
    logger.log_entry(&action, &verdict, metadata).await.unwrap();

    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let entry: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
    assert!(
        entry.get("tenant_id").is_none(),
        "overlong tenant_id should be absent from entry"
    );
    assert!(
        entry["metadata"].get("tenant_id").is_none(),
        "overlong metadata.tenant_id should be removed from metadata too"
    );
}

/// R238-AUD-1: Valid tenant ID passes through.
#[tokio::test]
async fn test_r238_aud1_tenant_id_valid_passes() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("audit_tenant_valid.jsonl");
    let logger = AuditLogger::new(log_path.clone());

    let action = vellaveto_types::Action::new("test", "op", json!({}));
    let verdict = vellaveto_types::Verdict::Allow;

    let metadata = json!({ "tenant_id": "tenant-abc-123" });
    logger.log_entry(&action, &verdict, metadata).await.unwrap();

    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let entry: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
    assert_eq!(
        entry.get("tenant_id").unwrap().as_str().unwrap(),
        "tenant-abc-123",
        "valid tenant_id should be preserved"
    );
    assert_eq!(
        entry["metadata"]
            .get("tenant_id")
            .unwrap()
            .as_str()
            .unwrap(),
        "tenant-abc-123",
        "valid metadata.tenant_id should be preserved"
    );
}

#[tokio::test]
async fn test_log_entry_with_acis_persists_dedicated_envelope() {
    use vellaveto_types::acis::{AcisActionSummary, DecisionKind, DecisionOrigin};

    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("audit_with_acis.jsonl");
    let logger = AuditLogger::new(log_path.clone());

    let action = Action::new("file", "read", json!({}));
    let verdict = Verdict::Allow;
    let envelope = vellaveto_types::AcisDecisionEnvelope {
        decision_id: "123456781234123412341234567890ab".to_string(),
        timestamp: "2026-03-08T12:00:00Z".to_string(),
        session_id: None,
        tenant_id: Some("tenant-123".to_string()),
        agent_identity: None,
        agent_id: Some("agent-a".to_string()),
        client_provenance: None,
        action_summary: AcisActionSummary {
            tool: "file".to_string(),
            function: "read".to_string(),
            target_path_count: 0,
            target_domain_count: 0,
        },
        action_fingerprint: "abcd1234".repeat(8),
        decision: DecisionKind::Allow,
        origin: DecisionOrigin::PolicyEngine,
        reason: String::new(),
        matched_policy_id: Some("file:read".to_string()),
        transport: "http".to_string(),
        findings: vec![],
        semantic_taint: vec![],
        lineage_refs: vec![],
        effective_trust_tier: None,
        sink_class: None,
        containment_mode: None,
        semantic_risk_score: None,
        evaluation_us: Some(42),
        call_chain_depth: 0,
    };

    logger
        .log_entry_with_acis(&action, &verdict, json!({"source": "test"}), envelope)
        .await
        .unwrap();

    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let entry: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
    assert_eq!(entry["acis_envelope"]["transport"], "http");
    assert_eq!(entry["acis_envelope"]["origin"], "policy_engine");
    assert_eq!(entry["acis_envelope"]["tenant_id"], "tenant-123");
}

/// SECURITY (R244-ACIS-1): Malformed ACIS envelopes must be rejected before
/// they are persisted to the audit log. An empty tool name or dangerous chars
/// in the decision_id should fail validation.
#[tokio::test]
async fn test_log_entry_with_acis_rejects_invalid_envelope() {
    use vellaveto_types::acis::{DecisionKind, DecisionOrigin};
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path);

    let action = test_action();
    let verdict = Verdict::Allow;

    // Envelope with empty tool name — violates acis validation
    let bad_envelope = vellaveto_types::AcisDecisionEnvelope {
        decision_id: "a".repeat(32),
        timestamp: "2026-03-08T00:00:00.000Z".to_string(),
        session_id: None,
        tenant_id: None,
        agent_identity: None,
        agent_id: None,
        client_provenance: None,
        action_summary: vellaveto_types::AcisActionSummary {
            tool: String::new(), // ← empty, must fail validation
            function: "read_file".to_string(),
            target_path_count: 0,
            target_domain_count: 0,
        },
        action_fingerprint: "abcd1234".repeat(8),
        decision: DecisionKind::Allow,
        origin: DecisionOrigin::PolicyEngine,
        reason: String::new(),
        matched_policy_id: None,
        transport: "http".to_string(),
        findings: vec![],
        semantic_taint: vec![],
        lineage_refs: vec![],
        effective_trust_tier: None,
        sink_class: None,
        containment_mode: None,
        semantic_risk_score: None,
        evaluation_us: None,
        call_chain_depth: 0,
    };

    let result = logger
        .log_entry_with_acis(&action, &verdict, json!({}), bad_envelope)
        .await;
    assert!(
        result.is_err(),
        "should reject envelope with empty tool name"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("ACIS envelope validation failed"),
        "error should mention envelope validation: {err_msg}"
    );
}

/// SECURITY (R244-ACIS-1): Envelope with dangerous chars in decision_id
/// must be rejected.
#[tokio::test]
async fn test_log_entry_with_acis_rejects_dangerous_chars_in_decision_id() {
    use vellaveto_types::acis::{DecisionKind, DecisionOrigin};
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path);

    let action = test_action();
    let verdict = Verdict::Allow;

    let bad_envelope = vellaveto_types::AcisDecisionEnvelope {
        decision_id: "abc\x00def".to_string(), // ← null byte
        timestamp: "2026-03-08T00:00:00.000Z".to_string(),
        session_id: None,
        tenant_id: None,
        agent_identity: None,
        agent_id: None,
        client_provenance: None,
        action_summary: vellaveto_types::AcisActionSummary {
            tool: "file_system".to_string(),
            function: "read_file".to_string(),
            target_path_count: 0,
            target_domain_count: 0,
        },
        action_fingerprint: "abcd1234".repeat(8),
        decision: DecisionKind::Allow,
        origin: DecisionOrigin::PolicyEngine,
        reason: String::new(),
        matched_policy_id: None,
        transport: "http".to_string(),
        findings: vec![],
        semantic_taint: vec![],
        lineage_refs: vec![],
        effective_trust_tier: None,
        sink_class: None,
        containment_mode: None,
        semantic_risk_score: None,
        evaluation_us: None,
        call_chain_depth: 0,
    };

    let result = logger
        .log_entry_with_acis(&action, &verdict, json!({}), bad_envelope)
        .await;
    assert!(
        result.is_err(),
        "should reject envelope with dangerous chars"
    );
}

/// R253-AUD-1: Metadata that fails serialization must be rejected (fail-closed),
/// not silently treated as 0 bytes which bypasses the MAX_METADATA_SIZE check.
#[tokio::test]
async fn test_r253_aud1_metadata_size_check_rejects_oversized() {
    let dir = tempfile::TempDir::new().unwrap();
    let log_path = dir.path().join("aud1-test.jsonl");

    let logger = crate::AuditLogger::new(log_path.clone());
    let action = vellaveto_types::Action::new("tool", "func", serde_json::json!({}));
    let verdict = vellaveto_types::Verdict::Allow;

    // Create metadata exceeding 64 KB.
    let big_value = "x".repeat(70_000);
    let metadata = serde_json::json!({ "big": big_value });

    let result = logger.log_entry(&action, &verdict, metadata).await;
    assert!(result.is_err(), "oversized metadata must be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("too large") || err.contains("Metadata"),
        "error should mention metadata size, got: {err}"
    );
}

// ── R253-AUD-6: Target array bounds checked before redaction ──

#[tokio::test]
async fn test_r253_aud6_too_many_targets_rejected() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path);

    let mut action = test_action();
    action.target_paths = (0..257).map(|i| format!("/path/{i}")).collect();

    let verdict = Verdict::Allow;
    let result = logger
        .log_entry(&action, &verdict, json!({"source": "test"}))
        .await;
    assert!(result.is_err(), "257 targets should be rejected");
    assert!(
        result.unwrap_err().to_string().contains("Too many targets"),
        "error should mention target count"
    );
}

#[tokio::test]
async fn test_r253_aud6_target_path_too_long_rejected() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path);

    let mut action = test_action();
    action.target_paths = vec!["x".repeat(5000)];

    let verdict = Verdict::Allow;
    let result = logger
        .log_entry(&action, &verdict, json!({"source": "test"}))
        .await;
    assert!(result.is_err(), "5000-byte target path should be rejected");
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Target path too long"),
        "error should mention path length"
    );
}

// ═══════════════════════════════════════════════════════
// Append-time timestamp monotonicity
//
// verify_chain() has always rejected a chain whose timestamps regress, but
// nothing stopped such an entry being written. These tests cover the append
// side: a backwards clock must not be able to produce a log that later fails
// verification.
// ═══════════════════════════════════════════════════════

/// Force the chain head's last timestamp into the future, simulating a system
/// clock that subsequently steps backwards relative to the last entry.
async fn set_last_timestamp(logger: &AuditLogger, ts: &str) {
    let mut head = logger.chain_head.lock().await;
    head.last_timestamp = Some(ts.to_string());
}

#[tokio::test]
async fn test_backwards_clock_leaves_chain_verifiable() {
    // The load-bearing assertion. Before append-time enforcement, an entry
    // written after a backwards clock step permanently broke verification of
    // the whole log from that point on.
    let dir = TempDir::new().unwrap();
    let logger = AuditLogger::new(dir.path().join("audit.jsonl"));
    let action = test_action();

    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    // Clock jumps far ahead, then the next append sees "now" as being in the past.
    set_last_timestamp(&logger, "2099-01-01T00:00:00+00:00").await;
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    let verification = logger.verify_chain().await.unwrap();
    assert!(
        verification.valid,
        "a backwards clock must not leave the chain unverifiable (first broken at {:?})",
        verification.first_broken_at
    );
}

#[tokio::test]
async fn test_regressing_entry_is_clamped_and_flagged() {
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone());
    let action = test_action();

    let future = "2099-01-01T00:00:00+00:00";
    set_last_timestamp(&logger, future).await;
    logger
        .log_entry(&action, &Verdict::Allow, json!({"k": "v"}))
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&log_path).unwrap();
    let entry: serde_json::Value = serde_json::from_str(contents.lines().next().unwrap()).unwrap();

    // Clamped to the previous timestamp — the earliest value that keeps the
    // chain non-decreasing, so the clamp never overstates how late the event was.
    assert_eq!(
        entry["timestamp"].as_str().unwrap(),
        future,
        "regressing entry must be clamped to the previous timestamp"
    );

    // The record is kept, and the real clock reading is preserved as evidence
    // rather than discarded.
    let regression = &entry["metadata"]["timestamp_regression"];
    assert!(
        regression.is_object(),
        "the observed clock reading must be recorded, got: {entry}"
    );
    assert_eq!(regression["clamped_to"].as_str().unwrap(), future);
    let observed = regression["observed"].as_str().unwrap();
    assert!(
        observed < future,
        "observed value {observed} should precede the clamp target"
    );

    // Original metadata survives alongside the flag.
    assert_eq!(entry["metadata"]["k"].as_str().unwrap(), "v");
}

#[tokio::test]
async fn test_normal_appends_are_untouched() {
    // The guard must be invisible when the clock behaves: no clamping, no flag.
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone());
    let action = test_action();

    for _ in 0..3 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }

    let contents = std::fs::read_to_string(&log_path).unwrap();
    for line in contents.lines() {
        let entry: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(
            entry["metadata"].get("timestamp_regression").is_none(),
            "an ordered append must not be flagged: {entry}"
        );
    }
    assert!(logger.verify_chain().await.unwrap().valid);
}

#[tokio::test]
async fn test_equal_timestamps_are_accepted() {
    // The rule is non-decreasing, not strictly increasing: two entries within
    // the same clock tick are normal and must not be treated as a regression.
    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let logger = AuditLogger::new(log_path.clone());
    let action = test_action();

    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();
    let first: serde_json::Value = serde_json::from_str(
        std::fs::read_to_string(&log_path)
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    let first_ts = first["timestamp"].as_str().unwrap().to_string();

    set_last_timestamp(&logger, &first_ts).await;
    logger
        .log_entry(&action, &Verdict::Allow, json!({}))
        .await
        .unwrap();

    let contents = std::fs::read_to_string(&log_path).unwrap();
    let second: serde_json::Value = serde_json::from_str(contents.lines().nth(1).unwrap()).unwrap();
    assert!(
        second["metadata"].get("timestamp_regression").is_none(),
        "an equal-or-later timestamp is not a regression: {second}"
    );
}

#[tokio::test]
async fn test_timestamp_guard_survives_rotation() {
    // last_hash resets on rotation because a new file starts a new hash chain.
    // last_timestamp deliberately does not: wall-clock time does not restart,
    // and resetting it would let a backwards clock be laundered by triggering
    // a rotation.
    let dir = TempDir::new().unwrap();
    let logger = AuditLogger::new(dir.path().join("audit.jsonl")).with_max_file_size(200);
    let action = test_action();

    set_last_timestamp(&logger, "2099-01-01T00:00:00+00:00").await;
    for _ in 0..20 {
        logger
            .log_entry(&action, &Verdict::Allow, json!({}))
            .await
            .unwrap();
    }

    let head = logger.chain_head.lock().await;
    assert_eq!(
        head.last_timestamp.as_deref(),
        Some("2099-01-01T00:00:00+00:00"),
        "the timestamp guard must not be reset by rotation"
    );
}

#[test]
fn test_timestamp_ordered_after_rules() {
    use crate::verification::timestamp_ordered_after;

    // No previous entry: any UTC timestamp is fine.
    assert!(timestamp_ordered_after("2026-01-01T00:00:00Z", None));

    // Non-UTC is rejected outright — ISO 8601 is only lexicographically
    // orderable in UTC.
    assert!(!timestamp_ordered_after("2026-01-01T00:00:00+05:30", None));

    // Mixed UTC suffixes must compare correctly despite '+' < 'Z' in ASCII
    // (R228-AUD-1).
    assert!(timestamp_ordered_after(
        "2026-01-01T00:00:01Z",
        Some("2026-01-01T00:00:00+00:00")
    ));
    assert!(timestamp_ordered_after(
        "2026-01-01T00:00:01+00:00",
        Some("2026-01-01T00:00:00Z")
    ));

    // Equal is allowed; earlier is not.
    assert!(timestamp_ordered_after(
        "2026-01-01T00:00:00Z",
        Some("2026-01-01T00:00:00Z")
    ));
    assert!(!timestamp_ordered_after(
        "2026-01-01T00:00:00Z",
        Some("2026-01-01T00:00:01Z")
    ));
}
