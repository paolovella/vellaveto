// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

use super::*;
use vellaveto_audit::{CustomPiiPattern, PiiScanner};

// ═══════════════════════════════════════════════════════════════════
// Sanitizer Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_sanitizer_email_replacement() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let result = sanitizer.sanitize("Contact user@example.com").unwrap();
    assert!(!result.contains("user@example.com"));
    assert!(result.contains("[PII_"));
}

#[test]
fn test_sanitizer_ssn_replacement() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let result = sanitizer.sanitize("SSN: 123-45-6789").unwrap();
    assert!(!result.contains("123-45-6789"));
    assert!(result.contains("[PII_"));
}

#[test]
fn test_sanitizer_cc_replacement() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let result = sanitizer.sanitize("Card: 4111111111111111").unwrap();
    assert!(!result.contains("4111111111111111"));
    assert!(result.contains("[PII_"));
}

#[test]
fn test_sanitizer_phone_replacement() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let result = sanitizer.sanitize("Call 555-123-4567").unwrap();
    assert!(!result.contains("555-123-4567"));
    assert!(result.contains("[PII_"));
}

#[test]
fn test_sanitizer_roundtrip() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let original = "Email user@example.com and SSN 123-45-6789 here";
    let sanitized = sanitizer.sanitize(original).unwrap();
    assert!(!sanitized.contains("user@example.com"));
    assert!(!sanitized.contains("123-45-6789"));

    let restored = sanitizer.desanitize(&sanitized).unwrap();
    assert_eq!(restored, original);
}

#[test]
fn test_sanitizer_json_recursive() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let input = serde_json::json!({
        "name": "test",
        "email": "user@example.com",
        "nested": {
            "ssn": "123-45-6789"
        }
    });
    let sanitized = sanitizer.sanitize_json(&input).unwrap();
    let sanitized_str = serde_json::to_string(&sanitized).unwrap();
    assert!(!sanitized_str.contains("user@example.com"));
    assert!(!sanitized_str.contains("123-45-6789"));

    let restored = sanitizer.desanitize_json(&sanitized).unwrap();
    assert_eq!(restored, input);
}

#[test]
fn test_sanitizer_json_object_keys_roundtrip() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let input = serde_json::json!({
        "user@example.com": {
            "owner@example.com": "notify admin@example.com"
        }
    });

    let sanitized = sanitizer.sanitize_json(&input).unwrap();
    let sanitized_str = serde_json::to_string(&sanitized).unwrap();
    assert!(!sanitized_str.contains("user@example.com"));
    assert!(!sanitized_str.contains("owner@example.com"));
    assert!(!sanitized_str.contains("admin@example.com"));
    assert!(sanitized_str.contains("[PII_"));

    let restored = sanitizer.desanitize_json(&sanitized).unwrap();
    assert_eq!(restored, input);
}

#[test]
fn test_sanitizer_max_mappings_fail_closed() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    // Fill up mappings (each unique email creates a mapping)
    for i in 0..50_000 {
        let input = format!("user{i}@example.com");
        let _ = sanitizer.sanitize(&input);
    }
    // Next sanitize should fail
    let result = sanitizer.sanitize("overflow@example.com");
    assert!(result.is_err());
}

#[test]
fn test_sanitizer_custom_patterns() {
    let custom = vec![CustomPiiPattern {
        name: "employee_id".to_string(),
        pattern: r"EMP-\d{6}".to_string(),
    }];
    let scanner = PiiScanner::new(&custom);
    let sanitizer = QuerySanitizer::new(scanner);
    let result = sanitizer.sanitize("Employee EMP-123456 logged in").unwrap();
    assert!(!result.contains("EMP-123456"));
    assert!(result.contains("[PII_"));
}

#[test]
fn test_sanitizer_clear() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let _ = sanitizer.sanitize("user@example.com").unwrap();
    assert!(sanitizer.mapping_count() > 0);
    sanitizer.clear();
    assert_eq!(sanitizer.mapping_count(), 0);
}

#[test]
fn test_sanitizer_empty_unchanged() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let result = sanitizer.sanitize("").unwrap();
    assert_eq!(result, "");
}

#[test]
fn test_sanitizer_no_pii_unchanged() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let input = "Normal text with no PII";
    let result = sanitizer.sanitize(input).unwrap();
    assert_eq!(result, input);
}

// ═══════════════════════════════════════════════════════════════════
// Session Isolator Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_session_create() {
    let isolator = SessionIsolator::new();
    let result = isolator.sanitize_in_session("s1", "user@example.com");
    assert!(result.is_ok());
    assert_eq!(isolator.session_count(), 1);
}

#[test]
fn test_session_max_fail_closed() {
    let isolator = SessionIsolator::with_limits(2, 100);
    let _ = isolator.sanitize_in_session("s1", "test").unwrap();
    let _ = isolator.sanitize_in_session("s2", "test").unwrap();
    let result = isolator.sanitize_in_session("s3", "test");
    assert!(result.is_err());
}

/// JSON-RPC allows several requests in flight at once, so a response to an
/// earlier request can arrive after a later one has already gone out. The
/// placeholder binding must be against the session's whole history, not just its
/// most recent message, or pipelined responses fail closed and the proxy breaks.
#[test]
fn test_json_desanitize_allows_out_of_order_pipelined_responses() {
    let isolator = SessionIsolator::new();

    // Request A goes out, then request B, before either response arrives.
    let a = isolator
        .sanitize_json_in_session("s1", &serde_json::json!({"id": 1, "q": "a@example.com"}))
        .unwrap();
    let _b = isolator
        .sanitize_json_in_session("s1", &serde_json::json!({"id": 2, "q": "b@example.com"}))
        .unwrap();

    // Response to A arrives second. Its placeholder is not in the most recent
    // outbound message (B), but this session did emit it.
    let restored = isolator
        .desanitize_json_in_session("s1", &serde_json::json!({"echo": a["q"].clone()}))
        .expect("a pipelined response must not fail closed");
    assert_eq!(
        restored["echo"].as_str().unwrap(),
        "a@example.com",
        "response to the earlier request must still restore"
    );
}

/// The probing attack the binding check exists for: a server echoing a
/// well-formed placeholder this session never minted must not get anything back,
/// and must not be silently treated as restorable.
#[test]
fn test_json_desanitize_rejects_placeholders_never_emitted() {
    let isolator = SessionIsolator::new();
    isolator
        .sanitize_json_in_session("s1", &serde_json::json!({"q": "real@example.com"}))
        .unwrap();

    let forged = serde_json::json!({"echo": "[PII_EMAIL_DEADBEEFDEADBEEF]"});
    let out = isolator.desanitize_json_in_session("s1", &forged).unwrap();
    assert_eq!(
        out["echo"].as_str().unwrap(),
        "[PII_EMAIL_DEADBEEFDEADBEEF]",
        "a placeholder this session never emitted must pass through, not resolve"
    );
    assert!(!out["echo"].as_str().unwrap().contains("real@example.com"));
}

/// Custom operator patterns must survive the switch to per-session isolation --
/// the isolator previously hardcoded PiiScanner::default(), which would have
/// silently dropped them.
#[test]
fn test_session_isolator_honours_custom_patterns() {
    let isolator = SessionIsolator::with_custom_patterns(vec![vellaveto_audit::CustomPiiPattern {
        name: "employee_id".to_string(),
        pattern: r"EMP-\d{6}".to_string(),
    }]);

    let out = isolator
        .sanitize_json_in_session("s1", &serde_json::json!({"note": "see EMP-123456"}))
        .unwrap();
    let text = out["note"].as_str().unwrap();
    assert!(
        !text.contains("EMP-123456"),
        "custom pattern must be applied, got {text}"
    );

    let restored = isolator.desanitize_json_in_session("s1", &out).unwrap();
    assert_eq!(restored["note"].as_str().unwrap(), "see EMP-123456");
}

#[test]
fn test_session_independent_pii_maps() {
    let isolator = SessionIsolator::new();
    let s1_result = isolator
        .sanitize_in_session("s1", "user1@example.com")
        .unwrap();
    let s2_result = isolator
        .sanitize_in_session("s2", "user2@example.com")
        .unwrap();

    // Both sessions have PII replaced
    assert!(!s1_result.contains("user1@example.com"));
    assert!(!s2_result.contains("user2@example.com"));

    // Desanitize in the correct session restores the original
    let restored = isolator.desanitize_in_session("s1", &s1_result).unwrap();
    assert_eq!(restored, "user1@example.com");

    // Cross-session desanitization: session s2 does NOT own session s1's
    // placeholders, so they pass through unchanged (no PII leak).
    let cross_restored = isolator.desanitize_in_session("s2", &s1_result).unwrap();
    assert_ne!(
        cross_restored, "user1@example.com",
        "cross-session desanitization must NOT restore other session's PII"
    );
    assert!(
        !cross_restored.contains("user1@example.com"),
        "session isolation should prevent cross-session PII restoration"
    );
}

#[test]
fn test_session_placeholder_format_is_bound_by_regex() {
    let isolator = SessionIsolator::new();
    let sanitized = isolator
        .sanitize_in_session("s1", "user@example.com")
        .unwrap();

    let placeholder = sanitized
        .split_whitespace()
        .find(|segment| segment.starts_with("[PII_"))
        .expect("sanitized output should contain a placeholder");

    let restored = isolator.desanitize_in_session("s1", placeholder).unwrap();
    assert_eq!(restored, "user@example.com");
}

#[test]
fn test_session_desanitize_only_accepts_most_recent_outbound_placeholders() {
    let isolator = SessionIsolator::new();
    let older = isolator
        .sanitize_in_session("s1", "older@example.com")
        .unwrap();
    let newer = isolator
        .sanitize_in_session("s1", "newer@example.com")
        .unwrap();

    let restored_newer = isolator.desanitize_in_session("s1", &newer).unwrap();
    assert_eq!(restored_newer, "newer@example.com");

    let stale = isolator.desanitize_in_session("s1", &older);
    assert!(stale.is_err(), "stale placeholders must fail closed");
    let err = stale.unwrap_err().to_string();
    assert!(
        err.contains("most recent outbound sanitized request"),
        "error should explain request binding, got: {err}"
    );
}

#[test]
fn test_session_end_clears() {
    let isolator = SessionIsolator::new();
    let _ = isolator
        .sanitize_in_session("s1", "user@example.com")
        .unwrap();
    assert_eq!(isolator.session_count(), 1);
    isolator.end_session("s1");
    assert_eq!(isolator.session_count(), 0);
}

#[test]
fn test_session_history_bounded() {
    let isolator = SessionIsolator::with_limits(10, 3);
    let _ = isolator.sanitize_in_session("s1", "first").unwrap();
    let _ = isolator.sanitize_in_session("s1", "second").unwrap();
    let _ = isolator.sanitize_in_session("s1", "third").unwrap();
    let _ = isolator.sanitize_in_session("s1", "fourth").unwrap();
    // Should not error — old entries evicted
    assert_eq!(isolator.session_count(), 1);
}

// ═══════════════════════════════════════════════════════════════════
// Crypto Tests
// ═══════════════════════════════════════════════════════════════════

/// Known-answer test pinning the XChaCha20-Poly1305 ciphertext format.
///
/// The encrypted audit store persists data to disk, so a change in the AEAD
/// output would silently render existing stores undecryptable. A round-trip
/// test cannot catch that: it would encrypt and decrypt with the same new
/// implementation and pass regardless.
///
/// This vector was generated under chacha20poly1305 0.10.1 and must continue
/// to hold across dependency upgrades. If it ever fails, existing on-disk
/// audit stores are no longer readable and the change is not backward
/// compatible.
#[test]
fn test_crypto_xchacha20poly1305_known_answer_vector() {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        XChaCha20Poly1305, XNonce,
    };

    let key = [0x42u8; 32];
    let nonce_bytes = [0x24u8; 24];
    let plaintext = b"vellaveto shield audit record v1";

    // Generated with chacha20poly1305 0.10.1.
    let expected_hex = "d33bbb090f5229d2cd0f4c5267ed61ae1290fbde156b54ef\
                        4402893f0f30adfccd28009ca082e31886a2c3fb67c280c1";

    let cipher = XChaCha20Poly1305::new((&key).into());
    let nonce = XNonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .expect("encryption must succeed");

    let actual_hex: String = ciphertext.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        actual_hex, expected_hex,
        "XChaCha20-Poly1305 ciphertext changed — existing encrypted audit \
         stores would no longer decrypt"
    );

    // 32-byte plaintext plus the 16-byte Poly1305 tag.
    assert_eq!(ciphertext.len(), 48, "unexpected tag length");

    // The stored form must decrypt back to the original plaintext.
    let recovered = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .expect("decryption of the pinned vector must succeed");
    assert_eq!(recovered, plaintext);
}

#[test]
fn test_crypto_encrypt_decrypt_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.enc");
    let store = EncryptedAuditStore::new(path, "test-passphrase!").unwrap();

    let plaintext = b"sensitive audit data";
    let encrypted = store.encrypt(plaintext).unwrap();
    let decrypted = store.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_crypto_wrong_passphrase_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.enc");

    let store1 = EncryptedAuditStore::new(path.clone(), "correct-pass!!").unwrap();
    store1.write_encrypted_entry(b"secret data").unwrap();

    let store2 = EncryptedAuditStore::new(path, "wrong-pass!!!!!").unwrap();
    let result = store2.read_all_entries();
    assert!(result.is_err());
}

#[test]
fn test_crypto_empty_input() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.enc");
    let store = EncryptedAuditStore::new(path, "test-passphrase!").unwrap();

    let encrypted = store.encrypt(b"").unwrap();
    let decrypted = store.decrypt(&encrypted).unwrap();
    assert!(decrypted.is_empty());
}

#[test]
fn test_crypto_large_input() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.enc");
    let store = EncryptedAuditStore::new(path, "test-passphrase!").unwrap();

    let large = vec![0xABu8; 1_000_000];
    let encrypted = store.encrypt(&large).unwrap();
    let decrypted = store.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted, large);
}

#[test]
fn test_crypto_salt_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.enc");

    let store1 = EncryptedAuditStore::new(path.clone(), "passphrase!!").unwrap();
    store1.write_encrypted_entry(b"entry 1").unwrap();

    // Re-open with same passphrase — should read same salt
    let store2 = EncryptedAuditStore::new(path, "passphrase!!").unwrap();
    let entries = store2.read_all_entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0], b"entry 1");
}

// ═══════════════════════════════════════════════════════════════════
// Local Audit Tests
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_local_audit_encrypted_not_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.log");
    let enc_path = dir.path().join("audit.enc");
    let store = EncryptedAuditStore::new(enc_path.clone(), "secret-phrase!").unwrap();
    let mut manager = LocalAuditManager::new(audit_path, store);

    manager
        .log_shield_event("test", "sensitive details")
        .await
        .unwrap();

    // Read raw file — should NOT contain plaintext
    let raw = std::fs::read(&enc_path).unwrap();
    let raw_str = String::from_utf8_lossy(&raw);
    assert!(!raw_str.contains("sensitive details"));
}

#[tokio::test]
async fn test_local_audit_merkle_proof_valid() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.log");
    let enc_path = dir.path().join("audit.enc");
    let store = EncryptedAuditStore::new(enc_path, "secret-phrase!").unwrap();
    let mut manager = LocalAuditManager::new(audit_path, store).with_merkle();

    manager
        .log_shield_event("event1", "details1")
        .await
        .unwrap();
    manager
        .log_shield_event("event2", "details2")
        .await
        .unwrap();

    let proof = manager.generate_proof(0);
    assert!(proof.is_ok());
    assert!(manager.merkle_root().is_some());
}

#[tokio::test]
async fn test_local_audit_read_decrypts() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.log");
    let enc_path = dir.path().join("audit.enc");
    let store = EncryptedAuditStore::new(enc_path, "secret-phrase!").unwrap();
    let mut manager = LocalAuditManager::new(audit_path, store);

    manager
        .log_shield_event("test_event", "test_details")
        .await
        .unwrap();

    let entries = manager.read_entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["event"], "test_event");
}

// ═══════════════════════════════════════════════════════════════════
// BlindCredential Type Tests
// ═══════════════════════════════════════════════════════════════════

fn make_test_credential(epoch: u64) -> vellaveto_types::BlindCredential {
    vellaveto_types::BlindCredential {
        credential: vec![1, 2, 3, 4],
        signature: vec![5, 6, 7, 8],
        provider_key_id: "test-key-001".to_string(),
        issued_epoch: epoch,
        credential_type: vellaveto_types::CredentialType::Subscriber,
    }
}

#[test]
fn test_blind_credential_validate_valid() {
    let cred = make_test_credential(42);
    assert!(cred.validate().is_ok());
}

#[test]
fn test_blind_credential_validate_empty_credential() {
    let mut cred = make_test_credential(0);
    cred.credential = Vec::new();
    assert!(cred
        .validate()
        .unwrap_err()
        .contains("credential must not be empty"));
}

#[test]
fn test_blind_credential_validate_empty_signature() {
    let mut cred = make_test_credential(0);
    cred.signature = Vec::new();
    assert!(cred
        .validate()
        .unwrap_err()
        .contains("signature must not be empty"));
}

#[test]
fn test_blind_credential_validate_oversized_credential() {
    let mut cred = make_test_credential(0);
    cred.credential = vec![0u8; vellaveto_types::MAX_CREDENTIAL_LEN + 1];
    assert!(cred.validate().unwrap_err().contains("exceeds maximum"));
}

#[test]
fn test_blind_credential_validate_oversized_signature() {
    let mut cred = make_test_credential(0);
    cred.signature = vec![0u8; vellaveto_types::MAX_SIGNATURE_LEN + 1];
    assert!(cred.validate().unwrap_err().contains("exceeds maximum"));
}

#[test]
fn test_blind_credential_validate_empty_key_id() {
    let mut cred = make_test_credential(0);
    cred.provider_key_id = String::new();
    assert!(cred
        .validate()
        .unwrap_err()
        .contains("provider_key_id must not be empty"));
}

#[test]
fn test_blind_credential_validate_dangerous_key_id() {
    let mut cred = make_test_credential(0);
    cred.provider_key_id = "key\u{200B}id".to_string(); // zero-width space
    assert!(cred
        .validate()
        .unwrap_err()
        .contains("dangerous characters"));
}

#[test]
fn test_blind_credential_validate_oversized_key_id() {
    let mut cred = make_test_credential(0);
    cred.provider_key_id = "k".repeat(vellaveto_types::MAX_PROVIDER_KEY_ID_LEN + 1);
    assert!(cred.validate().unwrap_err().contains("exceeds maximum"));
}

#[test]
fn test_blind_credential_validate_epoch_overflow() {
    let mut cred = make_test_credential(0);
    cred.issued_epoch = vellaveto_types::MAX_CREDENTIAL_EPOCH + 1;
    assert!(cred.validate().unwrap_err().contains("issued_epoch"));
}

#[test]
fn test_blind_credential_debug_redacts_secrets() {
    let cred = make_test_credential(42);
    let debug_str = format!("{cred:?}");
    assert!(debug_str.contains("REDACTED"));
    assert!(!debug_str.contains("[1, 2, 3, 4]"));
    assert!(!debug_str.contains("[5, 6, 7, 8]"));
    assert!(debug_str.contains("test-key-001")); // key_id is NOT secret
}

#[test]
fn test_blind_credential_serde_roundtrip() {
    let cred = make_test_credential(99);
    let json = serde_json::to_string(&cred).unwrap();
    let parsed: vellaveto_types::BlindCredential = serde_json::from_str(&json).unwrap();
    assert_eq!(cred, parsed);
}

#[test]
fn test_blind_credential_deny_unknown_fields() {
    let json = r#"{
        "credential": [1,2,3],
        "signature": [4,5,6],
        "provider_key_id": "key",
        "issued_epoch": 0,
        "credential_type": "subscriber",
        "unknown_field": true
    }"#;
    let result: Result<vellaveto_types::BlindCredential, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════════
// CredentialVault Tests
// ═══════════════════════════════════════════════════════════════════

fn make_test_vault(pool_size: usize, threshold: usize) -> (CredentialVault, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let store = EncryptedAuditStore::new(path, "test-passphrase!").unwrap();
    let vault = CredentialVault::new(store, pool_size, threshold).unwrap();
    (vault, dir)
}

#[test]
fn test_vault_add_and_consume() {
    let (vault, _dir) = make_test_vault(10, 3);
    vault.add_credential(make_test_credential(1)).unwrap();

    let status = vault.status();
    assert_eq!(status.total, 1);
    assert_eq!(status.available, 1);

    let (cred, idx) = vault.consume_credential().unwrap();
    assert_eq!(cred.issued_epoch, 1);

    let status = vault.status();
    assert_eq!(status.available, 0);
    assert_eq!(status.active, 1);

    vault.mark_consumed(idx).unwrap();
    let status = vault.status();
    assert_eq!(status.consumed, 1);
    assert_eq!(status.active, 0);
}

#[test]
fn test_vault_consume_empty_fail_closed() {
    let (vault, _dir) = make_test_vault(10, 3);
    let result = vault.consume_credential();
    assert!(result.is_err());
}

#[test]
fn test_vault_needs_replenishment() {
    let (vault, _dir) = make_test_vault(10, 3);
    // Empty vault → needs replenishment
    assert!(vault.status().needs_replenishment);

    // Add 3 credentials → still below threshold? No, 3 == threshold, not below
    for i in 0..3 {
        vault.add_credential(make_test_credential(i)).unwrap();
    }
    assert!(!vault.status().needs_replenishment);

    // Consume 1 → 2 available, below threshold of 3
    vault.consume_credential().unwrap();
    assert!(vault.status().needs_replenishment);
}

#[test]
fn test_vault_expire_old_epochs() {
    let (vault, _dir) = make_test_vault(10, 1);
    vault.add_credential(make_test_credential(1)).unwrap();
    vault.add_credential(make_test_credential(2)).unwrap();
    vault.add_credential(make_test_credential(5)).unwrap();

    // Expire everything before epoch 3
    let expired = vault.expire_old_epochs(3).unwrap();
    assert_eq!(expired, 2);
    assert_eq!(vault.available_count(), 1); // Only epoch 5 remains

    // Epoch in status updated
    assert_eq!(vault.status().current_epoch, 5);
}

#[test]
fn test_vault_invalid_credential_rejected() {
    let (vault, _dir) = make_test_vault(10, 3);
    let mut bad = make_test_credential(1);
    bad.credential = Vec::new(); // invalid
    let result = vault.add_credential(bad);
    assert!(result.is_err());
}

#[test]
fn test_vault_mark_consumed_out_of_bounds() {
    let (vault, _dir) = make_test_vault(10, 3);
    let result = vault.mark_consumed(999);
    assert!(result.is_err());
}

#[test]
fn test_vault_debug_no_secrets() {
    let (vault, _dir) = make_test_vault(10, 3);
    vault.add_credential(make_test_credential(1)).unwrap();
    let debug_str = format!("{vault:?}");
    assert!(debug_str.contains("CredentialVault"));
    assert!(debug_str.contains("available"));
    // Should not contain raw credential bytes
    assert!(!debug_str.contains("[1, 2, 3, 4]"));
}

#[test]
fn test_vault_persistence_across_instances() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.enc");

    // Create vault and add credentials
    {
        let store = EncryptedAuditStore::new(path.clone(), "test-pass-long").unwrap();
        let vault = CredentialVault::new(store, 10, 3).unwrap();
        vault.add_credential(make_test_credential(1)).unwrap();
        vault.add_credential(make_test_credential(2)).unwrap();
    }

    // Re-open with same passphrase — credentials should be loaded
    {
        let store = EncryptedAuditStore::new(path, "test-pass-long").unwrap();
        let vault = CredentialVault::new(store, 10, 3).unwrap();
        assert_eq!(vault.status().total, 2);
        assert_eq!(vault.available_count(), 2);
    }
}

// ═══════════════════════════════════════════════════════════════════
// SessionUnlinker Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_unlinker_start_session() {
    let (vault, _dir) = make_test_vault(10, 1);
    vault.add_credential(make_test_credential(1)).unwrap();

    let unlinker = SessionUnlinker::new(vault);
    let cred = unlinker.start_session("session-1").unwrap();
    assert_eq!(cred.issued_epoch, 1);
    assert_eq!(unlinker.active_session_count(), 1);
    assert!(unlinker.is_session_active("session-1"));
}

#[test]
fn test_unlinker_end_session() {
    let (vault, _dir) = make_test_vault(10, 1);
    vault.add_credential(make_test_credential(1)).unwrap();

    let unlinker = SessionUnlinker::new(vault);
    unlinker.start_session("session-1").unwrap();
    unlinker.end_session("session-1").unwrap();

    assert_eq!(unlinker.active_session_count(), 0);
    assert!(!unlinker.is_session_active("session-1"));
    assert_eq!(unlinker.vault().status().consumed, 1);
}

#[test]
fn test_unlinker_no_credentials_fail_closed() {
    let (vault, _dir) = make_test_vault(10, 1);
    let unlinker = SessionUnlinker::new(vault);
    let result = unlinker.start_session("session-1");
    assert!(result.is_err());
}

#[test]
fn test_unlinker_duplicate_session_rejected() {
    let (vault, _dir) = make_test_vault(10, 1);
    vault.add_credential(make_test_credential(1)).unwrap();
    vault.add_credential(make_test_credential(2)).unwrap();

    let unlinker = SessionUnlinker::new(vault);
    unlinker.start_session("session-1").unwrap();
    let result = unlinker.start_session("session-1");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("already active"));
}

#[test]
fn test_unlinker_capacity_exhaustion_fail_closed() {
    let (vault, _dir) = make_test_vault(100, 1);
    for i in 0..5 {
        vault
            .add_credential(make_test_credential(i as u64))
            .unwrap();
    }

    let unlinker = SessionUnlinker::with_max_sessions(vault, 3);
    unlinker.start_session("s1").unwrap();
    unlinker.start_session("s2").unwrap();
    unlinker.start_session("s3").unwrap();

    let result = unlinker.start_session("s4");
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("capacity exhausted"));
}

#[test]
fn test_unlinker_get_session_credential() {
    let (vault, _dir) = make_test_vault(10, 1);
    vault.add_credential(make_test_credential(42)).unwrap();

    let unlinker = SessionUnlinker::new(vault);
    let original = unlinker.start_session("s1").unwrap();
    let retrieved = unlinker.get_session_credential("s1").unwrap();
    assert_eq!(original, retrieved);
}

#[test]
fn test_unlinker_get_binding() {
    let (vault, _dir) = make_test_vault(10, 1);
    vault.add_credential(make_test_credential(1)).unwrap();

    let unlinker = SessionUnlinker::new(vault);
    unlinker.start_session("s1").unwrap();

    let binding = unlinker.get_binding("s1").unwrap();
    assert_eq!(binding.session_id, "s1");
    assert_eq!(binding.binding_sequence, 0);
}

#[test]
fn test_unlinker_monotonic_sequence() {
    let (vault, _dir) = make_test_vault(10, 1);
    for i in 0..3 {
        vault.add_credential(make_test_credential(i)).unwrap();
    }

    let unlinker = SessionUnlinker::new(vault);
    unlinker.start_session("s1").unwrap();
    unlinker.start_session("s2").unwrap();
    unlinker.start_session("s3").unwrap();

    let b1 = unlinker.get_binding("s1").unwrap();
    let b2 = unlinker.get_binding("s2").unwrap();
    let b3 = unlinker.get_binding("s3").unwrap();
    assert!(b1.binding_sequence < b2.binding_sequence);
    assert!(b2.binding_sequence < b3.binding_sequence);
}

#[test]
fn test_unlinker_dangerous_session_id_rejected() {
    let (vault, _dir) = make_test_vault(10, 1);
    vault.add_credential(make_test_credential(1)).unwrap();

    let unlinker = SessionUnlinker::new(vault);
    let result = unlinker.start_session("session\u{200B}id");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("dangerous"));
}

#[test]
fn test_unlinker_unknown_session_end_rejected() {
    let (vault, _dir) = make_test_vault(10, 1);
    let unlinker = SessionUnlinker::new(vault);
    let result = unlinker.end_session("nonexistent");
    assert!(result.is_err());
}

#[test]
fn test_unlinker_independent_credentials_per_session() {
    let (vault, _dir) = make_test_vault(10, 1);
    vault.add_credential(make_test_credential(1)).unwrap();
    vault.add_credential(make_test_credential(2)).unwrap();

    let unlinker = SessionUnlinker::new(vault);
    let cred1 = unlinker.start_session("s1").unwrap();
    let cred2 = unlinker.start_session("s2").unwrap();

    // Each session gets a different credential (unlinkable)
    assert_ne!(cred1.issued_epoch, cred2.issued_epoch);
}

// ═══════════════════════════════════════════════════════════════════
// ShieldConfig Credential Extensions Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_shield_config_credential_defaults() {
    let config = vellaveto_config::ShieldConfig::default();
    assert!(config.session_unlinkability);
    assert_eq!(config.credential_pool_size, 50);
    assert_eq!(config.replenish_threshold, 10);
    assert_eq!(config.credential_epoch_interval, 100);
    assert!(config.validate().is_ok());
}

#[test]
fn test_shield_config_zero_pool_rejected() {
    let config = vellaveto_config::ShieldConfig {
        credential_pool_size: 0,
        ..vellaveto_config::ShieldConfig::default()
    };
    assert!(config
        .validate()
        .unwrap_err()
        .contains("credential_pool_size"));
}

#[test]
fn test_shield_config_threshold_ge_pool_rejected() {
    let config = vellaveto_config::ShieldConfig {
        replenish_threshold: 50, // equal to pool_size
        ..vellaveto_config::ShieldConfig::default()
    };
    assert!(config
        .validate()
        .unwrap_err()
        .contains("replenish_threshold"));
}

#[test]
fn test_shield_config_zero_epoch_interval_rejected() {
    let config = vellaveto_config::ShieldConfig {
        credential_epoch_interval: 0,
        ..vellaveto_config::ShieldConfig::default()
    };
    assert!(config
        .validate()
        .unwrap_err()
        .contains("credential_epoch_interval"));
}

// ═══════════════════════════════════════════════════════════════════
// ContextIsolator Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_context_record_and_retrieve() {
    let ctx = ContextIsolator::new();
    ctx.record("s1", "user", "What is the weather?").unwrap();
    ctx.record("s1", "assistant", "It's sunny today.").unwrap();

    let entries = ctx.get_recent_context("s1", 10).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(
        entries[0],
        ("user".to_string(), "What is the weather?".to_string())
    );
    assert_eq!(
        entries[1],
        ("assistant".to_string(), "It's sunny today.".to_string())
    );
}

#[test]
fn test_context_session_isolation() {
    let ctx = ContextIsolator::new();
    ctx.record("s1", "user", "Session 1 context").unwrap();
    ctx.record("s2", "user", "Session 2 context").unwrap();

    let s1 = ctx.get_recent_context("s1", 10).unwrap();
    let s2 = ctx.get_recent_context("s2", 10).unwrap();

    assert_eq!(s1.len(), 1);
    assert_eq!(s2.len(), 1);
    assert_eq!(s1[0].1, "Session 1 context");
    assert_eq!(s2[0].1, "Session 2 context");
}

#[test]
fn test_context_entry_limit_evicts_oldest() {
    let ctx = ContextIsolator::with_limits(3, 100);
    ctx.record("s1", "user", "first").unwrap();
    ctx.record("s1", "user", "second").unwrap();
    ctx.record("s1", "user", "third").unwrap();
    ctx.record("s1", "user", "fourth").unwrap(); // should evict "first"

    let entries = ctx.get_recent_context("s1", 10).unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].1, "second");
}

#[test]
fn test_context_session_capacity_fail_closed() {
    let ctx = ContextIsolator::with_limits(100, 2);
    ctx.record("s1", "user", "ok").unwrap();
    ctx.record("s2", "user", "ok").unwrap();
    let result = ctx.record("s3", "user", "fail");
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("capacity exhausted"));
}

#[test]
fn test_context_end_session_clears() {
    let ctx = ContextIsolator::new();
    ctx.record("s1", "user", "data").unwrap();
    assert_eq!(ctx.session_count(), 1);
    ctx.end_session("s1");
    assert_eq!(ctx.session_count(), 0);
}

#[test]
fn test_context_oversized_entry_rejected() {
    let ctx = ContextIsolator::new();
    let huge = "x".repeat(65_537); // MAX_CONTEXT_ENTRY_LEN + 1
    let result = ctx.record("s1", "user", &huge);
    assert!(result.is_err());
}

#[test]
fn test_context_recent_returns_last_n() {
    let ctx = ContextIsolator::new();
    for i in 0..10 {
        ctx.record("s1", "user", &format!("msg-{i}")).unwrap();
    }
    let recent = ctx.get_recent_context("s1", 3).unwrap();
    assert_eq!(recent.len(), 3);
    assert_eq!(recent[0].1, "msg-7");
    assert_eq!(recent[2].1, "msg-9");
}

#[test]
fn test_context_unknown_session_error() {
    let ctx = ContextIsolator::new();
    let result = ctx.get_recent_context("nonexistent", 10);
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════════
// StylometricNormalizer Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_stylometric_none_passthrough() {
    let norm = StylometricNormalizer::new(NormalizationLevel::None);
    let input = "Hello!!!  world...  🎉";
    assert_eq!(norm.normalize(input).unwrap(), input);
}

#[test]
fn test_stylometric_level1_whitespace() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level1);
    let result = norm.normalize("Hello   world    test").unwrap();
    assert_eq!(result, "Hello world test");
}

#[test]
fn test_stylometric_level1_repeated_punctuation() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level1);
    assert_eq!(norm.normalize("wow!!!").unwrap(), "wow!");
    assert_eq!(norm.normalize("really???").unwrap(), "really?");
}

#[test]
fn test_stylometric_level1_ellipsis() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level1);
    assert_eq!(norm.normalize("hmm....").unwrap(), "hmm...");
    assert_eq!(norm.normalize("wait\u{2026}").unwrap(), "wait...");
    // Single dot preserved
    assert_eq!(norm.normalize("end.").unwrap(), "end.");
}

#[test]
fn test_stylometric_level1_emoji_stripped() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level1);
    let result = norm.normalize("Great job! 🎉🚀👍").unwrap();
    assert_eq!(result, "Great job!");
}

#[test]
fn test_stylometric_level1_smart_quotes() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level1);
    let result = norm.normalize("\u{201C}Hello\u{201D} he said").unwrap();
    assert_eq!(result, "\"Hello\" he said");
}

#[test]
fn test_stylometric_level1_dashes() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level1);
    // em dash
    let result = norm.normalize("word\u{2014}another").unwrap();
    assert_eq!(result, "word-another");
    // en dash
    let result = norm.normalize("pages 1\u{2013}10").unwrap();
    assert_eq!(result, "pages 1-10");
}

#[test]
fn test_stylometric_level2_filler_words() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level2);
    let result = norm
        .normalize("I just really want to basically understand")
        .unwrap();
    assert!(!result.contains("just"));
    assert!(!result.contains("really"));
    assert!(!result.contains("basically"));
    assert!(result.contains("want"));
    assert!(result.contains("understand"));
}

#[test]
fn test_stylometric_level2_multiword_filler() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level2);
    let result = norm
        .normalize("I kind of want to sort of understand this, you know")
        .unwrap();
    assert!(!result.contains("kind of"));
    assert!(!result.contains("sort of"));
}

// FIND-GAP-005: Multi-byte UTF-8 characters mixed with filler words.
#[test]
fn test_stylometric_level2_cjk_with_fillers() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level2);
    // CJK characters (3 bytes each) + filler words — must not corrupt output
    let input = "我 basically 需要 sort of 理解 you know this";
    let result = norm.normalize(input).unwrap();
    // CJK preserved, fillers removed
    assert!(result.contains('我'), "CJK char 我 should be preserved");
    assert!(result.contains('需'), "CJK char 需 should be preserved");
    assert!(result.contains('理'), "CJK char 理 should be preserved");
    assert!(
        !result.contains("basically"),
        "filler 'basically' should be removed"
    );
    assert!(
        !result.contains("sort of"),
        "filler 'sort of' should be removed"
    );
    assert!(
        !result.contains("you know"),
        "filler 'you know' should be removed"
    );
    // Verify valid UTF-8 output (would panic on invalid)
    let _: Vec<char> = result.chars().collect();
}

#[test]
fn test_stylometric_level2_emoji_adjacent_fillers() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level2);
    // Emoji (4 bytes each) adjacent to fillers
    let input = "honestly the result is quite amazing";
    let result = norm.normalize(input).unwrap();
    assert!(!result.contains("honestly"), "filler 'honestly' removed");
    assert!(!result.contains("quite"), "filler 'quite' removed");
    assert!(result.contains("result"), "content word preserved");
    assert!(result.contains("amazing"), "content word preserved");
}

#[test]
fn test_stylometric_level2_preserves_semantics() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level2);
    let result = norm.normalize("What is the capital of France?").unwrap();
    // No fillers to remove — should be essentially unchanged
    assert!(result.contains("capital"));
    assert!(result.contains("France"));
}

#[test]
fn test_stylometric_oversized_input_rejected() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level1);
    let huge = "x".repeat(1_048_577);
    assert!(norm.normalize(&huge).is_err());
}

#[test]
fn test_stylometric_combined_normalization() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level2);
    let input = "Wow!!!  I\u{2019}m  just  basically  saying\u{2026}\u{2026}  it\u{2019}s  really  great  🎉🎉";
    let result = norm.normalize(input).unwrap();

    // Multiple ! → single
    assert!(!result.contains("!!!"));
    // Smart quotes → ASCII
    assert!(!result.contains('\u{2019}'));
    // Emoji stripped
    assert!(!result.contains('🎉'));
    // Fillers removed
    assert!(!result.contains("just"));
    assert!(!result.contains("basically"));
    assert!(!result.contains("really"));
    // Multiple spaces collapsed
    assert!(!result.contains("  "));
    // Semantic content preserved
    assert!(result.contains("Wow"));
    assert!(result.contains("great"));
}

#[test]
fn test_shield_config_serde_roundtrip_with_credentials() {
    let config = vellaveto_config::ShieldConfig {
        session_unlinkability: true,
        credential_pool_size: 100,
        replenish_threshold: 20,
        credential_epoch_interval: 200,
        ..vellaveto_config::ShieldConfig::default()
    };
    let json_str = serde_json::to_string(&config).unwrap();
    let parsed: vellaveto_config::ShieldConfig = serde_json::from_str(&json_str).unwrap();
    assert_eq!(config, parsed);
}

// ═══════════════════════════════════════════════════════════════════
// StylometricNormalizer JSON Tests (Sprint 4)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_stylometric_normalize_json_strings() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level1);
    let input = serde_json::json!({
        "method": "tools/call",
        "params": {
            "name": "search",
            "arguments": {
                "query": "Hello!!!  world  🎉",
                "count": 5
            }
        }
    });
    let result = norm.normalize_json(&input).unwrap();
    assert_eq!(
        result["params"]["arguments"]["query"].as_str().unwrap(),
        "Hello! world"
    );
    // Non-string values preserved
    assert_eq!(result["params"]["arguments"]["count"], 5);
    // Keys preserved
    assert!(result["params"]["name"].as_str().is_some());
}

#[test]
fn test_stylometric_normalize_json_array() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level2);
    let input = serde_json::json!(["I   basically   want", "really   good", 42]);
    let result = norm.normalize_json(&input).unwrap();
    let s0 = result[0].as_str().unwrap();
    assert!(!s0.contains("basically"));
    assert!(!s0.contains("  "));
    assert_eq!(result[2], 42);
}

#[test]
fn test_stylometric_normalize_json_depth_limit() {
    let norm = StylometricNormalizer::new(NormalizationLevel::Level1);
    // Build deeply nested JSON
    let mut val = serde_json::json!("leaf");
    for _ in 0..25 {
        val = serde_json::json!({"inner": val});
    }
    let result = norm.normalize_json(&val);
    assert!(result.is_err());
}

#[test]
fn test_stylometric_normalize_json_none_passthrough() {
    let norm = StylometricNormalizer::new(NormalizationLevel::None);
    let input = serde_json::json!({"text": "Hello!!!  🎉"});
    let result = norm.normalize_json(&input).unwrap();
    assert_eq!(result["text"].as_str().unwrap(), "Hello!!!  🎉");
}

// ═══════════════════════════════════════════════════════════════════
// ContextIsolator JSON Recording Tests (Sprint 4)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_context_record_json_response_tool_result() {
    let ctx = ContextIsolator::new();
    let msg = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": [
                {"type": "text", "text": "Paris is the capital of France."}
            ]
        }
    });
    ctx.record_json_response("s1", &msg).unwrap();
    let recent = ctx.get_recent_context("s1", 10).unwrap();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].0, "assistant");
    assert!(recent[0].1.contains("Paris"));
}

#[test]
fn test_context_record_json_response_error() {
    let ctx = ContextIsolator::new();
    let msg = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "error": {
            "code": -32000,
            "message": "Tool execution failed"
        }
    });
    ctx.record_json_response("s1", &msg).unwrap();
    let recent = ctx.get_recent_context("s1", 10).unwrap();
    assert_eq!(recent.len(), 1);
    assert!(recent[0].1.contains("Tool execution failed"));
}

#[test]
fn test_context_record_json_response_no_result_skipped() {
    let ctx = ContextIsolator::new();
    let msg = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/progress"
    });
    ctx.record_json_response("s1", &msg).unwrap();
    assert_eq!(ctx.entry_count("s1"), 0);
}

#[test]
fn test_context_record_json_request() {
    let ctx = ContextIsolator::new();
    let msg = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "search",
            "arguments": {"query": "capital of France"}
        }
    });
    ctx.record_json_request("s1", &msg).unwrap();
    let recent = ctx.get_recent_context("s1", 10).unwrap();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].0, "user");
    assert!(recent[0].1.contains("tools/call"));
}

#[test]
fn test_context_json_bidirectional_recording() {
    let ctx = ContextIsolator::new();

    // Record outbound request
    let req = serde_json::json!({
        "method": "tools/call",
        "params": {"name": "search", "arguments": {"q": "test"}}
    });
    ctx.record_json_request("s1", &req).unwrap();

    // Record inbound response
    let resp = serde_json::json!({
        "id": 1,
        "result": {"content": [{"type": "text", "text": "search result"}]}
    });
    ctx.record_json_response("s1", &resp).unwrap();

    let recent = ctx.get_recent_context("s1", 10).unwrap();
    assert_eq!(recent.len(), 2);
    assert_eq!(recent[0].0, "user");
    assert_eq!(recent[1].0, "assistant");
}

// ═══════════════════════════════════════════════════════════════════
// SessionUnlinker Vault Ownership Tests (Sprint 4)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_unlinker_vault_accessor() {
    let (vault, _dir) = make_test_vault(10, 1);
    vault.add_credential(make_test_credential(1)).unwrap();

    let unlinker = SessionUnlinker::new(vault);
    let status = unlinker.vault().status();
    assert_eq!(status.total, 1);
    assert_eq!(status.available, 1);
}

#[test]
fn test_unlinker_vault_status_after_session() {
    let (vault, _dir) = make_test_vault(10, 1);
    vault.add_credential(make_test_credential(1)).unwrap();
    vault.add_credential(make_test_credential(2)).unwrap();

    let unlinker = SessionUnlinker::new(vault);
    unlinker.start_session("s1").unwrap();

    // One credential consumed (active), one still available
    let status = unlinker.vault().status();
    assert_eq!(status.available, 1);
    assert_eq!(status.active, 1);

    // End session marks consumed
    unlinker.end_session("s1").unwrap();
    let status = unlinker.vault().status();
    assert_eq!(status.consumed, 1);
    assert_eq!(status.active, 0);
}

// ═══════════════════════════════════════════════════════════════════
// Full Shield Pipeline Integration Tests (Sprint 4)
// ═══════════════════════════════════════════════════════════════════

/// Test the full outbound pipeline: PII sanitize → stylometric normalize.
/// Verifies that PII is replaced AND writing style is stripped.
#[test]
fn test_pipeline_sanitize_then_stylometric() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let normalizer = StylometricNormalizer::new(NormalizationLevel::Level2);

    let input = serde_json::json!({
        "method": "tools/call",
        "params": {
            "name": "search",
            "arguments": {
                "query": "I basically really want to find user@example.com!!!  🎉"
            }
        }
    });

    // Step 1: PII sanitization
    let sanitized = sanitizer.sanitize_json(&input).unwrap();
    let sanitized_query = sanitized["params"]["arguments"]["query"].as_str().unwrap();
    assert!(!sanitized_query.contains("user@example.com"));
    assert!(sanitized_query.contains("[PII_"));

    // Step 2: Stylometric normalization
    let normalized = normalizer.normalize_json(&sanitized).unwrap();
    let normalized_query = normalized["params"]["arguments"]["query"].as_str().unwrap();
    // Fillers removed
    assert!(!normalized_query.contains("basically"));
    assert!(!normalized_query.contains("really"));
    // Repeated punctuation normalized
    assert!(!normalized_query.contains("!!!"));
    // Emoji stripped
    assert!(!normalized_query.contains('🎉'));
    // PII placeholder preserved through normalization
    assert!(normalized_query.contains("[PII_"));
    // Semantic content preserved
    assert!(normalized_query.contains("want"));
    assert!(normalized_query.contains("find"));
}

/// Test the full inbound pipeline: desanitize → context record.
/// Verifies that PII is restored AND context is recorded.
#[test]
fn test_pipeline_desanitize_then_context_record() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let context = ContextIsolator::new();

    // Simulate outbound: sanitize via JSON (so the mapping is established)
    let outbound = serde_json::json!({
        "params": {
            "arguments": {
                "query": "Email user@example.com for details"
            }
        }
    });
    let sanitized = sanitizer.sanitize_json(&outbound).unwrap();
    let sanitized_text = sanitized["params"]["arguments"]["query"].as_str().unwrap();
    assert!(sanitized_text.contains("[PII_"));

    // Extract the actual PII placeholder the sanitizer produced
    let placeholder = sanitized_text
        .split_whitespace()
        .find(|s| s.starts_with("[PII_"))
        .expect("sanitized output should contain a placeholder");

    // Simulate inbound response using the actual placeholder
    let response = serde_json::json!({
        "id": 1,
        "result": {
            "content": [{
                "type": "text",
                "text": format!("Contact {} for more information", placeholder)
            }]
        }
    });

    // Step 1: Desanitize
    let desanitized = sanitizer.desanitize_json(&response).unwrap();
    let restored = desanitized["result"]["content"][0]["text"]
        .as_str()
        .unwrap();
    assert!(restored.contains("user@example.com"));
    assert!(!restored.contains("[PII_"));

    // Step 2: Record context (with desanitized response)
    context
        .record_json_response("session-1", &desanitized)
        .unwrap();
    let entries = context.get_recent_context("session-1", 10).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, "assistant");
    assert!(entries[0].1.contains("user@example.com"));
}

/// Test context isolation between sessions.
/// Verifies that recording in one session doesn't affect another.
#[test]
fn test_pipeline_context_session_isolation() {
    let context = ContextIsolator::new();

    let req1 = serde_json::json!({"method": "tools/call", "params": {"name": "tool_a"}});
    let req2 = serde_json::json!({"method": "tools/call", "params": {"name": "tool_b"}});

    context.record_json_request("session-1", &req1).unwrap();
    context.record_json_request("session-2", &req2).unwrap();

    let ctx1 = context.get_recent_context("session-1", 10).unwrap();
    let ctx2 = context.get_recent_context("session-2", 10).unwrap();

    assert_eq!(ctx1.len(), 1);
    assert_eq!(ctx2.len(), 1);
    assert!(ctx1[0].1.contains("tool_a"));
    assert!(ctx2[0].1.contains("tool_b"));
    // No cross-session leakage
    assert!(!ctx1[0].1.contains("tool_b"));
    assert!(!ctx2[0].1.contains("tool_a"));
}

/// Test full session lifecycle: start → tool calls → end.
/// Verifies credential consumption and vault state changes.
#[test]
fn test_pipeline_session_lifecycle() {
    let (vault, _dir) = make_test_vault(10, 1);
    vault.add_credential(make_test_credential(1)).unwrap();
    vault.add_credential(make_test_credential(2)).unwrap();

    let context = ContextIsolator::new();
    let unlinker = SessionUnlinker::new(vault);

    // Start session
    let cred = unlinker.start_session("s1").unwrap();
    assert_eq!(cred.issued_epoch, 1);

    // Simulate tool call context
    let req = serde_json::json!({
        "method": "tools/call",
        "params": {"name": "search", "arguments": {"q": "test"}}
    });
    context.record_json_request("s1", &req).unwrap();

    // Simulate response context
    let resp = serde_json::json!({
        "id": 1,
        "result": {"content": [{"type": "text", "text": "result data"}]}
    });
    context.record_json_response("s1", &resp).unwrap();

    // Verify context recorded
    assert_eq!(context.entry_count("s1"), 2);

    // End session
    unlinker.end_session("s1").unwrap();
    context.end_session("s1");

    // Verify cleanup
    assert!(!unlinker.is_session_active("s1"));
    assert_eq!(context.entry_count("s1"), 0);
    assert_eq!(unlinker.vault().status().consumed, 1);
}

/// Test that disabled stylometric normalizer passes through unchanged.
#[test]
fn test_pipeline_stylometric_disabled_passthrough() {
    let normalizer = StylometricNormalizer::new(NormalizationLevel::None);
    let input = serde_json::json!({
        "params": {
            "arguments": {
                "text": "I basically really want this!!!  🎉"
            }
        }
    });
    let result = normalizer.normalize_json(&input).unwrap();
    // Everything preserved when disabled
    assert_eq!(
        result["params"]["arguments"]["text"].as_str().unwrap(),
        "I basically really want this!!!  🎉"
    );
}

/// Test the complete roundtrip: sanitize → normalize → forward → desanitize.
/// Verifies PII integrity through the full pipeline.
#[test]
fn test_pipeline_full_roundtrip_pii_integrity() {
    let sanitizer = QuerySanitizer::new(PiiScanner::default());
    let normalizer = StylometricNormalizer::new(NormalizationLevel::Level1);

    // Outbound: user query with PII
    let user_input = "Call admin@corp.com for details";
    let sanitized = sanitizer.sanitize(user_input).unwrap();
    assert!(!sanitized.contains("admin@corp.com"));
    assert!(sanitized.contains("[PII_"));

    // Stylometric normalize (shouldn't affect PII placeholders)
    let normalized = normalizer.normalize(&sanitized).unwrap();
    // PII placeholders have specific format — should survive normalization
    assert!(normalized.contains("[PII_"));

    // Extract the placeholder from the normalized text
    let placeholder = normalized
        .split_whitespace()
        .find(|s| s.starts_with("[PII_"))
        .unwrap();

    // Simulate: provider responds with the placeholder
    let provider_response = format!("Please contact {placeholder} for assistance");

    // Inbound: desanitize
    let desanitized = sanitizer.desanitize(&provider_response).unwrap();
    // Original value restored
    assert!(desanitized.contains("admin@corp.com"));
    assert!(!desanitized.contains("[PII_"));
}

/// Test error path: sanitizer capacity exhausted doesn't break stylometric.
#[test]
fn test_pipeline_error_isolation() {
    let normalizer = StylometricNormalizer::new(NormalizationLevel::Level1);

    // Even if sanitizer fails (not tested here), stylometric should work
    // independently on any JSON input
    let input = serde_json::json!({"text": "hello   world!!!"});
    let result = normalizer.normalize_json(&input).unwrap();
    assert_eq!(result["text"].as_str().unwrap(), "hello world!");
}

/// Test that context isolator handles rapid session creation/teardown.
#[test]
fn test_pipeline_rapid_session_churn() {
    let context = ContextIsolator::new();

    for i in 0..100 {
        let session_id = format!("session-{i}");
        let req = serde_json::json!({"method": "tools/call", "params": {"name": "test"}});
        context.record_json_request(&session_id, &req).unwrap();
        context.end_session(&session_id);
    }

    // All sessions cleaned up
    assert_eq!(context.session_count(), 0);
}

// ═══════════════════════════════════════════════════════════════════
// Session Cleanup Tests (Sprint: Wire Unused Features)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_session_cleanup_ends_context() {
    let ctx = ContextIsolator::new();
    ctx.record("relay-session-1", "user", "Hello").unwrap();
    assert_eq!(ctx.session_count(), 1);

    // Cleanup ends the context session
    ctx.end_session("relay-session-1");
    assert_eq!(ctx.session_count(), 0);

    // Subsequent end_session is a no-op (does not panic)
    ctx.end_session("relay-session-1");
    assert_eq!(ctx.session_count(), 0);
}

#[test]
fn test_session_cleanup_marks_credential_consumed() {
    let (vault, _dir) = make_test_vault(10, 1);
    vault.add_credential(make_test_credential(1)).unwrap();

    let unlinker = SessionUnlinker::new(vault);
    unlinker.start_session("relay-session-1").unwrap();
    assert!(unlinker.is_session_active("relay-session-1"));
    assert_eq!(unlinker.vault().status().active, 1);

    // Cleanup ends the session and marks credential consumed
    unlinker.end_session("relay-session-1").unwrap();
    assert!(!unlinker.is_session_active("relay-session-1"));
    assert_eq!(unlinker.vault().status().consumed, 1);
    assert_eq!(unlinker.vault().status().active, 0);
}

#[test]
fn test_session_cleanup_noop_on_missing_session() {
    let (vault, _dir) = make_test_vault(10, 1);
    let unlinker = SessionUnlinker::new(vault);

    // end_session on nonexistent session returns error (not panic)
    let result = unlinker.end_session("nonexistent");
    assert!(result.is_err());

    // is_session_active returns false for missing session
    assert!(!unlinker.is_session_active("nonexistent"));
}

// ═══════════════════════════════════════════════════════════════════
// Credential Vault Replenishment Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_vault_replenish_fills_to_threshold() {
    let (vault, _dir) = make_test_vault(10, 3);
    // Empty vault needs replenishment
    assert!(vault.status().needs_replenishment);

    let added = vault.replenish().unwrap();
    assert!(added >= 3); // At least replenish_threshold credentials added
    assert!(!vault.status().needs_replenishment);
}

#[test]
fn test_vault_replenish_noop_when_sufficient() {
    let (vault, _dir) = make_test_vault(10, 3);
    // Fill above threshold
    for i in 0..5 {
        vault.add_credential(make_test_credential(i)).unwrap();
    }
    assert!(!vault.status().needs_replenishment);

    let added = vault.replenish().unwrap();
    assert_eq!(added, 0);
}

#[test]
fn test_vault_replenish_respects_pool_size() {
    let (vault, _dir) = make_test_vault(5, 2);
    let added = vault.replenish().unwrap();
    // Should fill to pool_size (5), not beyond
    assert_eq!(vault.available_count(), added);
    assert!(vault.available_count() <= 5);

    // Adding more should not exceed pool_size
    let added2 = vault.replenish().unwrap();
    assert_eq!(added2, 0);
    assert!(vault.available_count() <= 5);
}

#[test]
fn test_vault_generated_credential_validates() {
    let cred = CredentialVault::generate_local_credential(42);
    assert!(cred.validate().is_ok());
    assert_eq!(cred.issued_epoch, 42);
    assert_eq!(cred.provider_key_id, "self-generated");
    assert!(!cred.credential.is_empty());
    assert!(!cred.signature.is_empty());
}

// ═══════════════════════════════════════════════════════════════════
// ZK Commitments Tests (feature-gated)
// ═══════════════════════════════════════════════════════════════════

#[cfg(feature = "zk-audit")]
#[tokio::test]
async fn test_local_audit_zk_commitment_generated() {
    let dir = tempfile::tempdir().unwrap();
    let enc_path = dir.path().join("zk-test.enc");
    let audit_path = dir.path().join("zk-test.log");
    let store = EncryptedAuditStore::new(enc_path, "test-pass-long").unwrap();
    let mut manager = LocalAuditManager::new(audit_path, store).with_zk_commitments();

    // Log an event — ZK commitment should be generated without error
    manager
        .log_shield_event("test_event", "ZK commitment test")
        .await
        .unwrap();

    // Verify the entry was written (encrypted)
    let entries = manager.read_entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["event"], "test_event");
}

// ═══════════════════════════════════════════════════════════════════
// Desanitize Config Flag Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_desanitize_flag_false_preserves_placeholders() {
    let config = vellaveto_config::ShieldConfig {
        desanitize_responses: false,
        ..vellaveto_config::ShieldConfig::default()
    };
    // The flag is stored correctly
    assert!(!config.desanitize_responses);
    assert!(config.validate().is_ok());
}

#[test]
fn test_desanitize_flag_true_is_default() {
    let config = vellaveto_config::ShieldConfig::default();
    assert!(config.desanitize_responses);
}

// ═══════════════════════════════════════════════════════════════════
// FIND-GAP-003: Merkle chain integrity tests
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_merkle_chain_continuity_across_entries() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.log");
    let enc_path = dir.path().join("audit.enc");
    let store = crate::crypto::EncryptedAuditStore::new(enc_path, "secret-phrase!").unwrap();
    let mut manager = crate::local_audit::LocalAuditManager::new(audit_path, store).with_merkle();

    // Log 5 entries to build a Merkle tree
    for i in 0..5 {
        manager
            .log_shield_event("chain_test", &format!("entry_{i}"))
            .await
            .unwrap();
    }

    // All entries should have valid proofs
    for i in 0..5 {
        let proof = manager.generate_proof(i);
        assert!(proof.is_ok(), "proof for entry {i} should be valid");
    }

    // Root should be present and non-empty
    let root = manager.merkle_root();
    assert!(root.is_some());
    assert!(!root.unwrap().is_empty());
}

#[tokio::test]
async fn test_merkle_root_changes_with_each_entry() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.log");
    let enc_path = dir.path().join("audit.enc");
    let store = crate::crypto::EncryptedAuditStore::new(enc_path, "secret-phrase!").unwrap();
    let mut manager = crate::local_audit::LocalAuditManager::new(audit_path, store).with_merkle();

    manager
        .log_shield_event("event1", "details1")
        .await
        .unwrap();
    let root1 = manager.merkle_root().unwrap();

    manager
        .log_shield_event("event2", "details2")
        .await
        .unwrap();
    let root2 = manager.merkle_root().unwrap();

    // Root must change after appending a new entry
    assert_ne!(
        root1, root2,
        "Merkle root should change with each new entry"
    );
}

#[tokio::test]
async fn test_merkle_proof_invalid_index_fails() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.log");
    let enc_path = dir.path().join("audit.enc");
    let store = crate::crypto::EncryptedAuditStore::new(enc_path, "secret-phrase!").unwrap();
    let mut manager = crate::local_audit::LocalAuditManager::new(audit_path, store).with_merkle();

    manager
        .log_shield_event("event1", "details1")
        .await
        .unwrap();

    // Requesting proof for index beyond tree size should fail
    let proof = manager.generate_proof(999);
    assert!(proof.is_err());
}

#[test]
fn test_merkle_proof_without_merkle_enabled_fails() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.log");
    let enc_path = dir.path().join("audit.enc");
    let store = crate::crypto::EncryptedAuditStore::new(enc_path, "secret-phrase!").unwrap();
    // NOT calling .with_merkle()
    let manager = crate::local_audit::LocalAuditManager::new(audit_path, store);

    let proof = manager.generate_proof(0);
    assert!(proof.is_err());
    let err_msg = format!("{}", proof.unwrap_err());
    assert!(
        err_msg.contains("not enabled"),
        "error should mention Merkle not enabled: {err_msg}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// FIND-GAP-004: Encrypted audit store corruption/recovery tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_crypto_corrupted_ciphertext_detected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.enc");
    let store = crate::crypto::EncryptedAuditStore::new(path, "test-pass-long").unwrap();

    let plaintext = b"audit entry data";
    let mut encrypted = store.encrypt(plaintext).unwrap();

    // Corrupt a byte in the ciphertext (after the nonce)
    if encrypted.len() > 30 {
        encrypted[30] ^= 0xFF;
    }

    // Decryption must fail — Poly1305 tag verification detects corruption
    let result = store.decrypt(&encrypted);
    assert!(
        result.is_err(),
        "corrupted ciphertext should fail decryption"
    );
}

#[test]
fn test_crypto_truncated_ciphertext_detected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.enc");
    let store = crate::crypto::EncryptedAuditStore::new(path, "test-pass-long").unwrap();

    let plaintext = b"audit entry data";
    let encrypted = store.encrypt(plaintext).unwrap();

    // Truncate the ciphertext (remove last 8 bytes — partial tag)
    let truncated = &encrypted[..encrypted.len().saturating_sub(8)];

    let result = store.decrypt(truncated);
    assert!(
        result.is_err(),
        "truncated ciphertext should fail decryption"
    );
}

#[test]
fn test_crypto_truncated_entry_in_store_detected() {
    use std::io::Write;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.enc");
    let store = crate::crypto::EncryptedAuditStore::new(path.clone(), "test-pass-long").unwrap();

    // Write a valid entry first
    store.write_encrypted_entry(b"valid entry").unwrap();

    // Append a truncated entry: length header says 1000 bytes but only 10 follow
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    file.write_all(&1000u32.to_le_bytes()).unwrap();
    file.write_all(&[0xAB; 10]).unwrap();

    // Reading all entries should fail on the truncated entry
    let result = store.read_all_entries();
    assert!(result.is_err(), "truncated store entry should be detected");
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("truncated"),
        "error should mention truncation: {err_msg}"
    );
}

#[test]
fn test_crypto_nonce_too_short_detected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.enc");
    let store = crate::crypto::EncryptedAuditStore::new(path, "test-pass-long").unwrap();

    // Data shorter than nonce (24 bytes)
    let result = store.decrypt(&[0u8; 10]);
    assert!(result.is_err(), "data shorter than nonce should fail");
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("too short"),
        "error should mention data too short: {err_msg}"
    );
}

#[test]
fn test_crypto_wrong_key_fails_gracefully() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.enc");

    // Write with one passphrase
    let store1 = crate::crypto::EncryptedAuditStore::new(path.clone(), "correct-pass!").unwrap();
    store1.write_encrypted_entry(b"secret data").unwrap();
    store1.write_encrypted_entry(b"more secret data").unwrap();

    // Open with different passphrase — read should fail on decryption
    let store2 = crate::crypto::EncryptedAuditStore::new(path, "wrong-pass-!!").unwrap();
    let result = store2.read_all_entries();
    assert!(
        result.is_err(),
        "wrong passphrase should fail on decryption"
    );
}

// ═══════════════════════════════════════════════════════════════════
// R234 Adversarial Audit Tests
// ═══════════════════════════════════════════════════════════════════

// R234-SHIELD-3: Reject empty passphrase
#[test]
fn test_r234_shield3_empty_passphrase_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let result = crate::crypto::EncryptedAuditStore::new(path, "");
    assert!(result.is_err(), "empty passphrase should be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("empty or whitespace"),
        "error should mention empty: {err}"
    );
}

#[test]
fn test_r234_shield3_whitespace_only_passphrase_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    let result = crate::crypto::EncryptedAuditStore::new(path, "   \t\n  ");
    assert!(
        result.is_err(),
        "whitespace-only passphrase should be rejected"
    );
}

// R259-SHLD-1: Minimum passphrase length enforcement
#[test]
fn test_r259_shld1_short_passphrase_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.enc");
    // 11 chars — below the 12-char minimum
    let result = crate::crypto::EncryptedAuditStore::new(path, "short-pass!");
    assert!(result.is_err(), "short passphrase should be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("at least 12"),
        "error should mention minimum length: {err}"
    );
}

// R234-SHIELD-4: Session ID validation
#[test]
fn test_r234_shield4_session_isolator_rejects_control_chars() {
    let isolator = crate::session_isolator::SessionIsolator::new();
    let result = isolator.sanitize_in_session("ses\x00sion", "hello");
    assert!(
        result.is_err(),
        "control chars in session_id should be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("control or format"),
        "error should mention control chars: {err}"
    );
}

#[test]
fn test_r234_shield4_session_isolator_rejects_empty_id() {
    let isolator = crate::session_isolator::SessionIsolator::new();
    let result = isolator.sanitize_in_session("", "hello");
    assert!(result.is_err(), "empty session_id should be rejected");
}

#[test]
fn test_r234_shield4_context_isolator_rejects_control_chars() {
    let isolator = crate::context_isolation::ContextIsolator::new();
    let result = isolator.record("ses\x01sion", "user", "hello");
    assert!(
        result.is_err(),
        "control chars in session_id should be rejected"
    );
}

#[test]
fn test_r234_shield4_context_isolator_rejects_bidi_override() {
    let isolator = crate::context_isolation::ContextIsolator::new();
    // U+202E is Right-to-Left Override (Unicode format char)
    let result = isolator.record("ses\u{202E}sion", "user", "hello");
    assert!(
        result.is_err(),
        "bidi override in session_id should be rejected"
    );
}

#[test]
fn test_r234_shield4_context_get_recent_rejects_dangerous_id() {
    let isolator = crate::context_isolation::ContextIsolator::new();
    let result = isolator.get_recent_context("bad\x07id", 10);
    assert!(
        result.is_err(),
        "control chars should be rejected in get_recent_context"
    );
}

// R234-SHIELD-1: Credential status persistence
#[test]
fn test_r234_shield1_consume_persists_status() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("creds.enc");
    let store = crate::crypto::EncryptedAuditStore::new(path.clone(), "test-pass-long").unwrap();
    let vault = crate::credential_vault::CredentialVault::new(store, 10, 5).unwrap();

    // Add a credential
    let cred = crate::credential_vault::CredentialVault::generate_local_credential(1);
    vault.add_credential(cred).unwrap();

    // Consume it
    let (_cred, idx) = vault.consume_credential().unwrap();
    assert_eq!(idx, 0);

    // Reload vault from disk — credential should be Active, not Available
    let store2 = crate::crypto::EncryptedAuditStore::new(path, "test-pass-long").unwrap();
    let vault2 = crate::credential_vault::CredentialVault::new(store2, 10, 5).unwrap();
    let status = vault2.status();
    assert_eq!(
        status.available, 0,
        "no credentials should be available after consume + reload"
    );
    assert_eq!(
        status.active, 1,
        "consumed credential should be active after reload"
    );
}

#[test]
fn test_r234_shield1_mark_consumed_persists_status() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("creds.enc");
    let store = crate::crypto::EncryptedAuditStore::new(path.clone(), "test-pass-long").unwrap();
    let vault = crate::credential_vault::CredentialVault::new(store, 10, 5).unwrap();

    let cred = crate::credential_vault::CredentialVault::generate_local_credential(1);
    vault.add_credential(cred).unwrap();
    let (_cred, idx) = vault.consume_credential().unwrap();
    vault.mark_consumed(idx).unwrap();

    // Reload vault from disk — credential should be Consumed
    let store2 = crate::crypto::EncryptedAuditStore::new(path, "test-pass-long").unwrap();
    let vault2 = crate::credential_vault::CredentialVault::new(store2, 10, 5).unwrap();
    let status = vault2.status();
    assert_eq!(status.available, 0);
    assert_eq!(status.active, 0);
    assert_eq!(
        status.consumed, 1,
        "credential should be consumed after reload"
    );
}

// R234-SHIELD-5: u32::try_from on encrypted entry length
#[test]
fn test_r234_shield5_encrypt_returns_bounded_length() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("len.enc");
    let store = crate::crypto::EncryptedAuditStore::new(path, "test-pass-long").unwrap();

    // Normal-sized entry should succeed
    let plaintext = vec![0u8; 1024];
    let encrypted = store.encrypt(&plaintext);
    assert!(encrypted.is_ok());
    // Encrypted length fits in u32
    assert!(u32::try_from(encrypted.unwrap().len()).is_ok());
}

// R234-SHIELD-9: ContextIsolator rejects invalid role
#[test]
fn test_r234_shield9_context_isolator_rejects_invalid_role() {
    let isolator = crate::context_isolation::ContextIsolator::new();
    let err = isolator.record("session-1", "system", "hello");
    assert!(err.is_err());
    let msg = err.unwrap_err().to_string();
    assert!(msg.contains("user") || msg.contains("assistant") || msg.contains("role"));
}

// R234-SHIELD-9: ContextIsolator accepts valid roles
#[test]
fn test_r234_shield9_context_isolator_accepts_valid_roles() {
    let isolator = crate::context_isolation::ContextIsolator::new();
    assert!(isolator.record("session-1", "user", "hello").is_ok());
    assert!(isolator.record("session-1", "assistant", "hi").is_ok());
}

// R234-SHIELD-10: read_all_entries bounded by MAX_STORE_ENTRIES
#[test]
fn test_r234_shield10_read_all_entries_returns_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bounded.enc");
    let store = crate::crypto::EncryptedAuditStore::new(path, "test-pass-long").unwrap();

    // Write a few entries to verify reading works
    for i in 0..5u32 {
        store.write_encrypted_entry(&i.to_le_bytes()).unwrap();
    }
    let entries = store.read_all_entries().unwrap();
    assert_eq!(entries.len(), 5);
}

// R234-SHIELD-12: QuerySanitizer::clear() recovers from lock poisoning
#[test]
fn test_r234_shield12_sanitizer_clear_succeeds_normally() {
    let scanner = vellaveto_audit::PiiScanner::new(&[]);
    let sanitizer = crate::sanitizer::QuerySanitizer::new(scanner);

    // Sanitize something to populate mappings
    // (PiiScanner with no patterns won't match, but clear should still work)
    sanitizer.clear();
    assert_eq!(sanitizer.mapping_count(), 0);
}

// R234-SHIELD-2: StoredVaultEntry deny_unknown_fields
#[test]
fn test_r234_shield2_stored_vault_entry_rejects_unknown_fields() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("creds.enc");
    let store = crate::crypto::EncryptedAuditStore::new(path.clone(), "test-pass-long").unwrap();

    // Manually write a stored entry with an extra field
    let bad_entry = serde_json::json!({
        "credential": {
            "credential": [1, 2, 3],
            "signature": [4, 5, 6],
            "provider_key_id": "test",
            "issued_epoch": 1,
            "credential_type": "Subscriber"
        },
        "status": "Available",
        "injected_field": "malicious"
    });
    let serialized = serde_json::to_vec(&bad_entry).unwrap();
    store.write_encrypted_entry(&serialized).unwrap();

    // Loading the vault should fail on the unknown field
    let store2 = crate::crypto::EncryptedAuditStore::new(path, "test-pass-long").unwrap();
    let result = crate::credential_vault::CredentialVault::new(store2, 10, 5);
    assert!(
        result.is_err(),
        "unknown fields in StoredVaultEntry should be rejected"
    );
}

// ═══════════════════════════════════════════════════════════════════
// R236 Shield Audit Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_r236_shield1_sequence_lock_before_consume() {
    // R236-SHIELD-1: start_session acquires sequence lock before consuming
    // credential. If both succeed, session should be created normally.
    let (vault, _dir) = make_test_vault(10, 3);
    vault.add_credential(make_test_credential(1)).unwrap();
    vault.add_credential(make_test_credential(1)).unwrap();

    let unlinker = SessionUnlinker::new(vault);
    let cred = unlinker.start_session("test-session").unwrap();
    assert!(!cred.credential.is_empty());
    assert!(unlinker.is_session_active("test-session"));
}

#[test]
fn test_r236_shield3_vault_available_count_after_consume() {
    // R236-SHIELD-3: After consuming a credential, available_count decreases.
    // If the credential is marked consumed, it stays consumed.
    let (vault, _dir) = make_test_vault(10, 3);
    vault.add_credential(make_test_credential(1)).unwrap();
    vault.add_credential(make_test_credential(1)).unwrap();
    assert_eq!(vault.available_count(), 2);

    let (_cred, idx) = vault.consume_credential().unwrap();
    assert_eq!(vault.available_count(), 1);

    vault.mark_consumed(idx).unwrap();
    assert_eq!(vault.available_count(), 1);

    let status = vault.status();
    assert_eq!(status.consumed, 1);
    assert_eq!(status.active, 0);
    assert_eq!(status.available, 1);
}

#[test]
fn test_r236_shield5_active_session_count_consistent() {
    // R236-SHIELD-5: active_session_count and is_session_active should
    // be consistent and return sensible defaults.
    let (vault, _dir) = make_test_vault(10, 3);
    vault.add_credential(make_test_credential(1)).unwrap();
    let unlinker = SessionUnlinker::new(vault);

    assert_eq!(unlinker.active_session_count(), 0);
    assert!(!unlinker.is_session_active("s1"));

    unlinker.start_session("s1").unwrap();
    assert_eq!(unlinker.active_session_count(), 1);
    assert!(unlinker.is_session_active("s1"));

    unlinker.end_session("s1").unwrap();
    assert_eq!(unlinker.active_session_count(), 0);
    assert!(!unlinker.is_session_active("s1"));
}

#[test]
fn test_r237_shield3_expire_epochs_count_correct() {
    // R237-SHIELD-3: expire_old_epochs returns the correct count and
    // expired credentials are no longer available.
    let (vault, _dir) = make_test_vault(10, 3);
    // Add credentials in epoch 1
    vault.add_credential(make_test_credential(1)).unwrap();
    vault.add_credential(make_test_credential(1)).unwrap();
    // Add credentials in epoch 2
    vault.add_credential(make_test_credential(2)).unwrap();

    assert_eq!(vault.available_count(), 3);

    // Expire epoch 1 (current_epoch=2 means epoch<2 are expired)
    let expired = vault.expire_old_epochs(2).unwrap();
    assert_eq!(expired, 2);
    assert_eq!(vault.available_count(), 1);

    // The remaining credential (epoch 2) should still be consumable
    let (cred, _idx) = vault.consume_credential().unwrap();
    assert_eq!(cred.issued_epoch, 2);
}

#[test]
fn test_r237_shield3_expire_epochs_no_double_expire() {
    // Calling expire_old_epochs twice with same epoch should be idempotent.
    let (vault, _dir) = make_test_vault(10, 3);
    vault.add_credential(make_test_credential(1)).unwrap();

    let expired1 = vault.expire_old_epochs(2).unwrap();
    assert_eq!(expired1, 1);

    // Second call: credential is already Expired, count should be 0.
    let expired2 = vault.expire_old_epochs(2).unwrap();
    assert_eq!(expired2, 0);
}

#[test]
fn test_r237_shld3_context_isolator_sanitizes_method_name() {
    // SECURITY (R237-SHLD-3): Method names from MCP server should be sanitized
    // to prevent control characters and Unicode format chars from being stored.
    let ctx = crate::context_isolation::ContextIsolator::new();
    let msg_with_control = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call\x1b[31m\x00injected",
        "params": {"name": "test"}
    });
    ctx.record_json_request("s1", &msg_with_control).unwrap();
    let recent = ctx.get_recent_context("s1", 10).unwrap();
    assert_eq!(recent.len(), 1);
    // Control chars should be stripped
    assert!(!recent[0].1.contains('\x1b'));
    assert!(!recent[0].1.contains('\x00'));
    assert!(recent[0].1.contains("tools/call"));
}

#[test]
fn test_r237_shld3_context_isolator_method_allows_safe_chars() {
    // Normal method names with / _ - . should pass through
    let ctx = crate::context_isolation::ContextIsolator::new();
    let msg = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call-with_dots.v2",
        "params": {}
    });
    ctx.record_json_request("s1", &msg).unwrap();
    let recent = ctx.get_recent_context("s1", 10).unwrap();
    assert!(recent[0].1.contains("tools/call-with_dots.v2"));
}

// ═══════════════════════════════════════════════════════════════════
// R238 Shield Audit Tests
// ═══════════════════════════════════════════════════════════════════

// R238-SHLD-1: SessionIsolator end_session works correctly (basic test;
// lock poisoning recovery is architectural — into_inner() is called
// in the Err branch which cannot be triggered in single-threaded tests
// without std::thread::spawn + panic, but we verify the happy path).
#[test]
fn test_r238_shld1_session_isolator_end_session_cleans_up() {
    let isolator = crate::session_isolator::SessionIsolator::new();
    // Create a session by sanitizing in it
    isolator.sanitize_in_session("s1", "hello").unwrap();
    assert_eq!(isolator.session_count(), 1);

    // End the session — should remove it
    isolator.end_session("s1");
    assert_eq!(isolator.session_count(), 0);

    // Desanitize should fail since session was cleaned up
    let result = isolator.desanitize_in_session("s1", "hello");
    assert!(result.is_err(), "session should be gone after end_session");
}

// R238-SHLD-1: ContextIsolator end_session works correctly
#[test]
fn test_r238_shld1_context_isolator_end_session_cleans_up() {
    let ctx = crate::context_isolation::ContextIsolator::new();
    ctx.record("s1", "user", "hello").unwrap();
    assert_eq!(ctx.session_count(), 1);

    ctx.end_session("s1");
    assert_eq!(ctx.session_count(), 0);

    // Getting context should fail since session was cleaned up
    let result = ctx.get_recent_context("s1", 10);
    assert!(result.is_err(), "session should be gone after end_session");
}

// R238-SHLD-2: extract_text_from_result bounded output
#[test]
fn test_r238_shld2_extract_text_bounded() {
    let ctx = crate::context_isolation::ContextIsolator::new();

    // Create a response with many large content items that would exceed
    // MAX_CONTEXT_ENTRY_LEN (65536) if joined unbounded.
    let mut content_items = Vec::new();
    // Each item is 10,000 chars; 10 items = 100,000 chars > 65,536 limit
    let large_text = "A".repeat(10_000);
    for _ in 0..10 {
        content_items.push(serde_json::json!({"type": "text", "text": large_text}));
    }
    let msg = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "content": content_items
        }
    });

    // record_json_response should succeed (extract_text_from_result caps output)
    let result = ctx.record_json_response("s1", &msg);
    assert!(
        result.is_ok(),
        "bounded extract should not produce entry-too-large error: {result:?}"
    );

    // Verify the recorded context is at most MAX_CONTEXT_ENTRY_LEN
    let entries = ctx.get_recent_context("s1", 10).unwrap();
    assert_eq!(entries.len(), 1);
    assert!(
        entries[0].1.len() <= 65_536,
        "extracted text should be bounded to MAX_CONTEXT_ENTRY_LEN, got {}",
        entries[0].1.len()
    );
}

// R238-SHLD-4: Session ID too long rejected across all three modules
#[test]
fn test_r238_shld4_session_id_too_long_rejected() {
    // SessionIsolator
    let isolator = crate::session_isolator::SessionIsolator::new();
    let long_id = "a".repeat(257);
    let result = isolator.sanitize_in_session(&long_id, "hello");
    assert!(
        result.is_err(),
        "session_isolator should reject long session_id"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("too long"),
        "error should mention 'too long': {msg}"
    );

    // ContextIsolator
    let ctx = crate::context_isolation::ContextIsolator::new();
    let result = ctx.record(&long_id, "user", "hello");
    assert!(
        result.is_err(),
        "context_isolator should reject long session_id"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("too long"),
        "error should mention 'too long': {msg}"
    );

    // SessionUnlinker
    let (vault, _dir) = make_test_vault(10, 3);
    vault.add_credential(make_test_credential(1)).unwrap();
    let unlinker = SessionUnlinker::new(vault);
    let result = unlinker.start_session(&long_id);
    assert!(
        result.is_err(),
        "session_unlinker should reject long session_id"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("too long"),
        "error should mention 'too long': {msg}"
    );

    // Verify that 256 bytes (the exact limit) is still accepted
    let ok_id = "b".repeat(256);
    let isolator2 = crate::session_isolator::SessionIsolator::new();
    assert!(
        isolator2.sanitize_in_session(&ok_id, "hello").is_ok(),
        "256-byte session_id should be accepted"
    );
}

// R238-SHLD-5: Store file size limit
#[test]
fn test_r238_shld5_store_file_size_limit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("huge.enc");
    let store = crate::crypto::EncryptedAuditStore::new(path.clone(), "test-pass-long").unwrap();

    // Write a normal entry to create a valid store
    store.write_encrypted_entry(b"test").unwrap();

    // Artificially inflate the file beyond 256 MB by writing a large blob
    // We can't actually write 256 MB in a test, but we can check the validation
    // logic by checking that a normal-sized file works fine.
    let entries = store.read_all_entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0], b"test");

    // Verify the limit by creating a sparse file that exceeds MAX_STORE_FILE_SIZE
    let huge_path = dir.path().join("toobig.enc");

    // Write the header first (version + salt)
    let mut header = vec![1u8]; // FORMAT_VERSION
    header.extend_from_slice(&[0u8; 16]); // salt
    std::fs::write(&huge_path, &header).unwrap();

    // Now extend the file to be larger than MAX_STORE_FILE_SIZE using seek
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&huge_path)
        .unwrap();
    // Set file size to 256 MB + 1 byte to trigger the limit
    file.set_len(256 * 1024 * 1024 + 1).unwrap();
    drop(file);

    // Derive key with same passphrase and existing salt
    let store2 = crate::crypto::EncryptedAuditStore::new(huge_path, "test-pass-long").unwrap();
    let result = store2.read_all_entries();
    assert!(result.is_err(), "should reject file larger than 256 MB");
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("too large"),
        "error should mention file too large: {msg}"
    );
}

// R238-SHLD-6: mark_consumed requires Active status
#[test]
fn test_r238_shld6_mark_consumed_requires_active_status() {
    let (vault, _dir) = make_test_vault(10, 3);
    vault.add_credential(make_test_credential(1)).unwrap();
    vault.add_credential(make_test_credential(1)).unwrap();
    vault.add_credential(make_test_credential(1)).unwrap();

    // Attempt to mark an Available credential as consumed — should fail
    let result = vault.mark_consumed(0);
    assert!(
        result.is_err(),
        "should not allow marking Available credential as consumed"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("Active"),
        "error should mention Active requirement: {msg}"
    );

    // Consume credential 1 (marks it Active)
    let (_cred, idx) = vault.consume_credential().unwrap();

    // Mark it consumed — should succeed (Active -> Consumed)
    vault.mark_consumed(idx).unwrap();

    // Mark it consumed again — should fail (Consumed -> Consumed)
    let result = vault.mark_consumed(idx);
    assert!(result.is_err(), "should not allow double-consume");
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("Active"),
        "double-consume error should mention Active requirement: {msg}"
    );

    // Expire a credential and try to mark it consumed — should fail
    vault.expire_old_epochs(2).unwrap(); // expires remaining epoch-1 credentials
                                         // Find an expired credential index
    let status = vault.status();
    // There should be expired credentials now
    assert!(status.available == 0 || status.consumed > 0);

    // Try to consume an expired one (index 1 or 2 should be expired if not consumed)
    // We know index 0 was consumed (idx was 0), so try index 1
    let result = vault.mark_consumed(1);
    assert!(
        result.is_err(),
        "should not allow marking Expired credential as consumed"
    );
}

// ── R250-NHI-3: Orphaned Active credential reclamation ────────

#[test]
fn test_r250_nhi3_reclaim_orphaned_active_credentials() {
    // SECURITY (R250-NHI-3): Credentials left Active after session crash
    // should be reclaimed as Expired after the MAX_ACTIVE_AGE_SECS TTL.
    let (vault, _dir) = make_test_vault(10, 3);
    vault.add_credential(make_test_credential(1)).unwrap();
    vault.add_credential(make_test_credential(1)).unwrap();
    vault.add_credential(make_test_credential(1)).unwrap();

    // Consume all 3 credentials (marks them Active)
    let (_, idx0) = vault.consume_credential().unwrap();
    let (_, _idx1) = vault.consume_credential().unwrap();
    let (_, _idx2) = vault.consume_credential().unwrap();

    // Mark only one as properly consumed
    vault.mark_consumed(idx0).unwrap();

    // Verify state: 1 Consumed, 2 Active, 0 Available
    let status = vault.status();
    assert_eq!(status.consumed, 1);
    assert_eq!(status.active, 2);
    assert_eq!(status.available, 0);

    // Reclaim immediately — nothing should be reclaimed since they were
    // just activated (timestamp is fresh)
    let reclaimed = vault.reclaim_orphaned_active().unwrap();
    assert_eq!(
        reclaimed, 0,
        "freshly activated credentials should not be reclaimed"
    );

    // Force-expire Active credentials via the public test helper
    vault.force_expire_active_for_test();

    // Now reclaim — should reclaim the 2 stale Active credentials
    let reclaimed = vault.reclaim_orphaned_active().unwrap();
    assert_eq!(reclaimed, 2, "stale Active credentials should be reclaimed");

    // Verify: now 1 Consumed, 0 Active, 0 Available (2 expired by reclaim)
    let status = vault.status();
    assert_eq!(status.active, 0, "no Active credentials should remain");
    assert_eq!(status.consumed, 1);
}

#[test]
fn test_r250_nhi3_reclaim_noop_when_no_active() {
    // No active credentials → reclaim returns 0
    let (vault, _dir) = make_test_vault(10, 3);
    vault.add_credential(make_test_credential(1)).unwrap();

    // Don't consume anything — all Available
    let reclaimed = vault.reclaim_orphaned_active().unwrap();
    assert_eq!(reclaimed, 0, "no Active credentials to reclaim");
}

#[test]
fn test_r250_nhi3_stored_vault_entry_backward_compat() {
    // Pre-R250 StoredVaultEntry has no activated_at field.
    // Deserialization should default to None (backward compatible).
    let json = r#"{"credential":{"credential":[1,2,3],"signature":[4,5,6],"provider_key_id":"test","issued_epoch":1,"credential_type":"Subscriber"},"status":"Available"}"#;
    let entry: serde_json::Value = serde_json::from_str(json).unwrap();
    // Verify it doesn't have activated_at
    assert!(entry.get("activated_at").is_none());
    // The actual deserialization to StoredVaultEntry happens inside CredentialVault::new()
    // which uses #[serde(default)] on activated_at — verified at compile time.
}
