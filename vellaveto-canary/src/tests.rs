// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

use super::*;

fn test_signing_key() -> String {
    // Generate a deterministic test key
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    hex::encode(signing_key.to_bytes())
}

fn other_signing_key() -> String {
    let signing_key = SigningKey::from_bytes(&[99u8; 32]);
    hex::encode(signing_key.to_bytes())
}

/// SECURITY (DOC-CRED-2): Canaries published before domain separation must keep
/// verifying. A canary is a published artifact people re-check over time; a
/// change that silently invalidated old ones would look exactly like the
/// compromise a canary exists to signal.
#[test]
fn test_canary_signed_before_domain_separation_still_verifies() {
    let key = test_signing_key();
    let mut canary = create_canary("no warrants received", 30, &key).unwrap();

    let key_bytes = hex::decode(&key).unwrap();
    let key_array: [u8; 32] = key_bytes.try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&key_array);

    // Re-sign with the pre-domain-separation payload, as an existing published
    // canary would have been signed.
    let undomained = canonical_payload(
        canary.version,
        &canary.signed_date,
        &canary.expires_date,
        &canary.statement,
        false,
    )
    .unwrap();
    canary.signature = hex::encode(signing_key.sign(&undomained).to_bytes());

    let verification = verify_canary(&canary).expect("verify should succeed");
    assert!(
        verification.signature_valid,
        "canaries signed before domain separation must still verify"
    );
}

/// A canary signed under the domain must not verify against the undomained
/// payload, which is what makes the separation real rather than cosmetic.
#[test]
fn test_canary_domain_changes_the_signed_payload() {
    let key = test_signing_key();
    let canary = create_canary("no warrants received", 30, &key).unwrap();

    let domained = canonical_payload(
        canary.version,
        &canary.signed_date,
        &canary.expires_date,
        &canary.statement,
        true,
    )
    .unwrap();
    let undomained = canonical_payload(
        canary.version,
        &canary.signed_date,
        &canary.expires_date,
        &canary.statement,
        false,
    )
    .unwrap();

    assert_ne!(
        domained, undomained,
        "the domain tag must change the signed digest"
    );
}

#[test]
fn test_create_verify_roundtrip() {
    let key = test_signing_key();
    let canary = create_canary("No government surveillance orders received.", 90, &key)
        .expect("create should succeed");

    assert_eq!(canary.version, CANARY_VERSION);
    assert!(!canary.signature.is_empty());

    let verification = verify_canary(&canary).expect("verify should succeed");
    assert!(verification.signature_valid);
    assert!(!verification.expired);
    assert!(verification.days_remaining >= 89); // at least 89 days remaining
}

#[test]
fn test_expired_canary_detected() {
    let key = test_signing_key();
    let mut canary = create_canary("Test statement.", 90, &key).expect("create should succeed");

    // Manually set dates to the past (signed before expires for R259-CAN-1)
    canary.signed_date = "2019-06-01".to_string();
    canary.expires_date = "2020-01-01".to_string();
    // Re-sign with correct payload (otherwise signature will be invalid too)
    let key_bytes = hex::decode(&key).unwrap();
    let key_array: [u8; 32] = key_bytes.try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&key_array);
    let payload = canonical_payload(
        canary.version,
        &canary.signed_date,
        &canary.expires_date,
        &canary.statement,
        true,
    )
    .expect("canonical_payload should succeed");
    let sig = signing_key.sign(&payload);
    canary.signature = hex::encode(sig.to_bytes());

    let verification = verify_canary(&canary).expect("verify should succeed");
    assert!(verification.signature_valid);
    assert!(verification.expired);
    assert!(verification.days_remaining < 0);
}

#[test]
fn test_tampered_statement_rejected() {
    let key = test_signing_key();
    let mut canary = create_canary("Original statement.", 90, &key).expect("create should succeed");

    canary.statement = "Tampered statement.".to_string();

    let verification = verify_canary(&canary).expect("verify should succeed");
    assert!(
        !verification.signature_valid,
        "tampered canary should fail verification"
    );
}

#[test]
fn test_wrong_key_rejected() {
    let key = test_signing_key();
    let other_key = other_signing_key();

    let canary = create_canary("Test statement.", 90, &key).expect("create should succeed");

    // Create a new canary with a different key and swap the verifying key
    let other_canary =
        create_canary("Test statement.", 90, &other_key).expect("create should succeed");

    let mut tampered = canary.clone();
    tampered.verifying_key = other_canary.verifying_key;

    let verification = verify_canary(&tampered).expect("verify should succeed");
    assert!(
        !verification.signature_valid,
        "wrong key should fail verification"
    );
}

#[test]
fn test_max_statement_length_enforced() {
    let key = test_signing_key();
    let long_statement = "a".repeat(MAX_STATEMENT_LENGTH + 1);
    let result = create_canary(&long_statement, 90, &key);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("max length"));
}

#[test]
fn test_dangerous_chars_rejected() {
    let key = test_signing_key();
    let result = create_canary("test\u{200B}statement", 90, &key);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("dangerous"));
}

// R259-CAN-1: Reject canaries where signed_date > expires_date
#[test]
fn test_r259_can1_verify_rejects_reversed_dates() {
    let key = test_signing_key();
    let mut canary = create_canary("Test canary statement.", 90, &key).unwrap();

    // Forge a canary with signed_date in the future of expires_date.
    // Re-sign so the signature is valid — the check must still reject.
    canary.signed_date = "2026-12-31".to_string();
    canary.expires_date = "2026-01-01".to_string();

    let key_bytes = hex::decode(&key).unwrap();
    let key_array: [u8; 32] = key_bytes.try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&key_array);
    let payload = canonical_payload(
        canary.version,
        &canary.signed_date,
        &canary.expires_date,
        &canary.statement,
        true,
    )
    .unwrap();
    let sig = signing_key.sign(&payload);
    canary.signature = hex::encode(sig.to_bytes());

    let result = verify_canary(&canary);
    assert!(result.is_err(), "reversed dates should be rejected");
    let err = result.unwrap_err();
    assert!(
        err.contains("must not be after"),
        "error should mention date ordering: {err}"
    );
}
