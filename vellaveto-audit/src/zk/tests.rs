// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Tests for the ZK audit trail module (Phase 37).

use super::circuit::{hash_to_field, AuditChainCircuit};
use super::pedersen::PedersenCommitter;
use super::prover::ZkBatchProver;
use super::scheduler::ZkBatchScheduler;
use super::witness::{EntryWitness, WitnessStore};
use ark_bn254::Fr;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystem};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256};
use std::sync::Arc;

// ═══════════════════════════════════════════════════
// PEDERSEN COMMITMENT TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_pedersen_commit_verify_roundtrip() {
    let committer = PedersenCommitter::new();
    let entry_hash = [0x42u8; 32];

    let (commitment, blinding) = committer.commit(&entry_hash).unwrap();
    assert!(committer.verify(&commitment, &entry_hash, &blinding));
}

#[test]
fn test_pedersen_verify_rejects_wrong_hash() {
    let committer = PedersenCommitter::new();
    let entry_hash = [0x42u8; 32];
    let wrong_hash = [0x43u8; 32];

    let (commitment, blinding) = committer.commit(&entry_hash).unwrap();
    assert!(!committer.verify(&commitment, &wrong_hash, &blinding));
}

#[test]
fn test_pedersen_verify_rejects_wrong_blinding() {
    let committer = PedersenCommitter::new();
    let entry_hash = [0x42u8; 32];

    let (commitment, _blinding) = committer.commit(&entry_hash).unwrap();
    let wrong_blinding = Scalar::random(&mut rand_core_06::OsRng);
    assert!(!committer.verify(&commitment, &entry_hash, &wrong_blinding));
}

#[test]
fn test_pedersen_different_entries_different_commitments() {
    let committer = PedersenCommitter::new();
    let hash1 = [0x01u8; 32];
    let hash2 = [0x02u8; 32];

    let (c1, _) = committer.commit(&hash1).unwrap();
    let (c2, _) = committer.commit(&hash2).unwrap();

    assert_ne!(
        c1, c2,
        "Different entries should produce different commitments"
    );
}

#[test]
fn test_pedersen_same_entry_different_blinding() {
    let committer = PedersenCommitter::new();
    let entry_hash = [0xABu8; 32];

    let (c1, b1) = committer.commit(&entry_hash).unwrap();
    let (c2, b2) = committer.commit(&entry_hash).unwrap();

    // Same entry but different blinding should produce different commitments
    assert_ne!(b1, b2, "Blinding factors should differ");
    assert_ne!(
        c1, c2,
        "Commitments should differ due to different blinding"
    );

    // But both should verify
    assert!(committer.verify(&c1, &entry_hash, &b1));
    assert!(committer.verify(&c2, &entry_hash, &b2));
}

#[test]
fn test_pedersen_zero_entry_hash() {
    let committer = PedersenCommitter::new();
    let zero_hash = [0u8; 32];

    let (commitment, blinding) = committer.commit(&zero_hash).unwrap();
    assert!(committer.verify(&commitment, &zero_hash, &blinding));
}

#[test]
fn test_pedersen_max_entry_hash() {
    let committer = PedersenCommitter::new();
    let max_hash = [0xFFu8; 32];

    let (commitment, blinding) = committer.commit(&max_hash).unwrap();
    assert!(committer.verify(&commitment, &max_hash, &blinding));
}

#[test]
fn test_pedersen_commitment_is_valid_point() {
    let committer = PedersenCommitter::new();
    let entry_hash = [0x42u8; 32];

    let (commitment, _) = committer.commit(&entry_hash).unwrap();

    // Should be a valid compressed Ristretto point (decompressible)
    let decompressed = PedersenCommitter::decompress(&commitment);
    assert!(
        decompressed.is_ok(),
        "Commitment should be a valid Ristretto point"
    );
}

#[test]
fn test_pedersen_deterministic_h_generator() {
    // Two independently created committers should produce the same H
    let c1 = PedersenCommitter::new();
    let c2 = PedersenCommitter::new();

    let entry_hash = [0x42u8; 32];

    // Use the same blinding to check they produce identical commitments
    let blinding = Scalar::from(42u64);

    // Compute commitment using verify: both should accept the same commitment
    let entry_scalar = Scalar::from_bytes_mod_order(entry_hash);
    let expected = entry_scalar * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT
        + blinding * c1.h_point();
    let compressed = expected.compress();

    assert!(c1.verify(&compressed, &entry_hash, &blinding));
    assert!(c2.verify(&compressed, &entry_hash, &blinding));
}

#[test]
fn test_pedersen_default_creates_valid_committer() {
    let committer = PedersenCommitter::default();
    let entry_hash = [0x42u8; 32];
    let (commitment, blinding) = committer.commit(&entry_hash).unwrap();
    assert!(committer.verify(&commitment, &entry_hash, &blinding));
}

#[test]
fn test_pedersen_commitment_hex_roundtrip() {
    let committer = PedersenCommitter::new();
    let entry_hash = [0x42u8; 32];

    let (commitment, blinding) = committer.commit(&entry_hash).unwrap();

    // Convert to hex and back
    let commitment_hex = hex::encode(commitment.as_bytes());
    let blinding_hex = hex::encode(blinding.as_bytes());

    // Reconstruct commitment
    let commitment_bytes = hex::decode(&commitment_hex).unwrap();
    let restored_commitment =
        CompressedRistretto::from_slice(&commitment_bytes).expect("valid 32-byte slice");

    // Reconstruct blinding
    let blinding_bytes = hex::decode(&blinding_hex).unwrap();
    let mut blinding_arr = [0u8; 32];
    blinding_arr.copy_from_slice(&blinding_bytes);
    let restored_blinding = Scalar::from_canonical_bytes(blinding_arr);
    assert!(
        bool::from(restored_blinding.is_some()),
        "Blinding should be canonical"
    );
    let restored_blinding = restored_blinding.unwrap();

    assert!(committer.verify(&restored_commitment, &entry_hash, &restored_blinding));
}

#[test]
fn test_pedersen_multiple_commits_all_verify() {
    let committer = PedersenCommitter::new();
    for i in 0..50u8 {
        let hash = [i; 32];
        let (c, b) = committer.commit(&hash).unwrap();
        assert!(committer.verify(&c, &hash, &b), "Failed at i={}", i);
    }
}

// ═══════════════════════════════════════════════════
// WITNESS STORE TESTS
// ═══════════════════════════════════════════════════

fn make_test_witness(seq: u64) -> EntryWitness {
    EntryWitness {
        sequence: seq,
        entry_hash: [seq as u8; 32],
        prev_hash: [0u8; 32],
        blinding: Scalar::from(seq),
        commitment: CompressedRistretto::from_slice(&[0u8; 32]).expect("valid 32 bytes"),
    }
}

#[test]
fn test_witness_store_new_is_empty() {
    let store = WitnessStore::new();
    assert!(store.is_empty().unwrap());
    assert_eq!(store.len().unwrap(), 0);
}

#[test]
fn test_witness_store_append_and_len() {
    let store = WitnessStore::new();
    store.append(make_test_witness(0)).unwrap();
    assert_eq!(store.len().unwrap(), 1);
    assert!(!store.is_empty().unwrap());
}

#[test]
fn test_witness_store_drain_returns_in_order() {
    let store = WitnessStore::new();
    for i in 0..5 {
        store.append(make_test_witness(i)).unwrap();
    }

    let drained = store.drain(3).unwrap();
    assert_eq!(drained.len(), 3);
    assert_eq!(drained[0].sequence, 0);
    assert_eq!(drained[1].sequence, 1);
    assert_eq!(drained[2].sequence, 2);

    assert_eq!(store.len().unwrap(), 2);
}

#[test]
fn test_witness_store_drain_more_than_available() {
    let store = WitnessStore::new();
    store.append(make_test_witness(0)).unwrap();

    let drained = store.drain(100).unwrap();
    assert_eq!(drained.len(), 1);
    assert!(store.is_empty().unwrap());
}

#[test]
fn test_witness_store_drain_empty() {
    let store = WitnessStore::new();
    let drained = store.drain(10).unwrap();
    assert!(drained.is_empty());
}

#[test]
fn test_witness_store_capacity_bound() {
    let store = WitnessStore::with_capacity(3);
    assert_eq!(store.max_capacity(), 3);

    store.append(make_test_witness(0)).unwrap();
    store.append(make_test_witness(1)).unwrap();
    store.append(make_test_witness(2)).unwrap();

    // At capacity — next append should fail
    let result = store.append(make_test_witness(3));
    assert!(result.is_err(), "Should reject append at capacity");

    // After draining, can append again
    let _ = store.drain(1).unwrap();
    assert!(store.append(make_test_witness(3)).is_ok());
}

#[test]
fn test_witness_store_default_capacity() {
    let store = WitnessStore::new();
    assert_eq!(store.max_capacity(), 100_000);
}

#[test]
fn test_witness_store_default_trait() {
    let store = WitnessStore::default();
    assert!(store.is_empty().unwrap());
}

#[test]
fn test_witness_store_drain_preserves_remaining_order() {
    let store = WitnessStore::new();
    for i in 0..10 {
        store.append(make_test_witness(i)).unwrap();
    }

    let _ = store.drain(5).unwrap();

    let remaining = store.drain(5).unwrap();
    assert_eq!(remaining.len(), 5);
    assert_eq!(remaining[0].sequence, 5);
    assert_eq!(remaining[4].sequence, 9);
}

// ═══════════════════════════════════════════════════
// WITNESS STORE RESTORE TESTS (IMP-R120-001)
// ═══════════════════════════════════════════════════

#[test]
fn test_witness_store_restore_prepends_before_existing() {
    let store = WitnessStore::with_capacity(100);

    // Append witnesses 0..5
    for i in 0..5 {
        store.append(make_test_witness(i)).unwrap();
    }

    // Drain first 3 (sequences 0, 1, 2)
    let drained = store.drain(3).unwrap();
    assert_eq!(drained.len(), 3);
    assert_eq!(drained[0].sequence, 0);
    assert_eq!(drained[2].sequence, 2);

    // Store now has [3, 4]. Restore [0, 1, 2] to front.
    store.restore(drained).unwrap();

    // Drain all — should be [0, 1, 2, 3, 4]
    let all = store.drain(100).unwrap();
    assert_eq!(all.len(), 5);
    for (i, witness) in all.iter().enumerate() {
        assert_eq!(witness.sequence, i as u64, "wrong sequence at index {}", i);
    }
}

#[test]
fn test_witness_store_restore_empty_is_noop() {
    let store = WitnessStore::with_capacity(100);
    store.append(make_test_witness(42)).unwrap();

    store.restore(vec![]).unwrap();

    assert_eq!(store.len().unwrap(), 1);
    let all = store.drain(10).unwrap();
    assert_eq!(all[0].sequence, 42);
}

#[test]
fn test_witness_store_restore_preserves_order() {
    let store = WitnessStore::with_capacity(100);

    // Append [10, 11, 12]
    for i in 10..13 {
        store.append(make_test_witness(i)).unwrap();
    }

    // Drain all
    let drained = store.drain(100).unwrap();
    assert_eq!(drained.len(), 3);

    // Restore — order must be preserved
    store.restore(drained).unwrap();
    let result = store.drain(100).unwrap();
    assert_eq!(result[0].sequence, 10);
    assert_eq!(result[1].sequence, 11);
    assert_eq!(result[2].sequence, 12);
}

#[test]
fn test_witness_store_restore_caps_at_capacity() {
    // SECURITY (FIND-R222-006): restore() now enforces capacity to prevent
    // unbounded growth on persistent prover failure.
    let store = WitnessStore::with_capacity(5);

    // Fill to capacity
    for i in 0..5 {
        store.append(make_test_witness(i)).unwrap();
    }

    // Drain 3
    let drained = store.drain(3).unwrap();

    // Append 3 more — now at capacity again [3, 4, 5, 6, 7]
    for i in 5..8 {
        store.append(make_test_witness(i)).unwrap();
    }
    assert_eq!(store.len().unwrap(), 5);

    // Restore the 3 drained witnesses — capped at capacity (5).
    // Restored [0,1,2] are prioritized; 3 newest from [3,4,5,6,7] are dropped.
    store.restore(drained).unwrap();
    assert_eq!(store.len().unwrap(), 5); // Capped at max_capacity

    // Verify restored (older) witnesses are first, then surviving newer ones
    let all = store.drain(100).unwrap();
    assert_eq!(all[0].sequence, 0);
    assert_eq!(all[1].sequence, 1);
    assert_eq!(all[2].sequence, 2);
    assert_eq!(all[3].sequence, 3);
    assert_eq!(all[4].sequence, 4);
}

// ═══════════════════════════════════════════════════
// ZK TYPES SERDE TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_pedersen_commitment_type_serde_roundtrip() {
    let commitment = vellaveto_types::PedersenCommitment {
        commitment: "aabbccdd".repeat(8),
        blinding_hint: "11223344".repeat(8),
    };
    let json = serde_json::to_string(&commitment).unwrap();
    let deserialized: vellaveto_types::PedersenCommitment = serde_json::from_str(&json).unwrap();
    assert_eq!(commitment.commitment, deserialized.commitment);
    assert!(
        deserialized.blinding_hint.is_empty(),
        "blinding_hint must not roundtrip through serialized output"
    );
}

#[test]
fn test_zk_batch_proof_serde_roundtrip() {
    let proof = vellaveto_types::ZkBatchProof {
        proof: "deadbeef".repeat(16),
        batch_id: "batch-001".to_string(),
        entry_range: (0, 99),
        merkle_root: "abcd".repeat(16),
        first_prev_hash: "00".repeat(32),
        final_entry_hash: "ff".repeat(32),
        created_at: "2026-02-16T00:00:00Z".to_string(),
        entry_count: 100,
    };
    let json = serde_json::to_string(&proof).unwrap();
    let deserialized: vellaveto_types::ZkBatchProof = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.batch_id, "batch-001");
    assert_eq!(deserialized.entry_range, (0, 99));
    assert_eq!(deserialized.entry_count, 100);
}

#[test]
fn test_zk_verify_result_serde_roundtrip() {
    let result = vellaveto_types::ZkVerifyResult {
        valid: true,
        batch_id: "batch-001".to_string(),
        entry_range: (0, 99),
        verified_at: "2026-02-16T00:00:00Z".to_string(),
        error: None,
    };
    let json = serde_json::to_string(&result).unwrap();
    let deserialized: vellaveto_types::ZkVerifyResult = serde_json::from_str(&json).unwrap();
    assert!(deserialized.valid);
    assert!(deserialized.error.is_none());
}

#[test]
fn test_zk_verify_result_with_error() {
    let result = vellaveto_types::ZkVerifyResult {
        valid: false,
        batch_id: "batch-002".to_string(),
        entry_range: (100, 199),
        verified_at: "2026-02-16T01:00:00Z".to_string(),
        error: Some("Invalid proof".to_string()),
    };
    let json = serde_json::to_string(&result).unwrap();
    let deserialized: vellaveto_types::ZkVerifyResult = serde_json::from_str(&json).unwrap();
    assert!(!deserialized.valid);
    assert_eq!(deserialized.error.as_deref(), Some("Invalid proof"));
}

#[test]
fn test_zk_scheduler_status_serde_roundtrip() {
    let status = vellaveto_types::ZkSchedulerStatus {
        active: true,
        pending_witnesses: 42,
        completed_proofs: 5,
        last_proved_sequence: Some(499),
        last_proof_at: Some("2026-02-16T00:00:00Z".to_string()),
    };
    let json = serde_json::to_string(&status).unwrap();
    let deserialized: vellaveto_types::ZkSchedulerStatus = serde_json::from_str(&json).unwrap();
    assert!(deserialized.active);
    assert_eq!(deserialized.pending_witnesses, 42);
    assert_eq!(deserialized.completed_proofs, 5);
    assert_eq!(deserialized.last_proved_sequence, Some(499));
}

#[test]
fn test_zk_scheduler_status_minimal() {
    let status = vellaveto_types::ZkSchedulerStatus {
        active: false,
        pending_witnesses: 0,
        completed_proofs: 0,
        last_proved_sequence: None,
        last_proof_at: None,
    };
    let json = serde_json::to_string(&status).unwrap();
    assert!(!json.contains("last_proved_sequence"));
    assert!(!json.contains("last_proof_at"));
}

// ═══════════════════════════════════════════════════
// AUDIT ENTRY COMMITMENT FIELD TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_audit_entry_commitment_field_absent_by_default() {
    let entry = crate::AuditEntry {
        id: "test-1".to_string(),
        action: vellaveto_types::Action::new("tool", "fn", serde_json::json!({})),
        verdict: vellaveto_types::Verdict::Allow,
        timestamp: "2026-02-16T00:00:00Z".to_string(),
        metadata: serde_json::json!({}),
        sequence: 0,
        entry_hash: None,
        prev_hash: None,
        commitment: None,
        tenant_id: None,
        acis_envelope: None,
    };
    let json = serde_json::to_string(&entry).unwrap();
    assert!(
        !json.contains("commitment"),
        "commitment should be skipped when None"
    );
}

#[test]
fn test_audit_entry_with_commitment_serializes() {
    let entry = crate::AuditEntry {
        id: "test-2".to_string(),
        action: vellaveto_types::Action::new("tool", "fn", serde_json::json!({})),
        verdict: vellaveto_types::Verdict::Allow,
        timestamp: "2026-02-16T00:00:00Z".to_string(),
        metadata: serde_json::json!({}),
        sequence: 1,
        entry_hash: Some("aabb".repeat(16)),
        prev_hash: None,
        commitment: Some("ccdd".repeat(16)),
        tenant_id: None,
        acis_envelope: None,
    };
    let json = serde_json::to_string(&entry).unwrap();
    assert!(json.contains("commitment"), "commitment should be present");

    let deserialized: crate::AuditEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.commitment, Some("ccdd".repeat(16)));
}

#[test]
fn test_audit_entry_backward_compat_no_commitment() {
    let json = r#"{"id":"test","action":{"tool":"t","function":"f","parameters":{}},"verdict":"Allow","timestamp":"2026-02-16T00:00:00Z","metadata":{}}"#;
    let entry: crate::AuditEntry = serde_json::from_str(json).unwrap();
    assert!(entry.commitment.is_none());
}

// ═══════════════════════════════════════════════════
// PHASE 37.2: CIRCUIT TESTS
// ═══════════════════════════════════════════════════

/// Build a valid chain of (entry_hash, prev_hash) pairs as field elements.
fn make_test_chain(count: usize) -> (Vec<Fr>, Vec<Fr>) {
    let mut entry_hashes = Vec::new();
    let mut prev_hashes = Vec::new();
    let mut prev = [0u8; 32]; // genesis prev_hash

    for i in 0..count {
        let mut hasher = Sha256::new();
        hasher.update(format!("entry_{}", i).as_bytes());
        hasher.update(prev);
        let entry: [u8; 32] = hasher.finalize().into();

        prev_hashes.push(hash_to_field::<Fr>(&prev));
        entry_hashes.push(hash_to_field::<Fr>(&entry));
        prev = entry;
    }

    (entry_hashes, prev_hashes)
}

/// Build a valid chain of EntryWitness structs for prover tests.
fn make_chain_witnesses(count: usize) -> Vec<EntryWitness> {
    let committer = PedersenCommitter::new();
    let mut witnesses = Vec::new();
    let mut prev_hash = [0u8; 32]; // genesis

    for i in 0..count {
        let mut hasher = Sha256::new();
        hasher.update(format!("entry_{}", i).as_bytes());
        hasher.update(prev_hash);
        let entry_hash: [u8; 32] = hasher.finalize().into();

        let (commitment, blinding) = committer.commit(&entry_hash).unwrap();

        witnesses.push(EntryWitness {
            sequence: i as u64,
            entry_hash,
            prev_hash,
            blinding,
            commitment,
        });

        prev_hash = entry_hash;
    }

    witnesses
}

#[test]
fn test_hash_to_field_deterministic() {
    let hash = [0x42u8; 32];
    let f1: Fr = hash_to_field(&hash);
    let f2: Fr = hash_to_field(&hash);
    assert_eq!(f1, f2);
}

#[test]
fn test_hash_to_field_different_hashes_different_elements() {
    let hash1 = [0x01u8; 32];
    let hash2 = [0x02u8; 32];
    let f1: Fr = hash_to_field(&hash1);
    let f2: Fr = hash_to_field(&hash2);
    assert_ne!(f1, f2);
}

#[test]
fn test_hash_to_field_zero_hash() {
    let hash = [0u8; 32];
    let f: Fr = hash_to_field(&hash);
    assert_eq!(f, Fr::from(0u64));
}

#[test]
fn test_circuit_template_creation() {
    let circuit = AuditChainCircuit::<Fr>::template(10);
    assert_eq!(circuit.max_size, 10);
    assert!(circuit.first_prev_hash.is_none());
    assert!(circuit.final_hash.is_none());
    assert_eq!(circuit.entry_hashes.len(), 10);
    assert_eq!(circuit.prev_hashes.len(), 10);
}

#[test]
fn test_circuit_with_witnesses_wrong_entry_size() {
    let result = AuditChainCircuit::<Fr>::with_witnesses(
        3,
        Fr::from(0u64),
        Fr::from(1u64),
        vec![Fr::from(0u64); 2], // wrong: 2 instead of 3
        vec![Fr::from(0u64); 3],
    );
    assert!(result.is_err());
}

#[test]
fn test_circuit_with_witnesses_wrong_prev_size() {
    let result = AuditChainCircuit::<Fr>::with_witnesses(
        3,
        Fr::from(0u64),
        Fr::from(1u64),
        vec![Fr::from(0u64); 3],
        vec![Fr::from(0u64); 2], // wrong: 2 instead of 3
    );
    assert!(result.is_err());
}

#[test]
fn test_circuit_valid_chain_satisfied() {
    let (entry_hashes, prev_hashes) = make_test_chain(3);
    let first_prev = prev_hashes[0];
    let final_hash = entry_hashes[2];

    let circuit =
        AuditChainCircuit::with_witnesses(3, first_prev, final_hash, entry_hashes, prev_hashes)
            .unwrap();

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(
        cs.is_satisfied().unwrap(),
        "Valid chain should satisfy constraints"
    );
}

#[test]
fn test_circuit_single_entry_satisfied() {
    let (entry_hashes, prev_hashes) = make_test_chain(1);
    let first_prev = prev_hashes[0];
    let final_hash = entry_hashes[0];

    let circuit =
        AuditChainCircuit::with_witnesses(1, first_prev, final_hash, entry_hashes, prev_hashes)
            .unwrap();

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());
}

#[test]
fn test_circuit_broken_chain_linkage_unsatisfied() {
    let (mut entry_hashes, prev_hashes) = make_test_chain(3);
    let first_prev = prev_hashes[0];
    let final_hash = entry_hashes[2];

    // Tamper with entry_hash[0] — breaks linkage prev_hash[1] != entry_hash[0]
    entry_hashes[0] = Fr::from(99999u64);

    let circuit =
        AuditChainCircuit::with_witnesses(3, first_prev, final_hash, entry_hashes, prev_hashes)
            .unwrap();

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(
        !cs.is_satisfied().unwrap(),
        "Broken chain linkage should not satisfy constraints"
    );
}

#[test]
fn test_circuit_wrong_first_prev_hash_unsatisfied() {
    let (entry_hashes, prev_hashes) = make_test_chain(3);
    let final_hash = entry_hashes[2];

    // Wrong first_prev_hash
    let wrong_first = Fr::from(12345u64);

    let circuit =
        AuditChainCircuit::with_witnesses(3, wrong_first, final_hash, entry_hashes, prev_hashes)
            .unwrap();

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(
        !cs.is_satisfied().unwrap(),
        "Wrong first_prev_hash should not satisfy"
    );
}

#[test]
fn test_circuit_wrong_final_hash_unsatisfied() {
    let (entry_hashes, prev_hashes) = make_test_chain(3);
    let first_prev = prev_hashes[0];

    // Wrong final_hash
    let wrong_final = Fr::from(54321u64);

    let circuit =
        AuditChainCircuit::with_witnesses(3, first_prev, wrong_final, entry_hashes, prev_hashes)
            .unwrap();

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(
        !cs.is_satisfied().unwrap(),
        "Wrong final_hash should not satisfy"
    );
}

#[test]
fn test_circuit_empty_is_trivially_satisfied() {
    let circuit = AuditChainCircuit::<Fr> {
        max_size: 0,
        first_prev_hash: None,
        final_hash: None,
        entry_hashes: vec![],
        prev_hashes: vec![],
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());
}

#[test]
fn test_circuit_padded_batch_satisfied() {
    // Create a chain of 2 entries but use a circuit of size 4 (with padding)
    let (entry_hashes, prev_hashes) = make_test_chain(2);
    let first_prev = prev_hashes[0];
    let final_hash = entry_hashes[1];

    // Pad to size 4: replicate final_hash for both entry and prev
    let mut padded_entries = entry_hashes;
    let mut padded_prevs = prev_hashes;
    for _ in 0..2 {
        padded_entries.push(final_hash);
        padded_prevs.push(final_hash);
    }

    let circuit =
        AuditChainCircuit::with_witnesses(4, first_prev, final_hash, padded_entries, padded_prevs)
            .unwrap();

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(
        cs.is_satisfied().unwrap(),
        "Padded batch should satisfy constraints"
    );
}

#[test]
fn test_circuit_constraint_count() {
    // A chain of N entries should have N+2 constraints:
    // 1 for first_prev, N-1 for chain linkage, 1 for final_hash = N+1
    // (plus the variable allocation constraints from FpVar)
    let (entry_hashes, prev_hashes) = make_test_chain(5);
    let first_prev = prev_hashes[0];
    let final_hash = entry_hashes[4];

    let circuit =
        AuditChainCircuit::with_witnesses(5, first_prev, final_hash, entry_hashes, prev_hashes)
            .unwrap();

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    // At minimum: 1 + (N-1) + 1 = N+1 = 6 equality constraints
    let num_constraints = cs.num_constraints();
    assert!(
        num_constraints >= 6,
        "Expected at least 6 constraints, got {}",
        num_constraints
    );
}

// ═══════════════════════════════════════════════════
// PHASE 37.2: PROVER TESTS (slow — Groth16 operations)
// ═══════════════════════════════════════════════════

#[test]
fn test_prover_setup_succeeds() {
    let prover = ZkBatchProver::setup(3);
    assert!(prover.is_ok(), "Setup should succeed");
    assert_eq!(prover.unwrap().max_batch_size(), 3);
}

#[test]
fn test_prover_setup_zero_batch_size_rejected() {
    let result = ZkBatchProver::setup(0);
    assert!(result.is_err());
}

#[test]
fn test_prover_prove_verify_roundtrip() {
    let prover = ZkBatchProver::setup(3).unwrap();
    let witnesses = make_chain_witnesses(3);

    let proof = prover.prove(&witnesses).unwrap();
    assert_eq!(proof.entry_count, 3);
    assert_eq!(proof.entry_range, (0, 2));
    assert!(!proof.proof.is_empty());
    assert!(!proof.first_prev_hash.is_empty());
    assert!(!proof.final_entry_hash.is_empty());

    let result = prover.verify(&proof).unwrap();
    assert!(result.valid, "Proof should verify: {:?}", result.error);
}

#[test]
fn test_prover_prove_single_entry() {
    let prover = ZkBatchProver::setup(1).unwrap();
    let witnesses = make_chain_witnesses(1);

    let proof = prover.prove(&witnesses).unwrap();
    assert_eq!(proof.entry_count, 1);
    assert_eq!(proof.entry_range, (0, 0));

    let result = prover.verify(&proof).unwrap();
    assert!(result.valid, "Single entry proof should verify");
}

#[test]
fn test_prover_prove_padded_batch() {
    // Prover set up for size 4, proving only 2 entries
    let prover = ZkBatchProver::setup(4).unwrap();
    let witnesses = make_chain_witnesses(2);

    let proof = prover.prove(&witnesses).unwrap();
    assert_eq!(proof.entry_count, 2);

    let result = prover.verify(&proof).unwrap();
    assert!(result.valid, "Padded batch should verify");
}

#[test]
fn test_prover_prove_empty_batch_rejected() {
    let prover = ZkBatchProver::setup(3).unwrap();
    let result = prover.prove(&[]);
    assert!(result.is_err());
}

#[test]
fn test_prover_prove_batch_too_large_rejected() {
    let prover = ZkBatchProver::setup(2).unwrap();
    let witnesses = make_chain_witnesses(3);
    let result = prover.prove(&witnesses);
    assert!(result.is_err());
}

#[test]
fn test_prover_verify_tampered_proof_invalid() {
    let prover = ZkBatchProver::setup(3).unwrap();
    let witnesses = make_chain_witnesses(3);

    let mut proof = prover.prove(&witnesses).unwrap();

    // Tamper with the final_entry_hash (change public input)
    proof.final_entry_hash = "ff".repeat(32);

    let result = prover.verify(&proof).unwrap();
    assert!(!result.valid, "Tampered proof should not verify");
    assert!(result.error.is_some());
}

#[test]
fn test_prover_verify_tampered_proof_bytes_invalid() {
    let prover = ZkBatchProver::setup(3).unwrap();
    let witnesses = make_chain_witnesses(3);

    let mut proof = prover.prove(&witnesses).unwrap();

    // Tamper with the proof bytes themselves
    let mut bytes = hex::decode(&proof.proof).unwrap();
    if !bytes.is_empty() {
        bytes[0] ^= 0xFF;
    }
    proof.proof = hex::encode(&bytes);

    // Tampered proof bytes may fail deserialization or verification
    let result = prover.verify(&proof);
    // Either an error (deserialization) or invalid proof
    if let Ok(vr) = result {
        assert!(!vr.valid, "Tampered proof bytes should not verify");
    }
}

#[test]
fn test_prover_key_serialization_roundtrip() {
    let prover = ZkBatchProver::setup(2).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let pk_path = dir.path().join("pk.bin");
    let vk_path = dir.path().join("vk.bin");

    prover.save_keys(&pk_path, &vk_path).unwrap();

    // Load and verify with loaded keys
    let loaded = ZkBatchProver::from_files(&pk_path, &vk_path, 2).unwrap();
    let witnesses = make_chain_witnesses(2);

    let proof = loaded.prove(&witnesses).unwrap();
    let result = loaded.verify(&proof).unwrap();
    assert!(result.valid, "Proof from loaded keys should verify");

    // Original prover should also verify the proof
    let result2 = prover.verify(&proof).unwrap();
    assert!(
        result2.valid,
        "Original prover should verify loaded prover's proof"
    );
}

#[test]
fn test_prover_proof_contains_correct_metadata() {
    let prover = ZkBatchProver::setup(3).unwrap();
    let witnesses = make_chain_witnesses(3);

    let proof = prover.prove(&witnesses).unwrap();

    // Check public inputs match witness data
    assert_eq!(proof.first_prev_hash, hex::encode(witnesses[0].prev_hash));
    assert_eq!(proof.final_entry_hash, hex::encode(witnesses[2].entry_hash));
    assert!(!proof.batch_id.is_empty());
    assert!(!proof.merkle_root.is_empty());
    assert!(!proof.created_at.is_empty());
}

#[test]
fn test_prover_verify_wrong_hex_length_rejected() {
    let prover = ZkBatchProver::setup(2).unwrap();
    let witnesses = make_chain_witnesses(2);

    let mut proof = prover.prove(&witnesses).unwrap();
    proof.first_prev_hash = "aabb".to_string(); // too short

    let result = prover.verify(&proof);
    assert!(result.is_err());
}

#[test]
fn test_prover_batch_digest_deterministic() {
    let prover = ZkBatchProver::setup(2).unwrap();
    let witnesses = make_chain_witnesses(2);

    let proof1 = prover.prove(&witnesses).unwrap();
    let proof2 = prover.prove(&witnesses).unwrap();

    // Merkle root (batch digest) should be identical for same witnesses
    assert_eq!(proof1.merkle_root, proof2.merkle_root);
}

// ═══════════════════════════════════════════════════
// PHASE 37.2: SCHEDULER TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_scheduler_creation() {
    let prover = Arc::new(ZkBatchProver::setup(3).unwrap());
    let store = Arc::new(WitnessStore::new());
    let scheduler = ZkBatchScheduler::new(prover, store, 3, 300);
    assert_eq!(scheduler.pending_witnesses().unwrap(), 0);
    assert_eq!(scheduler.proof_count().unwrap(), 0);
}

#[test]
fn test_scheduler_prove_now_empty_returns_none() {
    let prover = Arc::new(ZkBatchProver::setup(3).unwrap());
    let store = Arc::new(WitnessStore::new());
    let scheduler = ZkBatchScheduler::new(prover, store, 3, 300);

    let result = scheduler.prove_now().unwrap();
    assert!(result.is_none(), "Empty store should produce no proof");
}

#[test]
fn test_scheduler_prove_now_with_witnesses() {
    let prover = Arc::new(ZkBatchProver::setup(3).unwrap());
    let store = Arc::new(WitnessStore::new());
    let witnesses = make_chain_witnesses(3);
    for w in witnesses {
        store.append(w).unwrap();
    }

    let scheduler = ZkBatchScheduler::new(prover.clone(), store.clone(), 3, 300);

    let result = scheduler.prove_now().unwrap();
    assert!(result.is_some(), "Should produce a proof");

    let proof = result.unwrap();
    assert_eq!(proof.entry_count, 3);

    // Store should be drained
    assert_eq!(store.len().unwrap(), 0);

    // Proof should be in the proof store
    assert_eq!(scheduler.proof_count().unwrap(), 1);
    let proofs = scheduler.proofs().unwrap();
    assert_eq!(proofs.len(), 1);
    assert_eq!(proofs[0].batch_id, proof.batch_id);
}

#[test]
fn test_scheduler_partial_drain() {
    // Scheduler drains batch_size=2 from a store with 5 witnesses
    let prover = Arc::new(ZkBatchProver::setup(3).unwrap());
    let store = Arc::new(WitnessStore::new());
    let witnesses = make_chain_witnesses(5);
    for w in witnesses {
        store.append(w).unwrap();
    }

    let scheduler = ZkBatchScheduler::new(prover, store.clone(), 2, 300);

    let result = scheduler.prove_now().unwrap();
    assert!(result.is_some());
    assert_eq!(result.unwrap().entry_count, 2);

    // 3 witnesses should remain
    assert_eq!(store.len().unwrap(), 3);
}

#[test]
fn test_scheduler_multiple_batches() {
    let prover = Arc::new(ZkBatchProver::setup(2).unwrap());
    let store = Arc::new(WitnessStore::new());

    // First batch
    let witnesses1 = make_chain_witnesses(2);
    for w in witnesses1 {
        store.append(w).unwrap();
    }
    let scheduler = ZkBatchScheduler::new(prover.clone(), store.clone(), 2, 300);
    scheduler.prove_now().unwrap();

    // Second batch (new chain, independent)
    let witnesses2 = make_chain_witnesses(2);
    for w in witnesses2 {
        store.append(w).unwrap();
    }
    scheduler.prove_now().unwrap();

    assert_eq!(scheduler.proof_count().unwrap(), 2);
}

#[test]
fn test_scheduler_proofs_returns_all() {
    let prover = Arc::new(ZkBatchProver::setup(2).unwrap());
    let store = Arc::new(WitnessStore::new());
    let scheduler = ZkBatchScheduler::new(prover, store.clone(), 2, 300);

    // Generate 3 proofs
    for _ in 0..3 {
        let witnesses = make_chain_witnesses(2);
        for w in witnesses {
            store.append(w).unwrap();
        }
        scheduler.prove_now().unwrap();
    }

    let proofs = scheduler.proofs().unwrap();
    assert_eq!(proofs.len(), 3);
}

// ═══════════════════════════════════════════════════
// PHASE 37.2: ZkBatchProof UPDATED SERDE TESTS
// ═══════════════════════════════════════════════════

#[test]
fn test_zk_batch_proof_with_public_inputs_serde() {
    let proof = vellaveto_types::ZkBatchProof {
        proof: "deadbeef".repeat(16),
        batch_id: "batch-pub".to_string(),
        entry_range: (10, 19),
        merkle_root: "abcd".repeat(16),
        first_prev_hash: "00".repeat(32),
        final_entry_hash: "ff".repeat(32),
        created_at: "2026-02-16T12:00:00Z".to_string(),
        entry_count: 10,
    };
    let json = serde_json::to_string(&proof).unwrap();
    assert!(json.contains("first_prev_hash"));
    assert!(json.contains("final_entry_hash"));

    let deserialized: vellaveto_types::ZkBatchProof = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.first_prev_hash, "00".repeat(32));
    assert_eq!(deserialized.final_entry_hash, "ff".repeat(32));
    assert_eq!(deserialized.entry_count, 10);
}

// ═══════════════════════════════════════════════════
// PHASE 9 COVERAGE: PEDERSEN COMMITMENT EXTRAS
// ═══════════════════════════════════════════════════

#[test]
fn test_pedersen_decompress_invalid_point_returns_error() {
    let invalid_bytes = [0xFFu8; 32];
    let compressed = CompressedRistretto::from_slice(&invalid_bytes).unwrap();
    let result = PedersenCommitter::decompress(&compressed);
    assert!(
        result.is_err(),
        "Decompressing invalid point bytes should return Err"
    );
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("Invalid compressed Ristretto point"));
}

#[test]
fn test_pedersen_decompress_valid_commitment_succeeds() {
    let committer = PedersenCommitter::new();
    let entry_hash = [0x55u8; 32];
    let (commitment, _) = committer.commit(&entry_hash).unwrap();
    let result = PedersenCommitter::decompress(&commitment);
    assert!(result.is_ok(), "Valid commitment should decompress");
}

#[test]
fn test_pedersen_h_generator_not_basepoint() {
    let committer = PedersenCommitter::new();
    let h = committer.h_point();
    assert_ne!(
        h,
        curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT,
        "H generator must not equal G"
    );
}

#[test]
fn test_pedersen_commitment_binding_property() {
    let committer = PedersenCommitter::new();
    let hash1 = [0x01u8; 32];
    let hash2 = [0x02u8; 32];
    let blinding = Scalar::from(12345u64);

    let h = committer.h_point();
    let s1 = Scalar::from_bytes_mod_order(hash1);
    let s2 = Scalar::from_bytes_mod_order(hash2);

    let c1 = s1 * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT + blinding * h;
    let c2 = s2 * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT + blinding * h;

    assert_ne!(
        c1.compress(),
        c2.compress(),
        "Same blinding, different messages must produce different commitments"
    );
}

#[test]
fn test_pedersen_verify_cross_committer_instances() {
    let c1 = PedersenCommitter::new();
    let c2 = PedersenCommitter::new();
    let entry_hash = [0x77u8; 32];

    let (commitment, blinding) = c1.commit(&entry_hash).unwrap();
    assert!(
        c2.verify(&commitment, &entry_hash, &blinding),
        "Commitment from c1 should verify with c2"
    );
}

// ═══════════════════════════════════════════════════
// PHASE 9 COVERAGE: WITNESS STORE EDGE CASES
// ═══════════════════════════════════════════════════

#[test]
fn test_witness_store_with_capacity_zero_clamps_to_one() {
    let store = WitnessStore::with_capacity(0);
    assert_eq!(
        store.max_capacity(),
        1,
        "Zero capacity should be clamped to 1"
    );
    store.append(make_test_witness(0)).unwrap();
    let result = store.append(make_test_witness(1));
    assert!(result.is_err());
}

#[test]
fn test_witness_store_restore_to_empty_store() {
    let store = WitnessStore::with_capacity(100);
    assert!(store.is_empty().unwrap());

    let witnesses = vec![make_test_witness(10), make_test_witness(11)];
    store.restore(witnesses).unwrap();

    assert_eq!(store.len().unwrap(), 2);
    let drained = store.drain(100).unwrap();
    assert_eq!(drained[0].sequence, 10);
    assert_eq!(drained[1].sequence, 11);
}

#[test]
fn test_witness_store_drain_zero_returns_empty() {
    let store = WitnessStore::new();
    store.append(make_test_witness(0)).unwrap();
    let drained = store.drain(0).unwrap();
    assert!(drained.is_empty());
    assert_eq!(store.len().unwrap(), 1);
}

#[test]
fn test_witness_store_restore_exactly_at_capacity() {
    let store = WitnessStore::with_capacity(3);
    store.append(make_test_witness(5)).unwrap();
    store
        .restore(vec![make_test_witness(1), make_test_witness(2)])
        .unwrap();
    assert_eq!(store.len().unwrap(), 3);
    let all = store.drain(100).unwrap();
    assert_eq!(all[0].sequence, 1);
    assert_eq!(all[1].sequence, 2);
    assert_eq!(all[2].sequence, 5);
}

#[test]
fn test_witness_debug_redacts_blinding() {
    let witness = make_test_witness(42);
    let debug_str = format!("{witness:?}");
    assert!(
        debug_str.contains("[REDACTED]"),
        "Blinding should be redacted in Debug output"
    );
    assert!(
        debug_str.contains("sequence: 42"),
        "Sequence should be visible in Debug"
    );
}

// ═══════════════════════════════════════════════════
// PHASE 9 COVERAGE: CIRCUIT EDGE CASES
// ═══════════════════════════════════════════════════

#[test]
fn test_circuit_with_witnesses_correct_sizes_succeeds() {
    let result = AuditChainCircuit::<Fr>::with_witnesses(
        2,
        Fr::from(0u64),
        Fr::from(1u64),
        vec![Fr::from(0u64); 2],
        vec![Fr::from(0u64); 2],
    );
    assert!(result.is_ok());
    let circuit = result.unwrap();
    assert_eq!(circuit.max_size, 2);
    assert!(circuit.first_prev_hash.is_some());
    assert!(circuit.final_hash.is_some());
}

#[test]
fn test_circuit_template_all_none_witnesses() {
    let circuit = AuditChainCircuit::<Fr>::template(5);
    for eh in &circuit.entry_hashes {
        assert!(eh.is_none(), "Template witnesses should all be None");
    }
    for ph in &circuit.prev_hashes {
        assert!(ph.is_none(), "Template prev_hashes should all be None");
    }
}

#[test]
fn test_hash_to_field_max_hash() {
    let max_hash = [0xFFu8; 32];
    let f: Fr = hash_to_field(&max_hash);
    assert_ne!(f, Fr::from(0u64), "All-0xFF should not reduce to zero");
}

#[test]
fn test_circuit_large_chain_satisfied() {
    let (entry_hashes, prev_hashes) = make_test_chain(10);
    let first_prev = prev_hashes[0];
    let final_hash = entry_hashes[9];

    let circuit =
        AuditChainCircuit::with_witnesses(10, first_prev, final_hash, entry_hashes, prev_hashes)
            .unwrap();

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(
        cs.is_satisfied().unwrap(),
        "Large valid chain should satisfy constraints"
    );
}

#[test]
fn test_circuit_tampered_middle_entry_unsatisfied() {
    let (mut entry_hashes, prev_hashes) = make_test_chain(5);
    let first_prev = prev_hashes[0];
    let final_hash = entry_hashes[4];

    entry_hashes[2] = Fr::from(77777u64);

    let circuit =
        AuditChainCircuit::with_witnesses(5, first_prev, final_hash, entry_hashes, prev_hashes)
            .unwrap();

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(
        !cs.is_satisfied().unwrap(),
        "Tampered middle entry should break chain linkage"
    );
}

// ═══════════════════════════════════════════════════
// PHASE 9 COVERAGE: PROVER ERROR PATHS
// ═══════════════════════════════════════════════════

#[test]
fn test_prover_from_files_nonexistent_pk_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let pk_path = dir.path().join("nonexistent_pk.bin");
    let vk_path = dir.path().join("nonexistent_vk.bin");

    let result = ZkBatchProver::from_files(&pk_path, &vk_path, 2);
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("Failed to stat proving key"));
}

#[test]
fn test_prover_from_files_invalid_content_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let pk_path = dir.path().join("pk.bin");
    let vk_path = dir.path().join("vk.bin");

    std::fs::write(&pk_path, [0u8; 100]).unwrap();
    std::fs::write(&vk_path, [0u8; 100]).unwrap();

    let result = ZkBatchProver::from_files(&pk_path, &vk_path, 2);
    assert!(result.is_err(), "Invalid key content should fail");
}

#[test]
fn test_prover_debug_redacts_keys() {
    let prover = ZkBatchProver::setup(2).unwrap();
    let debug_str = format!("{prover:?}");
    assert!(
        debug_str.contains("[REDACTED]"),
        "Debug should redact proving/verifying keys"
    );
    assert!(
        debug_str.contains("max_batch_size: 2"),
        "Debug should show max_batch_size"
    );
}

#[test]
fn test_prover_verify_invalid_hex_in_proof_field() {
    let prover = ZkBatchProver::setup(2).unwrap();
    let witnesses = make_chain_witnesses(2);
    let mut proof = prover.prove(&witnesses).unwrap();

    proof.proof = "ZZZZ_not_hex".to_string();

    let result = prover.verify(&proof);
    assert!(result.is_err(), "Non-hex proof should fail verification");
}

#[test]
fn test_prover_verify_invalid_hex_in_first_prev_hash() {
    let prover = ZkBatchProver::setup(2).unwrap();
    let witnesses = make_chain_witnesses(2);
    let mut proof = prover.prove(&witnesses).unwrap();

    proof.first_prev_hash = "not_valid_hex!".to_string();

    let result = prover.verify(&proof);
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════
// PHASE 9 COVERAGE: SCHEDULER EDGE CASES
// ═══════════════════════════════════════════════════

#[test]
fn test_scheduler_debug_redacts_prover() {
    let prover = Arc::new(ZkBatchProver::setup(2).unwrap());
    let store = Arc::new(WitnessStore::new());
    let scheduler = ZkBatchScheduler::new(prover, store, 2, 60);

    let debug_str = format!("{scheduler:?}");
    assert!(
        debug_str.contains("[REDACTED]"),
        "Scheduler debug should redact prover"
    );
    assert!(
        debug_str.contains("batch_size: 2"),
        "Scheduler debug should show batch_size"
    );
    assert!(
        debug_str.contains("proof_count: 0"),
        "Scheduler debug should show proof_count"
    );
}

#[test]
fn test_scheduler_pending_witnesses_reports_correctly() {
    let prover = Arc::new(ZkBatchProver::setup(2).unwrap());
    let store = Arc::new(WitnessStore::new());
    let scheduler = ZkBatchScheduler::new(prover, store.clone(), 2, 60);

    assert_eq!(scheduler.pending_witnesses().unwrap(), 0);

    for w in make_chain_witnesses(3) {
        store.append(w).unwrap();
    }
    assert_eq!(scheduler.pending_witnesses().unwrap(), 3);
}

#[test]
fn test_scheduler_prove_now_drains_batch_size_only() {
    let prover = Arc::new(ZkBatchProver::setup(3).unwrap());
    let store = Arc::new(WitnessStore::new());
    let witnesses = make_chain_witnesses(5);
    for w in witnesses {
        store.append(w).unwrap();
    }

    let scheduler = ZkBatchScheduler::new(prover, store.clone(), 2, 60);
    let result = scheduler.prove_now().unwrap();
    assert!(result.is_some());
    assert_eq!(result.unwrap().entry_count, 2);
    assert_eq!(store.len().unwrap(), 3);
}

// ═══════════════════════════════════════════════════
// PHASE 9 COVERAGE: ZK ERROR TYPES
// ═══════════════════════════════════════════════════

#[test]
fn test_zk_error_display_commitment() {
    let err = super::ZkError::Commitment("test commitment error".to_string());
    let msg = format!("{err}");
    assert!(msg.contains("Commitment error"));
    assert!(msg.contains("test commitment error"));
}

#[test]
fn test_zk_error_display_witness_store() {
    let err = super::ZkError::WitnessStore("store is full".to_string());
    let msg = format!("{err}");
    assert!(msg.contains("Witness store error"));
    assert!(msg.contains("store is full"));
}

#[test]
fn test_zk_error_display_proof() {
    let err = super::ZkError::Proof("proving failed".to_string());
    let msg = format!("{err}");
    assert!(msg.contains("Proof error"));
}

#[test]
fn test_zk_error_display_verification() {
    let err = super::ZkError::Verification("bad proof".to_string());
    let msg = format!("{err}");
    assert!(msg.contains("Verification error"));
}

#[test]
fn test_zk_error_display_key() {
    let err = super::ZkError::Key("key not found".to_string());
    let msg = format!("{err}");
    assert!(msg.contains("Key error"));
}

#[test]
fn test_zk_error_display_serialization() {
    let err = super::ZkError::Serialization("invalid bytes".to_string());
    let msg = format!("{err}");
    assert!(msg.contains("Serialization error"));
}
