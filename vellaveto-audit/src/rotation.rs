// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

use crate::logger::AuditLogger;
use crate::trusted_audit_fs;
use crate::types::{AuditEntry, AuditError, RotationVerification};
use crate::verified_audit_append;
use crate::verified_rotation_manifest;
use chrono::Utc;
use ed25519_dalek::{Signer, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use uuid::Uuid;

/// Default max file size before rotation: 100 MB.
pub(crate) const DEFAULT_MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;

/// Maximum number of rotated log files to retain.
/// Oldest files beyond this limit are deleted to prevent disk exhaustion.
const MAX_ROTATED_FILES: usize = 100;

impl AuditLogger {
    /// Initialize the hash chain by reading the last entry from the log.
    ///
    /// Call this once at startup to seed the chain head.
    pub async fn initialize_chain(&self) -> Result<(), AuditError> {
        let entries = self.load_entries().await?;
        if entries.is_empty() {
            return Ok(());
        }

        // Verify the chain before trusting any hash from the file.
        // A tampered file must not poison the in-memory chain head.
        let verification = self.verify_chain().await?;
        let mut chain_head = self.chain_head.lock().await;

        if verification.valid {
            if let Some(last_entry) = entries.last() {
                chain_head.last_hash = last_entry.entry_hash.clone();
                chain_head.last_timestamp = Some(last_entry.timestamp.clone());
            }
        } else {
            tracing::warn!(
                "Audit chain verification failed at entry {}. Starting new chain segment.",
                verification.first_broken_at.unwrap_or(0)
            );
            // Do NOT trust any hash from the file. Start a fresh chain segment
            // by leaving last_hash as None. The next entry will begin a new segment.
        }

        // Initialize entry count from loaded entries
        // SECURITY (FIND-R52-AUDIT-002): Use SeqCst for sequence counter to ensure
        // globally consistent ordering and prevent duplicate sequence numbers.
        self.entry_count
            .store(entries.len() as u64, Ordering::SeqCst);

        // SECURITY (FIND-R111-007): Initialize the global sequence counter from the
        // highest sequence number seen across all loaded entries. This ensures that
        // after a restart the global sequence continues from where it left off,
        // preventing duplicate sequence numbers across process restarts.
        // If no entries exist or none have a sequence field, start from 0.
        let max_sequence = entries.iter().map(|e| e.sequence).max().unwrap_or(0);
        // Start the next sequence one past the highest observed value.
        self.global_sequence.store(
            verified_audit_append::next_sequence_after_recovery(max_sequence),
            Ordering::SeqCst,
        );

        // Initialize Merkle tree from existing leaf file (if enabled)
        if let Some(ref merkle) = self.merkle_tree {
            let mut tree = merkle
                .lock()
                .map_err(|e| AuditError::Validation(format!("Merkle tree lock poisoned: {e}")))?;
            tree.initialize()?;
        }

        Ok(())
    }

    /// Get the path to the rotation manifest file.
    ///
    /// The manifest records each rotation event with the tail hash and
    /// entry count, enabling cross-rotation chain verification (H1).
    pub(crate) fn rotation_manifest_path(&self) -> PathBuf {
        // Safe: file_stem() returns None only for ".." or empty paths, which
        // are never valid audit log paths. unwrap_or_default yields "" as fallback.
        let stem = self
            .log_path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy();
        // Safe: parent() returns None only for root path "/". Audit log paths
        // are always within a directory, so "." is a safe fallback.
        let parent = self.log_path.parent().unwrap_or(Path::new("."));
        parent.join(format!("{stem}.rotation-manifest.jsonl"))
    }

    /// Rotate the log file if it exceeds `max_file_size`.
    ///
    /// The caller MUST hold `last_hash` lock. On successful rotation the
    /// caller should reset the lock to `None` (new file = new chain).
    ///
    /// H1: Before rotation, captures the tail hash of the current log.
    /// After rotation, appends a manifest entry recording the rotated file,
    /// its tail hash, and entry count for cross-rotation verification.
    ///
    /// Returns `true` if rotation occurred.
    pub(crate) async fn maybe_rotate(&self) -> Result<bool, AuditError> {
        if self.max_file_size == 0 {
            return Ok(false);
        }

        let metadata = match trusted_audit_fs::metadata_if_exists(&self.log_path).await? {
            Some(metadata) => metadata,
            None => return Ok(false),
        };

        if metadata.len() < self.max_file_size {
            return Ok(false);
        }

        // H1: Read the tail hash before rotation
        // SECURITY (R18-AUDIT-1): If load fails, skip rotation to avoid creating
        // a corrupt manifest with empty tail_hash. Keep writing to current file.
        let entries = match self.load_entries().await {
            Ok(e) => e,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    path = %self.log_path.display(),
                    "Failed to load audit entries for rotation — skipping rotation to preserve chain integrity"
                );
                return Ok(false);
            }
        };
        // SECURITY (R19-AUDIT-1): Strict tail hash computation.
        // - If entries is empty (first rotation), use empty string (valid first rotation).
        // - If entries exist but last entry has no hash, this is a data integrity error.
        //   Skip rotation to avoid creating a manifest with incorrect/missing tail_hash.
        let tail_hash = if entries.is_empty() {
            // First rotation — no previous entries, empty tail hash is valid
            String::new()
        } else {
            match entries.last().and_then(|e| e.entry_hash.clone()) {
                Some(hash) => hash,
                None => {
                    tracing::error!(
                        path = %self.log_path.display(),
                        entry_count = entries.len(),
                        "Last audit entry has no hash — skipping rotation to preserve chain integrity"
                    );
                    return Ok(false);
                }
            }
        };
        // Use loaded entry count (file is source of truth; in-memory counter is for optimization)
        let entry_count = entries.len();

        let rotated_path = self.rotated_path();
        trusted_audit_fs::rename_required(&self.log_path, &rotated_path).await?;

        // Rename the Merkle leaf file alongside the rotated log, then reset the tree
        if let Some(ref merkle) = self.merkle_tree {
            let leaf_path = self.merkle_leaf_path();
            // SECURITY (FIND-R170-003): Always attempt rename without prior exists()
            // check to eliminate TOCTOU gap. Handle NotFound as expected (no leaf file).
            let rotated_leaf_path = {
                let rotated_stem = rotated_path
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy();
                let rotated_parent = rotated_path.parent().unwrap_or(std::path::Path::new("."));
                rotated_parent.join(format!("{rotated_stem}.merkle-leaves"))
            };
            match trusted_audit_fs::rename_if_exists(&leaf_path, &rotated_leaf_path).await {
                Ok(true) => {}
                Ok(false) => {
                    // No leaf file to rename — expected if Merkle was not used
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "Failed to rename Merkle leaf file during rotation"
                    );
                }
            }
            let mut tree = merkle
                .lock()
                .map_err(|e| AuditError::Validation(format!("Merkle tree lock poisoned: {e}")))?;
            tree.reset();
        }

        // H1: Append rotation manifest entry
        // SECURITY (R9-1): Sign the manifest entry with Ed25519 when a signing
        // key is configured. Without signatures, an attacker with file write
        // access can forge manifest entries to hide deleted rotated files.
        // SECURITY (R14-AUDIT-2): Store only the filename component in the
        // manifest to prevent path traversal. The rotated file is always in
        // the same directory as the audit log, so a bare filename suffices.
        let rotated_filename = rotated_path
            .file_name()
            .ok_or_else(|| {
                AuditError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "rotated path has no filename component",
                ))
            })?
            .to_string_lossy();
        // SECURITY (FIND-R42-017): Record chain segment start hash for cross-rotation
        // linking. The start_hash is the prev_hash of the first entry (None for the first segment).
        let start_hash = entries
            .first()
            .and_then(|e| e.prev_hash.clone())
            .unwrap_or_default();

        // SECURITY (FIND-R46-ROT-003): Hash-chain manifest entries.
        // Compute `previous_hash` as SHA-256(last manifest line) to chain each
        // entry to its predecessor. This detects deletion, reordering, or
        // replacement of individual manifest entries.
        let manifest_path = self.rotation_manifest_path();
        let previous_hash = match trusted_audit_fs::read_to_string_if_exists(&manifest_path).await?
        {
            Some(content) => {
                // Find the last non-empty line
                match content.lines().rev().find(|l| !l.trim().is_empty()) {
                    Some(last_line) => {
                        let mut hasher = Sha256::new();
                        hasher.update(last_line.as_bytes());
                        hex::encode(hasher.finalize())
                    }
                    None => "genesis".to_string(),
                }
            }
            None => "genesis".to_string(),
        };

        let mut manifest_entry = serde_json::json!({
            "timestamp": Utc::now().to_rfc3339(),
            "rotated_file": rotated_filename,
            "tail_hash": tail_hash,
            "start_hash": start_hash,
            "entry_count": entry_count,
            "previous_hash": previous_hash,
        });
        // SECURITY (R226-AUD-1): Compute unsigned canonical digest ONCE before any
        // signatures are added. Both Ed25519 and ML-DSA-65 must sign the same content.
        // Previously, PQC signed after Ed25519 fields were added, but verification
        // strips all signature fields — causing a message mismatch.
        let unsigned_canonical = Self::canonical_json(&manifest_entry)?;
        let mut base_hasher = Sha256::new();
        base_hasher.update(&unsigned_canonical);
        let unsigned_digest = base_hasher.finalize();

        if let Some(signing_key) = &self.signing_key {
            let signature = signing_key.sign(&unsigned_digest);
            manifest_entry["signature"] =
                serde_json::Value::String(hex::encode(signature.to_bytes()));
            manifest_entry["verifying_key"] =
                serde_json::Value::String(hex::encode(signing_key.verifying_key().as_bytes()));
        }

        // Phase 54: Add ML-DSA-65 signature for hybrid manifest entries
        #[cfg(feature = "pqc-hybrid")]
        if let (Some(ref sk_hex), Some(ref pk_hex)) =
            (&self.pqc_secret_key_hex, &self.pqc_public_key_hex)
        {
            // SECURITY (R226-AUD-1): Use same unsigned digest as Ed25519 — matches
            // verification which strips all signature fields before re-computing digest
            let pqc_sig =
                crate::pqc::ml_dsa_sign(sk_hex, &unsigned_digest, crate::pqc::MANIFEST_CONTEXT)?;
            manifest_entry["pqc_signature"] = serde_json::Value::String(pqc_sig);
            manifest_entry["pqc_verifying_key"] = serde_json::Value::String(pk_hex.clone());
            manifest_entry["signature_version"] =
                serde_json::Value::Number(serde_json::Number::from(2u8));
        }

        let mut manifest_line =
            serde_json::to_string(&manifest_entry).map_err(AuditError::Serialization)?;
        manifest_line.push('\n');

        trusted_audit_fs::append_bytes(
            &manifest_path,
            manifest_line.as_bytes(),
            trusted_audit_fs::Durability::SyncData,
            "rotation manifest file",
        )
        .await?;

        tracing::info!(
            "Rotated audit log {} -> {} ({} bytes, {} entries, tail_hash={})",
            self.log_path.display(),
            rotated_path.display(),
            metadata.len(),
            entry_count,
            &tail_hash[..tail_hash.len().min(16)],
        );

        // SECURITY (FIND-041-007): Prune oldest rotated files beyond MAX_ROTATED_FILES
        // to prevent unbounded disk exhaustion.
        if let Err(e) = self.prune_rotated_files().await {
            tracing::warn!(
                error = %e,
                "Failed to prune old rotated audit log files"
            );
        }

        Ok(true)
    }

    /// Verify chain integrity across rotated log files (H1).
    ///
    /// Loads the rotation manifest, verifies each rotated file's internal
    /// hash chain, and checks that the recorded tail hashes match.
    /// Detects missing files, tampered files, and manifest forgery.
    pub async fn verify_across_rotations(&self) -> Result<RotationVerification, AuditError> {
        let manifest_path = self.rotation_manifest_path();
        // SECURITY (R33-SUP-5): Check manifest file size before reading to prevent
        // OOM from a corrupted or adversarially large manifest file.
        const MAX_MANIFEST_SIZE: u64 = 10 * 1024 * 1024; // 10MB
        match trusted_audit_fs::metadata_if_exists(&manifest_path).await? {
            Some(meta) => {
                if meta.len() > MAX_MANIFEST_SIZE {
                    return Err(AuditError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Rotation manifest file exceeds maximum size ({} > {})",
                            meta.len(),
                            MAX_MANIFEST_SIZE
                        ),
                    )));
                }
            }
            None => {
                return Ok(RotationVerification {
                    valid: true,
                    files_checked: 0,
                    first_failure: None,
                });
            }
        }
        let manifest_content =
            match trusted_audit_fs::read_to_string_if_exists(&manifest_path).await? {
                Some(content) => content,
                None => {
                    return Ok(RotationVerification {
                        valid: true,
                        files_checked: 0,
                        first_failure: None,
                    });
                }
            };

        let mut files_checked = 0;
        // SECURITY (FIND-R46-ROT-003): Track previous manifest line for hash-chain verification.
        let mut previous_manifest_line: Option<String> = None;
        // SECURITY (FIND-R46-013): Track previous segment's tail hash for
        // cross-rotation start_hash verification. The start_hash of each
        // segment should match the tail_hash of the preceding segment.
        let mut previous_tail_hash: Option<String> = None;

        /// SECURITY (FIND-R140-004): Maximum manifest line size (64 KB).
        /// Prevents CPU/memory DoS from a single oversized JSON line.
        const MAX_MANIFEST_LINE_SIZE: usize = 64 * 1024;

        for (i, line) in manifest_content.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            if line.len() > MAX_MANIFEST_LINE_SIZE {
                return Ok(RotationVerification {
                    valid: false,
                    files_checked: i,
                    first_failure: Some(format!(
                        "Manifest entry {} exceeds max line size ({} > {})",
                        i,
                        line.len(),
                        MAX_MANIFEST_LINE_SIZE
                    )),
                });
            }
            let entry: serde_json::Value = serde_json::from_str(line)?;

            // SECURITY (FIND-R46-ROT-003): Verify manifest entry hash chain.
            // Each entry must reference the SHA-256 hash of the previous entry's
            // serialized line, or "genesis" for the first entry. This detects
            // deletion, reordering, or replacement of individual entries.
            let claimed_previous = entry
                .get("previous_hash")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let expected_previous = match &previous_manifest_line {
                Some(prev_line) => {
                    let mut hasher = Sha256::new();
                    hasher.update(prev_line.as_bytes());
                    hex::encode(hasher.finalize())
                }
                None => "genesis".to_string(),
            };
            if claimed_previous != expected_previous {
                return Ok(RotationVerification {
                    valid: false,
                    files_checked: i,
                    first_failure: Some(format!(
                        "Manifest entry {i} hash chain broken: expected previous_hash {expected_previous}, got {claimed_previous}"
                    )),
                });
            }

            // SECURITY (R9-1): Verify manifest entry signature when present.
            // If a trusted verifying key is configured, ALL manifest entries
            // MUST be signed. Without a trusted key, signed entries are still
            // verified (opportunistic verification).
            if let Some(sig_hex) = entry.get("signature").and_then(|v| v.as_str()) {
                let vk_hex = entry
                    .get("verifying_key")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();

                // Key pinning: if trusted key is configured, manifest must match
                if let Some(trusted) = &self.trusted_verifying_key {
                    if vk_hex != trusted.as_str() {
                        return Ok(RotationVerification {
                            valid: false,
                            files_checked: i,
                            first_failure: Some(format!(
                                "Manifest entry {i} signed by untrusted key"
                            )),
                        });
                    }
                }

                // SECURITY (R227-AUD-1): Reconstruct the unsigned entry for signature
                // verification. Must strip ALL signature fields (Ed25519 AND PQC) to
                // match the unsigned content that was originally signed. Without this,
                // an attacker can inject PQC fields that change the digest, causing
                // Ed25519-only verification to fail or accept forged entries.
                let mut unsigned = entry.clone();
                if let Some(obj) = unsigned.as_object_mut() {
                    obj.remove("signature");
                    obj.remove("verifying_key");
                    obj.remove("pqc_signature");
                    obj.remove("pqc_verifying_key");
                    obj.remove("signature_version");
                }
                // SECURITY (R33-SUP-1): Fail-closed on malformed signatures.
                // Previously, failures in canonical_json, hex::decode, try_from,
                // or VerifyingKey::from_bytes silently fell through, allowing
                // entries with corrupted/truncated signatures to pass verification.
                let canonical = match Self::canonical_json(&unsigned) {
                    Ok(c) => c,
                    Err(_) => {
                        return Ok(RotationVerification {
                            valid: false,
                            files_checked: i,
                            first_failure: Some(format!(
                                "Manifest entry {i} failed to canonicalize"
                            )),
                        });
                    }
                };
                let vk_bytes = match hex::decode(vk_hex) {
                    Ok(b) => b,
                    Err(_) => {
                        return Ok(RotationVerification {
                            valid: false,
                            files_checked: i,
                            first_failure: Some(format!(
                                "Manifest entry {i} has invalid verifying key hex"
                            )),
                        });
                    }
                };
                let sig_bytes = match hex::decode(sig_hex) {
                    Ok(b) => b,
                    Err(_) => {
                        return Ok(RotationVerification {
                            valid: false,
                            files_checked: i,
                            first_failure: Some(format!(
                                "Manifest entry {i} has invalid signature hex"
                            )),
                        });
                    }
                };
                let mut hasher = Sha256::new();
                hasher.update(&canonical);
                let digest = hasher.finalize();
                let vk_arr: [u8; 32] = match vk_bytes.as_slice().try_into() {
                    Ok(a) => a,
                    Err(_) => {
                        return Ok(RotationVerification {
                            valid: false,
                            files_checked: i,
                            first_failure: Some(format!(
                                "Manifest entry {i} verifying key wrong length"
                            )),
                        });
                    }
                };
                let sig_arr: [u8; 64] = match sig_bytes.as_slice().try_into() {
                    Ok(a) => a,
                    Err(_) => {
                        return Ok(RotationVerification {
                            valid: false,
                            files_checked: i,
                            first_failure: Some(format!(
                                "Manifest entry {i} signature wrong length"
                            )),
                        });
                    }
                };
                let vk = match VerifyingKey::from_bytes(&vk_arr) {
                    Ok(k) => k,
                    Err(_) => {
                        return Ok(RotationVerification {
                            valid: false,
                            files_checked: i,
                            first_failure: Some(format!(
                                "Manifest entry {i} has invalid verifying key"
                            )),
                        });
                    }
                };
                let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
                if vk.verify(&digest, &sig).is_err() {
                    return Ok(RotationVerification {
                        valid: false,
                        files_checked: i,
                        first_failure: Some(format!(
                            "Manifest entry {i} Ed25519 signature invalid"
                        )),
                    });
                }

                // Phase 54: Verify ML-DSA-65 signature on manifest entries
                let manifest_sig_version = entry
                    .get("signature_version")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1);
                if manifest_sig_version >= 2 {
                    #[cfg(feature = "pqc-hybrid")]
                    {
                        let pqc_sig_hex = entry
                            .get("pqc_signature")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| {
                                AuditError::Validation(format!(
                                    "Manifest entry {} v2 missing pqc_signature",
                                    i
                                ))
                            })?;
                        let pqc_vk_hex = entry
                            .get("pqc_verifying_key")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| {
                                AuditError::Validation(format!(
                                    "Manifest entry {} v2 missing pqc_verifying_key",
                                    i
                                ))
                            })?;

                        // PQC key pinning
                        if let Some(ref trusted_pqc) = self.trusted_pqc_verifying_key {
                            if pqc_vk_hex != trusted_pqc.as_str() {
                                return Ok(RotationVerification {
                                    valid: false,
                                    files_checked: i,
                                    first_failure: Some(format!(
                                        "Manifest entry {} signed by untrusted PQC key",
                                        i
                                    )),
                                });
                            }
                        }

                        // Re-compute the unsigned entry digest for PQC verification
                        // (same digest Ed25519 signed — the unsigned entry before adding sigs)
                        let mut pqc_unsigned = entry.clone();
                        if let Some(obj) = pqc_unsigned.as_object_mut() {
                            obj.remove("signature");
                            obj.remove("verifying_key");
                            obj.remove("pqc_signature");
                            obj.remove("pqc_verifying_key");
                            obj.remove("signature_version");
                        }
                        let pqc_canonical = Self::canonical_json(&pqc_unsigned)?;
                        let mut pqc_hasher = Sha256::new();
                        pqc_hasher.update(&pqc_canonical);
                        let pqc_digest = pqc_hasher.finalize();

                        if let Err(e) = crate::pqc::ml_dsa_verify(
                            pqc_vk_hex,
                            &pqc_digest,
                            pqc_sig_hex,
                            crate::pqc::MANIFEST_CONTEXT,
                        ) {
                            return Ok(RotationVerification {
                                valid: false,
                                files_checked: i,
                                first_failure: Some(format!(
                                    "Manifest entry {} ML-DSA-65 signature invalid: {}",
                                    i, e
                                )),
                            });
                        }
                    }

                    #[cfg(not(feature = "pqc-hybrid"))]
                    {
                        return Ok(RotationVerification {
                            valid: false,
                            files_checked: i,
                            first_failure: Some(format!(
                                "Manifest entry {i} v2 requires pqc-hybrid feature to verify"
                            )),
                        });
                    }
                }
            } else if self.trusted_verifying_key.is_some() {
                // Trusted key is configured but manifest entry is unsigned
                return Ok(RotationVerification {
                    valid: false,
                    files_checked: i,
                    first_failure: Some(format!(
                        "Manifest entry {i} is unsigned but signing is required"
                    )),
                });
            }

            // SECURITY (FIND-R46-013): Verify cross-rotation start_hash linkage.
            // The start_hash field records the prev_hash of the first entry in
            // the rotated segment. When non-empty, it must match the tail_hash
            // of the preceding segment (indicating a continuous chain). An empty
            // start_hash indicates a fresh chain segment (normal after rotation).
            // If start_hash is non-empty but doesn't match, a segment was deleted
            // or reordered.
            let claimed_start_hash = entry
                .get("start_hash")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let claimed_start_hash_matches_previous_tail = previous_tail_hash
                .as_ref()
                .is_some_and(|prev_tail| claimed_start_hash == prev_tail);
            if !verified_rotation_manifest::rotation_start_hash_link_valid(
                claimed_start_hash.is_empty(),
                previous_tail_hash.is_some(),
                claimed_start_hash_matches_previous_tail,
            ) {
                let prev_tail = previous_tail_hash.as_deref().unwrap_or_default();
                return Ok(RotationVerification {
                    valid: false,
                    files_checked: i,
                    first_failure: Some(format!(
                        "Cross-rotation linkage broken at segment {i}: start_hash '{claimed_start_hash}' does not match previous tail_hash '{prev_tail}'"
                    )),
                });
            }

            let rotated_file = entry
                .get("rotated_file")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let expected_tail_hash = entry
                .get("tail_hash")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let expected_count = entry
                .get("entry_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize;

            // SECURITY (R14-AUDIT-2): Validate rotated_file before constructing
            // any path from it. Reject path traversal attempts:
            // 1. Must not contain ".." components
            // 2. Must not be an absolute path
            // 3. Must be a bare filename (no directory separators)
            let rotated_file_path = Path::new(rotated_file);
            let has_traversal = rotated_file_path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir));
            let is_absolute = rotated_file_path.is_absolute();
            let is_bare_filename = rotated_file_path
                .file_name()
                .map(|f| f == rotated_file)
                .unwrap_or(false);

            if !verified_rotation_manifest::rotated_file_reference_valid(
                has_traversal,
                is_absolute,
                is_bare_filename,
                rotated_file.is_empty(),
            ) {
                return Ok(RotationVerification {
                    valid: false,
                    files_checked: i,
                    first_failure: Some(format!(
                        "Rotated file path traversal detected: {rotated_file}"
                    )),
                });
            }

            // Resolve the filename relative to the audit log's directory
            let log_dir = self.log_path.parent().unwrap_or(Path::new("."));
            let rotated_path = log_dir.join(rotated_file);

            // SECURITY (FIND-R46-008): Track whether we've seen an existing file.
            // Once we encounter a file that exists, all subsequent manifest entries
            // MUST have their files present. Missing files after existing ones
            // indicate undetected deletion (not pruning, which removes oldest first).
            //
            // SECURITY (FIND-R43-017): Pruning removes the oldest files first, so
            // missing files are only acceptable at the start of the manifest (contiguous
            // prefix of missing files). Once we see a file that exists, we've passed
            // the prune boundary.
            if !rotated_path.exists() {
                if !verified_rotation_manifest::missing_rotated_file_allowed(files_checked) {
                    // We've already seen existing files — this is NOT a prune.
                    // A non-oldest file is missing, indicating undetected deletion.
                    return Ok(RotationVerification {
                        valid: false,
                        files_checked: i,
                        first_failure: Some(format!(
                            "Rotated file missing (not pruned — gap in sequence): {}",
                            rotated_path.display()
                        )),
                    });
                }
                tracing::info!(
                    path = %rotated_path.display(),
                    "Rotated file referenced in manifest no longer exists (likely pruned) — skipping"
                );
                // SECURITY (FIND-R46-013): Still update previous_tail_hash for
                // pruned files so cross-rotation linkage remains consistent.
                previous_tail_hash = Some(expected_tail_hash.to_string());
                previous_manifest_line = Some(line.to_string());
                continue;
            }

            // SECURITY (R38-SUP-1): Check rotated file size before reading
            // to prevent OOM from an adversarially large replacement file.
            let rotated_meta = trusted_audit_fs::metadata_required(&rotated_path).await?;
            if rotated_meta.len() > Self::MAX_AUDIT_LOG_SIZE {
                return Ok(RotationVerification {
                    valid: false,
                    files_checked: i,
                    first_failure: Some(format!(
                        "Rotated file exceeds size limit ({} bytes, max {} bytes): {}",
                        rotated_meta.len(),
                        Self::MAX_AUDIT_LOG_SIZE,
                        rotated_path.display()
                    )),
                });
            }

            // Load and verify the rotated file's chain
            let content = trusted_audit_fs::read_to_string_required(&rotated_path).await?;
            let mut entries = Vec::new();
            for file_line in content.lines() {
                if file_line.trim().is_empty() {
                    continue;
                }
                if let Ok(ae) = serde_json::from_str::<AuditEntry>(file_line) {
                    entries.push(ae);
                }
            }

            // Verify entry count
            if entries.len() != expected_count {
                return Ok(RotationVerification {
                    valid: false,
                    files_checked: i,
                    first_failure: Some(format!(
                        "Entry count mismatch in {}: expected {}, got {}",
                        rotated_path.display(),
                        expected_count,
                        entries.len()
                    )),
                });
            }

            // Verify tail hash
            let actual_tail_hash = entries
                .last()
                .and_then(|e| e.entry_hash.as_deref())
                .unwrap_or_default();
            if actual_tail_hash != expected_tail_hash {
                return Ok(RotationVerification {
                    valid: false,
                    files_checked: i,
                    first_failure: Some(format!(
                        "Tail hash mismatch in {}: expected {}, got {}",
                        rotated_path.display(),
                        expected_tail_hash,
                        actual_tail_hash
                    )),
                });
            }

            // Verify internal hash chain
            let mut prev_hash: Option<String> = None;
            for (j, ae) in entries.iter().enumerate() {
                if ae.prev_hash != prev_hash {
                    return Ok(RotationVerification {
                        valid: false,
                        files_checked: i,
                        first_failure: Some(format!(
                            "Internal chain broken at entry {} in {}",
                            j,
                            rotated_path.display()
                        )),
                    });
                }
                if let Some(ref eh) = ae.entry_hash {
                    let computed = Self::compute_entry_hash(ae)?;
                    if *eh != computed {
                        return Ok(RotationVerification {
                            valid: false,
                            files_checked: i,
                            first_failure: Some(format!(
                                "Hash mismatch at entry {} in {} (tampering detected)",
                                j,
                                rotated_path.display()
                            )),
                        });
                    }
                    prev_hash = Some(eh.clone());
                }
            }

            // SECURITY (FIND-R46-013): Update previous tail hash for next iteration.
            previous_tail_hash = Some(expected_tail_hash.to_string());
            previous_manifest_line = Some(line.to_string());
            files_checked += 1;
        }

        Ok(RotationVerification {
            valid: true,
            files_checked,
            first_failure: None,
        })
    }

    /// Build the destination path for a rotated log file.
    ///
    /// Format: `<stem>.<timestamp>-<seq>.<ext>` where `<seq>` is the current value
    /// of the monotonic global sequence counter and `<timestamp>` uses hyphens
    /// (filesystem-safe) e.g. `audit.2026-02-02T12-00-00-000042.log`.
    ///
    /// SECURITY (FIND-R111-006): Using a monotonic counter in the filename (rather
    /// than only a second-resolution timestamp) prevents filename collisions when
    /// multiple rotations occur within the same second. The sequence counter
    /// (`global_sequence`) is atomically incremented on every audit entry and on
    /// every rotation, so it is guaranteed to increase even when the wall clock does
    /// not advance between rotations. This eliminates the need for the expensive
    /// filesystem existence check loop used previously.
    pub(crate) fn rotated_path(&self) -> PathBuf {
        let timestamp = Utc::now().format("%Y-%m-%dT%H-%M-%S");
        // Include the current global sequence counter in the filename to guarantee
        // uniqueness even when multiple rotations happen within the same second.
        let seq = self
            .global_sequence
            .load(std::sync::atomic::Ordering::SeqCst);
        let stem = self
            .log_path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy();
        let ext = self
            .log_path
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy()))
            .unwrap_or_default();
        let parent = self.log_path.parent().unwrap_or(Path::new("."));

        let candidate = parent.join(format!("{stem}.{timestamp}-{seq:010}{ext}"));
        if !candidate.exists() {
            return candidate;
        }

        // Extremely unlikely fallback: sequence collision (should never happen in
        // practice since sequence is strictly monotonic and this runs under the
        // last_hash write lock). Add a UUID suffix to guarantee uniqueness.
        tracing::warn!(
            path = %candidate.display(),
            "rotated_path: sequence-based candidate already exists — using UUID fallback"
        );
        parent.join(format!("{}.{}-{}{}", stem, timestamp, Uuid::new_v4(), ext))
    }

    /// List rotated log files in the same directory as the active log.
    ///
    /// Returns paths sorted oldest-first. Only files whose name starts
    /// with the active log's stem and contains a timestamp segment are
    /// included.
    pub fn list_rotated_files(&self) -> Result<Vec<PathBuf>, AuditError> {
        let parent = self.log_path.parent().unwrap_or(Path::new("."));
        let stem = self
            .log_path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let mut rotated: Vec<PathBuf> = Vec::new();

        let entries = match std::fs::read_dir(parent) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(AuditError::Io(e)),
        };

        for entry in entries {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            // Match pattern: <stem>.<timestamp>.<ext>
            // e.g. "audit.2026-02-02T12-00-00.log"
            if name.starts_with(&format!("{stem}."))
                && name
                    != self
                        .log_path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
            {
                // SECURITY (FIND-R43-005): Exclude companion files from rotated file list.
                // Merkle leaf files and manifest files should never be pruned as rotated logs.
                if name.ends_with(".merkle-leaves") || name.ends_with(".rotation-manifest.jsonl") {
                    continue;
                }

                // Verify it looks like a rotated file (contains a timestamp-like segment)
                let after_stem = &name[stem.len() + 1..];
                if after_stem.contains('T') && after_stem.contains('-') {
                    rotated.push(entry.path());
                }
            }
        }

        rotated.sort();
        Ok(rotated)
    }

    /// Remove the oldest rotated log files when the count exceeds `MAX_ROTATED_FILES`.
    ///
    /// Files are sorted by modification time (oldest first) and the excess
    /// oldest files are deleted. Errors on individual file deletions are
    /// logged but do not abort the pruning of remaining files.
    async fn prune_rotated_files(&self) -> Result<(), AuditError> {
        let mut rotated = self.list_rotated_files()?;

        if rotated.len() <= MAX_ROTATED_FILES {
            return Ok(());
        }

        // Sort by modification time (oldest first) for deterministic pruning.
        // Fall back to epoch on metadata errors so those files sort first and
        // get pruned preferentially.
        rotated.sort_by(|a, b| {
            let time_a = trusted_audit_fs::modified_time_or_epoch_sync(a);
            let time_b = trusted_audit_fs::modified_time_or_epoch_sync(b);
            time_a.cmp(&time_b)
        });

        let excess = rotated.len() - MAX_ROTATED_FILES;
        for path in rotated.iter().take(excess) {
            match tokio::fs::remove_file(path).await {
                Ok(()) => {
                    tracing::info!(
                        path = %path.display(),
                        "Pruned old rotated audit log file (FIND-041-007)"
                    );

                    // SECURITY (FIND-R43-005): Also remove companion merkle-leaves file.
                    let merkle_path = path.with_extension("merkle-leaves");
                    if merkle_path.exists() {
                        if let Err(e) = std::fs::remove_file(&merkle_path) {
                            tracing::warn!(
                                path = %merkle_path.display(),
                                error = %e,
                                "Failed to remove companion merkle-leaves file during pruning"
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        path = %path.display(),
                        "Failed to prune rotated audit log file"
                    );
                }
            }
        }

        Ok(())
    }
}
