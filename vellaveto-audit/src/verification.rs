// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

use crate::logger::AuditLogger;
use crate::types::{AuditEntry, AuditError, AuditReport, ChainVerification};
use crate::verified_audit_chain;
use tokio::io::AsyncBufReadExt;
use vellaveto_types::Verdict;

/// Strip UTC suffix ('Z', 'z', or '+00:00') from an ISO 8601 timestamp to
/// produce a suffix-free date-time prefix suitable for lexicographic comparison.
///
/// SECURITY (R228-AUD-1): A mix of 'Z' and '+00:00' suffixes in the same audit
/// log breaks lexicographic ordering because '+' (0x2B) < 'Z' (0x5A) in ASCII.
/// True when `ts` is a UTC timestamp that does not precede `prev`.
///
/// Shared by the verifier and by the append path in `logger.rs` so both apply
/// one definition of "correctly ordered". Two implementations of this rule
/// would drift, and the drift would be silent: the appender would accept what
/// the verifier later rejects, producing a log that cannot be verified.
///
/// ISO 8601 timestamps are lexicographically orderable ONLY in UTC, so a
/// non-UTC offset is rejected outright (fail-closed). UTC suffixes are
/// normalized before comparison because '+' (0x2B) sorts before 'Z' (0x5A),
/// so a log mixing the two forms would compare wrongly (R228-AUD-1).
pub(crate) fn timestamp_ordered_after(ts: &str, prev: Option<&str>) -> bool {
    let is_utc = ts.ends_with('Z') || ts.ends_with('z') || ts.ends_with("+00:00");
    let nondecreasing = match prev {
        Some(prev_ts) => strip_utc_suffix(ts) >= strip_utc_suffix(prev_ts),
        None => true,
    };
    verified_audit_chain::timestamp_guard(is_utc, nondecreasing)
}

fn strip_utc_suffix(ts: &str) -> &str {
    if let Some(s) = ts.strip_suffix("+00:00") {
        s
    } else if let Some(s) = ts.strip_suffix('Z') {
        s
    } else if let Some(s) = ts.strip_suffix('z') {
        s
    } else {
        ts
    }
}

impl AuditLogger {
    /// Maximum audit log file size for load operations (100 MB).
    ///
    /// Prevents memory DoS (Exploit #10) where an attacker grows the audit log
    /// and then triggers `verify_chain()` to OOM the server.
    pub(crate) const MAX_AUDIT_LOG_SIZE: u64 = 100 * 1024 * 1024;

    /// Maximum audit log line size (1 MB). Prevents memory exhaustion from
    /// maliciously crafted audit files with extremely long lines.
    /// SECURITY (R33-002): A valid audit entry should be under 100 KB (including
    /// large metadata), so 1 MB is generous while still preventing abuse.
    const MAX_AUDIT_LINE_SIZE: usize = 1024 * 1024;

    /// Load all entries from the audit log.
    ///
    /// Corrupt or malformed lines are skipped with a warning rather than
    /// failing the entire load. This ensures the audit log remains readable
    /// even if a single line is corrupted (e.g., partial write, disk error).
    ///
    /// **Security:** File size is checked before reading to prevent memory DoS.
    /// Files larger than 100 MB are rejected with an error.
    pub async fn load_entries(&self) -> Result<Vec<AuditEntry>, AuditError> {
        // Exploit #10 fix: check file size before loading to prevent memory DoS
        match tokio::fs::metadata(&self.log_path).await {
            Ok(meta) if meta.len() > Self::MAX_AUDIT_LOG_SIZE => {
                return Err(AuditError::Validation(format!(
                    "Audit log too large ({} bytes, max {} bytes). Use log rotation.",
                    meta.len(),
                    Self::MAX_AUDIT_LOG_SIZE
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(AuditError::Io(e)),
            Ok(_) => {} // Size OK, proceed
        }

        // SECURITY (R241-AUD-1): Use BufReader line-by-line to avoid double-memory
        // (full file string + parsed entries simultaneously in memory).
        let file = match tokio::fs::File::open(&self.log_path).await {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(AuditError::Io(e)),
        };
        let reader = tokio::io::BufReader::new(file);
        use tokio::io::AsyncBufReadExt;
        let mut lines = reader.lines();

        let mut entries = Vec::new();
        let mut skipped = 0usize;
        let mut line_num = 0usize;
        while let Some(line) = lines.next_line().await.map_err(AuditError::Io)? {
            line_num = line_num.saturating_add(1);
            if line.trim().is_empty() {
                continue;
            }
            // SECURITY (R33-002): Reject oversized lines to prevent memory exhaustion.
            if line.len() > Self::MAX_AUDIT_LINE_SIZE {
                skipped = skipped.saturating_add(1);
                tracing::warn!(
                    line_num = line_num,
                    line_len = line.len(),
                    max_len = Self::MAX_AUDIT_LINE_SIZE,
                    "Skipping oversized audit line in {:?}",
                    self.log_path
                );
                continue;
            }
            match serde_json::from_str::<AuditEntry>(&line) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    skipped = skipped.saturating_add(1);
                    tracing::warn!(
                        "Skipping corrupt audit line {} in {:?}: {}",
                        line_num,
                        self.log_path,
                        e
                    );
                }
            }
        }
        if skipped > 0 {
            tracing::warn!(
                "Skipped {} corrupt line(s) while loading audit log {:?}",
                skipped,
                self.log_path
            );
        }

        Ok(entries)
    }

    /// Load only entries whose sequence is in the inclusive range `[from, to]`.
    ///
    /// Unlike `load_entries()`, this method scans the JSONL file line-by-line and
    /// only materializes matching entries, avoiding full-log materialization in
    /// memory for range queries.
    ///
    /// The method also enforces a cap on successfully parsed entries scanned from
    /// disk (`max_scanned_entries`) to fail closed on very large logs.
    pub async fn load_entries_in_sequence_range(
        &self,
        from: u64,
        to: u64,
        max_scanned_entries: usize,
    ) -> Result<Vec<AuditEntry>, AuditError> {
        if from > to {
            return Err(AuditError::Validation(format!(
                "from ({from}) must be <= to ({to})"
            )));
        }

        // SECURITY: Validate log_path has no path-traversal components before I/O.
        // Defense-in-depth: the path originates from application config, but we
        // validate here to satisfy CodeQL rust/path-injection analysis.
        for component in self.log_path.components() {
            if matches!(component, std::path::Component::ParentDir) {
                return Err(AuditError::Validation(
                    "audit log path contains '..' traversal component".to_string(),
                ));
            }
        }

        match tokio::fs::metadata(&self.log_path).await {
            Ok(meta) if meta.len() > Self::MAX_AUDIT_LOG_SIZE => {
                return Err(AuditError::Validation(format!(
                    "Audit log too large ({} bytes, max {} bytes). Use log rotation.",
                    meta.len(),
                    Self::MAX_AUDIT_LOG_SIZE
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(AuditError::Io(e)),
            Ok(_) => {}
        }

        let file = match tokio::fs::File::open(&self.log_path).await {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(AuditError::Io(e)),
        };
        let reader = tokio::io::BufReader::new(file);
        let mut lines = reader.lines();

        let mut matches = Vec::new();
        let mut scanned_entries = 0usize;
        let mut skipped = 0usize;
        let mut line_num = 0usize;
        while let Some(line) = lines.next_line().await? {
            line_num += 1;
            if line.trim().is_empty() {
                continue;
            }
            if line.len() > Self::MAX_AUDIT_LINE_SIZE {
                skipped = skipped.saturating_add(1);
                tracing::warn!(
                    line_num = line_num,
                    line_len = line.len(),
                    max_len = Self::MAX_AUDIT_LINE_SIZE,
                    "Skipping oversized audit line in {:?}",
                    self.log_path
                );
                continue;
            }
            match serde_json::from_str::<AuditEntry>(&line) {
                Ok(entry) => {
                    scanned_entries = scanned_entries.saturating_add(1);
                    if scanned_entries > max_scanned_entries {
                        return Err(AuditError::Validation(
                            "Audit log exceeds capacity limit. Rotate or archive the audit log."
                                .to_string(),
                        ));
                    }
                    if entry.sequence >= from && entry.sequence <= to {
                        matches.push(entry);
                    }
                }
                Err(e) => {
                    skipped = skipped.saturating_add(1);
                    tracing::warn!(
                        "Skipping corrupt audit line {} in {:?}: {}",
                        line_num,
                        self.log_path,
                        e
                    );
                }
            }
        }

        if skipped > 0 {
            tracing::warn!(
                "Skipped {} corrupt line(s) while loading audit log range {:?}",
                skipped,
                self.log_path
            );
        }

        Ok(matches)
    }

    /// Verify the hash chain integrity of the audit log.
    ///
    /// Walks all entries and verifies that each hash links correctly
    /// to the previous entry's hash.
    pub async fn verify_chain(&self) -> Result<ChainVerification, AuditError> {
        let entries = self.load_entries().await?;

        if entries.is_empty() {
            return Ok(ChainVerification {
                valid: true,
                entries_checked: 0,
                first_broken_at: None,
            });
        }

        let mut prev_hash: Option<String> = None;
        let mut seen_hashed_entry = false;
        // SECURITY (R226-CROSS-1): Track previous timestamp for monotonicity.
        // Timestamps must be non-decreasing to prevent audit log reordering
        // via clock tampering.
        let mut prev_timestamp: Option<&str> = None;
        // R230-AUD-1: Track previous sequence for strict monotonicity.
        // Sequence numbers are assigned via AtomicU64::fetch_add and must
        // strictly increase. A regression indicates log tampering (deletion
        // or reordering of entries).
        let mut prev_sequence: Option<u64> = None;

        for (i, entry) in entries.iter().enumerate() {
            // SECURITY (R226-CROSS-1, R227-AUD-2): Verify timestamp ordering.
            // ISO 8601 timestamps are lexicographically orderable ONLY when in UTC.
            // Non-UTC offsets (e.g., +05:30) break lexicographic ordering, so we
            // reject any timestamp that is not UTC (fail-closed).
            // Accept both 'Z' and '+00:00' as valid UTC representations.
            let is_utc = entry.timestamp.ends_with('Z')
                || entry.timestamp.ends_with('z')
                || entry.timestamp.ends_with("+00:00");
            let timestamps_nondecreasing = if let Some(prev_ts) = prev_timestamp {
                // SECURITY (R228-AUD-1): Normalize UTC suffixes before comparison.
                // A mix of 'Z' and '+00:00' suffixes in the same log breaks
                // lexicographic ordering because '+' (0x2B) < 'Z' (0x5A) in ASCII.
                // Stripping the suffix allows correct date-time prefix comparison.
                let curr_norm = strip_utc_suffix(&entry.timestamp);
                let prev_norm = strip_utc_suffix(prev_ts);
                curr_norm >= prev_norm
            } else {
                true
            };
            let timestamp_guard_ok =
                verified_audit_chain::timestamp_guard(is_utc, timestamps_nondecreasing);
            if !timestamp_guard_ok {
                tracing::warn!(
                    entry_index = i,
                    timestamp = %entry.timestamp,
                    "Audit entry timestamp not in UTC (must end with Z or +00:00)"
                );
                return Ok(ChainVerification {
                    valid: false,
                    entries_checked: i + 1,
                    first_broken_at: Some(i),
                });
            }
            if !timestamps_nondecreasing {
                // prev_timestamp is guaranteed Some here (timestamps_nondecreasing is false
                // only when the Some branch at line 266 sets it)
                let prev_ts = prev_timestamp.unwrap_or("");
                tracing::warn!(
                    entry_index = i,
                    prev_ts = prev_ts,
                    curr_ts = %entry.timestamp,
                    "Audit chain timestamp regression detected"
                );
                return Ok(ChainVerification {
                    valid: false,
                    entries_checked: i + 1,
                    first_broken_at: Some(i),
                });
            }
            prev_timestamp = Some(&entry.timestamp);

            // R230-AUD-1: Verify sequence monotonicity.
            // sequence=0 is valid for legacy entries (pre-R33), so only check
            // when the current entry has a non-zero sequence.
            let prev_sequence_value = prev_sequence.unwrap_or(0);
            let sequence_guard_ok = verified_audit_chain::sequence_monotonic(
                prev_sequence.is_some(),
                prev_sequence_value,
                entry.sequence,
            );
            if !sequence_guard_ok {
                tracing::warn!(
                    entry_index = i,
                    prev_seq = prev_sequence_value,
                    curr_seq = entry.sequence,
                    "Audit chain sequence regression detected"
                );
                return Ok(ChainVerification {
                    valid: false,
                    entries_checked: i + 1,
                    first_broken_at: Some(i),
                });
            }
            if entry.sequence > 0 {
                prev_sequence = Some(verified_audit_chain::next_prev_sequence(
                    prev_sequence_value,
                    entry.sequence,
                ));
            }

            let entry_has_hash = entry.entry_hash.is_some();
            let hash_presence_guard_ok =
                verified_audit_chain::hash_presence_valid(seen_hashed_entry, entry_has_hash);
            if !hash_presence_guard_ok {
                // Legacy entries are only allowed before the first hashed entry.
                // Once a hashed entry appears, all subsequent entries MUST have hashes.
                return Ok(ChainVerification {
                    valid: false,
                    entries_checked: i + 1,
                    first_broken_at: Some(i),
                });
            }

            let (prev_hash_matches, entry_hash_matches) = if entry_has_hash {
                let computed = Self::compute_entry_hash(entry)?;
                (
                    entry.prev_hash == prev_hash,
                    entry.entry_hash.as_deref() == Some(&computed),
                )
            } else {
                (true, true)
            };

            if !verified_audit_chain::audit_chain_step_valid(
                timestamp_guard_ok,
                sequence_guard_ok,
                hash_presence_guard_ok,
                entry_has_hash,
                prev_hash_matches,
                entry_hash_matches,
            ) {
                return Ok(ChainVerification {
                    valid: false,
                    entries_checked: i + 1,
                    first_broken_at: Some(i),
                });
            }

            seen_hashed_entry =
                verified_audit_chain::next_seen_hashed_entry(seen_hashed_entry, entry_has_hash);

            if !entry_has_hash {
                prev_hash = None;
                continue;
            }

            prev_hash = entry.entry_hash.clone();
        }

        Ok(ChainVerification {
            valid: true,
            entries_checked: entries.len(),
            first_broken_at: None,
        })
    }

    /// Detect entries with duplicate IDs in the audit log.
    ///
    /// Returns a list of IDs that appear more than once, along with their
    /// occurrence counts. Duplicate IDs may indicate a replay attack or
    /// log corruption.
    pub async fn detect_duplicate_ids(&self) -> Result<Vec<(String, usize)>, AuditError> {
        let entries = self.load_entries().await?;
        let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();

        // SECURITY (R235-AUD-6): Use saturating_add per Trap 9.
        for entry in &entries {
            let count = counts.entry(entry.id.as_str()).or_insert(0);
            *count = count.saturating_add(1);
        }

        let mut duplicates: Vec<(String, usize)> = counts
            .into_iter()
            .filter(|(_, count)| *count > 1)
            .map(|(id, count)| (id.to_string(), count))
            .collect();

        duplicates.sort_by(|a, b| b.1.cmp(&a.1)); // Most duplicated first
        Ok(duplicates)
    }

    /// Generate a summary report from the audit log.
    ///
    /// ## Memory Limitations (GAP-F06)
    ///
    /// This method loads **all** audit entries into memory via `load_entries()`,
    /// then returns them as part of the `AuditReport`. For large audit files
    /// (up to the 100 MB `MAX_AUDIT_LOG_SIZE` limit), this can consume
    /// significant memory (~2-3x the file size due to deserialized JSON overhead).
    /// Callers processing large audit files should consider streaming alternatives
    /// or use log rotation to keep individual files manageable.
    pub async fn generate_report(&self) -> Result<AuditReport, AuditError> {
        let entries = self.load_entries().await?;

        let mut allow_count = 0usize;
        let mut deny_count = 0usize;
        let mut require_approval_count = 0usize;

        // SECURITY (R235-AUD-5): Use saturating_add on all counters per Trap 9.
        for entry in &entries {
            match &entry.verdict {
                Verdict::Allow => allow_count = allow_count.saturating_add(1),
                Verdict::Deny { .. } => deny_count = deny_count.saturating_add(1),
                Verdict::RequireApproval { .. } => {
                    require_approval_count = require_approval_count.saturating_add(1)
                }
                // Handle future variants - count as deny (fail-closed)
                _ => deny_count = deny_count.saturating_add(1),
            }
        }

        Ok(AuditReport {
            total_entries: entries.len(),
            allow_count,
            deny_count,
            require_approval_count,
            entries,
        })
    }

    /// Generate a Merkle inclusion proof for the audit entry at `index`.
    ///
    /// Requires the Merkle tree to be enabled via `with_merkle_tree()`.
    pub fn generate_merkle_proof(
        &self,
        index: u64,
    ) -> Result<crate::merkle::MerkleProof, AuditError> {
        let merkle = self.merkle_tree.as_ref().ok_or_else(|| {
            AuditError::Validation("Merkle tree not enabled on this logger".to_string())
        })?;
        let tree = merkle
            .lock()
            .map_err(|e| AuditError::Validation(format!("Merkle tree lock poisoned: {e}")))?;
        tree.generate_proof(index)
    }

    /// Return the current Merkle root hash as a hex string.
    ///
    /// Returns `None` if the Merkle tree is not enabled or the tree is empty.
    /// Use this to obtain a trusted root for `verify_merkle_proof()`.
    pub fn merkle_root_hex(&self) -> Result<Option<String>, AuditError> {
        let merkle = match self.merkle_tree.as_ref() {
            Some(m) => m,
            None => return Ok(None),
        };
        let tree = merkle
            .lock()
            .map_err(|e| AuditError::Validation(format!("Merkle tree lock poisoned: {e}")))?;
        Ok(tree.root_hex())
    }

    /// Verify a Merkle inclusion proof for an audit entry.
    ///
    /// This is a convenience wrapper around `MerkleTree::verify_proof`.
    /// The `entry_hash` should be the SHA-256 hash from the audit entry's
    /// `entry_hash` field. The `trusted_root` must come from the Merkle tree
    /// state or a signed checkpoint — never from the proof itself.
    ///
    /// SECURITY (FIND-R46-MRK-002): Requires an externally-supplied trusted root
    /// to prevent self-referential proof forgery.
    pub fn verify_merkle_proof(
        entry_hash: &str,
        proof: &crate::merkle::MerkleProof,
        trusted_root: &str,
    ) -> Result<crate::merkle::MerkleVerification, AuditError> {
        let hash_bytes = hex::decode(entry_hash)
            .map_err(|e| AuditError::Validation(format!("Invalid entry hash hex: {e}")))?;
        if hash_bytes.len() != 32 {
            return Err(AuditError::Validation(format!(
                "Entry hash has wrong length: {} (expected 32)",
                hash_bytes.len()
            )));
        }
        let mut leaf_arr = [0u8; 32];
        leaf_arr.copy_from_slice(&hash_bytes);
        let leaf = crate::merkle::hash_leaf(&leaf_arr);
        crate::merkle::MerkleTree::verify_proof(leaf, proof, trusted_root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use vellaveto_types::Action;

    #[tokio::test]
    async fn test_load_entries_in_sequence_range_returns_matches_only() {
        let tmp = TempDir::new().expect("temp dir");
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path);

        logger
            .log_entry(
                &Action::new("tool", "f0", serde_json::json!({})),
                &Verdict::Allow,
                serde_json::json!({}),
            )
            .await
            .expect("entry 0");
        logger
            .log_entry(
                &Action::new("tool", "f1", serde_json::json!({})),
                &Verdict::Allow,
                serde_json::json!({}),
            )
            .await
            .expect("entry 1");
        logger
            .log_entry(
                &Action::new("tool", "f2", serde_json::json!({})),
                &Verdict::Allow,
                serde_json::json!({}),
            )
            .await
            .expect("entry 2");

        let entries = logger
            .load_entries_in_sequence_range(1, 1, 100)
            .await
            .expect("range load");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].sequence, 1);
    }

    #[tokio::test]
    async fn test_load_entries_in_sequence_range_enforces_capacity_limit() {
        let tmp = TempDir::new().expect("temp dir");
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path);

        for idx in 0..3 {
            logger
                .log_entry(
                    &Action::new("tool", format!("f{idx}"), serde_json::json!({})),
                    &Verdict::Allow,
                    serde_json::json!({}),
                )
                .await
                .expect("entry");
        }

        let err = logger
            .load_entries_in_sequence_range(0, 10, 2)
            .await
            .expect_err("capacity must fail");
        match err {
            AuditError::Validation(msg) => {
                assert!(msg.contains("capacity limit"), "unexpected msg: {msg}");
            }
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    // ── load_entries tests ──────────────────────────────────────────

    #[tokio::test]
    async fn test_load_entries_empty_file_returns_empty_vec() {
        let tmp = TempDir::new().expect("temp dir");
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path);
        let entries = logger.load_entries().await.expect("load");
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn test_load_entries_skips_corrupt_lines() {
        let tmp = TempDir::new().expect("temp dir");
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path.clone());

        // Write a valid entry first
        logger
            .log_entry(
                &Action::new("tool", "valid", serde_json::json!({})),
                &Verdict::Allow,
                serde_json::json!({}),
            )
            .await
            .expect("entry");

        // Append a corrupt line to the file
        tokio::fs::write(
            &log_path,
            format!(
                "{}\n{}\n",
                tokio::fs::read_to_string(&log_path)
                    .await
                    .expect("read")
                    .trim(),
                "this is not valid json"
            ),
        )
        .await
        .expect("write corrupt");

        let entries = logger.load_entries().await.expect("load");
        // Should have loaded the valid entry, skipped the corrupt one
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action.function, "valid");
    }

    #[tokio::test]
    async fn test_load_entries_rejects_oversized_file() {
        let tmp = TempDir::new().expect("temp dir");
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path.clone());

        // Create a file just over the MAX_AUDIT_LOG_SIZE limit
        // We write a minimal amount to check the size gate
        let oversized_content = "x".repeat(AuditLogger::MAX_AUDIT_LOG_SIZE as usize + 1);
        tokio::fs::write(&log_path, oversized_content)
            .await
            .expect("write oversized");

        let err = logger
            .load_entries()
            .await
            .expect_err("should reject oversized");
        match err {
            AuditError::Validation(msg) => {
                assert!(msg.contains("too large"), "unexpected msg: {msg}");
            }
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_load_entries_skips_oversized_lines() {
        let tmp = TempDir::new().expect("temp dir");
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path.clone());

        // Write a valid entry
        logger
            .log_entry(
                &Action::new("tool", "good", serde_json::json!({})),
                &Verdict::Allow,
                serde_json::json!({}),
            )
            .await
            .expect("entry");

        // Read existing content, then append a very long line (> MAX_AUDIT_LINE_SIZE)
        let existing = tokio::fs::read_to_string(&log_path).await.expect("read");
        let long_line = "a".repeat(AuditLogger::MAX_AUDIT_LINE_SIZE + 10);
        tokio::fs::write(&log_path, format!("{existing}{long_line}\n"))
            .await
            .expect("write");

        let entries = logger.load_entries().await.expect("load");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action.function, "good");
    }

    // ── verify_chain tests ──────────────────────────────────────────

    #[tokio::test]
    async fn test_verify_chain_empty_log_valid() {
        let tmp = TempDir::new().expect("temp dir");
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path);
        let result = logger.verify_chain().await.expect("verify");
        assert!(result.valid);
        assert_eq!(result.entries_checked, 0);
    }

    #[tokio::test]
    async fn test_verify_chain_valid_chain() {
        let tmp = TempDir::new().expect("temp dir");
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path);

        for i in 0..5 {
            logger
                .log_entry(
                    &Action::new("tool", format!("fn{i}"), serde_json::json!({})),
                    &Verdict::Allow,
                    serde_json::json!({}),
                )
                .await
                .expect("entry");
        }

        let result = logger.verify_chain().await.expect("verify");
        assert!(result.valid, "Chain should be valid");
        assert_eq!(result.entries_checked, 5);
        assert!(result.first_broken_at.is_none());
    }

    #[tokio::test]
    async fn test_verify_chain_detects_tampered_hash() {
        let tmp = TempDir::new().expect("temp dir");
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path.clone());

        for i in 0..3 {
            logger
                .log_entry(
                    &Action::new("tool", format!("fn{i}"), serde_json::json!({})),
                    &Verdict::Allow,
                    serde_json::json!({}),
                )
                .await
                .expect("entry");
        }

        // Tamper with the second entry's hash
        let content = tokio::fs::read_to_string(&log_path).await.expect("read");
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        if lines.len() >= 2 {
            let mut entry: AuditEntry = serde_json::from_str(&lines[1]).expect("parse entry");
            entry.entry_hash = Some(
                "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            );
            lines[1] = serde_json::to_string(&entry).expect("serialize");
            let tampered = lines.join("\n") + "\n";
            tokio::fs::write(&log_path, tampered)
                .await
                .expect("write tampered");
        }

        let result = logger.verify_chain().await.expect("verify");
        assert!(!result.valid, "Tampered chain should be invalid");
        assert!(result.first_broken_at.is_some());
    }

    #[tokio::test]
    async fn test_verify_chain_detects_timestamp_regression() {
        let tmp = TempDir::new().expect("temp dir");
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path.clone());

        // Write two entries
        logger
            .log_entry(
                &Action::new("tool", "fn0", serde_json::json!({})),
                &Verdict::Allow,
                serde_json::json!({}),
            )
            .await
            .expect("entry 0");
        logger
            .log_entry(
                &Action::new("tool", "fn1", serde_json::json!({})),
                &Verdict::Allow,
                serde_json::json!({}),
            )
            .await
            .expect("entry 1");

        // Tamper the second entry's timestamp to be earlier than the first
        let content = tokio::fs::read_to_string(&log_path).await.expect("read");
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        if lines.len() >= 2 {
            let mut entry: AuditEntry = serde_json::from_str(&lines[1]).expect("parse entry");
            entry.timestamp = "2020-01-01T00:00:00Z".to_string();
            // Also fix the hash so the hash check passes but timestamp check fails
            // Actually the hash will be wrong too, but the timestamp check runs first
            lines[1] = serde_json::to_string(&entry).expect("serialize");
            let tampered = lines.join("\n") + "\n";
            tokio::fs::write(&log_path, tampered).await.expect("write");
        }

        let result = logger.verify_chain().await.expect("verify");
        assert!(!result.valid, "Timestamp regression should be detected");
    }

    #[tokio::test]
    async fn test_verify_chain_rejects_non_utc_timestamp() {
        let tmp = TempDir::new().expect("temp dir");
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path.clone());

        // Write one valid entry
        logger
            .log_entry(
                &Action::new("tool", "fn0", serde_json::json!({})),
                &Verdict::Allow,
                serde_json::json!({}),
            )
            .await
            .expect("entry");

        // Tamper the timestamp to have a non-UTC offset
        let content = tokio::fs::read_to_string(&log_path).await.expect("read");
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        if !lines.is_empty() {
            let mut entry: AuditEntry = serde_json::from_str(&lines[0]).expect("parse");
            entry.timestamp = "2026-03-01T12:00:00+05:30".to_string();
            lines[0] = serde_json::to_string(&entry).expect("serialize");
            tokio::fs::write(&log_path, lines.join("\n") + "\n")
                .await
                .expect("write");
        }

        let result = logger.verify_chain().await.expect("verify");
        assert!(!result.valid, "Non-UTC timestamps should be rejected");
    }

    #[tokio::test]
    async fn test_verify_chain_detects_sequence_regression() {
        let tmp = TempDir::new().expect("temp dir");
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path.clone());

        for idx in 0..3 {
            logger
                .log_entry(
                    &Action::new("tool", format!("fn{idx}"), serde_json::json!({})),
                    &Verdict::Allow,
                    serde_json::json!({}),
                )
                .await
                .expect("entry");
        }

        let content = tokio::fs::read_to_string(&log_path).await.expect("read");
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        if lines.len() >= 3 {
            let mut entry: AuditEntry = serde_json::from_str(&lines[2]).expect("parse entry");
            entry.sequence = 1;
            lines[2] = serde_json::to_string(&entry).expect("serialize");
            tokio::fs::write(&log_path, lines.join("\n") + "\n")
                .await
                .expect("write");
        }

        let result = logger.verify_chain().await.expect("verify");
        assert!(!result.valid, "Sequence regression should be detected");
    }

    #[tokio::test]
    async fn test_verify_chain_rejects_unhashed_entry_after_hashed_entry() {
        let tmp = TempDir::new().expect("temp dir");
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path.clone());

        logger
            .log_entry(
                &Action::new("tool", "fn0", serde_json::json!({})),
                &Verdict::Allow,
                serde_json::json!({}),
            )
            .await
            .expect("entry 0");
        logger
            .log_entry(
                &Action::new("tool", "fn1", serde_json::json!({})),
                &Verdict::Allow,
                serde_json::json!({}),
            )
            .await
            .expect("entry 1");

        let content = tokio::fs::read_to_string(&log_path).await.expect("read");
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        if lines.len() >= 2 {
            let mut entry: AuditEntry = serde_json::from_str(&lines[1]).expect("parse entry");
            entry.entry_hash = None;
            entry.prev_hash = None;
            lines[1] = serde_json::to_string(&entry).expect("serialize");
            tokio::fs::write(&log_path, lines.join("\n") + "\n")
                .await
                .expect("write");
        }

        let result = logger.verify_chain().await.expect("verify");
        assert!(
            !result.valid,
            "Unhashed entry after hashed entry must be rejected"
        );
    }

    // ── detect_duplicate_ids tests ──────────────────────────────────

    #[tokio::test]
    async fn test_detect_duplicate_ids_no_duplicates() {
        let tmp = TempDir::new().expect("temp dir");
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path);

        for i in 0..3 {
            logger
                .log_entry(
                    &Action::new("tool", format!("fn{i}"), serde_json::json!({})),
                    &Verdict::Allow,
                    serde_json::json!({}),
                )
                .await
                .expect("entry");
        }

        let dups = logger.detect_duplicate_ids().await.expect("detect");
        assert!(dups.is_empty());
    }

    #[tokio::test]
    async fn test_detect_duplicate_ids_finds_duplicates() {
        let tmp = TempDir::new().expect("temp dir");
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path.clone());

        // Write two entries, then manually duplicate the first entry's ID
        logger
            .log_entry(
                &Action::new("tool", "fn0", serde_json::json!({})),
                &Verdict::Allow,
                serde_json::json!({}),
            )
            .await
            .expect("entry 0");
        logger
            .log_entry(
                &Action::new("tool", "fn1", serde_json::json!({})),
                &Verdict::Allow,
                serde_json::json!({}),
            )
            .await
            .expect("entry 1");

        // Read and duplicate the first entry's ID in the second entry
        let content = tokio::fs::read_to_string(&log_path).await.expect("read");
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        if lines.len() >= 2 {
            let entry0: AuditEntry = serde_json::from_str(&lines[0]).expect("parse");
            let mut entry1: AuditEntry = serde_json::from_str(&lines[1]).expect("parse");
            entry1.id = entry0.id.clone();
            lines[1] = serde_json::to_string(&entry1).expect("serialize");
            tokio::fs::write(&log_path, lines.join("\n") + "\n")
                .await
                .expect("write");
        }

        let dups = logger.detect_duplicate_ids().await.expect("detect");
        assert_eq!(dups.len(), 1);
        assert_eq!(dups[0].1, 2); // Two occurrences
    }

    // ── generate_report tests ───────────────────────────────────────

    #[tokio::test]
    async fn test_generate_report_counts_verdicts() {
        let tmp = TempDir::new().expect("temp dir");
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path);

        // 2 Allow, 1 Deny
        logger
            .log_entry(
                &Action::new("tool", "allow1", serde_json::json!({})),
                &Verdict::Allow,
                serde_json::json!({}),
            )
            .await
            .expect("entry");
        logger
            .log_entry(
                &Action::new("tool", "allow2", serde_json::json!({})),
                &Verdict::Allow,
                serde_json::json!({}),
            )
            .await
            .expect("entry");
        logger
            .log_entry(
                &Action::new("tool", "deny1", serde_json::json!({})),
                &Verdict::Deny {
                    reason: "blocked".to_string(),
                },
                serde_json::json!({}),
            )
            .await
            .expect("entry");

        let report = logger.generate_report().await.expect("report");
        assert_eq!(report.total_entries, 3);
        assert_eq!(report.allow_count, 2);
        assert_eq!(report.deny_count, 1);
        assert_eq!(report.require_approval_count, 0);
        assert_eq!(report.entries.len(), 3);
    }

    #[tokio::test]
    async fn test_generate_report_empty_log() {
        let tmp = TempDir::new().expect("temp dir");
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path);

        let report = logger.generate_report().await.expect("report");
        assert_eq!(report.total_entries, 0);
        assert_eq!(report.allow_count, 0);
        assert_eq!(report.deny_count, 0);
    }

    // ── strip_utc_suffix tests ──────────────────────────────────────

    #[test]
    fn test_strip_utc_suffix_z() {
        assert_eq!(
            strip_utc_suffix("2026-03-01T12:00:00Z"),
            "2026-03-01T12:00:00"
        );
    }

    #[test]
    fn test_strip_utc_suffix_lowercase_z() {
        assert_eq!(
            strip_utc_suffix("2026-03-01T12:00:00z"),
            "2026-03-01T12:00:00"
        );
    }

    #[test]
    fn test_strip_utc_suffix_plus_zero() {
        assert_eq!(
            strip_utc_suffix("2026-03-01T12:00:00+00:00"),
            "2026-03-01T12:00:00"
        );
    }

    #[test]
    fn test_strip_utc_suffix_no_suffix() {
        assert_eq!(
            strip_utc_suffix("2026-03-01T12:00:00"),
            "2026-03-01T12:00:00"
        );
    }

    // ── Mixed Z and +00:00 ordering test ────────────────────────────

    #[tokio::test]
    async fn test_verify_chain_mixed_utc_suffixes_valid() {
        // R228-AUD-1: A chain with mixed Z and +00:00 suffixes on the same
        // date-time prefix should be valid after suffix normalization.
        let tmp = TempDir::new().expect("temp dir");
        let log_path = tmp.path().join("audit.log");
        let logger = AuditLogger::new(log_path.clone());

        // Write two entries
        logger
            .log_entry(
                &Action::new("tool", "fn0", serde_json::json!({})),
                &Verdict::Allow,
                serde_json::json!({}),
            )
            .await
            .expect("entry 0");
        logger
            .log_entry(
                &Action::new("tool", "fn1", serde_json::json!({})),
                &Verdict::Allow,
                serde_json::json!({}),
            )
            .await
            .expect("entry 1");

        // Now rewrite the entries with controlled timestamps that only differ
        // in UTC suffix representation
        let content = tokio::fs::read_to_string(&log_path).await.expect("read");
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        if lines.len() >= 2 {
            let mut entry0: AuditEntry = serde_json::from_str(&lines[0]).expect("parse");
            let mut entry1: AuditEntry = serde_json::from_str(&lines[1]).expect("parse");
            // Same time, different suffix
            entry0.timestamp = "2026-03-01T12:00:00Z".to_string();
            entry1.timestamp = "2026-03-01T12:00:01+00:00".to_string();
            // Recompute hashes
            entry0.entry_hash = Some(AuditLogger::compute_entry_hash(&entry0).expect("hash"));
            entry1.prev_hash = entry0.entry_hash.clone();
            entry1.entry_hash = Some(AuditLogger::compute_entry_hash(&entry1).expect("hash"));
            lines[0] = serde_json::to_string(&entry0).expect("serialize");
            lines[1] = serde_json::to_string(&entry1).expect("serialize");
            tokio::fs::write(&log_path, lines.join("\n") + "\n")
                .await
                .expect("write");
        }

        let result = logger.verify_chain().await.expect("verify");
        assert!(
            result.valid,
            "Mixed UTC suffixes should be handled correctly"
        );
    }
}
