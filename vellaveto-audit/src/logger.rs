// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

use crate::merkle::MerkleTree;
use crate::pii::PiiScanner;
use crate::redaction::{
    redact_keys_and_patterns, redact_keys_and_patterns_with_scanner, redact_keys_only, PII_REGEXES,
    REDACTED,
};
use crate::types::{AuditEntry, AuditError, RedactionLevel};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Mutex;
use uuid::Uuid;
use vellaveto_types::{AcisDecisionEnvelope, Action, Verdict};

use crate::pii::CustomPiiPattern;
use crate::rotation::DEFAULT_MAX_FILE_SIZE;
use crate::{trusted_audit_fs, verified_audit_append};

/// Append-only audit logger for policy evaluation decisions.
///
/// Records every [`Action`] + [`Verdict`] pair to a persistent log file
/// in JSONL format for compliance, debugging, and forensic analysis.
///
/// New entries include SHA-256 hash chains for tamper evidence.
/// Sensitive values in parameters are redacted by default.
///
/// When the log file exceeds `max_file_size`, it is rotated to a
/// timestamped filename (e.g., `audit.2026-02-02T12-00-00.log`) and
/// a fresh file + hash chain is started.
/// The head of the hash chain, plus the timestamp of the last appended entry.
///
/// These two travel together under a single lock deliberately. They express one
/// invariant — "what the last entry was" — and splitting them across two mutexes
/// would let a concurrent append observe a hash and a timestamp from different
/// entries, which is exactly the kind of race that makes the timestamp guard
/// below useless.
#[derive(Debug, Default)]
pub(crate) struct ChainHead {
    /// Hash of the last successfully written entry.
    pub(crate) last_hash: Option<String>,
    /// Timestamp of the last successfully written entry.
    ///
    /// SECURITY: Deliberately NOT reset on rotation, unlike `last_hash`. A new
    /// file starts a new hash chain, but wall-clock time does not restart, so
    /// carrying the timestamp across rotation keeps a backwards clock from being
    /// laundered by triggering a rotation.
    pub(crate) last_timestamp: Option<String>,
}

pub struct AuditLogger {
    pub(crate) log_path: PathBuf,
    pub(crate) chain_head: Mutex<ChainHead>,
    pub(crate) redaction_level: RedactionLevel,
    /// Maximum log file size in bytes before rotation. 0 = no rotation.
    pub(crate) max_file_size: u64,
    /// Optional Ed25519 signing key for creating signed checkpoints.
    /// Boxed to prevent stack copies of key material during moves.
    pub(crate) signing_key: Option<Box<SigningKey>>,
    /// Optional pinned verifying key (hex-encoded 32-byte Ed25519 public key).
    /// When set, `verify_checkpoints()` rejects checkpoints signed by any other key.
    /// This prevents an attacker with file write access from forging checkpoints
    /// with their own keypair.
    pub(crate) trusted_verifying_key: Option<String>,
    /// Optional PII scanner with custom patterns (replaces global PII_REGEXES).
    /// When present, uses substring redaction instead of whole-value replacement.
    pub(crate) pii_scanner: Option<PiiScanner>,
    /// In-memory entry count for the current log file.
    /// Incremented after each successful write. Reset to 0 on rotation.
    /// Used to avoid re-reading the file to count entries during rotation.
    pub(crate) entry_count: AtomicU64,
    /// Monotonically increasing global sequence counter.
    ///
    /// SECURITY (FIND-R111-007): Unlike `entry_count`, this counter is NEVER reset
    /// on log rotation. It is used as the `sequence` field in each audit entry,
    /// ensuring globally unique and strictly monotonic sequence numbers across all
    /// rotated log files. Resetting to 0 on rotation would cause sequence number
    /// reuse (entries 0, 1, 2, … in file 1, then 0, 1, 2, … again in file 2),
    /// breaking the uniqueness invariant that underpins hash-chain tamper detection
    /// (SECURITY R33-001) and audit forensics.
    pub(crate) global_sequence: AtomicU64,
    /// Optional Merkle tree for inclusion proofs.
    /// When enabled, every log entry's hash is appended as a leaf.
    pub(crate) merkle_tree: Option<std::sync::Mutex<MerkleTree>>,
    /// Optional audit sink for dual-writing to external stores (Phase 43).
    /// When present, entries are forwarded after the file write succeeds.
    /// Sink failures are non-fatal by default (logged as warnings).
    pub(crate) sink: Option<std::sync::Arc<dyn crate::sink::AuditSink>>,
    /// Whether sink failures should be treated as fatal errors.
    pub(crate) sink_failure_fatal: bool,
    /// Phase 54: ML-DSA-65 secret key (hex-encoded 4032-byte key).
    /// Used for creating hybrid (v2) checkpoints and rotation manifests.
    #[cfg(feature = "pqc-hybrid")]
    pub(crate) pqc_secret_key_hex: Option<String>,
    /// Phase 54: ML-DSA-65 public key (hex-encoded 1952-byte key).
    /// Stored alongside secret key for embedding in checkpoints.
    #[cfg(feature = "pqc-hybrid")]
    pub(crate) pqc_public_key_hex: Option<String>,
    /// Phase 54: Trusted ML-DSA-65 verifying key (hex-encoded 1952-byte key).
    /// When set, hybrid checkpoint verification rejects any checkpoint signed
    /// by a different PQC key. NOT feature-gated because verification logic
    /// must reject v2 checkpoints even when the feature is disabled.
    pub(crate) trusted_pqc_verifying_key: Option<String>,
}

impl AuditLogger {
    /// Create a new audit logger writing to the specified path.
    /// Sensitive value redaction is enabled by default.
    /// Log rotation is enabled at 100 MB by default.
    ///
    /// SECURITY (R22-SUP-1): A default PiiScanner is always constructed so that
    /// credit card (with Luhn), JWT, IPv4, and AWS key patterns are applied even
    /// when no custom patterns are configured. The legacy PII_REGEXES fallback
    /// (email/SSN/phone only) is never used.
    pub fn new(log_path: PathBuf) -> Self {
        Self {
            log_path,
            chain_head: Mutex::new(ChainHead::default()),
            redaction_level: RedactionLevel::KeysAndPatterns,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            signing_key: None,
            trusted_verifying_key: None,
            pii_scanner: Some(PiiScanner::new(&[])),
            entry_count: AtomicU64::new(0),
            global_sequence: AtomicU64::new(0),
            merkle_tree: None,
            sink: None,
            sink_failure_fatal: false,
            #[cfg(feature = "pqc-hybrid")]
            pqc_secret_key_hex: None,
            #[cfg(feature = "pqc-hybrid")]
            pqc_public_key_hex: None,
            trusted_pqc_verifying_key: None,
        }
    }

    /// Create a new audit logger with redaction disabled.
    /// Use this only for testing or when full parameter logging is required.
    pub fn new_unredacted(log_path: PathBuf) -> Self {
        Self {
            log_path,
            chain_head: Mutex::new(ChainHead::default()),
            redaction_level: RedactionLevel::Off,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            signing_key: None,
            trusted_verifying_key: None,
            pii_scanner: None,
            entry_count: AtomicU64::new(0),
            global_sequence: AtomicU64::new(0),
            merkle_tree: None,
            sink: None,
            sink_failure_fatal: false,
            #[cfg(feature = "pqc-hybrid")]
            pqc_secret_key_hex: None,
            #[cfg(feature = "pqc-hybrid")]
            pqc_public_key_hex: None,
            trusted_pqc_verifying_key: None,
        }
    }

    /// Set the redaction level for audit log entries.
    pub fn with_redaction_level(mut self, level: RedactionLevel) -> Self {
        self.redaction_level = level;
        self
    }

    /// Set the maximum log file size before rotation.
    /// Pass 0 to disable rotation entirely.
    pub fn with_max_file_size(mut self, max_bytes: u64) -> Self {
        self.max_file_size = max_bytes;
        self
    }

    /// Set the Ed25519 signing key for creating signed checkpoints.
    /// The key is boxed to prevent stack copies of sensitive key material.
    pub fn with_signing_key(mut self, key: SigningKey) -> Self {
        self.signing_key = Some(Box::new(key));
        self
    }

    /// Pin a trusted Ed25519 verifying key (hex-encoded 32-byte public key).
    ///
    /// When set, `verify_checkpoints()` rejects any checkpoint signed by a
    /// different key. This prevents an attacker with file write access from
    /// forging checkpoints with their own keypair.
    ///
    /// If not set, key continuity is still enforced: the first checkpoint's
    /// key pins all subsequent ones (TOFU model).
    pub fn with_trusted_key(mut self, hex_key: String) -> Self {
        self.trusted_verifying_key = Some(hex_key);
        self
    }

    /// Set ML-DSA-65 key pair for creating hybrid (v2) checkpoints.
    ///
    /// When set, `create_checkpoint()` and `maybe_rotate()` will produce
    /// hybrid Ed25519 + ML-DSA-65 signatures (signature_version = 2).
    #[cfg(feature = "pqc-hybrid")]
    pub fn with_pqc_keypair(mut self, secret_key_hex: String, public_key_hex: String) -> Self {
        self.pqc_secret_key_hex = Some(secret_key_hex);
        self.pqc_public_key_hex = Some(public_key_hex);
        self
    }

    /// Pin a trusted ML-DSA-65 verifying key (hex-encoded 1952-byte public key).
    ///
    /// When set, `verify_checkpoints()` rejects any v2 checkpoint signed by
    /// a different PQC key. This prevents PQC key substitution attacks.
    pub fn with_trusted_pqc_key(mut self, hex_key: String) -> Self {
        self.trusted_pqc_verifying_key = Some(hex_key);
        self
    }

    /// Set custom PII patterns for enhanced detection.
    ///
    /// When called, a `PiiScanner` is built with both default and custom patterns.
    /// The scanner uses **substring** replacement (e.g., `"Call 555-123-4567"` →
    /// `"Call [REDACTED]"`) instead of the legacy whole-value replacement.
    pub fn with_custom_pii_patterns(mut self, patterns: &[CustomPiiPattern]) -> Self {
        self.pii_scanner = Some(PiiScanner::new(patterns));
        self
    }

    /// Enable Merkle tree inclusion proofs.
    ///
    /// When enabled, every audit entry's hash is appended as a leaf to an
    /// incremental Merkle tree. The tree root is included in checkpoints,
    /// and inclusion proofs can be generated for individual entries.
    ///
    /// The Merkle tree leaf file is stored alongside the audit log with a
    /// `.merkle-leaves` suffix.
    pub fn with_merkle_tree(mut self) -> Self {
        let leaf_path = self.merkle_leaf_path();
        self.merkle_tree = Some(std::sync::Mutex::new(MerkleTree::new(leaf_path)));
        self
    }

    /// Attach an audit sink for dual-writing entries to an external store.
    ///
    /// The sink receives each entry after the file write succeeds.
    /// By default, sink failures are non-fatal (logged as warnings).
    /// Set `fatal` to `true` to make sink failures return errors to callers.
    pub fn with_sink(
        mut self,
        sink: std::sync::Arc<dyn crate::sink::AuditSink>,
        fatal: bool,
    ) -> Self {
        self.sink = Some(sink);
        self.sink_failure_fatal = fatal;
        self
    }

    /// Compute the path to the Merkle leaf file for this audit log.
    pub(crate) fn merkle_leaf_path(&self) -> PathBuf {
        let stem = self
            .log_path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy();
        let parent = self.log_path.parent().unwrap_or(std::path::Path::new("."));
        parent.join(format!("{stem}.merkle-leaves"))
    }

    /// Generate a new random Ed25519 signing key.
    pub fn generate_signing_key() -> SigningKey {
        SigningKey::generate(&mut rand::rng())
    }

    /// Load an Ed25519 signing key from raw 32-byte seed.
    pub fn signing_key_from_bytes(bytes: &[u8; 32]) -> SigningKey {
        SigningKey::from_bytes(bytes)
    }

    /// Serialize a value to RFC 8785 canonical JSON (deterministic key order,
    /// normalized numbers, minimal Unicode escaping).
    pub(crate) fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, AuditError> {
        let raw = serde_json::to_vec(value)?;
        let canonical = serde_json_canonicalizer::to_string(&raw)
            .map_err(|e| AuditError::Validation(format!("Canonical JSON error: {e}")))?;
        Ok(canonical.into_bytes())
    }

    /// Compute the SHA-256 hash of an entry's content.
    ///
    /// Hash = SHA-256(id || sequence || action_json || verdict_json || timestamp || metadata_json || prev_hash)
    ///
    /// Uses RFC 8785 (JSON Canonicalization Scheme) for deterministic JSON serialization.
    /// This ensures hash stability across serde_json versions and key insertion orders.
    ///
    /// SECURITY (R33-001): The sequence number is included in the hash to prevent
    /// collision attacks under high load where timestamps might be identical.
    pub(crate) fn compute_entry_hash(entry: &AuditEntry) -> Result<String, AuditError> {
        let action_json = Self::canonical_json(&entry.action)?;
        let verdict_json = Self::canonical_json(&entry.verdict)?;
        let metadata_json = Self::canonical_json(&entry.metadata)?;
        let prev_hash = entry.prev_hash.as_deref().unwrap_or("");

        let mut hasher = Sha256::new();
        // Length-prefix each field with u64 little-endian to prevent
        // boundary-shift collisions (e.g., id="ab",action="cd" vs id="abc",action="d")
        Self::hash_field(&mut hasher, entry.id.as_bytes());
        // SECURITY (R33-001): Include monotonic sequence number to ensure uniqueness
        // even if two entries have identical timestamps under high load.
        hasher.update(entry.sequence.to_le_bytes());
        Self::hash_field(&mut hasher, &action_json);
        Self::hash_field(&mut hasher, &verdict_json);
        Self::hash_field(&mut hasher, entry.timestamp.as_bytes());
        Self::hash_field(&mut hasher, &metadata_json);
        Self::hash_field(&mut hasher, prev_hash.as_bytes());

        Ok(hex::encode(hasher.finalize()))
    }

    /// Write a length-prefixed field into the hasher.
    pub(crate) fn hash_field(hasher: &mut Sha256, data: &[u8]) {
        hasher.update((data.len() as u64).to_le_bytes());
        hasher.update(data);
    }

    /// Log an action-verdict pair to the audit file.
    ///
    /// Validates input before writing. Each entry is a single JSON line
    /// with a SHA-256 hash chain linking it to the previous entry.
    pub async fn log_entry(
        &self,
        action: &Action,
        verdict: &Verdict,
        metadata: serde_json::Value,
    ) -> Result<(), AuditError> {
        self.log_entry_inner(action, verdict, metadata, None).await
    }

    /// Log an action-verdict pair with a dedicated ACIS decision envelope.
    ///
    /// SECURITY (R244-ACIS-1): The envelope is validated before persistence to
    /// prevent malformed envelopes (oversized fields, dangerous characters,
    /// collection bound violations) from corrupting JSONL audit logs.
    pub async fn log_entry_with_acis(
        &self,
        action: &Action,
        verdict: &Verdict,
        metadata: serde_json::Value,
        acis_envelope: AcisDecisionEnvelope,
    ) -> Result<(), AuditError> {
        if let Err(e) = acis_envelope.validate() {
            return Err(AuditError::Validation(format!(
                "ACIS envelope validation failed: {e}"
            )));
        }
        self.log_entry_inner(action, verdict, metadata, Some(acis_envelope))
            .await
    }

    async fn log_entry_inner(
        &self,
        action: &Action,
        verdict: &Verdict,
        metadata: serde_json::Value,
        acis_envelope: Option<AcisDecisionEnvelope>,
    ) -> Result<(), AuditError> {
        // Validate input
        self.validate_action(action)?;

        // SECURITY (R9-4): Validate metadata size to prevent oversized entries
        // from exhausting disk space or pushing the log past the load limit.
        // SECURITY (R253-AUD-1): Fail-closed on serialization failure instead of
        // defaulting to 0 bytes, which would bypass the size check entirely.
        const MAX_METADATA_SIZE: usize = 65536; // 64 KB
        let metadata_size = serde_json::to_string(&metadata)
            .map_err(|e| {
                AuditError::Validation(format!("Metadata serialization failed (fail-closed): {e}"))
            })?
            .len();
        if metadata_size > MAX_METADATA_SIZE {
            return Err(AuditError::Validation(format!(
                "Metadata too large: {metadata_size} bytes (max {MAX_METADATA_SIZE} bytes)"
            )));
        }

        // SECURITY (R16-AUDIT-2): Validate metadata nesting depth to prevent
        // stack overflow in recursive redaction functions. Action parameters are
        // already depth-checked (max 20), but metadata was not.
        const MAX_METADATA_DEPTH: usize = 20;
        if Self::json_depth(&metadata) > MAX_METADATA_DEPTH {
            return Err(AuditError::Validation(format!(
                "Metadata exceeds maximum nesting depth of {MAX_METADATA_DEPTH}"
            )));
        }

        // R230-AUD-2: Validate metadata keys for control/format characters.
        // Metadata keys appear in log output and SIEM queries — control chars
        // enable log injection, Unicode format chars enable confusion attacks.
        // SECURITY (R256-AUD-1): Recurse into nested objects so that deeply buried
        // keys with dangerous chars are also rejected. Bounded by MAX_METADATA_KEY_DEPTH
        // to prevent stack overflow from attacker-crafted deeply nested metadata.
        const MAX_METADATA_KEY_DEPTH: usize = 5;
        Self::validate_metadata_keys(&metadata, 0, MAX_METADATA_KEY_DEPTH)?;

        // Redact sensitive values based on configured redaction level
        let logged_action = match self.redaction_level {
            RedactionLevel::Off => action.clone(),
            RedactionLevel::KeysOnly => {
                let mut a = action.clone();
                a.parameters = redact_keys_only(&action.parameters);
                a
            }
            RedactionLevel::KeysAndPatterns => {
                let mut a = action.clone();
                a.parameters = if let Some(scanner) = &self.pii_scanner {
                    redact_keys_and_patterns_with_scanner(&action.parameters, scanner)
                } else {
                    redact_keys_and_patterns(&action.parameters)
                };
                // SECURITY (R33-SUP-2): Also scan target_paths, target_domains,
                // and resolved_ips for PII patterns. Paths like /home/john.doe/
                // or domains with personal subdomains could leak PII into audit logs.
                // SECURITY (R36-SUP-1): Use configured PiiScanner when available
                // instead of legacy PII_REGEXES (which only detects email/SSN/phone).
                // PiiScanner also detects credit cards, IPv4, JWT, and AWS keys.
                // SECURITY (R36-SUP-3): Also redact resolved_ips which may contain
                // internal network addresses or other PII-adjacent data.
                let pii_scanner_ref = &self.pii_scanner;
                let redact_strings = |strings: &[String]| -> Vec<String> {
                    strings
                        .iter()
                        .map(|s| {
                            if let Some(ref scanner) = pii_scanner_ref {
                                if scanner.has_pii(s) {
                                    REDACTED.to_string()
                                } else {
                                    s.clone()
                                }
                            } else if PII_REGEXES.iter().any(|re| re.is_match(s)) {
                                REDACTED.to_string()
                            } else {
                                s.clone()
                            }
                        })
                        .collect()
                };
                a.target_paths = redact_strings(&action.target_paths);
                a.target_domains = redact_strings(&action.target_domains);
                a.resolved_ips = redact_strings(&action.resolved_ips);
                a
            }
        };

        let mut logged_metadata = match self.redaction_level {
            RedactionLevel::Off => metadata,
            RedactionLevel::KeysOnly => redact_keys_only(&metadata),
            RedactionLevel::KeysAndPatterns => {
                if let Some(scanner) = &self.pii_scanner {
                    redact_keys_and_patterns_with_scanner(&metadata, scanner)
                } else {
                    redact_keys_and_patterns(&metadata)
                }
            }
        };

        // SECURITY (R37-SUP-1): Redact PII in verdict deny/approval reasons.
        // Deny reasons can contain user-controlled data (paths, domains, JWT claims)
        // that would be caught by PII scanning in action fields but were not being
        // redacted in the verdict. This closes that gap.
        let logged_verdict = match self.redaction_level {
            RedactionLevel::Off => verdict.clone(),
            RedactionLevel::KeysOnly => verdict.clone(),
            RedactionLevel::KeysAndPatterns => match verdict {
                Verdict::Deny { reason } => {
                    let redacted_reason = if let Some(ref scanner) = self.pii_scanner {
                        scanner.redact_string(reason)
                    } else {
                        let mut r = reason.clone();
                        for re in PII_REGEXES.iter() {
                            r = re.replace_all(&r, REDACTED).to_string();
                        }
                        r
                    };
                    Verdict::Deny {
                        reason: redacted_reason,
                    }
                }
                Verdict::RequireApproval { reason } => {
                    let redacted_reason = if let Some(ref scanner) = self.pii_scanner {
                        scanner.redact_string(reason)
                    } else {
                        let mut r = reason.clone();
                        for re in PII_REGEXES.iter() {
                            r = re.replace_all(&r, REDACTED).to_string();
                        }
                        r
                    };
                    Verdict::RequireApproval {
                        reason: redacted_reason,
                    }
                }
                other => other.clone(),
            },
        };

        let logged_acis_envelope = match self.redaction_level {
            RedactionLevel::Off | RedactionLevel::KeysOnly => acis_envelope,
            RedactionLevel::KeysAndPatterns => acis_envelope.map(|mut envelope| {
                envelope.reason = if let Some(ref scanner) = self.pii_scanner {
                    scanner.redact_string(&envelope.reason)
                } else {
                    let mut redacted = envelope.reason.clone();
                    for re in PII_REGEXES.iter() {
                        redacted = re.replace_all(&redacted, REDACTED).to_string();
                    }
                    redacted
                };
                envelope
            }),
        };

        // SECURITY (FIND-R46-005): Lock-holding duration tradeoff.
        //
        // All data preparation (validation, redaction, PII scanning) is performed
        // ABOVE this lock acquisition, minimizing the critical section to:
        //   1. maybe_rotate() — conditional, only when file exceeds max_file_size
        //   2. entry creation, hash computation, file write, and Merkle append
        //
        // The lock MUST be held during rotation to prevent concurrent writes from
        // racing and producing a corrupt hash chain. The rotation path involves I/O
        // (file rename, manifest write) that blocks the lock for the duration. This
        // is acceptable because rotation is infrequent (~1 per 100MB of entries).
        // The common path (no rotation) holds the lock only for hash computation
        // and a single append write.
        let mut chain_head = self.chain_head.lock().await;

        // Rotate if the current log exceeds max_file_size.
        // Done under the lock to prevent concurrent writes from racing.
        if self.maybe_rotate().await? {
            chain_head.last_hash = None; // New file = new hash chain
                                         // (last_timestamp deliberately survives — see ChainHead)
                                         // SECURITY (FIND-R52-AUDIT-002): Use SeqCst for sequence counter to prevent
                                         // reordering that could cause duplicate sequence numbers under concurrent access.
            self.entry_count.store(
                verified_audit_append::entry_count_after_rotation(),
                Ordering::SeqCst,
            ); // Reset per-file counter for new file
               // SECURITY (FIND-R111-007): global_sequence is intentionally NOT reset here.
               // It must increase monotonically across rotations to prevent duplicate
               // sequence numbers across log files.
        }

        // SECURITY (R33-001): Assign monotonic sequence number BEFORE creating entry.
        // This ensures the sequence is included in the hash, preventing collision
        // attacks where two entries might have identical timestamps under high load.
        // SECURITY (FIND-R52-AUDIT-002): Use SeqCst for sequence counter to ensure
        // globally consistent ordering and prevent duplicate sequence numbers.
        // SECURITY (FIND-R111-007): Use global_sequence (never reset on rotation)
        // rather than entry_count (reset to 0 on each rotation) to prevent duplicate
        // sequence numbers across rotated log files.
        let sequence =
            verified_audit_append::assigned_sequence(self.global_sequence.load(Ordering::SeqCst));

        // Phase 44: Extract tenant_id from metadata for per-tenant audit scoping.
        // The tenant_id is injected into metadata by build_evaluate_audit_metadata(),
        // so we extract it here to populate the dedicated AuditEntry field.
        //
        // SECURITY (R238-AUD-1): Validate tenant_id for dangerous characters and length.
        // Metadata KEYS are validated at line 350, but VALUES (including tenant_id) were
        // not. A malicious tenant_id could inject control/bidi chars into audit logs,
        // break multi-tenant queries, or corrupt JSONL exports.
        let tenant_id = match logged_metadata.get("tenant_id") {
            Some(serde_json::Value::String(s)) => {
                if s.len() > vellaveto_types::audit_store::MAX_TENANT_ID_LEN {
                    tracing::warn!(
                        "tenant_id exceeds max length ({} > {}), dropping",
                        s.len(),
                        vellaveto_types::audit_store::MAX_TENANT_ID_LEN
                    );
                    None
                } else if vellaveto_types::has_dangerous_chars(s) {
                    tracing::warn!("tenant_id contains dangerous characters, dropping");
                    None
                } else {
                    Some(s.clone())
                }
            }
            Some(_) => {
                tracing::warn!("tenant_id is not a string, dropping");
                None
            }
            None => None,
        };
        if tenant_id.is_none() {
            if let Some(obj) = logged_metadata.as_object_mut() {
                obj.remove("tenant_id");
            }
        }

        let mut entry = AuditEntry {
            id: Uuid::new_v4().to_string(),
            action: logged_action,
            verdict: logged_verdict,
            timestamp: Utc::now().to_rfc3339(),
            metadata: logged_metadata,
            sequence,
            entry_hash: None,
            prev_hash: chain_head.last_hash.clone(),
            commitment: None,
            tenant_id,
            acis_envelope: logged_acis_envelope,
        };

        // SECURITY: Enforce timestamp monotonicity at APPEND, not only at verify.
        //
        // verify_chain() has always rejected a chain whose timestamps regress
        // (R226-CROSS-1), but nothing stopped such an entry being written. A
        // clock that steps backwards — NTP correction, VM migration, or
        // tampering on a host that already has write access — therefore produced
        // entries that appended cleanly and permanently broke verification of
        // every later entry, discovered only when someone next verified.
        //
        // The entry is clamped rather than refused. Refusing would drop the
        // record, and since every audit call site logs and continues rather than
        // propagating, that drop would be invisible in the audit trail itself —
        // handing anyone who can move the clock backwards a way to suppress
        // audit entries. Clamping keeps the record, keeps the chain verifiable,
        // and turns the anomaly into evidence: the observed wall-clock reading
        // is preserved in metadata under `timestamp_regression`.
        //
        // Uses the verifier's own rule via timestamp_ordered_after, under the
        // same lock that links the hash chain, so a concurrent append cannot
        // slip past it.
        if !crate::verification::timestamp_ordered_after(
            &entry.timestamp,
            chain_head.last_timestamp.as_deref(),
        ) {
            let observed = entry.timestamp.clone();
            // Clamp to the previous entry's timestamp: the earliest value that
            // keeps the chain non-decreasing, so the clamp never overstates how
            // late the event was.
            let clamped = chain_head
                .last_timestamp
                .clone()
                .unwrap_or_else(|| observed.clone());

            tracing::error!(
                observed_timestamp = %observed,
                clamped_to = %clamped,
                "Audit timestamp regression: system clock moved backwards. Entry \
                 clamped to preserve chain verifiability; observed value recorded \
                 in metadata."
            );

            entry.timestamp = clamped.clone();
            if let Some(obj) = entry.metadata.as_object_mut() {
                obj.insert(
                    "timestamp_regression".to_string(),
                    serde_json::json!({
                        "observed": observed,
                        "clamped_to": clamped,
                    }),
                );
            }
        }

        // Compute hash
        let hash = Self::compute_entry_hash(&entry)?;
        entry.entry_hash = Some(hash.clone());

        let mut line_bytes = serde_json::to_vec(&entry)?;
        line_bytes.push(b'\n');

        // Fix #35: For Deny verdicts, require sync_data() so the entry survives
        // power loss. Other verdicts may remain flush-only.
        let durability = if matches!(verdict, Verdict::Deny { .. }) {
            trusted_audit_fs::Durability::SyncData
        } else {
            trusted_audit_fs::Durability::FlushOnly
        };
        trusted_audit_fs::append_bytes(&self.log_path, &line_bytes, durability, "audit log file")
            .await?;

        // Update chain head ONLY after successful file write.
        // If the write fails, the in-memory hash must not advance,
        // otherwise the chain diverges from what's on disk.
        chain_head.last_hash = Some(hash.clone());
        chain_head.last_timestamp = Some(entry.timestamp.clone());

        // Append leaf hash to Merkle tree (if enabled)
        if let Some(ref merkle) = self.merkle_tree {
            let leaf_bytes = hex::decode(&hash).map_err(|e| {
                AuditError::Validation(format!("Invalid entry hash hex for Merkle tree: {e}"))
            })?;
            // SECURITY (FIND-R140-002): Fail-closed on wrong-length hash.
            // Previously a short decode silently used a zero-padded array,
            // allowing a tampered hash to produce a false Merkle inclusion proof.
            if leaf_bytes.len() != 32 {
                return Err(AuditError::Validation(format!(
                    "Entry hash has wrong length: {} (expected 32)",
                    leaf_bytes.len()
                )));
            }
            let mut leaf_arr = [0u8; 32];
            leaf_arr.copy_from_slice(&leaf_bytes);
            let leaf = crate::merkle::hash_leaf(&leaf_arr);
            let mut tree = merkle
                .lock()
                .map_err(|e| AuditError::Validation(format!("Merkle tree lock poisoned: {e}")))?;
            tree.append(leaf)?;
        }

        // Increment in-memory entry count for rotation metadata (tracks entries in current file).
        // SECURITY (FIND-R52-AUDIT-002): Use SeqCst for sequence counter to ensure
        // the increment is globally visible and prevents reordering.
        // SECURITY (FIND-R186-005): Use fetch_update with saturating_add instead of
        // fetch_add to comply with project coding standard (Trap 9). While u64 overflow
        // is physically impossible at realistic logging rates, saturating arithmetic
        // is the project-wide convention for all counters.
        let _ = self
            .entry_count
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                Some(verified_audit_append::next_entry_count(v))
            });
        // SECURITY (FIND-R111-007): Also increment the global sequence counter that
        // is never reset on rotation, ensuring cross-rotation sequence uniqueness.
        let _ = self
            .global_sequence
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                Some(verified_audit_append::next_global_sequence(v))
            });

        // Phase 43: Dual-write to external sink (if configured).
        // The file write above is the source of truth. Sink failures are
        // non-fatal by default — the entry is already persisted to disk.
        if let Some(ref sink) = self.sink {
            if let Err(e) = sink.sink(&entry).await {
                if self.sink_failure_fatal {
                    return Err(AuditError::Validation(format!(
                        "Audit sink write failed (fatal mode): {e}"
                    )));
                }
                tracing::warn!(
                    error = %e,
                    entry_id = %entry.id,
                    "Audit sink write failed (non-fatal), entry persisted to file only"
                );
            }
        }

        Ok(())
    }

    /// Validate an action before logging.
    ///
    /// Rejects actions with control characters in tool/function names,
    /// and limits JSON nesting depth in parameters.
    ///
    /// SECURITY (FIND-074): Expanded from newline/null checks to reject ALL
    /// control characters (U+0000–U+001F, U+007F, U+0080–U+009F). This
    /// prevents log injection via tabs, backspaces, escape sequences, etc.
    fn validate_action(&self, action: &Action) -> Result<(), AuditError> {
        // SECURITY (FIND-R122-007): Check for both control characters and Unicode
        // format characters (zero-width, bidi overrides) in tool/function names.
        if action
            .tool
            .chars()
            .any(|c| c.is_control() || vellaveto_types::is_unicode_format_char(c))
        {
            return Err(AuditError::Validation(
                "Tool name contains control or format characters".to_string(),
            ));
        }
        if action
            .function
            .chars()
            .any(|c| c.is_control() || vellaveto_types::is_unicode_format_char(c))
        {
            return Err(AuditError::Validation(
                "Function name contains control or format characters".to_string(),
            ));
        }

        // SECURITY (R253-AUD-6): Validate target array bounds before redaction.
        // Without this, oversized target arrays bypass Action::validate() if the
        // caller constructs an Action directly and passes it to log_entry().
        let total_targets = action
            .target_paths
            .len()
            .saturating_add(action.target_domains.len())
            .saturating_add(action.resolved_ips.len());
        if total_targets > 256 {
            return Err(AuditError::Validation(format!(
                "Too many targets: {total_targets} (max 256)"
            )));
        }
        for path in &action.target_paths {
            if path.len() > 4096 {
                return Err(AuditError::Validation(format!(
                    "Target path too long: {} bytes (max 4096)",
                    path.len()
                )));
            }
        }
        for domain in &action.target_domains {
            if domain.len() > 4096 {
                return Err(AuditError::Validation(format!(
                    "Target domain too long: {} bytes (max 4096)",
                    domain.len()
                )));
            }
        }

        // Check JSON nesting depth
        if Self::json_depth(&action.parameters) > 20 {
            return Err(AuditError::Validation(
                "Parameters exceed maximum nesting depth of 20".to_string(),
            ));
        }

        // Check serialized size
        let size = action.parameters.to_string().len();
        if size > 1_000_000 {
            return Err(AuditError::Validation(format!(
                "Parameters too large: {size} bytes (max 1000000)"
            )));
        }

        Ok(())
    }

    /// SECURITY (R256-AUD-1): Recursively validate that no metadata key at any
    /// nesting level contains control or Unicode format characters. Uses an
    /// iterative stack to avoid stack overflow on deep payloads.
    fn validate_metadata_keys(
        value: &serde_json::Value,
        current_depth: usize,
        max_depth: usize,
    ) -> Result<(), AuditError> {
        if current_depth > max_depth {
            // Depth already validated by MAX_METADATA_DEPTH check above;
            // this guard prevents unbounded recursion in this helper.
            return Ok(());
        }
        if let Some(obj) = value.as_object() {
            for (key, val) in obj {
                if vellaveto_types::has_dangerous_chars(key) {
                    return Err(AuditError::Validation(format!(
                        "Metadata key contains control or format characters at depth {} (key starts with: '{}')",
                        current_depth,
                        key.chars().take(32).collect::<String>()
                    )));
                }
                // Recurse into nested objects and arrays
                Self::validate_metadata_keys(val, current_depth + 1, max_depth)?;
            }
        } else if let Some(arr) = value.as_array() {
            for item in arr {
                Self::validate_metadata_keys(item, current_depth + 1, max_depth)?;
            }
        }
        Ok(())
    }

    pub(crate) fn json_depth(value: &serde_json::Value) -> usize {
        let mut max_depth: usize = 0;
        let mut stack: Vec<(&serde_json::Value, usize)> = vec![(value, 0)];
        while let Some((val, depth)) = stack.pop() {
            if depth > max_depth {
                max_depth = depth;
            }
            if max_depth > 128 {
                return max_depth;
            }
            match val {
                serde_json::Value::Array(arr) => {
                    for item in arr {
                        stack.push((item, depth + 1));
                    }
                }
                serde_json::Value::Object(obj) => {
                    for item in obj.values() {
                        stack.push((item, depth + 1));
                    }
                }
                _ => {}
            }
        }
        max_depth
    }
}
