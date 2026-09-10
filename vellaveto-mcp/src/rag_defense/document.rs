// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Document verification and trust scoring for RAG defense.
//!
//! Implements document provenance tracking and trust scoring to detect
//! malicious document injection into RAG knowledge bases.

use std::collections::HashMap;
use std::sync::RwLock;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use vellaveto_config::DocumentVerificationConfig;

use super::error::RagDefenseError;

/// Metadata for a document in the RAG knowledge base.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentMetadata {
    /// Unique document identifier.
    pub id: String,

    /// SHA-256 hash of the document content.
    pub content_hash: String,

    /// Source of the document (URL, file path, etc.).
    pub source: String,

    /// When the document was first added.
    pub created_at: DateTime<Utc>,

    /// When the document was last modified.
    pub modified_at: DateTime<Utc>,

    /// Whether an admin has approved this document.
    pub admin_approved: bool,

    /// Optional Ed25519 signature of the content hash.
    pub signature: Option<String>,

    /// Chain of previous content hashes (for version tracking).
    pub version_chain: Vec<String>,
}

impl DocumentMetadata {
    /// Creates new document metadata.
    pub fn new(
        id: impl Into<String>,
        content_hash: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: id.into(),
            content_hash: content_hash.into(),
            source: source.into(),
            created_at: now,
            modified_at: now,
            admin_approved: false,
            signature: None,
            version_chain: Vec::new(),
        }
    }

    /// Creates metadata with admin approval.
    pub fn with_admin_approval(mut self) -> Self {
        self.admin_approved = true;
        self
    }

    /// Adds a signature to the metadata.
    pub fn with_signature(mut self, signature: impl Into<String>) -> Self {
        self.signature = Some(signature.into());
        self
    }

    /// Returns the age of the document in hours.
    pub fn age_hours(&self) -> u64 {
        let duration = Utc::now().signed_duration_since(self.created_at);
        duration.num_hours().max(0) as u64
    }

    /// Returns the number of mutations (version changes).
    pub fn mutation_count(&self) -> usize {
        self.version_chain.len()
    }
}

/// Factors contributing to document trust score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrustFactor {
    /// Age bonus: +0.1 per week, capped at 0.3.
    AgeBonus(f64),
    /// Admin approval: +0.2.
    AdminApproval(f64),
    /// Verified signature: +0.2.
    SignatureVerified(f64),
    /// Version stability: +0.1 if no recent changes.
    VersionStability(f64),
    /// Mutation penalty: -0.3 per schema change.
    MutationPenalty(f64),
}

impl TrustFactor {
    /// Returns the contribution of this factor to the trust score.
    pub fn value(&self) -> f64 {
        match self {
            TrustFactor::AgeBonus(v) => *v,
            TrustFactor::AdminApproval(v) => *v,
            TrustFactor::SignatureVerified(v) => *v,
            TrustFactor::VersionStability(v) => *v,
            TrustFactor::MutationPenalty(v) => *v,
        }
    }

    /// Returns a description of this factor.
    pub fn description(&self) -> &'static str {
        match self {
            TrustFactor::AgeBonus(_) => "Document age bonus",
            TrustFactor::AdminApproval(_) => "Admin approval",
            TrustFactor::SignatureVerified(_) => "Signature verified",
            TrustFactor::VersionStability(_) => "Version stability",
            TrustFactor::MutationPenalty(_) => "Mutation penalty",
        }
    }
}

/// Trust score for a document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentTrustScore {
    /// Computed trust score (0.0-1.0).
    pub score: f64,
    /// Factors contributing to the score.
    pub factors: Vec<TrustFactor>,
    /// When the score was computed.
    pub computed_at: DateTime<Utc>,
}

impl DocumentTrustScore {
    /// Creates a new trust score.
    pub fn new(score: f64, factors: Vec<TrustFactor>) -> Self {
        Self {
            score: score.clamp(0.0, 1.0),
            factors,
            computed_at: Utc::now(),
        }
    }
}

/// SECURITY (FIND-R69-004): Maximum tracked documents to prevent OOM.
const MAX_TRACKED_DOCUMENTS: usize = 100_000;

/// SECURITY (FIND-R69-004): Maximum tracked sessions for document counts.
const MAX_DOC_SESSIONS: usize = 50_000;

/// SECURITY (FIND-R106-004): Maximum trust cache entries to prevent OOM.
const MAX_TRUST_CACHE_SIZE: usize = 100_000;

/// Verifies documents and computes trust scores.
pub struct DocumentVerifier {
    config: DocumentVerificationConfig,
    documents: RwLock<HashMap<String, DocumentMetadata>>,
    trust_cache: RwLock<HashMap<String, DocumentTrustScore>>,
    session_doc_counts: RwLock<HashMap<String, usize>>,
}

impl DocumentVerifier {
    /// Creates a new document verifier.
    pub fn new(config: DocumentVerificationConfig) -> Self {
        Self {
            config,
            documents: RwLock::new(HashMap::new()),
            trust_cache: RwLock::new(HashMap::new()),
            session_doc_counts: RwLock::new(HashMap::new()),
        }
    }

    /// Creates a disabled verifier that allows all documents.
    pub fn disabled() -> Self {
        Self::new(DocumentVerificationConfig {
            enabled: false,
            ..Default::default()
        })
    }

    /// Returns whether verification is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Verifies a document and returns its trust score.
    pub fn verify(&self, doc: &DocumentMetadata) -> Result<DocumentTrustScore, RagDefenseError> {
        if !self.config.enabled {
            return Ok(DocumentTrustScore::new(1.0, vec![]));
        }

        // Check document age
        let age_hours = doc.age_hours();
        if age_hours > self.config.max_doc_age_hours {
            return Err(RagDefenseError::DocumentTooOld {
                age_hours,
                max_hours: self.config.max_doc_age_hours,
            });
        }

        // Compute trust score
        let score = self.compute_trust_score(doc);

        // Check against threshold
        if score.score < self.config.require_trust_score {
            return Err(RagDefenseError::LowTrustScore {
                score: score.score,
                threshold: self.config.require_trust_score,
            });
        }

        // Cache the score
        // SECURITY (FIND-R106-004): Bound trust cache to prevent OOM from
        // repeated verify() calls with distinct doc IDs.
        if let Ok(mut cache) = self.trust_cache.write() {
            if !cache.contains_key(&doc.id) && cache.len() >= MAX_TRUST_CACHE_SIZE {
                tracing::warn!(
                    max = MAX_TRUST_CACHE_SIZE,
                    "Trust cache at capacity — skipping cache insert"
                );
            } else {
                cache.insert(doc.id.clone(), score.clone());
            }
        }

        Ok(score)
    }

    /// Computes the trust score for a document.
    pub fn compute_trust_score(&self, doc: &DocumentMetadata) -> DocumentTrustScore {
        let mut factors = Vec::new();
        let base_score = 0.5;
        let mut score = base_score;

        // Age bonus: +0.1 per week, capped at 0.3
        let age_days = doc.age_hours() / 24;
        let age_weeks = age_days / 7;
        let age_bonus = (age_weeks as f64 * 0.1).min(0.3);
        if age_bonus > 0.0 {
            factors.push(TrustFactor::AgeBonus(age_bonus));
            score += age_bonus;
        }

        // Admin approval: +0.2
        if doc.admin_approved {
            factors.push(TrustFactor::AdminApproval(0.2));
            score += 0.2;
        }

        // SECURITY (R245-DLP-2): Only award trust bonus for non-empty signatures.
        // Previously is_some() gave +0.2 for any signature including garbage.
        // Full Ed25519 verification requires a public key registry (future work),
        // but rejecting empty/trivially-short signatures is defense-in-depth.
        if let Some(ref sig) = doc.signature {
            if sig.len() >= 64 {
                // Ed25519 signatures are 64 bytes; only award for plausible length
                factors.push(TrustFactor::SignatureVerified(0.2));
                score += 0.2;
            }
        }

        // Version stability: +0.1 if no recent changes
        let hours_since_modified = {
            let duration = Utc::now().signed_duration_since(doc.modified_at);
            duration.num_hours().max(0) as u64
        };
        if hours_since_modified > 168 {
            // More than a week since modification
            factors.push(TrustFactor::VersionStability(0.1));
            score += 0.1;
        }

        // Mutation penalty: -0.3 per content mutation
        let mutation_count = doc.mutation_count();
        if mutation_count > 0 {
            let penalty = (mutation_count as f64 * 0.3).min(0.6);
            factors.push(TrustFactor::MutationPenalty(-penalty));
            score -= penalty;
        }

        DocumentTrustScore::new(score, factors)
    }

    /// Verifies that content matches the expected hash.
    pub fn verify_content_hash(
        &self,
        doc_id: &str,
        content: &[u8],
    ) -> Result<bool, RagDefenseError> {
        if !self.config.require_content_hash {
            return Ok(true);
        }

        let docs = self.documents.read().map_err(|_| {
            RagDefenseError::Internal("Failed to acquire document read lock".to_string())
        })?;

        let doc = docs.get(doc_id).ok_or_else(|| {
            RagDefenseError::DocumentVerification(format!("Document not found: {}", doc_id))
        })?;

        let actual_hash = compute_content_hash(content);

        if actual_hash != doc.content_hash {
            return Err(RagDefenseError::ContentHashMismatch {
                expected: doc.content_hash.clone(),
                actual: actual_hash,
            });
        }

        Ok(true)
    }

    /// Registers a document for tracking.
    pub fn register_document(&self, metadata: DocumentMetadata) -> Result<(), RagDefenseError> {
        if !self.config.enabled {
            return Ok(());
        }

        // Check if document should be blocked
        if self.config.block_unverified && !metadata.admin_approved && metadata.signature.is_none()
        {
            return Err(RagDefenseError::UnverifiedDocument {
                doc_id: metadata.id.clone(),
            });
        }

        let mut docs = self.documents.write().map_err(|_| {
            RagDefenseError::Internal("Failed to acquire document write lock".to_string())
        })?;

        // SECURITY (FIND-R69-004): Reject new documents when at capacity.
        if !docs.contains_key(&metadata.id) && docs.len() >= MAX_TRACKED_DOCUMENTS {
            tracing::warn!(max = MAX_TRACKED_DOCUMENTS, "Document registry at capacity");
            return Err(RagDefenseError::Internal(
                "Document registry at capacity".to_string(),
            ));
        }

        docs.insert(metadata.id.clone(), metadata);

        Ok(())
    }

    /// Checks and updates session document count.
    pub fn check_session_limit(&self, session_id: &str) -> Result<(), RagDefenseError> {
        if !self.config.enabled {
            return Ok(());
        }

        let mut counts = self.session_doc_counts.write().map_err(|_| {
            RagDefenseError::Internal("Failed to acquire session count lock".to_string())
        })?;

        // SECURITY (FIND-R69-004): Cap session tracking entries.
        if !counts.contains_key(session_id) && counts.len() >= MAX_DOC_SESSIONS {
            tracing::warn!(
                max = MAX_DOC_SESSIONS,
                "Session document tracker at capacity"
            );
            return Err(RagDefenseError::Internal(
                "Session document tracker at capacity".to_string(),
            ));
        }

        let count = counts.entry(session_id.to_string()).or_insert(0);
        // SECURITY (CA-003): Use saturating_add to prevent u64 overflow which could
        // reset the counter and bypass document count limits.
        *count = count.saturating_add(1);

        if *count > self.config.max_docs_per_session {
            return Err(RagDefenseError::SessionDocumentLimit {
                count: *count,
                max: self.config.max_docs_per_session,
            });
        }

        Ok(())
    }

    /// Gets the cached trust score for a document.
    pub fn get_cached_score(&self, doc_id: &str) -> Option<DocumentTrustScore> {
        // SECURITY (IMP-R222-004): Log lock poisoning instead of silently returning None.
        match self.trust_cache.read() {
            Ok(cache) => cache.get(doc_id).cloned(),
            Err(_) => {
                tracing::error!("DocumentVerifier trust_cache lock poisoned in get_cached_score");
                None
            }
        }
    }

    /// Returns the number of registered documents.
    pub fn document_count(&self) -> usize {
        // SECURITY (IMP-R222-004): Log lock poisoning instead of silently returning 0.
        self.documents.read().map(|d| d.len()).unwrap_or_else(|_| {
            tracing::error!("DocumentVerifier documents lock poisoned in document_count");
            0
        })
    }

    /// Clears session document counts.
    pub fn reset_session(&self, session_id: &str) {
        // SECURITY (IMP-R222-004): Log lock poisoning instead of silently skipping reset.
        match self.session_doc_counts.write() {
            Ok(mut counts) => {
                counts.remove(session_id);
            }
            Err(_) => {
                tracing::error!(
                    "DocumentVerifier session_doc_counts lock poisoned in reset_session"
                );
            }
        }
    }
}

/// Computes SHA-256 hash of content.
pub fn compute_content_hash(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_document_metadata_creation() {
        let doc = DocumentMetadata::new("doc1", "abc123", "https://example.com/doc.pdf");
        assert_eq!(doc.id, "doc1");
        assert_eq!(doc.content_hash, "abc123");
        assert!(!doc.admin_approved);
    }

    #[test]
    fn test_document_with_admin_approval() {
        let doc = DocumentMetadata::new("doc1", "abc123", "source").with_admin_approval();
        assert!(doc.admin_approved);
    }

    #[test]
    fn test_trust_score_base() {
        let config = DocumentVerificationConfig::default();
        let verifier = DocumentVerifier::new(config);

        let doc = DocumentMetadata::new("doc1", "abc123", "source");
        let score = verifier.compute_trust_score(&doc);

        // Base score is 0.5, new doc has no bonuses
        assert!(score.score >= 0.5);
        assert!(score.score <= 0.6);
    }

    #[test]
    fn test_trust_score_with_approval() {
        let config = DocumentVerificationConfig::default();
        let verifier = DocumentVerifier::new(config);

        let doc = DocumentMetadata::new("doc1", "abc123", "source").with_admin_approval();
        let score = verifier.compute_trust_score(&doc);

        // Should have admin approval bonus
        assert!(score.score >= 0.7);
        assert!(score
            .factors
            .iter()
            .any(|f| matches!(f, TrustFactor::AdminApproval(_))));
    }

    #[test]
    fn test_trust_score_with_signature() {
        let config = DocumentVerificationConfig::default();
        let verifier = DocumentVerifier::new(config);

        // SECURITY (R245-DLP-2): the bonus is only awarded for signatures of
        // plausible Ed25519 length (>= 64). A shorter placeholder gets no
        // bonus — see test_trust_score_short_signature_gets_no_bonus.
        let signature = "e".repeat(64);
        let doc = DocumentMetadata::new("doc1", "abc123", "source").with_signature(signature);
        let score = verifier.compute_trust_score(&doc);

        assert!(score.score >= 0.7);
        assert!(score
            .factors
            .iter()
            .any(|f| matches!(f, TrustFactor::SignatureVerified(_))));
    }

    #[test]
    fn test_trust_score_short_signature_gets_no_bonus() {
        let config = DocumentVerificationConfig::default();
        let verifier = DocumentVerifier::new(config);

        let doc = DocumentMetadata::new("doc1", "abc123", "source").with_signature("short");
        let score = verifier.compute_trust_score(&doc);

        assert!(!score
            .factors
            .iter()
            .any(|f| matches!(f, TrustFactor::SignatureVerified(_))));
    }

    #[test]
    fn test_trust_score_mutation_penalty() {
        let config = DocumentVerificationConfig::default();
        let verifier = DocumentVerifier::new(config);

        let mut doc = DocumentMetadata::new("doc1", "abc123", "source");
        doc.version_chain = vec!["old_hash1".to_string(), "old_hash2".to_string()];

        let score = verifier.compute_trust_score(&doc);

        assert!(score.score < 0.5); // Below base due to mutations
        assert!(score
            .factors
            .iter()
            .any(|f| matches!(f, TrustFactor::MutationPenalty(_))));
    }

    #[test]
    fn test_verify_low_trust_score() {
        let config = DocumentVerificationConfig {
            enabled: true,
            require_trust_score: 0.9, // Very high threshold
            ..Default::default()
        };
        let verifier = DocumentVerifier::new(config);

        let doc = DocumentMetadata::new("doc1", "abc123", "source");
        let result = verifier.verify(&doc);

        assert!(matches!(result, Err(RagDefenseError::LowTrustScore { .. })));
    }

    #[test]
    fn test_verify_disabled() {
        let verifier = DocumentVerifier::disabled();

        let doc = DocumentMetadata::new("doc1", "abc123", "source");
        let result = verifier.verify(&doc);

        assert!(result.is_ok());
        assert_eq!(result.unwrap().score, 1.0);
    }

    #[test]
    fn test_content_hash() {
        let content = b"Hello, World!";
        let hash = compute_content_hash(content);

        assert_eq!(hash.len(), 64); // SHA-256 produces 64 hex chars

        // Same content should produce same hash
        let hash2 = compute_content_hash(content);
        assert_eq!(hash, hash2);

        // Different content should produce different hash
        let hash3 = compute_content_hash(b"Different content");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_session_document_limit() {
        let config = DocumentVerificationConfig {
            enabled: true,
            max_docs_per_session: 2,
            ..Default::default()
        };
        let verifier = DocumentVerifier::new(config);

        // First two should succeed
        assert!(verifier.check_session_limit("session1").is_ok());
        assert!(verifier.check_session_limit("session1").is_ok());

        // Third should fail
        let result = verifier.check_session_limit("session1");
        assert!(matches!(
            result,
            Err(RagDefenseError::SessionDocumentLimit { .. })
        ));

        // Different session should work
        assert!(verifier.check_session_limit("session2").is_ok());
    }

    #[test]
    fn test_register_unverified_blocked() {
        let config = DocumentVerificationConfig {
            enabled: true,
            block_unverified: true,
            ..Default::default()
        };
        let verifier = DocumentVerifier::new(config);

        let doc = DocumentMetadata::new("doc1", "abc123", "source");
        let result = verifier.register_document(doc);

        assert!(matches!(
            result,
            Err(RagDefenseError::UnverifiedDocument { .. })
        ));
    }

    #[test]
    fn test_register_approved_allowed() {
        let config = DocumentVerificationConfig {
            enabled: true,
            block_unverified: true,
            ..Default::default()
        };
        let verifier = DocumentVerifier::new(config);

        let doc = DocumentMetadata::new("doc1", "abc123", "source").with_admin_approval();
        let result = verifier.register_document(doc);

        assert!(result.is_ok());
        assert_eq!(verifier.document_count(), 1);
    }

    #[test]
    fn test_trust_cache_bounded() {
        // SECURITY (FIND-R106-004): Verify trust_cache doesn't grow beyond MAX_TRUST_CACHE_SIZE.
        let config = DocumentVerificationConfig {
            enabled: true,
            require_trust_score: 0.0, // accept all
            ..Default::default()
        };
        let verifier = DocumentVerifier::new(config);

        // Fill cache to capacity
        for i in 0..100 {
            let doc = DocumentMetadata::new(format!("doc-{}", i), "hash", "source");
            let _ = verifier.verify(&doc);
        }

        // Verify cache is populated
        let cache = verifier.trust_cache.read().unwrap();
        assert!(cache.len() <= MAX_TRUST_CACHE_SIZE);
        assert_eq!(cache.len(), 100);
    }
}
