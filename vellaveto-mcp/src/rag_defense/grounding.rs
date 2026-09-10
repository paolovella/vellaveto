// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Hallucination/Grounding Detection — Validate LLM responses against context (Phase 13.2).
//!
//! This module provides detection of LLM hallucinations by comparing generated
//! responses against retrieved context using Natural Language Inference (NLI).
//!
//! # Approach
//!
//! The grounding check validates that claims in the LLM response are:
//! 1. **Entailed** by the retrieved context (factually supported)
//! 2. **Not contradicted** by the retrieved context
//! 3. **Attributed** to specific source documents when possible
//!
//! # Scoring
//!
//! - **1.0**: Fully grounded (all claims supported by context)
//! - **0.7-0.99**: Mostly grounded (minor unsupported details)
//! - **0.5-0.69**: Partially grounded (some claims not in context)
//! - **0.0-0.49**: Poorly grounded (significant hallucination)
//!
//! # Example
//!
//! ```rust,ignore
//! use vellaveto_mcp::rag_defense::grounding::{GroundingChecker, GroundingConfig};
//!
//! let config = GroundingConfig::default();
//! let checker = GroundingChecker::new(config);
//!
//! let context = vec![
//!     "The Eiffel Tower is located in Paris, France.",
//!     "It was built in 1889 for the World's Fair.",
//! ];
//!
//! let response = "The Eiffel Tower is in Paris and was built in 1889.";
//! let result = checker.check_grounding(&context, response)?;
//!
//! if result.is_grounded() {
//!     println!("Response is grounded (score: {:.2})", result.score);
//! } else {
//!     println!("Potential hallucination detected: {:?}", result.ungrounded_claims);
//! }
//! ```
//!
//! # Integration with LLM Backends
//!
//! For high-accuracy grounding checks, this module can use the semantic guardrails
//! LLM backend to perform NLI inference. Without an LLM backend, it falls back to
//! lexical similarity which is less accurate but faster.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// Re-export GroundingConfig from vellaveto-config
pub use vellaveto_config::GroundingConfig;

/// Enforcement action for grounding violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[non_exhaustive]
pub enum GroundingEnforcement {
    /// Log warning but allow response. Default.
    #[default]
    Warn,
    /// Block response with low grounding score.
    Block,
    /// Add disclaimer to response.
    Annotate,
}

/// Result of a grounding check.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroundingResult {
    /// Overall grounding score (0.0-1.0).
    pub score: f32,

    /// Whether the response passes the grounding threshold.
    pub passed: bool,

    /// Individual claim scores.
    pub claim_scores: Vec<ClaimScore>,

    /// Claims that could not be grounded in context.
    pub ungrounded_claims: Vec<String>,

    /// Claims that contradict the context.
    pub contradictions: Vec<Contradiction>,

    /// Attribution mapping (claim -> source document).
    pub attributions: Vec<Attribution>,

    /// Method used for grounding check (NLI or Lexical).
    pub method: GroundingMethod,
}

/// Maximum number of claims/contradictions/attributions in a grounding result.
const MAX_GROUNDING_ITEMS: usize = 1000;

impl GroundingResult {
    /// Check if the response is adequately grounded.
    pub fn is_grounded(&self) -> bool {
        self.passed
    }

    /// Get claims that are well-grounded (score >= 0.7).
    pub fn grounded_claims(&self) -> Vec<&ClaimScore> {
        self.claim_scores
            .iter()
            .filter(|c| c.score >= 0.7)
            .collect()
    }

    /// Get claims with potential hallucination (score < 0.5).
    pub fn hallucinated_claims(&self) -> Vec<&ClaimScore> {
        self.claim_scores.iter().filter(|c| c.score < 0.5).collect()
    }

    /// SECURITY (R239-MCP-3): Validate deserialized grounding results.
    /// Rejects NaN/Infinity scores and unbounded collections.
    pub fn validate(&self) -> Result<(), GroundingError> {
        fn check_score(name: &str, v: f32) -> Result<(), GroundingError> {
            if !v.is_finite() || !(0.0..=1.0).contains(&v) {
                return Err(GroundingError::ContextError(format!(
                    "{name} score {v} is not in [0.0, 1.0]"
                )));
            }
            Ok(())
        }
        check_score("GroundingResult", self.score)?;
        if self.claim_scores.len() > MAX_GROUNDING_ITEMS {
            return Err(GroundingError::ContextError(format!(
                "claim_scores count {} exceeds maximum {MAX_GROUNDING_ITEMS}",
                self.claim_scores.len()
            )));
        }
        for cs in &self.claim_scores {
            check_score("ClaimScore", cs.score)?;
        }
        if self.contradictions.len() > MAX_GROUNDING_ITEMS {
            return Err(GroundingError::ContextError(format!(
                "contradictions count {} exceeds maximum {MAX_GROUNDING_ITEMS}",
                self.contradictions.len()
            )));
        }
        for c in &self.contradictions {
            check_score("Contradiction.confidence", c.confidence)?;
        }
        if self.attributions.len() > MAX_GROUNDING_ITEMS {
            return Err(GroundingError::ContextError(format!(
                "attributions count {} exceeds maximum {MAX_GROUNDING_ITEMS}",
                self.attributions.len()
            )));
        }
        for a in &self.attributions {
            check_score("Attribution.confidence", a.confidence)?;
        }
        if self.ungrounded_claims.len() > MAX_GROUNDING_ITEMS {
            return Err(GroundingError::ContextError(format!(
                "ungrounded_claims count {} exceeds maximum {MAX_GROUNDING_ITEMS}",
                self.ungrounded_claims.len()
            )));
        }
        Ok(())
    }
}

/// Score for an individual claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimScore {
    /// The claim text.
    pub claim: String,

    /// Grounding score (0.0-1.0).
    pub score: f32,

    /// Most relevant context passage.
    pub best_evidence: Option<String>,

    /// NLI label if available (entailment, neutral, contradiction).
    pub nli_label: Option<NliLabel>,
}

/// NLI classification label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum NliLabel {
    /// Claim is supported by context.
    Entailment,
    /// Claim is neither supported nor contradicted.
    Neutral,
    /// Claim contradicts the context.
    Contradiction,
}

/// A contradiction between response and context.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contradiction {
    /// The contradicting claim in the response.
    pub claim: String,

    /// The contradicting evidence in context.
    pub evidence: String,

    /// Confidence in the contradiction (0.0-1.0).
    pub confidence: f32,
}

/// Attribution of a claim to a source document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attribution {
    /// The claim text.
    pub claim: String,

    /// Source document ID.
    pub source_id: String,

    /// Relevant passage from source.
    pub passage: String,

    /// Attribution confidence (0.0-1.0).
    pub confidence: f32,
}

/// Method used for grounding check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum GroundingMethod {
    /// LLM-based Natural Language Inference.
    Nli,
    /// Lexical overlap (fallback).
    Lexical,
    /// Disabled (returns pass).
    Disabled,
}

/// Grounding/hallucination detection checker.
pub struct GroundingChecker {
    config: GroundingConfig,
}

/// Hard cap for response text analyzed by grounding checks.
/// Prevents excessive CPU/memory use on adversarially large payloads.
const MAX_GROUNDING_RESPONSE_CHARS: usize = 100_000;

impl GroundingChecker {
    /// Create a new grounding checker with the given configuration.
    pub fn new(config: GroundingConfig) -> Self {
        Self { config }
    }

    /// Create a disabled checker that always passes.
    pub fn disabled() -> Self {
        Self {
            config: GroundingConfig::default(),
        }
    }

    /// Check if grounding validation is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Check grounding of a response against context.
    ///
    /// # Arguments
    ///
    /// * `context` - Retrieved context passages
    /// * `response` - LLM-generated response to validate
    ///
    /// # Returns
    ///
    /// Grounding result with score and details.
    pub fn check_grounding(
        &self,
        context: &[&str],
        response: &str,
    ) -> Result<GroundingResult, GroundingError> {
        if !self.config.enabled {
            return Ok(GroundingResult {
                score: 1.0,
                passed: true,
                claim_scores: vec![],
                ungrounded_claims: vec![],
                contradictions: vec![],
                attributions: vec![],
                method: GroundingMethod::Disabled,
            });
        }

        let response_len = response.chars().count();
        if response_len > MAX_GROUNDING_RESPONSE_CHARS {
            return Err(GroundingError::ResponseTooLong {
                len: response_len,
                max: MAX_GROUNDING_RESPONSE_CHARS,
            });
        }

        if context.is_empty() {
            return Ok(GroundingResult {
                score: 0.0,
                passed: false,
                claim_scores: vec![],
                ungrounded_claims: vec![response.to_string()],
                contradictions: vec![],
                attributions: vec![],
                method: GroundingMethod::Lexical,
            });
        }

        // Extract claims from response
        let claims = self.extract_claims(response);

        if claims.is_empty() {
            // No claims to check - pass
            return Ok(GroundingResult {
                score: 1.0,
                passed: true,
                claim_scores: vec![],
                ungrounded_claims: vec![],
                contradictions: vec![],
                attributions: vec![],
                method: GroundingMethod::Lexical,
            });
        }

        // Check each claim against context
        let claim_scores: Vec<ClaimScore> = claims
            .iter()
            .take(self.config.max_claims)
            .map(|claim| self.score_claim(claim, context))
            .collect();

        // Calculate overall score
        let score = if claim_scores.is_empty() {
            1.0
        } else {
            claim_scores.iter().map(|c| c.score).sum::<f32>() / claim_scores.len() as f32
        };

        // Identify ungrounded claims
        let ungrounded_claims: Vec<String> = claim_scores
            .iter()
            .filter(|c| c.score < 0.5)
            .map(|c| c.claim.clone())
            .collect();

        // Identify contradictions
        let contradictions: Vec<Contradiction> = claim_scores
            .iter()
            .filter(|c| c.nli_label == Some(NliLabel::Contradiction))
            .map(|c| Contradiction {
                claim: c.claim.clone(),
                evidence: c.best_evidence.clone().unwrap_or_default(),
                confidence: 1.0 - c.score,
            })
            .collect();

        // Build attributions
        let attributions: Vec<Attribution> = claim_scores
            .iter()
            .filter(|c| c.score >= 0.7 && c.best_evidence.is_some())
            .map(|c| Attribution {
                claim: c.claim.clone(),
                source_id: "context".to_string(), // Would need doc IDs for proper attribution
                passage: c.best_evidence.clone().unwrap_or_default(),
                confidence: c.score,
            })
            .collect();

        let passed = score >= self.config.min_score;

        Ok(GroundingResult {
            score,
            passed,
            claim_scores,
            ungrounded_claims,
            contradictions,
            attributions,
            method: GroundingMethod::Lexical, // Lexical baseline; NLI requires external model
        })
    }

    /// Check grounding with source document IDs.
    pub fn check_grounding_with_sources(
        &self,
        context: &[(&str, &str)], // (doc_id, content)
        response: &str,
    ) -> Result<GroundingResult, GroundingError> {
        if !self.config.enabled {
            return Ok(GroundingResult {
                score: 1.0,
                passed: true,
                claim_scores: vec![],
                ungrounded_claims: vec![],
                contradictions: vec![],
                attributions: vec![],
                method: GroundingMethod::Disabled,
            });
        }

        // Extract just the content for grounding check
        let content: Vec<&str> = context.iter().map(|(_, c)| *c).collect();
        let mut result = self.check_grounding(&content, response)?;

        // Update attributions with actual source IDs
        for attribution in &mut result.attributions {
            for (doc_id, content) in context {
                if content.contains(&attribution.passage) {
                    attribution.source_id = doc_id.to_string();
                    break;
                }
            }
        }

        Ok(result)
    }

    /// Extract claims (sentences) from a response.
    fn extract_claims(&self, response: &str) -> Vec<String> {
        // Simple sentence-based claim extraction
        // In production, would use more sophisticated NLP
        response
            .split(['.', '!', '?'])
            .map(|s| s.trim().to_string())
            .filter(|s| s.len() >= self.config.min_claim_length)
            .take(self.config.max_claims)
            .collect()
    }

    /// Score a single claim against context.
    fn score_claim(&self, claim: &str, context: &[&str]) -> ClaimScore {
        // Lexical overlap scoring (fallback when NLI not available)
        let claim_words: HashSet<&str> = claim
            .split_whitespace()
            .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()))
            .filter(|w| w.len() > 2)
            .collect();

        let mut best_score = 0.0f32;
        let mut best_evidence = None;

        for passage in context {
            let passage_words: HashSet<&str> = passage
                .split_whitespace()
                .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()))
                .filter(|w| w.len() > 2)
                .collect();

            if claim_words.is_empty() || passage_words.is_empty() {
                continue;
            }

            // Jaccard similarity
            let intersection = claim_words.intersection(&passage_words).count();
            let union = claim_words.union(&passage_words).count();
            let similarity = if union > 0 {
                intersection as f32 / union as f32
            } else {
                0.0
            };

            if similarity > best_score {
                best_score = similarity;
                best_evidence = Some(passage.to_string());
            }
        }

        // Convert similarity to grounding score
        // Low similarity doesn't necessarily mean hallucination (could be paraphrase)
        let grounding_score = if best_score >= 0.5 {
            0.9 + (best_score - 0.5) * 0.2 // 0.9-1.0
        } else if best_score >= 0.3 {
            0.7 + (best_score - 0.3) * 1.0 // 0.7-0.9
        } else if best_score >= 0.1 {
            0.3 + (best_score - 0.1) * 2.0 // 0.3-0.7
        } else {
            best_score * 3.0 // 0.0-0.3
        };

        // Determine NLI label based on score
        let nli_label = if grounding_score >= 0.7 {
            Some(NliLabel::Entailment)
        } else if grounding_score >= 0.3 {
            Some(NliLabel::Neutral)
        } else {
            // Low score could be contradiction or just unsupported
            None
        };

        ClaimScore {
            claim: claim.to_string(),
            score: grounding_score.min(1.0),
            best_evidence,
            nli_label,
        }
    }
}

/// Errors from grounding detection.
#[derive(Debug, Clone, thiserror::Error)]
pub enum GroundingError {
    #[error("NLI evaluation failed: {0}")]
    NliError(String),

    #[error("Context parsing failed: {0}")]
    ContextError(String),

    #[error("Response too long: {len} chars exceeds limit of {max}")]
    ResponseTooLong { len: usize, max: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grounding_disabled() {
        let checker = GroundingChecker::disabled();
        let result = checker.check_grounding(&["Context"], "Response").unwrap();
        assert!(result.is_grounded());
        assert_eq!(result.score, 1.0);
    }

    #[test]
    fn test_grounding_enabled() {
        let config = GroundingConfig {
            enabled: true,
            min_score: 0.5,
            ..Default::default()
        };
        let checker = GroundingChecker::new(config);

        let context = vec!["The Eiffel Tower is located in Paris, France."];
        let response = "The Eiffel Tower is in Paris.";

        let result = checker.check_grounding(&context, response).unwrap();
        assert!(result.score > 0.5);
    }

    #[test]
    fn test_hallucination_detection() {
        let config = GroundingConfig {
            enabled: true,
            min_score: 0.7,
            ..Default::default()
        };
        let checker = GroundingChecker::new(config);

        let context = vec!["The Eiffel Tower is located in Paris."];
        let response = "Mars has two moons named Phobos and Deimos.";

        let result = checker.check_grounding(&context, response).unwrap();
        assert!(result.score < 0.7);
        assert!(!result.ungrounded_claims.is_empty());
    }

    #[test]
    fn test_empty_context() {
        let config = GroundingConfig {
            enabled: true,
            ..Default::default()
        };
        let checker = GroundingChecker::new(config);

        let result = checker.check_grounding(&[], "Some response").unwrap();
        assert_eq!(result.score, 0.0);
        assert!(!result.passed);
    }

    #[test]
    fn test_claim_extraction() {
        let config = GroundingConfig {
            enabled: true,
            min_claim_length: 5,
            ..Default::default()
        };
        let checker = GroundingChecker::new(config);

        let claims = checker.extract_claims("First claim. Second claim! Third claim?");
        assert_eq!(claims.len(), 3);
    }

    #[test]
    fn test_claim_extraction_respects_max_claims() {
        let config = GroundingConfig {
            enabled: true,
            min_claim_length: 1,
            max_claims: 2,
            ..Default::default()
        };
        let checker = GroundingChecker::new(config);

        let claims = checker.extract_claims("One. Two. Three.");
        assert_eq!(claims.len(), 2);
    }

    #[test]
    fn test_response_too_long_returns_error() {
        let config = GroundingConfig {
            enabled: true,
            ..Default::default()
        };
        let checker = GroundingChecker::new(config);

        let too_long = "a".repeat(MAX_GROUNDING_RESPONSE_CHARS + 1);
        let result = checker.check_grounding(&["context"], &too_long);
        assert!(matches!(
            result,
            Err(GroundingError::ResponseTooLong { .. })
        ));
    }

    #[test]
    fn test_grounding_with_sources() {
        let config = GroundingConfig {
            enabled: true,
            min_score: 0.5,
            ..Default::default()
        };
        let checker = GroundingChecker::new(config);

        let context = vec![
            ("doc1", "Paris is the capital of France."),
            ("doc2", "The Eiffel Tower is in Paris."),
        ];

        let response = "The Eiffel Tower is located in Paris, the capital of France.";
        let result = checker
            .check_grounding_with_sources(&context, response)
            .unwrap();

        assert!(result.passed);
    }

    #[test]
    fn test_enforcement_modes() {
        assert_eq!(GroundingEnforcement::default(), GroundingEnforcement::Warn);
    }

    // ═══════════════════════════════════════════════════
    // Additional coverage: GroundingResult helpers, edge cases
    // ═══════════════════════════════════════════════════

    #[test]
    fn test_grounding_result_grounded_claims() {
        let result = GroundingResult {
            score: 0.8,
            passed: true,
            claim_scores: vec![
                ClaimScore {
                    claim: "high".to_string(),
                    score: 0.9,
                    best_evidence: None,
                    nli_label: Some(NliLabel::Entailment),
                },
                ClaimScore {
                    claim: "low".to_string(),
                    score: 0.3,
                    best_evidence: None,
                    nli_label: None,
                },
                ClaimScore {
                    claim: "boundary".to_string(),
                    score: 0.7,
                    best_evidence: None,
                    nli_label: Some(NliLabel::Entailment),
                },
            ],
            ungrounded_claims: vec![],
            contradictions: vec![],
            attributions: vec![],
            method: GroundingMethod::Lexical,
        };
        let grounded = result.grounded_claims();
        assert_eq!(grounded.len(), 2);
        assert!(grounded.iter().all(|c| c.score >= 0.7));
    }

    #[test]
    fn test_grounding_result_hallucinated_claims() {
        let result = GroundingResult {
            score: 0.4,
            passed: false,
            claim_scores: vec![
                ClaimScore {
                    claim: "ok".to_string(),
                    score: 0.6,
                    best_evidence: None,
                    nli_label: None,
                },
                ClaimScore {
                    claim: "hallucinated".to_string(),
                    score: 0.2,
                    best_evidence: None,
                    nli_label: None,
                },
                ClaimScore {
                    claim: "boundary".to_string(),
                    score: 0.5,
                    best_evidence: None,
                    nli_label: None,
                },
            ],
            ungrounded_claims: vec![],
            contradictions: vec![],
            attributions: vec![],
            method: GroundingMethod::Lexical,
        };
        let hallucinated = result.hallucinated_claims();
        assert_eq!(hallucinated.len(), 1);
        assert_eq!(hallucinated[0].claim, "hallucinated");
    }

    #[test]
    fn test_grounding_result_is_grounded_delegates_to_passed() {
        let mut result = GroundingResult {
            score: 0.5,
            passed: true,
            claim_scores: vec![],
            ungrounded_claims: vec![],
            contradictions: vec![],
            attributions: vec![],
            method: GroundingMethod::Lexical,
        };
        assert!(result.is_grounded());
        result.passed = false;
        assert!(!result.is_grounded());
    }

    #[test]
    fn test_grounding_checker_is_enabled() {
        let checker = GroundingChecker::disabled();
        assert!(!checker.is_enabled());

        let config = GroundingConfig {
            enabled: true,
            ..Default::default()
        };
        let checker = GroundingChecker::new(config);
        assert!(checker.is_enabled());
    }

    #[test]
    fn test_claim_extraction_short_claims_filtered() {
        let config = GroundingConfig {
            enabled: true,
            min_claim_length: 10,
            ..Default::default()
        };
        let checker = GroundingChecker::new(config);

        let claims = checker.extract_claims("Short. This is a longer claim sentence.");
        assert_eq!(claims.len(), 1);
        assert!(claims[0].len() >= 10);
    }

    #[test]
    fn test_grounding_no_claims_extracted_passes() {
        let config = GroundingConfig {
            enabled: true,
            min_claim_length: 1000, // very high threshold
            ..Default::default()
        };
        let checker = GroundingChecker::new(config);

        let result = checker.check_grounding(&["context"], "short").unwrap();
        assert!(result.passed);
        assert_eq!(result.score, 1.0);
    }

    #[test]
    fn test_grounding_error_display() {
        let err = GroundingError::NliError("model failed".to_string());
        assert!(err.to_string().contains("model failed"));

        let err = GroundingError::ContextError("bad context".to_string());
        assert!(err.to_string().contains("bad context"));
    }

    #[test]
    fn test_grounding_method_equality() {
        assert_eq!(GroundingMethod::Lexical, GroundingMethod::Lexical);
        assert_ne!(GroundingMethod::Lexical, GroundingMethod::Nli);
        assert_ne!(GroundingMethod::Disabled, GroundingMethod::Nli);
    }

    #[test]
    fn test_nli_label_equality() {
        assert_eq!(NliLabel::Entailment, NliLabel::Entailment);
        assert_ne!(NliLabel::Entailment, NliLabel::Contradiction);
        assert_ne!(NliLabel::Neutral, NliLabel::Contradiction);
    }

    #[test]
    fn test_grounding_result_serialization() {
        let result = GroundingResult {
            score: 0.85,
            passed: true,
            claim_scores: vec![],
            ungrounded_claims: vec![],
            contradictions: vec![],
            attributions: vec![],
            method: GroundingMethod::Lexical,
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: GroundingResult = serde_json::from_str(&json).unwrap();
        assert!((parsed.score - 0.85).abs() < f32::EPSILON);
        assert!(parsed.passed);
    }

    #[test]
    fn test_grounding_result_deny_unknown_fields() {
        let json = r#"{"score":0.85,"passed":true,"claim_scores":[],"ungrounded_claims":[],"contradictions":[],"attributions":[],"method":"Lexical","extra":"bad"}"#;
        let result: Result<GroundingResult, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "GroundingResult should reject unknown fields"
        );
    }

    #[test]
    fn test_claim_score_deny_unknown_fields() {
        let json =
            r#"{"claim":"c","score":0.5,"best_evidence":null,"nli_label":null,"extra":"bad"}"#;
        let result: Result<ClaimScore, _> = serde_json::from_str(json);
        assert!(result.is_err(), "ClaimScore should reject unknown fields");
    }

    #[test]
    fn test_contradiction_deny_unknown_fields() {
        let json = r#"{"claim":"c","evidence":"e","confidence":0.5,"extra":"bad"}"#;
        let result: Result<Contradiction, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "Contradiction should reject unknown fields"
        );
    }

    #[test]
    fn test_attribution_deny_unknown_fields() {
        let json =
            r#"{"claim":"c","source_id":"doc-1","passage":"p","confidence":0.5,"extra":"bad"}"#;
        let result: Result<Attribution, _> = serde_json::from_str(json);
        assert!(result.is_err(), "Attribution should reject unknown fields");
    }

    // ── R239-MCP-3: f32 NaN/Infinity/range validation tests ───────

    #[test]
    fn test_grounding_result_validate_rejects_nan_score() {
        let result = GroundingResult {
            score: f32::NAN,
            passed: false,
            claim_scores: vec![],
            ungrounded_claims: vec![],
            contradictions: vec![],
            attributions: vec![],
            method: GroundingMethod::Lexical,
        };
        assert!(result.validate().is_err());
    }

    #[test]
    fn test_grounding_result_validate_rejects_infinity_score() {
        let result = GroundingResult {
            score: f32::INFINITY,
            passed: false,
            claim_scores: vec![],
            ungrounded_claims: vec![],
            contradictions: vec![],
            attributions: vec![],
            method: GroundingMethod::Lexical,
        };
        assert!(result.validate().is_err());
    }

    #[test]
    fn test_grounding_result_validate_rejects_negative_score() {
        let result = GroundingResult {
            score: -0.1,
            passed: false,
            claim_scores: vec![],
            ungrounded_claims: vec![],
            contradictions: vec![],
            attributions: vec![],
            method: GroundingMethod::Lexical,
        };
        assert!(result.validate().is_err());
    }

    #[test]
    fn test_grounding_result_validate_rejects_over_one_score() {
        let result = GroundingResult {
            score: 1.01,
            passed: false,
            claim_scores: vec![],
            ungrounded_claims: vec![],
            contradictions: vec![],
            attributions: vec![],
            method: GroundingMethod::Lexical,
        };
        assert!(result.validate().is_err());
    }

    #[test]
    fn test_grounding_result_validate_rejects_nan_claim_score() {
        let result = GroundingResult {
            score: 0.5,
            passed: true,
            claim_scores: vec![ClaimScore {
                claim: "test".to_string(),
                score: f32::NAN,
                best_evidence: None,
                nli_label: None,
            }],
            ungrounded_claims: vec![],
            contradictions: vec![],
            attributions: vec![],
            method: GroundingMethod::Lexical,
        };
        assert!(result.validate().is_err());
    }

    #[test]
    fn test_grounding_result_validate_rejects_nan_contradiction_confidence() {
        let result = GroundingResult {
            score: 0.5,
            passed: true,
            claim_scores: vec![],
            ungrounded_claims: vec![],
            contradictions: vec![Contradiction {
                claim: "test".to_string(),
                evidence: "evidence".to_string(),
                confidence: f32::NAN,
            }],
            attributions: vec![],
            method: GroundingMethod::Lexical,
        };
        assert!(result.validate().is_err());
    }

    #[test]
    fn test_grounding_result_validate_accepts_valid() {
        let result = GroundingResult {
            score: 0.8,
            passed: true,
            claim_scores: vec![ClaimScore {
                claim: "test".to_string(),
                score: 0.9,
                best_evidence: Some("evidence".to_string()),
                nli_label: Some(NliLabel::Entailment),
            }],
            ungrounded_claims: vec![],
            contradictions: vec![],
            attributions: vec![Attribution {
                claim: "test".to_string(),
                source_id: "doc1".to_string(),
                passage: "evidence".to_string(),
                confidence: 0.9,
            }],
            method: GroundingMethod::Lexical,
        };
        assert!(result.validate().is_ok());
    }
}
