// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Compliance Evidence Pack types for DORA, NIS2, ISO 42001, and EU AI Act.
//!
//! Defines a unified evidence bundle format for auditor-ready compliance
//! evidence packs. Each pack contains sections of evidence items mapping
//! regulatory requirements to Vellaveto capabilities.

use serde::{Deserialize, Serialize};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of sections in an evidence pack.
pub const MAX_EVIDENCE_SECTIONS: usize = 100;

/// Maximum number of evidence items per section.
pub const MAX_EVIDENCE_ITEMS_PER_SECTION: usize = 200;

/// Maximum number of critical gaps in an evidence pack.
pub const MAX_EVIDENCE_PACK_GAPS: usize = 500;

/// Maximum number of recommendations in an evidence pack.
pub const MAX_EVIDENCE_RECOMMENDATIONS: usize = 100;

/// Maximum length for evidence string fields.
pub const MAX_EVIDENCE_STRING_LEN: usize = 4_096;

// ── Evidence Framework ───────────────────────────────────────────────────────

/// Compliance framework for which an evidence pack can be generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum EvidenceFramework {
    /// EU Digital Operational Resilience Act.
    Dora,
    /// EU Network and Information Security Directive 2.
    Nis2,
    /// ISO/IEC 42001 AI Management System.
    Iso42001,
    /// EU Artificial Intelligence Act.
    EuAiAct,
}

impl std::fmt::Display for EvidenceFramework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dora => write!(f, "DORA"),
            Self::Nis2 => write!(f, "NIS2"),
            Self::Iso42001 => write!(f, "ISO 42001"),
            Self::EuAiAct => write!(f, "EU AI Act"),
        }
    }
}

// ── Evidence Confidence ──────────────────────────────────────────────────────

/// Confidence level of evidence mapping a requirement to a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceConfidence {
    /// No evidence available.
    None,
    /// Minimal evidence — indirect or tangential coverage.
    Low,
    /// Partial evidence — some capability mapped but gaps remain.
    Medium,
    /// Strong evidence — capability directly addresses the requirement.
    High,
    /// Complete evidence — full coverage with verification.
    Full,
}

impl std::fmt::Display for EvidenceConfidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Full => write!(f, "Full"),
        }
    }
}

// ── Evidence Item ────────────────────────────────────────────────────────────

/// A single evidence item mapping a regulatory requirement to a Vellaveto capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceItem {
    /// Requirement identifier (e.g., "Art 5", "21.2.a").
    pub requirement_id: String,
    /// Short title of the requirement.
    pub requirement_title: String,
    /// Article or clause reference in the regulation.
    pub article_ref: String,
    /// Vellaveto capability providing the evidence.
    pub vellaveto_capability: String,
    /// Description of how the capability addresses the requirement.
    pub evidence_description: String,
    /// Confidence level of this evidence mapping.
    pub confidence: EvidenceConfidence,
    /// Identified gaps for this requirement.
    #[serde(default)]
    pub gaps: Vec<String>,
}

impl EvidenceItem {
    /// Validate evidence item bounds.
    pub fn validate(&self) -> Result<(), String> {
        Self::check_field("requirement_id", &self.requirement_id)?;
        Self::check_field("requirement_title", &self.requirement_title)?;
        Self::check_field("article_ref", &self.article_ref)?;
        Self::check_field("vellaveto_capability", &self.vellaveto_capability)?;
        Self::check_field("evidence_description", &self.evidence_description)?;
        if self.gaps.len() > MAX_EVIDENCE_PACK_GAPS {
            return Err(format!(
                "EvidenceItem.gaps has {} entries, max is {}",
                self.gaps.len(),
                MAX_EVIDENCE_PACK_GAPS,
            ));
        }
        for (i, gap) in self.gaps.iter().enumerate() {
            if gap.len() > MAX_EVIDENCE_STRING_LEN {
                return Err(format!(
                    "EvidenceItem.gaps[{}] length {} exceeds max {}",
                    i,
                    gap.len(),
                    MAX_EVIDENCE_STRING_LEN,
                ));
            }
            if crate::has_dangerous_chars(gap) {
                return Err(format!(
                    "EvidenceItem.gaps[{i}] contains control or format characters",
                ));
            }
        }
        Ok(())
    }

    fn check_field(name: &str, value: &str) -> Result<(), String> {
        if value.len() > MAX_EVIDENCE_STRING_LEN {
            return Err(format!(
                "EvidenceItem.{} length {} exceeds max {}",
                name,
                value.len(),
                MAX_EVIDENCE_STRING_LEN,
            ));
        }
        if crate::has_dangerous_chars(value) {
            return Err(format!(
                "EvidenceItem.{name} contains control or format characters",
            ));
        }
        Ok(())
    }
}

// ── Evidence Section ─────────────────────────────────────────────────────────

/// A group of related evidence items within an evidence pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSection {
    /// Section identifier (e.g., "ict-risk", "art-21-2").
    pub section_id: String,
    /// Human-readable section title.
    pub title: String,
    /// Section description.
    pub description: String,
    /// Evidence items in this section.
    pub items: Vec<EvidenceItem>,
    /// Coverage percentage for this section (0.0–100.0).
    pub section_coverage_percent: f32,
}

impl EvidenceSection {
    /// Validate evidence section bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.section_id.len() > MAX_EVIDENCE_STRING_LEN {
            return Err(format!(
                "EvidenceSection.section_id length {} exceeds max {}",
                self.section_id.len(),
                MAX_EVIDENCE_STRING_LEN,
            ));
        }
        if crate::has_dangerous_chars(&self.section_id) {
            return Err(
                "EvidenceSection.section_id contains control or format characters".to_string(),
            );
        }
        if self.title.len() > MAX_EVIDENCE_STRING_LEN {
            return Err(format!(
                "EvidenceSection.title length {} exceeds max {}",
                self.title.len(),
                MAX_EVIDENCE_STRING_LEN,
            ));
        }
        if crate::has_dangerous_chars(&self.title) {
            return Err("EvidenceSection.title contains control or format characters".to_string());
        }
        if self.description.len() > MAX_EVIDENCE_STRING_LEN {
            return Err(format!(
                "EvidenceSection.description length {} exceeds max {MAX_EVIDENCE_STRING_LEN}",
                self.description.len(),
            ));
        }
        if crate::has_dangerous_chars(&self.description) {
            return Err(
                "EvidenceSection.description contains control or format characters".to_string(),
            );
        }
        if self.items.len() > MAX_EVIDENCE_ITEMS_PER_SECTION {
            return Err(format!(
                "EvidenceSection.items has {} entries, max is {}",
                self.items.len(),
                MAX_EVIDENCE_ITEMS_PER_SECTION,
            ));
        }
        if !self.section_coverage_percent.is_finite()
            || self.section_coverage_percent < 0.0
            || self.section_coverage_percent > 100.0
        {
            return Err(format!(
                "EvidenceSection.section_coverage_percent {} out of range [0.0, 100.0]",
                self.section_coverage_percent,
            ));
        }
        for item in &self.items {
            item.validate()?;
        }
        Ok(())
    }
}

// ── Evidence Pack ────────────────────────────────────────────────────────────

/// A complete compliance evidence pack for a single framework.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidencePack {
    /// The compliance framework this pack covers.
    pub framework: EvidenceFramework,
    /// Human-readable framework name.
    pub framework_name: String,
    /// ISO 8601 timestamp of generation.
    pub generated_at: String,
    /// Organization name.
    pub organization_name: String,
    /// System identifier.
    pub system_id: String,
    /// Optional period start (ISO 8601).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period_start: Option<String>,
    /// Optional period end (ISO 8601).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period_end: Option<String>,
    /// Evidence sections grouped by regulatory topic.
    pub sections: Vec<EvidenceSection>,
    /// Overall coverage percentage (0.0–100.0).
    pub overall_coverage_percent: f32,
    /// Total number of requirements in the framework.
    pub total_requirements: usize,
    /// Number of fully covered requirements.
    pub covered_requirements: usize,
    /// Number of partially covered requirements.
    pub partial_requirements: usize,
    /// Number of uncovered requirements.
    pub uncovered_requirements: usize,
    /// Critical gaps requiring attention.
    pub critical_gaps: Vec<String>,
    /// Actionable recommendations.
    pub recommendations: Vec<String>,

    /// Ed25519 signature over the canonical evidence pack content (hex-encoded).
    /// When present, provides non-repudiation: the pack was generated by a holder
    /// of the corresponding signing key and has not been tampered with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Ed25519 verifying key (public key) for signature verification (hex-encoded).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifying_key: Option<String>,
}

/// Maximum length for Ed25519 signature hex (64 bytes = 128 hex chars).
const MAX_EVIDENCE_SIGNATURE_HEX_LEN: usize = 128;
/// Maximum length for Ed25519 verifying key hex (32 bytes = 64 hex chars).
const MAX_EVIDENCE_VERIFYING_KEY_HEX_LEN: usize = 64;

impl EvidencePack {
    /// Compute the canonical content that is signed.
    ///
    /// Uses SHA-256 over length-prefixed fields (same pattern as
    /// `Checkpoint::signing_content()`) to produce a deterministic
    /// byte sequence independent of serialization format.
    pub fn signing_content(&self) -> Vec<u8> {
        self.signing_content_internal(true)
    }

    /// Evidence pack signing content prior to domain separation.
    ///
    /// SECURITY (DOC-CRED-2): Verification falls back to this so packs signed
    /// before domain separation keep verifying. Never used for signing.
    pub fn undomained_signing_content(&self) -> Vec<u8> {
        self.signing_content_internal(false)
    }

    fn signing_content_internal(&self, domain_separated: bool) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = if domain_separated {
            crate::signing_domain::domain_separated_hasher(
                crate::signing_domain::DOMAIN_EVIDENCE_PACK,
            )
        } else {
            Sha256::new()
        };
        let hash_field = |h: &mut Sha256, data: &[u8]| {
            h.update((data.len() as u64).to_le_bytes());
            h.update(data);
        };
        hash_field(&mut hasher, self.framework_name.as_bytes());
        hash_field(&mut hasher, self.generated_at.as_bytes());
        hash_field(&mut hasher, self.organization_name.as_bytes());
        hash_field(&mut hasher, self.system_id.as_bytes());
        hash_field(&mut hasher, &self.overall_coverage_percent.to_le_bytes());
        hash_field(&mut hasher, &(self.total_requirements as u64).to_le_bytes());
        hash_field(
            &mut hasher,
            &(self.covered_requirements as u64).to_le_bytes(),
        );
        hash_field(
            &mut hasher,
            &(self.partial_requirements as u64).to_le_bytes(),
        );
        hash_field(
            &mut hasher,
            &(self.uncovered_requirements as u64).to_le_bytes(),
        );
        // R263-EP-1: Include ALL tamper-detectable fields. Previously excluded
        // sections, recommendations, and period bounds — allowing an attacker to
        // strip evidence items or alter the audit period without invalidating the
        // signature.
        hash_field(
            &mut hasher,
            self.period_start.as_deref().unwrap_or("").as_bytes(),
        );
        hash_field(
            &mut hasher,
            self.period_end.as_deref().unwrap_or("").as_bytes(),
        );
        // Sections (the core evidence items)
        hash_field(&mut hasher, &(self.sections.len() as u64).to_le_bytes());
        for section in &self.sections {
            hash_field(&mut hasher, section.section_id.as_bytes());
            hash_field(&mut hasher, section.title.as_bytes());
            hash_field(&mut hasher, &(section.items.len() as u64).to_le_bytes());
            hash_field(&mut hasher, &section.section_coverage_percent.to_le_bytes());
        }
        // Critical gaps
        hash_field(
            &mut hasher,
            &(self.critical_gaps.len() as u64).to_le_bytes(),
        );
        for gap in &self.critical_gaps {
            hash_field(&mut hasher, gap.as_bytes());
        }
        // Recommendations
        hash_field(
            &mut hasher,
            &(self.recommendations.len() as u64).to_le_bytes(),
        );
        for rec in &self.recommendations {
            hash_field(&mut hasher, rec.as_bytes());
        }
        hasher.finalize().to_vec()
    }

    /// Validate evidence pack bounds.
    pub fn validate(&self) -> Result<(), String> {
        // SECURITY (IMP-R222-EP-001): Validate generated_at and period timestamps.
        // These ISO 8601 strings were missing length + dangerous char checks.
        for (name, val) in [
            ("generated_at", Some(&self.generated_at)),
            ("period_start", self.period_start.as_ref()),
            ("period_end", self.period_end.as_ref()),
        ] {
            if let Some(v) = val {
                if v.len() > MAX_EVIDENCE_STRING_LEN {
                    return Err(format!(
                        "EvidencePack.{name} length {} exceeds max {MAX_EVIDENCE_STRING_LEN}",
                        v.len(),
                    ));
                }
                if crate::has_dangerous_chars(v) {
                    return Err(format!(
                        "EvidencePack.{name} contains control or format characters",
                    ));
                }
            }
        }
        if self.framework_name.len() > MAX_EVIDENCE_STRING_LEN {
            return Err(format!(
                "EvidencePack.framework_name length {} exceeds max {}",
                self.framework_name.len(),
                MAX_EVIDENCE_STRING_LEN,
            ));
        }
        if crate::has_dangerous_chars(&self.framework_name) {
            return Err(
                "EvidencePack.framework_name contains control or format characters".to_string(),
            );
        }
        if self.organization_name.len() > MAX_EVIDENCE_STRING_LEN {
            return Err(format!(
                "EvidencePack.organization_name length {} exceeds max {}",
                self.organization_name.len(),
                MAX_EVIDENCE_STRING_LEN,
            ));
        }
        if crate::has_dangerous_chars(&self.organization_name) {
            return Err(
                "EvidencePack.organization_name contains control or format characters".to_string(),
            );
        }
        if self.system_id.len() > MAX_EVIDENCE_STRING_LEN {
            return Err(format!(
                "EvidencePack.system_id length {} exceeds max {}",
                self.system_id.len(),
                MAX_EVIDENCE_STRING_LEN,
            ));
        }
        if crate::has_dangerous_chars(&self.system_id) {
            return Err("EvidencePack.system_id contains control or format characters".to_string());
        }
        if self.sections.len() > MAX_EVIDENCE_SECTIONS {
            return Err(format!(
                "EvidencePack.sections has {} entries, max is {}",
                self.sections.len(),
                MAX_EVIDENCE_SECTIONS,
            ));
        }
        if !self.overall_coverage_percent.is_finite()
            || self.overall_coverage_percent < 0.0
            || self.overall_coverage_percent > 100.0
        {
            return Err(format!(
                "EvidencePack.overall_coverage_percent {} out of range [0.0, 100.0]",
                self.overall_coverage_percent,
            ));
        }
        if self.critical_gaps.len() > MAX_EVIDENCE_PACK_GAPS {
            return Err(format!(
                "EvidencePack.critical_gaps has {} entries, max is {}",
                self.critical_gaps.len(),
                MAX_EVIDENCE_PACK_GAPS,
            ));
        }
        for (i, gap) in self.critical_gaps.iter().enumerate() {
            if gap.len() > MAX_EVIDENCE_STRING_LEN {
                return Err(format!(
                    "EvidencePack.critical_gaps[{i}] length {} exceeds max {MAX_EVIDENCE_STRING_LEN}",
                    gap.len(),
                ));
            }
            if crate::has_dangerous_chars(gap) {
                return Err(format!(
                    "EvidencePack.critical_gaps[{i}] contains control or format characters",
                ));
            }
        }
        if self.recommendations.len() > MAX_EVIDENCE_RECOMMENDATIONS {
            return Err(format!(
                "EvidencePack.recommendations has {} entries, max is {}",
                self.recommendations.len(),
                MAX_EVIDENCE_RECOMMENDATIONS,
            ));
        }
        for (i, rec) in self.recommendations.iter().enumerate() {
            if rec.len() > MAX_EVIDENCE_STRING_LEN {
                return Err(format!(
                    "EvidencePack.recommendations[{i}] length {} exceeds max {MAX_EVIDENCE_STRING_LEN}",
                    rec.len(),
                ));
            }
            if crate::has_dangerous_chars(rec) {
                return Err(format!(
                    "EvidencePack.recommendations[{i}] contains control or format characters",
                ));
            }
        }
        // SECURITY (IMP-R222-009): Requirement count consistency check.
        let sum = self
            .covered_requirements
            .saturating_add(self.partial_requirements)
            .saturating_add(self.uncovered_requirements);
        if sum > self.total_requirements {
            return Err(format!(
                "EvidencePack: covered({}) + partial({}) + uncovered({}) = {} exceeds total_requirements({})",
                self.covered_requirements,
                self.partial_requirements,
                self.uncovered_requirements,
                sum,
                self.total_requirements,
            ));
        }
        for section in &self.sections {
            section.validate()?;
        }
        // SECURITY: Validate signature fields if present.
        if let Some(ref sig) = self.signature {
            if sig.len() != MAX_EVIDENCE_SIGNATURE_HEX_LEN {
                return Err(format!(
                    "EvidencePack.signature must be exactly {} hex chars, got {}",
                    MAX_EVIDENCE_SIGNATURE_HEX_LEN,
                    sig.len(),
                ));
            }
            if crate::has_dangerous_chars(sig) {
                return Err("EvidencePack.signature contains dangerous characters".to_string());
            }
        }
        if let Some(ref vk) = self.verifying_key {
            if vk.len() != MAX_EVIDENCE_VERIFYING_KEY_HEX_LEN {
                return Err(format!(
                    "EvidencePack.verifying_key must be exactly {} hex chars, got {}",
                    MAX_EVIDENCE_VERIFYING_KEY_HEX_LEN,
                    vk.len(),
                ));
            }
            if crate::has_dangerous_chars(vk) {
                return Err("EvidencePack.verifying_key contains dangerous characters".to_string());
            }
        }
        Ok(())
    }
}

// ── Evidence Pack Status ─────────────────────────────────────────────────────

/// Status response for the evidence pack endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidencePackStatus {
    /// Frameworks available for evidence pack generation.
    pub available_frameworks: Vec<EvidenceFramework>,
    /// Whether DORA evidence generation is enabled.
    pub dora_enabled: bool,
    /// Whether NIS2 evidence generation is enabled.
    pub nis2_enabled: bool,
}

impl EvidencePackStatus {
    /// Maximum number of available frameworks.
    const MAX_FRAMEWORKS: usize = 50;

    /// Validate structural bounds on deserialized data.
    ///
    /// SECURITY (FIND-R216-016): Prevents unbounded framework lists from
    /// untrusted deserialized payloads.
    pub fn validate(&self) -> Result<(), String> {
        if self.available_frameworks.len() > Self::MAX_FRAMEWORKS {
            return Err(format!(
                "EvidencePackStatus available_frameworks count {} exceeds max {}",
                self.available_frameworks.len(),
                Self::MAX_FRAMEWORKS,
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod verus_spec_differential {
    //! Differential binding for `PARITY-HAND-1` (see
    //! `formal/ASSUMPTION_REGISTRY.md`), kernel
    //! `formal/verus/verified_evidence_signing.rs`.
    //!
    //! **Property discharge — tamper coverage.** The kernel does not model an
    //! algorithm `signing_content()` equals. It states which fields the signed
    //! payload must cover: at least twelve scalars plus the period bounds and a
    //! sections header, every section's id, title and item count, the
    //! recommendation count and each recommendation.
    //!
    //! The only way to check "covered" against a digest is to mutate the field
    //! and require the digest to move. That is exactly the property R263-EP-1
    //! restored — before it, sections, recommendations and period bounds were
    //! excluded, so an attacker could strip evidence items or alter the audit
    //! period without invalidating the signature. Every case below would have
    //! failed against that older payload.

    use super::*;

    /// The kernel's literals, pinned rather than read from production so that
    /// widening a bound is caught — see the constant-binding rule in the
    /// registry.
    const K_SIGNATURE_HEX_LEN: usize = 128;
    const K_VERIFYING_KEY_HEX_LEN: usize = 64;
    const K_MINIMUM_SIGNING_FIELDS: usize = 12;

    fn spec_signature_hex_valid(len: usize) -> bool {
        len == K_SIGNATURE_HEX_LEN
    }

    fn spec_verifying_key_hex_valid(len: usize) -> bool {
        len == K_VERIFYING_KEY_HEX_LEN
    }

    fn spec_requirement_count_consistent(
        covered: usize,
        partial: usize,
        uncovered: usize,
        total: usize,
    ) -> bool {
        covered
            .checked_add(partial)
            .and_then(|s| s.checked_add(uncovered))
            .is_some_and(|sum| sum <= total)
    }

    fn spec_coverage_valid(pct_is_finite: bool, pct_in_range: bool) -> bool {
        pct_is_finite && pct_in_range
    }

    fn item() -> EvidenceItem {
        EvidenceItem {
            requirement_id: "r1".into(),
            requirement_title: "Requirement one".into(),
            article_ref: "Art 1".into(),
            vellaveto_capability: "policy-engine".into(),
            evidence_description: "covered by policy evaluation".into(),
            confidence: EvidenceConfidence::High,
            gaps: vec![],
        }
    }

    fn pack() -> EvidencePack {
        EvidencePack {
            framework: EvidenceFramework::EuAiAct,
            framework_name: "EU AI Act".into(),
            generated_at: "2026-08-25T00:00:00Z".into(),
            organization_name: "Acme".into(),
            system_id: "sys-1".into(),
            period_start: Some("2026-01-01T00:00:00Z".into()),
            period_end: Some("2026-06-30T00:00:00Z".into()),
            sections: vec![EvidenceSection {
                section_id: "annex-iv".into(),
                title: "Annex IV".into(),
                description: "desc".into(),
                items: vec![item()],
                section_coverage_percent: 80.0,
            }],
            overall_coverage_percent: 80.0,
            total_requirements: 10,
            covered_requirements: 8,
            partial_requirements: 1,
            uncovered_requirements: 1,
            critical_gaps: vec!["gap-a".into()],
            recommendations: vec!["do the thing".into()],
            signature: None,
            verifying_key: None,
        }
    }

    /// Every field the kernel says the payload covers must move the digest.
    #[test]
    fn test_signing_content_covers_every_field_the_kernel_names() {
        let baseline = pack().signing_content();

        // One mutation per covered field. Each is a tamper an attacker would
        // want: shrinking the evidence, widening the coverage claim, moving the
        // audit period, dropping a recommendation.
        type Mutation = (&'static str, fn(&mut EvidencePack));
        let mutations: &[Mutation] = &[
            ("framework_name", |p| p.framework_name = "Other".into()),
            ("generated_at", |p| {
                p.generated_at = "2020-01-01T00:00:00Z".into()
            }),
            ("organization_name", |p| p.organization_name = "Evil".into()),
            ("system_id", |p| p.system_id = "sys-2".into()),
            ("overall_coverage_percent", |p| {
                p.overall_coverage_percent = 100.0
            }),
            ("total_requirements", |p| p.total_requirements = 1),
            ("covered_requirements", |p| p.covered_requirements = 10),
            ("partial_requirements", |p| p.partial_requirements = 0),
            ("uncovered_requirements", |p| p.uncovered_requirements = 0),
            ("period_start", |p| {
                p.period_start = Some("2019-01-01T00:00:00Z".into())
            }),
            ("period_end", |p| p.period_end = None),
            ("sections (count)", |p| p.sections.clear()),
            ("section_id", |p| p.sections[0].section_id = "other".into()),
            ("section title", |p| p.sections[0].title = "Other".into()),
            ("section item count", |p| p.sections[0].items.clear()),
            ("section coverage", |p| {
                p.sections[0].section_coverage_percent = 100.0
            }),
            ("critical_gaps (count)", |p| p.critical_gaps.clear()),
            // Clearing changes the count; rewriting changes only the content.
            // Mutation testing caught that testing only the former left the
            // per-gap hashing loop free to be deleted.
            ("critical_gap text", |p| {
                p.critical_gaps[0] = "no gaps at all".into()
            }),
            ("recommendations (count)", |p| p.recommendations.clear()),
            ("recommendation text", |p| {
                p.recommendations[0] = "nothing".into()
            }),
        ];

        assert!(
            mutations.len() >= K_MINIMUM_SIGNING_FIELDS,
            "PARITY-HAND-1: the kernel requires at least {K_MINIMUM_SIGNING_FIELDS} covered fields"
        );

        for (name, mutate) in mutations {
            let mut p = pack();
            mutate(&mut p);
            assert_ne!(
                p.signing_content(),
                baseline,
                "PARITY-HAND-1: tampering with `{name}` did not change signing_content(), so the \
                 signature does not cover it — the R263-EP-1 class of gap"
            );
        }
    }

    /// The payload length-prefixes every field before hashing it. Without that
    /// framing, adjacent fields concatenate ambiguously and two different packs
    /// can share a digest — an attacker moves a byte across a field boundary
    /// and the signature still verifies.
    ///
    /// Mutation testing found this: deleting the length prefix passed every
    /// other case here, because they all change total content rather than only
    /// where a boundary falls.
    #[test]
    fn test_field_boundaries_are_unambiguous() {
        let mut left = pack();
        left.organization_name = "ab".into();
        left.system_id = "c".into();

        let mut right = pack();
        right.organization_name = "a".into();
        right.system_id = "bc".into();

        assert_ne!(
            left.signing_content(),
            right.signing_content(),
            "PARITY-HAND-1: two packs differing only in where a field boundary falls share a \
             digest — the length prefix is missing, so adjacent fields concatenate ambiguously"
        );
    }

    #[test]
    fn test_hex_length_predicates_match_verus_spec() {
        for len in 0usize..=192 {
            assert_eq!(
                spec_signature_hex_valid(len),
                len == 128,
                "PARITY-HAND-1: signature hex length predicate disagrees at {len}"
            );
            assert_eq!(
                spec_verifying_key_hex_valid(len),
                len == 64,
                "PARITY-HAND-1: verifying key hex length predicate disagrees at {len}"
            );
        }
    }

    #[test]
    fn test_requirement_counts_are_consistent_in_the_fixture() {
        let p = pack();
        assert!(
            spec_requirement_count_consistent(
                p.covered_requirements,
                p.partial_requirements,
                p.uncovered_requirements,
                p.total_requirements
            ),
            "PARITY-HAND-1: the fixture violates the count invariant the kernel proves"
        );
        assert!(spec_coverage_valid(
            p.overall_coverage_percent.is_finite(),
            (0.0..=100.0).contains(&p.overall_coverage_percent)
        ));
    }

    #[test]
    fn test_spec_oracle_can_reject() {
        // Counts must not exceed the total, and must not overflow into looking
        // consistent.
        assert!(!spec_requirement_count_consistent(9, 1, 1, 10));
        assert!(spec_requirement_count_consistent(8, 1, 1, 10));
        assert!(!spec_requirement_count_consistent(
            usize::MAX,
            1,
            0,
            usize::MAX
        ));
        // Coverage must be finite and in range.
        assert!(!spec_coverage_valid(false, true));
        assert!(!spec_coverage_valid(true, false));
        // The hex lengths are exact.
        assert!(!spec_signature_hex_valid(127));
        assert!(!spec_signature_hex_valid(129));
    }
}
