// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Evidence Pack Generator and HTML Renderer.
//!
//! Generates unified compliance evidence packs for DORA, NIS2, ISO 42001,
//! and EU AI Act by converting framework-specific registry reports into
//! the common `EvidencePack` format.
//!
//! # Usage
//!
//! ```ignore
//! use vellaveto_audit::evidence_pack::generate_evidence_pack;
//! use vellaveto_types::EvidenceFramework;
//!
//! let pack = generate_evidence_pack(EvidenceFramework::Dora, "Acme Bank", "acme-001");
//! println!("Coverage: {:.1}%", pack.overall_coverage_percent);
//! ```

use vellaveto_types::{
    EvidenceConfidence, EvidenceFramework, EvidenceItem, EvidencePack, EvidenceSection,
};

// ── Generator ────────────────────────────────────────────────────────────────

/// Generate an evidence pack for the specified compliance framework.
///
/// Instantiates the corresponding registry, generates its report, and
/// converts the framework-specific types into the unified `EvidencePack`
/// format.
pub fn generate_evidence_pack(
    framework: EvidenceFramework,
    organization_name: &str,
    system_id: &str,
) -> EvidencePack {
    match framework {
        EvidenceFramework::Dora => generate_dora_pack(organization_name, system_id),
        EvidenceFramework::Nis2 => generate_nis2_pack(organization_name, system_id),
        EvidenceFramework::Iso42001 => generate_iso42001_pack(organization_name, system_id),
        EvidenceFramework::EuAiAct => generate_eu_ai_act_pack(organization_name, system_id),
        // EvidenceFramework is #[non_exhaustive] — fail-closed for unknown variants.
        _ => EvidencePack {
            framework,
            framework_name: format!("{framework}"),
            generated_at: chrono::Utc::now().to_rfc3339(),
            organization_name: organization_name.to_string(),
            system_id: system_id.to_string(),
            period_start: None,
            period_end: None,
            sections: vec![],
            overall_coverage_percent: 0.0,
            total_requirements: 0,
            covered_requirements: 0,
            partial_requirements: 0,
            uncovered_requirements: 0,
            critical_gaps: vec!["Unknown framework — no evidence available".to_string()],
            recommendations: vec!["Add support for this framework".to_string()],
            signature: None,
            verifying_key: None,
        },
    }
}

// ── DORA Pack ────────────────────────────────────────────────────────────────

fn generate_dora_pack(org: &str, sys_id: &str) -> EvidencePack {
    let registry = crate::dora::DoraRegistry::new();
    let report = registry.generate_report(org, sys_id);

    // Group assessments by chapter
    let mut ict_risk = Vec::new(); // Art 5-16
    let mut incidents = Vec::new(); // Art 17-23
    let mut testing = Vec::new(); // Art 24-27
    let mut third_party = Vec::new(); // Art 28+
    let mut other = Vec::new(); // Art 45+

    for a in &report.assessments {
        let art_num = extract_article_number(&a.article_id.0);
        let item = dora_assessment_to_item(a);
        match art_num {
            5..=16 => ict_risk.push(item),
            17..=23 => incidents.push(item),
            24..=27 => testing.push(item),
            28..=44 => third_party.push(item),
            _ => other.push(item),
        }
    }

    let sections = vec![
        make_section("ict-risk-management", "Chapter II: ICT Risk Management", "Art 5-16 — ICT risk management framework, identification, protection, detection, response, recovery, and learning", ict_risk),
        make_section("ict-incidents", "Chapter III: ICT-Related Incidents", "Art 17-23 — Incident management, classification, reporting, and notification", incidents),
        make_section("resilience-testing", "Chapter IV: Digital Operational Resilience Testing", "Art 24-27 — Testing programme, advanced TLPT, tester requirements", testing),
        make_section("third-party-risk", "Chapter V: Third-Party ICT Risk Management", "Art 28-44 — Third-party risk, contractual provisions, register of information", third_party),
        make_section("information-sharing", "Chapter VI: Information Sharing", "Art 45 — Cyber threat intelligence sharing", other),
    ];

    build_pack(
        EvidenceFramework::Dora,
        "DORA (Digital Operational Resilience Act)",
        org,
        sys_id,
        sections,
        &report
            .assessments
            .iter()
            .map(|a| dora_status_to_confidence(a.status))
            .collect::<Vec<_>>(),
    )
}

fn dora_assessment_to_item(a: &crate::dora::DoraAssessment) -> EvidenceItem {
    let confidence = dora_status_to_confidence(a.status);
    let gaps = if a.status == crate::dora::DoraComplianceStatus::NotImplemented {
        vec![format!("{}: No Vellaveto evidence available", a.title)]
    } else if a.status == crate::dora::DoraComplianceStatus::Partial {
        vec![format!(
            "{}: Partial coverage — additional evidence may be needed",
            a.title
        )]
    } else {
        vec![]
    };
    EvidenceItem {
        requirement_id: a.article_id.0.clone(),
        requirement_title: a.title.clone(),
        article_ref: a.article_id.0.clone(),
        vellaveto_capability: a
            .capabilities
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        evidence_description: a.evidence.clone(),
        confidence,
        gaps,
    }
}

fn dora_status_to_confidence(status: crate::dora::DoraComplianceStatus) -> EvidenceConfidence {
    match status {
        crate::dora::DoraComplianceStatus::Compliant => EvidenceConfidence::High,
        crate::dora::DoraComplianceStatus::Partial => EvidenceConfidence::Medium,
        crate::dora::DoraComplianceStatus::NotImplemented => EvidenceConfidence::None,
    }
}

// ── NIS2 Pack ────────────────────────────────────────────────────────────────

fn generate_nis2_pack(org: &str, sys_id: &str) -> EvidencePack {
    let registry = crate::nis2::Nis2Registry::new();
    let report = registry.generate_report(org, sys_id);

    let mut risk_measures = Vec::new(); // Art 21
    let mut supply_chain = Vec::new(); // Art 22
    let mut notification = Vec::new(); // Art 23

    for a in &report.assessments {
        let item = nis2_assessment_to_item(a);
        if a.article_id.0.starts_with("Art 21") {
            risk_measures.push(item);
        } else if a.article_id.0.starts_with("Art 22") {
            supply_chain.push(item);
        } else {
            notification.push(item);
        }
    }

    let sections = vec![
        make_section(
            "risk-management-measures",
            "Art 21: Cybersecurity Risk-Management Measures",
            "Art 21.1-21.2.j — Technical, operational, and organisational measures",
            risk_measures,
        ),
        make_section(
            "supply-chain-security",
            "Art 22: Supply Chain Security",
            "Art 22 — Coordinated security risk assessments of critical supply chains",
            supply_chain,
        ),
        make_section(
            "incident-notification",
            "Art 23: Reporting Obligations",
            "Art 23.1-23.4 — Significant incident notification timeline",
            notification,
        ),
    ];

    build_pack(
        EvidenceFramework::Nis2,
        "NIS2 (Network and Information Security Directive 2)",
        org,
        sys_id,
        sections,
        &report
            .assessments
            .iter()
            .map(|a| nis2_status_to_confidence(a.status))
            .collect::<Vec<_>>(),
    )
}

fn nis2_assessment_to_item(a: &crate::nis2::Nis2Assessment) -> EvidenceItem {
    let confidence = nis2_status_to_confidence(a.status);
    let gaps = if a.status == crate::nis2::Nis2ComplianceStatus::NotImplemented {
        vec![format!("{}: No Vellaveto evidence available", a.title)]
    } else if a.status == crate::nis2::Nis2ComplianceStatus::Partial {
        vec![format!(
            "{}: Partial coverage — additional evidence may be needed",
            a.title
        )]
    } else {
        vec![]
    };
    EvidenceItem {
        requirement_id: a.article_id.0.clone(),
        requirement_title: a.title.clone(),
        article_ref: a.article_id.0.clone(),
        vellaveto_capability: a
            .capabilities
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        evidence_description: a.evidence.clone(),
        confidence,
        gaps,
    }
}

fn nis2_status_to_confidence(status: crate::nis2::Nis2ComplianceStatus) -> EvidenceConfidence {
    match status {
        crate::nis2::Nis2ComplianceStatus::Compliant => EvidenceConfidence::High,
        crate::nis2::Nis2ComplianceStatus::Partial => EvidenceConfidence::Medium,
        crate::nis2::Nis2ComplianceStatus::NotImplemented => EvidenceConfidence::None,
    }
}

// ── ISO 42001 Pack ───────────────────────────────────────────────────────────

fn generate_iso42001_pack(org: &str, sys_id: &str) -> EvidencePack {
    let registry = crate::iso42001::Iso42001Registry::new();
    let report = registry.generate_report(org, sys_id);

    // Group assessments by clause major number
    let mut grouped: std::collections::BTreeMap<u8, Vec<EvidenceItem>> =
        std::collections::BTreeMap::new();
    for a in &report.assessments {
        let clause_major = a
            .clause_id
            .split('.')
            .next()
            .and_then(|s| s.parse::<u8>().ok())
            .unwrap_or(0);
        let confidence = iso42001_status_to_confidence(a.status);
        let gaps = if a.status == crate::iso42001::ComplianceStatus::NotImplemented {
            vec![format!(
                "Clause {}: No Vellaveto evidence available",
                a.clause_id
            )]
        } else if a.status == crate::iso42001::ComplianceStatus::Partial {
            vec![format!("Clause {}: Partial coverage", a.clause_id)]
        } else {
            vec![]
        };
        let item = EvidenceItem {
            requirement_id: a.clause_id.clone(),
            requirement_title: a.title.clone(),
            article_ref: format!("ISO 42001 Clause {}", a.clause_id),
            vellaveto_capability: a
                .capabilities
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            evidence_description: a.evidence.join("; "),
            confidence,
            gaps,
        };
        grouped.entry(clause_major).or_default().push(item);
    }

    let clause_titles: std::collections::HashMap<u8, (&str, &str)> = [
        (4, ("Clause 4: Context of the Organization", "Understanding the organization, interested parties, scope, and AI management system")),
        (5, ("Clause 5: Leadership", "Leadership commitment, AI policy, roles and responsibilities")),
        (6, ("Clause 6: Planning", "Risk assessment, risk treatment, AI objectives")),
        (7, ("Clause 7: Support", "Resources, communication, documented information")),
        (8, ("Clause 8: Operation", "Operational planning, risk assessment execution, impact assessment")),
        (9, ("Clause 9: Performance Evaluation", "Monitoring, measurement, internal audit, management review")),
        (10, ("Clause 10: Improvement", "Continual improvement, nonconformity and corrective action")),
    ].into_iter().collect();

    let sections: Vec<EvidenceSection> = grouped
        .into_iter()
        .map(|(major, items)| {
            let (title, desc) = clause_titles
                .get(&major)
                .copied()
                .unwrap_or(("Other Clauses", "Additional clause requirements"));
            make_section(&format!("clause-{major}"), title, desc, items)
        })
        .collect();

    let confidences: Vec<EvidenceConfidence> = report
        .assessments
        .iter()
        .map(|a| iso42001_status_to_confidence(a.status))
        .collect();

    build_pack(
        EvidenceFramework::Iso42001,
        "ISO/IEC 42001 AI Management System",
        org,
        sys_id,
        sections,
        &confidences,
    )
}

fn iso42001_status_to_confidence(status: crate::iso42001::ComplianceStatus) -> EvidenceConfidence {
    match status {
        crate::iso42001::ComplianceStatus::Compliant => EvidenceConfidence::High,
        crate::iso42001::ComplianceStatus::Partial => EvidenceConfidence::Medium,
        crate::iso42001::ComplianceStatus::NotImplemented => EvidenceConfidence::None,
    }
}

// ── EU AI Act Pack ───────────────────────────────────────────────────────────

fn generate_eu_ai_act_pack(org: &str, sys_id: &str) -> EvidencePack {
    let registry = crate::eu_ai_act::EuAiActRegistry::new();
    let report =
        registry.generate_assessment(vellaveto_types::AiActRiskClass::HighRisk, org, sys_id);

    // Group by article range
    let mut risk_mgmt = Vec::new(); // Art 9
    let mut data_governance = Vec::new(); // Art 10
    let mut record_keeping = Vec::new(); // Art 12
    let mut transparency = Vec::new(); // Art 13, 50
    let mut oversight = Vec::new(); // Art 14
    let mut other = Vec::new();

    for a in &report.assessments {
        let art_num = extract_article_number(&a.article_id);
        let confidence = eu_ai_act_status_to_confidence(a.status);
        let gaps = if a.status == crate::eu_ai_act::ComplianceStatus::NotImplemented {
            vec![format!("{}: No evidence", a.title)]
        } else if a.status == crate::eu_ai_act::ComplianceStatus::Partial {
            vec![format!("{}: Partial coverage", a.title)]
        } else {
            vec![]
        };
        let item = EvidenceItem {
            requirement_id: a.article_id.clone(),
            requirement_title: a.title.clone(),
            article_ref: a.article_id.clone(),
            vellaveto_capability: a
                .capabilities
                .iter()
                .map(|c| format!("{c:?}"))
                .collect::<Vec<_>>()
                .join(", "),
            evidence_description: a.evidence.join("; "),
            confidence,
            gaps,
        };
        match art_num {
            9 => risk_mgmt.push(item),
            10 => data_governance.push(item),
            12 => record_keeping.push(item),
            13 | 50 => transparency.push(item),
            14 => oversight.push(item),
            _ => other.push(item),
        }
    }

    let mut sections = Vec::new();
    if !risk_mgmt.is_empty() {
        sections.push(make_section(
            "risk-management",
            "Art 9: Risk Management System",
            "Risk identification, mitigation, and monitoring",
            risk_mgmt,
        ));
    }
    if !data_governance.is_empty() {
        sections.push(make_section(
            "data-governance",
            "Art 10: Data Governance",
            "Data quality, training data, and bias mitigation",
            data_governance,
        ));
    }
    if !record_keeping.is_empty() {
        sections.push(make_section(
            "record-keeping",
            "Art 12: Record-Keeping",
            "Automatic logging and audit trail capabilities",
            record_keeping,
        ));
    }
    if !transparency.is_empty() {
        sections.push(make_section(
            "transparency",
            "Art 13 & 50: Transparency",
            "Transparency obligations and AI content marking",
            transparency,
        ));
    }
    if !oversight.is_empty() {
        sections.push(make_section(
            "human-oversight",
            "Art 14: Human Oversight",
            "Human oversight measures and intervention capabilities",
            oversight,
        ));
    }
    if !other.is_empty() {
        sections.push(make_section(
            "other-articles",
            "Other Articles",
            "Additional EU AI Act requirements",
            other,
        ));
    }

    let confidences: Vec<EvidenceConfidence> = report
        .assessments
        .iter()
        .map(|a| eu_ai_act_status_to_confidence(a.status))
        .collect();

    build_pack(
        EvidenceFramework::EuAiAct,
        "EU Artificial Intelligence Act",
        org,
        sys_id,
        sections,
        &confidences,
    )
}

fn eu_ai_act_status_to_confidence(
    status: crate::eu_ai_act::ComplianceStatus,
) -> EvidenceConfidence {
    match status {
        crate::eu_ai_act::ComplianceStatus::Compliant => EvidenceConfidence::High,
        crate::eu_ai_act::ComplianceStatus::Partial => EvidenceConfidence::Medium,
        crate::eu_ai_act::ComplianceStatus::NotImplemented => EvidenceConfidence::None,
        crate::eu_ai_act::ComplianceStatus::NotApplicable => EvidenceConfidence::Full,
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Extract the numeric article number from a string like "Art 5", "Art 21.2.a".
fn extract_article_number(s: &str) -> u32 {
    let stripped = s.strip_prefix("Art ").unwrap_or(s);
    stripped
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

/// Build an `EvidenceSection` from items, computing coverage percent.
fn make_section(
    id: &str,
    title: &str,
    description: &str,
    items: Vec<EvidenceItem>,
) -> EvidenceSection {
    let total = items.len();
    let covered = items
        .iter()
        .filter(|i| i.confidence >= EvidenceConfidence::High)
        .count();
    let partial = items
        .iter()
        .filter(|i| {
            i.confidence == EvidenceConfidence::Medium || i.confidence == EvidenceConfidence::Low
        })
        .count();
    let pct = if total > 0 {
        ((covered as f32 + partial as f32 * 0.5) / total as f32) * 100.0
    } else {
        0.0
    };

    EvidenceSection {
        section_id: id.to_string(),
        title: title.to_string(),
        description: description.to_string(),
        items,
        section_coverage_percent: pct,
    }
}

/// Build an `EvidencePack` from sections and a flat list of confidences.
fn build_pack(
    framework: EvidenceFramework,
    framework_name: &str,
    org: &str,
    sys_id: &str,
    sections: Vec<EvidenceSection>,
    confidences: &[EvidenceConfidence],
) -> EvidencePack {
    let total = confidences.len();
    let covered = confidences
        .iter()
        .filter(|c| **c >= EvidenceConfidence::High)
        .count();
    let partial = confidences
        .iter()
        .filter(|c| **c == EvidenceConfidence::Medium || **c == EvidenceConfidence::Low)
        .count();
    let uncovered = total.saturating_sub(covered).saturating_sub(partial);

    let overall_pct = if total > 0 {
        ((covered as f32 + partial as f32 * 0.5) / total as f32) * 100.0
    } else {
        0.0
    };

    let mut critical_gaps = Vec::new();
    let mut recommendations = Vec::new();

    for section in &sections {
        for item in &section.items {
            if item.confidence == EvidenceConfidence::None {
                critical_gaps.push(format!(
                    "{}: {} — no Vellaveto evidence",
                    item.requirement_id, item.requirement_title,
                ));
            }
        }
        if section.section_coverage_percent < 80.0 {
            recommendations.push(format!(
                "Improve {} coverage from {:.0}% to >= 80%",
                section.title, section.section_coverage_percent,
            ));
        }
    }

    if critical_gaps.is_empty() {
        recommendations.push(format!(
            "All {framework} requirements have evidence — maintain through continuous monitoring",
        ));
    }

    EvidencePack {
        framework,
        framework_name: framework_name.to_string(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        organization_name: org.to_string(),
        system_id: sys_id.to_string(),
        period_start: None,
        period_end: None,
        sections,
        overall_coverage_percent: overall_pct,
        total_requirements: total,
        covered_requirements: covered,
        partial_requirements: partial,
        uncovered_requirements: uncovered,
        critical_gaps,
        recommendations,
        signature: None,
        verifying_key: None,
    }
}

/// Sign an evidence pack with Ed25519, setting `signature` and `verifying_key`.
///
/// The signature covers the canonical content hash produced by
/// `EvidencePack::signing_content()`, providing non-repudiation and
/// tamper detection for compliance artifacts.
pub fn sign_evidence_pack(pack: &mut EvidencePack, signing_key: &ed25519_dalek::SigningKey) {
    use ed25519_dalek::Signer;
    let content = pack.signing_content();
    let sig = signing_key.sign(&content);
    pack.signature = Some(hex::encode(sig.to_bytes()));
    pack.verifying_key = Some(hex::encode(signing_key.verifying_key().to_bytes()));
}

/// Verify an evidence pack's Ed25519 signature.
///
/// Returns `Ok(true)` if valid, `Ok(false)` if the signature doesn't match,
/// or `Err` if fields are malformed (missing, wrong length, bad hex).
pub fn verify_evidence_pack_signature(pack: &EvidencePack) -> Result<bool, crate::AuditError> {
    use ed25519_dalek::Verifier;
    let sig_hex = pack.signature.as_deref().ok_or_else(|| {
        crate::AuditError::Validation("evidence pack has no signature".to_string())
    })?;
    let vk_hex = pack.verifying_key.as_deref().ok_or_else(|| {
        crate::AuditError::Validation("evidence pack has no verifying_key".to_string())
    })?;

    let sig_bytes = hex::decode(sig_hex)
        .map_err(|_| crate::AuditError::Validation("invalid signature hex".to_string()))?;
    if sig_bytes.len() != 64 {
        return Err(crate::AuditError::Validation(format!(
            "signature must be 64 bytes, got {}",
            sig_bytes.len()
        )));
    }
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| crate::AuditError::Validation("signature conversion failed".to_string()))?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

    let vk_bytes = hex::decode(vk_hex)
        .map_err(|_| crate::AuditError::Validation("invalid verifying_key hex".to_string()))?;
    if vk_bytes.len() != 32 {
        return Err(crate::AuditError::Validation(format!(
            "verifying_key must be 32 bytes, got {}",
            vk_bytes.len()
        )));
    }
    let vk_array: [u8; 32] = vk_bytes.try_into().map_err(|_| {
        crate::AuditError::Validation("verifying_key conversion failed".to_string())
    })?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&vk_array)
        .map_err(|e| crate::AuditError::Validation(format!("invalid verifying key: {e}")))?;

    // SECURITY (DOC-CRED-2): Try the domain-separated content first, then fall
    // back to the pre-domain-separation form so packs signed before the change
    // keep verifying. Signing always uses the domain-separated form.
    let content = pack.signing_content();
    if verifying_key.verify(&content, &signature).is_ok() {
        return Ok(true);
    }
    let undomained = pack.undomained_signing_content();
    Ok(verifying_key.verify(&undomained, &signature).is_ok())
}

// ── HTML Renderer ────────────────────────────────────────────────────────────

/// Render an evidence pack as self-contained HTML suitable for browser print-to-PDF.
///
/// Reuses `html_escape()` from `access_review.rs` for safe HTML embedding.
pub fn render_evidence_pack_html(pack: &EvidencePack) -> String {
    let mut html = String::with_capacity(16_384);

    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    html.push_str(&format!(
        "<title>{} Compliance Evidence Pack</title>\n",
        crate::access_review::html_escape(&pack.framework_name),
    ));
    html.push_str("<style>\n");
    html.push_str("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 2em; color: #333; }\n");
    html.push_str("h1, h2, h3 { color: #1a1a2e; }\n");
    html.push_str("table { border-collapse: collapse; width: 100%; margin: 1em 0; }\n");
    html.push_str("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n");
    html.push_str("th { background-color: #f4f4f8; }\n");
    html.push_str("tr:nth-child(even) { background-color: #fafafa; }\n");
    html.push_str(
        ".summary { background: #f0f4ff; padding: 1em; border-radius: 6px; margin: 1em 0; }\n",
    );
    html.push_str(".badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }\n");
    html.push_str(".badge-full { background: #d4edda; color: #155724; }\n");
    html.push_str(".badge-high { background: #cce5ff; color: #004085; }\n");
    html.push_str(".badge-medium { background: #fff3cd; color: #856404; }\n");
    html.push_str(".badge-low { background: #ffeeba; color: #856404; }\n");
    html.push_str(".badge-none { background: #f8d7da; color: #721c24; }\n");
    html.push_str(".gaps { margin-top: 2em; } .gaps li { color: #c0392b; }\n");
    html.push_str(".recs { margin-top: 1em; } .recs li { color: #2c3e50; }\n");
    html.push_str(
        "@media print { body { margin: 1cm; } .page-break { page-break-before: always; } }\n",
    );
    html.push_str("</style>\n</head>\n<body>\n");

    let esc = crate::access_review::html_escape;

    // Cover / Header
    html.push_str(&format!(
        "<h1>{} Compliance Evidence Pack</h1>\n",
        esc(&pack.framework_name),
    ));
    html.push_str(&format!(
        "<p><strong>Organization:</strong> {}</p>\n",
        esc(&pack.organization_name),
    ));
    html.push_str(&format!(
        "<p><strong>System ID:</strong> {}</p>\n",
        esc(&pack.system_id),
    ));
    html.push_str(&format!(
        "<p><strong>Generated:</strong> {}</p>\n",
        esc(&pack.generated_at),
    ));
    if let Some(ref start) = pack.period_start {
        html.push_str(&format!(
            "<p><strong>Period:</strong> {} to {}</p>\n",
            esc(start),
            esc(pack.period_end.as_deref().unwrap_or("—")),
        ));
    }

    // Executive Summary
    html.push_str("<div class=\"summary\">\n");
    html.push_str("<h2>Executive Summary</h2>\n");
    html.push_str("<table>\n<tr><th>Metric</th><th>Value</th></tr>\n");
    html.push_str(&format!(
        "<tr><td>Overall Coverage</td><td>{:.1}%</td></tr>\n",
        pack.overall_coverage_percent,
    ));
    html.push_str(&format!(
        "<tr><td>Total Requirements</td><td>{}</td></tr>\n",
        pack.total_requirements,
    ));
    html.push_str(&format!(
        "<tr><td>Fully Covered</td><td>{}</td></tr>\n",
        pack.covered_requirements,
    ));
    html.push_str(&format!(
        "<tr><td>Partially Covered</td><td>{}</td></tr>\n",
        pack.partial_requirements,
    ));
    html.push_str(&format!(
        "<tr><td>Uncovered</td><td>{}</td></tr>\n",
        pack.uncovered_requirements,
    ));
    html.push_str("</table>\n</div>\n");

    // Per-section tables
    for (i, section) in pack.sections.iter().enumerate() {
        if i > 0 {
            html.push_str("<div class=\"page-break\"></div>\n");
        }
        html.push_str(&format!(
            "<h2>{} <small>({:.0}%)</small></h2>\n",
            esc(&section.title),
            section.section_coverage_percent,
        ));
        html.push_str(&format!("<p>{}</p>\n", esc(&section.description)));

        if section.items.is_empty() {
            html.push_str("<p><em>No requirements in this section.</em></p>\n");
            continue;
        }

        html.push_str("<table>\n<tr>");
        html.push_str("<th>Requirement</th><th>Title</th><th>Capability</th><th>Evidence</th><th>Confidence</th>");
        html.push_str("</tr>\n");

        for item in &section.items {
            let badge_class = match item.confidence {
                EvidenceConfidence::Full => "badge-full",
                EvidenceConfidence::High => "badge-high",
                EvidenceConfidence::Medium => "badge-medium",
                EvidenceConfidence::Low => "badge-low",
                EvidenceConfidence::None => "badge-none",
            };
            html.push_str("<tr>");
            html.push_str(&format!("<td>{}</td>", esc(&item.requirement_id)));
            html.push_str(&format!("<td>{}</td>", esc(&item.requirement_title)));
            html.push_str(&format!("<td>{}</td>", esc(&item.vellaveto_capability)));
            html.push_str(&format!("<td>{}</td>", esc(&item.evidence_description)));
            html.push_str(&format!(
                "<td><span class=\"badge {}\">{}</span></td>",
                badge_class,
                esc(&item.confidence.to_string()),
            ));
            html.push_str("</tr>\n");
        }
        html.push_str("</table>\n");
    }

    // Critical Gaps
    if !pack.critical_gaps.is_empty() {
        html.push_str("<div class=\"gaps\">\n");
        html.push_str(&format!(
            "<h2>Critical Gaps ({})</h2>\n<ul>\n",
            pack.critical_gaps.len(),
        ));
        for gap in &pack.critical_gaps {
            html.push_str(&format!("<li>{}</li>\n", esc(gap)));
        }
        html.push_str("</ul>\n</div>\n");
    }

    // Recommendations
    if !pack.recommendations.is_empty() {
        html.push_str("<div class=\"recs\">\n");
        html.push_str("<h2>Recommendations</h2>\n<ol>\n");
        for rec in &pack.recommendations {
            html.push_str(&format!("<li>{}</li>\n", esc(rec)));
        }
        html.push_str("</ol>\n</div>\n");
    }

    html.push_str("</body>\n</html>\n");
    html
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_dora_pack() {
        let pack = generate_evidence_pack(EvidenceFramework::Dora, "Bank", "bank-001");
        assert_eq!(pack.framework, EvidenceFramework::Dora);
        assert!(!pack.sections.is_empty());
        assert!(pack.total_requirements > 0);
        assert!(pack.overall_coverage_percent > 0.0);
        assert!(pack.validate().is_ok());
    }

    #[test]
    fn test_generate_nis2_pack() {
        let pack = generate_evidence_pack(EvidenceFramework::Nis2, "Corp", "corp-001");
        assert_eq!(pack.framework, EvidenceFramework::Nis2);
        assert!(!pack.sections.is_empty());
        assert!(pack.total_requirements > 0);
        assert!(pack.overall_coverage_percent > 0.0);
        assert!(pack.validate().is_ok());
    }

    #[test]
    fn test_generate_iso42001_pack() {
        let pack = generate_evidence_pack(EvidenceFramework::Iso42001, "Acme", "acme-001");
        assert_eq!(pack.framework, EvidenceFramework::Iso42001);
        assert!(!pack.sections.is_empty());
        assert!(pack.total_requirements > 0);
        assert!(pack.validate().is_ok());
    }

    #[test]
    fn test_generate_eu_ai_act_pack() {
        let pack = generate_evidence_pack(EvidenceFramework::EuAiAct, "AI Co", "ai-001");
        assert_eq!(pack.framework, EvidenceFramework::EuAiAct);
        assert!(!pack.sections.is_empty());
        assert!(pack.total_requirements > 0);
        assert!(pack.validate().is_ok());
    }

    #[test]
    fn test_all_packs_have_recommendations() {
        for fw in &[
            EvidenceFramework::Dora,
            EvidenceFramework::Nis2,
            EvidenceFramework::Iso42001,
            EvidenceFramework::EuAiAct,
        ] {
            let pack = generate_evidence_pack(*fw, "Test", "test");
            assert!(
                !pack.recommendations.is_empty(),
                "{fw} pack has no recommendations",
            );
        }
    }

    #[test]
    fn test_coverage_within_range() {
        for fw in &[
            EvidenceFramework::Dora,
            EvidenceFramework::Nis2,
            EvidenceFramework::Iso42001,
            EvidenceFramework::EuAiAct,
        ] {
            let pack = generate_evidence_pack(*fw, "Test", "test");
            assert!(
                pack.overall_coverage_percent >= 0.0 && pack.overall_coverage_percent <= 100.0,
                "{} coverage {:.1}% out of range",
                fw,
                pack.overall_coverage_percent,
            );
        }
    }

    #[test]
    fn test_serde_roundtrip() {
        let pack = generate_evidence_pack(EvidenceFramework::Dora, "Test", "test");
        let json = serde_json::to_string(&pack).expect("serialize");
        let deserialized: EvidencePack = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.framework, pack.framework);
        assert_eq!(deserialized.total_requirements, pack.total_requirements);
    }

    #[test]
    fn test_render_html_contains_framework_name() {
        let pack = generate_evidence_pack(EvidenceFramework::Dora, "Bank AG", "bank-001");
        let html = render_evidence_pack_html(&pack);
        assert!(html.contains("DORA"), "HTML should contain framework name");
        assert!(html.contains("Bank AG"), "HTML should contain org name");
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("</html>"));
    }

    #[test]
    fn test_render_html_escapes_user_content() {
        let pack = generate_evidence_pack(EvidenceFramework::Nis2, "Org<script>", "sys&id");
        let html = render_evidence_pack_html(&pack);
        assert!(!html.contains("<script>"), "HTML should escape script tags");
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("sys&amp;id"));
    }

    #[test]
    fn test_extract_article_number() {
        assert_eq!(extract_article_number("Art 5"), 5);
        assert_eq!(extract_article_number("Art 21.2.a"), 21);
        assert_eq!(extract_article_number("Art 50(1)"), 50);
        assert_eq!(extract_article_number("unknown"), 0);
    }

    // ── Evidence Pack Signing Tests ──────────────────────────────────────

    fn test_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[42u8; 32])
    }

    #[test]
    fn test_sign_verify_evidence_pack_roundtrip() {
        let mut pack = generate_evidence_pack(EvidenceFramework::Dora, "Bank", "bank-001");
        sign_evidence_pack(&mut pack, &test_signing_key());
        assert!(pack.signature.is_some());
        assert!(pack.verifying_key.is_some());
        assert!(pack.validate().is_ok());
        let valid = verify_evidence_pack_signature(&pack).unwrap();
        assert!(valid, "signed evidence pack should verify");
    }

    #[test]
    fn test_verify_evidence_pack_tampered_returns_false() {
        let mut pack = generate_evidence_pack(EvidenceFramework::Nis2, "Corp", "corp-001");
        sign_evidence_pack(&mut pack, &test_signing_key());
        // Tamper with the content
        pack.overall_coverage_percent = 99.9;
        let valid = verify_evidence_pack_signature(&pack).unwrap();
        assert!(!valid, "tampered evidence pack should not verify");
    }

    #[test]
    fn test_verify_evidence_pack_missing_signature_errors() {
        let pack = generate_evidence_pack(EvidenceFramework::Dora, "Bank", "bank-001");
        let result = verify_evidence_pack_signature(&pack);
        assert!(result.is_err(), "missing signature should return error");
    }

    #[test]
    fn test_sign_evidence_pack_sets_verifying_key() {
        let mut pack = generate_evidence_pack(EvidenceFramework::EuAiAct, "AI", "ai-001");
        sign_evidence_pack(&mut pack, &test_signing_key());
        let vk = pack.verifying_key.as_ref().unwrap();
        assert_eq!(vk.len(), 64, "verifying_key should be 64 hex chars");
        let expected_vk = hex::encode(test_signing_key().verifying_key().to_bytes());
        assert_eq!(*vk, expected_vk);
    }

    #[test]
    fn test_evidence_pack_serde_roundtrip_with_signature() {
        let mut pack = generate_evidence_pack(EvidenceFramework::Iso42001, "Acme", "acme-001");
        sign_evidence_pack(&mut pack, &test_signing_key());
        let json = serde_json::to_string(&pack).unwrap();
        let deserialized: EvidencePack = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.signature, pack.signature);
        assert_eq!(deserialized.verifying_key, pack.verifying_key);
        let valid = verify_evidence_pack_signature(&deserialized).unwrap();
        assert!(valid, "deserialized pack should still verify");
    }
}
