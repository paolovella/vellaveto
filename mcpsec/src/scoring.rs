// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//! Score calculation from attack results.

use crate::{AttackResult, PropertyScore};

/// Property weights (must sum to 1.0).
const PROPERTY_WEIGHTS: [(&str, f64); 10] = [
    ("P1", 0.15),  // Tool-Level Access Control
    ("P2", 0.12),  // Parameter Constraint Enforcement
    ("P3", 0.05),  // Priority Monotonicity
    ("P4", 0.15),  // Injection Resistance
    ("P5", 0.10),  // Schema Integrity
    ("P6", 0.12),  // Response Confidentiality
    ("P7", 0.10),  // Audit Immutability
    ("P8", 0.08),  // Delegation Monotonicity
    ("P9", 0.08),  // Unicode Normalization
    ("P10", 0.05), // Temporal Consistency
];

const PROPERTY_NAMES: [(&str, &str); 10] = [
    ("P1", "Tool-Level Access Control"),
    ("P2", "Parameter Constraint Enforcement"),
    ("P3", "Priority Monotonicity"),
    ("P4", "Injection Resistance"),
    ("P5", "Schema Integrity"),
    ("P6", "Response Confidentiality"),
    ("P7", "Audit Immutability"),
    ("P8", "Delegation Monotonicity"),
    ("P9", "Unicode Normalization"),
    ("P10", "Temporal Consistency"),
];

/// Mapping from attack IDs to the properties they test.
fn attack_to_properties(attack_id: &str) -> Vec<&'static str> {
    let prefix = attack_id.split('.').next().unwrap_or(attack_id);
    match prefix {
        "A1" => vec!["P4", "P9"],
        "A2" => vec!["P5"],
        "A3" => vec!["P1", "P2"],
        "A4" => vec!["P6"],
        "A5" => {
            // More granular mapping within A5
            match attack_id {
                "A5.1" => vec!["P1"],
                "A5.2" | "A5.3" | "A5.6" => vec!["P3"],
                "A5.4" => vec!["P8"],
                "A5.5" => vec!["P1", "P2"],
                "A5.7" | "A5.8" | "A5.9" | "A5.10" => vec!["P8"],
                _ => vec!["P1", "P3", "P8"],
            }
        }
        "A6" => vec!["P4", "P6"],
        "A7" => vec!["P5", "P9"],
        "A8" => vec!["P7"],
        "A9" => vec!["P2"],
        "A10" => vec!["P10"],
        "A11" => vec!["P2", "P6"],
        "A12" => vec!["P1", "P4"],
        "A13" => vec!["P6"],
        "A14" => vec!["P5"],
        "A15" => vec!["P1", "P9"],
        "A16" => vec!["P10"],
        // A17 is Legitimate Traffic Preservation. It is deliberately mapped to
        // NO property: it is scored on its own availability axis so it can
        // neither perturb the P1-P10 security score nor be averaged away by it.
        "A17" => vec![],
        _ => vec![],
    }
}

/// Calculate per-property scores from attack results.
pub fn calculate_property_scores(attacks: &[AttackResult]) -> Vec<PropertyScore> {
    PROPERTY_NAMES
        .iter()
        .map(|(pid, name)| {
            let mut passed = 0usize;
            let mut total = 0usize;

            for attack in attacks {
                let props = attack_to_properties(&attack.attack_id);
                if props.contains(pid) {
                    total += 1;
                    if attack.passed {
                        passed += 1;
                    }
                }
            }

            let score = if total > 0 {
                (passed as f64 / total as f64) * 100.0
            } else {
                0.0
            };

            PropertyScore {
                property_id: pid.to_string(),
                name: name.to_string(),
                score,
                tests_passed: passed,
                tests_total: total,
            }
        })
        .collect()
}

/// Calculate overall weighted score from property scores.
pub fn calculate_overall_score(properties: &[PropertyScore]) -> f64 {
    let mut weighted_sum = 0.0;

    for (pid, weight) in &PROPERTY_WEIGHTS {
        if let Some(prop) = properties.iter().find(|p| p.property_id == *pid) {
            weighted_sum += prop.score * weight;
        }
    }

    weighted_sum
}

/// Convert overall score to tier (0-5).
pub fn score_to_tier(score: f64) -> u8 {
    match score as u32 {
        0..=19 => 0,
        20..=39 => 1,
        40..=59 => 2,
        60..=79 => 3,
        80..=94 => 4,
        _ => 5,
    }
}

/// Get the name for a tier.
pub fn tier_name(tier: u8) -> &'static str {
    match tier {
        0 => "Unsafe",
        1 => "Basic",
        2 => "Moderate",
        3 => "Strong",
        4 => "Comprehensive",
        _ => "Hardened",
    }
}

/// Percentage of the A17 legitimate-traffic checks that passed (0-100).
///
/// Reported separately from `calculate_overall_score` rather than folded into
/// it. The security properties are weighted to sum to exactly 1.00, so adding
/// an eleventh would rescale all ten and silently move every score ever
/// published, including the reference result — and a blended figure would hide
/// which dimension is weak. "96 security / 0 availability" says something a
/// single number does not.
///
/// Returns 100.0 when no A17 tests ran (e.g. under a class filter), so a
/// filtered run does not report a spurious availability failure.
pub fn calculate_availability_score(attacks: &[AttackResult]) -> f64 {
    let a17: Vec<&AttackResult> = attacks
        .iter()
        .filter(|a| a.attack_id.split('.').next() == Some("A17"))
        .collect();
    if a17.is_empty() {
        return 100.0;
    }
    let passed = a17.iter().filter(|a| a.passed).count();
    (passed as f64 / a17.len() as f64) * 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_score_to_tier() {
        assert_eq!(score_to_tier(0.0), 0);
        assert_eq!(score_to_tier(19.0), 0);
        assert_eq!(score_to_tier(20.0), 1);
        assert_eq!(score_to_tier(39.0), 1);
        assert_eq!(score_to_tier(40.0), 2);
        assert_eq!(score_to_tier(59.0), 2);
        assert_eq!(score_to_tier(60.0), 3);
        assert_eq!(score_to_tier(79.0), 3);
        assert_eq!(score_to_tier(80.0), 4);
        assert_eq!(score_to_tier(94.0), 4);
        assert_eq!(score_to_tier(95.0), 5);
        assert_eq!(score_to_tier(100.0), 5);
    }

    #[test]
    fn test_tier_name() {
        assert_eq!(tier_name(0), "Unsafe");
        assert_eq!(tier_name(1), "Basic");
        assert_eq!(tier_name(2), "Moderate");
        assert_eq!(tier_name(3), "Strong");
        assert_eq!(tier_name(4), "Comprehensive");
        assert_eq!(tier_name(5), "Hardened");
    }

    #[test]
    fn test_weights_sum_to_one() {
        let sum: f64 = PROPERTY_WEIGHTS.iter().map(|(_, w)| w).sum();
        assert!(
            (sum - 1.0).abs() < 0.001,
            "Property weights must sum to 1.0, got {sum}"
        );
    }

    #[test]
    fn test_all_pass_gives_100() {
        let attacks: Vec<AttackResult> = crate::attacks::all_tests()
            .iter()
            .map(|t| AttackResult {
                attack_id: t.id.to_string(),
                name: t.name.to_string(),
                class: t.class.to_string(),
                passed: true,
                latency_ns: 0,
                details: String::new(),
            })
            .collect();

        let props = calculate_property_scores(&attacks);
        let score = calculate_overall_score(&props);
        assert!(
            (score - 100.0).abs() < 0.01,
            "All-pass should give 100%, got {score}"
        );
    }

    #[test]
    fn test_all_fail_gives_zero() {
        let attacks: Vec<AttackResult> = crate::attacks::all_tests()
            .iter()
            .map(|t| AttackResult {
                attack_id: t.id.to_string(),
                name: t.name.to_string(),
                class: t.class.to_string(),
                passed: false,
                latency_ns: 0,
                details: String::new(),
            })
            .collect();

        let props = calculate_property_scores(&attacks);
        let score = calculate_overall_score(&props);
        assert!(score.abs() < 0.01, "All-fail should give 0%, got {score}");
    }
}
