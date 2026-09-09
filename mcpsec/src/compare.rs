// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//! Baseline comparison — detect score regressions and improvements between runs.

use crate::BenchmarkResult;

/// Difference between a baseline and a new benchmark run.
pub struct ComparisonResult {
    /// Overall score change (positive = improvement).
    pub score_delta: f64,
    /// Tier change (positive = improvement).
    pub tier_delta: i8,
    /// Tests that regressed (passed in baseline, failed in new).
    pub regressions: Vec<TestDelta>,
    /// Tests that improved (failed in baseline, passed in new).
    pub improvements: Vec<TestDelta>,
    /// New tests not present in baseline.
    pub new_tests: Vec<String>,
    /// Tests removed from baseline (present in baseline, absent in new).
    pub removed_tests: Vec<String>,
}

/// A single test that changed status between runs.
pub struct TestDelta {
    pub attack_id: String,
    pub name: String,
    pub class: String,
}

/// Compare a new result against a baseline.
pub fn compare(baseline: &BenchmarkResult, current: &BenchmarkResult) -> ComparisonResult {
    let score_delta = current.overall_score - baseline.overall_score;
    let tier_delta = current.tier as i8 - baseline.tier as i8;

    let mut regressions = Vec::new();
    let mut improvements = Vec::new();
    let mut new_tests = Vec::new();
    let mut removed_tests = Vec::new();

    // Index baseline by attack_id
    let baseline_map: std::collections::HashMap<&str, bool> = baseline
        .attacks
        .iter()
        .map(|a| (a.attack_id.as_str(), a.passed))
        .collect();

    let current_map: std::collections::HashMap<&str, bool> = current
        .attacks
        .iter()
        .map(|a| (a.attack_id.as_str(), a.passed))
        .collect();

    // Find regressions, improvements, and new tests
    for attack in &current.attacks {
        match baseline_map.get(attack.attack_id.as_str()) {
            Some(&baseline_passed) => {
                if baseline_passed && !attack.passed {
                    regressions.push(TestDelta {
                        attack_id: attack.attack_id.clone(),
                        name: attack.name.clone(),
                        class: attack.class.clone(),
                    });
                } else if !baseline_passed && attack.passed {
                    improvements.push(TestDelta {
                        attack_id: attack.attack_id.clone(),
                        name: attack.name.clone(),
                        class: attack.class.clone(),
                    });
                }
            }
            None => {
                new_tests.push(attack.attack_id.clone());
            }
        }
    }

    // Find removed tests
    for attack in &baseline.attacks {
        if !current_map.contains_key(attack.attack_id.as_str()) {
            removed_tests.push(attack.attack_id.clone());
        }
    }

    ComparisonResult {
        score_delta,
        tier_delta,
        regressions,
        improvements,
        new_tests,
        removed_tests,
    }
}

/// Format a comparison result as a human-readable string.
pub fn format_comparison(cmp: &ComparisonResult) -> String {
    let mut out = String::new();

    // Score delta
    let arrow = if cmp.score_delta > 0.0 { "+" } else { "" };
    out.push_str(&format!("Score: {arrow}{:.1}%", cmp.score_delta));
    if cmp.tier_delta != 0 {
        let tier_arrow = if cmp.tier_delta > 0 { "+" } else { "" };
        out.push_str(&format!(" (tier {tier_arrow}{})", cmp.tier_delta));
    }
    out.push('\n');

    // Regressions
    if !cmp.regressions.is_empty() {
        out.push_str(&format!("\nRegressions ({}):\n", cmp.regressions.len()));
        for r in &cmp.regressions {
            out.push_str(&format!(
                "  REGRESSED  {} — {} ({})\n",
                r.attack_id, r.name, r.class
            ));
        }
    }

    // Improvements
    if !cmp.improvements.is_empty() {
        out.push_str(&format!("\nImprovements ({}):\n", cmp.improvements.len()));
        for i in &cmp.improvements {
            out.push_str(&format!(
                "  FIXED      {} — {} ({})\n",
                i.attack_id, i.name, i.class
            ));
        }
    }

    // New tests
    if !cmp.new_tests.is_empty() {
        out.push_str(&format!(
            "\nNew tests ({}): {}\n",
            cmp.new_tests.len(),
            cmp.new_tests.join(", ")
        ));
    }

    // Removed tests
    if !cmp.removed_tests.is_empty() {
        out.push_str(&format!(
            "\nRemoved tests ({}): {}\n",
            cmp.removed_tests.len(),
            cmp.removed_tests.join(", ")
        ));
    }

    if cmp.regressions.is_empty() && cmp.improvements.is_empty() && cmp.score_delta.abs() < 0.01 {
        out.push_str("\nNo changes detected.\n");
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttackResult, BenchmarkResult, BenchmarkSummary};

    fn make_result(
        attacks: Vec<(&str, &str, &str, bool)>,
        score: f64,
        tier: u8,
    ) -> BenchmarkResult {
        let attack_results: Vec<AttackResult> = attacks
            .iter()
            .map(|(id, name, class, passed)| AttackResult {
                attack_id: id.to_string(),
                name: name.to_string(),
                class: class.to_string(),
                passed: *passed,
                latency_ns: 0,
                details: String::new(),
            })
            .collect();
        let passed = attack_results.iter().filter(|a| a.passed).count();
        let total = attack_results.len();
        BenchmarkResult {
            framework: "MCPSEC".to_string(),
            version: "1.1.0".to_string(),
            timestamp: String::new(),
            gateway: "test".to_string(),
            gateway_version: String::new(),
            overall_score: score,
            availability_score: 100.0,
            tier,
            tier_name: String::new(),
            properties: vec![],
            attacks: attack_results,
            summary: BenchmarkSummary {
                total_tests: total,
                passed,
                failed: total - passed,
                skipped: 0,
            },
        }
    }

    #[test]
    fn test_compare_no_changes() {
        let a = make_result(
            vec![
                ("A1.1", "Test", "Class", true),
                ("A1.2", "Test2", "Class", false),
            ],
            50.0,
            2,
        );
        let b = make_result(
            vec![
                ("A1.1", "Test", "Class", true),
                ("A1.2", "Test2", "Class", false),
            ],
            50.0,
            2,
        );
        let cmp = compare(&a, &b);
        assert!(cmp.regressions.is_empty());
        assert!(cmp.improvements.is_empty());
        assert!(cmp.score_delta.abs() < 0.01);
        assert_eq!(cmp.tier_delta, 0);
    }

    #[test]
    fn test_compare_regression() {
        let baseline = make_result(
            vec![
                ("A1.1", "Test", "Class", true),
                ("A1.2", "Test2", "Class", true),
            ],
            100.0,
            5,
        );
        let current = make_result(
            vec![
                ("A1.1", "Test", "Class", true),
                ("A1.2", "Test2", "Class", false),
            ],
            50.0,
            2,
        );
        let cmp = compare(&baseline, &current);
        assert_eq!(cmp.regressions.len(), 1);
        assert_eq!(cmp.regressions[0].attack_id, "A1.2");
        assert!(cmp.improvements.is_empty());
        assert!(cmp.score_delta < 0.0);
        assert!(cmp.tier_delta < 0);
    }

    #[test]
    fn test_compare_improvement() {
        let baseline = make_result(vec![("A1.1", "Test", "Class", false)], 0.0, 0);
        let current = make_result(vec![("A1.1", "Test", "Class", true)], 100.0, 5);
        let cmp = compare(&baseline, &current);
        assert!(cmp.regressions.is_empty());
        assert_eq!(cmp.improvements.len(), 1);
        assert_eq!(cmp.improvements[0].attack_id, "A1.1");
    }

    #[test]
    fn test_compare_new_and_removed_tests() {
        let baseline = make_result(
            vec![
                ("A1.1", "Test", "Class", true),
                ("A1.2", "Old", "Class", true),
            ],
            100.0,
            5,
        );
        let current = make_result(
            vec![
                ("A1.1", "Test", "Class", true),
                ("A1.3", "New", "Class", true),
            ],
            100.0,
            5,
        );
        let cmp = compare(&baseline, &current);
        assert_eq!(cmp.new_tests, vec!["A1.3"]);
        assert_eq!(cmp.removed_tests, vec!["A1.2"]);
    }

    #[test]
    fn test_format_comparison_output() {
        let baseline = make_result(
            vec![
                ("A1.1", "Test", "Injection", true),
                ("A1.2", "Test2", "Injection", false),
            ],
            50.0,
            2,
        );
        let current = make_result(
            vec![
                ("A1.1", "Test", "Injection", false),
                ("A1.2", "Test2", "Injection", true),
                ("A1.3", "New", "Injection", true),
            ],
            75.0,
            3,
        );
        let cmp = compare(&baseline, &current);
        let output = format_comparison(&cmp);
        assert!(output.contains("+25.0%"));
        assert!(output.contains("tier +1"));
        assert!(output.contains("REGRESSED"));
        assert!(output.contains("FIXED"));
        assert!(output.contains("A1.3"));
    }
}
