// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! End-to-end check of the Consumer Shield's documented behaviour.
//!
//! README opens the Shield section with a worked example: a file path is
//! replaced before the provider sees it, and restored on the way back. Until
//! a path pattern existed, that example did not happen — the path was sent
//! verbatim. These tests run the documented string through the real sanitizer.

use vellaveto_audit::{CustomPiiPattern, PiiScanner};
use vellaveto_mcp_shield::QuerySanitizer;

const README_INPUT: &str = "Read my medical records at /home/alice/health/lab-results.pdf";
const README_PATH: &str = "/home/alice/health/lab-results.pdf";

#[test]
fn readme_example_sanitizes_and_round_trips() {
    let sanitizer = QuerySanitizer::new(PiiScanner::new(&[]));

    let sanitized = sanitizer.sanitize(README_INPUT).expect("sanitize");
    assert!(
        !sanitized.contains(README_PATH),
        "the provider must not see the path; got: {sanitized}"
    );
    assert!(
        sanitized.contains("[PII_PATH_"),
        "expected a PII_PATH placeholder; got: {sanitized}"
    );
    assert!(
        sanitized.starts_with("Read my medical records at "),
        "surrounding text must survive; got: {sanitized}"
    );

    let restored = sanitizer.desanitize(&sanitized).expect("desanitize");
    assert_eq!(restored, README_INPUT, "the response leg must restore it");
}

#[test]
fn overlapping_patterns_do_not_panic() {
    // A custom pattern duplicating a built-in produces two matches on the same
    // span. The sanitizer walks spans slicing input[last_end..m.start], so
    // before overlap resolution this panicked outright — reachable by any
    // operator adding a custom pattern, which the shipped preset documents.
    let sanitizer = QuerySanitizer::new(PiiScanner::new(&[CustomPiiPattern {
        name: "dup".to_string(),
        pattern: r"alice@example\.com".to_string(),
    }]));

    let sanitized = sanitizer
        .sanitize("mail alice@example.com now")
        .expect("sanitize");
    assert!(!sanitized.contains("alice@example.com"));
    assert_eq!(
        sanitizer.desanitize(&sanitized).expect("desanitize"),
        "mail alice@example.com now"
    );
}

#[test]
fn a_path_containing_an_ip_round_trips_whole() {
    // Path and ipv4 both match here. The longer span wins, and the value must
    // still restore exactly.
    let sanitizer = QuerySanitizer::new(PiiScanner::new(&[]));
    let input = "back up /var/backups/192.168.1.10/db.sql tonight";

    let sanitized = sanitizer.sanitize(input).expect("sanitize");
    assert!(!sanitized.contains("/var/backups/192.168.1.10/db.sql"));
    assert_eq!(sanitizer.desanitize(&sanitized).expect("desanitize"), input);
}

#[test]
fn ordinary_prose_is_left_alone() {
    // A sanitizer that mangles ordinary text gets switched off, which is a
    // security failure rather than a cosmetic one.
    let sanitizer = QuerySanitizer::new(PiiScanner::new(&[]));
    for input in [
        "use and/or as needed",
        "the ratio was 3/4 overall",
        "meeting at 10:30 tomorrow",
        "read the file please",
    ] {
        assert_eq!(
            sanitizer.sanitize(input).expect("sanitize"),
            input,
            "{input:?} should pass through untouched"
        );
    }
}
