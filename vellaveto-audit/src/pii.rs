// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! PII detection and substring redaction for audit log entries.
//!
//! This module provides a configurable PII scanner that detects and redacts
//! sensitive patterns in string values. It uses **substring** replacement
//! (via `regex.replace_all`) rather than whole-value replacement, preserving
//! surrounding context in log entries.

use regex::Regex;

/// A custom PII detection pattern provided by the operator.
///
/// This is the audit-crate's own representation, independent of `vellaveto-config`.
/// Servers map from `vellaveto_config::CustomPiiPattern` when wiring the logger.
#[derive(Debug, Clone)]
pub struct CustomPiiPattern {
    /// Human-readable name for this pattern (used in diagnostics).
    pub name: String,
    /// Regex pattern string. Invalid patterns are logged and skipped at startup.
    pub pattern: String,
}

const REDACTED: &str = "[REDACTED]";

/// Maximum regex pattern length to prevent ReDoS via overlength patterns.
const MAX_REGEX_LEN: usize = 1024;

/// Validate a regex pattern for ReDoS safety.
///
/// Rejects patterns that are too long (>1024 chars) or contain nested
/// quantifiers like `(a+)+`, `(a*)*`, `(a+)*`, `(a*)+` which can cause
/// exponential backtracking in regex engines. Also rejects unbounded
/// repetition `{n,}` inside groups that have outer quantifiers.
///
/// Note: The `regex` crate uses a finite automaton engine that is immune
/// to catastrophic backtracking for most patterns. This validation is
/// defense-in-depth for patterns that may be used with other engines or
/// future regex implementations.
///
/// # Known Limitation: Flat Boolean Tracking (FIND-R110-AUD-001)
///
/// The `has_inner_quantifier` flag is reset on every `(` token. This means
/// patterns with multiple nested groups lose the outer group's quantifier
/// context when the inner group is entered. For example, the pattern
/// `(a+b(c)d)+` is a **false negative**: the outer group `(a+b...d)+` has
/// an inner quantifier (`+` on `a`), but when `(c)` is parsed, the flag is
/// reset to `false`, so the outer group's quantifier is no longer detected.
///
/// Fixing this correctly would require a stack-based paren-depth tracker.
/// Given that the `regex` crate's DFA engine prevents actual catastrophic
/// backtracking regardless of pattern structure, this false-negative only
/// affects defense-in-depth rather than real ReDoS risk.
pub fn validate_regex_safety(pattern: &str) -> Result<(), String> {
    if pattern.len() > MAX_REGEX_LEN {
        return Err(format!(
            "Regex pattern exceeds maximum length of {} chars ({} chars)",
            MAX_REGEX_LEN,
            pattern.len()
        ));
    }

    // Detect nested quantifiers: a quantifier applied to a group that
    // itself contains a quantifier. Simplified check for common patterns.
    let quantifiers = ['+', '*'];
    let mut paren_depth = 0i32;
    let mut has_inner_quantifier = false;
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] == '\\' {
            // Skip escaped character (both the backslash AND the next char)
            i += 2;
            continue;
        }
        match chars[i] {
            '(' => {
                paren_depth += 1;
                has_inner_quantifier = false;
            }
            ')' => {
                paren_depth = (paren_depth - 1).max(0);
                // Check if the next char is a quantifier
                if i + 1 < chars.len()
                    && (quantifiers.contains(&chars[i + 1]) || chars[i + 1] == '{')
                    && has_inner_quantifier
                {
                    return Err(format!(
                        "Regex pattern contains nested quantifiers (potential ReDoS): '{}'",
                        &pattern[..pattern.len().min(100)]
                    ));
                }
            }
            c if quantifiers.contains(&c) && paren_depth > 0 => {
                has_inner_quantifier = true;
            }
            '{' if paren_depth > 0 => {
                // Check for unbounded repetition like {5,} inside a group
                // (bounded {5,10} is fine)
                let rest: String = chars[i..].iter().collect();
                if let Some(end) = rest.find('}') {
                    let spec = &rest[1..end];
                    if spec.ends_with(',')
                        || (spec.contains(',') && {
                            let parts: Vec<&str> = spec.split(',').collect();
                            parts.len() == 2 && parts[1].is_empty()
                        })
                    {
                        has_inner_quantifier = true;
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }

    // SECURITY (R26-ENG-6): Reject trailing backslash (incomplete escape sequence).
    // While Regex::new() would also reject this, catching it early provides a
    // clearer error message and consistent validation behavior.
    // Count trailing backslashes: odd count means incomplete escape.
    let trailing_bs = chars.iter().rev().take_while(|&&c| c == '\\').count();
    if trailing_bs % 2 == 1 {
        return Err(format!(
            "Regex pattern ends with incomplete escape sequence: '{}'",
            &pattern[..pattern.len().min(100)]
        ));
    }

    Ok(())
}

/// A named PII regex pattern for built-in detection.
struct NamedPiiRegex {
    name: &'static str,
    regex: Regex,
    /// SECURITY (R21-SUP-1): When true, matches are post-filtered through the
    /// Luhn algorithm. This replaces the fragile magic-number index (`i == 3`)
    /// that would silently break if patterns were reordered.
    luhn_postfilter: bool,
}

/// Default built-in PII detection patterns.
fn default_patterns() -> Vec<NamedPiiRegex> {
    let patterns: &[(&str, &str, bool)] = &[
        (
            "email",
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
            false,
        ),
        ("ssn", r"\b\d{3}-\d{2}-\d{4}\b", false),
        (
            "us_phone",
            r"\b(?:\+1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b",
            false,
        ),
        ("credit_card", r"\b(?:\d[ -]*?){13,19}\b", true),
        (
            "ipv4",
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
            false,
        ),
        (
            "jwt",
            r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
            false,
        ),
        ("aws_key_id", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", false),
        // IPv6, so the documented "IPs" coverage is not IPv4-only. Deliberately
        // narrow: full 8-group form and the common `::`-compressed forms, each
        // needing at least two groups. A permissive IPv6 regex matches things
        // like "1::" inside ordinary text, and over-matching here corrupts
        // messages the user did want sent.
        (
            "ipv6",
            r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*",
            false,
        ),
        // File paths — the case the Consumer Shield documentation is built on,
        // and which nothing matched before.
        //
        // Over-matching is the real risk, not under-matching: a greedy path
        // regex swallows prose containing slashes and mangles text the user
        // intended to send, and a sanitizer that garbles messages gets turned
        // off. Hence at least two segments, so a bare "/tmp" or an "and/or"
        // does not match, and no whitespace inside a path.
        (
            "path",
            // POSIX absolute (/a/b), home-relative (~/a/b), Windows (C:\a\b).
            r"(?:~|/)(?:[A-Za-z0-9._\-]+/)+[A-Za-z0-9._\-]*|\b[A-Za-z]:\\(?:[^\\/:*?<>|\r\n]+\\)+[^\\/:*?<>|\r\n]*",
            false,
        ),
    ];

    patterns
        .iter()
        .filter_map(|(name, pat, luhn)| {
            Regex::new(pat).ok().map(|regex| NamedPiiRegex {
                name,
                regex,
                luhn_postfilter: *luhn,
            })
        })
        .collect()
}

/// Luhn check for credit card validation post-filter.
///
/// Returns true if the digit string passes the Luhn algorithm.
fn luhn_check(digits: &str) -> bool {
    let digits: Vec<u32> = digits
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let mut sum = 0u32;
    let mut double = false;

    for &d in digits.iter().rev() {
        let mut val = d;
        if double {
            val *= 2;
            if val > 9 {
                val -= 9;
            }
        }
        sum += val;
        double = !double;
    }

    sum.is_multiple_of(10)
}

/// A detected PII match with position, text, and category information.
#[derive(Debug, Clone)]
pub struct PiiMatch {
    /// Start byte offset in the input string.
    pub start: usize,
    /// End byte offset in the input string (exclusive).
    pub end: usize,
    /// The matched text.
    pub text: String,
    /// PII category (e.g., "email", "ssn", "credit_card").
    pub category: String,
}

/// Configurable PII scanner with both built-in and custom patterns.
///
/// Constructed once at startup with optional custom patterns. Invalid custom
/// regex patterns are logged and skipped rather than causing a panic.
pub struct PiiScanner {
    default_patterns: Vec<NamedPiiRegex>,
    custom_patterns: Vec<(String, Regex)>,
}

impl PiiScanner {
    /// Create a new PII scanner with default patterns plus optional custom ones.
    ///
    /// Invalid custom patterns and patterns that fail ReDoS safety validation
    /// are logged via `tracing::warn!` and skipped.
    pub fn new(custom: &[CustomPiiPattern]) -> Self {
        let mut custom_patterns = Vec::new();
        for pat in custom {
            // R2-3: Validate for ReDoS before compiling
            if let Err(reason) = validate_regex_safety(&pat.pattern) {
                tracing::warn!(
                    "Skipping unsafe custom PII pattern '{}': {}",
                    pat.name,
                    reason
                );
                continue;
            }
            match Regex::new(&pat.pattern) {
                Ok(re) => {
                    custom_patterns.push((pat.name.clone(), re));
                }
                Err(e) => {
                    tracing::warn!("Skipping invalid custom PII pattern '{}': {}", pat.name, e);
                }
            }
        }
        Self {
            default_patterns: default_patterns(),
            custom_patterns,
        }
    }

    /// Redact PII patterns in a string using substring replacement.
    ///
    /// Returns the input with all PII matches replaced by `[REDACTED]`.
    /// For credit card patterns, a Luhn check post-filter is applied.
    pub fn redact_string(&self, input: &str) -> String {
        let mut result = input.to_string();

        for named in &self.default_patterns {
            if named.luhn_postfilter {
                // Credit card pattern — apply Luhn post-filter
                result = named
                    .regex
                    .replace_all(&result, |caps: &regex::Captures| {
                        let matched = caps.get(0).map(|m| m.as_str()).unwrap_or("");
                        if luhn_check(matched) {
                            REDACTED.to_string()
                        } else {
                            matched.to_string()
                        }
                    })
                    .to_string();
            } else {
                result = named.regex.replace_all(&result, REDACTED).to_string();
            }
        }

        for (_, re) in &self.custom_patterns {
            result = re.replace_all(&result, REDACTED).to_string();
        }

        result
    }

    /// Find all PII matches in the input, returning spans with categories.
    ///
    /// Results are sorted by position (start byte offset) and are guaranteed
    /// **non-overlapping**. For credit card patterns, a Luhn check post-filter
    /// is applied — only valid card numbers are included.
    ///
    /// # Overlap resolution
    ///
    /// Several patterns can match the same text: a file path can contain an IP
    /// address, and a custom pattern can duplicate a built-in one. Callers
    /// substitute matches by walking spans in order, so overlapping spans are
    /// not merely redundant — they are unusable. `QuerySanitizer::sanitize`
    /// slices `input[last_end..m.start]`, which panics outright when a later
    /// match starts before the previous one ended.
    ///
    /// Overlaps are therefore resolved here rather than left to each caller:
    /// the longest match at the earliest position wins, since the longer span
    /// is the more specific reading (a whole path rather than the IP inside
    /// it), and it redacts strictly more. Ties break on category name so the
    /// result is deterministic regardless of pattern registration order.
    pub fn find_matches(&self, input: &str) -> Vec<PiiMatch> {
        let mut matches = Vec::new();

        for named in &self.default_patterns {
            for m in named.regex.find_iter(input) {
                if named.luhn_postfilter && !luhn_check(m.as_str()) {
                    continue;
                }
                matches.push(PiiMatch {
                    start: m.start(),
                    end: m.end(),
                    text: m.as_str().to_string(),
                    category: named.name.to_string(),
                });
            }
        }

        for (name, re) in &self.custom_patterns {
            for m in re.find_iter(input) {
                matches.push(PiiMatch {
                    start: m.start(),
                    end: m.end(),
                    text: m.as_str().to_string(),
                    category: name.clone(),
                });
            }
        }

        // Earliest start first; at the same start, longest span first; then
        // category name so equal spans resolve deterministically.
        matches.sort_by(|a, b| {
            a.start
                .cmp(&b.start)
                .then((b.end - b.start).cmp(&(a.end - a.start)))
                .then(a.category.cmp(&b.category))
        });

        // Greedily keep non-overlapping matches. Because the list is ordered
        // longest-first at each start, the first match kept at any position is
        // the most specific one available there.
        let mut deduped: Vec<PiiMatch> = Vec::with_capacity(matches.len());
        let mut next_free = 0usize;
        for m in matches {
            if m.start >= next_free {
                next_free = m.end;
                deduped.push(m);
            }
        }
        deduped
    }

    /// Check if any PII pattern matches the input string.
    pub fn has_pii(&self, input: &str) -> bool {
        for named in &self.default_patterns {
            if named.luhn_postfilter {
                // Credit card: needs Luhn check
                if named
                    .regex
                    .find(input)
                    .is_some_and(|m| luhn_check(m.as_str()))
                {
                    return true;
                }
            } else if named.regex.is_match(input) {
                return true;
            }
        }
        for (_, re) in &self.custom_patterns {
            if re.is_match(input) {
                return true;
            }
        }
        false
    }
}

impl Default for PiiScanner {
    fn default() -> Self {
        Self::new(&[])
    }
}

impl std::fmt::Debug for PiiScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PiiScanner")
            .field("default_patterns", &self.default_patterns.len())
            .field("custom_patterns", &self.custom_patterns.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scanner() -> PiiScanner {
        PiiScanner::default()
    }

    #[test]
    fn test_email_detected() {
        let s = scanner();
        assert_eq!(
            s.redact_string("Contact user@example.com for details"),
            "Contact [REDACTED] for details"
        );
    }

    #[test]
    fn test_ssn_detected() {
        let s = scanner();
        assert_eq!(s.redact_string("SSN is 123-45-6789"), "SSN is [REDACTED]");
    }

    #[test]
    fn test_phone_detected() {
        let s = scanner();
        assert_eq!(s.redact_string("Call 555-123-4567"), "Call [REDACTED]");
    }

    #[test]
    fn test_credit_card_valid_luhn() {
        let s = scanner();
        // 4111 1111 1111 1111 passes Luhn
        let result = s.redact_string("Card: 4111111111111111");
        assert!(
            result.contains(REDACTED),
            "Valid CC should be redacted: {result}"
        );
    }

    #[test]
    fn test_credit_card_invalid_luhn_not_redacted() {
        let s = scanner();
        // 1234567890123456 does NOT pass Luhn
        let result = s.redact_string("Ref: 1234567890123456");
        // With invalid Luhn, the number should NOT be redacted
        assert!(
            !result.contains(REDACTED) || result.contains("1234567890123456"),
            "Invalid Luhn CC should not be redacted: {result}"
        );
    }

    #[test]
    fn test_ipv4_detected() {
        let s = scanner();
        assert_eq!(
            s.redact_string("Server at 192.168.1.100"),
            "Server at [REDACTED]"
        );
    }

    #[test]
    fn test_jwt_detected() {
        let s = scanner();
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123_def";
        let result = s.redact_string(&format!("Token: {jwt}"));
        assert!(
            result.contains(REDACTED),
            "JWT should be redacted: {result}"
        );
    }

    #[test]
    fn test_aws_key_id_detected() {
        let s = scanner();
        assert_eq!(
            s.redact_string("Key: AKIAIOSFODNN7EXAMPLE"),
            "Key: [REDACTED]"
        );
    }

    #[test]
    fn test_substring_redaction_mixed_text() {
        let s = scanner();
        let result = s.redact_string("Email user@example.com and SSN 123-45-6789 are here");
        assert_eq!(result, "Email [REDACTED] and SSN [REDACTED] are here");
    }

    #[test]
    fn test_custom_pattern_applied() {
        let custom = vec![CustomPiiPattern {
            name: "employee_id".to_string(),
            pattern: r"EMP-\d{6}".to_string(),
        }];
        let s = PiiScanner::new(&custom);
        assert_eq!(
            s.redact_string("Employee EMP-123456 logged in"),
            "Employee [REDACTED] logged in"
        );
    }

    #[test]
    fn test_invalid_custom_regex_skipped() {
        let custom = vec![CustomPiiPattern {
            name: "bad_pattern".to_string(),
            pattern: r"[invalid(".to_string(),
        }];
        let s = PiiScanner::new(&custom);
        // Should not crash, just skip the invalid pattern
        assert_eq!(s.redact_string("Some text"), "Some text");
    }

    #[test]
    fn test_redaction_idempotent() {
        let s = scanner();
        let input = "Email user@example.com here";
        let once = s.redact_string(input);
        let twice = s.redact_string(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn test_no_pii_unchanged() {
        let s = scanner();
        assert_eq!(
            s.redact_string("Normal text with no PII"),
            "Normal text with no PII"
        );
    }

    #[test]
    fn test_luhn_check_valid() {
        assert!(luhn_check("4111111111111111"));
        assert!(luhn_check("5500000000000004"));
    }

    #[test]
    fn test_luhn_check_invalid() {
        assert!(!luhn_check("1234567890123456"));
        assert!(!luhn_check("1111111111111112"));
    }

    // ── R2-3: ReDoS Protection Tests ──────────────────

    #[test]
    fn test_redos_nested_quantifiers_rejected() {
        let result = validate_regex_safety("(a+)+b");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("nested quantifier"));
    }

    #[test]
    fn test_redos_star_star_rejected() {
        let result = validate_regex_safety("(a*)*");
        assert!(result.is_err());
    }

    #[test]
    fn test_redos_overlength_rejected() {
        let long_pattern = "a".repeat(MAX_REGEX_LEN + 1);
        let result = validate_regex_safety(&long_pattern);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds maximum length"));
    }

    #[test]
    fn test_redos_valid_patterns_accepted() {
        assert!(validate_regex_safety(r"^/[\w/.\-]+$").is_ok());
        assert!(validate_regex_safety(r"[a-z]+").is_ok());
        assert!(validate_regex_safety(r"foo|bar|baz").is_ok());
        assert!(validate_regex_safety(r"(abc)+").is_ok()); // quantifier on group without inner quantifier
        assert!(validate_regex_safety(r"EMP-\d{6}").is_ok());
    }

    #[test]
    fn test_pii_scanner_rejects_redos_custom_pattern() {
        let custom = vec![
            CustomPiiPattern {
                name: "safe_pattern".to_string(),
                pattern: r"EMP-\d{6}".to_string(),
            },
            CustomPiiPattern {
                name: "evil_redos".to_string(),
                pattern: r"(a+)+b".to_string(),
            },
        ];
        let s = PiiScanner::new(&custom);
        // Only the safe pattern should be compiled
        assert_eq!(
            s.custom_patterns.len(),
            1,
            "ReDoS pattern should be rejected"
        );
        assert_eq!(s.custom_patterns[0].0, "safe_pattern");
    }

    #[test]
    fn test_pii_scanner_rejects_overlength_custom_pattern() {
        let custom = vec![CustomPiiPattern {
            name: "too_long".to_string(),
            pattern: "a".repeat(MAX_REGEX_LEN + 1),
        }];
        let s = PiiScanner::new(&custom);
        assert_eq!(
            s.custom_patterns.len(),
            0,
            "Overlength pattern should be rejected"
        );
    }

    #[test]
    fn test_redos_unbounded_repetition_in_group_rejected() {
        // (x{5,})+ has unbounded inner repetition with outer quantifier
        assert!(validate_regex_safety("(x{5,})+").is_err());
    }

    #[test]
    fn test_redos_bounded_repetition_in_group_accepted() {
        // (x{5,10})+ has bounded inner repetition — acceptable
        assert!(validate_regex_safety("(x{5,10})+").is_ok());
    }

    #[test]
    fn test_redos_group_with_curly_outer_quantifier_rejected() {
        // (a+){2,} — nested: inner + and outer {2,}
        assert!(validate_regex_safety("(a+){2,}").is_err());
    }

    #[test]
    fn test_redos_escaped_quantifier_not_flagged() {
        // (\+)+ — the inner + is escaped, so this is safe
        assert!(validate_regex_safety(r"(\+)+").is_ok());
    }

    #[test]
    fn test_redos_escaped_paren_not_counted() {
        // \(a+\)+ — the parens are escaped, not a real group
        assert!(validate_regex_safety(r"\(a+\)+").is_ok());
    }

    #[test]
    fn test_redos_deeply_nested_groups_rejected() {
        // ((a+))+ — nested groups with inner quantifier
        assert!(validate_regex_safety("((a+))+").is_err());
    }

    #[test]
    fn test_redos_trailing_backslash_rejected() {
        // R26-ENG-6: Trailing backslash is an incomplete escape sequence
        assert!(validate_regex_safety(r"abc\").is_err());
        // Double backslash at end is a valid escaped backslash
        assert!(validate_regex_safety(r"abc\\").is_ok());
        // Triple backslash = escaped backslash + trailing backslash
        assert!(validate_regex_safety(r"abc\\\").is_err());
    }

    #[test]
    fn test_has_pii_uses_luhn_for_credit_cards() {
        let s = scanner();
        // Valid Luhn number
        assert!(s.has_pii("4111111111111111"));
        // Invalid Luhn number — should NOT be flagged as PII
        assert!(!s.has_pii("1234567890123456"));
    }

    // ── find_matches tests ──────────────────────────────────────

    #[test]
    fn test_find_matches_email_span() {
        let s = scanner();
        let matches = s.find_matches("Contact user@example.com for info");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].text, "user@example.com");
        assert_eq!(matches[0].category, "email");
        assert_eq!(matches[0].start, 8);
        assert_eq!(matches[0].end, 24);
    }

    #[test]
    fn test_find_matches_multiple_categories() {
        let s = scanner();
        let matches = s.find_matches("Email user@example.com SSN 123-45-6789");
        assert!(matches.len() >= 2);
        let categories: Vec<&str> = matches.iter().map(|m| m.category.as_str()).collect();
        assert!(categories.contains(&"email"));
        assert!(categories.contains(&"ssn"));
    }

    #[test]
    fn test_find_matches_luhn_filter() {
        let s = scanner();
        // Invalid Luhn — should NOT appear in matches
        let matches = s.find_matches("Ref: 1234567890123456");
        let cc_matches: Vec<_> = matches
            .iter()
            .filter(|m| m.category == "credit_card")
            .collect();
        assert!(cc_matches.is_empty(), "Invalid Luhn should be filtered out");

        // Valid Luhn — should appear
        let matches = s.find_matches("Card: 4111111111111111");
        let cc_matches: Vec<_> = matches
            .iter()
            .filter(|m| m.category == "credit_card")
            .collect();
        assert!(!cc_matches.is_empty(), "Valid Luhn should be included");
    }

    // ── File paths: the case the Consumer Shield docs are built on ──────

    fn categories_at(scanner: &PiiScanner, input: &str) -> Vec<String> {
        scanner
            .find_matches(input)
            .into_iter()
            .map(|m| m.category)
            .collect()
    }

    #[test]
    fn test_readme_consumer_shield_example_is_reproducible() {
        // The exact string the README opens the Consumer Shield section with.
        // Before a path pattern existed, this path was sent to the provider
        // verbatim — the outcome that section promises to prevent.
        let scanner = PiiScanner::new(&[]);
        let matches =
            scanner.find_matches("Read my medical records at /home/alice/health/lab-results.pdf");
        assert_eq!(
            matches.len(),
            1,
            "expected exactly the path, got {matches:?}"
        );
        assert_eq!(matches[0].category, "path");
        assert_eq!(matches[0].text, "/home/alice/health/lab-results.pdf");
    }

    #[test]
    fn test_path_variants_are_detected() {
        let scanner = PiiScanner::new(&[]);
        for input in [
            "/home/alice/health/lab-results.pdf",
            "~/Documents/taxes/2025.pdf",
            "/var/log/nginx/access.log",
            r"C:\Users\alice\Documents\notes.txt",
        ] {
            let cats = categories_at(&scanner, input);
            assert!(
                cats.contains(&"path".to_string()),
                "{input} should match the path pattern, got {cats:?}"
            );
        }
    }

    #[test]
    fn test_path_pattern_does_not_swallow_ordinary_text() {
        // Over-matching is the real risk: a sanitizer that mangles ordinary
        // prose gets turned off, which is a security failure, not a cosmetic
        // one. None of these should be treated as a path.
        let scanner = PiiScanner::new(&[]);
        for input in [
            "use and/or as needed",
            "the ratio was 3/4 overall",
            "see /tmp for details",
            "read the file",
            "50/50 split",
        ] {
            let cats = categories_at(&scanner, input);
            assert!(
                !cats.contains(&"path".to_string()),
                "{input:?} must NOT match the path pattern, got {cats:?}"
            );
        }
    }

    // ── IPv6, so the documented "IPs" coverage is honest ────────────────

    #[test]
    fn test_ipv6_is_detected() {
        let scanner = PiiScanner::new(&[]);
        for input in [
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "2001:db8::8a2e:370:7334",
        ] {
            let cats = categories_at(&scanner, input);
            assert!(
                cats.contains(&"ipv6".to_string()),
                "{input} should match ipv6, got {cats:?}"
            );
        }
    }

    #[test]
    fn test_ipv6_pattern_does_not_match_ordinary_text() {
        let scanner = PiiScanner::new(&[]);
        for input in ["meeting at 10:30", "ratio 1:2", "see chapter 3:14"] {
            let cats = categories_at(&scanner, input);
            assert!(
                !cats.contains(&"ipv6".to_string()),
                "{input:?} must NOT match ipv6, got {cats:?}"
            );
        }
    }

    // ── Overlap resolution ──────────────────────────────────────────────

    #[test]
    fn test_matches_never_overlap() {
        // Callers substitute by walking spans in order and slicing
        // input[last_end..m.start]; an overlapping pair makes that a reversed
        // range, which panics. This held before any custom pattern was added
        // and is what makes the guarantee load-bearing rather than tidy.
        let scanner = PiiScanner::new(&[CustomPiiPattern {
            name: "dup".to_string(),
            pattern: r"alice@example\.com".to_string(),
        }]);
        let matches = scanner.find_matches("mail alice@example.com now");
        assert_eq!(
            matches.len(),
            1,
            "duplicate spans must collapse to one, got {matches:?}"
        );

        let mut next_free = 0;
        for m in &matches {
            assert!(m.start >= next_free, "overlapping match: {matches:?}");
            next_free = m.end;
        }
    }

    #[test]
    fn test_path_containing_an_ip_yields_one_match() {
        // A path can contain an IP. The longer, more specific span wins, and
        // the result must still be non-overlapping.
        let scanner = PiiScanner::new(&[]);
        let matches = scanner.find_matches("/var/backups/192.168.1.10/db.sql");
        assert_eq!(matches.len(), 1, "expected one span, got {matches:?}");
        assert_eq!(matches[0].category, "path");
        assert_eq!(matches[0].text, "/var/backups/192.168.1.10/db.sql");
    }

    #[test]
    fn test_overlap_resolution_is_deterministic() {
        // Equal spans from different patterns must resolve the same way every
        // time, regardless of registration order.
        let scanner = PiiScanner::new(&[CustomPiiPattern {
            name: "zzz_dup".to_string(),
            pattern: r"alice@example\.com".to_string(),
        }]);
        let first: Vec<(usize, usize, String)> = scanner
            .find_matches("alice@example.com")
            .into_iter()
            .map(|m| (m.start, m.end, m.category))
            .collect();
        for _ in 0..20 {
            let again: Vec<(usize, usize, String)> = scanner
                .find_matches("alice@example.com")
                .into_iter()
                .map(|m| (m.start, m.end, m.category))
                .collect();
            assert_eq!(again, first);
        }
    }
}
