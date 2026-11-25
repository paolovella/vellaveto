// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Token/credential leakage detection in tool call parameters.
//!
//! Detects when OAuth tokens, API keys, or other credentials appear
//! in tool call arguments where they shouldn't — indicating either
//! credential stuffing or accidental exposure via LLM hallucination.

/// A token leakage finding.
#[derive(Debug, Clone)]
pub struct TokenLeakageFinding {
    pub token_type: TokenType,
    pub confidence: u32,
    pub location: String,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    /// Bearer/OAuth token.
    BearerToken,
    /// API key pattern.
    ApiKey,
    /// JWT token.
    Jwt,
    /// AWS-style access key.
    AwsAccessKey,
    /// GitHub personal access token.
    GithubPat,
    /// Generic secret/password.
    GenericSecret,
}

/// Scan text for token/credential patterns.
pub fn scan_for_token_leakage(text: &str) -> Vec<TokenLeakageFinding> {
    let mut findings = Vec::new();

    // Bearer tokens
    if let Some(pos) = text.find("Bearer ") {
        let token_start = pos + 7;
        let token = &text[token_start..text.len().min(token_start + 200)];
        let token_end = token
            .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
            .unwrap_or(token.len());
        if token_end > 20 {
            findings.push(TokenLeakageFinding {
                token_type: TokenType::BearerToken,
                confidence: 85,
                location: format!("offset {pos}"),
                description: format!("Bearer token ({token_end} chars)"),
            });
        }
    }

    // API key patterns
    let api_key_prefixes = [
        ("sk-", TokenType::ApiKey, "OpenAI"),
        ("sk-ant-", TokenType::ApiKey, "Anthropic"),
        ("gsk_", TokenType::ApiKey, "Groq"),
        ("xai-", TokenType::ApiKey, "xAI"),
        ("AKIA", TokenType::AwsAccessKey, "AWS"),
        ("ghp_", TokenType::GithubPat, "GitHub PAT"),
        ("gho_", TokenType::GithubPat, "GitHub OAuth"),
        (
            "github_pat_",
            TokenType::GithubPat,
            "GitHub fine-grained PAT",
        ),
        ("glpat-", TokenType::ApiKey, "GitLab PAT"),
        ("xoxb-", TokenType::ApiKey, "Slack bot"),
        ("xoxp-", TokenType::ApiKey, "Slack user"),
    ];

    for (prefix, token_type, provider) in &api_key_prefixes {
        if let Some(pos) = text.find(prefix) {
            let rest = &text[pos..text.len().min(pos + 200)];
            let token_end = rest
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',')
                .unwrap_or(rest.len());
            if token_end > prefix.len() + 10 {
                findings.push(TokenLeakageFinding {
                    token_type: *token_type,
                    confidence: 90,
                    location: format!("offset {pos}"),
                    description: format!("{provider} key detected ({token_end} chars)"),
                });
            }
        }
    }

    // JWT pattern (three base64 segments separated by dots)
    for segment in text.split_whitespace() {
        if segment.len() > 50 && segment.matches('.').count() == 2 {
            let parts: Vec<&str> = segment.split('.').collect();
            if parts.len() == 3
                && parts.iter().all(|p| {
                    p.len() > 10
                        && p.chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
                })
            {
                findings.push(TokenLeakageFinding {
                    token_type: TokenType::Jwt,
                    confidence: 75,
                    location: "parameter value".to_string(),
                    description: format!("JWT token ({} chars)", segment.len()),
                });
            }
        }
    }

    // Generic password/secret patterns
    let secret_patterns = [
        "password=",
        "passwd=",
        "secret=",
        "api_secret=",
        "client_secret=",
        "private_key=",
    ];
    // PERF: lowercase once, not once per pattern. This was inside the loop, so
    // a payload matching none of the six patterns allocated the whole text six
    // times over -- up to ~300KB of churn on a 50KB parameter blob. It matters
    // more now the scanners run on the HTTP/WebSocket/gRPC paths, which carry
    // far more traffic than the stdio relay against a <5ms P99 budget.
    let lowered = text.to_lowercase();
    for p in &secret_patterns {
        if lowered.contains(p) {
            findings.push(TokenLeakageFinding {
                token_type: TokenType::GenericSecret,
                confidence: 70,
                location: "parameter value".to_string(),
                description: format!("Secret pattern: '{p}'"),
            });
            break;
        }
    }

    findings
}

/// Scan JSON params for token leakage.
pub fn scan_params_for_tokens(params: &serde_json::Value) -> Vec<TokenLeakageFinding> {
    let mut text = String::new();
    collect_strings(params, &mut text, 0);
    scan_for_token_leakage(&text)
}

fn collect_strings(value: &serde_json::Value, out: &mut String, depth: usize) {
    if depth > 10 || out.len() > 50_000 {
        return;
    }
    match value {
        serde_json::Value::String(s) => {
            out.push_str(s);
            out.push(' ');
        }
        serde_json::Value::Array(arr) => {
            arr.iter().for_each(|i| collect_strings(i, out, depth + 1))
        }
        serde_json::Value::Object(obj) => obj
            .values()
            .for_each(|v| collect_strings(v, out, depth + 1)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bearer_token_detected() {
        let findings = scan_for_token_leakage(
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
        );
        assert!(findings
            .iter()
            .any(|f| f.token_type == TokenType::BearerToken));
    }

    #[test]
    fn test_openai_key_detected() {
        let findings =
            scan_for_token_leakage("Use this key: sk-proj-abc123def456ghi789jkl012mno345");
        assert!(findings.iter().any(|f| f.token_type == TokenType::ApiKey));
    }

    #[test]
    fn test_aws_key_detected() {
        let findings = scan_for_token_leakage("aws_access_key_id = AKIAIOSFODNN7EXAMPLE");
        assert!(findings
            .iter()
            .any(|f| f.token_type == TokenType::AwsAccessKey));
    }

    #[test]
    fn test_github_pat_detected() {
        let findings =
            scan_for_token_leakage("Set token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789");
        assert!(findings
            .iter()
            .any(|f| f.token_type == TokenType::GithubPat));
    }

    #[test]
    fn test_generic_secret() {
        let findings = scan_for_token_leakage("Configure with password=hunter2 in the env");
        assert!(findings
            .iter()
            .any(|f| f.token_type == TokenType::GenericSecret));
    }

    #[test]
    fn test_clean_text() {
        let findings = scan_for_token_leakage("Read the file at /tmp/data.txt and summarize");
        assert!(findings.is_empty());
    }
}
