// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Consumer Shield configuration.
//!
//! Controls bidirectional PII sanitization, session isolation, and
//! encrypted local audit for consumer AI interactions.

use serde::{Deserialize, Serialize};

/// Maximum number of custom PII patterns in shield config.
pub const MAX_SHIELD_CUSTOM_PII_PATTERNS: usize = 100;

/// Maximum sessions allowed.
const MAX_SHIELD_SESSIONS: usize = 100_000;

/// Maximum history entries per session.
const MAX_SHIELD_HISTORY_PER_SESSION: usize = 100_000;

/// Maximum PII mappings.
const MAX_SHIELD_PII_MAPPINGS: usize = 1_000_000;

/// Maximum pattern length for custom PII patterns.
const MAX_SHIELD_PATTERN_LEN: usize = 1024;

/// Maximum pattern name length.
const MAX_SHIELD_PATTERN_NAME_LEN: usize = 256;

/// Check for dangerous characters (control chars, Unicode format chars).
fn has_dangerous_chars(s: &str) -> bool {
    vellaveto_types::has_dangerous_chars(s)
}

/// A custom PII pattern for the shield scanner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ShieldCustomPiiPattern {
    /// Human-readable name for this pattern.
    pub name: String,
    /// Regex pattern string.
    pub pattern: String,
}

/// Consumer Shield configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ShieldConfig {
    /// Whether the consumer shield is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Audit mode: "local" for encrypted local audit, "remote" for server-side.
    #[serde(default = "default_audit_mode")]
    pub audit_mode: String,

    /// Whether to sanitize outbound queries (PII removal before AI provider).
    #[serde(default = "default_true")]
    pub sanitize_queries: bool,

    /// Whether to desanitize inbound responses (PII restoration after AI provider).
    #[serde(default = "default_true")]
    pub desanitize_responses: bool,

    /// Whether to isolate PII mappings per session.
    #[serde(default = "default_true")]
    pub session_isolation: bool,

    /// Whether to generate Merkle proofs for audit entries.
    #[serde(default = "default_true")]
    pub merkle_proofs: bool,

    /// Whether to generate zero-knowledge commitments for audit entries.
    #[serde(default)]
    pub zk_commitments: bool,

    /// Custom PII patterns beyond the built-in set.
    #[serde(default)]
    pub custom_pii_patterns: Vec<ShieldCustomPiiPattern>,

    /// Maximum PII mappings before fail-closed.
    #[serde(default = "default_max_pii_mappings")]
    pub max_pii_mappings: usize,

    /// Maximum concurrent sessions.
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,

    /// Maximum history entries per session.
    #[serde(default = "default_max_history_per_session")]
    pub max_history_per_session: usize,

    /// Whether session unlinkability is enabled (credential rotation per session).
    #[serde(default = "default_true")]
    pub session_unlinkability: bool,

    /// Number of blind credentials to pre-generate in the local vault.
    /// Each new session consumes one credential.
    /// Default: 50. When available count drops below `replenish_threshold`,
    /// background replenishment starts.
    #[serde(default = "default_credential_pool_size")]
    pub credential_pool_size: usize,

    /// When available credentials drop below this count, trigger replenishment.
    /// Default: 10.
    #[serde(default = "default_replenish_threshold")]
    pub replenish_threshold: usize,

    /// Credential epoch rotation interval (abstract counter, not seconds).
    /// Provider issues credentials tagged with an epoch. Credentials from
    /// past epochs are expired during vault cleanup.
    /// Default: 100.
    #[serde(default = "default_credential_epoch_interval")]
    pub credential_epoch_interval: u64,

    /// Stylometric normalization level.
    /// "none" = disabled, "level1" = whitespace/punctuation/emoji, "level2" = level1 + filler words.
    /// Default: "none".
    #[serde(default = "default_stylometric_level")]
    pub stylometric_level: String,

    /// Whether traffic padding is offered on the HTTP transport.
    ///
    /// Enabling this does not pad every response. Padding uses a
    /// length-prefixed framing a standard MCP client cannot parse, so it is
    /// applied only to clients that opt in with `X-Vellaveto-Padding: v1`.
    /// Everyone else gets the unpadded body unchanged. Default: false.
    #[serde(default)]
    pub traffic_padding: bool,

    /// Whether to strip correlation and tracing headers from upstream requests.
    ///
    /// `traceparent`, `tracestate`, and the `x-*-trace-id` family let an
    /// upstream operator correlate a user's requests across sessions. Stripping
    /// them costs distributed tracing through the proxy, which is why it is
    /// opt-in rather than the default. Unlike padding this changes no wire
    /// format and needs no negotiation. Default: false.
    #[serde(default)]
    pub strip_privacy_headers: bool,
}

fn default_audit_mode() -> String {
    "local".to_string()
}

fn default_true() -> bool {
    true
}

fn default_max_pii_mappings() -> usize {
    50_000
}

fn default_max_sessions() -> usize {
    1_000
}

fn default_max_history_per_session() -> usize {
    10_000
}

fn default_credential_pool_size() -> usize {
    50
}

fn default_replenish_threshold() -> usize {
    10
}

fn default_credential_epoch_interval() -> u64 {
    100
}

fn default_stylometric_level() -> String {
    "none".to_string()
}

impl Default for ShieldConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            audit_mode: default_audit_mode(),
            sanitize_queries: true,
            desanitize_responses: true,
            session_isolation: true,
            merkle_proofs: true,
            zk_commitments: false,
            custom_pii_patterns: Vec::new(),
            max_pii_mappings: default_max_pii_mappings(),
            max_sessions: default_max_sessions(),
            max_history_per_session: default_max_history_per_session(),
            session_unlinkability: true,
            credential_pool_size: default_credential_pool_size(),
            replenish_threshold: default_replenish_threshold(),
            credential_epoch_interval: default_credential_epoch_interval(),
            stylometric_level: default_stylometric_level(),
            traffic_padding: false,
            strip_privacy_headers: false,
        }
    }
}

impl ShieldConfig {
    /// Validate the shield configuration.
    pub fn validate(&self) -> Result<(), String> {
        // Check dangerous chars before value matching
        if has_dangerous_chars(&self.audit_mode) {
            return Err("audit_mode contains dangerous characters".to_string());
        }

        // Validate audit_mode
        match self.audit_mode.as_str() {
            "local" | "remote" => {}
            other => {
                return Err(format!(
                    "invalid audit_mode '{other}': must be 'local' or 'remote'"
                ));
            }
        }

        // Validate bounds
        if self.max_sessions == 0 {
            return Err("max_sessions must be > 0".to_string());
        }
        if self.max_sessions > MAX_SHIELD_SESSIONS {
            return Err(format!(
                "max_sessions {} exceeds maximum {}",
                self.max_sessions, MAX_SHIELD_SESSIONS
            ));
        }

        if self.max_history_per_session == 0 {
            return Err("max_history_per_session must be > 0".to_string());
        }
        if self.max_history_per_session > MAX_SHIELD_HISTORY_PER_SESSION {
            return Err(format!(
                "max_history_per_session {} exceeds maximum {}",
                self.max_history_per_session, MAX_SHIELD_HISTORY_PER_SESSION
            ));
        }

        if self.max_pii_mappings == 0 {
            return Err("max_pii_mappings must be > 0".to_string());
        }
        if self.max_pii_mappings > MAX_SHIELD_PII_MAPPINGS {
            return Err(format!(
                "max_pii_mappings {} exceeds maximum {}",
                self.max_pii_mappings, MAX_SHIELD_PII_MAPPINGS
            ));
        }

        // Validate credential pool config
        if self.credential_pool_size == 0 {
            return Err("credential_pool_size must be > 0".to_string());
        }
        if self.credential_pool_size > vellaveto_types::MAX_CREDENTIAL_POOL_SIZE {
            return Err(format!(
                "credential_pool_size {} exceeds maximum {}",
                self.credential_pool_size,
                vellaveto_types::MAX_CREDENTIAL_POOL_SIZE
            ));
        }
        if self.replenish_threshold >= self.credential_pool_size {
            return Err(format!(
                "replenish_threshold ({}) must be less than credential_pool_size ({})",
                self.replenish_threshold, self.credential_pool_size
            ));
        }
        if self.credential_epoch_interval == 0 {
            return Err("credential_epoch_interval must be > 0".to_string());
        }
        if self.credential_epoch_interval > vellaveto_types::MAX_CREDENTIAL_EPOCH {
            return Err(format!(
                "credential_epoch_interval {} exceeds maximum",
                self.credential_epoch_interval
            ));
        }

        // Validate stylometric level
        if has_dangerous_chars(&self.stylometric_level) {
            return Err("stylometric_level contains dangerous characters".to_string());
        }
        match self.stylometric_level.as_str() {
            "none" | "level1" | "level2" => {}
            other => {
                return Err(format!(
                    "invalid stylometric_level '{other}': must be 'none', 'level1', or 'level2'"
                ));
            }
        }

        // Validate custom PII patterns
        if self.custom_pii_patterns.len() > MAX_SHIELD_CUSTOM_PII_PATTERNS {
            return Err(format!(
                "custom_pii_patterns has {} entries, max is {}",
                self.custom_pii_patterns.len(),
                MAX_SHIELD_CUSTOM_PII_PATTERNS
            ));
        }

        for (i, pat) in self.custom_pii_patterns.iter().enumerate() {
            if pat.name.is_empty() {
                return Err(format!("custom_pii_patterns[{i}].name must not be empty"));
            }
            if pat.name.len() > MAX_SHIELD_PATTERN_NAME_LEN {
                return Err(format!(
                    "custom_pii_patterns[{}].name exceeds max length ({} > {})",
                    i,
                    pat.name.len(),
                    MAX_SHIELD_PATTERN_NAME_LEN
                ));
            }
            if has_dangerous_chars(&pat.name) {
                return Err(format!(
                    "custom_pii_patterns[{i}].name contains dangerous characters"
                ));
            }
            if pat.pattern.is_empty() {
                return Err(format!(
                    "custom_pii_patterns[{i}].pattern must not be empty"
                ));
            }
            if pat.pattern.len() > MAX_SHIELD_PATTERN_LEN {
                return Err(format!(
                    "custom_pii_patterns[{}].pattern exceeds max length ({} > {})",
                    i,
                    pat.pattern.len(),
                    MAX_SHIELD_PATTERN_LEN
                ));
            }
            // SECURITY (R237-CFG-2): Validate pattern field for dangerous chars
            // and regex compilation, consistent with PolicyConfig::validate().
            if has_dangerous_chars(&pat.pattern) {
                return Err(format!(
                    "custom_pii_patterns[{i}].pattern contains dangerous characters"
                ));
            }
            if let Err(e) = regex::Regex::new(&pat.pattern) {
                return Err(format!(
                    "custom_pii_patterns[{i}].pattern is not valid regex: {e}"
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shield_defaults() {
        let config = ShieldConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.audit_mode, "local");
        assert!(config.sanitize_queries);
        assert!(config.desanitize_responses);
        assert!(config.session_isolation);
        assert!(config.merkle_proofs);
        assert!(!config.zk_commitments);
        assert!(config.custom_pii_patterns.is_empty());
        assert_eq!(config.max_pii_mappings, 50_000);
        assert_eq!(config.max_sessions, 1_000);
        assert_eq!(config.max_history_per_session, 10_000);
        assert!(config.session_unlinkability);
        assert_eq!(config.credential_pool_size, 50);
        assert_eq!(config.replenish_threshold, 10);
        assert_eq!(config.credential_epoch_interval, 100);
        assert_eq!(config.stylometric_level, "none");
        assert!(!config.traffic_padding);
    }

    #[test]
    fn test_shield_invalid_audit_mode() {
        let config = ShieldConfig {
            audit_mode: "invalid".to_string(),
            ..ShieldConfig::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("audit_mode"));
    }

    #[test]
    fn test_shield_zero_sessions_rejected() {
        let config = ShieldConfig {
            max_sessions: 0,
            ..ShieldConfig::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("max_sessions"));
    }

    #[test]
    fn test_shield_dangerous_chars_rejected() {
        let config = ShieldConfig {
            audit_mode: "local\u{200B}".to_string(),
            ..ShieldConfig::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("dangerous"));
    }

    #[test]
    fn test_shield_toml_roundtrip() {
        let config = ShieldConfig::default();
        let toml_str = toml::to_string(&config).unwrap();
        let parsed: ShieldConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(config, parsed);
    }

    #[test]
    fn test_shield_traffic_padding_toml_roundtrip() {
        let toml_str = r#"
enabled = true
traffic_padding = true
"#;
        let config: ShieldConfig = toml::from_str(toml_str).unwrap();
        assert!(config.traffic_padding);

        // Roundtrip
        let serialized = toml::to_string(&config).unwrap();
        let reparsed: ShieldConfig = toml::from_str(&serialized).unwrap();
        assert!(reparsed.traffic_padding);
    }

    #[test]
    fn test_shield_deny_unknown_fields() {
        let toml_str = r#"
enabled = true
audit_mode = "local"
unknown_field = true
"#;
        let result: Result<ShieldConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_shield_full_policy_config_parse() {
        let toml_str = r#"
[shield]
enabled = true
audit_mode = "local"
sanitize_queries = true
max_sessions = 500

[[shield.custom_pii_patterns]]
name = "employee_id"
pattern = "EMP-\\d{6}"
"#;
        let config: crate::PolicyConfig = toml::from_str(toml_str).unwrap();
        assert!(config.shield.enabled);
        assert_eq!(config.shield.max_sessions, 500);
        assert_eq!(config.shield.custom_pii_patterns.len(), 1);
        assert!(config.shield.validate().is_ok());
    }

    // ── R237-CFG-2: custom_pii_patterns pattern field validation ──

    #[test]
    fn test_shield_custom_pii_invalid_regex() {
        let config = ShieldConfig {
            custom_pii_patterns: vec![ShieldCustomPiiPattern {
                name: "bad_pattern".to_string(),
                pattern: "(?P<bad".to_string(),
            }],
            ..ShieldConfig::default()
        };
        let result = config.validate();
        assert!(
            result.is_err(),
            "Invalid regex pattern should fail validation"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("not valid regex"),
            "Error should mention 'not valid regex', got: {err}"
        );
    }

    #[test]
    fn test_shield_custom_pii_dangerous_chars_in_pattern() {
        let config = ShieldConfig {
            custom_pii_patterns: vec![ShieldCustomPiiPattern {
                name: "zwsp_pattern".to_string(),
                pattern: "foo\u{200B}bar".to_string(),
            }],
            ..ShieldConfig::default()
        };
        let result = config.validate();
        assert!(
            result.is_err(),
            "Pattern with dangerous chars should fail validation"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("dangerous characters"),
            "Error should mention 'dangerous characters', got: {err}"
        );
    }
}
