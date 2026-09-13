// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! A2A (Agent-to-Agent) protocol security configuration.

use crate::default_true;
use crate::validation::validate_ed25519_pubkey;
use serde::{Deserialize, Serialize};

/// A2A (Agent-to-Agent) protocol security configuration.
///
/// Controls Vellaveto's A2A proxy behavior including message interception,
/// policy evaluation, agent card verification, and security feature integration.
///
/// # TOML Example
///
/// ```toml
/// [a2a]
/// enabled = true
/// upstream_url = "https://agent.example.com"
/// listen_addr = "0.0.0.0:8082"
/// require_agent_card = true
/// agent_card_cache_secs = 3600
/// allowed_auth_methods = ["bearer", "oauth2"]
/// enable_circuit_breaker = true
/// enable_shadow_agent_detection = true
/// enable_dlp_scanning = true
/// enable_injection_detection = true
/// max_message_size = 10485760
/// request_timeout_ms = 30000
/// allowed_task_operations = []
///
/// [a2a.signature]
/// enabled = true
/// max_token_lifetime_secs = 3600
/// clock_skew_secs = 60
/// require_card_hash_match = true
///
/// [[a2a.signature.trusted_keys]]
/// key_id = "agent-prod-2026"
/// public_key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
/// issuer = "https://agent.example.com"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct A2aConfig {
    /// Enable A2A protocol support. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Upstream A2A server URL (when acting as proxy).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_url: Option<String>,

    /// Listen address for A2A proxy (e.g., "0.0.0.0:8082").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_addr: Option<String>,

    /// Require agent card verification before allowing requests. Default: false.
    #[serde(default)]
    pub require_agent_card: bool,

    /// Cache agent cards for this duration in seconds. Default: 3600 (1 hour).
    #[serde(default = "default_a2a_card_cache_secs")]
    pub agent_card_cache_secs: u64,

    /// Allowed authentication methods. Default: ["apikey", "bearer"].
    /// Valid values: "apikey", "bearer", "oauth2", "mtls"
    #[serde(default = "default_a2a_auth_methods")]
    pub allowed_auth_methods: Vec<String>,

    /// Apply circuit breaker to upstream A2A servers. Default: true.
    #[serde(default = "default_true")]
    pub enable_circuit_breaker: bool,

    /// Enable shadow agent detection for A2A traffic. Default: true.
    #[serde(default = "default_true")]
    pub enable_shadow_agent_detection: bool,

    /// Enable DLP scanning on A2A message content. Default: true.
    #[serde(default = "default_true")]
    pub enable_dlp_scanning: bool,

    /// Enable injection detection on A2A text content. Default: true.
    #[serde(default = "default_true")]
    pub enable_injection_detection: bool,

    /// Maximum message size in bytes. Default: 10 MB.
    #[serde(default = "default_a2a_max_message_size")]
    pub max_message_size: usize,

    /// Request timeout in milliseconds. Default: 30000 (30 seconds).
    #[serde(default = "default_a2a_timeout")]
    pub request_timeout_ms: u64,

    /// Allowed task operations (empty = all allowed). Default: [].
    /// Valid values: "get", "cancel", "resubscribe"
    #[serde(default)]
    pub allowed_task_operations: Vec<String>,

    /// Agent Card Ed25519 signature enforcement.
    #[serde(default)]
    pub signature: A2aSignatureConfig,
}

/// Agent Card Ed25519 signature enforcement configuration.
///
/// Mirrors `vellaveto_mcp::a2a::SignatureEnforcementConfig` and supplies the
/// trusted signing keys, which have no other source — without at least one key
/// no card can ever verify.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct A2aSignatureConfig {
    /// Enforce Agent Card signatures. Default: true (fail-closed).
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Maximum accepted card token lifetime in seconds. Default: 3600.
    #[serde(default = "default_a2a_max_token_lifetime")]
    pub max_token_lifetime_secs: u64,

    /// Clock skew tolerance in seconds. Default: 60.
    #[serde(default = "default_a2a_clock_skew")]
    pub clock_skew_secs: u64,

    /// Require the claims' card hash to match the fetched card. Default: true.
    ///
    /// Turning this off accepts a signature over a *different* card than the
    /// one being used, so it defaults on and should stay on.
    #[serde(default = "default_true")]
    pub require_card_hash_match: bool,

    /// Trusted Ed25519 signing keys. Default: empty.
    #[serde(default)]
    pub trusted_keys: Vec<TrustedAgentKey>,
}

/// A trusted Ed25519 Agent Card signing key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TrustedAgentKey {
    /// Key identifier, matched against the `kid` claim on a card.
    pub key_id: String,

    /// Hex-encoded Ed25519 verifying key (32 bytes).
    pub public_key: String,

    /// Expected issuer for cards signed with this key.
    pub issuer: String,
}

impl Default for A2aSignatureConfig {
    fn default() -> Self {
        Self {
            // SECURITY: Fail-closed — enforcement on by default. It only takes
            // effect where the A2A listener runs, and `a2a.enabled` is false by
            // default, so this does not silently gate other transports.
            enabled: true,
            max_token_lifetime_secs: default_a2a_max_token_lifetime(),
            clock_skew_secs: default_a2a_clock_skew(),
            require_card_hash_match: true,
            trusted_keys: Vec::new(),
        }
    }
}

fn default_a2a_max_token_lifetime() -> u64 {
    3600 // 1 hour
}

fn default_a2a_clock_skew() -> u64 {
    60 // 1 minute
}

fn default_a2a_card_cache_secs() -> u64 {
    3600 // 1 hour
}

fn default_a2a_auth_methods() -> Vec<String> {
    vec!["apikey".to_string(), "bearer".to_string()]
}

fn default_a2a_max_message_size() -> usize {
    10 * 1024 * 1024 // 10 MB
}

fn default_a2a_timeout() -> u64 {
    30000 // 30 seconds
}

/// Maximum URL length for A2A upstream/listen addresses.
const MAX_A2A_URL_LENGTH: usize = 2048;

/// Maximum listen address length.
const MAX_A2A_LISTEN_ADDR_LENGTH: usize = 256;

/// Maximum A2A card cache duration (7 days).
const MAX_A2A_CARD_CACHE_SECS: u64 = 604_800;

/// Maximum auth methods / task operations entries.
const MAX_A2A_LIST_ENTRIES: usize = 20;

/// Maximum per-entry string length for auth methods / task operations.
const MAX_A2A_ENTRY_LENGTH: usize = 64;

/// Maximum message size (100 MB).
const MAX_A2A_MESSAGE_SIZE: usize = 100 * 1024 * 1024;

/// Maximum request timeout (5 minutes).
const MAX_A2A_TIMEOUT_MS: u64 = 300_000;

/// Valid A2A auth methods.
const VALID_A2A_AUTH_METHODS: &[&str] = &["apikey", "bearer", "oauth2", "mtls"];

/// Valid A2A task operations.
const VALID_A2A_TASK_OPERATIONS: &[&str] = &["get", "cancel", "resubscribe"];

/// Maximum number of trusted Agent Card signing keys.
const MAX_A2A_TRUSTED_KEYS: usize = 64;

/// Maximum `key_id` length.
const MAX_A2A_KEY_ID_LENGTH: usize = 128;

/// Maximum issuer length.
const MAX_A2A_ISSUER_LENGTH: usize = 256;

/// Maximum accepted card token lifetime (24 hours).
const MAX_A2A_TOKEN_LIFETIME_SECS: u64 = 86_400;

/// Maximum accepted clock skew tolerance (5 minutes).
///
/// Skew widens the window in which an expired card is still accepted, so this
/// is deliberately far tighter than the token lifetime bound.
const MAX_A2A_CLOCK_SKEW_SECS: u64 = 300;

impl A2aSignatureConfig {
    /// Validate signature enforcement configuration.
    ///
    /// The key material itself is only charset- and length-checked here; the
    /// bytes are decoded and validated by `AgentSigningKey::new` when the
    /// verifier is built, which keeps base64 out of this crate's dependencies.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_token_lifetime_secs == 0 {
            return Err("a2a.signature.max_token_lifetime_secs must be > 0".to_string());
        }
        if self.max_token_lifetime_secs > MAX_A2A_TOKEN_LIFETIME_SECS {
            return Err(format!(
                "a2a.signature.max_token_lifetime_secs {} exceeds maximum {} (24 hours)",
                self.max_token_lifetime_secs, MAX_A2A_TOKEN_LIFETIME_SECS
            ));
        }
        if self.clock_skew_secs > MAX_A2A_CLOCK_SKEW_SECS {
            return Err(format!(
                "a2a.signature.clock_skew_secs {} exceeds maximum {} (5 minutes)",
                self.clock_skew_secs, MAX_A2A_CLOCK_SKEW_SECS
            ));
        }

        if self.trusted_keys.len() > MAX_A2A_TRUSTED_KEYS {
            return Err(format!(
                "a2a.signature.trusted_keys count {} exceeds maximum {}",
                self.trusted_keys.len(),
                MAX_A2A_TRUSTED_KEYS
            ));
        }

        let mut seen_key_ids: Vec<&str> = Vec::with_capacity(self.trusted_keys.len());
        for key in &self.trusted_keys {
            key.validate()?;
            // SECURITY: A duplicate key_id silently shadows one of the keys, so
            // which public key a `kid` resolves to would depend on ordering.
            if seen_key_ids.contains(&key.key_id.as_str()) {
                return Err(format!(
                    "a2a.signature.trusted_keys contains duplicate key_id '{}'",
                    key.key_id
                ));
            }
            seen_key_ids.push(&key.key_id);
        }

        Ok(())
    }
}

impl TrustedAgentKey {
    /// Validate a single trusted key entry.
    pub fn validate(&self) -> Result<(), String> {
        if self.key_id.is_empty() {
            return Err("a2a.signature.trusted_keys entry has an empty key_id".to_string());
        }
        if self.key_id.len() > MAX_A2A_KEY_ID_LENGTH {
            return Err(format!(
                "a2a.signature.trusted_keys key_id length {} exceeds maximum {}",
                self.key_id.len(),
                MAX_A2A_KEY_ID_LENGTH
            ));
        }
        if vellaveto_types::has_dangerous_chars(&self.key_id) {
            return Err(format!(
                "a2a.signature.trusted_keys key_id '{}' contains control or format characters",
                self.key_id
            ));
        }

        if self.issuer.is_empty() {
            return Err(format!(
                "a2a.signature.trusted_keys entry '{}' has an empty issuer",
                self.key_id
            ));
        }
        if self.issuer.len() > MAX_A2A_ISSUER_LENGTH {
            return Err(format!(
                "a2a.signature.trusted_keys entry '{}' issuer length {} exceeds maximum {}",
                self.key_id,
                self.issuer.len(),
                MAX_A2A_ISSUER_LENGTH
            ));
        }
        if vellaveto_types::has_dangerous_chars(&self.issuer) {
            return Err(format!(
                "a2a.signature.trusted_keys entry '{}' issuer contains control or format characters",
                self.key_id
            ));
        }

        // Reuses the shared validator (same as acis.rs trusted_request_signers):
        // hex, exactly 32 bytes, and not all-zeros — an all-zeros key is
        // cryptographically invalid and would otherwise sit in the trust store
        // looking legitimate.
        validate_ed25519_pubkey(&self.public_key).map_err(|err| {
            format!(
                "a2a.signature.trusted_keys entry '{}' public_key invalid: {err}",
                self.key_id
            )
        })?;

        Ok(())
    }
}

impl A2aConfig {
    /// Validate A2A configuration fields.
    pub fn validate(&self) -> Result<(), String> {
        // Validate upstream_url
        if let Some(ref url) = self.upstream_url {
            if url.len() > MAX_A2A_URL_LENGTH {
                return Err(format!(
                    "a2a.upstream_url length {} exceeds maximum {}",
                    url.len(),
                    MAX_A2A_URL_LENGTH
                ));
            }
            if vellaveto_types::has_dangerous_chars(url) {
                return Err("a2a.upstream_url contains control or format characters".to_string());
            }
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Err("a2a.upstream_url must start with http:// or https://".to_string());
            }
        }

        // Validate listen_addr
        if let Some(ref addr) = self.listen_addr {
            if addr.len() > MAX_A2A_LISTEN_ADDR_LENGTH {
                return Err(format!(
                    "a2a.listen_addr length {} exceeds maximum {}",
                    addr.len(),
                    MAX_A2A_LISTEN_ADDR_LENGTH
                ));
            }
            if vellaveto_types::has_dangerous_chars(addr) {
                return Err("a2a.listen_addr contains control or format characters".to_string());
            }
        }

        // Validate agent_card_cache_secs
        // SECURITY (FIND-R86-004): Reject zero cache TTL — it disables caching entirely,
        // causing every request to re-fetch the agent card (performance DoS vector).
        if self.agent_card_cache_secs == 0 {
            return Err("a2a.agent_card_cache_secs must be > 0".to_string());
        }
        if self.agent_card_cache_secs > MAX_A2A_CARD_CACHE_SECS {
            return Err(format!(
                "a2a.agent_card_cache_secs {} exceeds maximum {} (7 days)",
                self.agent_card_cache_secs, MAX_A2A_CARD_CACHE_SECS
            ));
        }

        // Validate allowed_auth_methods
        if self.allowed_auth_methods.len() > MAX_A2A_LIST_ENTRIES {
            return Err(format!(
                "a2a.allowed_auth_methods count {} exceeds maximum {}",
                self.allowed_auth_methods.len(),
                MAX_A2A_LIST_ENTRIES
            ));
        }
        for method in &self.allowed_auth_methods {
            if method.is_empty() {
                return Err("a2a.allowed_auth_methods contains an empty string".to_string());
            }
            if method.len() > MAX_A2A_ENTRY_LENGTH {
                return Err(format!(
                    "a2a.allowed_auth_methods entry length {} exceeds maximum {}",
                    method.len(),
                    MAX_A2A_ENTRY_LENGTH
                ));
            }
            if vellaveto_types::has_dangerous_chars(method) {
                return Err(format!(
                    "a2a.allowed_auth_methods entry '{method}' contains control or format characters"
                ));
            }
            if !VALID_A2A_AUTH_METHODS.contains(&method.as_str()) {
                return Err(format!(
                    "a2a.allowed_auth_methods contains invalid value '{method}'. \
                     Valid values: {VALID_A2A_AUTH_METHODS:?}"
                ));
            }
        }

        // Validate max_message_size
        if self.max_message_size == 0 {
            return Err("a2a.max_message_size must be > 0".to_string());
        }
        if self.max_message_size > MAX_A2A_MESSAGE_SIZE {
            return Err(format!(
                "a2a.max_message_size {} exceeds maximum {} (100 MB)",
                self.max_message_size, MAX_A2A_MESSAGE_SIZE
            ));
        }

        // Validate request_timeout_ms
        if self.request_timeout_ms == 0 {
            return Err("a2a.request_timeout_ms must be > 0".to_string());
        }
        if self.request_timeout_ms > MAX_A2A_TIMEOUT_MS {
            return Err(format!(
                "a2a.request_timeout_ms {} exceeds maximum {} (5 minutes)",
                self.request_timeout_ms, MAX_A2A_TIMEOUT_MS
            ));
        }

        // Validate allowed_task_operations
        if self.allowed_task_operations.len() > MAX_A2A_LIST_ENTRIES {
            return Err(format!(
                "a2a.allowed_task_operations count {} exceeds maximum {}",
                self.allowed_task_operations.len(),
                MAX_A2A_LIST_ENTRIES
            ));
        }
        for op in &self.allowed_task_operations {
            if op.is_empty() {
                return Err("a2a.allowed_task_operations contains an empty string".to_string());
            }
            if op.len() > MAX_A2A_ENTRY_LENGTH {
                return Err(format!(
                    "a2a.allowed_task_operations entry length {} exceeds maximum {}",
                    op.len(),
                    MAX_A2A_ENTRY_LENGTH
                ));
            }
            if vellaveto_types::has_dangerous_chars(op) {
                return Err(format!(
                    "a2a.allowed_task_operations entry '{op}' contains control or format characters"
                ));
            }
            if !VALID_A2A_TASK_OPERATIONS.contains(&op.as_str()) {
                return Err(format!(
                    "a2a.allowed_task_operations contains invalid value '{op}'. \
                     Valid values: {VALID_A2A_TASK_OPERATIONS:?}"
                ));
            }
        }

        // Validate signature enforcement
        self.signature.validate()?;

        // SECURITY: Enforcement with no trusted keys can never verify a card, so
        // every request would be denied. That is fail-closed but indistinguishable
        // from a broken deployment, so surface it as a config error rather than
        // letting the operator discover it as a total outage.
        if self.enabled
            && self.require_agent_card
            && self.signature.enabled
            && self.signature.trusted_keys.is_empty()
        {
            return Err(
                "a2a.signature.enabled is true with a2a.require_agent_card, but \
                 a2a.signature.trusted_keys is empty — no Agent Card could ever be \
                 verified and every request would be denied. Add at least one \
                 trusted key, or set a2a.signature.enabled = false to accept \
                 unsigned cards."
                    .to_string(),
            );
        }

        Ok(())
    }
}

impl Default for A2aConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            upstream_url: None,
            listen_addr: None,
            // SECURITY: Fail-closed — require agent card verification by default.
            require_agent_card: true,
            agent_card_cache_secs: default_a2a_card_cache_secs(),
            allowed_auth_methods: default_a2a_auth_methods(),
            enable_circuit_breaker: true,
            enable_shadow_agent_detection: true,
            enable_dlp_scanning: true,
            enable_injection_detection: true,
            max_message_size: default_a2a_max_message_size(),
            request_timeout_ms: default_a2a_timeout(),
            // SECURITY: Fail-closed — only allow safe read-only task operations by default.
            allowed_task_operations: vec!["get".into(), "cancel".into(), "resubscribe".into()],
            signature: A2aSignatureConfig::default(),
        }
    }
}
