// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! A2A Agent Card Signature Enforcement — Phase 65.
//!
//! The A2A specification leaves Agent Card signature validation optional.
//! This module makes it **mandatory** for Vellaveto deployments:
//!
//! - **Signature validation**: Every Agent Card must carry a JWS signature
//!   (detached or embedded) that is verified before the card is accepted.
//! - **Token lifetime enforcement**: Agent Cards carry an `exp` claim;
//!   expired cards are rejected.
//! - **Agent identity binding**: The card signer's key must match the
//!   agent's declared identity.
//!
//! # Signature Format
//!
//! The signature is a **detached Ed25519 signature over the raw Agent Card JSON
//! bytes** — not JWS Compact Serialization (RFC 7515), despite the JWS-style
//! claim names. The claims (`iss`, `sub`, `iat`, `exp`, `kid`, `card_hash`) are
//! not part of the signed preimage; they are bound to the card only indirectly,
//! by checking `card_hash == SHA-256(card_json)`. A verifier written against
//! RFC 7515 will not interoperate with this format.
//!
//! The signature is carried in an HTTP header (`X-Agent-Card-Signature`)
//! or in the card JSON itself under `_signature`.
//!
//! # Security Design
//!
//! - Fail-closed: missing or invalid signature -> reject.
//! - Bounded: maximum signature size, key count, and cache entries.
//! - No secrets in Debug: signing keys are redacted.
//!
//! # No replay protection
//!
//! Agent Cards carry no nonce, so a validly signed card can be replayed for the
//! whole of its `exp` lifetime — the only bound on reuse is the card's own
//! expiry, together with the `iat`/`exp` skew and lifetime limits enforced
//! here. The cache in this module is a *positive-result* cache: it remembers
//! cards that verified, which speeds up repeat presentation rather than
//! preventing it. Keep card lifetimes short.
//! - All counters use `saturating_add`.

use ed25519_dalek::{Signature, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::error::A2aError;

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Maximum length of a raw signature string (base64-encoded).
const MAX_SIGNATURE_LENGTH: usize = 4096;

/// Maximum length of the signed payload (Agent Card JSON).
const MAX_SIGNED_PAYLOAD_SIZE: usize = 1_048_576; // 1 MB

/// Maximum number of trusted signing keys.
const MAX_TRUSTED_KEYS: usize = 100;

/// Maximum number of cached signature verifications.
const MAX_SIG_CACHE_ENTRIES: usize = 10_000;

/// Default token lifetime maximum in seconds (24 hours).
const DEFAULT_MAX_TOKEN_LIFETIME_SECS: u64 = 86_400;

/// Minimum token lifetime in seconds (1 minute).
const MIN_TOKEN_LIFETIME_SECS: u64 = 60;

/// Maximum clock skew tolerance in seconds.
const MAX_CLOCK_SKEW_SECS: u64 = 300;

/// Maximum key ID length.
const MAX_KEY_ID_LENGTH: usize = 256;

/// Maximum issuer length.
const MAX_ISSUER_LENGTH: usize = 512;

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// Ed25519 public key for Agent Card signature verification.
///
/// Custom Debug implementation redacts the key bytes.
#[derive(Clone)]
pub struct AgentSigningKey {
    /// Key identifier (matches `kid` in the JWS header).
    pub key_id: String,
    /// The Ed25519 verifying key.
    key: VerifyingKey,
    /// Issuer identity this key is trusted for.
    pub issuer: String,
}

impl fmt::Debug for AgentSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentSigningKey")
            .field("key_id", &self.key_id)
            .field("key", &"[REDACTED]")
            .field("issuer", &self.issuer)
            .finish()
    }
}

impl AgentSigningKey {
    /// Create a new trusted signing key.
    ///
    /// # Errors
    ///
    /// Returns `A2aError::AgentCardInvalid` if the key bytes are invalid,
    /// or if the key_id/issuer contain dangerous characters.
    pub fn new(key_id: &str, public_key_bytes: &[u8], issuer: &str) -> Result<Self, A2aError> {
        if key_id.len() > MAX_KEY_ID_LENGTH {
            return Err(A2aError::AgentCardInvalid(format!(
                "key_id length {} exceeds maximum {}",
                key_id.len(),
                MAX_KEY_ID_LENGTH
            )));
        }
        if vellaveto_types::has_dangerous_chars(key_id) {
            return Err(A2aError::AgentCardInvalid(
                "key_id contains control or Unicode format characters".to_string(),
            ));
        }
        if issuer.len() > MAX_ISSUER_LENGTH {
            return Err(A2aError::AgentCardInvalid(format!(
                "issuer length {} exceeds maximum {}",
                issuer.len(),
                MAX_ISSUER_LENGTH
            )));
        }
        if vellaveto_types::has_dangerous_chars(issuer) {
            return Err(A2aError::AgentCardInvalid(
                "issuer contains control or Unicode format characters".to_string(),
            ));
        }
        if public_key_bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(A2aError::AgentCardInvalid(format!(
                "Ed25519 public key must be {} bytes, got {}",
                PUBLIC_KEY_LENGTH,
                public_key_bytes.len()
            )));
        }
        let mut key_bytes = [0u8; PUBLIC_KEY_LENGTH];
        key_bytes.copy_from_slice(public_key_bytes);
        let key = VerifyingKey::from_bytes(&key_bytes).map_err(|e| {
            A2aError::AgentCardInvalid(format!("invalid Ed25519 public key: {}", e))
        })?;
        Ok(Self {
            key_id: key_id.to_string(),
            key,
            issuer: issuer.to_string(),
        })
    }

    /// Access the underlying verifying key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.key
    }
}

/// Claims embedded in or associated with a signed Agent Card.
///
/// These mirror JWT-style claims for token lifetime enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCardClaims {
    /// Issuer of the Agent Card.
    pub iss: String,
    /// Subject (agent URL or identifier).
    pub sub: String,
    /// Issued-at timestamp (Unix epoch seconds).
    pub iat: u64,
    /// Expiration timestamp (Unix epoch seconds).
    pub exp: u64,
    /// Key ID used to sign.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Agent Card content hash (SHA-256 hex).
    pub card_hash: String,
}

impl AgentCardClaims {
    /// Validate the claims are well-formed and within bounds.
    pub fn validate(&self) -> Result<(), A2aError> {
        if self.iss.is_empty() || self.iss.len() > MAX_ISSUER_LENGTH {
            return Err(A2aError::AgentCardInvalid(
                "claims issuer must be non-empty and within bounds".to_string(),
            ));
        }
        if vellaveto_types::has_dangerous_chars(&self.iss) {
            return Err(A2aError::AgentCardInvalid(
                "claims issuer contains dangerous characters".to_string(),
            ));
        }
        if self.sub.is_empty() || self.sub.len() > 2048 {
            return Err(A2aError::AgentCardInvalid(
                "claims subject must be non-empty and within bounds".to_string(),
            ));
        }
        if vellaveto_types::has_dangerous_chars(&self.sub) {
            return Err(A2aError::AgentCardInvalid(
                "claims subject contains dangerous characters".to_string(),
            ));
        }
        if self.card_hash.len() != 64 {
            return Err(A2aError::AgentCardInvalid(
                "card_hash must be a 64-character hex SHA-256 digest".to_string(),
            ));
        }
        // SECURITY (R229-A2A-1): Validate card_hash is actually hex, not just 64 chars.
        // A non-hex card_hash could be used for cache key injection or hash comparison bypass.
        if !self.card_hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(A2aError::AgentCardInvalid(
                "card_hash contains non-hex characters".to_string(),
            ));
        }
        // SECURITY (R229-A2A-2): Validate kid field if present.
        // kid flows into cache keys and log entries — must be bounded and safe.
        if let Some(ref kid) = self.kid {
            if kid.len() > 256 {
                return Err(A2aError::AgentCardInvalid(
                    "kid exceeds maximum length of 256".to_string(),
                ));
            }
            if kid.is_empty() {
                return Err(A2aError::AgentCardInvalid(
                    "kid must not be empty when present".to_string(),
                ));
            }
            if vellaveto_types::has_dangerous_chars(kid) {
                return Err(A2aError::AgentCardInvalid(
                    "kid contains dangerous characters".to_string(),
                ));
            }
        }
        // Expiration must be after issued-at
        if self.exp <= self.iat {
            return Err(A2aError::AgentCardInvalid(
                "exp must be after iat".to_string(),
            ));
        }
        Ok(())
    }
}

/// Configuration for Agent Card signature enforcement.
#[derive(Debug, Clone)]
pub struct SignatureEnforcementConfig {
    /// Whether signature enforcement is enabled (fail-closed: default true).
    pub enabled: bool,
    /// Maximum allowed token lifetime in seconds.
    pub max_token_lifetime_secs: u64,
    /// Clock skew tolerance in seconds.
    pub clock_skew_secs: u64,
    /// Whether to require the card hash to match the presented card.
    pub require_card_hash_match: bool,
}

impl Default for SignatureEnforcementConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_token_lifetime_secs: DEFAULT_MAX_TOKEN_LIFETIME_SECS,
            clock_skew_secs: MAX_CLOCK_SKEW_SECS,
            require_card_hash_match: true,
        }
    }
}

/// Cached signature verification result.
struct CachedVerification {
    valid: bool,
    verified_at: Instant,
}

/// Agent Card Signature Verifier.
///
/// Maintains a set of trusted signing keys and verifies Agent Card signatures.
/// Thread-safe via internal `RwLock` on the trusted keys and cache.
pub struct AgentCardSignatureVerifier {
    trusted_keys: RwLock<HashMap<String, AgentSigningKey>>,
    config: SignatureEnforcementConfig,
    /// Cache of recent verification results keyed by (card_hash, key_id).
    verification_cache: RwLock<HashMap<String, CachedVerification>>,
    /// Cache TTL for positive verifications.
    cache_ttl: Duration,
    /// Counter for total verifications performed (for metrics).
    verification_count: std::sync::atomic::AtomicU64,
    /// Counter for verification failures.
    failure_count: std::sync::atomic::AtomicU64,
}

impl fmt::Debug for AgentCardSignatureVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentCardSignatureVerifier")
            .field("config", &self.config)
            .field("trusted_keys_count", &self.trusted_key_count())
            .field(
                "verification_count",
                &self
                    .verification_count
                    .load(std::sync::atomic::Ordering::Relaxed),
            )
            .field(
                "failure_count",
                &self
                    .failure_count
                    .load(std::sync::atomic::Ordering::Relaxed),
            )
            .finish()
    }
}

impl AgentCardSignatureVerifier {
    /// Create a new verifier with the given configuration.
    pub fn new(config: SignatureEnforcementConfig) -> Self {
        Self {
            trusted_keys: RwLock::new(HashMap::new()),
            config,
            verification_cache: RwLock::new(HashMap::new()),
            cache_ttl: Duration::from_secs(300),
            verification_count: std::sync::atomic::AtomicU64::new(0),
            failure_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Register a trusted signing key.
    ///
    /// # Errors
    ///
    /// Returns error if the key store is at capacity.
    pub fn add_trusted_key(&self, key: AgentSigningKey) -> Result<(), A2aError> {
        let mut keys = self.trusted_keys.write().map_err(|_| {
            tracing::error!(
                target: "vellaveto::security",
                "AgentCardSignatureVerifier trusted_keys write lock poisoned"
            );
            A2aError::AgentCardInvalid("signature verifier internal error".to_string())
        })?;
        if !keys.contains_key(&key.key_id) && keys.len() >= MAX_TRUSTED_KEYS {
            return Err(A2aError::AgentCardInvalid(format!(
                "trusted key store at capacity ({})",
                MAX_TRUSTED_KEYS
            )));
        }
        keys.insert(key.key_id.clone(), key);
        Ok(())
    }

    /// Remove a trusted key by key_id.
    pub fn remove_trusted_key(&self, key_id: &str) -> Result<bool, A2aError> {
        let mut keys = self.trusted_keys.write().map_err(|_| {
            tracing::error!(
                target: "vellaveto::security",
                "AgentCardSignatureVerifier trusted_keys write lock poisoned"
            );
            A2aError::AgentCardInvalid("signature verifier internal error".to_string())
        })?;
        Ok(keys.remove(key_id).is_some())
    }

    /// Number of trusted keys currently loaded.
    pub fn trusted_key_count(&self) -> usize {
        match self.trusted_keys.read() {
            Ok(keys) => keys.len(),
            Err(_) => {
                tracing::error!(
                    target: "vellaveto::security",
                    "AgentCardSignatureVerifier trusted_keys read lock poisoned"
                );
                0
            }
        }
    }

    /// Verify an Agent Card signature and claims.
    ///
    /// # Arguments
    ///
    /// * `card_json` — The raw JSON bytes of the Agent Card.
    /// * `signature_b64` — Base64-encoded Ed25519 signature over the card JSON.
    /// * `claims` — The claims associated with the card (issuer, exp, etc.).
    ///
    /// # Errors
    ///
    /// Fails closed: any verification failure returns an error.
    pub fn verify_card(
        &self,
        card_json: &[u8],
        signature_b64: &str,
        claims: &AgentCardClaims,
    ) -> Result<(), A2aError> {
        self.verification_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        // Gate: enforcement must be enabled
        if !self.config.enabled {
            return Ok(());
        }

        // Bounds check on inputs
        if card_json.len() > MAX_SIGNED_PAYLOAD_SIZE {
            self.increment_failures();
            return Err(A2aError::AgentCardInvalid(format!(
                "card payload size {} exceeds maximum {}",
                card_json.len(),
                MAX_SIGNED_PAYLOAD_SIZE
            )));
        }
        if signature_b64.len() > MAX_SIGNATURE_LENGTH {
            self.increment_failures();
            return Err(A2aError::AgentCardInvalid(format!(
                "signature length {} exceeds maximum {}",
                signature_b64.len(),
                MAX_SIGNATURE_LENGTH
            )));
        }

        // Validate claims structure
        claims.validate()?;

        // Check token lifetime
        self.check_token_lifetime(claims)?;

        // Check card hash if required
        if self.config.require_card_hash_match {
            let computed_hash = compute_card_hash(card_json);
            // SECURITY (R228-A2A-12): Normalize both hashes to lowercase before
            // comparison. compute_card_hash returns lowercase hex, but external
            // issuers may encode card_hash in claims as uppercase hex. Without
            // normalization, valid cards from uppercase-encoding issuers are rejected.
            let claims_hash_lower = claims.card_hash.to_ascii_lowercase();
            if !constant_time_eq(computed_hash.as_bytes(), claims_hash_lower.as_bytes()) {
                self.increment_failures();
                return Err(A2aError::AgentCardInvalid(
                    "card hash does not match claims".to_string(),
                ));
            }
        }

        // Check verification cache
        // SECURITY (R228-A2A-1): Include kid in cache key. Without kid, a cached
        // verification for one key would be reused when the issuer rotates keys,
        // allowing a stale/compromised key to pass verification via cache hit.
        let kid_component = claims.kid.as_deref().unwrap_or("");
        // SECURITY (R231-A2A-1): Include exp claim in cache key. Without exp,
        // a cached verification result outlasts the token's intended lifetime,
        // allowing expired cards to pass verification via cache hit.
        let cache_key = format!(
            "{}:{}:{}:{}",
            claims.card_hash, claims.iss, kid_component, claims.exp
        );
        if self.check_cache(&cache_key) {
            return Ok(());
        }

        // Decode signature
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signature_b64)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(signature_b64))
            .map_err(|e| {
                self.increment_failures();
                A2aError::AgentCardInvalid(format!("invalid base64 signature: {}", e))
            })?;
        if sig_bytes.len() != SIGNATURE_LENGTH {
            self.increment_failures();
            return Err(A2aError::AgentCardInvalid(format!(
                "Ed25519 signature must be {} bytes, got {}",
                SIGNATURE_LENGTH,
                sig_bytes.len()
            )));
        }
        let mut sig_array = [0u8; SIGNATURE_LENGTH];
        sig_array.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_array);

        // Find the matching trusted key
        let key_id = claims.kid.as_deref().unwrap_or(&claims.iss);

        let keys = self.trusted_keys.read().map_err(|_| {
            tracing::error!(
                target: "vellaveto::security",
                "AgentCardSignatureVerifier trusted_keys read lock poisoned"
            );
            self.increment_failures();
            A2aError::AgentCardInvalid("signature verifier internal error".to_string())
        })?;

        // SECURITY (R230-A2A-1): When kid is explicitly specified, ONLY look up
        // by kid. Do NOT fall back to issuer-based search. The fallback allowed a
        // compromised key (kid="k1") to verify cards claiming kid="k2" for the same
        // issuer, bypassing key-specific revocation.
        // Only fall back to issuer-based lookup when kid is absent (uses iss as key_id).
        let matching_key = if claims.kid.is_some() {
            // kid specified → exact key_id match only, no fallback
            keys.get(key_id)
        } else {
            // kid absent → key_id == iss, try exact match then issuer scan
            keys.get(key_id)
                .or_else(|| keys.values().find(|k| k.issuer == claims.iss))
        };

        let signing_key = matching_key.ok_or_else(|| {
            self.increment_failures();
            A2aError::AgentCardInvalid(format!("no trusted key found for issuer '{}'", claims.iss))
        })?;

        // Verify the issuer matches the key's trusted issuer
        if signing_key.issuer != claims.iss {
            self.increment_failures();
            return Err(A2aError::AgentCardInvalid(format!(
                "key issuer '{}' does not match claims issuer '{}'",
                signing_key.issuer, claims.iss
            )));
        }

        // Verify the Ed25519 signature
        use ed25519_dalek::Verifier;
        signing_key.key.verify(card_json, &signature).map_err(|_| {
            self.increment_failures();
            A2aError::AgentCardInvalid("Ed25519 signature verification failed".to_string())
        })?;

        // Store in cache on success
        self.store_cache(&cache_key);

        Ok(())
    }

    /// Check if a token's lifetime is within the configured bounds.
    fn check_token_lifetime(&self, claims: &AgentCardClaims) -> Result<(), A2aError> {
        // SECURITY (R228-A2A-2): Fail-closed on system clock error instead of
        // defaulting to epoch 0. With unwrap_or(0), all tokens would be rejected
        // as "iat in the future" — fail-closed but with misleading diagnostics.
        // Explicit error provides actionable information.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| {
                A2aError::AgentCardInvalid(
                    "system clock error: cannot determine current time".to_string(),
                )
            })?;

        let skew = self.config.clock_skew_secs;

        // Check iat not too far in the future
        if claims.iat > now.saturating_add(skew) {
            self.increment_failures();
            return Err(A2aError::AgentCardInvalid(
                "claims iat is in the future (beyond clock skew tolerance)".to_string(),
            ));
        }

        // Check expiration
        if claims.exp.saturating_add(skew) < now {
            self.increment_failures();
            return Err(A2aError::AgentCardInvalid(
                "agent card signature has expired".to_string(),
            ));
        }

        // Check lifetime is not excessive
        let lifetime = claims.exp.saturating_sub(claims.iat);
        if lifetime > self.config.max_token_lifetime_secs {
            self.increment_failures();
            return Err(A2aError::AgentCardInvalid(format!(
                "token lifetime {} seconds exceeds maximum {} seconds",
                lifetime, self.config.max_token_lifetime_secs
            )));
        }

        // Check lifetime is not too short
        if lifetime < MIN_TOKEN_LIFETIME_SECS {
            self.increment_failures();
            return Err(A2aError::AgentCardInvalid(format!(
                "token lifetime {} seconds is below minimum {} seconds",
                lifetime, MIN_TOKEN_LIFETIME_SECS
            )));
        }

        Ok(())
    }

    /// Check the verification cache for a recent positive result.
    fn check_cache(&self, cache_key: &str) -> bool {
        let cache = match self.verification_cache.read() {
            Ok(c) => c,
            Err(_) => {
                tracing::error!(
                    target: "vellaveto::security",
                    "AgentCardSignatureVerifier cache read lock poisoned"
                );
                return false;
            }
        };
        if let Some(entry) = cache.get(cache_key) {
            if entry.valid && entry.verified_at.elapsed() < self.cache_ttl {
                return true;
            }
        }
        false
    }

    /// Store a positive verification result in the cache.
    fn store_cache(&self, cache_key: &str) {
        let mut cache = match self.verification_cache.write() {
            Ok(c) => c,
            Err(_) => {
                tracing::error!(
                    target: "vellaveto::security",
                    "AgentCardSignatureVerifier cache write lock poisoned"
                );
                return;
            }
        };
        // Evict expired entries first
        let ttl = self.cache_ttl;
        cache.retain(|_, v| v.verified_at.elapsed() < ttl);
        // Evict oldest if at capacity
        while cache.len() >= MAX_SIG_CACHE_ENTRIES {
            if let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, v)| v.verified_at)
                .map(|(k, _)| k.clone())
            {
                cache.remove(&oldest_key);
            } else {
                break;
            }
        }
        cache.insert(
            cache_key.to_string(),
            CachedVerification {
                valid: true,
                verified_at: Instant::now(),
            },
        );
    }

    /// Increment the failure counter.
    fn increment_failures(&self) {
        self.failure_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// Get the total number of verifications attempted.
    pub fn total_verifications(&self) -> u64 {
        self.verification_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get the total number of verification failures.
    pub fn total_failures(&self) -> u64 {
        self.failure_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Clear the verification cache.
    pub fn clear_cache(&self) {
        let mut cache = match self.verification_cache.write() {
            Ok(c) => c,
            Err(_) => {
                tracing::error!(
                    target: "vellaveto::security",
                    "AgentCardSignatureVerifier cache write lock poisoned during clear"
                );
                return;
            }
        };
        cache.clear();
    }
}

/// Compute the SHA-256 hash of an Agent Card's JSON representation.
pub fn compute_card_hash(card_json: &[u8]) -> String {
    let hash = Sha256::digest(card_json);
    hex::encode(hash)
}

/// Constant-time byte comparison to prevent timing side channels.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

// Import base64 engine for decode
use base64::Engine;

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn test_keypair() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::generate(&mut rand::rng());
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn make_claims(card_json: &[u8], iss: &str) -> AgentCardClaims {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        AgentCardClaims {
            iss: iss.to_string(),
            sub: "https://agent.example.com".to_string(),
            iat: now,
            exp: now + 3600,
            kid: None,
            card_hash: compute_card_hash(card_json),
        }
    }

    fn sign_card(signing_key: &SigningKey, card_json: &[u8]) -> String {
        let signature = signing_key.sign(card_json);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes())
    }

    // ── AgentSigningKey creation ────────────────────────────────────────

    #[test]
    fn test_agent_signing_key_new_valid() {
        let (_, verifying_key) = test_keypair();
        let key = AgentSigningKey::new(
            "key-1",
            verifying_key.as_bytes(),
            "https://issuer.example.com",
        );
        assert!(key.is_ok());
        let key = key.unwrap();
        assert_eq!(key.key_id, "key-1");
        assert_eq!(key.issuer, "https://issuer.example.com");
    }

    #[test]
    fn test_agent_signing_key_new_invalid_key_bytes() {
        let result = AgentSigningKey::new("key-1", &[0u8; 16], "issuer");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("32 bytes"));
    }

    #[test]
    fn test_agent_signing_key_new_key_id_too_long() {
        let (_, vk) = test_keypair();
        let result = AgentSigningKey::new(&"k".repeat(257), vk.as_bytes(), "issuer");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("key_id length"));
    }

    #[test]
    fn test_agent_signing_key_new_dangerous_chars_in_key_id() {
        let (_, vk) = test_keypair();
        let result = AgentSigningKey::new("key\x00id", vk.as_bytes(), "issuer");
        assert!(
            result.is_err(),
            "expected error for key_id with NUL byte, got: {:?}",
            result
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("control or Unicode format characters"),
            "unexpected error: {}",
            err_msg
        );
    }

    #[test]
    fn test_agent_signing_key_new_issuer_too_long() {
        let (_, vk) = test_keypair();
        let result = AgentSigningKey::new("key-1", vk.as_bytes(), &"i".repeat(513));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("issuer length"));
    }

    #[test]
    fn test_agent_signing_key_debug_redacts() {
        let (_, vk) = test_keypair();
        let key = AgentSigningKey::new("key-1", vk.as_bytes(), "issuer").unwrap();
        let debug_str = format!("{:?}", key);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains(&hex::encode(vk.as_bytes())));
    }

    // ── AgentCardClaims validation ──────────────────────────────────────

    #[test]
    fn test_claims_validate_valid() {
        let card_json = b"{}";
        let claims = make_claims(card_json, "https://issuer.example.com");
        assert!(claims.validate().is_ok());
    }

    #[test]
    fn test_claims_validate_empty_issuer_rejected() {
        let mut claims = make_claims(b"{}", "iss");
        claims.iss = String::new();
        assert!(claims.validate().is_err());
    }

    #[test]
    fn test_claims_validate_exp_before_iat_rejected() {
        let mut claims = make_claims(b"{}", "iss");
        claims.exp = claims.iat;
        assert!(claims.validate().is_err());
    }

    #[test]
    fn test_claims_validate_bad_card_hash_rejected() {
        let mut claims = make_claims(b"{}", "iss");
        claims.card_hash = "short".to_string();
        assert!(claims.validate().is_err());
    }

    // ── SignatureEnforcementConfig defaults ──────────────────────────────

    #[test]
    fn test_config_defaults_are_fail_closed() {
        let config = SignatureEnforcementConfig::default();
        assert!(config.enabled);
        assert!(config.require_card_hash_match);
        assert_eq!(config.max_token_lifetime_secs, 86_400);
    }

    // ── Verifier: add/remove trusted keys ───────────────────────────────

    #[test]
    fn test_verifier_add_trusted_key() {
        let verifier = AgentCardSignatureVerifier::new(SignatureEnforcementConfig::default());
        let (_, vk) = test_keypair();
        let key = AgentSigningKey::new("key-1", vk.as_bytes(), "issuer").unwrap();
        assert!(verifier.add_trusted_key(key).is_ok());
        assert_eq!(verifier.trusted_key_count(), 1);
    }

    #[test]
    fn test_verifier_remove_trusted_key() {
        let verifier = AgentCardSignatureVerifier::new(SignatureEnforcementConfig::default());
        let (_, vk) = test_keypair();
        let key = AgentSigningKey::new("key-1", vk.as_bytes(), "issuer").unwrap();
        verifier.add_trusted_key(key).unwrap();
        assert!(verifier.remove_trusted_key("key-1").unwrap());
        assert!(!verifier.remove_trusted_key("key-1").unwrap());
        assert_eq!(verifier.trusted_key_count(), 0);
    }

    // ── Verifier: successful verification ───────────────────────────────

    #[test]
    fn test_verify_card_valid_signature() {
        let (sk, vk) = test_keypair();
        let verifier = AgentCardSignatureVerifier::new(SignatureEnforcementConfig::default());
        let key =
            AgentSigningKey::new("key-1", vk.as_bytes(), "https://issuer.example.com").unwrap();
        verifier.add_trusted_key(key).unwrap();

        let card_json = br#"{"name":"Test Agent","url":"https://agent.example.com","version":"1.0","capabilities":{}}"#;
        let signature = sign_card(&sk, card_json);
        let claims = make_claims(card_json, "https://issuer.example.com");

        let result = verifier.verify_card(card_json, &signature, &claims);
        assert!(result.is_ok(), "verify_card failed: {:?}", result.err());
        assert_eq!(verifier.total_verifications(), 1);
        assert_eq!(verifier.total_failures(), 0);
    }

    // ── Verifier: invalid signature ─────────────────────────────────────

    #[test]
    fn test_verify_card_wrong_signature_rejected() {
        let (_, vk) = test_keypair();
        let (other_sk, _) = test_keypair(); // Different key
        let verifier = AgentCardSignatureVerifier::new(SignatureEnforcementConfig::default());
        let key =
            AgentSigningKey::new("key-1", vk.as_bytes(), "https://issuer.example.com").unwrap();
        verifier.add_trusted_key(key).unwrap();

        let card_json = b"test card";
        let wrong_sig = sign_card(&other_sk, card_json);
        let claims = make_claims(card_json, "https://issuer.example.com");

        let result = verifier.verify_card(card_json, &wrong_sig, &claims);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("signature verification failed"));
        assert_eq!(verifier.total_failures(), 1);
    }

    // ── Verifier: tampered payload ──────────────────────────────────────

    #[test]
    fn test_verify_card_tampered_payload_rejected() {
        let (sk, vk) = test_keypair();
        let verifier = AgentCardSignatureVerifier::new(SignatureEnforcementConfig::default());
        let key =
            AgentSigningKey::new("key-1", vk.as_bytes(), "https://issuer.example.com").unwrap();
        verifier.add_trusted_key(key).unwrap();

        let card_json = b"original payload";
        let signature = sign_card(&sk, card_json);
        let claims = make_claims(card_json, "https://issuer.example.com");

        // Tamper with the payload
        let tampered = b"tampered payload";
        let result = verifier.verify_card(tampered, &signature, &claims);
        assert!(result.is_err());
        // Either hash mismatch or signature mismatch
    }

    // ── Verifier: expired token ─────────────────────────────────────────

    #[test]
    fn test_verify_card_expired_token_rejected() {
        let (sk, vk) = test_keypair();
        let verifier = AgentCardSignatureVerifier::new(SignatureEnforcementConfig {
            clock_skew_secs: 0, // No skew tolerance
            ..SignatureEnforcementConfig::default()
        });
        let key =
            AgentSigningKey::new("key-1", vk.as_bytes(), "https://issuer.example.com").unwrap();
        verifier.add_trusted_key(key).unwrap();

        let card_json = b"card data";
        let signature = sign_card(&sk, card_json);
        let mut claims = make_claims(card_json, "https://issuer.example.com");
        // Set expiration to the past
        claims.iat = claims.iat.saturating_sub(7200);
        claims.exp = claims.iat.saturating_add(3600);

        let result = verifier.verify_card(card_json, &signature, &claims);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    // ── Verifier: excessive lifetime ────────────────────────────────────

    #[test]
    fn test_verify_card_excessive_lifetime_rejected() {
        let (sk, vk) = test_keypair();
        let verifier = AgentCardSignatureVerifier::new(SignatureEnforcementConfig {
            max_token_lifetime_secs: 3600,
            ..SignatureEnforcementConfig::default()
        });
        let key =
            AgentSigningKey::new("key-1", vk.as_bytes(), "https://issuer.example.com").unwrap();
        verifier.add_trusted_key(key).unwrap();

        let card_json = b"card data";
        let signature = sign_card(&sk, card_json);
        let mut claims = make_claims(card_json, "https://issuer.example.com");
        claims.exp = claims.iat + 86_400; // 24 hours > 1 hour max

        let result = verifier.verify_card(card_json, &signature, &claims);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
    }

    // ── Verifier: too-short lifetime ────────────────────────────────────

    #[test]
    fn test_verify_card_too_short_lifetime_rejected() {
        let (sk, vk) = test_keypair();
        let verifier = AgentCardSignatureVerifier::new(SignatureEnforcementConfig::default());
        let key =
            AgentSigningKey::new("key-1", vk.as_bytes(), "https://issuer.example.com").unwrap();
        verifier.add_trusted_key(key).unwrap();

        let card_json = b"card data";
        let signature = sign_card(&sk, card_json);
        let mut claims = make_claims(card_json, "https://issuer.example.com");
        claims.exp = claims.iat + 30; // 30 seconds < 60 second minimum

        let result = verifier.verify_card(card_json, &signature, &claims);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("below minimum"));
    }

    // ── Verifier: no trusted key ────────────────────────────────────────

    #[test]
    fn test_verify_card_no_trusted_key_rejected() {
        let (sk, _) = test_keypair();
        let verifier = AgentCardSignatureVerifier::new(SignatureEnforcementConfig::default());

        let card_json = b"card data";
        let signature = sign_card(&sk, card_json);
        let claims = make_claims(card_json, "https://unknown-issuer.example.com");

        let result = verifier.verify_card(card_json, &signature, &claims);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no trusted key"));
    }

    // ── Verifier: disabled enforcement passes ───────────────────────────

    #[test]
    fn test_verify_card_disabled_enforcement_passes() {
        let verifier = AgentCardSignatureVerifier::new(SignatureEnforcementConfig {
            enabled: false,
            ..SignatureEnforcementConfig::default()
        });

        let result = verifier.verify_card(b"anything", "bad-sig", &make_claims(b"x", "iss"));
        assert!(result.is_ok());
    }

    // ── Verifier: oversized inputs ──────────────────────────────────────

    #[test]
    fn test_verify_card_oversized_payload_rejected() {
        let verifier = AgentCardSignatureVerifier::new(SignatureEnforcementConfig::default());
        let huge = vec![0u8; MAX_SIGNED_PAYLOAD_SIZE + 1];
        let claims = make_claims(&huge, "iss");
        let result = verifier.verify_card(&huge, "sig", &claims);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("payload size"));
    }

    #[test]
    fn test_verify_card_oversized_signature_rejected() {
        let verifier = AgentCardSignatureVerifier::new(SignatureEnforcementConfig::default());
        let big_sig = "A".repeat(MAX_SIGNATURE_LENGTH + 1);
        let claims = make_claims(b"card", "iss");
        let result = verifier.verify_card(b"card", &big_sig, &claims);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("signature length"));
    }

    // ── Verifier: cache hit ─────────────────────────────────────────────

    #[test]
    fn test_verify_card_cache_hit_on_second_call() {
        let (sk, vk) = test_keypair();
        let verifier = AgentCardSignatureVerifier::new(SignatureEnforcementConfig::default());
        let key =
            AgentSigningKey::new("key-1", vk.as_bytes(), "https://issuer.example.com").unwrap();
        verifier.add_trusted_key(key).unwrap();

        let card_json = br#"{"name":"Test"}"#;
        let signature = sign_card(&sk, card_json);
        let claims = make_claims(card_json, "https://issuer.example.com");

        // First call verifies signature
        verifier
            .verify_card(card_json, &signature, &claims)
            .unwrap();
        // Second call should hit cache
        verifier
            .verify_card(card_json, &signature, &claims)
            .unwrap();
        assert_eq!(verifier.total_verifications(), 2);
    }

    // ── Verifier: clear cache ───────────────────────────────────────────

    #[test]
    fn test_verifier_clear_cache() {
        let verifier = AgentCardSignatureVerifier::new(SignatureEnforcementConfig::default());
        verifier.clear_cache();
        // No panic
    }

    // ── compute_card_hash ───────────────────────────────────────────────

    #[test]
    fn test_compute_card_hash_deterministic() {
        let hash1 = compute_card_hash(b"hello");
        let hash2 = compute_card_hash(b"hello");
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn test_compute_card_hash_different_inputs_differ() {
        assert_ne!(compute_card_hash(b"a"), compute_card_hash(b"b"));
    }

    // ── constant_time_eq ────────────────────────────────────────────────

    #[test]
    fn test_constant_time_eq_equal() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn test_constant_time_eq_not_equal() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"hi", b"hello"));
    }

    // ── Verifier: iat in future rejected ────────────────────────────────

    #[test]
    fn test_verify_card_future_iat_rejected() {
        let (sk, vk) = test_keypair();
        let verifier = AgentCardSignatureVerifier::new(SignatureEnforcementConfig {
            clock_skew_secs: 60,
            ..SignatureEnforcementConfig::default()
        });
        let key =
            AgentSigningKey::new("key-1", vk.as_bytes(), "https://issuer.example.com").unwrap();
        verifier.add_trusted_key(key).unwrap();

        let card_json = b"card";
        let signature = sign_card(&sk, card_json);
        let mut claims = make_claims(card_json, "https://issuer.example.com");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // iat 10 minutes in the future (well beyond 60s skew)
        claims.iat = now + 600;
        claims.exp = claims.iat + 3600;

        let result = verifier.verify_card(card_json, &signature, &claims);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("future"));
    }

    // ── Verifier: issuer mismatch with key ──────────────────────────────

    #[test]
    fn test_verify_card_issuer_mismatch_rejected() {
        let (sk, vk) = test_keypair();
        let verifier = AgentCardSignatureVerifier::new(SignatureEnforcementConfig::default());
        let key =
            AgentSigningKey::new("key-1", vk.as_bytes(), "https://trusted-issuer.com").unwrap();
        verifier.add_trusted_key(key).unwrap();

        let card_json = b"card";
        let signature = sign_card(&sk, card_json);
        // Claims use a different issuer than the trusted key
        let claims = make_claims(card_json, "https://evil-issuer.com");

        let result = verifier.verify_card(card_json, &signature, &claims);
        assert!(result.is_err());
    }

    // ── R230-A2A-1: Fallback key match must not cross kid boundaries ──

    #[test]
    fn test_r230_kid_specified_no_fallback_to_issuer_match() {
        // When kid is explicitly set, a key with the same issuer but different
        // key_id must NOT be used for verification (no fallback).
        let (sk1, vk1) = test_keypair();
        let (_, _vk2) = test_keypair();
        let verifier = AgentCardSignatureVerifier::new(SignatureEnforcementConfig::default());

        // Register key with key_id "key-actual"
        let key1 = AgentSigningKey::new("key-actual", vk1.as_bytes(), "https://issuer.example.com")
            .unwrap();
        verifier.add_trusted_key(key1).unwrap();

        let card_json = br#"{"name":"test-agent","version":"1.0"}"#;
        let signature = sign_card(&sk1, card_json);

        // Claims specify kid="key-WRONG" (not "key-actual")
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let claims = AgentCardClaims {
            iss: "https://issuer.example.com".to_string(),
            sub: "https://agent.example.com".to_string(),
            iat: now,
            exp: now + 3600,
            kid: Some("key-WRONG".to_string()),
            card_hash: compute_card_hash(card_json),
        };

        // Must fail: kid is specified but doesn't match any registered key,
        // and R230-A2A-1 prevents fallback to issuer-based lookup.
        let result = verifier.verify_card(card_json, &signature, &claims);
        assert!(
            result.is_err(),
            "Expected error when kid doesn't match any key"
        );
        assert!(
            result.unwrap_err().to_string().contains("no trusted key"),
            "Should report no trusted key found"
        );
    }

    #[test]
    fn test_r230_kid_absent_allows_issuer_fallback() {
        // When kid is NOT set, fallback to issuer-based lookup is allowed.
        let (sk1, vk1) = test_keypair();
        let verifier = AgentCardSignatureVerifier::new(SignatureEnforcementConfig::default());

        let key1 = AgentSigningKey::new(
            "internal-key-1",
            vk1.as_bytes(),
            "https://issuer.example.com",
        )
        .unwrap();
        verifier.add_trusted_key(key1).unwrap();

        let card_json = br#"{"name":"test-agent","version":"1.0"}"#;
        let signature = sign_card(&sk1, card_json);

        // Claims with NO kid — should fall back to issuer-based lookup
        let claims = make_claims(card_json, "https://issuer.example.com");

        let result = verifier.verify_card(card_json, &signature, &claims);
        assert!(
            result.is_ok(),
            "Should succeed via issuer fallback when kid absent"
        );
    }

    // ── Debug output ────────────────────────────────────────────────────

    #[test]
    fn test_verifier_debug_does_not_leak_keys() {
        let verifier = AgentCardSignatureVerifier::new(SignatureEnforcementConfig::default());
        let debug_str = format!("{:?}", verifier);
        assert!(debug_str.contains("AgentCardSignatureVerifier"));
        assert!(debug_str.contains("trusted_keys_count"));
    }
}
