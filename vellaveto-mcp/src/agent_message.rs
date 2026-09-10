// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Inter-Agent Message Signing (Phase 3.2)
//!
//! Provides cryptographic signing and verification for inter-agent messages
//! to ensure message integrity and prevent tampering in multi-agent systems.
//!
//! Features:
//! - Ed25519 message signing over a length-delimited
//!   `sender ‖ recipient ‖ payload ‖ nonce ‖ timestamp` preimage
//! - Anti-replay: a 32-byte CSPRNG nonce and a Unix timestamp, both covered by
//!   the signature, checked against a bounded freshness window in both
//!   directions and a seen-nonce cache scoped to that window
//! - Signature verification against a registered sender key
//!
//! # Replay protection: what this does and does not give you
//!
//! A nonce alone is not replay protection — it makes messages distinguishable,
//! but nothing stops a captured message being resent. What bounds the attack is
//! the pairing: the timestamp limits how long a captured message stays useful,
//! and the nonce cache rejects anything already seen inside that window. Both
//! are covered by the signature, so neither can be edited in transit. This is
//! the same shape as using a TAI64N timestamp directly as the nonce, with the
//! two kept as separate fields so that messages created within one clock tick
//! do not collide.
//!
//! Two limits worth knowing:
//!
//! - [`NonceTracker`] is **per-process**. It does not survive a restart and is
//!   not shared between replicas, so replay protection is scoped to a single
//!   process — a replay to a different replica, or after a restart, is not
//!   caught here.
//! - Freshness depends on the local clock, and the sender's and verifier's
//!   clocks are compared without any external time source. A verifier with a
//!   badly skewed clock will reject fresh messages or accept stale ones.
//!
//! This module provides the primitives. As of this writing they are **not
//! wired into the relay path** — see DOC-CRED-5 in `docs/AUDIT_LOG.md`.
//!
//! Reference: MCP 2025-11-25 Security Best Practices

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Errors that can occur during message signing/verification.
#[derive(Error, Debug, Clone)]
pub enum MessageError {
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Message expired: age {age_secs}s exceeds max {max_secs}s")]
    MessageExpired { age_secs: u64, max_secs: u64 },
    #[error("Nonce already seen (replay attack)")]
    NonceReplay,
    #[error("Invalid nonce format")]
    InvalidNonce,
    #[error("Signature verification failed: {0}")]
    VerificationFailed(String),
    #[error("Missing sender public key")]
    MissingSenderKey,
    /// SECURITY (FIND-027): Random nonce generation failed (no entropy).
    #[error("Random nonce generation failed")]
    RandomGeneratorFailed,
    /// SECURITY (R239-MCP-9): Invalid sender or recipient ID.
    #[error("Invalid sender/recipient: {0}")]
    InvalidSender(String),
}

/// Signed inter-agent message envelope.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAgentMessage {
    /// Agent ID of the sender
    pub sender: String,
    /// Agent ID of the recipient
    pub recipient: String,
    /// Message payload (serialized)
    pub payload: Vec<u8>,
    /// Ed25519 signature over (sender || recipient || payload || nonce || timestamp)
    #[serde(with = "signature_serde")]
    pub signature: [u8; 64],
    /// Random nonce for replay protection
    pub nonce: [u8; 32],
    /// Unix timestamp (seconds)
    pub timestamp: u64,
}

// SECURITY (R239-XCUT-6): Custom Debug redacts signature and nonce to prevent
// cryptographic material leakage in logs.
impl std::fmt::Debug for SignedAgentMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedAgentMessage")
            .field("sender", &self.sender)
            .field("recipient", &self.recipient)
            .field("payload_len", &self.payload.len())
            .field("signature", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

/// Custom serde for signature bytes
mod signature_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("signature must be 64 bytes"));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// Maximum length for agent ID fields in signed messages.
const MAX_AGENT_ID_LEN: usize = 512;
/// Maximum payload size for signed messages (1 MB).
const MAX_SIGNED_PAYLOAD_LEN: usize = 1_048_576;

impl SignedAgentMessage {
    /// SECURITY (R241-MCP-2): Validate deserialized message fields before processing.
    pub fn validate(&self) -> Result<(), MessageError> {
        if self.sender.len() > MAX_AGENT_ID_LEN {
            return Err(MessageError::InvalidSender(format!(
                "sender length {} exceeds max {MAX_AGENT_ID_LEN}",
                self.sender.len()
            )));
        }
        if vellaveto_types::has_dangerous_chars(&self.sender) {
            return Err(MessageError::InvalidSender(
                "sender contains dangerous characters".to_string(),
            ));
        }
        if self.recipient.len() > MAX_AGENT_ID_LEN {
            return Err(MessageError::InvalidSender(format!(
                "recipient length {} exceeds max {MAX_AGENT_ID_LEN}",
                self.recipient.len()
            )));
        }
        if vellaveto_types::has_dangerous_chars(&self.recipient) {
            return Err(MessageError::InvalidSender(
                "recipient contains dangerous characters".to_string(),
            ));
        }
        if self.payload.len() > MAX_SIGNED_PAYLOAD_LEN {
            return Err(MessageError::InvalidSender(format!(
                "payload length {} exceeds max {MAX_SIGNED_PAYLOAD_LEN}",
                self.payload.len()
            )));
        }
        Ok(())
    }

    /// Sign a message with the sender's private key.
    /// SECURITY (FIND-027): Returns Result to handle RNG failure without panic.
    pub fn sign(
        sender_key: &SigningKey,
        sender_id: &str,
        recipient: &str,
        payload: &[u8],
    ) -> Result<Self, MessageError> {
        // SECURITY (R239-MCP-9): Validate sender_id and recipient for dangerous chars.
        if vellaveto_types::has_dangerous_chars(sender_id) {
            return Err(MessageError::InvalidSender(
                "sender_id contains dangerous characters".to_string(),
            ));
        }
        if vellaveto_types::has_dangerous_chars(recipient) {
            return Err(MessageError::InvalidSender(
                "recipient contains dangerous characters".to_string(),
            ));
        }

        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| MessageError::RandomGeneratorFailed)?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let message_bytes =
            Self::build_signing_input(sender_id, recipient, payload, &nonce, timestamp);
        let signature = sender_key.sign(&message_bytes);

        Ok(Self {
            sender: sender_id.to_string(),
            recipient: recipient.to_string(),
            payload: payload.to_vec(),
            signature: signature.to_bytes(),
            nonce,
            timestamp,
        })
    }

    /// Verify the message signature, freshness, and nonce novelty.
    ///
    /// Replay protection needs all three of these together, and none of them is
    /// sufficient alone:
    ///
    /// - The **nonce** is 32 random bytes covered by the signature, so it
    ///   cannot be altered without invalidating the message. On its own it only
    ///   makes messages distinguishable — it does not stop a captured message
    ///   from being resent.
    /// - The **timestamp** is also covered by the signature and is checked in
    ///   both directions against `max_age_secs`: stale messages are rejected,
    ///   and so are far-future ones (which would otherwise bypass the age check
    ///   through `saturating_sub` returning 0). This bounds how long a captured
    ///   message stays useful.
    /// - The **nonce tracker** rejects a nonce seen before within that window.
    ///   It is required, not optional: a bounded freshness window without a
    ///   seen-nonce cache still admits replays inside the window.
    ///
    /// # Arguments
    /// * `sender_pubkey` - The sender's public key for verification
    /// * `max_age_secs` - Maximum allowed message age in seconds, in both
    ///   directions. The tracker's retention window should be at least this
    ///   long, or a nonce can be forgotten while its message is still fresh.
    /// * `nonce_tracker` - Seen-nonce cache. Per-process: it does not survive a
    ///   restart and is not shared across replicas, so replay protection is
    ///   scoped to one process.
    ///
    /// # Errors
    /// Returns [`MessageError::NonceReplay`] if the nonce has been seen,
    /// [`MessageError::MessageExpired`] if the timestamp is outside the window,
    /// and [`MessageError::InvalidSignature`] if verification fails.
    pub fn verify(
        &self,
        sender_pubkey: &VerifyingKey,
        max_age_secs: u64,
        nonce_tracker: &NonceTracker,
    ) -> Result<(), MessageError> {
        // SECURITY (R241-MCP-2): Validate fields before processing.
        self.validate()?;

        // Check message freshness
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // SECURITY (R241-MCP-1): Reject far-future timestamps that would bypass the
        // age check via saturating_sub returning 0. Allow modest clock skew (same window
        // as max_age_secs) but reject timestamps beyond that.
        if self.timestamp > now.saturating_add(max_age_secs) {
            return Err(MessageError::MessageExpired {
                age_secs: 0,
                max_secs: max_age_secs,
            });
        }

        let age = now.saturating_sub(self.timestamp);
        if age > max_age_secs {
            return Err(MessageError::MessageExpired {
                age_secs: age,
                max_secs: max_age_secs,
            });
        }

        // SECURITY (DOC-CRED-5): Replay check is mandatory. This was previously
        // `Option<&NonceTracker>`, so passing `None` silently disabled replay
        // protection while the freshness check above still passed — a fail-open
        // default in a security API.
        if !nonce_tracker.check_and_record(&self.nonce) {
            return Err(MessageError::NonceReplay);
        }

        // Verify signature
        let message_bytes = Self::build_signing_input(
            &self.sender,
            &self.recipient,
            &self.payload,
            &self.nonce,
            self.timestamp,
        );

        let signature = Signature::from_bytes(&self.signature);
        sender_pubkey
            .verify(&message_bytes, &signature)
            .map_err(|e| MessageError::VerificationFailed(e.to_string()))
    }

    /// Build the byte string to be signed.
    fn build_signing_input(
        sender: &str,
        recipient: &str,
        payload: &[u8],
        nonce: &[u8; 32],
        timestamp: u64,
    ) -> Vec<u8> {
        let mut input = Vec::new();
        input.extend_from_slice(sender.as_bytes());
        input.push(0); // Separator
        input.extend_from_slice(recipient.as_bytes());
        input.push(0);
        input.extend_from_slice(payload);
        input.push(0);
        input.extend_from_slice(nonce);
        input.extend_from_slice(&timestamp.to_be_bytes());
        input
    }

    /// Get the payload as a string (if valid UTF-8).
    pub fn payload_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.payload).ok()
    }
}

/// Anti-replay nonce tracker.
///
/// Keeps track of seen nonces within a configurable time window
/// to prevent message replay attacks.
pub struct NonceTracker {
    /// Seen nonces with their first-seen time
    seen_nonces: RwLock<HashMap<[u8; 32], Instant>>,
    /// How long to remember nonces
    expiry_duration: Duration,
    /// Maximum number of nonces to track (memory limit)
    max_nonces: usize,
}

impl NonceTracker {
    /// Create a new nonce tracker with the specified expiry.
    pub fn new(expiry_secs: u64) -> Self {
        Self::with_config(expiry_secs, 100_000)
    }

    /// Create a new nonce tracker with custom configuration.
    pub fn with_config(expiry_secs: u64, max_nonces: usize) -> Self {
        Self {
            seen_nonces: RwLock::new(HashMap::new()),
            expiry_duration: Duration::from_secs(expiry_secs),
            max_nonces,
        }
    }

    /// Check if a nonce has been seen and record it if not.
    ///
    /// Returns `true` if the nonce is new (not a replay).
    /// Returns `false` if the nonce was already seen (replay attack).
    pub fn check_and_record(&self, nonce: &[u8; 32]) -> bool {
        let now = Instant::now();

        let mut seen = match self.seen_nonces.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in NonceTracker::check_and_record");
                return false; // fail-closed: treat as replay (block the message)
            }
        };

        // Clean up expired nonces first
        seen.retain(|_, first_seen| now.duration_since(*first_seen) < self.expiry_duration);

        // Check if nonce exists
        if seen.contains_key(nonce) {
            return false;
        }

        // Check capacity
        if seen.len() >= self.max_nonces {
            // Remove oldest nonce
            if let Some(oldest_key) = seen.iter().min_by_key(|(_, time)| *time).map(|(k, _)| *k) {
                seen.remove(&oldest_key);
            }
        }

        // Record new nonce
        seen.insert(*nonce, now);
        true
    }

    /// Check if a nonce has been seen (without recording).
    pub fn is_seen(&self, nonce: &[u8; 32]) -> bool {
        let seen = match self.seen_nonces.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in NonceTracker::is_seen");
                return true; // fail-closed: assume seen (block)
            }
        };
        seen.contains_key(nonce)
    }

    /// Get the number of tracked nonces.
    pub fn count(&self) -> usize {
        let seen = match self.seen_nonces.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in NonceTracker::count");
                return 0;
            }
        };
        seen.len()
    }

    /// Clear all tracked nonces.
    pub fn clear(&self) {
        let mut seen = match self.seen_nonces.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in NonceTracker::clear");
                return;
            }
        };
        seen.clear();
    }

    /// Perform cleanup of expired nonces.
    pub fn cleanup(&self) {
        let now = Instant::now();
        let mut seen = match self.seen_nonces.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in NonceTracker::cleanup");
                return;
            }
        };
        seen.retain(|_, first_seen| now.duration_since(*first_seen) < self.expiry_duration);
    }
}

impl Default for NonceTracker {
    fn default() -> Self {
        Self::new(300) // 5 minutes default
    }
}

/// Agent key pair for signing messages.
#[derive(Clone)]
pub struct AgentKeyPair {
    /// The agent's signing key (private)
    signing_key: SigningKey,
    /// The agent's verifying key (public)
    verifying_key: VerifyingKey,
    /// Agent ID
    agent_id: String,
}

impl AgentKeyPair {
    /// Generate a new random key pair.
    pub fn generate(agent_id: &str) -> Self {
        let signing_key = SigningKey::generate(&mut rand::rng());
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
            agent_id: agent_id.to_string(),
        }
    }

    /// Create from an existing signing key.
    pub fn from_signing_key(agent_id: &str, signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
            agent_id: agent_id.to_string(),
        }
    }

    /// Get the agent ID.
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// Get the verifying (public) key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Sign a message to another agent.
    pub fn sign_message(
        &self,
        recipient: &str,
        payload: &[u8],
    ) -> Result<SignedAgentMessage, MessageError> {
        SignedAgentMessage::sign(&self.signing_key, &self.agent_id, recipient, payload)
    }

    /// Get the public key as bytes for sharing.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
}

/// SECURITY (FIND-R69-003): Maximum registered agent keys to prevent OOM.
const MAX_AGENT_KEYS: usize = 10_000;

/// Registry of known agent public keys.
pub struct AgentKeyRegistry {
    /// Agent ID -> Verifying key
    keys: RwLock<HashMap<String, VerifyingKey>>,
}

impl AgentKeyRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
        }
    }

    /// Register an agent's public key.
    pub fn register(&self, agent_id: &str, key: VerifyingKey) {
        let mut keys = match self.keys.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentKeyRegistry::register");
                return; // fail-closed: don't register with corrupted state
            }
        };
        // SECURITY (FIND-R69-003): Cap registered keys to prevent OOM.
        if !keys.contains_key(agent_id) && keys.len() >= MAX_AGENT_KEYS {
            tracing::warn!(
                max = MAX_AGENT_KEYS,
                "Agent key registry at capacity, rejecting new key"
            );
            return;
        }
        keys.insert(agent_id.to_string(), key);
    }

    /// Register an agent's public key from bytes.
    pub fn register_bytes(&self, agent_id: &str, key_bytes: &[u8; 32]) -> Result<(), MessageError> {
        let key = VerifyingKey::from_bytes(key_bytes)
            .map_err(|e| MessageError::VerificationFailed(e.to_string()))?;
        self.register(agent_id, key);
        Ok(())
    }

    /// Get an agent's public key.
    pub fn get(&self, agent_id: &str) -> Option<VerifyingKey> {
        let keys = match self.keys.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentKeyRegistry::get");
                return None; // fail-closed: no key = can't verify
            }
        };
        keys.get(agent_id).copied()
    }

    /// Remove an agent's public key.
    pub fn remove(&self, agent_id: &str) {
        let mut keys = match self.keys.write() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentKeyRegistry::remove");
                return;
            }
        };
        keys.remove(agent_id);
    }

    /// Check if an agent is registered.
    pub fn is_registered(&self, agent_id: &str) -> bool {
        let keys = match self.keys.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentKeyRegistry::is_registered");
                return false; // fail-closed: not registered = can't proceed
            }
        };
        keys.contains_key(agent_id)
    }

    /// Get the number of registered agents.
    pub fn count(&self) -> usize {
        let keys = match self.keys.read() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!(target: "vellaveto::security", "RwLock poisoned in AgentKeyRegistry::count");
                return 0;
            }
        };
        keys.len()
    }

    /// Verify a signed message using the registry.
    ///
    /// Resolves the sender's key from the registry, then applies the full
    /// check in [`SignedAgentMessage::verify`] — signature, bidirectional
    /// freshness window, and mandatory nonce novelty.
    pub fn verify_message(
        &self,
        message: &SignedAgentMessage,
        max_age_secs: u64,
        nonce_tracker: &NonceTracker,
    ) -> Result<(), MessageError> {
        let sender_key = self
            .get(&message.sender)
            .ok_or(MessageError::MissingSenderKey)?;

        message.verify(&sender_key, max_age_secs, nonce_tracker)
    }
}

impl Default for AgentKeyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let alice = AgentKeyPair::generate("alice");
        let registry = AgentKeyRegistry::new();
        registry.register("alice", *alice.verifying_key());

        let message = alice.sign_message("bob", b"Hello, Bob!").unwrap();

        assert_eq!(message.sender, "alice");
        assert_eq!(message.recipient, "bob");
        assert_eq!(message.payload, b"Hello, Bob!");

        // Verify with alice's public key
        let result = registry.verify_message(&message, 60, &NonceTracker::new(300));
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_wrong_key() {
        let alice = AgentKeyPair::generate("alice");
        let eve = AgentKeyPair::generate("eve");
        let registry = AgentKeyRegistry::new();
        // Register Eve's key as Alice's (simulating key confusion)
        registry.register("alice", *eve.verifying_key());

        let message = alice.sign_message("bob", b"Hello, Bob!").unwrap();

        // Verification should fail
        let result = registry.verify_message(&message, 60, &NonceTracker::new(300));
        assert!(matches!(result, Err(MessageError::VerificationFailed(_))));
    }

    #[test]
    fn test_message_expiry() {
        let alice = AgentKeyPair::generate("alice");
        let registry = AgentKeyRegistry::new();
        registry.register("alice", *alice.verifying_key());

        let mut message = alice.sign_message("bob", b"Hello!").unwrap();
        // Set timestamp to 2 hours ago
        message.timestamp -= 7200;

        // Re-sign with old timestamp (simulating expired message)
        // Note: In real usage, you can't re-sign without the private key,
        // so we test by creating a message with an old timestamp
        let result = registry.verify_message(&message, 60, &NonceTracker::new(300));
        assert!(matches!(result, Err(MessageError::MessageExpired { .. })));
    }

    #[test]
    fn test_nonce_replay_protection() {
        let alice = AgentKeyPair::generate("alice");
        let registry = AgentKeyRegistry::new();
        registry.register("alice", *alice.verifying_key());
        let nonce_tracker = NonceTracker::new(300);

        let message = alice.sign_message("bob", b"Hello!").unwrap();

        // First verification should succeed
        let result = registry.verify_message(&message, 60, &nonce_tracker);
        assert!(result.is_ok());

        // Replay should fail
        let result = registry.verify_message(&message, 60, &nonce_tracker);
        assert!(matches!(result, Err(MessageError::NonceReplay)));
    }

    /// SECURITY (DOC-CRED-5): A caller cannot opt out of replay protection.
    ///
    /// The tracker used to be `Option<&NonceTracker>`, so `None` disabled the
    /// replay check while the freshness window still passed — a replay inside
    /// the window was accepted. The signature is now `&NonceTracker`, so the
    /// only way to reach `verify` is with a tracker, and a message replayed
    /// well inside its freshness window is rejected.
    #[test]
    fn test_replay_within_freshness_window_is_rejected() {
        let alice = AgentKeyPair::generate("alice");
        let registry = AgentKeyRegistry::new();
        registry.register("alice", *alice.verifying_key());
        let nonce_tracker = NonceTracker::new(3600);

        let message = alice.sign_message("bob", b"transfer funds").unwrap();

        // A generous freshness window: the timestamp check cannot be what
        // rejects the replay here, so only the nonce cache can.
        assert!(registry
            .verify_message(&message, 3600, &nonce_tracker)
            .is_ok());

        for _ in 0..3 {
            assert!(
                matches!(
                    registry.verify_message(&message, 3600, &nonce_tracker),
                    Err(MessageError::NonceReplay)
                ),
                "a message replayed inside its freshness window must be rejected"
            );
        }
    }

    /// Distinct messages get distinct nonces, so the replay check does not
    /// reject legitimate traffic between the same pair of agents.
    #[test]
    fn test_distinct_messages_are_not_treated_as_replays() {
        let alice = AgentKeyPair::generate("alice");
        let registry = AgentKeyRegistry::new();
        registry.register("alice", *alice.verifying_key());
        let nonce_tracker = NonceTracker::new(300);

        for i in 0..8u8 {
            let message = alice.sign_message("bob", &[i]).unwrap();
            assert!(
                registry
                    .verify_message(&message, 60, &nonce_tracker)
                    .is_ok(),
                "message {i} was wrongly rejected as a replay"
            );
        }
    }

    #[test]
    fn test_nonce_tracker_cleanup() {
        let tracker = NonceTracker::with_config(1, 100); // 1 second expiry

        let nonce1 = [1u8; 32];
        assert!(tracker.check_and_record(&nonce1));
        assert!(tracker.is_seen(&nonce1));

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(1100));

        // Cleanup should remove expired nonce
        tracker.cleanup();
        assert!(!tracker.is_seen(&nonce1));

        // Should be able to use the same nonce again
        assert!(tracker.check_and_record(&nonce1));
    }

    #[test]
    fn test_nonce_tracker_capacity() {
        let tracker = NonceTracker::with_config(300, 3); // Max 3 nonces

        let nonce1 = [1u8; 32];
        let nonce2 = [2u8; 32];
        let nonce3 = [3u8; 32];
        let nonce4 = [4u8; 32];

        assert!(tracker.check_and_record(&nonce1));
        assert!(tracker.check_and_record(&nonce2));
        assert!(tracker.check_and_record(&nonce3));
        assert_eq!(tracker.count(), 3);

        // Adding 4th should evict oldest
        assert!(tracker.check_and_record(&nonce4));
        assert_eq!(tracker.count(), 3);
    }

    #[test]
    fn test_missing_sender_key() {
        let alice = AgentKeyPair::generate("alice");
        let registry = AgentKeyRegistry::new();
        // Don't register alice's key

        let message = alice.sign_message("bob", b"Hello!").unwrap();

        let result = registry.verify_message(&message, 60, &NonceTracker::new(300));
        assert!(matches!(result, Err(MessageError::MissingSenderKey)));
    }

    #[test]
    fn test_agent_key_registry() {
        let registry = AgentKeyRegistry::new();
        let alice = AgentKeyPair::generate("alice");

        assert!(!registry.is_registered("alice"));
        registry.register("alice", *alice.verifying_key());
        assert!(registry.is_registered("alice"));
        assert_eq!(registry.count(), 1);

        registry.remove("alice");
        assert!(!registry.is_registered("alice"));
    }

    #[test]
    fn test_payload_str() {
        let alice = AgentKeyPair::generate("alice");
        let message = alice.sign_message("bob", b"Hello, World!").unwrap();
        assert_eq!(message.payload_str(), Some("Hello, World!"));

        // Invalid UTF-8
        let message = alice.sign_message("bob", &[0xff, 0xfe]).unwrap();
        assert_eq!(message.payload_str(), None);
    }

    #[test]
    fn test_signed_agent_message_deny_unknown_fields() {
        let json = format!(
            r#"{{
                "sender": "alice",
                "recipient": "bob",
                "payload": [104, 105],
                "signature": "{}",
                "nonce": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                "timestamp": 123,
                "extra": true
            }}"#,
            "00".repeat(64)
        );

        let result: Result<SignedAgentMessage, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    // =========================================================================
    // R241-MCP-2: SignedAgentMessage validate() tests
    // =========================================================================

    #[test]
    fn test_validate_valid_message() {
        let msg = SignedAgentMessage {
            sender: "agent-a".to_string(),
            recipient: "agent-b".to_string(),
            payload: vec![1, 2, 3],
            signature: [0u8; 64],
            nonce: [0u8; 32],
            timestamp: 1000,
        };
        assert!(msg.validate().is_ok());
    }

    #[test]
    fn test_validate_sender_too_long() {
        let msg = SignedAgentMessage {
            sender: "a".repeat(600),
            recipient: "agent-b".to_string(),
            payload: vec![1, 2, 3],
            signature: [0u8; 64],
            nonce: [0u8; 32],
            timestamp: 1000,
        };
        let err = msg.validate().unwrap_err();
        assert!(err.to_string().contains("sender"), "{err}");
    }

    #[test]
    fn test_validate_sender_dangerous_chars() {
        let msg = SignedAgentMessage {
            sender: "agent\x00a".to_string(),
            recipient: "agent-b".to_string(),
            payload: vec![1, 2, 3],
            signature: [0u8; 64],
            nonce: [0u8; 32],
            timestamp: 1000,
        };
        let err = msg.validate().unwrap_err();
        assert!(err.to_string().contains("sender"), "{err}");
    }

    #[test]
    fn test_validate_recipient_too_long() {
        let msg = SignedAgentMessage {
            sender: "agent-a".to_string(),
            recipient: "b".repeat(600),
            payload: vec![1, 2, 3],
            signature: [0u8; 64],
            nonce: [0u8; 32],
            timestamp: 1000,
        };
        let err = msg.validate().unwrap_err();
        assert!(err.to_string().contains("recipient"), "{err}");
    }

    #[test]
    fn test_validate_recipient_dangerous_chars() {
        let msg = SignedAgentMessage {
            sender: "agent-a".to_string(),
            recipient: "agent\x1Bb".to_string(),
            payload: vec![1, 2, 3],
            signature: [0u8; 64],
            nonce: [0u8; 32],
            timestamp: 1000,
        };
        let err = msg.validate().unwrap_err();
        assert!(err.to_string().contains("recipient"), "{err}");
    }

    #[test]
    fn test_validate_payload_too_large() {
        let msg = SignedAgentMessage {
            sender: "agent-a".to_string(),
            recipient: "agent-b".to_string(),
            payload: vec![0u8; 2_000_000],
            signature: [0u8; 64],
            nonce: [0u8; 32],
            timestamp: 1000,
        };
        let err = msg.validate().unwrap_err();
        assert!(err.to_string().contains("payload"), "{err}");
    }

    #[test]
    fn test_verify_calls_validate() {
        // Verify that verify() rejects a message with dangerous chars in sender
        // BEFORE attempting signature verification.
        let key = SigningKey::generate(&mut rand::rng());
        let pubkey = key.verifying_key();
        let msg = SignedAgentMessage {
            sender: "agent\x00evil".to_string(),
            recipient: "bob".to_string(),
            payload: vec![],
            signature: [0u8; 64],
            nonce: {
                let mut n = [0u8; 32];
                getrandom::fill(&mut n).unwrap();
                n
            },
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        let err = msg
            .verify(&pubkey, 300, &NonceTracker::new(300))
            .unwrap_err();
        assert!(
            matches!(err, MessageError::InvalidSender(_)),
            "expected InvalidSender, got: {err}"
        );
    }
}
