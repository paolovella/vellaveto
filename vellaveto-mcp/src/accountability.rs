// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Accountability attestation signing and verification.
//!
//! Provides Ed25519 signing and verification of accountability attestations
//! that bind agents to policy compliance statements. Uses length-prefixed
//! content to prevent boundary collision attacks (same pattern as audit
//! checkpoints in `vellaveto-audit/src/checkpoints.rs`).
//!
//! Uses `ed25519-dalek`, `sha2`, `hex`, `chrono`, `uuid`, and `subtle`
//! (transitive dep of ed25519-dalek, now direct for constant-time comparison).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;
use vellaveto_types::{AccountabilityAttestation, AttestationVerificationResult};

/// SECURITY (FIND-R73-004): Maximum TTL for attestations (1 year).
/// Prevents `ttl_secs as i64` overflow on u64 values > i64::MAX.
const MAX_ATTESTATION_TTL_SECS: u64 = 365 * 24 * 3600;

/// SECURITY (IMP-R118-004/013): Maximum length for agent_id strings.
const MAX_AGENT_ID_LEN: usize = 256;

/// SECURITY (IMP-R118-013): Maximum length for statement strings.
const MAX_STATEMENT_LEN: usize = 4096;

/// SECURITY (IMP-R118-013): Maximum length for policy_hash strings.
const MAX_POLICY_HASH_LEN: usize = 256;

/// SECURITY (FIND-R186-002): Maximum clock skew (seconds) for created_at validation.
/// Parity with capability_token.rs MAX_ISSUED_AT_SKEW_SECS.
const MAX_CREATED_AT_SKEW_SECS: i64 = 60;

/// SECURITY (FIND-R174-007): Maximum length for DID strings.
const MAX_DID_LEN: usize = 512;

/// SECURITY (IMP-R118-004): Validate string has no control or Unicode format characters.
/// SECURITY (IMP-R120-008): Delegates to shared `has_dangerous_chars()` predicate.
fn validate_no_dangerous_chars(value: &str, field_name: &str) -> Result<(), AttestationError> {
    if vellaveto_types::has_dangerous_chars(value) {
        return Err(AttestationError::SigningFailed(format!(
            "{field_name} contains control or Unicode format characters"
        )));
    }
    Ok(())
}

/// Errors from attestation operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum AttestationError {
    /// The signing key is invalid (not valid hex or wrong length).
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    /// Signing failed.
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    /// Verification failed.
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    /// The attestation has expired.
    #[error("Attestation has expired")]
    Expired,
}

/// Sign an accountability attestation.
///
/// Creates a new attestation with:
/// - Length-prefixed SHA-256 of canonical content
/// - Ed25519 signature using the provided signing key
/// - Unique attestation ID (UUID v4)
/// - Expiration based on `ttl_secs`
///
/// # Content Format
///
/// The signed content is a length-prefixed concatenation of ALL semantically
/// significant fields to prevent boundary collision and field tampering attacks:
///
/// ```text
/// <attestation_id_len>:<attestation_id><agent_id_len>:<agent_id><did_len>:<did><statement_len>:<statement><policy_hash_len>:<policy_hash><created_at_len>:<created_at><expires_at_len>:<expires_at>
/// ```
/// Digest of an attestation's canonical content, bound to the accountability domain.
///
/// SECURITY (DOC-CRED-2): See `vellaveto_types::signing_domain`. `domain_separated`
/// is false only when verifying attestations issued before this change.
fn content_digest(canonical: &str, domain_separated: bool) -> Vec<u8> {
    let mut hasher = if domain_separated {
        vellaveto_types::signing_domain::domain_separated_hasher(
            vellaveto_types::signing_domain::DOMAIN_ACCOUNTABILITY,
        )
    } else {
        Sha256::new()
    };
    hasher.update(canonical.as_bytes());
    hasher.finalize().to_vec()
}

pub fn sign_attestation(
    agent_id: &str,
    did: Option<&str>,
    statement: &str,
    policy_hash: &str,
    signing_key_hex: &str,
    ttl_secs: u64,
) -> Result<AccountabilityAttestation, AttestationError> {
    // SECURITY (FIND-R73-004): Validate ttl_secs before casting to i64.
    if ttl_secs > MAX_ATTESTATION_TTL_SECS {
        return Err(AttestationError::SigningFailed(format!(
            "ttl_secs {ttl_secs} exceeds maximum {MAX_ATTESTATION_TTL_SECS} (1 year)"
        )));
    }

    // SECURITY (FIND-068): Validate required fields are non-empty.
    // Empty agent_id or statement would produce valid but meaningless attestations.
    if agent_id.is_empty() {
        return Err(AttestationError::SigningFailed(
            "agent_id must not be empty".to_string(),
        ));
    }
    if statement.is_empty() {
        return Err(AttestationError::SigningFailed(
            "statement must not be empty".to_string(),
        ));
    }
    if policy_hash.is_empty() {
        return Err(AttestationError::SigningFailed(
            "policy_hash must not be empty".to_string(),
        ));
    }

    // SECURITY (IMP-R118-013): Validate max lengths.
    if agent_id.len() > MAX_AGENT_ID_LEN {
        return Err(AttestationError::SigningFailed(format!(
            "agent_id length {} exceeds maximum {}",
            agent_id.len(),
            MAX_AGENT_ID_LEN
        )));
    }
    if statement.len() > MAX_STATEMENT_LEN {
        return Err(AttestationError::SigningFailed(format!(
            "statement length {} exceeds maximum {}",
            statement.len(),
            MAX_STATEMENT_LEN
        )));
    }
    if policy_hash.len() > MAX_POLICY_HASH_LEN {
        return Err(AttestationError::SigningFailed(format!(
            "policy_hash length {} exceeds maximum {}",
            policy_hash.len(),
            MAX_POLICY_HASH_LEN
        )));
    }

    // SECURITY (IMP-R118-004): Validate no control or Unicode format characters.
    validate_no_dangerous_chars(agent_id, "agent_id")?;
    validate_no_dangerous_chars(statement, "statement")?;
    validate_no_dangerous_chars(policy_hash, "policy_hash")?;
    if let Some(d) = did {
        // SECURITY (FIND-R174-007): Validate DID length.
        if d.len() > MAX_DID_LEN {
            return Err(AttestationError::SigningFailed(format!(
                "did length {} exceeds maximum {}",
                d.len(),
                MAX_DID_LEN
            )));
        }
        validate_no_dangerous_chars(d, "did")?;
    }

    // Parse signing key
    let key_bytes = hex::decode(signing_key_hex)
        .map_err(|e| AttestationError::InvalidKey(format!("hex decode failed: {e}")))?;
    if key_bytes.len() != 32 {
        return Err(AttestationError::InvalidKey(format!(
            "expected 32 bytes, got {}",
            key_bytes.len()
        )));
    }
    let signing_key = SigningKey::from_bytes(
        key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| AttestationError::InvalidKey("invalid key length".to_string()))?,
    );
    let verifying_key = signing_key.verifying_key();
    let public_key_hex = hex::encode(verifying_key.as_bytes());

    let now = chrono::Utc::now();
    let created_at = now.to_rfc3339();
    let expires_at = (now + chrono::Duration::seconds(ttl_secs as i64)).to_rfc3339();

    // SECURITY (FIND-R146-MA-004): Generate attestation_id before signing so it
    // is included in the canonical content. This prevents signature reuse across
    // attestations with different IDs.
    let attestation_id = Uuid::new_v4().to_string();

    // SECURITY (FIND-R146-MA-001/002/003/004): Build length-prefixed canonical
    // content including ALL semantically significant fields.
    let canonical = build_canonical_content(
        &attestation_id,
        agent_id,
        did,
        statement,
        policy_hash,
        &created_at,
        &expires_at,
    );

    // Ed25519 sign the domain-separated digest of the canonical content
    let content_hash = content_digest(&canonical, true);
    let signature = signing_key.sign(&content_hash);
    let signature_hex = hex::encode(signature.to_bytes());

    Ok(AccountabilityAttestation {
        attestation_id,
        agent_id: agent_id.to_string(),
        did: did.map(|s| s.to_string()),
        statement: statement.to_string(),
        policy_hash: policy_hash.to_string(),
        signature: signature_hex,
        algorithm: "Ed25519".to_string(),
        public_key: public_key_hex,
        created_at,
        expires_at,
        verified: false,
    })
}

/// Verify an accountability attestation.
///
/// Checks:
/// 1. Ed25519 signature over length-prefixed canonical content
/// 2. Expiration (using `now` parameter)
/// 3. Public key matches expected key (if provided)
pub fn verify_attestation(
    attestation: &AccountabilityAttestation,
    expected_public_key_hex: Option<&str>,
    now: &chrono::DateTime<chrono::Utc>,
) -> Result<AttestationVerificationResult, AttestationError> {
    // Parse public key from attestation
    let pub_key_bytes = hex::decode(&attestation.public_key)
        .map_err(|e| AttestationError::InvalidKey(format!("public key hex decode failed: {e}")))?;
    let verifying_key =
        VerifyingKey::from_bytes(pub_key_bytes.as_slice().try_into().map_err(|_| {
            AttestationError::InvalidKey(format!(
                "public key must be 32 bytes, got {}",
                pub_key_bytes.len()
            ))
        })?)
        .map_err(|e| AttestationError::VerificationFailed(format!("invalid public key: {e}")))?;

    // Parse signature
    let sig_bytes = hex::decode(&attestation.signature).map_err(|e| {
        AttestationError::VerificationFailed(format!("signature hex decode failed: {e}"))
    })?;
    let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().map_err(|_| {
        AttestationError::VerificationFailed(format!(
            "signature must be 64 bytes, got {}",
            sig_bytes.len()
        ))
    })?);

    // SECURITY (FIND-R146-MA-001/002/003/004): Rebuild canonical content including
    // ALL signed fields (attestation_id, did, expires_at, created_at with length prefix).
    let canonical = build_canonical_content(
        &attestation.attestation_id,
        &attestation.agent_id,
        attestation.did.as_deref(),
        &attestation.statement,
        &attestation.policy_hash,
        &attestation.created_at,
        &attestation.expires_at,
    );
    // SECURITY (DOC-CRED-2): Domain-separated digest first, then the
    // pre-domain-separation form so attestations issued before the change keep
    // verifying until they expire.
    let signature_valid = verifying_key
        .verify(&content_digest(&canonical, true), &signature)
        .is_ok()
        || verifying_key
            .verify(&content_digest(&canonical, false), &signature)
            .is_ok();

    // Check expiry
    let mut expired = chrono::DateTime::parse_from_rfc3339(&attestation.expires_at)
        .map(|expires| now >= &expires.with_timezone(&chrono::Utc))
        .unwrap_or(true); // Fail-closed: unparseable expiry = expired

    // SECURITY (FIND-R186-002): Reject attestations with created_at unreasonably far
    // in the future. Parity with verify_capability_token MAX_ISSUED_AT_SKEW_SECS check.
    // Prevents pre-minting attack: compromised key stockpiles future-dated attestations.
    // Treated as temporal invalidity (expired=true) so is_valid() correctly rejects.
    let created_at_future_skew = chrono::DateTime::parse_from_rfc3339(&attestation.created_at)
        .map(|created| {
            let skew = created
                .with_timezone(&chrono::Utc)
                .signed_duration_since(*now)
                .num_seconds();
            if skew > MAX_CREATED_AT_SKEW_SECS {
                Some(skew)
            } else {
                None
            }
        })
        .ok(); // None = unparseable created_at

    // Determine if created_at is invalid: either unparseable or too far in the future.
    let created_at_invalid = match created_at_future_skew {
        Some(Some(skew)) => Some(skew), // Parsed and too far in the future
        Some(None) => None,             // Parsed and within skew tolerance
        None => Some(-1),               // Unparseable — use sentinel for fail-closed
    };

    if created_at_invalid.is_some() {
        expired = true; // Temporally invalid
    }

    // Check key match (constant-time to prevent timing side-channel)
    let key_matches_agent = match expected_public_key_hex {
        Some(expected) => {
            let a = attestation.public_key.to_ascii_lowercase();
            let b = expected.to_ascii_lowercase();
            a.len() == b.len() && a.as_bytes().ct_eq(b.as_bytes()).into()
        }
        None => true, // No expected key to compare against
    };

    let message = if !signature_valid {
        "Invalid signature".to_string()
    } else if let Some(skew) = created_at_invalid {
        if skew < 0 {
            // IMP-R186-001: Distinct message for unparseable created_at
            "created_at is malformed (unparseable RFC 3339 timestamp)".to_string()
        } else {
            format!(
                "created_at is {skew} seconds in the future (max allowed skew: {MAX_CREATED_AT_SKEW_SECS} seconds)"
            )
        }
    } else if expired {
        "Attestation has expired".to_string()
    } else if !key_matches_agent {
        "Public key does not match agent's registered key".to_string()
    } else {
        "Attestation is valid".to_string()
    };

    Ok(AttestationVerificationResult {
        signature_valid,
        expired,
        key_matches_agent,
        message,
    })
}

/// Build length-prefixed canonical content for signing/verification.
///
/// Format:
/// ```text
/// <attestation_id_len>:<attestation_id>
/// <agent_id_len>:<agent_id>
/// <did_len>:<did>
/// <statement_len>:<statement>
/// <policy_hash_len>:<policy_hash>
/// <created_at_len>:<created_at>
/// <expires_at_len>:<expires_at>
/// ```
///
/// SECURITY (FIND-R146-MA-001/002/003/004): All fields that affect attestation
/// semantics are included in the signed canonical content with length prefixes.
/// Missing fields would allow attackers to modify `expires_at` (extend lifetime),
/// `did` (rebind identity), or `attestation_id` (replay with different ID)
/// without invalidating the Ed25519 signature.
///
/// Length prefixing prevents boundary collision: without it, `agent_id="ab" + statement="cd"`
/// would hash identically to `agent_id="abc" + statement="d"`.
fn build_canonical_content(
    attestation_id: &str,
    agent_id: &str,
    did: Option<&str>,
    statement: &str,
    policy_hash: &str,
    created_at: &str,
    expires_at: &str,
) -> String {
    let did_value = did.unwrap_or("");
    format!(
        "{}:{}{}:{}{}:{}{}:{}{}:{}{}:{}{}:{}",
        attestation_id.len(),
        attestation_id,
        agent_id.len(),
        agent_id,
        did_value.len(),
        did_value,
        statement.len(),
        statement,
        policy_hash.len(),
        policy_hash,
        created_at.len(),
        created_at,
        expires_at.len(),
        expires_at,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn generate_test_keypair() -> (String, String) {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        (
            hex::encode(signing_key.to_bytes()),
            hex::encode(verifying_key.as_bytes()),
        )
    }

    #[test]
    fn test_sign_and_verify_attestation() {
        let (signing_key_hex, public_key_hex) = generate_test_keypair();

        let attestation = sign_attestation(
            "agent-1",
            Some("did:plc:ewvi7nxsareczkwkx5pz6q6e"),
            "I accept the data handling policy",
            "sha256:abcdef1234567890",
            &signing_key_hex,
            86400,
        )
        .expect("sign");

        assert_eq!(attestation.agent_id, "agent-1");
        assert_eq!(attestation.algorithm, "Ed25519");
        assert!(!attestation.verified);

        let now = chrono::Utc::now();
        let result = verify_attestation(&attestation, Some(&public_key_hex), &now).expect("verify");
        assert!(result.is_valid());
        assert!(result.signature_valid);
        assert!(!result.expired);
        assert!(result.key_matches_agent);
    }

    #[test]
    fn test_verify_detects_tampered_statement() {
        let (signing_key_hex, public_key_hex) = generate_test_keypair();

        let mut attestation = sign_attestation(
            "agent-1",
            None,
            "Original statement",
            "hash123",
            &signing_key_hex,
            86400,
        )
        .expect("sign");

        // Tamper with statement
        attestation.statement = "Tampered statement".to_string();

        let now = chrono::Utc::now();
        let result = verify_attestation(&attestation, Some(&public_key_hex), &now).expect("verify");
        assert!(!result.signature_valid);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_verify_detects_tampered_agent_id() {
        let (signing_key_hex, public_key_hex) = generate_test_keypair();

        let mut attestation = sign_attestation(
            "agent-1",
            None,
            "Policy statement",
            "hash123",
            &signing_key_hex,
            86400,
        )
        .expect("sign");

        attestation.agent_id = "agent-evil".to_string();

        let now = chrono::Utc::now();
        let result = verify_attestation(&attestation, Some(&public_key_hex), &now).expect("verify");
        assert!(!result.signature_valid);
    }

    #[test]
    fn test_verify_detects_expired() {
        let (signing_key_hex, public_key_hex) = generate_test_keypair();

        let attestation = sign_attestation(
            "agent-1",
            None,
            "Statement",
            "hash",
            &signing_key_hex,
            1, // 1 second TTL
        )
        .expect("sign");

        // Check with a time far in the future
        let future = chrono::Utc::now() + chrono::Duration::hours(1);
        let result =
            verify_attestation(&attestation, Some(&public_key_hex), &future).expect("verify");
        assert!(result.expired);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_verify_detects_wrong_key() {
        let (signing_key_hex, _) = generate_test_keypair();
        let wrong_key = hex::encode([99u8; 32]); // Wrong key

        let attestation = sign_attestation(
            "agent-1",
            None,
            "Statement",
            "hash",
            &signing_key_hex,
            86400,
        )
        .expect("sign");

        let now = chrono::Utc::now();
        let result = verify_attestation(&attestation, Some(&wrong_key), &now).expect("verify");
        assert!(!result.key_matches_agent);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_sign_invalid_key_hex() {
        let result = sign_attestation("agent", None, "stmt", "hash", "not-hex!", 86400);
        assert!(matches!(result, Err(AttestationError::InvalidKey(_))));
    }

    #[test]
    fn test_sign_invalid_key_length() {
        let result = sign_attestation("agent", None, "stmt", "hash", "abcd", 86400);
        assert!(matches!(result, Err(AttestationError::InvalidKey(_))));
    }

    // ════════════════════════════════════════════════════════
    // FIND-068: Empty field validation
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_sign_rejects_empty_agent_id() {
        let (signing_key_hex, _) = generate_test_keypair();
        let result = sign_attestation("", None, "stmt", "hash", &signing_key_hex, 86400);
        assert!(matches!(result, Err(AttestationError::SigningFailed(_))));
    }

    #[test]
    fn test_sign_rejects_empty_statement() {
        let (signing_key_hex, _) = generate_test_keypair();
        let result = sign_attestation("agent", None, "", "hash", &signing_key_hex, 86400);
        assert!(matches!(result, Err(AttestationError::SigningFailed(_))));
    }

    #[test]
    fn test_sign_rejects_empty_policy_hash() {
        let (signing_key_hex, _) = generate_test_keypair();
        let result = sign_attestation("agent", None, "stmt", "", &signing_key_hex, 86400);
        assert!(matches!(result, Err(AttestationError::SigningFailed(_))));
    }

    #[test]
    fn test_boundary_collision_prevention() {
        let (signing_key_hex, _) = generate_test_keypair();

        // These two should produce different attestations due to length prefixing
        let att1 =
            sign_attestation("ab", None, "cd", "hash", &signing_key_hex, 86400).expect("sign 1");
        let att2 =
            sign_attestation("abc", None, "d", "hash", &signing_key_hex, 86400).expect("sign 2");

        assert_ne!(att1.signature, att2.signature);
    }

    #[test]
    fn test_verify_no_expected_key() {
        let (signing_key_hex, _) = generate_test_keypair();

        let attestation = sign_attestation(
            "agent-1",
            None,
            "Statement",
            "hash",
            &signing_key_hex,
            86400,
        )
        .expect("sign");

        let now = chrono::Utc::now();
        // No expected key -> key_matches_agent is true
        let result = verify_attestation(&attestation, None, &now).expect("verify");
        assert!(result.key_matches_agent);
        assert!(result.is_valid());
    }

    #[test]
    fn test_attestation_unique_ids() {
        let (signing_key_hex, _) = generate_test_keypair();

        let att1 =
            sign_attestation("agent", None, "stmt", "hash", &signing_key_hex, 86400).expect("1");
        let att2 =
            sign_attestation("agent", None, "stmt", "hash", &signing_key_hex, 86400).expect("2");

        assert_ne!(att1.attestation_id, att2.attestation_id);
    }

    // ════════════════════════════════════════════════════════
    // IMP-R118-004: Control character validation
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_sign_rejects_agent_id_control_chars() {
        let (signing_key_hex, _) = generate_test_keypair();
        let result = sign_attestation(
            "agent\x00evil",
            None,
            "stmt",
            "hash",
            &signing_key_hex,
            86400,
        );
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("control"), "error: {msg}");
    }

    #[test]
    fn test_sign_rejects_agent_id_bidi_override() {
        let (signing_key_hex, _) = generate_test_keypair();
        let result = sign_attestation(
            "agent\u{202E}live",
            None,
            "stmt",
            "hash",
            &signing_key_hex,
            86400,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_rejects_statement_zero_width() {
        let (signing_key_hex, _) = generate_test_keypair();
        let result = sign_attestation(
            "agent",
            None,
            "stmt\u{200B}ment",
            "hash",
            &signing_key_hex,
            86400,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_rejects_policy_hash_control_chars() {
        let (signing_key_hex, _) = generate_test_keypair();
        let result = sign_attestation(
            "agent",
            None,
            "stmt",
            "hash\x1B[0m",
            &signing_key_hex,
            86400,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_rejects_did_control_chars() {
        let (signing_key_hex, _) = generate_test_keypair();
        let result = sign_attestation(
            "agent",
            Some("did:plc:\x00evil"),
            "stmt",
            "hash",
            &signing_key_hex,
            86400,
        );
        assert!(result.is_err());
    }

    // ════════════════════════════════════════════════════════
    // IMP-R118-013: Max length validation
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_sign_rejects_agent_id_too_long() {
        let (signing_key_hex, _) = generate_test_keypair();
        let long_id = "a".repeat(MAX_AGENT_ID_LEN + 1);
        let result = sign_attestation(&long_id, None, "stmt", "hash", &signing_key_hex, 86400);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("length"));
    }

    #[test]
    fn test_sign_rejects_statement_too_long() {
        let (signing_key_hex, _) = generate_test_keypair();
        let long_stmt = "s".repeat(MAX_STATEMENT_LEN + 1);
        let result = sign_attestation("agent", None, &long_stmt, "hash", &signing_key_hex, 86400);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("length"));
    }

    #[test]
    fn test_sign_rejects_policy_hash_too_long() {
        let (signing_key_hex, _) = generate_test_keypair();
        let long_hash = "h".repeat(MAX_POLICY_HASH_LEN + 1);
        let result = sign_attestation("agent", None, "stmt", &long_hash, &signing_key_hex, 86400);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("length"));
    }

    #[test]
    fn test_sign_accepts_max_length_agent_id() {
        let (signing_key_hex, _) = generate_test_keypair();
        let max_id = "a".repeat(MAX_AGENT_ID_LEN);
        let result = sign_attestation(&max_id, None, "stmt", "hash", &signing_key_hex, 86400);
        assert!(result.is_ok());
    }

    // ════════════════════════════════════════════════════════
    // IMP-R120-002: Malformed expires_at fail-closed
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_verify_malformed_expires_at_treated_as_expired() {
        let (signing_key_hex, public_key_hex) = generate_test_keypair();

        let mut attestation = sign_attestation(
            "agent-1",
            None,
            "Statement",
            "hash",
            &signing_key_hex,
            86400,
        )
        .expect("sign");

        // Corrupt the expires_at field — unparseable date
        attestation.expires_at = "not-a-valid-date".to_string();

        let now = chrono::Utc::now();
        let result = verify_attestation(&attestation, Some(&public_key_hex), &now).expect("verify");
        // Fail-closed: unparseable expiry should be treated as expired
        assert!(
            result.expired,
            "malformed expires_at must be treated as expired"
        );
        // SECURITY (FIND-R146-MA-001): expires_at is now in signed canonical content,
        // so tampering also invalidates the signature (double fail-closed).
        assert!(
            !result.signature_valid,
            "tampered expires_at must invalidate signature"
        );
        assert!(!result.is_valid());
    }

    // ════════════════════════════════════════════════════════
    // IMP-R120-003: MAX_ATTESTATION_TTL_SECS rejection
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_sign_rejects_ttl_exceeding_max() {
        let (signing_key_hex, _) = generate_test_keypair();
        let result = sign_attestation(
            "agent",
            None,
            "stmt",
            "hash",
            &signing_key_hex,
            MAX_ATTESTATION_TTL_SECS + 1,
        );
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("exceeds maximum"), "error: {msg}");
    }

    #[test]
    fn test_sign_accepts_max_ttl() {
        let (signing_key_hex, _) = generate_test_keypair();
        let result = sign_attestation(
            "agent",
            None,
            "stmt",
            "hash",
            &signing_key_hex,
            MAX_ATTESTATION_TTL_SECS,
        );
        assert!(result.is_ok());
    }

    // ════════════════════════════════════════════════════════
    // FIND-R146-MA-001: expires_at in signed canonical content
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_verify_detects_tampered_expires_at() {
        let (signing_key_hex, public_key_hex) = generate_test_keypair();

        let mut attestation = sign_attestation(
            "agent-1",
            None,
            "Statement",
            "hash",
            &signing_key_hex,
            86400,
        )
        .expect("sign");

        // Tamper with expires_at to extend lifetime — must invalidate signature
        let far_future = (chrono::Utc::now() + chrono::Duration::days(365)).to_rfc3339();
        attestation.expires_at = far_future;

        let now = chrono::Utc::now();
        let result = verify_attestation(&attestation, Some(&public_key_hex), &now).expect("verify");
        assert!(
            !result.signature_valid,
            "tampered expires_at must invalidate signature"
        );
        assert!(!result.is_valid());
    }

    // ════════════════════════════════════════════════════════
    // FIND-R146-MA-002: did field in signed canonical content
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_verify_detects_tampered_did() {
        let (signing_key_hex, public_key_hex) = generate_test_keypair();

        let mut attestation = sign_attestation(
            "agent-1",
            Some("did:plc:original"),
            "Statement",
            "hash",
            &signing_key_hex,
            86400,
        )
        .expect("sign");

        // Tamper with DID to rebind to different identity — must invalidate signature
        attestation.did = Some("did:plc:attacker".to_string());

        let now = chrono::Utc::now();
        let result = verify_attestation(&attestation, Some(&public_key_hex), &now).expect("verify");
        assert!(
            !result.signature_valid,
            "tampered did must invalidate signature"
        );
        assert!(!result.is_valid());
    }

    #[test]
    fn test_verify_detects_did_added_after_signing_without_did() {
        let (signing_key_hex, public_key_hex) = generate_test_keypair();

        // Sign without DID
        let mut attestation = sign_attestation(
            "agent-1",
            None,
            "Statement",
            "hash",
            &signing_key_hex,
            86400,
        )
        .expect("sign");

        // Tamper: add a DID that was not present at signing time
        attestation.did = Some("did:plc:injected".to_string());

        let now = chrono::Utc::now();
        let result = verify_attestation(&attestation, Some(&public_key_hex), &now).expect("verify");
        assert!(
            !result.signature_valid,
            "injected did must invalidate signature"
        );
        assert!(!result.is_valid());
    }

    #[test]
    fn test_verify_detects_did_removed_after_signing_with_did() {
        let (signing_key_hex, public_key_hex) = generate_test_keypair();

        // Sign with DID
        let mut attestation = sign_attestation(
            "agent-1",
            Some("did:plc:original"),
            "Statement",
            "hash",
            &signing_key_hex,
            86400,
        )
        .expect("sign");

        // Tamper: remove the DID that was present at signing time
        attestation.did = None;

        let now = chrono::Utc::now();
        let result = verify_attestation(&attestation, Some(&public_key_hex), &now).expect("verify");
        assert!(
            !result.signature_valid,
            "removed did must invalidate signature"
        );
        assert!(!result.is_valid());
    }

    // ════════════════════════════════════════════════════════
    // FIND-R146-MA-003: created_at length prefix
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_canonical_content_all_fields_length_prefixed() {
        // Verify that changing any field's value produces different canonical content,
        // even when concatenated strings would otherwise collide.
        let c1 = build_canonical_content(
            "id1",
            "agent",
            None,
            "stmt",
            "hash",
            "2026-01-01T00:00:00Z",
            "2026-01-02T00:00:00Z",
        );
        let c2 = build_canonical_content(
            "id1",
            "agent",
            None,
            "stmt",
            "hash",
            "2026-01-01T00:00:00",
            "Z2026-01-02T00:00:00Z",
        );
        // With length prefixes, these must differ even though concatenation is similar
        assert_ne!(
            c1, c2,
            "length prefixes must prevent created_at/expires_at boundary collision"
        );
    }

    // ════════════════════════════════════════════════════════
    // FIND-R146-MA-004: attestation_id in signed canonical content
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_verify_detects_tampered_attestation_id() {
        let (signing_key_hex, public_key_hex) = generate_test_keypair();

        let mut attestation = sign_attestation(
            "agent-1",
            None,
            "Statement",
            "hash",
            &signing_key_hex,
            86400,
        )
        .expect("sign");

        // Tamper with attestation_id — must invalidate signature
        attestation.attestation_id = Uuid::new_v4().to_string();

        let now = chrono::Utc::now();
        let result = verify_attestation(&attestation, Some(&public_key_hex), &now).expect("verify");
        assert!(
            !result.signature_valid,
            "tampered attestation_id must invalidate signature"
        );
        assert!(!result.is_valid());
    }

    #[test]
    fn test_two_attestations_same_content_different_signatures() {
        let (signing_key_hex, _) = generate_test_keypair();

        // Two attestations with identical content must have different signatures
        // because attestation_id (UUID) is included in canonical content.
        let att1 =
            sign_attestation("agent", None, "stmt", "hash", &signing_key_hex, 86400).expect("1");
        let att2 =
            sign_attestation("agent", None, "stmt", "hash", &signing_key_hex, 86400).expect("2");

        assert_ne!(att1.attestation_id, att2.attestation_id);
        // Signatures must differ because attestation_id and timestamps differ
        assert_ne!(att1.signature, att2.signature);
    }

    // ── FIND-R186-002: Future created_at validation ──────────────────────

    #[test]
    fn test_verify_rejects_future_created_at() {
        let (signing_key_hex, public_key_hex) = generate_test_keypair();
        let mut attestation = sign_attestation(
            "agent-1",
            None,
            "statement",
            "hash",
            &signing_key_hex,
            86400,
        )
        .expect("sign");

        // Set created_at 120 seconds in the future (beyond 60s skew tolerance)
        let future = chrono::Utc::now() + chrono::Duration::seconds(120);
        attestation.created_at = future.to_rfc3339();

        // Re-sign with the new created_at (so signature is still valid)
        let canonical = build_canonical_content(
            &attestation.attestation_id,
            &attestation.agent_id,
            attestation.did.as_deref(),
            &attestation.statement,
            &attestation.policy_hash,
            &attestation.created_at,
            &attestation.expires_at,
        );
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        let content_hash = hasher.finalize();
        let sk_bytes = hex::decode(&signing_key_hex).unwrap();
        let signing_key = SigningKey::from_bytes(sk_bytes.as_slice().try_into().unwrap());
        let sig = signing_key.sign(&content_hash);
        attestation.signature = hex::encode(sig.to_bytes());

        let now = chrono::Utc::now();
        let result = verify_attestation(&attestation, Some(&public_key_hex), &now).expect("verify");
        assert!(result.signature_valid, "signature should be valid");
        assert!(
            result.expired,
            "future-dated attestation should be treated as expired"
        );
        assert!(
            !result.is_valid(),
            "future-dated attestation must not pass is_valid()"
        );
        assert!(
            result.message.contains("in the future"),
            "message should mention future: {}",
            result.message
        );
    }

    #[test]
    fn test_verify_accepts_created_at_within_skew() {
        let (signing_key_hex, public_key_hex) = generate_test_keypair();
        let attestation = sign_attestation(
            "agent-1",
            None,
            "statement",
            "hash",
            &signing_key_hex,
            86400,
        )
        .expect("sign");

        // Verify with "now" 30 seconds in the past (simulates clock skew < 60s)
        let past_now = chrono::Utc::now() - chrono::Duration::seconds(30);
        let result =
            verify_attestation(&attestation, Some(&public_key_hex), &past_now).expect("verify");
        assert!(
            result.is_valid(),
            "attestation within 60s skew should be valid: {}",
            result.message
        );
    }

    #[test]
    fn test_verify_malformed_created_at_treated_as_expired() {
        let (signing_key_hex, public_key_hex) = generate_test_keypair();
        let mut attestation = sign_attestation(
            "agent-1",
            None,
            "statement",
            "hash",
            &signing_key_hex,
            86400,
        )
        .expect("sign");

        // Set created_at to unparseable value and re-sign so signature is still valid
        attestation.created_at = "not-a-valid-date".to_string();
        let canonical = build_canonical_content(
            &attestation.attestation_id,
            &attestation.agent_id,
            attestation.did.as_deref(),
            &attestation.statement,
            &attestation.policy_hash,
            &attestation.created_at,
            &attestation.expires_at,
        );
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        let content_hash = hasher.finalize();
        let sk_bytes = hex::decode(&signing_key_hex).unwrap();
        let signing_key = SigningKey::from_bytes(sk_bytes.as_slice().try_into().unwrap());
        let sig = signing_key.sign(&content_hash);
        attestation.signature = hex::encode(sig.to_bytes());

        let now = chrono::Utc::now();
        let result = verify_attestation(&attestation, Some(&public_key_hex), &now).expect("verify");
        assert!(
            result.signature_valid,
            "re-signed attestation should have valid signature"
        );
        assert!(
            result.expired,
            "malformed created_at should be treated as expired"
        );
        assert!(
            !result.is_valid(),
            "malformed created_at must not pass is_valid()"
        );
        assert!(
            result.message.contains("malformed"),
            "message should mention malformed: {}",
            result.message
        );
    }
}
