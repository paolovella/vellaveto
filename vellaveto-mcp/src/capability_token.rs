// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Capability token issuance, attenuation, and verification.
//!
//! Provides Ed25519-based signing and verification of capability delegation
//! tokens. Tokens can be attenuated (narrowed) and delegated with monotonically
//! decreasing privileges.
//!
//! # Security Properties
//!
//! - Length-prefixed canonical content prevents boundary collision attacks
//! - Ed25519 signatures prevent token forgery
//! - Monotonic attenuation: delegated tokens can only narrow permissions
//! - Bounded delegation depth prevents infinite chains
//! - Constant-time key comparison via `subtle::ConstantTimeEq`

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use vellaveto_types::{
    Action, CapabilityError, CapabilityGrant, CapabilityToken, CapabilityVerification,
    MAX_DELEGATION_DEPTH, MAX_GRANTS,
};

use crate::verified_capability_attenuation;
use crate::verified_capability_coverage;
use crate::verified_capability_domain;
use crate::verified_capability_glob;
use crate::verified_capability_glob_subset;
use crate::verified_capability_grant;
use crate::verified_capability_identity;
use crate::verified_capability_literal;
use crate::verified_capability_path;
use crate::verified_capability_pattern;
use crate::verified_capability_selection;
use crate::verified_capability_verification;

/// SECURITY (FIND-R74-002): Maximum TTL for capability tokens (1 year).
/// Prevents `ttl_secs as i64` overflow on u64 values > i64::MAX.
const MAX_CAPABILITY_TTL_SECS: u64 = 365 * 24 * 3600;

/// SECURITY (IMP-R118-004): Maximum length for issuer/holder identity strings.
const MAX_IDENTITY_LEN: usize = 256;

/// SECURITY (IMP-R118-004): Validate string has no control or Unicode format characters.
/// SECURITY (IMP-R120-008): Delegates to shared `has_dangerous_chars()` predicate.
fn validate_no_dangerous_chars(value: &str, field_name: &str) -> Result<(), CapabilityError> {
    if value.len() > MAX_IDENTITY_LEN {
        return Err(CapabilityError::SigningFailed(format!(
            "{} length {} exceeds maximum {}",
            field_name,
            value.len(),
            MAX_IDENTITY_LEN
        )));
    }
    if vellaveto_types::has_dangerous_chars(value) {
        return Err(CapabilityError::SigningFailed(format!(
            "{field_name} contains control or Unicode format characters"
        )));
    }
    Ok(())
}

/// Issue a new root capability token.
///
/// Creates a fresh token with the specified grants, signed by the issuer's
/// Ed25519 key. The token is valid for `ttl_secs` from now.
pub fn issue_capability_token(
    issuer: &str,
    holder: &str,
    grants: Vec<CapabilityGrant>,
    remaining_depth: u8,
    signing_key_hex: &str,
    ttl_secs: u64,
) -> Result<CapabilityToken, CapabilityError> {
    // Validate inputs
    if issuer.is_empty() {
        return Err(CapabilityError::SigningFailed(
            "issuer must not be empty".to_string(),
        ));
    }
    if holder.is_empty() {
        return Err(CapabilityError::SigningFailed(
            "holder must not be empty".to_string(),
        ));
    }
    // SECURITY (IMP-R118-004): Validate no control or Unicode format characters.
    validate_no_dangerous_chars(issuer, "issuer")?;
    validate_no_dangerous_chars(holder, "holder")?;
    if grants.is_empty() {
        return Err(CapabilityError::SigningFailed(
            "grants must not be empty".to_string(),
        ));
    }
    // SECURITY (FIND-R74-002): Cap TTL to prevent `as i64` overflow.
    if ttl_secs > MAX_CAPABILITY_TTL_SECS {
        return Err(CapabilityError::SigningFailed(format!(
            "ttl_secs {ttl_secs} exceeds maximum {MAX_CAPABILITY_TTL_SECS} (1 year)"
        )));
    }
    if grants.len() > MAX_GRANTS {
        return Err(CapabilityError::SigningFailed(format!(
            "too many grants: {} (max {})",
            grants.len(),
            MAX_GRANTS
        )));
    }
    if remaining_depth > MAX_DELEGATION_DEPTH {
        return Err(CapabilityError::SigningFailed(format!(
            "remaining_depth {remaining_depth} exceeds max {MAX_DELEGATION_DEPTH}"
        )));
    }

    // Parse signing key
    let signing_key = parse_signing_key(signing_key_hex)?;
    let verifying_key = signing_key.verifying_key();
    let public_key_hex = hex::encode(verifying_key.as_bytes());

    let now = chrono::Utc::now();
    let issued_at = now.to_rfc3339();
    let expires_at = (now + chrono::Duration::seconds(ttl_secs as i64)).to_rfc3339();

    let token_id = Uuid::new_v4().to_string();

    // Build canonical content and sign
    let canonical = build_canonical_content(
        &token_id,
        None,
        issuer,
        holder,
        &grants,
        remaining_depth,
        &issued_at,
        &expires_at,
    )?;
    let signature_hex = sign_content(&signing_key, &canonical)?;

    let token = CapabilityToken {
        token_id,
        parent_token_id: None,
        issuer: issuer.to_string(),
        holder: holder.to_string(),
        grants,
        remaining_depth,
        issued_at,
        expires_at,
        signature: signature_hex,
        issuer_public_key: public_key_hex,
    };

    token
        .validate_structure()
        .map_err(|e| CapabilityError::SigningFailed(format!("token validation failed: {e}")))?;

    Ok(token)
}

// VERIFIED [S11]: Monotonic attenuation — delegated tokens can only reduce, never expand, capabilities (CapabilityDelegation.als S11)
// VERIFIED [S12]: Transitive attenuation — delegated tokens maintain monotonic privilege reduction across the full chain (CapabilityDelegation.als S12)
/// Attenuate (narrow) a parent capability token for delegation.
///
/// The new token must have:
/// - `remaining_depth` strictly less than the parent's (decremented)
/// - `grants` that are a subset of the parent's
/// - `expires_at` no later than the parent's
///
/// # Security: Monotonic Attenuation
///
/// This enforces that delegated tokens can only become more restrictive,
/// never more permissive. This prevents privilege escalation via delegation.
pub fn attenuate_capability_token(
    parent: &CapabilityToken,
    new_holder: &str,
    new_grants: Vec<CapabilityGrant>,
    signing_key_hex: &str,
    ttl_secs: u64,
) -> Result<CapabilityToken, CapabilityError> {
    let new_depth =
        verified_capability_attenuation::attenuated_remaining_depth(parent.remaining_depth)
            .ok_or_else(|| {
                CapabilityError::AttenuationViolation(
                    "parent token has remaining_depth 0 — cannot delegate further".to_string(),
                )
            })?;

    if new_holder.is_empty() {
        return Err(CapabilityError::SigningFailed(
            "new_holder must not be empty".to_string(),
        ));
    }
    // SECURITY (IMP-R118-004): Validate no control or Unicode format characters.
    validate_no_dangerous_chars(new_holder, "new_holder")?;

    // SECURITY (IMP-R118-010, FIND-R116-MCP-005): Reject self-delegation — an agent
    // cannot delegate a token to itself, which would create a fresh token with a new
    // issued_at effectively bypassing temporal constraints.
    // SECURITY (FIND-R116-MCP-005): Normalize Unicode confusables (homoglyphs) before
    // comparing to prevent bypass via Cyrillic/Greek/fullwidth lookalikes.
    let normalized_new = vellaveto_types::unicode::normalize_homoglyphs(new_holder);
    let normalized_parent = vellaveto_types::unicode::normalize_homoglyphs(&parent.holder);
    let normalized_new_equals_parent_holder_ignore_ascii_case =
        normalized_new.eq_ignore_ascii_case(&normalized_parent);
    if !verified_capability_identity::delegation_holder_distinct(
        normalized_new_equals_parent_holder_ignore_ascii_case,
    ) {
        return Err(CapabilityError::AttenuationViolation(
            "self-delegation is not permitted".to_string(),
        ));
    }

    if new_grants.is_empty() {
        return Err(CapabilityError::SigningFailed(
            "new_grants must not be empty".to_string(),
        ));
    }
    // SECURITY (FIND-R74-002): Cap TTL to prevent `as i64` overflow.
    if ttl_secs > MAX_CAPABILITY_TTL_SECS {
        return Err(CapabilityError::SigningFailed(format!(
            "ttl_secs {ttl_secs} exceeds maximum {MAX_CAPABILITY_TTL_SECS} (1 year)"
        )));
    }

    // SECURITY (FIND-R143-002): Verify parent token has not expired before
    // issuing a child token. Without this check, an expired parent can produce
    // a child that, due to clock skew tolerance in verify_capability_token,
    // could appear valid within the MAX_ISSUED_AT_SKEW_SECS window.
    let now = chrono::Utc::now();
    let parent_expires = chrono::DateTime::parse_from_rfc3339(&parent.expires_at)
        .map_err(|e| CapabilityError::SigningFailed(format!("invalid parent expires_at: {e}")))?;
    let parent_expires_utc = parent_expires.with_timezone(&chrono::Utc);
    if now >= parent_expires_utc {
        return Err(CapabilityError::AttenuationViolation(
            "parent token has expired".to_string(),
        ));
    }

    // Verify grants are a subset of parent's grants
    for new_grant in &new_grants {
        let covered = parent
            .grants
            .iter()
            .any(|parent_grant| grant_is_subset(new_grant, parent_grant));
        if !covered {
            return Err(CapabilityError::AttenuationViolation(format!(
                "grant for tool '{}' function '{}' is not covered by parent token",
                new_grant.tool_pattern, new_grant.function_pattern
            )));
        }
    }

    let signing_key = parse_signing_key(signing_key_hex)?;
    let verifying_key = signing_key.verifying_key();
    let public_key_hex = hex::encode(verifying_key.as_bytes());

    let issued_at = now.to_rfc3339();
    let now_epoch = u64::try_from(now.timestamp())
        .map_err(|_| CapabilityError::SigningFailed("system time before Unix epoch".to_string()))?;
    let parent_expires_epoch = u64::try_from(parent_expires_utc.timestamp()).map_err(|_| {
        CapabilityError::SigningFailed("parent expires_at before Unix epoch".to_string())
    })?;
    let clamped_expires_epoch = verified_capability_attenuation::attenuated_expiry_epoch(
        parent_expires_epoch,
        now_epoch,
        ttl_secs,
        MAX_CAPABILITY_TTL_SECS,
    )
    .ok_or_else(|| {
        CapabilityError::SigningFailed("attenuation expiry computation failed".to_string())
    })?;
    let clamped_expires =
        chrono::DateTime::<chrono::Utc>::from_timestamp(clamped_expires_epoch as i64, 0)
            .ok_or_else(|| {
                CapabilityError::SigningFailed("attenuation expiry out of range".to_string())
            })?;
    let expires_at = clamped_expires.to_rfc3339();

    let token_id = Uuid::new_v4().to_string();

    let canonical = build_canonical_content(
        &token_id,
        Some(&parent.token_id),
        &parent.holder, // Issuer of child = holder of parent
        new_holder,
        &new_grants,
        new_depth,
        &issued_at,
        &expires_at,
    )?;
    let signature_hex = sign_content(&signing_key, &canonical)?;

    let token = CapabilityToken {
        token_id,
        parent_token_id: Some(parent.token_id.clone()),
        issuer: parent.holder.clone(),
        holder: new_holder.to_string(),
        grants: new_grants,
        remaining_depth: new_depth,
        issued_at,
        expires_at,
        signature: signature_hex,
        issuer_public_key: public_key_hex,
    };

    if !verified_capability_identity::delegated_child_issuer_valid(
        token.parent_token_id.is_some(),
        token.issuer == parent.holder,
    ) {
        return Err(CapabilityError::AttenuationViolation(
            "delegated child issuer must equal parent holder".to_string(),
        ));
    }

    token
        .validate_structure()
        .map_err(|e| CapabilityError::SigningFailed(format!("token validation failed: {e}")))?;

    Ok(token)
}

/// Verify a capability token's signature and validity.
///
/// Checks:
/// 1. Ed25519 signature over canonical content
/// 2. Expiration (using `now` parameter)
/// 3. Holder matches expected_holder
/// 4. Public key matches expected key (if provided)
pub fn verify_capability_token(
    token: &CapabilityToken,
    expected_holder: Option<&str>,
    expected_public_key_hex: Option<&str>,
    now: &chrono::DateTime<chrono::Utc>,
) -> Result<CapabilityVerification, CapabilityError> {
    // Structural validation
    if let Err(e) = token.validate_structure() {
        return Ok(CapabilityVerification {
            valid: false,
            failure_reason: Some(format!("structural validation failed: {e}")),
        });
    }

    // Check expiration
    let expires = chrono::DateTime::parse_from_rfc3339(&token.expires_at)
        .map_err(|e| CapabilityError::VerificationFailed(format!("invalid expires_at: {e}")))?;
    if !verified_capability_verification::capability_not_expired(*now < expires) {
        return Ok(CapabilityVerification {
            valid: false,
            failure_reason: Some("token has expired".to_string()),
        });
    }

    // SECURITY (FIND-R111-003): Validate issued_at is not in the future.
    //
    // A token with issued_at far in the future could be pre-minted and held
    // until the future time, bypassing intended access windows or audit trails.
    // Reject tokens whose issued_at exceeds `now` by more than the allowed clock
    // skew tolerance (60 seconds). This tolerates minor NTP drift while preventing
    // future-dated pre-minting attacks.
    const MAX_ISSUED_AT_SKEW_SECS: i64 = 60;
    let issued_at = chrono::DateTime::parse_from_rfc3339(&token.issued_at)
        .map_err(|e| CapabilityError::VerificationFailed(format!("invalid issued_at: {e}")))?;
    let skew = issued_at.signed_duration_since(*now).num_seconds();
    if !verified_capability_verification::capability_issued_at_within_skew(
        skew,
        MAX_ISSUED_AT_SKEW_SECS,
    ) {
        return Ok(CapabilityVerification {
            valid: false,
            failure_reason: Some(format!(
                "token issued_at is {skew} seconds in the future (max allowed skew: {MAX_ISSUED_AT_SKEW_SECS} seconds)"
            )),
        });
    }

    // Check holder match
    // SECURITY (FIND-R212-002): Use homoglyph normalization for holder comparison
    // instead of plain eq_ignore_ascii_case.  This prevents cross-identity token
    // theft where "alice" (different principal) claims a token issued to "Alice",
    // and also normalizes Cyrillic/Greek confusables that could bypass ASCII-only
    // case folding.  Both sides are normalized before comparison.
    if let Some(expected) = expected_holder {
        let norm_holder =
            vellaveto_types::unicode::normalize_homoglyphs(&token.holder.to_ascii_lowercase());
        let norm_expected =
            vellaveto_types::unicode::normalize_homoglyphs(&expected.to_ascii_lowercase());
        if !verified_capability_identity::holder_expectation_satisfied(norm_holder == norm_expected)
        {
            return Ok(CapabilityVerification {
                valid: false,
                failure_reason: Some(format!(
                    "holder mismatch: expected '{}', got '{}'",
                    expected, token.holder
                )),
            });
        }
    }

    // Check public key match (constant-time)
    if let Some(expected_key) = expected_public_key_hex {
        let expected_bytes = hex::decode(expected_key)
            .map_err(|e| CapabilityError::InvalidKey(format!("invalid expected key hex: {e}")))?;
        let actual_bytes = hex::decode(&token.issuer_public_key)
            .map_err(|e| CapabilityError::InvalidKey(format!("invalid token key hex: {e}")))?;
        if !verified_capability_verification::capability_expected_public_key_matches(
            expected_bytes.ct_eq(&actual_bytes).into(),
        ) {
            return Ok(CapabilityVerification {
                valid: false,
                failure_reason: Some("public key mismatch".to_string()),
            });
        }
    }

    // Verify Ed25519 signature
    let pub_key_bytes = hex::decode(&token.issuer_public_key)
        .map_err(|e| CapabilityError::InvalidKey(format!("public key hex decode: {e}")))?;
    if !verified_capability_verification::capability_public_key_length_valid(pub_key_bytes.len()) {
        return Ok(CapabilityVerification {
            valid: false,
            failure_reason: Some(format!(
                "public key wrong length: {} (expected 32)",
                pub_key_bytes.len()
            )),
        });
    }
    let vk_arr: [u8; 32] = pub_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CapabilityError::InvalidKey("public key conversion failed".to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(&vk_arr)
        .map_err(|e| CapabilityError::InvalidKey(format!("invalid public key: {e}")))?;

    let sig_bytes = hex::decode(&token.signature)
        .map_err(|e| CapabilityError::VerificationFailed(format!("signature hex decode: {e}")))?;
    if !verified_capability_verification::capability_signature_length_valid(sig_bytes.len()) {
        return Ok(CapabilityVerification {
            valid: false,
            failure_reason: Some(format!(
                "signature wrong length: {} (expected 64)",
                sig_bytes.len()
            )),
        });
    }
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        CapabilityError::VerificationFailed("signature conversion failed".to_string())
    })?;
    let signature = Signature::from_bytes(&sig_arr);

    let canonical = build_canonical_content(
        &token.token_id,
        token.parent_token_id.as_deref(),
        &token.issuer,
        &token.holder,
        &token.grants,
        token.remaining_depth,
        &token.issued_at,
        &token.expires_at,
    )?;

    // SECURITY (DOC-CRED-2): Domain-separated digest first, then the
    // pre-domain-separation form so tokens issued before the change keep
    // verifying until they expire. Signing always uses the domain-separated form.
    let content_hash = content_digest(&canonical, true);
    let signature_ok = verifying_key.verify(&content_hash, &signature).is_ok()
        || verifying_key
            .verify(&content_digest(&canonical, false), &signature)
            .is_ok();

    if !signature_ok {
        return Ok(CapabilityVerification {
            valid: false,
            failure_reason: Some("signature verification failed".to_string()),
        });
    }

    Ok(CapabilityVerification {
        valid: true,
        failure_reason: None,
    })
}

/// Check if a capability token's grants cover the given action.
///
/// Returns the index of the first matching grant, or `None` if no grant
/// covers the action.
pub fn check_grant_coverage(token: &CapabilityToken, action: &Action) -> Option<usize> {
    let mut selected_index = None;
    for (i, grant) in token.grants.iter().enumerate() {
        selected_index = verified_capability_selection::next_covering_grant_index(
            selected_index,
            i,
            grant_covers_action(grant, action),
        );
    }
    selected_index
}

/// Check if a grant covers the given action.
fn grant_covers_action(grant: &CapabilityGrant, action: &Action) -> bool {
    // Check tool pattern
    if !pattern_matches(&grant.tool_pattern, &action.tool) {
        return false;
    }
    // Check function pattern
    if !pattern_matches(&grant.function_pattern, &action.function) {
        return false;
    }
    // Check path constraints (if any)
    // SECURITY (FIND-R57-CAP-001): Fail-closed when grant requires path restrictions
    // but the action provides no target_paths. Otherwise a missing extraction path
    // would bypass grant constraints.
    let grant_has_allowed_paths = !grant.allowed_paths.is_empty();
    let action_has_target_paths = !action.target_paths.is_empty();
    let all_target_paths_covered = if grant_has_allowed_paths && action_has_target_paths {
        // SECURITY (FIND-083): Normalize action paths before matching to prevent
        // path traversal attacks (e.g., "/safe/../etc/passwd" matching "/safe/**").
        action.target_paths.iter().all(|path| {
            // Fail-closed: if normalization fails, deny the grant
            let normalized = match verified_capability_path::normalize_path_for_grant(path) {
                Some(n) => n,
                None => return false,
            };
            grant
                .allowed_paths
                .iter()
                .any(|pattern| pattern_matches(pattern, &normalized))
        })
    } else {
        false
    };
    // Check domain constraints (if any)
    // SECURITY (FIND-R57-CAP-001): Fail-closed when grant requires domain restrictions
    // but the action provides no target_domains.
    let grant_has_allowed_domains = !grant.allowed_domains.is_empty();
    let action_has_target_domains = !action.target_domains.is_empty();
    let all_target_domains_covered = if grant_has_allowed_domains && action_has_target_domains {
        action.target_domains.iter().all(|domain| {
            grant
                .allowed_domains
                .iter()
                .any(|pattern| verified_capability_domain::domain_matches_pattern(pattern, domain))
        })
    } else {
        false
    };
    if !verified_capability_coverage::grant_restrictions_cover_action(
        grant_has_allowed_paths,
        action_has_target_paths,
        all_target_paths_covered,
        grant_has_allowed_domains,
        action_has_target_domains,
        all_target_domains_covered,
    ) {
        return false;
    }
    true
}

/// Simple glob pattern matching (supports `*` and `?`).
fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let pattern_has_metacharacters = verified_capability_pattern::has_glob_metacharacters(pattern);
    if verified_capability_literal::literal_pattern_matches(
        pattern_has_metacharacters,
        pattern.eq_ignore_ascii_case(value),
    ) {
        return true;
    }
    if !pattern_has_metacharacters {
        return false;
    }
    verified_capability_glob::literal_child_matches_parent_glob(pattern, value)
}

/// Check if new_grant is a subset of parent_grant.
///
/// A grant is a subset if its tool/function patterns are equal to or more
/// specific than the parent's. For simplicity, exact equality or parent
/// having `*` patterns are accepted.
///
/// # Security (FIND-FV46-001, FIND-R46-004, FIND-FV46-002)
///
/// - Empty `allowed_paths`/`allowed_domains` in child when parent restricts = escalation
/// - Path patterns are normalized before comparison to prevent `/../` traversal
/// - `max_invocations` must be monotonically attenuated (child <= parent)
fn grant_is_subset(new_grant: &CapabilityGrant, parent_grant: &CapabilityGrant) -> bool {
    // SECURITY (FIND-CREATIVE-002): Glob metacharacter confusion in pattern-to-pattern
    // subset check. pattern_matches(parent, child) treats the child as a LITERAL string
    // matched against the parent glob. But at runtime, child patterns are used as GLOBS.
    // Example: parent "fi?" matches literal "fi*", but at runtime "fi*" is broader than "fi?".
    //
    // Fix: Keep the wildcard/equality/literal fast paths, and route the
    // remaining child-glob branch through the exact subset checker.
    fn pattern_is_subset(parent: &str, child: &str) -> bool {
        let parent_is_wildcard = parent == "*";
        let parent_equals_child_ignore_ascii_case = parent.eq_ignore_ascii_case(child);
        let child_has_metacharacters = verified_capability_pattern::has_glob_metacharacters(child);

        if verified_capability_pattern::pattern_subset_guard(
            parent_is_wildcard,
            parent_equals_child_ignore_ascii_case,
            child_has_metacharacters,
        ) {
            if parent_is_wildcard || parent_equals_child_ignore_ascii_case {
                return true;
            }

            // Child is a literal value — safe to check against parent glob.
            return verified_capability_literal::literal_child_pattern_subset(
                child_has_metacharacters,
                verified_capability_glob::literal_child_matches_parent_glob(parent, child),
            );
        }

        verified_capability_glob_subset::glob_pattern_subset(parent, child)
    }

    // Tool pattern must be subset of parent
    if !pattern_is_subset(&parent_grant.tool_pattern, &new_grant.tool_pattern) {
        return false;
    }
    // Function pattern must be subset of parent
    if !pattern_is_subset(&parent_grant.function_pattern, &new_grant.function_pattern) {
        return false;
    }
    if !verified_capability_grant::grant_restrictions_attenuated(
        !parent_grant.allowed_paths.is_empty(),
        !new_grant.allowed_paths.is_empty(),
        !parent_grant.allowed_domains.is_empty(),
        !new_grant.allowed_domains.is_empty(),
        parent_grant.max_invocations,
        new_grant.max_invocations,
    ) {
        return false;
    }
    // SECURITY (FIND-FV46-001): If parent has path restrictions, child MUST also
    // have non-empty path restrictions. An empty child `allowed_paths` means
    // "unrestricted", which is strictly more permissive than the parent's
    // restrictions — violating monotonic attenuation.
    if !parent_grant.allowed_paths.is_empty() {
        for path in &new_grant.allowed_paths {
            // SECURITY (FIND-R46-004): Normalize path patterns in the child grant
            // before checking subset containment. Without normalization, a child
            // with "/safe/../../etc" passes the parent's "/safe/*" pattern match
            // but at runtime resolves to "/etc".
            let normalized = match verified_capability_path::normalize_path_for_grant(path) {
                Some(n) => n,
                None => return false, // Fail-closed: malformed path = deny
            };
            let covered = parent_grant.allowed_paths.iter().any(|pp| {
                // Also normalize parent pattern for consistent comparison
                let parent_normalized =
                    verified_capability_path::normalize_path_for_grant(pp).unwrap_or_default();
                if parent_normalized.is_empty() {
                    return false; // Malformed parent pattern — fail-closed
                }
                pattern_matches(&parent_normalized, &normalized)
            });
            if !covered {
                return false;
            }
        }
    }
    // SECURITY (FIND-FV46-001): Same check for domains — child must not drop
    // parent's domain restrictions.
    if !parent_grant.allowed_domains.is_empty() {
        for domain in &new_grant.allowed_domains {
            let covered = parent_grant
                .allowed_domains
                .iter()
                .any(|pd| verified_capability_domain::domain_pattern_is_subset(pd, domain));
            if !covered {
                return false;
            }
        }
    }
    true
}

// ── Internal helpers ────────────────────────────────────────────────────────

fn parse_signing_key(hex_key: &str) -> Result<SigningKey, CapabilityError> {
    let key_bytes = hex::decode(hex_key)
        .map_err(|e| CapabilityError::InvalidKey(format!("hex decode failed: {e}")))?;
    if key_bytes.len() != 32 {
        return Err(CapabilityError::InvalidKey(format!(
            "expected 32 bytes, got {}",
            key_bytes.len()
        )));
    }
    let arr: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CapabilityError::InvalidKey("key conversion failed".to_string()))?;
    Ok(SigningKey::from_bytes(&arr))
}

/// Build length-prefixed canonical content for signing.
///
/// Format: `<field_len>:<field>` for each field, preventing boundary collision.
///
/// # Security (FIND-R116-MCP-001)
///
/// The `expires_at` field MUST be included in the signed canonical content.
/// Without it, an attacker possessing a valid token can modify `expires_at`
/// to extend the token's lifetime indefinitely without invalidating the signature.
#[allow(clippy::too_many_arguments)] // FIND-R116-MCP-001: expires_at is a security-required parameter
fn build_canonical_content(
    token_id: &str,
    parent_token_id: Option<&str>,
    issuer: &str,
    holder: &str,
    grants: &[CapabilityGrant],
    remaining_depth: u8,
    issued_at: &str,
    expires_at: &str,
) -> Result<String, CapabilityError> {
    let grants_json = serde_json::to_string(grants)
        .map_err(|e| CapabilityError::SigningFailed(format!("grants serialization failed: {e}")))?;
    let parent_str = parent_token_id.unwrap_or("");
    // SECURITY (FIND-R115-020): Use actual byte length of the remaining_depth string
    // representation, not a hardcoded `1`. For depth values >= 10 (two digits), the
    // hardcoded prefix caused canonical content collisions.
    let depth_str = remaining_depth.to_string();
    Ok(format!(
        "{}:{}{}:{}{}:{}{}:{}{}:{}{}:{}{}:{}{}:{}",
        token_id.len(),
        token_id,
        parent_str.len(),
        parent_str,
        issuer.len(),
        issuer,
        holder.len(),
        holder,
        grants_json.len(),
        grants_json,
        depth_str.len(),
        depth_str,
        issued_at.len(),
        issued_at,
        expires_at.len(),
        expires_at,
    ))
}

/// Digest of a token's canonical content, bound to the capability-token domain.
///
/// SECURITY (DOC-CRED-2): Seeding the hash with a type-specific constant means
/// a signature over a capability token cannot be presented as a signature over
/// another artifact type signed by the same key. `domain_separated` is false
/// only when verifying tokens issued before this change.
fn content_digest(canonical: &str, domain_separated: bool) -> Vec<u8> {
    let mut hasher = if domain_separated {
        vellaveto_types::signing_domain::domain_separated_hasher(
            vellaveto_types::signing_domain::DOMAIN_CAPABILITY_TOKEN,
        )
    } else {
        Sha256::new()
    };
    hasher.update(canonical.as_bytes());
    hasher.finalize().to_vec()
}

fn sign_content(signing_key: &SigningKey, canonical: &str) -> Result<String, CapabilityError> {
    let signature = signing_key.sign(&content_digest(canonical, true));
    Ok(hex::encode(signature.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vellaveto_types::CapabilityGrant;

    fn test_key_hex() -> String {
        let key = SigningKey::generate(&mut rand::rng());
        hex::encode(key.to_bytes())
    }

    fn test_grants() -> Vec<CapabilityGrant> {
        vec![CapabilityGrant {
            tool_pattern: "file_system".into(),
            function_pattern: "read_file".into(),
            allowed_paths: vec!["/tmp/*".into()],
            allowed_domains: vec![],
            max_invocations: 0,
        }]
    }

    #[test]
    fn test_issue_and_verify_roundtrip() {
        let key_hex = test_key_hex();
        let token =
            issue_capability_token("issuer-1", "holder-1", test_grants(), 5, &key_hex, 3600)
                .unwrap();

        let key = parse_signing_key(&key_hex).unwrap();
        let pub_key_hex = hex::encode(key.verifying_key().as_bytes());
        let now = chrono::Utc::now();
        let result =
            verify_capability_token(&token, Some("holder-1"), Some(&pub_key_hex), &now).unwrap();
        assert!(
            result.valid,
            "Token should verify: {:?}",
            result.failure_reason
        );
    }

    #[test]
    fn test_tampered_signature_rejected() {
        let key_hex = test_key_hex();
        let mut token =
            issue_capability_token("issuer-1", "holder-1", test_grants(), 5, &key_hex, 3600)
                .unwrap();
        // Tamper with the signature
        token.signature = hex::encode([0xffu8; 64]);
        let now = chrono::Utc::now();
        let result = verify_capability_token(&token, None, None, &now).unwrap();
        assert!(!result.valid);
        assert!(result.failure_reason.unwrap().contains("signature"));
    }

    #[test]
    fn test_tampered_content_rejected() {
        let key_hex = test_key_hex();
        let mut token =
            issue_capability_token("issuer-1", "holder-1", test_grants(), 5, &key_hex, 3600)
                .unwrap();
        token.holder = "attacker".to_string();
        let now = chrono::Utc::now();
        let result = verify_capability_token(&token, None, None, &now).unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn test_expired_token_rejected() {
        let key_hex = test_key_hex();
        let token = issue_capability_token(
            "issuer-1",
            "holder-1",
            test_grants(),
            5,
            &key_hex,
            1, // 1 second TTL
        )
        .unwrap();
        // Set "now" far in the future
        let future = chrono::Utc::now() + chrono::Duration::hours(1);
        let result = verify_capability_token(&token, None, None, &future).unwrap();
        assert!(!result.valid);
        assert!(result.failure_reason.unwrap().contains("expired"));
    }

    #[test]
    fn test_holder_mismatch_rejected() {
        let key_hex = test_key_hex();
        let token =
            issue_capability_token("issuer-1", "holder-1", test_grants(), 5, &key_hex, 3600)
                .unwrap();
        let now = chrono::Utc::now();
        let result = verify_capability_token(&token, Some("wrong-holder"), None, &now).unwrap();
        assert!(!result.valid);
        assert!(result.failure_reason.unwrap().contains("holder mismatch"));
    }

    #[test]
    fn test_wrong_key_rejected() {
        let key_hex = test_key_hex();
        let token =
            issue_capability_token("issuer-1", "holder-1", test_grants(), 5, &key_hex, 3600)
                .unwrap();
        let wrong_key = test_key_hex();
        let wrong_key_obj = parse_signing_key(&wrong_key).unwrap();
        let wrong_pub = hex::encode(wrong_key_obj.verifying_key().as_bytes());
        let now = chrono::Utc::now();
        let result = verify_capability_token(&token, None, Some(&wrong_pub), &now).unwrap();
        assert!(!result.valid);
        assert!(result.failure_reason.unwrap().contains("key mismatch"));
    }

    #[test]
    fn test_verify_rejects_wrong_public_key_length() {
        let key_hex = test_key_hex();
        let mut token =
            issue_capability_token("issuer-1", "holder-1", test_grants(), 5, &key_hex, 3600)
                .unwrap();
        token.issuer_public_key = hex::encode([0xabu8; 31]);

        let now = chrono::Utc::now();
        let result = verify_capability_token(&token, None, None, &now).unwrap();
        assert!(!result.valid);
        assert!(result
            .failure_reason
            .unwrap()
            .contains("public key wrong length"));
    }

    #[test]
    fn test_verify_rejects_wrong_signature_length() {
        let key_hex = test_key_hex();
        let mut token =
            issue_capability_token("issuer-1", "holder-1", test_grants(), 5, &key_hex, 3600)
                .unwrap();
        token.signature = hex::encode([0xcdu8; 63]);

        let now = chrono::Utc::now();
        let result = verify_capability_token(&token, None, None, &now).unwrap();
        assert!(!result.valid);
        assert!(result
            .failure_reason
            .unwrap()
            .contains("signature wrong length"));
    }

    #[test]
    fn test_grant_coverage_exact_match() {
        let key_hex = test_key_hex();
        let token =
            issue_capability_token("issuer", "holder", test_grants(), 5, &key_hex, 3600).unwrap();
        let mut action = Action::new(
            "file_system".to_string(),
            "read_file".to_string(),
            serde_json::json!({"path": "/tmp/test.txt"}),
        );
        action.target_paths = vec!["/tmp/test.txt".into()];
        assert!(check_grant_coverage(&token, &action).is_some());
    }

    #[test]
    fn test_grant_coverage_no_match() {
        let key_hex = test_key_hex();
        let token =
            issue_capability_token("issuer", "holder", test_grants(), 5, &key_hex, 3600).unwrap();
        let action = Action::new(
            "database".to_string(),
            "query".to_string(),
            serde_json::json!({}),
        );
        assert!(check_grant_coverage(&token, &action).is_none());
    }

    #[test]
    fn test_grant_coverage_glob_match() {
        let key_hex = test_key_hex();
        let grants = vec![CapabilityGrant {
            tool_pattern: "file_*".into(),
            function_pattern: "*".into(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }];
        let token = issue_capability_token("issuer", "holder", grants, 5, &key_hex, 3600).unwrap();
        let action = Action::new(
            "file_system".to_string(),
            "write_file".to_string(),
            serde_json::json!({}),
        );
        assert!(check_grant_coverage(&token, &action).is_some());
    }

    #[test]
    fn test_grant_coverage_returns_first_matching_index() {
        let key_hex = test_key_hex();
        let grants = vec![
            CapabilityGrant {
                tool_pattern: "file_*".into(),
                function_pattern: "*".into(),
                allowed_paths: vec![],
                allowed_domains: vec![],
                max_invocations: 0,
            },
            CapabilityGrant {
                tool_pattern: "*".into(),
                function_pattern: "*".into(),
                allowed_paths: vec![],
                allowed_domains: vec![],
                max_invocations: 0,
            },
        ];
        let token = issue_capability_token("issuer", "holder", grants, 5, &key_hex, 3600).unwrap();
        let action = Action::new(
            "file_system".to_string(),
            "write_file".to_string(),
            serde_json::json!({}),
        );

        assert_eq!(check_grant_coverage(&token, &action), Some(0));
    }

    #[test]
    fn test_attenuation_valid() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent = issue_capability_token(
            "root",
            "agent-a",
            vec![CapabilityGrant {
                tool_pattern: "*".into(),
                function_pattern: "*".into(),
                allowed_paths: vec![],
                allowed_domains: vec![],
                max_invocations: 0,
            }],
            5,
            &parent_key_hex,
            3600,
        )
        .unwrap();

        let child =
            attenuate_capability_token(&parent, "agent-b", test_grants(), &child_key_hex, 1800)
                .unwrap();

        assert_eq!(child.remaining_depth, 4);
        assert_eq!(child.issuer, "agent-a");
        assert_eq!(child.holder, "agent-b");
        assert!(child.parent_token_id.is_some());
    }

    #[test]
    fn test_attenuation_escalation_rejected() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent =
            issue_capability_token("root", "agent-a", test_grants(), 5, &parent_key_hex, 3600)
                .unwrap();

        // Try to grant access to "database" which parent doesn't have
        let escalated_grants = vec![CapabilityGrant {
            tool_pattern: "database".into(),
            function_pattern: "*".into(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }];
        let result =
            attenuate_capability_token(&parent, "agent-b", escalated_grants, &child_key_hex, 1800);
        assert!(result.is_err());
        match result.unwrap_err() {
            CapabilityError::AttenuationViolation(_) => {}
            other => panic!("Expected AttenuationViolation, got: {other:?}"),
        }
    }

    #[test]
    fn test_attenuation_depth_zero_rejected() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent =
            issue_capability_token("root", "agent-a", test_grants(), 0, &parent_key_hex, 3600)
                .unwrap();

        let result =
            attenuate_capability_token(&parent, "agent-b", test_grants(), &child_key_hex, 1800);
        assert!(result.is_err());
        match result.unwrap_err() {
            CapabilityError::AttenuationViolation(_) => {}
            other => panic!("Expected AttenuationViolation, got: {other:?}"),
        }
    }

    #[test]
    fn test_attenuation_expiry_clamping() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent = issue_capability_token(
            "root",
            "agent-a",
            test_grants(),
            5,
            &parent_key_hex,
            60, // 60 seconds
        )
        .unwrap();

        let child = attenuate_capability_token(
            &parent,
            "agent-b",
            test_grants(),
            &child_key_hex,
            999999, // very long
        )
        .unwrap();

        // Child's expiry should be clamped to parent's
        let parent_exp = chrono::DateTime::parse_from_rfc3339(&parent.expires_at).unwrap();
        let child_exp = chrono::DateTime::parse_from_rfc3339(&child.expires_at).unwrap();
        assert!(child_exp <= parent_exp);
    }

    #[test]
    fn test_structural_validation_empty_fields() {
        let token = CapabilityToken {
            token_id: "".into(), // Empty!
            parent_token_id: None,
            issuer: "a".into(),
            holder: "b".into(),
            grants: test_grants(),
            remaining_depth: 0,
            issued_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2027-01-01T00:00:00Z".into(),
            signature: "sig".into(),
            issuer_public_key: "key".into(),
        };
        assert!(token.validate_structure().is_err());
    }

    #[test]
    fn test_structural_validation_too_many_grants() {
        let mut grants = Vec::new();
        for i in 0..65 {
            grants.push(CapabilityGrant {
                tool_pattern: format!("tool_{i}"),
                function_pattern: "*".into(),
                allowed_paths: vec![],
                allowed_domains: vec![],
                max_invocations: 0,
            });
        }
        let token = CapabilityToken {
            token_id: "tok-1".into(),
            parent_token_id: None,
            issuer: "a".into(),
            holder: "b".into(),
            grants,
            remaining_depth: 0,
            issued_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2027-01-01T00:00:00Z".into(),
            signature: "sig".into(),
            issuer_public_key: "key".into(),
        };
        assert!(token.validate_structure().is_err());
    }

    #[test]
    fn test_structural_validation_depth_exceeds_max() {
        let token = CapabilityToken {
            token_id: "tok-1".into(),
            parent_token_id: None,
            issuer: "a".into(),
            holder: "b".into(),
            grants: test_grants(),
            remaining_depth: 17, // > MAX_DELEGATION_DEPTH
            issued_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2027-01-01T00:00:00Z".into(),
            signature: "sig".into(),
            issuer_public_key: "key".into(),
        };
        assert!(token.validate_structure().is_err());
    }

    #[test]
    fn test_serde_roundtrip() {
        let key_hex = test_key_hex();
        let token =
            issue_capability_token("issuer-1", "holder-1", test_grants(), 5, &key_hex, 3600)
                .unwrap();
        let json = serde_json::to_string(&token).unwrap();
        let deserialized: CapabilityToken = serde_json::from_str(&json).unwrap();
        assert_eq!(token, deserialized);
    }

    #[test]
    fn test_empty_issuer_rejected() {
        let key_hex = test_key_hex();
        let result = issue_capability_token("", "holder", test_grants(), 5, &key_hex, 3600);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_holder_rejected() {
        let key_hex = test_key_hex();
        let result = issue_capability_token("issuer", "", test_grants(), 5, &key_hex, 3600);
        assert!(result.is_err());
    }

    #[test]
    fn test_grant_path_constraint_match() {
        let key_hex = test_key_hex();
        let grants = vec![CapabilityGrant {
            tool_pattern: "fs".into(),
            function_pattern: "read".into(),
            allowed_paths: vec!["/data/*".into()],
            allowed_domains: vec![],
            max_invocations: 0,
        }];
        let token = issue_capability_token("issuer", "holder", grants, 5, &key_hex, 3600).unwrap();

        let mut action = Action::new("fs".to_string(), "read".to_string(), serde_json::json!({}));
        action.target_paths = vec!["/data/file.txt".into()];
        assert!(check_grant_coverage(&token, &action).is_some());

        // Path outside allowed
        let mut action2 = Action::new("fs".to_string(), "read".to_string(), serde_json::json!({}));
        action2.target_paths = vec!["/etc/passwd".into()];
        assert!(check_grant_coverage(&token, &action2).is_none());
    }

    #[test]
    fn test_grant_domain_constraint_match() {
        let key_hex = test_key_hex();
        let grants = vec![CapabilityGrant {
            tool_pattern: "http".into(),
            function_pattern: "get".into(),
            allowed_paths: vec![],
            allowed_domains: vec!["*.example.com".into()],
            max_invocations: 0,
        }];
        let token = issue_capability_token("issuer", "holder", grants, 5, &key_hex, 3600).unwrap();

        let mut action = Action::new("http".to_string(), "get".to_string(), serde_json::json!({}));
        action.target_domains = vec!["api.example.com".into()];
        assert!(check_grant_coverage(&token, &action).is_some());

        let mut action2 = Action::new("http".to_string(), "get".to_string(), serde_json::json!({}));
        action2.target_domains = vec!["evil.com".into()];
        assert!(check_grant_coverage(&token, &action2).is_none());
    }

    #[test]
    fn test_grant_domain_constraint_normalizes_case_and_trailing_dot() {
        let key_hex = test_key_hex();
        let grants = vec![CapabilityGrant {
            tool_pattern: "http".into(),
            function_pattern: "get".into(),
            allowed_paths: vec![],
            allowed_domains: vec!["API.EXAMPLE.COM.".into(), "*.MÜNCHEN.DE".into()],
            max_invocations: 0,
        }];
        let token = issue_capability_token("issuer", "holder", grants, 5, &key_hex, 3600).unwrap();

        let mut action = Action::new("http".to_string(), "get".to_string(), serde_json::json!({}));
        action.target_domains = vec!["api.example.com".into(), "service.xn--mnchen-3ya.de".into()];
        assert!(check_grant_coverage(&token, &action).is_some());
    }

    // SECURITY (FIND-R57-CAP-001): Missing targets must fail-closed when grants
    // define path/domain restrictions.
    #[test]
    fn test_grant_path_constraint_missing_action_paths_denied() {
        let key_hex = test_key_hex();
        let grants = vec![CapabilityGrant {
            tool_pattern: "fs".into(),
            function_pattern: "read".into(),
            allowed_paths: vec!["/data/*".into()],
            allowed_domains: vec![],
            max_invocations: 0,
        }];
        let token = issue_capability_token("issuer", "holder", grants, 5, &key_hex, 3600).unwrap();

        // No target_paths present => deny by fail-closed coverage check.
        let action = Action::new("fs".to_string(), "read".to_string(), serde_json::json!({}));
        assert!(check_grant_coverage(&token, &action).is_none());
    }

    #[test]
    fn test_grant_domain_constraint_missing_action_domains_denied() {
        let key_hex = test_key_hex();
        let grants = vec![CapabilityGrant {
            tool_pattern: "http".into(),
            function_pattern: "get".into(),
            allowed_paths: vec![],
            allowed_domains: vec!["*.example.com".into()],
            max_invocations: 0,
        }];
        let token = issue_capability_token("issuer", "holder", grants, 5, &key_hex, 3600).unwrap();

        // No target_domains present => deny by fail-closed coverage check.
        let action = Action::new("http".to_string(), "get".to_string(), serde_json::json!({}));
        assert!(check_grant_coverage(&token, &action).is_none());
    }

    #[test]
    fn test_grant_path_constraint_malformed_action_path_denied() {
        let key_hex = test_key_hex();
        let grants = vec![CapabilityGrant {
            tool_pattern: "fs".into(),
            function_pattern: "read".into(),
            allowed_paths: vec!["/safe/*".into()],
            allowed_domains: vec![],
            max_invocations: 0,
        }];
        let token = issue_capability_token("issuer", "holder", grants, 5, &key_hex, 3600).unwrap();

        let mut action = Action::new("fs".to_string(), "read".to_string(), serde_json::json!({}));
        action.target_paths = vec!["/safe/../../etc/passwd".into()];
        assert!(check_grant_coverage(&token, &action).is_none());
    }

    #[test]
    fn test_grant_path_constraint_requires_all_targets_covered() {
        let key_hex = test_key_hex();
        let grants = vec![CapabilityGrant {
            tool_pattern: "fs".into(),
            function_pattern: "read".into(),
            allowed_paths: vec!["/data/*".into()],
            allowed_domains: vec![],
            max_invocations: 0,
        }];
        let token = issue_capability_token("issuer", "holder", grants, 5, &key_hex, 3600).unwrap();

        let mut action = Action::new("fs".to_string(), "read".to_string(), serde_json::json!({}));
        action.target_paths = vec!["/data/file.txt".into(), "/etc/passwd".into()];
        assert!(check_grant_coverage(&token, &action).is_none());
    }

    #[test]
    fn test_grant_domain_constraint_requires_all_targets_covered() {
        let key_hex = test_key_hex();
        let grants = vec![CapabilityGrant {
            tool_pattern: "http".into(),
            function_pattern: "get".into(),
            allowed_paths: vec![],
            allowed_domains: vec!["*.example.com".into()],
            max_invocations: 0,
        }];
        let token = issue_capability_token("issuer", "holder", grants, 5, &key_hex, 3600).unwrap();

        let mut action = Action::new("http".to_string(), "get".to_string(), serde_json::json!({}));
        action.target_domains = vec!["api.example.com".into(), "evil.com".into()];
        assert!(check_grant_coverage(&token, &action).is_none());
    }

    #[test]
    fn test_grant_domain_constraint_malformed_action_domain_denied() {
        let key_hex = test_key_hex();
        let grants = vec![CapabilityGrant {
            tool_pattern: "http".into(),
            function_pattern: "get".into(),
            allowed_paths: vec![],
            allowed_domains: vec!["*.example.com".into()],
            max_invocations: 0,
        }];
        let token = issue_capability_token("issuer", "holder", grants, 5, &key_hex, 3600).unwrap();

        let mut action = Action::new("http".to_string(), "get".to_string(), serde_json::json!({}));
        action.target_domains = vec!["api.example.com:443".into()];
        assert!(check_grant_coverage(&token, &action).is_none());
    }

    #[test]
    fn test_boundary_collision_different_issuer_holder() {
        // "issuerA" + "holderB" should produce different canonical content than
        // "issuer" + "AholderB" due to length prefixing
        let key_hex = test_key_hex();
        let token1 =
            issue_capability_token("issuerA", "holderB", test_grants(), 5, &key_hex, 3600).unwrap();
        let token2 =
            issue_capability_token("issuer", "AholderB", test_grants(), 5, &key_hex, 3600).unwrap();
        // Different tokens should have different signatures
        assert_ne!(token1.signature, token2.signature);
    }

    // SECURITY (FIND-FV46-001): Empty allowed_paths in child when parent restricts
    // must be rejected — empty means "unrestricted", which escalates privileges.
    #[test]
    fn test_attenuation_empty_paths_escalation_rejected() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent = issue_capability_token(
            "root",
            "agent-a",
            vec![CapabilityGrant {
                tool_pattern: "*".into(),
                function_pattern: "*".into(),
                allowed_paths: vec!["/data/*".into()],
                allowed_domains: vec![],
                max_invocations: 0,
            }],
            5,
            &parent_key_hex,
            3600,
        )
        .unwrap();

        // Child tries to drop path restrictions (empty = unrestricted)
        let child_grants = vec![CapabilityGrant {
            tool_pattern: "*".into(),
            function_pattern: "*".into(),
            allowed_paths: vec![], // Escalation: drops parent's path restriction
            allowed_domains: vec![],
            max_invocations: 0,
        }];
        let result =
            attenuate_capability_token(&parent, "agent-b", child_grants, &child_key_hex, 1800);
        assert!(
            result.is_err(),
            "FIND-FV46-001: Child with empty paths when parent restricts must be rejected"
        );
    }

    // SECURITY (FIND-FV46-001): Same for domains.
    #[test]
    fn test_attenuation_empty_domains_escalation_rejected() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent = issue_capability_token(
            "root",
            "agent-a",
            vec![CapabilityGrant {
                tool_pattern: "*".into(),
                function_pattern: "*".into(),
                allowed_paths: vec![],
                allowed_domains: vec!["*.example.com".into()],
                max_invocations: 0,
            }],
            5,
            &parent_key_hex,
            3600,
        )
        .unwrap();

        let child_grants = vec![CapabilityGrant {
            tool_pattern: "*".into(),
            function_pattern: "*".into(),
            allowed_paths: vec![],
            allowed_domains: vec![], // Escalation: drops parent's domain restriction
            max_invocations: 0,
        }];
        let result =
            attenuate_capability_token(&parent, "agent-b", child_grants, &child_key_hex, 1800);
        assert!(
            result.is_err(),
            "FIND-FV46-001: Child with empty domains when parent restricts must be rejected"
        );
    }

    #[test]
    fn test_attenuation_allows_exact_child_domain_under_parent_wildcard() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent = issue_capability_token(
            "root",
            "agent-a",
            vec![CapabilityGrant {
                tool_pattern: "*".into(),
                function_pattern: "*".into(),
                allowed_paths: vec![],
                allowed_domains: vec!["*.example.com".into()],
                max_invocations: 0,
            }],
            5,
            &parent_key_hex,
            3600,
        )
        .unwrap();

        let child_grants = vec![CapabilityGrant {
            tool_pattern: "*".into(),
            function_pattern: "*".into(),
            allowed_paths: vec![],
            allowed_domains: vec!["api.example.com".into()],
            max_invocations: 0,
        }];
        let result =
            attenuate_capability_token(&parent, "agent-b", child_grants, &child_key_hex, 1800);
        assert!(
            result.is_ok(),
            "exact child domain under parent wildcard must succeed"
        );
    }

    #[test]
    fn test_attenuation_allows_narrower_child_domain_wildcard() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent = issue_capability_token(
            "root",
            "agent-a",
            vec![CapabilityGrant {
                tool_pattern: "*".into(),
                function_pattern: "*".into(),
                allowed_paths: vec![],
                allowed_domains: vec!["*.example.com".into()],
                max_invocations: 0,
            }],
            5,
            &parent_key_hex,
            3600,
        )
        .unwrap();

        let child_grants = vec![CapabilityGrant {
            tool_pattern: "*".into(),
            function_pattern: "*".into(),
            allowed_paths: vec![],
            allowed_domains: vec!["*.api.example.com".into()],
            max_invocations: 0,
        }];
        let result =
            attenuate_capability_token(&parent, "agent-b", child_grants, &child_key_hex, 1800);
        assert!(
            result.is_ok(),
            "narrower child wildcard domain under parent wildcard must succeed"
        );
    }

    #[test]
    fn test_attenuation_rejects_invalid_child_domain_pattern() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent = issue_capability_token(
            "root",
            "agent-a",
            vec![CapabilityGrant {
                tool_pattern: "*".into(),
                function_pattern: "*".into(),
                allowed_paths: vec![],
                allowed_domains: vec!["*.example.com".into()],
                max_invocations: 0,
            }],
            5,
            &parent_key_hex,
            3600,
        )
        .unwrap();

        let child_grants = vec![CapabilityGrant {
            tool_pattern: "*".into(),
            function_pattern: "*".into(),
            allowed_paths: vec![],
            allowed_domains: vec!["api?.example.com".into()],
            max_invocations: 0,
        }];
        let result =
            attenuate_capability_token(&parent, "agent-b", child_grants, &child_key_hex, 1800);
        assert!(
            result.is_err(),
            "invalid child domain pattern must be rejected"
        );
    }

    // SECURITY (FIND-R46-004): Path traversal via unnormalized paths in child grant.
    #[test]
    fn test_attenuation_path_traversal_rejected() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent = issue_capability_token(
            "root",
            "agent-a",
            vec![CapabilityGrant {
                tool_pattern: "*".into(),
                function_pattern: "*".into(),
                allowed_paths: vec!["/safe/*".into()],
                allowed_domains: vec![],
                max_invocations: 0,
            }],
            5,
            &parent_key_hex,
            3600,
        )
        .unwrap();

        // Child tries path traversal: /safe/../../etc normalizes to above root
        let child_grants = vec![CapabilityGrant {
            tool_pattern: "*".into(),
            function_pattern: "*".into(),
            allowed_paths: vec!["/safe/../../etc".into()],
            allowed_domains: vec![],
            max_invocations: 0,
        }];
        let result =
            attenuate_capability_token(&parent, "agent-b", child_grants, &child_key_hex, 1800);
        assert!(
            result.is_err(),
            "FIND-R46-004: Path traversal in child grant paths must be rejected"
        );
    }

    // SECURITY (FIND-FV46-002): max_invocations must be monotonically attenuated.
    #[test]
    fn test_attenuation_max_invocations_escalation_rejected() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent = issue_capability_token(
            "root",
            "agent-a",
            vec![CapabilityGrant {
                tool_pattern: "*".into(),
                function_pattern: "*".into(),
                allowed_paths: vec![],
                allowed_domains: vec![],
                max_invocations: 10,
            }],
            5,
            &parent_key_hex,
            3600,
        )
        .unwrap();

        // Child tries unlimited invocations (0 = unlimited)
        let child_grants = vec![CapabilityGrant {
            tool_pattern: "*".into(),
            function_pattern: "*".into(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0, // Unlimited — exceeds parent's 10
        }];
        let result =
            attenuate_capability_token(&parent, "agent-b", child_grants, &child_key_hex, 1800);
        assert!(
            result.is_err(),
            "FIND-FV46-002: Child with unlimited invocations when parent limits must be rejected"
        );
    }

    #[test]
    fn test_attenuation_max_invocations_exceeds_parent_rejected() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent = issue_capability_token(
            "root",
            "agent-a",
            vec![CapabilityGrant {
                tool_pattern: "*".into(),
                function_pattern: "*".into(),
                allowed_paths: vec![],
                allowed_domains: vec![],
                max_invocations: 10,
            }],
            5,
            &parent_key_hex,
            3600,
        )
        .unwrap();

        // Child tries more invocations than parent allows
        let child_grants = vec![CapabilityGrant {
            tool_pattern: "*".into(),
            function_pattern: "*".into(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 20, // Exceeds parent's 10
        }];
        let result =
            attenuate_capability_token(&parent, "agent-b", child_grants, &child_key_hex, 1800);
        assert!(
            result.is_err(),
            "FIND-FV46-002: Child with more invocations than parent must be rejected"
        );
    }

    // ════════════════════════════════════════════════════════
    // IMP-R118-004: Control character validation
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_issue_rejects_issuer_control_chars() {
        let key_hex = test_key_hex();
        let result =
            issue_capability_token("issuer\x00", "holder", test_grants(), 5, &key_hex, 3600);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("control"));
    }

    #[test]
    fn test_issue_rejects_holder_bidi_override() {
        let key_hex = test_key_hex();
        let result = issue_capability_token(
            "issuer",
            "holder\u{202E}evil",
            test_grants(),
            5,
            &key_hex,
            3600,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("control"));
    }

    #[test]
    fn test_issue_rejects_issuer_zero_width() {
        let key_hex = test_key_hex();
        let result =
            issue_capability_token("issuer\u{200B}", "holder", test_grants(), 5, &key_hex, 3600);
        assert!(result.is_err());
    }

    #[test]
    fn test_issue_rejects_issuer_too_long() {
        let key_hex = test_key_hex();
        let long_issuer = "i".repeat(MAX_IDENTITY_LEN + 1);
        let result =
            issue_capability_token(&long_issuer, "holder", test_grants(), 5, &key_hex, 3600);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("length"));
    }

    #[test]
    fn test_issue_accepts_max_length_issuer() {
        let key_hex = test_key_hex();
        let max_issuer = "i".repeat(MAX_IDENTITY_LEN);
        let result =
            issue_capability_token(&max_issuer, "holder", test_grants(), 5, &key_hex, 3600);
        assert!(result.is_ok());
    }

    #[test]
    fn test_attenuate_rejects_new_holder_control_chars() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent = issue_capability_token(
            "root",
            "agent-a",
            vec![CapabilityGrant {
                tool_pattern: "*".into(),
                function_pattern: "*".into(),
                allowed_paths: vec![],
                allowed_domains: vec![],
                max_invocations: 0,
            }],
            5,
            &parent_key_hex,
            3600,
        )
        .unwrap();
        let result = attenuate_capability_token(
            &parent,
            "agent-b\x1B[0m",
            test_grants(),
            &child_key_hex,
            1800,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("control"));
    }

    // ════════════════════════════════════════════════════════
    // IMP-R118-010: Self-delegation rejection
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_attenuate_rejects_self_delegation() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent = issue_capability_token(
            "root",
            "agent-a",
            vec![CapabilityGrant {
                tool_pattern: "*".into(),
                function_pattern: "*".into(),
                allowed_paths: vec![],
                allowed_domains: vec![],
                max_invocations: 0,
            }],
            5,
            &parent_key_hex,
            3600,
        )
        .unwrap();

        let result = attenuate_capability_token(
            &parent,
            "agent-a", // same as parent.holder
            test_grants(),
            &child_key_hex,
            1800,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("self-delegation"));
    }

    #[test]
    fn test_attenuate_rejects_self_delegation_case_insensitive() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent = issue_capability_token(
            "root",
            "Agent-A",
            vec![CapabilityGrant {
                tool_pattern: "*".into(),
                function_pattern: "*".into(),
                allowed_paths: vec![],
                allowed_domains: vec![],
                max_invocations: 0,
            }],
            5,
            &parent_key_hex,
            3600,
        )
        .unwrap();

        let result = attenuate_capability_token(
            &parent,
            "AGENT-A", // case-different but same identity
            test_grants(),
            &child_key_hex,
            1800,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("self-delegation"));
    }

    // ════════════════════════════════════════════════════════
    // IMP-R120-004: Future issued_at rejection
    // ════════════════════════════════════════════════════════

    #[test]
    fn test_verify_rejects_future_issued_at_beyond_skew() {
        let key_hex = test_key_hex();
        let mut token =
            issue_capability_token("root", "agent-a", test_grants(), 5, &key_hex, 3600).unwrap();

        // Set issued_at to 120 seconds in the future (beyond 60s skew tolerance)
        let future_time = chrono::Utc::now() + chrono::Duration::seconds(120);
        token.issued_at = future_time.to_rfc3339();

        let now = chrono::Utc::now();
        let result = verify_capability_token(&token, Some("agent-a"), None, &now).unwrap();
        assert!(!result.valid, "future-dated token should be rejected");
        assert!(
            result.failure_reason.as_ref().unwrap().contains("future"),
            "error should mention 'future', got: {:?}",
            result.failure_reason
        );
    }

    #[test]
    fn test_verify_accepts_issued_at_within_skew() {
        let key_hex = test_key_hex();
        let mut token =
            issue_capability_token("root", "agent-a", test_grants(), 5, &key_hex, 3600).unwrap();

        // Set issued_at to 30 seconds in the future (within 60s skew tolerance)
        let near_future = chrono::Utc::now() + chrono::Duration::seconds(30);
        token.issued_at = near_future.to_rfc3339();

        // Re-sign the token after modifying issued_at so the signature matches
        let signing_key = parse_signing_key(&key_hex).unwrap();
        let canonical = build_canonical_content(
            &token.token_id,
            token.parent_token_id.as_deref(),
            &token.issuer,
            &token.holder,
            &token.grants,
            token.remaining_depth,
            &token.issued_at,
            &token.expires_at,
        )
        .unwrap();
        token.signature = sign_content(&signing_key, &canonical).unwrap();

        let now = chrono::Utc::now();
        let result = verify_capability_token(&token, Some("agent-a"), None, &now).unwrap();
        // Should be valid (within skew tolerance)
        assert!(
            result.valid,
            "token within skew should be accepted: {:?}",
            result.failure_reason
        );
    }

    #[test]
    fn test_attenuation_max_invocations_valid_subset() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent = issue_capability_token(
            "root",
            "agent-a",
            vec![CapabilityGrant {
                tool_pattern: "*".into(),
                function_pattern: "*".into(),
                allowed_paths: vec![],
                allowed_domains: vec![],
                max_invocations: 10,
            }],
            5,
            &parent_key_hex,
            3600,
        )
        .unwrap();

        // Child with fewer invocations is fine
        let child_grants = vec![CapabilityGrant {
            tool_pattern: "*".into(),
            function_pattern: "*".into(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 5, // Less than parent's 10 — valid
        }];
        let result =
            attenuate_capability_token(&parent, "agent-b", child_grants, &child_key_hex, 1800);
        assert!(
            result.is_ok(),
            "Child with fewer invocations than parent should succeed: {:?}",
            result.err()
        );
    }

    // ════════════════════════════════════════════════════════
    // FIND-R115-020: Canonical content depth collision fix
    // ════════════════════════════════════════════════════════

    /// FIND-R115-020: Tokens with different remaining_depth values must produce
    /// different canonical content. Previously, a hardcoded length prefix of `1`
    /// caused collisions for depth values >= 10 (two digits).
    #[test]
    fn test_canonical_content_no_collision_different_depths() {
        let grants = test_grants();
        let token_id = "test-token-id";
        let issuer = "issuer-1";
        let holder = "holder-1";
        let issued_at = "2026-01-01T00:00:00Z";
        let expires_at = "2027-01-01T00:00:00Z";

        // Depth 5 (single digit)
        let canonical_5 = build_canonical_content(
            token_id, None, issuer, holder, &grants, 5, issued_at, expires_at,
        )
        .unwrap();

        // Depth 15 (two digits)
        let canonical_15 = build_canonical_content(
            token_id, None, issuer, holder, &grants, 15, issued_at, expires_at,
        )
        .unwrap();

        assert_ne!(
            canonical_5, canonical_15,
            "FIND-R115-020: Depth 5 and 15 must produce different canonical content"
        );
    }

    /// FIND-R115-020: Verify the length prefix for remaining_depth correctly
    /// reflects the string representation length.
    #[test]
    fn test_canonical_content_depth_length_prefix_correct() {
        let grants = test_grants();

        // Single-digit depth: length prefix should be "1"
        let canonical = build_canonical_content(
            "tok",
            None,
            "iss",
            "hold",
            &grants,
            5,
            "2026-01-01T00:00:00Z",
            "2027-01-01T00:00:00Z",
        )
        .unwrap();
        // The depth field should appear as "1:5" (length=1, value=5)
        assert!(
            canonical.contains("1:5"),
            "Single-digit depth should have length prefix 1"
        );

        // Two-digit depth: length prefix should be "2"
        let canonical = build_canonical_content(
            "tok",
            None,
            "iss",
            "hold",
            &grants,
            12,
            "2026-01-01T00:00:00Z",
            "2027-01-01T00:00:00Z",
        )
        .unwrap();
        // The depth field should appear as "2:12" (length=2, value=12)
        assert!(
            canonical.contains("2:12"),
            "Two-digit depth should have length prefix 2"
        );
    }

    /// FIND-R115-020: Issue and verify roundtrip works with two-digit depth values.
    #[test]
    fn test_issue_and_verify_two_digit_depth() {
        let key_hex = test_key_hex();
        let token = issue_capability_token(
            "issuer-1",
            "holder-1",
            test_grants(),
            12, // Two-digit depth
            &key_hex,
            3600,
        )
        .unwrap();

        assert_eq!(token.remaining_depth, 12);

        let key = parse_signing_key(&key_hex).unwrap();
        let pub_key_hex = hex::encode(key.verifying_key().as_bytes());
        let now = chrono::Utc::now();
        let result =
            verify_capability_token(&token, Some("holder-1"), Some(&pub_key_hex), &now).unwrap();
        assert!(
            result.valid,
            "FIND-R115-020: Token with two-digit depth should verify: {:?}",
            result.failure_reason
        );
    }

    // ════════════════════════════════════════════════════════
    // FIND-R116-MCP-001: expires_at included in Ed25519 signature
    // ════════════════════════════════════════════════════════

    /// FIND-R116-MCP-001: Modifying `expires_at` on a signed token must cause
    /// verification failure. Without `expires_at` in the canonical content, an
    /// attacker could extend a token's lifetime without invalidating the signature.
    #[test]
    fn test_tampered_expires_at_rejected() {
        let key_hex = test_key_hex();
        let token =
            issue_capability_token("issuer-1", "holder-1", test_grants(), 5, &key_hex, 3600)
                .unwrap();

        // Tamper with expires_at to extend the token's lifetime by 10 years
        let mut tampered = token.clone();
        let far_future = chrono::Utc::now() + chrono::Duration::days(3650);
        tampered.expires_at = far_future.to_rfc3339();

        let now = chrono::Utc::now();
        let result = verify_capability_token(&tampered, None, None, &now).unwrap();
        assert!(
            !result.valid,
            "FIND-R116-MCP-001: Token with tampered expires_at must fail verification"
        );
        assert!(
            result
                .failure_reason
                .as_ref()
                .unwrap()
                .contains("signature"),
            "FIND-R116-MCP-001: Failure should be signature-related, got: {:?}",
            result.failure_reason
        );
    }

    /// FIND-R116-MCP-001: Canonical content includes expires_at with correct
    /// length prefix.
    #[test]
    fn test_canonical_content_includes_expires_at() {
        let grants = test_grants();
        let expires_at = "2027-06-15T12:00:00Z";
        let canonical = build_canonical_content(
            "tok",
            None,
            "iss",
            "hold",
            &grants,
            5,
            "2026-01-01T00:00:00Z",
            expires_at,
        )
        .unwrap();
        // expires_at is 20 chars, so the canonical should contain "20:2027-06-15T12:00:00Z"
        assert!(
            canonical.contains(&format!("{}:{}", expires_at.len(), expires_at)),
            "FIND-R116-MCP-001: Canonical content must include length-prefixed expires_at"
        );
    }

    // ════════════════════════════════════════════════════════
    // FIND-R116-MCP-005: Self-delegation via Unicode confusables
    // ════════════════════════════════════════════════════════

    /// FIND-R116-MCP-005: Self-delegation via Cyrillic confusable must be rejected.
    #[test]
    fn test_attenuate_rejects_self_delegation_homoglyph() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        // Parent holder uses Latin "agent-a"
        let parent = issue_capability_token(
            "root",
            "agent-a",
            vec![CapabilityGrant {
                tool_pattern: "*".into(),
                function_pattern: "*".into(),
                allowed_paths: vec![],
                allowed_domains: vec![],
                max_invocations: 0,
            }],
            5,
            &parent_key_hex,
            3600,
        )
        .unwrap();

        // Attacker tries to self-delegate using Cyrillic 'а' (U+0430) instead of Latin 'a'
        let result = attenuate_capability_token(
            &parent,
            "\u{0430}gent-\u{0430}", // Cyrillic 'а' confusable
            test_grants(),
            &child_key_hex,
            1800,
        );
        assert!(
            result.is_err(),
            "FIND-R116-MCP-005: Self-delegation via homoglyphs must be rejected"
        );
        assert!(
            result.unwrap_err().to_string().contains("self-delegation"),
            "FIND-R116-MCP-005: Error should mention self-delegation"
        );
    }

    // ════════════════════════════════════════════════════════
    // FIND-CREATIVE-002: Glob metacharacter escalation in
    // capability token delegation
    // ════════════════════════════════════════════════════════

    /// FIND-CREATIVE-002 (P1): Parent grants "fi?" tool pattern (matches fi + one char).
    /// Child attempts "fi*" (matches fi + any suffix). Before the fix, pattern_matches("fi?", "fi*")
    /// treated "fi*" as a literal and matched successfully (? matches *). But at runtime,
    /// "fi*" is broader than "fi?" — this is a privilege escalation.
    #[test]
    fn test_attenuation_rejects_glob_escalation_tool_pattern() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent = issue_capability_token(
            "root",
            "agent-a",
            vec![CapabilityGrant {
                tool_pattern: "fi?".into(), // Matches fi + exactly one char
                function_pattern: "*".into(),
                allowed_paths: vec![],
                allowed_domains: vec![],
                max_invocations: 100,
            }],
            5,
            &parent_key_hex,
            3600,
        )
        .unwrap();

        // Child tries to escalate: "fi*" matches anything starting with "fi"
        let child_grants = vec![CapabilityGrant {
            tool_pattern: "fi*".into(), // Broader than parent's "fi?"
            function_pattern: "*".into(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 50,
        }];
        let result =
            attenuate_capability_token(&parent, "agent-b", child_grants, &child_key_hex, 1800);
        assert!(
            result.is_err(),
            "FIND-CREATIVE-002: Child 'fi*' is broader than parent 'fi?' — must be rejected"
        );
    }

    /// FIND-CREATIVE-002: Same escalation on function_pattern.
    #[test]
    fn test_attenuation_rejects_glob_escalation_function_pattern() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent = issue_capability_token(
            "root",
            "agent-a",
            vec![CapabilityGrant {
                tool_pattern: "*".into(),
                function_pattern: "read_?".into(), // Matches read_ + one char
                allowed_paths: vec![],
                allowed_domains: vec![],
                max_invocations: 100,
            }],
            5,
            &parent_key_hex,
            3600,
        )
        .unwrap();

        // Child tries: "read_*" matches read_ + anything
        let child_grants = vec![CapabilityGrant {
            tool_pattern: "*".into(),
            function_pattern: "read_*".into(), // Broader than parent's "read_?"
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 50,
        }];
        let result =
            attenuate_capability_token(&parent, "agent-b", child_grants, &child_key_hex, 1800);
        assert!(
            result.is_err(),
            "FIND-CREATIVE-002: Child 'read_*' is broader than parent 'read_?' — must be rejected"
        );
    }

    /// FIND-CREATIVE-002: Exact same glob pattern should still be allowed.
    #[test]
    fn test_attenuation_allows_identical_glob_pattern() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent = issue_capability_token(
            "root",
            "agent-a",
            vec![CapabilityGrant {
                tool_pattern: "file_*".into(),
                function_pattern: "read_?".into(),
                allowed_paths: vec![],
                allowed_domains: vec![],
                max_invocations: 100,
            }],
            5,
            &parent_key_hex,
            3600,
        )
        .unwrap();

        // Child uses exact same patterns — should succeed
        let child_grants = vec![CapabilityGrant {
            tool_pattern: "file_*".into(),
            function_pattern: "read_?".into(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 50,
        }];
        let result =
            attenuate_capability_token(&parent, "agent-b", child_grants, &child_key_hex, 1800);
        assert!(
            result.is_ok(),
            "FIND-CREATIVE-002: Identical glob patterns must be accepted: {:?}",
            result.err()
        );
    }

    /// FIND-CREATIVE-002: Literal child under glob parent should still work.
    #[test]
    fn test_attenuation_allows_literal_child_under_glob_parent() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent = issue_capability_token(
            "root",
            "agent-a",
            vec![CapabilityGrant {
                tool_pattern: "file_*".into(), // Matches file_ + anything
                function_pattern: "*".into(),
                allowed_paths: vec![],
                allowed_domains: vec![],
                max_invocations: 100,
            }],
            5,
            &parent_key_hex,
            3600,
        )
        .unwrap();

        // Child uses a literal — strictly narrower than parent's glob
        let child_grants = vec![CapabilityGrant {
            tool_pattern: "file_read".into(), // Literal, matched by parent's "file_*"
            function_pattern: "execute".into(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 50,
        }];
        let result =
            attenuate_capability_token(&parent, "agent-b", child_grants, &child_key_hex, 1800);
        assert!(
            result.is_ok(),
            "FIND-CREATIVE-002: Literal child 'file_read' under parent 'file_*' must succeed: {:?}",
            result.err()
        );
    }

    /// FIND-CREATIVE-002: Narrower child globs should be accepted when their
    /// language is truly contained within the parent glob language.
    #[test]
    fn test_attenuation_allows_narrower_child_glob_subset() {
        let parent_key_hex = test_key_hex();
        let child_key_hex = test_key_hex();
        let parent = issue_capability_token(
            "root",
            "agent-a",
            vec![CapabilityGrant {
                tool_pattern: "file_*".into(),
                function_pattern: "read_*".into(),
                allowed_paths: vec![],
                allowed_domains: vec![],
                max_invocations: 0,
            }],
            5,
            &parent_key_hex,
            3600,
        )
        .unwrap();

        let child_grants = vec![CapabilityGrant {
            tool_pattern: "file_read*".into(),
            function_pattern: "read_2026*".into(),
            allowed_paths: vec![],
            allowed_domains: vec![],
            max_invocations: 0,
        }];

        let result =
            attenuate_capability_token(&parent, "agent-b", child_grants, &child_key_hex, 1800);
        assert!(
            result.is_ok(),
            "Narrower child globs must be accepted by exact subset checking: {:?}",
            result.err()
        );
    }
}
