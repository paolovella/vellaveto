// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//! Warrant canary creation and cryptographic verification.
//!
//! A warrant canary is a cryptographically signed statement that asserts
//! no government surveillance orders have been received. When the canary
//! expires or is not renewed, users can infer that a gag order may have
//! been issued.

use chrono::{NaiveDate, Utc};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Maximum statement length to prevent abuse.
const MAX_STATEMENT_LENGTH: usize = 4096;

/// Maximum signing key hex length (Ed25519 = 64 hex chars).
const MAX_KEY_HEX_LENGTH: usize = 128;

/// Canary version — increment on format changes.
const CANARY_VERSION: u8 = 1;

/// A cryptographically signed warrant canary.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WarrantCanary {
    /// Format version for forward compatibility.
    pub version: u8,
    /// Date the canary was signed (YYYY-MM-DD).
    pub signed_date: String,
    /// Date the canary expires (YYYY-MM-DD).
    pub expires_date: String,
    /// The canary statement text.
    pub statement: String,
    /// Ed25519 signature over the canonical payload (hex-encoded).
    pub signature: String,
    /// Ed25519 verifying key (hex-encoded).
    pub verifying_key: String,
}

// SECURITY (R239-CAN-4): Custom Debug redacts signature to prevent
// cryptographic material leakage in logs.
impl std::fmt::Debug for WarrantCanary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WarrantCanary")
            .field("version", &self.version)
            .field("signed_date", &self.signed_date)
            .field("expires_date", &self.expires_date)
            .field("statement", &self.statement)
            .field("signature", &"[REDACTED]")
            .field("verifying_key", &self.verifying_key)
            .finish()
    }
}

/// Result of canary verification.
#[derive(Debug, Clone, PartialEq)]
pub struct CanaryVerification {
    /// Whether the signature is cryptographically valid.
    pub signature_valid: bool,
    /// Whether the canary has expired.
    pub expired: bool,
    /// Days until expiration (negative if expired).
    pub days_remaining: i64,
}

/// Returns true if the character is a Unicode format character (category Cf)
/// that could cause identity confusion or log injection.
///
/// SECURITY (R239-CAN-1): Aligned with canonical `vellaveto_types::is_unicode_format_char()`
/// to cover all known dangerous Unicode format character ranges. The canary crate is
/// Apache-2.0 standalone, so we copy rather than depend on vellaveto-types.
fn is_unicode_format_char(c: char) -> bool {
    matches!(c,
        '\u{00AD}'              |  // soft hyphen
        '\u{0600}'..='\u{0605}' |  // Arabic number/sign marks (Cf)
        '\u{061C}'              |  // Arabic Letter Mark (invisible bidi)
        '\u{06DD}'              |  // Arabic End of Ayah (Cf)
        '\u{070F}'              |  // Syriac Abbreviation Mark (Cf)
        '\u{0890}'..='\u{0891}' |  // Arabic Pound/Piastre Mark (Cf, Unicode 15.0+)
        '\u{08E2}'              |  // Arabic Disputed End of Ayah (Cf)
        '\u{200B}'..='\u{200F}' |  // zero-width space, ZWNJ, ZWJ, LRM, RLM
        '\u{202A}'..='\u{202E}' |  // bidi overrides (LRE, RLE, PDF, LRO, RLO)
        '\u{2060}'..='\u{2069}' |  // word joiner, invisible separators, bidi isolates
        '\u{FEFF}'              |  // BOM / zero-width no-break space
        '\u{FFF9}'..='\u{FFFB}' |  // interlinear annotation anchors
        '\u{110BD}'             |  // Kaithi Number Sign (Cf)
        '\u{110CD}'             |  // Kaithi Number Sign Above (Cf)
        '\u{17B4}'..='\u{17B5}' |  // Khmer invisible Cf chars
        '\u{180B}'..='\u{180F}' |  // Mongolian Free Variation Selectors (Cf)
        '\u{1D173}'..='\u{1D17A}' | // Musical Symbol format chars (Cf)
        '\u{FE00}'..='\u{FE0F}'   | // Variation Selectors (VS1-VS16, Mn/Cf)
        '\u{E0001}'..='\u{E007F}'  // TAG characters
    )
}

/// Check a string for dangerous characters (control chars, Unicode format chars).
///
/// SECURITY (R239-CAN-1): Uses `is_unicode_format_char()` aligned with the canonical
/// implementation in `vellaveto-types` to ensure full coverage of dangerous Unicode ranges.
fn has_dangerous_chars(s: &str) -> bool {
    s.chars()
        .any(|c| c.is_control() || is_unicode_format_char(c))
}

/// Build the canonical payload for signing/verification.
///
/// # Errors
/// Returns an error if JSON canonicalization fails (should never happen
/// for well-formed inputs, but fail-closed is mandatory).
/// Domain tag bound into the signed digest.
///
/// SECURITY (DOC-CRED-2): Without this, the signed value is a bare SHA-256
/// digest — 32 opaque bytes that say nothing about which kind of artifact they
/// came from. Seeding the hash with a type-specific constant means a canary
/// signature cannot be presented as a signature over any other artifact type,
/// which matters because one operator key may sign several.
///
/// Inlined rather than taken from `vellaveto_types::signing_domain`: this crate
/// is deliberately standalone and Apache-2.0, so it must not depend on the
/// BUSL-licensed workspace crates. The framing below is identical to theirs.
const DOMAIN_WARRANT_CANARY: &str = "vellaveto/warrant-canary/v1";

fn canonical_payload(
    version: u8,
    signed_date: &str,
    expires_date: &str,
    statement: &str,
    domain_separated: bool,
) -> Result<Vec<u8>, String> {
    let obj = serde_json::json!({
        "version": version,
        "signed_date": signed_date,
        "expires_date": expires_date,
        "statement": statement,
    });
    // SECURITY (R235-SHIELD-3): Propagate errors instead of unwrap_or_default().
    // Silent fallback could produce different canonical forms for the same input,
    // causing signature verification to silently fail or pass incorrectly.
    let canonical = serde_json_canonicalizer::to_string(&obj)
        .or_else(|_| serde_json::to_string(&obj))
        .map_err(|e| format!("canonical payload serialization failed: {e}"))?;
    let mut hasher = Sha256::new();
    if domain_separated {
        // Length-prefixed so the domain cannot be confused with the payload
        // that follows it.
        let domain = DOMAIN_WARRANT_CANARY.as_bytes();
        hasher.update((domain.len() as u64).to_le_bytes());
        hasher.update(domain);
    }
    hasher.update(canonical.as_bytes());
    Ok(hasher.finalize().to_vec())
}

/// Create a new warrant canary.
///
/// # Arguments
/// - `statement`: The canary statement text (max 4096 chars).
/// - `valid_days`: Number of days the canary is valid from today.
/// - `signing_key_hex`: Ed25519 signing key as hex string.
///
/// # Errors
/// Returns an error string if the statement is too long, contains dangerous
/// characters, or the signing key is invalid.
pub fn create_canary(
    statement: &str,
    valid_days: u64,
    signing_key_hex: &str,
) -> Result<WarrantCanary, String> {
    // SECURITY (R256-CAN-1): Reject valid_days == 0 — a canary that expires
    // on the same day it is created is effectively already expired and provides
    // no meaningful guarantee to consumers.
    if valid_days == 0 {
        return Err("valid_days must be at least 1".to_string());
    }

    // Validate statement
    if statement.is_empty() {
        return Err("statement must not be empty".to_string());
    }
    if statement.len() > MAX_STATEMENT_LENGTH {
        return Err(format!(
            "statement exceeds max length ({} > {})",
            statement.len(),
            MAX_STATEMENT_LENGTH
        ));
    }
    if has_dangerous_chars(statement) {
        return Err("statement contains dangerous characters".to_string());
    }

    // Validate signing key
    if signing_key_hex.len() > MAX_KEY_HEX_LENGTH {
        return Err("signing key hex too long".to_string());
    }
    let key_bytes =
        hex::decode(signing_key_hex).map_err(|e| format!("invalid signing key hex: {e}"))?;
    if key_bytes.len() != 32 {
        return Err(format!(
            "signing key must be 32 bytes, got {}",
            key_bytes.len()
        ));
    }
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "signing key must be exactly 32 bytes".to_string())?;
    let signing_key = SigningKey::from_bytes(&key_array);
    let verifying_key = signing_key.verifying_key();

    // Compute dates
    let now = Utc::now().date_naive();
    let signed_date = now.format("%Y-%m-%d").to_string();
    let expires_date = now
        .checked_add_days(chrono::Days::new(valid_days))
        .ok_or_else(|| "valid_days overflow".to_string())?
        .format("%Y-%m-%d")
        .to_string();

    // Sign canonical payload
    let payload = canonical_payload(CANARY_VERSION, &signed_date, &expires_date, statement, true)?;
    let signature = signing_key.sign(&payload);

    Ok(WarrantCanary {
        version: CANARY_VERSION,
        signed_date,
        expires_date,
        statement: statement.to_string(),
        signature: hex::encode(signature.to_bytes()),
        verifying_key: hex::encode(verifying_key.to_bytes()),
    })
}

/// Verify a warrant canary's signature consistency and expiration status.
///
/// # This does NOT authenticate the signer
///
/// The signature is verified against [`WarrantCanary::verifying_key`] — a field
/// of the canary itself. A `signature_valid: true` result therefore means the
/// canary is *internally consistent*, not that it came from any particular
/// publisher: anyone can generate a keypair, sign an arbitrary statement, and
/// obtain a valid result.
///
/// Callers MUST compare `canary.verifying_key` against a publisher key obtained
/// out of band before treating the statement as authentic.
///
/// # Timestamps are self-asserted
///
/// `signed_date` is written from the signer's own clock at day granularity
/// (see [`create_canary`]). There is no RFC 3161 timestamp authority or other
/// external anchor, so `expired` / `days_remaining` are computed by comparing
/// two unattested dates against the *verifier's* clock. To bound when a canary
/// was actually signed, the statement should quote a recent public
/// unpredictable value (a news headline, a recent block hash).
///
/// # Errors
/// Returns an error string if the canary data is malformed (invalid hex,
/// wrong key size, unparseable dates).
pub fn verify_canary(canary: &WarrantCanary) -> Result<CanaryVerification, String> {
    // SECURITY (R240-CAN-1): Reject unknown canary versions fail-closed.
    // Prevents forward-compatibility confusion where a future version with
    // a different payload format could be silently processed with v1 logic.
    if canary.version != CANARY_VERSION {
        return Err(format!(
            "unsupported canary version: {} (expected {})",
            canary.version, CANARY_VERSION
        ));
    }

    // Validate statement bounds
    if canary.statement.len() > MAX_STATEMENT_LENGTH {
        return Err(format!(
            "statement exceeds max length ({} > {})",
            canary.statement.len(),
            MAX_STATEMENT_LENGTH
        ));
    }
    if has_dangerous_chars(&canary.statement) {
        return Err("statement contains dangerous characters".to_string());
    }

    // SECURITY (R239-CAN-2): Validate signed_date and expires_date for dangerous chars
    // and correct date format. Previously only statement was validated here.
    if has_dangerous_chars(&canary.signed_date) {
        return Err("signed_date contains dangerous characters".to_string());
    }
    if has_dangerous_chars(&canary.expires_date) {
        return Err("expires_date contains dangerous characters".to_string());
    }
    // Validate signed_date is a valid YYYY-MM-DD date
    if NaiveDate::parse_from_str(&canary.signed_date, "%Y-%m-%d").is_err() {
        return Err(format!(
            "signed_date '{}' is not a valid YYYY-MM-DD date",
            canary.signed_date
        ));
    }
    // SECURITY (R239-CAN-3): Also validate expires_date format early (previously only
    // validated late at line 271 — fail-fast is more defensive).
    let parsed_expires =
        NaiveDate::parse_from_str(&canary.expires_date, "%Y-%m-%d").map_err(|_| {
            format!(
                "expires_date '{}' is not a valid YYYY-MM-DD date",
                canary.expires_date
            )
        })?;
    // SECURITY (R259-CAN-1): Validate chronological ordering. A canary with
    // signed_date > expires_date is semantically invalid — it was "born expired".
    // While create_canary() guarantees this by construction, verify_canary() must
    // also check because it processes untrusted input (attacker-crafted canaries).
    let parsed_signed =
        NaiveDate::parse_from_str(&canary.signed_date, "%Y-%m-%d").map_err(|_| {
            format!(
                "signed_date '{}' parse failed unexpectedly",
                canary.signed_date
            )
        })?;
    if parsed_signed > parsed_expires {
        return Err(format!(
            "signed_date ({}) must not be after expires_date ({})",
            canary.signed_date, canary.expires_date
        ));
    }

    // Parse verifying key
    let vk_bytes = hex::decode(&canary.verifying_key)
        .map_err(|e| format!("invalid verifying key hex: {e}"))?;
    if vk_bytes.len() != 32 {
        return Err(format!(
            "verifying key must be 32 bytes, got {}",
            vk_bytes.len()
        ));
    }
    let vk_array: [u8; 32] = vk_bytes
        .try_into()
        .map_err(|_| "verifying key conversion failed".to_string())?;
    let verifying_key =
        VerifyingKey::from_bytes(&vk_array).map_err(|e| format!("invalid verifying key: {e}"))?;

    // Parse signature
    let sig_bytes =
        hex::decode(&canary.signature).map_err(|e| format!("invalid signature hex: {e}"))?;
    if sig_bytes.len() != 64 {
        return Err(format!(
            "signature must be 64 bytes, got {}",
            sig_bytes.len()
        ));
    }
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "signature conversion failed".to_string())?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

    // Verify signature.
    //
    // SECURITY (DOC-CRED-2): Try the domain-separated payload first, then fall
    // back to the pre-domain-separation form so canaries published before the
    // change keep verifying. Signing always uses the domain-separated form.
    let payload = canonical_payload(
        canary.version,
        &canary.signed_date,
        &canary.expires_date,
        &canary.statement,
        true,
    )?;
    let signature_valid = if verifying_key.verify(&payload, &signature).is_ok() {
        true
    } else {
        let undomained = canonical_payload(
            canary.version,
            &canary.signed_date,
            &canary.expires_date,
            &canary.statement,
            false,
        )?;
        verifying_key.verify(&undomained, &signature).is_ok()
    };

    // Check expiration
    let expires = NaiveDate::parse_from_str(&canary.expires_date, "%Y-%m-%d")
        .map_err(|e| format!("invalid expires_date: {e}"))?;
    let today = Utc::now().date_naive();
    let days_remaining = (expires - today).num_days();
    let expired = days_remaining < 0;

    Ok(CanaryVerification {
        signature_valid,
        expired,
        days_remaining,
    })
}

#[cfg(test)]
mod tests;
